#!/usr/bin/env python3
"""Authorize release execution from server-side metadata, never PR scripts."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from oidc_credentials import NoRedirect

RELEASE_FILES = {'CHANGELOG.md', '.release-please-manifest.json', 'version.txt'}
RELEASE_BRANCHES = {'release-please--branches--coreweave',
                    'release-please--branches--coreweave--components--coreweave'}
GATE = 'storage-acceptance'
# GitHub signs API-created commits for the built-in Actions bot.
GITHUB_ACTIONS_BOT_ID = 41898282
GITHUB_SIGNER_ID = 19864447
CI_CHECKS = {'credential-helper'} | {
    f'{kind} ({system}/go-{version}.x)'
    for kind in ('build', 'test') for system in ('ubuntu', 'macos', 'windows')
    for version in ('1.20', '1.21', '1.22')
} | {f'qa ({version}.x, ubuntu)' for version in ('1.20', '1.21', '1.22')}


def require(condition):
    if not condition:
        raise ValueError('release authorization failed')


def version_parts(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value))
    return tuple(int(part) for part in value.split('.'))


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value))
    return value


def claims_release(pr, bot_id):
    return (pr['head']['ref'] in RELEASE_BRANCHES or
            any(label['name'].startswith('autorelease:') for label in pr['labels']) or
            (bot_id != 0 and pr['user']['id'] == bot_id))


def verify_candidate(pr, files, commits, manifest, version_text, previous,
                     merge, head_commit, repository, bot_id):
    require(bot_id > 0 and pr['user']['id'] == bot_id and pr['user']['type'] == 'Bot')
    require(pr['base']['ref'] == 'coreweave' and not pr['draft'])
    require(pr['base']['repo']['full_name'] == repository == pr['head']['repo']['full_name'])
    require(pr['head']['ref'] in RELEASE_BRANCHES)
    require(any(label['name'] in ('autorelease: pending', 'autorelease: tagged') for label in pr['labels']))
    require({file['filename'] for file in files} == RELEASE_FILES and
            all(file['status'] == 'modified' for file in files))
    require(commits and all(commit['author'] and commit['author']['id'] == bot_id and
                           commit['committer'] and commit['committer']['id'] == GITHUB_SIGNER_ID and
                           commit['commit']['verification']['verified'] and
                           commit['commit']['verification']['reason'] == 'valid' for commit in commits))
    require(set(manifest) == {'.'})
    version = manifest['.']
    require(version_parts(version) > version_parts(previous.strip()))
    require(version_text.strip() == version)
    body = pr.get('body') or ''
    require(body.startswith(':robot: I have created a release *beep* *boop*\n---\n'))
    require('This PR was generated with [Release Please](https://github.com/googleapis/release-please).' in body)
    require(re.search(r'^#{2,} \[?' + re.escape(version) + r'(?:\]|\s|$)', body, re.MULTILINE))
    head, base = sha(pr['head']['sha']), sha(pr['base']['sha'])
    require([parent['sha'] for parent in merge['parents']] == [base, head])
    require(head_commit['sha'] == head and head_commit['tree']['sha'] == merge['tree']['sha'])
    return {'pr': pr['number'], 'branch': pr['head']['ref'], 'head': head, 'base': base, 'merge': sha(merge['sha']),
            'tree': sha(merge['tree']['sha']), 'version': version, 'tag': 'coreweave-v' + version}


def verify_publication(proof, pr, commit, run, checks, reviews, repository, bot_id, evidence):
    require(proof == evidence)
    require(pr['merged'] and pr['state'] == 'closed' and pr['user']['id'] == bot_id)
    require(pr['base']['ref'] == 'coreweave' and pr['head']['repo']['full_name'] == repository)
    require(proof['pr'] == pr['number'] and proof['head'] == pr['head']['sha'])
    require(commit['sha'] == pr['merge_commit_sha'] and commit['tree']['sha'] == proof['tree'])
    require(commit['parents'] and commit['parents'][0]['sha'] == proof['base'])
    require(run['id'] == proof['run_id'] and run['repository']['full_name'] == repository)
    require(run['run_attempt'] == proof['run_attempt'])
    require(run['path'] == '.github/workflows/storage-gate.yml' and
            run['event'] == 'workflow_dispatch' and run['head_branch'] == 'coreweave' and run['head_sha'] == proof['base'] and
            run['status'] == 'completed' and run['conclusion'] == 'success')
    latest = {check['name']: check for check in checks if check['app']['slug'] == 'github-actions'}
    require(all(name in latest and latest[name]['status'] == 'completed' and
                latest[name]['conclusion'] == 'success' for name in CI_CHECKS))
    approvals = {}
    for review in sorted(reviews, key=lambda item: item['submitted_at'] or ''):
        if review['user']['type'] == 'User' and review['state'] != 'COMMENTED':
            approvals[review['user']['id']] = review
    require(any(review['state'] == 'APPROVED' and review['commit_id'] == proof['head'] and
                review.get('author_association') in ('OWNER', 'MEMBER', 'COLLABORATOR') and
                review.get('_may_approve') is True
                for review in approvals.values()))
    version_parts(proof['version'])
    require(proof['tag'] == 'coreweave-v' + proof['version'])
    return dict(proof, commit=sha(commit['sha']))


class GitHub:
    def __init__(self):
        self.repository = os.environ['GITHUB_REPOSITORY']
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository))
        self.root = 'https://api.github.com/repos/' + self.repository
        self.token = os.environ['GH_TOKEN']

    def request(self, path, method='GET', data=None, missing=False):
        require(path == '' or path.startswith('/') and not path.startswith('//'))
        request = urllib.request.Request(self.root + path, method=method,
                                         data=json.dumps(data).encode() if data is not None else None,
                                         headers={'Authorization': 'Bearer ' + self.token,
                                                  'Accept': 'application/vnd.github+json',
                                                  'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                body = response.read(4 * 1024 * 1024 + 1)
                require(len(body) <= 4 * 1024 * 1024)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise ValueError('GitHub request failed') from None

    def pages(self, path, key=None):
        items = []
        for page in range(1, 11):
            result = self.request(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            values = result[key] if key else result
            items.extend(values)
            if len(values) < 100:
                return items
        raise ValueError('metadata limit exceeded')

    def content(self, path, ref):
        data = self.request('/contents/' + path + '?ref=' + sha(ref))
        require(data['type'] == 'file' and data['size'] < 1024 * 1024)
        return base64.b64decode(data['content'], validate=False).decode()


def outputs(values):
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        for key, value in values.items():
            text = json.dumps(value, separators=(',', ':')) if isinstance(value, dict) else str(value)
            require('\n' not in text and '\r' not in text)
            stream.write(f'{key}={text}\n')


def candidate(api, number, bot_id):
    require(api.request('')['default_branch'] == 'coreweave')
    pr = api.request(f'/pulls/{number}')
    require(pr['state'] == 'open')
    base = api.request('/git/ref/heads/coreweave')['object']['sha']
    require(base == pr['base']['sha'])
    merge_ref = sha(pr['merge_commit_sha'])
    proof = verify_candidate(pr, api.pages(f'/pulls/{number}/files'),
                             api.pages(f'/pulls/{number}/commits'),
                             json.loads(api.content('.release-please-manifest.json', pr['head']['sha'])),
                             api.content('version.txt', pr['head']['sha']),
                             api.content('version.txt', base),
                             api.request('/git/commits/' + sha(merge_ref)),
                             api.request('/git/commits/' + sha(pr['head']['sha'])), api.repository, bot_id)
    return proof


def prepared_candidate(api, number, bot_id):
    # GitHub computes a new PR's merge commit asynchronously.
    for attempt in range(10):
        pr = api.request(f'/pulls/{number}')
        if pr['merge_commit_sha'] is not None:
            return candidate(api, number, bot_id)
        require(pr['state'] == 'open' and pr.get('mergeable') is None)
        if attempt < 9:
            time.sleep(2)
    raise ValueError('candidate merge is unavailable')


def capture_candidate(api, bot_id):
    prs = json.loads(os.environ.get('RELEASE_PLEASE_PRS') or '[]')
    require(isinstance(prs, list) and len(prs) <= 1)
    if not prs:
        outputs({'candidate': 'false'})
        return
    proof = prepared_candidate(api, int(prs[0]['number']), bot_id)
    require(proof['base'] == os.environ['GITHUB_SHA'])
    proof.update(producer_run_id=int(os.environ['GITHUB_RUN_ID']),
                 producer_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']))
    Path('release-candidate.json').write_text(json.dumps(proof, separators=(',', ':')) + '\n')
    outputs({'candidate': 'true'})


def release_tip(api):
    require(os.environ['GITHUB_REF'] == 'refs/heads/coreweave')
    current = api.request('/git/ref/heads/coreweave')['object']['sha'] == os.environ['GITHUB_SHA']
    outputs({'current': 'true' if current else 'false'})
    if not current:
        print('Release PR refresh skipped because newer commits are present.')


def verify_producer(proof, run, jobs, repository):
    require(run['id'] == proof['producer_run_id'] and run['run_attempt'] == proof['producer_attempt'])
    require(run['repository']['full_name'] == repository and run['head_sha'] == proof['base'] and
            run['head_branch'] == 'coreweave' and run['path'] == '.github/workflows/release.yml' and
            run['event'] in ('push', 'workflow_dispatch'))
    producers = [job for job in jobs if job['name'] == 'release-please']
    require(len(producers) == 1 and producers[0]['conclusion'] == 'success')
    steps = {step['name'] for step in producers[0]['steps'] if step['conclusion'] == 'success'}
    require({'Update the release PR', 'Record the release candidate', 'Store candidate source hashes'} <= steps)


def source_artifact(api, run_id, artifact_name):
    artifacts = api.pages(f'/actions/runs/{int(run_id)}/artifacts', 'artifacts')
    records = [artifact for artifact in artifacts if artifact['name'] == artifact_name]
    require(len(records) == 1 and not records[0]['expired'])
    with tempfile.TemporaryDirectory(prefix='s5cmd-evidence-') as directory:
        subprocess.run(['gh', 'run', 'download', str(int(run_id)), '--repo', api.repository,
                        '--name', artifact_name, '--dir', directory],
                       check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        filename = 'release-candidate.json' if artifact_name.startswith('release-candidate-') else 'acceptance-evidence.json'
        path = Path(directory) / filename
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 4096)
        return json.loads(path.read_text())


def producer_evidence(api, run_id, attempt):
    run_id, attempt = int(run_id), int(attempt)
    require(run_id > 0 and attempt > 0)
    proof = source_artifact(api, run_id, f'release-candidate-{attempt}')
    require(proof['producer_run_id'] == run_id and proof['producer_attempt'] == attempt)
    run = api.request(f'/actions/runs/{run_id}/attempts/{attempt}')
    jobs = api.pages(f'/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    verify_producer(proof, run, jobs, api.repository)
    return proof


def fresh_producer(api, bot_id):
    proof = producer_evidence(api, os.environ['PRODUCER_RUN_ID'], os.environ['PRODUCER_ATTEMPT'])
    current = candidate(api, proof['pr'], bot_id)
    require(all(current[key] == proof[key] for key in current))
    return proof


def dispatch_validation(api, bot_id):
    proof = fresh_producer(api, bot_id)
    require(proof['base'] == os.environ['GITHUB_SHA'])
    inputs = {'producer_run_id': str(proof['producer_run_id']),
              'producer_attempt': str(proof['producer_attempt'])}
    api.request('/actions/workflows/ci.yml/dispatches', 'POST', {
        'ref': proof['branch'],
        'inputs': dict(inputs, expected_head=proof['head'])})
    api.request('/actions/workflows/storage-gate.yml/dispatches', 'POST', {
        'ref': 'coreweave', 'inputs': dict(inputs, pr=str(proof['pr']))})


def ci_preflight(api, bot_id):
    require(sha(os.environ['EXPECTED_HEAD']) == os.environ['GITHUB_SHA'])
    proof = fresh_producer(api, bot_id)
    require(proof['head'] == os.environ['GITHUB_SHA'])


def ci_evidence(api, proof, checks):
    latest = {check['name']: check for check in checks if check['app']['slug'] == 'github-actions'}
    require(all(name in latest and latest[name]['status'] == 'completed' and
                latest[name]['conclusion'] == 'success' for name in CI_CHECKS))
    suites = {latest[name]['check_suite']['id'] for name in CI_CHECKS}
    require(len(suites) == 1)
    runs = api.pages(f'/actions/runs?check_suite_id={suites.pop()}', 'workflow_runs')
    require(len(runs) == 1)
    run = runs[0]
    require(run['path'] == '.github/workflows/ci.yml' and run['event'] == 'workflow_dispatch' and
            run['head_sha'] == proof['head'] and run['repository']['full_name'] == api.repository and
            run['status'] == 'completed' and run['conclusion'] == 'success')
    jobs = api.pages(f'/actions/runs/{int(run["id"])}/attempts/{int(run["run_attempt"])}/jobs', 'jobs')
    preflight = [job for job in jobs if job['name'] == 'release-preflight']
    require(len(preflight) == 1 and preflight[0]['conclusion'] == 'success' and
            any(step['name'] == 'Verify release candidate' and step['conclusion'] == 'success'
                for step in preflight[0]['steps']))


def complete_check(api, identifier, conclusion, summary):
    api.request(f'/check-runs/{identifier}', 'PATCH', {
        'status': 'completed', 'conclusion': conclusion,
        'output': {'title': GATE, 'summary': summary}})


def gate_uses_current_base(api, head):
    checks = api.pages(f'/commits/{head}/check-runs', 'check_runs')
    gates = [check for check in checks if check['name'] == GATE and check['app']['slug'] == 'github-actions']
    if not gates:
        return False
    check = max(gates, key=lambda item: item['id'])
    identifier = check.get('external_id') or ''
    if not re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', identifier):
        return False
    run_id, attempt = identifier.split(':')
    run = api.request(f'/actions/runs/{run_id}/attempts/{attempt}')
    return (run['path'] == '.github/workflows/storage-gate.yml' and run['event'] == 'workflow_dispatch' and
            run['head_sha'] == os.environ['GITHUB_SHA'] and run['head_branch'] == 'coreweave')


def inspect(api, bot_id):
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    dispatch = os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
    if dispatch:
        require(os.environ['GITHUB_REF'] == 'refs/heads/coreweave')
        number = int(event['inputs']['pr'])
    elif 'pull_request' in event:
        number = event['pull_request']['number']
    else:
        require(os.environ['GITHUB_REF'] == 'refs/heads/coreweave')
        if api.request('/git/ref/heads/coreweave')['object']['sha'] != os.environ['GITHUB_SHA']:
            outputs({'live': 'false'})
            return
        prs = [pr for pr in api.pages('/pulls?state=open&base=coreweave')
               if pr['user']['id'] == bot_id and
               (pr['head']['repo'] or {}).get('full_name') == api.repository and claims_release(pr, bot_id)]
        require(len(prs) <= 1)
        if not prs:
            outputs({'live': 'false'})
            return
        number = prs[0]['number']
    pr = api.request(f'/pulls/{number}')
    head = sha(pr['head']['sha'])
    # Bot updates use an explicit dispatch with immutable producer evidence.
    # Automatic PR events must not replace its pending or completed live gate.
    if not dispatch and 'pull_request' in event and pr['user']['id'] == bot_id and claims_release(pr, bot_id):
        outputs({'live': 'false'})
        return
    # A slow base-push handler must not invalidate the newer explicit dispatch.
    if not dispatch and 'pull_request' not in event and gate_uses_current_base(api, head):
        outputs({'live': 'false'})
        return
    # A check belongs to a SHA, so a fork of a release head must not overwrite
    # that release's live gate with an ordinary PR success (or failure).
    protected = [other for other in api.pages(f'/commits/{head}/pulls')
                 if other['number'] != number and other['head']['sha'] == head and
                 other['user']['id'] == bot_id and
                 (other['head']['repo'] or {}).get('full_name') == api.repository and claims_release(other, bot_id)]
    if protected:
        outputs({'live': 'false'})
        return
    check = api.request('/check-runs', 'POST', {
        'name': GATE, 'head_sha': head, 'status': 'in_progress',
        'external_id': f'{int(os.environ["GITHUB_RUN_ID"])}:{int(os.environ["GITHUB_RUN_ATTEMPT"])}',
        'details_url': f'https://github.com/{api.repository}/actions/runs/{int(os.environ["GITHUB_RUN_ID"])}'})
    try:
        require(check['external_id'] == f'{int(os.environ["GITHUB_RUN_ID"])}:{int(os.environ["GITHUB_RUN_ATTEMPT"])}')
        if not claims_release(pr, bot_id):
            complete_check(api, check['id'], 'success', 'Ordinary PR: live storage execution is not requested.')
            outputs({'live': 'false'})
            return
        require(os.environ.get('RELEASE_AUTOMATION_ENABLED') == 'true')
        if not dispatch:
            complete_check(api, check['id'], 'failure', 'The base changed; waiting for release candidate validation.')
            outputs({'live': 'false'})
            return
        proof = producer_evidence(api, event['inputs']['producer_run_id'], event['inputs']['producer_attempt'])
        require(proof['pr'] == number)
        current = candidate(api, number, bot_id)
        require(all(current[key] == proof[key] for key in current))
        require(proof['base'] == os.environ['GITHUB_SHA'])
        proof['run_id'] = int(os.environ['GITHUB_RUN_ID'])
        proof['run_attempt'] = int(os.environ['GITHUB_RUN_ATTEMPT'])
        outputs({'live': 'true', 'check': check['id'], 'proof': proof,
                 'base': proof['base'], 'merge': proof['merge'], 'pr': number})
    except Exception:
        complete_check(api, check['id'], 'failure', 'Release verification failed; no storage credentials were requested.')
        raise


def finish(api, bot_id):
    proof = json.loads(os.environ['RELEASE_PROOF'])
    identifier = int(os.environ['RELEASE_CHECK'])
    try:
        verify_attempt(proof)
        require(os.environ['ACCEPTANCE_RESULT'] == 'success')
        current = candidate(api, proof['pr'], bot_id)
        require(all(current[key] == proof[key] for key in current))
        complete_check(api, identifier, 'success', json.dumps(proof, separators=(',', ':')))
    except Exception:
        complete_check(api, identifier, 'failure', 'Live acceptance, cleanup, or revision freshness failed.')
        raise


def evidence(api, bot_id):
    proof = json.loads(os.environ['RELEASE_PROOF'])
    verify_attempt(proof)
    require(os.environ['ACCEPTANCE_RESULT'] == 'success')
    current = candidate(api, proof['pr'], bot_id)
    require(all(current[key] == proof[key] for key in current))
    Path('acceptance-evidence.json').write_text(json.dumps(proof, separators=(',', ':')) + '\n')


def verify_attempt(proof):
    require(proof['run_id'] == int(os.environ['GITHUB_RUN_ID']) and
            proof['run_attempt'] == int(os.environ['GITHUB_RUN_ATTEMPT']))


def eligible_reviews(api, reviews):
    permissions = {}
    for review in reviews:
        user = review['user']
        if user['type'] != 'User':
            review['_may_approve'] = False
            continue
        if user['id'] not in permissions:
            result = api.request('/collaborators/' + urllib.parse.quote(user['login'], safe='') + '/permission', missing=True)
            permissions[user['id']] = bool(result and result['permission'] in ('write', 'maintain', 'admin'))
        review['_may_approve'] = permissions[user['id']]
    return reviews


def acceptance_evidence(api, run_id, attempt):
    run_id = int(run_id)
    attempt = int(attempt)
    jobs = api.pages(f'/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    live_jobs = [job for job in jobs if job['name'] == 'acceptance']
    require(len(live_jobs) == 1 and live_jobs[0]['conclusion'] == 'success')
    required_steps = {'Reverify after environment approval', 'Check out only the verified candidate merge',
                      'Run bounded live suite', 'Recover the exact run bucket and remove private files'}
    successful_steps = {step['name'] for step in live_jobs[0]['steps'] if step['conclusion'] == 'success'}
    require(required_steps <= successful_steps)
    return source_artifact(api, run_id, f'storage-acceptance-evidence-{attempt}')


def publication_plan(api, bot_id):
    require(os.environ['GITHUB_REF'] == 'refs/heads/coreweave')
    commit_sha = sha(os.environ['GITHUB_SHA'])
    prs = [pr for pr in api.pages(f'/commits/{commit_sha}/pulls')
           if pr.get('merged_at') and pr['base']['ref'] == 'coreweave' and
           pr['merge_commit_sha'] == commit_sha]
    require(len(prs) <= 1)
    if not prs or not claims_release(prs[0], bot_id):
        outputs({'publish': 'false'})
        return
    require(os.environ.get('RELEASE_AUTOMATION_ENABLED') == 'true')
    pr = api.request(f'/pulls/{prs[0]["number"]}')
    checks = api.pages('/commits/' + sha(pr['head']['sha']) + '/check-runs', 'check_runs')
    checks.sort(key=lambda check: check['id'])
    gates = [check for check in checks if check['name'] == GATE and check['app']['slug'] == 'github-actions']
    require(gates and gates[-1]['status'] == 'completed' and gates[-1]['conclusion'] == 'success')
    proof = json.loads(gates[-1]['output']['summary'])
    require(gates[-1]['external_id'] == f'{int(proof["run_id"])}:{int(proof["run_attempt"])}')
    producer = producer_evidence(api, proof['producer_run_id'], proof['producer_attempt'])
    require(all(producer[key] == proof[key] for key in producer))
    ci_evidence(api, proof, checks)
    commit = api.request('/git/commits/' + commit_sha)
    plan = verify_publication(proof, pr, commit, api.request(f'/actions/runs/{int(proof["run_id"])}/attempts/{int(proof["run_attempt"])}'),
                              checks, eligible_reviews(api, api.pages(f'/pulls/{pr["number"]}/reviews')), api.repository, bot_id,
                              acceptance_evidence(api, proof['run_id'], proof['run_attempt']))
    # Revalidate release metadata at the immutable head before creating a tag.
    frozen = dict(pr, base=dict(pr['base'], sha=proof['base']))
    expected_merge = {'sha': proof['merge'], 'tree': {'sha': proof['tree']},
                      'parents': [{'sha': proof['base']}, {'sha': proof['head']}]}
    verified = verify_candidate(frozen, api.pages(f'/pulls/{pr["number"]}/files'),
                                api.pages(f'/pulls/{pr["number"]}/commits'),
                                json.loads(api.content('.release-please-manifest.json', proof['head'])),
                                api.content('version.txt', proof['head']),
                                api.content('version.txt', proof['base']), expected_merge,
                                api.request('/git/commits/' + sha(proof['head'])), api.repository, bot_id)
    require(all(verified[key] == proof[key] for key in verified))
    outputs({'publish': 'true', 'plan': plan, 'tag': plan['tag'], 'version': plan['version'], 'commit': commit_sha})


def find_release(api, tag):
    matches = [release for release in api.pages('/releases') if release['tag_name'] == tag]
    require(len(matches) <= 1)
    return matches[0] if matches else None


def prepare_release(api):
    plan = json.loads(os.environ['RELEASE_PLAN'])
    tag = 'coreweave-v' + '.'.join(str(part) for part in version_parts(plan['version']))
    require(tag == plan['tag'])
    commit = sha(plan['commit'])
    require(api.request('/git/commits/' + commit)['tree']['sha'] == plan['tree'])
    ref = api.request('/git/ref/tags/' + tag, missing=True)
    if ref:
        require(ref['object']['type'] == 'commit' and ref['object']['sha'] == commit)
    else:
        api.request('/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': commit})
    release = find_release(api, tag)
    if not release:
        release = api.request('/releases', 'POST', {
            'tag_name': tag, 'target_commitish': commit, 'name': tag, 'draft': True,
            'body': release_notes(api.content('CHANGELOG.md', commit), plan['version'])})
    outputs({'release': release['id'], 'build': 'true' if release['draft'] else 'false'})


def finalize_release(api):
    plan = json.loads(os.environ['RELEASE_PLAN'])
    tag = 'coreweave-v' + '.'.join(str(part) for part in version_parts(plan['version']))
    require(plan['tag'] == tag)
    release = api.request('/releases/' + str(int(os.environ['RELEASE_ID'])))
    require(release['tag_name'] == tag)
    require(api.request('/git/ref/tags/' + tag)['object']['sha'] == sha(plan['commit']))
    latest = api.content('version.txt', api.request('/git/ref/heads/coreweave')['object']['sha']).strip() == plan['version']
    api.request(f'/releases/{release["id"]}', 'PATCH', {'draft': False, 'make_latest': 'true' if latest else 'false'})
    number = int(plan['pr'])
    api.request(f'/issues/{number}/labels', 'POST', {'labels': ['autorelease: tagged']})
    api.request(f'/issues/{number}/labels/' + urllib.parse.quote('autorelease: pending', safe=''),
                'DELETE', missing=True)


def release_notes(changelog, version):
    version_parts(version)
    sections = re.split(r'(?=^## )', changelog, flags=re.MULTILINE)
    notes = [section for section in sections if re.match(r'^## \[?' + re.escape(version) + r'(?:\]|\s|$)', section)]
    require(len(notes) == 1)
    return notes[0].strip()


def publication_tags(api):
    plan = json.loads(os.environ['RELEASE_PLAN'])
    version_parts(plan['version'])
    require(plan['tag'] == 'coreweave-v' + plan['version'])
    prefix = 'ghcr.io/' + api.repository + ':'
    tags = [prefix + plan['tag'], prefix + sha(plan['commit'])]
    current = api.request('/git/ref/heads/coreweave')['object']['sha']
    if api.content('version.txt', current).strip() == plan['version']:
        tags.append(prefix + 'latest')
    outputs({'tags': ','.join(tags)})


def execute(args):
    require(len(args) == 1)
    api = GitHub()
    bot_id = GITHUB_ACTIONS_BOT_ID
    if args[0] == 'inspect':
        inspect(api, bot_id)
    elif args[0] == 'finish':
        finish(api, bot_id)
    elif args[0] == 'evidence':
        evidence(api, bot_id)
    elif args[0] == 'publication-plan':
        publication_plan(api, bot_id)
    elif args[0] == 'prepare-release':
        prepare_release(api)
    elif args[0] == 'finalize-release':
        finalize_release(api)
    elif args[0] == 'publication-tags':
        publication_tags(api)
    elif args[0] == 'capture-candidate':
        capture_candidate(api, bot_id)
    elif args[0] == 'dispatch-validation':
        dispatch_validation(api, bot_id)
    elif args[0] == 'ci-preflight':
        ci_preflight(api, bot_id)
    elif args[0] == 'release-tip':
        release_tip(api)
    else:
        raise ValueError('unsupported operation')


def main(args):
    try:
        execute(args)
        return 0
    except Exception:
        sys.stderr.write('release authorization failed\n')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
