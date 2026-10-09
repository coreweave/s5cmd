"""Synthetic release authorization tests; no GitHub or storage credentials."""

import copy
import json
import unittest

import release_gate as gate


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.pr = {
            'number': 7, 'state': 'open', 'draft': False,
            'user': {'id': 123, 'type': 'Bot'},
            'base': {'ref': 'coreweave', 'sha': 'a' * 40,
                     'repo': {'full_name': 'example/s5cmd'}},
            'head': {'ref': 'release-please--branches--coreweave', 'sha': 'b' * 40,
                     'repo': {'full_name': 'example/s5cmd'}},
            'labels': [{'name': 'autorelease: pending'}],
            'body': ':robot: I have created a release *beep* *boop*\n---\n\n## [2.4.0](https://example.com)\n\n---\nThis PR was generated with [Release Please](https://github.com/googleapis/release-please).',
        }
        self.files = [{'filename': name, 'status': 'modified'} for name in gate.RELEASE_FILES]
        self.commits = [{'author': {'id': 123}, 'committer': {'id': 19864447},
                         'commit': {'verification': {'verified': True, 'reason': 'valid'}}}]
        self.merge = {'sha': 'c' * 40, 'tree': {'sha': 'd' * 40},
                      'parents': [{'sha': 'a' * 40}, {'sha': 'b' * 40}]}
        self.head_commit = {'sha': 'b' * 40, 'tree': {'sha': 'd' * 40}}

    def candidate(self):
        return gate.verify_candidate(self.pr, self.files, self.commits,
                                     {'.': '2.4.0'}, '2.4.0\n', '2.3.0',
                                     self.merge, self.head_commit, 'example/s5cmd', 123)

    def test_valid_candidate_records_exact_content(self):
        proof = self.candidate()
        self.assertEqual(proof['tree'], 'd' * 40)
        self.assertEqual(proof['base'], 'a' * 40)
        self.assertEqual(proof['tag'], 'coreweave-v2.4.0')

    def test_ordinary_pr_does_not_request_storage(self):
        self.pr['head']['ref'] = 'feature'
        self.pr['labels'] = []
        self.pr['user']['id'] = 456
        self.assertFalse(gate.claims_release(self.pr, 123))

    def test_spoofed_release_cannot_authorize_execution(self):
        for change in ('author', 'fork', 'unsigned', 'signer', 'code', 'base', 'label', 'draft'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'author':
                    self.pr['user']['id'] = 456
                elif change == 'fork':
                    self.pr['head']['repo']['full_name'] = 'attacker/s5cmd'
                elif change == 'unsigned':
                    self.commits[0]['commit']['verification']['verified'] = False
                elif change == 'signer':
                    self.commits[0]['committer']['id'] = 456
                elif change == 'code':
                    self.files.append({'filename': 'scripts/oidc_credentials.py', 'status': 'modified'})
                elif change == 'base':
                    self.pr['base']['ref'] = 'master'
                elif change == 'label':
                    self.pr['labels'] = []
                else:
                    self.pr['draft'] = True
                with self.assertRaises(ValueError):
                    self.candidate()

    def test_version_and_release_metadata_must_agree(self):
        self.pr['body'] = self.pr['body'].replace('2.4.0', '9.0.0')
        with self.assertRaises(ValueError):
            self.candidate()
        self.setUp()
        for manifest, version, previous in [({'.': '2.4.0'}, '2.5.0', '2.3.0'),
                                            ({'.': '2.4.0'}, '2.4.0', '2.4.0'),
                                            ({'.': '2.4.0', 'other': '1.0.0'}, '2.4.0', '2.3.0')]:
            with self.assertRaises(ValueError):
                gate.verify_candidate(self.pr, self.files, self.commits, manifest,
                                      version, previous, self.merge, self.head_commit, 'example/s5cmd', 123)

    def test_stale_merge_ref_is_rejected(self):
        self.merge['parents'][0]['sha'] = 'e' * 40
        with self.assertRaises(ValueError):
            self.candidate()

    def test_missing_bot_configuration_fails_closed_for_release(self):
        with self.assertRaises(ValueError):
            gate.verify_candidate(self.pr, self.files, self.commits, {'.': '2.4.0'},
                                  '2.4.0', '2.3.0', self.merge, self.head_commit, 'example/s5cmd', 0)

    def test_ci_head_tree_must_equal_accepted_merge_tree(self):
        self.head_commit['tree']['sha'] = 'f' * 40
        with self.assertRaises(ValueError):
            self.candidate()
        self.setUp()
        self.head_commit['sha'] = 'f' * 40
        with self.assertRaises(ValueError):
            self.candidate()

    def publication(self, mutate=None):
        proof = self.candidate()
        proof['run_id'] = 42
        proof['run_attempt'] = 1
        merged = copy.deepcopy(self.pr)
        merged.update(state='closed', merged=True, merge_commit_sha='e' * 40)
        commit = {'sha': 'e' * 40, 'tree': {'sha': 'd' * 40},
                  'parents': [{'sha': 'a' * 40}]}
        run = {'id': 42, 'run_attempt': 1, 'path': '.github/workflows/storage-gate.yml',
               'event': 'workflow_dispatch', 'head_branch': 'coreweave', 'status': 'completed',
               'conclusion': 'success', 'head_sha': 'a' * 40,
               'repository': {'full_name': 'example/s5cmd'}}
        checks = [{'name': name, 'conclusion': 'success', 'status': 'completed',
                   'app': {'slug': 'github-actions'}} for name in gate.CI_CHECKS]
        reviews = [{'user': {'id': 999, 'type': 'User', 'login': 'maintainer'}, 'state': 'APPROVED',
                    'author_association': 'COLLABORATOR', '_may_approve': True,
                    'commit_id': 'b' * 40, 'submitted_at': '2026-01-01T00:00:00Z'}]
        if mutate:
            mutate(proof, merged, commit, run, checks, reviews)
        return gate.verify_publication(proof, merged, commit, run, checks, reviews,
                                       'example/s5cmd', 123, copy.deepcopy(proof))

    def test_only_tested_approved_merge_is_publishable(self):
        self.assertEqual(self.publication()['tag'], 'coreweave-v2.4.0')

    def test_stale_tree_base_head_and_failed_skipped_missing_ci_block_publication(self):
        changes = [lambda p, pr, c, r, checks, reviews: c['tree'].update(sha='f' * 40),
                   lambda p, pr, c, r, checks, reviews: c['parents'][0].update(sha='f' * 40),
                   lambda p, pr, c, r, checks, reviews: pr['head'].update(sha='f' * 40),
                   lambda p, pr, c, r, checks, reviews: checks[0].update(conclusion='failure'),
                   lambda p, pr, c, r, checks, reviews: checks[0].update(conclusion='skipped'),
                   lambda p, pr, c, r, checks, reviews: checks.pop(),
                   lambda p, pr, c, r, checks, reviews: r.update(event='pull_request'),
                   lambda p, pr, c, r, checks, reviews: reviews.clear(),
                   lambda p, pr, c, r, checks, reviews: reviews[0].update(author_association='NONE'),
                   lambda p, pr, c, r, checks, reviews: reviews[0].update(_may_approve=False),
                   lambda p, pr, c, r, checks, reviews: reviews[0].update(commit_id='f' * 40)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.publication(change)

    def test_dismissed_approval_cannot_authorize_release(self):
        def dismiss(p, pr, c, r, checks, reviews):
            reviews.append({'user': {'id': 999, 'type': 'User'}, 'state': 'DISMISSED',
                            'commit_id': 'b' * 40, 'submitted_at': '2026-01-02T00:00:00Z'})
        with self.assertRaises(ValueError):
            self.publication(dismiss)

    def test_release_notes_do_not_include_older_releases(self):
        changelog = '# Changelog\n## [2.4.0](https://example.com)\nnew behavior\n## 2.3.0\nolder behavior\n'
        self.assertIn('new behavior', gate.release_notes(changelog, '2.4.0'))
        self.assertNotIn('older behavior', gate.release_notes(changelog, '2.4.0'))
        with self.assertRaises(ValueError):
            gate.release_notes(changelog, '9.0.0')

    def test_rerun_reserves_same_tag_and_refuses_collision(self):
        from unittest import mock
        import os
        api = mock.Mock()
        plan = dict(self.candidate(), commit='e' * 40)
        api.request.side_effect = [{'tree': {'sha': plan['tree']}},
                                   {'object': {'type': 'commit', 'sha': plan['commit']}}]
        api.pages.return_value = [{'id': 7, 'tag_name': plan['tag'], 'draft': True}]
        with mock.patch.dict(os.environ, {'RELEASE_PLAN': json.dumps(plan)}), mock.patch.object(gate, 'outputs'):
            gate.prepare_release(api)
        self.assertTrue(all(len(call.args) == 1 for call in api.request.call_args_list))
        api.request.side_effect = [{'tree': {'sha': plan['tree']}},
                                   {'object': {'type': 'commit', 'sha': 'f' * 40}}]
        with mock.patch.dict(os.environ, {'RELEASE_PLAN': json.dumps(plan)}), self.assertRaises(ValueError):
            gate.prepare_release(api)

    def test_draft_finalize_uses_id_without_published_tag_lookup(self):
        from unittest import mock
        import os
        plan = dict(self.candidate(), commit='e' * 40)
        api = mock.Mock()
        api.request.side_effect = [{'id': 7, 'tag_name': plan['tag'], 'draft': True},
                                   {'object': {'sha': plan['commit']}},
                                   {'object': {'sha': 'f' * 40}}, None, None, None]
        api.content.return_value = plan['version']
        with mock.patch.dict(os.environ, {'RELEASE_PLAN': json.dumps(plan), 'RELEASE_ID': '7'}):
            gate.finalize_release(api)
        paths = [call.args[0] for call in api.request.call_args_list]
        self.assertIn('/releases/7', paths)
        self.assertNotIn('/releases/tags/' + plan['tag'], paths)

    def test_public_release_rerun_does_not_rebuild(self):
        from unittest import mock
        import os
        api = mock.Mock()
        plan = dict(self.candidate(), commit='e' * 40)
        api.request.side_effect = [{'tree': {'sha': plan['tree']}},
                                   {'object': {'type': 'commit', 'sha': plan['commit']}}]
        api.pages.return_value = [{'id': 7, 'tag_name': plan['tag'], 'draft': False}]
        with mock.patch.dict(os.environ, {'RELEASE_PLAN': json.dumps(plan)}), mock.patch.object(gate, 'outputs') as output:
            gate.prepare_release(api)
        self.assertEqual(output.call_args.args[0]['build'], 'false')

    def test_partial_rerun_cannot_reuse_earlier_attempt(self):
        from unittest import mock
        import os
        proof = dict(self.candidate(), run_id=42, run_attempt=1)
        api = mock.Mock()
        environment = {'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '2', 'RELEASE_PROOF': json.dumps(proof),
                       'RELEASE_CHECK': '8', 'ACCEPTANCE_RESULT': 'success'}
        with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'candidate', return_value=self.candidate()):
            with self.assertRaises(ValueError):
                gate.evidence(api, 123)
            with self.assertRaises(ValueError):
                gate.finish(api, 123)
        self.assertEqual(api.request.call_args.args[2]['conclusion'], 'failure')

    def test_fork_of_release_head_cannot_override_required_check(self):
        from unittest import mock
        from pathlib import Path
        import os
        import tempfile
        release = copy.deepcopy(self.pr)
        self.pr['number'] = 8
        self.pr['user']['id'] = 456
        self.pr['head']['ref'] = 'ordinary'
        self.pr['head']['repo']['full_name'] = 'attacker/s5cmd'
        self.pr['labels'] = []
        api = mock.Mock(repository='example/s5cmd')
        api.request.return_value = self.pr
        api.pages.return_value = [release, self.pr]
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / 'event.json'
            event.write_text(json.dumps({'pull_request': {'number': 8}}))
            with mock.patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(event), 'GITHUB_RUN_ID': '42'}), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, 123)
        self.assertEqual(len(api.request.call_args_list), 1)
        output.assert_called_once_with({'live': 'false'})

    def test_fork_release_name_cannot_suppress_base_push_invalidation(self):
        from unittest import mock
        from pathlib import Path
        import os
        import tempfile
        fake = copy.deepcopy(self.pr)
        fake['number'] = 8
        fake['user']['id'] = 456
        fake['head']['repo']['full_name'] = 'attacker/s5cmd'
        api = mock.Mock(repository='example/s5cmd')
        api.pages.side_effect = [[fake, self.pr], [], []]
        api.request.side_effect = [{'object': {'sha': 'a' * 40}}, self.pr, {'id': 9, 'external_id': '42:1'}, None]
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / 'event.json'
            event.write_text('{}')
            environment = {'GITHUB_EVENT_PATH': str(event), 'GITHUB_REF': 'refs/heads/coreweave',
                           'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40,
                           'RELEASE_AUTOMATION_ENABLED': 'true'}
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'candidate', return_value=self.candidate()), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, 123)
        self.assertEqual(output.call_args.args[0]['live'], 'false')
        self.assertEqual(api.request.call_args.args[2]['conclusion'], 'failure')

    def test_review_author_requires_repository_write_access(self):
        from unittest import mock
        api = mock.Mock()
        api.request.side_effect = [{'permission': 'read'}, {'permission': 'write'}]
        reviews = [{'user': {'id': 1, 'type': 'User', 'login': 'reader'}},
                   {'user': {'id': 2, 'type': 'User', 'login': 'writer'}}]
        result = gate.eligible_reviews(api, reviews)
        self.assertFalse(result[0]['_may_approve'])
        self.assertTrue(result[1]['_may_approve'])

    def test_older_publication_does_not_move_latest_image(self):
        from unittest import mock
        import os
        plan = dict(self.candidate(), commit='e' * 40)
        api = mock.Mock(repository='example/s5cmd')
        api.request.return_value = {'object': {'sha': 'f' * 40}}
        for current, latest in [('2.4.0', True), ('2.5.0', False)]:
            api.content.return_value = current
            with mock.patch.dict(os.environ, {'RELEASE_PLAN': json.dumps(plan)}), mock.patch.object(gate, 'outputs') as output:
                gate.publication_tags(api)
            self.assertEqual(':latest' in output.call_args.args[0]['tags'], latest)

    def test_inspection_never_enters_storage_for_ordinary_or_spoofed_pr(self):
        from unittest import mock
        from pathlib import Path
        import os
        import tempfile
        api = mock.Mock()
        api.pages.return_value = []
        self.pr['user']['id'] = 456
        ordinary = copy.deepcopy(self.pr)
        ordinary['head']['ref'] = 'feature'
        ordinary['labels'] = []
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / 'event.json'
            event.write_text(json.dumps({'pull_request': {'number': 7}}))
            environment = {'GITHUB_EVENT_PATH': str(event), 'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '1', 'RELEASE_AUTOMATION_ENABLED': 'true'}
            api.request.side_effect = [ordinary, {'id': 8, 'external_id': '42:1'}, None]
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, 123)
            output.assert_called_once_with({'live': 'false'})
            api.request.side_effect = [self.pr, {'id': 8, 'external_id': '42:1'}, None]
            environment['RELEASE_AUTOMATION_ENABLED'] = 'false'
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'outputs') as output, self.assertRaises(ValueError):
                gate.inspect(api, 123)
            output.assert_not_called()
            self.assertEqual(api.request.call_args.args[2]['conclusion'], 'failure')

    def test_failed_suite_and_revision_change_cannot_record_success(self):
        from unittest import mock
        import os
        proof = dict(self.candidate(), run_id=42, run_attempt=1)
        for result, changed in [('failure', False), ('success', True)]:
            current = self.candidate()
            if changed:
                current['base'] = 'f' * 40
            api = mock.Mock()
            environment = {'RELEASE_PROOF': json.dumps(proof), 'RELEASE_CHECK': '8', 'ACCEPTANCE_RESULT': result,
                           'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '1'}
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'candidate', return_value=current), self.assertRaises(ValueError):
                gate.finish(api, 123)
            self.assertEqual(api.request.call_args.args[2]['conclusion'], 'failure')

    def test_error_output_does_not_echo_api_response(self):
        from unittest import mock
        import contextlib
        import io
        output = io.StringIO()
        with mock.patch.object(gate, 'execute', side_effect=ValueError('synthetic-private-value')), contextlib.redirect_stderr(output):
            self.assertEqual(gate.main(['inspect']), 1)
        self.assertEqual(output.getvalue(), 'release authorization failed\n')


if __name__ == '__main__':
    unittest.main()
