#!/usr/bin/env python3
"""Renewable AWS credential_process for a protected GitHub Actions job."""

import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('OIDC redirects are forbidden')


def oidc_token():
    url = urllib.parse.urlsplit(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'])
    if (url.scheme != 'https' or url.username or url.password or url.fragment
            or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com')
            or url.port not in (None, 443)):
        raise ValueError('invalid GitHub OIDC endpoint')
    query = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != 'audience']
    query.append(('audience', 'https://coreweave.com/iam'))
    target = urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(target, headers={
        'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        data = response.read(64 * 1024 + 1)
    if len(data) > 64 * 1024:
        raise ValueError('oversized OIDC response')
    token = json.loads(data)['value']
    if not isinstance(token, str) or not token.strip():
        raise ValueError('empty OIDC token')
    return token


def credentials():
    # Require explicit configuration; a wrong deployment must fail closed.
    for key in ['CWIC_API_URL', 'CWIC_CACHE_DIR', 'S5CMD_TEST_ORG']:
        if not os.environ.get(key):
            raise ValueError('missing credential configuration')
    endpoint = urllib.parse.urlsplit(os.environ['CWIC_API_URL'])
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('invalid API endpoint')
    cache = Path(os.environ['CWIC_CACHE_DIR'])
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    if cache.is_symlink() or (cache.stat().st_mode & 0o077):
        raise ValueError('credential cache must be private')
    # CWIC caches storage credentials, then invokes --token again when they
    # approach expiry. Each invocation obtains a fresh GitHub OIDC token.
    cmd = ['cwic', 'auth', 'accesskey', 'oidc', '--storage', 'disk',
           '--org-id', os.environ['S5CMD_TEST_ORG'], '--',
           sys.executable, str(Path(__file__).resolve()), '--token']
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=50, check=True)
    if len(result.stdout) > 8192:
        raise ValueError('oversized credential response')
    data = json.loads(result.stdout)
    if data.get('Version') != 1 or not data.get('AccessKeyId') or not data.get('SecretAccessKey'):
        raise ValueError('invalid credential response')
    expiration = datetime.datetime.fromisoformat(data['Expiration'].replace('Z', '+00:00'))
    if expiration <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('expired credential response')
    return data


def main(args):
    # Restrict all files created by the helper and CWIC in this process tree.
    os.umask(0o077)
    try:
        if args == ['--token']:
            value = {'apiVersion': 'client.authentication.k8s.io/v1', 'kind': 'ExecCredential',
                     'status': {'token': oidc_token()}}
        elif not args:
            value = credentials()
        else:
            raise ValueError('unsupported arguments')
        sys.stdout.write(json.dumps(value) + '\n')
        return 0
    except Exception:
        # Never print URL, HTTP body, JWT, CWIC output, or provider exceptions.
        sys.stderr.write('temporary credential exchange failed\n')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
