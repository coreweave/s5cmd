import contextlib
import base64
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import oidc_credentials as helper


class OIDCCredentialsTests(unittest.TestCase):
    def test_configured_subject_and_issuer_must_match_before_exchange(self):
        env = {'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://tokens.actions.githubusercontent.com/id',
               'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-request-token',
               'S5CMD_OIDC_SUBJECT': 'synthetic-approved-subject'}
        for field in (None, 'sub', 'aud', 'iss'):
            claims = {'sub': 'synthetic-approved-subject', 'aud': 'https://coreweave.com/iam',
                      'iss': 'https://token.actions.githubusercontent.com'}
            if field:
                claims[field] = 'synthetic-unapproved-value'
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
            token = 'synthetic-header.' + payload + '.synthetic-signature'
            class Opener:
                def open(self, request, timeout):
                    return io.BytesIO(json.dumps({'value': token}).encode())
            with patch.dict(os.environ, env, clear=True), patch.object(helper.urllib.request, 'build_opener', return_value=Opener()):
                if field:
                    with self.assertRaises(ValueError):
                        helper.oidc_token()
                else:
                    self.assertEqual(helper.oidc_token(), token)

    def test_failed_exchange_is_sanitized(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(helper, 'credentials', side_effect=RuntimeError('synthetic-private-jwt')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(helper.main([]), 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn('synthetic-private', stderr.getvalue())

    def test_token_is_requested_on_every_call(self):
        env = {'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://tokens.actions.githubusercontent.com/id?api-version=2',
               'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-request-token'}
        class Response(io.BytesIO):
            pass
        class Opener:
            def open(self, request, timeout):
                self_request.append(request)
                return Response(json.dumps({'value': 'synthetic-fresh-token'}).encode())
        self_request = []
        with patch.dict(os.environ, env, clear=True), patch.object(helper.urllib.request, 'build_opener', return_value=Opener()):
            self.assertEqual(helper.oidc_token(), 'synthetic-fresh-token')
            self.assertEqual(helper.oidc_token(), 'synthetic-fresh-token')
        self.assertEqual(len(self_request), 2)
        self.assertIn('audience=https%3A%2F%2Fcoreweave.com%2Fiam', self_request[0].full_url)

    def test_token_endpoint_rejects_unsafe_urls(self):
        for url in ['http://tokens.actions.githubusercontent.com/id', 'https://example.invalid/id',
                    'https://tokens.actions.githubusercontent.com@evil.invalid/id']:
            with self.subTest(url=url), patch.dict(os.environ, {'ACTIONS_ID_TOKEN_REQUEST_URL': url, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-token'}, clear=True):
                with self.assertRaises(ValueError):
                    helper.oidc_token()

    def test_token_failures_never_echo_response(self):
        with patch.object(helper, 'oidc_token', side_effect=RuntimeError('synthetic-private-jwt')):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(helper.main(['--token']), 1)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn('synthetic-private', stderr.getvalue())

    def test_cwic_receives_a_token_command_and_only_expiring_credentials_pass(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).isoformat()
        valid = {'Version': 1, 'AccessKeyId': 'synthetic-key', 'SecretAccessKey': 'synthetic-secret', 'Expiration': expiry}
        for invalid in [None, 'missing expiry', 'expired', 'bad version', 'oversized']:
            with self.subTest(case=invalid), tempfile.TemporaryDirectory() as directory:
                env = {'CWIC_API_URL': 'https://api.example.invalid', 'CWIC_CACHE_DIR': str(Path(directory) / 'cache'), 'S5CMD_TEST_ORG': 'synthetic-org'}
                data = dict(valid)
                if invalid == 'missing expiry':
                    del data['Expiration']
                elif invalid == 'expired':
                    data['Expiration'] = '2000-01-01T00:00:00Z'
                elif invalid == 'bad version':
                    data['Version'] = 2
                stdout = json.dumps(data).encode() if invalid != 'oversized' else b'x' * 8193
                result = subprocess.CompletedProcess([], 0, stdout=stdout)
                with patch.dict(os.environ, env, clear=True), patch.object(helper.subprocess, 'run', return_value=result) as call:
                    if invalid is None:
                        self.assertEqual(helper.credentials(), valid)
                        argv = call.call_args.args[0]
                        self.assertIn('--token', argv)
                        self.assertIn('oidc', argv)
                        self.assertEqual(call.call_args.kwargs['stderr'], subprocess.DEVNULL)
                    else:
                        with self.assertRaises((ValueError, KeyError)):
                            helper.credentials()


if __name__ == '__main__':
    unittest.main()
