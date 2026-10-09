#!/usr/bin/env python3
"""Trusted job control: bounded execution, private profiles, silent diagnostics."""

import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys

import release_gate as gate


def bounded(command, directory, timeout):
    environment = dict(os.environ)
    environment.pop('GH_TOKEN', None)
    process = subprocess.Popen(command, cwd=directory, env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    def cancelled(signum, frame):
        raise subprocess.TimeoutExpired('cancelled storage operation', timeout)
    handlers = {number: signal.signal(number, cancelled) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        return process.wait(timeout=timeout) == 0
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=240)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        return False
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


def private_root():
    return Path(os.environ['RUNNER_TEMP']) / 's5cmd-acceptance'


def configure(control):
    os.umask(0o077)
    root = private_root()
    root.mkdir(mode=0o700)
    (root / 'cache').mkdir(mode=0o700)
    helper = shlex.quote(str(control.resolve() / 'scripts' / 'oidc_credentials.py'))
    (root / 'config').write_text('[profile acceptance]\ncredential_process = python3 ' + helper + '\n')
    (root / 'credentials').write_text('')
    return root


def fresh_candidate(proof):
    current = gate.candidate(gate.GitHub(), proof['pr'], gate.GITHUB_ACTIONS_BOT_ID)
    gate.require(all(current[key] == proof[key] for key in current))


def verify_checkout(directory, proof):
    for option, expected in [('HEAD', proof['merge']), ('HEAD^{tree}', proof['tree'])]:
        result = subprocess.run(['git', '-C', str(directory), 'rev-parse', option],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=10)
        gate.require(result.stdout.decode().strip() == expected)


def execute(args):
    gate.require(len(args) == 1)
    control = Path(__file__).resolve().parent.parent
    candidate = Path(os.environ['GITHUB_WORKSPACE']) / 'candidate'
    proof = json.loads(os.environ['RELEASE_PROOF'])
    root = private_root()
    if args[0] == 'prepare':
        fresh_candidate(proof)
        gate.require(all(os.environ.get(key) for key in ('CWIC_API_URL', 'S5CMD_TEST_ORG',
                                                       'S5CMD_TEST_ENDPOINT_URL', 'S5CMD_REGION', 'S5CMD_OIDC_SUBJECT')))
        gate.require(not any(os.environ.get(key) for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                                                             'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'AWS_SESSION_TOKEN',
                                                             'S5CMD_ACCESS_KEY_ID', 'S5CMD_SECRET_ACCESS_KEY')))
        gate.require(os.environ.get('RUNNER_DEBUG') != '1')
        configure(control)
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as stream:
            for key, value in {'CWIC_CACHE_DIR': root / 'cache', 'AWS_CONFIG_FILE': root / 'config',
                               'AWS_SHARED_CREDENTIALS_FILE': root / 'credentials',
                               'S5CMD_TEST_RESOURCE_FILE': root / 'resource'}.items():
                gate.require('\n' not in str(value))
                stream.write(f'{key}={value}\n')
    elif args[0] == 'test':
        verify_checkout(candidate, proof)
        fresh_candidate(proof)
        gate.require(bounded(['make', 'acceptance'], candidate, 17 * 60))
        print('Live storage suite and scoped cleanup passed for tree ' + gate.sha(proof['tree']))
    elif args[0] == 'cleanup':
        if not root.exists():
            return
        succeeded = False
        try:
            if (root / 'resource').exists():
                verify_checkout(candidate, proof)
                gate.require(bounded(['go', 'test', '-mod=readonly', './e2e', '-run',
                                      '^TestAcceptanceRecovery$', '-count=1', '-timeout=4m'], candidate, 4 * 60))
                gate.require(not (root / 'resource').exists())
            succeeded = True
        finally:
            for name in ('cache', 'config', 'credentials'):
                path = root / name
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            if succeeded:
                root.rmdir()
    else:
        raise ValueError('unsupported operation')


def main(args):
    try:
        execute(args)
        return 0
    except Exception:
        sys.stderr.write('storage acceptance operation failed\n')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
