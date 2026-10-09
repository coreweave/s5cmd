import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run_storage_acceptance as runner


class RunnerTests(unittest.TestCase):
    def test_cancellation_uses_the_same_cleanup_window(self):
        process = mock.Mock(pid=123)
        handlers = {}
        def register(number, handler):
            previous = handlers.get(number)
            handlers[number] = handler
            return previous
        waits = 0
        def wait(timeout):
            nonlocal waits
            waits += 1
            if waits == 1:
                handlers[runner.signal.SIGTERM](runner.signal.SIGTERM, None)
            return 1
        process.wait.side_effect = wait
        with mock.patch.object(runner.subprocess, 'Popen', return_value=process), mock.patch.object(runner.signal, 'signal', side_effect=register), mock.patch.object(runner.os, 'killpg') as kill:
            self.assertFalse(runner.bounded(['test'], '.', 1))
        kill.assert_called_once_with(123, runner.signal.SIGTERM)
        self.assertEqual(process.wait.call_args.kwargs['timeout'], 240)
        self.assertEqual(handlers, {runner.signal.SIGINT: None, runner.signal.SIGTERM: None})

    def test_timeout_terminates_group_and_waits_for_cleanup(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired('test', 1), 1]
        with mock.patch.object(runner.subprocess, 'Popen', return_value=process), mock.patch.object(runner.os, 'killpg') as kill:
            self.assertFalse(runner.bounded(['test'], '.', 1))
        kill.assert_called_once_with(123, runner.signal.SIGTERM)
        self.assertEqual(process.wait.call_args.kwargs['timeout'], 240)

    def test_process_output_is_never_forwarded_to_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertFalse(runner.bounded(['python3', '-c', 'import sys; print("synthetic-private-value"); sys.exit(1)'], directory, 5))
            self.assertEqual(output.getvalue(), '')

    def test_private_profile_references_trusted_helper_only(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'RUNNER_TEMP': directory}, clear=True):
            root = runner.configure(Path(directory) / 'control')
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'config').stat().st_mode & 0o777, 0o600)
            self.assertIn('control/scripts/oidc_credentials.py', (root / 'config').read_text())
            self.assertEqual((root / 'credentials').read_text(), '')

    def test_existing_private_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'RUNNER_TEMP': directory}, clear=True):
            runner.configure(Path(directory) / 'control')
            with self.assertRaises(FileExistsError):
                runner.configure(Path(directory) / 'control')

    def test_fixed_error_does_not_expose_configuration(self):
        output = io.StringIO()
        with mock.patch.object(runner, 'execute', side_effect=ValueError('synthetic-private-value')), contextlib.redirect_stderr(output):
            self.assertEqual(runner.main(['test']), 1)
        self.assertEqual(output.getvalue(), 'storage acceptance operation failed\n')


if __name__ == '__main__':
    unittest.main()
