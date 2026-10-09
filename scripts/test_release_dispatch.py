"""Release provenance and explicit dispatch regressions, without credentials."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_gate as gate


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.proof = {'pr': 7, 'branch': 'release-please--branches--coreweave', 'head': 'b' * 40, 'base': 'a' * 40,
                      'merge': 'c' * 40, 'tree': 'd' * 40,
                      'version': '2.4.0', 'tag': 'coreweave-v2.4.0',
                      'producer_run_id': 21, 'producer_attempt': 1}
        self.run = {'id': 21, 'run_attempt': 1, 'head_sha': 'a' * 40,
                    'head_branch': 'coreweave', 'event': 'push',
                    'path': '.github/workflows/release.yml',
                    'repository': {'full_name': 'example/s5cmd'}}
        self.jobs = [{'name': 'release-please', 'conclusion': 'success', 'steps': [
            {'name': name, 'conclusion': 'success'} for name in
            ('Update the release PR', 'Record the release candidate', 'Store candidate source hashes')]}]

    def test_producer_requires_exact_trusted_source_and_successful_steps(self):
        gate.verify_producer(self.proof, self.run, self.jobs, 'example/s5cmd')
        for field, value in [('head_sha', 'f' * 40), ('head_branch', 'feature'),
                             ('event', 'pull_request'), ('path', '.github/workflows/ci.yml'),
                             ('run_attempt', 2), ('id', 22)]:
            run = dict(self.run, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.verify_producer(self.proof, run, self.jobs, 'example/s5cmd')
        for conclusion in ('failure', 'skipped', None):
            jobs = copy.deepcopy(self.jobs)
            jobs[0]['steps'][0]['conclusion'] = conclusion
            with self.assertRaises(ValueError):
                gate.verify_producer(self.proof, self.run, jobs, 'example/s5cmd')

    def test_dispatch_checks_freshness_before_scheduling_both_workflows(self):
        api = mock.Mock()
        with mock.patch.object(gate, 'producer_evidence', return_value=self.proof), mock.patch.object(gate, 'candidate', return_value={k: v for k, v in self.proof.items() if not k.startswith('producer_')}), mock.patch.dict(os.environ, {'PRODUCER_RUN_ID': '21', 'PRODUCER_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}):
            gate.dispatch_validation(api, gate.GITHUB_ACTIONS_BOT_ID)
        self.assertEqual([call.args[0] for call in api.request.call_args_list],
                         ['/actions/workflows/ci.yml/dispatches', '/actions/workflows/storage-gate.yml/dispatches'])
        self.assertEqual(api.request.call_args_list[0].args[2]['inputs']['expected_head'], 'b' * 40)
        self.assertEqual(api.request.call_args_list[1].args[2]['ref'], 'coreweave')
        stale = dict(self.proof, head='f' * 40)
        api.reset_mock()
        with mock.patch.object(gate, 'producer_evidence', return_value=self.proof), mock.patch.object(gate, 'candidate', return_value=stale), mock.patch.dict(os.environ, {'PRODUCER_RUN_ID': '21', 'PRODUCER_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}), self.assertRaises(ValueError):
            gate.dispatch_validation(api, gate.GITHUB_ACTIONS_BOT_ID)
        api.request.assert_not_called()

    def test_ci_ref_race_is_rejected_before_builds(self):
        with mock.patch.dict(os.environ, {'EXPECTED_HEAD': 'b' * 40, 'GITHUB_SHA': 'f' * 40}), self.assertRaises(ValueError):
            gate.ci_preflight(mock.Mock(), gate.GITHUB_ACTIONS_BOT_ID)

    def test_empty_release_please_output_does_not_schedule_validation(self):
        with mock.patch.dict(os.environ, {'RELEASE_PLEASE_PRS': ''}), mock.patch.object(gate, 'outputs') as output:
            gate.capture_candidate(mock.Mock(), gate.GITHUB_ACTIONS_BOT_ID)
        output.assert_called_once_with({'candidate': 'false'})

    def test_old_publication_retry_does_not_refresh_the_current_release_pr(self):
        api = mock.Mock()
        api.request.return_value = {'object': {'sha': 'f' * 40}}
        with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/coreweave', 'GITHUB_SHA': 'a' * 40}), mock.patch.object(gate, 'outputs') as output, mock.patch('sys.stdout'):
            gate.release_tip(api)
        output.assert_called_once_with({'current': 'false'})
        api.request.assert_called_once_with('/git/ref/heads/coreweave')

    def test_captured_record_contains_only_verified_source_metadata(self):
        candidate = {k: v for k, v in self.proof.items() if not k.startswith('producer_')}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release-candidate.json'
            environment = {'RELEASE_PLEASE_PRS': json.dumps([{'number': 7}]),
                           'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '21', 'GITHUB_RUN_ATTEMPT': '1'}
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'prepared_candidate', return_value=candidate), mock.patch.object(gate, 'outputs'), mock.patch.object(gate, 'Path', return_value=path):
                gate.capture_candidate(mock.Mock(), gate.GITHUB_ACTIONS_BOT_ID)
            self.assertEqual(json.loads(path.read_text()), self.proof)

    def test_new_merge_ref_is_polled_without_retrying_invalid_candidates(self):
        api = mock.Mock()
        api.request.side_effect = [{'state': 'open', 'mergeable': None, 'merge_commit_sha': None},
                                   {'merge_commit_sha': 'c' * 40}]
        with mock.patch.object(gate.time, 'sleep') as sleep, mock.patch.object(gate, 'candidate', return_value=self.proof):
            self.assertEqual(gate.prepared_candidate(api, 7, gate.GITHUB_ACTIONS_BOT_ID), self.proof)
        sleep.assert_called_once_with(2)
        api.request.side_effect = None
        api.request.return_value = {'state': 'open', 'mergeable': False, 'merge_commit_sha': None}
        with self.assertRaises(ValueError):
            gate.prepared_candidate(api, 7, gate.GITHUB_ACTIONS_BOT_ID)

    def test_late_base_push_cannot_overwrite_gate_for_current_base(self):
        api = mock.Mock()
        api.pages.return_value = [{'name': gate.GATE, 'id': 7, 'app': {'slug': 'github-actions'},
                                   'external_id': '42:1'}]
        api.request.return_value = {'path': '.github/workflows/storage-gate.yml',
                                    'event': 'workflow_dispatch', 'head_sha': 'a' * 40, 'head_branch': 'coreweave'}
        with mock.patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
            self.assertTrue(gate.gate_uses_current_base(api, 'b' * 40))
        api.request.return_value['head_sha'] = 'f' * 40
        with mock.patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
            self.assertFalse(gate.gate_uses_current_base(api, 'b' * 40))

    def test_superseded_base_push_cannot_create_a_check_on_new_release_head(self):
        api = mock.Mock()
        api.request.return_value = {'object': {'sha': 'f' * 40}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            path.write_text('{}')
            with mock.patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(path), 'GITHUB_SHA': 'a' * 40,
                                               'GITHUB_REF': 'refs/heads/coreweave'}), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, gate.GITHUB_ACTIONS_BOT_ID)
        output.assert_called_once_with({'live': 'false'})
        api.pages.assert_not_called()
        api.request.assert_called_once_with('/git/ref/heads/coreweave')

    def test_storage_dispatch_needs_matching_producer_before_live_output(self):
        candidate = {key: value for key, value in self.proof.items() if not key.startswith('producer_')}
        pr = {'number': 7, 'head': {'sha': 'b' * 40, 'ref': self.proof['branch']},
              'user': {'id': gate.GITHUB_ACTIONS_BOT_ID}, 'labels': []}
        api = mock.Mock()
        api.pages.return_value = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            path.write_text(json.dumps({'inputs': {'pr': '7', 'producer_run_id': '21', 'producer_attempt': '1'}}))
            environment = {'GITHUB_EVENT_PATH': str(path), 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                           'GITHUB_REF': 'refs/heads/coreweave', 'GITHUB_SHA': 'a' * 40,
                           'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '1', 'RELEASE_AUTOMATION_ENABLED': 'true'}
            api.request.side_effect = [pr, {'id': 8, 'external_id': '42:1'}]
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'producer_evidence', return_value=dict(self.proof)), mock.patch.object(gate, 'candidate', return_value=candidate), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, gate.GITHUB_ACTIONS_BOT_ID)
            self.assertEqual(output.call_args.args[0]['live'], 'true')
            self.assertEqual(output.call_args.args[0]['proof']['producer_run_id'], 21)
            api.request.side_effect = [pr, {'id': 9, 'external_id': '42:1'}, None]
            with mock.patch.dict(os.environ, environment), mock.patch.object(gate, 'producer_evidence', return_value=dict(self.proof, head='f' * 40)), mock.patch.object(gate, 'candidate', return_value=candidate), mock.patch.object(gate, 'outputs') as output, self.assertRaises(ValueError):
                gate.inspect(api, gate.GITHUB_ACTIONS_BOT_ID)
            output.assert_not_called()
            self.assertEqual(api.request.call_args.args[2]['conclusion'], 'failure')

    def test_automatic_release_pr_event_cannot_replace_explicit_gate(self):
        api = mock.Mock()
        api.request.return_value = {'head': {'sha': 'b' * 40, 'ref': self.proof['branch']},
                                    'user': {'id': gate.GITHUB_ACTIONS_BOT_ID}, 'labels': []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            path.write_text(json.dumps({'pull_request': {'number': 7}}))
            with mock.patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(path), 'GITHUB_EVENT_NAME': 'pull_request_target'}), mock.patch.object(gate, 'outputs') as output:
                gate.inspect(api, gate.GITHUB_ACTIONS_BOT_ID)
        api.request.assert_called_once_with('/pulls/7')
        output.assert_called_once_with({'live': 'false'})

    def test_ci_check_names_cannot_substitute_for_a_trusted_complete_run(self):
        checks = [{'name': name, 'check_suite': {'id': 50}, 'app': {'slug': 'github-actions'},
                   'status': 'completed', 'conclusion': 'success'} for name in gate.CI_CHECKS]
        run = {'id': 60, 'run_attempt': 1, 'path': '.github/workflows/ci.yml',
               'event': 'workflow_dispatch', 'head_sha': 'b' * 40, 'status': 'completed',
               'conclusion': 'success', 'repository': {'full_name': 'example/s5cmd'}}
        jobs = [{'name': 'release-preflight', 'conclusion': 'success', 'steps': [
            {'name': 'Verify release candidate', 'conclusion': 'success'}]}]
        api = mock.Mock(repository='example/s5cmd')
        api.pages.side_effect = [[run], jobs]
        gate.ci_evidence(api, self.proof, checks)
        checks[0]['check_suite']['id'] = 99
        with self.assertRaises(ValueError):
            gate.ci_evidence(api, self.proof, checks)
        checks[0]['check_suite']['id'] = 50
        for change in ('head', 'path', 'step'):
            changed_run, changed_jobs = copy.deepcopy(run), copy.deepcopy(jobs)
            if change == 'head':
                changed_run['head_sha'] = 'f' * 40
            elif change == 'path':
                changed_run['path'] = '.github/workflows/other.yml'
            else:
                changed_jobs[0]['steps'][0]['conclusion'] = 'skipped'
            api.pages.side_effect = [[changed_run], changed_jobs]
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.ci_evidence(api, self.proof, checks)


if __name__ == '__main__':
    unittest.main()
