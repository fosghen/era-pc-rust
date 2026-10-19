import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_capture import JsonlRecorder, capture, failure_record, validate_options


class FakeJob:
    def __init__(self, fail_assign=False):
        self.assigned = None
        self.closed = False
        self.fail_assign = fail_assign

    def assign(self, pid):
        if self.fail_assign:
            raise RuntimeError('assignment failed')
        self.assigned = pid

    def close(self):
        self.closed = True

    def exit_code(self):
        return 0


class FakeDevice:
    def __init__(self, coverage=True, fail_attach=False, agent_error=False):
        self.coverage = coverage
        self.fail_attach = fail_attach
        self.agent_error = agent_error
        self.resumed = False
        self.killed = []
        self.callbacks = {}

    def on(self, name, callback):
        self.callbacks[name] = callback

    def off(self, name, callback):
        del self.callbacks[name]

    def spawn(self, argv, **kwargs):
        self.spawn_args = (argv, kwargs)
        return 4242

    def attach(self, pid):
        if self.fail_attach:
            raise RuntimeError('attach failed')
        return self

    def create_script(self, text):
        self.script_source = text
        return self

    def load(self):
        if self.agent_error:
            self.callbacks['message']({'type': 'error', 'description': 'synthetic error'}, None)
        else:
            self.callbacks['message']({'type': 'send', 'payload': dict(type='ready',
                platform='windows', arch='ia32', coveredApis=['WaitForMultipleObjects',
                'CreateFileW', 'DeviceIoControl'] if self.coverage else [])}, None)
        self.callbacks['message']({'type': 'send', 'payload': {'type': 'unsafe', 'secret': 'binary'}}, b'not saved')

    def resume(self, pid):
        self.resumed = True
        self.callbacks['output'](pid, 1, b'private target output')
        self.callbacks['detached']('process-terminated', None)

    def kill(self, pid):
        self.killed.append(pid)

    def detach(self):
        pass


class NativeCaptureTests(unittest.TestCase):
    def execute(self, device, job):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'own-fixture.bin'
            target.write_bytes(b'own fixture, never executed')
            path = Path(directory) / 'capture.jsonl'
            recorder = JsonlRecorder(path, 140)
            try:
                result = capture(target, device=device, job=job, observer_source='// own test',
                                 recorder=recorder, seconds=0.01, max_events=10, ready_timeout=0.01)
            finally:
                recorder.close()
            records = [json.loads(line) for line in path.read_text().splitlines()]
            return result, records

    def test_capture_observes_only_owned_spawn_and_cleans_job(self):
        device, job = FakeDevice(), FakeJob()
        result, records = self.execute(device, job)
        self.assertTrue(device.resumed)
        self.assertEqual(job.assigned, 4242)
        self.assertTrue(job.closed)
        self.assertEqual(device.killed, [])
        self.assertEqual(result['reason'], 'detached')
        self.assertEqual(result['native_exit_code'], 0)
        self.assertTrue(result['input_unchanged'])
        self.assertEqual(result['stdout_bytes'], len(b'private target output'))
        encoded = json.dumps(records)
        self.assertNotIn('private target output', encoded)
        self.assertNotIn('"secret"', encoded)
        self.assertEqual(records[-1]['type'], 'summary')

    def test_missing_coverage_or_agent_error_never_resumes(self):
        for device in (FakeDevice(coverage=False), FakeDevice(agent_error=True)):
            job = FakeJob()
            result, records = self.execute(device, job)
            self.assertFalse(device.resumed)
            self.assertTrue(job.closed)
            self.assertEqual(result['reason'], 'capture_error')

    def test_attach_failure_closes_assigned_job(self):
        device, job = FakeDevice(fail_attach=True), FakeJob()
        result, _ = self.execute(device, job)
        self.assertTrue(job.closed)
        self.assertFalse(device.resumed)
        self.assertEqual(device.killed, [])
        self.assertEqual(result['reason'], 'capture_error')

    def test_assignment_failure_kills_only_owned_suspended_pid(self):
        device, job = FakeDevice(), FakeJob(fail_assign=True)
        result, _ = self.execute(device, job)
        self.assertEqual(device.killed, [4242])
        self.assertFalse(device.resumed)
        self.assertTrue(result['unassigned_spawn_terminated'])

    def test_budgets(self):
        for seconds in (True, 0, -1, 61, float('nan'), float('inf')):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                validate_options(seconds, 10)
        for count in (True, 0, 1, 100001, 10.5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                validate_options(10, count)

    def test_watchdog_cleanup_failure_signals_and_finally_retries(self):
        job = FakeJob()
        attempts = []

        def close():
            attempts.append(True)
            if len(attempts) == 1:
                raise OSError('synthetic close failure')
            job.closed = True

        class ImmediateTimer:
            def __init__(self, delay, callback):
                self.callback = callback

            def start(self):
                self.callback()

            def cancel(self):
                pass

        job.close = close
        device = FakeDevice()
        with patch('native_capture.threading.Timer', ImmediateTimer):
            result, _ = self.execute(device, job)
        self.assertTrue(result['watchdog_fired'])
        self.assertEqual(result['watchdog_cleanup_error'], 'OSError')
        self.assertFalse(device.resumed)
        self.assertTrue(result['job_closed'])
        self.assertEqual(len(attempts), 2)

    def test_error_provenance_distinguishes_unknown_from_not_resumed(self):
        error = RuntimeError('cleanup failed')
        self.assertIs(failure_record(error, False, None)['target_resumed'], False)
        self.assertIsNone(failure_record(error, True, None)['target_resumed'])
        record = failure_record(error, True, {'resumed': True})
        self.assertEqual(record['type'], 'runner_error')
        self.assertIs(record['target_resumed'], True)

    def test_exclusive_bounded_jsonl_with_final_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.jsonl'
            recorder = JsonlRecorder(path, 1)
            try:
                with self.assertRaises(FileExistsError):
                    JsonlRecorder(path, 1)
                self.assertFalse(recorder.write({'huge': 'x' * 32769}))
                self.assertTrue(recorder.write({'type': 'header'}))
                self.assertFalse(recorder.write({'type': 'extra'}))
                self.assertTrue(recorder.write({'type': 'summary'}, final=True))
                self.assertEqual(recorder.dropped, 2)
            finally:
                recorder.close()
            self.assertEqual(len(path.read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
