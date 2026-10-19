"""Fake-backend and ctypes layout tests; never open/terminate a real process."""
import ctypes as c
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

import windows_process_job as job


class FakeAPI:
    def __init__(self, failure=None, elevated=False):
        self.calls, self.failure, self.elevated = [], failure, elevated

    def call(self, name, *args):
        self.calls.append((name,) + args)
        if self.failure == name:
            raise OSError('synthetic ' + name)

    def is_elevated(self):
        self.call('elevation')
        return self.elevated

    def create_job(self):
        self.call('create')
        return 0x123456789

    def configure_job(self, handle):
        self.call('configure', handle)

    def open_process(self, pid):
        self.call('open', pid)
        return 0x987654321

    def assign(self, handle, process):
        self.call('assign', handle, process)

    def get_exit_code(self, process):
        self.call('exit_code', process)
        return job.STILL_ACTIVE

    def close_handle(self, handle):
        self.call('close', handle)


class JobTests(unittest.TestCase):
    def test_lifetime_order_idempotence_and_single_assignment(self):
        api = FakeAPI()
        with job.WindowsProcessJob(api) as guard:
            self.assertIsNone(guard.exit_code())
            guard.assign(123)
            self.assertEqual(guard.exit_code(), 259)
            with self.assertRaises(RuntimeError):
                guard.assign(124)
        guard.close()
        self.assertIsNone(guard.exit_code())
        self.assertEqual(api.calls, [('elevation',), ('create',), ('configure', 0x123456789),
            ('open', 123), ('assign', 0x123456789, 0x987654321), ('exit_code', 0x987654321),
            ('close', 0x123456789), ('close', 0x987654321)])

    def test_elevation_fail_closed_before_job_creation(self):
        for elevated in (True, None, 0):
            api = FakeAPI(elevated=elevated)
            with self.assertRaises(PermissionError):
                job.WindowsProcessJob(api)
            self.assertEqual(api.calls, [('elevation',)])
        with self.assertRaises(OSError):
            job.WindowsProcessJob(FakeAPI(failure='elevation'))

    def test_constructor_failure_cleanup(self):
        for failure, expected in [('create', []), ('configure', [('close', 0x123456789)])]:
            api = FakeAPI(failure=failure)
            with self.assertRaises(OSError):
                job.WindowsProcessJob(api)
            self.assertEqual([x for x in api.calls if x[0] == 'close'], expected)

    def test_assignment_failure_closes_handles(self):
        for failure, expected in [('open', [0x123456789]), ('assign', [0x123456789, 0x987654321])]:
            api = FakeAPI(failure=failure)
            guard = job.WindowsProcessJob(api)
            with self.assertRaises(OSError):
                guard.assign(123)
            self.assertEqual([x[1] for x in api.calls if x[0] == 'close'], expected)
            self.assertIsNone(guard.exit_code())
            with self.assertRaises(RuntimeError):
                guard.assign(123)

    def test_invalid_pid_and_closed_guard(self):
        api = FakeAPI()
        guard = job.WindowsProcessJob(api)
        for pid in (True, 0, -1, 2**32, '123'):
            with self.assertRaises(ValueError):
                guard.assign(pid)
        self.assertFalse(any(x[0] == 'open' for x in api.calls))
        guard.close()
        with self.assertRaises(RuntimeError):
            guard.assign(123)
        with self.assertRaises(RuntimeError):
            guard.__enter__()

    def test_close_failure_attempts_both_and_can_retry(self):
        api = FakeAPI()
        guard = job.WindowsProcessJob(api)
        guard.assign(123)
        api.failure = 'close'
        with self.assertRaises(OSError):
            guard.close()
        self.assertEqual([x[1] for x in api.calls if x[0] == 'close'], [0x123456789, 0x987654321])
        api.failure = None
        guard.close()
        count = len(api.calls)
        guard.close()
        self.assertEqual(len(api.calls), count)

    def test_concurrent_close_and_query_are_serialized(self):
        api = FakeAPI()
        guard = job.WindowsProcessJob(api)
        guard.assign(123)
        errors = []
        def action():
            try:
                guard.exit_code()
                guard.close()
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=action) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len([x for x in api.calls if x[0] == 'close']), 2)
        first_close = next(i for i, x in enumerate(api.calls) if x[0] == 'close')
        self.assertFalse(any(x[0] == 'exit_code' for x in api.calls[first_close:]))

    def test_native_backend_refuses_nonwindows(self):
        with patch.object(job.os, 'name', 'posix'), self.assertRaises(RuntimeError):
            job.WindowsAPI()

    def test_windows_fixed_width_layout_and_flags(self):
        self.assertEqual(c.sizeof(job.DWORD), 4)
        self.assertEqual(c.sizeof(job.BOOL), 4)
        self.assertEqual(c.sizeof(job.TokenElevation), 4)
        self.assertEqual(job.BasicLimitInformation.LimitFlags.offset, 16)
        if c.sizeof(c.c_void_p) == 8:
            self.assertEqual(c.sizeof(job.BasicLimitInformation), 64)
            self.assertEqual(c.sizeof(job.ExtendedLimitInformation), 144)
        api = job.WindowsAPI.__new__(job.WindowsAPI)
        captured = []
        def configure(handle, kind, pointer, size):
            info = c.cast(pointer, c.POINTER(job.ExtendedLimitInformation)).contents
            captured.append((handle, kind, size, info.BasicLimitInformation.LimitFlags))
            return 1
        api.kernel = SimpleNamespace(SetInformationJobObject=configure)
        api.configure_job(7)
        self.assertEqual(captured, [(7, 9, c.sizeof(job.ExtendedLimitInformation), 0x2000)])
        self.assertEqual(job.PROCESS_ACCESS, 0x1101)

    def test_native_token_query_uses_elevation_class_and_closes(self):
        for flag in (0, 1):
            calls = []
            def open_token(process, access, output):
                calls.append(('open_token', process, access))
                output._obj.value = 77
                return 1
            def query(token, kind, output, size, returned):
                calls.append(('query', token.value, kind, size))
                c.cast(output, c.POINTER(job.TokenElevation)).contents.TokenIsElevated = flag
                returned._obj.value = 4
                return 1
            api = job.WindowsAPI.__new__(job.WindowsAPI)
            api.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1,
                CloseHandle=lambda h: calls.append(('close', h)) or 1)
            api.security = SimpleNamespace(OpenProcessToken=open_token, GetTokenInformation=query)
            self.assertEqual(api.is_elevated(), bool(flag))
            self.assertEqual(calls, [('open_token', -1, 8), ('query', 77, 20, 4), ('close', 77)])

    def test_native_token_query_failure_and_wrong_size_close_token(self):
        for failure in ('query', 'size'):
            closed = []
            def open_token(process, access, output):
                output._obj.value = 77
                return 1
            def query(token, kind, output, size, returned):
                if failure == 'query':
                    raise OSError('synthetic query error')
                returned._obj.value = 0
                return 1
            api = job.WindowsAPI.__new__(job.WindowsAPI)
            api.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1,
                CloseHandle=lambda h: closed.append(h) or 1)
            api.security = SimpleNamespace(OpenProcessToken=open_token, GetTokenInformation=query)
            with self.assertRaises((OSError, RuntimeError)):
                api.is_elevated()
            self.assertEqual(closed, [77])

    def test_native_open_access_and_unsigned_exit_code(self):
        calls = []
        def open_process(access, inherit, pid):
            calls.append((access, inherit, pid))
            return 12345
        def exit_code(handle, output):
            output._obj.value = 0xffffffff
            return 1
        api = job.WindowsAPI.__new__(job.WindowsAPI)
        api.kernel = SimpleNamespace(OpenProcess=open_process, GetExitCodeProcess=exit_code)
        self.assertEqual(api.open_process(789), 12345)
        self.assertEqual(calls, [(0x1101, False, 789)])
        self.assertEqual(api.get_exit_code(12345), 0xffffffff)


if __name__ == '__main__':
    unittest.main()
