"""Lifetime guard for a caller-owned, already spawned Windows process.

This is NOT a sandbox/security boundary: it does not isolate files, devices,
registry or networking, and does not cover children created through external
brokers such as WMI. No process is created or discovered here. The caller must
pass only its own spawned PID, assign before resuming it, and always close the
job. An assignment failure cannot terminate an as-yet-unassigned process; the
caller remains responsible for its suspended child in that case.

Microsoft contracts:
https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
"""
import ctypes as c
import os
import threading


DWORD = c.c_uint32
BOOL = c.c_int32
HANDLE = c.c_void_p
SIZE_T = c.c_size_t
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION = 20
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
PROCESS_ACCESS = 0x0100 | 0x0001 | 0x1000  # SET_QUOTA | TERMINATE | QUERY_LIMITED_INFORMATION
STILL_ACTIVE = 259


class BasicLimitInformation(c.Structure):
    _fields_ = [('PerProcessUserTimeLimit', c.c_int64), ('PerJobUserTimeLimit', c.c_int64),
                ('LimitFlags', DWORD), ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', DWORD),
                ('Affinity', SIZE_T), ('PriorityClass', DWORD), ('SchedulingClass', DWORD)]


class IOCounters(c.Structure):
    _fields_ = [(name, c.c_uint64) for name in ('ReadOperationCount', 'WriteOperationCount',
                'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class ExtendedLimitInformation(c.Structure):
    _fields_ = [('BasicLimitInformation', BasicLimitInformation), ('IoInfo', IOCounters),
                ('ProcessMemoryLimit', SIZE_T), ('JobMemoryLimit', SIZE_T),
                ('PeakProcessMemoryUsed', SIZE_T), ('PeakJobMemoryUsed', SIZE_T)]


class TokenElevation(c.Structure):
    _fields_ = [('TokenIsElevated', DWORD)]


class WindowsAPI:
    """ctypes backend; deliberately unavailable on non-Windows hosts."""
    def __init__(self):
        if os.name != 'nt':
            raise RuntimeError('WindowsProcessJob requires Windows, not WSL/Linux elevation')
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.security = c.WinDLL('advapi32', use_last_error=True)
        signatures = (
            (self.kernel, 'GetCurrentProcess', [], HANDLE),
            (self.security, 'OpenProcessToken', [HANDLE, DWORD, c.POINTER(HANDLE)], BOOL),
            (self.security, 'GetTokenInformation',
             [HANDLE, c.c_int32, c.c_void_p, DWORD, c.POINTER(DWORD)], BOOL),
            (self.kernel, 'CreateJobObjectW', [c.c_void_p, c.c_wchar_p], HANDLE),
            (self.kernel, 'SetInformationJobObject', [HANDLE, c.c_int32, c.c_void_p, DWORD], BOOL),
            (self.kernel, 'OpenProcess', [DWORD, BOOL, DWORD], HANDLE),
            (self.kernel, 'AssignProcessToJobObject', [HANDLE, HANDLE], BOOL),
            (self.kernel, 'GetExitCodeProcess', [HANDLE, c.POINTER(DWORD)], BOOL),
            (self.kernel, 'CloseHandle', [HANDLE], BOOL),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def _require(result, operation):
        if not result:
            error = c.get_last_error()
            raise OSError(error, operation + ' failed (Win32 error ' + str(error) + ')')
        return result

    def is_elevated(self):
        token = HANDLE()
        self._require(self.security.OpenProcessToken(self.kernel.GetCurrentProcess(),
                      TOKEN_QUERY, c.byref(token)), 'OpenProcessToken')
        try:
            if not token.value:
                raise RuntimeError('OpenProcessToken returned a null token')
            elevation, returned = TokenElevation(), DWORD()
            self._require(self.security.GetTokenInformation(token, TOKEN_ELEVATION,
                          c.byref(elevation), c.sizeof(elevation), c.byref(returned)),
                          'GetTokenInformation(TokenElevation)')
            if returned.value != c.sizeof(elevation):
                raise RuntimeError('Unexpected TokenElevation result size')
            return elevation.TokenIsElevated != 0
        finally:
            if token.value:
                self.close_handle(token.value)

    def create_job(self):
        return self._require(self.kernel.CreateJobObjectW(None, None), 'CreateJobObjectW')

    def configure_job(self, job):
        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self._require(self.kernel.SetInformationJobObject(job,
                      JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, c.byref(information),
                      c.sizeof(information)), 'SetInformationJobObject')

    def open_process(self, pid):
        return self._require(self.kernel.OpenProcess(PROCESS_ACCESS, False, pid), 'OpenProcess')

    def assign(self, job, process):
        self._require(self.kernel.AssignProcessToJobObject(job, process), 'AssignProcessToJobObject')

    def get_exit_code(self, process):
        result = DWORD()
        self._require(self.kernel.GetExitCodeProcess(process, c.byref(result)), 'GetExitCodeProcess')
        return result.value

    def close_handle(self, handle):
        self._require(self.kernel.CloseHandle(handle), 'CloseHandle')


class WindowsProcessJob:
    """One caller-owned PID, non-elevated token, serialized lifetime operations.

    exit_code() returns a DWORD (259 may mean STILL_ACTIVE), or None before
    assignment/after close. close() closes the job first, then the retained process
    handle, without waiting for termination. Successful repeated close is a no-op.
    Failed CloseHandle operations raise and retain that handle for a retry; the
    object remains closed to assignment/query. `api` is for own synthetic tests.
    """
    def __init__(self, api=None):
        self._lock = threading.RLock()
        self._api = WindowsAPI() if api is None else api
        self._job = self._process = None
        self._closed = False
        self._assigned = False
        elevated = self._api.is_elevated()
        if elevated is not False:
            raise PermissionError('Refusing an elevated or unverified Windows process token')
        try:
            self._job = self._api.create_job()
            if not self._job:
                self._job = None
                raise RuntimeError('Backend returned a null job handle')
            self._api.configure_job(self._job)
        except BaseException:
            self.close()
            raise

    def assign(self, pid):
        if type(pid) is not int or not 0 < pid <= 0xffffffff:
            raise ValueError('PID must be a nonzero DWORD for the caller-owned spawned process')
        with self._lock:
            if self._closed or self._assigned:
                raise RuntimeError('Job is closed or already assigned')
            try:
                self._process = self._api.open_process(pid)
                if not self._process:
                    self._process = None
                    raise RuntimeError('Backend returned a null process handle')
                self._api.assign(self._job, self._process)
                self._assigned = True
            except BaseException:
                self.close()
                raise

    def exit_code(self):
        with self._lock:
            if self._closed or not self._assigned:
                return None
            return self._api.get_exit_code(self._process)

    def close(self):
        with self._lock:
            self._closed = True
            failures = []
            for attribute in ('_job', '_process'):
                handle = getattr(self, attribute)
                if handle is not None:
                    try:
                        self._api.close_handle(handle)
                    except Exception as error:
                        failures.append(error)
                    else:
                        setattr(self, attribute, None)
            if failures:
                raise failures[0]

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise RuntimeError('Job already closed')
            return self

    def __exit__(self, kind, value, traceback):
        self.close()
        return False
