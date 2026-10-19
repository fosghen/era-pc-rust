"""Bounded native Windows observation; NOT an emulator or security sandbox.

Only launches the explicitly selected executable. No attach-to-existing-PID,
license patches, device payload dumps, driver installation or elevated runs.
Job cleanup is process lifetime management, not file/network isolation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time


REQUIRED_APIS = {'WaitForMultipleObjects', 'CreateFileW', 'DeviceIoControl'}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_options(seconds, max_events):
    if type(seconds) not in (int, float) or not 0 < seconds <= 60:
        raise ValueError('Native execution duration must be positive and <=60 seconds')
    if type(max_events) is not int or not 2 <= max_events <= 100000:
        raise ValueError('Native observation budget must be 2..100000 integer API events')


class JsonlRecorder:
    """Exclusive-create bounded metadata stream; never writes binary messages."""
    def __init__(self, path, limit):
        self.stream = Path(path).open('x', encoding='utf-8')
        self.lock = threading.RLock()
        self.limit = limit
        self.count = 0
        self.dropped = 0

    def write(self, item, *, final=False):
        encoded = json.dumps(item, ensure_ascii=True, allow_nan=False)
        with self.lock:
            if self.stream.closed or len(encoded) > 32768 or (self.count >= self.limit and not final):
                self.dropped += 1
                return False
            self.stream.write(encoded + '\n')
            self.stream.flush()
            self.count += 1
            return True

    def close(self):
        with self.lock:
            self.stream.close()


def capture(executable, *, device, job, observer_source, recorder, seconds=10, max_events=10000,
            ready_timeout=5):
    """Job must have checked a non-elevated token before this function is called."""
    validate_options(seconds, max_events)
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file():
        raise ValueError('Target must be one explicit file')
    initial_hash = sha256(executable)
    ready = threading.Event()
    detached = threading.Event()
    data_lock = threading.RLock()
    status = dict(resumed=False, ready=False, reason='setup', pid=None, stdout_bytes=0,
                  stderr_bytes=0, instrumentation_errors=0, detached_reason=None,
                  native_exit_code=None, job_closed=False, watchdog_fired=False)
    session = None
    script = None
    assigned = False
    watchdog = None
    started = time.monotonic()

    def on_message(message, binary):
        # Binary payloads and target output are intentionally never saved.
        if message.get('type') == 'send' and binary is None and isinstance(message.get('payload'), dict):
            payload = message['payload']
            recorder.write(dict(type='agent', payload=payload))
            if payload.get('type') == 'ready':
                covered = payload.get('coveredApis', [])
                with data_lock:
                    status['ready'] = (payload.get('platform') == 'windows'
                        and payload.get('arch') in ('ia32', 'x64')
                        and isinstance(covered, list) and all(isinstance(v, str) for v in covered)
                        and REQUIRED_APIS.issubset(covered))
                    status['agent_arch'] = payload.get('arch')
                ready.set()
        elif message.get('type') == 'error':
            with data_lock:
                status['instrumentation_errors'] += 1
            recorder.write(dict(type='agent_error', description=str(message.get('description', ''))[:512]))
            ready.set()

    def on_detached(reason, crash=None):
        with data_lock:
            status['detached_reason'] = str(reason)[:128]
            status['crash_report_present'] = crash is not None
        detached.set()

    def on_output(pid, fd, chunk):
        if pid == status['pid'] and fd in (1, 2):
            with data_lock:
                status['stdout_bytes' if fd == 1 else 'stderr_bytes'] += len(chunk)

    def expire():
        with data_lock:
            status['watchdog_fired'] = True
        try:
            job.close()
        except Exception as error:
            with data_lock:
                status['watchdog_cleanup_error'] = type(error).__name__
        finally:
            detached.set()

    recorder.write(dict(type='header', schema=1, executable_name=executable.name,
        input_sha256=initial_hash, observer_sha256=hashlib.sha256(observer_source.encode()).hexdigest(),
        runner_sha256=sha256(__file__), limits=dict(seconds=seconds, api_events=max_events),
        semantics='Native process with observation hooks; no API result replacement; NOT isolated',
        limitations='Hooks perturb timing/code; coverage is not complete; no child instrumentation; '
                    'job cleanup does not isolate file/registry/network/device access or broker-created processes'))
    try:
        device.on('output', on_output)
        status['pid'] = device.spawn([str(executable)], cwd=str(executable.parent), stdio='pipe')
        recorder.write(dict(type='spawned_suspended', pid=status['pid']))
        job.assign(status['pid'])
        assigned = True
        watchdog = threading.Timer(seconds + ready_timeout + 5, expire)
        watchdog.daemon = True
        watchdog.start()
        session = device.attach(status['pid'])
        session.on('detached', on_detached)
        script = session.create_script(observer_source + '\nstartObserver(' +
            json.dumps(dict(maxEvents=max_events)) + ');\n')
        script.on('message', on_message)
        script.load()
        if (not ready.wait(ready_timeout) or not status['ready']
                or status['instrumentation_errors'] or detached.is_set()):
            raise RuntimeError('Observer readiness/required API coverage failed; target not resumed')
        device.resume(status['pid'])
        status['resumed'] = True
        status['reason'] = 'detached' if detached.wait(seconds) else 'duration_limit'
        status['native_exit_code'] = job.exit_code()
    except Exception as error:
        status['reason'] = 'capture_error'
        status['error_type'] = type(error).__name__
        status['error'] = str(error)[:512]
    finally:
        if watchdog is not None:
            watchdog.cancel()
        try:
            job.close()
            status['job_closed'] = True
        except Exception as error:
            status['cleanup_error'] = type(error).__name__
        if status['pid'] is not None and not assigned:
            try:
                device.kill(status['pid'])
                status['unassigned_spawn_terminated'] = True
            except Exception as error:
                status['unassigned_spawn_cleanup_error'] = type(error).__name__
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        try:
            device.off('output', on_output)
        except Exception:
            pass
        status['elapsed_seconds'] = time.monotonic() - started
        try:
            status['input_unchanged'] = sha256(executable) == initial_hash
        except OSError:
            status['input_unchanged'] = False
        recorder.write(dict(type='summary', **status, recorder_dropped=recorder.dropped), final=True)
    return status


def failure_record(error, capture_started, result):
    """Unknown progress must never be reported as proof the target did not run."""
    return dict(type='runner_error' if capture_started else 'startup_error',
                error_type=type(error).__name__, error=str(error)[:512],
                target_resumed=result['resumed'] if result is not None
                else (None if capture_started else False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--max-events', type=int, default=10000)
    parser.add_argument('--allow-host-execution', action='store_true',
                        help='Explicit acknowledgement: actual Windows execution, NOT isolation')
    args = parser.parse_args()
    validate_options(args.seconds, args.max_events)
    if sys.platform != 'win32' or not args.allow_host_execution:
        parser.error('Requires Windows and explicit --allow-host-execution')
    import frida
    from windows_process_job import WindowsProcessJob
    source = Path(__file__).with_name('native_api_observer.js').read_text(encoding='utf-8')
    recorder = JsonlRecorder(args.report, args.max_events + 128)
    capture_started = False
    result = None
    try:
        recorder.write(dict(type='runtime', frida_version=frida.__version__, python=sys.version.split()[0]))
        with WindowsProcessJob() as job:
            device = frida.get_local_device()
            capture_started = True
            result = capture(args.executable, device=device, job=job,
                observer_source=source, recorder=recorder, seconds=args.seconds, max_events=args.max_events)
        print(json.dumps(result))
        return 1 if (result['reason'] == 'capture_error' or not result['job_closed']
                     or result['instrumentation_errors'] or result['watchdog_fired']) else 0
    except Exception as error:
        recorder.write(failure_record(error, capture_started, result), final=True)
        raise
    finally:
        recorder.close()


if __name__ == '__main__':
    raise SystemExit(main())
