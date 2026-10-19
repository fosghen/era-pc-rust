"""Opt-in Rust code hook; compile only our adjacent source into a private tempdir.

Uses the private engine handle of the pinned Unicorn Python binding. Fail closed
on other versions/platforms; no automatic fallback changes a requested run.
Native code handles addresses/counters only, never executes input PE bytes.
"""
import ctypes as c
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

import unicorn as uc


CALLBACK = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint64, c.c_uint32, c.c_void_p)


class Range(c.Structure):
    _fields_ = [('start', c.c_uint64), ('end', c.c_uint64)]


class Observer(c.Structure):
    _fields_ = [('instructions', c.c_uint64), ('tail', c.c_uint64 * 24),
                ('next', c.c_uint32), ('used', c.c_uint32), ('range_count', c.c_uint32),
                ('ranges', Range * 128), ('callback', CALLBACK), ('callback_data', c.c_void_p)]


def merged_ranges(ranges):
    result = []
    for start, end in sorted(ranges):
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= 2**32:
            raise ValueError('Observer ranges must be nonempty x86 half-open intervals')
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    if len(result) > 128:
        raise ValueError('At most 128 disjoint observer ranges')
    return result


@lru_cache(maxsize=1)
def build_library():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('Rust observer currently supports Linux x86_64 research hosts only')
    if uc.__version__ != '2.1.4':
        raise RuntimeError('Rust observer requires the pinned Unicorn 2.1.4 binding')
    compiler = shutil.which(os.environ.get('RUSTC', 'rustc'))
    if compiler is None:
        raise RuntimeError('Rust observer requires rustc on PATH or an explicit RUSTC path')
    source = Path(__file__).with_name('trace_observer.rs')
    source_bytes = source.read_bytes()
    directory = tempfile.TemporaryDirectory(prefix='era-native-observer-')
    try:
        # Compile a captured source snapshot, not a potentially changing pathname.
        snapshot = Path(directory.name) / source.name
        snapshot.write_bytes(source_bytes)
        library_path = Path(directory.name) / 'libtrace_observer.so'
        compiler_version = subprocess.run([compiler, '--version', '--verbose'], check=True,
            capture_output=True, text=True, timeout=30).stdout.strip()
        flags = ['--edition=2021', '--crate-type=cdylib', '-C', 'opt-level=3', '-C', 'panic=abort']
        subprocess.run([compiler, *flags, str(snapshot), '-o', str(library_path)], check=True,
                       capture_output=True, text=True, timeout=60)
        library = c.CDLL(str(library_path))
        library.observer_size.argtypes = []
        library.observer_size.restype = c.c_size_t
        library.observer_abi.argtypes = []
        library.observer_abi.restype = c.c_uint32
        if library.observer_size() != c.sizeof(Observer) or library.observer_abi() != 1:
            raise RuntimeError('Rust observer ABI mismatch')
        metadata = dict(mode='rust', abi=1, source_sha256=hashlib.sha256(source_bytes).hexdigest(),
            adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            library_sha256=hashlib.sha256(library_path.read_bytes()).hexdigest(),
            compiler=compiler_version, compiler_flags=flags, host=platform.machine(),
            binding_version=uc.__version__)
        return library, directory, metadata
    except BaseException:
        directory.cleanup()
        raise


class NativeObserver:
    def __init__(self, machine, ranges, instruction, state, tail):
        from unicorn.unicorn_py3.unicorn import uclib, uc_hook_h

        ranges = merged_ranges(ranges)
        self.library, self.directory, self.metadata = build_library()
        self.machine, self.state, self.tail = machine, state, tail
        self.uclib = uclib
        self.error = None
        self.data = Observer()
        self.data.range_count = len(ranges)
        for index, (start, end) in enumerate(ranges):
            self.data.ranges[index] = Range(start, end)

        def dispatch(_engine, address, size, _data):
            try:
                self.sync()
                before = state['instructions']
                instruction(machine, address, size, None)
                delta = state['instructions'] - before
                if delta not in (0, 1):
                    raise RuntimeError('Unexpected Python observer instruction delta')
                return delta
            except BaseException as error:
                # ctypes must not silently swallow an exception and continue.
                self.error = error
                machine.emu_stop()
                return 0

        self.callback = CALLBACK(dispatch)
        self.data.callback = self.callback
        self.handle = uc_hook_h()
        status = uclib.uc_hook_add(machine._uch, c.byref(self.handle), uc.UC_HOOK_CODE,
            c.cast(self.library.observer_hook, c.c_void_p), c.cast(c.pointer(self.data), c.c_void_p), 1, 0)
        if status:
            raise uc.UcError(status)

    def sync(self):
        self.state['instructions'] = self.data.instructions
        self.tail.clear()
        start = (self.data.next - self.data.used) % 24
        self.tail.extend(self.data.tail[(start + i) % 24] for i in range(self.data.used))

    def check_error(self):
        if self.error is not None:
            raise self.error

    def close(self):
        if self.handle.value:
            status = self.uclib.uc_hook_del(self.machine._uch, self.handle)
            if status:
                raise uc.UcError(status)
            self.handle.value = 0
