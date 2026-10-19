"""Differential tests: the same synthetic PE images through both observers."""
import platform
import unittest
from unittest.mock import patch

import unicorn as uc
from unicorn import x86_const as x86

from native_observer import NativeObserver, NativeMemoryFilter, NativeMemoryHooks, build_library, merged_ranges
import test_loader_trace as fixtures
import test_startup_model as startup_fixtures


def semantic_report(result):
    report = {key: value for key, value in result.items()
              if key not in ('elapsed_seconds', 'instruction_observer')}
    if 'worker_entry_probe' in report:
        report['worker_entry_probe'] = {key: value for key, value in report['worker_entry_probe'].items()
                                        if key not in ('elapsed_seconds', 'setup_seconds')}
    return report


@unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                     'Native observer currently supports Linux x86_64 only')
class RustObserverParityTests(fixtures.LoaderTraceTests):
    def run_image(self, image, *args, **options):
        expected = super().run_image(image, *args, **options)
        actual = super().run_image(image, *args, observer='rust', **options)
        self.assertEqual(semantic_report(actual), semantic_report(expected))
        self.assertEqual(actual['instruction_observer']['mode'], 'rust')
        self.assertEqual(len(actual['instruction_observer']['source_sha256']), 64)
        return actual

    def test_multiple_execution_chunks_and_tail_wraparound(self):
        # 600,001 loop instructions followed by ret; crosses 250k chunk limits.
        image = fixtures.synthetic_pe(bytes.fromhex('b9e0930400 49 75fd c3'))
        result = self.run_image(image, limit=700_000)
        self.assertEqual(result['instructions'], 600_002)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(len(result['tail_instruction_addresses']), 24)

    def test_exact_limits_at_observation_and_return(self):
        image = fixtures.synthetic_pe(bytes.fromhex('90 90 c3'))
        for limit in (1, 2, 3, 4):
            result = self.run_image(image, limit=limit, observe=[0x401000, 0x401001, 0x401002])
            self.assertEqual(result['instructions'], min(limit, 3))

    def test_frequent_observation_does_not_double_count(self):
        image = fixtures.synthetic_pe(bytes.fromhex('b90a000000 49 75fd c3'))
        result = self.run_image(image, observe=[0x401005, 0x401006])
        self.assertEqual(result['instructions'], 22)
        self.assertEqual(len(result['execution_observations']), 20)

    def test_instruction_only_ablation_has_identical_semantics(self):
        image = fixtures.synthetic_pe(bytes.fromhex('c605f011400042 c3'))
        options = dict(watch=[(0x4011f0, 1)], startup_model=True)
        expected = self.run_image(image, **options)
        actual = super().run_image(image, observer='rust', memory_observer='python', **options)
        self.assertEqual(semantic_report(expected), semantic_report(actual))
        self.assertEqual(actual['instruction_observer']['memory_mode'], 'python')
        self.assertNotIn('memory_hooks', actual['instruction_observer'])

    def test_lock_stop_and_image_write_observer_keep_hook_order(self):
        for layout in (None, 'win10-x86-19041'):
            image = fixtures.resolver_caller(api='InitializeCriticalSection')
            # Initialize lock inside the input image, then a write starting two
            # bytes before it. Guard, write statistics and watched events must
            # match the original hook ordering, even when the guard stops CPU.
            code = bytes.fromhex('68d0114000 ff1560114000 a3ce114000 c3')
            image[512:512 + len(code)] = code
            result = self.run_image(image, startup_model=True, critical_section_layout=layout,
                                    watch=[(0x4011cc, 32)])
            self.assertEqual(result['reason'], 'unsupported_critical_section_memory')
            self.assertEqual(result['critical_section_access']['address'], '0x4011ce')
            self.assertEqual(result['instruction_observer']['memory_hooks']['critical_sections']
                             ['forwarded_to_python'], 1)

    def test_callback_exception_propagates_and_hook_can_be_removed(self):
        from collections import deque
        machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        machine.mem_map(0x1000, 4096)
        machine.mem_write(0x1000, b'\x90\x90')

        def broken(*_):
            raise ValueError('synthetic callback failure')

        state = dict(instructions=0)
        observer = NativeObserver(machine, [(0x1000, 0x1001)], broken, state, deque(maxlen=24))
        try:
            machine.emu_start(0x1000, 0x1002, count=2)
            with self.assertRaisesRegex(ValueError, 'synthetic callback failure'):
                observer.check_error()
            self.assertEqual(observer.data.instructions, 0)
        finally:
            observer.close()
        observer.close()
        machine.emu_start(0x1000, 0x1002, count=2)
        self.assertEqual(observer.data.instructions, 0)


@unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                     'Native observer currently supports Linux x86_64 only')
class RustMemoryStartupTests(startup_fixtures.StartupModelTests):
    def setUp(self):
        self.configure_native_model(None)

    def configure_native_model(self, layout):
        self.machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.machine.mem_map(0x10000, 0x3000)
        self.memory_hooks = NativeMemoryHooks(self.machine)
        self.addCleanup(self.memory_hooks.close)
        self.model = startup_fixtures.StartupModel(self.machine, critical_section_layout=layout,
                                                  memory_hooks=self.memory_hooks)

    def enable_measured_lock_layout(self):
        self.configure_native_model('win10-x86-19041')

    def test_many_locks_dynamic_removal_and_reinitialization(self):
        for i in range(128):
            self.result('InitializeCriticalSection', 0x11000 + 24 * i)
        hook = self.memory_hooks.hooks['critical_sections']
        self.assertEqual(hook.data.range_count, 1)  # Adjacent locks merge for filtering only.
        self.result('DeleteCriticalSection', 0x11018)
        self.assertEqual(hook.data.range_count, 2)
        self.result('InitializeCriticalSection', 0x11018)
        self.assertEqual(hook.data.range_count, 1)
        self.machine.mem_write(0x10000, bytes.fromhex('a300100100'))
        self.machine.emu_start(0x10000, 0x10005)
        self.memory_hooks.check_error()
        self.assertEqual(self.model.trace_state['reason'], 'unsupported_critical_section_memory')
        self.assertEqual(hook.report()['forwarded_to_python'], 1)


@unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                     'Native observer currently supports Linux x86_64 only')
class NativeMemoryFilterTests(unittest.TestCase):
    def setUp(self):
        self.machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.machine.mem_map(0x1000, 0x2000)
        self.machine.mem_write(0x1000, bytes.fromhex('8902'))  # mov [edx],eax
        self.events = []

    def install(self, ranges=(), overlap=True, callback=None):
        hook = NativeMemoryFilter(self.machine, uc.UC_HOOK_MEM_WRITE,
            callback or (lambda m, kind, address, size, value, _: self.events.append((address, size, value))),
            ranges, overlap=overlap)
        self.addCleanup(hook.close)
        return hook

    def write_at(self, address):
        self.machine.reg_write(x86.UC_X86_REG_EDX, address)
        self.machine.reg_write(x86.UC_X86_REG_EAX, 0xdeadbeef)
        self.machine.emu_start(0x1000, 0x1002, count=1)

    def test_crossing_boundary_is_forwarded_but_adjacent_is_not(self):
        hook = self.install([(0x2010, 0x2018), (0x2020, 0x2024)])
        for address in (0x200c, 0x200e, 0x2017, 0x2018, 0x201e, 0x2024):
            self.write_at(address)
        self.assertEqual([e[0] for e in self.events], [0x200e, 0x2017, 0x201e])
        self.assertTrue(all(e[1:] == (4, 0xdeadbeef) for e in self.events))
        self.assertEqual(hook.report(), dict(accesses=6, forwarded_to_python=3, filter='overlap'))

    def test_start_filter_preserves_image_observer_contract(self):
        hook = self.install([(0x2010, 0x2018)], overlap=False)
        for address in (0x200e, 0x2010, 0x2017, 0x2018):
            self.write_at(address)
        self.assertEqual([e[0] for e in self.events], [0x2010, 0x2017])
        self.assertEqual(hook.report()['accesses'], 4)

    def test_updates_empty_ranges_and_rejects_bad_update_atomically(self):
        hook = self.install()
        self.write_at(0x2010)
        hook.set_ranges([(0x2010, 0x2018)])
        with self.assertRaises(ValueError):
            hook.set_ranges([(3, 2)])
        self.write_at(0x2010)
        hook.set_ranges([])
        self.write_at(0x2010)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(hook.report()['accesses'], 3)

    def test_memory_callback_exception_stops_and_propagates(self):
        def broken(*_):
            raise RuntimeError('synthetic memory failure')
        hook = self.install([(0x2000, 0x3000)], callback=broken)
        self.write_at(0x2010)
        with self.assertRaisesRegex(RuntimeError, 'synthetic memory failure'):
            hook.check_error()
        hook.close()
        self.write_at(0x2010)
        self.assertEqual(hook.report()['accesses'], 1)

    def test_invalid_hook_kind_is_rejected(self):
        for kind in (0, uc.UC_HOOK_CODE, uc.UC_HOOK_MEM_FETCH, uc.UC_HOOK_MEM_INVALID):
            with self.assertRaises(ValueError):
                NativeMemoryFilter(self.machine, kind, lambda *_: None)


class ObserverRangeTests(unittest.TestCase):
    def test_unsupported_host_and_binding_fail_without_fallback(self):
        with patch('native_observer.platform.system', return_value='Windows'):
            with self.assertRaisesRegex(RuntimeError, 'Linux x86_64'):
                build_library.__wrapped__()
        with patch('native_observer.platform.system', return_value='Linux'), \
                patch('native_observer.platform.machine', return_value='x86_64'), \
                patch('native_observer.uc.__version__', 'unsupported'):
            with self.assertRaisesRegex(RuntimeError, 'pinned Unicorn'):
                build_library.__wrapped__()

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'Native compiler check requires a supported host')
    def test_missing_compiler_fails_without_fallback(self):
        with patch('native_observer.shutil.which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'requires rustc'):
                build_library.__wrapped__()

    def test_unknown_observer_is_rejected_before_reading_input(self):
        from pathlib import Path
        with self.assertRaisesRegex(ValueError, 'Observer must be'):
            fixtures.trace(Path('nonexistent-input'), None, 0, 1, 1, observer='unknown')
        for mode in ('rust', 'unknown'):
            with self.assertRaisesRegex(ValueError, 'memory observer requires'):
                fixtures.trace(Path('nonexistent-input'), None, 0, 1, 1, memory_observer=mode)

    def test_merges_only_overlapping_or_adjacent_intervals(self):
        self.assertEqual(merged_ranges([(5, 7), (1, 3), (2, 4), (4, 5), (9, 10)]),
                         [(1, 7), (9, 10)])
        self.assertEqual(merged_ranges([]), [])
        self.assertEqual(merged_ranges([(0xffffffff, 2**32)]), [(0xffffffff, 2**32)])

    def test_rejects_invalid_or_excessive_ranges(self):
        for ranges in [[(2, 2)], [(-1, 3)], [(0, 2**32 + 1)], [(1.0, 2)], [(False, 2)],
                       [(i * 2, i * 2 + 1) for i in range(129)]]:
            with self.assertRaises(ValueError):
                merged_ranges(ranges)
