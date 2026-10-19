"""Differential tests: the same synthetic PE images through both observers."""
import platform
import unittest
from unittest.mock import patch

import unicorn as uc

from native_observer import NativeObserver, build_library, merged_ranges
import test_loader_trace as fixtures


def semantic_report(result):
    return {key: value for key, value in result.items()
            if key not in ('elapsed_seconds', 'instruction_observer')}


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
