"""Own instruction fixtures only; no Windows or vendor binary execution."""
import hashlib
import struct
import unittest
from unittest.mock import patch

import unicorn as uc
from unicorn import x86_const as x86

import worker_entry_probe as probe


class WorkerProbeTests(unittest.TestCase):
    def setUp(self):
        self.source = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.source.mem_map(0x10000, 0x2000)
        self.source.reg_write(x86.UC_X86_REG_EAX, 0x12345678)

    def run_probe(self, code, **kwargs):
        self.source.mem_write(0x10000, code)
        args = dict(entry=0x10000, parameter=0x11223344, thread_id=4098,
                    image_ranges=((0x10000, 0x1000),), stop_addresses={}, reference_ranges=())
        args.update(kwargs)
        before = bytes(self.source.mem_read(0x10000, 0x2000))
        registers = [self.source.reg_read(r) for r in probe.REGISTERS.values()]
        result = probe.probe_worker_entry(self.source, **args)
        self.assertEqual(before, bytes(self.source.mem_read(0x10000, 0x2000)))
        self.assertEqual(registers, [self.source.reg_read(r) for r in probe.REGISTERS.values()])
        return result

    def test_return_parameter_and_manifest(self):
        result = self.run_probe(b'\x8b\x44\x24\x04\xc2\x04\x00')
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x11223344')
        self.assertTrue(result['stack_cleanup_matches'])
        self.assertFalse(result['resume_thread_success'])
        self.assertEqual(result['initial_registers']['eax'], '0x0')
        self.assertEqual(result['clone_manifest'][0]['sha256'],
                         hashlib.sha256(bytes(self.source.mem_read(0x10000, 0x2000))).hexdigest())

    def test_child_writes_do_not_touch_source(self):
        code = b'\xc7\x05' + struct.pack('<II', 0x11000, 0xabcdef01)
        code += b'\xa1' + struct.pack('<I', 0x11000) + b'\xc2\x04\x00'
        result = self.run_probe(code)
        self.assertEqual(result['registers']['eax'], '0xabcdef01')
        self.assertEqual(self.source.mem_read(0x11000, 4), bytes(4))

    def test_api_and_reference_stop_before_execute(self):
        for options, reason in ((dict(stop_addresses={0x10000: 'fixture!API'}), 'external_boundary'),
                                (dict(reference_ranges=((0x10000, 10),)), 'reference_boundary')):
            with self.subTest(reason=reason):
                result = self.run_probe(b'\xb8\x01\x00\x00\x00', **options)
                self.assertEqual(result['reason'], reason)
                self.assertEqual(result['instructions'], 0)
                self.assertEqual(result['registers']['eax'], '0x0')

    def test_outside_image(self):
        result = self.run_probe(b'\xe9' + struct.pack('<i', 0x11000 - 0x10005))
        self.assertEqual(result['reason'], 'outside_input_images')

    def test_worker_tib_tid(self):
        result = self.run_probe(b'\x64\xa1\x24\x00\x00\x00\xc2\x04\x00')
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], hex(4098))

    def test_unknown_tib_and_cross_boundary(self):
        for address in (probe.TIB + 0x2c, probe.TIB - 1):
            result = self.run_probe(b'\xa1' + struct.pack('<I', address))
            self.assertEqual(result['reason'], 'unsupported_thread_field')

    def test_creator_tib_and_opaque_overlap(self):
        for options, reason in ((dict(creator_tib_range=(0x11000, 0x1000)), 'creator_tib_access'),
                                (dict(protected_ranges=((0x11000, 24),)), 'protected_region_access')):
            result = self.run_probe(b'\xa1' + struct.pack('<I', 0x10fff), **options)
            self.assertEqual(result['reason'], reason)

    def test_permissions_preserved(self):
        self.source.mem_protect(0x11000, 0x1000, uc.UC_PROT_READ)
        result = self.run_probe(b'\xa3' + struct.pack('<I', 0x11000))
        self.assertEqual(result['reason'], 'unmapped_or_protected_memory')
        self.assertEqual(result['clone_manifest'][1]['permissions'], uc.UC_PROT_READ)

    def test_unmapped_interrupt_syscall(self):
        self.assertEqual(self.run_probe(b'\xa1\x00\x00\x00\x00')['reason'], 'unmapped_or_protected_memory')
        for code in (b'\xcd\x80', b'\x0f\x05', b'\x0f\x34', b'\x0f\x31', b'\xe4\x60', b'\xf3\x6e'):
            result = self.run_probe(code)
            self.assertEqual(result['reason'], 'unsupported_instruction')
            self.assertEqual(result['instructions'], 0)

    def test_instruction_and_time_limits(self):
        result = self.run_probe(b'\xeb\xfe', max_instructions=7)
        self.assertEqual(result['reason'], 'instruction_limit')
        self.assertEqual(result['instructions'], 7)
        result = self.run_probe(b'\xeb\xfe', max_seconds=0.000001)
        self.assertEqual(result['reason'], 'time_limit')

    def test_collision_and_clone_budget(self):
        self.source.mem_map(probe.STACK, 0x1000)
        with self.assertRaisesRegex(ValueError, 'collides'):
            self.run_probe(b'\xc3')
        self.source.mem_unmap(probe.STACK, 0x1000)
        with patch.object(probe, 'CLONE_LIMIT', 4096):
            with self.assertRaisesRegex(ValueError, 'budget'):
                self.run_probe(b'\xc3')

    def test_invalid_configuration(self):
        for options in (dict(thread_id=0), dict(max_instructions=100001), dict(max_seconds=float('nan')),
                        dict(image_ranges=((0x10000, 0),)), dict(stop_addresses={probe.SENTINEL: 'bad'})):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.run_probe(b'\xc3', **options)

    def test_callback_failure_stops_without_execution(self):
        with patch.object(probe.cs, 'Cs') as decoder:
            decoder.return_value.disasm.side_effect = RuntimeError('synthetic callback failure')
            result = self.run_probe(b'\xb8\x01\x00\x00\x00')
        self.assertEqual(result['reason'], 'callback_error')
        self.assertEqual(result['instructions'], 0)
        self.assertEqual(result['registers']['eax'], '0x0')

    def test_random_and_processor_environment_instructions_stop(self):
        for code in ('0fc7f0', '0fc7f8', '0f32', '0f30', '0f33', '0f01d0', '0f01d1',
                     'f30fc7f8', '0f01ee', '0f01ef', 'fa', 'fb'):
            with self.subTest(code=code):
                result = self.run_probe(bytes.fromhex(code) + bytes.fromhex('c20400'))
                self.assertEqual(result['reason'], 'unsupported_instruction')
                self.assertEqual(result['instructions'], 0)

    def test_invalid_instruction_hook_size_is_bounded_before_memory_read(self):
        for code in (b'\x0f\x0b', b'\x0f\xff', b'\x66' * 15):
            with self.subTest(code=code):
                result = self.run_probe(code)
                self.assertEqual(result['reason'], 'unsupported_instruction')
                self.assertEqual(result['instructions'], 0)

    def test_instruction_fetch_cannot_enter_or_cross_opaque_storage(self):
        for key, reason in (('protected_ranges', 'protected_region_access'),
                            ('creator_tib_range', 'creator_tib_access')):
            for offset in (0, 2):
                region = (0x10000 + offset, 24)
                options = {key: (region,) if key == 'protected_ranges' else region}
                result = self.run_probe(bytes.fromhex('b801000000 c20400'), **options)
                self.assertEqual(result['reason'], reason)
                self.assertEqual(result['operation'], 'fetch')
                self.assertEqual(result['instructions'], 0)

    def test_rdtsc_default_and_empty_sequence_remain_stop_only(self):
        for values in ((), []):
            result = self.run_probe(bytes.fromhex('0f31 c20400'), rdtsc_values=values)
            self.assertEqual(result['reason'], 'unsupported_instruction')
            self.assertEqual(result['instructions'], 0)
            self.assertEqual(result['rdtsc_events'], [])
            self.assertEqual(result['registers']['eip'], '0x10000')

    def test_rdtsc_uint64_split_flags_and_return(self):
        # xor sets ZF/PF, stc sets CF: EFLAGS is 0x47 before RDTSC.
        code = bytes.fromhex('31c0 f9 0f31 c20400')
        for value in (0, 0x12345678abcdef01, 0xffffffffffffffff):
            result = self.run_probe(code, rdtsc_values=[value])
            self.assertEqual(result['reason'], 'returned')
            self.assertEqual(result['registers']['eax'], hex(value & 0xffffffff))
            self.assertEqual(result['registers']['edx'], hex(value >> 32))
            self.assertEqual(result['registers']['eflags'], '0x47')
            self.assertEqual(result['instructions'], 4)
            self.assertEqual(result['rdtsc_events'], [dict(address='0x10003', instruction_index=2,
                                                          value=hex(value))])
            self.assertEqual(result['fixture']['rdtsc_values'], [hex(value)])

    def test_rdtsc_skips_actual_instruction_and_stops_at_next_boundary(self):
        result = self.run_probe(bytes.fromhex('0f31 b8ffffffff'), rdtsc_values=(7,),
                                stop_addresses={0x10002: 'fixture!next'})
        self.assertEqual(result['reason'], 'external_boundary')
        self.assertEqual(result['registers']['eip'], '0x10002')
        self.assertEqual(result['registers']['eax'], '0x7')
        self.assertEqual(result['instructions'], 1)
        self.assertEqual(result['tail_instruction_addresses'], ['0x10000'])

    def test_rdtsc_sequence_and_exhaustion(self):
        code = bytes.fromhex('0f31 89c6 89d7 0f31 c20400')
        values = (0x123456789abcdef0, 0xfedcba9876543210)
        result = self.run_probe(code, rdtsc_values=values)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['esi'], '0x9abcdef0')
        self.assertEqual(result['registers']['edi'], '0x12345678')
        self.assertEqual(result['registers']['eax'], '0x76543210')
        self.assertEqual(result['registers']['edx'], '0xfedcba98')
        self.assertEqual([e['instruction_index'] for e in result['rdtsc_events']], [0, 3])
        exhausted = self.run_probe(code, rdtsc_values=values[:1])
        stopped = self.run_probe(code, rdtsc_values=values[:1], stop_addresses={0x10006: 'fixture!next'})
        self.assertEqual(exhausted['reason'], 'rdtsc_fixture_exhausted')
        self.assertEqual(exhausted['registers'], stopped['registers'])
        self.assertEqual(exhausted['instructions'], 3)
        self.assertEqual(len(exhausted['rdtsc_events']), 1)

    def test_rdtsc_input_validation_and_count_budget(self):
        for values in (None, '1', (True,), (-1,), (2**64,), (1.0,), [0] * 65, iter([1])):
            with self.subTest(values=repr(values)), self.assertRaisesRegex(ValueError, 'uint64'):
                self.run_probe(bytes.fromhex('0f31'), rdtsc_values=values)
        result = self.run_probe(bytes.fromhex('0f31 ebfc'), rdtsc_values=[0] * 64,
                                max_instructions=3)
        self.assertEqual(result['reason'], 'instruction_limit')
        self.assertEqual(result['instructions'], 3)
        self.assertEqual(len(result['rdtsc_events']), 2)

    def test_rdtsc_fixture_does_not_enable_rdtscp_or_random(self):
        for code in ('0f01f9', '0fc7f0', '0f32', '0f30'):
            result = self.run_probe(bytes.fromhex(code), rdtsc_values=[1])
            self.assertEqual(result['reason'], 'unsupported_instruction')
            self.assertEqual(result['rdtsc_events'], [])
            self.assertEqual(result['instructions'], 0)


if __name__ == '__main__':
    unittest.main()
