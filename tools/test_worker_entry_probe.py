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

    def test_stopped_stack_metadata_is_bounded_to_own_stack(self):
        result = self.run_probe(b'\x90', stop_addresses={0x10000: 'fixture!API'})
        words = result['stack_observation']['words']
        self.assertEqual(words[:2], [hex(probe.SENTINEL), '0x11223344'])
        self.assertEqual(len(words), 4)
        self.assertEqual(result['stack_observation']['captured_words'], 4)
        self.assertTrue(result['stack_observation']['truncated'])
        moved = self.run_probe(bytes.fromhex('bc00100100 90'), stop_addresses={0x10005: 'fixture!API'})
        self.assertEqual(moved['reason'], 'external_boundary')
        self.assertEqual(moved['stack_observation']['words'], [])
        self.assertIn('outside', moved['stack_observation']['error'])

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
        for options in (dict(thread_id=0), dict(max_instructions=1000001), dict(max_seconds=float('nan')),
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
        for values in (None, '1', (True,), (-1,), (2**64,), (1.0,), [0] * 1025, iter([1])):
            with self.subTest(values=repr(values)), self.assertRaisesRegex(ValueError, 'uint64'):
                self.run_probe(bytes.fromhex('0f31'), rdtsc_values=values)
        result = self.run_probe(bytes.fromhex('0f31 ebfc'), rdtsc_values=[0] * 1024,
                                max_instructions=3)
        self.assertEqual(result['reason'], 'instruction_limit')
        self.assertEqual(result['instructions'], 3)
        self.assertEqual(len(result['rdtsc_events']), 2)
        self.assertEqual(len(result['fixture']['rdtsc_values']), 1024)

    def test_rdtsc_fixture_does_not_enable_rdtscp_or_random(self):
        for code in ('0f01f9', '0fc7f0', '0f32', '0f30'):
            result = self.run_probe(bytes.fromhex(code), rdtsc_values=[1])
            self.assertEqual(result['reason'], 'unsupported_instruction')
            self.assertEqual(result['rdtsc_events'], [])
            self.assertEqual(result['instructions'], 0)

    def compare_decoder_modes(self, code, **options):
        results = [self.run_probe(code, decode_cache=mode, **options) for mode in (False, True)]
        ignored = {'elapsed_seconds', 'setup_seconds', 'decoder_cache'}
        self.assertEqual(*[{key: value for key, value in result.items() if key not in ignored}
                           for result in results])
        return results

    def test_decode_cache_parity_and_hits(self):
        reference, cached = self.compare_decoder_modes(bytes.fromhex('40 ebfd'), max_instructions=21)
        self.assertEqual(reference['decoder_cache'], dict(mode='disabled', hits=0, misses=21,
                         limit=4096, resets=0, entries=0))
        self.assertEqual(cached['decoder_cache'], dict(mode='exact_bytes', hits=19, misses=2,
                         limit=4096, resets=0, entries=2))
        # Identical bytes at distinct addresses share only a classification;
        # address-dependent operands and execution remain Unicorn's concern.
        self.compare_decoder_modes(bytes.fromhex('90 90 c20400'))

    def test_decode_cache_parity_for_boundaries_and_rdtsc(self):
        for code, options in [
                ('0f31 ebfc', dict(rdtsc_values=(1, 2))),
                ('0fc7f0', {}), ('fa', {}), ('0f0b', {}),
                ('b801000000', dict(protected_ranges=((0x10002, 4),))),
                ('90 90', dict(stop_addresses={0x10001: 'fixture!boundary'}))]:
            with self.subTest(code=code):
                self.compare_decoder_modes(bytes.fromhex(code), **options)

    def test_decode_cache_self_modification_cannot_hide_rdtsc(self):
        # First classify a 2-byte NOP; overwrite it with forbidden RDTSC and
        # jump back to the exact same address, preserving instruction length.
        code = bytes.fromhex('6690 66c705') + struct.pack('<IH', 0x10000, 0x310f)
        code += b'\xe9' + struct.pack('<i', -16)
        reference, cached = self.compare_decoder_modes(code)
        self.assertEqual(cached['reason'], 'unsupported_instruction')
        self.assertEqual(cached['instruction_kind'], 'rdtsc')
        self.assertEqual(cached['registers']['eip'], '0x10000')
        self.assertEqual(cached['registers']['eax'], '0x0')
        self.assertEqual(cached['rdtsc_events'], [])

    def test_decode_cache_is_bounded_and_resets(self):
        self.source.mem_map(0x12000, 0x5000)
        code = b''.join(b'\xb8' + struct.pack('<I', value) for value in range(4097))
        code += bytes.fromhex('c20400')
        reference, cached = self.compare_decoder_modes(code, image_ranges=((0x10000, 0x7000),))
        self.assertEqual(cached['reason'], 'returned')
        self.assertEqual(cached['decoder_cache'], dict(mode='exact_bytes', hits=0, misses=4098,
                         limit=4096, resets=1, entries=2))

    def test_decode_cache_strict_bool_and_expanded_budget(self):
        for value in (None, 0, 1, 'yes', [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'bool'):
                self.run_probe(b'\xc3', decode_cache=value)
        for value in (100001, 1000000):
            result = self.run_probe(bytes.fromhex('c20400'), max_instructions=value)
            self.assertEqual(result['reason'], 'returned')
            self.assertEqual(result['limits']['instructions'], value)

    def tick_call(self, prefix=b'', suffix=bytes.fromhex('c20400')):
        self.source.mem_write(0x11000, bytes.fromhex('b8ffffffff c3'))
        call_address = 0x10000 + len(prefix)
        return prefix + b'\xe8' + struct.pack('<i', 0x11000 - call_address - 5) + suffix

    def test_tick_default_empty_and_strict_api_allowlist(self):
        code = self.tick_call()
        for values in ((), []):
            result = self.run_probe(code, stop_addresses={0x11000: 'KERNEL32.dll!GetTickCount'},
                                    tick_count_values=values)
            self.assertEqual(result['reason'], 'external_boundary')
            self.assertEqual(result['instructions'], 1)
            self.assertEqual(result['tick_count_events'], [])
        for name in ('kernelbase.dll!GetTickCount', 'api-ms-win-core-sysinfo-l1-1-0.dll!GetTickCount',
                     'otherkernel32.dll!GetTickCount', 'kernel32.dll!GetTickCount64',
                     'kernel32.dll!gettickcount', 'GetTickCount', 'kernel32.dll!GetTickCount!suffix'):
            with self.subTest(name=name):
                result = self.run_probe(code, stop_addresses={0x11000: name}, tick_count_values=(1,))
                self.assertEqual(result['reason'], 'external_boundary')
                self.assertEqual(result['tick_count_events'], [])

    def test_tick_single_value_dword_flags_and_separate_count(self):
        code = self.tick_call(bytes.fromhex('31c0 f9'))
        for value in (0, 0x12345678, 0xffffffff):
            with self.subTest(value=value):
                reference, result = self.compare_decoder_modes(code,
                    stop_addresses={0x11000: 'KeRnEl32.DlL!GetTickCount'}, tick_count_values=[value],
                    max_instructions=1000000, max_seconds=10)
                self.assertEqual(result['reason'], 'returned')
                self.assertEqual(result['registers']['eax'], hex(value))
                self.assertEqual(result['registers']['eflags'], '0x47')
                self.assertEqual(result['registers']['edx'], '0x0')
                self.assertEqual(result['instructions'], 4)
                self.assertTrue(result['stack_cleanup_matches'])
                self.assertEqual(result['model_event_count'], 1)
                self.assertEqual(result['tick_count_events'], [dict(address='0x11000', instruction_index=3,
                    value_index=0, value=hex(value), return_address='0x10008')])
                self.assertEqual(result['fixture']['tick_count_values'], [hex(value)])

    def test_tick_return_does_not_modify_stack_word(self):
        # After the model pop, the old return word remains at ESP-4.
        code = self.tick_call(suffix=bytes.fromhex('8b5424fc c20400'))
        result = self.run_probe(code, stop_addresses={0x11000: 'kernel32.dll!GetTickCount'},
                                tick_count_values=[123])
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x7b')
        self.assertEqual(result['registers']['edx'], '0x10005')

    def test_tick_exhaustion_preserves_last_value_and_frame(self):
        code = self.tick_call(suffix=bytes.fromhex('ebf9'))
        for values in ((123,), tuple(range(16))):
            reference, result = self.compare_decoder_modes(code,
                stop_addresses={0x11000: 'kernel32.dll!GetTickCount'}, tick_count_values=values)
            self.assertEqual(result['reason'], 'tick_count_fixture_exhausted')
            self.assertEqual(result['registers']['eax'], hex(values[-1]))
            self.assertEqual(result['registers']['eip'], '0x11000')
            self.assertEqual(result['registers']['esp'], hex(probe.STACK + probe.STACK_SIZE - 20))
            self.assertEqual(result['stack_observation']['words'][0], '0x10005')
            self.assertEqual(result['instructions'], len(values) * 2 + 1)
            self.assertEqual(result['model_event_count'], len(values))
            self.assertEqual([event['value_index'] for event in result['tick_count_events']], list(range(len(values))))

    def assert_tick_rejected_atomically(self, code, **options):
        options['stop_addresses'] = {0x11000: 'kernel32.dll!GetTickCount'}
        baseline = self.run_probe(code, **options)
        reference, result = self.compare_decoder_modes(code, tick_count_values=(99,), **options)
        self.assertEqual(baseline['reason'], 'external_boundary')
        self.assertEqual(result['reason'], 'tick_count_fixture_error')
        self.assertEqual(result['registers'], baseline['registers'])
        self.assertEqual(result['instructions'], baseline['instructions'])
        self.assertEqual(result['stack_observation'], baseline['stack_observation'])
        self.assertEqual(result['tick_count_events'], [])
        self.assertEqual(result['model_event_count'], 0)

    def test_tick_invalid_stack_is_atomic(self):
        for address in (0, 0x10000, probe.STACK - 1, probe.STACK + probe.STACK_SIZE - 3):
            with self.subTest(address=address):
                # Set ESP without accessing it, then JMP (not CALL) to the API.
                code = b'\xbc' + struct.pack('<I', address)
                code += b'\xe9' + struct.pack('<i', 0x11000 - 0x1000a)
                self.assert_tick_rejected_atomically(code)

    def test_tick_invalid_return_is_atomic(self):
        self.source.mem_map(0x12000, 0x1000, uc.UC_PROT_READ)
        cases = [(0, {}), (0x11000, dict(image_ranges=((0x10000, 0x2000),))),
                 (probe.SENTINEL, {}), (0x10080, dict(protected_ranges=((0x10080, 24),))),
                 (0x10090, dict(reference_ranges=((0x10090, 24),))),
                 (0x100a0, dict(creator_tib_range=(0x100a0, 24))),
                 (0x12000, dict(image_ranges=((0x10000, 0x3000),))),
                 (0x13000, dict(image_ranges=((0x10000, 0x5000),)))]
        for target, options in cases:
            with self.subTest(target=target, options=options):
                code = b'\x68' + struct.pack('<I', target)
                code += b'\xe9' + struct.pack('<i', 0x11000 - 0x1000a)
                self.assert_tick_rejected_atomically(code, **options)

    def test_tick_sequence_validation_and_instruction_budget(self):
        for values in (None, True, '1', (True,), (-1,), (2**32,), (1.0,), [0] * 17, iter([1])):
            with self.subTest(values=repr(values)), self.assertRaisesRegex(ValueError, 'uint32'):
                self.run_probe(b'\xc3', tick_count_values=values)
        code = self.tick_call()
        result = self.run_probe(code, tick_count_values=[1], max_instructions=1,
                               stop_addresses={0x11000: 'kernel32.dll!GetTickCount'})
        self.assertEqual(result['reason'], 'instruction_limit')
        self.assertEqual(result['instructions'], 1)
        self.assertEqual(result['tick_count_events'], [])
        self.assertEqual(result['registers']['eax'], '0x0')


if __name__ == '__main__':
    unittest.main()
