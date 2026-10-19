"""Tests use a tiny synthetic PE assembled here, never vendor binaries."""
from pathlib import Path
import struct
import tempfile
import unittest

from loader_trace import trace
from pe_module_model import ModuleModel, utf16_z
from startup_model import VIRTUAL_BASE
import unicorn as uc


def synthetic_pe(code):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x10B)
    for offset, value in [(4, 512), (16, 0x1000), (20, 0x1000), (28, 0x400000),
                          (32, 0x1000), (36, 512), (56, 0x2000), (60, 512),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)]:
        struct.pack_into('<I', data, opt + offset, value)
    struct.pack_into('<H', data, opt + 68, 3)
    section = opt + 224
    struct.pack_into('<8sIIIIIIHHI', data, section, b'.text\0\0\0', 512, 0x1000,
                     512, 512, 0, 0, 0, 0, 0x60000020)
    data[512:512+len(code)] = code
    return data


def synthetic_module(forwarder=None):
    data = synthetic_pe(b'\xcc')
    data.extend(bytes(1024))
    struct.pack_into('<I', data, 0x98 + 28, 0x60000000)
    struct.pack_into('<I', data, 0x98 + 224 + 8, 1536)
    struct.pack_into('<I', data, 0x98 + 224 + 16, 1536)
    struct.pack_into('<II', data, 0x98 + 96, 0x1100, 0x200)
    struct.pack_into('<IIHHIIIIIII', data, 0x300, 0, 0, 0, 0, 0x1190, 1, 3, 3, 0x1140, 0x1160, 0x1180)
    struct.pack_into('<III', data, 0x340, 0x1000, 0x1010, 0x1250 if forwarder else 0x1020)
    struct.pack_into('<III', data, 0x360, 0x11a0, 0x11c0, 0x11e0)
    struct.pack_into('<HHH', data, 0x380, 0, 1, 2)
    for offset, name in [(0x390, 'kernel32.dll'), (0x3a0, 'GetModuleHandleA'),
                         (0x3c0, 'GetProcAddress'), (0x3e0, 'Probe')]:
        value = name.encode() + b'\0'
        data[offset:offset+len(value)] = value
    if forwarder:
        value = forwarder.encode() + b'\0'
        data[0x450:0x450+len(value)] = value
    return data


def resolver_caller(module_name='KERNEL32.dll', api='GetModuleHandleA'):
    # push module name; call IAT GetModuleHandleA; push export name; push eax;
    # call mapped GetProcAddress; call its result. No mapped code may run.
    data = synthetic_pe(bytes.fromhex('68a0114000 ff1560114000 68c0114000 50 ba10100060 ffd2 ffd0 cc'))
    struct.pack_into('<II', data, 0x98+104, 0x1100, 40)
    struct.pack_into('<IIIII', data, 0x300, 0x1140, 0, 0, 0x1150, 0x1160)
    struct.pack_into('<I', data, 0x340, 0x1170)
    struct.pack_into('<I', data, 0x360, 0x1170)
    for offset, value in [(0x350, b'KERNEL32.dll\0'), (0x370, b'\0\0' + api.encode() + b'\0'),
                          (0x3a0, module_name.encode() + b'\0'), (0x3c0, b'Probe\0')]:
        data[offset:offset+len(value)] = value
    return data


class LoaderTraceTests(unittest.TestCase):
    def test_lock_layout_requires_startup_and_is_reported(self):
        with self.assertRaisesRegex(ValueError, 'requires the explicit startup model'):
            self.run_image(synthetic_pe(b'\xc3'), critical_section_layout='win10-x86-19041')
        result = self.run_image(synthetic_pe(b'\xc3'), startup_model=True,
                                critical_section_layout='win10-x86-19041')
        self.assertEqual(result['startup_model']['critical_section_layout'], 'win10-x86-19041')

    def run_image(self, image, limit=100, modules=(), thread_model=False, argument=0, **options):
        with tempfile.TemporaryDirectory(prefix='era-trace-test-') as directory:
            path = Path(directory) / 'synthetic.exe'
            path.write_bytes(image)
            return trace(path, None, argument, limit, 2., modules, thread_model, **options)

    def test_dll_entry_uses_actual_three_argument_attach_contract(self):
        data = synthetic_pe(bytes.fromhex('8b442404 8b4c2408 8b54240c c20c00'))
        struct.pack_into('<H', data, 0x84 + 18, 0x2102)
        result = self.run_image(data, dll_attach=True)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x400000')
        self.assertEqual(result['registers']['ecx'], '0x1')
        self.assertEqual(result['registers']['edx'], '0x0')
        self.assertEqual(result['registers']['esp'], '0x70008010')
        with self.assertRaisesRegex(ValueError, 'requires a DLL'):
            self.run_image(synthetic_pe(b'\xc3'), dll_attach=True)

    def test_chained_export_preserves_attach_memory_and_argument(self):
        data = synthetic_module()
        struct.pack_into('<H', data, 0x84 + 18, 0x2102)
        code = bytes.fromhex('c7050015006078563412 b801000000 c20c00')
        data[512:512+len(code)] = code
        code = bytes.fromhex('a100150060 8b4c2404 c20400')
        data[544:544+len(code)] = code
        result = self.run_image(data, dll_attach=True, after_attach_export='Probe', thread_model=True, argument=-1)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x12345678')
        self.assertEqual(result['registers']['ecx'], '0xffffffff')
        self.assertEqual(result['registers']['esp'], '0x70008008')
        self.assertEqual([s['stage'] for s in result['stage_returns']], ['dll_attach', 'export_after_attach'])
        self.assertEqual(result['stage_returns'][0]['eax'], '0x1')
        self.assertEqual(result['export_start_instruction'], 3)
        self.assertTrue(result['input_unchanged'])
        bounded = self.run_image(data, dll_attach=True, after_attach_export='Probe', limit=4)
        self.assertEqual(bounded['reason'], 'instruction_limit')
        self.assertEqual(bounded['instructions'], 4)
        self.assertEqual(bounded['active_stage'], 'export_after_attach')

    def test_chained_export_requires_success_and_balanced_attach(self):
        for code, reason in [('31c0 c20c00', 'dll_attach_failed'),
                             ('b801000000 c3', 'dll_attach_unbalanced_stack')]:
            data = synthetic_module()
            struct.pack_into('<H', data, 0x84 + 18, 0x2102)
            code = bytes.fromhex(code)
            data[512:512+len(code)] = code
            result = self.run_image(data, dll_attach=True, after_attach_export='Probe')
            self.assertEqual(result['reason'], reason)
            self.assertEqual(len(result['stage_returns']), 1)
        with self.assertRaisesRegex(ValueError, 'requires DLL attach'):
            self.run_image(synthetic_pe(b'\xc3'), after_attach_export='Probe')

    def test_host_calls_real_guest_export_with_shared_memory_and_caller_stack(self):
        dll = synthetic_module()
        struct.pack_into('<H', dll, 0x84 + 18, 0x2102)
        code = bytes.fromhex('c7050015006078563412 b801000000 c20c00')
        dll[512:512+len(code)] = code
        code = bytes.fromhex('8b442404 030500150060 c20400')
        dll[544:544+len(code)] = code
        host = resolver_caller(api='Probe')
        host[0x350:0x350+14] = b'synthetic.exe\0'
        code = bytes.fromhex('c605f011400042 6802000000 ff1560114000 c3')
        host[512:512+len(code)] = code
        with tempfile.TemporaryDirectory(prefix='era-host-test-') as directory:
            path = Path(directory) / 'host.exe'
            path.write_bytes(host)
            result = self.run_image(dll, dll_attach=True, host_after_attach=path,
                thread_model=True, observe=[0x401000], watch=[(0x4011f0, 1), (0x60001500, 4)])
            self.assertEqual(result['reason'], 'returned')
            self.assertEqual(result['registers']['eax'], '0x1234567a')
            self.assertEqual(result['registers']['esp'], '0x70008004')
            self.assertEqual(result['active_stage'], 'host_after_attach')
            self.assertEqual(len(result['guest_calls']), 1)
            self.assertEqual(result['guest_calls'][0]['api'], 'synthetic.exe!Probe')
            self.assertEqual(result['guest_calls'][0]['stack_words'][1], '0x2')
            self.assertEqual(result['execution_observations'][0]['address'], '0x401000')
            self.assertEqual(result['watched_ranges'][0]['changed_byte_count'], 1)
            self.assertEqual(result['watched_ranges'][1]['changed_byte_count'], 4)
            self.assertEqual(result['image_writes_by_section']['host:.text@0x401000'], 1)
            self.assertTrue(result['host_image']['input_unchanged'])
            self.assertEqual(path.read_bytes(), host)

    def test_host_continuation_rejects_bad_invocations_and_overlap(self):
        dll = synthetic_module()
        struct.pack_into('<H', dll, 0x84 + 18, 0x2102)
        with self.assertRaisesRegex(ValueError, 'requires DLL attach'):
            self.run_image(dll, host_after_attach=Path('not-opened.exe'))
        with self.assertRaisesRegex(ValueError, 'without an explicit export'):
            self.run_image(dll, dll_attach=True, host_after_attach=Path('not-opened.exe'), after_attach_export='Probe')
        with tempfile.TemporaryDirectory(prefix='era-host-test-') as directory:
            path = Path(directory) / 'host.exe'
            host = synthetic_pe(b'\xc3')
            struct.pack_into('<I', host, 0x98 + 28, 0x60000000)
            path.write_bytes(host)
            with self.assertRaisesRegex(ValueError, 'overlaps trace harness'):
                self.run_image(dll, dll_attach=True, host_after_attach=path)

    def test_unknown_guest_export_does_not_get_synthetic_success(self):
        dll = synthetic_module()
        struct.pack_into('<H', dll, 0x84 + 18, 0x2102)
        dll[512:520] = bytes.fromhex('b801000000 c20c00')
        host = resolver_caller(api='Unknown')
        host[0x350:0x350+14] = b'synthetic.exe\0'
        host[512:519] = bytes.fromhex('ff1560114000 c3')
        with tempfile.TemporaryDirectory(prefix='era-host-test-') as directory:
            path = Path(directory) / 'host.exe'
            path.write_bytes(host)
            result = self.run_image(dll, dll_attach=True, host_after_attach=path)
            self.assertEqual(result['reason'], 'external_import')
            self.assertEqual(result['external_import'], 'synthetic.exe!Unknown')
            self.assertEqual(result['guest_calls'], [])

    def test_host_resolves_guest_module_and_executes_getprocaddress_result(self):
        dll = synthetic_module()
        struct.pack_into('<H', dll, 0x84 + 18, 0x2102)
        dll[512:520] = bytes.fromhex('b801000000 c20c00')
        code = bytes.fromhex('8b442404 83c005 c20400')
        dll[544:544+len(code)] = code
        host = resolver_caller(module_name='synthetic.exe')
        struct.pack_into('<3I', host, 0x340, 0x1170, 0x11d0, 0)
        struct.pack_into('<3I', host, 0x360, 0x1170, 0x11d0, 0)
        name = b'\0\0GetProcAddress\0'
        host[0x3d0:0x3d0+len(name)] = name
        code = bytes.fromhex('68a0114000 ff1560114000 68c0114000 50 ff1564114000 6a02 ffd0 c3')
        host[512:512+len(code)] = code
        with tempfile.TemporaryDirectory(prefix='era-host-test-') as directory:
            path = Path(directory) / 'host.exe'
            path.write_bytes(host)
            result = self.run_image(dll, dll_attach=True, host_after_attach=path)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x7')
        events = result['module_model']['resolver_events']
        self.assertEqual([e['result'] for e in events], ['0x60000000', '0x60001020'])
        self.assertEqual(len(result['module_model']['guest_modules']), 2)
        self.assertEqual(result['module_model']['modules'], [])

    def test_getmodulehandle_null_requires_explicit_host_identity(self):
        dll = synthetic_module()
        struct.pack_into('<H', dll, 0x84 + 18, 0x2102)
        dll[512:520] = bytes.fromhex('b801000000 c20c00')
        host = resolver_caller()
        code = bytes.fromhex('6a00 ff1560114000 c3')
        host[512:512+len(code)] = code
        with tempfile.TemporaryDirectory(prefix='era-host-test-') as directory:
            path = Path(directory) / 'host.exe'
            path.write_bytes(host)
            result = self.run_image(dll, dll_attach=True, host_after_attach=path)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x400000')
        self.assertTrue(result['module_model']['resolver_events'][0]['null_name_means_explicit_host'])

    def test_chained_export_rejects_unrestored_exception_chain(self):
        data = synthetic_module()
        struct.pack_into('<H', data, 0x84 + 18, 0x2102)
        code = bytes.fromhex('64c7050000000000100060 b801000000 c20c00')
        data[512:512+len(code)] = code
        result = self.run_image(data, dll_attach=True, after_attach_export='Probe', thread_model=True)
        self.assertEqual(result['reason'], 'dll_attach_unrestored_seh')
        self.assertEqual(len(result['stage_returns']), 1)

    def test_nls_requires_explicit_startup_model(self):
        with self.assertRaisesRegex(ValueError, 'require the explicit startup model'):
            self.run_image(synthetic_pe(b'\xc3'), nls_codepage='unopened-path')

    def test_virtual_arena_is_reserved_before_loading_input_images(self):
        data = synthetic_pe(b'\xc3')
        struct.pack_into('<I', data, 0x98 + 28, VIRTUAL_BASE)
        with self.assertRaisesRegex(ValueError, 'overlaps trace harness'):
            self.run_image(data, startup_model=True)

    def test_virtual_arena_leaves_reference_comdlg_range_free_and_rejects_collisions(self):
        with tempfile.TemporaryDirectory(prefix='era-virtual-layout-') as directory:
            path = Path(directory) / 'comdlg32.dll'
            for base in (0x52080000, VIRTUAL_BASE):
                module = synthetic_module()
                struct.pack_into('<I', module, 0x98 + 28, base)
                path.write_bytes(module)
                if base == VIRTUAL_BASE:
                    with self.assertRaisesRegex(ValueError, 'comdlg32.dll.*overlaps'):
                        self.run_image(synthetic_pe(b'\xc3'), modules=[path], startup_model=True)
                else:
                    result = self.run_image(synthetic_pe(b'\xc3'), modules=[path], startup_model=True)
                    self.assertEqual(result['reason'], 'returned')

    def test_reference_iat_markers_stop_unknown_and_model_exact_api(self):
        with tempfile.TemporaryDirectory(prefix='era-reference-iat-') as directory:
            path = Path(directory) / 'reference.dll'
            for api in ('UnknownApi', 'GetCurrentProcess'):
                reference = resolver_caller(api=api)
                struct.pack_into('<I', reference, 0x98 + 28, 0x60000000)
                path.write_bytes(reference)
                # An indirect call through the reference DLL's IAT, not its code.
                image = synthetic_pe(bytes.fromhex('ff1560110060 c3'))
                result = self.run_image(image, modules=[path], startup_model=True,
                                        reference_import_markers=True)
                if api == 'UnknownApi':
                    self.assertEqual(result['reason'], 'external_import')
                    self.assertEqual(result['external_import'], 'KERNEL32.dll!UnknownApi')
                    self.assertEqual(result['instructions'], 1)
                else:
                    self.assertEqual(result['reason'], 'returned')
                    self.assertEqual(result['registers']['eax'], '0xffffffff')
                bindings = result['module_model']['reference_import_bindings']
                self.assertEqual(len(bindings), 1)
                self.assertEqual(bindings[0]['iat_va'], '0x60001160')
                self.assertTrue(result['module_model']['modules'][0]['input_unchanged'])
                self.assertEqual(path.read_bytes(), reference)
            write = synthetic_pe(bytes.fromhex('c7056011006000000000 c3'))
            rejected = self.run_image(write, modules=[path], reference_import_markers=True)
            self.assertEqual(rejected['reason'], 'unmapped_or_protected_memory')
            self.assertEqual(rejected['access'], uc.UC_MEM_WRITE_PROT)

    def test_reference_marker_option_requires_modules_and_reserves_address(self):
        with self.assertRaisesRegex(ValueError, 'require explicit modules'):
            self.run_image(synthetic_pe(b'\xc3'), reference_import_markers=True)
        data = synthetic_pe(b'\xc3')
        struct.pack_into('<I', data, 0x98 + 28, 0x75000000)
        with self.assertRaisesRegex(ValueError, 'overlaps trace harness'):
            self.run_image(data, modules=['never-opened.dll'], reference_import_markers=True)

    def test_observations_and_watch_do_not_export_code_bytes(self):
        data = synthetic_pe(bytes.fromhex('c6052010400090 c3'))
        result = self.run_image(data, observe=[0x401000], watch=[(0x401020, 16)])
        self.assertEqual(result['execution_observations'][0]['stack_words'][:2], ['0x71000000', '0x0'])
        self.assertEqual(result['watched_ranges'][0]['changed_byte_count'], 1)
        self.assertEqual(result['watched_ranges'][0]['first_changed_address'], '0x401020')
        self.assertTrue(result['watched_ranges'][0]['initial_all_zero'])
        self.assertFalse(result['watched_ranges'][0]['final_all_zero'])
        self.assertNotEqual(result['watched_ranges'][0]['initial_sha256'], result['watched_ranges'][0]['final_sha256'])
        self.assertNotIn('bytes', result['watched_ranges'][0])
        self.assertEqual(result['watched_ranges'][0]['last_cpu_write_events'], [dict(
            instruction='0x401000', instruction_index=1, address='0x401020', size=1)])
        with self.assertRaisesRegex(ValueError, 'Watch must'):
            self.run_image(data, watch=[(0x70000000, 16)])

    def test_observation_log_is_bounded(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('ebfe')), limit=1000, observe=[0x401000])
        self.assertEqual(result['reason'], 'observation_limit')
        self.assertEqual(len(result['execution_observations']), 256)

    def test_watch_write_history_keeps_only_last_eight_events(self):
        code = bytes.fromhex('b914000000 fe0500114000 e2f8 c3')
        result = self.run_image(synthetic_pe(code), watch=[(0x401100, 1)])
        history = result['watched_ranges'][0]['last_cpu_write_events']
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(len(history), 8)
        self.assertEqual(history[0]['instruction_index'], 26)
        self.assertEqual(history[-1]['instruction_index'], 40)

    def test_thread_model_fs_base_and_high_stack_are_real_segments(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('64a100000000 50 59 64a118000000 c3')), thread_model=True)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['ecx'], '0xffffffff')
        self.assertEqual(result['registers']['eax'], '0x73001000')
        self.assertEqual(result['registers']['esp'], '0x70008004')

    def test_thread_model_does_not_map_the_null_page(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('a100000000 c3')), thread_model=True)
        self.assertEqual(result['reason'], 'unmapped_or_protected_memory')
        self.assertEqual(result['memory_address'], '0x0')

    def test_copied_thread_id_reader_requires_and_matches_startup_fixture(self):
        data = synthetic_pe(bytes.fromhex('64a118000000 8b4024 c3'))
        missing = self.run_image(data, thread_model=True)
        self.assertEqual(missing['reason'], 'unsupported_thread_field')
        self.assertEqual(missing['thread_access']['offset'], '0x24')
        result = self.run_image(data, thread_model=True, startup_model=True)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(int(result['registers']['eax'], 16), result['startup_model']['profile']['thread_id'])
        self.assertEqual(result['thread_model']['thread_id_fixture'], 4097)

    def test_thread_id_field_is_read_only_and_neighbors_remain_unknown(self):
        for code, offset in [('64c7052400000001000000 c3', '0x24'),
                             ('64a120000000 c3', '0x20'), ('64a128000000 c3', '0x28')]:
            result = self.run_image(synthetic_pe(bytes.fromhex(code)), thread_model=True, startup_model=True)
            self.assertEqual(result['reason'], 'unsupported_thread_field')
            self.assertEqual(result['thread_access']['offset'], offset)

    def test_thread_unknown_peb_field_is_not_zero_filled(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('64a130000000 cc')), thread_model=True)
        self.assertEqual(result['reason'], 'unsupported_thread_field')
        self.assertEqual(result['thread_access']['offset'], '0x30')

    def test_thread_exception_chain_is_observed_without_dispatch(self):
        # Install a synthetic stack record (next=-1, handler=0x401080), then INT3.
        result = self.run_image(synthetic_pe(bytes.fromhex('6880104000 6aff 64892500000000 cc')), thread_model=True)
        self.assertEqual(result['reason'], 'CPU_interrupt')
        self.assertEqual(result['thread_model']['seh_chain'], [dict(record='0x70007ff8', next='0xffffffff', handler='0x401080')])
        self.assertEqual(len(result['thread_model']['exception_list_writes']), 1)

    def test_thread_stack_bounds_and_self_are_read_only(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('64c7050400000000000000 cc')), thread_model=True)
        self.assertEqual(result['reason'], 'unsupported_thread_field')
        self.assertEqual(result['thread_access']['operation'], 'write')

    def test_thread_exception_chain_can_be_restored(self):
        # push handler/old chain, install ESP, then restore old chain and stack.
        result = self.run_image(synthetic_pe(bytes.fromhex(
            '6880104000 64ff3500000000 64892500000000 58 64a300000000 83c404 c3')),
            thread_model=True)
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['thread_model']['final_exception_list'], '0xffffffff')
        self.assertEqual(result['thread_model']['seh_chain'], [])
        self.assertEqual(len(result['thread_model']['exception_list_writes']), 2)

    def test_thread_regions_are_reserved_before_mapping_modules(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            image = synthetic_module()
            struct.pack_into('<I', image, 0x98 + 28, 0x73000000)
            path.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                self.run_image(synthetic_pe(b'\xc3'), modules=[path], thread_model=True)

    def test_thread_snapshot_rejects_out_of_stack_chain(self):
        result = self.run_image(synthetic_pe(bytes.fromhex('64c7050000000000104000 cc')), thread_model=True)
        self.assertEqual(result['reason'], 'CPU_interrupt')
        self.assertEqual(result['thread_model']['seh_chain_stop'], 'outside_modeled_stack_or_unaligned')
        self.assertEqual(result['thread_model']['seh_chain'], [])

    def run_code(self, code, limit=100):
        return self.run_image(synthetic_pe(code), limit)

    def test_return_value_and_input_unchanged(self):
        result = self.run_code(b'\xb8\x78\x56\x34\x12\xc3')
        self.assertEqual(result['reason'], 'returned')
        self.assertEqual(result['registers']['eax'], '0x12345678')
        self.assertEqual(result['instructions'], 2)
        self.assertTrue(result['input_unchanged'])

    def test_unknown_memory_is_not_filled_with_success_values(self):
        result = self.run_code(b'\xa1\x30\x00\x00\x00\xc3')
        self.assertEqual(result['reason'], 'unmapped_or_protected_memory')
        self.assertEqual(result['memory_address'], '0x30')
        self.assertEqual(result['fault_instruction']['mnemonic'], 'mov')

    def test_fault_diagnostic_distinguishes_fs_addressing(self):
        result = self.run_code(bytes.fromhex('64a100000000 c3'))
        self.assertEqual(result['reason'], 'unmapped_or_protected_memory')
        self.assertEqual(result['memory_address'], '0x0')
        self.assertEqual(result['fault_instruction']['memory_operands'][0]['segment'], 'fs')

    def test_fetch_fault_reports_origin_without_dumping_code(self):
        code = b'\xe9' + struct.pack('<i', 0x12340 - 0x401005)
        result = self.run_code(code)
        self.assertEqual(result['memory_address'], '0x12340')
        origin = result['fetch_origin']
        self.assertEqual(origin['address'], '0x401000')
        self.assertEqual(origin['mnemonic'], 'jmp')
        self.assertEqual(origin['immediate_target'], '0x12340')
        self.assertFalse(origin['differs_from_input_image'])
        self.assertNotIn('bytes', origin)

    def test_fetch_fault_detects_modified_transfer(self):
        # Overwrite the following jump displacement, then execute that jump.
        code = bytes.fromhex('c7050b104000') + struct.pack('<I', (0x12340 - 0x40100f) & 0xffffffff)
        code += b'\xe9\0\0\0\0'
        result = self.run_code(code)
        self.assertEqual(result['memory_address'], '0x12340')
        self.assertTrue(result['fetch_origin']['differs_from_input_image'])

    def test_fetch_fault_reports_absolute_indirect_pointer(self):
        code = bytes.fromhex('ff2506104000') + struct.pack('<I', 0x12340)
        result = self.run_code(code)
        self.assertEqual(result['memory_address'], '0x12340')
        self.assertEqual(result['fetch_origin']['indirect_pointer_address'], '0x401006')
        self.assertEqual(result['fetch_origin']['indirect_pointer_value'], '0x12340')
        self.assertEqual(result['fetch_origin']['indirect_operand']['size'], 4)

    def test_interrupt_and_instruction_limit_are_explicit(self):
        self.assertEqual(self.run_code(b'\xcc')['reason'], 'CPU_interrupt')
        result = self.run_code(b'\xeb\xfe', limit=17)
        self.assertEqual(result['reason'], 'instruction_limit')
        self.assertEqual(result['instructions'], 17)

    def test_image_write_is_recorded_without_modifying_disk(self):
        result = self.run_code(b'\xc6\x05\x20\x10\x40\x00\x90\xc3')
        self.assertEqual(result['image_write_events'], 1)
        self.assertEqual(result['image_writes_by_section'], {'.text@0x401000': 1})
        self.assertTrue(result['input_unchanged'])

    def test_external_import_and_module_name_are_observed_not_executed(self):
        data = synthetic_pe(b'\x68\xa0\x11\x40\x00\xff\x15\x60\x11\x40\x00\xcc')
        struct.pack_into('<II', data, 0x98+104, 0x1100, 40)
        struct.pack_into('<IIIII', data, 0x300, 0x1140, 0, 0, 0x1150, 0x1160)
        struct.pack_into('<I', data, 0x340, 0x1170)
        name = b'KERNEL32.dll\0'
        data[0x350:0x350+len(name)] = name
        struct.pack_into('<I', data, 0x360, 0x1170)
        symbol = b'\0\0GetModuleHandleA\0'
        data[0x370:0x370+len(symbol)] = symbol
        data[0x3A0:0x3A0+len(name)] = name
        result = self.run_image(data)
        self.assertEqual(result['reason'], 'external_import')
        self.assertEqual(result['external_import'], 'KERNEL32.dll!GetModuleHandleA')
        self.assertEqual(result['module_name_argument'], 'KERNEL32.dll')
        self.assertEqual(result['instructions'], 2)
        self.assertIsNone(result['returned_import_pointer'])

    def test_explicit_module_resolvers_stop_before_export_execution(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            result = self.run_image(resolver_caller(), modules=[path])
        self.assertEqual(result['reason'], 'external_import')
        self.assertEqual(result['external_import'], 'kernel32.dll!Probe')
        self.assertEqual(result['registers']['eax'], '0x60001020')
        self.assertEqual(result['registers']['esp'], '0x70007ffc')
        self.assertEqual(result['module_model']['observed_resolver_calls'], 2)
        self.assertTrue(result['module_model']['modules'][0]['input_unchanged'])

    def test_missing_module_is_not_faked_as_success_or_failure(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            result = self.run_image(resolver_caller('absent.dll'), modules=[path])
        self.assertEqual(result['external_import'], 'KERNEL32.dll!GetModuleHandleA')
        self.assertIn('not explicitly mapped', result['unresolved_module_call']['model_error'])
        self.assertNotIn('result', result['module_model']['resolver_events'][0])

    def test_wide_module_lookup_uses_explicit_mapping(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            data = resolver_caller(api='GetModuleHandleW')
            value = 'KeRnEl32\0'.encode('utf-16-le')
            data[0x3a0:0x3a0+len(value)] = value
            result = self.run_image(data, modules=[path])
        self.assertEqual(result['external_import'], 'kernel32.dll!Probe')
        event = result['module_model']['resolver_events'][0]
        self.assertEqual(event['module'], 'KeRnEl32')
        self.assertEqual(event['result'], '0x60000000')
        self.assertEqual(result['module_model']['modules'][0]['loadlibrary_acquisitions'], 0)

    def test_wide_strings_are_bounded_and_validate_encoding(self):
        machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        machine.mem_map(0x10000, 4096)
        machine.mem_write(0x10000, 'тест\0'.encode('utf-16-le'))
        self.assertEqual(utf16_z(machine, 0x10000), 'тест')
        with self.assertRaisesRegex(ValueError, 'NULL'):
            utf16_z(machine, 0)
        with self.assertRaisesRegex(ValueError, 'limit'):
            utf16_z(machine, 0x10000, 2)
        machine.mem_write(0x10000, bytes.fromhex('00d80000'))
        with self.assertRaises(UnicodeError):
            utf16_z(machine, 0x10000)

    def test_startup_heap_region_reserved_before_modules(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            data = synthetic_module()
            struct.pack_into('<I', data, 0x98 + 28, 0x50000000)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                self.run_image(synthetic_pe(b'\xc3'), modules=[path], startup_model=True)

    def test_startup_is_opt_in_and_resumes_at_stdcall_return(self):
        data = resolver_caller(api='QueryPerformanceCounter')
        data[512:527] = bytes.fromhex('68a0114000 ff1560114000 c3 909090')
        disabled = self.run_image(data)
        self.assertEqual(disabled['reason'], 'external_import')
        self.assertEqual(disabled['external_import'], 'KERNEL32.dll!QueryPerformanceCounter')
        enabled = self.run_image(data, startup_model=True, watch=[(0x4011a0, 8)])
        self.assertEqual(enabled['reason'], 'returned')
        self.assertEqual(enabled['instructions'], 3)
        self.assertEqual(enabled['registers']['eax'], '0x1')
        self.assertEqual(enabled['registers']['esp'], '0x70008004')
        self.assertTrue(enabled['input_unchanged'])
        self.assertGreater(enabled['watched_ranges'][0]['changed_byte_count'], 0)
        # Host-side model writes are logged separately from CPU writes.
        self.assertEqual(enabled['image_write_events'], 0)
        self.assertEqual(enabled['startup_model']['events'][0]['memory_writes'],
                         [dict(address='0x4011a0', size=8)])

    def test_startup_model_does_not_swallow_device_imports(self):
        result = self.run_image(resolver_caller(api='DeviceIoControl'), startup_model=True)
        self.assertEqual(result['reason'], 'external_import')
        self.assertEqual(result['external_import'], 'KERNEL32.dll!DeviceIoControl')
        self.assertEqual(result['startup_model']['events'], [])

    def test_loadlibrary_only_acquires_explicitly_mapped_module(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            result = self.run_image(resolver_caller(api='LoadLibraryA'), modules=[path])
            missing = self.run_image(resolver_caller('absent.dll', 'LoadLibraryA'), modules=[path])
        self.assertEqual(result['external_import'], 'kernel32.dll!Probe')
        self.assertEqual(result['module_model']['modules'][0]['loadlibrary_acquisitions'], 1)
        self.assertIn('already mapped', result['module_model']['resolver_events'][0]['assumption'])
        self.assertIn('not explicitly mapped', missing['unresolved_module_call']['model_error'])
        self.assertEqual(missing['module_model']['modules'][0]['loadlibrary_acquisitions'], 0)

    def test_module_overlap_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            image = synthetic_module()
            struct.pack_into('<I', image, 0x98 + 28, 0x400000)
            path.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                self.run_image(resolver_caller(), modules=[path])

    def test_reference_module_memory_is_read_only(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            result = self.run_image(synthetic_pe(bytes.fromhex('c6050010006090 c3')), modules=[path])
        self.assertEqual(result['reason'], 'unmapped_or_protected_memory')
        self.assertEqual(result['memory_address'], '0x60001000')
        self.assertTrue(result['module_model']['modules'][0]['input_unchanged'])

    def test_non_export_module_address_is_not_executed(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module())
            result = self.run_image(synthetic_pe(bytes.fromhex('b850100060 ffd0 cc')), modules=[path])
        self.assertEqual(result['reason'], 'external_import')
        self.assertEqual(result['external_import'], 'mapped_module!0x60001050')
        self.assertEqual(result['instructions'], 2)

    def test_forwarder_missing_target_does_not_return_forwarder_string(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module('absent.Probe'))
            result = self.run_image(resolver_caller(), modules=[path])
        self.assertEqual(result['external_import'], 'kernel32.dll!GetProcAddress')
        self.assertIn('not explicitly mapped', result['unresolved_module_call']['model_error'])

    def test_ordinal_case_sensitivity_and_forwarder_cycles(self):
        with tempfile.TemporaryDirectory(prefix='era-module-test-') as directory:
            path = Path(directory) / 'kernel32.dll'
            path.write_bytes(synthetic_module('kernel32.Probe'))
            model = ModuleModel(uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32), [path], [])
            self.assertEqual(model.resolve('KERNEL32.dll', 1), 0x60001000)
            with self.assertRaisesRegex(ValueError, 'not available'):
                model.resolve('kernel32.dll', 'getprocaddress')
            with self.assertRaisesRegex(ValueError, 'depth limit'):
                model.resolve('kernel32.dll', 'Probe')


if __name__ == '__main__':
    unittest.main()
