"""Tests use a tiny synthetic PE assembled here, never vendor binaries."""
from pathlib import Path
import struct
import tempfile
import unittest

from loader_trace import trace
from pe_module_model import ModuleModel
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
    def run_image(self, image, limit=100, modules=()):
        with tempfile.TemporaryDirectory(prefix='era-trace-test-') as directory:
            path = Path(directory) / 'synthetic.exe'
            path.write_bytes(image)
            return trace(path, None, 0, limit, 2., modules)

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
