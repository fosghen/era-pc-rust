"""Tests use a tiny synthetic PE assembled here, never vendor binaries."""
from pathlib import Path
import struct
import tempfile
import unittest

from loader_trace import trace


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


class LoaderTraceTests(unittest.TestCase):
    def run_image(self, image, limit=100):
        with tempfile.TemporaryDirectory(prefix='era-trace-test-') as directory:
            path = Path(directory) / 'synthetic.exe'
            path.write_bytes(image)
            return trace(path, None, 0, limit, 2.)

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


if __name__ == '__main__':
    unittest.main()
