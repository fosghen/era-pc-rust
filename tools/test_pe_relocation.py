"""Strict relocation tests use only synthetic PE files, never vendor code."""
from pathlib import Path
import struct
import tempfile
import unittest

import pefile
import unicorn as uc

from pe_module_model import ModuleModel, relocate_reference_image
from test_loader_trace import synthetic_module


def relocation_image(entries=(0x33c0, 0), page=0x1000):
    data = synthetic_module()
    table = struct.pack('<II', page, 8 + 2 * len(entries))
    table += struct.pack('<' + 'H' * len(entries), *entries)
    struct.pack_into('<II', data, 0x98 + 96 + 5 * 8, 0x1400, len(table))
    data[0x600:0x600 + len(table)] = table
    struct.pack_into('<I', data, 0x5c0, 0x60001020)
    return data


class ReferenceRelocationTests(unittest.TestCase):
    def map_image(self, data, base=0x61000000, markers=False, occupied=()):
        directory = tempfile.TemporaryDirectory(prefix='era-relocation-test-')
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'kernel32.dll'
        path.write_bytes(data)
        machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        model = ModuleModel(machine, [path], occupied, import_markers=markers,
                            module_bases=() if base is None else [('KERNEL32.DLL', base)])
        self.assertEqual(path.read_bytes(), data)
        return machine, model

    def test_positive_negative_and_modulo_deltas(self):
        for base, value in [(0x61000000, 0x60001020), (0x5f000000, 0x60001020),
                            (0x61000000, 0xffffffff), (0x5f000000, 1)]:
            with self.subTest(base=base, value=value):
                data = relocation_image()
                struct.pack_into('<I', data, 0x5c0, value)
                machine, model = self.map_image(data, base)
                actual = struct.unpack('<I', machine.mem_read(base + 0x13c0, 4))[0]
                self.assertEqual(actual, (value + base - 0x60000000) & 0xffffffff)
                record = model.report()['modules'][0]
                self.assertEqual(record['preferred_base'], '0x60000000')
                self.assertEqual(record['base'], hex(base))
                self.assertEqual(record['relocation_delta'], base - 0x60000000)
                self.assertEqual(record['relocation_highlow_count'], 1)
                self.assertTrue(record['explicit_base'])
                self.assertTrue(record['input_unchanged'])

    def test_headers_exports_and_read_only_mapping(self):
        machine, model = self.map_image(relocation_image())
        self.assertEqual(struct.unpack('<I', machine.mem_read(0x61000000 + 0x98 + 28, 4))[0], 0x60000000)
        self.assertEqual(model.resolve('kernel32.dll', 'Probe'), 0x61001020)
        self.assertEqual(model.address_names[0x61001020], ['kernel32.dll!Probe'])
        self.assertTrue(model.contains(0x61001020))
        self.assertFalse(model.contains(0x60001020))
        self.assertEqual(list(machine.mem_regions()), [(0x61000000, 0x61001fff, uc.UC_PROT_READ | uc.UC_PROT_EXEC)])
        # Guest registration retains its original preferred base and is not relocated.
        model.register_guest('guest.dll', pefile.PE(data=bytes(relocation_image())))
        self.assertEqual(model.resolve('guest.dll', 'Probe'), 0x60001020)

    def test_iat_markers_use_relocated_slot_and_preferred_rva(self):
        data = relocation_image()
        struct.pack_into('<II', data, 0x98 + 104, 0x1300, 40)
        struct.pack_into('<IIIII', data, 0x500, 0x1340, 0, 0, 0x1350, 0x1360)
        struct.pack_into('<I', data, 0x540, 0x1370)
        struct.pack_into('<I', data, 0x560, 0x1370)
        data[0x550:0x55d] = b'KERNEL32.dll\0'
        data[0x570:0x57a] = b'\0\0Unknown\0'
        machine, model = self.map_image(data, markers=True)
        binding = model.report()['reference_import_bindings'][0]
        self.assertEqual(binding['iat_va'], '0x61001360')
        self.assertEqual(binding['imported_name'], 'KERNEL32.dll!Unknown')
        self.assertEqual(struct.unpack('<I', machine.mem_read(0x61001360, 4))[0], int(binding['marker'], 16))

    def test_default_and_explicit_preferred_base_need_no_table(self):
        for base in (None, 0x60000000):
            with self.subTest(base=base):
                machine, model = self.map_image(synthetic_module(), base)
                record = model.report()['modules'][0]
                self.assertEqual(record['relocation_delta'], 0)
                self.assertEqual(record['relocation_highlow_count'], 0)
                self.assertEqual(record['explicit_base'], base is not None)
                self.assertEqual(model.resolve('kernel32.dll', 'Probe'), 0x60001020)

    def test_missing_and_stripped_relocations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no relocation directory'):
            self.map_image(synthetic_module())
        data = relocation_image()
        struct.pack_into('<H', data, 0x84 + 18, 0x103)
        with self.assertRaisesRegex(ValueError, 'stripped'):
            self.map_image(data)

    def test_bad_directories_rejected(self):
        for rva, size in [(0, 12), (0x1400, 0), (0x1401, 12), (0x2000, 12),
                          (0x1ffc, 12), (0x1400, 0xffffffff), (0x1600, 12), (0x1400, 7)]:
            with self.subTest(rva=rva, size=size):
                data = relocation_image()
                struct.pack_into('<II', data, 0x98 + 96 + 5 * 8, rva, size)
                with self.assertRaises(ValueError):
                    self.map_image(data)
        data = relocation_image()[:0x609]
        with self.assertRaisesRegex(ValueError, 'Truncated raw'):
            self.map_image(data)

    def test_bad_blocks_and_types_rejected(self):
        for block_size in (0, 4, 7, 10, 16, 0xffffffff):
            with self.subTest(block_size=block_size):
                data = relocation_image()
                struct.pack_into('<I', data, 0x604, block_size)
                with self.assertRaisesRegex(ValueError, 'block size'):
                    self.map_image(data)
        for page in (1, 0x1001, 0x2000, 0xfffff000):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, 'page RVA'):
                self.map_image(relocation_image(page=page))
        for kind in (1, 2, 4, 5, 10, 15):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'Unsupported'):
                self.map_image(relocation_image(entries=((kind << 12) | 0x3c0, 0)))

    def test_out_of_range_and_overlapping_fixups_rejected(self):
        with self.assertRaisesRegex(ValueError, 'fixup outside'):
            self.map_image(relocation_image(entries=(0x3ffe, 0)))
        for second in (0x33c0, 0x33c1, 0x33c3, 0x33bf):
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, 'Overlapping'):
                self.map_image(relocation_image(entries=(0x33c0, second)))
        data = relocation_image()
        data[0x60c:0x618] = data[0x600:0x60c]
        struct.pack_into('<I', data, 0x98 + 96 + 5 * 8 + 4, 24)
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            self.map_image(data)

    def test_absolute_padding_is_not_a_fixup(self):
        machine, model = self.map_image(relocation_image(entries=(0x33c0, 0x0fff)))
        self.assertEqual(model.report()['modules'][0]['relocation_highlow_count'], 1)
        self.assertEqual(struct.unpack('<I', machine.mem_read(0x610013c0, 4))[0], 0x61001020)

    def test_multiple_blocks_and_zero_filled_target(self):
        data = relocation_image()
        # A second block targets the final valid DWORD in virtual zero fill.
        data[0x60c:0x618] = struct.pack('<IIHH', 0x1000, 12, 0x3ffc, 0)
        struct.pack_into('<I', data, 0x98 + 96 + 5 * 8 + 4, 24)
        machine, model = self.map_image(data)
        self.assertEqual(model.report()['modules'][0]['relocation_highlow_count'], 2)
        self.assertEqual(struct.unpack('<I', machine.mem_read(0x61001ffc, 4))[0], 0x01000000)

    def test_invalid_directory_never_partially_mutates_private_image(self):
        data = relocation_image(entries=(0x33c0, 0x13c4))
        pe = pefile.PE(data=bytes(data))
        image = bytearray(pe.get_memory_mapped_image())
        before = bytes(image)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            relocate_reference_image(pe, bytes(data), image, 0x61000000)
        self.assertEqual(bytes(image), before)

    def test_base_overrides_validate_before_mapping(self):
        invalid = [[('missing.dll', 0x61000000)], [('kernel32.dll', True)],
                   [('kernel32.dll', 0)], [('kernel32.dll', -4096)],
                   [('kernel32.dll', 2**32)], [('kernel32.dll', 0x61000001)],
                   [('kernel32.dll', 1.0)], [('kernel32.dll', '0x61000000')],
                   [('kernel32.dll', 0x61000000), ('KERNEL32.dll', 0x62000000)],
                   [('folder/kernel32.dll', 0x61000000)], [('C:\\kernel32.dll', 0x61000000)],
                   [(None, 0x61000000)], [('', 0x61000000)]]
        for overrides in invalid:
            machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                ModuleModel(machine, [Path('kernel32.dll')], [], module_bases=overrides)
            self.assertEqual(list(machine.mem_regions()), [])

    def test_actual_range_overflow_and_collisions_rejected(self):
        with self.assertRaisesRegex(ValueError, 'address range'):
            self.map_image(relocation_image(), 0xfffff000)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            self.map_image(relocation_image(), occupied=[(0x61001000, 4096)])
        with self.assertRaisesRegex(ValueError, 'Duplicate module basename'):
            ModuleModel(uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32),
                        [Path('kernel32.dll'), Path('sub/KERNEL32.dll')], [])


if __name__ == '__main__':
    unittest.main()
