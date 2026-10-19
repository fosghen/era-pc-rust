"""NLS layout tests assembled from artificial data, not Windows tables."""
from pathlib import Path
import struct
import tempfile
import unittest

from nls_model import NlsModel


def synthetic_codepage():
    data = bytearray(546 + 65536)
    struct.pack_into('<7H', data, 0, 13, 1251, 1, 63, 63, 63, 63)
    struct.pack_into('<H', data, 26, 259)
    struct.pack_into('<256H', data, 28, *range(256))
    data[546:] = bytes(range(256)) * 256
    return data


def synthetic_sort():
    records = struct.pack('<9H', 1, 2, 4, 10, 20, 40, 100, 200, 400)
    index = struct.pack('<256H', *([512] * 256))
    index += struct.pack('<16H', *([544] * 16))
    index += bytes(i % 3 for i in range(16))
    section = struct.pack('<2H', 4 + len(records) + len(index), 2 + len(records)) + records + index
    return bytearray(struct.pack('<4I', 16, 16, 16, 16 + len(section)) + section)


def synthetic_case():
    upper = [256] * 256 + [272] * 16 + [0] * 16
    lower = list(upper)
    upper[273] = 32
    lower[273] = 65504
    return bytearray(struct.pack('<' + 'H' * (2 + len(upper) + len(lower)), 1, len(upper), *upper, *lower))


class NlsModelTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='era-nls-test-')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.cp, self.sort, self.case = [root / name for name in ('cp.nls', 'sort.nls', 'case.nls')]
        self.cp.write_bytes(synthetic_codepage())
        self.sort.write_bytes(synthetic_sort())
        self.case.write_bytes(synthetic_case())

    def test_all_single_byte_values_roundtrip_with_explicit_file(self):
        model = NlsModel(self.cp)
        data = bytes(range(256))
        wide = model.to_wide(data)
        self.assertEqual(wide, struct.pack('<256H', *range(256)))
        self.assertEqual(model.from_wide_exact(wide), data)
        with self.assertRaisesRegex(ValueError, 'Best-fit'):
            model.from_wide_exact('я'.encode('utf-16-le'))
        self.assertTrue(model.report()['inputs'][0]['input_unchanged'])

    def test_classification_three_planes_and_index_levels(self):
        model = NlsModel(sort_path=self.sort)
        raw = struct.pack('<4H', 0, 1, 2, 0xfffe)
        self.assertEqual(model.classify(raw, 1), struct.pack('<4H', 1, 10, 100, 100))
        self.assertEqual(model.classify(raw, 2), struct.pack('<4H', 2, 20, 200, 200))
        self.assertEqual(model.classify(raw, 4), struct.pack('<4H', 4, 40, 400, 400))
        with self.assertRaises(ValueError):
            model.classify(raw, 3)

    def test_case_tables_and_signed_deltas(self):
        model = NlsModel(case_path=self.case)
        self.assertEqual(model.map_case('A'.encode('utf-16-le'), True), 'a'.encode('utf-16-le'))
        self.assertEqual(model.map_case('a'.encode('utf-16-le'), False), 'A'.encode('utf-16-le'))
        self.assertEqual(model.map_case('B'.encode('utf-16-le'), True), 'B'.encode('utf-16-le'))

    def test_absent_references_are_not_approximated(self):
        model = NlsModel()
        for function, args in [(model.to_wide, (b'a',)), (model.from_wide_exact, (b'a\0',)),
                               (model.classify, (b'a\0', 1)), (model.map_case, (b'a\0', True))]:
            with self.assertRaises(ValueError):
                function(*args)

    def test_codepage_header_ranges_and_ascii_invariants(self):
        for offset, value in [(2, 932), (4, 2), (26, 65535), (540, 1), (542, 1), (28 + 2 * 65, 0)]:
            data = synthetic_codepage()
            struct.pack_into('<H', data, offset, value)
            self.cp.write_bytes(data)
            with self.assertRaises(ValueError):
                NlsModel(self.cp)
        self.cp.write_bytes(b'bad')
        with self.assertRaises(ValueError):
            NlsModel(self.cp)

    def test_malformed_sort_offsets_and_record_indexes(self):
        data = synthetic_sort()
        struct.pack_into('<I', data, 12, len(data) + 1)
        self.sort.write_bytes(data)
        with self.assertRaises(ValueError):
            NlsModel(sort_path=self.sort)
        data = synthetic_sort()
        data[-1] = 255
        self.sort.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'record'):
            NlsModel(sort_path=self.sort)

    def test_malformed_case_offset_and_changed_reference(self):
        data = synthetic_case()
        struct.pack_into('<H', data, 4, 65535)
        self.case.write_bytes(data)
        with self.assertRaises(ValueError):
            NlsModel(case_path=self.case)
        model = NlsModel(self.cp)
        self.cp.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            model.report()


if __name__ == '__main__':
    unittest.main()
