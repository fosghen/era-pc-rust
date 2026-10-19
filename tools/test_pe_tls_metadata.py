"""Independent synthetic PE fixtures; no vendor code is executed or required."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pe_tls_metadata import inspect_tls


BASE = 0x400000
OPTIONAL = 0x98
SECTIONS = OPTIONAL + 224
DIRECTORY = OPTIONAL + 96 + 9 * 8
TLS = 0x300


def synthetic_tls():
    data = bytearray(0xa00)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, 2, 0, 0, 0, 224, 0x102)
    struct.pack_into('<H', data, OPTIONAL, 0x10b)
    struct.pack_into('<III', data, OPTIONAL + 28, BASE, 0x1000, 0x200)
    struct.pack_into('<II', data, OPTIONAL + 56, 0x3000, 0x200)
    struct.pack_into('<I', data, OPTIONAL + 92, 16)
    struct.pack_into('<II', data, DIRECTORY, 0x1100, 24)
    for offset, name, rva, virtual_size, raw_size, raw_offset, flags in [
            (SECTIONS, b'.data', 0x1000, 0x1000, 0x600, 0x200, 0xc0000040),
            (SECTIONS + 40, b'.text', 0x2000, 0x1000, 0x200, 0x800, 0x60000020)]:
        struct.pack_into('<8sIIIIIIHHI', data, offset, name, virtual_size, rva,
                         raw_size, raw_offset, 0, 0, 0, 0, flags)
    struct.pack_into('<6I', data, TLS, BASE + 0x1200, BASE + 0x1204,
                     BASE + 0x1300, BASE + 0x1400, 8, 0x00300000)
    data[0x400:0x404] = b'TEST'
    struct.pack_into('<II', data, 0x600, BASE + 0x2000, 0)
    return data


def fields(data, **changes):
    names = ('start', 'end', 'index', 'callbacks', 'zero_fill', 'characteristics')
    for name, value in changes.items():
        struct.pack_into('<I', data, TLS + 4 * names.index(name), value)
    return data


class TlsMetadataTests(unittest.TestCase):
    def inspect(self, data=None):
        data = synthetic_tls() if data is None else data
        directory = tempfile.TemporaryDirectory(prefix='era-tls-metadata-')
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'fixture.exe'
        self.path.write_bytes(data)
        result = inspect_tls(self.path)
        self.assertEqual(self.path.read_bytes(), data)
        self.assertTrue(result['input_unchanged'])
        self.assertFalse(result['readiness']['native_ready'])
        return result

    def assert_invalid(self, data, field=None):
        result = self.inspect(data)
        self.assertEqual(result['metadata_status'], 'invalid_or_unsupported')
        errors = [d for d in result['diagnostics'] if d['severity'] == 'error']
        self.assertTrue(errors)
        if field:
            self.assertEqual(errors[0]['field'], field)
        return result

    def test_valid_sizes_hashes_callbacks_and_read_only_report(self):
        result = self.inspect()
        self.assertEqual(result['metadata_status'], 'metadata_valid')
        self.assertEqual(result['diagnostics'], [])
        template = result['template']
        self.assertEqual((template['initialized_size'], template['zero_fill_size'], template['total_size']), (4, 8, 12))
        self.assertEqual(template['disk_template_sha256'], hashlib.sha256(b'TEST').hexdigest())
        self.assertEqual(template['storage']['disk_backing'], 'complete')
        self.assertFalse(template['runtime_template_verified'])
        self.assertEqual(result['alignment_bytes'], 4)
        self.assertEqual(result['callback_count'], 1)
        self.assertEqual(result['callbacks'][0]['va'], '0x402000')
        serialized = json.dumps(result)
        self.assertNotIn('TEST', serialized)
        self.assertNotIn(str(self.path.parent), serialized)

    def test_no_tls_and_absent_directory_slot(self):
        for absent in (False, True):
            data = synthetic_tls()
            struct.pack_into('<II', data, DIRECTORY, 0, 0)
            if absent:
                struct.pack_into('<I', data, OPTIONAL + 92, 9)
            result = self.inspect(data)
            self.assertEqual(result['metadata_status'], 'no_tls')
            self.assertFalse(result['tls_present'])

    def test_empty_template_and_zero_fill_only(self):
        result = self.inspect(fields(synthetic_tls(), start=0, end=0, zero_fill=32, callbacks=0))
        self.assertEqual(result['metadata_status'], 'metadata_valid')
        self.assertEqual(result['template']['total_size'], 32)
        self.assertEqual(result['template']['disk_template_sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(result['callback_array_status'], 'null_pointer')

    def test_virtual_only_and_partial_template_are_not_malformed(self):
        for start, size, backed, status in [(0x1620, 60, 0, 'unavailable'), (0x15fc, 8, 4, 'partial')]:
            with self.subTest(status=status):
                result = self.inspect(fields(synthetic_tls(), start=BASE + start, end=BASE + start + size))
                self.assertEqual(result['metadata_status'], 'metadata_valid')
                template = result['template']
                self.assertIsNone(template['disk_template_sha256'])
                self.assertEqual(template['storage']['file_backed_size'], backed)
                self.assertEqual(template['storage']['virtual_only_size'], size - backed)
                self.assertEqual(template['storage']['disk_backing'], status)

    def test_bss_index_and_readonly_index_warning(self):
        for index, warning in [(0x1700, False), (0x2000, True)]:
            result = self.inspect(fields(synthetic_tls(), index=BASE + index))
            self.assertEqual(result['metadata_status'], 'metadata_valid')
            self.assertEqual(any(d['field'] == 'tls_index' for d in result['diagnostics']), warning)

    def test_unavailable_directory_not_zero_initialized(self):
        data = synthetic_tls()
        struct.pack_into('<II', data, DIRECTORY, 0x1700, 24)
        result = self.inspect(data)
        self.assertEqual(result['metadata_status'], 'metadata_unavailable')
        self.assertNotIn('tls_fields', result)

    def test_unknown_callback_slots_do_not_imply_null_termination(self):
        for address, count in [(0x1700, 0), (0x15fc, 1)]:
            data = fields(synthetic_tls(), callbacks=BASE + address)
            if count:
                struct.pack_into('<I', data, 0x7fc, BASE + 0x2000)
            result = self.inspect(data)
            self.assertEqual(result['metadata_status'], 'metadata_valid')
            self.assertEqual(result['callback_array_status'], 'incomplete_disk_backing')
            self.assertIsNone(result['callback_count'])
            self.assertEqual(len(result['callbacks']), count)

    def test_empty_callback_array_and_virtual_target(self):
        data = synthetic_tls()
        struct.pack_into('<I', data, 0x600, 0)
        self.assertEqual(self.inspect(data)['callback_count'], 0)
        struct.pack_into('<I', data, 0x600, BASE + 0x2300)
        result = self.inspect(data)
        self.assertEqual(result['metadata_status'], 'metadata_valid')
        self.assertEqual(result['callbacks'][0]['storage']['disk_backing'], 'unavailable')

    def test_null_reversed_outside_and_gap_fields(self):
        for changes, field in [({'start': 0}, 'template'), ({'end': BASE + 0x11ff}, 'template'),
                ({'start': BASE - 4, 'end': BASE}, 'template'),
                ({'start': BASE + 0x800, 'end': BASE + 0x804}, 'template'),
                ({'index': 0}, 'tls_index'), ({'index': BASE + 0x2fff}, 'tls_index'),
                ({'callbacks': 3}, 'callback_array')]:
            with self.subTest(changes=changes):
                self.assert_invalid(fields(synthetic_tls(), **changes), field)

    def test_template_and_reserved_characteristic_limits(self):
        for changes, field in [({'zero_fill': 1024 * 1024}, 'template.size'),
                ({'characteristics': 1}, 'tls_characteristics'),
                ({'characteristics': 0xf00000}, 'tls_characteristics')]:
            self.assert_invalid(fields(synthetic_tls(), **changes), field)

    def test_directory_size_range_and_pair_validation(self):
        for rva, size in [(0, 24), (0x1100, 0), (0x1100, 23), (0x1100, 4097), (0x2ff0, 24)]:
            data = synthetic_tls()
            struct.pack_into('<II', data, DIRECTORY, rva, size)
            self.assert_invalid(data)

    def test_callback_target_bounds_and_unterminated_limit(self):
        data = synthetic_tls()
        struct.pack_into('<I', data, 0x600, BASE + 0x3000)
        self.assert_invalid(data, 'callbacks[0]')
        data = fields(synthetic_tls(), callbacks=BASE + 0x1300)
        for offset in range(129):
            struct.pack_into('<I', data, 0x500 + offset * 4, BASE + 0x2000)
        self.assert_invalid(data, 'callback_array')

    def test_exact_callback_limit_is_accepted(self):
        data = fields(synthetic_tls(), callbacks=BASE + 0x1300)
        for offset in range(128):
            struct.pack_into('<I', data, 0x500 + offset * 4, BASE + 0x2000)
        struct.pack_into('<I', data, 0x700, 0)
        self.assertEqual(self.inspect(data)['callback_count'], 128)

    def test_truncated_file_sections_and_overlap(self):
        self.assert_invalid(synthetic_tls()[:-1], 'sections[1].raw_range')
        data = synthetic_tls()
        struct.pack_into('<I', data, SECTIONS + 40 + 12, 0x1100)
        self.assert_invalid(data, 'tls_directory')
        self.assert_invalid(bytearray(b'not a PE'), 'pe_headers')

    def test_wrong_machine_format_and_optional_header_bounds(self):
        for offset, fmt, value in [(0x84, '<H', 0x8664), (OPTIONAL, '<H', 0x20b),
                (OPTIONAL + 92, '<I', 17), (OPTIONAL + 56, '<I', 0xffffffff),
                (OPTIONAL + 60, '<I', 0x100)]:
            data = synthetic_tls()
            struct.pack_into(fmt, data, offset, value)
            self.assert_invalid(data)

    def test_source_change_and_size_caps(self):
        data = bytes(synthetic_tls())
        with patch('pe_tls_metadata.bounded_read', side_effect=[data, data + b'x']):
            result = inspect_tls('not-opened.exe')
        self.assertFalse(result['input_unchanged'])
        self.assertEqual(result['metadata_status'], 'invalid_or_unsupported')
        self.inspect()
        with patch('pe_tls_metadata.MAX_FILE', 10):
            result = inspect_tls(self.path)
        self.assertEqual(result['metadata_status'], 'invalid_or_unsupported')
        self.assertEqual(result['diagnostics'][0]['field'], 'source')

    def test_cli_json_and_status_codes(self):
        for valid in (True, False):
            data = synthetic_tls() if valid else b'bad'
            self.inspect(data)
            process = subprocess.run([sys.executable, str(Path(__file__).with_name('pe_tls_metadata.py')),
                                      str(self.path)], capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 0 if valid else 2)
            self.assertEqual(process.stderr, '')
            self.assertEqual(json.loads(process.stdout)['name'], 'fixture.exe')
            self.assertEqual(self.path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
