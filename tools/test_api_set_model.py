"""API-set parsing tests use independently constructed synthetic PE schemas."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from api_set_model import ApiSetSchema, MAX_BYTES


def synthetic_schema(entries=(('api-ms-win-core-com-l1-1-3', 'combase.dll'),), factor=31):
    """Return PE bytes. Entries are (contract, host) pairs, no external fixtures."""
    count = len(entries)
    hash_offset = 28 + count * 24
    value_offset = hash_offset + count * 8
    namespace = bytearray(value_offset + count * 20)
    hashes = []
    for index, (name, host) in enumerate(entries):
        name_bytes, host_bytes = name.encode('utf-16-le'), host.encode('utf-16-le')
        name_offset = len(namespace)
        namespace.extend(name_bytes)
        host_offset = len(namespace)
        namespace.extend(host_bytes)
        prefix = name.lower().rsplit('-', 1)[0]
        hashed = 0
        for character in prefix:
            hashed = (hashed * factor + ord(character)) & 0xffffffff
        hashes.append((hashed, index))
        struct.pack_into('<6I', namespace, 28 + 24 * index, 1, name_offset,
                         len(name_bytes), len(prefix.encode('utf-16-le')), value_offset + index * 20, 1)
        struct.pack_into('<5I', namespace, value_offset + index * 20,
                         0, 0, 0, host_offset, len(host_bytes))
    struct.pack_into('<7I', namespace, 0, 6, len(namespace), 0, count, 28, hash_offset, factor)
    for index, record in enumerate(sorted(hashes)):
        struct.pack_into('<II', namespace, hash_offset + index * 8, *record)
    raw_size = (len(namespace) + 511) & ~511
    image_size = (0x1000 + len(namespace) + 4095) & ~4095
    data = bytearray(512 + raw_size)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x2102)
    struct.pack_into('<H', data, 0x98, 0x10b)
    for offset, value in [(28, 0x60000000), (32, 4096), (36, 512), (56, image_size),
                          (60, 512), (92, 16)]:
        struct.pack_into('<I', data, 0x98 + offset, value)
    struct.pack_into('<8sIIIIIIHHI', data, 0x178, b'.apiset\0', len(namespace), 0x1000,
                     raw_size, 512, 0, 0, 0, 0, 0x40000040)
    data[512:512 + len(namespace)] = namespace
    return data


class ApiSetSchemaTests(unittest.TestCase):
    def parse(self, data=None):
        temporary = tempfile.TemporaryDirectory(prefix='era-api-set-test-')
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'synthetic-schema.dll'
        path.write_bytes(synthetic_schema() if data is None else data)
        return ApiSetSchema(path)

    def test_resolution_is_case_insensitive_and_uses_hashed_prefix(self):
        schema = self.parse()
        for name in ('api-ms-win-core-com-l1-1-0', 'API-MS-WIN-CORE-COM-L1-1-0.DLL',
                     'api-ms-win-core-com-l1-1-3.dll', 'api-ms-win-core-com-l1-1-999'):
            with self.subTest(name=name):
                self.assertEqual(schema.resolve(name), dict(requested=name,
                    namespace_entry='api-ms-win-core-com-l1-1-3', prefix='api-ms-win-core-com-l1-1',
                    host='combase.dll', hash='0x654b521e', entry_index=0, entry_flags=1))
        with self.assertRaisesRegex(ValueError, 'not found'):
            schema.resolve('api-ms-win-core-com-l1-2-0')

    def test_nonhardcoded_host_and_ext_contract(self):
        schema = self.parse(synthetic_schema([('ext-test-feature-l1-1-8', 'OTHER.DLL')]))
        self.assertEqual(schema.resolve('EXT-TEST-FEATURE-L1-1-0.dll')['host'], 'other.dll')

    def test_only_observed_entry_flags_are_supported_and_reported(self):
        for flags in (0, 1, 2, 3, 0xffffffff):
            with self.subTest(flags=flags):
                data = synthetic_schema()
                struct.pack_into('<I', data, 512 + 28, flags)
                if flags not in (0, 1):
                    with self.assertRaisesRegex(ValueError, 'entry flags'):
                        self.parse(data)
                else:
                    schema = self.parse(data)
                    self.assertEqual(schema.resolve('api-ms-win-core-com-l1-1-0')['entry_flags'], flags)
                    self.assertEqual(schema.report()['entry_flag_values'], [flags])

    def test_reports_bounded_metadata_and_detects_source_mutation(self):
        data = synthetic_schema()
        schema = self.parse(data)
        report = schema.report()
        self.assertEqual(report['name'], 'synthetic-schema.dll')
        self.assertNotIn('path', report)
        self.assertEqual(report['sha256'], hashlib.sha256(data).hexdigest())
        size = struct.unpack_from('<I', data, 516)[0]
        self.assertEqual(report['namespace_sha256'], hashlib.sha256(data[512:512 + size]).hexdigest())
        self.assertEqual(report['entry_count'], 1)
        self.assertTrue(report['input_unchanged'])
        schema.path.write_bytes(data + b'changed')
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            schema.report()

    def test_invalid_requested_names_are_not_paths_or_implicit_aliases(self):
        schema = self.parse()
        for name in (None, '', 1, 'combase.dll', '../api-ms-win-core-com-l1-1-0.dll',
                     r'C:\api-ms-win-core-com-l1-1-0.dll', 'api-test-0.dll.dll',
                     'api-тест-0', 'api-test-0\0', 'api-test-.dll', 'api-test-alpha',
                     'api-' + 'x' * 255 + '-0'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                schema.resolve(name)

    def test_hash_collision_compares_full_prefix(self):
        # Factor zero means these different prefixes collide on their last char.
        schema = self.parse(synthetic_schema([('api-first-l1-1-0', 'one.dll'),
                                             ('api-second-l1-1-0', 'two.dll')], factor=0))
        self.assertEqual(schema.resolve('api-first-l1-1-7')['host'], 'one.dll')
        self.assertEqual(schema.resolve('api-second-l1-1-7')['host'], 'two.dll')
        with self.assertRaisesRegex(ValueError, 'not found'):
            schema.resolve('api-third-l1-1-7')

    def test_duplicate_prefix_is_ambiguous(self):
        schema = self.parse(synthetic_schema([('api-test-l1-1-0', 'one.dll'),
                                             ('api-test-l1-1-3', 'two.dll')]))
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            schema.resolve('api-test-l1-1-1')

    def test_namespace_version_bounds_counts_and_alignment(self):
        for field, value in [(0, 4), (4, 27), (4, 0xffffffff), (8, 1), (12, 16385),
                             (16, 29), (16, 0xfffffffc), (20, 0xfffffffc), (20, 4)]:
            with self.subTest(field=field, value=value):
                data = synthetic_schema()
                struct.pack_into('<I', data, 512 + field, value)
                with self.assertRaises(ValueError):
                    self.parse(data)

    def test_section_and_file_bounds(self):
        for field, value in [(8, 16), (8, MAX_BYTES + 1), (12, 0xfffff000),
                             (16, MAX_BYTES + 1), (20, 0xffffffff)]:
            with self.subTest(field=field, value=value):
                data = synthetic_schema()
                struct.pack_into('<I', data, 0x178 + field, value)
                with self.assertRaises(ValueError):
                    self.parse(data)
        with self.assertRaises(ValueError):
            self.parse(synthetic_schema()[:-1])
        with self.assertRaisesRegex(ValueError, '16-MiB'):
            self.parse(bytes(MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'Invalid API-set PE'):
            self.parse(b'not a PE')

    def test_missing_or_duplicate_section(self):
        data = synthetic_schema()
        data[0x178:0x180] = b'.other\0\0'
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.parse(data)
        data = synthetic_schema()
        struct.pack_into('<H', data, 0x86, 2)
        data[0x1a0:0x1c8] = data[0x178:0x1a0]
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.parse(data)

    def test_entry_and_value_bounds(self):
        for field, value in [(4, 0xfffffffe), (8, 0xfffffffe), (12, 0xffffffff),
                             (12, 2), (16, 0xfffffffc), (20, 16385)]:
            with self.subTest(field=field):
                data = synthetic_schema()
                struct.pack_into('<I', data, 512 + 28 + field, value)
                with self.assertRaises(ValueError):
                    self.parse(data)
        for field in (4, 8, 12, 16):
            with self.subTest(value_field=field):
                data = synthetic_schema()
                value_offset = struct.unpack_from('<I', data, 512 + 28 + 16)[0]
                struct.pack_into('<I', data, 512 + value_offset + field, 0xfffffffe)
                with self.assertRaises(ValueError):
                    self.parse(data)

    def test_invalid_utf16_nonascii_and_null_strings_rejected(self):
        for value in (b'\x00\xd8', b'\x10\x04', b'\0\0'):
            with self.subTest(value=value):
                data = synthetic_schema()
                name_offset = struct.unpack_from('<I', data, 512 + 28 + 4)[0]
                data[512 + name_offset:514 + name_offset] = value
                with self.assertRaises(ValueError):
                    self.parse(data)
        data = synthetic_schema()
        struct.pack_into('<I', data, 512 + 28 + 8, 51)
        with self.assertRaisesRegex(ValueError, 'UTF16'):
            self.parse(data)
        with self.assertRaisesRegex(ValueError, '260-character'):
            self.parse(synthetic_schema([('api-test-l1-1-0', 'x' * 261)]))

    def test_bad_hashes_indices_and_order(self):
        data = synthetic_schema()
        struct.pack_into('<I', data, 512 + 52, 0)
        with self.assertRaisesRegex(ValueError, 'hash does not match'):
            self.parse(data)
        data = synthetic_schema()
        struct.pack_into('<I', data, 512 + 56, 1)
        with self.assertRaisesRegex(ValueError, 'permutation'):
            self.parse(data)
        data = synthetic_schema([('api-first-l1-1-0', 'one.dll'), ('api-second-l1-1-0', 'two.dll')])
        hashes = 512 + 28 + 48
        struct.pack_into('<I', data, hashes + 12, struct.unpack_from('<I', data, hashes + 4)[0])
        with self.assertRaisesRegex(ValueError, 'permutation'):
            self.parse(data)
        data = synthetic_schema([('api-first-l1-1-0', 'one.dll'), ('api-second-l1-1-0', 'two.dll')])
        first, second = data[hashes:hashes + 8], data[hashes + 8:hashes + 16]
        data[hashes:hashes + 16] = second + first
        with self.assertRaisesRegex(ValueError, 'not sorted'):
            self.parse(data)

    def test_selector_multiple_missing_and_flagged_values_stop(self):
        for mode in ('selector', 'multiple', 'missing', 'flags'):
            with self.subTest(mode=mode):
                data = synthetic_schema()
                value_offset = struct.unpack_from('<I', data, 512 + 28 + 16)[0]
                if mode == 'selector':
                    name_offset = struct.unpack_from('<I', data, 512 + 28 + 4)[0]
                    struct.pack_into('<II', data, 512 + value_offset + 4, name_offset, 6)
                elif mode == 'flags':
                    struct.pack_into('<I', data, 512 + value_offset, 1)
                elif mode == 'missing':
                    struct.pack_into('<I', data, 512 + 28 + 20, 0)
                else:
                    # Replace the first name bytes with a second valid value;
                    # move the existing name/host payload first to keep offsets valid.
                    entry = list(struct.unpack_from('<6I', data, 512 + 28))
                    size = struct.unpack_from('<I', data, 516)[0]
                    payload = bytes(data[512 + entry[1]:512 + size])
                    new_offset = size
                    data[512 + new_offset:512 + new_offset + len(payload)] = payload
                    old_name_offset = entry[1]
                    entry[1] = new_offset
                    entry[5] = 2
                    struct.pack_into('<6I', data, 512 + 28, *entry)
                    old_host = struct.unpack_from('<I', data, 512 + value_offset + 12)[0]
                    struct.pack_into('<I', data, 512 + value_offset + 12,
                                     new_offset + old_host - old_name_offset)
                    data[512 + value_offset + 20:512 + value_offset + 40] = data[512 + value_offset:512 + value_offset + 20]
                    struct.pack_into('<I', data, 516, size + len(payload))
                    struct.pack_into('<I', data, 0x178 + 8, size + len(payload))
                schema = self.parse(data)
                with self.assertRaisesRegex(ValueError, 'sole default'):
                    schema.resolve('api-ms-win-core-com-l1-1-0')

    def test_empty_or_path_host_never_resolves(self):
        for host in ('', '../combase.dll', r'C:\combase.dll', 'combase', 'a.dll.bak'):
            with self.subTest(host=host):
                schema = self.parse(synthetic_schema([('api-test-l1-1-0', host)]))
                with self.assertRaisesRegex(ValueError, 'DLL basename'):
                    schema.resolve('api-test-l1-1-0')


if __name__ == '__main__':
    unittest.main()
