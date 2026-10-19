"""Bounded readers for explicitly supplied Windows NLS reference data.

No files are searched automatically or exported. Only the SBCS layout used by
the inspected CP1251 input is accepted. Format references are documented in
docs/CRT_TLS_RESEARCH.md; this is not a full Windows locale implementation.
"""
import hashlib
from pathlib import Path
import struct


class NlsModel:
    def __init__(self, codepage_path=None, sort_path=None, case_path=None):
        self.inputs = []
        self.forward = None
        self.reverse = None
        self.types = None
        self.case_tables = None
        if codepage_path:
            data = self.read(codepage_path, 128 * 1024)
            if len(data) < 546 or struct.unpack_from('<3H', data) != (13, 1251, 1):
                raise ValueError('Unsupported NLS codepage header')
            if self.u16(data, 540) or self.u16(data, 542):
                raise ValueError('Glyph or DBCS tables not supported')
            reverse_start = 28 + 2 * self.u16(data, 26)
            if reverse_start < 544 or reverse_start + 65536 != len(data):
                raise ValueError('Invalid SBCS reverse table range')
            self.forward = struct.unpack_from('<256H', data, 28)
            self.reverse = data[reverse_start:]
            if self.forward[:128] != tuple(range(128)) or self.reverse[:128] != bytes(range(128)):
                raise ValueError('Codepage ASCII invariants failed')
        if sort_path:
            data = self.read(sort_path, 8 * 1024 * 1024)
            if len(data) < 16:
                raise ValueError('Truncated sort header')
            start, end = struct.unpack_from('<II', data, 8)
            if not 16 <= start < end <= len(data):
                raise ValueError('Invalid classification section')
            section = data[start:end]
            index_start = 2 + self.u16(section, 2)
            if not 4 < index_start < len(section) or (index_start - 4) % 6:
                raise ValueError('Invalid classification records')
            records = [struct.unpack_from('<3H', section, i) for i in range(4, index_start, 6)]
            index = section[index_start:]
            decoded = []
            # Three-level byte-offset index: high byte, high nibble, low nibble.
            for high in range(256):
                row = self.u16(index, 2 * high)
                for middle in range(16):
                    leaf = self.u16(index, row + 2 * middle)
                    if leaf + 16 > len(index):
                        raise ValueError('Classification leaf outside section')
                    for record in index[leaf:leaf + 16]:
                        if record >= len(records):
                            raise ValueError('Classification record outside table')
                        decoded.append(records[record])
            self.types = decoded
        if case_path:
            data = self.read(case_path, 1024 * 1024)
            if len(data) % 2 or self.u16(data, 0) != 1:
                raise ValueError('Unsupported case table header')
            split = 2 * (self.u16(data, 2) + 2)
            if not 4 < split <= len(data) - 512:
                raise ValueError('Invalid case table boundary')
            self.case_tables = {}
            for operation, table in [('upper', data[4:split]), ('lower', data[split:])]:
                values = []
                for high in range(256):
                    middle = self.u16(table, 2 * high)
                    for nibble in range(16):
                        leaf = self.u16(table, 2 * (middle + nibble))
                        for low in range(16):
                            code = (high << 8) | (nibble << 4) | low
                            values.append((code + self.u16(table, 2 * (leaf + low))) & 0xffff)
                self.case_tables[operation] = values

    @staticmethod
    def u16(data, offset):
        if not 0 <= offset <= len(data) - 2:
            raise ValueError('NLS offset outside data')
        return struct.unpack_from('<H', data, offset)[0]

    def read(self, path, limit):
        path = Path(path)
        with path.open('rb') as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError('NLS file exceeds model budget')
        self.inputs.append(dict(path=path, sha256=hashlib.sha256(data).hexdigest(), size=len(data)))
        return data

    def to_wide(self, data):
        if self.forward is None:
            raise ValueError('Explicit NLS codepage file required')
        return struct.pack('<' + 'H' * len(data), *(self.forward[b] for b in data))

    def classify(self, raw, kind):
        if self.types is None or kind not in (1, 2, 4) or len(raw) % 2:
            raise ValueError('Explicit NLS sort table and supported CTYPE required')
        column = {1: 0, 2: 1, 4: 2}[kind]
        result = [self.types[value][column] for (value,) in struct.iter_unpack('<H', raw)]
        return struct.pack('<' + 'H' * len(result), *result)

    def from_wide_exact(self, raw):
        if self.reverse is None or len(raw) % 2:
            raise ValueError('Explicit NLS codepage file required')
        result = bytearray()
        for (code,) in struct.iter_unpack('<H', raw):
            value = self.reverse[code]
            if self.forward[value] != code:
                raise ValueError('Best-fit or replacement mapping is not modeled')
            result.append(value)
        return bytes(result)

    def map_case(self, raw, upper):
        if self.case_tables is None or len(raw) % 2:
            raise ValueError('Explicit NLS case table required')
        values = self.case_tables['upper' if upper else 'lower']
        result = [values[code] for (code,) in struct.iter_unpack('<H', raw)]
        return struct.pack('<' + 'H' * len(result), *result)

    def report(self):
        result = []
        for item in self.inputs:
            unchanged = hashlib.sha256(item['path'].read_bytes()).hexdigest() == item['sha256']
            if not unchanged:
                raise RuntimeError('NLS reference file changed during trace')
            result.append(dict(name=item['path'].name, sha256=item['sha256'], size=item['size'], input_unchanged=True))
        return dict(inputs=result, limitations='SBCS CP1251, BMP classification and simple case table data only; no native NLS execution, linguistic casing, normalization or best-fit replacement')
