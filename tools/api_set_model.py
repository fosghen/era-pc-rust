"""Explicit, read-only API-set schema v6 lookup; no loading or API execution.

The public contract/schema distinction is described by Microsoft:
https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation
The v6 layout and last-hyphen hashed-prefix algorithm are verified against the
explicit local schema and x86 ntdll, not promised as a general Windows ABI.
Only a unique entry with one default, nonempty host is supported. A file schema
does not establish the composed namespace of an actual running process.
"""
import hashlib
from pathlib import Path
import re
import struct

import pefile


MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 16384
MAX_VALUES = 16384
CONTRACT = re.compile(r'(?:api|ext)-[a-z0-9]+(?:-[a-z0-9]+)+\Z', re.ASCII)
HOST = re.compile(r'[a-z0-9_-]+\.dll\Z', re.ASCII)


def bounded_file(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('API-set source exceeds 16-MiB limit')
    return raw


def contract_name(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 260 or not name.isascii():
        raise ValueError('API-set name must be an ASCII basename')
    normalized = name.lower()
    if normalized.endswith('.dll'):
        normalized = normalized[:-4]
    if not CONTRACT.fullmatch(normalized) or not normalized.rsplit('-', 1)[1].isdigit():
        raise ValueError('Unsupported API-set contract basename')
    return normalized


def prefix_hash(prefix, factor):
    result = 0
    for character in prefix:
        result = (result * factor + ord(character)) & 0xffffffff
    return result


class ApiSetSchema:
    def __init__(self, path):
        self.path = Path(path)
        raw = bounded_file(self.path)
        self.sha256 = hashlib.sha256(raw).hexdigest()
        try:
            pe = pefile.PE(data=raw, fast_load=True)
        except pefile.PEFormatError as error:
            raise ValueError('Invalid API-set PE image') from error
        sections = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.apiset']
        if len(sections) != 1:
            raise ValueError('Expected exactly one .apiset section')
        section = sections[0]
        start, raw_size = section.PointerToRawData, section.SizeOfRawData
        if (not 28 <= raw_size <= MAX_BYTES or not 28 <= section.Misc_VirtualSize <= MAX_BYTES
                or not 0 <= start <= len(raw) - raw_size
                or section.VirtualAddress + section.Misc_VirtualSize > pe.OPTIONAL_HEADER.SizeOfImage):
            raise ValueError('Invalid or truncated .apiset section bounds')
        data = raw[start:start + raw_size]
        version, size, flags, count, entry_offset, hash_offset, factor = struct.unpack_from('<7I', data)
        if version != 6:
            raise ValueError('Only API-set schema version 6 is supported')
        if flags:
            raise ValueError('Unsupported API-set namespace flags')
        if not 28 <= size <= min(raw_size, section.Misc_VirtualSize):
            raise ValueError('API-set namespace size outside section')
        if count > MAX_ENTRIES:
            raise ValueError('API-set entry count exceeds limit')
        data = data[:size]
        self.namespace_sha256 = hashlib.sha256(data).hexdigest()
        self.size, self.flags, self.factor = size, flags, factor
        self.entry_offset, self.hash_offset = entry_offset, hash_offset
        self.section_rva, self.section_raw_offset = section.VirtualAddress, start

        def bounds(offset, length):
            if not 0 <= offset <= size or not 0 <= length <= size - offset:
                raise ValueError('API-set field outside namespace bounds')

        def array_bounds(offset, length):
            if length == 0:
                bounds(offset, 0)
                return
            if offset < 28 or offset % 4:
                raise ValueError('Invalid API-set array alignment or header overlap')
            bounds(offset, length)

        def string(offset, length):
            bounds(offset, length)
            if length > 520:
                raise ValueError('API-set string exceeds 260-character limit')
            if offset % 2 or length % 2:
                raise ValueError('Invalid API-set UTF16 alignment or length')
            try:
                value = data[offset:offset + length].decode('utf-16-le')
            except UnicodeError as error:
                raise ValueError('Invalid API-set UTF16 encoding') from error
            if not value.isascii() or '\0' in value:
                raise ValueError('API-set strings must be ASCII without embedded NUL')
            return value

        array_bounds(entry_offset, count * 24)
        array_bounds(hash_offset, count * 8)
        self.entries = []
        total_values = 0
        for index in range(count):
            entry_flags, no, nl, hl, vo, vc = struct.unpack_from('<6I', data, entry_offset + index * 24)
            # Only these values occur in the inspected v6 namespace. Do not
            # silently accept additional, unmodeled entry-flag semantics.
            if entry_flags not in (0, 1):
                raise ValueError('Unsupported API-set entry flags')
            name = string(no, nl)
            normalized = contract_name(name)
            if name.lower() != normalized:
                raise ValueError('Namespace contract names must omit the DLL suffix')
            if hl > nl or hl % 2:
                raise ValueError('Invalid API-set hashed length')
            prefix = string(no, hl).lower()
            if prefix != normalized.rsplit('-', 1)[0]:
                raise ValueError('Unsupported API-set hashed-prefix form')
            total_values += vc
            if total_values > MAX_VALUES:
                raise ValueError('API-set value count exceeds limit')
            array_bounds(vo, vc * 20)
            values = []
            for value_index in range(vc):
                vf, alias_offset, alias_length, host_offset, host_length = struct.unpack_from(
                    '<5I', data, vo + value_index * 20)
                values.append(dict(flags=vf, alias=string(alias_offset, alias_length),
                                   host=string(host_offset, host_length)))
            self.entries.append(dict(name=name, prefix=prefix, flags=entry_flags, values=values))
        self.hash_index = {}
        seen = set()
        previous_hash = -1
        for position in range(count):
            value, index = struct.unpack_from('<II', data, hash_offset + position * 8)
            if index >= count or index in seen:
                raise ValueError('API-set hash indices must be a complete permutation')
            if value < previous_hash:
                raise ValueError('API-set hash table is not sorted')
            if value != prefix_hash(self.entries[index]['prefix'], factor):
                raise ValueError('API-set hash does not match entry prefix')
            self.hash_index.setdefault(value, []).append(index)
            seen.add(index)
            previous_hash = value

    def resolve(self, name):
        normalized = contract_name(name)
        prefix = normalized.rsplit('-', 1)[0]
        hashed = prefix_hash(prefix, self.factor)
        matches = [index for index in self.hash_index.get(hashed, [])
                   if self.entries[index]['prefix'] == prefix]
        if not matches:
            raise ValueError('API-set contract not found in explicit schema')
        if len(matches) != 1:
            raise ValueError('Ambiguous API-set hashed prefix')
        index = matches[0]
        entry = self.entries[index]
        values = entry['values']
        if len(values) != 1 or values[0]['alias'] or values[0]['flags']:
            raise ValueError('Only a sole default API-set host value is supported')
        host = values[0]['host'].lower()
        if not HOST.fullmatch(host):
            raise ValueError('API-set host must be a nonempty DLL basename')
        return dict(requested=name, namespace_entry=entry['name'], prefix=prefix,
                    host=host, hash=hex(hashed), entry_index=index, entry_flags=entry['flags'])

    def report(self):
        if hashlib.sha256(bounded_file(self.path)).hexdigest() != self.sha256:
            raise RuntimeError('API-set source changed during trace')
        return dict(name=self.path.name, sha256=self.sha256, namespace_sha256=self.namespace_sha256,
                    version=6, size=self.size, flags=self.flags, entry_count=len(self.entries),
                    entry_flag_values=sorted({entry['flags'] for entry in self.entries}),
                    entry_offset=self.entry_offset, hash_offset=self.hash_offset, hash_factor=self.factor,
                    section_rva=hex(self.section_rva), section_raw_offset=self.section_raw_offset,
                    input_unchanged=True,
                    limitations='Explicit file schema, not a live composed process namespace; v6 hashed-prefix lookup only; '
                                'one default host only; no selector overrides, host loading, DLL initialization, '
                                'API execution, revision-availability checks or schema extensions')
