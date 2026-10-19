"""Bounded read-only PE32 static TLS metadata, never a Windows loader.

Specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section
TLS pointers are preferred-image VAs, not RVAs. EndAddressOfRawData is treated
as the exclusive end of the initialized template. Virtual-only storage is not
malformed and is never silently replaced with assumed runtime zero bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile


MAX_FILE = 64 * 1024 * 1024
MAX_IMAGE = 256 * 1024 * 1024
MAX_TLS = 1024 * 1024
MAX_CALLBACKS = 128
MAX_DIRECTORY = 4096


class MetadataError(ValueError):
    def __init__(self, field, message):
        super().__init__(message)
        self.field = field


def bounded_read(path):
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise MetadataError('source', 'Source exceeds 64-MiB analysis limit')
    return data


class ImageReader:
    def __init__(self, raw):
        self.raw = raw
        try:
            self.pe = pefile.PE(data=raw, fast_load=True)
        except pefile.PEFormatError as error:
            raise MetadataError('pe_headers', 'Invalid or truncated PE headers') from error
        pe = self.pe
        if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
            raise MetadataError('pe_headers', 'Only x86 PE32 images are supported')
        optional_size = pe.FILE_HEADER.SizeOfOptionalHeader
        optional_end = pe.DOS_HEADER.e_lfanew + 24 + optional_size
        if optional_size < 96 or optional_end > len(raw):
            raise MetadataError('pe_headers', 'Truncated PE32 optional header')
        if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes > (optional_size - 96) // 8:
            raise MetadataError('pe_headers', 'Declared data directories exceed optional header')
        self.base, self.size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
        if not 0 < self.size <= MAX_IMAGE or self.base + self.size > 2**32:
            raise MetadataError('image_range', 'Preferred image range exceeds x86 bounds or 256-MiB limit')
        headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        if not 0 < headers <= min(len(raw), self.size):
            raise MetadataError('headers_range', 'Declared headers are outside file or image')
        if optional_end + 40 * pe.FILE_HEADER.NumberOfSections > headers:
            raise MetadataError('sections', 'Section table extends beyond declared headers')
        if len(pe.sections) != pe.FILE_HEADER.NumberOfSections or len(pe.sections) > 96:
            raise MetadataError('sections', 'Incomplete section table or section-count limit exceeded')
        self.regions = [dict(start=0, end=headers, raw_offset=0, raw_size=headers,
                             name='headers', flags=0x40000000)]
        for index, section in enumerate(pe.sections):
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if section.VirtualAddress + size > self.size:
                raise MetadataError(f'sections[{index}].virtual_range', 'Section extends outside declared image')
            if section.SizeOfRawData and section.PointerToRawData + section.SizeOfRawData > len(raw):
                raise MetadataError(f'sections[{index}].raw_range', 'Section raw data is truncated in source file')
            if size:
                self.regions.append(dict(start=section.VirtualAddress, end=section.VirtualAddress + size,
                    raw_offset=section.PointerToRawData, raw_size=section.SizeOfRawData,
                    name=section.Name.rstrip(b'\0').decode('ascii', errors='replace'),
                    flags=section.Characteristics))

    def va_rva(self, address, size, field):
        rva = address - self.base
        if not address or not 0 <= rva <= self.size or not 0 <= size <= self.size - rva:
            raise MetadataError(field, 'VA interval is outside the preferred image or is NULL')
        return rva

    def chunks(self, rva, size, field):
        if not 0 <= rva <= self.size or not 0 <= size <= self.size - rva:
            raise MetadataError(field, 'RVA interval is outside declared image')
        end = rva + size
        while rva < end:
            matches = [region for region in self.regions if region['start'] <= rva < region['end']]
            if len(matches) != 1:
                raise MetadataError(field, 'RVA interval falls in a gap or overlapping image regions')
            region = matches[0]
            stop = min([end, region['end']] + [r['start'] for r in self.regions if rva < r['start'] < end])
            length = stop - rva
            backed = min(length, max(0, region['raw_size'] - (rva - region['start'])))
            yield rva, length, backed, region
            rva = stop

    def storage(self, rva, size, field):
        pieces = list(self.chunks(rva, size, field))
        backed = sum(piece[2] for piece in pieces)
        return dict(size=size, file_backed_size=backed, virtual_only_size=size - backed,
            disk_backing='complete' if backed == size else ('partial' if backed else 'unavailable'),
            sections=list(dict.fromkeys(piece[3]['name'] for piece in pieces)),
            writable_by_section_flags=all(piece[3]['flags'] & 0x80000000 != 0 for piece in pieces) if pieces else None,
            executable_by_section_flags=all(piece[3]['flags'] & 0x20000000 != 0 for piece in pieces) if pieces else None)

    def disk_bytes(self, rva, size, field):
        pieces = list(self.chunks(rva, size, field))
        if any(length != backed for _, length, backed, _ in pieces):
            return None
        return b''.join(self.raw[region['raw_offset'] + address - region['start']:
                                 region['raw_offset'] + address - region['start'] + length]
                        for address, length, _, region in pieces)


def inspect_tls(path):
    """Return JSON-ready metadata/diagnostics; no mapped image or template bytes."""
    path = Path(path)
    result = dict(name=path.name, metadata_status='invalid_or_unsupported', diagnostics=[],
        readiness=dict(native_ready=False, runtime_verified=False,
            limitations='Disk metadata only; no relocations, TLS allocation, index assignment, TEB/TLS-array setup, '
                        'callbacks, DllMain, dependency initialization, mapping or execution; absence of TLS is not worker readiness'),
        limits=dict(file_bytes=MAX_FILE, image_bytes=MAX_IMAGE, total_tls_bytes=MAX_TLS, callbacks=MAX_CALLBACKS))
    raw = None

    def warning(field, message):
        result['diagnostics'].append(dict(severity='warning', field=field, message=message))

    def parse():
        image = ImageReader(raw)
        result.update(machine='x86', pe_format='PE32', preferred_image_base=hex(image.base), image_size=image.size)
        directories = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        directory = directories[9] if len(directories) > 9 else None
        rva, size = (directory.VirtualAddress, directory.Size) if directory else (0, 0)
        if not rva and not size:
            result.update(tls_present=False, metadata_status='no_tls')
            return
        result['tls_present'] = True
        if not rva or not size:
            raise MetadataError('tls_directory', 'Directory RVA and size must both be nonzero, or both zero for absent TLS')
        if not 24 <= size <= MAX_DIRECTORY:
            raise MetadataError('tls_directory.size', 'PE32 TLS directory must contain 24 bytes and fit the 4096-byte limit')
        result['tls_directory'] = dict(rva=hex(rva), declared_size=size,
                                      storage=image.storage(rva, size, 'tls_directory'))
        data = image.disk_bytes(rva, 24, 'tls_directory')
        if data is None:
            warning('tls_directory', 'TLS directory fields are not fully file-backed; runtime metadata is unknown')
            result['metadata_status'] = 'metadata_unavailable'
            return
        if size > 24:
            warning('tls_directory.size', 'Bytes after the standard 24-byte PE32 TLS header are not interpreted')
        start, end, index, callbacks, zero_fill, characteristics = struct.unpack('<6I', data)
        result['tls_fields'] = dict(template_start_va=hex(start), template_end_va=hex(end),
            index_va=hex(index), callbacks_va=hex(callbacks), zero_fill_size=zero_fill,
            characteristics=hex(characteristics))
        if bool(start) != bool(end):
            raise MetadataError('template', 'Template start/end must either both be NULL or both be non-NULL')
        if end < start:
            raise MetadataError('template', 'Template end VA precedes start VA')
        initialized = end - start
        if initialized + zero_fill > MAX_TLS:
            raise MetadataError('template.size', 'Initialized template plus zero fill exceeds 1-MiB limit')
        template_rva = image.va_rva(start, initialized, 'template') if start else 0
        storage = image.storage(template_rva, initialized, 'template')
        template = image.disk_bytes(template_rva, initialized, 'template')
        result['template'] = dict(initialized_size=initialized, zero_fill_size=zero_fill,
            total_size=initialized + zero_fill, storage=storage,
            disk_template_sha256=hashlib.sha256(template).hexdigest() if template is not None else None,
            runtime_template_verified=False)
        if template is None:
            warning('template', 'Template has virtual-only storage; disk bytes cannot establish runtime contents or a complete template SHA')
        alignment = (characteristics >> 20) & 0xf
        if characteristics & ~0x00f00000 or alignment == 15:
            raise MetadataError('tls_characteristics', 'Reserved TLS characteristic bits or unsupported alignment encoding')
        result['alignment_bytes'] = (1 << (alignment - 1)) if alignment else None
        index_rva = image.va_rva(index, 4, 'tls_index')
        result['index_storage'] = dict(rva=hex(index_rva), **image.storage(index_rva, 4, 'tls_index'))
        if not result['index_storage']['writable_by_section_flags']:
            warning('tls_index', 'Index storage is not writable according to section flags; runtime loader behavior is not established')
        result.update(callbacks=[], callback_count=0, callback_array_status='null_pointer')
        if callbacks:
            array_rva = image.va_rva(callbacks, 4, 'callback_array')
            result['callback_array_rva'] = hex(array_rva)
            for position in range(MAX_CALLBACKS + 1):
                slot_rva = array_rva + 4 * position
                slot = image.disk_bytes(slot_rva, 4, f'callback_array[{position}]')
                if slot is None:
                    warning('callback_array', f'Callback slot {position} is not fully file-backed; NULL termination and final callback count are unknown')
                    result.update(callback_count=None, callback_array_status='incomplete_disk_backing')
                    break
                address = struct.unpack('<I', slot)[0]
                if not address:
                    result.update(callback_count=position, callback_array_status='null_terminated')
                    break
                if position == MAX_CALLBACKS:
                    raise MetadataError('callback_array', 'No NULL terminator within the 128-callback analysis limit')
                target_rva = image.va_rva(address, 1, f'callbacks[{position}]')
                target = image.storage(target_rva, 1, f'callbacks[{position}]')
                result['callbacks'].append(dict(va=hex(address), rva=hex(target_rva), storage=target))
                if not target['executable_by_section_flags']:
                    warning(f'callbacks[{position}]', 'Callback target is not executable according to section flags; no runtime execution assessment')
                if target['disk_backing'] != 'complete':
                    warning(f'callbacks[{position}]', 'Callback target bytes unavailable on disk; runtime contents unknown')
        result['metadata_status'] = 'metadata_valid'

    try:
        raw = bounded_read(path)
        result.update(source_sha256=hashlib.sha256(raw).hexdigest(), source_size=len(raw))
        parse()
    except MetadataError as error:
        result['diagnostics'].append(dict(severity='error', field=error.field, message=str(error)))
    except OSError as error:
        result['diagnostics'].append(dict(severity='error', field='source', message=error.strerror or type(error).__name__))
    if raw is not None:
        try:
            unchanged = hashlib.sha256(bounded_read(path)).hexdigest() == result['source_sha256']
        except (OSError, MetadataError):
            unchanged = False
        result['input_unchanged'] = unchanged
        if not unchanged:
            result['metadata_status'] = 'invalid_or_unsupported'
            result['diagnostics'].append(dict(severity='error', field='source', message='Source changed or became unreadable during inspection'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path, help='Explicit PE32 file to inspect read-only')
    args = parser.parse_args()
    report = inspect_tls(args.file)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if any(item['severity'] == 'error' for item in report['diagnostics']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
