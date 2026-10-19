"""Read-only PE module/export model; never runs host or mapped-module APIs.

Only explicitly supported kernel32/kernelbase/API-set resolver calls return.
Already mapped guest inputs can be registered separately from stop-only
reference modules; registering them does not map or initialize new code.
Missing modules, unsupported names and unknown exports stop, rather than
pretending a Windows operation succeeded or failed. This is not a loader.
"""
import hashlib
from pathlib import Path
import struct

import pefile
import unicorn as uc
from unicorn import x86_const as x86

REFERENCE_IMPORT_REGIONS = [(0x75000000, 0x100000)]


def ascii_z(machine, address, limit=260):
    if not address:
        raise ValueError('NULL string not modeled')
    chars = bytearray()
    for offset in range(limit):
        value = machine.mem_read(address + offset, 1)
        if value == b'\0':
            return chars.decode('ascii')
        chars.extend(value)
    raise ValueError('String exceeds model limit')


def utf16_z(machine, address, limit=260):
    if not address:
        raise ValueError('NULL string not modeled')
    chars = bytearray()
    for offset in range(limit):
        value = machine.mem_read(address + 2 * offset, 2)
        if value == b'\0\0':
            return chars.decode('utf-16-le')
        chars.extend(value)
    raise ValueError('String exceeds model limit')


def raw_image_range(pe, raw, rva, length):
    """Read an unambiguous, fully file-backed RVA interval, never zero padding."""
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    if not 0 <= rva < image_size or not 0 < length <= image_size - rva:
        raise ValueError('Relocation directory outside image')
    spans = [(0, pe.OPTIONAL_HEADER.SizeOfHeaders, 0)]
    spans += [(s.VirtualAddress, s.VirtualAddress + s.SizeOfRawData, s.PointerToRawData)
              for s in pe.sections if s.SizeOfRawData]
    output = bytearray()
    end = rva + length
    while rva < end:
        matches = [(start, stop, offset) for start, stop, offset in spans if start <= rva < stop]
        if len(matches) != 1:
            raise ValueError('Relocation directory is not uniquely file-backed')
        start, stop, offset = matches[0]
        limit = min([end, stop] + [a for a, _, _ in spans if rva < a < end])
        position = offset + rva - start
        count = limit - rva
        if not 0 <= position <= len(raw) - count:
            raise ValueError('Truncated raw relocation directory')
        output.extend(raw[position:position + count])
        rva = limit
    return bytes(output)


def relocate_reference_image(pe, raw, image, actual_base):
    """Strict x86 ABSOLUTE/HIGHLOW subset, applied only to a private bytearray.

    PE/COFF .reloc specifies actual-minus-preferred addition modulo 2**32.
    We do not rewrite OptionalHeader.ImageBase: it describes the preferred base.
    https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
    """
    delta = actual_base - pe.OPTIONAL_HEADER.ImageBase
    if not delta:
        return 0
    if pe.FILE_HEADER.Characteristics & 1:
        raise ValueError('Reference image has stripped relocations')
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(directories) <= 5 or not directories[5].VirtualAddress or not directories[5].Size:
        raise ValueError('Reference image has no relocation directory')
    directory = directories[5]
    if directory.VirtualAddress % 4:
        raise ValueError('Relocation directory is not 4-byte aligned')
    table = raw_image_range(pe, raw, directory.VirtualAddress, directory.Size)
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    fixups = []
    cursor = 0
    while cursor < len(table):
        if len(table) - cursor < 8:
            raise ValueError('Truncated relocation block header')
        page, block_size = struct.unpack_from('<II', table, cursor)
        if page % 4096 or page >= image_size:
            raise ValueError('Invalid relocation page RVA')
        if block_size < 8 or block_size % 4 or block_size > len(table) - cursor:
            raise ValueError('Invalid or truncated relocation block size')
        for position in range(cursor + 8, cursor + block_size, 2):
            entry = struct.unpack_from('<H', table, position)[0]
            kind, offset = entry >> 12, entry & 0xfff
            if kind == 0:
                continue
            if kind != 3:
                raise ValueError(f'Unsupported x86 relocation type {kind}')
            target = page + offset
            if target > image_size - 4:
                raise ValueError('Relocation fixup outside image')
            fixups.append(target)
        cursor += block_size
    ordered = sorted(fixups)
    if any(right < left + 4 for left, right in zip(ordered, ordered[1:])):
        raise ValueError('Overlapping relocation fixups')
    # Validate the entire directory first, including overlaps across blocks.
    image.extend(bytes(max(0, image_size - len(image))))
    for target in fixups:
        value = struct.unpack_from('<I', image, target)[0]
        struct.pack_into('<I', image, target, (value + delta) & 0xffffffff)
    return len(fixups)


class ModuleModel:
    def __init__(self, machine, paths, occupied, import_markers=False, module_bases=(), api_set_schema=None):
        paths = [Path(path) for path in paths]
        path_names = [path.name.lower() for path in paths]
        if len(set(path_names)) != len(path_names):
            raise ValueError('Duplicate module basename')
        overrides = {}
        for name, base in module_bases:
            if not isinstance(name, str) or not name or name in ('.', '..') or any(c in name for c in '/\\:\0'):
                raise ValueError('Module base requires a basename')
            name = name.lower()
            if name in overrides:
                raise ValueError('Duplicate module base override')
            if name not in path_names:
                raise ValueError('Module base override names an unknown reference module')
            if type(base) is not int or not 0 < base < 2**32 or base % 4096:
                raise ValueError('Module base must be a positive 4-KiB-aligned 32-bit integer')
            overrides[name] = base
        self.machine = machine
        self.modules = {}
        self.guest_modules = {}
        self.main_module = None
        self.api_set = None
        self.api_set_resolutions = []
        if api_set_schema is not None:
            from api_set_model import ApiSetSchema
            self.api_set = ApiSetSchema(api_set_schema)
        self.events = []
        self.observed_calls = 0
        self.address_names = {}
        self.reserved = list(occupied)
        self.import_bindings = []
        bound_slots = set()
        self.import_markers_enabled = import_markers
        if import_markers:
            start, length = REFERENCE_IMPORT_REGIONS[0]
            if any((a, n) != (start, length) and start < a + n and start + length > a
                   for a, n in self.reserved):
                raise ValueError('Reference import markers overlap reserved memory')
            machine.mem_map(start, length, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
            if (start, length) not in self.reserved:
                self.reserved.append((start, length))
        for path in paths:
            path = Path(path)
            name = path.name.lower()
            if name in self.modules:
                raise ValueError('Duplicate module basename')
            raw = path.read_bytes()
            pe = pefile.PE(data=raw)
            preferred_base = pe.OPTIONAL_HEADER.ImageBase
            base = overrides.get(name, preferred_base)
            size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
            if (pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b
                    or not 0 < size <= 32 * 1024 * 1024):
                raise ValueError('Module must be a bounded x86 PE image')
            if base % 4096 or base + size > 2**32:
                raise ValueError('Invalid module address range')
            if any(base < start + length and base + size > start for start, length in self.reserved):
                raise ValueError(f'Module {name} at {base:#x}..{base + size:#x} overlaps existing memory; choose an explicit nonoverlapping base')
            image = bytearray(pe.get_memory_mapped_image())
            if len(image) > size:
                raise ValueError('Mapped module exceeds declared size')
            relocation_count = relocate_reference_image(pe, raw, image, base)
            if import_markers:
                for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
                    for imp in descriptor.imports:
                        marker = REFERENCE_IMPORT_REGIONS[0][0] + 16 * len(self.import_bindings)
                        if marker >= sum(REFERENCE_IMPORT_REGIONS[0]):
                            raise ValueError('Reference import marker budget exceeded')
                        offset = imp.address - preferred_base
                        if not 0 <= offset <= len(image) - 4:
                            raise ValueError('Reference IAT outside mapped image')
                        symbol = imp.name.decode('ascii') if imp.name else f'ordinal:{imp.ordinal}'
                        imported_name = descriptor.dll.decode('ascii') + '!' + symbol
                        slot = base + offset
                        if slot in bound_slots:
                            raise ValueError('Duplicate reference IAT slot')
                        bound_slots.add(slot)
                        struct.pack_into('<I', image, offset, marker)
                        self.address_names[marker] = [imported_name]
                        self.import_bindings.append(dict(source_module=name, iat_va=hex(slot),
                            marker=hex(marker), imported_name=imported_name))
            machine.mem_map(base, size)
            machine.mem_write(base, bytes(image))
            # Execution fetches are allowed only so the tracer can stop BEFORE
            # executing any instruction from these modules. Writes are forbidden.
            machine.mem_protect(base, size, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
            self.reserved.append((base, size))
            symbols = getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
            by_name, by_ordinal = {}, {}
            for symbol in symbols:
                by_ordinal[symbol.ordinal] = symbol
                if symbol.name:
                    by_name[symbol.name.decode('ascii')] = symbol
                if symbol.address and not symbol.forwarder:
                    if not 0 <= symbol.address < size:
                        raise ValueError('Export outside module')
                    label = symbol.name.decode('ascii') if symbol.name else f'ordinal:{symbol.ordinal}'
                    self.address_names.setdefault(base + symbol.address, []).append(name + '!' + label)
            self.modules[name] = dict(path=path, sha256=hashlib.sha256(raw).hexdigest(),
                                      base=base, size=size, names=by_name, ordinals=by_ordinal,
                                      preferred_base=preferred_base, relocation_delta=base - preferred_base,
                                      relocation_highlow_count=relocation_count, explicit_base=name in overrides,
                                      loadlibrary_acquisitions=0)
        self.range_start = min((m['base'] for m in self.modules.values()), default=2**32)
        self.range_end = max((m['base'] + m['size'] for m in self.modules.values()), default=0)

    def register_guest(self, name, pe, is_main=False):
        """Register an already mapped input, without making it a stop-only module."""
        name = name.lower()
        if name in self.modules or name in self.guest_modules or (is_main and self.main_module):
            raise ValueError('Duplicate guest module identity')
        symbols = getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
        size = pe.OPTIONAL_HEADER.SizeOfImage
        if any(s.address and not s.forwarder and not 0 < s.address < size for s in symbols):
            raise ValueError('Guest export outside image')
        self.guest_modules[name] = dict(base=pe.OPTIONAL_HEADER.ImageBase, size=size,
            names={s.name.decode('ascii'): s for s in symbols if s.name},
            ordinals={s.ordinal: s for s in symbols}, loadlibrary_acquisitions=0)
        if is_main:
            self.main_module = name

    def lookup_module(self, name):
        name = name.lower()
        module = self.modules.get(name) or self.guest_modules.get(name)
        if module is None and self.api_set and name.startswith(('api-', 'ext-')):
            if len(self.api_set_resolutions) >= 4096:
                raise ValueError('API-set resolution event limit')
            resolution = self.api_set.resolve(name)
            module = self.modules.get(resolution['host'])
            self.api_set_resolutions.append(dict(resolution, host_explicitly_mapped=module is not None))
            if module is None:
                raise ValueError('API-set host not explicitly mapped: ' + resolution['host'])
        return module

    def contains(self, address):
        if self.import_markers_enabled and REFERENCE_IMPORT_REGIONS[0][0] <= address < sum(REFERENCE_IMPORT_REGIONS[0]):
            return True
        if not self.range_start <= address < self.range_end:
            return False
        return any(m['base'] <= address < m['base'] + m['size'] for m in self.modules.values())

    def resolve(self, module_name, symbol, depth=0):
        if depth >= 16:
            raise ValueError('Forwarder depth limit')
        module = self.lookup_module(module_name)
        if module is None:
            raise ValueError('Module not explicitly mapped: ' + module_name)
        entry = module['ordinals' if isinstance(symbol, int) else 'names'].get(symbol)
        if entry is None or not entry.address:
            raise ValueError('Export not available in mapped image')
        if entry.forwarder:
            target_module, target = entry.forwarder.decode('ascii').rsplit('.', 1)
            if not target_module.lower().endswith('.dll'):
                target_module += '.dll'
            return self.resolve(target_module, int(target[1:]) if target.startswith('#') else target, depth + 1)
        return module['base'] + entry.address

    def handle(self, name):
        """Return (handled, observation). No unsupported function gets a result."""
        module_name, _, function = name.partition('!')
        allowed = module_name.lower() in ('kernel32.dll', 'kernelbase.dll')
        if module_name.lower() == 'api-ms-win-core-libraryloader-l1-2-0.dll' and function in ('GetModuleHandleA', 'GetProcAddress'):
            allowed = True
        if not allowed or function not in ('GetModuleHandleA', 'GetModuleHandleW', 'LoadLibraryA', 'GetProcAddress'):
            return False, None
        event = dict(api=name)
        self.observed_calls += 1
        if len(self.events) >= 4096:
            return False, dict(api=name, model_error='Resolver event limit')
        try:
            esp = self.machine.reg_read(x86.UC_X86_REG_ESP)
            argc = 2 if function == 'GetProcAddress' else 1
            words = struct.unpack('<' + 'I' * (argc + 1), self.machine.mem_read(esp, 4 * (argc + 1)))
            event['return_address'] = hex(words[0])
            if function in ('GetModuleHandleA', 'GetModuleHandleW', 'LoadLibraryA'):
                if words[1] == 0 and function.startswith('GetModuleHandle') and self.main_module:
                    requested = self.main_module
                    event['null_name_means_explicit_host'] = True
                else:
                    requested = (utf16_z if function.endswith('W') else ascii_z)(self.machine, words[1])
                event['module'] = requested
                if '/' in requested or '\\' in requested:
                    raise ValueError('Path-based module lookup not modeled')
                lookup = requested.lower()
                if '.' not in lookup:
                    lookup += '.dll'
                module = self.lookup_module(lookup)
                if module is None:
                    raise ValueError('Requested module not explicitly mapped')
                result = module['base']
                if function == 'LoadLibraryA':
                    module['loadlibrary_acquisitions'] += 1
                    event['assumption'] = 'Module already mapped; no search, dependency loading or DllMain'
            else:
                event['module_handle'] = hex(words[1])
                matches = [n for n, m in (self.modules | self.guest_modules).items() if m['base'] == words[1]]
                if not matches:
                    raise ValueError('Unknown module handle')
                symbol = words[2] if words[2] <= 0xffff else ascii_z(self.machine, words[2])
                event.update(module=matches[0], symbol=symbol)
                result = self.resolve(matches[0], symbol)
            event.update(result=hex(result), basis='Explicitly mapped PE module/export table')
            self.machine.reg_write(x86.UC_X86_REG_EAX, result)
            self.machine.reg_write(x86.UC_X86_REG_ESP, esp + 4 * (argc + 1))
            self.machine.reg_write(x86.UC_X86_REG_EIP, words[0])
            self.events.append(event)
            return True, event
        except (ValueError, uc.UcError) as error:
            event['model_error'] = str(error)
            self.events.append(event)
            return False, event

    def report(self):
        records = []
        for name, module in self.modules.items():
            unchanged = hashlib.sha256(module['path'].read_bytes()).hexdigest() == module['sha256']
            if not unchanged:
                raise RuntimeError('Reference module changed during trace')
            records.append(dict(name=name, sha256=module['sha256'], base=hex(module['base']),
                                preferred_base=hex(module['preferred_base']),
                                relocation_delta=module['relocation_delta'],
                                relocation_highlow_count=module['relocation_highlow_count'],
                                explicit_base=module['explicit_base'],
                                mapped_size=module['size'], input_unchanged=unchanged,
                                loadlibrary_acquisitions=module['loadlibrary_acquisitions']))
        return dict(modules=records, resolver_events=self.events,
                    api_set_schema=self.api_set.report() if self.api_set else None,
                    api_set_resolutions=self.api_set_resolutions,
                    guest_modules=[dict(name=name, base=hex(m['base']), size=m['size'],
                        is_main=name == self.main_module, loadlibrary_acquisitions=m['loadlibrary_acquisitions'])
                        for name, m in self.guest_modules.items()],
                    observed_resolver_calls=self.observed_calls,
                    reference_import_markers=self.import_markers_enabled,
                    reference_import_bindings=self.import_bindings,
                    limitations='Preferred bases by default; explicit reference-only x86 ABSOLUTE/HIGHLOW relocation; optional file-backed API-set v6 resolution only to already mapped references; explicit module identities take precedence; optional ordinary IAT stop markers are synthetic call boundaries, not resolved Windows addresses; no live API-set composition or alias-specific hosts, delayed-import binding, DLL initialization, automatic address placement, other relocation types, last-error state or OS execution; unknown operations stop')
