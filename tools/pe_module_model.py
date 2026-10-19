"""Read-only PE module/export model; never runs host or mapped-module APIs.

Only explicitly supported kernel32/kernelbase resolver calls can return.
Missing modules, unsupported names and unknown exports stop, rather than
pretending a Windows operation succeeded or failed. This is not a loader.
"""
import hashlib
from pathlib import Path
import struct

import pefile
import unicorn as uc
from unicorn import x86_const as x86


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


class ModuleModel:
    def __init__(self, machine, paths, occupied):
        self.machine = machine
        self.modules = {}
        self.events = []
        self.observed_calls = 0
        self.address_names = {}
        self.reserved = list(occupied)
        for path in paths:
            path = Path(path)
            name = path.name.lower()
            if name in self.modules:
                raise ValueError('Duplicate module basename')
            raw = path.read_bytes()
            pe = pefile.PE(data=raw)
            base = pe.OPTIONAL_HEADER.ImageBase
            size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
            if pe.FILE_HEADER.Machine != 0x14c or not 0 < size <= 32 * 1024 * 1024:
                raise ValueError('Module must be a bounded x86 PE image')
            if base % 4096 or base + size > 2**32:
                raise ValueError('Invalid module address range')
            if any(base < start + length and base + size > start for start, length in self.reserved):
                raise ValueError('Module overlaps existing memory; relocation not modeled')
            image = pe.get_memory_mapped_image()
            if len(image) > size:
                raise ValueError('Mapped module exceeds declared size')
            machine.mem_map(base, size)
            machine.mem_write(base, image)
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
                                      loadlibrary_acquisitions=0)
        self.range_start = min((m['base'] for m in self.modules.values()), default=2**32)
        self.range_end = max((m['base'] + m['size'] for m in self.modules.values()), default=0)

    def contains(self, address):
        if not self.range_start <= address < self.range_end:
            return False
        return any(m['base'] <= address < m['base'] + m['size'] for m in self.modules.values())

    def resolve(self, module_name, symbol, depth=0):
        if depth >= 16:
            raise ValueError('Forwarder depth limit')
        module = self.modules.get(module_name.lower())
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
        if module_name.lower() not in ('kernel32.dll', 'kernelbase.dll') or function not in ('GetModuleHandleA', 'GetModuleHandleW', 'LoadLibraryA', 'GetProcAddress'):
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
                requested = (utf16_z if function.endswith('W') else ascii_z)(self.machine, words[1])
                event['module'] = requested
                if '/' in requested or '\\' in requested:
                    raise ValueError('Path-based module lookup not modeled')
                lookup = requested.lower()
                if '.' not in lookup:
                    lookup += '.dll'
                if lookup not in self.modules:
                    raise ValueError('Requested module not explicitly mapped')
                result = self.modules[lookup]['base']
                if function == 'LoadLibraryA':
                    self.modules[lookup]['loadlibrary_acquisitions'] += 1
                    event['assumption'] = 'Module already mapped; no search, dependency loading or DllMain'
            else:
                event['module_handle'] = hex(words[1])
                matches = [n for n, m in self.modules.items() if m['base'] == words[1]]
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
                                mapped_size=module['size'], input_unchanged=unchanged,
                                loadlibrary_acquisitions=module['loadlibrary_acquisitions']))
        return dict(modules=records, resolver_events=self.events,
                    observed_resolver_calls=self.observed_calls,
                    limitations='Preferred bases only; no DLL initialization, relocation, API-set mapping, last-error state or OS execution; unknown operations stop')
