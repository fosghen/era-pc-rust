"""Explicit synthetic Windows startup fixtures; no host APIs or licensing.

Values are test assumptions, NOT observations of Windows. Unsupported calls
stop. Each completed call records its arguments, result and memory effects.
"""
import struct

import unicorn as uc
from unicorn import x86_const as x86
from nls_model import NlsModel
from pe_module_model import utf16_z

HEAP_BASE, HEAP_CAPACITY = 0x50000000, 0x1000000
STRINGS_BASE = 0x51000000
VIRTUAL_BASE, VIRTUAL_CAPACITY = 0x56000000, 0x4000000
STARTUP_REGIONS = [(HEAP_BASE, HEAP_CAPACITY), (STRINGS_BASE, 4096), (VIRTUAL_BASE, VIRTUAL_CAPACITY)]
PAGE_PROTECTIONS = {1: 0, 2: uc.UC_PROT_READ, 4: uc.UC_PROT_READ | uc.UC_PROT_WRITE,
                   0x10: uc.UC_PROT_EXEC, 0x20: uc.UC_PROT_READ | uc.UC_PROT_EXEC,
                   0x40: uc.UC_PROT_ALL}


class StartupModel:
    ARGUMENTS = {'GetSystemTimeAsFileTime': 1, 'QueryPerformanceCounter': 1,
                 'GetCurrentProcessId': 0, 'GetCurrentThreadId': 0, 'GetTickCount': 0,
                 'HeapCreate': 3, 'HeapAlloc': 3, 'HeapReAlloc': 4, 'HeapFree': 3,
                 'HeapSize': 3, 'HeapDestroy': 1, 'GetProcessHeap': 0,
                 'TlsAlloc': 0, 'TlsFree': 1, 'TlsGetValue': 1, 'TlsSetValue': 2,
                 'FlsAlloc': 1, 'FlsFree': 1, 'FlsGetValue': 1, 'FlsSetValue': 2,
                 'GetLastError': 0, 'SetLastError': 1,
                 'EncodePointer': 1, 'DecodePointer': 1,
                 'InitializeCriticalSection': 1, 'InitializeCriticalSectionAndSpinCount': 2,
                 'EnterCriticalSection': 1, 'LeaveCriticalSection': 1,
                 'TryEnterCriticalSection': 1, 'DeleteCriticalSection': 1,
                 'InterlockedIncrement': 1, 'InterlockedDecrement': 1,
                 'InterlockedExchange': 2, 'InterlockedCompareExchange': 3,
                 'GetCommandLineA': 0, 'GetCommandLineW': 0,
                 'GetEnvironmentStringsW': 0, 'FreeEnvironmentStringsW': 1,
                 'WideCharToMultiByte': 8, 'GetStartupInfoW': 1,
                 'GetStdHandle': 1, 'GetModuleFileNameA': 3, 'GetModuleFileNameW': 3,
                 'SetHandleCount': 1, 'GetACP': 0, 'GetCPInfo': 2, 'IsValidCodePage': 1,
                 'MultiByteToWideChar': 6, 'GetStringTypeW': 4, 'LCMapStringW': 6,
                 'IsProcessorFeaturePresent': 1, 'GetUserDefaultUILanguage': 0,
                 'RegOpenKeyExW': 5, 'VirtualProtect': 4,
                 'GetCurrentProcess': 0, 'FlushInstructionCache': 3,
                 'GetUserDefaultLangID': 0, 'DuplicateHandle': 7, 'CloseHandle': 1,
                 'VirtualAlloc': 4, 'VirtualFree': 3}

    def __init__(self, machine, nls_codepage=None, nls_sort=None, nls_case=None, critical_section_layout=None):
        if critical_section_layout not in (None, 'win10-x86-19041'):
            raise ValueError('Unknown critical-section layout profile')
        self.critical_section_layout = critical_section_layout
        self.machine = machine
        self.nls = NlsModel(nls_codepage, nls_sort, nls_case)
        self.events = []
        self.profile = dict(filetime=133485408000000000, performance_counter=123456789,
                            process_id=4096, thread_id=4097, tick_count=123456,
                            pointer_xor_fixture=0x5a39c6e1,
                            command_line='C:\\era-lab\\host.exe', environment={},
                            startup_flags=0, inherited_handles=False, standard_handles='absent',
                            initial_last_error=0, ansi_code_page=1251,
                            processor_features={'10': True}, user_ui_language=0x419, user_language=0x419,
                            absent_registry_keys=['HKCU\\Software\\Aktiv\\Guardant\\SDK7'])
        machine.mem_map(HEAP_BASE, HEAP_CAPACITY, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        self.heaps = {}
        self.blocks = {}
        self.cursor = HEAP_BASE
        self.process_heap = None
        self.slots = {'Tls': {}, 'Fls': {}}
        self.last_error = self.profile['initial_last_error']
        self.locks = {}
        self.trace_state = {}
        self.primary_region = None
        self.additional_image_regions = []
        machine.mem_map(STRINGS_BASE, 4096, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        machine.mem_write(STRINGS_BASE, self.profile['command_line'].encode('ascii') + b'\0')
        machine.mem_write(STRINGS_BASE + 512, (self.profile['command_line'] + '\0').encode('utf-16-le'))
        machine.mem_protect(STRINGS_BASE, 4096, uc.UC_PROT_READ)
        self.environment_blocks = set()
        self.object_handles = {}
        self.virtual_allocations = {}
        self.virtual_cursor = VIRTUAL_BASE

    def virtual_memory_call(self, function, args, event):
        if function == 'VirtualFree':
            address, size, flags = args
            allocation = self.virtual_allocations.get(address)
            if flags != 0x8000 or size or not allocation or not allocation['active']:
                raise ValueError('Only MEM_RELEASE of an exact live allocation with size zero supported')
            if any(address < p + 24 and address + allocation['size'] > p for p in self.locks):
                raise ValueError('Releasing storage of an active opaque critical section')
            self.machine.mem_unmap(address, allocation['size'])
            allocation['active'] = False
            event['released_region'] = dict(address=hex(address), size=allocation['size'])
            return 1
        address, requested, flags, protection = args
        if address or flags not in (0x1000, 0x3000) or protection not in PAGE_PROTECTIONS:
            raise ValueError('Only new NULL-address committed allocations with basic protection supported')
        if not 0 < requested <= VIRTUAL_CAPACITY or len(self.virtual_allocations) >= 256:
            raise ValueError('Virtual allocation size/count budget')
        size = (requested + 4095) & ~4095
        address = (self.virtual_cursor + 65535) & ~65535
        if address + size > VIRTUAL_BASE + VIRTUAL_CAPACITY:
            raise ValueError('Virtual arena exhausted; not a modeled Windows allocation failure')
        # Unicorn creates zero-filled pages; protection is real in this model.
        self.machine.mem_map(address, size, PAGE_PROTECTIONS[protection])
        self.virtual_cursor = address + size
        self.virtual_allocations[address] = dict(size=size, requested=requested, active=True,
                                                initial_protection=hex(protection))
        event['memory_writes'] = [dict(address=hex(address), size=size, operation='zero_initialized_pages')]
        if flags == 0x1000:
            event['compatibility'] = 'NULL-address MEM_COMMIT implicit reservation, documented Windows compatibility behavior'
        return address

    def object_handle_call(self, function, args, event):
        if function == 'CloseHandle':
            record = self.object_handles.get(args[0])
            if not record or not record['active']:
                raise ValueError('Only live model-owned real handles can be closed')
            record['active'] = False
            return 1
        source_process, source, target_process, output, desired_access, inherit, options = args
        if source_process != 0xffffffff or target_process != 0xffffffff or options != 2 or inherit not in (0, 1):
            raise ValueError('Only same-process DUPLICATE_SAME_ACCESS supported')
        if source in (0xffffffff, 0xfffffffe):
            obj = 'current_process' if source == 0xffffffff else 'current_thread'
        else:
            record = self.object_handles.get(source)
            if not record or not record['active']:
                raise ValueError('Source is not a known live process/thread handle')
            obj = record['object']
        if len(self.object_handles) >= 128:
            raise ValueError('Object handle model budget exceeded')
        handle = 0x76000000 + 4 * len(self.object_handles)
        # Validate/write before changing the ownership registry. The desired
        # access argument is ignored by the explicit SAME_ACCESS contract.
        self.write(output, struct.pack('<I', handle), event)
        self.object_handles[handle] = dict(object=obj, inheritable=bool(inherit), active=True)
        event['object_handle'] = hex(handle)
        return 1

    def sync_critical_section(self, address, lock, event):
        if self.critical_section_layout is None:
            return
        self.writable(address, 24)
        depth = lock['depth'] if lock else 0
        data = (struct.pack('<IiiIII', 0xffffffff, -2 if depth else -1, depth,
                            self.profile['thread_id'] if depth else 0, 0,
                            lock['spin'] or 0x020007d0) if lock else bytes(24))
        # API-side writes do not fire Unicorn CPU hooks. Guest writes still stop.
        self.machine.mem_write(address, data)
        event.setdefault('memory_writes', []).append(dict(address=hex(address), size=24,
            operation='critical_section_layout_fixture'))
        event['layout_basis'] = 'Own x86 ntdll 10.0.19041.4842 uncontended probe; synthetic thread ID; not portable Windows ABI'

    def critical_section_call(self, function, args, event):
        address = args[0]
        if function.startswith('Initialize'):
            self.writable(address, 24)  # x86 CRITICAL_SECTION storage, opaque.
            if any(address < p + 24 and address + 24 > p for p in self.locks):
                raise ValueError('Critical section overlaps an active object')
            if len(self.locks) >= 128:
                raise ValueError('Critical section model budget')
            spin = args[1] if len(args) == 2 else 0
            if self.critical_section_layout and spin not in (0, 4000):
                raise ValueError('Spin count not measured for the selected layout fixture')

            def direct_access(machine, kind, pointer, size, value, _):
                if self.critical_section_layout and kind == uc.UC_MEM_READ:
                    return
                self.trace_state.update(reason='unsupported_critical_section_memory',
                                        critical_section_access=dict(address=hex(pointer), size=size,
                                            operation='write' if kind == uc.UC_MEM_WRITE else 'read'))
                machine.emu_stop()

            hook = self.machine.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                                         direct_access, begin=address, end=address + 23)
            self.locks[address] = dict(depth=0, spin=spin, hook=hook)
            self.sync_critical_section(address, self.locks[address], event)
            return 1 if len(args) == 2 else None
        lock = self.locks.get(address)
        if lock is None:
            raise ValueError('Critical section not initialized in this model')
        if self.critical_section_layout:
            self.writable(address, 24)
        if function in ('EnterCriticalSection', 'TryEnterCriticalSection'):
            if lock['depth'] == 0x7fffffff:
                raise ValueError('Critical section recursion exceeds layout range')
            lock['depth'] += 1  # One modeled thread; reentrant, no contention.
            self.sync_critical_section(address, lock, event)
            return 1 if function.startswith('Try') else None
        if function == 'LeaveCriticalSection':
            if not lock['depth']:
                raise ValueError('Critical section is not owned')
            lock['depth'] -= 1
            self.sync_critical_section(address, lock, event)
            return None
        if lock['depth']:
            raise ValueError('Deleting an owned critical section is not modeled')
        self.sync_critical_section(address, None, event)
        self.machine.hook_del(lock['hook'])
        del self.locks[address]
        return None

    def local_storage_call(self, function, args, event):
        family, operation = function[:3], function[3:]
        slots = self.slots[family]
        if operation == 'Alloc':
            free = next((i for i in range(64) if i not in slots), None)
            if free is None:
                raise ValueError('Local storage model budget exceeded, not Windows exhaustion')
            slots[free] = dict(value=0, callback=args[0] if family == 'Fls' else 0)
            event['slot'] = free
            return free
        index = args[0]
        if index not in slots:
            raise ValueError('Local storage index not allocated in this model')
        slot = slots[index]
        if operation == 'GetValue':
            # TLS explicitly guarantees ERROR_SUCCESS. The FLS documentation
            # does not promise the same successful-call last-error contract.
            self.last_error = 0 if family == 'Tls' else None
            return slot['value']
        if operation == 'SetValue':
            slot['value'] = args[1]
            return 1
        if slot['callback'] and slot['value']:
            event['pending_callback'] = dict(address=hex(slot['callback']), argument=hex(slot['value']))
            raise ValueError('FLS destruction callback requires guest execution; not skipped')
        del slots[index]
        return 1

    def create_heap(self, options, initial, maximum):
        # Fixed-size Windows heaps have additional rounding/overhead rules.
        # Restrict this fixture to growable heaps rather than approximate them.
        if options not in (0, 1) or initial > HEAP_CAPACITY or maximum != 0:
            raise ValueError('Unsupported heap flags or size outside model budget')
        if len(self.heaps) >= 64:
            raise ValueError('Heap count budget')
        handle = 0x74000000 + 16 * len(self.heaps)
        self.heaps[handle] = dict(limit=HEAP_CAPACITY, live=0, active=True)
        return handle

    def heap(self, handle):
        if handle not in self.heaps or not self.heaps[handle]['active']:
            raise ValueError('Unknown or destroyed heap handle')
        return self.heaps[handle]

    def block(self, handle, pointer):
        self.heap(handle)
        block = self.blocks.get(pointer)
        if block is None or not block['active'] or block['heap'] != handle:
            raise ValueError('Pointer is not a live allocation of this heap')
        return block

    def allocate(self, handle, flags, size, event, prefix=b'', credit=0):
        heap = self.heap(handle)
        if flags & ~8:
            raise ValueError('Unsupported allocation flags')
        occupied = (max(1, size) + 15) & ~15
        if heap['live'] - credit + size > heap['limit'] or self.cursor + occupied > HEAP_BASE + HEAP_CAPACITY:
            raise ValueError('Heap arena budget exceeded; not a modeled Windows allocation failure')
        pointer = self.cursor
        fill = b'\0' if flags & 8 else b'\xa5'
        self.write(pointer, prefix[:size] + fill * (occupied - min(len(prefix), size)), event)
        self.cursor += occupied
        self.blocks[pointer] = dict(heap=handle, size=size, active=True)
        heap['live'] += size
        return pointer

    def heap_call(self, function, args, event):
        if function == 'HeapCreate':
            return self.create_heap(*args)
        if function == 'GetProcessHeap':
            if self.process_heap is None:
                self.process_heap = self.create_heap(0, 0, 0)
            return self.process_heap
        handle = args[0]
        heap = self.heap(handle)
        if function == 'HeapDestroy':
            heap['active'] = False
            return 1
        flags, pointer_or_size = args[1:3]
        if function == 'HeapAlloc':
            return self.allocate(handle, flags, pointer_or_size, event)
        block = self.block(handle, pointer_or_size)
        if function == 'HeapReAlloc':
            size = args[3]
            prefix = bytes(self.machine.mem_read(pointer_or_size, min(block['size'], size))) if min(block['size'], size) else b''
            pointer = self.allocate(handle, flags, size, event, prefix, block['size'])
            block['active'] = False
            heap['live'] -= block['size']
            return pointer
        if flags:
            raise ValueError('Unsupported heap operation flags')
        if function == 'HeapSize':
            return block['size']
        block['active'] = False
        heap['live'] -= block['size']
        return 1

    def writable(self, address, size):
        if not address or size <= 0 or address + size > 2**32:
            raise ValueError('Invalid output buffer')
        current, end = address, address + size
        for start, last, permissions in sorted(self.machine.mem_regions()):
            if start <= current <= last:
                if not permissions & uc.UC_PROT_WRITE:
                    raise ValueError('Output buffer is not writable')
                current = min(end, last + 1)
                if current == end:
                    return
        raise ValueError('Output buffer is not fully mapped')

    def write(self, address, data, event):
        self.writable(address, len(data))
        if any(address < p + 24 and address + len(data) > p for p in self.locks):
            raise ValueError('API output overlaps an opaque critical section')
        self.machine.mem_write(address, data)
        event.setdefault('memory_writes', []).append(dict(address=hex(address), size=len(data)))

    def invoke(self, function, args, event):
        if function in ('VirtualAlloc', 'VirtualFree'):
            return self.virtual_memory_call(function, args, event)
        if function in ('DuplicateHandle', 'CloseHandle'):
            return self.object_handle_call(function, args, event)
        if function == 'GetUserDefaultLangID':
            return self.profile['user_language']
        if function == 'GetCurrentProcess':
            return 0xffffffff
        if function in ('VirtualProtect', 'FlushInstructionCache'):
            if self.primary_region is None and not self.virtual_allocations:
                raise ValueError('Primary image range not established')
            if function == 'VirtualProtect':
                address, size, protection, previous = args
            else:
                process, address, size = args
                if process != 0xffffffff:
                    raise ValueError('Only current synthetic process supported')
            ranges = ([self.primary_region] if self.primary_region else []) + self.additional_image_regions
            ranges += [(p, item['size']) for p, item in self.virtual_allocations.items() if item['active']]
            if not size or not any(start <= address < address + size <= start + length for start, length in ranges):
                raise ValueError('Memory operation outside explicit input images or live virtual allocations')
            first, end = address & ~4095, (address + size + 4095) & ~4095
            if function == 'FlushInstructionCache':
                self.machine.ctl_remove_cache(first, end)
                return 1
            flags = PAGE_PROTECTIONS
            if protection not in flags:
                raise ValueError('Guard/copy-on-write or unknown page protection not modeled')
            self.writable(previous, 4)
            if first < previous + 4 and end > previous:
                raise ValueError('Old-protection output overlaps modified pages')
            old = next((p for begin, last, p in self.machine.mem_regions() if begin <= first <= last), None)
            reverse = {value: key for key, value in flags.items()}
            if old not in reverse:
                raise ValueError('Old page permissions not representable')
            # Validate output against model-owned opaque storage before mutation.
            if any(previous < p + 24 and previous + 4 > p for p in self.locks):
                raise ValueError('Old-protection output overlaps critical section')
            self.machine.mem_protect(first, end - first, flags[protection])
            self.write(previous, struct.pack('<I', reverse[old]), event)
            event['page_protection'] = dict(start=hex(first), end=hex(end), old_first_page=hex(reverse[old]), new=hex(protection))
            return 1
        if function == 'RegOpenKeyExW':
            root, pointer, options, access, output = args
            key = utf16_z(self.machine, pointer)
            event['registry_subkey'] = key
            if root != 0x80000001 or options or access != 1 or ('HKCU\\' + key).lower() not in [k.lower() for k in self.profile['absent_registry_keys']]:
                raise ValueError('Registry lookup outside explicit absent-key fixture')
            self.writable(output, 4)
            event['assumption'] = 'This exact user-settings key is absent in the synthetic profile; not a host registry observation'
            return 2  # ERROR_FILE_NOT_FOUND; leave output handle untouched.
        if function == 'GetUserDefaultUILanguage':
            return self.profile['user_ui_language']
        if function == 'IsProcessorFeaturePresent':
            feature = str(args[0])
            if feature not in self.profile['processor_features']:
                raise ValueError('Processor feature outside explicit fixture')
            return int(self.profile['processor_features'][feature])
        if function == 'LCMapStringW':
            locale, flags, source, count, output, capacity = args
            if locale != 0 or flags not in (0x100, 0x200) or not source or not 1 <= count <= 4096 or capacity > 4096:
                raise ValueError('Only neutral simple BMP lower/upper case mapping modeled')
            converted = self.nls.map_case(bytes(self.machine.mem_read(source, 2 * count)), flags == 0x200)
            if capacity:
                if capacity < count:
                    raise ValueError('Case mapping output buffer too small')
                self.write(output, converted, event)
            return count
        if function == 'MultiByteToWideChar':
            codepage, flags, source, count, output, capacity = args
            if codepage not in (0, 1251) or flags not in (0, 1) or not source or not 1 <= count <= 4096 or capacity > 4096:
                raise ValueError('Unsupported multibyte conversion parameters')
            converted = self.nls.to_wide(bytes(self.machine.mem_read(source, count)))
            if capacity:
                if source < output + 2 * count and output < source + count:
                    raise ValueError('Overlapping conversion buffers not modeled')
                if capacity < count:
                    raise ValueError('Wide output buffer too small')
                self.write(output, converted, event)
            return count
        if function == 'GetStringTypeW':
            kind, source, count, output = args
            if not source or not 1 <= count <= 4096:
                raise ValueError('Unsupported classification buffer/count')
            result = self.nls.classify(bytes(self.machine.mem_read(source, 2 * count)), kind)
            self.write(output, result, event)
            return 1
        if function == 'IsValidCodePage':
            if args[0] != self.profile['ansi_code_page']:
                raise ValueError('Codepage availability outside fixture not known')
            return 1
        if function == 'GetACP':
            return self.profile['ansi_code_page']
        if function == 'GetCPInfo':
            if args[0] not in (0, self.profile['ansi_code_page']):
                raise ValueError('Codepage outside explicit startup profile')
            self.write(args[1], struct.pack('<I', 1) + b'?\0' + bytes(14), event)
            return 1
        if function == 'SetHandleCount':
            return args[0]  # No-op in the explicitly inspected kernel32 reference.
        if function == 'GetStartupInfoW':
            self.write(args[0], struct.pack('<I', 68) + bytes(64), event)
            return None
        if function == 'GetStdHandle':
            if args[0] not in (0xfffffff6, 0xfffffff5, 0xfffffff4):
                raise ValueError('Unknown standard handle selector')
            return 0  # Explicit fixture: no stdin/stdout/stderr handles.
        if function in ('GetModuleFileNameA', 'GetModuleFileNameW'):
            module, output, capacity = args
            if module:
                raise ValueError('Only synthetic main-process filename modeled')
            name = self.profile['command_line']
            if capacity <= len(name):
                raise ValueError('Truncated module filename not modeled')
            self.write(output, (name + '\0').encode('utf-16-le' if function.endswith('W') else 'ascii'), event)
            return len(name)
        if function == 'WideCharToMultiByte':
            codepage, flags, source, count, output, capacity, default, used_default = args
            if codepage not in (0, 1251) or flags or default or used_default or not source or capacity > 4096:
                raise ValueError('Only CP1251 exact conversion with no optional flags/defaults modeled')
            if count == 0xffffffff:
                count = next((i + 1 for i in range(4096)
                              if self.machine.mem_read(source + 2 * i, 2) == b'\0\0'), None)
            if count is None or not 1 <= count <= 4096:
                raise ValueError('Wide string count outside model limit')
            raw = bytes(self.machine.mem_read(source, count * 2))
            # ASCII has the same byte values in the supported startup fixture;
            # do not silently approximate Windows best-fit/codepage behavior.
            encoded = self.nls.from_wide_exact(raw) if self.nls.reverse is not None else raw.decode('utf-16-le').encode('ascii')
            if capacity:
                if source < output + len(encoded) and output < source + 2 * count:
                    raise ValueError('Overlapping conversion buffers not modeled')
                if capacity < len(encoded):
                    raise ValueError('Output buffer too small; no partial conversion')
                self.write(output, encoded, event)
            return len(encoded)
        if function.startswith('GetCommandLine'):
            return STRINGS_BASE + (512 if function.endswith('W') else 0)
        if function == 'GetEnvironmentStringsW':
            if self.process_heap is None:
                self.process_heap = self.create_heap(0, 0, 0)
            pointer = self.allocate(self.process_heap, 8, 4, event)
            self.environment_blocks.add(pointer)
            return pointer
        if function == 'FreeEnvironmentStringsW':
            if args[0] not in self.environment_blocks:
                raise ValueError('Unknown environment block')
            self.heap_call('HeapFree', (self.process_heap, 0, args[0]), event)
            self.environment_blocks.remove(args[0])
            return 1
        if function.startswith('Interlocked'):
            address = args[0]
            if address % 4:
                raise ValueError('Unaligned interlocked operand')
            self.writable(address, 4)
            old = struct.unpack('<I', self.machine.mem_read(address, 4))[0]
            if function == 'InterlockedIncrement':
                new = (old + 1) & 0xffffffff
            elif function == 'InterlockedDecrement':
                new = (old - 1) & 0xffffffff
            elif function == 'InterlockedExchange':
                new = args[1]
            else:
                if old != args[2]:
                    event['previous_value'] = hex(old)
                    return old
                new = args[1]
            self.write(address, struct.pack('<I', new), event)
            event['previous_value'] = hex(old)
            return old if 'Exchange' in function else new
        if 'CriticalSection' in function:
            return self.critical_section_call(function, args, event)
        if function in ('EncodePointer', 'DecodePointer'):
            # Deliberately synthetic reversible mapping, not Windows' secret
            # algorithm or any dongle key. Only the API pair's round trip holds.
            return args[0] ^ self.profile['pointer_xor_fixture']
        if function.startswith(('Tls', 'Fls')):
            return self.local_storage_call(function, args, event)
        if function == 'SetLastError':
            self.last_error = args[0]
            return None
        if function == 'GetLastError':
            if self.last_error is None:
                raise ValueError('Last-error state is not established')
            return self.last_error
        if function.startswith('Heap') or function == 'GetProcessHeap':
            return self.heap_call(function, args, event)
        if function == 'GetSystemTimeAsFileTime':
            self.write(args[0], struct.pack('<Q', self.profile['filetime']), event)
            return None  # VOID: do not invent a success code in EAX.
        if function == 'QueryPerformanceCounter':
            self.write(args[0], struct.pack('<q', self.profile['performance_counter']), event)
            return 1
        return self.profile[{'GetCurrentProcessId': 'process_id', 'GetCurrentThreadId': 'thread_id',
                             'GetTickCount': 'tick_count'}[function]]

    def handle(self, name):
        module, _, function = name.partition('!')
        allowed_module = (module.lower() == 'advapi32.dll' if function == 'RegOpenKeyExW'
                          else module.lower() in ('kernel32.dll', 'kernelbase.dll'))
        # Exact API contract listed in Microsoft's GetCurrentProcess metadata;
        # this is not a wildcard API-set alias or a host DLL loader.
        if module.lower() == 'api-ms-win-core-processthreads-l1-1-0.dll' and function == 'GetCurrentProcess':
            allowed_module = True
        if module.lower() == 'api-ms-win-core-handle-l1-1-0.dll' and function in ('DuplicateHandle', 'CloseHandle'):
            allowed_module = True
        if module.lower() == 'api-ms-win-core-memory-l1-1-0.dll' and function in ('VirtualAlloc', 'VirtualFree', 'VirtualProtect'):
            allowed_module = True
        if not allowed_module or function not in self.ARGUMENTS:
            return False, None
        event = dict(api=name, basis='Explicit synthetic startup profile; not a native Windows observation')
        if len(self.events) >= 4096:
            return False, dict(api=name, model_error='Startup event limit')
        try:
            argc = self.ARGUMENTS[function]
            esp = self.machine.reg_read(x86.UC_X86_REG_ESP)
            words = struct.unpack('<' + 'I' * (argc + 1), self.machine.mem_read(esp, 4 * (argc + 1)))
            event.update(return_address=hex(words[0]), arguments=[hex(a) for a in words[1:]])
            result = self.invoke(function, words[1:], event)
            event['result'] = hex(result & 0xffffffff) if result is not None else None
            event['last_error'] = self.last_error
            if result is not None:
                self.machine.reg_write(x86.UC_X86_REG_EAX, result & 0xffffffff)
            self.machine.reg_write(x86.UC_X86_REG_ESP, esp + 4 * (argc + 1))
            self.machine.reg_write(x86.UC_X86_REG_EIP, words[0])
            self.events.append(event)
            return True, event
        except (ValueError, uc.UcError) as error:
            event['model_error'] = str(error)
            self.events.append(event)
            return False, event

    def report(self):
        return dict(profile=self.profile, events=self.events,
                    critical_section_layout=self.critical_section_layout or 'opaque-stop-on-access',
                    nls=self.nls.report(),
                    local_storage=self.slots, last_error=self.last_error,
                    critical_sections={hex(p): {k: v for k, v in lock.items() if k != 'hook'}
                                       for p, lock in self.locks.items()},
                    heaps={hex(h): data for h, data in self.heaps.items()},
                    object_handles={hex(h): data for h, data in self.object_handles.items()},
                    virtual_allocations={hex(p): item for p, item in self.virtual_allocations.items()},
                    virtual_arena=dict(base=hex(VIRTUAL_BASE), capacity=VIRTUAL_CAPACITY,
                        used=self.virtual_cursor - VIRTUAL_BASE, page_size=4096, allocation_granularity=65536,
                        limitations='NULL-address commit only; MEM_RELEASE only; no decommit, address selection, reserve-only, reuse or host allocations'),
                    memory_operation_regions=[dict(base=hex(base), size=size)
                        for base, size in ([self.primary_region] if self.primary_region else []) + self.additional_image_regions],
                    heap_arena=dict(base=hex(HEAP_BASE), capacity=HEAP_CAPACITY, used=self.cursor - HEAP_BASE),
                    limitations='Explicit synthetic process profile, reversible XOR pointer fixture, single-thread locks/atomics and bounded heaps; locks opaque by default, optional measured read-only layout for uncontended spin 0/4000 only; copied locks are not live objects; 64 TLS/FLS slots each, no direct TEB storage or callback dispatch; unknown last-error reads stop; only the named registry key is assumed absent; NLS data requires explicit files; page permissions apply to explicit input images and live virtual allocations; freed heap blocks not reused/unmapped, released virtual allocations unmapped and not reused; unspecified heap allocation bytes A5; no host API, device, license, filesystem operations, scheduling or time progression; API writes logged separately from CPU writes')
