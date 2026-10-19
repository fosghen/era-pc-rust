"""Explicit synthetic Windows startup fixtures; no host APIs or licensing.

Values are test assumptions, NOT observations of Windows. Unsupported calls
stop. Each completed call records its arguments, result and memory effects.
"""
import struct

import unicorn as uc
from unicorn import x86_const as x86

HEAP_BASE, HEAP_CAPACITY = 0x50000000, 0x1000000
STARTUP_REGIONS = [(HEAP_BASE, HEAP_CAPACITY)]


class StartupModel:
    ARGUMENTS = {'GetSystemTimeAsFileTime': 1, 'QueryPerformanceCounter': 1,
                 'GetCurrentProcessId': 0, 'GetCurrentThreadId': 0, 'GetTickCount': 0,
                 'HeapCreate': 3, 'HeapAlloc': 3, 'HeapReAlloc': 4, 'HeapFree': 3,
                 'HeapSize': 3, 'HeapDestroy': 1, 'GetProcessHeap': 0}

    def __init__(self, machine):
        self.machine = machine
        self.events = []
        self.profile = dict(filetime=133485408000000000, performance_counter=123456789,
                            process_id=4096, thread_id=4097, tick_count=123456)
        machine.mem_map(HEAP_BASE, HEAP_CAPACITY, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        self.heaps = {}
        self.blocks = {}
        self.cursor = HEAP_BASE
        self.process_heap = None

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
        self.machine.mem_write(address, data)
        event.setdefault('memory_writes', []).append(dict(address=hex(address), size=len(data)))

    def invoke(self, function, args, event):
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
        if module.lower() not in ('kernel32.dll', 'kernelbase.dll') or function not in self.ARGUMENTS:
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
                    heaps={hex(h): data for h, data in self.heaps.items()},
                    heap_arena=dict(base=hex(HEAP_BASE), capacity=HEAP_CAPACITY, used=self.cursor - HEAP_BASE),
                    limitations='Synthetic clock/IDs and bounded single-thread heaps; freed blocks not reused or unmapped; unspecified allocation contents filled A5 unless zero requested; no OS calls, device, license, filesystem, scheduling or time progression; API writes logged separately from CPU write events')
