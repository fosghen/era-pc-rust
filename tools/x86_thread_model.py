"""Opt-in x86 NT_TIB skeleton, not a Windows exception dispatcher.

The initial empty SEH chain is an explicit hypothesis. Unknown TEB fields
stop the experiment; no PEB, TLS, license state or API answers are invented.
"""
import struct

import unicorn as uc
from unicorn import x86_const as x86


GDT_BASE = 0x73000000
TIB_BASE = 0x73001000
THREAD_REGIONS = [(GDT_BASE, 0x1000), (TIB_BASE, 0x1000)]


def segment_descriptor(base, limit, access, flags):
    if not 0 <= base < 2**32 or not 0 <= limit < 2**20:
        raise ValueError('Segment descriptor outside x86 bounds')
    low = (limit & 0xffff) | ((base & 0xffff) << 16)
    high = ((base >> 16) & 0xff) | (access << 8) | (limit & 0xf0000) | (flags << 20) | (base & 0xff000000)
    return struct.pack('<II', low, high)


class X86ThreadModel:
    def __init__(self, machine, stack_base, stack_size):
        self.machine = machine
        self.stack_low, self.stack_high = stack_base, stack_base + stack_size
        self.events = []
        self.read_events = 0
        for address, size in THREAD_REGIONS:
            machine.mem_map(address, size, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        # An explicit 32-bit SS is needed when loading real segment descriptors:
        # do not accidentally turn the emulator's high-address stack into SP16.
        descriptors = bytes(8) + segment_descriptor(0, 0xfffff, 0x93, 0xc)
        descriptors += segment_descriptor(TIB_BASE, 0xfff, 0xf3, 0x4)
        machine.mem_write(GDT_BASE, descriptors)
        machine.reg_write(x86.UC_X86_REG_GDTR, (0, GDT_BASE, len(descriptors) - 1, 0))
        machine.reg_write(x86.UC_X86_REG_SS, 0x08)
        machine.reg_write(x86.UC_X86_REG_FS, 0x13)
        machine.mem_protect(GDT_BASE, 0x1000, uc.UC_PROT_READ)
        # NT_TIB x86 layout: ExceptionList, StackBase, StackLimit,
        # SubSystemTib, FiberData, ArbitraryUserPointer, Self.
        machine.mem_write(TIB_BASE, struct.pack('<7I', 0xffffffff, self.stack_high,
                                               self.stack_low, 0, 0, 0, TIB_BASE))

    def install_hooks(self, state):
        def access(machine, kind, address, size, value, _):
            offset = address - TIB_BASE
            write = kind == uc.UC_MEM_WRITE
            supported = 0 <= offset and offset + size <= (4 if write else 28)
            if not supported:
                state.update(reason='unsupported_thread_field', thread_access=dict(
                    offset=hex(offset), size=size, operation='write' if write else 'read',
                    instruction=hex(machine.reg_read(x86.UC_X86_REG_EIP))))
                machine.emu_stop()
                return
            if write:
                if len(self.events) >= 4096:
                    state['reason'] = 'thread_event_limit'
                    machine.emu_stop()
                    return
                self.events.append(dict(instruction=hex(machine.reg_read(x86.UC_X86_REG_EIP)),
                                        offset=offset, size=size, value=hex(value & ((1 << (8 * size)) - 1))))
            else:
                self.read_events += 1

        self.machine.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, access,
                              begin=TIB_BASE, end=TIB_BASE + 0xfff)

    def report(self):
        head = struct.unpack('<I', self.machine.mem_read(TIB_BASE, 4))[0]
        chain, seen, current = [], set(), head
        chain_stop = 'empty_or_terminated'
        while current != 0xffffffff:
            if len(chain) == 32:
                chain_stop = 'depth_limit'
                break
            if current in seen:
                chain_stop = 'cycle'
                break
            if current % 4 or not self.stack_low <= current <= self.stack_high - 8:
                chain_stop = 'outside_modeled_stack_or_unaligned'
                break
            seen.add(current)
            following, handler = struct.unpack('<II', self.machine.mem_read(current, 8))
            chain.append(dict(record=hex(current), next=hex(following), handler=hex(handler)))
            current = following
        return dict(tib_base=hex(TIB_BASE), gdt_base=hex(GDT_BASE),
                    fs_selector=hex(self.machine.reg_read(x86.UC_X86_REG_FS)),
                    ss_selector=hex(self.machine.reg_read(x86.UC_X86_REG_SS)),
                    stack_limit=hex(self.stack_low), stack_base=hex(self.stack_high),
                    initial_exception_list='0xffffffff', final_exception_list=hex(head),
                    exception_list_writes=self.events, tib_reads=self.read_events,
                    seh_chain=chain, seh_chain_stop=chain_stop,
                    limitations='One synthetic NT_TIB with initially empty SEH chain; only ExceptionList writable; no PEB, TLS, OS dispatch, unwind or Windows segment-selector fidelity')
