"""Disposable synthetic worker-entry dependency probe; never ResumeThread.

The caller must keep the source engine stopped throughout cloning/probing. No
source registers, memory, hooks or model objects are modified. Only addresses,
bounded scalar observations and hashes leave this helper, never cloned bytes.
"""
from collections import deque
import hashlib
import math
from pathlib import Path
import struct
import time

import capstone as cs
import unicorn as uc
from unicorn import x86_const as x86

from x86_thread_model import segment_descriptor


GDT = 0x78000000
TIB = 0x78001000
SENTINEL = 0x78002000
STACK = 0x78010000
STACK_SIZE = 0x10000
FIXTURES = ((GDT, 0x1000), (TIB, 0x1000), (SENTINEL, 0x1000), (STACK, STACK_SIZE))
CLONE_LIMIT = 512 * 1024 * 1024
REGION_LIMIT = 8192
CHUNK = 1024 * 1024
MAX_RDTSC_VALUES = 1024
REGISTERS = {name: getattr(x86, 'UC_X86_REG_' + name.upper()) for name in
             ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags')}


def _dword(value):
    return type(value) is int and 0 <= value < 2**32


def _ranges(values):
    values = tuple(values)
    if len(values) > REGION_LIMIT:
        raise ValueError('Too many ranges')
    for start, size in values:
        if not _dword(start) or type(size) is not int or size <= 0 or start + size > 2**32:
            raise ValueError('Ranges must be nonempty x86 (start, size) pairs')
    return values


def _overlaps(address, size, ranges):
    return any(address < start + length and start < address + size for start, length in ranges)


def probe_worker_entry(source_machine, *, entry, parameter, thread_id, image_ranges,
                       stop_addresses, reference_ranges, creator_tib_range=None,
                       protected_ranges=(), max_instructions=100000, max_seconds=2,
                       rdtsc_values=()):
    """Clone a stopped UC32 and inspect an artificial stdcall entry, stop-only.

    All range arguments contain (start, size), not inclusive end addresses.
    Configuration errors raise ValueError before execution. Runtime boundaries
    return a report. This function neither validates nor resumes a thread handle.
    """
    setup_started = time.monotonic()
    if (source_machine.query(uc.UC_QUERY_ARCH) != uc.UC_ARCH_X86 or
            source_machine.query(uc.UC_QUERY_MODE) != uc.UC_MODE_32):
        raise ValueError('Source must be a stopped x86 UC_MODE_32 engine')
    if not all(_dword(v) for v in (entry, parameter, thread_id)) or thread_id == 0:
        raise ValueError('Entry/parameter/TID must be DWORDs, TID nonzero')
    if type(max_instructions) is not int or not 1 <= max_instructions <= 100000:
        raise ValueError('Instruction budget must be 1..100000')
    if (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds)
            or not 0 < max_seconds <= 10):
        raise ValueError('Execution time budget must be positive and <=10 seconds')
    if (type(rdtsc_values) not in (tuple, list) or len(rdtsc_values) > MAX_RDTSC_VALUES or
            any(type(value) is not int or not 0 <= value < 2**64 for value in rdtsc_values)):
        raise ValueError(f'RDTSC fixture must be a tuple/list of at most {MAX_RDTSC_VALUES} uint64 integers')
    rdtsc_values = tuple(rdtsc_values)
    images = _ranges(image_ranges)
    references = _ranges(reference_ranges)
    opaque = _ranges(protected_ranges)
    creator = _ranges((creator_tib_range,)) if creator_tib_range is not None else ()
    stops = dict(stop_addresses)
    if len(stops) > 65536 or any(not _dword(p) or not isinstance(n, str) or len(n) > 512
                               for p, n in stops.items()):
        raise ValueError('Invalid bounded stop-address map')
    if not _overlaps(entry, 1, images):
        raise ValueError('Entry must be in an explicit input image')
    regions = [(start, last - start + 1, permissions)
               for start, last, permissions in source_machine.mem_regions()]
    if len(regions) > REGION_LIMIT or sum(size for _, size, _ in regions) > CLONE_LIMIT:
        raise ValueError('Clone region/byte budget exceeded')
    for start, size, _ in regions:
        if _overlaps(start, size, FIXTURES):
            raise ValueError('Source mapping collides with worker fixtures')
    for start, size in images + references + creator + opaque:
        if _overlaps(start, size, FIXTURES):
            raise ValueError('Declared range collides with worker fixtures')
    if any(_overlaps(address, 1, FIXTURES) for address in stops):
        raise ValueError('Stop address collides with worker fixtures')

    child = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
    manifest = []
    for start, size, permissions in regions:
        child.mem_map(start, size, uc.UC_PROT_ALL)
        digest = hashlib.sha256()
        for offset in range(0, size, CHUNK):
            data = bytes(source_machine.mem_read(start + offset, min(CHUNK, size - offset)))
            digest.update(data)
            child.mem_write(start + offset, data)
        child.mem_protect(start, size, permissions)
        manifest.append(dict(address=hex(start), size=size, permissions=permissions,
                             sha256=digest.hexdigest()))
    for start, size in FIXTURES:
        child.mem_map(start, size, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
    descriptors = bytes(8) + segment_descriptor(0, 0xfffff, 0x93, 0xc)
    descriptors += segment_descriptor(TIB, 0xfff, 0xf3, 0x4)
    child.mem_write(GDT, descriptors)
    child.reg_write(x86.UC_X86_REG_GDTR, (0, GDT, len(descriptors) - 1, 0))
    child.reg_write(x86.UC_X86_REG_SS, 8)
    child.reg_write(x86.UC_X86_REG_FS, 0x13)
    child.mem_protect(GDT, 0x1000, uc.UC_PROT_READ)
    child.mem_protect(SENTINEL, 0x1000, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
    child.mem_write(TIB, struct.pack('<7I', 0xffffffff, STACK + STACK_SIZE, STACK,
                                     0, 0, 0, TIB))
    child.mem_write(TIB + 0x24, struct.pack('<I', thread_id))
    for register in REGISTERS.values():
        child.reg_write(register, 0)
    sp = STACK + STACK_SIZE - 16
    child.mem_write(sp, struct.pack('<2I', SENTINEL, parameter))
    child.reg_write(x86.UC_X86_REG_ESP, sp)
    child.reg_write(x86.UC_X86_REG_EIP, entry)
    child.reg_write(x86.UC_X86_REG_EFLAGS, 2)
    child.reg_write(x86.UC_X86_REG_MXCSR, 0x1f80)
    initial = {name: hex(child.reg_read(reg)) for name, reg in REGISTERS.items()}
    state = dict(reason='running', instructions=0)
    rdtsc_events = []
    tail = deque(maxlen=24)
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    decoder.detail = True

    def stop(reason, **metadata):
        if state['reason'] == 'running':
            state.update(reason=reason, **metadata)
        child.emu_stop()

    def guarded(callback):
        def wrapper(*args):
            try:
                return callback(*args)
            except Exception as error:
                stop('callback_error', callback_error=type(error).__name__)
        return wrapper

    @guarded
    def instruction(machine, address, size, _):
        if state['reason'] != 'running':
            machine.emu_stop()
            return
        if not 1 <= size <= 15:
            stop('unsupported_instruction', instruction_size=size)
            return
        if _overlaps(address, size, creator):
            stop('creator_tib_access', memory_address=hex(address), access_size=size, operation='fetch')
            return
        if _overlaps(address, size, opaque):
            stop('protected_region_access', memory_address=hex(address), access_size=size, operation='fetch')
            return
        if address == SENTINEL:
            stop('returned', stack_cleanup_matches=machine.reg_read(x86.UC_X86_REG_ESP) == sp + 8)
            return
        if address in stops:
            stop('external_boundary', boundary=stops[address], boundary_address=hex(address))
            return
        if _overlaps(address, size, references):
            stop('reference_boundary', boundary_address=hex(address))
            return
        if not any(start <= address and address + size <= start + length for start, length in images):
            stop('outside_input_images', boundary_address=hex(address))
            return
        if state['instructions'] >= max_instructions:
            stop('instruction_limit')
            return
        decoded = next(decoder.disasm(bytes(machine.mem_read(address, size)), address, count=1), None)
        if decoded is None:
            stop('unsupported_instruction')
            return
        if decoded.id == cs.x86_const.X86_INS_RDTSC and rdtsc_values:
            if len(rdtsc_events) == len(rdtsc_values):
                stop('rdtsc_fixture_exhausted', boundary_address=hex(address))
                return
            value = rdtsc_values[len(rdtsc_events)]
            machine.reg_write(x86.UC_X86_REG_EAX, value & 0xffffffff)
            machine.reg_write(x86.UC_X86_REG_EDX, value >> 32)
            machine.reg_write(x86.UC_X86_REG_EIP, (address + size) & 0xffffffff)
            rdtsc_events.append(dict(address=hex(address), instruction_index=state['instructions'],
                                     value=hex(value)))
            state['instructions'] += 1
            tail.append(hex(address))
            # Resume only from the outer loop, without executing actual RDTSC.
            # No flags, other registers, timestamps or model objects are changed.
            machine.emu_stop()
            return
        # Do not silently obtain time/CPU/I/O or privileged environment behavior.
        if decoded.group(cs.CS_GRP_PRIVILEGE) or decoded.mnemonic.split()[-1] in ('syscall', 'sysenter', 'sysret', 'sysexit', 'int', 'int1',
                                'int3', 'into', 'in', 'insb', 'insw', 'insd', 'out',
                                'outsb', 'outsw', 'outsd', 'hlt', 'rdtsc', 'rdtscp', 'cpuid',
                                'rdrand', 'rdseed', 'rdmsr', 'wrmsr', 'rdpmc', 'xgetbv', 'xsetbv',
                                'rdpid', 'rdpkru', 'wrpkru', 'sgdt', 'sidt', 'sldt', 'str', 'smsw'):
            stop('unsupported_instruction', instruction_kind=decoded.mnemonic)
            return
        state['instructions'] += 1
        tail.append(hex(address))

    @guarded
    def memory(machine, kind, address, size, value, _):
        operation = 'write' if kind == uc.UC_MEM_WRITE else 'read'
        metadata = dict(memory_address=hex(address), access_size=size, operation=operation)
        if _overlaps(address, size, creator):
            stop('creator_tib_access', **metadata)
        elif _overlaps(address, size, opaque):
            stop('protected_region_access', **metadata)
        elif _overlaps(address, size, ((TIB, 0x1000),)):
            offset = address - TIB
            allowed = (0 <= offset and offset + size <= (4 if operation == 'write' else 28))
            allowed |= operation == 'read' and 0x24 <= offset and offset + size <= 0x28
            if not allowed:
                stop('unsupported_thread_field', **metadata)

    @guarded
    def invalid(machine, access, address, size, value, _):
        stop('unmapped_or_protected_memory', memory_address=hex(address), access_size=size,
             access=access)
        return False

    @guarded
    def interrupt(machine, number, _):
        stop('interrupt', interrupt_number=number)

    child.hook_add(uc.UC_HOOK_CODE, instruction)
    child.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, memory)
    child.hook_add(uc.UC_HOOK_MEM_INVALID, invalid)
    child.hook_add(uc.UC_HOOK_INTR, interrupt)
    setup_seconds = time.monotonic() - setup_started
    started = time.monotonic()
    while state['reason'] == 'running':
        remaining = max_seconds - (time.monotonic() - started)
        if remaining <= 0:
            stop('time_limit')
            break
        if state['instructions'] >= max_instructions:
            stop('instruction_limit')
            break
        try:
            child.emu_start(child.reg_read(x86.UC_X86_REG_EIP), 0,
                            count=min(10000, max_instructions - state['instructions']),
                            timeout=max(1, int(min(remaining, 0.1) * 1000000)))
        except uc.UcError as error:
            stop('emulator_error', emulator_error=str(error))
    # Bounded raw metadata from our own stack only; not an ABI interpretation
    # and never a dereference of argument pointers or copied process buffers.
    stopped_sp = child.reg_read(x86.UC_X86_REG_ESP)
    stack_observation = dict(address=hex(stopped_sp), words=[],
        scope='At most nine raw DWORDs within the synthetic worker stack; not validated API arguments')
    if STACK <= stopped_sp < STACK + STACK_SIZE:
        count = min(9, (STACK + STACK_SIZE - stopped_sp) // 4)
        try:
            stack_observation['words'] = [hex(value) for value in struct.unpack(
                '<' + 'I' * count, child.mem_read(stopped_sp, count * 4))]
        except uc.UcError:
            stack_observation['error'] = 'Synthetic stack unreadable'
    else:
        stack_observation['error'] = 'ESP outside synthetic worker stack'
    stack_observation.update(requested_words=9, captured_words=len(stack_observation['words']),
                             truncated=len(stack_observation['words']) < 9)
    state.update(elapsed_seconds=time.monotonic() - started, setup_seconds=setup_seconds,
                 stack_observation=stack_observation,
                 initial_registers=initial,
                 registers={name: hex(child.reg_read(reg)) for name, reg in REGISTERS.items()},
                 tail_instruction_addresses=list(tail), clone_manifest=manifest,
                 cloned_bytes=sum(size for _, size, _ in regions),
                 limits=dict(instructions=max_instructions, seconds=max_seconds,
                             clone_bytes=CLONE_LIMIT, clone_regions=REGION_LIMIT),
                 fixture=dict(entry=hex(entry), parameter=hex(parameter), thread_id=thread_id,
                              stack_base=hex(STACK), stack_size=STACK_SIZE, tib=hex(TIB),
                              sentinel=hex(SENTINEL), fs_selector='0x13', ss_selector='0x8',
                              mxcsr='0x1f80', other_cpu_state='Fresh Unicorn defaults, not creator state',
                              rdtsc_values=[hex(value) for value in rdtsc_values]),
                 rdtsc_events=rdtsc_events,
                 source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 versions=dict(unicorn=uc.__version__, capstone=cs.__version__),
                 observer='python', resume_thread_success=False,
                 policy_ranges=dict(input_images=[(hex(p), n) for p, n in images],
                                    reference_images=[(hex(p), n) for p, n in references],
                                    creator_tib=[(hex(p), n) for p, n in creator],
                                    protected=[(hex(p), n) for p, n in opaque]),
                 stop_address_count=len(stops),
                 semantics='Artificial entry dependency probe, not a native worker or ResumeThread success',
                 instruction_count_semantics='Approved instruction hook entries including modeled RDTSC; event instruction_index is zero-based; faulting/memory-stopped instruction may be counted, boundary instructions excluded',
                 limitations='Stopped source required; independent byte/permission clone, no source CPU/model state inherited; explicit stdcall registers/stack/NT_TIB; optional finite RDTSC sequence writes EDX:EAX without executing RDTSC, preserving flags, no clock progression or native timing; no APIs, TLS, DllMain, callbacks, scheduling, exception dispatch, host/device access or main continuation; memory guards are pre-access observations, not proof of instruction commit; only explicit input-image code allowed; first boundary depends on these artificial assumptions')
    return state
