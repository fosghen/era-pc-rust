"""Bounded x86 PE loader tracing in Unicorn, without native execution.

No licensing server or dongle is emulated. Imported function addresses are
replaced IN EMULATED MEMORY ONLY by stop markers. An optional read-only PE
module model resolves module/export lookups only (LoadLibraryA requires an
already mapped module). An incomplete
process environment means a stop is evidence about this experiment, not proof
of what a real Windows process would do. No vendor bytes are exported.
"""
import argparse
from collections import Counter, deque
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import struct
import time

import capstone
import pefile
import unicorn as uc
from unicorn import x86_const as x86

from pe_module_model import ModuleModel, utf16_z
from x86_thread_model import THREAD_REGIONS, TIB_BASE, X86ThreadModel
from startup_model import STARTUP_REGIONS, StartupModel


def integer(text):
    return int(text, 0)


def address_size(text):
    address, size = text.split(':', 1)
    return integer(address), integer(size)


def trace(path, export, argument, max_instructions, max_seconds, modules=(), thread_model=False,
          dll_attach=False, observe=(), watch=(), startup_model=False, nls_codepage=None, nls_sort=None, nls_case=None,
          after_attach_export=None):
    if (nls_codepage or nls_sort or nls_case) and not startup_model:
        raise ValueError('NLS references require the explicit startup model')
    if after_attach_export and not dll_attach:
        raise ValueError('Chained export requires DLL attach')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    pe = pefile.PE(data=raw)
    if pe.FILE_HEADER.Machine != 0x14C:
        raise ValueError('Only 32-bit x86 PE images supported')
    base = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    if dll_attach and (export or not pe.FILE_HEADER.Characteristics & 0x2000):
        raise ValueError('DLL attach requires a DLL entry point, not an export or executable')
    if len(observe) > 32 or len(watch) > 32:
        raise ValueError('At most 32 observation points and watched ranges')
    if any(not base <= address < base + image_size for address in observe):
        raise ValueError('Observation point outside primary image')
    if any(not (1 <= size <= 4096 and base <= address and address + size <= base + image_size)
           for address, size in watch):
        raise ValueError('Watch must be 1..4096 bytes within the primary image')
    mapped_size = (image_size + 4095) & ~4095
    if not 0 < mapped_size <= 256 * 1024 * 1024:
        raise ValueError('Image size outside trace limits')
    stack, sentinel, imports_base = 0x70000000, 0x71000000, 0x72000000
    reserved_regions = [(stack, 0x10000), (sentinel, 0x1000), (imports_base, 0x10000)]
    if thread_model:
        reserved_regions += THREAD_REGIONS
    if startup_model:
        reserved_regions += STARTUP_REGIONS
    for reserved, size in reserved_regions:
        if base < reserved + size and base + mapped_size > reserved:
            raise ValueError('Image overlaps trace harness memory')
    machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
    machine.mem_map(base, mapped_size)
    machine.mem_write(base, raw[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    for section in pe.sections:
        data = section.get_data()
        if data:
            machine.mem_write(base + section.VirtualAddress, data)
    for address, size in [(stack, 0x10000), (sentinel, 0x1000), (imports_base, 0x10000)]:
        machine.mem_map(address, size)
    module_model = ModuleModel(machine, modules, [(base, mapped_size)] + reserved_regions)
    thread = X86ThreadModel(machine, stack, 0x10000) if thread_model else None
    startup = StartupModel(machine, nls_codepage, nls_sort, nls_case) if startup_model else None
    if startup:
        startup.primary_region = (base, mapped_size)
    functions = {}
    iat_map = []
    for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        for imp in descriptor.imports:
            marker = imports_base + 16 * len(functions)
            if marker >= imports_base + 0x10000:
                raise ValueError('Too many imports')
            name = imp.name.decode(errors='replace') if imp.name else f'ordinal:{imp.ordinal}'
            name = descriptor.dll.decode(errors='replace') + '!' + name
            functions[marker] = name
            machine.mem_write(imp.address, struct.pack('<I', marker))
            iat_map.append(dict(iat_va=hex(imp.address), marker=hex(marker), name=name))
    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    next_entry = None
    if export or after_attach_export:
        symbols = getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
        matches = [s for s in symbols if s.name and s.name.decode() == (export or after_attach_export)]
        if not matches or matches[0].forwarder:
            raise ValueError('Export missing or forwarded')
        if not 0 < matches[0].address < image_size:
            raise ValueError('Export address outside primary image')
        if export:
            entry = base + matches[0].address
        else:
            next_entry = base + matches[0].address
    sp = stack + 0x8000
    arguments = [base, 1, 0] if dll_attach else [argument & 0xFFFFFFFF]
    machine.mem_write(sp, struct.pack('<' + 'I' * (1 + len(arguments)), sentinel, *arguments))
    machine.reg_write(x86.UC_X86_REG_ESP, sp)
    machine.reg_write(x86.UC_X86_REG_EFLAGS, 2)
    state = dict(input_name=path.name, input_sha256=digest, input_size=len(raw),
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 module_model_sha256=hashlib.sha256(Path(__file__).with_name('pe_module_model.py').read_bytes()).hexdigest(),
                 thread_model_sha256=hashlib.sha256(Path(__file__).with_name('x86_thread_model.py').read_bytes()).hexdigest(),
                 startup_model_sha256=hashlib.sha256(Path(__file__).with_name('startup_model.py').read_bytes()).hexdigest(),
                 nls_model_sha256=hashlib.sha256(Path(__file__).with_name('nls_model.py').read_bytes()).hexdigest(),
                 entry=hex(entry), export=export, argument=argument,
                 invocation='DLL_PROCESS_ATTACH entry (no dependency initialization)' if dll_attach else 'Single entry/export call',
                 initial_stack_arguments=[hex(value) for value in arguments],
                 limits=dict(instructions=max_instructions, seconds=max_seconds),
                 versions=dict(unicorn=version('unicorn'), capstone=version('capstone'), pefile=version('pefile')),
                 runtime_version_strings=dict(unicorn=uc.__version__, capstone=capstone.__version__, pefile=pefile.__version__),
                 instructions=0, image_write_events=0, reason='running',
                 instruction_count_semantics='Observed instruction starts; includes a faulting instruction, excludes stop markers',
                 environment='No native Windows process; no PEB or dependency initialization; imports are stop markers; image pages initially RWX',
                 iat_markers=iat_map)
    state['active_stage'] = 'dll_attach' if dll_attach else 'single_call'
    state['stage_returns'] = []
    if after_attach_export:
        state['after_attach_export'] = after_attach_export
        state['invocation'] = 'DLL_PROCESS_ATTACH then export in the same CPU/memory state, only on successful attach'
    if thread:
        thread.install_hooks(state)
        state['environment'] += '; synthetic NT_TIB/FS with initially empty SEH chain, no OS exception dispatch'
    if startup:
        startup.trace_state = state
    tail = deque(maxlen=24)
    writes = Counter()
    write_ranges = {}
    observed = set(observe)
    observations = []
    watched = [(address, bytes(machine.mem_read(address, size))) for address, size in watch]
    watch_writes = [deque(maxlen=8) for _ in watched]
    sections = [(base + s.VirtualAddress, base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                 s.Name.rstrip(b'\0').decode(errors='replace') + '@' + hex(base + s.VirtualAddress)) for s in pe.sections]
    started = time.monotonic()

    def instruction(m, address, size, _):
        if address == sentinel:
            state['stage_returns'].append(dict(stage=state['active_stage'],
                instruction_index=state['instructions'], eax=hex(m.reg_read(x86.UC_X86_REG_EAX)),
                esp=hex(m.reg_read(x86.UC_X86_REG_ESP))))
            if state['active_stage'] == 'dll_attach' and next_entry is not None:
                if not m.reg_read(x86.UC_X86_REG_EAX):
                    state['reason'] = 'dll_attach_failed'
                elif m.reg_read(x86.UC_X86_REG_ESP) != sp + 16:
                    state['reason'] = 'dll_attach_unbalanced_stack'
                elif thread and struct.unpack('<I', m.mem_read(TIB_BASE, 4))[0] != 0xffffffff:
                    state['reason'] = 'dll_attach_unrestored_seh'
                else:
                    state['active_stage'] = 'export_after_attach'
                    state['export_start_instruction'] = state['instructions']
                    m.mem_write(sp, struct.pack('<2I', sentinel, argument & 0xffffffff))
                    m.reg_write(x86.UC_X86_REG_ESP, sp)
                    m.reg_write(x86.UC_X86_REG_EIP, next_entry)
                m.emu_stop()
                return
        if address in observed:
            if len(observations) >= 256:
                state['reason'] = 'observation_limit'
                m.emu_stop()
                return
            event = dict(address=hex(address), instruction_index=state['instructions'])
            event['eax'] = hex(m.reg_read(x86.UC_X86_REG_EAX))
            try:
                esp = m.reg_read(x86.UC_X86_REG_ESP)
                event['stack_words'] = [hex(w) for w in struct.unpack('<9I', m.mem_read(esp, 36))]
            except uc.UcError:
                event['stack_unreadable'] = True
            observations.append(event)
        # Markers are observed but never executed and do not count as instructions.
        external_name = functions.get(address)
        if modules and external_name is None and module_model.contains(address):
            names = module_model.address_names.get(address, [])
            external_name = names[0] if names else 'mapped_module!' + hex(address)
        if external_name and modules:
            handled, observation = module_model.handle(external_name)
            if handled:
                # Resume outside the hook, after the modeled stdcall return.
                m.emu_stop()
                return
            if observation:
                state['unresolved_module_call'] = observation
        if external_name and startup:
            handled, observation = startup.handle(external_name)
            if handled:
                m.emu_stop()
                return
            if observation:
                state['unresolved_startup_call'] = observation
        if address == sentinel or external_name:
            state['reason'] = 'returned' if address == sentinel else 'external_import'
            if external_name:
                state['external_import'] = external_name
                esp = m.reg_read(x86.UC_X86_REG_ESP)
                try:
                    words = struct.unpack('<9I', m.mem_read(esp, 36))
                    state['external_stack_words'] = [hex(w) for w in words]
                    if external_name.lower() == 'advapi32.dll!regopenkeyexw':
                        try:
                            state['registry_request'] = dict(root_handle=hex(words[1]),
                                subkey=utf16_z(m, words[2]), options=hex(words[3]),
                                desired_access=hex(words[4]), output_handle_address=hex(words[5]))
                        except (ValueError, uc.UcError) as error:
                            state['registry_argument_error'] = str(error)
                    if external_name.lower().endswith(('!getmodulehandlea', '!loadlibrarya')):
                        chars = bytearray()
                        if words[1]:
                            for offset in range(260):
                                byte = m.mem_read(words[1] + offset, 1)
                                if byte == b'\0':
                                    break
                                chars.extend(byte)
                        state['module_name_argument'] = chars.decode('ascii', errors='replace') if words[1] else None
                except uc.UcError:
                    pass
            m.emu_stop()
            return
        state['instructions'] += 1
        tail.append(address)

    def invalid(m, access, address, size, value, _):
        state.update(reason='unmapped_or_protected_memory', access=access,
                     memory_address=hex(address), access_size=size)
        # Describe the addressing mechanism, not proprietary instruction bytes.
        pc = m.reg_read(x86.UC_X86_REG_EIP)
        try:
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            decoder.detail = True
            decoded = next(decoder.disasm(bytes(m.mem_read(pc, 15)), pc, count=1), None)
            if decoded:
                operands = []
                for operand in decoded.operands:
                    if operand.type == capstone.x86_const.X86_OP_MEM:
                        mem = operand.mem
                        operands.append(dict(segment=decoded.reg_name(mem.segment),
                                             base=decoded.reg_name(mem.base),
                                             index=decoded.reg_name(mem.index),
                                             scale=mem.scale, displacement=mem.disp,
                                             operand_size=operand.size))
                state['fault_instruction'] = dict(address=hex(pc), mnemonic=decoded.mnemonic,
                                                  memory_operands=operands)
        except (uc.UcError, capstone.CsError):
            pass
        if access in (uc.UC_MEM_FETCH_UNMAPPED, uc.UC_MEM_FETCH_PROT) and tail:
            # At a fetch fault EIP already names the destination. Describe the
            # last observed instruction separately, without exporting its bytes.
            origin = tail[-1]
            try:
                available = next(end - origin + 1 for start, end, _ in m.mem_regions()
                                 if start <= origin <= end)
                code = bytes(m.mem_read(origin, min(15, available)))
                decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                decoder.detail = True
                decoded = next(decoder.disasm(code, origin, count=1), None)
                if decoded:
                    info = dict(address=hex(origin), mnemonic=decoded.mnemonic,
                                size=decoded.size,
                                basis='Decoded from memory at fault time, not an execution-time snapshot')
                    if decoded.group(capstone.CS_GRP_JUMP) or decoded.group(capstone.CS_GRP_CALL):
                        if decoded.operands and decoded.operands[0].type == capstone.x86_const.X86_OP_IMM:
                            info['immediate_target'] = hex(decoded.operands[0].imm & 0xffffffff)
                        elif decoded.operands and decoded.operands[0].type == capstone.x86_const.X86_OP_MEM:
                            operand = decoded.operands[0]
                            mem = operand.mem
                            info['indirect_operand'] = dict(segment=decoded.reg_name(mem.segment),
                                base=decoded.reg_name(mem.base), index=decoded.reg_name(mem.index),
                                scale=mem.scale, displacement=mem.disp, size=operand.size)
                            if not mem.segment and not mem.base and not mem.index and operand.size == 4:
                                pointer = mem.disp & 0xffffffff
                                info['indirect_pointer_address'] = hex(pointer)
                                info['indirect_pointer_value'] = hex(struct.unpack('<I', m.mem_read(pointer, 4))[0])
                    if base <= origin and origin + decoded.size <= base + image_size:
                        initial = pe.get_data(origin - base, decoded.size)
                        if len(initial) == decoded.size:
                            info['differs_from_input_image'] = initial != code[:decoded.size]
                    state['fetch_origin'] = info
            except (uc.UcError, capstone.CsError, StopIteration, pefile.PEFormatError):
                pass
        return False

    def interrupt(m, number, _):
        state.update(reason='CPU_interrupt', interrupt=number)
        m.emu_stop()

    def written(m, access, address, size, value, _):
        if base <= address < base + image_size:
            state['image_write_events'] += 1
            name = next((n for start, end, n in sections if start <= address < end), 'headers_or_gap')
            writes[name] += 1
            if name not in write_ranges:
                write_ranges[name] = [address, address + size]
            else:
                write_ranges[name][0] = min(write_ranges[name][0], address)
                write_ranges[name][1] = max(write_ranges[name][1], address + size)
            for index, (start, initial) in enumerate(watched):
                if address < start + len(initial) and start < address + size:
                    watch_writes[index].append(dict(instruction=hex(m.reg_read(x86.UC_X86_REG_EIP)),
                        instruction_index=state['instructions'], address=hex(address), size=size))

    machine.hook_add(uc.UC_HOOK_CODE, instruction)
    machine.hook_add(uc.UC_HOOK_MEM_INVALID, invalid)
    machine.hook_add(uc.UC_HOOK_INTR, interrupt)
    machine.hook_add(uc.UC_HOOK_MEM_WRITE, written)
    next_progress = started + 5
    while state['reason'] == 'running':
        if state['instructions'] >= max_instructions:
            state['reason'] = 'instruction_limit'
            break
        remaining_seconds = max_seconds - (time.monotonic() - started)
        if remaining_seconds <= 0:
            state['reason'] = 'time_limit'
            break
        pc = entry if state['instructions'] == 0 else machine.reg_read(x86.UC_X86_REG_EIP)
        try:
            machine.emu_start(pc, 0, timeout=max(1, int(min(2., remaining_seconds) * 1_000_000)),
                              count=min(250_000, max_instructions - state['instructions']))
        except uc.UcError as error:
            state['emulator_error'] = str(error)
            if state['reason'] == 'running':
                state['reason'] = 'emulator_error'
        if time.monotonic() >= next_progress:
            print(json.dumps(dict(progress_instructions=state['instructions'],
                                  eip=hex(machine.reg_read(x86.UC_X86_REG_EIP)),
                                  image_writes=state['image_write_events'])), flush=True)
            next_progress = time.monotonic() + 5
    state['elapsed_seconds'] = round(time.monotonic() - started, 4)
    state['registers'] = {name: hex(machine.reg_read(reg)) for name, reg in [
        ('eax', x86.UC_X86_REG_EAX), ('ebx', x86.UC_X86_REG_EBX), ('ecx', x86.UC_X86_REG_ECX),
        ('edx', x86.UC_X86_REG_EDX), ('esi', x86.UC_X86_REG_ESI), ('edi', x86.UC_X86_REG_EDI),
        ('ebp', x86.UC_X86_REG_EBP), ('esp', x86.UC_X86_REG_ESP), ('eip', x86.UC_X86_REG_EIP)]}
    state['returned_import_pointer'] = functions.get(machine.reg_read(x86.UC_X86_REG_EAX)) if state['reason'] == 'returned' else None
    state['image_writes_by_section'] = dict(writes)
    state['image_write_ranges_exclusive_end'] = {n: [hex(a), hex(b)] for n, (a, b) in write_ranges.items()}
    # Addresses only: no proprietary bytes or disassembly in this shareable report.
    state['tail_instruction_addresses'] = [hex(a) for a in tail]
    state['input_unchanged'] = hashlib.sha256(path.read_bytes()).hexdigest() == digest
    if modules:
        state['module_model'] = module_model.report()
        state['environment'] += '; opt-in mapped-PE resolver model, no mapped-module code execution'
    if thread:
        state['thread_model'] = thread.report()
    if startup:
        state['startup_model'] = startup.report()
        state['environment'] += '; opt-in synthetic startup APIs including TLS/FLS (not a native Windows process)'
    if observed:
        state['execution_observations'] = observations
    if watched:
        state['watched_ranges'] = []
        for index, (address, initial) in enumerate(watched):
            final = bytes(machine.mem_read(address, len(initial)))
            changes = [i for i, (old, new) in enumerate(zip(initial, final)) if old != new]
            state['watched_ranges'].append(dict(address=hex(address), size=len(initial),
                initial_sha256=hashlib.sha256(initial).hexdigest(), final_sha256=hashlib.sha256(final).hexdigest(),
                initial_all_zero=not any(initial), final_all_zero=not any(final),
                changed_byte_count=len(changes), first_changed_address=hex(address + changes[0]) if changes else None,
                last_changed_address=hex(address + changes[-1]) if changes else None,
                last_cpu_write_events=list(watch_writes[index]),
                baseline='Mapped image after harness IAT markers, before CPU execution; bytes not exported'))
    if not state['input_unchanged']:
        raise RuntimeError('Input changed during trace')
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--export')
    parser.add_argument('--argument', type=integer, default=0)
    parser.add_argument('--thread-model', action='store_true',
                        help='Opt-in minimal x86 NT_TIB/FS; no exception dispatch or unknown TEB fields')
    parser.add_argument('--dll-attach', action='store_true',
                        help='Call DLL PE entry as (image_base, DLL_PROCESS_ATTACH, NULL), not an export')
    parser.add_argument('--after-attach-export', help='Call named one-argument export in the same state after successful DLL attach')
    parser.add_argument('--startup-model', action='store_true',
                        help='Opt-in explicitly synthetic startup API fixtures; unknown calls stop')
    parser.add_argument('--nls-codepage', type=Path, help='Explicit read-only SBCS CP1251 reference file')
    parser.add_argument('--nls-sort', type=Path, help='Explicit read-only sortdefault.nls classification reference')
    parser.add_argument('--nls-case', type=Path, help='Explicit read-only l_intl.nls simple BMP case reference')
    parser.add_argument('--observe', action='append', type=integer, default=[],
                        help='Record bounded stack observations at a primary-image instruction address')
    parser.add_argument('--watch', action='append', type=address_size, default=[],
                        help='Compare a VA:SIZE memory range before/after; hashes/counts only, no bytes')
    parser.add_argument('--module', action='append', type=Path, default=[],
                        help='Opt-in read-only reference PE for module/export resolution; repeatable')
    parser.add_argument('--max-instructions', type=integer, default=20_000_000)
    parser.add_argument('--max-seconds', type=float, default=45.)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if not 1 <= args.max_instructions <= 200_000_000 or not 0 < args.max_seconds <= 300:
        parser.error('Limits: 1..200000000 instructions; 0..300 seconds')
    if args.report.exists():
        parser.error('Report already exists; choose a new evidence filename')
    result = trace(args.file, args.export, args.argument, args.max_instructions, args.max_seconds,
                   args.module, args.thread_model, args.dll_attach, args.observe, args.watch, args.startup_model,
                   args.nls_codepage, args.nls_sort, args.nls_case, args.after_attach_export)
    with args.report.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2, ensure_ascii=False)
        output.write('\n')
    print(json.dumps({k: result[k] for k in ['reason', 'instructions', 'registers', 'image_writes_by_section', 'input_unchanged']}))


if __name__ == '__main__':
    main()
