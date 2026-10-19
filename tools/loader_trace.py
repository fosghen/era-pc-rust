"""Bounded x86 PE loader tracing in Unicorn, without native execution.

No licensing server or dongle is emulated. Imported function addresses are
replaced IN EMULATED MEMORY ONLY by stop markers. An optional read-only PE
module model resolves module/export lookups only (LoadLibraryA requires an
already mapped module). An explicit host continuation can execute the input
DLL's real exports with the EXE's caller stack. An incomplete
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

from pe_module_model import ModuleModel, REFERENCE_IMPORT_REGIONS, ascii_z, utf16_z
from x86_thread_model import THREAD_REGIONS, TIB_BASE, X86ThreadModel
from startup_model import STARTUP_REGIONS, StartupModel

WORKER_TIMESTAMP_LIMIT = 1024

def integer(text):
    return int(text, 0)


def address_size(text):
    address, size = text.split(':', 1)
    return integer(address), integer(size)


def module_base(text):
    name, address = text.split('=', 1)
    if not name or '/' in name or '\\' in name:
        raise ValueError('Expected module basename=address')
    return name, integer(address)


def rdtsc_sequence(text):
    start, step, count = (int(part, 0) for part in text.split(':'))
    if not (0 <= start < 2**64 and 0 <= step < 2**64 and 1 <= count <= WORKER_TIMESTAMP_LIMIT
            and start + step * (count - 1) < 2**64):
        raise ValueError(f'RDTSC sequence requires uint64 start:step:count, count 1..{WORKER_TIMESTAMP_LIMIT} and no overflow')
    return tuple(start + step * index for index in range(count))


def validate_limits(max_instructions, max_seconds):
    if (type(max_instructions) is not int or not 1 <= max_instructions <= 4_000_000_000
            or not 0 < max_seconds <= 900):
        raise ValueError('Limits: 1..4000000000 integer instructions; 0..900 seconds')


def trace(path, export, argument, max_instructions, max_seconds, modules=(), thread_model=False,
          dll_attach=False, observe=(), watch=(), startup_model=False, nls_codepage=None, nls_sort=None, nls_case=None,
          after_attach_export=None, reference_import_markers=False, host_after_attach=None, critical_section_layout=None,
          observer='python', memory_observer=None, module_bases=(), api_set_schema=None, computer_name=None,
          get_version_result=None, suspended_threads=False, create_thread_interior=False, event_state=False,
          worker_entry_probe=False, worker_rdtsc_sequences=(), worker_max_instructions=100000,
          worker_max_seconds=2, worker_tick_count_values=()):
    validate_limits(max_instructions, max_seconds)
    if observer not in ('python', 'rust'):
        raise ValueError('Observer must be python or rust')
    if memory_observer is None:
        memory_observer = observer
    if memory_observer not in ('python', 'rust') or (memory_observer == 'rust' and observer != 'rust'):
        raise ValueError('Rust memory observer requires the Rust instruction observer')
    if critical_section_layout and not startup_model:
        raise ValueError('Critical-section layout requires the explicit startup model')
    if computer_name is not None and not startup_model:
        raise ValueError('Computer-name fixture requires the explicit startup model')
    if get_version_result is not None and not startup_model:
        raise ValueError('GetVersion fixture requires the explicit startup model')
    if any(type(flag) is not bool for flag in (suspended_threads, create_thread_interior, event_state, worker_entry_probe)):
        raise ValueError('Thread model switches must be bool')
    if suspended_threads and not startup_model:
        raise ValueError('Suspended-thread fixture requires the explicit startup model')
    if event_state and not startup_model:
        raise ValueError('Event-state fixture requires the explicit startup model')
    if worker_entry_probe and not (startup_model and thread_model and suspended_threads):
        raise ValueError('Worker-entry probe requires startup model, thread model and suspended threads')
    if (not isinstance(worker_rdtsc_sequences, (tuple, list)) or len(worker_rdtsc_sequences) > 3
            or any(not isinstance(seq, (tuple, list)) or not 1 <= len(seq) <= WORKER_TIMESTAMP_LIMIT
                   or any(type(v) is not int or not 0 <= v < 2**64 for v in seq)
                   for seq in worker_rdtsc_sequences)):
        raise ValueError(f'At most three nonempty worker RDTSC sequences of 1..{WORKER_TIMESTAMP_LIMIT} uint64 values')
    if worker_rdtsc_sequences and not worker_entry_probe:
        raise ValueError('Worker RDTSC sequences require the explicit worker-entry probe')
    if (type(worker_tick_count_values) not in (tuple, list) or len(worker_tick_count_values) > 16
            or any(type(v) is not int or not 0 <= v < 2**32 for v in worker_tick_count_values)):
        raise ValueError('Worker GetTickCount fixture requires at most 16 uint32 values')
    if worker_tick_count_values and not worker_entry_probe:
        raise ValueError('Worker GetTickCount fixture requires the explicit worker-entry probe')
    if (type(worker_max_instructions) is not int or not 1 <= worker_max_instructions <= 1_000_000
            or type(worker_max_seconds) not in (int, float) or not 0 < worker_max_seconds <= 10):
        raise ValueError('Worker probe budgets: 1..1000000 integer instructions and 0..10 seconds')
    if not worker_entry_probe and (worker_max_instructions != 100000 or worker_max_seconds != 2):
        raise ValueError('Worker probe budgets require the explicit worker-entry probe')
    if create_thread_interior and not (startup_model and suspended_threads and modules):
        raise ValueError('Interior CreateThread profile requires startup model, suspended threads and reference modules')
    if host_after_attach and (not dll_attach or after_attach_export or export):
        raise ValueError('Host continuation requires DLL attach without an explicit export call')
    if reference_import_markers and not modules:
        raise ValueError('Reference import markers require explicit modules')
    if module_bases and not modules:
        raise ValueError('Module base overrides require explicit reference modules')
    if api_set_schema is not None and not modules:
        raise ValueError('API-set schema requires explicit reference modules')
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
    host = None
    image_ranges = [(base, image_size)]
    if host_after_attach:
        host_raw = host_after_attach.read_bytes()
        host_pe = pefile.PE(data=host_raw)
        host_base = host_pe.OPTIONAL_HEADER.ImageBase
        host_size = (host_pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
        host_entry = host_base + host_pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if (host_pe.FILE_HEADER.Machine != 0x14c or host_pe.FILE_HEADER.Characteristics & 0x2000
                or not 0 < host_size <= 256 * 1024 * 1024 or host_base % 4096
                or host_base + host_size > 2**32 or not host_base <= host_entry < host_base + host_size):
            raise ValueError('Host must be a bounded x86 executable with an in-image entry')
        host = dict(pe=host_pe, raw=host_raw, base=host_base, size=host_size, entry=host_entry,
                    sha256=hashlib.sha256(host_raw).hexdigest())
        image_ranges.append((host_base, host_pe.OPTIONAL_HEADER.SizeOfImage))
    if dll_attach and (export or not pe.FILE_HEADER.Characteristics & 0x2000):
        raise ValueError('DLL attach requires a DLL entry point, not an export or executable')
    if len(observe) > 32 or len(watch) > 32:
        raise ValueError('At most 32 observation points and watched ranges')
    if any(not any(start <= address < start + length for start, length in image_ranges) for address in observe):
        raise ValueError('Observation point outside input images')
    if any(not (1 <= size <= 4096 and any(start <= address and address + size <= start + length
                                        for start, length in image_ranges))
           for address, size in watch):
        raise ValueError('Watch must be 1..4096 bytes within an input image')
    mapped_size = (image_size + 4095) & ~4095
    if not 0 < mapped_size <= 256 * 1024 * 1024:
        raise ValueError('Image size outside trace limits')
    stack, sentinel, imports_base = 0x70000000, 0x71000000, 0x72000000
    reserved_regions = [(stack, 0x10000), (sentinel, 0x1000), (imports_base, 0x10000)]
    if thread_model:
        reserved_regions += THREAD_REGIONS
    if startup_model:
        reserved_regions += STARTUP_REGIONS
    if reference_import_markers:
        reserved_regions += REFERENCE_IMPORT_REGIONS
    if host:
        if any(host['base'] < start + length and host['base'] + host['size'] > start
               for start, length in reserved_regions):
            raise ValueError('Host image overlaps trace harness memory')
        reserved_regions.append((host['base'], host['size']))
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
    if host:
        machine.mem_map(host['base'], host['size'])
        machine.mem_write(host['base'], host['raw'][:host['pe'].OPTIONAL_HEADER.SizeOfHeaders])
        for section in host['pe'].sections:
            data = section.get_data()
            if data:
                machine.mem_write(host['base'] + section.VirtualAddress, data)
    module_model = ModuleModel(machine, modules, [(base, mapped_size)] + reserved_regions,
                              reference_import_markers, module_bases=module_bases, api_set_schema=api_set_schema)
    if host:
        module_model.register_guest(path.name, pe)
        module_model.register_guest(host_after_attach.name, host['pe'], is_main=True)
    thread = X86ThreadModel(machine, stack, 0x10000) if thread_model else None
    memory_hooks = None
    if memory_observer == 'rust':
        from native_observer import NativeMemoryHooks
        memory_hooks = NativeMemoryHooks(machine)
    startup = StartupModel(machine, nls_codepage, nls_sort, nls_case, critical_section_layout,
                           memory_hooks=memory_hooks, computer_name=computer_name,
                           get_version_result=get_version_result, suspended_threads=suspended_threads,
                           event_state=event_state) if startup_model else None
    interior = None
    if create_thread_interior:
        from interior_api_model import CreateThreadInteriorModel
        interior = CreateThreadInteriorModel(machine, module_model, stack, 0x10000)
    if startup:
        startup.primary_region = (base, mapped_size)
        if host:
            startup.additional_image_regions = [(host['base'], host['size'])]
        if thread:
            thread.set_thread_id_fixture(startup.profile['thread_id'])
    functions = {}
    iat_map = []
    import_descriptors = list(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))
    if host:
        import_descriptors += list(getattr(host['pe'], 'DIRECTORY_ENTRY_IMPORT', []))
    for descriptor in import_descriptors:
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
    guest_exports = {}
    if host:
        for symbol in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
            if symbol.forwarder or not 0 < symbol.address < image_size:
                continue
            guest_exports[f'ordinal:{symbol.ordinal}'] = base + symbol.address
            if symbol.name:
                guest_exports[symbol.name.decode('ascii')] = base + symbol.address
        next_entry = host['entry']
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
    if host:
        state['host_image'] = dict(name=host_after_attach.name, sha256=host['sha256'],
            input_size=len(host['raw']), base=hex(host['base']), entry=hex(host['entry']))
        state['guest_calls'] = []
        state['invocation'] = 'DLL_PROCESS_ATTACH then host PE entry in shared memory; explicit guest DLL exports execute with caller stack'
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
    if api_set_schema is not None:
        state['api_set_model_sha256'] = hashlib.sha256(Path(__file__).with_name('api_set_model.py').read_bytes()).hexdigest()
    if interior is not None:
        state['interior_api_model_sha256'] = hashlib.sha256(Path(__file__).with_name('interior_api_model.py').read_bytes()).hexdigest()
    observations = []
    watched = [(address, bytes(machine.mem_read(address, size))) for address, size in watch]
    watch_writes = [deque(maxlen=8) for _ in watched]
    handle_image_writes = deque(maxlen=128)
    handle_image_write_count = 0
    sections = [(base + s.VirtualAddress, base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                 s.Name.rstrip(b'\0').decode(errors='replace') + '@' + hex(base + s.VirtualAddress)) for s in pe.sections]
    if host:
        sections.extend((host['base'] + s.VirtualAddress,
            host['base'] + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
            'host:' + s.Name.rstrip(b'\0').decode(errors='replace') + '@' + hex(host['base'] + s.VirtualAddress))
            for s in host['pe'].sections)
    native = None

    def sync_observer():
        if native is not None:
            native.sync()

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
                    state['active_stage'] = 'host_after_attach' if host else 'export_after_attach'
                    state['host_start_instruction' if host else 'export_start_instruction'] = state['instructions']
                    next_arguments = [] if host else [argument & 0xffffffff]
                    m.mem_write(sp, struct.pack('<' + 'I' * (1 + len(next_arguments)), sentinel, *next_arguments))
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
                event['esp'] = hex(esp)
                event['stack_words'] = [hex(w) for w in struct.unpack('<9I', m.mem_read(esp, 36))]
            except uc.UcError:
                event['stack_unreadable'] = True
            observations.append(event)
        # Markers are observed but never executed and do not count as instructions.
        external_name = functions.get(address)
        if host and external_name:
            module_name, _, symbol_name = external_name.partition('!')
            if module_name.lower() == path.name.lower() and symbol_name in guest_exports:
                if len(state['guest_calls']) >= 256:
                    state['reason'] = 'guest_call_limit'
                else:
                    esp = m.reg_read(x86.UC_X86_REG_ESP)
                    event = dict(api=external_name, destination=hex(guest_exports[symbol_name]),
                                 instruction_index=state['instructions'], esp=hex(esp))
                    try:
                        event['stack_words'] = [hex(w) for w in struct.unpack('<9I', m.mem_read(esp, 36))]
                    except uc.UcError:
                        event['stack_unreadable'] = True
                    state['guest_calls'].append(event)
                    m.reg_write(x86.UC_X86_REG_EIP, guest_exports[symbol_name])
                m.emu_stop()
                return
        if modules and external_name is None and module_model.contains(address):
            names = module_model.address_names.get(address, [])
            external_name = names[0] if names else 'mapped_module!' + hex(address)
        if external_name and interior:
            handled, observation = interior.handle(address, startup)
            if handled:
                m.emu_stop()
                return
            if observation:
                state['unresolved_interior_call'] = observation
        if external_name and (modules or host):
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
                    module, _, api = external_name.lower().partition('!')
                    # Read-only metadata at the stop boundary. Never call the
                    # host OS, dereference buffers, or manufacture an API result.
                    if module in ('kernel32.dll', 'kernelbase.dll'):
                        if api in ('createfilea', 'createfilew'):
                            state['file_request'] = dict(filename_address=hex(words[1]),
                                desired_access=hex(words[2]), share_mode=hex(words[3]),
                                security_attributes_address=hex(words[4]), creation_disposition=hex(words[5]),
                                flags_and_attributes=hex(words[6]), template_handle=hex(words[7]))
                            try:
                                decoder = ascii_z if api == 'createfilea' else utf16_z
                                state['file_request']['filename'] = decoder(m, words[1], limit=260)
                            except (ValueError, uc.UcError) as error:
                                state['file_argument_error'] = str(error)
                        elif api == 'deviceiocontrol':
                            state['device_io_control_request'] = dict(device_handle=hex(words[1]),
                                control_code=hex(words[2]), input_buffer_address=hex(words[3]),
                                input_buffer_size=words[4], output_buffer_address=hex(words[5]),
                                output_buffer_size=words[6], bytes_returned_address=hex(words[7]),
                                overlapped_address=hex(words[8]))
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
                except uc.UcError as error:
                    state['external_argument_error'] = str(error)
            m.emu_stop()
            return
        state['instructions'] += 1
        tail.append(address)

    def invalid(m, access, address, size, value, _):
        sync_observer()
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
        sync_observer()
        state.update(reason='CPU_interrupt', interrupt=number)
        m.emu_stop()

    def written(m, access, address, size, value, _):
        nonlocal handle_image_write_count
        if any(start <= address < start + length for start, length in image_ranges):
            if startup and size == 4:
                handle = value & 0xffffffff
                record = startup.object_handles.get(handle)
                if record and record['active']:
                    sync_observer()
                    handle_image_write_count += 1
                    handle_image_writes.append(dict(address=hex(address), size=4,
                        instruction=hex(m.reg_read(x86.UC_X86_REG_EIP)), instruction_index=state['instructions'],
                        value=hex(handle), object_id=record['object']))
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
                    sync_observer()
                    watch_writes[index].append(dict(instruction=hex(m.reg_read(x86.UC_X86_REG_EIP)),
                        instruction_index=state['instructions'], address=hex(address), size=size))

    if observer == 'rust':
        from native_observer import NativeObserver
        # Keep Python for exactly the addresses that need semantic handling.
        # A whole reference module is stop-only, including non-export addresses.
        ranges = [(sentinel, sentinel + 1), (imports_base, imports_base + 0x10000)]
        ranges += [(address, address + 1) for address in observed]
        ranges += [(m['base'], m['base'] + m['size']) for m in module_model.modules.values()]
        if reference_import_markers:
            ranges += [(start, start + length) for start, length in REFERENCE_IMPORT_REGIONS]
        native = NativeObserver(machine, ranges, instruction, state, tail)
        state['instruction_observer'] = native.metadata
    else:
        machine.hook_add(uc.UC_HOOK_CODE, instruction)
        state['instruction_observer'] = dict(mode='python')
    machine.hook_add(uc.UC_HOOK_MEM_INVALID, invalid)
    machine.hook_add(uc.UC_HOOK_INTR, interrupt)
    if memory_hooks is None:
        machine.hook_add(uc.UC_HOOK_MEM_WRITE, written)
    else:
        # Preserve the existing image-write observer's access-start semantics.
        # Critical-section guards separately use full interval overlap.
        memory_hooks.install('image_writes', uc.UC_HOOK_MEM_WRITE, written,
            [(start, start + size) for start, size in image_ranges], overlap=False)
    state['instruction_observer']['memory_mode'] = memory_observer
    started = time.monotonic()  # Compilation/setup is excluded from execution timing.
    next_progress = started + 5
    try:
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
            finally:
                sync_observer()
            if native is not None:
                native.check_error()
            if memory_hooks is not None:
                memory_hooks.check_error()
            if time.monotonic() >= next_progress:
                print(json.dumps(dict(progress_instructions=state['instructions'],
                                      elapsed_seconds=round(time.monotonic() - started, 3),
                                      eip=hex(machine.reg_read(x86.UC_X86_REG_EIP)),
                                      image_writes=state['image_write_events'])), flush=True)
                next_progress = time.monotonic() + 5
    finally:
        try:
            if memory_hooks is not None:
                memory_hooks.close()
        finally:
            if native is not None:
                native.close()
    if memory_hooks is not None:
        state['instruction_observer']['memory_hooks'] = memory_hooks.report()
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
    if host:
        state['host_image']['input_unchanged'] = hashlib.sha256(host_after_attach.read_bytes()).hexdigest() == host['sha256']
        if not state['host_image']['input_unchanged']:
            raise RuntimeError('Host image changed during trace')
    if modules or host:
        state['module_model'] = module_model.report()
        state['environment'] += '; opt-in mapped-PE resolver model, no mapped-module code execution'
    if thread:
        state['thread_model'] = thread.report()
    if startup:
        state['startup_model'] = startup.report()
        for candidate in handle_image_writes:
            try:
                current = struct.unpack('<I', machine.mem_read(int(candidate['address'], 16), 4))[0]
                candidate['final_value_matches'] = current == int(candidate['value'], 16)
            except uc.UcError:
                candidate['final_value_matches'] = None
        state['model_handle_image_writes'] = dict(total_matches=handle_image_write_count,
            retained_events=list(handle_image_writes), retained_limit=128,
            scope='Pre-write CPU DWORD store attempts starting in input images whose value equals a live synthetic handle; '
                  'final_value_matches checks equality at the parent stop, not whether this store completed; '
                  'candidate references only, equality is not proof of ownership; '
                  'excludes stack and API-side writes')
        state['environment'] += '; opt-in synthetic startup APIs including TLS/FLS (not a native Windows process)'
    if interior is not None:
        state['interior_api_model'] = interior.report()
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
    if worker_entry_probe:
        from worker_entry_probe import probe_worker_entry
        state['worker_entry_probe_sha256'] = hashlib.sha256(
            Path(__file__).with_name('worker_entry_probe.py').read_bytes()).hexdigest()
        words = state.get('external_stack_words', [])
        api = state.get('external_import', '').lower()
        eligible = state['reason'] == 'external_import' and api in (
            'kernel32.dll!resumethread', 'kernelbase.dll!resumethread',
            'api-ms-win-core-processthreads-l1-1-0.dll!resumethread')
        handle = int(words[1], 16) if eligible and len(words) >= 2 else None
        record = startup.object_handles.get(handle, {})
        worker = startup.thread_objects.get(record.get('object'), {})
        if not (eligible and record.get('active') and worker.get('state') == 'suspended'
                and worker.get('execution_started') is False and worker.get('suspend_count', 0) > 0):
            state['worker_entry_probe'] = dict(attempted=False,
                reason='Not a ResumeThread boundary for a live, unexecuted suspended model thread')
        else:
            stops = {address: names[0] for address, names in module_model.address_names.items() if names}
            stops.update(functions)
            def run_child(sequence=()):
                try:
                    child = probe_worker_entry(machine, entry=int(worker['start_address'], 16),
                        parameter=int(worker['parameter'], 16), thread_id=worker['thread_id'],
                        image_ranges=image_ranges, stop_addresses=stops,
                        reference_ranges=[(m['base'], m['size']) for m in module_model.modules.values()],
                        creator_tib_range=(TIB_BASE, 0x1000),
                        protected_ranges=[(address, 24) for address in startup.locks], rdtsc_values=sequence,
                        max_instructions=worker_max_instructions, max_seconds=worker_max_seconds,
                        tick_count_values=worker_tick_count_values)
                except Exception as error:
                    # Preserve the expensive parent stop even if the optional
                    # disposable diagnostic fails. Never continue its ResumeThread.
                    child = dict(reason='probe_error', error_type=type(error).__name__, error=str(error))
                child.update(attempted=True, parent_stop=state['external_import'],
                    parent_instruction_index=state['instructions'], parent_return_address=words[0],
                    thread_handle=hex(handle), object_id=record['object'],
                    parent_resume_performed=False, parent_thread_execution_started=False)
                # Each probe has a disposable engine with callback cycles;
                # reclaim it before constructing another full memory clone.
                import gc
                gc.collect()
                return child
            state['worker_entry_probe'] = run_child()
            if worker_rdtsc_sequences:
                state['worker_entry_probe_scenarios'] = [run_child(sequence) for sequence in worker_rdtsc_sequences]
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
    parser.add_argument('--reference-import-markers', action='store_true',
                        help='Replace ordinary IAT entries in reference modules by explicit API stop markers in emulated memory')
    parser.add_argument('--host-after-attach', type=Path,
                        help='After DLL attach, run this explicit x86 EXE and route its imports of this DLL to actual guest exports')
    parser.add_argument('--startup-model', action='store_true',
                        help='Opt-in explicitly synthetic startup API fixtures; unknown calls stop')
    parser.add_argument('--computer-name',
                        help='Explicit synthetic GetComputerNameA/W fixture: 1..15 uppercase ASCII letters, digits or hyphens; requires startup model')
    parser.add_argument('--get-version-result', type=integer,
                        help='Explicit synthetic NT GetVersion packed DWORD (0..0x7fffffff); no manifest or host OS inference; requires startup model')
    parser.add_argument('--suspended-threads', action='store_true',
                        help='Opt-in synthetic CREATE_SUSPENDED identities only; no thread execution, resume or scheduling')
    parser.add_argument('--event-state', action='store_true',
                        help='Opt-in local event Set/Reset and immediately decidable waits only; no blocking or scheduling')
    parser.add_argument('--worker-entry-probe', action='store_true',
                        help='Separate disposable stop-only worker entry experiment at ResumeThread; no main continuation, TLS initialization or Windows thread startup')
    parser.add_argument('--worker-rdtsc-sequence', type=rdtsc_sequence, action='append', default=[],
                        help='Explicit artificial start:step:count timestamp sequence, at most 3 independent child scenarios; requires worker-entry probe')
    parser.add_argument('--worker-max-instructions', type=integer, default=100000,
                        help='Separate child instruction budget, 1..1000000; default 100000')
    parser.add_argument('--worker-max-seconds', type=float, default=2,
                        help='Separate child execution budget, positive and at most 10 seconds; default 2')
    parser.add_argument('--worker-tick-count', type=integer, action='append', default=[],
                        help='Explicit finite GetTickCount DWORD fixture, repeat at most 16 times; child only, requires worker-entry probe')
    parser.add_argument('--create-thread-interior', action='store_true',
                        help='Opt-in validated kernel32 CreateThread +11 partial-frame profile; requires suspended threads and reference modules')
    parser.add_argument('--critical-section-layout', choices=['win10-x86-19041'],
                        help='Opt-in measured uncontended x86 lock layout fixture; direct guest writes still stop')
    parser.add_argument('--nls-codepage', type=Path, help='Explicit read-only SBCS CP1251 reference file')
    parser.add_argument('--nls-sort', type=Path, help='Explicit read-only sortdefault.nls classification reference')
    parser.add_argument('--nls-case', type=Path, help='Explicit read-only l_intl.nls simple BMP case reference')
    parser.add_argument('--observe', action='append', type=integer, default=[],
                        help='Record bounded stack observations at a primary-image instruction address')
    parser.add_argument('--watch', action='append', type=address_size, default=[],
                        help='Compare a VA:SIZE memory range before/after; hashes/counts only, no bytes')
    parser.add_argument('--module', action='append', type=Path, default=[],
                        help='Opt-in read-only reference PE for module/export resolution; repeatable')
    parser.add_argument('--module-base', action='append', type=module_base, default=[],
                        help='Explicit reference-only NAME=ADDRESS placement using bounded PE32 HIGHLOW relocations')
    parser.add_argument('--api-set-schema', type=Path,
                        help='Explicit read-only PE API-set v6 schema; only single default hosts already mapped are supported')
    parser.add_argument('--max-instructions', type=integer, default=20_000_000)
    parser.add_argument('--max-seconds', type=float, default=45.)
    parser.add_argument('--observer', choices=['python', 'rust'], default='python',
                        help='Instruction observer; rust requires rustc and Linux x86_64, Python remains the reference')
    parser.add_argument('--memory-observer', choices=['python', 'rust'],
                        help='Defaults to --observer; python retains unfiltered memory callbacks for comparison')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_limits(args.max_instructions, args.max_seconds)
    except ValueError as error:
        parser.error(str(error))
    if args.report.exists():
        parser.error('Report already exists; choose a new evidence filename')
    result = trace(args.file, args.export, args.argument, args.max_instructions, args.max_seconds,
                   args.module, args.thread_model, args.dll_attach, args.observe, args.watch, args.startup_model,
                   args.nls_codepage, args.nls_sort, args.nls_case, args.after_attach_export, args.reference_import_markers,
                   args.host_after_attach, args.critical_section_layout, args.observer, args.memory_observer,
                   args.module_base, args.api_set_schema, args.computer_name, args.get_version_result,
                   args.suspended_threads, args.create_thread_interior, args.event_state, args.worker_entry_probe,
                   args.worker_rdtsc_sequence, args.worker_max_instructions, args.worker_max_seconds,
                   args.worker_tick_count)
    with args.report.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2, ensure_ascii=False)
        output.write('\n')
    print(json.dumps({k: result[k] for k in ['reason', 'instructions', 'registers', 'image_writes_by_section', 'input_unchanged']}))


if __name__ == '__main__':
    main()
