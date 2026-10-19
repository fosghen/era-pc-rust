"""Opt-in normalization of one structurally verified partial CreateThread frame.

No reference instruction executes. The exact 11-byte x86 prologue is a
structural profile, not a claim about all Windows versions or API aliases.
The startup model owns validation/atomicity of API memory and registry effects.
"""
import hashlib
import struct

import unicorn as uc
from unicorn import x86_const as x86


PREFIX = bytes.fromhex('8bff558becff751c8b4518')


def readable(machine, address, length):
    """Unicorn's host mem_read ignores guest permissions; check them explicitly."""
    if not 0 <= address < 2**32 or not 0 < length <= 2**32 - address:
        raise ValueError('Read interval outside x86 address space')
    cursor, end = address, address + length
    for start, last, permissions in sorted(machine.mem_regions()):
        if start <= cursor <= last:
            if not permissions & uc.UC_PROT_READ:
                raise ValueError('Frame or prefix memory is not readable')
            cursor = min(end, last + 1)
            if cursor == end:
                return
    raise ValueError('Frame or prefix memory is not fully mapped')


class CreateThreadInteriorModel:
    def __init__(self, machine, module_model, stack_base, stack_size):
        if (type(stack_base) is not int or type(stack_size) is not int
                or not 0 <= stack_base < 2**32 or not 0 < stack_size <= 2**32 - stack_base):
            raise ValueError('Invalid harness stack bounds')
        module = module_model.modules.get('kernel32.dll')
        if module is None:
            raise ValueError('CreateThread interior profile requires explicit kernel32.dll')
        symbol = module['names'].get('CreateThread')
        if symbol is None or not symbol.address or symbol.forwarder:
            raise ValueError('CreateThread interior profile requires a non-forwarded export')
        self.machine = machine
        self.stack_base, self.stack_size = stack_base, stack_size
        self.entry = module['base'] + symbol.address
        self.target = self.entry + len(PREFIX)
        if not (0 <= module['base'] < self.entry < self.target
                < module['base'] + module['size'] <= 2**32):
            raise ValueError('CreateThread interior profile is outside reference image')
        # The interior boundary must not already be an export/API entry.
        symbols = list(module['names'].values()) + list(module['ordinals'].values())
        if any(item.address and not item.forwarder
               and module['base'] + item.address == self.target for item in symbols):
            raise ValueError('CreateThread interior address aliases another export')
        if module_model.address_names.get(self.target):
            raise ValueError('CreateThread interior address already has an API identity')
        self.validate_prefix()
        self.reference_sha256 = module['sha256']

    def validate_prefix(self):
        readable(self.machine, self.entry, len(PREFIX))
        if bytes(self.machine.mem_read(self.entry, len(PREFIX))) != PREFIX:
            raise ValueError('Unsupported CreateThread interior prologue')
        for start, last, permissions in self.machine.mem_regions():
            if start < self.target and self.entry <= last and permissions & uc.UC_PROT_WRITE:
                raise ValueError('CreateThread reference prologue must be read-only')

    def decode(self, address):
        if address != self.target:
            return None
        if self.machine.reg_read(x86.UC_X86_REG_EIP) != self.target:
            raise ValueError('Interior EIP does not match the requested boundary')
        self.validate_prefix()
        esp = self.machine.reg_read(x86.UC_X86_REG_ESP)
        ebp = self.machine.reg_read(x86.UC_X86_REG_EBP)
        if ebp != esp + 4:
            raise ValueError('Interior EBP must equal raw ESP plus four')
        if not self.stack_base <= esp <= self.stack_base + self.stack_size - 36:
            raise ValueError('Interior 36-byte frame is outside the harness stack')
        readable(self.machine, esp, 36)
        words = struct.unpack('<9I', self.machine.mem_read(esp, 36))
        if words[0] != words[8]:
            raise ValueError('Interior copied thread-ID pointer differs from argument six')
        if self.machine.reg_read(x86.UC_X86_REG_EAX) != words[7]:
            raise ValueError('Interior EAX differs from creation-flags argument')
        output = words[8]
        if output and output < esp + 36 and esp < output + 4:
            raise ValueError('Thread-ID output overlaps the raw partial-prologue frame')
        return dict(original_entry=hex(self.entry), boundary=hex(self.target), offset=len(PREFIX),
                    raw_esp=hex(esp), raw_ebp=hex(ebp), canonical_esp=hex(esp + 8),
                    restored_ebp=hex(words[1]), return_address=hex(words[2]),
                    arguments=[hex(value) for value in words[3:]],
                    validated='Exact prologue, EIP, frame bounds/readability, EBP/ESP, flags, copied pointer and disjoint output')

    def handle(self, address, startup):
        if address != self.target:
            return False, None
        try:
            frame = self.decode(address)
        except (ValueError, uc.UcError) as error:
            return False, dict(api='kernel32.dll!CreateThread', model_error=str(error),
                               interior_boundary=hex(self.target))
        context = self.machine.context_save()
        committed = False
        try:
            self.machine.reg_write(x86.UC_X86_REG_ESP, int(frame['canonical_esp'], 16))
            self.machine.reg_write(x86.UC_X86_REG_EBP, int(frame['restored_ebp'], 16))
            handled, event = startup.handle('kernel32.dll!CreateThread')
            if not handled:
                observation = dict(event or {}, interior_frame=frame)
                observation.setdefault('api', 'kernel32.dll!CreateThread')
                observation.setdefault('model_error', 'Startup model did not handle CreateThread')
                return False, observation
            event['interior_frame'] = frame
            committed = True
            return True, event
        except Exception as error:
            return False, dict(api='kernel32.dll!CreateThread', interior_frame=frame,
                               model_error=f'{type(error).__name__}: {error}'[:1024])
        finally:
            if not committed:
                self.machine.context_restore(context)

    def report(self):
        return dict(profile='x86-create-thread-plus-11', reference_module='kernel32.dll',
                    reference_sha256=self.reference_sha256, entry=hex(self.entry),
                    target=hex(self.target), offset=len(PREFIX),
                    prefix_sha256=hashlib.sha256(PREFIX).hexdigest(),
                    reference_code_executed=False,
                    limitations='Structural prologue profile only, not a Windows-version claim or general interior-API alias; '
                                'fixed 36-byte frame within the supplied stack; no reference code execution; '
                                'CPU rollback on rejected startup call; startup must reject unsupported API effects '
                                'before mutating memory or object registries')
