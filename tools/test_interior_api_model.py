"""Own synthetic PE/frame tests, never Windows or vendor image fixtures."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace

import unicorn as uc
from unicorn import x86_const as x86

from interior_api_model import CreateThreadInteriorModel, PREFIX
from pe_module_model import ModuleModel
from startup_model import StartupModel


class CreateThreadInteriorTests(unittest.TestCase):
    def setUp(self):
        # Local import prevents loader_trace -> helper -> fixture import cycles.
        from test_loader_trace import synthetic_module
        self.directory = tempfile.TemporaryDirectory(prefix='era-interior-api-test-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'kernel32.dll'
        data = synthetic_module()
        data[0x3e0:0x3ed] = b'CreateThread\0'
        data[0x220:0x220 + len(PREFIX)] = PREFIX
        self.path.write_bytes(data)
        self.machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.machine.mem_map(0x10000, 0x3000)
        self.modules = ModuleModel(self.machine, [self.path], [(0x10000, 0x3000)])
        self.model = self.construct()
        self.words = [0x11000, 0x12345000, 0x12345678, 0, 0, 0x401000, 0x4567, 4, 0x11000]
        self.install_frame()

    def construct(self):
        return CreateThreadInteriorModel(self.machine, self.modules, 0x10000, 0x3000)

    def install_frame(self, words=None, esp=0x10800):
        self.machine.mem_write(esp, struct.pack('<9I', *(self.words if words is None else words)))
        self.machine.reg_write(x86.UC_X86_REG_EIP, self.model.target)
        self.machine.reg_write(x86.UC_X86_REG_ESP, esp)
        self.machine.reg_write(x86.UC_X86_REG_EBP, esp + 4)
        self.machine.reg_write(x86.UC_X86_REG_EAX, 4)
        self.machine.reg_write(x86.UC_X86_REG_EBX, 0x11223344)
        self.machine.reg_write(x86.UC_X86_REG_EFLAGS, 0x202)

    def snapshot(self):
        registers = (x86.UC_X86_REG_EAX, x86.UC_X86_REG_EBX, x86.UC_X86_REG_ECX,
                     x86.UC_X86_REG_EDX, x86.UC_X86_REG_ESI, x86.UC_X86_REG_EDI,
                     x86.UC_X86_REG_EBP, x86.UC_X86_REG_ESP, x86.UC_X86_REG_EIP,
                     x86.UC_X86_REG_EFLAGS)
        return ([self.machine.reg_read(r) for r in registers], bytes(self.machine.mem_read(0x10000, 0x3000)))

    def test_profile_and_positive_frame(self):
        frame = self.model.decode(self.model.target)
        self.assertEqual(frame['canonical_esp'], '0x10808')
        self.assertEqual(frame['restored_ebp'], '0x12345000')
        self.assertEqual(frame['arguments'], ['0x0', '0x0', '0x401000', '0x4567', '0x4', '0x11000'])
        report = self.model.report()
        self.assertEqual(report['reference_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(report['prefix_sha256'], hashlib.sha256(PREFIX).hexdigest())
        self.assertFalse(report['reference_code_executed'])
        self.assertNotIn('prefix_bytes', report)

    def test_other_address_is_noop_even_with_no_startup(self):
        before = self.snapshot()
        self.assertIsNone(self.model.decode(self.model.entry))
        self.assertEqual(self.model.handle(self.model.entry, None), (False, None))
        self.assertEqual(before, self.snapshot())

    def test_missing_forwarded_and_aliased_exports_rejected(self):
        module = self.modules.modules['kernel32.dll']
        export = module['names']['CreateThread']
        del self.modules.modules['kernel32.dll']
        with self.assertRaisesRegex(ValueError, 'requires explicit'):
            self.construct()
        self.modules.modules['kernel32.dll'] = module
        del module['names']['CreateThread']
        with self.assertRaisesRegex(ValueError, 'non-forwarded'):
            self.construct()
        module['names']['CreateThread'] = export
        module['names']['CreateThread'] = SimpleNamespace(address=export.address, forwarder=b'other.CreateThread')
        with self.assertRaisesRegex(ValueError, 'non-forwarded'):
            self.construct()
        module['names']['CreateThread'] = export
        module['ordinals'][99] = SimpleNamespace(address=export.address + 11, forwarder=None)
        with self.assertRaisesRegex(ValueError, 'aliases'):
            self.construct()
        del module['ordinals'][99]
        self.modules.address_names[self.model.target] = ['other!Alias']
        with self.assertRaisesRegex(ValueError, 'API identity'):
            self.construct()

    def test_invalid_prefix_and_writable_or_unreadable_reference_rejected(self):
        self.machine.mem_write(self.model.entry, b'\x90')
        with self.assertRaisesRegex(ValueError, 'prologue'):
            self.construct()
        self.machine.mem_write(self.model.entry, PREFIX)
        self.machine.mem_protect(0x60001000, 4096, uc.UC_PROT_ALL)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            self.construct()
        self.machine.mem_protect(0x60001000, 4096, uc.UC_PROT_EXEC)
        with self.assertRaisesRegex(ValueError, 'not readable'):
            self.construct()

    def test_prefix_and_permissions_rechecked_at_each_recognized_boundary(self):
        for change, message in (('bytes', 'prologue'), ('writable', 'read-only'),
                                 ('unreadable', 'not readable')):
            with self.subTest(change=change):
                self.machine.mem_write(self.model.entry, PREFIX)
                self.machine.mem_protect(0x60001000, 4096, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
                if change == 'bytes':
                    self.machine.mem_write(self.model.entry, b'\x90')
                elif change == 'writable':
                    self.machine.mem_protect(0x60001000, 4096, uc.UC_PROT_ALL)
                else:
                    self.machine.mem_protect(0x60001000, 4096, uc.UC_PROT_EXEC)
                before = self.snapshot()
                handled, event = self.model.handle(self.model.target, None)
                self.assertFalse(handled)
                self.assertIn(message, event['model_error'])
                self.assertEqual(before, self.snapshot())

    def test_bad_bounds_rejected(self):
        for start, size in ((True, 4096), (-1, 4096), (0x10000, 0), (0xffffffff, 2)):
            with self.subTest(start=start, size=size), self.assertRaises(ValueError):
                CreateThreadInteriorModel(self.machine, self.modules, start, size)
        self.modules.modules['kernel32.dll']['size'] = 0x102b
        with self.assertRaisesRegex(ValueError, 'outside reference'):
            self.construct()

    def test_invalid_registers_and_words_preserve_cpu_and_memory(self):
        for kind in ('eip', 'ebp', 'eax', 'copied_pointer'):
            with self.subTest(kind=kind):
                self.install_frame()
                if kind == 'copied_pointer':
                    self.machine.mem_write(0x10800, struct.pack('<I', 0x11004))
                else:
                    register = getattr(x86, 'UC_X86_REG_' + kind.upper())
                    self.machine.reg_write(register, self.machine.reg_read(register) + 1)
                before = self.snapshot()
                handled, event = self.model.handle(self.model.target, None)
                self.assertFalse(handled)
                self.assertIn('model_error', event)
                self.assertEqual(before, self.snapshot())

    def test_read_only_stack_allowed_but_unreadable_or_unmapped_frame_rejected(self):
        self.machine.mem_protect(0x10000, 4096, uc.UC_PROT_READ)
        self.assertIsNotNone(self.model.decode(self.model.target))
        self.machine.mem_protect(0x10000, 4096, uc.UC_PROT_WRITE)
        with self.assertRaisesRegex(ValueError, 'not readable'):
            self.model.decode(self.model.target)
        self.machine.mem_protect(0x10000, 4096, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        self.install_frame(esp=0x10ff0)
        self.machine.mem_unmap(0x11000, 4096)
        with self.assertRaisesRegex(ValueError, 'not fully mapped'):
            self.model.decode(self.model.target)

    def test_frame_must_be_inside_harness_not_just_mapped(self):
        self.machine.reg_write(x86.UC_X86_REG_ESP, 0x12fe0)
        self.machine.reg_write(x86.UC_X86_REG_EBP, 0x12fe4)
        with self.assertRaisesRegex(ValueError, 'outside the harness'):
            self.model.decode(self.model.target)

    def test_tid_output_full_frame_overlap_including_partial_overlap(self):
        for output in (0x107fd, 0x10800, 0x10804, 0x10808, 0x10820, 0x10823):
            with self.subTest(output=hex(output)):
                words = list(self.words)
                words[0] = words[8] = output
                self.install_frame(words)
                before = self.snapshot()
                handled, event = self.model.handle(self.model.target, None)
                self.assertFalse(handled)
                self.assertIn('overlaps', event['model_error'])
                self.assertEqual(before, self.snapshot())
        for output in (0, 0x107fc, 0x10824, 0x11000):
            words = list(self.words)
            words[0] = words[8] = output
            self.install_frame(words)
            self.assertIsNotNone(self.model.decode(self.model.target))

    def test_success_normalizes_ebp_and_callee_stack_cleanup(self):
        machine = self.machine
        event = {'api': 'kernel32.dll!CreateThread'}

        def handle(name):
            self.assertEqual(name, 'kernel32.dll!CreateThread')
            self.assertEqual(machine.reg_read(x86.UC_X86_REG_EBP), self.words[1])
            esp = machine.reg_read(x86.UC_X86_REG_ESP)
            self.assertEqual(esp, 0x10808)
            self.assertEqual(struct.unpack('<7I', machine.mem_read(esp, 28)), tuple(self.words[2:]))
            machine.reg_write(x86.UC_X86_REG_EAX, 0x76000000)
            machine.reg_write(x86.UC_X86_REG_ESP, esp + 28)
            machine.reg_write(x86.UC_X86_REG_EIP, self.words[2])
            return True, event

        before_memory = self.snapshot()[1]
        handled, result = self.model.handle(self.model.target, SimpleNamespace(handle=handle))
        self.assertTrue(handled)
        self.assertIs(result, event)
        self.assertIn('interior_frame', event)
        self.assertEqual(machine.reg_read(x86.UC_X86_REG_ESP), 0x10824)
        self.assertEqual(machine.reg_read(x86.UC_X86_REG_EBP), self.words[1])
        self.assertEqual(machine.reg_read(x86.UC_X86_REG_EIP), self.words[2])
        self.assertEqual(self.snapshot()[1], before_memory)

    def test_unhandled_and_exception_roll_back_complete_cpu_context(self):
        for failure in ('none', 'event', 'exception'):
            with self.subTest(failure=failure):
                self.install_frame()
                before = self.snapshot()

                def handle(_name):
                    self.machine.reg_write(x86.UC_X86_REG_EAX, 0xdeadbeef)
                    self.machine.reg_write(x86.UC_X86_REG_EFLAGS, 0x246)
                    if failure == 'exception':
                        raise ValueError('synthetic unsupported flags')
                    return False, None if failure == 'none' else {'model_error': 'synthetic unsupported flags'}

                handled, event = self.model.handle(self.model.target, SimpleNamespace(handle=handle))
                self.assertFalse(handled)
                self.assertIn('model_error', event)
                self.assertEqual(before, self.snapshot())

    def test_real_startup_unhandled_call_rolls_back_without_registry_changes(self):
        startup = StartupModel(self.machine)
        before = self.snapshot()
        handled, event = self.model.handle(self.model.target, startup)
        self.assertFalse(handled)
        self.assertIn('model_error', event)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(startup.object_handles, {})
        self.assertEqual(startup.event_objects, {})

    def test_real_suspended_thread_success_accepts_zero_caller_ebp(self):
        words = list(self.words)
        words[1] = 0
        self.install_frame(words)
        startup = StartupModel(self.machine, suspended_threads=True)
        handled, event = self.model.handle(self.model.target, startup)
        self.assertTrue(handled, event)
        self.assertEqual(struct.unpack('<I', self.machine.mem_read(0x11000, 4))[0], 4098)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_ESP), 0x10824)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EBP), 0)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EIP), self.words[2])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 0x76000000)
        self.assertEqual(event['interior_frame']['restored_ebp'], '0x0')
        self.assertIs(startup.events[-1], event)
        self.assertEqual(startup.thread_objects['thread:0']['state'], 'suspended')
        self.assertFalse(startup.thread_objects['thread:0']['execution_started'])

    def test_real_startup_rejects_flags_or_bad_output_with_full_rollback(self):
        startup = StartupModel(self.machine, suspended_threads=True)
        for flags, output in ((0, 0x11000), (5, 0x11000), (4, 0x50000), (4, 0x12ffe)):
            with self.subTest(flags=flags, output=output):
                words = list(self.words)
                words[0] = words[8] = output
                words[7] = flags
                self.install_frame(words)
                self.machine.reg_write(x86.UC_X86_REG_EAX, flags)
                startup.last_error = 321
                before = self.snapshot()
                handled, event = self.model.handle(self.model.target, startup)
                self.assertFalse(handled)
                self.assertIn('model_error', event)
                self.assertEqual(before, self.snapshot())
                self.assertEqual(startup.object_handles, {})
                self.assertEqual(startup.thread_objects, {})
                self.assertEqual(startup.last_error, 321)


if __name__ == '__main__':
    unittest.main()
