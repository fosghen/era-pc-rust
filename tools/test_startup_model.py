import struct
import unittest

import unicorn as uc
from unicorn import x86_const as x86

from startup_model import StartupModel, HEAP_CAPACITY


class StartupModelTests(unittest.TestCase):
    def setUp(self):
        self.machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.machine.mem_map(0x10000, 0x3000)
        self.model = StartupModel(self.machine)

    def call(self, name, *args):
        self.machine.reg_write(x86.UC_X86_REG_ESP, 0x10800)
        self.machine.mem_write(0x10800, struct.pack('<' + 'I' * (1 + len(args)), 0x12345678, *args))
        return self.model.handle('KERNEL32.dll!' + name)

    def test_clock_output_and_void_contract(self):
        self.machine.reg_write(x86.UC_X86_REG_EAX, 0xdeadbeef)
        ok, event = self.call('GetSystemTimeAsFileTime', 0x11000)
        self.assertTrue(ok)
        self.assertIsNone(event['result'])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 0xdeadbeef)
        self.assertEqual(struct.unpack('<Q', self.machine.mem_read(0x11000, 8))[0], self.model.profile['filetime'])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_ESP), 0x10808)

    def test_counter_and_ids_are_explicit_fixtures(self):
        self.assertTrue(self.call('QueryPerformanceCounter', 0x11000)[0])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 1)
        self.assertEqual(struct.unpack('<Q', self.machine.mem_read(0x11000, 8))[0], 123456789)
        self.assertTrue(self.call('GetCurrentProcessId')[0])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 4096)
        self.assertTrue(self.call('GetCurrentThreadId')[0])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 4097)

    def test_bad_buffers_do_not_get_success_or_partial_writes(self):
        for pointer in (0, 0x12ffc, 0x50000):
            ok, event = self.call('QueryPerformanceCounter', pointer)
            self.assertFalse(ok)
            self.assertIn('model_error', event)
            self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_ESP), 0x10800)
        self.machine.mem_protect(0x11000, 0x1000, uc.UC_PROT_READ)
        self.assertFalse(self.call('QueryPerformanceCounter', 0x11000)[0])

    def test_unknown_licensing_and_device_calls_remain_unhandled(self):
        for name in ('DeviceIoControl', 'CreateFileW', 'GrdLogin'):
            self.assertEqual(self.call(name), (False, None))
        self.assertEqual(self.model.events, [])

    def result(self, name, *args):
        ok, event = self.call(name, *args)
        self.assertTrue(ok, event)
        return self.machine.reg_read(x86.UC_X86_REG_EAX)

    def test_heap_allocation_reallocation_and_lifetime(self):
        heap = self.result('HeapCreate', 0, 4096, 0)
        pointer = self.result('HeapAlloc', heap, 8, 10)
        self.assertEqual(bytes(self.machine.mem_read(pointer, 10)), bytes(10))
        self.machine.mem_write(pointer, b'hello')
        moved = self.result('HeapReAlloc', heap, 8, pointer, 20)
        self.assertEqual(bytes(self.machine.mem_read(moved, 20)), b'hello' + bytes(15))
        self.assertFalse(self.call('HeapFree', heap, 0, pointer)[0])
        self.assertEqual(self.result('HeapSize', heap, 0, moved), 20)
        self.assertEqual(self.result('HeapFree', heap, 0, moved), 1)
        self.assertFalse(self.call('HeapFree', heap, 0, moved)[0])
        self.assertEqual(self.model.heaps[heap]['live'], 0)

    def test_heap_limits_wrong_ownership_and_zero_size(self):
        self.assertFalse(self.call('HeapCreate', 0, 0, 64)[0])
        first = self.result('HeapCreate', 0, 0, 0)
        second = self.result('HeapCreate', 0, 0, 0)
        pointer = self.result('HeapAlloc', first, 0, 0)
        self.assertEqual(self.result('HeapSize', first, 0, pointer), 0)
        self.assertFalse(self.call('HeapFree', second, 0, pointer)[0])
        self.assertFalse(self.call('HeapAlloc', first, 0, HEAP_CAPACITY + 1)[0])
        self.assertFalse(self.call('HeapAlloc', first, 4, 16)[0])
        self.result('HeapDestroy', first)
        self.assertFalse(self.call('HeapAlloc', first, 0, 1)[0])

    def test_failed_reallocation_preserves_live_block(self):
        heap = self.result('GetProcessHeap')
        self.assertEqual(self.result('GetProcessHeap'), heap)
        pointer = self.result('HeapAlloc', heap, 0, 16)
        self.assertEqual(bytes(self.machine.mem_read(pointer, 16)), b'\xa5' * 16)
        cursor = self.model.cursor
        self.assertFalse(self.call('HeapReAlloc', heap, 8, pointer, HEAP_CAPACITY + 1)[0])
        self.assertEqual(self.model.cursor, cursor)
        self.assertEqual(self.model.heaps[heap]['live'], 16)
        self.assertEqual(self.result('HeapSize', heap, 0, pointer), 16)
        self.machine.mem_write(pointer, b'abcdefgh')
        moved = self.result('HeapReAlloc', heap, 0, pointer, 4)
        self.assertEqual(bytes(self.machine.mem_read(moved, 4)), b'abcd')
        self.assertEqual(self.model.heaps[heap]['live'], 4)


if __name__ == '__main__':
    unittest.main()
