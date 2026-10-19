import struct
from pathlib import Path
import tempfile
import unittest

import unicorn as uc
from unicorn import x86_const as x86

from startup_model import StartupModel, HEAP_CAPACITY, VIRTUAL_BASE, VIRTUAL_CAPACITY
from nls_model import NlsModel
from test_nls_model import synthetic_codepage, synthetic_sort, synthetic_case


class StartupModelTests(unittest.TestCase):
    def setUp(self):
        self.machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.machine.mem_map(0x10000, 0x3000)
        self.model = StartupModel(self.machine)

    def call(self, name, *args, module='KERNEL32.dll'):
        self.machine.reg_write(x86.UC_X86_REG_ESP, 0x10800)
        self.machine.mem_write(0x10800, struct.pack('<' + 'I' * (1 + len(args)), 0x12345678, *args))
        return self.model.handle(module + '!' + name)

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

    def test_page_protection_can_target_explicit_second_input_only(self):
        self.model.primary_region = (0x10000, 0x1000)
        self.model.additional_image_regions = [(0x11000, 0x1000)]
        self.assertEqual(self.result('VirtualProtect', 0x11000, 0x1000, 2, 0x12000), 1)
        self.assertEqual(next(p for a, b, p in self.machine.mem_regions() if a <= 0x11000 <= b), uc.UC_PROT_READ)
        self.assertFalse(self.call('VirtualProtect', 0x12000, 0x1000, 2, 0x10000)[0])
        self.assertFalse(self.call('VirtualProtect', 0x10fff, 2, 2, 0x12000)[0])

    def test_virtual_alloc_zero_pages_alignment_and_exact_release(self):
        contract = 'api-ms-win-core-memory-l1-1-0.dll'
        ok, event = self.call('VirtualAlloc', 0, 0x421c, 0x1000, 4, module=contract)
        self.assertTrue(ok, event)
        address = self.machine.reg_read(x86.UC_X86_REG_EAX)
        self.assertEqual(address, VIRTUAL_BASE)
        self.assertEqual(self.model.virtual_allocations[address]['size'], 0x5000)
        self.assertEqual(bytes(self.machine.mem_read(address, 0x5000)), bytes(0x5000))
        second = self.result('VirtualAlloc', 0, 1, 0x3000, 4)
        self.assertEqual(second, address + 0x10000)
        self.assertFalse(self.call('VirtualFree', address + 1, 0, 0x8000)[0])
        self.assertFalse(self.call('VirtualFree', address, 0x5000, 0x8000)[0])
        self.assertTrue(self.call('VirtualFree', address, 0, 0x8000, module=contract)[0])
        with self.assertRaises(uc.UcError):
            self.machine.mem_read(address, 1)
        self.assertFalse(self.call('VirtualFree', address, 0, 0x8000)[0])
        self.assertTrue(self.model.virtual_allocations[second]['active'])

    def test_virtual_pages_enforce_execute_permissions_and_allow_explicit_protect(self):
        pointer = self.result('VirtualAlloc', 0, 5, 0x3000, 4)
        self.machine.mem_write(pointer, bytes.fromhex('b82a000000'))
        with self.assertRaises(uc.UcError):
            self.machine.emu_start(pointer, pointer + 5)
        self.assertEqual(self.result('VirtualProtect', pointer, 5, 0x20, 0x11000), 1)
        self.assertEqual(struct.unpack('<I', self.machine.mem_read(0x11000, 4))[0], 4)
        self.machine.emu_start(pointer, pointer + 5)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 42)
        self.assertEqual(self.result('VirtualFree', pointer, 0, 0x8000), 1)

    def test_virtual_alloc_unsupported_requests_do_not_create_pages(self):
        for args in [(0, 0, 0x1000, 4), (VIRTUAL_BASE, 4096, 0x1000, 4),
                     (0, 4096, 0x2000, 4), (0, 4096, 0x3000, 0x104),
                     (0, VIRTUAL_CAPACITY + 1, 0x3000, 4)]:
            self.assertFalse(self.call('VirtualAlloc', *args)[0])
            self.assertEqual(self.model.virtual_allocations, {})
            self.assertEqual(self.model.virtual_cursor, VIRTUAL_BASE)
        self.model.virtual_cursor = VIRTUAL_BASE + VIRTUAL_CAPACITY
        self.assertFalse(self.call('VirtualAlloc', 0, 4096, 0x1000, 4)[0])
        self.assertEqual(self.model.virtual_allocations, {})

    def test_api_set_contract_is_exact_not_a_wildcard_alias(self):
        self.machine.reg_write(x86.UC_X86_REG_ESP, 0x10800)
        self.machine.mem_write(0x10800, struct.pack('<I', 0x12345678))
        contract = 'api-ms-win-core-processthreads-l1-1-0.dll!'
        self.assertTrue(self.model.handle(contract + 'GetCurrentProcess')[0])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 0xffffffff)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_ESP), 0x10804)
        for name in (contract + 'CreateThread', 'unknown.dll!GetCurrentProcess',
                     'api-ms-win-core-processthreads-l1-1-99.dll!GetCurrentProcess'):
            self.assertEqual(self.model.handle(name), (False, None))

    def test_duplicate_current_thread_and_close_preserve_object_identity(self):
        self.assertEqual(self.result('DuplicateHandle', 0xffffffff, 0xfffffffe, 0xffffffff, 0x11000, 1, 0, 2), 1)
        handle = struct.unpack('<I', self.machine.mem_read(0x11000, 4))[0]
        self.assertEqual(self.model.object_handles[handle], dict(object='current_thread', inheritable=False, active=True))
        self.assertEqual(self.result('DuplicateHandle', 0xffffffff, handle, 0xffffffff, 0x11004, 0, 1, 2), 1)
        second = struct.unpack('<I', self.machine.mem_read(0x11004, 4))[0]
        self.assertNotEqual(handle, second)
        self.assertEqual(self.result('CloseHandle', handle), 1)
        self.assertTrue(self.model.object_handles[second]['active'])
        self.assertFalse(self.call('CloseHandle', handle)[0])
        self.assertFalse(self.call('DuplicateHandle', 0xffffffff, handle, 0xffffffff, 0x11000, 0, 0, 2)[0])

    def test_duplicate_handle_rejects_unknown_objects_and_outputs_without_mutation(self):
        for source, target, output, options in [(123, 0xffffffff, 0x11000, 2),
                (0xfffffffe, 123, 0x11000, 2), (0xfffffffe, 0xffffffff, 0, 2),
                (0xfffffffe, 0xffffffff, 0x11000, 3)]:
            self.assertFalse(self.call('DuplicateHandle', 0xffffffff, source, target, output, 0, 0, options)[0])
            self.assertEqual(self.model.object_handles, {})
        self.assertFalse(self.call('CloseHandle', 0xffffffff)[0])

    def test_handle_api_set_and_budget_are_explicit(self):
        contract = 'api-ms-win-core-handle-l1-1-0.dll'
        for _ in range(128):
            self.assertTrue(self.call('DuplicateHandle', 0xffffffff, 0xffffffff,
                                     0xffffffff, 0x11000, 0, 0, 2, module=contract)[0])
        before = bytes(self.machine.mem_read(0x11000, 4))
        ok, event = self.call('DuplicateHandle', 0xffffffff, 0xffffffff,
                             0xffffffff, 0x11000, 0, 0, 2, module=contract)
        self.assertFalse(ok)
        self.assertIn('budget', event['model_error'])
        self.assertEqual(bytes(self.machine.mem_read(0x11000, 4)), before)
        handle = struct.unpack('<I', before)[0]
        self.assertTrue(self.call('CloseHandle', handle, module=contract)[0])

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

    def test_tls_lifetime_values_and_last_error(self):
        self.assertEqual(self.result('GetLastError'), 0)
        first = self.result('TlsAlloc')
        second = self.result('TlsAlloc')
        self.assertNotEqual(first, second)
        self.result('SetLastError', 123)
        self.assertEqual(self.result('GetLastError'), 123)
        self.assertEqual(self.result('TlsGetValue', first), 0)
        self.assertEqual(self.result('GetLastError'), 0)
        self.result('TlsSetValue', first, 0xdeadbeef)
        self.assertEqual(self.result('TlsGetValue', first), 0xdeadbeef)
        self.assertEqual(self.result('TlsGetValue', second), 0)
        self.result('TlsFree', first)
        self.assertFalse(self.call('TlsGetValue', first)[0])
        self.assertFalse(self.call('TlsFree', first)[0])
        reused = self.result('TlsAlloc')
        self.assertEqual(reused, first)
        self.assertEqual(self.result('TlsGetValue', reused), 0)

    def test_fls_is_separate_and_callbacks_are_not_silently_skipped(self):
        tls = self.result('TlsAlloc')
        fls = self.result('FlsAlloc', 0x401000)
        self.result('TlsSetValue', tls, 10)
        self.result('FlsSetValue', fls, 20)
        self.assertEqual(self.result('TlsGetValue', tls), 10)
        self.assertEqual(self.result('FlsGetValue', fls), 20)
        self.assertFalse(self.call('GetLastError')[0])
        ok, event = self.call('FlsFree', fls)
        self.assertFalse(ok)
        self.assertEqual(event['pending_callback'], dict(address='0x401000', argument='0x14'))
        self.assertEqual(self.result('FlsGetValue', fls), 20)
        self.result('FlsSetValue', fls, 0)
        self.assertEqual(self.result('FlsFree', fls), 1)
        self.assertFalse(self.call('FlsGetValue', fls)[0])

    def test_local_storage_budget_does_not_fabricate_failure_code(self):
        for _ in range(64):
            self.result('TlsAlloc')
        self.machine.reg_write(x86.UC_X86_REG_EAX, 123)
        self.assertFalse(self.call('TlsAlloc')[0])
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_EAX), 123)
        self.assertEqual(len(self.model.slots['Tls']), 64)

    def test_pointer_encoding_pair_is_reversible_and_nonidentity(self):
        for pointer in (0, 1, 0x401000, 0x80000000, 0xffffffff):
            encoded = self.result('EncodePointer', pointer)
            self.assertNotEqual(encoded, pointer)
            self.assertEqual(self.result('DecodePointer', encoded), pointer)

    def test_single_thread_critical_section_lifetime_and_recursion(self):
        self.assertFalse(self.call('EnterCriticalSection', 0x11000)[0])
        self.assertEqual(self.result('InitializeCriticalSectionAndSpinCount', 0x11000, 4000), 1)
        self.assertFalse(self.call('InitializeCriticalSection', 0x11004)[0])
        self.result('EnterCriticalSection', 0x11000)
        self.assertEqual(self.result('TryEnterCriticalSection', 0x11000), 1)
        self.assertEqual(self.model.locks[0x11000]['depth'], 2)
        self.assertFalse(self.call('DeleteCriticalSection', 0x11000)[0])
        self.result('LeaveCriticalSection', 0x11000)
        self.result('LeaveCriticalSection', 0x11000)
        self.assertFalse(self.call('LeaveCriticalSection', 0x11000)[0])
        self.result('DeleteCriticalSection', 0x11000)
        self.result('InitializeCriticalSection', 0x11000)

    def test_opaque_lock_storage_cannot_be_read_or_overwritten(self):
        self.result('InitializeCriticalSection', 0x11000)
        self.assertFalse(self.call('QueryPerformanceCounter', 0x11000)[0])
        self.machine.mem_write(0x10000, bytes.fromhex('a100100100 90'))
        self.machine.emu_start(0x10000, 0x10006)
        self.assertEqual(self.model.trace_state['reason'], 'unsupported_critical_section_memory')

    def test_interlocked_wraparound_and_compare_exchange(self):
        pointer = 0x11000
        self.machine.mem_write(pointer, bytes.fromhex('ffffffff'))
        self.assertEqual(self.result('InterlockedIncrement', pointer), 0)
        self.assertEqual(self.result('InterlockedDecrement', pointer), 0xffffffff)
        self.assertEqual(self.result('InterlockedCompareExchange', pointer, 42, 1), 0xffffffff)
        self.assertEqual(self.result('InterlockedCompareExchange', pointer, 42, 0xffffffff), 0xffffffff)
        self.assertEqual(self.result('InterlockedExchange', pointer, 21), 42)
        self.assertEqual(struct.unpack('<I', self.machine.mem_read(pointer, 4))[0], 21)
        self.assertFalse(self.call('InterlockedIncrement', pointer + 1)[0])
        self.machine.mem_protect(pointer, 4096, uc.UC_PROT_READ)
        self.assertFalse(self.call('InterlockedIncrement', pointer)[0])

    def test_command_line_and_empty_environment_are_explicit_fixtures(self):
        command = self.result('GetCommandLineA')
        self.assertEqual(bytes(self.machine.mem_read(command, 20)), b'C:\\era-lab\\host.exe\0')
        self.assertFalse(self.call('QueryPerformanceCounter', command)[0])
        first = self.result('GetEnvironmentStringsW')
        second = self.result('GetEnvironmentStringsW')
        self.assertNotEqual(first, second)
        self.assertEqual(bytes(self.machine.mem_read(first, 4)), bytes(4))
        self.assertEqual(self.result('FreeEnvironmentStringsW', first), 1)
        self.assertFalse(self.call('FreeEnvironmentStringsW', first)[0])
        self.assertFalse(self.call('FreeEnvironmentStringsW', command)[0])

    def test_wide_conversion_counts_nul_and_rejects_unmodeled_encoding(self):
        self.machine.mem_write(0x11000, 'abc\0'.encode('utf-16-le'))
        self.assertEqual(self.result('WideCharToMultiByte', 0, 0, 0x11000, 0xffffffff, 0, 0, 0, 0), 4)
        self.assertEqual(self.result('WideCharToMultiByte', 0, 0, 0x11000, 3, 0x12000, 3, 0, 0), 3)
        self.assertEqual(bytes(self.machine.mem_read(0x12000, 3)), b'abc')
        self.assertFalse(self.call('WideCharToMultiByte', 0, 0, 0x11000, 4, 0x12000, 3, 0, 0)[0])
        self.machine.mem_write(0x11000, 'я\0'.encode('utf-16-le'))
        self.assertFalse(self.call('WideCharToMultiByte', 0, 0, 0x11000, 2, 0, 0, 0, 0)[0])

    def test_process_startup_has_no_inherited_or_standard_handles(self):
        self.assertEqual(self.result('SetHandleCount', 32), 32)
        self.machine.mem_write(0x11000, b'\xa5' * 68)
        self.result('GetStartupInfoW', 0x11000)
        self.assertEqual(bytes(self.machine.mem_read(0x11000, 68)), struct.pack('<I', 68) + bytes(64))
        self.assertEqual(self.result('GetStdHandle', 0xfffffff5), 0)
        self.assertFalse(self.call('GetStdHandle', 123)[0])
        self.assertEqual(self.result('GetModuleFileNameW', 0, 0x11000, 260), 19)
        self.assertEqual(bytes(self.machine.mem_read(0x11000, 40)).decode('utf-16-le'), 'C:\\era-lab\\host.exe\0')
        self.assertFalse(self.call('GetModuleFileNameA', 0x10000000, 0x11000, 260)[0])
        self.assertFalse(self.call('GetModuleFileNameA', 0, 0x11000, 19)[0])

    def test_codepage_info_is_bounded_to_explicit_single_byte_profile(self):
        self.assertEqual(self.result('IsValidCodePage', 1251), 1)
        self.assertFalse(self.call('IsValidCodePage', 932)[0])
        self.assertEqual(self.result('GetACP'), 1251)
        self.assertEqual(self.result('GetCPInfo', 1251, 0x11000), 1)
        self.assertEqual(bytes(self.machine.mem_read(0x11000, 20)), struct.pack('<I', 1) + b'?\0' + bytes(14))
        self.assertFalse(self.call('GetCPInfo', 932, 0x11000)[0])

    def test_sse2_fixture_matches_basic_emulated_instruction_support(self):
        self.assertEqual(self.result('IsProcessorFeaturePresent', 10), 1)
        self.assertFalse(self.call('IsProcessorFeaturePresent', 999)[0])
        self.machine.mem_write(0x10000, bytes.fromhex('660f76c0 660fefc0'))
        self.machine.emu_start(0x10000, 0x10008)
        self.assertEqual(self.machine.reg_read(x86.UC_X86_REG_XMM0), 0)

    def test_virtual_protection_is_scoped_and_enforced(self):
        self.model.primary_region = (0x11000, 0x2000)
        self.assertEqual(self.result('VirtualProtect', 0x11fff, 2, 2, 0x10020), 1)
        self.assertEqual(struct.unpack('<I', self.machine.mem_read(0x10020, 4))[0], 0x40)
        self.assertFalse(self.call('QueryPerformanceCounter', 0x12000)[0])
        self.assertFalse(self.call('VirtualProtect', 0x10000, 1, 4, 0x10020)[0])
        self.assertFalse(self.call('VirtualProtect', 0x11000, 1, 0x104, 0x10020)[0])
        self.result('VirtualProtect', 0x11000, 0x2000, 4, 0x10020)
        self.assertEqual(struct.unpack('<I', self.machine.mem_read(0x10020, 4))[0], 2)
        self.assertTrue(self.call('QueryPerformanceCounter', 0x12000)[0])
        self.assertEqual(self.result('GetCurrentProcess'), 0xffffffff)
        self.assertTrue(self.call('FlushInstructionCache', 0xffffffff, 0x11000, 16)[0])
        self.assertFalse(self.call('FlushInstructionCache', 123, 0x11000, 16)[0])

    def test_registry_fixture_is_exact_not_blanket_missing_keys(self):
        self.machine.mem_write(0x11000, 'Software\\Aktiv\\Guardant\\SDK7\0'.encode('utf-16-le'))
        args = (0x80000001, 0x11000, 0, 1, 0x12000)
        self.machine.mem_write(0x12000, b'keep')
        self.call('RegOpenKeyExW', *args)  # Sets up stack, wrong DLL is unhandled.
        ok, event = self.model.handle('ADVAPI32.dll!RegOpenKeyExW')
        self.assertTrue(ok, event)
        self.assertEqual(event['result'], '0x2')
        self.assertEqual(bytes(self.machine.mem_read(0x12000, 4)), b'keep')
        self.machine.mem_write(0x11000, 'Software\\Unknown\0'.encode('utf-16-le'))
        self.call('RegOpenKeyExW', *args)
        self.assertFalse(self.model.handle('ADVAPI32.dll!RegOpenKeyExW')[0])

    def test_nls_api_buffer_sizes_and_reference_data(self):
        with tempfile.TemporaryDirectory(prefix='era-nls-api-test-') as directory:
            paths = [Path(directory) / n for n in ('cp', 'sort', 'case')]
            for path, data in zip(paths, (synthetic_codepage(), synthetic_sort(), synthetic_case())):
                path.write_bytes(data)
            self.model.nls = NlsModel(*paths)
            self.machine.mem_write(0x11000, b'A\0\x80')
            self.assertEqual(self.result('MultiByteToWideChar', 1251, 1, 0x11000, 3, 0, 0), 3)
            self.assertEqual(self.result('MultiByteToWideChar', 1251, 1, 0x11000, 3, 0x12000, 3), 3)
            self.assertEqual(bytes(self.machine.mem_read(0x12000, 6)), b'A\0\0\0\x80\0')
            self.assertFalse(self.call('MultiByteToWideChar', 1251, 1, 0x11000, 3, 0x12000, 2)[0])
            self.assertFalse(self.call('MultiByteToWideChar', 1251, 1, 0x11000, 3, 0x11000, 3)[0])
            self.assertEqual(self.result('WideCharToMultiByte', 1251, 0, 0x12000, 3, 0x11000, 3, 0, 0), 3)
            self.assertEqual(self.result('GetStringTypeW', 1, 0x12000, 3, 0x11000), 1)
            self.assertEqual(struct.unpack('<3H', self.machine.mem_read(0x11000, 6)), (10, 1, 1))
            self.assertEqual(self.result('LCMapStringW', 0, 0x200, 0x12000, 1, 0, 0), 1)
            self.result('LCMapStringW', 0, 0x200, 0x12000, 1, 0x11000, 1)
            self.assertEqual(bytes(self.machine.mem_read(0x11000, 2)), b'a\0')
            self.assertFalse(self.call('LCMapStringW', 0, 0x400, 0x12000, 1, 0, 0)[0])
            self.assertFalse(self.call('LCMapStringW', 0, 0x200, 0x12000, 1, 0, 0xffffffff)[0])


if __name__ == '__main__':
    unittest.main()
