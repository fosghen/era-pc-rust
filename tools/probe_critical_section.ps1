# Self-authored, x86 Windows API experiment. Does not load vendor code,
# access a dongle, use a driver, contact a service, or change registry settings.
# Run with SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File ...
# Add-Type may create compiler temporary files in the current Windows TEMP.
$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 4) { throw 'This probe requires a 32-bit PowerShell process.' }
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class EraCriticalSectionProbe {
    [DllImport("kernel32.dll")] static extern void InitializeCriticalSection(IntPtr p);
    [DllImport("kernel32.dll")] static extern bool InitializeCriticalSectionAndSpinCount(IntPtr p, uint spin);
    [DllImport("kernel32.dll")] static extern void EnterCriticalSection(IntPtr p);
    [DllImport("kernel32.dll")] static extern bool TryEnterCriticalSection(IntPtr p);
    [DllImport("kernel32.dll")] static extern void LeaveCriticalSection(IntPtr p);
    [DllImport("kernel32.dll")] static extern void DeleteCriticalSection(IntPtr p);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    static object Snapshot(IntPtr p, string stage) {
        byte[] bytes = new byte[24];
        Marshal.Copy(p, bytes, 0, bytes.Length);
        uint debug = BitConverter.ToUInt32(bytes, 0);
        uint owner = BitConverter.ToUInt32(bytes, 12);
        uint semaphore = BitConverter.ToUInt32(bytes, 16);
        // Classify native pointers/IDs; never transplant them into emulation.
        return new {
            stage = stage,
            debug_info_kind = debug == 0 ? "null" : debug == UInt32.MaxValue ? "minus_one" : "pointer",
            lock_count = BitConverter.ToInt32(bytes, 4),
            recursion_count = BitConverter.ToInt32(bytes, 8),
            owner_kind = owner == 0 ? "none" : owner == GetCurrentThreadId() ? "current_thread" : "unexpected",
            semaphore_kind = semaphore == 0 ? "null" : "nonzero",
            spin_count = BitConverter.ToUInt32(bytes, 20)
        };
    }
    public static object Run(uint spin, bool basic) {
        IntPtr p = Marshal.AllocHGlobal(24);
        bool initialized = false;
        int depth = 0;
        var stages = new List<object>();
        try {
            for (int i = 0; i < 24; ++i) Marshal.WriteByte(p, i, 0xA5);
            if (basic) InitializeCriticalSection(p);
            else if (!InitializeCriticalSectionAndSpinCount(p, spin)) throw new Exception("Initialization failed");
            initialized = true;
            stages.Add(Snapshot(p, "initialized"));
            EnterCriticalSection(p); ++depth;
            stages.Add(Snapshot(p, "entered"));
            if (!TryEnterCriticalSection(p)) throw new Exception("Recursive TryEnter failed");
            ++depth;
            stages.Add(Snapshot(p, "recursive"));
            LeaveCriticalSection(p); --depth;
            stages.Add(Snapshot(p, "leave_once"));
            LeaveCriticalSection(p); --depth;
            stages.Add(Snapshot(p, "released"));
            DeleteCriticalSection(p); initialized = false;
            stages.Add(Snapshot(p, "deleted_storage"));
            return new { api = basic ? "InitializeCriticalSection" : "InitializeCriticalSectionAndSpinCount", requested_spin = spin, stages = stages };
        } finally {
            if (initialized) {
                while (depth > 0) { LeaveCriticalSection(p); --depth; }
                DeleteCriticalSection(p);
            }
            Marshal.FreeHGlobal(p);
        }
    }
}
'@
[ordered]@{
    schema = 1
    purpose = 'Own uncontended x86 critical-section API probe; no vendor execution'
    pointer_size = [IntPtr]::Size
    processor_count = [Environment]::ProcessorCount
    ntdll_file_version = (Get-Item "$env:windir\SysWOW64\ntdll.dll").VersionInfo.FileVersion
    cases = @([EraCriticalSectionProbe]::Run(0, $true)) + @(0, 4000 | ForEach-Object { [EraCriticalSectionProbe]::Run([uint32]$_, $false) })
} | ConvertTo-Json -Depth 8
