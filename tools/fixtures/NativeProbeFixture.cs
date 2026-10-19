// Own controlled Win32 fixture, intended for .NET Framework csc /platform:x86.
// No vendor code, dongles, real device handles, network, registry or file writes.
// The CLR performs its normal runtime housekeeping. Thread creation is deliberately
// omitted: this first fixture does not require an unmanaged managed-code callback.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

internal static class NativeProbeFixture
{
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 0x102;
    private const uint WaitFailed = 0xffffffff;
    private const uint OpenExisting = 3;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);
    private static readonly List<IntPtr> OwnedHandles = new List<IntPtr>();
    private static readonly List<string> Calls = new List<string>();
    private static readonly List<string> Assertions = new List<string>();

    private static class Native
    {
        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateEventW(IntPtr security,
            [MarshalAs(UnmanagedType.Bool)] bool manualReset,
            [MarshalAs(UnmanagedType.Bool)] bool initialState, string name);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetEvent(IntPtr handle);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ResetEvent(IntPtr handle);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint WaitForMultipleObjects(uint count, [In] IntPtr[] handles,
            [MarshalAs(UnmanagedType.Bool)] bool waitAll, uint milliseconds);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFileW(string name, uint desiredAccess, uint shareMode,
            IntPtr security, uint creationDisposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeviceIoControl(IntPtr device, uint controlCode,
            IntPtr input, uint inputSize, IntPtr output, uint outputSize,
            out uint bytesReturned, IntPtr overlapped);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern uint GetCurrentProcessId();
    }

    private static string Quote(string value)
    {
        StringBuilder result = new StringBuilder("\"");
        foreach (char ch in value)
        {
            if (ch == '\\' || ch == '"') result.Append('\\').Append(ch);
            else if (ch < 32) result.Append("\\u").Append(((int)ch).ToString("x4"));
            else result.Append(ch);
        }
        return result.Append('"').ToString();
    }

    private static void Record(string api, string result, int? error)
    {
        Calls.Add("{\"api\":" + Quote(api) + ",\"result\":" + result +
            ",\"last_error\":" + (error.HasValue ? error.Value.ToString() : "null") + "}");
    }

    private static void Check(bool passed, string name)
    {
        Assertions.Add("{\"name\":" + Quote(name) + ",\"passed\":" +
            (passed ? "true" : "false") + "}");
        if (!passed) throw new InvalidOperationException(name);
    }

    private static string HandleValue(IntPtr handle)
    {
        return Quote("0x" + unchecked((uint)handle.ToInt64()).ToString("x8"));
    }

    private static IntPtr Event(bool manual, string label)
    {
        IntPtr handle = Native.CreateEventW(IntPtr.Zero, manual, false, null);
        int? error = handle == IntPtr.Zero ? (int?)Marshal.GetLastWin32Error() : null;
        Record("CreateEventW", HandleValue(handle), error);
        if (handle != IntPtr.Zero && handle != InvalidHandle) OwnedHandles.Add(handle);
        Check(handle != IntPtr.Zero && handle != InvalidHandle, label + ": created unnamed event");
        return handle;
    }

    private static void Set(IntPtr handle, string label)
    {
        bool success = Native.SetEvent(handle);
        int? error = success ? null : (int?)Marshal.GetLastWin32Error();
        Record("SetEvent", success ? "true" : "false", error);
        Check(success, label + ": SetEvent succeeded");
    }

    private static void Reset(IntPtr handle, string label)
    {
        bool success = Native.ResetEvent(handle);
        int? error = success ? null : (int?)Marshal.GetLastWin32Error();
        Record("ResetEvent", success ? "true" : "false", error);
        Check(success, label + ": ResetEvent succeeded");
    }

    private static void Wait(IntPtr handle, uint expected, string label)
    {
        uint result = Native.WaitForSingleObject(handle, 0);
        int? error = result == WaitFailed ? (int?)Marshal.GetLastWin32Error() : null;
        Record("WaitForSingleObject", result.ToString(), error);
        Check(result == expected, label);
    }

    private static void WaitAny(IntPtr first, IntPtr second, uint expected, string label)
    {
        uint result = Native.WaitForMultipleObjects(2, new IntPtr[] { first, second }, false, 0);
        int? error = result == WaitFailed ? (int?)Marshal.GetLastWin32Error() : null;
        Record("WaitForMultipleObjects", result.ToString(), error);
        Check(result == expected, label);
    }

    private static void Run()
    {
        Check(IntPtr.Size == 4, "x86 process");
        IntPtr manual = Event(true, "manual");
        IntPtr automatic = Event(false, "automatic");
        Wait(manual, WaitTimeout, "manual initially unsignaled, timeout zero");
        Set(manual, "manual");
        Wait(manual, WaitObject0, "manual signaled wait succeeds");
        Wait(manual, WaitObject0, "manual signal persists after wait");
        Reset(manual, "manual");
        Wait(manual, WaitTimeout, "manual reset removes signal");
        Wait(automatic, WaitTimeout, "automatic initially unsignaled");
        Set(automatic, "automatic");
        Wait(automatic, WaitObject0, "automatic signaled wait succeeds");
        Wait(automatic, WaitTimeout, "automatic signal consumed by wait");
        WaitAny(manual, automatic, WaitTimeout, "wait-any both unsignaled");
        Set(automatic, "automatic for index-one wait");
        WaitAny(manual, automatic, WaitObject0 + 1, "wait-any returns second object's index");
        Wait(automatic, WaitTimeout, "wait-any consumes automatic signal");

        // OPEN_EXISTING, desiredAccess=0: never create/truncate/write a file.
        // PID plus a fresh GUID makes accidental device-name collision negligible.
        // Unexpected success is a failed test; that handle is only closed, not used.
        uint processId = Native.GetCurrentProcessId();
        Record("GetCurrentProcessId", processId.ToString(), null);
        Check(processId != 0, "current process ID is nonzero");
        string absentName = @"\\.\ERA_RE_NONEXISTENT_FIXTURE_" +
            processId.ToString() + "_" + Guid.NewGuid().ToString("N");
        IntPtr absent = Native.CreateFileW(absentName, 0, 0, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        int? absentError = absent == InvalidHandle ? (int?)Marshal.GetLastWin32Error() : null;
        Record("CreateFileW", HandleValue(absent), absentError);
        if (absent != InvalidHandle && absent != IntPtr.Zero) OwnedHandles.Add(absent);
        Check(absent == InvalidHandle, "unique nonexistent device name cannot be opened");
        Check(absentError.HasValue && absentError.Value != 0, "failed open supplies an error");

        // The invalid handle cannot identify a real device. No input/output buffer
        // or overlapped operation is supplied; failure outputs are not interpreted.
        uint returned;
        bool control = Native.DeviceIoControl(InvalidHandle, 0, IntPtr.Zero, 0,
            IntPtr.Zero, 0, out returned, IntPtr.Zero);
        int? controlError = control ? null : (int?)Marshal.GetLastWin32Error();
        Record("DeviceIoControl", control ? "true" : "false", controlError);
        Check(!control, "DeviceIoControl with INVALID_HANDLE_VALUE fails");
        Check(controlError.HasValue && controlError.Value != 0, "failed control supplies an error");
    }

    private static void CloseOwnedHandles()
    {
        bool allClosed = true;
        foreach (IntPtr handle in OwnedHandles)
        {
            bool closed = Native.CloseHandle(handle);
            int? error = closed ? null : (int?)Marshal.GetLastWin32Error();
            Record("CloseHandle", closed ? "true" : "false", error);
            Assertions.Add("{\"name\":\"owned handle closed\",\"passed\":" +
                (closed ? "true" : "false") + "}");
            allClosed = allClosed && closed;
        }
        OwnedHandles.Clear();
        if (!allClosed) throw new InvalidOperationException("CloseHandle failed for an owned handle");
    }

    private static int Main()
    {
        string failure = null;
        try { Run(); }
        catch (Exception error) { failure = error.GetType().Name + ": " + error.Message; }
        finally
        {
            try { CloseOwnedHandles(); }
            catch (Exception error)
            {
                failure = (failure == null ? "" : failure + "; ") +
                    error.GetType().Name + ": " + error.Message;
            }
        }
        Console.WriteLine("{\"fixture\":\"owned-win32-events-and-invalid-device-v1\",\"success\":" +
            (failure == null ? "true" : "false") + ",\"pointer_size\":" + IntPtr.Size.ToString() +
            ",\"call_count\":" + Calls.Count.ToString() + ",\"assertion_count\":" + Assertions.Count.ToString() +
            ",\"calls\":[" + String.Join(",", Calls.ToArray()) + "],\"assertions\":[" +
            String.Join(",", Assertions.ToArray()) + "],\"thread_coverage\":false," +
            "\"scope\":\"Own unnamed events, zero-time waits, nonexistent device-name OPEN_EXISTING with access zero, invalid-handle IOCTL only; no vendor or real device interaction\"," +
            "\"error\":" + (failure == null ? "null" : Quote(failure)) + "}");
        return failure == null ? 0 : 1;
    }
}
