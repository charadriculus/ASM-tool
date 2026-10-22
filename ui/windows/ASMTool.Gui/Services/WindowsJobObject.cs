using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ASMTool.Gui.Services;

/// <summary>
/// Kernel-enforced process-tree lifetime. Closing the GUI releases the last
/// Job handle and terminates still-running members, including descendants.
/// A failed assignment is fatal: never run an uncontained research process.
/// </summary>
public sealed class WindowsJobObject : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int ExtendedLimitInformation = 9;
    private readonly SafeFileHandle _handle;
    private bool _disposed;

    private WindowsJobObject(SafeFileHandle handle) => _handle = handle;

    public static WindowsJobObject CreateKillOnClose()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows Job Objects are required.");
        var handle = CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            var code = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(code, "Невозможно создать Windows Job Object.");
        }
        var info = new JobObjectExtendedLimitInformation();
        info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        if (!SetInformationJobObject(handle, ExtendedLimitInformation, ref info,
            (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            var code = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(code, "Невозможно включить KILL_ON_JOB_CLOSE.");
        }
        return new WindowsJobObject(handle);
    }

    public void Assign(Process process)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (process.HasExited)
            throw new InvalidOperationException("Процесс завершился до назначения Job Object.");
        if (!AssignProcessToJobObject(_handle, process.Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Не удалось поместить Go-процесс в Windows Job Object.");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _handle.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass,
        ref JobObjectExtendedLimitInformation info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr processHandle);
}
