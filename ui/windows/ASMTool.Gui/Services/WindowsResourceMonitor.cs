using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ASMTool.Gui.Services;

/// <summary>Best-effort operational metrics; network traffic is for a shared interface, not the core.</summary>
public sealed record ResourceSnapshot(double? CpuPercent, long? SumWorkingSet,
    double? InterfaceRxBytesPerSecond, double? InterfaceTxBytesPerSecond,
    double? ProcessReadBytesPerSecond, double? ProcessWriteBytesPerSecond,
    TimeSpan Elapsed, int ProcessCount, string? NetworkInterfaceName);

public sealed class WindowsResourceMonitor
{
    private readonly int _rootPid;
    private readonly Stopwatch _timer = Stopwatch.StartNew();
    private readonly Dictionary<int, (TimeSpan Cpu, DateTimeOffset Created)> _cpu = new();
    private readonly Dictionary<int, (DateTimeOffset Created, ulong Read, ulong Write)> _io = new();
    private DateTimeOffset? _lastSample;
    private (long Rx, long Tx)? _previousNetwork;
    private string? _networkName;

    public WindowsResourceMonitor(int rootPid) => _rootPid = rootPid;

    public ResourceSnapshot Sample()
    {
        var at = DateTimeOffset.UtcNow;
        double elapsed = _lastSample is { } prev ? Math.Max(0.001, (at - prev).TotalSeconds) : 0;
        _lastSample = at;

        var parentByPid = GetParentPids();
        var selected = new HashSet<int> { _rootPid };
        bool expanded;
        do
        {
            expanded = false;
            foreach (var (pid, parent) in parentByPid)
                if (selected.Contains(parent) && selected.Add(pid))
                    expanded = true;
        } while (expanded);

        double cpu = 0;
        long ram = 0;
        bool hasCpu = false, hasRam = false;
        ulong readDiff = 0, writeDiff = 0;
        int count = 0;
        var nextCpu = new Dictionary<int, (TimeSpan Cpu, DateTimeOffset Created)>();
        var nextIo = new Dictionary<int, (DateTimeOffset Created, ulong Read, ulong Write)>();
        foreach (var pid in selected)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                var created = new DateTimeOffset(proc.StartTime.ToUniversalTime(), TimeSpan.Zero);
                var total = proc.TotalProcessorTime;
                var memory = proc.WorkingSet64;
                count++;
                ram += memory;
                hasRam = true;
                if (_cpu.TryGetValue(pid, out var old) && old.Created == created && elapsed > 0)
                {
                    cpu += Math.Max(0, (total - old.Cpu).TotalSeconds);
                    hasCpu = true;
                }
                nextCpu[pid] = (total, created);
                if (GetProcessIoCounters(proc.Handle, out var io))
                {
                    if (_io.TryGetValue(pid, out var prevIo) && prevIo.Created == created)
                    {
                        if (io.ReadTransferCount >= prevIo.Read)
                            readDiff += io.ReadTransferCount - prevIo.Read;
                        if (io.WriteTransferCount >= prevIo.Write)
                            writeDiff += io.WriteTransferCount - prevIo.Write;
                    }
                    nextIo[pid] = (created, io.ReadTransferCount, io.WriteTransferCount);
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                or System.ComponentModel.Win32Exception)
            {
                // A child may exit or access to its counters may be denied.
            }
        }
        _cpu.Clear();
        foreach (var kv in nextCpu) _cpu[kv.Key] = kv.Value;
        _io.Clear();
        foreach (var kv in nextIo) _io[kv.Key] = kv.Value;

        double? rx = null, tx = null;
        try
        {
            var iface = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
                n.OperationalStatus == OperationalStatus.Up &&
                n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or
                    NetworkInterfaceType.Wireless80211);
            if (iface is not null)
            {
                var stats = iface.GetIPv4Statistics();
                if (_previousNetwork is { } prevNet && _networkName == iface.Id && elapsed > 0)
                {
                    rx = Math.Max(0, stats.BytesReceived - prevNet.Rx) / elapsed;
                    tx = Math.Max(0, stats.BytesSent - prevNet.Tx) / elapsed;
                }
                _networkName = iface.Id;
                _previousNetwork = (stats.BytesReceived, stats.BytesSent);
            }
            else { _networkName = null; _previousNetwork = null; }
        }
        catch (NetworkInformationException)
        {
            _previousNetwork = null;
        }

        return new ResourceSnapshot(hasCpu ? cpu / elapsed / Math.Max(1, Environment.ProcessorCount) * 100 : null,
            hasRam ? ram : null, rx, tx,
            elapsed > 0 ? readDiff / elapsed : null,
            elapsed > 0 ? writeDiff / elapsed : null,
            _timer.Elapsed, count, _networkName);
    }

    private static Dictionary<int, int> GetParentPids()
    {
        var parents = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(0x00000002, 0);
        if (snapshot == new IntPtr(-1)) return parents;
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (Process32FirstW(snapshot, ref entry))
                do { parents[unchecked((int)entry.ProcessId)] = unchecked((int)entry.ParentProcessId); }
                while (Process32NextW(snapshot, ref entry));
        }
        finally { CloseHandle(snapshot); }
        return parents;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size, Usage, ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId, Threads, ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperations, WriteOperations, OtherOperations;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr process, out IoCounters ioCounters);
}
