using System.Diagnostics;
using System.Text;
using ASMTool.Gui.Models;

namespace ASMTool.Gui.Services;

public sealed record RunUpdate(CoreRunStatus? Status, ResourceSnapshot? Resources,
    string? StatusDiagnostic = null, bool StatusPending = false);

public sealed record RunOutcome(string RunDirectory, int ExitCode, CoreRunStatus? Status,
    string DiagnosticLog, bool ForceTerminated, string? StatusDiagnostic = null)
{
    public bool VerifiedSuccess => !ForceTerminated && ExitCode == 0 &&
        Status?.State == "complete" && Status.Incomplete == false &&
        Status.HasWorkerErrors == false;
    public bool VerifiedIncomplete => !ForceTerminated && ExitCode == 4 &&
        Status?.State == "complete" && Status.Incomplete == true;
    public bool VerifiedInterrupted => !ForceTerminated && ExitCode == 130 &&
        Status?.State == "interrupted";
}

/// <summary>
/// Runs one authenticated Go executable, with bounded diagnostics and independent status polling.
/// Go 0.12.3 has no GUI cancellation protocol: force-stop requires explicit user confirmation.
/// </summary>
public sealed class CoreRunner
{
    private const int MaxDiagnosticBytes = 8 * 1024 * 1024;
    private readonly string? _bundleDirectory;
    private readonly string? _diagnosticRoot;
    public CoreRunner(string? bundleDirectory = null, string? diagnosticRoot = null)
    {
        _bundleDirectory = bundleDirectory;
        _diagnosticRoot = diagnosticRoot;
    }
    private Process? _activeProcess;
    private string? _runDirectory;
    private bool _forceTerminated;
    private int _runGate;
    public bool IsRunning => Volatile.Read(ref _runGate) != 0;

    public void ForceTerminateAfterUserConfirmation()
    {
        var process = _activeProcess;
        if (process is not { HasExited: false })
            throw new InvalidOperationException("Нет выполняющегося исследования.");
        _forceTerminated = true;
        process.Kill(entireProcessTree: true);
    }

    public async Task<RunOutcome> RunAuthorizedAsync(
        ScanOptions options, bool authorized, Action<RunUpdate> observer,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _runGate, 1, 0) != 0)
            throw new InvalidOperationException("Исследование уже выполняется.");
        try
        {
            return await RunCoreAsync(options, authorized, observer, cancellationToken);
        }
        finally
        {
            Volatile.Write(ref _runGate, 0);
        }
    }

    private async Task<RunOutcome> RunCoreAsync(
        ScanOptions options, bool authorized, Action<RunUpdate> observer,
        CancellationToken cancellationToken)
    {
        if (options.Validate() is { } invalid)
            throw new ArgumentException(invalid);
        var bundle = (_bundleDirectory ?? AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar);
        var exe = CorePackageVerifier.VerifyExecutable(bundle);
        var argv = options.ToCoreArguments(authorized);
        if (Directory.Exists(options.OutputDirectory) || File.Exists(options.OutputDirectory))
            throw new IOException("Каталог исследования уже существует: требуется новый путь.");

        var dataRoot = _diagnosticRoot ?? Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData), "ASM Tool", "logs");
        Directory.CreateDirectory(dataRoot);
        var logfile = Path.Combine(dataRoot, "gui_" + Guid.NewGuid().ToString("N") + ".log");
        using var log = new FileStream(logfile, FileMode.CreateNew, FileAccess.Write,
            FileShare.Read, bufferSize: 4096, useAsync: true);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = bundle,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false)
        };
        foreach (var arg in argv) psi.ArgumentList.Add(arg);
        // Limit hostile environment overrides. The Go runtime verifies its own portable payload.
        foreach (var key in new[] { "GODEBUG", "GOTOOLCHAIN", "GOWORK",
            "GOPATH", "GOPROXY", "GOFLAGS" })
            psi.Environment.Remove(key);
        using var job = WindowsJobObject.CreateKillOnClose();
        using var process = new Process { StartInfo = psi };
        if (!process.Start())
            throw new InvalidOperationException("Не удалось запустить Go-ядро.");

        try
        {
            job.Assign(process);
        }
        catch
        {
            // Assignment failed: stop the uncontained process immediately.
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            throw;
        }

        _activeProcess = process;
        _runDirectory = options.OutputDirectory;
        _forceTerminated = false;
        var monitor = new WindowsResourceMonitor(process.Id);
        using var writeLock = new SemaphoreSlim(1, 1);
        var recorded = 0;

        async Task DrainAsync(StreamReader source, string label)
        {
            var buffer = new char[2048];
            try
            {
                int count;
                while ((count = await source.ReadAsync(buffer.AsMemory(), CancellationToken.None)) > 0)
                {
                    await writeLock.WaitAsync();
                    try
                    {
                        if (recorded >= MaxDiagnosticBytes) continue;
                        var bytes = Encoding.UTF8.GetBytes(label + new string(buffer, 0, count));
                        var length = Math.Min(bytes.Length, MaxDiagnosticBytes - recorded);
                        if (length > 0)
                        {
                            await log.WriteAsync(bytes.AsMemory(0, length));
                            recorded += length;
                        }
                    }
                    finally { writeLock.Release(); }
                }
            }
            catch (IOException)
            {
                // Exit code and persisted status are the authoritative outcomes.
            }
        }

        async Task PollAsync(CancellationToken token)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            while (!token.IsCancellationRequested)
            {
                var read = RunStatusReader.Read(options.OutputDirectory);
                ResourceSnapshot? resources;
                try { resources = await Task.Run(monitor.Sample, token); }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // Operational monitoring must never terminate the actual scan.
                    resources = null;
                }
                observer(new RunUpdate(read.Status, resources, read.Diagnostic, !read.FilePresent));
                if (!await timer.WaitForNextTickAsync(token)) break;
            }
        }

        using var pollStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var stdoutDrain = DrainAsync(process.StandardOutput, "");
        var stderrDrain = DrainAsync(process.StandardError, "[stderr] ");
        var polling = Task.Run(async () =>
        {
            try { await PollAsync(pollStop.Token); }
            catch (OperationCanceledException) { }
        });
        try
        {
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(stdoutDrain, stderrDrain);
            await log.FlushAsync();
            var finalRead = RunStatusReader.Read(options.OutputDirectory);
            var finalStatus = finalRead.Status;
            var finalDiagnostic = finalRead.Diagnostic ?? (finalStatus is null
                ? "Файл run_status.json отсутствует после завершения ядра."
                : null);
            observer(new RunUpdate(finalStatus, null, finalDiagnostic, false));
            return new RunOutcome(options.OutputDirectory, process.ExitCode,
                finalStatus, logfile, _forceTerminated, finalDiagnostic);
        }
        finally
        {
            pollStop.Cancel();
            await polling;
            _activeProcess = null;
            _runDirectory = null;
        }
    }
}
