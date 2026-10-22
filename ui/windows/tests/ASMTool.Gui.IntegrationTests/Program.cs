using System.Security.Cryptography;
using System.Text;
using ASMTool.Gui.Models;
using ASMTool.Gui.Services;

int checks = 0;
void Check(bool yes, string label)
{
    if (!yes) throw new Exception("INTEGRATION FAIL: " + label);
    checks++;
    Console.WriteLine("PASS: " + label);
}
var fakePath = Environment.GetEnvironmentVariable("ASM_GUI_TEST_FAKE_EXE")
    ?? throw new Exception("ASM_GUI_TEST_FAKE_EXE is required.");
if (!File.Exists(fakePath)) throw new FileNotFoundException("Fake core missing", fakePath);
var root = Path.Combine(Path.GetTempPath(), "asmgui_integration_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var bundle = Path.Combine(root, "fake_bundle");
Directory.CreateDirectory(bundle);
var exe = Path.Combine(bundle, "asm-tool.exe");
File.Copy(fakePath, exe);
var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exe)));
File.WriteAllText(Path.Combine(bundle, "SHA256SUMS"), hash.ToLowerInvariant() + "  asm-tool.exe\n");
// This bundle contains ONLY an offline fake and MUST NOT be distributed.
var options = new ScanOptions("success.test", ScanProfile.Passive, root, 1000,
    "standard", "en", false, false, false, null, false, false);
try
{
    async Task<(RunOutcome Outcome, List<RunUpdate> Updates)> Run(string test, bool authorized = false,
        ScanProfile profile = ScanProfile.Passive)
    {
        var target = Path.Combine(root, "run_" + test);
        var item = options with { Target = test + ".test", OutputDirectory = target, Profile = profile };
        var events = new List<RunUpdate>();
        var gate = new object();
        var engine = new CoreRunner(bundle, Path.Combine(root, "logs"));
        var result = await engine.RunAuthorizedAsync(item, authorized, update =>
        {
            lock (gate) events.Add(update);
        });
        lock (gate) return (result, events.ToList());
    }

    var ok = await Run("success");
    Check(ok.Outcome.VerifiedSuccess, "exit0 and complete are verified success");
    Check(ok.Outcome.ExitCode == 0 && File.Exists(ok.Outcome.DiagnosticLog),
        "core exit and diagnostic log collected");
    Check(ok.Updates.Any(u => u.Status?.ActiveProgress?.HasDeterminateProgress == true),
        "live worker progress captured");
    Check(ok.Updates.Any(u => u.Resources is { ProcessCount: > 0, SumWorkingSet: > 0 }),
        "Windows process monitor captured");
    Check(File.ReadAllText(ok.Outcome.DiagnosticLog).Contains("--non-interactive"),
        "async redirected stdout drained");
    Check(ok.Outcome.Status?.State == "complete" &&
        ok.Outcome.Status?.Incomplete == false, "final status is authoritative");

    var incomplete = await Run("incomplete");
    Check(incomplete.Outcome.VerifiedIncomplete && !incomplete.Outcome.VerifiedSuccess,
        "exit4 + incomplete distinguished from success");

    var error = await Run("error");
    Check(error.Outcome.ExitCode == 1 && !error.Outcome.VerifiedSuccess &&
        !error.Outcome.VerifiedIncomplete, "error state never shown as successful");
    Check(File.ReadAllText(error.Outcome.DiagnosticLog).Contains("fixture expected failure"),
        "stderr is drained and logged");

    var workerError = await Run("workererror");
    Check(workerError.Outcome.Status?.State == "error" &&
        workerError.Outcome.Status.Message == "fixture worker failed explicitly" &&
        !workerError.Outcome.VerifiedSuccess,
        "worker error status and diagnostic remain visible");

    var contradictoryWorkerError = await Run("workererrorcomplete");
    Check(contradictoryWorkerError.Outcome.ExitCode == 0 &&
        contradictoryWorkerError.Outcome.Status?.State == "complete" &&
        contradictoryWorkerError.Outcome.Status.Incomplete == false &&
        contradictoryWorkerError.Outcome.Status.HasWorkerErrors &&
        contradictoryWorkerError.Outcome.Status.WorkerErrorDiagnostic?.Contains(
            "fixture worker failed", StringComparison.Ordinal) == true &&
        !contradictoryWorkerError.Outcome.VerifiedSuccess,
        "exit0 plus complete cannot hide a worker error or pass success");

    var missingStatus = await Run("missingstatus");
    Check(missingStatus.Outcome.ExitCode == 0 && !missingStatus.Outcome.VerifiedSuccess &&
        missingStatus.Outcome.StatusDiagnostic?.Contains("отсутствует", StringComparison.Ordinal) == true,
        "exit zero without final status is not treated as success");

    var interrupted = await Run("interrupted");
    Check(interrupted.Outcome.VerifiedInterrupted && !interrupted.Outcome.VerifiedSuccess,
        "exit130 + interrupted status classified");

    var invalid = await Run("invalidstatus");
    Check(invalid.Outcome.Status is null &&
        !invalid.Outcome.VerifiedSuccess && invalid.Outcome.StatusDiagnostic is not null,
        "corrupted final status is diagnosed and never accepted as success");

    var noAuthorize = options with { Profile = ScanProfile.Verify,
        Target = "unauthorized.test", OutputDirectory = Path.Combine(root, "no_auth") };
    try
    {
        await new CoreRunner(bundle, Path.Combine(root, "logs")).RunAuthorizedAsync(noAuthorize, false, _ => { });
        throw new Exception("Unapproved active investigation accepted");
    }
    catch (InvalidOperationException)
    {
        Check(!Directory.Exists(noAuthorize.OutputDirectory),
            "active profile fails before output without authorization");
    }

    var existing = Path.Combine(root, "preexisting");
    Directory.CreateDirectory(existing);
    try
    {
        await new CoreRunner(bundle, Path.Combine(root, "logs")).RunAuthorizedAsync(options with {
            Target = "existing.test", OutputDirectory = existing }, false, _ => { });
        throw new Exception("Existing output directory accepted");
    }
    catch (IOException)
    {
        Check(Directory.Exists(existing), "preexisting results are never overwritten");
    }

    var tamper = Path.Combine(bundle, "SHA256SUMS");
    File.WriteAllText(tamper, new string('0', 64) + "  asm-tool.exe\n");
    try
    {
        await new CoreRunner(bundle, Path.Combine(root, "logs")).RunAuthorizedAsync(options with {
            Target = "tamper.test", OutputDirectory = Path.Combine(root, "tamper") }, false, _ => { });
        throw new Exception("Tampered bundle accepted");
    }
    catch (InvalidDataException)
    {
        Check(!Directory.Exists(Path.Combine(root, "tamper")),
            "tampered core fails closed before creating output");
    }
    File.WriteAllText(tamper, hash.ToLowerInvariant() + "  asm-tool.exe\n");

    var busyRunDir = Path.Combine(root, "busy");
    var busyEngine = new CoreRunner(bundle, Path.Combine(root, "logs"));
    var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    var busy = busyEngine.RunAuthorizedAsync(options with { Target = "busy.test",
        OutputDirectory = busyRunDir }, false, update =>
        {
            if (update.Status?.State == "running")
                started.TrySetResult(true);
        });
    await started.Task.WaitAsync(TimeSpan.FromSeconds(8));
    Check(busyEngine.IsRunning, "live CoreRunner owns process");
    var secondRunDir = Path.Combine(root, "must_not_start_while_busy");
    try
    {
        await busyEngine.RunAuthorizedAsync(options with {
            Target = "success.test", OutputDirectory = secondRunDir }, false, _ => { });
        throw new Exception("Concurrent start was accepted");
    }
    catch (InvalidOperationException)
    {
        Check(!Directory.Exists(secondRunDir), "concurrent start blocked before output");
    }
    busyEngine.ForceTerminateAfterUserConfirmation();
    var killed = await busy.WaitAsync(TimeSpan.FromSeconds(10));
    Check(killed.ForceTerminated && !killed.VerifiedSuccess && !killed.VerifiedIncomplete,
        "force termination never claims success");
    Check(!busyEngine.IsRunning, "force-stopped process joined");

    var recovery = await Run("success2");
    Check(recovery.Outcome.VerifiedSuccess, "new run succeeds after previous force stop");

    // Invoke the real accepted Go Core only with --validate-only: no collection, DNS or HTTP.
    var acceptedGo = Environment.GetEnvironmentVariable("ASM_GUI_TEST_ACCEPTED_GO_EXE");
    if (!string.IsNullOrWhiteSpace(acceptedGo))
    {
        var variants = new[]
        {
            options,
            options with { Target = "example.com", DnsBudget = 1, PassiveSources = "deep" },
            options with { Target = "example.com", ReportLanguage = "ru", FullReport = true },
            options with { Target = "example.com", Profile = ScanProfile.Verify, DisableBrowser = true },
            options with { Target = "example.com", Profile = ScanProfile.Verify,
                DisableBrowser = false },
            options with { Target = "example.com", Profile = ScanProfile.Verify,
                AllowHttpFallback = true, DisableBrowser = true, PrimaryDomainOnly = true },
            options with { Target = "example.com", Profile = ScanProfile.Verify,
                AllowHttpFallback = true, DisableBrowser = true, IncludeWildcardAmbiguous = true },
            options with { Target = "example.com", Profile = ScanProfile.Full,
                Ports = "80,443", DisableBrowser = true,
                AllowHttpFallback = true },
            options with { Target = "example.com", Profile = ScanProfile.Full,
                Ports = "443", DisableBrowser = true, FullReport = true,
                ReportLanguage = "ru" },
        };
        for (var i = 0; i < variants.Length; i++)
        {
            var variant = variants[i] with {
                Target = "example.com",
                OutputDirectory = Path.Combine(root, "core-validation-" + i)
            };
            var psi = new System.Diagnostics.ProcessStartInfo {
                FileName = acceptedGo, UseShellExecute = false,
                RedirectStandardError = true, RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            foreach (var arg in variant.ToCoreArguments(variant.Profile != ScanProfile.Passive))
                psi.ArgumentList.Add(arg);
            psi.ArgumentList.Add("--validate-only");
            using var proc = new System.Diagnostics.Process { StartInfo = psi };
            proc.Start();
            var errTask = proc.StandardError.ReadToEndAsync();
            var outTask = proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
            var errText = await errTask;
            var outText = await outTask;
            Check(proc.ExitCode == 0 && outText.Contains("configuration valid"),
                "accepted Go validate-only profile variant " + i + ": " + errText);
            Check(!Directory.Exists(variant.OutputDirectory),
                "Go validate-only performs no run output variant " + i);
        }
    }

    Console.WriteLine("TOTAL PASS: " + checks + " integration assertions");
}
finally
{
    try { Directory.Delete(root, true); } catch (IOException) { }
}
