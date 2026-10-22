using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ASMTool.Gui.Models;
using ASMTool.Gui.Services;

var assertions = 0;
void Check(bool ok, string name)
{
    if (!ok) throw new Exception("FAILED: " + name);
    assertions++;
}
var root = Path.Combine(Path.GetTempPath(), "asmtool_0120_gui_tests_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var passive = new ScanOptions("example.com", ScanProfile.Passive, root,
        1000, "standard", "en", false, false, false, null, false, false);
    Check(passive.Validate() is null, "valid passive");
    var passiveArgs = passive.ToCoreArguments(false);
    Check(passiveArgs.SequenceEqual(new[] { "start", "--domain", "example.com",
        "--profile", "passive", "--non-interactive", "--output-dir", root,
        "--dns-budget", "1000", "--passive-sources", "standard",
        "--language", "en" }), "Go passive argv exact");
    Check(!passiveArgs.Contains("--gui-run-id"), "no Python cancellation flag");
    Check(!passiveArgs.Contains("--ai-review"), "no AI in Go argv");
    Check(!passiveArgs.Contains("--allow-unresolved"), "no historic Python flag");

    var verify = passive with { Profile = ScanProfile.Verify, PrimaryDomainOnly = true,
        AllowHttpFallback = true };
    Check(verify.Validate() is null, "valid verify");
    try { verify.ToCoreArguments(false); throw new Exception("Authorization bypass"); }
    catch (InvalidOperationException) { assertions++; }
    var vArgs = verify.ToCoreArguments(true);
    Check(vArgs.Contains("--confirm-authorization"), "Go active authorization");
    Check(vArgs.Contains("--primary-domain-only"), "Go primary-only");
    Check(vArgs.Contains("--allow-http-fallback"), "explicit HTTP fallback");
    Check(vArgs.SequenceEqual(vArgs.Where(x => x != "--allow-unresolved")), "unknown flag absent");
    Check(vArgs.SkipWhile(x => x != "--browser").Take(2)
        .SequenceEqual(new[] { "--browser", "disabled" }), "explicit browser disabling");
    Check(!(verify with { DisableBrowser = false }).ToCoreArguments(true).Contains("--browser"),
        "browser defaults to enabled; no undocumented override");
    Check(!(verify with { AllowHttpFallback = false })
        .ToCoreArguments(true).Contains("--allow-http-fallback"), "no implicit fallback");

    var full = passive with { Profile = ScanProfile.Full, Ports = "80;443" };
    Check(full.Validate() is null, "valid full");
    var fullArgs = full.ToCoreArguments(true);
    Check(!fullArgs.Any(a => a.Contains("nmap", StringComparison.OrdinalIgnoreCase) ||
        a.Contains("service-detection", StringComparison.OrdinalIgnoreCase)), "no obsolete Nmap/service flag");
    Check(fullArgs.SkipWhile(x => x != "--ports").Take(2)
        .SequenceEqual(new[] { "--ports", "80,443" }), "canonical ports");
    Check((full with { Ports = "80-443" }).Validate() is not null, "reject ranges");
    Check((full with { Ports = "80," }).Validate() is not null, "reject empty token");
    Check((passive with { AllowHttpFallback = true }).Validate() is not null, "passive fallback rejected");
    Check((passive with { Target = "--full" }).Validate() is not null, "reject injection target");
    Check((passive with { Target = "exa mple.com" }).Validate() is not null, "reject target whitespace");
    Check((passive with { Target = "example.com/path" }).Validate() is not null, "reject target path");
    Check((passive with { Target = "example.com:8443" }).Validate() is not null, "reject domain port");
    Check((passive with { Target = "https://example.com:443" }).Validate() is not null, "reject URL port");
    Check((passive with { PassiveSources = "research" }).Validate() is not null, "no research profile");
    Check((passive with { DnsBudget = -1 }).Validate() is not null, "negative DNS budget");
    Check((passive with { DnsBudget = 0 }).Validate() is not null, "Go rejects DNS budget zero");

    var runRoot = Path.Combine(root, "Тестовый каталог");
    var first = RunDirectoryFactory.Propose(runRoot);
    var second = RunDirectoryFactory.Propose(runRoot);
    Check(first != second && !Directory.Exists(first) && !Directory.Exists(second),
        "fresh proposed directories never precreated");
    Check(Directory.Exists(runRoot), "parent root created");

    var statusFolder = Path.Combine(root, "status");
    Directory.CreateDirectory(statusFolder);
    File.WriteAllText(Path.Combine(statusFolder, "run_status.json"), JsonSerializer.Serialize(new
    {
        state = "running", stage = "http", current_operation = "HTTP probe",
        heartbeat_at_utc = DateTimeOffset.UtcNow.ToString("O"),
        last_progress_at_utc = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O"),
        completed = 43, planned = 120, incomplete = false,
        workers = new Dictionary<string, object> { ["http-01"] = new {
            state = "running", operation = "probe", target = "example.com",
            completed = 43, planned = 120, operation_elapsed_seconds = 1.5 } }
    }));
    var st = RunStatusReader.TryRead(statusFolder);
    Check(st?.State == "running" && st.Incomplete == false, "status and incomplete parsing");
    Check(st?.ActiveProgress is { } p && p.Completed == 43 &&
        p.Planned == 120 && p.Fraction > .35 && p.Fraction < .36, "worker fraction");
    Check(st is not null && !st.IsStale && st.SinceProgress?.TotalSeconds >= 2,
        "heartbeat differs from progress");
    File.WriteAllText(Path.Combine(statusFolder, "run_status.json"),
        "{\"state\":\"running\",\"workers\":{\"w\":{\"completed\":8,\"planned\":null}}}");
    Check(RunStatusReader.TryRead(statusFolder)?.ActiveProgress is null,
        "unknown plan must not fake progress");
    File.WriteAllText(Path.Combine(statusFolder, "run_status.json"), "{");
    var damaged = RunStatusReader.Read(statusFolder);
    Check(damaged.IsDamaged && damaged.Diagnostic is not null,
        "malformed status is a visible damaged-file result");
    File.WriteAllBytes(Path.Combine(statusFolder, "run_status.json"), new byte[1_048_577]);
    Check(RunStatusReader.Read(statusFolder).IsDamaged, "reject oversized status");
    var pendingFolder = Path.Combine(root, "status-pending");
    Directory.CreateDirectory(pendingFolder);
    var pending = RunStatusReader.Read(pendingFolder);
    Check(!pending.FilePresent && pending.Status is null && pending.Diagnostic is null,
        "missing status remains an expected pending state");
    File.WriteAllText(Path.Combine(statusFolder, "run_status.json"), JsonSerializer.Serialize(new {
        state = "error", message = "worker failed: fixture", workers = new Dictionary<string, object> {
            ["worker-1"] = new { state = "error", message = "specific worker failure" }
        }
    }));
    var workerError = RunStatusReader.Read(statusFolder).Status;
    Check(workerError?.State == "error" && workerError.Message == "worker failed: fixture" &&
        workerError.HasWorkerErrors &&
        workerError.WorkerErrorDiagnostic?.Contains("specific worker failure", StringComparison.Ordinal) == true &&
        RunStatusReader.CompactDisplay(workerError).Contains("specific worker failure", StringComparison.Ordinal),
        "worker error status and diagnostic remain visible");
    var contradictory = workerError! with {
        State = "complete", Incomplete = false,
        Workers = new[] { new WorkerProgress("worker-1", "fetch", "fixture.test", "error",
            4, 4, 1.0, "explicit worker failure") }
    };
    var falseSuccess = new RunOutcome(statusFolder, 0, contradictory, "fixture.log", false);
    Check(!falseSuccess.VerifiedSuccess && falseSuccess.VerifiedIncomplete == false,
        "exit0 complete cannot override a failed worker");
    var incompleteWithError = new RunOutcome(statusFolder, 4,
        contradictory with { Incomplete = true }, "fixture.log", false);
    Check(incompleteWithError.VerifiedIncomplete,
        "proper exit4 incomplete status remains incomplete when worker errors exist");

    var bundle = Path.Combine(root, "bundle");
    Directory.CreateDirectory(bundle);
    var coreFile = Path.Combine(bundle, "asm-tool.exe");
    File.WriteAllBytes(coreFile, Encoding.UTF8.GetBytes("dummy verified bytes"));
    var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(coreFile))).ToLowerInvariant();
    File.WriteAllText(Path.Combine(bundle, "SHA256SUMS"), hash + "  asm-tool.exe\n");
    Check(CorePackageVerifier.VerifyExecutable(bundle) == coreFile, "verify bundled Go executable hash");
    File.AppendAllText(coreFile, "modified");
    try { CorePackageVerifier.VerifyExecutable(bundle); throw new Exception("Tamper accepted"); }
    catch (InvalidDataException) { assertions++; }

    var prefsRoot = Path.Combine(root, "prefs");
    var settings = new GuiSettingsStore(prefsRoot);
    Check(settings.LoadResultsRoot() == settings.DefaultRunsRoot,
        "missing settings return private default");
    var unicodeDirectory = Path.Combine(root, "Результаты", "Тест каталог");
    settings.SaveResultsRoot(unicodeDirectory);
    Check(settings.LoadResultsRoot() == unicodeDirectory, "Unicode preferences roundtrip");
    var settingsFile = Path.Combine(prefsRoot, "config", "gui-settings.json");
    Check(File.Exists(settingsFile), "preferences persisted atomically");
    File.WriteAllText(settingsFile, "{broken");
    Check(settings.LoadResultsRoot() == settings.DefaultRunsRoot,
        "malformed settings fall back to default");
    File.WriteAllText(settingsFile, JsonSerializer.Serialize(new {
        schema_version = 999, results_root = "Z:" }));
    Check(settings.LoadResultsRoot() == settings.DefaultRunsRoot,
        "unsupported preferences schema fails closed");
    File.WriteAllText(settingsFile, new string('x', 65537));
    Check(settings.LoadResultsRoot() == settings.DefaultRunsRoot,
        "oversized preferences ignored");

    Console.WriteLine($"PASS: {assertions} ASM Tool 0.12.3 GUI offline assertions");
}
finally
{
    Directory.Delete(root, recursive: true);
}
