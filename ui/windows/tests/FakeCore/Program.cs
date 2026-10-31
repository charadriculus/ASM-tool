using System.Text.Json;

// Offline-only deterministic test double. NEVER include in public/production bundles.
var flags = args.ToList();
static string? Value(List<string> a, string name)
{
    var i = a.IndexOf(name);
    return i >= 0 && i + 1 < a.Count ? a[i + 1] : null;
}
var domain = Value(flags, "--domain") ?? "success.test";
var outdir = Value(flags, "--output-dir");
if (outdir is null) return 2;
if (Directory.Exists(outdir) || File.Exists(outdir)) return 2;
Directory.CreateDirectory(outdir);
void WriteStatus(string state, string operation, bool incomplete, int done,
    string? message = null, string? workerState = null)
{
    var path = Path.Combine(outdir, "run_status.json");
    var payload = new
    {
        state, stage = "synthetic_fixture", current_operation = operation, message = message ?? operation,
        heartbeat_at_utc = DateTimeOffset.UtcNow.ToString("O"),
        last_progress_at_utc = DateTimeOffset.UtcNow.ToString("O"),
        completed = done, planned = 4, incomplete,
        workers = new Dictionary<string, object> { ["fixture-0"] = new {
            state = workerState ?? (state is "running" or "error" ? state : "complete"),
            operation, target = domain, completed = done, planned = 4,
            message = message ?? operation,
            operation_elapsed_seconds = 1.0 } }
    };
    var tmp = path + ".tmp";
    File.WriteAllText(tmp, JsonSerializer.Serialize(payload));
    File.Move(tmp, path, overwrite: true);
}
Console.WriteLine("FAKE_CORE_ARGS:" + string.Join("|", flags));
if (domain.Equals("busy.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("running", "fixture-start", false, 0);
    for (var i = 1; i <= 120; i++)
    {
        if (i % 5 == 0) WriteStatus("running", "fixture-busy", false, i % 4);
        await Task.Delay(100);
    }
}
else
{
    WriteStatus("running", "fixture-start", false, 1);
    await Task.Delay(1300);
    WriteStatus("running", "fixture-progress", false, 2);
    await Task.Delay(400);
}
if (domain.Equals("invalidstatus.test", StringComparison.OrdinalIgnoreCase))
{
    File.WriteAllText(Path.Combine(outdir, "run_status.json"), "{");
    Console.Error.WriteLine("fixture intentionally invalid status");
    return 1;
}
if (domain.Equals("missingstatus.test", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("fixture intentionally omitted status");
    return 0;
}
if (domain.Equals("workererror.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("error", "worker_error", true, 2, "fixture worker failed explicitly");
    Console.Error.WriteLine("fixture worker failed explicitly");
    return 1;
}
if (domain.Equals("workererrorcomplete.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("complete", "complete_with_worker_error", false, 4,
        "fixture worker failed but root state says complete", "error");
    return 0;
}
if (domain.Equals("error.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("error", "fixture-error", true, 2);
    Console.Error.WriteLine("fixture expected failure");
    return 1;
}
if (domain.Equals("interrupted.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("interrupted", "fixture-interrupted", true, 2);
    return 130;
}
if (domain.Equals("incomplete.test", StringComparison.OrdinalIgnoreCase))
{
    WriteStatus("complete", "fixture-incomplete", true, 4);
    File.WriteAllText(Path.Combine(outdir, "run_summary.json"), "{\"incomplete\":true}");
    return 4;
}
WriteStatus("complete", "fixture-complete", false, 4);
File.WriteAllText(Path.Combine(outdir, "run_summary.json"), "{\"incomplete\":false}");
return 0;
