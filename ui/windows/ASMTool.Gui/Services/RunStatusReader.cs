using System.Text.Json;

namespace ASMTool.Gui.Services;

public sealed record WorkerProgress(
    string Id, string? Operation, string? Target, string? State,
    long? Completed, long? Planned, double? ElapsedSeconds, string? Message = null)
{
    public bool HasDeterminateProgress =>
        Completed is >= 0 && Planned is > 0 && Completed <= Planned;
    public double Fraction => HasDeterminateProgress
        ? Math.Clamp((double)Completed!.Value / Planned!.Value, 0, 1) : 0;
}

public sealed record CoreRunStatus(
    string? State, string? Stage, string? CurrentOperation, string? Message,
    DateTimeOffset? HeartbeatUtc, DateTimeOffset? LastProgressUtc,
    long? Completed, long? Planned, bool? Incomplete, IReadOnlyList<WorkerProgress> Workers)
{
    public bool Terminal => State is "complete" or "interrupted" or "error";
    public bool IsStale => HeartbeatUtc is { } stamp &&
        DateTimeOffset.UtcNow - stamp > TimeSpan.FromSeconds(30);
    public TimeSpan? SinceProgress => LastProgressUtc is { } stamp
        ? DateTimeOffset.UtcNow - stamp : null;
    public bool HasWorkerErrors => Workers.Any(IsFailedWorker);
    public string? WorkerErrorDiagnostic
    {
        get
        {
            var errors = Workers.Where(IsFailedWorker).Take(3)
                .Select(w => string.IsNullOrWhiteSpace(w.Message)
                    ? $"{w.Id}: {w.State}" : $"{w.Id}: {w.Message}");
            var text = string.Join("; ", errors);
            return text.Length > 360 ? text[..359] + "…" : text.Length == 0 ? null : text;
        }
    }
    private static bool IsFailedWorker(WorkerProgress worker) =>
        string.Equals(worker.State, "error", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(worker.State, "failed", StringComparison.OrdinalIgnoreCase);
    public WorkerProgress? ActiveProgress => Workers.FirstOrDefault(w =>
        w.HasDeterminateProgress && w.State is not ("complete" or "idle" or "stopped"));
}

public sealed record StatusReadResult(CoreRunStatus? Status, bool FilePresent, string? Diagnostic)
{
    public bool IsDamaged => FilePresent && Status is null;
}

public static class RunStatusReader
{
    private const long MaxStatusBytes = 1_048_576;
    private const int MaxTextLength = 180;

    public static StatusReadResult Read(string runDirectory)
    {
        var path = Path.Combine(runDirectory, "run_status.json");
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length is < 2 or > MaxStatusBytes)
                return new(null, true, "Файл run_status.json пуст или превышает 1 МиБ.");
            using var doc = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 32 });
            var status = Parse(doc.RootElement);
            return status is null
                ? new(null, true, "Файл run_status.json имеет неподдерживаемую структуру.")
                : new(status, true, null);
        }
        catch (FileNotFoundException) { return new(null, false, null); }
        catch (DirectoryNotFoundException) { return new(null, false, null); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or NotSupportedException)
        {
            return new(null, true, "Не удалось прочитать run_status.json: " + SafeDiagnostic(ex));
        }
    }

    private static string SafeDiagnostic(Exception ex)
    {
        var message = new string(ex.Message.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return message.Length > MaxTextLength ? message[..(MaxTextLength - 1)] + "…" : message;
    }

    public static CoreRunStatus? TryRead(string runDirectory)
    {
        return Read(runDirectory).Status;
    }

    public static CoreRunStatus? Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        string? Str(JsonElement item, string key)
        {
            if (!item.TryGetProperty(key, out var v) || v.ValueKind != JsonValueKind.String)
                return null;
            var text = v.GetString() ?? "";
            text = new string(text.Where(c => !char.IsControl(c)).ToArray()).Trim();
            return text.Length > MaxTextLength ? text[..(MaxTextLength - 1)] + "…" : text;
        }
        static long? Number(JsonElement item, string key)
            => item.TryGetProperty(key, out var v) &&
               v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;
        static DateTimeOffset? Timestamp(string? value)
            => DateTimeOffset.TryParse(value, out var stamp) ? stamp : null;

        var state = Str(root, "state");
        if (state is not ("initializing" or "running" or "stopping" or "complete" or "error" or "interrupted"))
            return null;
        var workers = new List<WorkerProgress>();
        if (root.TryGetProperty("workers", out var w))
        {
            if (w.ValueKind != JsonValueKind.Object) return null;
            var properties = w.EnumerateObject().Take(257).ToArray();
            if (properties.Length > 256) return null;
            foreach (var property in properties)
            {
                if (property.Value.ValueKind != JsonValueKind.Object) return null;
                var v = property.Value;
                var workerState = Str(v, "state");
                if (workerState is null) return null;
                var workerId = new string(property.Name.Where(c => !char.IsControl(c))
                    .Take(MaxTextLength).ToArray()).Trim();
                workers.Add(new WorkerProgress(workerId.Length == 0 ? "worker" : workerId, Str(v, "operation"),
                    Str(v, "url") ?? Str(v, "target"), workerState,
                    Number(v, "completed"), Number(v, "planned"),
                    v.TryGetProperty("operation_elapsed_seconds", out var el) &&
                    el.ValueKind == JsonValueKind.Number && el.TryGetDouble(out var sec) &&
                    double.IsFinite(sec) && sec >= 0 ? sec : null,
                    Str(v, "message")));
            }
        }
        bool? incomplete = root.TryGetProperty("incomplete", out var inc) &&
            inc.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? inc.GetBoolean() : null;
        return new CoreRunStatus(state, Str(root, "stage"),
            Str(root, "current_operation"), Str(root, "message"),
            Timestamp(Str(root, "heartbeat_at_utc")),
            Timestamp(Str(root, "last_progress_at_utc")),
            Number(root, "completed"), Number(root, "planned"), incomplete, workers);
    }

    public static string CompactDisplay(CoreRunStatus? status)
    {
        if (status is null) return "Ожидание данных от ядра";
        if (status.HasWorkerErrors) return "Ошибка рабочего модуля: " + status.WorkerErrorDiagnostic;
        if (status.State == "stopping") return "Остановка исследования…";
        if (status.IsStale) return "Нет актуального сигнала от ядра";
        if (status.State == "error") return status.Message ?? status.CurrentOperation ?? "Ошибка ядра";
        return status.CurrentOperation ?? status.Message ?? status.Stage ?? "Исследование выполняется";
    }
}
