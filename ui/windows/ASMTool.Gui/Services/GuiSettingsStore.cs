using System.Text.Json;

namespace ASMTool.Gui.Services;

/// <summary>
/// GUI-only preference file. Never edits core's config/settings.yml.
/// </summary>
public sealed class GuiSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true
    };

    private readonly string _file;
    public string DefaultRunsRoot { get; }

    public GuiSettingsStore(string? testDataRoot = null)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dataRoot = testDataRoot ?? Path.Combine(local, "ASM Tool");
        _file = Path.Combine(dataRoot, "config", "gui-settings.json");
        DefaultRunsRoot = Path.Combine(dataRoot, "runs");
    }

    public string LoadResultsRoot()
    {
        try
        {
            if (!File.Exists(_file)) return DefaultRunsRoot;
            var json = File.ReadAllText(_file);
            if (json.Length > 65536) return DefaultRunsRoot;
            var saved = JsonSerializer.Deserialize<GuiSettings>(json, JsonOptions);
            return saved?.SchemaVersion == 1 && !string.IsNullOrWhiteSpace(saved.ResultsRoot)
                ? saved.ResultsRoot : DefaultRunsRoot;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return DefaultRunsRoot;
        }
    }

    public void SaveResultsRoot(string directory)
    {
        var parent = Path.GetDirectoryName(_file)!;
        Directory.CreateDirectory(parent);
        var temp = Path.Combine(parent, Path.GetRandomFileName());
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(
                new GuiSettings { SchemaVersion = 1, ResultsRoot = directory }, JsonOptions));
            File.Move(temp, _file, true);
        }
        finally
        {
            try { File.Delete(temp); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private sealed class GuiSettings
    {
        public int SchemaVersion { get; set; } = 1;
        public string? ResultsRoot { get; set; }
    }
}
