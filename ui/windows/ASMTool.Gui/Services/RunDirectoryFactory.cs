namespace ASMTool.Gui.Services;

/// <summary>Allocate a fresh path. Only Go Core creates the actual run directory.</summary>
public static class RunDirectoryFactory
{
    public static string Propose(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Каталог результатов не указан.");
        var resolved = Path.GetFullPath(root);
        Directory.CreateDirectory(resolved);
        RejectReparsePoints(resolved);
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var name = "scan_" + DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss")
                + "_" + Guid.NewGuid().ToString("N")[..12];
            var child = Path.Combine(resolved, name);
            if (!Directory.Exists(child) && !File.Exists(child))
                return child;
        }
        throw new IOException("Не удалось подобрать уникальный каталог исследования.");
    }

    private static void RejectReparsePoints(string path)
    {
        for (DirectoryInfo? dir = new(path); dir is not null; dir = dir.Parent)
            if (dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Каталог результатов не должен проходить через точку перенаправления.");
    }
}
