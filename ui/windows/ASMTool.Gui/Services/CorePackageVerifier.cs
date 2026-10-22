using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ASMTool.Gui.Services;

/// <summary>Checks local bundle integrity. SHA256SUMS is not a cryptographic publisher signature.</summary>
public static class CorePackageVerifier
{
    public static string VerifyExecutable(string bundle)
    {
        var executable = Path.GetFullPath(Path.Combine(bundle, "asm-tool.exe"));
        var manifest = Path.Combine(bundle, "SHA256SUMS");
        if (!File.Exists(executable))
            throw new FileNotFoundException("В комплекте отсутствует Go-ядро asm-tool.exe.");
        if (!File.Exists(manifest))
            throw new FileNotFoundException("В комплекте отсутствует SHA256SUMS для проверки ядра.");
        using var manifestStream = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (manifestStream.Length is < 65 or > 4_194_304)
            throw new InvalidDataException("Неверный размер SHA256SUMS.");
        using var reader = new StreamReader(manifestStream);
        string? expected = null;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length < 66 || !Regex.IsMatch(line[..64], "^[0-9a-fA-F]{64}$"))
                continue;
            var path = line[64..].Trim().TrimStart('*').Replace('\\', '/');
            if (path.StartsWith("./", StringComparison.Ordinal)) path = path[2..];
            if (!path.Equals("asm-tool.exe", StringComparison.OrdinalIgnoreCase))
                continue;
            if (expected is not null) throw new InvalidDataException("Дублирующая запись asm-tool.exe в SHA256SUMS.");
            expected = line[..64];
        }
        if (expected is null)
            throw new InvalidDataException("Отсутствует SHA256 для asm-tool.exe.");
        using var coreStream = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        var digest = Convert.ToHexString(SHA256.HashData(coreStream));
        if (!digest.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Контрольная сумма Go-ядра не совпадает.");
        return executable;
    }
}
