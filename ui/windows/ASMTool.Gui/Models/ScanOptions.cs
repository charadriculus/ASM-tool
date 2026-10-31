using System.Globalization;
using System.Text.RegularExpressions;

namespace ASMTool.Gui.Models;

public enum ScanProfile { Passive, Verify, Full }

/// <summary>Validated GUI input for the ASM Tool 0.12.3 Go CLI.</summary>
public sealed record ScanOptions(
    string Target,
    ScanProfile Profile,
    string OutputDirectory,
    int DnsBudget,
    string PassiveSources,
    string ReportLanguage,
    bool FullReport,
    bool PrimaryDomainOnly,
    bool IncludeWildcardAmbiguous,
    string? Ports,
    bool AllowHttpFallback,
    bool DisableBrowser)
{
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Target)) return "Укажите домен.";
        if (Target.Length > 1024 || Target.Any(char.IsControl) || Target.Any(char.IsWhiteSpace)
            || Target.StartsWith("-", StringComparison.Ordinal))
            return "Недопустимое значение домена.";
        string candidate;
        try
        {
            var supplied = Target.Contains("://", StringComparison.Ordinal)
                ? Target : "https://" + Target;
            if (!Uri.TryCreate(supplied, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment) || uri.AbsolutePath != "/")
                return "Укажите только домен, без пути и параметров.";
            // A target port is not a CLI domain; require a bare host even for URLs.
            var authority = Target.Contains("://", StringComparison.Ordinal)
                ? Target[(Target.IndexOf("://", StringComparison.Ordinal) + 3)..]
                : Target;
            authority = authority.TrimEnd('/');
            if (authority.Contains(':'))
                return "В поле домена нельзя указывать порт.";
            candidate = uri.IdnHost;
        }
        catch (UriFormatException) { return "Недопустимое значение домена."; }
        if (candidate.Length is < 1 or > 253 ||
            candidate.Split('.').Any(l => l.Length is < 1 or > 63 ||
                !Regex.IsMatch(l, @"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$", RegexOptions.CultureInvariant)))
            return "Недопустимое значение домена.";

        if (DnsBudget is < 1 or > 1_000_000)
            return "Лимит DNS-кандидатов должен быть от 1 до 1 000 000.";
        if (PassiveSources is not ("standard" or "deep"))
            return "Недопустимый профиль пассивных источников.";
        if (ReportLanguage is not ("ru" or "en"))
            return "Недопустимый язык отчёта.";
        if (string.IsNullOrWhiteSpace(OutputDirectory))
            return "Укажите каталог результатов.";
        if (Profile == ScanProfile.Passive && (PrimaryDomainOnly || IncludeWildcardAmbiguous ||
            !string.IsNullOrWhiteSpace(Ports) || AllowHttpFallback))
            return "Для Passive недопустимы параметры активных проверок.";
        if (Profile != ScanProfile.Full && !string.IsNullOrWhiteSpace(Ports))
            return "Настройка портов доступна только в режиме Full.";
        if (Profile == ScanProfile.Full && !string.IsNullOrWhiteSpace(Ports))
        {
            foreach (var part in Ports.Split(new[] { ',', ';' }, StringSplitOptions.None))
            {
                var token = part.Trim();
                if (token.Length == 0 ||
                    !int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
                    port is < 1 or > 65535)
                    return "Порты: укажите номера от 1 до 65535 через запятую.";
            }
        }
        return null;
    }

    public IReadOnlyList<string> ToCoreArguments(bool authorized)
    {
        var error = Validate();
        if (error is not null) throw new ArgumentException(error);
        if (Profile != ScanProfile.Passive && !authorized)
            throw new InvalidOperationException("Для активного профиля необходимо подтверждение авторизации.");

        var argv = new List<string>
        {
            "start", "--domain", Target.Trim(),
            "--profile", Profile switch { ScanProfile.Passive => "passive",
                ScanProfile.Verify => "verify", _ => "full" },
            "--non-interactive", "--output-dir", OutputDirectory,
            "--dns-budget", DnsBudget.ToString(CultureInfo.InvariantCulture),
            "--passive-sources", PassiveSources,
            "--language", ReportLanguage
        };
        if (Profile != ScanProfile.Passive) argv.Add("--confirm-authorization");
        if (FullReport) argv.Add("--full-report");
        if (Profile != ScanProfile.Passive)
        {
            if (PrimaryDomainOnly) argv.Add("--primary-domain-only");
            if (IncludeWildcardAmbiguous) argv.Add("--include-wildcard-ambiguous");
            if (AllowHttpFallback) argv.Add("--allow-http-fallback");
            if (DisableBrowser) { argv.Add("--browser"); argv.Add("disabled"); }
        }
        if (Profile == ScanProfile.Full)
        {
            if (!string.IsNullOrWhiteSpace(Ports))
            {
                argv.Add("--ports");
                argv.Add(string.Join(",", Ports.Split(new[] { ',', ';' },
                    StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim())));
            }
        }
        return argv;
    }
}
