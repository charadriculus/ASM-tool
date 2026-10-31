# Builds a local ASM Tool 0.12.3 Windows owner-trial candidate. Does not publish a release.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$GoBundlePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$DotNet = ''
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$DotNet) { $DotNet = Join-Path $root '.toolchain\dotnet\dotnet.exe' }
$bundle = (Resolve-Path $GoBundlePath).Path
$core = Join-Path $bundle 'asm-tool.exe'
$sums = Join-Path $bundle 'SHA256SUMS'
$payload = Join-Path $bundle 'payload'
if (!(Test-Path -LiteralPath $core -PathType Leaf) -or
    !(Test-Path -LiteralPath $sums -PathType Leaf) -or
    !(Test-Path -LiteralPath $payload -PathType Container)) {
    throw 'The Go candidate bundle is missing asm-tool.exe, SHA256SUMS or payload/'
}
if (!(Test-Path -LiteralPath $DotNet -PathType Leaf)) {
    throw "A local .NET 10 SDK is required at: $DotNet"
}
$entry = @(Get-Content -LiteralPath $sums | Where-Object {
    $_ -match '^[a-fA-F0-9]{64}\s+\*?(\./)?asm-tool\.exe$'
})
if ($entry.Count -ne 1) { throw 'Expected exactly one SHA256SUMS entry for asm-tool.exe.' }
$expected = $entry[0].Substring(0,64)
$actual = (Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash
if ($expected -ne $actual) { throw 'Go executable does not match the candidate SHA256SUMS.' }

# Verify every portable file before copying any payload into the GUI candidate.
# The input manifest is the allow-list: paths must be relative, unique, complete,
# and free of reparse points at every component. Unlisted input files are rejected.
$checked = 0
$seen = @{}
$verifiedFiles = [System.Collections.Generic.List[object]]::new()
$bundlePrefix = [System.IO.Path]::GetFullPath($bundle).TrimEnd('\') + '\'
if ((Get-Item -LiteralPath $bundle -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Go bundle root cannot be a reparse point.'
}
foreach ($line in [System.IO.File]::ReadLines($sums)) {
    if ($line -notmatch '^([a-fA-F0-9]{64})  (.+)$') {
        throw "Unexpected Go SHA256SUMS entry at line $($checked + 1)"
    }
    $recordedHash = $Matches[1]
    $relativeUnix = $Matches[2].TrimStart('*').Replace('\', '/')
    if ($relativeUnix.StartsWith('./', [StringComparison]::Ordinal)) {
        $relativeUnix = $relativeUnix.Substring(2)
    }
    $segments = $relativeUnix.Split([char]'/')
    $invalidSegments = @($segments | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })
    $invalidWindowsSegments = @($segments | Where-Object { $_ -match '[ .]$' })
    if ($relativeUnix.Length -eq 0 -or $invalidSegments.Count -gt 0) {
        throw "Unsafe Go SHA256SUMS path: $relativeUnix"
    }
    $relative = $relativeUnix.Replace('/', '\')
    if ([System.IO.Path]::IsPathRooted($relative) -or
        $relative -match '^[a-zA-Z]:' -or $relative.Contains(':') -or
        $invalidWindowsSegments.Count -gt 0) {
        throw "Unsafe Go SHA256SUMS path: $relative"
    }
    $full = [System.IO.Path]::GetFullPath((Join-Path $bundle $relative))
    if (!$full.StartsWith($bundlePrefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Go manifest escaped the bundle: $relative"
    }
    if ($seen.ContainsKey($relativeUnix)) { throw "Duplicate Go manifest entry: $relativeUnix" }
    $seen[$relativeUnix] = $true
    if (!(Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Missing Go candidate payload file: $relativeUnix"
    }
    $cursor = $bundle
    foreach ($segment in $segments) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -LiteralPath $cursor -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Go manifest path contains a reparse point: $relativeUnix"
        }
    }
    if ($relativeUnix -match '(?i)(^|/)(nmap(?:\.exe|-scripts|-services|-protocols|-service-probes|-os-db|-payloads|-rpc|-mac-prefixes)?)(/|$)' -or
        $relativeUnix -match '(?i)(^|/)(python(?:-embed|-runtime)?)(/|$)|(^|/)(pythonw?\d*(?:\.exe|\.dll)?|pyvenv\.cfg|bootstrap\.py)$|(^|/)site-packages(/|$)') {
        throw "Forbidden Nmap or legacy Python runtime component in Go bundle: $relativeUnix"
    }
    $digest = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    if ($digest -ne $recordedHash) {
        throw "Go payload integrity mismatch: $relativeUnix"
    }
    $verifiedFiles.Add([pscustomobject]@{
        RelativePath = $relativeUnix; FullPath = $full; Hash = $recordedHash
    })
    $checked++
}
if ($checked -lt 10) { throw 'Unexpectedly small Go manifest.' }

# SHA256SUMS itself is the only unlisted root file. Reject loose/unmanifested
# files so the copied GUI bundle has a reviewable integrity boundary.
foreach ($item in Get-ChildItem -LiteralPath $bundle -File -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Go bundle contains an untrusted reparse file: $($item.FullName)"
    }
    $relativeUnix = $item.FullName.Substring($bundlePrefix.Length).Replace('\', '/')
    if ($relativeUnix -eq 'SHA256SUMS') { continue }
    if (!$seen.ContainsKey($relativeUnix)) { throw "Unmanifested Go bundle file: $relativeUnix" }
}
foreach ($item in Get-ChildItem -LiteralPath $bundle -Directory -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Go bundle contains a reparse directory: $($item.FullName)"
    }
}

# This authenticated, local-only invocation confirms the core version without
# starting a scan or contacting any target.
$versionInfo = [System.Diagnostics.ProcessStartInfo]::new()
$versionInfo.FileName = $core
$versionInfo.WorkingDirectory = $bundle
$versionInfo.Arguments = '--version'
$versionInfo.UseShellExecute = $false
$versionInfo.CreateNoWindow = $true
$versionInfo.RedirectStandardOutput = $true
$versionInfo.RedirectStandardError = $true
$versionProcess = [System.Diagnostics.Process]::new()
$versionProcess.StartInfo = $versionInfo
try {
    if (!$versionProcess.Start()) { throw 'Unable to execute hash-verified Go candidate.' }
    $versionOut = $versionProcess.StandardOutput.ReadToEndAsync()
    $versionErr = $versionProcess.StandardError.ReadToEndAsync()
    if (!$versionProcess.WaitForExit(8000)) {
        try { $versionProcess.Kill() } catch { }
        throw 'Hash-verified Go --version timed out.'
    }
    if ($versionProcess.ExitCode -ne 0 -or $versionOut.Result.Trim() -notmatch '^0\.12\.3-go(?:\s|$)') {
        throw "Expected Go candidate version 0.12.3-go; output='$($versionOut.Result.Trim())' stderr='$($versionErr.Result.Trim())'"
    }
}
finally { $versionProcess.Dispose() }
Write-Output "GO_FILES_VERIFIED: $checked"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$dest = Join-Path $OutputDirectory 'ASM_Tool_0.12.3-portable-Windows-x64.zip'
if (Test-Path $dest) { throw "Refusing to overwrite: $dest" }
$stage = Join-Path $OutputDirectory ('.stage_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    & $DotNet publish (Join-Path $root 'ASMTool.Gui\ASMTool.Gui.csproj') -c Release -r win-x64 -p:Platform=x64 --self-contained true --nologo -o $stage
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($LASTEXITCODE)" }
    foreach ($verified in $verifiedFiles) {
        $destination = Join-Path $stage ($verified.RelativePath.Replace('/', '\'))
        if (Test-Path -LiteralPath $destination) {
            throw "Go candidate file collides with a GUI publish output: $($verified.RelativePath)"
        }
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
        Copy-Item -LiteralPath $verified.FullPath -Destination $destination
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $verified.Hash) {
            throw "Go candidate file changed while being copied: $($verified.RelativePath)"
        }
    }
    $destinationSums = Join-Path $stage 'SHA256SUMS'
    if (Test-Path -LiteralPath $destinationSums) {
        throw 'Go SHA256SUMS collides with a GUI publish output.'
    }
    Copy-Item -LiteralPath $sums -Destination $destinationSums
    $notice = @'
ASM Tool 0.12.3 GUI — local owner-trial candidate
The application launches a verified Go executable. Cooperative stop support
is NOT implemented; only confirmed force termination is available.
Browser execution is available but NOT_SECURITY_QUALIFIED. The historical
candidate31 network-security test was FAIL; do not infer that this is fixed.
No Nmap payload is included. Public redistribution rights for components
marked LICENSING_NOT_CLEARED in the accompanying reports are unconfirmed.
'@
    [System.IO.File]::WriteAllText((Join-Path $stage 'GUI_DEVELOPMENT_NOTICE.txt'), $notice)
    $stageFull = [System.IO.Path]::GetFullPath($stage)
    $lines = Get-ChildItem -LiteralPath $stageFull -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = [System.IO.Path]::GetRelativePath($stageFull, $_.FullName).Replace('\','/')
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $rel
    }
    [System.IO.File]::WriteAllLines((Join-Path $stage 'GUI_DISTRIBUTION_MANIFEST.sha256'), $lines)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $dest,
        [System.IO.Compression.CompressionLevel]::Optimal, $false)
    $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    Write-Output "DEVELOPMENT_BUNDLE: $dest"
    Write-Output "SHA256: $hash"
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Force -Recurse
    }
}
