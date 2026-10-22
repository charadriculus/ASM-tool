# Preparation only: hashes, file/PE headers and local OS metadata. No EXE launch.
param(
  [Parameter(Mandatory=$true)][string]$PortableRoot,
  [Parameter(Mandatory=$true)][string]$CheckRoot,
  [Parameter(Mandatory=$true)][string]$EvidenceRoot
)
$ErrorActionPreference='Stop'
foreach ($path in @($PortableRoot,$CheckRoot,$EvidenceRoot)) {
  if ($path -notmatch '^[A-Za-z]:[\\/]') { throw 'Use absolute local paths, not UNC or relative paths' }
  $drive=New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($path))
  if ($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)) { throw 'Use a local fixed/removable drive, not a mapped network drive' }
}
function Reject-ReparseAncestors([string]$path) {
  $item=Get-Item -LiteralPath $path -Force
  while ($null -ne $item) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse path: '+$item.FullName) }
    if ($item -is [IO.FileInfo]) { $item=$item.Directory } else { $item=$item.Parent }
  }
}
function File-SHA([string]$path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function PE-Machine([string]$path) {
  $b=[IO.File]::ReadAllBytes($path)
  if ($b.Length -lt 64 -or $b[0] -ne 77 -or $b[1] -ne 90) { throw ('Invalid MZ: '+$path) }
  $offset=[BitConverter]::ToUInt32($b,60)
  if ($offset -gt ($b.Length-6) -or [BitConverter]::ToUInt32($b,$offset) -ne 17744) { throw ('Invalid PE: '+$path) }
  return [BitConverter]::ToUInt16($b,$offset+4)
}
$PortableRoot=(Resolve-Path -LiteralPath $PortableRoot).Path
$CheckRoot=(Resolve-Path -LiteralPath $CheckRoot).Path
Reject-ReparseAncestors $PortableRoot
Reject-ReparseAncestors $CheckRoot
$EvidenceRoot=[IO.Path]::GetFullPath($EvidenceRoot)
if (Test-Path -LiteralPath $EvidenceRoot) { throw 'EvidenceRoot must be fresh; retain previous evidence' }
$parent=Split-Path -Parent $EvidenceRoot
Reject-ReparseAncestors $parent
New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
$record=[ordered]@{status='RUNNING'; native_execution='NOT_RUN'; windows11='NOT_RUN_SEPARATE'; old_linux_gate='FAIL_PRESERVED'; browser='BLOCKED_candidate31'; commands_executed=@(); checked_files=@(); started_utc=[DateTime]::UtcNow.ToString('o')}
$exitCode=1
try {
  $os=Get-CimInstance Win32_OperatingSystem
  $record.os_caption=$os.Caption
  $record.os_build=$os.BuildNumber
  $record.machine=$env:COMPUTERNAME
  $record.elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not [Environment]::Is64BitOperatingSystem -or [int]$os.BuildNumber -lt 19041 -or [int]$os.BuildNumber -gt 19045 -or $os.Caption -notmatch 'Windows 10') { throw 'This preparation profile requires Windows10 x64 build19041-19045; Windows11 is separate' }
  if ($record.elevated) { throw 'Run as standard user; elevation does not qualify this scenario' }
  if (-not $PortableRoot.Contains(' ') -or $PortableRoot -notmatch '[^\x00-\x7f]') { throw 'PortableRoot must exercise both spaces and Unicode' }
  $fixed=@{
    (Join-Path $PortableRoot 'asm-tool.exe')='4e5f35efc9f6dec065a655570ab9c61926e7063a2736365e75078b5483b811e1'
    (Join-Path $PortableRoot 'payload\bundle.json')='c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479'
    (Join-Path $CheckRoot 'approved-windows-native.test.exe')='9b32bc75e9b65d6e2384210f36bf133bb751056d0c397734a663b0f1eeaf34d9'
    (Join-Path $CheckRoot 'windows-local-check-v2.ps1')='2b735de8a81c34dfdf1a96a7899fc0cc0fb2ccd74fd7c55fd20b0ea3fc85d08b'
  }
  foreach ($path in $fixed.Keys) {
    Reject-ReparseAncestors $path
    if ((File-SHA $path) -ne $fixed[$path]) { throw ('SHA mismatch: '+$path) }
    $record.checked_files+=@{path=$path;sha256=$fixed[$path]}
  }
  $payload=Join-Path $PortableRoot 'payload'
  Reject-ReparseAncestors $payload
  $manifest=Get-Content -LiteralPath (Join-Path $payload 'bundle.json') -Raw | ConvertFrom-Json
  $expected=@{}
  foreach ($file in $manifest.files) { $expected[$file.path.Replace('/','\')]=$file.sha256 }
  $seen=@{}
  $directories=New-Object 'Collections.Generic.Queue[string]'
  $directories.Enqueue($payload)
  while ($directories.Count -gt 0) {
    foreach ($item in Get-ChildItem -LiteralPath $directories.Dequeue() -Force) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse member: '+$item.FullName) }
      if ($item.PSIsContainer) { $directories.Enqueue($item.FullName);continue }
      $rel=$item.FullName.Substring($payload.Length+1)
      if ($rel -eq 'bundle.json') { continue }
      if (-not $expected.ContainsKey($rel) -or (File-SHA $item.FullName) -ne $expected[$rel]) { throw ('Unexpected/corrupt payload member: '+$rel) }
      $seen[$rel]=$true
    }
  }
  if ($seen.Count -ne $expected.Count) { throw 'Incomplete payload tree' }
  $record.payload_members_verified=$seen.Count
  $toolPaths=@{nmap=(Join-Path $payload 'bin\nmap\nmap.exe');typst=(Join-Path $payload 'bin\typst.exe');subfaster=(Join-Path $payload 'bin\subfaster.exe')}
  if ((PE-Machine $toolPaths.nmap) -ne 332 -or (PE-Machine $toolPaths.typst) -ne 34404 -or (PE-Machine $toolPaths.subfaster) -ne 34404) { throw 'Unexpected Nmap x86 / Typst+Subfaster x64 architecture' }
  $record.pe=@{nmap='x86_0x14c_WOW64_RUNTIME_NOT_RUN';typst='x64_0x8664';subfaster='x64_0x8664'}
  $record.wow64_system_files_present=(Test-Path -LiteralPath (Join-Path $env:SystemRoot 'SysWOW64\kernel32.dll')) -and (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'SysWOW64\ntdll.dll'))
  if (-not $record.wow64_system_files_present) { throw 'WOW64 system files unavailable' }
  $record.process_baseline=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath.StartsWith($PortableRoot,[StringComparison]::OrdinalIgnoreCase) -or $_.ExecutablePath.StartsWith($CheckRoot,[StringComparison]::OrdinalIgnoreCase)) } | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath)
  if ($record.process_baseline.Count -ne 0) { throw 'Existing process uses prepared roots; STOP, do not terminate it' }
  $record.test_exe='V2 selected harness: manifest-only Subfaster identity, no Subfaster invocation'
  $record.strict_network_gate='NOT_RUN; absence of all external attempts requires independent native evidence'
  $record.status='READY_STATIC_ONLY_AWAITING_NATIVE_AUTHORIZATION'
  $exitCode=0
} catch {
  $record.status='FAIL_PREPARATION'
  $record.error=$_.Exception.Message
  Write-Warning $record.error
} finally {
  $record.finished_utc=[DateTime]::UtcNow.ToString('o')
  $record.exit_code=$exitCode
  $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'windows10-preflight.json') -Encoding UTF8
}
exit $exitCode
