param(
  [Parameter(Mandatory=$true)][string]$PortableRoot,
  [Parameter(Mandatory=$true)][string]$EvidenceRoot,
  [string]$TestExecutable = (Join-Path $PSScriptRoot 'approved-windows-native.test.exe')
)
$ErrorActionPreference = 'Stop'
$anchor = 'c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479'
$testSHA = '9b32bc75e9b65d6e2384210f36bf133bb751056d0c397734a663b0f1eeaf34d9'
$appSHA = '4e5f35efc9f6dec065a655570ab9c61926e7063a2736365e75078b5483b811e1'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 required' }
$PortableRoot = (Resolve-Path -LiteralPath $PortableRoot).Path
$TestExecutable = (Resolve-Path -LiteralPath $TestExecutable).Path
$payload = Join-Path $PortableRoot 'payload'
$app = Join-Path $PortableRoot 'asm-tool.exe'
foreach ($item in @(@($TestExecutable,$testSHA), @($app,$appSHA), @((Join-Path $payload 'bundle.json'),$anchor))) {
  if ((Get-FileHash -LiteralPath $item[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item[1]) { throw ('SHA mismatch: ' + $item[0]) }
}
if (Test-Path -LiteralPath $EvidenceRoot) { throw 'EvidenceRoot must be new; retain previous results' }
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
$record = [ordered]@{status='RUNNING'; started_utc=[DateTime]::UtcNow.ToString('o'); platform='windows/amd64'; os=[Environment]::OSVersion.VersionString; os_caption=(Get-CimInstance Win32_OperatingSystem).Caption; elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); bundle_sha256=$anchor; executable_sha256=$testSHA; browser='BLOCKED_candidate31_FAIL'; strict_network_gate='NOT_RUN'; kit_version='2'; subfaster_runtime='NOT_RUN_MANIFEST_ONLY'; old_linux_network_gate='FAIL_PRESERVED'; note='Selected harness authenticates Subfaster identity only; it does not start Subfaster. Strict Windows network gate remains NOT_RUN, not inferred from functional success.'; commands=@()}
$exitCode = 1
$names = @('ASM_APPROVED_NATIVE_PAYLOAD','ASM_APPROVED_NATIVE_BUNDLE_SHA256','ASM_APPROVED_NATIVE_EVIDENCE_DIR')
$old = @{}
foreach ($name in $names) { $old[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
function Scoped-Processes {
  $roots=@($PortableRoot.TrimEnd('\')+'\',(Split-Path -Parent $TestExecutable).TrimEnd('\')+'\',$EvidenceRoot.TrimEnd('\')+'\')
  @(Get-CimInstance Win32_Process | Where-Object {
    $path=$_.ExecutablePath
    $path -and @($roots | Where-Object { $path.StartsWith($_,[StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
  } | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath)
}
try {
  if ($record.elevated) { throw 'Standard-user execution required; do not elevate' }
  $record.process_before=@(Scoped-Processes)
  if ($record.process_before.Count -ne 0) { throw 'Existing scoped process; STOP, do not terminate it' }
  $oldPath=$env:PATH
  try {
    $env:PATH=Join-Path $env:SystemRoot 'System32'
    $record.startup_path=$env:PATH
    foreach ($flag in @('--help','--version')) {
    $log=Join-Path $EvidenceRoot ($flag.TrimStart('-')+'.log')
    & $app $flag *> $log
    $code=$LASTEXITCODE
    $record.commands += [ordered]@{executable=$app; arguments=@($flag); exit_code=$code; log_sha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()}
    if ($code -ne 0) { throw ('STOP: CLI '+$flag+' exit '+$code) }
  }
  } finally { $env:PATH=$oldPath }
  $env:ASM_APPROVED_NATIVE_PAYLOAD=$payload
  $env:ASM_APPROVED_NATIVE_BUNDLE_SHA256=$anchor
  $env:ASM_APPROVED_NATIVE_EVIDENCE_DIR=Join-Path $EvidenceRoot 'artifacts'
  $arguments=@('-test.run','^TestApprovedNativePortableQualification$','-test.v','-test.timeout','150s')
  $log=Join-Path $EvidenceRoot 'native-test.log'
  & $TestExecutable @arguments *> $log
  $code=$LASTEXITCODE
  $record.commands += [ordered]@{executable=$TestExecutable; arguments=$arguments; exit_code=$code; log_sha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()}
  if ($code -ne 0) { throw ('STOP: functional test exit '+$code+'; do not rerun automatically') }
  $result=Get-Content -LiteralPath (Join-Path $env:ASM_APPROVED_NATIVE_EVIDENCE_DIR 'qualification-result.json') -Raw | ConvertFrom-Json
  if ($result.status -ne 'PASS') { throw 'STOP: incomplete or failed functional evidence' }
  if ($result.platform -ne 'windows/amd64' -or $result.bundle_sha256 -ne $anchor) { throw 'Unexpected result platform or trust anchor' }
  if ($result.subfaster_probe.status -ne 'MANIFEST_IDENTITY_VERIFIED' -or $result.subfaster_probe.runtime_probe -ne 'NOT_RUN' -or $result.subfaster_probe.observed_version_status -ne 'NOT_RUN' -or $result.subfaster_probe.bundle_sha256 -ne $anchor) { throw 'Wrong harness or false runtime-version evidence' }
  if ($result.native_nmap -ne 'PASS' -or $result.nmap_execution.exit_code -ne 0 -or $result.nmap_execution.timed_out -or -not $result.nmap_execution.artifact_written -or $result.cleanup.http_fixture_server -ne 'PASS') { throw 'Incomplete native tool/cleanup evidence' }
  if ($result.profiles.full.status -ne 'complete' -or $result.profiles.verify.status -ne 'complete' -or $result.profiles.full.nmap_invocations -ne 1 -or $result.profiles.verify.nmap_invocations -ne 0) { throw 'Wrong selected-mode results' }
  $record.process_after=@(Scoped-Processes)
  if ($record.process_after.Count -ne 0) { throw 'Observed scoped survivor; STOP, preserve evidence, do not kill unknown processes' }
  $record.cleanup_scope='NO_OBSERVED_SCOPED_SURVIVORS; sampled census, exhaustive lifetime/cancel qualification NOT_RUN'
  $record.status='PASS_FUNCTIONAL_ONLY'
  $exitCode=0
} catch {
  $record.status='FAIL'
  $record.error=$_.Exception.Message
  try { $record.process_after=@(Scoped-Processes) } catch { $record.process_observation_error=$_.Exception.Message }
  Write-Warning $record.error
} finally {
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$old[$name],'Process') }
  $record.finished_utc=[DateTime]::UtcNow.ToString('o')
  $record.exit_code=$exitCode
  $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'windows-result.json') -Encoding UTF8
}
exit $exitCode
