param(
  [Parameter(Mandatory=$true)][string]$PortableRoot,
  [Parameter(Mandatory=$true)][string]$EvidenceRoot,
  [string]$TestExecutable = (Join-Path $PSScriptRoot 'approved-windows-native.test.exe')
)
$ErrorActionPreference = 'Stop'
$anchor = 'c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479'
$testSHA = 'ba000ce695c8f852169bf62e5c1fd531a6dab6eacf7be148de64cca546203cbd'
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
$record = [ordered]@{status='RUNNING'; started_utc=[DateTime]::UtcNow.ToString('o'); platform='windows/amd64'; os=[Environment]::OSVersion.VersionString; os_caption=(Get-CimInstance Win32_OperatingSystem).Caption; elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); bundle_sha256=$anchor; executable_sha256=$testSHA; browser='BLOCKED_candidate31_FAIL'; strict_network_gate='NOT_RUN'; note='Subfaster version init has a known failed UDP route probe on Linux. This test is not a zero-connect gate or release acceptance.'; commands=@()}
$exitCode = 1
$names = @('ASM_APPROVED_NATIVE_PAYLOAD','ASM_APPROVED_NATIVE_BUNDLE_SHA256','ASM_APPROVED_NATIVE_EVIDENCE_DIR')
$old = @{}
foreach ($name in $names) { $old[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
try {
  foreach ($flag in @('--help','--version')) {
    $log=Join-Path $EvidenceRoot ($flag.TrimStart('-')+'.log')
    & $app $flag *> $log
    $code=$LASTEXITCODE
    $record.commands += [ordered]@{executable=$app; arguments=@($flag); exit_code=$code; log_sha256=(Get-FileHash $log -Algorithm SHA256).Hash.ToLowerInvariant()}
    if ($code -ne 0) { throw ('STOP: CLI '+$flag+' exit '+$code) }
  }
  $env:ASM_APPROVED_NATIVE_PAYLOAD=$payload
  $env:ASM_APPROVED_NATIVE_BUNDLE_SHA256=$anchor
  $env:ASM_APPROVED_NATIVE_EVIDENCE_DIR=Join-Path $EvidenceRoot 'artifacts'
  $arguments=@('-test.run','^TestApprovedNativePortableQualification$','-test.v','-test.timeout','150s')
  $log=Join-Path $EvidenceRoot 'native-test.log'
  & $TestExecutable @arguments *> $log
  $code=$LASTEXITCODE
  $record.commands += [ordered]@{executable=$TestExecutable; arguments=$arguments; exit_code=$code; log_sha256=(Get-FileHash $log -Algorithm SHA256).Hash.ToLowerInvariant()}
  if ($code -ne 0) { throw ('STOP: functional test exit '+$code+'; do not rerun automatically') }
  $result=Get-Content -LiteralPath (Join-Path $env:ASM_APPROVED_NATIVE_EVIDENCE_DIR 'qualification-result.json') -Raw | ConvertFrom-Json
  if ($result.status -ne 'PASS') { throw 'STOP: incomplete or failed functional evidence' }
  $record.status='PASS_FUNCTIONAL_ONLY'
  $exitCode=0
} catch {
  $record.status='FAIL'
  $record.error=$_.Exception.Message
  Write-Warning $record.error
} finally {
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$old[$name],'Process') }
  $record.finished_utc=[DateTime]::UtcNow.ToString('o')
  $record.exit_code=$exitCode
  $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'windows-result.json') -Encoding UTF8
}
exit $exitCode
