[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference='Stop'
$bundle=(Resolve-Path $BundlePath).Path
if(!(Test-Path (Join-Path $bundle 'TEST_FIXTURE_ONLY.txt'))){throw 'Not a test bundle'}
$fake=[System.IO.Path]::GetFullPath((Join-Path $bundle 'asm-tool.exe'))
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function FindById($window,[string]$id){
  $match=New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty,$id)
  $item=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$match)
  if(!$item){throw "Missing control: $id"}
  return $item
}
$p=Start-Process -FilePath (Join-Path $bundle 'ASMTool.exe') -WorkingDirectory $bundle -PassThru
$childPid=0
try{
  $window=$null
  for($i=0;$i -lt 25;$i++){
    Start-Sleep -Milliseconds 250
    if($p.HasExited){throw 'Test GUI exited before fixture run'}
    $pc=New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
    $window=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
      [System.Windows.Automation.TreeScope]::Children,$pc)
    if($window){break}
  }
  if(!$window){throw 'GUI window absent'}
  $root=FindById $window 'ResultsRootInput'
  $runsRoot=Join-Path $env:LOCALAPPDATA 'ASM Tool\runs'
  $actual=$root.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
  if(![System.IO.Path]::GetFullPath($actual).Equals(
     [System.IO.Path]::GetFullPath($runsRoot),
     [System.StringComparison]::OrdinalIgnoreCase)){throw 'Non-default results directory'}
  (FindById $window 'DomainInput').GetCurrentPattern(
     [System.Windows.Automation.ValuePattern]::Pattern).SetValue('busy.test')
  (FindById $window 'RunButton').GetCurrentPattern(
     [System.Windows.Automation.InvokePattern]::Pattern).Invoke()
  $until=[DateTime]::UtcNow.AddSeconds(6)
  do {
    Start-Sleep -Milliseconds 150
    $matches=Get-CimInstance Win32_Process -Filter ("ParentProcessId="+$p.Id) |
      Where-Object { $_.Name -eq 'asm-tool.exe' -and $_.ExecutablePath -eq $fake }
    if($matches){$childPid=[int]$matches[0].ProcessId; break}
  } while([DateTime]::UtcNow -lt $until)
  if(!$childPid){throw 'Synthetic Go child not found'}
  Write-Output ("CHILD_STARTED: "+$childPid)
  Stop-Process -Id $p.Id -Force -ErrorAction Stop
  $ended=$false
  for($i=0;$i -lt 30;$i++){
    Start-Sleep -Milliseconds 100
    if(!(Get-Process -Id $childPid -ErrorAction SilentlyContinue)){
      $ended=$true; break
    }
  }
  if(!$ended){throw 'KILL_ON_JOB_CLOSE did not terminate synthetic child'}
  Write-Output 'PASS_CRASH_CONTAINMENT: GUI process killed, synthetic Go process exited'
}
finally{
  if($p -and !$p.HasExited){$p.Kill()}
  if($p){$p.Dispose()}
  if($childPid){
    $remaining=Get-CimInstance Win32_Process -Filter ("ProcessId="+$childPid)
    if($remaining -and $remaining.ExecutablePath -eq $fake){
      Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue
    }
  }
}
