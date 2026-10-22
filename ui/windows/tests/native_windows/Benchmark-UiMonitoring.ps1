[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BundlePath,
  [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'
$bundle=(Resolve-Path $BundlePath).Path
if(!(Test-Path (Join-Path $bundle 'TEST_FIXTURE_ONLY.txt'))){throw 'Refuse non-fixture binary'}
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function FindById($window,[string]$id) {
  $condition=New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
  $e=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
  if(!$e){throw "Missing automation element: $id"}
  return $e
}
$p=Start-Process -FilePath (Join-Path $bundle 'ASMTool.exe') -WorkingDirectory $bundle -PassThru
$samples=New-Object System.Collections.Generic.List[object]
try {
  $win=$null
  for($i=0;$i -lt 25;$i++) {
    Start-Sleep -Milliseconds 250
    if($p.HasExited){throw 'GUI startup crash'}
    $pc=New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
    $win=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
      [System.Windows.Automation.TreeScope]::Children,$pc)
    if($win){break}
  }
  if(!$win){throw 'GUI main window not found'}
  $domain=FindById $win 'DomainInput'
  $launch=FindById $win 'RunButton'
  $status=FindById $win 'StatusText'
  $resources=FindById $win 'ResourcesText'
  $progress=FindById $win 'ProgressLabel'
  $root=FindById $win 'ResultsRootInput'
  $expected=Join-Path $env:LOCALAPPDATA 'ASM Tool\runs'
  $actual=$root.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
  if(![System.IO.Path]::GetFullPath($actual).Equals(
     [System.IO.Path]::GetFullPath($expected),
     [System.StringComparison]::OrdinalIgnoreCase)) {throw 'Refusing to use non-default results root'}
  $domain.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue('busy.test')
  $launch.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
  $oldCpu=$p.TotalProcessorTime
  $oldClock=[DateTime]::UtcNow
  for($i=0;$i -lt 26;$i++) {
    Start-Sleep -Milliseconds 400
    if($p.HasExited){throw 'GUI crashed while monitoring'}
    $p.Refresh()
    $time=[DateTime]::UtcNow
    $duration=($time-$oldClock).TotalSeconds
    $cpu=if($duration -gt 0){($p.TotalProcessorTime-$oldCpu).TotalSeconds/$duration/[Environment]::ProcessorCount*100}else{0}
    $oldCpu=$p.TotalProcessorTime
    $oldClock=$time
    $samples.Add([pscustomobject]@{
      at=$time.ToString('o')
      gui_cpu_percent=[Math]::Round($cpu,3)
      gui_working_set_bytes=$p.WorkingSet64
      gui_status=$status.Current.Name
      progress=$progress.Current.Name
      resources=$resources.Current.Name
    })
  }
  $valid=$samples | Where-Object {$_.resources -match 'RAM'}
  if($valid.Count -lt 5) {throw 'No valid resource line during active fake run'}
  $max=($samples|Measure-Object -Property gui_cpu_percent -Maximum).Maximum
  $mean=($samples|Measure-Object -Property gui_cpu_percent -Average).Average
  $ramPeak=($samples|Measure-Object -Property gui_working_set_bytes -Maximum).Maximum
  $changed=@($samples | Select-Object -ExpandProperty progress -Unique)
  if($changed.Count -lt 2){throw 'Progress never changed'}
  $samples | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'ui_resource_samples.json') -Encoding UTF8
  Write-Output ("PASS_MONITOR: samples="+$samples.Count+" changed_progress="+$changed.Count)
  Write-Output ("GUI_CPU_MEAN="+([Math]::Round($mean,3))+"%; GUI_CPU_PEAK="+([Math]::Round($max,3))+"%")
  Write-Output ("GUI_RAM_PEAK_MiB="+([Math]::Round($ramPeak/1MB,1)))
}
finally {
  if($p -and !$p.HasExited) {
    $null=$p.CloseMainWindow()
    if(!$p.WaitForExit(1500)) { $p.Kill() }
  }
  if($p){$p.Dispose()}
}
