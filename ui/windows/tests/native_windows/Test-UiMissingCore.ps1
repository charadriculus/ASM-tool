[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference='Stop'
$root=(Resolve-Path $BundlePath).Path
if(Test-Path (Join-Path $root 'asm-tool.exe')) {throw 'Safety gate: Core should be absent'}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function FindControl($window,[string]$id) {
    $condition=New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::AutomationIdProperty,$id)
    $e=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
    if(!$e){throw "Missing control: $id"}
    return $e
}
$p=Start-Process (Join-Path $root 'ASMTool.exe') -WorkingDirectory $root -PassThru
try {
    $window=$null
    for($i=0;$i -lt 25;$i++){
      Start-Sleep -Milliseconds 250
      if($p.HasExited){throw 'GUI startup crash'}
      $pc=New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
      $window=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
        [System.Windows.Automation.TreeScope]::Children,$pc)
      if($window){break}
    }
    if(!$window){throw 'GUI window not found'}
    $domain=FindControl $window 'DomainInput'
    $launch=FindControl $window 'RunButton'
    $domain.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue('fixture.test')
    $launch.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $status=FindControl $window 'StatusText'
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    $seen=$false
    do {
      Start-Sleep -Milliseconds 250
      if($p.HasExited){throw 'GUI crashed instead of reporting absent Core'}
      if($status.Current.Name -eq 'Не удалось выполнить исследование'){
        $seen=$true; break
      }
    } while([DateTime]::UtcNow -lt $deadline)
    if(!$seen){throw ("No error status for missing Go Core. Got "+$status.Current.Name)}
    Write-Output 'PASS_GUI_MISSING_CORE: visible error; GUI remains running'
    $found=$false
    $children=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      [System.Windows.Automation.Condition]::TrueCondition)
    for($i=0;$i -lt $children.Count;$i++){
      if($children.Item($i).Current.Name -match 'asm-tool.exe'){
        $found=$true; break
      }
    }
    if(!$found){throw 'Expected explanatory message about missing asm-tool.exe'}
    Write-Output 'PASS_GUI_DIAGNOSTIC: explicit missing executable'
}
finally {
    if($p -and !$p.HasExited){
      $null=$p.CloseMainWindow()
      if(!$p.WaitForExit(4000)){$p.Kill()}
    }
    if($p){$p.Dispose()}
}
