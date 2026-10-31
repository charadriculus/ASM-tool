[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms
$root=(Resolve-Path $BundlePath).Path
$p=Start-Process -FilePath (Join-Path $root 'ASMTool.exe') -WorkingDirectory $root -PassThru
function FindById($window,[string]$id) {
    $condition=New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::AutomationIdProperty,$id)
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
}
try{
    $window=$null
    for($i=0;$i -lt 25;$i++){
      Start-Sleep -Milliseconds 220
      if($p.HasExited){ throw "GUI exited early: $($p.ExitCode)" }
      $pc=New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
      $window=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
        [System.Windows.Automation.TreeScope]::Children,$pc)
      if($window){break}
    }
    if(!$window){throw 'GUI window absent'}
    foreach($control in @('DomainInput','ProfileInput','ResultsRootInput',
        'BrowseButton','RunButton','RunProgress','DnsBudgetInput')){
        $element=FindById $window $control
        if(!$element){throw "Missing $control"}
        if([string]::IsNullOrWhiteSpace($element.Current.Name)){
            throw "Missing accessible name: $control"
        }
        Write-Output ("PASS_ACCESSIBLE_NAME: " + $control)
    }
    $domain=FindById $window 'DomainInput'
    $profile=FindById $window 'ProfileInput'
    if(!$domain.Current.IsKeyboardFocusable -or !$profile.Current.IsKeyboardFocusable){
        throw 'Domain/Profile not keyboard focusable'
    }
    $domain.SetFocus()
    Start-Sleep -Milliseconds 200
    $focused=[System.Windows.Automation.AutomationElement]::FocusedElement
    if($focused.Current.AutomationId -ne 'DomainInput'){
        throw "Domain focus not set; current=$($focused.Current.AutomationId)"
    }
    [System.Windows.Forms.SendKeys]::SendWait('{TAB}')
    Start-Sleep -Milliseconds 250
    $focused=[System.Windows.Automation.AutomationElement]::FocusedElement
    if($focused.Current.AutomationId -ne 'ProfileInput'){
        throw "Tab did not reach profile; current=$($focused.Current.AutomationId)"
    }
    Write-Output 'PASS_KEYBOARD: DomainInput -> ProfileInput'
    $progress=FindById $window 'RunProgress'
    if($progress.Current.Name -notmatch 'Прогресс'){
        throw 'Progress bar missing accessible purpose'
    }
    Write-Output ('PASS_ACCESSIBILITY: progress bar "'+$progress.Current.Name+'"')
    Write-Output ('CURRENT_SYSTEM_HIGH_CONTRAST: '+[System.Windows.Forms.SystemInformation]::HighContrast)
    Write-Output ('CURRENT_SYSTEM_DPI: '+[System.Windows.Forms.SystemInformation]::PrimaryMonitorSize)
}
finally{
    if($p -and !$p.HasExited){
        $null=$p.CloseMainWindow()
        if(!$p.WaitForExit(5000)){$p.Kill()}
    }
    if($p){$p.Dispose()}
}
