[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path $BundlePath).Path
$gui = Join-Path $root 'ASMTool.exe'
$core = Join-Path $root 'asm-tool.exe'
if (!(Test-Path $gui) -or !(Test-Path $core) -or !(Test-Path (Join-Path $root 'SHA256SUMS'))) {
    throw 'Incomplete GUI + Go test package.'
}
& $core --version
if ($LASTEXITCODE -ne 0) { throw 'Go executable smoke failed.' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$p = Start-Process -FilePath $gui -WorkingDirectory $root -PassThru
try {
    $window = $null
    for($i=0; $i -lt 25; $i++) {
        Start-Sleep -Milliseconds 350
        if($p.HasExited) { throw "GUI exited with code $($p.ExitCode) before UI Automation." }
        $byProcess = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children, $byProcess)
        if($window -ne $null) { break }
    }
    if($window -eq $null) { throw 'WinUI 3 main window not found via UI Automation.' }
    Write-Output ("GUI_WINDOW: " + $window.Current.Name)
    $all = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition)
    $ids = New-Object 'System.Collections.Generic.HashSet[string]'
    for($i=0; $i -lt $all.Count; $i++) {
        $a = $all.Item($i).Current.AutomationId
        if($a) { $null = $ids.Add($a) }
    }
    foreach($required in @('DomainInput','ProfileInput','RunButton','RunProgress')) {
        if(!$ids.Contains($required)) {
            throw "Expected automation id missing: $required"
        }
    }
    Write-Output ("PASS_GUI_UIA: " + $all.Count + " elements")
}
finally {
    if(!$p.HasExited) {
        $null = $p.CloseMainWindow()
        if(!$p.WaitForExit(5000)) { $p.Kill() }
    }
    $p.Dispose()
}
