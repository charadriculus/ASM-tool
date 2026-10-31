[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BundlePath,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
$bundle = (Resolve-Path $BundlePath).Path
if(!(Test-Path (Join-Path $bundle 'TEST_FIXTURE_ONLY.txt'))) {
    throw 'Safety gate: refusing to run UI integration without TEST_FIXTURE_ONLY marker.'
}
$expectedHash = ((Get-Content (Join-Path $bundle 'SHA256SUMS') -TotalCount 1).Substring(0,64)).ToUpperInvariant()
$actualHash = (Get-FileHash (Join-Path $bundle 'asm-tool.exe') -Algorithm SHA256).Hash
if($expectedHash -ne $actualHash) { throw 'Safety gate: fixture executable SHA mismatch.' }
$preferences = Join-Path $env:LOCALAPPDATA 'ASM Tool\config\gui-settings.json'
if(Test-Path $preferences) {
    throw 'Safety gate: user GUI preferences exist; do not override or read their settings.'
}
$runsRoot = Join-Path $env:LOCALAPPDATA 'ASM Tool\runs'
$rootWasPresent = Test-Path $runsRoot
$beforePaths = @{}
if($rootWasPresent) {
    Get-ChildItem -LiteralPath $runsRoot -Directory | ForEach-Object {
        $beforePaths[$_.FullName] = $true
    }
}
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
function GetControl($window, [string]$id) {
    $match = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
    $element = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$match)
    if($null -eq $element) { throw "Missing UIAutomation control: $id" }
    return $element
}
$p = Start-Process -FilePath (Join-Path $bundle 'ASMTool.exe') -WorkingDirectory $bundle -PassThru
$results = New-Object System.Collections.Generic.List[object]
try {
    $window=$null
    for($i=0;$i -lt 25;$i++){
        Start-Sleep -Milliseconds 300
        if($p.HasExited){ throw "GUI exited unexpectedly with $($p.ExitCode)" }
        $cond=New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
        $window=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,$cond)
        if($window -ne $null){break}
    }
    if($null -eq $window){ throw 'GUI did not become available' }
    $domain = GetControl $window 'DomainInput'
    $launch = GetControl $window 'RunButton'
    $status = GetControl $window 'StatusText'
    $progress = GetControl $window 'RunProgress'
    $rootControl = GetControl $window 'ResultsRootInput'
    $rootValue = $rootControl.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
    if(![System.IO.Path]::GetFullPath($rootValue).Equals([System.IO.Path]::GetFullPath($runsRoot),
         [System.StringComparison]::OrdinalIgnoreCase)){
        throw 'Safety gate: GUI results path differs from default, refusing launch.'
    }

    foreach($case in @(
        @{ Domain='success.test'; Status='Исследование успешно завершено' },
        @{ Domain='incomplete.test'; Status='Завершено с неполными результатами' },
        @{ Domain='error.test'; Status='Исследование завершилось с ошибкой (код 1)' },
        @{ Domain='interrupted.test'; Status='Исследование остановлено' },
        @{ Domain='invalidstatus.test'; Status='Исследование завершилось с ошибкой (код 1)' }
    )){
        $domain.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($case.Domain)
        $launch.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        $observed = ''
        do {
            Start-Sleep -Milliseconds 250
            if($p.HasExited){ throw 'GUI crashed during synthetic test' }
            $observed = $status.Current.Name
            $runText = $launch.Current.Name
            if($observed -eq $case.Status -and $runText -eq 'Начать исследование') { break }
        } while([DateTime]::UtcNow -lt $deadline)
        if($observed -ne $case.Status -or $runText -ne 'Начать исследование') {
            throw "Wrong GUI status: expected '$($case.Status)', got '$observed', button '$runText'"
        }
        $results.Add([pscustomobject]@{domain=$case.Domain;gui_status=$observed;pass=$true})
        Write-Output "PASS_GUI_ACTION: $($case.Domain) => $observed"
    }
}
finally {
    if($p -and !$p.HasExited) {
        $null=$p.CloseMainWindow()
        if(!$p.WaitForExit(5000)) { $p.Kill() }
    }
    if($p) { $p.Dispose() }
    $created=@()
    if(Test-Path $runsRoot) {
        foreach($dir in Get-ChildItem -LiteralPath $runsRoot -Directory) {
            if($beforePaths.ContainsKey($dir.FullName)) { continue }
            $statusPath=Join-Path $dir.FullName 'run_status.json'
            if(Test-Path $statusPath) {
                try {
                    $text=Get-Content -LiteralPath $statusPath -Raw
                    $parsed=$text|ConvertFrom-Json
                    if($parsed.stage -eq 'synthetic_fixture' -and $parsed.target_domain -eq $null) {
                        # Exact target is stored by FakeCore in worker row and diagnostic log.
                        $created+= $dir.FullName
                    }
                } catch {}
            }
        }
    }
    $results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'ui_fake_core_results.json') -Encoding UTF8
    $created | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'ui_fake_core_run_paths.txt')
    Write-Output ("FIXTURE_RUN_DIRS: "+$created.Count+"; test outputs retained for inspection")
}
