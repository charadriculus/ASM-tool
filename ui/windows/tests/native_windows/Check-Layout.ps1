[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeLayout {
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter,
    int x, int y, int cx, int cy, uint flags);
}
'@
$bundle=(Resolve-Path $BundlePath).Path
$p=Start-Process -FilePath (Join-Path $bundle 'ASMTool.exe') -WorkingDirectory $bundle -PassThru
try {
    $window=$null
    for($i=0;$i -lt 30;$i++){
        Start-Sleep -Milliseconds 300
        if($p.HasExited){throw "GUI early exit: $($p.ExitCode)"}
        $cond=New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
        $window=[System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,$cond)
        if($window -ne $null){break}
    }
    if($window -eq $null){throw 'GUI window not found'}
    $hwnd=[IntPtr]$window.Current.NativeWindowHandle
    $names=@('DomainInput','ProfileInput','BrowseButton','RunButton','RunProgress')
    $found=@{}
    foreach($name in $names){
        $condition=New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::AutomationIdProperty,$name)
        $found[$name]=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
        if($null -eq $found[$name]){throw "Missing control: $name"}
    }
    foreach($dims in @(@(980,640),@(700,600),@(620,500))){
        $w=$dims[0];$h=$dims[1]
        $null=[NativeLayout]::SetWindowPos($hwnd,[IntPtr]::Zero,0,0,$w,$h,0x0002 -bor 0x0004)
        Start-Sleep -Milliseconds 650
        $wb=$window.Current.BoundingRectangle
        foreach($name in $names){
            $b=$found[$name].Current.BoundingRectangle
            if($b.IsEmpty -or $b.Width -lt 3 -or $b.Height -lt 3){
                throw "Control hidden at width $w : $name"
            }
            if($b.Left -lt $wb.Left-3 -or $b.Right -gt $wb.Right+3 -or
               $b.Top -lt $wb.Top-3 -or $b.Bottom -gt $wb.Bottom+3){
                throw "Control out of window $w x $h : $name"
            }
        }
        Write-Output ("PASS_LAYOUT: "+$w+"x"+$h)
    }
}
finally{
    if(!$p.HasExited){
        $null=$p.CloseMainWindow()
        if(!$p.WaitForExit(5000)){$p.Kill()}
    }
    $p.Dispose()
}
