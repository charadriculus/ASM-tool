[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
$root=(Resolve-Path $BundlePath).Path
$manifest=Join-Path $root 'GUI_DISTRIBUTION_MANIFEST.sha256'
if(!(Test-Path $manifest)){throw 'GUI bundle checksum manifest missing'}
$n=0
foreach($line in [System.IO.File]::ReadLines($manifest)){
    if($line -notmatch '^([0-9a-fA-F]{64})  (.+)$'){throw "Malformed checksum manifest line: $n"}
    $expected=$Matches[1]
    $relative=$Matches[2].Replace('/','\')
    if($relative.StartsWith('..') -or [System.IO.Path]::IsPathRooted($relative)){
        throw "Unsafe manifest relative path: $relative"
    }
    $file=Join-Path $root $relative
    if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing: $relative"}
    $digest=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if($digest -ne $expected){throw "SHA256 mismatch: $relative"}
    $n++
}
if($n -lt 200){throw "Unexpectedly small bundle: $n"}
if((Test-Path (Join-Path $root 'runtime\python.exe')) -or
   (Test-Path (Join-Path $root 'bootstrap.py'))){
    throw 'Python runtime unexpectedly present'
}
Write-Output "PASS_MANIFEST: $n files; no Embedded Python"
