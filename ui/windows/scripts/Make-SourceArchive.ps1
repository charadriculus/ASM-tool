[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$dest=Join-Path $OutputDirectory 'ASM_Tool_0.12.3_GUI_source.zip'
if(Test-Path $dest){throw "Refusing to overwrite source archive: $dest"}
$stage=Join-Path $OutputDirectory ('.sources_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    robocopy (Join-Path $root 'ASMTool.Gui') (Join-Path $stage 'ASMTool.Gui') /E /XD bin obj /NFL /NDL /NJH /NJS /NP | Out-Null
    foreach($relative in @('tests\ASMTool.Gui.SelfTests','tests\ASMTool.Gui.IntegrationTests')){
        robocopy (Join-Path $root $relative) (Join-Path $stage $relative) /E /XD bin obj /NFL /NDL /NJH /NJS /NP | Out-Null
    }
    foreach($relative in @('tests\FakeCore\FakeCore.csproj','tests\FakeCore\Program.cs')){
        $target=Join-Path $stage $relative
        New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $target
    }
    Copy-Item -LiteralPath (Join-Path $root 'tests\native_windows') -Destination (Join-Path $stage 'tests\native_windows') -Recurse
    Copy-Item -LiteralPath (Join-Path $root 'scripts') -Destination $stage -Recurse
    foreach($file in @('.gitignore','README_0_12_3_GUI.md','GUI_GO_CONTRACT_0_12_3.md')){
        if(Test-Path (Join-Path $root $file)){
            Copy-Item -LiteralPath (Join-Path $root $file) -Destination $stage
        }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage,$dest,
        [System.IO.Compression.CompressionLevel]::Optimal,$false)
    $hash=(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    Write-Output "SOURCES_ZIP: $dest"
    Write-Output "SOURCES_SHA256: $hash"
}
finally{
    if(Test-Path $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
}
