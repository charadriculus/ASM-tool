[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$logs=Join-Path $env:LOCALAPPDATA 'ASM Tool\logs'
$runs=Join-Path $env:LOCALAPPDATA 'ASM Tool\runs'
$prefix=[System.IO.Path]::GetFullPath($runs).TrimEnd('\')+'\'
$allowed=@('success.test','success2.test','incomplete.test',
    'error.test','interrupted.test','invalidstatus.test','busy.test')
$deletedLogs=0;$deletedRuns=0
$index=New-Object System.Collections.Generic.List[object]
if(Test-Path $logs){
  foreach($log in Get-ChildItem -LiteralPath $logs -File -Filter 'gui_*.log'){
    $first=Get-Content -LiteralPath $log.FullName -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue
    if(!$first -or !$first.StartsWith('FAKE_CORE_ARGS:')){continue}
    $argv=$first.Substring('FAKE_CORE_ARGS:'.Length).Split('|')
    $di=[Array]::IndexOf($argv,'--domain')
    $oi=[Array]::IndexOf($argv,'--output-dir')
    if($di -lt 0 -or $di+1 -ge $argv.Length -or
       $oi -lt 0 -or $oi+1 -ge $argv.Length){continue}
    $domain=$argv[$di+1]
    $output=$argv[$oi+1]
    if($allowed -cnotcontains $domain){continue}
    $record=[ordered]@{domain=$domain;log=$log.Name;result_deleted=$false}
    $absolute=[System.IO.Path]::GetFullPath($output)
    if($absolute.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and
       [System.IO.Path]::GetFileName($absolute).StartsWith('scan_') -and
       (Test-Path -LiteralPath $absolute -PathType Container)){
      $items=@(Get-ChildItem -LiteralPath $absolute -Force)
      $unexpected=@($items | Where-Object {
          $_.PSIsContainer -or $_.Name -notin @('run_status.json','run_summary.json')
      })
      if($unexpected.Count -eq 0){
        Remove-Item -LiteralPath $absolute -Recurse -Force
        $deletedRuns++
        $record.result_deleted=$true
      }
    }
    $index.Add([pscustomobject]$record)
    Remove-Item -LiteralPath $log.FullName -Force
    $deletedLogs++
  }
}
$index | ConvertTo-Json -Depth 4 |
  Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'fixture_cleanup_index.json') -Encoding UTF8
Write-Output ("CLEANUP_FIXTURE_LOGS="+$deletedLogs+"; CLEANUP_FIXTURE_RUNS="+$deletedRuns)
