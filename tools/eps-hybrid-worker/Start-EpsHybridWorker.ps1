#Requires -Version 7.2
<#
.SYNOPSIS
    One Entra Policy Suite hybrid worker cycle - what the scheduled task 'EntraPolicySuite Hybrid Worker' runs every 5
    minutes, AS THE gMSA, on the domain-joined worker (DESIGN §6).
.DESCRIPTION
    Reads <Root>\worker.json (written by Install-EpsHybridWorker.ps1), signs in to SQL with the MACHINE's managed identity
    (an Azure VM: IMDS; an Azure Arc-enabled server: the Arc agent), heartbeats, refreshes the AD groups the tagging job
    asked for, and applies the queued AD tag changes - each written, read back and recorded on its change. Nothing
    inbound, no password, no module: AD through .NET System.DirectoryServices. Refuses to run as SYSTEM.
    Log: <Root>\logs\worker-<yyyyMMdd>.log (kept 30 days). Exit 0 = the cycle ran, 1 = it failed, 2 = misconfigured.
.LINK
    https://invardia.com/docs/eps/scripts/Install-EpsHybridWorker
#>
[CmdletBinding()] param([string]$Root = 'C:\EntraPolicySuite', [switch]$Once)
$ErrorActionPreference = 'Stop'
$app = Join-Path $Root 'app'
foreach ($f in 'EPS-SqlStore', 'EPS-AdDirectory', 'EPS-HybridWorker') { . (Join-Path $app "engine\_shared\$f.ps1") }
$logDir = Join-Path $Root 'logs'; New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir "worker-$([datetime]::UtcNow.ToString('yyyyMMdd')).log"
function Say($m) { $l = "[$([datetime]::UtcNow.ToString('u'))] $m"; Add-Content -LiteralPath $log -Value $l; Write-Host $l }
Get-ChildItem -LiteralPath $logDir -Filter 'worker-*.log' | Where-Object LastWriteTimeUtc -lt ([datetime]::UtcNow.AddDays(-30)) | Remove-Item -ErrorAction SilentlyContinue

$cfgFile = Join-Path $Root 'worker.json'
if (-not (Test-Path -LiteralPath $cfgFile)) { Say "no $cfgFile - run Install-EpsHybridWorker.ps1"; exit 2 }
$cfg = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
try { $runAs = Assert-EpsAdWriter } catch { Say "$($_.Exception.Message)"; exit 2 }
if ($cfg.ManagedIdentityClientId) { $env:EPS_ManagedIdentityClientId = $cfg.ManagedIdentityClientId }
$version = (Get-Content -LiteralPath (Join-Path $app 'VERSION') -Raw).Trim()
try {
    $ad = New-EpsAdDirectory -Server $cfg.AdServer
    $r = Invoke-EpsHybridWorkerCycle -ConnectionString $cfg.ConnectionString -Ad $ad -WorkerName $cfg.WorkerName -RunAs $runAs -Version $version
    Say "cycle as $runAs`: groups $($r.Groups) (errors $($r.GroupErrors)), packages $($r.Claimed): done $($r.Done), failed $($r.Failed)$(if ($r.AdUsers) { ", AD users read $(if ($r.AdUsers -lt 0) { 'FAILED' } else { $r.AdUsers })" })"
    exit 0
} catch {
    Say "FAILED: $($_.Exception.Message)"
    exit 1
}
