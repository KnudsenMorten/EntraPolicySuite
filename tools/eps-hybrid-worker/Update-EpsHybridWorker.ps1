#Requires -Version 7.2
<#
.SYNOPSIS
    The Entra Policy Suite hybrid worker's update - what the scheduled task 'EntraPolicySuite Hybrid Worker Update'
    runs every hour AS SYSTEM on the worker (framework §5.5; Install-EpsHybridWorker.ps1 registers it).
.DESCRIPTION
    Moves the worker to the version the Entra Policy Suite install runs, and only to a release Invardia signed: reads the
    install's version and ring from its database (the machine's managed identity), asks Invardia for the signed release of
    that ring, checks the signature, the sequence, the archive's SHA-256 and size and the VERSION inside, unpacks it next
    to the running version, switches <Root>\app to it, sets the folder permissions again and runs the new version's
    self-test - and switches back to the previous version when the test fails. The outcome is written to the worker's
    heartbeat (the Hybrid worker page) and to <Root>\logs\update-<yyyyMMdd>.log.
    Exit 0 = updated, already current or waiting; 1 = refused, switched back or failed; 2 = misconfigured.
.PARAMETER Root
    The worker's folder (Install-EpsHybridWorker.ps1 -Root; C:\EntraPolicySuite, or C:\EPS as a guest of PIM's worker).
.PARAMETER SelfTest
    Only the self-test of the code this script belongs to (the update runs the NEW version's script with it).
.LINK
    https://invardia.com/docs/eps/scripts/Install-EpsHybridWorker
#>
[CmdletBinding()] param([string]$Root = 'C:\EntraPolicySuite', [switch]$SelfTest, [string]$Version = '')
$ErrorActionPreference = 'Stop'
$tree = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'InvardiaUpdate.verify', 'EPS-Updater', 'EPS-WorkerUpdate') { . (Join-Path $tree "engine\_shared\$f.ps1") }
if ($SelfTest) {
    $r = Test-EpsWorkerSelfTest -AppPath $tree -Version $Version
    Write-Output "EPS-WORKER-SELFTEST $(@{ ok = [bool]$r.Ok; reason = "$($r.Reason)" } | ConvertTo-Json -Compress)"
    exit $(if ($r.Ok) { 0 } else { 1 })
}
$logDir = Join-Path $Root 'logs'; New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir "update-$([datetime]::UtcNow.ToString('yyyyMMdd')).log"
function Say($m) { $l = "[$([datetime]::UtcNow.ToString('u'))] $m"; Add-Content -LiteralPath $log -Value $l; Write-Host $l }
Get-ChildItem -LiteralPath $logDir -Filter 'update-*.log' | Where-Object LastWriteTimeUtc -lt ([datetime]::UtcNow.AddDays(-90)) | Remove-Item -ErrorAction SilentlyContinue
$cfgFile = Join-Path $Root 'worker.json'
if (-not (Test-Path -LiteralPath $cfgFile)) { Say "no $cfgFile - run Install-EpsHybridWorker.ps1"; exit 2 }
$cfg = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
if ($cfg.ManagedIdentityClientId) { $env:EPS_ManagedIdentityClientId = $cfg.ManagedIdentityClientId }
# the gMSA the worker task runs as: worker.json (2.0.102+), else the task's own principal (an older install)
$gmsa = "$($cfg.Gmsa)".Trim()
if (-not $gmsa) { $t = @(Get-ScheduledTask -TaskName 'EntraPolicySuite Hybrid Worker' -ErrorAction SilentlyContinue)[0]; if ($t) { $gmsa = "$($t.Principal.UserId)".Trim() } }
$acl = {
    param($r)
    if (-not $gmsa) { Say 'permissions: the gMSA is not known - the folder keeps the permissions it inherits'; return }
    & icacls $r /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${gmsa}:(OI)(CI)RX" | Out-Null
    & icacls (Join-Path $r 'logs') /grant "${gmsa}:(OI)(CI)M" | Out-Null
}
$runSelfTest = {
    param($a, $v)
    # the NEW version's own self-test, in its own process (nothing of it loads here)
    $s = Join-Path $a 'tools\eps-hybrid-worker\Update-EpsHybridWorker.ps1'
    $px = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    $out = @(& $px -NoProfile -NonInteractive -File $s -SelfTest -Version $v 2>&1 | ForEach-Object { "$_" })
    $line = @($out | Where-Object { $_ -like 'EPS-WORKER-SELFTEST *' } | Select-Object -Last 1)
    if (-not $line.Count) { return @{ Ok = $false; Reason = "no answer (exit $LASTEXITCODE): $((@($out | Select-Object -Last 2)) -join ' ')" } }
    $j = $line[0].Substring(20) | ConvertFrom-Json
    @{ Ok = [bool]$j.ok; Reason = "$($j.reason)" }
}
# WORKER-UPD-2 (2.1.1): this task runs every hour, not daily 05:30 - a worker installed before 2.1.1 switches its own
# trigger here (as SYSTEM, the task's own principal; nothing else of the task changes)
try {
    $ut = @(Get-ScheduledTask -TaskName $script:EpsWorkerUpdateTask -ErrorAction SilentlyContinue)[0]
    if ($ut -and -not @($ut.Triggers | Where-Object { "$($_.Repetition.Interval)" -eq 'PT1H' }).Count) {
        Set-ScheduledTask -TaskName $ut.TaskName -TaskPath $ut.TaskPath -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Hours 1)) | Out-Null
        Say "schedule: the update task now runs every hour (it ran once a day)"
    }
} catch { Say "schedule: the update task could not be moved to every hour ($($_.Exception.Message)) - it keeps its schedule" }
try {
    $r = Invoke-EpsWorkerUpdate -Root $Root -ConnectionString $cfg.ConnectionString -WorkerName $cfg.WorkerName -SelfTest $runSelfTest -ApplyAcl $acl -Say { param($m) Say $m }
    exit $(if ($r.Outcome -in 'updated', 'current', 'waiting') { 0 } else { 1 })
} catch {
    Say "FAILED: $($_.Exception.Message)"
    exit 1
}
