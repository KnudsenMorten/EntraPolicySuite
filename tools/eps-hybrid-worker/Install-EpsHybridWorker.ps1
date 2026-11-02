#Requires -Version 7.2
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the EntraPolicySuite hybrid worker on a domain-joined Windows server (an Azure VM or an Azure Arc-enabled
    on-premises server) - run ON the worker, elevated (DESIGN §6; one worker per product, D5).
.DESCRIPTION
    The worker writes the tags of AD-synced users in on-premises AD and reads AD group membership for the rules. It
    talks to EntraPolicySuite only through its SQL database, with the MACHINE's managed identity; nothing inbound, no
    password, no certificate, no gallery module (the in-box Windows ScheduledTasks module and icacls / secedit are used -
    owner-approved for the hybrid worker). AD is written AS THE gMSA you give (create it and delegate it first:
    Initialize-EpsHybridWorkerAd.ps1), and the worker's identity is given access to the database with
    Grant-EpsHybridWorkerAccess.ps1.
    It: copies the code to <Root>\app; locks <Root> down (only SYSTEM and Administrators write the code the gMSA runs,
    the gMSA reads it and writes only <Root>\logs); writes <Root>\worker.json (the database, the worker's name - no
    secret); on an Arc server adds the gMSA to the local group 'Hybrid agent extension applications' (it reads the Arc
    agent's identity key); grants the gMSA 'Log on as a batch job'; registers the task 'EntraPolicySuite Hybrid Worker'
    (every 5 minutes, as the gMSA) and runs it once.
    -WhatIf: every step it would take, nothing changed. -Remove: the task, the group membership and <Root>\app go
    (the logs stay; the gMSA, the machine and its domain membership are not touched).
    -AsGuestOf pim (owner 2026-10-30: "we must support both, in internal we reuse the pim hybrid worker"; framework
    §12.26 SHARED-WORKER): on PIM's worker HOST, never under PIM's identity - EPS's own gMSA, its own task (task folder
    \EPS\), its own root C:\EPS beside C:\PIM, its own USER-ASSIGNED managed identity (-ManagedIdentityClientId, required:
    the VM's system identity belongs to the host's product), and the guest registration file
    C:\ProgramData\HybridWorkerHost\guests\eps.json (PIM's remove refuses to delete the machine while it exists). Refused on
    an Azure Arc host (only the system identity exists there) and where PIM's worker is not installed.
.EXAMPLE
    .\Install-EpsHybridWorker.ps1 -GmsaName 'CORP\gmsa-eps$' -SqlServer sql-eps-1a2b3c4d.database.windows.net -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Install-EpsHybridWorker
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[^\\]+\\[^\\]+\$$')][string]$GmsaName,
    [string]$SqlServer,
    [string]$Database = 'eps',
    [string]$WorkerName = $env:COMPUTERNAME,
    [string]$AdServer = '',
    [string]$ManagedIdentityClientId = '',
    [ValidateSet('Auto', 'AzureVm', 'Arc')][string]$HostType = 'Auto',
    [string]$Root = 'C:\EntraPolicySuite',
    [ValidateSet('', 'pim')][string]$AsGuestOf = '',
    [string]$SourcePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://invardia.com/docs/eps/scripts/Install-EpsHybridWorker'
$task = 'EntraPolicySuite Hybrid Worker'; $taskPath = '\EPS\'   # its own task folder (§12.26: never the host's names)
$guestFile = 'C:\ProgramData\HybridWorkerHost\guests\eps.json'
if ($AsGuestOf -and -not $PSBoundParameters.ContainsKey('Root')) { $Root = 'C:\EPS' }   # a sibling of C:\PIM, never inside it
$arcGroup = 'Hybrid agent extension applications'
$isArc = if ($HostType -eq 'Auto') { [bool](Get-Service -Name himds -ErrorAction SilentlyContinue) } else { $HostType -eq 'Arc' }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
function Step($text, [scriptblock]$do) { if ($what) { Write-Host "  WhatIf: $text" } else { Write-Host "  $text"; & $do } }

if ($Remove) {
    Step "unregister the scheduled task '$taskPath$task'" { Unregister-ScheduledTask -TaskName $task -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $task -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $guestFile) { Step "delete the guest registration $guestFile (the host may then be removed)" { Remove-Item -LiteralPath $guestFile -Force } }
    if ($isArc) { Step "remove $GmsaName from the local group '$arcGroup'" { Remove-LocalGroupMember -Group $arcGroup -Member $GmsaName -ErrorAction SilentlyContinue } }
    Step "delete $Root\app (the logs stay)" { Remove-Item -LiteralPath (Join-Path $Root 'app') -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host 'Removed. The gMSA, its AD delegation and the database user are not touched (Initialize-EpsHybridWorkerAd.ps1 -Remove, Grant-EpsHybridWorkerAccess.ps1 -Remove).'
    return
}
if ($AsGuestOf -eq 'pim') {
    if ($isArc) { throw 'a guest on an Azure Arc host is not supported yet: an Arc host has only the system identity, which belongs to the host''s product (framework §12.26)' }
    if (-not (Test-Path -LiteralPath 'C:\PIM\bin\worker.json')) { throw 'PIM''s hybrid worker is not installed on this machine (no C:\PIM\bin\worker.json) - install it first, or install EntraPolicySuite''s own worker' }
    if ($ManagedIdentityClientId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'as a guest, -ManagedIdentityClientId is required: EntraPolicySuite''s OWN user-assigned identity (id-eps-worker), attached to this VM - never the VM''s system identity' }
    if ($Root -like 'C:\PIM*') { throw "-Root $Root is inside PIM's folder - a guest has its own root beside it (C:\EPS)" }
}
if (-not $SqlServer) { throw '-SqlServer is required (the EntraPolicySuite SQL server: <name>.database.windows.net)' }
if ($SqlServer -notmatch '^[a-z0-9-]{1,63}\.database\.windows\.net$') { throw "-SqlServer '$SqlServer': give <name>.database.windows.net" }
$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $pwsh) { throw 'PowerShell 7 (pwsh.exe) is required on the worker' }
foreach ($need in 'engine\_shared\EPS-SqlStore.ps1', 'engine\_shared\EPS-AdDirectory.ps1', 'engine\_shared\EPS-HybridWorker.ps1', 'tools\eps-hybrid-worker\Start-EpsHybridWorker.ps1', 'VERSION') {
    if (-not (Test-Path -LiteralPath (Join-Path $SourcePath $need))) { throw "-SourcePath $SourcePath has no $need (point it at the EntraPolicySuite release folder)" }
}
Write-Host "EntraPolicySuite hybrid worker '$WorkerName' on $env:COMPUTERNAME ($(if ($isArc) { 'Azure Arc' } else { 'Azure VM' })), AD as $GmsaName, SQL $SqlServer/$Database" -ForegroundColor Cyan

$appDir = Join-Path $Root 'app'
Step "copy the worker code to $appDir" {
    New-Item -ItemType Directory -Force -Path $appDir, (Join-Path $appDir 'engine'), (Join-Path $appDir 'tools') | Out-Null
    Copy-Item -LiteralPath (Join-Path $SourcePath 'engine\_shared') -Destination (Join-Path $appDir 'engine') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $SourcePath 'tools\eps-hybrid-worker') -Destination (Join-Path $appDir 'tools') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $SourcePath 'VERSION') -Destination $appDir -Force
}
Step "lock $Root down: SYSTEM + Administrators full; $GmsaName read + execute, modify only on logs" {
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'logs') | Out-Null
    & icacls $Root /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${GmsaName}:(OI)(CI)RX" | Out-Null
    & icacls (Join-Path $Root 'logs') /grant "${GmsaName}:(OI)(CI)M" | Out-Null
}
$cfg = [ordered]@{ WorkerName = $WorkerName; AdServer = $AdServer; ManagedIdentityClientId = $ManagedIdentityClientId
                   ConnectionString = "Server=tcp:$SqlServer,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30" }
Step "write $Root\worker.json (the database and the worker's name - no secret)" { $cfg | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'worker.json') -Encoding utf8 }
if ($isArc) { Step "add $GmsaName to the local group '$arcGroup' (it reads the Arc agent's identity key)" { if (-not (Get-LocalGroupMember -Group $arcGroup -ErrorAction SilentlyContinue | Where-Object Name -eq $GmsaName)) { Add-LocalGroupMember -Group $arcGroup -Member $GmsaName } } }
Step "grant $GmsaName 'Log on as a batch job' (the task runs as it)" {
    $sid = ([Security.Principal.NTAccount]$GmsaName).Translate([Security.Principal.SecurityIdentifier]).Value
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "eps-secpol-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        & secedit /export /cfg "$tmp\cur.inf" /areas USER_RIGHTS | Out-Null
        $line = (Get-Content "$tmp\cur.inf" | Where-Object { $_ -match '^SeBatchLogonRight' }) -replace '^SeBatchLogonRight\s*=\s*', ''
        if ($line -notmatch [regex]::Escape("*$sid")) {
            $new = @($(if ($line) { $line }), "*$sid") -join ','
            Set-Content -LiteralPath "$tmp\new.inf" -Encoding Unicode -Value "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n[Privilege Rights]`r`nSeBatchLogonRight = $new"
            & secedit /configure /db "$tmp\sec.sdb" /cfg "$tmp\new.inf" /areas USER_RIGHTS | Out-Null
        }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
Step "register the task '$task': every 5 minutes as $GmsaName" {
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -NonInteractive -File `"$appDir\tools\eps-hybrid-worker\Start-EpsHybridWorker.ps1`" -Root `"$Root`" -Once"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId $GmsaName -LogonType Password -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 4) -StartWhenAvailable
    Register-ScheduledTask -TaskName $task -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'EntraPolicySuite hybrid worker (DESIGN §6): AD tags + AD group snapshots, through SQL' -Force | Out-Null
}
Step "run the task once and show its result" {
    Start-ScheduledTask -TaskName $task -TaskPath $taskPath
    Start-Sleep -Seconds 45
    $last = Get-ChildItem -LiteralPath (Join-Path $Root 'logs') -Filter 'worker-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
    if ($last) { Get-Content -LiteralPath $last.FullName -Tail 3 } else { Write-Warning "no log yet in $Root\logs - check the task's history" }
}
if ($AsGuestOf) {
    Step "register as a guest of $AsGuestOf's worker host: $guestFile" {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $guestFile) | Out-Null
        [ordered]@{ product = 'entrapolicysuite'; root = $Root; taskPath = $taskPath; tasks = @($task); gmsa = $GmsaName; uamiClientId = $ManagedIdentityClientId
                    version = (Get-Content -LiteralPath (Join-Path $SourcePath 'VERSION') -Raw).Trim(); installedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $guestFile -Encoding utf8
    }
}
Write-Host $(if ($what) { "`nWhatIf: nothing was changed." } else { "`nInstalled. The worker heartbeats every 5 minutes; EntraPolicySuite queues AD-synced tags for it." }) -ForegroundColor Green
