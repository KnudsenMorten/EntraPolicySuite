#Requires -Version 7.2
<#
.SYNOPSIS
    The entry of every Entra Policy Suite Container Apps Job - the tick and the work jobs run this same script from the
    same image (DESIGN §2); EPS_JOB says which.
.DESCRIPTION
    EPS_JOB = Tick            the scheduler (every 5 min): starts the jobs that are due and the requests (EPS-Scheduler)
    EPS_JOB = UserTagging     user tagging: takes the oldest request the tick dispatched for it, or runs on schedule
    EPS_JOB = DeviceTagging   device tagging, the same way
    EPS_JOB = CAPolicyAnalyzer the CA Policy Analyzer (read only): one ad-hoc request (EPS_REQUEST_ID) or one monitor (EPS_CA_MONITOR)
    EPS_JOB = DbInit          the database setup job (caj-eps-dbinit, SEC-08): schema, roles, users, the front's state
    EPS_JOB = Web             the GUI (tools/eps-web/Start-EpsWeb.ps1), behind the shared sign-in front
    A scheduled run uses the feature's mode setting (<Job>.Mode, default Preview: a new install previews until the
    customer has tested and switched the job to Apply - DESIGN §5.8 "never the whole tenant untested").
    Environment (set by the install on the job): EPS_SQL_CONNECTION (the database; the managed identity signs in),
    EPS_TENANT_ID, EPS_SUBSCRIPTION_ID + EPS_RESOURCE_GROUP (the tick, to start jobs), EPS_ManagedIdentityClientId.
    Exit code: 0 = done (a held run is done: an admin decides), 1 = the run failed, 2 = misconfigured.
#>
[CmdletBinding()] param([string]$Job = $env:EPS_JOB, [string]$ConnectionString = $env:EPS_SQL_CONNECTION)
$ErrorActionPreference = 'Stop'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-Conditions', 'EPS-TagEngine', 'EPS-Guard', 'EPS-SqlStore', 'EPS-Graph', 'EPS-Exchange', 'EPS-TagJob', 'EPS-Scheduler', 'EPS-TamperMonitor', 'EPS-HybridWorker', 'EPS-WorkerPage', 'EPS-Mail', 'EPS-WebAuth', 'EPS-Audit', 'EPS-CaAnalyzer', 'EPS-CaManage', 'EPS-CaWrite', 'EPS-CaOptions', 'EPS-Backup', 'EPS-Onboarding', 'EPS-GroupManage', 'EPS-GroupWrite', 'EPS-OnboardManage', 'EPS-OnboardWrite', 'EPS-IdentityReport', 'EPS-SignInMethods', 'EPS-LogAnalytics', 'EPS-Settings', 'EPS-Rules', 'EPS-V1Import', 'EPS-WebApi', 'EPS-ConfigEngine', 'EPS-Uplink', 'InvardiaUpdate.verify', 'EPS-Updater', 'EPS-Licence', 'EPS-SupportRead', 'EPS-Watchdog') { . (Join-Path $sol "engine\_shared\$f.ps1") }
# EPS PRO: the Pro package's modules (pro/engine/*.ps1, their engine-only writes included); absent without the Pro package
$proEngine = Join-Path $sol 'pro\engine'
if (Test-Path -LiteralPath $proEngine) { foreach ($pf in @(Get-ChildItem -LiteralPath $proEngine -Filter '*.ps1' -File | Sort-Object Name)) { . $pf.FullName } }
$version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim()
function Say($m) { Write-Host "[$([datetime]::UtcNow.ToString('u'))] [eps $version $Job] $m" }

# Deterministic-failure gap (6) (Invardia 2026-11-08: "every job reports"): the jobs without their own run row (DbInit,
# SupportAccess, Config) write ONE finished eps.Run row at their end, so the uplink reports them and their streak counts.
# A failed write never fails the job (DbInit's first run may find no schema before it has made it).
function Write-EpsFinishedRunRow {
    param([Parameter(Mandatory)][string]$RunJob, [Parameter(Mandatory)][datetime]$StartedUtc, [Parameter(Mandatory)][ValidateSet('Succeeded', 'PartlyFailed', 'Failed')][string]$Status, [string]$Text, [int]$Applied = 0, [int]$Failed = 0, [int]$Skipped = 0)
    $h = if ($Text) { if ($Text.Length -gt 1000) { $Text.Substring(0, 997) + '...' } else { $Text } } else { $null }
    try {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [guid]::NewGuid(); j = $RunJob; t = $StartedUtc; s = $Status; h = $h; a = $Applied; f = $Failed; k = $Skipped } `
            -Query "INSERT INTO eps.Run (RunId, Job, Mode, StartedAtUtc, EndedAtUtc, Status, HeldReason, Applied, Failed, Skipped) VALUES (@id, @j, 'Apply', @t, SYSUTCDATETIME(), @s, @h, @a, @f, @k)" | Out-Null
    } catch { Say "could not record the run: $((("$($_.Exception.Message)") -split "`n")[0])" }
}
$script:__started = [datetime]::UtcNow

if (-not $Job) { Say 'EPS_JOB is not set'; exit 2 }
if (-not $ConnectionString) { Say 'EPS_SQL_CONNECTION is not set'; exit 2 }
# UPD-STUCK-RUN (internal 2026-11-06): caj-eps-tamper-4w76v ran 5.5 h and printed NOTHING - every job says it started, so
# a hang is placed (before this line = the container; after it = SQL, the queue or the job's own work)
Say "start$(if ($env:CONTAINER_APP_REPLICA_NAME) { " ($env:CONTAINER_APP_REPLICA_NAME)" })"
# STALL-1 (framework 8.18): the work jobs report their progress, and end themselves when the engine marks the run stalled
# (EPS-Watchdog.ps1); the jobs without a running run row (the checks, the setup, the GUI) have nothing to watch
if ($Job -notin 'Tick', 'Wake', 'Web', 'DbInit', 'SupportAccess', 'SupportRead', 'Config') {
    Say (Start-EpsRunWatchdog -ConnectionString $ConnectionString -Job $Job -StartedUtc $script:__started -MayStop:($Job -notin $script:EpsStallNeverStop))
}
# V1-PARITY P16: this job's log level (Log.Level.<Job>: Off / Normal / Verbose); warnings and errors are always kept
$script:__logLevel = if ($Job -in $script:EpsLogFeatures) { Get-EpsLogLevel -ConnectionString $ConnectionString -Feature $Job } else { 'Normal' }
# gap (4): the jobs that page through Graph and bulk-copy run with smaller sizes after repeated failed runs (halved per run in
# a row that did not complete, at most 8x) - a size that keeps timing out is not retried unchanged
if ($Job -in 'UserTagging', 'DeviceTagging', 'IdentityReport', 'CAPolicyAnalyzer') {
    $streak = Get-EpsJobRunStreak -ConnectionString $ConnectionString -Job $Job -EndedAtUtc ([datetime]::UtcNow)
    $f = Set-EpsSizeShrink -Streak $streak
    if ($f -gt 1) { Say "the last $streak run(s) did not complete: batches and pages are $f times smaller this run (Graph pages $(Get-EpsGraphPageSize), bulk copies $(Get-EpsShrunkSize -Base 5000 -Min 100))" }
}

try {
    if ($Job -eq 'Tick') {
        $t = Invoke-EpsTick -ConnectionString $ConnectionString
        foreach ($d in $t.Decisions) { Say ("{0,-15} {1,-11} {2}" -f $d.Job, $d.Action, $d.Reason) }
        Say "tick $($t.RunId): $($t.Status)"
        # V1-PARITY P16: run log lines older than Log.KeepDays go - the first tick of each hour, a bounded batch
        if ([datetime]::UtcNow.Minute -lt 5) { $gone = Remove-EpsExpiredRunLogs -ConnectionString $ConnectionString; if ($gone) { Say "run log retention: $gone old line(s) removed$(if ($gone -lt 0) { ' - FAILED' })" } }
        exit $(if ($t.Status -eq 'Failed') { 1 } else { 0 })
    }
    if ($Job -eq 'DbInit') {
        # SEC-08 plan A: the database setup job caj-eps-dbinit, as its own identity id-eps-dbinit (a member of the SQL
        # admin group) - started by the installer / the updater, never by the tick and never from a queue. Its decisions
        # are in EPS-DbInit.ps1; exit 0 only when every principal is read back.
        . (Join-Path $sol 'engine\_shared\EPS-Install.ps1')   # with EPS-InstallWeb (the front's state SQL) and EPS-DbInit
        $script:__last = ''
        $rc = Invoke-EpsDbInit -ConnectionString $ConnectionString -SolutionRoot $sol -Log { param($m) $script:__last = "$m"; Say $m }
        Write-EpsFinishedRunRow -RunJob 'DbInit' -StartedUtc $script:__started -Status $(if ($rc -eq 0) { 'Succeeded' } else { 'Failed' }) -Text $(if ($rc -ne 0) { "exit $rc`: $($script:__last)" })
        exit $rc
    }
    if ($Job -eq 'SupportAccess') {
        # OPEN-01 (framework SUPPORT ACCESS): caj-eps-support, every 5 minutes, as id-eps-dbinit - reads the customer's
        # consent from Invardia ITSELF and converges the Support app's database user (EPS-SupportAccess.ps1)
        foreach ($f in 'EPS-Install', 'EPS-SupportAccess') { . (Join-Path $sol "engine\_shared\$f.ps1") }
        $script:__last = ''
        $rc = Invoke-EpsSupportAccess -ConnectionString $ConnectionString -Log { param($m) $script:__last = "$m"; Say $m }
        Write-EpsFinishedRunRow -RunJob 'SupportAccess' -StartedUtc $script:__started -Status $(if ($rc -eq 0) { 'Succeeded' } else { 'Failed' }) -Text $(if ($rc -ne 0) { "exit $rc`: $($script:__last)" })
        exit $rc
    }
    if ($Job -eq 'SupportRead') {
        # SUP-02 (2.0.101): caj-eps-supportread as id-eps-support - ONE named read from the shipped allow-list, asked for by
        # a message on its own queue (Invardia's Support app may only send there); the result to this console, audited
        . (Join-Path $sol 'engine\_shared\EPS-SupportRead.ps1')
        $sr = Invoke-EpsSupportReadJob -ConnectionString $ConnectionString -Say { param($m) Say $m }
        exit $(if ($sr.Outcome -eq 'error') { 1 } else { 0 })
    }
    if ($Job -eq 'Web') {
        # the GUI (DESIGN §2): behind the shared sign-in front, on 127.0.0.1 only - it never returns
        & (Join-Path $sol 'tools\eps-web\Start-EpsWeb.ps1') -ConnectionString $ConnectionString
        exit $LASTEXITCODE
    }
    if ($env:EPS_STORAGE_ACCOUNT -and $env:EPS_ACA_JOB) {
        # 2.0.9 (SEC-AUDIT-1 S4): an event-triggered work job - started by a message on its own queue, never by the tick
        # through ARM. Take ONE message (deleted at once); its per-run parameters are checked in Read-EpsJobMessage and
        # are the only way in - anything set in the environment for them before is dropped.
        foreach ($k in 'EPS_REQUEST_ID', 'EPS_CA_MONITOR', 'EPS_TAG_TRIGGER') { Remove-Item "env:$k" -ErrorAction SilentlyContinue }
        $msg = Read-EpsJobMessage -StorageAccount $env:EPS_STORAGE_ACCOUNT -AcaJobName $env:EPS_ACA_JOB
        if ($null -eq $msg) {
            # the uplink job is also started directly (framework SECAUDIT-1a: the Support session starts the heartbeat once
            # so support begins without waiting an interval) - it takes no parameters, so it runs its normal cycle
            if ($Job -notin 'Uplink', 'Update') { Say 'no message on the queue (another execution took it) - nothing to do'; exit 0 }
            Say "no message on the queue (a direct start) - the normal $($Job.ToLowerInvariant()) cycle"
        }
        elseif ($msg.Refused) { Say $msg.Refused; exit 0 }
        else { foreach ($k in $msg.Keys) { Set-Item "env:$k" $msg[$k] } }
    }
    if ($Job -eq 'Wake') {
        # FAST-START: the web app's wake-up - one normal engine check now (claims, guards and the run record as every tick)
        $t = Invoke-EpsTick -ConnectionString $ConnectionString
        foreach ($d in $t.Decisions) { Say ("{0,-15} {1,-11} {2}" -f $d.Job, $d.Action, $d.Reason) }
        Say "wake-up check $($t.RunId): $($t.Status)"
        exit $(if ($t.Status -eq 'Failed') { 1 } else { 0 })
    }
    if ($Job -eq 'Uplink') {
        # UPLINK-1 (owner 2026-11-01 "Yes, identified only"): the heartbeat, alert and run records to Invardia - only with
        # the per-install key from the install's Key Vault; none = nothing sent. A "Run now" request is taken and closed.
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'Uplink' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'Uplink', 'Apply', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $u = Invoke-EpsUplinkCycle -ConnectionString $ConnectionString -Version $version -Log $log
        # SUPPORT-LINK-1: amber only after 3 undelivered cycles in a row (the count is kept in eps.UplinkState); never a mail
        $before = 0; try { [void][int]::TryParse("$((Get-EpsUplinkState -ConnectionString $ConnectionString)['delivery.failedCycles'])", [ref]$before) } catch { }
        $cy = Get-EpsSupportLinkCycleStatus -Stopped "$($u.Stopped)" -FailedBefore $before
        if ($cy.Failed -ne $before) { try { Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'delivery.failedCycles' -Value "$($cy.Failed)" } catch { } }
        $st = $cy.Status
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $st; a = [int]($u.Runs + $u.Alerts + $(if ($u.Heartbeat -like 'ok*') { 1 } else { 0 })); h = $(if ($cy.Text) { $cy.Text } elseif ($u.Mode -eq 'disabled') { "$($u.Lines | Select-Object -Last 1)" }) } `
            -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Applied = @a, HeldReason = @h WHERE RunId = @id' | Out-Null
        if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = 'Done'; t = "$($u.Mode): $($u.Lines | Select-Object -Last 1)" } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        exit 0
    }
    if ($Job -eq 'Update') {
        # UPDATER-1: which release is approved for this install's ring (verified), and - phase 2 - its apply as the job's
        # own identity id-eps-updater (EPS-UpdateApply.ps1: no SQL; the run record below stays the engine identity's). A
        # "Run now" request is taken and closed like the uplink's.
        foreach ($f in 'EPS-Arm', 'EPS-Install', 'EPS-UpdateApply') { . (Join-Path $sol "engine\_shared\$f.ps1") }
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'Update' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'Update', 'Preview', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $u = $null; $ok = $false
        try { $u = Invoke-EpsUpdateCheck -ConnectionString $ConnectionString -Version $version -Log $log -RunId $runId; $ok = $u.State -notin 'refused', 'unreachable' -and -not ($u.Applied -and -not $u.Applied.Ok) }
        catch { & $log 'Error' "$($_.Exception.Message)" }
        $sum = if ($u) { $u.Summary } else { 'the check failed - see its log' }
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'PartlyFailed' }); h = $sum; a = $(if ($u.Applied.Ok) { @($u.Applied.Rolled).Count } else { 0 }) } `
            -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Applied = @a, HeldReason = @h WHERE RunId = @id' | Out-Null
        if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $sum } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'CAPolicyAnalyzer') {
        # the CA Policy Analyzer (DESIGN §5.7) - READ ONLY towards the tenant. One execution = one ad-hoc request
        # (EPS_REQUEST_ID) or one monitor (EPS_CA_MONITOR); several run side by side, each with its own parameters.
        $runId = [guid]::NewGuid(); $label = ''; $body = $null; $reqId = $env:EPS_REQUEST_ID; $monitor = $env:EPS_CA_MONITOR
        Set-EpsWatchRun -RunId $runId   # several executions side by side: this one watches its own run row
        if ($reqId) {
            $q = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = [guid]$reqId; r = $runId } -Query @'
UPDATE q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.Scope, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (UPDLOCK, ROWLOCK)
WHERE q.RequestId = @id AND q.Job = 'CAPolicyAnalyzer' AND q.Status = 'Dispatched'
'@)[0]
            if (-not $q) { Say "request $reqId is not waiting for this job (taken or gone)"; exit 0 }
            $body = $q.Scope | ConvertFrom-Json; $label = "request $reqId by $($q.RequestedBy)"
        } elseif ($monitor) {
            $mrow = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ n = $monitor } -Query 'SELECT Name, Definition FROM eps.CaMonitor WHERE Name = @n')[0]
            if (-not $mrow) { Say "monitor '$monitor' does not exist"; exit 2 }
            $body = $mrow.Definition | ConvertFrom-Json; $label = "monitor $monitor"
        } else { Say 'neither EPS_REQUEST_ID nor EPS_CA_MONITOR is set: nothing to analyse'; exit 2 }
        $v = ConvertTo-EpsCaRequest -Body $body
        if (-not $v.Ok) { Say "$label`: $($v.Error)"; if ($reqId) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [guid]$reqId; t = $v.Error } -Query "UPDATE eps.JobRequest SET Status = 'Failed', StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id" | Out-Null }; exit 2 }
        if ($monitor) { $v.Request.Monitor = $monitor }
        $scope = ([ordered]@{ monitor = $(if ($monitor) { $monitor } else { $null }); request = $(if ($reqId) { $reqId } else { $null }) } | ConvertTo-Json -Compress)   # the tick matches this text (overlap guard per monitor)
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $scope } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'CAPolicyAnalyzer', 'Preview', @s)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            & $log 'Info' "$label - $($v.Request.Mode), read only (nothing in the tenant is changed)"
            $res = Invoke-EpsCaPolicyAnalyzer -ConnectionString $ConnectionString -Request $v.Request -RunId $runId -Version $version -Log $log
            $ok = $true
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) & $log 'Info' $m })   # framework §12.27 SQL-STATS, warn-only
            $objects = if ($res) { ($res.Analyses | ForEach-Object { $_.Summary.InScope } | Measure-Object -Sum).Sum } else { 0 }
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); o = [int]$objects; p = [int]$(if ($res) { $res.Impacted } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = @p, Applied = 0 WHERE RunId = @id' | Out-Null
            if ($reqId) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [guid]$reqId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "$(@($res.Analyses).Count) policy(ies), $($res.Impacted) impacted" } else { 'the analysis failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'TamperMonitor') {
        # a restore the GUI asked for (one click on the Tamper page): the engine writes the tag back - signed first
        Say 'requests from the GUI (test mail, restore)'
        while ($q = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query @'
UPDATE TOP (1) q SET Status = 'Running', UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.Mode, INSERTED.Scope, INSERTED.RequestedBy, DELETED.SignedToken, INSERTED.SignedVerifiedAtUtc, INSERTED.CorrelationId
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'TamperMonitor' AND q.Status = 'Dispatched'
'@)[0]) {
            $sc = if ($q.Scope) { $q.Scope | ConvertFrom-Json }
            if ($sc.testMail) {
                # "Send a test mail": sent as the engine's identity, nothing in the directory changes
                $x = try { Send-EpsTestMail -ConnectionString $ConnectionString -RequestedBy $q.RequestedBy -Version $version } catch { @{ Sent = $false; Reason = "the test mail failed: $($_.Exception.Message)" } }
                Say "request $($q.RequestId) by $($q.RequestedBy): test mail - $($x.Reason)"
                Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId; s = $(if ($x.Sent) { 'Done' } else { 'Failed' }); t = "test mail: $($x.Reason)" } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null
                continue
            }
            $ids = @(if ($sc) { $sc.restore })
            $gate = Confirm-EpsJobRequest -Request $q -ConnectionString $ConnectionString -ChangesOutside:($ids.Count -gt 0)
            Say "request $($q.RequestId) by $($q.RequestedBy): restore $($ids -join ', ') - $($gate.Text)"
            $done = [System.Collections.Generic.List[string]]::new()
            if ($gate.Allow) {
                foreach ($id in $ids) {
                    $x = Restore-EpsTamperEvent -ConnectionString $ConnectionString -EventId ([long]$id) -By $q.RequestedBy
                    $done.Add("event $id`: $(if ($x.Restored) { "restored '$($x.Value)'" } else { "FAILED: $($x.Error)" })")
                    Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'tamper.event.restore' -Actor $q.RequestedBy -ActorSource 'job' -Target "TamperEvent|$id" `
                        -Outcome $(if ($x.Restored) { 'ok' } else { 'error' }) -OutcomeText $(if (-not $x.Restored) { "$($x.Error)" }) -After @{ appliedBy = 'TamperMonitor'; value = $x.Value } -CorrelationId $q.CorrelationId
                }
            }
            $st = if (-not $gate.Allow) { 'Refused' } elseif ($done | Where-Object { $_ -match 'FAILED' }) { 'Failed' } else { 'Done' }
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId; s = $st; t = (@($gate.Text) + $done) -join '; ' } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null
            foreach ($d in $done) { Say "  $d" }
        }
        try { [void](Update-EpsWebAccessObjectIds -ConnectionString $ConnectionString) } catch { Say "could not bind access grants to object ids: $($_.Exception.Message)" }   # SEC-AUDIT-1 S7
        # every 15 min a delta; the daily full compare when the last one is more than 24 h old (DESIGN §5.7a)
        $lastFull = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.MonitorState WHERE Name = 'fullCompare'"
        $full = -not $lastFull -or ([datetime]::UtcNow - [datetime]::Parse($lastFull, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)).TotalHours -ge 24
        Say "monitor: $(if ($full) { 'full compare' } else { 'delta' })"
        $m = Invoke-EpsTamperMonitor -ConnectionString $ConnectionString -Mode $(if ($full) { 'Full' } else { 'Delta' })
        if ($full) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = [datetime]::UtcNow.ToString('o') } -Query "MERGE eps.MonitorState AS d USING (SELECT 'fullCompare' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES ('fullCompare', @v);" | Out-Null }
        $open = @($m.Events | Where-Object Status -eq 'Open')
        Say "tamper monitor ($(if ($full) { 'full compare' } else { 'delta' })): $($m.Objects) object(s) read, $($open.Count) foreign change(s), $(@($open | Where-Object Severity -eq 'High').Count) high"
        foreach ($e in $open) { Say "  FOREIGN [$($e.Severity)] $($e.Detail)" }
        foreach ($n in $m.Notes) { Say "  note: $n" }
        # the alert at once (DESIGN §5.7a): one mail for the events not alerted yet - before anything restores them
        $al = Send-EpsTamperAlert -ConnectionString $ConnectionString -Version $version
        if ($al.Events) { Say "  alert: $($al.Events) event(s), $(if ($al.Sent) { "mailed ($($al.Reason))" } else { "NOT mailed - $($al.Reason); tried again next run" })" }
        # framework lesson 2026-11-08 (2.0.104): an alert mail that could not be sent while mail IS set up makes this run
        # PartlyFailed - so 3 runs in a row become a repeat-failure (a fix-request cause) instead of a retry forever
        if ($al.Events -and -not $al.Sent -and $m.RunId -and "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Mail.Mode' -Default 'none')" -ne 'none') {
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $m.RunId; h = "the tamper alert mail was not sent: $("$($al.Reason)".Substring(0, [Math]::Min(300, "$($al.Reason)".Length)))" } `
                -Query "UPDATE eps.Run SET Status = 'PartlyFailed', HeldReason = @h WHERE RunId = @id AND Status = 'Succeeded'" | Out-Null
        }
        if ($open -and "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'TamperMonitor.AutoRestore' -Default 'false')" -eq 'true') {
            foreach ($e in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $m.RunId } -Query "SELECT EventId FROM eps.TamperEvent WHERE RunId = @r AND Status = 'Open'")) {
                $x = Restore-EpsTamperEvent -ConnectionString $ConnectionString -EventId $e.EventId -By 'auto-restore (TamperMonitor.AutoRestore)'
                Say "  auto-restore of event $($e.EventId): $(if ($x.Restored) { "restored '$($x.Value)'" } else { "FAILED: $($x.Error)" })"
            }
        }
        exit 0
    }
    if ($Job -eq 'Config') {
        # SEC-AUDIT-1 S1: configuration is written by the ENGINE only - from the requester's signed request, which must
        # verify (whatever Security.SignedRequests says: there is no observe for a configuration change)
        $n = 0; $cDone = 0; $cFailed = 0; $cRefused = 0; $cLast = ''
        try { $b = Update-EpsWebAccessObjectIds -ConnectionString $ConnectionString; if ($b) { Say "bound $b access grant(s) to the person's object id" } } catch { Say "could not bind access grants to object ids: $($_.Exception.Message)" }
        while ($q = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query @'
UPDATE TOP (1) q SET Status = 'Running', UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.Mode, INSERTED.Scope, INSERTED.RequestedBy, DELETED.SignedToken, INSERTED.SignedVerifiedAtUtc, INSERTED.CorrelationId
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'Config' AND q.Status = 'Dispatched'
'@)[0]) {
            $n++
            $gate = Confirm-EpsJobRequest -Request $q -ConnectionString $ConnectionString -ChangesOutside
            $st = 'Refused'; $txt = $gate.Text
            if ($gate.Verified) {
                $sc = $q.Scope | ConvertFrom-Json
                $r = Invoke-EpsEngineConfigRequest -ConnectionString $ConnectionString -Scope $sc -Identity $gate.Identity -ObjectId $gate.ObjectId -Token $q.SignedToken -CorrelationId $q.CorrelationId
                $st = if ($r.Status -lt 400) { 'Done' } elseif ($r.Status -in 400, 403, 404, 409) { 'Refused' } else { 'Failed' }
                $txt = "$($sc.method) $($sc.path): $($r.Text)"
            } else { $txt = "REFUSED (a configuration change must carry a verified signature): $($gate.Text)" }
            if ($txt.Length -gt 1000) { $txt = $txt.Substring(0, 997) + '...' }
            Say "request $($q.RequestId) by $($q.RequestedBy): $st - $txt"
            switch ($st) { 'Done' { $cDone++ } 'Failed' { $cFailed++; $cLast = $txt } default { $cRefused++ } }
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId; s = $st; t = $txt } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null
        }
        if ($n) { [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) Say $m }) }   # framework §12.27 SQL-STATS (an import, many rules), warn-only
        Say "configuration: $n request(s)"
        # gap (6): a run that took requests is recorded (none taken = another execution had them: nothing to report). A
        # refused request (a wrong signature, a 4xx answer) is the check doing its job - counted, never a failure
        if ($n) {
            $cst = if (-not $cFailed) { 'Succeeded' } elseif ($cDone) { 'PartlyFailed' } else { 'Failed' }
            Write-EpsFinishedRunRow -RunJob 'Config' -StartedUtc $script:__started -Status $cst -Applied $cDone -Failed $cFailed -Skipped $cRefused -Text $(if ($cFailed) { "$cFailed of $n request(s) failed; last: $cLast" })
        }
        exit 0
    }
    if ($Job -eq 'Backup') {
        # UNDO-BACKUP (owner 2026-11-05: "ok go with daily keep 30"): every Conditional Access policy, named location and
        # authentication strength, and the tagging configuration, as one set each (EPS-Backup.ps1) - READS the tenant only.
        # A "Back up now" request is taken first (nothing outside changes: nothing to sign); otherwise the daily run.
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy, INSERTED.Reason
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'Backup' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'Backup', 'Apply', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            $res = if ($req) { Invoke-EpsBackupJob -ConnectionString $ConnectionString -Kind Manual -Actor "$($req.RequestedBy)" -Cause "Back up now$(if ($req.Reason) { ": $($req.Reason)" })" -Log $log }
                   else { Invoke-EpsBackupJob -ConnectionString $ConnectionString -Kind Daily -Log $log }
            $ok = $true
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) & $log 'Info' $m })   # framework §12.27 SQL-STATS, warn-only
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); o = [int]$(if ($res) { $res.Policies + $res.ConfigItems } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = 0, Applied = 0 WHERE RunId = @id' | Out-Null
            if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "CA backup $($res.CaBackupId) ($($res.Policies) policies), configuration backup $($res.ConfigBackupId)" } else { 'the backup failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'CaOptions') {
        # CA-EDIT-PICKERS (owner 2026-11-05: "talk with graph to understand the optins per field" / "consider a discovery
        # process monthly to get available options per field via graph"): Graph v1.0's $metadata + the tenant's lists ->
        # the policy Edit form's options (EPS-CaOptions.ps1). READS the tenant only. A Run now request is taken first.
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'CaOptions' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'CaOptions', 'Preview', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            & $log 'Info' "$(if ($req) { "request $($req.RequestId) by $($req.RequestedBy)" } else { 'scheduled run' }) - read only (nothing in the tenant is changed)"
            $res = Invoke-EpsCaOptionsDiscovery -ConnectionString $ConnectionString -Log $log
            $ok = [bool]$res.Ok
            [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) & $log 'Info' $m })   # framework §12.27 SQL-STATS, warn-only
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); o = [int]$(if ($res) { (@($res.Tenant.Values) | Measure-Object -Sum).Sum } else { 0 }); p = [int]$(if ($res) { @($res.NewFromGraph).Count } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = @p, Applied = 0 WHERE RunId = @id' | Out-Null
            if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "Read the options from Graph: $(@($res.NewFromGraph).Count) new from Graph" } else { 'the read failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'IdentityReport') {
        # the identity report (DESIGN §5.4) - READ ONLY towards the tenant and AD: one run = one snapshot the GUI reads.
        # A "Run now" request is taken first (nothing to sign: nothing outside changes); otherwise the scheduled run.
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'IdentityReport' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'IdentityReport', 'Preview', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            & $log 'Info' "$(if ($req) { "request $($req.RequestId) by $($req.RequestedBy)" } else { 'scheduled run' }) - read only (nothing in the tenant or AD is changed)"
            $res = Invoke-EpsIdentityReportJob -ConnectionString $ConnectionString -RunId $runId -Version $version -Log $log
            $ok = $true
            # EPS PRO 'passkey-tracker': today's ready count per persona from this run (a no-op without the Pro licence; never fails the run)
            if (Get-Command Update-EpsProPasskeyProgress -ErrorAction SilentlyContinue) { [void](Update-EpsProPasskeyProgress -ConnectionString $ConnectionString -Log $log -Version $version) }
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) & $log 'Info' $m })   # framework §12.27 SQL-STATS, warn-only
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); o = [int]$(if ($res) { $res.Users + $res.Devices } else { 0 }); p = [int]$(if ($res) { $res.Gaps } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = @p, Applied = 0 WHERE RunId = @id' | Out-Null
            if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "$($res.Users) users, $($res.Devices) devices, $($res.Gaps) open gap view(s)" } else { 'the report failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'SignInMethods') {
        # the per-user sign-in methods (EPS-SignInMethods.ps1, SecurityInsight's design): READ ONLY towards the tenant - reads
        # the users whose change key moved (privileged first), caches them per user; 8 minutes at most, the next run carries on
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'SignInMethods' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'SignInMethods', 'Preview', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            & $log 'Info' "$(if ($req) { "request $($req.RequestId) by $($req.RequestedBy)" } else { 'scheduled run' }) - read only (nothing in the tenant is changed)"
            $res = Invoke-EpsSignInMethodsFill -ConnectionString $ConnectionString -Log $log
            $ok = -not $res.Refused
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); o = [int]$(if ($res) { $res.Read + $res.Unknown } else { 0 }); a = [int]$(if ($res) { $res.Read } else { 0 }); f = [int]$(if ($res) { $res.Unknown } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = @o, Applied = @a, Failed = @f WHERE RunId = @id' | Out-Null
            if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "$($res.Read) user(s) read, $($res.Unknown) unknown; $($res.Stopped)" } else { 'the read failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    if ($Job -eq 'NamedLocations') {
        # V1-PARITY P8 (v1's EntraNamedLocations_AzureNetworkServiceTags.ps1, a daily VisualCron job): the Azure service tags
        # as IP named locations 'Azure.Network.ServiceTag.<tag>' - written only when a tag's prefixes changed (or its
        # location is missing), only those locations (EPS-OnboardWrite.ps1). Runs when NamedLocations.Enabled is on.
        $runId = [guid]::NewGuid()
        $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.RequestedBy
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = 'NamedLocations' AND q.Status = 'Dispatched'
'@)[0]
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId } -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope) VALUES (@id, 'NamedLocations', 'Apply', NULL)" | Out-Null
        $script:__seq = 0
        $log = { param($level, $msg) if (-not (Test-EpsLogLine -Level $script:__logLevel -Line $level)) { return }; $script:__seq++; Say "$level $msg"; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
        $ok = $false; $res = $null
        try {
            & $log 'Info' "$(if ($req) { "request $($req.RequestId) by $($req.RequestedBy)" } else { 'scheduled run' }) - the service-tag named locations"
            $res = Invoke-EpsServiceTagJob -ConnectionString $ConnectionString -Log $log
            $ok = -not $res.Failed
        } catch { & $log 'Error' "$($_.Exception.Message)" }
        finally {
            [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) & $log 'Info' $m })   # framework §12.27 SQL-STATS, warn-only
            $st = if ($ok) { 'Succeeded' } elseif ($res -and $res.Written) { 'PartlyFailed' } else { 'Failed' }
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $st; o = [int]$(if ($res) { $res.Tags } else { 0 }); p = [int]$(if ($res) { $res.Written + $res.Failed } else { 0 }); a = [int]$(if ($res) { $res.Written } else { 0 }); f = [int]$(if ($res) { $res.Failed } else { 0 }) } `
                -Query 'UPDATE eps.Run SET Status = @s, EndedAtUtc = SYSUTCDATETIME(), Objects = @o, Planned = @p, Applied = @a, Failed = @f WHERE RunId = @id' | Out-Null
            if ($req) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($res) { "$($res.Tags) tag(s): $($res.Written) written, $($res.Unchanged) unchanged, $($res.Failed) failed" } else { 'the job failed - see its log' }) } -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null }
        }
        exit $(if ($ok) { 0 } else { 1 })
    }
    $objectType = switch ($Job) { 'UserTagging' { 'User' } 'DeviceTagging' { 'Device' } default { $null } }
    if (-not $objectType) { Say "job '$Job' is not in this release"; exit 2 }

    # a request the tick dispatched for this job (Run now / preview / scoped test / an approved re-run), oldest first
    $runId = [guid]::NewGuid()
    $req = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ j = $Job; r = $runId } -Query @'
UPDATE TOP (1) q SET Status = 'Running', RunId = @r, UpdatedAtUtc = SYSUTCDATETIME(), SignedToken = NULL
OUTPUT INSERTED.RequestId, INSERTED.Mode, INSERTED.Scope, INSERTED.ApprovedBy, INSERTED.RequestedBy, DELETED.SignedToken, INSERTED.SignedVerifiedAtUtc
FROM eps.JobRequest q WITH (READPAST, UPDLOCK, ROWLOCK)
WHERE q.Job = @j AND q.Status = 'Dispatched' AND q.RequestedAtUtc = (SELECT MIN(RequestedAtUtc) FROM eps.JobRequest WHERE Job = @j AND Status = 'Dispatched')
'@)[0]
    if ($req) {
        # §12.11f: an Apply request changes the directory - the requester's signature first
        # TAG-TEST: a go live (one Apply on everyone) is a SuperAdmin's - the signer must still be one now
        $gate = Confirm-EpsJobRequest -Request $req -ConnectionString $ConnectionString -ChangesOutside:($req.Mode -eq 'Apply') -NeedRole $(if ("$($req.Scope)" -match '"GoLive"\s*:\s*true') { 'SuperAdmin' } else { 'Admin' })
        Say "request $($req.RequestId): $($gate.Text)"
        if (-not $gate.Allow) {
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; t = $gate.Text } -Query "UPDATE eps.JobRequest SET Status = 'Refused', StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id" | Out-Null
            exit 0
        }
        $mode = $req.Mode; $approved = $req.ApprovedBy
        $scope = if ($req.Scope) { $req.Scope | ConvertFrom-Json -AsHashtable }
        Say "request $($req.RequestId) by $($req.RequestedBy): $mode$(if ($scope) { ', scoped' })$(if ($approved) { ", approved by $approved" })"
    } else {
        $mode = [string](Get-EpsSetting -ConnectionString $ConnectionString -Name "$Job.Mode" -Default 'Preview')
        if ($mode -notin 'Preview', 'Apply') { Say "setting $Job.Mode = '$mode' is not Preview or Apply - running Preview"; $mode = 'Preview' }
        $approved = $null; $scope = $null
        Say "scheduled run: $mode"
    }
    $guard = @{}
    foreach ($k in (Get-EpsGuardDefaults).Keys) { $v = Get-EpsSetting -ConnectionString $ConnectionString -Name "$Job.Guard.$k" -Default $null; if ($null -ne $v) { $guard[$k] = [double]$v } }

    if (-not $req -and $env:EPS_TAG_TRIGGER -eq 'directory') {
        # the opt-in directory trigger (<Job>.RunOnDirectoryChange): only the objects that changed, in the job's mode
        if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name "$Job.RunOnDirectoryChange" -Default 'false')" -ne 'true') { Say 'directory trigger: switched off meanwhile - nothing to do'; exit 0 }
        $x = Invoke-EpsTagDirectoryCheck -ObjectType $objectType -Mode $mode -ConnectionString $ConnectionString -GuardSettings $guard
        Say "directory trigger ($mode): $($x.Action)$(if ($x.Changed) { " - $($x.Changed) changed object(s)" })$(if ($x.Run) { ", run $($x.Run.RunId) $($x.Run.Status): $($x.Run.Summary.Changes) change(s), applied $($x.Run.Applied)" })"
        exit 0
    }

    $ok = $false
    try {
        $r = Invoke-EpsTagJob -ObjectType $objectType -Mode $mode -ConnectionString $ConnectionString -Scope $scope -ApprovedBy $approved -GuardSettings $guard -RunId $runId
        $s = $r.Summary
        Say "run $($r.RunId): $($r.Status) - $($s.Objects) object(s), $($s.Changes) change(s), $($s.Overwrites) overwrite(s), applied $($r.Applied), failed $($r.Failed)"
        if ($r.HeldReason) { Say "HELD: $($r.HeldReason)" }
        if ($script:EpsLastGuardRecord) { Say "guard record: $($script:EpsLastGuardRecord | ConvertTo-Json -Compress -Depth 4)" }   # the uplink sends it (GUARD-1.2), not built yet
        $ok = $true
    } finally {
        [void](Invoke-EpsStatsRefresh -ConnectionString $ConnectionString -Log { param($m) Say $m })   # framework §12.27 SQL-STATS, warn-only
        if ($req) {
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $req.RequestId; s = $(if ($ok) { 'Done' } else { 'Failed' }); t = $(if ($ok) { "$($r.Status)" } else { 'the run failed - see its log' }) } `
                -Query 'UPDATE eps.JobRequest SET Status = @s, StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id' | Out-Null
        }
    }
    exit 0
} catch {
    Say "FAILED: $($_.Exception.Message)"
    exit 1
}
