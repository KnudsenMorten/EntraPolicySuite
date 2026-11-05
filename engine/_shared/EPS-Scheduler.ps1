# EntraPolicySuite -- the scheduler: the tick job (Container Apps Job, every 5 min) works out which recurring job is due
# and STARTS that job's own Container Apps Job (DESIGN §2, §4). The tick runs no job itself, so a long user tagging run
# never delays the tamper monitor.
#
#   converge the schedule rows -> requests ("Run now", previews, approved re-runs) -> due scheduled jobs
#   each start: enabled? implemented? not still running (overlap guard)? -> claim atomically -> ARM start
#
# Every tick is an eps.Run (Job = 'Tick') with its decisions, so "why did my job not run at 01:00?" has an answer.
# Dot-source EPS-SqlStore.ps1 and EPS-Graph.ps1 (Get-EpsToken, $script:EpsHttp) first.

Set-StrictMode -Off
$script:EpsAcaApi = '2024-03-01'   # pinned, as PIM: a floating api-version turns a platform change into a broken tick

function Get-EpsDefaultJobSchedule {
    # DESIGN §4: today's VisualCron jobs, de-duplicated. Implemented = this release has the job's code; the tick never
    # starts a job that is not (it says so in its run record).
    @(
        [pscustomobject]@{ Job = 'UserTagging';    Schedule = 'daily 01:00'; AcaJobName = 'caj-eps-usertag';   Implemented = $true }
        [pscustomobject]@{ Job = 'DeviceTagging';  Schedule = 'daily 01:30'; AcaJobName = 'caj-eps-devicetag'; Implemented = $true }
        [pscustomobject]@{ Job = 'IdentityReport'; Schedule = 'daily 02:00'; AcaJobName = 'caj-eps-idreport';  Implemented = $true }
        [pscustomobject]@{ Job = 'NamedLocations'; Schedule = 'daily 06:00'; AcaJobName = 'caj-eps-namedloc';  Implemented = $false }
        [pscustomobject]@{ Job = 'TamperMonitor';  Schedule = 'every 15m';   AcaJobName = 'caj-eps-tamper';    Implemented = $true }
        [pscustomobject]@{ Job = 'PolicyDeploy';   Schedule = 'manual';      AcaJobName = 'caj-eps-policy';    Implemented = $false }
        # the CA Policy Analyzer (DESIGN §5.7): manual - its MONITORS have their own schedules (eps.CaMonitor); Parallel =
        # several executions side by side, one per request / monitor (owner 2026-10-30), the overlap guard per monitor
        [pscustomobject]@{ Job = 'CAPolicyAnalyzer'; Schedule = 'manual';    AcaJobName = 'caj-eps-caanalyzer'; Implemented = $true; Parallel = $true }
        # SEC-AUDIT-1 S1: the engine applies every configuration change (signed requests from the web app); always on
        [pscustomobject]@{ Job = 'Config';         Schedule = 'manual';      AcaJobName = 'caj-eps-config';    Implemented = $true; AlwaysOn = $true }
        # UPLINK-1 (owner 2026-11-01 "Yes, identified only"): the Invardia heartbeat every 4 h (framework §8.4) + run and
        # alert records, from its OWN job and queue - not the tick, not a work job. Uplink.Enabled is ON by default but
        # INERT without the per-install key in the install's Key Vault (the job then sends nothing and says why)
        [pscustomobject]@{ Job = 'Uplink';         Schedule = 'every 4h';    AcaJobName = 'caj-eps-uplink';    Implemented = $true; EnabledDefault = $true }
        # UPDATER-1 phase 1 (owner 2026-11-04 "Yes, build it now"): every night, which release is approved for this install's
        # ring - CHECK ONLY: it reports, it installs nothing (EPS-Updater.ps1)
        [pscustomobject]@{ Job = 'Update';         Schedule = 'daily 03:00'; AcaJobName = 'caj-eps-update';    Implemented = $true; EnabledDefault = $true }
    )
}

function ConvertFrom-EpsSchedule {
    # 'daily 01:00' | 'weekly sun 19:00' | 'every 15m' | 'every 3h' | 'manual' -> @{ Kind; Hour; Minute; Day; Every }
    # (Every in minutes). Throws on anything else, so a typo is refused when the setting is saved, not discovered at 01:00.
    param([Parameter(Mandatory)][string]$Schedule)
    $s = $Schedule.Trim().ToLowerInvariant()
    if ($s -eq 'manual') { return @{ Kind = 'manual' } }
    if ($s -match '^every\s+(\d{1,3})h$') { $n = [int]$Matches[1]; if ($n -lt 1 -or $n -gt 168) { throw "'$Schedule': every 1h to every 168h" }; return @{ Kind = 'every'; Every = $n * 60 } }
    if ($s -match '^every\s+(\d{1,4})m$') { $n = [int]$Matches[1]; if ($n -lt 5) { throw "'$Schedule': the engine checks schedules every 5 minutes - at least 'every 5m'" }; return @{ Kind = 'every'; Every = $n } }
    if ($s -match '^daily\s+([01]\d|2[0-3]):([0-5]\d)$') { return @{ Kind = 'daily'; Hour = [int]$Matches[1]; Minute = [int]$Matches[2] } }
    if ($s -match '^weekly\s+(mon|tue|wed|thu|fri|sat|sun)\s+([01]\d|2[0-3]):([0-5]\d)$') {
        $d = @{ sun = 0; mon = 1; tue = 2; wed = 3; thu = 4; fri = 5; sat = 6 }[$Matches[1]]
        return @{ Kind = 'weekly'; Day = [DayOfWeek]$d; Hour = [int]$Matches[2]; Minute = [int]$Matches[3] }
    }
    throw "'$Schedule' is not a schedule: use 'daily HH:mm', 'weekly <mon..sun> HH:mm', 'every <N>m', 'every <N>h' or 'manual'"
}

function Test-EpsJobDue {
    <#
    .SYNOPSIS
        Is a job due at -NowUtc? Returns @{ Due; Reason; OccurrenceUtc }.
        A daily / weekly job is due once per occurrence, when it has not started since that occurrence and the
        occurrence is at most -CatchUpHours old (a tick that was down at 01:00 still runs it at 01:20, not two days later).
    #>
    param([Parameter(Mandatory)][string]$Schedule, [Parameter(Mandatory)][datetime]$NowUtc, $LastStartedUtc,
          [string]$TimeZone = 'UTC', [int]$CatchUpHours = 6)
    $p = ConvertFrom-EpsSchedule $Schedule
    $now = [datetime]::SpecifyKind($NowUtc, 'Utc')
    $last = if ($LastStartedUtc) { [datetime]::SpecifyKind([datetime]$LastStartedUtc, 'Utc') }
    switch ($p.Kind) {
        'manual' { return @{ Due = $false; Reason = 'manual (Run now only)' } }
        'every' {
            # 30 s of slack: a tick that fires a few seconds early must not push an every-15m job to 20 minutes
            if (-not $last -or ($now - $last).TotalSeconds -ge ($p.Every * 60 - 30)) { return @{ Due = $true; Reason = "every $($p.Every)m"; OccurrenceUtc = $now } }
            return @{ Due = $false; Reason = "every $($p.Every)m: last start $([math]::Round(($now - $last).TotalMinutes)) min ago" }
        }
    }
    $tz = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZone)
    $local = [TimeZoneInfo]::ConvertTimeFromUtc($now, $tz)
    $occ = [datetime]::new($local.Year, $local.Month, $local.Day, $p.Hour, $p.Minute, 0, [DateTimeKind]::Unspecified)
    if ($p.Kind -eq 'weekly') { while ($occ.DayOfWeek -ne $p.Day -or $occ -gt $local) { $occ = $occ.AddDays(-1) } }
    elseif ($occ -gt $local) { $occ = $occ.AddDays(-1) }
    $occUtc = [TimeZoneInfo]::ConvertTimeToUtc($occ, $tz)
    if ($last -and $last -ge $occUtc) { return @{ Due = $false; Reason = "already started for $($occ.ToString('yyyy-MM-dd HH:mm')) $TimeZone"; OccurrenceUtc = $occUtc } }
    if (($now - $occUtc).TotalHours -gt $CatchUpHours) { return @{ Due = $false; Reason = "missed $($occ.ToString('yyyy-MM-dd HH:mm')) by more than $CatchUpHours h - waits for the next"; OccurrenceUtc = $occUtc } }
    @{ Due = $true; Reason = "$Schedule ($($occ.ToString('yyyy-MM-dd HH:mm')) $TimeZone)"; OccurrenceUtc = $occUtc }
}

function Sync-EpsJobSchedule {
    # Adds the missing default rows (install, and after an update that brings a new job); never changes a row the
    # customer has (framework CONVERGE-DEFAULTS).
    param([Parameter(Mandatory)][string]$ConnectionString)
    $added = 0
    foreach ($d in Get-EpsDefaultJobSchedule) {
        $added += [int](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $d.Job; s = $d.Schedule; a = $d.AcaJobName } `
            -Query 'IF NOT EXISTS (SELECT 1 FROM eps.JobSchedule WHERE Job = @j) INSERT INTO eps.JobSchedule (Job, Schedule, AcaJobName) VALUES (@j, @s, @a)')
    }
    [math]::Max(0, $added)
}

function Start-EpsAcaJob {
    # ARM POST .../jobs/<name>/start. 409 = the job is still provisioning: a short wait, not a failure. Never throws:
    # returns @{ Ok; Execution; Reason } - a start that failed is recorded and retried by the next tick.
    # -Env: extra environment for THIS execution only (the CA Policy Analyzer: EPS_CA_MONITOR / EPS_REQUEST_ID, so several
    # executions of one job run side by side, each with its own parameters - owner 2026-10-30). The start API replaces the
    # container list, so the job's own containers are read first and the variables added to them.
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [int[]]$Waits = @(0, 10, 20), [hashtable]$Env)
    $base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$Name"
    $uri = "$base/start?api-version=$script:EpsAcaApi"
    $auth = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" }
    $body = '{}'
    if ($Env -and $Env.Count) {
        $job = try { & $script:EpsHttp 'GET' "$base`?api-version=$script:EpsAcaApi" $auth $null } catch { $null }
        if (-not $job -or $job.Status -ge 300) { return @{ Ok = $false; Execution = ''; Reason = "could not read job $Name to start it with its parameters: $(if ($job) { "ARM $($job.Status)" } else { 'no answer' })" } }
        $containers = @(($job.Body | ConvertFrom-Json -Depth 20).properties.template.containers)
        foreach ($c in $containers) {
            $e = [System.Collections.Generic.List[object]]::new(); foreach ($x in @($c.env)) { if ($x -and -not $Env.ContainsKey([string]$x.name)) { $e.Add($x) } }
            foreach ($k in $Env.Keys) { $e.Add([pscustomobject]@{ name = $k; value = [string]$Env[$k] }) }
            $c | Add-Member -NotePropertyName env -NotePropertyValue @($e) -Force
        }
        $body = @{ containers = $containers } | ConvertTo-Json -Depth 20 -Compress
    }
    $last = ''
    foreach ($w in $Waits) {
        if ($w) { Start-Sleep -Seconds $w }
        try {
            $r = & $script:EpsHttp 'POST' $uri $auth $body
        } catch { $last = "$($_.Exception.Message)"; continue }
        if ($r.Status -lt 300) { $e = try { ($r.Body | ConvertFrom-Json).name } catch { '' }; return @{ Ok = $true; Execution = "$e"; Reason = 'started' } }
        $last = "ARM $($r.Status): $(try { ($r.Body | ConvertFrom-Json).error.message } catch { $r.Body })"
        if ($r.Status -ne 409) { break }
    }
    @{ Ok = $false; Execution = ''; Reason = $last }
}

function Get-EpsJobQueueName {
    # caj-eps-usertag -> eps-usertag: one storage queue per work job (SEC-AUDIT-1 S4); a queue name is 3-63 lower-case
    param([Parameter(Mandatory)][string]$AcaJobName)
    $q = ($AcaJobName -replace '^caj-', '').ToLowerInvariant()
    if ($q -notmatch '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$') { throw "no queue name for job '$AcaJobName'" }
    $q
}

function Send-EpsJobMessage {
    <#
      SEC-AUDIT-1 S4 (2.0.9): the tick no longer STARTS a job through ARM - the start API takes a container override, so
      the start right let the tick identity run any command as the engine identity (proven live 2026-11-01). The tick
      puts one message on the job's own storage queue (Storage Queue Data Message Sender, nothing else); the job is
      event-triggered by that queue and reads the message itself. A message can only carry the per-run parameters the
      job accepts and checks (Read-EpsJobMessage). Never throws: @{ Ok; Execution; Reason } as Start-EpsAcaJob.
    #>
    param([Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][string]$AcaJobName, [hashtable]$Env)
    $q = Get-EpsJobQueueName $AcaJobName
    $payload = [ordered]@{ job = $AcaJobName; env = [ordered]@{} }
    if ($Env) { foreach ($k in $Env.Keys | Sort-Object) { $payload.env[$k] = [string]$Env[$k] } }
    $text = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
    $uri = "https://$StorageAccount.queue.core.windows.net/$q/messages?messagettl=86400"
    try {
        $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://storage.azure.com/')"; 'x-ms-version' = '2021-08-06'; 'Content-Type' = 'application/xml' }
        $r = & $script:EpsHttp 'POST' $uri $h "<QueueMessage><MessageText>$text</MessageText></QueueMessage>"
    } catch { return @{ Ok = $false; Execution = ''; Reason = "queue $q`: $($_.Exception.Message)" } }
    if ($r.Status -lt 300) { $id = if ("$($r.Body)" -match '<MessageId>([^<]+)</MessageId>') { "msg $($Matches[1])" } else { 'queued' }; return @{ Ok = $true; Execution = $id; Reason = 'queued' } }
    @{ Ok = $false; Execution = ''; Reason = "queue $q`: HTTP $($r.Status)" }
}

function Read-EpsJobMessage {
    <#
      The job's side (2.0.9): take ONE message from its own queue and delete it at once (KEDA starts an execution per
      message; a message left behind would start another). Returns $null when there is none (an execution KEDA started
      for a message another execution took - nothing to do), else the per-run parameters, CHECKED: only the names this
      job takes, each in its own shape (a tick identity that is not ours can at most ask for a normal run).
    #>
    param([Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][string]$AcaJobName)
    $q = Get-EpsJobQueueName $AcaJobName
    $base = "https://$StorageAccount.queue.core.windows.net/$q/messages"
    $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://storage.azure.com/')"; 'x-ms-version' = '2021-08-06' }
    $r = & $script:EpsHttp 'GET' "$base`?numofmessages=1&visibilitytimeout=300" $h $null
    if ($r.Status -ge 300) { throw "queue $q`: HTTP $($r.Status)" }
    $x = "$($r.Body)"
    if ($x -notmatch '<MessageId>([^<]+)</MessageId>') { return $null }
    $id = $Matches[1]
    $pop = if ($x -match '<PopReceipt>([^<]+)</PopReceipt>') { $Matches[1] } else { '' }
    $txt = if ($x -match '<MessageText>([^<]*)</MessageText>') { $Matches[1] } else { '' }
    $d = & $script:EpsHttp 'DELETE' "$base/$id`?popreceipt=$([uri]::EscapeDataString([System.Net.WebUtility]::HtmlDecode($pop)))" $h $null
    if ($d.Status -ge 300 -and $d.Status -ne 404) { throw "queue $q`: delete HTTP $($d.Status)" }
    $allowed = @{
        EPS_REQUEST_ID  = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        EPS_CA_MONITOR  = '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$'
        EPS_TAG_TRIGGER = '^directory$'
    }
    $out = @{}
    $m = try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($txt)) | ConvertFrom-Json -AsHashtable } catch { $null }
    if (-not $m -or "$($m.job)" -ne $AcaJobName) { return @{ Refused = "message $id is not a message for $AcaJobName - ignored, a normal run" } }
    foreach ($k in @($m.env.Keys)) {
        $v = [string]$m.env[$k]
        if (-not $allowed.ContainsKey($k) -or $v -notmatch $allowed[$k]) { return @{ Refused = "message $id carries a parameter this job does not take ($k) - refused" } }
        $out[$k] = $v
    }
    $out
}

function Get-EpsSetting {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, $Default)
    $v = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $Name } -Query 'SELECT Value FROM eps.Setting WHERE Name = @n'
    if ($null -eq $v -or "$v" -eq '') { $Default } else { $v }
}

function Invoke-EpsTick {
    <#
    .SYNOPSIS
        One tick. Returns the tick's run record with one decision per job / request.
    .PARAMETER Starter
        { param($AcaJobName) -> @{ Ok; Execution; Reason } }. Default: Send-EpsJobMessage to the job's queue (2.0.9; the
        tick holds no start right since 2.0.10 - Start-EpsAcaJob is only the INSTALLER's, for its verify run). Before:
        Start-EpsAcaJob in the install's subscription and
        resource group (EPS_SUBSCRIPTION_ID / EPS_RESOURCE_GROUP). A test passes its own.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Starter, [int]$RunLimitDays = 7)
    if (-not $Starter) {
        # 2.0.9 (SEC-AUDIT-1 S4): a message on the job's queue, never an ARM start (2.0.10: the tick has no start right)
        $sa = $env:EPS_STORAGE_ACCOUNT
        if (-not $sa) { throw 'the tick needs EPS_STORAGE_ACCOUNT (the job queues) - set by the install on the job' }
        $Starter = { param($name, $envs) Send-EpsJobMessage -StorageAccount $sa -AcaJobName $name -Env $envs }.GetNewClosure()
    }
    $runId = [guid]::NewGuid()
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; t = $NowUtc } -Query "INSERT INTO eps.Run (RunId, Job, Mode, StartedAtUtc) VALUES (@id, 'Tick', 'Apply', @t)" | Out-Null
    $decisions = [System.Collections.Generic.List[object]]::new()
    try {
        [void](Sync-EpsJobSchedule -ConnectionString $ConnectionString)
        $impl = @{}; $parallel = @{}; $alwaysOn = @{}; $enDef = @{}; foreach ($d in Get-EpsDefaultJobSchedule) { $impl[$d.Job] = $d.Implemented; $parallel[$d.Job] = [bool]$d.Parallel; $alwaysOn[$d.Job] = [bool]$d.AlwaysOn; $enDef[$d.Job] = [bool]$d.EnabledDefault }
        $tz = [string](Get-EpsSetting -ConnectionString $ConnectionString -Name 'Platform.TimeZone' -Default 'UTC')
        $master = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Platform.JobsEnabled' -Default 'true')" -eq 'true'
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT * FROM eps.JobSchedule')
        $byJob = @{}; foreach ($r in $rows) { $byJob[$r.Job] = $r }
        # UPD-HOLD (framework §8.18): an update waiting to install or installing goes FIRST - nothing new starts (requests wait,
        # never refused); it never blocks the update itself. Read once per check; a failed read = no hold (EPS-Updater.ps1).
        $updateHold = [bool]((Get-Command Test-EpsUpdateHold -ErrorAction SilentlyContinue) -and (Test-EpsUpdateHold -ConnectionString $ConnectionString))

        # a run still marked Running after the run limit is dead (framework JOB-RUN-LIMIT): closed, so it stops blocking
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $NowUtc.AddDays(-$RunLimitDays) } `
            -Query "UPDATE eps.Run SET Status = 'Failed', EndedAtUtc = SYSUTCDATETIME(), HeldReason = 'exceeded the run limit - closed by the engine' WHERE Status = 'Running' AND Job <> 'Tick' AND StartedAtUtc < @t" | Out-Null
        # a request the job took but never finished (the job crashed), while no run of that job is running: closed, so it
        # stops blocking the job (found live 2026-10-31: a crashed test mail held the tamper monitor back)
        # (the database's own clock: UpdatedAtUtc is written by it)
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery `
            -Query "UPDATE q SET Status = 'Failed', StatusText = 'the job ended without finishing this request - closed by the engine', UpdatedAtUtc = SYSUTCDATETIME() FROM eps.JobRequest q WHERE q.Status IN ('Dispatched', 'Running') AND q.UpdatedAtUtc < DATEADD(MINUTE, -60, SYSUTCDATETIME()) AND NOT EXISTS (SELECT 1 FROM eps.Run r WHERE r.Job = q.Job AND r.Status = 'Running')" | Out-Null

        $blocked = {
            param($job)
            $r = $byJob[$job]
            if (-not $r) { return 'no schedule row' }
            if (-not $impl[$job]) { return 'not in this release' }
            if ($updateHold -and $job -ne 'Update') { return 'an update is being installed (update hold) - starts when it is done' }
            if ($alwaysOn[$job]) { return $null }   # the Config job: configuration changes always get applied (SEC-AUDIT-1 S1)
            if (-not $master) { return 'all jobs are switched off (Platform.JobsEnabled)' }
            if (-not $r.Enabled) { return 'the job is switched off' }
            # every feature is off until the customer switches it on - except a job whose default is on (the uplink, inert without its key)
            if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name "$job.Enabled" -Default $(if ($enDef[$job]) { 'true' } else { 'false' }))" -ne 'true') { return "the feature is switched off ($job.Enabled)" }
            if ($parallel[$job]) { return $null }   # several executions side by side: the guard is per monitor (below)
            $running = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ j = $job } -Query "SELECT COUNT(*) FROM eps.Run WHERE Job = @j AND Status = 'Running'"
            $dispatched = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ j = $job } -Query "SELECT COUNT(RequestId) FROM eps.JobRequest WHERE Job = @j AND Status IN ('Dispatched', 'Running')"
            if ($running -or $dispatched) { return 'the previous run is still running (overlap guard)' }
            $null
        }
        $start = {
            param($job, $why, [bool]$fromRequest, [hashtable]$envs)
            $r = $byJob[$job]
            if ($parallel[$job]) {
                # a parallel job: no schedule-row claim (the request's own Pending -> Dispatched claim, or the monitor's,
                # decides); this execution gets its own parameters
                $res = & $Starter $r.AcaJobName $envs
                Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $job; s = "$(if ($res.Ok) { "started $($res.Execution)" } else { "start failed: $($res.Reason)" })" } -Query 'UPDATE eps.JobSchedule SET LastStartResult = @s WHERE Job = @j' | Out-Null
                return @{ Job = $job; Action = $(if ($res.Ok) { 'Started' } else { 'StartFailed' }); Reason = $(if ($res.Ok) { $why } else { $res.Reason }); Execution = $res.Execution }
            }
            # the claim: only one tick can move LastStartedUtc from the value it read
            $won = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $job; now = $NowUtc; old = $r.LastStartedUtc } `
                -Query 'UPDATE eps.JobSchedule SET LastStartedUtc = @now WHERE Job = @j AND ((LastStartedUtc IS NULL AND @old IS NULL) OR LastStartedUtc = @old)'
            if ($won -ne 1) { return @{ Job = $job; Action = 'Skipped'; Reason = 'another engine check claimed it' } }
            $res = & $Starter $r.AcaJobName
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $job; s = "$(if ($res.Ok) { "started $($res.Execution)" } else { "start failed: $($res.Reason)" })"; old = $r.LastStartedUtc; ok = [bool]$res.Ok } `
                -Query 'UPDATE eps.JobSchedule SET LastStartResult = @s, LastStartedUtc = CASE WHEN @ok = 1 THEN LastStartedUtc ELSE @old END WHERE Job = @j' | Out-Null
            @{ Job = $job; Action = $(if ($res.Ok) { 'Started' } else { 'StartFailed' }); Reason = $(if ($res.Ok) { $why } else { $res.Reason }); Execution = $res.Execution }
        }

        # 1. requests first: an admin is waiting for them
        $startedNow = @{}
        foreach ($q in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT RequestId, Job, Mode, RequestedBy FROM eps.JobRequest WHERE Status = 'Pending' ORDER BY RequestedAtUtc")) {
            if ($startedNow[$q.Job] -and -not $parallel[$q.Job]) {
                if ($alwaysOn[$q.Job]) {
                    # BULK-1 (owner 2026-11-02, 234 adopts at once - "the engine applies them, usually within a minute or
                    # two" was wrong: one request per 5-minute check = ~19 h): the Config job takes EVERY dispatched request
                    # in one execution (job-entry.ps1 loops until none is left), so the rest go with the run just started
                    $won = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId } -Query "UPDATE eps.JobRequest SET Status = 'Dispatched', UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id AND Status = 'Pending'"
                    $decisions.Add(@{ Job = $q.Job; Action = $(if ($won -eq 1) { 'Dispatched' } else { 'Skipped' }); Reason = $(if ($won -eq 1) { 'with the run started in this engine check' } else { 'another engine check took this request' }); RequestId = $q.RequestId })
                    continue
                }
                $decisions.Add(@{ Job = $q.Job; Action = 'Waiting'; Reason = 'an earlier request for this job was started in this engine check'; RequestId = $q.RequestId }); continue
            }
            $why = & $blocked $q.Job
            if ($why -and $why -notmatch 'overlap|update hold') {
                Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId; t = $why } -Query "UPDATE eps.JobRequest SET Status = 'Refused', StatusText = @t, UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id" | Out-Null
                $decisions.Add(@{ Job = $q.Job; Action = 'Refused'; Reason = $why; RequestId = $q.RequestId }); continue
            }
            if ($why) { $decisions.Add(@{ Job = $q.Job; Action = 'Waiting'; Reason = $why; RequestId = $q.RequestId }); continue }
            # the claim: Pending -> Dispatched only once, whichever tick gets there first
            $won = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId } -Query "UPDATE eps.JobRequest SET Status = 'Dispatched', UpdatedAtUtc = SYSUTCDATETIME() WHERE RequestId = @id AND Status = 'Pending'"
            if ($won -ne 1) { $decisions.Add(@{ Job = $q.Job; Action = 'Skipped'; Reason = 'another engine check took this request'; RequestId = $q.RequestId }); continue }
            $d = & $start $q.Job "request by $($q.RequestedBy) ($($q.Mode))" $true $(if ($parallel[$q.Job]) { @{ EPS_REQUEST_ID = "$($q.RequestId)" } })
            if ($d.Action -ne 'Started') { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $q.RequestId } -Query "UPDATE eps.JobRequest SET Status = 'Pending' WHERE RequestId = @id" | Out-Null }
            else { $startedNow[$q.Job] = $true; $byJob[$q.Job].LastStartedUtc = $NowUtc }
            $d.RequestId = $q.RequestId; $decisions.Add($d)
        }
        # 2. the scheduled jobs
        foreach ($r in $rows | Sort-Object Job) {
            if ($startedNow[$r.Job]) { continue }
            $due = try { Test-EpsJobDue -Schedule $r.Schedule -NowUtc $NowUtc -LastStartedUtc $r.LastStartedUtc -TimeZone $tz } catch { @{ Due = $false; Reason = "schedule error: $($_.Exception.Message)" } }
            if (-not $due.Due) { $decisions.Add(@{ Job = $r.Job; Action = 'NotDue'; Reason = $due.Reason }); continue }
            $why = & $blocked $r.Job
            if ($why) { $decisions.Add(@{ Job = $r.Job; Action = 'Skipped'; Reason = $why }); continue }
            $decisions.Add((& $start $r.Job $due.Reason $false))
        }
        # 2b. tag a changed user / device within minutes - OPT-IN (owner 2026-10-31: "chg in directory must not by default
        # trigger a run, as there are millions of chg"). The job reads a Graph delta of the rule properties and tags only
        # what changed; a check that finds nothing records no run. Never moves the schedule's LastStartedUtc.
        foreach ($job in 'UserTagging', 'DeviceTagging') {
            if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name "$job.RunOnDirectoryChange" -Default 'false')" -ne 'true') { continue }
            $label = "${job}:directory"
            if (@($decisions | Where-Object { $_.Job -eq $job -and $_.Action -eq 'Started' }).Count) { $decisions.Add(@{ Job = $label; Action = 'NotDue'; Reason = 'a full run of the job started in this engine check' }); continue }
            $why = & $blocked $job
            if ($why) { $decisions.Add(@{ Job = $label; Action = 'Skipped'; Reason = $why }); continue }
            $res = & $Starter $byJob[$job].AcaJobName @{ EPS_TAG_TRIGGER = 'directory' }
            $decisions.Add(@{ Job = $label; Action = $(if ($res.Ok) { 'Started' } else { 'StartFailed' }); Reason = $(if ($res.Ok) { 'directory changes (RunOnDirectoryChange)' } else { $res.Reason }); Execution = $res.Execution })
        }
        # 3. the CA Policy Analyzer's monitors: each its own schedule and its own execution (owner 2026-10-30: several, in
        # parallel, each with its own parameters); a monitor whose previous run is still running waits (guard per monitor)
        foreach ($mon in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Schedule, Enabled, LastStartedUtc FROM eps.CaMonitor WHERE Enabled = 1 ORDER BY Name')) {
            $label = "CAPolicyAnalyzer:$($mon.Name)"
            $due = try { Test-EpsJobDue -Schedule $mon.Schedule -NowUtc $NowUtc -LastStartedUtc $mon.LastStartedUtc -TimeZone $tz } catch { @{ Due = $false; Reason = "schedule error: $($_.Exception.Message)" } }
            if (-not $due.Due) { $decisions.Add(@{ Job = $label; Action = 'NotDue'; Reason = $due.Reason }); continue }
            $why = & $blocked 'CAPolicyAnalyzer'
            if (-not $why) {
                $scope = ([ordered]@{ monitor = [string]$mon.Name; request = $null } | ConvertTo-Json -Compress)   # the same text the job writes (job-entry)
                if ([int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ s = $scope } -Query "SELECT COUNT(*) FROM eps.Run WHERE Job = 'CAPolicyAnalyzer' AND Status = 'Running' AND Scope = @s")) { $why = 'its previous run is still running (overlap guard per monitor)' }
            }
            if ($why) { $decisions.Add(@{ Job = $label; Action = 'Skipped'; Reason = $why }); continue }
            $won = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $mon.Name; now = $NowUtc; old = $mon.LastStartedUtc } `
                -Query 'UPDATE eps.CaMonitor SET LastStartedUtc = @now WHERE Name = @n AND ((LastStartedUtc IS NULL AND @old IS NULL) OR LastStartedUtc = @old)'
            if ($won -ne 1) { $decisions.Add(@{ Job = $label; Action = 'Skipped'; Reason = 'another engine check claimed it' }); continue }
            $d = & $start 'CAPolicyAnalyzer' "monitor $($mon.Name): $($due.Reason)" $false @{ EPS_CA_MONITOR = [string]$mon.Name }
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $mon.Name; s = "$($d.Action): $($d.Reason)"; old = $mon.LastStartedUtc; ok = ($d.Action -eq 'Started') } `
                -Query 'UPDATE eps.CaMonitor SET LastStartResult = @s, LastStartedUtc = CASE WHEN @ok = 1 THEN LastStartedUtc ELSE @old END WHERE Name = @n' | Out-Null
            $d.Job = $label; $decisions.Add($d)
        }
        $failed = @($decisions | Where-Object { $_.Action -eq 'StartFailed' }).Count
        $status = if ($failed) { 'PartlyFailed' } else { 'Succeeded' }
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $status; j = ($decisions | ConvertTo-Json -Compress -Depth 4); n = @($decisions | Where-Object { $_.Action -eq 'Started' }).Count; f = $failed } `
            -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @s, SummaryJson = @j, Applied = @n, Failed = @f WHERE RunId = @id' | Out-Null
        [pscustomobject]@{ RunId = $runId; Status = $status; Decisions = @($decisions) }
    } catch {
        $e = "$($_.Exception.Message)"
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; e = $e } -Query "UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = 'Failed', HeldReason = @e WHERE RunId = @id" | Out-Null
        throw
    }
}
