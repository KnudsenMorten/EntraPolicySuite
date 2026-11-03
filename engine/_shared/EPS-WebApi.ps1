# EntraPolicySuite -- the web app's request handling (DESIGN §2): every request in, one response out. PURE of the
# listener: Start-EpsWeb.ps1 turns an HttpListener request into @{ Method; Path; Query; Headers; Body } and writes back
# what Invoke-EpsWebRequest returns - so the whole of it is tested offline with a fake request.
#
# The rules, in the order they apply:
#   1. /healthz is the only path without a caller (it says "ok", nothing else).
#   2. Every other request needs the sign-in front's access token, VERIFIED here (EPS-WebAuth) - pages and files too.
#      A refused token = 401 (with the running version, BRAND-2.11) and an audit row (throttled per reason).
#   3. A changing call (anything but GET) must carry the header X-EPS-Request: 1 with a JSON body and must not come from
#      another site (Sec-Fetch-Site) - a cross-site form or script cannot send that header without a CORS preflight this
#      app never answers (the anti-forgery check; stateless, so any number of replicas).
#   4. Roles: every route names the least role it needs (Reader < Admin < SuperAdmin; unnamed = Reader).
#   5. Routes are DATA: a route with an audit Action is audited by the dispatcher on success AND on failure - a changing
#      route without an Action fails the suite (AUDIT-1.5 item 2: coverage by construction).
#   6. One way (framework §12.11f): nothing here writes Entra, Exchange or AD, or starts a job. A change outside is a
#      JobRequest row carrying the caller's verified token; the engine verifies it again and acts.
#   7. An error answers 500 with a correlation id - never the exception text (it is logged, not shown).

Set-StrictMode -Off

$script:EpsWebAuditThrottle = @{}

function ConvertTo-EpsWebValue {
    # SQL rows -> JSON-ready: a datetime2 comes back Kind=Unspecified and IS UTC - say so ('Z'), the page shows local time
    param($Rows)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $o[$p.Name] = if ($p.Value -is [datetime]) { [datetime]::SpecifyKind($p.Value, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") } else { $p.Value } }
        [pscustomobject]$o
    }
}

function ConvertTo-EpsCsv {
    # the WHOLE result, invariant (BRAND-2.6), and safe in Excel: a cell that starts with = + - @ (or a tab / CR) is
    # prefixed with ' - directory values (a tag someone else wrote, an object name) are attacker-controlled text
    param($Rows, [string[]]$Columns)
    $esc = { param($v)
        $s = if ($null -eq $v) { '' } elseif ($v -is [datetime]) { [datetime]::SpecifyKind($v, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") } elseif ($v -is [IFormattable]) { $v.ToString($null, [Globalization.CultureInfo]::InvariantCulture) } else { "$v" }
        if ($s -match '^[=+\-@\t\r]') { $s = "'" + $s }
        '"' + $s.Replace('"', '""') + '"' }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(($Columns | ForEach-Object { & $esc $_ }) -join ',')
    foreach ($r in @($Rows)) { if ($null -ne $r) { $lines.Add(($Columns | ForEach-Object { & $esc $r.$_ }) -join ',') } }
    ($lines -join "`r`n") + "`r`n"
}

function Get-EpsWebPaging {
    param($Query)
    $page = [Math]::Max(1, [int]("$($Query.page)" -replace '\D', '' -replace '^$', '1'))
    $size = [Math]::Min(500, [Math]::Max(1, [int]("$($Query.pageSize)" -replace '\D', '' -replace '^$', '100')))
    @{ Page = $page; Size = $size; Skip = ($page - 1) * $size }
}

function New-EpsWebResponse { param([int]$Status = 200, $Body, [string]$ContentType = 'application/json; charset=utf-8', [hashtable]$Headers = @{}, $Audit) @{ Status = $Status; Body = $Body; ContentType = $ContentType; Headers = $Headers; Audit = $Audit } }
function New-EpsWebError { param([int]$Status, [string]$Message) New-EpsWebResponse -Status $Status -Body @{ error = $Message } }

function Get-EpsWebRoutes {
    # Method, Pattern (anchored; named groups become $m), Role, Action (audited when set), Handler { param($c, $m) }
    # $c = @{ Ctx; Caller; Role; Query; Body (parsed JSON); Correlation }. A handler returns New-EpsWebResponse.
    $cs = { $c.Ctx.ConnectionString }
    @(
        @{ Method = 'GET'; Pattern = '^/api/me$'; Summary = 'Who you are in this app: your name, your role, the version and the environment.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body ([ordered]@{ identity = $c.Caller.identity; name = $c.Caller.name; role = $c.Role; version = $c.Ctx.Version; edition = 'Community'
                environment = "$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name 'Platform.EnvironmentName' -Default '')"
                tenantName = "$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name 'Platform.TenantName' -Default '')"; tenantId = $c.Ctx.AuthConfig.TenantId
                noSuperAdmin = -not [int](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Query "SELECT COUNT(*) FROM eps.WebAccess WHERE Role = 'SuperAdmin'") }) } }
        # the API reference (framework APIDOC-1): generated from THIS table, for the version that runs, filtered to the
        # caller's role; no SQL beyond the role lookup the dispatcher already did
        @{ Method = 'GET'; Pattern = '^/api/reference$'; Summary = 'This API reference for the version that runs, with the routes your role may call.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m) New-EpsWebResponse -Body (Get-EpsApiReference -Audience Full -Role $c.Role -Version $c.Ctx.Version) } }
        @{ Method = 'GET'; Pattern = '^/api/version$'; Summary = 'The version that runs.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m) New-EpsWebResponse -Body @{ version = $c.Ctx.Version } } }
        @{ Method = 'GET'; Pattern = '^/api/overview$'; Summary = 'The overview page: enabled rules, open tamper events, open requests, queued work, the last run of each job, the hybrid workers and the Invardia telemetry state.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $q = { param($sql) Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Query $sql }
            # UPLINK-1: the support state Invardia answered to the heartbeat (SECAUDIT-1a) - shown, nothing is granted from it
            $sup = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT TOP (1) State, AccessLevel, Reason, TicketNumber, OpenedBy, MaxUntilUtc, ReceivedAtUtc, LastSeenUtc, CAST(CASE WHEN State = ''open'' AND MaxUntilUtc > SYSUTCDATETIME() THEN 1 ELSE 0 END AS BIT) AS Active FROM eps.SupportEvent ORDER BY SupportEventId DESC'))[0]
            $ul = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query "SELECT Name, Value FROM eps.UplinkState WHERE Name IN ('last', 'heartbeat')")) { $ul["$($r.Name)"] = $(if ($r.Value -is [DBNull]) { $null } else { "$($r.Value)" }) }
            New-EpsWebResponse -Body ([ordered]@{
                userRules = & $q 'SELECT COUNT(*) FROM eps.UserTagRule WHERE Enabled = 1'; deviceRules = & $q 'SELECT COUNT(*) FROM eps.DeviceTagRule WHERE Enabled = 1'
                tamperOpen = & $q "SELECT COUNT(*) FROM eps.TamperEvent WHERE Status = 'Open'"; tamperOpenHigh = & $q "SELECT COUNT(*) FROM eps.TamperEvent WHERE Status = 'Open' AND Severity = 'High'"
                requestsOpen = & $q "SELECT COUNT(*) FROM eps.JobRequest WHERE Status IN ('Pending', 'Dispatched', 'Running')"
                workPackagesQueued = & $q "SELECT COUNT(*) FROM eps.WorkPackage WHERE Status IN ('Queued', 'Claimed')"
                schemaVersion = & $q 'SELECT MAX(Version) FROM eps.SchemaVersion'
                lastRuns = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT r.Job, r.RunId, r.Mode, r.Status, r.StartedAtUtc, r.EndedAtUtc, r.Objects, r.Planned, r.Applied, r.Failed, r.HeldReason FROM eps.Run r WHERE r.StartedAtUtc = (SELECT MAX(StartedAtUtc) FROM eps.Run x WHERE x.Job = r.Job) ORDER BY r.Job'))
                workers = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT WorkerName, Machine, Version, LastSeenUtc, LastResult FROM eps.WorkerHeartbeat ORDER BY WorkerName'))
                uplink = @{ last = $ul.last; heartbeatUtc = $ul.heartbeat }
                support = $sup
            }) } }
        @{ Method = 'GET'; Pattern = '^/api/runs$'; Summary = 'The job runs, newest first, one page at a time.'; Body = 'job, status: filters; page, pageSize (at most 500)'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $pg = Get-EpsWebPaging $c.Query
            $w = 'WHERE (@j = '''' OR Job = @j) AND (@s = '''' OR Status = @s)'
            $p = @{ j = "$($c.Query.job)"; s = "$($c.Query.status)"; k = $pg.Skip; n = $pg.Size }
            New-EpsWebResponse -Body @{ total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $p -Query "SELECT COUNT(*) FROM eps.Run $w"
                rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query "SELECT RunId, Job, Mode, Status, StartedAtUtc, EndedAtUtc, Objects, Planned, Overwrites, Applied, Failed, Skipped, HeldReason, ApprovedBy FROM eps.Run $w ORDER BY StartedAtUtc DESC OFFSET @k ROWS FETCH NEXT @n ROWS ONLY")) } } }
        @{ Method = 'GET'; Pattern = '^/api/runs/(?<id>[0-9a-fA-F-]{36})$'; Summary = 'One run: its counts, its log and its tag changes by status.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $p = @{ id = [guid]$m.id }
            $run = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query 'SELECT * FROM eps.Run WHERE RunId = @id'))[0]
            if (-not $run) { return New-EpsWebError 404 'no such run' }
            New-EpsWebResponse -Body @{ run = $run
                log = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query 'SELECT TOP (5000) Seq, AtUtc, Level, Message FROM eps.RunLog WHERE RunId = @id ORDER BY Seq'))
                changes = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query 'SELECT Status, COUNT(*) AS Count FROM eps.TagChange WHERE RunId = @id GROUP BY Status') } } }
        @{ Method = 'GET'; Pattern = '^/api/changes$'; Summary = 'The tag changes the jobs made or planned, newest first, one page at a time.'; Body = 'runId, status, q (search in name, values and persona); page, pageSize'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $pg = Get-EpsWebPaging $c.Query; $f = Get-EpsWebChangeFilter $c.Query; $f.P.k = $pg.Skip; $f.P.n = $pg.Size
            New-EpsWebResponse -Body @{ total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $f.P -Query "SELECT COUNT(*) FROM eps.TagChange $($f.Where)"
                rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $f.P -Query "SELECT ChangeId, RunId, AtUtc, ObjectType, ObjectName, ObjectId, Directory, TagType, Attribute, OldValue, NewValue, Reason, Persona, Status, Via, Error FROM eps.TagChange $($f.Where) ORDER BY ChangeId DESC OFFSET @k ROWS FETCH NEXT @n ROWS ONLY")) } } }
        @{ Method = 'GET'; Pattern = '^/api/changes/export$'; Summary = 'The tag changes that match the filter as a CSV file (at most 200,000 rows).'; Body = 'runId, status, q'; Public = $true
           Role = 'Reader'; Action = 'changes.export'; Handler = { param($c, $m)
            $f = Get-EpsWebChangeFilter $c.Query; $cols = 'ChangeId', 'RunId', 'AtUtc', 'ObjectType', 'ObjectName', 'ObjectId', 'Directory', 'TagType', 'Attribute', 'OldValue', 'NewValue', 'Reason', 'Persona', 'Status', 'Via', 'Error'
            $rows = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $f.P -Query "SELECT TOP (200001) $($cols -join ', ') FROM eps.TagChange $($f.Where) ORDER BY ChangeId DESC")
            if ($rows.Count -gt 200000) { return New-EpsWebResponse -Status 413 -Body @{ error = 'more than 200,000 changes - narrow the filter' } -Audit @{ Target = 'TagChange'; Outcome = 'refused'; OutcomeText = 'over 200,000 rows' } }   # SEC-AUDIT-1 S9
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $rows -Columns $cols) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = 'attachment; filename="eps-tag-changes.csv"' } `
                -Audit @{ Target = 'TagChange'; After = @{ filter = $f.Echo; rows = $rows.Count } } } }
        @{ Method = 'GET'; Pattern = '^/api/tamper$'; Summary = 'The tamper events: tag values changed outside EntraPolicySuite.'; Body = 'status: one state, e.g. Open'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $p = @{ s = "$($c.Query.status)" }
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query "SELECT TOP (2000) EventId, FoundAtUtc, ObjectType, ObjectName, ObjectId, TagType, Attribute, OldValue, NewValue, Severity, Initiator, InitiatorKind, FoundBy, Detail, Status, ResolvedBy, ResolvedAtUtc, AlertedAtUtc FROM eps.TamperEvent WHERE (@s = '' OR Status = @s) ORDER BY FoundAtUtc DESC")) } } }
        @{ Method = 'POST'; Pattern = '^/api/tamper/(?<id>\d+)/accept$'; Summary = 'Accept an open tamper event: the new value stays.'; Public = $true
           Role = 'Admin'; Action = 'tamper.event.accept'; NeedsReason = $true; Handler = { param($c, $m)
            $id = [long]$m.id
            $before = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ id = $id } -Query 'SELECT EventId, Status, ObjectName, Attribute, OldValue, NewValue FROM eps.TamperEvent WHERE EventId = @id')[0]
            if (-not $before) { return New-EpsWebError 404 'no such event' }
            if ($before.Status -ne 'Open') { return New-EpsWebResponse -Status 409 -Body @{ error = "the event is $($before.Status), not Open" } -Audit @{ Target = "TamperEvent|$id"; Outcome = 'refused'; OutcomeText = "not Open ($($before.Status))" } }
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters @{ id = $id; by = $c.Caller.identity } -Query "UPDATE eps.TamperEvent SET Status = 'Accepted', ResolvedBy = @by, ResolvedAtUtc = SYSUTCDATETIME() WHERE EventId = @id AND Status = 'Open'")
            New-EpsWebResponse -Body @{ ok = $true } -Audit @{ Target = "TamperEvent|$id ($($before.ObjectName) $($before.Attribute))"; Before = $before; After = @{ Status = 'Accepted' } } } }
        @{ Method = 'POST'; Pattern = '^/api/tamper/(?<id>\d+)/restore$'; Summary = 'Ask the engine to write the earlier value back for an open tamper event (at its next run).'; Public = $false
           Role = 'Admin'; Action = 'tamper.event.restore.request'; NeedsReason = $true; Handler = { param($c, $m)
            $id = [long]$m.id
            $ev = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ id = $id } -Query 'SELECT EventId, Status, ObjectName, Attribute FROM eps.TamperEvent WHERE EventId = @id')[0]
            if (-not $ev) { return New-EpsWebError 404 'no such event' }
            if ($ev.Status -ne 'Open') { return New-EpsWebResponse -Status 409 -Body @{ error = "the event is $($ev.Status), not Open" } -Audit @{ Target = "TamperEvent|$id"; Outcome = 'refused'; OutcomeText = "not Open ($($ev.Status))" } }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job 'TamperMonitor' -Mode 'Apply' -Scope @{ restore = @($id) }
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = 'The engine restores the value at its next run (within 15 minutes).' } -Audit @{ Target = "TamperEvent|$id ($($ev.ObjectName) $($ev.Attribute))"; After = @{ requestId = $rq } } } }
        @{ Method = 'GET'; Pattern = '^/api/jobs$'; Summary = 'The jobs with their schedule, on / off and last run, and the latest 200 job requests.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $impl = @{}; foreach ($d in Get-EpsDefaultJobSchedule) { $impl[$d.Job] = [bool]$d.Implemented }
            $rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT s.Job, s.Schedule, s.Enabled, s.LastStartedUtc, s.LastStartResult, r.Status AS LastStatus, r.StartedAtUtc AS LastRunUtc FROM eps.JobSchedule s OUTER APPLY (SELECT TOP (1) Status, StartedAtUtc FROM eps.Run WHERE Job = s.Job ORDER BY StartedAtUtc DESC) r ORDER BY s.Job'))
            foreach ($r in $rows) { $r | Add-Member -NotePropertyName Implemented -NotePropertyValue ([bool]$impl[$r.Job]) }
            New-EpsWebResponse -Body @{ rows = $rows
                requests = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT TOP (200) RequestId, Job, Mode, RequestedBy, RequestedAtUtc, Status, StatusText, RunId, Reason FROM eps.JobRequest ORDER BY RequestedAtUtc DESC')) } } }
        @{ Method = 'POST'; Pattern = '^/api/jobs/(?<job>[A-Za-z]{2,40})/run$'; Summary = 'Request a job run now: Preview (plan only, nothing written) or Apply. A tagging job takes an optional test scope.'; Body = 'mode: Preview or Apply; scopeName: a saved scope, or scope: a scope given now (tagging jobs only)'; Public = $true
           Role = 'Admin'; Action = 'job.run.request'; NeedsReason = $true; Handler = { param($c, $m)
            $def = @(Get-EpsDefaultJobSchedule | Where-Object { $_.Job -eq $m.job })[0]
            if ($def.Job -eq 'CAPolicyAnalyzer') { return New-EpsWebResponse -Status 400 -Body @{ error = 'the CA Policy Analyzer is started from its own page (Analyse now / a monitor)' } -Audit @{ Target = 'Job|CAPolicyAnalyzer'; Outcome = 'refused'; OutcomeText = 'use the analyzer page' } }
            if (-not $def -or -not $def.Implemented) { return New-EpsWebResponse -Status 400 -Body @{ error = "no job '$($m.job)' in this release" } -Audit @{ Target = "Job|$($m.job)"; Outcome = 'refused'; OutcomeText = 'unknown or not implemented job' } }
            $mode = "$($c.Body.mode)"
            if ($mode -notin 'Preview', 'Apply') { return New-EpsWebResponse -Status 400 -Body @{ error = 'mode must be Preview or Apply' } -Audit @{ Target = "Job|$($m.job)"; Outcome = 'refused'; OutcomeText = "mode '$mode'" } }
            # a test scope (DESIGN §5.8: "apply on a test scope"): given here, or a saved one by name; none = everyone
            $scope = $null; $sot = @{ UserTagging = 'User'; DeviceTagging = 'Device' }[$def.Job]
            if ($c.Body.scopeName -or $c.Body.scope) {
                if (-not $sot) { return New-EpsWebResponse -Status 400 -Body @{ error = "$($def.Job) runs on everything it watches - it has no scope" } -Audit @{ Target = "Job|$($def.Job)"; Outcome = 'refused'; OutcomeText = 'scope on a job without one' } }
                $body = $c.Body.scope
                if ($c.Body.scopeName) {
                    $sv = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ n = "$($c.Body.scopeName)" } -Query 'SELECT ObjectType, Definition FROM eps.Scope WHERE Name = @n')[0]
                    if (-not $sv -or $sv.ObjectType -ne $sot) { return New-EpsWebResponse -Status 400 -Body @{ error = "no saved $($sot.ToLowerInvariant()) scope '$($c.Body.scopeName)'" } -Audit @{ Target = "Job|$($def.Job)"; Outcome = 'refused'; OutcomeText = 'unknown scope' } }
                    $d = $sv.Definition | ConvertFrom-Json; $body = [pscustomobject]@{ kind = $d.Kind; values = $d.Values; property = $d.Property; pattern = $d.Pattern }
                }
                $sc = ConvertTo-EpsScope -ObjectType $sot -Body $body
                if (-not $sc.Ok) { return New-EpsWebResponse -Status 400 -Body @{ error = $sc.Error } -Audit @{ Target = "Job|$($def.Job)"; Outcome = 'refused'; OutcomeText = $sc.Error } }
                $scope = $sc.Scope
            }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job $def.Job -Mode $mode -Scope $scope
            $on = if ($scope) { if ($scope.Kind -eq 'Objects') { " on $($scope.Values.Count) named object(s)" } else { " on $($scope.Property) like $($scope.Pattern)" } } else { ' on everyone' }
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = "Requested: the scheduler starts $($def.Job) ($mode$on) within 5 minutes." } -Audit @{ Target = "Job|$($def.Job)"; After = @{ requestId = $rq; mode = $mode; scope = $scope }; WhatIf = ($mode -eq 'Preview') } } }
        # a job's schedule and on / off (DESIGN §4 "every schedule is a setting the customer can change in the GUI";
        # owner 2026-10-31 TAG-TRIGGER: "i must be able to configure this in the patform for both users + device tagging")
        @{ Method = 'PUT'; Pattern = '^/api/jobs/(?<job>[A-Za-z]{2,40})/schedule$'; Summary = 'Change the schedule of a job and switch it on or off.'; Body = 'schedule: daily 01:00, weekly sun 19:00, every 3h, every 15m or manual; enabled: true / false'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'job.schedule.change'; NeedsReason = $true; Handler = { param($c, $m)
            $def = @(Get-EpsDefaultJobSchedule | Where-Object { $_.Job -eq $m.job })[0]
            $t = "JobSchedule|$($m.job)"
            if (-not $def) { return New-EpsWebResponse -Status 404 -Body @{ error = "no job '$($m.job)'" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'unknown job' } }
            if ($def.Job -eq 'CAPolicyAnalyzer') { return New-EpsWebResponse -Status 400 -Body @{ error = 'the CA Policy Analyzer has no schedule of its own: its monitors do (CA Policy Analyzer page)' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'use the monitors' } }
            $sch = "$($c.Body.schedule)".Trim()
            try { [void](ConvertFrom-EpsSchedule -Schedule $sch) } catch { return New-EpsWebResponse -Status 400 -Body @{ error = "$($_.Exception.Message)" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "schedule '$sch'" } }
            if ($null -eq $c.Body.enabled) { return New-EpsWebResponse -Status 400 -Body @{ error = 'enabled (true / false) is required' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'enabled missing' } }
            $en = [bool]$c.Body.enabled
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ j = $def.Job } -Query 'SELECT Schedule, Enabled FROM eps.JobSchedule WHERE Job = @j')[0]
            if (-not $cur) { return New-EpsWebResponse -Status 409 -Body @{ error = 'the job has no schedule row yet - the engine creates it at its next check (within 5 minutes)' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'no row yet' } }
            $before = @{ schedule = [string]$cur.Schedule; enabled = [bool]$cur.Enabled } | ConvertTo-Json -Compress
            $after = @{ schedule = $sch; enabled = $en } | ConvertTo-Json -Compress
            $p = @{ j = $def.Job; s = $sch; e = $en } + (New-EpsJournalParameters -Actor $c.Caller.identity -Entity 'JobSchedule' -Key $def.Job -Action 'Update' -Before $before -After $after)
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; UPDATE eps.JobSchedule SET Schedule = @s, Enabled = @e, UpdatedAtUtc = SYSUTCDATETIME() WHERE Job = @j; $(Get-EpsJournalSql) COMMIT;")
            New-EpsWebResponse -Body @{ ok = $true; text = "$($def.Job): $(if ($en) { "runs $sch from the engine's next check (within 5 minutes)" } else { 'switched off - the schedule no longer starts it (Run now still works)' })." } -Audit @{ Target = $t; Before = ($before | ConvertFrom-Json); After = ($after | ConvertFrom-Json) } } }
        # ---- rules (DESIGN §5.9): one card per rule; a broken reference refuses the save, everything else is a hint ----
        @{ Method = 'GET'; Pattern = '^/api/rules$'; Summary = 'The tagging rules of one object type as cards, with their hints, how many objects each rule decided in the last run, the tag types and the condition types.'; Body = 'objectType: User (default) or Device'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $ot = if ("$($c.Query.objectType)" -eq 'Device') { 'Device' } else { 'User' }
            $x = Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString
            $cards = @(Read-EpsRuleCardsForEdit -ConnectionString $c.Ctx.ConnectionString -ObjectType $ot)
            $hints = @(Get-EpsRuleHints -Cards $cards -Catalog $x.Catalog -TagTypes $x.TagTypes) + @(Get-EpsRuleShadowHints -Cards $cards -TagTypes $x.TagTypes)
            $byRule = $hints | Group-Object { "$($_.RuleId)" } -AsHashTable -AsString
            $job = if ($ot -eq 'User') { 'UserTagging' } else { 'DeviceTagging' }
            # "Matched" (RULES-UX, owner 2026-10-31 "love it"): the objects each rule decided in the last run on everyone
            $last = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ j = $job } -Query "SELECT TOP 1 RunId, Mode, StartedAtUtc, SummaryJson FROM eps.Run WHERE Job = @j AND Scope IS NULL AND Status IN ('Succeeded', 'PartlyFailed', 'Held') AND SummaryJson LIKE '%`"Matched`"%' ORDER BY StartedAtUtc DESC")[0]
            $matched = if ($last) { try { ($last.SummaryJson | ConvertFrom-Json).Matched } catch { $null } }
            $rows = foreach ($k in $cards) {
                $o = [ordered]@{}; foreach ($n in $k.Keys) { $o[$n] = $k[$n] }; $o.UpdatedAtUtc = ConvertTo-EpsWebTime $k.UpdatedAtUtc
                $o.Matched = if ($matched) { [int]($matched."$($k.RuleId)") } else { $null }
                $o.Hints = @(if ($byRule -and $byRule["$($k.RuleId)"]) { $byRule["$($k.RuleId)"] | ForEach-Object { [ordered]@{ code = $_.Code; text = $_.Text } } }); $o }
            New-EpsWebResponse -Body @{ objectType = $ot; rows = @($rows); ruleSet = 'default'; queueOn = (Test-EpsCommitQueueOn -ConnectionString $c.Ctx.ConnectionString)
                matchedRun =$(if ($matched) { [ordered]@{ runId = "$($last.RunId)"; mode = $last.Mode; startedAtUtc = (ConvertTo-EpsWebTime $last.StartedAtUtc) } })
                tagTypes = @(foreach ($t in @($x.TagTypes.Values | Where-Object ObjectType -eq $ot | Sort-Object Name)) { [ordered]@{ name = $t.Name; enabled = [bool]$t.Enabled; valueMode = $t.ValueMode; attribute = $t.Attribute
                    values = @($x.Values["${ot}:$($t.Name)"] | Where-Object { $_ } | ForEach-Object { [ordered]@{ value = $_.Value; isPattern = [bool]$_.IsPattern; description = $_.Description } }) } })
                conditionTypes = @(foreach ($d in @($x.Catalog.Values | Where-Object ObjectType -eq $ot | Sort-Object Id)) { [ordered]@{ id = $d.Id; description = $d.Description; kind = $d.Kind; operator = $d.Operator; shipped = [bool]$d.Shipped; modifiesValue = [bool]$d.ModifiesValue } })
                featureEnabled = "$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name "$job.Enabled" -Default 'false')" -eq 'true' } } }
        # "Try on a user / device" (RULES-UX, owner 2026-10-31 "love it"): a PREVIEW of that one object that records the
        # whole decision - which rule won per tag type, and why the others did not. The engine reads the object (the web
        # app has no Graph right), so the answer comes with the next tick; nothing is written.
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)/try$'; Summary = 'Try the rules on one user or device: a preview that records the whole decision. Nothing is written.'; Body = 'object: one UPN, display name or object id'; Public = $true
           Role = 'Admin'; Action = 'job.run.request'; Handler = { param($c, $m)
            $who = "$($c.Body.object)".Trim()
            if ($who -notmatch '^[^\s''"<>]{1,320}$') { return New-EpsWebResponse -Status 400 -Body @{ error = 'give one UPN, display name or object id' } -Audit @{ Target = "Try|$($m.ot)"; Outcome = 'refused'; OutcomeText = 'no object' } }
            $job = if ($m.ot -eq 'User') { 'UserTagging' } else { 'DeviceTagging' }
            if ("$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name "$job.Enabled" -Default 'false')" -ne 'true') { return New-EpsWebResponse -Status 400 -Body @{ error = "$job is switched off (Settings)" } -Audit @{ Target = "Try|$who"; Outcome = 'refused'; OutcomeText = 'feature off' } }
            if (-not "$($c.Body.reason)".Trim()) { $c.Body | Add-Member -NotePropertyName reason -NotePropertyValue "try the rules on $who" -Force }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job $job -Mode 'Preview' -Scope @{ Kind = 'Objects'; Values = @($who); Trace = $true }
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = "Trying the rules on $who - the answer comes within 5 minutes (a preview: nothing is written)." } -Audit @{ Target = "Try|$who"; After = @{ requestId = $rq }; WhatIf = $true } } }
        # a request's state - the page follows a queued configuration change until the engine has applied it (SEC-AUDIT-1 S1)
        # BULK-1: the page follows a bulk change with ONE call per round (owner 2026-11-02: 234 adopts at once - one call per
        # request every 5 s was ~47 calls a second)
        @{ Method = 'GET'; Pattern = '^/api/requests/mine$'; Summary = 'Your own requests since a time (since = ISO 8601, UTC): the state of each, at most 2,000.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $since = [datetime]::MinValue
            if (-not [datetime]::TryParse("$($c.Query.since)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$since)) { return New-EpsWebError 400 'since: a time (ISO 8601, UTC)' }
            $rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ by = "$($c.Caller.identity)"; s = $since } -Query 'SELECT TOP (2000) RequestId, Job, Status, StatusText, RequestedAtUtc, UpdatedAtUtc FROM eps.JobRequest WHERE RequestedBy = @by AND RequestedAtUtc >= @s ORDER BY RequestedAtUtc'))
            New-EpsWebResponse -Body @{ rows = $rows } } }
        @{ Method = 'GET'; Pattern = '^/api/requests/(?<rid>[0-9a-fA-F-]{36})$'; Summary = 'The state of one request: queued, running, done, failed or refused, with its result text.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $q = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ id = [guid]$m.rid } -Query 'SELECT RequestId, Job, Status, StatusText, RequestedBy, RequestedAtUtc, UpdatedAtUtc FROM eps.JobRequest WHERE RequestId = @id'))[0]
            if (-not $q) { return New-EpsWebError 404 'no such request' }
            New-EpsWebResponse -Body $q } }
        @{ Method = 'GET'; Pattern = '^/api/rules/try/(?<rid>[0-9a-fA-F-]{36})$'; Summary = 'The answer to a Try: the decision per tag type and the changes it would make.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $q = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ id = [guid]$m.rid } -Query 'SELECT q.Status, q.StatusText, q.RunId, r.SummaryJson FROM eps.JobRequest q LEFT JOIN eps.Run r ON r.RunId = q.RunId WHERE q.RequestId = @id')[0]
            if (-not $q) { return New-EpsWebError 404 'no such request' }
            $traces = if ($q.SummaryJson -is [string]) { try { @(($q.SummaryJson | ConvertFrom-Json).Traces) } catch { @() } } else { @() }
            $changes = if ($q.RunId -isnot [DBNull] -and $q.RunId) { @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ r = $q.RunId } -Query 'SELECT ObjectName, TagType, Attribute, OldValue, NewValue, Reason, Persona FROM eps.TagChange WHERE RunId = @r')) } else { @() }
            New-EpsWebResponse -Body @{ status = [string]$q.Status; statusText = [string]$q.StatusText; done = ([string]$q.Status -in 'Done', 'Failed', 'Refused'); traces = @($traces | Where-Object { $_ }); changes = $changes } } }
        @{ Method = 'GET'; Pattern = '^/api/rules/(?<ot>User|Device)/deleted$'; Summary = 'The latest deleted rules (to put one back).'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Get-EpsConfigHistory -ConnectionString $c.Ctx.ConnectionString -Entity (Get-EpsRuleTable $m.ot) -Top 500 | Where-Object Action -eq 'Delete' | Select-Object -First 50)) } } }
        @{ Method = 'GET'; Pattern = '^/api/rules/(?<ot>User|Device)/(?<id>\d{1,9})/history$'; Summary = 'The change history of one rule.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Get-EpsConfigHistory -ConnectionString $c.Ctx.ConnectionString -Entity (Get-EpsRuleTable $m.ot) -Key $m.id)) } } }
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)$'; Summary = 'Create a rule.'; Body = 'tagType; enabled; notes; conditions: [ { conditionType, target } ]; users: persona, tagValueAD, tagValueCloud; devices: tagValue; insertAfter: the rule to put it after'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'rule.create'; NeedsReason = $true
           Stage = { param($c, $m)
            $v = ConvertTo-EpsRuleCard -ObjectType $m.ot -Body $c.Body -Context (Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString)
            if (-not $v.Ok) { return @{ Refusal = (New-EpsWebRuleRefusal -Target "$($m.ot)TagRule|new" -Errors $v.Errors) } }
            @{ ObjectType = $m.ot; Entity = "$($m.ot)TagRule"; Key = "new:$([guid]::NewGuid().ToString('N'))"; Op = 'Create'; Summary = "New $($m.ot.ToLowerInvariant()) rule: $(Get-EpsRuleCardText $v.Card)" } }
           Handler = { param($c, $m)
            $x = Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString
            $v = ConvertTo-EpsRuleCard -ObjectType $m.ot -Body $c.Body -Context $x
            if (-not $v.Ok) { return New-EpsWebRuleRefusal -Target "$($m.ot)TagRule|new" -Errors $v.Errors }
            $s = Save-EpsRuleCard -ConnectionString $c.Ctx.ConnectionString -Card $v.Card -InsertAfter ([int]((("$($c.Body.insertAfter)" -replace '\D', '') -replace '^$', '0'))) -Actor $c.Caller.identity
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = 'the rule to put it after is gone - reload' } -Audit @{ Target = "$($m.ot)TagRule|new"; Outcome = 'refused'; OutcomeText = $s.Result } }
            $pv = Request-EpsAutoPreview -Ctx $c -ObjectType $m.ot
            New-EpsWebResponse -Body @{ ok = $true; ruleId = $s.RuleId; preview = $pv; text = "Rule $($s.RuleId) created. $($pv.text)" } -Audit @{ Target = "$($m.ot)TagRule|$($s.RuleId)"; After = ($s.After | ConvertFrom-Json); OutcomeText = $pv.text } } }
        @{ Method = 'PUT'; Pattern = '^/api/rules/(?<ot>User|Device)/(?<id>\d{1,9})$'; Summary = 'Change a rule.'; Body = 'the fields of Create; expected: when the rule was last changed as you saw it'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'rule.update'; NeedsReason = $true
           Stage = { param($c, $m)
            $cur = Get-EpsRuleCardById -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -RuleId ([int]$m.id)
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such rule (deleted?) - reload' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            $v = ConvertTo-EpsRuleCard -ObjectType $m.ot -Body $c.Body -Context (Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString)
            if (-not $v.Ok) { return @{ Refusal = (New-EpsWebRuleRefusal -Target "$($m.ot)TagRule|$($m.id)" -Errors $v.Errors) } }
            @{ ObjectType = $m.ot; Entity = "$($m.ot)TagRule"; Key = "$($m.id)"; Op = 'Update'; Before = (ConvertTo-EpsRuleJournal -Card $cur -ObjectType $m.ot); Summary = "Rule $($m.id): $(Get-EpsRuleCardText $v.Card)" } }
           Handler = { param($c, $m)
            $x = Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString
            $v = ConvertTo-EpsRuleCard -ObjectType $m.ot -Body $c.Body -Context $x
            if (-not $v.Ok) { return New-EpsWebRuleRefusal -Target "$($m.ot)TagRule|$($m.id)" -Errors $v.Errors }
            $s = Save-EpsRuleCard -ConnectionString $c.Ctx.ConnectionString -Card $v.Card -RuleId ([int]$m.id) -Expected (ConvertTo-EpsExpectedText $c.Body.expected) -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such rule (deleted?) - reload' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = 'someone else changed this rule after you opened it - reload and look again' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'changed by someone else' } }
            $pv = Request-EpsAutoPreview -Ctx $c -ObjectType $m.ot
            New-EpsWebResponse -Body @{ ok = $true; ruleId = [int]$m.id; preview = $pv; text = "Rule $($m.id) saved. $($pv.text)" } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Before = ($s.Before | ConvertFrom-Json); After = ($s.After | ConvertFrom-Json); OutcomeText = $pv.text } } }
        @{ Method = 'DELETE'; Pattern = '^/api/rules/(?<ot>User|Device)/(?<id>\d{1,9})$'; Summary = 'Delete a rule (Deleted rules can put it back).'; Body = 'expected: when the rule was last changed as you saw it'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'rule.delete'; NeedsReason = $true
           Stage = { param($c, $m)
            $cur = Get-EpsRuleCardById -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -RuleId ([int]$m.id)
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such rule' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            @{ ObjectType = $m.ot; Entity = "$($m.ot)TagRule"; Key = "$($m.id)"; Op = 'Delete'; Before = (ConvertTo-EpsRuleJournal -Card $cur -ObjectType $m.ot); Summary = "Delete rule $($m.id): $(Get-EpsRuleCardText $cur)" } }
           Handler = { param($c, $m)
            $s = Remove-EpsRuleCard -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -RuleId ([int]$m.id) -Expected (ConvertTo-EpsExpectedText $c.Body.expected) -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such rule' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = 'someone else changed this rule after you opened it - reload and look again' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'changed by someone else' } }
            $pv = Request-EpsAutoPreview -Ctx $c -ObjectType $m.ot
            New-EpsWebResponse -Body @{ ok = $true; preview = $pv; text = "Rule $($m.id) deleted (Deleted rules can put it back). $($pv.text)" } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Before = ($s.Before | ConvertFrom-Json); OutcomeText = $pv.text } } }
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)/(?<id>\d{1,9})/move$'; Summary = 'Move a rule one place up or down (the order decides which rule wins).'; Body = 'direction: up or down'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'rule.move'; NeedsReason = $true
           Stage = { param($c, $m)
            $dir = "$($c.Body.direction)"
            if ($dir -notin 'up', 'down') { return @{ Refusal = (New-EpsWebResponse -Status 400 -Body @{ error = 'direction is up or down' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = "direction '$dir'" }) } }
            $cur = Get-EpsRuleCardById -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -RuleId ([int]$m.id)
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such rule' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            @{ ObjectType = $m.ot; Entity = "$($m.ot)TagRule"; Key = "move:$($m.id):$([guid]::NewGuid().ToString('N'))"; Op = 'Move'; Before = (@{ order = $cur.Order } | ConvertTo-Json -Compress); Summary = "Move rule $($m.id) $dir (now number $($cur.Order))" } }
           Handler = { param($c, $m)
            $dir = "$($c.Body.direction)"
            if ($dir -notin 'up', 'down') { return New-EpsWebResponse -Status 400 -Body @{ error = 'direction is up or down' } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = "direction '$dir'" } }
            $s = Move-EpsRuleCard -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -RuleId ([int]$m.id) -Direction $dir -Actor $c.Caller.identity
            $st = @{ missing = 404; edge = 400; conflict = 409 }[$s.Result]
            if ($st) { return New-EpsWebResponse -Status $st -Body @{ error = @{ missing = 'no such rule'; edge = "it is already the $(if ($dir -eq 'up') { 'first' } else { 'last' })"; conflict = 'the rules changed meanwhile - reload' }[$s.Result] } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; Outcome = 'refused'; OutcomeText = $s.Result } }
            $pv = Request-EpsAutoPreview -Ctx $c -ObjectType $m.ot
            New-EpsWebResponse -Body @{ ok = $true; position = $s.Position; preview = $pv; text = "Rule $($m.id) is now number $($s.Position). $($pv.text)" } -Audit @{ Target = "$($m.ot)TagRule|$($m.id)"; After = @{ direction = $dir; position = $s.Position }; OutcomeText = $pv.text } } }
        # ---- the grid (RULES-GRID, owner 2026-11-01: "multi select, duplicate, copy paste values search move", "like excel
        # edits"): a grid edit / paste / fill-down / bulk action / import is ONE batch, checked first (what would change, every
        # cell validated), then staged as ONE queue entry - or, with the queue off, applied by the engine (Apply = 'Engine')
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)/batch/check$'; Summary = 'Check a grid batch without saving it: what would change, with every cell validated.'; Body = 'ops: the batch (create / update / delete / move per rule; addvalue = a plain value added to a tag type)'; Public = $true
           Role = 'Admin'; Action = 'rule.batch.check'; Handler = { param($c, $m)
            $chk = Test-EpsRuleBatch -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Ops @($c.Body.ops)
            New-EpsWebResponse -Body (ConvertTo-EpsRuleBatchView $chk) -Audit @{ Target = "$($m.ot)TagRule|batch"; After = @{ ok = [bool]$chk.Ok; summary = $chk.Summary }; WhatIf = $true } } }
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)/batch$'; Summary = 'Save a grid batch (edits, paste, fill-down, bulk actions, an import plan) as one change.'; Body = 'ops: the batch, as checked'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'rule.batch'; NeedsReason = $true
           Stage = { param($c, $m)
            $chk = Test-EpsRuleBatch -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Ops @($c.Body.ops)
            if (-not $chk.Ok) { return @{ Refusal = (New-EpsWebRuleRefusal -Target "$($m.ot)TagRule|batch" -Errors $chk.Errors) } }
            @{ ObjectType = $m.ot; Entity = "$($m.ot)TagRule"; Key = "batch:$([guid]::NewGuid().ToString('N'))"; Op = 'Batch'; Before = (ConvertTo-Json -InputObject @($chk.Before) -Compress -Depth 6); Summary = "$($m.ot) rules, one batch: $($chk.Summary)" } }
           Handler = { param($c, $m)
            $t = "$($m.ot)TagRule|batch"
            $r = Invoke-EpsRuleBatch -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Ops @($c.Body.ops) -Actor $c.Caller.identity
            if ($r.Result -eq 'refused') { return New-EpsWebRuleRefusal -Target $t -Errors $r.Errors }
            if ($r.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = "PARTLY applied: $($r.Applied) change(s) written, then change $($r.FailedAt) was refused ($($r.Why): the rules changed meanwhile) - reload and look again"; created = @($r.Created) } -Audit @{ Target = $t; Outcome = 'error'; OutcomeText = "partly: $($r.Applied) applied, change $($r.FailedAt) $($r.Why)"; After = @{ created = @($r.Created) } } }
            $pv = Request-EpsAutoPreview -Ctx $c -ObjectType $m.ot
            New-EpsWebResponse -Body @{ ok = $true; applied = $r.Applied; created = @($r.Created); preview = $pv; text = "Written: $($r.Check.Summary). $($pv.text)" } -Audit @{ Target = $t; Before = @($r.Check.Before); After = @{ summary = $r.Check.Summary; counts = $r.Check.Counts; created = @($r.Created); values = @($r.Values) }; OutcomeText = $pv.text } } }
        @{ Method = 'GET'; Pattern = '^/api/rules/(?<ot>User|Device)/export$'; Summary = 'The rules of one object type as a CSV file (the format the import reads).'; Public = $true
           Role = 'Reader'; Action = 'rules.export'; Handler = { param($c, $m)
            $tb = ConvertTo-EpsRuleCsvTable -Cards @(Read-EpsRuleCardsForEdit -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot) -ObjectType $m.ot
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $tb.Rows -Columns $tb.Columns) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = "attachment; filename=`"eps-$($m.ot.ToLowerInvariant())-rules.csv`"" } `
                -Audit @{ Target = "$($m.ot)TagRule"; After = @{ rows = $tb.Rows.Count } } } }
        # an import is a PLAN (nothing is staged here): the page shows it, then sends its batch to /batch
        @{ Method = 'POST'; Pattern = '^/api/rules/(?<ot>User|Device)/import$'; Summary = 'Read an import file and return its plan (the batch to save). Nothing is saved.'; Body = 'format: v2 (this app''s CSV) or v1 (the v1 tagging files); text (v2) or files: [ { name, text } ] (v1); deleteMissing (v2); mode: append or replace-imported (v1); addValues: true = the plan also adds the tag values the v1 files need (v1)'; Public = $true
           Role = 'Admin'; Action = 'rule.import.plan'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $fmt = "$($c.Body.format)"; $t = "$($m.ot)TagRule|import"
            $x = Get-EpsEditContext -ConnectionString $cs
            $cur = @(Read-EpsRuleCardsForEdit -ConnectionString $cs -ObjectType $m.ot)
            $info = $null; $rowErrors = @()
            if ($fmt -eq 'v2') {
                $txt = "$($c.Body.text)"
                if ($txt.Length -gt 900000) { return New-EpsWebResponse -Status 413 -Body @{ error = 'the file is larger than 900 KB' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'too large' } }
                $p = ConvertFrom-EpsRuleCsv -Text $txt -ObjectType $m.ot -Current $cur -DeleteMissing:([bool]$c.Body.deleteMissing)
                $ops = @($p.Ops); $rowErrors = @($p.Errors)
                if (-not $ops.Count -and $rowErrors.Count) { return New-EpsWebResponse -Status 400 -Body @{ error = ($rowErrors | Select-Object -First 10) -join '; '; errors = $rowErrors } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = ($rowErrors | Select-Object -First 3) -join '; ' } }
            } elseif ($fmt -eq 'v1') {
                $files = @(@($c.Body.files) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ name = [IO.Path]::GetFileName("$($_.name)"); text = "$($_.text)" } })
                if (@($files | Where-Object { $_.text.Length -gt 900000 }).Count) { return New-EpsWebResponse -Status 413 -Body @{ error = 'a file is larger than 900 KB' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'too large' } }
                $mode = if ("$($c.Body.mode)" -eq 'replace-imported') { 'replace-imported' } else { 'append' }
                $p = ConvertFrom-EpsV1Upload -Files $files -ObjectType $m.ot -Context $x -Current $cur -Mode $mode -AddValues:([bool]$c.Body.addValues)
                if ($p.Error) { return New-EpsWebResponse -Status 400 -Body @{ error = $p.Error } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $p.Error } }
                $ops = @($p.Ops); $info = $p.Info
            } else { return New-EpsWebResponse -Status 400 -Body @{ error = 'format is v2 (this app''s export) or v1 (Identity_Tagging / Device_Tagging)' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "format '$fmt'" } }
            $chk = if ($ops.Count) { Test-EpsRuleBatch -ConnectionString $cs -ObjectType $m.ot -Ops $ops -Context $x -Current $cur } else { $null }
            # a row that is exactly the rule already is left out of the batch (it would change nothing)
            if ($chk -and @($chk.Items | Where-Object unchanged).Count) {
                $ops = @(for ($i = 0; $i -lt $ops.Count; $i++) { if (-not $chk.Items[$i].unchanged) { $ops[$i] } })
                $chk = if ($ops.Count) { Test-EpsRuleBatch -ConnectionString $cs -ObjectType $m.ot -Ops $ops -Context $x -Current $cur } else { $null }
            }
            $view = if ($chk) { ConvertTo-EpsRuleBatchView $chk } else { [ordered]@{ ok = $false; errors = @('nothing changes: every row is as the rule already is'); summary = 'nothing changes'; items = @() } }
            New-EpsWebResponse -Body ([ordered]@{ format = $fmt; ops = @($ops); check = $view; rowErrors = @($rowErrors); v1 = $info }) -Audit @{ Target = $t; After = @{ format = $fmt; ops = $ops.Count; ok = [bool]$view.ok; rowErrors = $rowErrors.Count }; WhatIf = $true } } }

        # ---- tag types and their values (DESIGN §5.6a) ----
        @{ Method = 'GET'; Pattern = '^/api/tagtypes$'; Summary = 'The tag types with their allowed values and how many rules use each.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $vals = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT ObjectType, TagType, Value, IsPattern, Description FROM eps.TagValue ORDER BY ObjectType, TagType, Value') | Group-Object { "$($_.ObjectType)|$($_.TagType)" } -AsHashTable -AsString
            $use = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query "SELECT 'User' AS ObjectType, TagType, COUNT(*) AS Rules FROM eps.UserTagRule GROUP BY TagType UNION ALL SELECT 'Device', TagType, COUNT(*) FROM eps.DeviceTagRule GROUP BY TagType") | Group-Object { "$($_.ObjectType)|$($_.TagType)" } -AsHashTable -AsString
            $types = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT * FROM eps.TagType ORDER BY ObjectType, Name'))
            foreach ($t in $types) {
                $k = "$($t.ObjectType)|$($t.Name)"
                $t | Add-Member -NotePropertyName Values -NotePropertyValue @(if ($vals -and $vals[$k]) { $vals[$k] | Select-Object Value, IsPattern, Description })
                $t | Add-Member -NotePropertyName Rules -NotePropertyValue $(if ($use -and $use[$k]) { [int]$use[$k][0].Rules } else { 0 }) }
            New-EpsWebResponse -Body @{ rows = $types } } }
        @{ Method = 'PUT'; Pattern = '^/api/tagtypes/(?<ot>User|Device)/(?<name>[A-Za-z][A-Za-z0-9_]{1,59})$'; Summary = 'Create or change a tag type.'; Body = 'attribute, valueMode, enabled, description, allowMultiple, fallbackAD, fallbackCloud; expected'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'tagtype.change'; NeedsReason = $true
           Stage = { param($c, $m)
            $v = ConvertTo-EpsTagType -ObjectType $m.ot -Name $m.name -Body $c.Body
            if (-not $v.Ok) { return @{ Refusal = (New-EpsWebRuleRefusal -Target "TagType|$($m.ot):$($m.name)" -Errors $v.Errors) } }
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; n = $m.name } -Query 'SELECT * FROM eps.TagType WHERE ObjectType = @o AND Name = @n')[0]
            @{ ObjectType = $m.ot; Entity = 'TagType'; Key = "$($m.ot):$($m.name)"; Op = $(if ($cur) { 'Update' } else { 'Create' }); Before = $(if ($cur) { ConvertTo-EpsWebValue @($cur) | Select-Object -First 1 }); Summary = "$(if ($cur) { 'Change' } else { 'New' }) $($m.ot.ToLowerInvariant()) tag type $($m.name)$(if ($c.Body.attribute) { " ($($c.Body.attribute))" })" } }
           Handler = { param($c, $m)
            $t = "TagType|$($m.ot):$($m.name)"
            $v = ConvertTo-EpsTagType -ObjectType $m.ot -Name $m.name -Body $c.Body
            if (-not $v.Ok) { return New-EpsWebRuleRefusal -Target $t -Errors $v.Errors }
            $s = Save-EpsTagType -ConnectionString $c.Ctx.ConnectionString -TagType $v.TagType -Expected (ConvertTo-EpsExpectedText $c.Body.expected) -Actor $c.Caller.identity
            if ($s.Result -eq 'refused') { return New-EpsWebResponse -Status 409 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "guard: $($s.Text)"; Guard = $true } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = 'someone else changed this tag type after you opened it - reload' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'changed by someone else' } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Tag type $($m.name) $(if ($s.Created) { 'created' } else { 'saved' })." } -Audit @{ Target = $t; Before = $(if ($s.Before) { $s.Before | ConvertFrom-Json }); After = ($s.After | ConvertFrom-Json) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/tagtypes/(?<ot>User|Device)/(?<name>[A-Za-z][A-Za-z0-9_]{1,59})$'; Summary = 'Delete a tag type.'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'tagtype.delete'; NeedsReason = $true
           Stage = { param($c, $m)
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; n = $m.name } -Query 'SELECT * FROM eps.TagType WHERE ObjectType = @o AND Name = @n')[0]
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such tag type' } -Audit @{ Target = "TagType|$($m.ot):$($m.name)"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            @{ ObjectType = $m.ot; Entity = 'TagType'; Key = "$($m.ot):$($m.name)"; Op = 'Delete'; Before = (ConvertTo-EpsWebValue @($cur) | Select-Object -First 1); Summary = "Delete $($m.ot.ToLowerInvariant()) tag type $($m.name)" } }
           Handler = { param($c, $m)
            $t = "TagType|$($m.ot):$($m.name)"
            $s = Remove-EpsTagType -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Name $m.name -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such tag type' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "guard: $($s.Text)"; Guard = $true } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Tag type $($m.name) deleted." } -Audit @{ Target = $t } } }
        @{ Method = 'PUT'; Pattern = '^/api/tagtypes/(?<ot>User|Device)/(?<name>[A-Za-z][A-Za-z0-9_]{1,59})/values$'; Summary = 'Add or change an allowed value of a tag type.'; Body = 'value; description; isPattern: true / false'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'tagvalue.change'; NeedsReason = $true
           Stage = { param($c, $m)
            $val = "$($c.Body.value)".Trim()
            if (-not $val) { return @{ Refusal = (New-EpsWebResponse -Status 400 -Body @{ error = 'give the value' } -Audit @{ Target = "TagValue|$($m.ot):$($m.name):"; Outcome = 'refused'; OutcomeText = 'no value' }) } }
            if (-not [int](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters @{ o = $m.ot; n = $m.name } -Query 'SELECT COUNT(*) FROM eps.TagType WHERE ObjectType = @o AND Name = @n')) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such tag type' } -Audit @{ Target = "TagValue|$($m.ot):$($m.name):$val"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; n = $m.name; v = $val } -Query 'SELECT Value, IsPattern, Description FROM eps.TagValue WHERE ObjectType = @o AND TagType = @n AND Value = @v')[0]
            @{ ObjectType = $m.ot; Entity = 'TagValue'; Key = "$($m.ot):$($m.name):$val"; Op = $(if ($cur) { 'Update' } else { 'Create' }); Before = $(if ($cur) { ConvertTo-EpsWebValue @($cur) | Select-Object -First 1 }); Summary = "$(if ($cur) { 'Change' } else { 'Add' }) value '$val' $(if ($cur) { 'in' } else { 'to' }) $($m.name)" } }
           Handler = { param($c, $m)
            $t = "TagValue|$($m.ot):$($m.name):$("$($c.Body.value)".Trim())"
            $s = Save-EpsTagValue -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -TagType $m.name -Body $c.Body -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such tag type' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 400 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $s.Text } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Value '$($s.Value)' $(if ($s.Created) { 'added to' } else { 'saved in' }) $($m.name)." } -Audit @{ Target = $t; After = ($s.After | ConvertFrom-Json) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/tagtypes/(?<ot>User|Device)/(?<name>[A-Za-z][A-Za-z0-9_]{1,59})/values$'; Summary = 'Remove an allowed value from a tag type.'; Body = 'value'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'tagvalue.remove'; NeedsReason = $true
           Stage = { param($c, $m)
            $val = "$($c.Body.value)"
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; n = $m.name; v = $val } -Query 'SELECT Value, IsPattern, Description FROM eps.TagValue WHERE ObjectType = @o AND TagType = @n AND Value = @v')[0]
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such value' } -Audit @{ Target = "TagValue|$($m.ot):$($m.name):$val"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            @{ ObjectType = $m.ot; Entity = 'TagValue'; Key = "$($m.ot):$($m.name):$val"; Op = 'Delete'; Before = (ConvertTo-EpsWebValue @($cur) | Select-Object -First 1); Summary = "Remove value '$val' from $($m.name)" } }
           Handler = { param($c, $m)
            $val = "$($c.Body.value)"; $t = "TagValue|$($m.ot):$($m.name):$val"
            $s = Remove-EpsTagValue -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -TagType $m.name -Value $val -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such value' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "guard: $($s.Text)"; Guard = $true } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Value '$val' removed from $($m.name)." } -Audit @{ Target = $t; Before = $s.Before } } }

        # ---- the customer's own property condition types (DESIGN §5.6b kind 1) ----
        @{ Method = 'GET'; Pattern = '^/api/conditions$'; Summary = 'The condition types: the shipped ones and your own.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $x = Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString
            $cat = @(foreach ($d in @($x.Catalog.Values | Sort-Object ObjectType, Id)) { [ordered]@{ objectType = $d.ObjectType; id = $d.Id; kind = $d.Kind; shipped = [bool]$d.Shipped; property = $d.Property; operator = $d.Operator; guard = $d.Guard; description = $d.Description; enabled = $true } })
            $cat += @(foreach ($d in @($x.Custom | Where-Object { -not $_.Enabled })) { [ordered]@{ objectType = $d.ObjectType; id = $d.Id; kind = 'Property'; shipped = $false; property = $d.Property; operator = $d.Operator; guard = $d.Guard; description = $d.Description; enabled = $false } })
            New-EpsWebResponse -Body @{ rows = @($cat) } } }
        @{ Method = 'PUT'; Pattern = '^/api/conditions/(?<ot>User|Device)/(?<cid>[A-Za-z][A-Za-z0-9_]{2,99})$'; Summary = 'Create or change one of your own property condition types.'; Body = 'property; operator; guard; description; enabled'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'condition.change'; NeedsReason = $true
           Stage = { param($c, $m)
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; i = $m.cid } -Query 'SELECT Id, Property, Operator, Guard, Description, Enabled FROM eps.ConditionType WHERE ObjectType = @o AND Id = @i')[0]
            @{ ObjectType = $m.ot; Entity = 'ConditionType'; Key = "$($m.ot):$($m.cid)"; Op = $(if ($cur) { 'Update' } else { 'Create' }); Before = $(if ($cur) { ConvertTo-EpsWebValue @($cur) | Select-Object -First 1 }); Summary = "$(if ($cur) { 'Change' } else { 'New' }) condition type $($m.cid): $($c.Body.property) $($c.Body.operator)" } }
           Handler = { param($c, $m)
            $t = "ConditionType|$($m.ot):$($m.cid)"
            $s = Save-EpsConditionType -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Id $m.cid -Body $c.Body -Context (Get-EpsEditContext -ConnectionString $c.Ctx.ConnectionString) -Actor $c.Caller.identity
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 400 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $s.Text } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Condition type $($m.cid) $(if ($s.Created) { 'created' } else { 'saved' }). The next run reads it." } -Audit @{ Target = $t; Before = $(if ($s.Before) { $s.Before | ConvertFrom-Json }); After = ($s.After | ConvertFrom-Json) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/conditions/(?<ot>User|Device)/(?<cid>[A-Za-z][A-Za-z0-9_]{2,99})$'; Summary = 'Delete one of your own condition types.'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'condition.delete'; NeedsReason = $true
           Stage = { param($c, $m)
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ o = $m.ot; i = $m.cid } -Query 'SELECT Id, Property, Operator, Guard, Description, Enabled FROM eps.ConditionType WHERE ObjectType = @o AND Id = @i')[0]
            if (-not $cur) { return @{ Refusal = (New-EpsWebResponse -Status 404 -Body @{ error = 'no such condition type of your own (shipped ones cannot be deleted)' } -Audit @{ Target = "ConditionType|$($m.ot):$($m.cid)"; Outcome = 'refused'; OutcomeText = 'missing' }) } }
            @{ ObjectType = $m.ot; Entity = 'ConditionType'; Key = "$($m.ot):$($m.cid)"; Op = 'Delete'; Before = (ConvertTo-EpsWebValue @($cur) | Select-Object -First 1); Summary = "Delete condition type $($m.cid)" } }
           Handler = { param($c, $m)
            $t = "ConditionType|$($m.ot):$($m.cid)"
            $s = Remove-EpsConditionType -ConnectionString $c.Ctx.ConnectionString -ObjectType $m.ot -Id $m.cid -Actor $c.Caller.identity
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such condition type of your own (shipped ones cannot be deleted)' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 409 -Body @{ error = $s.Text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "guard: $($s.Text)"; Guard = $true } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Condition type $($m.cid) deleted." } -Audit @{ Target = $t } } }

        # ---- the CA Policy Analyzer (DESIGN §5.7): READ ONLY - the web app reads what the engine stored and queues requests ----
        @{ Method = 'GET'; Pattern = '^/api/ca/policies$'; Summary = 'The CA policies as the engine last read them.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            # + the personas each is in (CA-PERSONA: the managed list - several, or none) and the monitors it is in now
            # (CA-MONADD: the small tags on each policy) - the analyzer groups and picks by persona
            $v = Get-EpsCaPersonaView -ConnectionString $c.Ctx.ConnectionString
            New-EpsWebResponse -Body @{ rows = @($v.Policies) } } }
        @{ Method = 'POST'; Pattern = '^/api/ca/analyze$'; Summary = 'Request a CA Policy Analyzer run now (read only), or a new read of the policy list.'; Body = 'policyIds, policyNames, policyPrefixes, policyPatterns: which policies; mode and its time window as on the page; listOnly: true reads the policy list again'; Public = $true
           Role = 'Admin'; Action = 'ca.analyze.request'; NeedsReason = $true; Handler = { param($c, $m)
            $v = ConvertTo-EpsCaRequest -Body $c.Body
            if (-not $v.Ok) { return New-EpsWebResponse -Status 400 -Body @{ error = $v.Error } -Audit @{ Target = 'CAPolicyAnalyzer'; Outcome = 'refused'; OutcomeText = $v.Error } }
            $b = [ordered]@{}; foreach ($p in $c.Body.PSObject.Properties) { if ($p.Name -notin 'reason') { $b[$p.Name] = $p.Value } }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job 'CAPolicyAnalyzer' -Mode 'Preview' -Scope $b
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = $(if ($v.Request.ListOnly) { 'Requested: the policy list is read again within 5 minutes.' } else { "Requested: the analysis ($($v.Request.Mode)) starts within 5 minutes - read only, nothing in the tenant is changed." }) } -Audit @{ Target = 'CAPolicyAnalyzer'; After = $b; WhatIf = $true } } }
        @{ Method = 'GET'; Pattern = '^/api/ca/analyses$'; Summary = 'The CA Policy Analyzer analyses, newest first.'; Body = 'q: search; monitor: one monitor''s analyses'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $pg = Get-EpsWebPaging $c.Query; $p = @{ q = "$($c.Query.q)"; mo = "$($c.Query.monitor)"; k = $pg.Skip; n = $pg.Size }
            $w = "WHERE (@q = '' OR DisplayName LIKE '%' + @q + '%') AND (@mo = '' OR Monitor = @mo)"
            New-EpsWebResponse -Body @{ total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $p -Query "SELECT COUNT(*) FROM eps.CaAnalysis $w"
                rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query "SELECT AnalysisId, RunId, PolicyId, DisplayName, PolicyState, Mode, WindowStartUtc, WindowEndUtc, InScope, Impacted, NotImpacted, Errors, Monitor, CreatedAtUtc FROM eps.CaAnalysis $w ORDER BY CreatedAtUtc DESC OFFSET @k ROWS FETCH NEXT @n ROWS ONLY")) } } }
        @{ Method = 'GET'; Pattern = '^/api/ca/analyses/(?<aid>[0-9a-fA-F-]{36})$'; Summary = 'One analysis with its findings.'; Body = 'q: search; all: every row, not only the findings'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $a = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ a = [guid]$m.aid } -Query 'SELECT * FROM eps.CaAnalysis WHERE AnalysisId = @a'))[0]
            if (-not $a) { return New-EpsWebError 404 'no such analysis' }
            $pg = Get-EpsWebPaging $c.Query; $p = @{ a = [guid]$m.aid; all = [bool]("$($c.Query.all)" -eq '1'); q = "$($c.Query.q)"; k = $pg.Skip; n = $pg.Size }
            $w = "WHERE AnalysisId = @a AND (@all = 1 OR Impacted = 1) AND (@q = '' OR UserPrincipalName LIKE '%' + @q + '%' OR DisplayName LIKE '%' + @q + '%' OR Classification = @q)"
            New-EpsWebResponse -Body @{ analysis = $a; total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $p -Query "SELECT COUNT(*) FROM eps.CaAnalysisResult $w"
                rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query "SELECT * FROM eps.CaAnalysisResult $w ORDER BY Impacted DESC, Seq OFFSET @k ROWS FETCH NEXT @n ROWS ONLY")) } } }
        @{ Method = 'GET'; Pattern = '^/api/ca/analyses/(?<aid>[0-9a-fA-F-]{36})/export$'; Summary = 'One analysis as a CSV file.'; Public = $true
           Role = 'Reader'; Action = 'ca.export'; Handler = { param($c, $m)
            $cols = 'UserPrincipalName', 'DisplayName', 'IsSpn', 'Classification', 'Impacted', 'Reason', 'GrantControls', 'SessionControls', 'LastSignInUtc', 'Country', 'City', 'IPAddress', 'DeviceOS', 'Browser', 'ClientApp', 'Application', 'RiskLevel', 'RiskState', 'CAResult', 'FailureReason', 'SignInCount', 'CountriesSeen', 'DistinctIPCount', 'UserId'
            $rows = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ a = [guid]$m.aid } -Query "SELECT $($cols -join ', ') FROM eps.CaAnalysisResult WHERE AnalysisId = @a ORDER BY Impacted DESC, Seq")
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $rows -Columns $cols) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = "attachment; filename=""eps-ca-analysis-$($m.aid).csv""" } `
                -Audit @{ Target = "CaAnalysis|$($m.aid)"; After = @{ rows = $rows.Count } } } }
        @{ Method = 'GET'; Pattern = '^/api/ca/monitors$'; Summary = 'The analyzer monitors: saved analyses that run on a schedule.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT Name, Definition, Schedule, Enabled, LastStartedUtc, LastStartResult, UpdatedAtUtc FROM eps.CaMonitor ORDER BY Name')) } } }
        @{ Method = 'PUT'; Pattern = '^/api/ca/monitors/(?<mn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Create or change a monitor.'; Body = 'definition: the analysis (as for analyze; excludePolicyIds: policies left out of this monitor); schedule; enabled'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'ca.monitor.change'; NeedsReason = $true; Handler = { param($c, $m)
            $t = "CaMonitor|$($m.mn)"
            $v = ConvertTo-EpsCaRequest -Body $c.Body.definition
            if (-not $v.Ok -or $v.Request.ListOnly) { $e = if ($v.Error) { $v.Error } else { 'a monitor names policies' }; return New-EpsWebResponse -Status 400 -Body @{ error = $e } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $e } }
            $sch = "$($c.Body.schedule)".Trim()
            try { $sx = ConvertFrom-EpsSchedule -Schedule $sch; if ($sx.Kind -eq 'every' -and $sx.Every -lt 60) { throw "'$sch': a monitor runs at most every 60m (every run reads the sign-in log)" } } catch { return New-EpsWebResponse -Status 400 -Body @{ error = "$($_.Exception.Message)" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "schedule '$sch'" } }
            $def = $c.Body.definition | ConvertTo-Json -Compress -Depth 6
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ n = $m.mn } -Query 'SELECT Definition, Schedule, Enabled FROM eps.CaMonitor WHERE Name = @n')[0]
            $after = @{ definition = $def; schedule = $sch; enabled = [bool]$c.Body.enabled } | ConvertTo-Json -Compress
            $p = @{ n = $m.mn; d = $def; s = $sch; e = [bool]$c.Body.enabled } + (New-EpsJournalParameters -Actor $c.Caller.identity -Entity 'CaMonitor' -Key $m.mn -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before $(if ($cur) { @{ definition = $cur.Definition; schedule = $cur.Schedule; enabled = [bool]$cur.Enabled } | ConvertTo-Json -Compress }) -After $after)
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; MERGE eps.CaMonitor AS x USING (SELECT @n AS Name) AS s ON x.Name = s.Name WHEN MATCHED THEN UPDATE SET Definition = @d, Schedule = @s, Enabled = @e, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Definition, Schedule, Enabled) VALUES (@n, @d, @s, @e); $(Get-EpsJournalSql) COMMIT;")
            New-EpsWebResponse -Body @{ ok = $true; text = "Monitor $($m.mn) saved$(if ($c.Body.enabled) { " - it runs $sch, read only" } else { ' (off)' })." } -Audit @{ Target = $t; After = ($after | ConvertFrom-Json) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/ca/monitors/(?<mn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Delete a monitor.'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'ca.monitor.delete'; NeedsReason = $true; Handler = { param($c, $m)
            $cur = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ n = $m.mn } -Query 'SELECT Definition, Schedule, Enabled FROM eps.CaMonitor WHERE Name = @n')[0]
            if (-not $cur) { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such monitor' } -Audit @{ Target = "CaMonitor|$($m.mn)"; Outcome = 'refused'; OutcomeText = 'missing' } }
            $p = @{ n = $m.mn } + (New-EpsJournalParameters -Actor $c.Caller.identity -Entity 'CaMonitor' -Key $m.mn -Action 'Delete' -Before (@{ definition = $cur.Definition; schedule = $cur.Schedule } | ConvertTo-Json -Compress) -After $null)
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; DELETE FROM eps.CaMonitor WHERE Name = @n; $(Get-EpsJournalSql) COMMIT;")
            New-EpsWebResponse -Body @{ ok = $true; text = "Monitor $($m.mn) deleted. Its analyses stay." } -Audit @{ Target = "CaMonitor|$($m.mn)" } } }
        # ---- the analyzer's personas (CA-PERSONA, owner 2026-11-02: "it should be possible edit/delete/create existing
        # monitors persona. this functionality replaces the series button"): a name + picked policies + name rules; the
        # template personas are the starting list (seeded once by the engine); a monitor names personas and resolves them
        # at each run. Written by the engine from the signed request (Apply = 'Engine'), journaled and audited. ----
        @{ Method = 'GET'; Pattern = '^/api/ca/personas$'; Summary = 'The personas of the CA Policy Analyzer: each with its picked policies, its name rules, the policies it takes now and the monitors that name it.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $v = Get-EpsCaPersonaView -ConnectionString $c.Ctx.ConnectionString
            New-EpsWebResponse -Body @{ rows = @($v.Personas); seeded = $v.Seeded; seed = $v.Seed } } }
        @{ Method = 'PUT'; Pattern = '^/api/ca/personas/(?<pn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Create or change a persona of the CA Policy Analyzer; a new name renames it and the monitors that name it follow.'; Body = 'policyIds: picked policy ids; rules: name rules, e.g. CA2 (every CA2xx), CA006, CA6*; excludeIds: policies a rule takes that stay out; newName: a new name (optional)'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'ca.persona.change'; NeedsReason = $true; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $t = "CaPersona|$($m.pn)"
            $v = ConvertTo-EpsCaPersonaBody -Body $c.Body -Name $m.pn
            if (-not $v.Ok) { return New-EpsWebResponse -Status 400 -Body @{ error = $v.Error } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $v.Error } }
            [void](Initialize-EpsCaPersonas -ConnectionString $cs)   # an edit before the first analyzer run starts from the seeded list
            $cur = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ n = [string]$m.pn } -Query 'SELECT Name, PolicyIdsJson, RulesJson, ExcludeIdsJson, Source FROM eps.CaPersona WHERE Name = @n')[0]
            if ($v.NewName -and -not $cur) { return New-EpsWebResponse -Status 404 -Body @{ error = "no persona '$($m.pn)' to rename - reload" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            $old = if ($cur) { [string]$cur.Name } else { [string]$m.pn }
            $new = if ($v.NewName) { $v.NewName } else { $old }
            $rename = [bool]$cur -and $new -cne $old
            if ($rename -and $new -ine $old -and [int](Invoke-EpsSql -ConnectionString $cs -Scalar -Parameters @{ n = $new } -Query 'SELECT COUNT(*) FROM eps.CaPersona WHERE Name = @n')) { return New-EpsWebResponse -Status 409 -Body @{ error = "a persona '$new' exists already" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "'$new' exists" } }
            $ids = ConvertTo-Json -InputObject @($v.PolicyIds) -Compress; $rules = ConvertTo-Json -InputObject @($v.Rules) -Compress; $exc = ConvertTo-Json -InputObject @($v.ExcludeIds) -Compress
            $before = if ($cur) { [ordered]@{ name = $old; policyIds = @($cur.PolicyIdsJson | ConvertFrom-Json); rules = @($cur.RulesJson | ConvertFrom-Json); excludeIds = @("$($cur.ExcludeIdsJson)" | ConvertFrom-Json) } | ConvertTo-Json -Compress -Depth 4 }
            $after = [ordered]@{ name = $new; policyIds = @($v.PolicyIds); rules = @($v.Rules); excludeIds = @($v.ExcludeIds) } | ConvertTo-Json -Compress -Depth 4
            $p = @{ n = $old; nn = $new; i = $ids; r = $rules; x = $exc; by = [string]$c.Caller.identity; act = $(if ($cur) { 'Update' } else { 'Create' }); jb = $before; jaf = $after }
            # a rename: every monitor that names the old persona names the new one, in the same transaction (journaled each)
            $mons = [System.Collections.Generic.List[string]]::new(); $msql = ''
            if ($rename) {
                foreach ($mo in @(Invoke-EpsSql -ConnectionString $cs -Query 'SELECT Name, Definition FROM eps.CaMonitor ORDER BY Name')) {
                    if (-not @(Get-EpsCaMonitorPersonas -Definition "$($mo.Definition)" | Where-Object { $_ -ieq $old }).Count) { continue }
                    $d = "$($mo.Definition)" | ConvertFrom-Json
                    $d.personas = @(@($d.personas) | ForEach-Object { if ("$_".Trim() -ieq $old) { $new } else { "$_" } } | Select-Object -Unique)
                    $k = $mons.Count; $mons.Add([string]$mo.Name)
                    $p["mn$k"] = [string]$mo.Name; $p["mb$k"] = [string]$mo.Definition; $p["md$k"] = ($d | ConvertTo-Json -Compress -Depth 6)
                    $msql += "UPDATE eps.CaMonitor SET Definition = @md$k, UpdatedAtUtc = SYSUTCDATETIME() WHERE Name = @mn$k; INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@by, 'CaMonitor', @mn$k, 'Update', @mb$k, @md$k, 'gui'); "
                }
            }
            $write = if ($cur) { 'UPDATE eps.CaPersona SET Name = @nn, PolicyIdsJson = @i, RulesJson = @r, ExcludeIdsJson = @x, UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = @by WHERE Name = @n;' } else { "INSERT INTO eps.CaPersona (Name, PolicyIdsJson, RulesJson, ExcludeIdsJson, Source, UpdatedBy) VALUES (@nn, @i, @r, @x, 'custom', @by);" }
            [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; $write INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@by, 'CaPersona', @nn, @act, @jb, @jaf, 'gui'); $msql COMMIT;")
            $txt = if ($rename) { "Persona $old renamed to $new" + $(if ($mons.Count) { "; the monitor(s) $($mons -join ', ') follow" } else { '' }) + '.' } elseif ($cur) { "Persona $new saved." } else { "Persona $new created." }
            New-EpsWebResponse -Body @{ ok = $true; name = $new; monitors = @($mons); text = "$txt Monitors take the change at their next run." } -Audit @{ Target = "CaPersona|$new"; Before = $(if ($before) { $before | ConvertFrom-Json }); After = (@{ persona = ($after | ConvertFrom-Json); monitors = @($mons) }) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/ca/personas/(?<pn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Delete a persona of the CA Policy Analyzer; refused while a monitor names it, unless force takes it out of those monitors.'; Body = 'force: true takes the persona out of the monitors that name it'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'ca.persona.delete'; NeedsReason = $true; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $t = "CaPersona|$($m.pn)"
            [void](Initialize-EpsCaPersonas -ConnectionString $cs)
            $cur = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ n = [string]$m.pn } -Query 'SELECT Name, PolicyIdsJson, RulesJson, ExcludeIdsJson, Source FROM eps.CaPersona WHERE Name = @n')[0]
            if (-not $cur) { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such persona' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            $name = [string]$cur.Name
            # the last persona CAN be deleted (CA-LIMITS fix 4): the import happened once (its marker), so an empty list stays empty
            $users = @(Invoke-EpsSql -ConnectionString $cs -Query 'SELECT Name, Definition, Enabled FROM eps.CaMonitor ORDER BY Name' | Where-Object { @(Get-EpsCaMonitorPersonas -Definition "$($_.Definition)" | Where-Object { $_ -ieq $name }).Count })
            if ($users.Count -and -not ($c.Body.force -eq $true)) {
                $mn = @($users | ForEach-Object { [string]$_.Name })
                return New-EpsWebResponse -Status 409 -Body @{ error = "the monitor(s) $($mn -join ', ') name this persona - delete it again with force to take it out of them"; monitors = $mn } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "in use by $($mn -join ', ')" } }
            $before = [ordered]@{ name = $name; policyIds = @($cur.PolicyIdsJson | ConvertFrom-Json); rules = @($cur.RulesJson | ConvertFrom-Json); excludeIds = @("$($cur.ExcludeIdsJson)" | ConvertFrom-Json) } | ConvertTo-Json -Compress -Depth 4
            $p = @{ n = $name; by = [string]$c.Caller.identity; jb = $before }
            $msql = ''; $off = [System.Collections.Generic.List[string]]::new(); $k = 0
            foreach ($mo in $users) {
                $d = "$($mo.Definition)" | ConvertFrom-Json
                $d.personas = @(@($d.personas) | Where-Object { "$_".Trim() -ine $name })
                # a monitor left with nothing to analyse is switched off (it would only fail) - and the answer says so
                $empty = -not @(@($d.policyIds) + @($d.policyNames) + @($d.policyPrefixes) + @($d.policyPatterns) + @($d.personas) | Where-Object { "$_".Trim() }).Count
                if ($empty -and $mo.Enabled) { $off.Add([string]$mo.Name) }
                $p["mn$k"] = [string]$mo.Name; $p["mb$k"] = [string]$mo.Definition; $p["md$k"] = ($d | ConvertTo-Json -Compress -Depth 6); $p["me$k"] = [bool]$empty
                $msql += "UPDATE eps.CaMonitor SET Definition = @md$k, Enabled = CASE WHEN @me$k = 1 THEN 0 ELSE Enabled END, UpdatedAtUtc = SYSUTCDATETIME() WHERE Name = @mn$k; INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@by, 'CaMonitor', @mn$k, 'Update', @mb$k, @md$k, 'gui'); "
                $k++
            }
            [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; DELETE FROM eps.CaPersona WHERE Name = @n; INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@by, 'CaPersona', @n, 'Delete', @jb, NULL, 'gui'); $msql COMMIT;")
            $mn = @($users | ForEach-Object { [string]$_.Name })
            $txt = "Persona $name deleted." + $(if ($mn.Count) { " Taken out of the monitor(s) $($mn -join ', ')." } else { '' }) + $(if ($off.Count) { " $($off -join ', ') named nothing else and is switched off." } else { '' })
            New-EpsWebResponse -Body @{ ok = $true; monitors = $mn; switchedOff = @($off); text = $txt } -Audit @{ Target = "CaPersona|$name"; Before = ($before | ConvertFrom-Json); After = @{ monitors = $mn; switchedOff = @($off) } } } }
        # ---- template updates (TEMPLATE-UPDATES, owner 2026-11-02: "templates can be used for updates if new features are
        # added but always operator controlled. easy to see chg is importantant"): a newer library changes nothing by itself;
        # the view shows what is new / changed against what this install has taken, the operator takes persona changes,
        # and a template change is only marked as seen - policies are shown and exported, never written. ----
        @{ Method = 'GET'; Pattern = '^/api/ca/template-updates$'; Summary = 'What a newer template library brings against what this install has taken: new, changed and removed templates with a readable before and after, and the persona changes.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $u = Get-EpsCaTemplateUpdates -ConnectionString $c.Ctx.ConnectionString
            New-EpsWebResponse -Body @{ recorded = $u.Recorded; library = $u.Library; taken = @($u.Taken); templates = @($u.Templates); personas = @($u.Personas) } } }
        @{ Method = 'GET'; Pattern = '^/api/ca/template-updates/export$'; Summary = 'One template of the shipped library (or as this install took it) as a JSON file.'; Body = 'id: the CA number; which: after (the shipped template, default) or before (as taken)'; Answer = 'file (JSON)'; Public = $true
           Role = 'Reader'; Action = 'ca.export'; Handler = { param($c, $m)
            $id = "$($c.Query.id)".Trim().ToUpperInvariant()
            if ($id -notmatch $script:EpsCaTemplateIdRx) { return New-EpsWebError 400 'id: a CA number, e.g. CA101' }
            if ("$($c.Query.which)" -eq 'before') {
                $j = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters @{ i = $id } -Query 'SELECT TemplateJson FROM eps.CaTemplateTaken WHERE TemplateId = @i'
                if ($null -eq $j -or $j -is [DBNull]) { return New-EpsWebError 404 "$id was not taken before" }
                $body = [ordered]@{ id = $id }; $h = "$j" | ConvertFrom-Json -AsHashtable -Depth 30; foreach ($k in $h.Keys) { $body[$k] = $h[$k] }; $file = "$id-taken"
            } else {
                $t = (Get-EpsCaTemplateCatalog).ById[$id]
                if (-not $t) { return New-EpsWebError 404 "$id is not in the shipped library" }
                $body = $t; $file = "$id-$($t.version)"
            }
            New-EpsWebResponse -Body ($body | ConvertTo-Json -Depth 30) -ContentType 'application/json; charset=utf-8' -Headers @{ 'Content-Disposition' = "attachment; filename=""$file.json""" } -Audit @{ Target = "CaTemplate|$id"; After = @{ which = $(if ("$($c.Query.which)" -eq 'before') { 'before' } else { 'after' }) } } } }
        @{ Method = 'POST'; Pattern = '^/api/ca/template-updates/take$'; Summary = 'Take what a newer template library brings: persona changes applied to the personas or skipped, template changes marked as seen; no policy is written.'; Body = 'templates: CA numbers whose change you have seen; personas: [{ name, apply: true = change the persona, false = skip }]'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'ca.template.take'; NeedsReason = $true; Handler = { param($c, $m)
            $t = 'CaTemplateTaken'
            $ids = @(@($c.Body.templates) | ForEach-Object { "$_".Trim().ToUpperInvariant() } | Where-Object { $_ } | Select-Object -Unique)
            $pers = @(@($c.Body.personas) | Where-Object { $_ })
            $bad = if (-not $ids.Count -and -not $pers.Count) { 'take at least one template or one persona change' }
                elseif ($ids.Count -gt 1000 -or $pers.Count -gt 200) { 'too many items in one request' }
                elseif (@($ids | Where-Object { $_ -notmatch $script:EpsCaTemplateIdRx }).Count) { "'$(@($ids | Where-Object { $_ -notmatch $script:EpsCaTemplateIdRx })[0])' is not a CA number" }
                elseif (@($pers | Where-Object { "$($_.name)" -notmatch $script:EpsCaPersonaNamePattern -or $_.apply -isnot [bool] }).Count) { 'each persona change: a name and apply true or false' }
            if ($bad) { return New-EpsWebResponse -Status 400 -Body @{ error = $bad } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $bad } }
            $r = Invoke-EpsCaTemplateTake -ConnectionString $c.Ctx.ConnectionString -Templates $ids -Personas $pers -Actor ([string]$c.Caller.identity)
            $parts = @()
            if ($r.Templates.Count) { $parts += "$($r.Templates.Count) template change(s) marked as seen" }
            if ($r.Applied.Count) { $parts += "persona(s) changed: $($r.Applied -join ', ')" }
            if ($r.Skipped.Count) { $parts += "persona change(s) skipped: $($r.Skipped -join ', ')" }
            if ($r.NotPending.Count) { $parts += "not pending (taken already or no change): $($r.NotPending -join ', ')" }
            if (-not ($r.Templates.Count + $r.Applied.Count + $r.Skipped.Count)) { return New-EpsWebResponse -Status 409 -Body @{ error = "nothing to take - $($parts -join '; ')"; notPending = @($r.NotPending) } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'nothing pending' } }
            New-EpsWebResponse -Body @{ ok = $true; templates = @($r.Templates); applied = @($r.Applied); skipped = @($r.Skipped); notPending = @($r.NotPending); text = "$($parts -join '; '). No Conditional Access policy was changed." } -Audit @{ Target = $t; After = @{ changes = @($r.Changes); notPending = @($r.NotPending) } } } }

        # ---- Conditional Access management, the READ-ONLY half (DESIGN §5.1; owner 2026-10-30: "dont touch any ca policy
        # stuff ... otherwise i can be locked out of my tenant"). The web app reads what the engine stored; Adopt / Release
        # are RECORDS the engine writes from the operator's signed request - nothing in the tenant ever changes. ----
        @{ Method = 'GET'; Pattern = '^/api/capolicies$'; Summary = 'The Conditional Access policies as the engine last read them: each one''s template, stage, differences, exclusions and whether it is adopted.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $o = Get-EpsCaOverview -ConnectionString $cs
            $cat = Get-EpsCaTemplateCatalog
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue $o.Rows); findings = @(ConvertTo-EpsWebValue $o.Findings)
                monitoring = "$(Get-EpsSetting -ConnectionString $cs -Name 'CA.Monitoring.Enabled' -Default 'false')" -eq 'true'
                method = "$(Get-EpsSetting -ConnectionString $cs -Name 'CA.GroupTargetingMethod' -Default '')"
                templates = @($cat.templates).Count; library = $cat.library; stages = @($cat.stages)
                readAtUtc = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $cs -Query 'SELECT MAX(SeenAtUtc) AS At FROM eps.CaPolicy'))[0].At } } }
        @{ Method = 'GET'; Pattern = '^/api/capolicies/policies/(?<policy>[0-9a-fA-F-]{36})$'; Summary = 'One Conditional Access policy: its body with the names, its review against the template, its adoption record and its findings.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $d = Get-EpsCaPolicyDetail -ConnectionString $c.Ctx.ConnectionString -PolicyId ([guid]$m.policy)
            if (-not $d) { return New-EpsWebError 404 'no such policy in the last read of the policy list' }
            $t = if ($d.Review -and $d.Review.templateId) { (Get-EpsCaTemplateCatalog).ById["$($d.Review.templateId)"] }
            New-EpsWebResponse -Body @{ policy = @(ConvertTo-EpsWebValue ($d.Policy | Select-Object PolicyId, DisplayName, State, ModifiedAtUtc, SeenAtUtc))[0]; body = $d.Body; names = $d.Names; review = $d.Review
                adoption = @(ConvertTo-EpsWebValue $d.Adoption)[0]; findings = @(ConvertTo-EpsWebValue $d.Findings); documentation = $d.Documentation; template = $t
                moves = @(ConvertTo-EpsWebValue $d.Moves); stageMoves = @(Get-EpsCaStageMoves "$($d.Review.stage)"); stages = @($script:EpsCaStageOrder) } } }
        # CA-LIFECYCLE (owner 2026-11-03: "in ca policy i need buttons to easily controll and movevto another lufecycle phase
        # like pilot1, pilot2"; "Write on approval", "SuperAdmin only"): the preview of ONE move, from the last read - the
        # page shows it before the operator approves; the engine makes the plan again from the live policy before it writes
        @{ Method = 'GET'; Pattern = '^/api/capolicies/policies/(?<policy>[0-9a-fA-F-]{36})/stage-plan$'; Summary = 'What moving one Conditional Access policy to another stage would change (its name, state and who it targets), from the last read. Changes nothing.'; Body = 'to: Pilot1, Pilot2, Pilot3, Prod or Disabled'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $to = "$($c.Query.to)"
            if ($to -notin @($script:EpsCaStageOrder) + 'Disabled') { return New-EpsWebError 400 'to: one of Pilot1, Pilot2, Pilot3, Prod or Disabled' }
            $plan = Get-EpsCaStagePlanFromStore -ConnectionString $c.Ctx.ConnectionString -PolicyId ([guid]$m.policy) -To $to
            if (-not $plan) { return New-EpsWebError 404 'no such policy in the last read of the policy list' }
            $ad = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ p = [guid]$m.policy } -Query 'SELECT Status FROM eps.CaAdoption WHERE PolicyId = @p')[0]
            $plan.adopted = [bool]($ad -and "$($ad.Status)" -eq 'Adopted')
            if ($plan.ok -and -not $plan.adopted) { $plan.ok = $false; $plan.reason = 'only an adopted policy moves through the stages - adopt it first' }
            New-EpsWebResponse -Body $plan } }
        @{ Method = 'POST'; Pattern = '^/api/capolicies/policies/(?<policy>[0-9a-fA-F-]{36})/stage$'; Summary = 'Move one adopted Conditional Access policy one stage, or disable it, after the engine checks it again (break-glass included).'; Body = 'to; expected: the review hash as you saw it; reason'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'ca.policy.stage'; NeedsReason = $true; Handler = { param($c, $m)
            $t = "CaPolicy|$($m.policy)"; $to = "$($c.Body.to)"
            if ($to -notin @($script:EpsCaStageOrder) + 'Disabled') { return New-EpsWebResponse -Status 400 -Body @{ error = 'to: one of Pilot1, Pilot2, Pilot3, Prod or Disabled' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "bad stage '$to'" } }
            if (-not (Get-Command Invoke-EpsCaStageMove -ErrorAction SilentlyContinue)) { return New-EpsWebResponse -Status 500 -Body @{ error = 'only the engine changes a Conditional Access policy' } -Audit @{ Target = $t; Outcome = 'error'; OutcomeText = 'not the engine' } }
            $s = Invoke-EpsCaStageMove -ConnectionString $c.Ctx.ConnectionString -PolicyId ([guid]$m.policy) -To $to -Expected "$($c.Body.expected)" -Actor $c.Caller.identity -Reason "$($c.Body.reason)"
            $code = switch ($s.Result) { 'ok' { 200 } 'missing' { 404 } 'changed' { 409 } 'notadopted' { 409 } 'refused' { 409 } default { 502 } }
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status $code -Body @{ error = "Not moved: $($s.Reason). The policy was not changed." } -Audit @{ Target = $t; Outcome = $(if ($code -eq 502) { 'error' } else { 'refused' }); OutcomeText = "$($s.Reason)" } }
            New-EpsWebResponse -Body @{ ok = $true; verified = [bool]$s.Verified; text = "Moved $($s.Before.displayName) from $($s.Before.stage) to $to$(if ($s.After.displayName -cne $s.Before.displayName) { " (now $($s.After.displayName))" }).$(if (-not $s.Verified) { " Read back, it differs from the plan: $($s.Differs -join '; ')." })" } `
                -Audit @{ Target = "$t ($($s.After.displayName))"; Before = $s.Before; After = $s.After } } }
        # GET-STARTED (owner 2026-11-03: "i also need a get started wizard to onboard fxbreak glass, auth methods, naming
        # conv for groups etc. see all req in v1 scripts"; DESIGN §5.10): the engine checks, the page shows what it found
        @{ Method = 'GET'; Pattern = '^/api/onboarding$'; Summary = 'Get started: every onboarding step with what the last check found, the break-glass accounts and the targeting method.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $o = Get-EpsOnboardingOverview -ConnectionString $cs
            New-EpsWebResponse -Body @{ steps = @($o.Steps); checkedAtUtc = @(ConvertTo-EpsWebValue ([pscustomobject]@{ At = $o.CheckedAtUtc }))[0].At; checkedBy = $o.CheckedBy
                breakGlass = @(ConvertTo-EpsWebValue (Get-EpsBreakGlassAccounts -ConnectionString $cs))
                method = "$(Get-EpsSetting -ConnectionString $cs -Name 'CA.GroupTargetingMethod' -Default '')"; methods = @((Get-EpsCaTemplateCatalog).groupTargetingMethods) } } }
        @{ Method = 'POST'; Pattern = '^/api/onboarding/check$'; Summary = 'Check every onboarding step against the tenant now (reads only).'; Body = 'reason'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'onboarding.check'; NeedsReason = $true; Handler = { param($c, $m)
            if (-not (Get-Command Invoke-EpsOnboardingCheck -ErrorAction SilentlyContinue)) { return New-EpsWebError 500 'only the engine checks the tenant' }
            $r = Invoke-EpsOnboardingCheck -ConnectionString $c.Ctx.ConnectionString
            Save-EpsOnboardingCheck -ConnectionString $c.Ctx.ConnectionString -Rows $r.Rows -Actor $c.Caller.identity
            $n = { param($s) @($r.Rows | Where-Object { $_.state -eq $s }).Count }
            New-EpsWebResponse -Body @{ ok = $true; text = "Checked $(@($r.Rows).Count) item(s): $(& $n 'ok') ok, $(& $n 'missing') missing, $(& $n 'check') to check. Nothing in the tenant was changed." } -Audit @{ Target = 'Onboarding'; After = @{ items = @($r.Rows).Count; missing = (& $n 'missing') } } } }
        @{ Method = 'POST'; Pattern = '^/api/breakglass$'; Summary = 'Add or change a break-glass account in EntraPolicySuite''s list (the accounts every policy must exclude).'; Body = 'upn; displayName; method: MFA or FIDO; placement: where it is kept (no secret); enabled; reason'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'breakglass.change'; NeedsReason = $true; Handler = { param($c, $m)
            $b = $c.Body; $upn = "$($b.upn)".Trim()
            $bad = if ($upn -notmatch '^[^@\s]{1,200}@[A-Za-z0-9.-]{3,100}$') { 'upn: a user principal name (name@domain)' } elseif ("$($b.method)" -notin '', 'MFA', 'FIDO') { 'method: MFA or FIDO' } elseif ("$($b.placement)".Length -gt 1000 -or "$($b.displayName)".Length -gt 200) { 'placement at most 1000, displayName at most 200 characters' } elseif ($null -ne $b.enabled -and $b.enabled -isnot [bool]) { 'enabled: true or false' }
            if ($bad) { return New-EpsWebResponse -Status 400 -Body @{ error = $bad } -Audit @{ Target = "BreakGlassAccount|$upn"; Outcome = 'refused'; OutcomeText = $bad } }
            $s = Save-EpsBreakGlassAccount -ConnectionString $c.Ctx.ConnectionString -UserPrincipalName $upn -DisplayName "$($b.displayName)" -Method "$($b.method)" -Placement "$($b.placement)" -Enabled $(if ($null -eq $b.enabled) { $true } else { [bool]$b.enabled }) -Actor $c.Caller.identity
            New-EpsWebResponse -Body @{ ok = $true; text = $(if ($s.Result -eq 'unchanged') { "Nothing to change for $upn." } else { "Saved $upn in the break-glass list. Nothing in the tenant changed - read the policy list again to check every policy excludes it." }) } -Audit @{ Target = "BreakGlassAccount|$upn"; Before = $s.Before; After = $s.After } } }
        @{ Method = 'GET'; Pattern = '^/api/capolicies/templates$'; Summary = 'The Conditional Access template library of this release (CA000-CA800), each template with its stages and its notes.'; Body = 'id: one template, with its body'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $cat = Get-EpsCaTemplateCatalog
            if ("$($c.Query.id)") { $t = $cat.ById["$($c.Query.id)".ToUpperInvariant()]; if (-not $t) { return New-EpsWebError 404 'no such template' }; return New-EpsWebResponse -Body @{ template = $t; refs = $cat.refs; stageState = $cat.stageState } }
            New-EpsWebResponse -Body @{ library = $cat.library; stages = @($cat.stages); refs = $cat.refs
                rows = @($cat.templates | ForEach-Object { [ordered]@{ id = $_.id; version = $_.version; name = $_.name; persona = $_.persona; breakGlassPolicy = [bool]$_.breakGlassPolicy; incomplete = [bool]$_.incomplete; notes = (@($_.gaps) -join '; ') } }) } } }
        @{ Method = 'POST'; Pattern = '^/api/capolicies/policies/(?<policy>[0-9a-fA-F-]{36})/adopt$'; Summary = 'Adopt a Conditional Access policy as it is: EntraPolicySuite records it (its body becomes the baseline). Nothing in the tenant changes.'; Body = 'expected: the review hash as you saw it; reason'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'ca.policy.adopt'; NeedsReason = $true; Handler = { param($c, $m)
            $t = "CaPolicy|$($m.policy)"
            $s = Save-EpsCaAdoption -ConnectionString $c.Ctx.ConnectionString -PolicyId ([guid]$m.policy) -Expected "$($c.Body.expected)" -Actor $c.Caller.identity -Reason "$($c.Body.reason)"
            if ($s.Result -eq 'missing') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such policy in the last read of the policy list (read it again)' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            if ($s.Result -eq 'changed') { return New-EpsWebResponse -Status 409 -Body @{ error = 'the policy changed since you looked at it (a newer read of the tenant) - reload and look again' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'changed since seen' } }
            if ($s.Result -eq 'already') { return New-EpsWebResponse -Status 409 -Body @{ error = "the policy is already adopted (by $($s.By))" } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'already adopted' } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Adopted $($s.After.displayName): recorded in EntraPolicySuite only - nothing in the tenant changed." } -Audit @{ Target = "$t ($($s.After.displayName))"; Before = $s.Before; After = $s.After } } }
        @{ Method = 'POST'; Pattern = '^/api/capolicies/policies/(?<policy>[0-9a-fA-F-]{36})/release$'; Summary = 'Stop managing an adopted Conditional Access policy in EntraPolicySuite (the record says so). Nothing in the tenant changes.'; Body = 'reason'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'ca.policy.release'; NeedsReason = $true; Handler = { param($c, $m)
            $t = "CaPolicy|$($m.policy)"
            $s = Save-EpsCaRelease -ConnectionString $c.Ctx.ConnectionString -PolicyId ([guid]$m.policy) -Actor $c.Caller.identity -Reason "$($c.Body.reason)"
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 404 -Body @{ error = 'the policy is not adopted' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'not adopted' } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Released $($s.Before.displayName): EntraPolicySuite no longer manages it - nothing in the tenant changed." } -Audit @{ Target = "$t ($($s.Before.displayName))"; Before = $s.Before; After = @{ status = 'Released' } } } }
        @{ Method = 'GET'; Pattern = '^/api/capolicies/documentation$'; Summary = 'The Conditional Access documentation: one row per policy, every id resolved to a name where it could be read.'; Body = 'ids: 1 keeps each id next to its name'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $rows = @(Invoke-EpsSql -ConnectionString $cs -Query 'SELECT PolicyId, BodyJson, ReviewJson FROM eps.CaPolicy ORDER BY DisplayName')
            New-EpsWebResponse -Body @{ columns = @(Get-EpsCaDocColumns); rows = @(Get-EpsCaDocumentationRows -Rows $rows -Names (Get-EpsCaNameMap -ConnectionString $cs) -WithIds:("$($c.Query.ids)" -eq '1')) } } }
        @{ Method = 'GET'; Pattern = '^/api/capolicies/documentation/export$'; Summary = 'The Conditional Access documentation as an Excel or CSV file.'; Body = 'format: xlsx or csv; ids: 1 keeps each id next to its name'; Answer = 'file (xlsx or CSV)'; Public = $false
           Role = 'Reader'; Action = 'ca.documentation.export'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $ids = "$($c.Query.ids)" -eq '1'
            $rows = @(Get-EpsCaDocumentationRows -Rows @(Invoke-EpsSql -ConnectionString $cs -Query 'SELECT PolicyId, BodyJson, ReviewJson FROM eps.CaPolicy ORDER BY DisplayName') -Names (Get-EpsCaNameMap -ConnectionString $cs) -WithIds:$ids)
            $file = "Entra-CA-Policies-Documentation$(if ($ids) { '-with-IDs' })-$([datetime]::UtcNow.ToString('yyyyMMdd'))"
            $audit = @{ Target = 'CaPolicy|documentation'; After = @{ rows = $rows.Count; format = "$($c.Query.format)"; ids = $ids } }
            if ("$($c.Query.format)" -eq 'xlsx') {
                $bytes = ConvertTo-EpsXlsx -Sheets ([ordered]@{ 'CA policies' = @($rows) })
                return New-EpsWebResponse -Body $bytes -ContentType 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' -Headers @{ 'Content-Disposition' = "attachment; filename=""$file.xlsx""" } -Audit $audit
            }
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $rows -Columns @(Get-EpsCaDocColumns)) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = "attachment; filename=""$file.csv""" } -Audit $audit } }

        # ---- the identity report (DESIGN §5.4): READ ONLY - the snapshot the engine wrote; saved views (LIST-1) ----
        @{ Method = 'GET'; Pattern = '^/api/identity$'; Summary = 'The identity report: the latest snapshot, its views (each gap with its severity) and the ready-made pivots.'; Body = 'run: an earlier snapshot'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $run = Get-EpsIdentityLatestRun -ConnectionString $cs -RunId "$($c.Query.run)"
            $counts = if ($run -and $run.ViewCountsJson) { $run.ViewCountsJson | ConvertFrom-Json -AsHashtable } else { @{} }
            $views = @(foreach ($v in Get-EpsIdentityViewCatalog) { [ordered]@{ name = $v.Name; group = $v.Group; kind = $v.Kind; severity = $v.Severity; title = $v.Title; what = $v.What; fix = $v.Fix; columns = $v.Columns; v1 = $v.V1; count = $(if ($counts.ContainsKey($v.Name)) { $counts[$v.Name] } else { $null }) } })
            $hist = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $cs -Query 'SELECT TOP 30 RunId, CreatedAtUtc, Users, Devices, ViewCountsJson FROM eps.IdentitySnapshot ORDER BY CreatedAtUtc DESC'))
            $ad = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $cs -Query 'SELECT RequestedAtUtc, RefreshedAtUtc, Users, Error FROM eps.AdUserSnapshotInfo WHERE Id = 1'))[0]
            $cols = @{}; if ($run) { foreach ($k in 'User', 'Device') { $cols[$k] = Get-EpsIdentityColumns -ConnectionString $cs -RunId $run.RunId -Kind $k } }
            New-EpsWebResponse -Body @{ snapshot = $(if ($run) { @(ConvertTo-EpsWebValue ($run | Select-Object RunId, CreatedAtUtc, Users, Devices, NotesJson))[0] }); views = $views
                pivots = $(if ($run -and $run.PivotsJson) { $run.PivotsJson | ConvertFrom-Json } else { @() }); history = $hist; ad = $ad; columns = $cols
                enabled = "$(Get-EpsSetting -ConnectionString $cs -Name 'IdentityReport.Enabled' -Default 'false')" -eq 'true'; me = $c.Caller.identity; role = $c.Role } } }
        @{ Method = 'GET'; Pattern = '^/api/identity/rows$'; Summary = 'The rows of one view: filtered, sorted and one page at a time.'; Body = 'view; filters (JSON list of column / op / value); q; sort; dir; columns; page; pageSize'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $q = Resolve-EpsIdentityQuery -ConnectionString $c.Ctx.ConnectionString -Query $c.Query
            if (-not $q.Ok) { return New-EpsWebError $q.Status $q.Error }
            $pg = Get-EpsWebPaging $c.Query; $p = $q.Parameters + @{ k = $pg.Skip; n = $pg.Size }
            $total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $q.Parameters -Query "SELECT COUNT(*) $($q.From) $($q.Where)"
            $rows = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $p -Query "SELECT r.Data $($q.From) $($q.Where) $(Get-EpsIdentityOrderBy $q.Columns "$($c.Query.sort)" "$($c.Query.dir)") OFFSET @k ROWS FETCH NEXT @n ROWS ONLY" | ForEach-Object { $_.Data | ConvertFrom-Json })
            New-EpsWebResponse -Body @{ total = $total; rows = $rows; view = $q.View.Name; kind = $q.Kind } } }
        @{ Method = 'GET'; Pattern = '^/api/identity/pivot$'; Summary = 'The counts of one view by a column, or a column by a column.'; Body = 'view; rows; cols; filters; q'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $q = Resolve-EpsIdentityQuery -ConnectionString $c.Ctx.ConnectionString -Query $c.Query
            if (-not $q.Ok) { return New-EpsWebError $q.Status $q.Error }
            $rk = "$($c.Query.rows)"; $ck = "$($c.Query.cols)"
            if (-not $q.Columns.Contains($rk)) { return New-EpsWebError 400 "pivot rows: unknown column '$rk'" }
            if ($ck -and -not $q.Columns.Contains($ck)) { return New-EpsWebError 400 "pivot columns: unknown column '$ck'" }
            $a = "ISNULL(NULLIF(JSON_VALUE(r.Data, '$.`"$rk`"'), ''), '(empty)')"; $b = if ($ck) { "ISNULL(NULLIF(JSON_VALUE(r.Data, '$.`"$ck`"'), ''), '(empty)')" } else { "'Count'" }
            $grp = if ($ck) { "$a, $b" } else { $a }   # a constant may not be in GROUP BY (found by Test-EpsLeastPrivilege)
            $cells = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $q.Parameters -Query "SELECT TOP 5000 $a AS R, $b AS C, COUNT(*) AS N $($q.From) $($q.Where) GROUP BY $grp")
            $byRow = [ordered]@{}; $colTot = @{}
            foreach ($x in $cells) { $r0 = [string]$x.R; $c0 = [string]$x.C; if (-not $byRow.Contains($r0)) { $byRow[$r0] = @{} }; $byRow[$r0][$c0] = [int]$x.N; $colTot[$c0] = [int]$colTot[$c0] + [int]$x.N }
            $columns = @($colTot.Keys | Sort-Object @{ e = { $colTot[$_] }; Descending = $true }, @{ e = { $_ } })
            $rows = @($byRow.Keys | ForEach-Object { $t = 0; foreach ($v in $byRow[$_].Values) { $t += $v }; [pscustomobject]@{ Value = $_; Counts = $byRow[$_]; Total = $t } } | Sort-Object @{ e = { $_.Total }; Descending = $true }, Value)
            New-EpsWebResponse -Body @{ rowKey = $rk; columnKey = $ck; columns = $columns; rows = $rows; total = ($rows | Measure-Object Total -Sum).Sum; truncated = ($cells.Count -ge 5000) } } }
        @{ Method = 'GET'; Pattern = '^/api/identity/export$'; Summary = 'One view, or the whole report, as an Excel or CSV file (at most 200,000 rows).'; Body = 'view; format: xlsx or csv; filters; q; sort; dir; columns'; Answer = 'file (xlsx or CSV)'; Public = $true
           Role = 'Reader'; Action = 'identity.export'; Handler = { param($c, $m)
            $q = Resolve-EpsIdentityQuery -ConnectionString $c.Ctx.ConnectionString -Query $c.Query
            if (-not $q.Ok) { return New-EpsWebResponse -Status $q.Status -Body @{ error = $q.Error } -Audit @{ Target = 'IdentityReport'; Outcome = 'refused'; OutcomeText = $q.Error } }
            # SEC-AUDIT-1 S9: one export may not hold the (single-threaded) web app for everyone - at most 200,000 rows
            $cnt = [int](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $q.Parameters -Query "SELECT COUNT(*) $($q.From) $($q.Where)")
            if ($cnt -gt 200000) { return New-EpsWebResponse -Status 413 -Body @{ error = "$cnt rows - narrow the filter (an export holds at most 200,000)" } -Audit @{ Target = "IdentityView|$($q.View.Name)"; Outcome = 'refused'; OutcomeText = "$cnt rows" } }
            $rows = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $q.Parameters -Query "SELECT r.Data $($q.From) $($q.Where) $(Get-EpsIdentityOrderBy $q.Columns "$($c.Query.sort)" "$($c.Query.dir)")" | ForEach-Object { $_.Data | ConvertFrom-Json })
            $cols = @(if ("$($c.Query.columns)") { "$($c.Query.columns)" -split ',' | Where-Object { $q.Columns.Contains($_) } } else { $q.Columns.Keys })
            $file = "eps-identity-$($q.View.Name)-$(([datetime]$q.Run.CreatedAtUtc).ToString('yyyyMMdd'))"
            $audit = @{ Target = "IdentityView|$($q.View.Name)"; After = @{ rows = $rows.Count; format = "$($c.Query.format)"; filters = "$($c.Query.filters)"; q = "$($c.Query.q)" } }
            if ("$($c.Query.format)" -eq 'xlsx') {
                $sheet = @($rows | Select-Object -Property $cols)
                $bytes = ConvertTo-EpsXlsx -Sheets ([ordered]@{ $q.View.Name = $sheet })
                return New-EpsWebResponse -Body $bytes -ContentType 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' -Headers @{ 'Content-Disposition' = "attachment; filename=""$file.xlsx""" } -Audit $audit
            }
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $rows -Columns $cols) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = "attachment; filename=""$file.csv""" } -Audit $audit } }
        @{ Method = 'POST'; Pattern = '^/api/identity/run$'; Summary = 'Request an identity report run now.'; Public = $true
           Role = 'Admin'; Action = 'identity.run.request'; NeedsReason = $true; Handler = { param($c, $m)
            if ("$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name 'IdentityReport.Enabled' -Default 'false')" -ne 'true') { return New-EpsWebResponse -Status 400 -Body @{ error = 'the identity report is switched off (Settings > Identity report)' } -Audit @{ Target = 'IdentityReport'; Outcome = 'refused'; OutcomeText = 'feature off' } }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job 'IdentityReport' -Mode 'Preview' -Scope $null
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = 'Requested: the report runs within 5 minutes - read only, nothing in the tenant or AD is changed.' } -Audit @{ Target = 'IdentityReport'; After = @{ requestId = $rq } } } }
        @{ Method = 'GET'; Pattern = '^/api/identity/saved$'; Summary = 'Your saved views and the shared ones.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ me = $c.Caller.identity; oid = [guid]$c.Caller.objectId } -Query "SELECT ViewId, Name, Owner, Shared, IsDefault, Definition, UpdatedAtUtc, CASE WHEN OwnerId = @oid OR (OwnerId IS NULL AND Owner = @me) THEN 1 ELSE 0 END AS Mine FROM eps.SavedView WHERE Page = 'identity' AND (Shared = 1 OR OwnerId = @oid OR (OwnerId IS NULL AND Owner = @me)) ORDER BY Shared DESC, Name")) } } }
        @{ Method = 'PUT'; Pattern = '^/api/identity/saved/(?<vid>[0-9a-fA-F-]{36})$'; Summary = 'Save a view: your own, or shared.'; Body = 'name; definition (view, filters, columns, pivot); shared; isDefault'; Public = $true
           Role = 'Reader'; Action = 'view.save'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $t = "SavedView|$($m.vid)"
            $name = "$($c.Body.name)".Trim(); $shared = [bool]$c.Body.shared; $def = [bool]$c.Body.isDefault
            if ($name.Length -lt 1 -or $name.Length -gt 100 -or $name -match '[\u0000-\u001f]') { return New-EpsWebResponse -Status 400 -Body @{ error = 'a name of 1 to 100 characters' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'name' } }
            if (($shared -or $def) -and -not (Test-EpsWebRole -Have $c.Role -Need 'SuperAdmin')) { return New-EpsWebResponse -Status 403 -Body @{ error = 'only a SuperAdmin saves a shared or default view (LIST-1); save it as your own' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'shared needs SuperAdmin' } }
            $v = Test-EpsSavedViewDefinition -Definition $c.Body.definition
            if (-not $v.Ok) { return New-EpsWebResponse -Status 400 -Body @{ error = $v.Error } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $v.Error } }
            $cur = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ i = [guid]$m.vid } -Query 'SELECT Owner, OwnerId, Shared FROM eps.SavedView WHERE ViewId = @i')[0]
            $mine = $cur -and ($(if ($cur.OwnerId) { "$($cur.OwnerId)" -eq "$($c.Caller.objectId)" } else { $cur.Owner -eq $c.Caller.identity }))
            if ($cur -and -not $mine -and -not (Test-EpsWebRole -Have $c.Role -Need 'SuperAdmin')) { return New-EpsWebResponse -Status 403 -Body @{ error = 'this view is someone else''s' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'not the owner' } }
            $p = @{ i = [guid]$m.vid; n = $name; o = $c.Caller.identity; oid = [guid]$c.Caller.objectId; s = $shared; d = ($shared -and $def); j = $v.Json }
            $sql = if ($cur) { 'UPDATE eps.SavedView SET Name = @n, Shared = @s, IsDefault = @d, Definition = @j, UpdatedAtUtc = SYSUTCDATETIME() WHERE ViewId = @i' } else { "INSERT INTO eps.SavedView (ViewId, Page, Name, Owner, OwnerId, Shared, IsDefault, Definition) VALUES (@i, 'identity', @n, @o, @oid, @s, @d, @j)" }
            if ($p.d) { $sql = "SET XACT_ABORT ON; BEGIN TRAN; UPDATE eps.SavedView SET IsDefault = 0 WHERE Page = 'identity' AND ViewId <> @i; $sql; COMMIT;" }
            [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters $p -Query $sql)
            New-EpsWebResponse -Body @{ ok = $true; text = "View '$name' saved$(if ($shared) { ' (shared with everyone)' })." } -Audit @{ Target = $t; After = @{ name = $name; shared = $shared; isDefault = $p.d } } } }
        @{ Method = 'DELETE'; Pattern = '^/api/identity/saved/(?<vid>[0-9a-fA-F-]{36})$'; Summary = 'Delete a saved view.'; Public = $false
           Role = 'Reader'; Action = 'view.delete'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString; $t = "SavedView|$($m.vid)"
            $cur = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ i = [guid]$m.vid } -Query 'SELECT Name, Owner, OwnerId, Shared FROM eps.SavedView WHERE ViewId = @i')[0]
            if (-not $cur) { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such view' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'missing' } }
            $mine = if ($cur.OwnerId) { "$($cur.OwnerId)" -eq "$($c.Caller.objectId)" } else { $cur.Owner -eq $c.Caller.identity }
            if (($cur.Shared -or -not $mine) -and -not (Test-EpsWebRole -Have $c.Role -Need 'SuperAdmin')) { return New-EpsWebResponse -Status 403 -Body @{ error = 'only its owner deletes a view; a shared view only a SuperAdmin' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = 'not allowed' } }
            [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters @{ i = [guid]$m.vid } -Query 'DELETE FROM eps.SavedView WHERE ViewId = @i')
            New-EpsWebResponse -Body @{ ok = $true; text = "View '$($cur.Name)' deleted." } -Audit @{ Target = $t; Before = @{ name = $cur.Name; shared = [bool]$cur.Shared } } } }

        # "Send a test mail": the engine sends one through the configured sender, as ITS identity (the scoped right)
        @{ Method = 'POST'; Pattern = '^/api/mail/test$'; Summary = 'Ask the engine to send one test mail to the alert recipients.'; Public = $true
           Role = 'Admin'; Action = 'mail.test.request'; NeedsReason = $true; Handler = { param($c, $m)
            $cfg = Get-EpsMailConfig -ConnectionString $c.Ctx.ConnectionString
            if ($cfg.Mode -ne 'sharedMailbox' -or -not $cfg.Sender) { return New-EpsWebResponse -Status 400 -Body @{ error = 'alert mail is not set up (Mail.Mode / Mail.Sender) - run Initialize-EpsMailSender.ps1' } -Audit @{ Target = 'Mail'; Outcome = 'refused'; OutcomeText = 'mail not set up' } }
            $rq = New-EpsSignedJobRequest -Ctx $c -Job 'TamperMonitor' -Mode 'Preview' -Scope @{ testMail = $true }
            New-EpsWebResponse -Status 202 -Body @{ requestId = $rq; text = "Requested: the engine sends a test mail from $($cfg.Sender) to $(@($cfg.Recipients) -join ', ') within 5 minutes (Jobs > Requests shows the result)." } -Audit @{ Target = "Mail|$($cfg.Sender)"; After = @{ requestId = $rq; recipients = @($cfg.Recipients) } } } }
        # ---- the commit queue (owner 2026-10-31, PIM's setup): staged tagging-config changes, committed by hand ----
        @{ Method = 'GET'; Pattern = '^/api/queue$'; Summary = 'The commit queue: staged tagging changes and what became of them.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $cs -Query "SELECT Id, ObjectType, Entity, EntityKey, Op, Summary, Action, BodyJson, BeforeJson, StagedBy, StagedAtUtc, StageReason, Status, CommitId, CommittedBy, CommittedAtUtc, Error, DiscardedBy, DiscardedAtUtc, DiscardReason FROM eps.PendingChange WHERE Status = 'Pending' OR Id IN (SELECT TOP (200) Id FROM eps.PendingChange WHERE Status <> 'Pending' ORDER BY Id DESC) ORDER BY Id DESC"))
            New-EpsWebResponse -Body @{ rows = $rows; enabled = (Test-EpsCommitQueueOn -ConnectionString $cs)
                secondApprover = "$(Get-EpsSetting -ConnectionString $cs -Name 'CommitQueue.SecondApprover' -Default 'off')"; me = $c.Caller.identity } } }
        @{ Method = 'POST'; Pattern = '^/api/queue/commit$'; Summary = 'Commit staged changes: they are written, then one tagging run is requested.'; Body = 'ids: the staged changes'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'queue.commit'; NeedsReason = $true; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $ids = @($c.Body.ids | Where-Object { "$_" -match '^\d{1,18}$' } | ForEach-Object { [long]$_ })
            if (-not $ids.Count) { return New-EpsWebResponse -Status 400 -Body @{ error = 'select at least one change to commit' } -Audit @{ Target = 'PendingChange'; Outcome = 'refused'; OutcomeText = 'nothing selected' } }
            $pend = @(Invoke-EpsSql -ConnectionString $cs -Query "SELECT Id, StagedBy FROM eps.PendingChange WHERE Status = 'Pending'" | Where-Object { $ids -contains [long]$_.Id })
            if ($pend.Count -ne $ids.Count) { return New-EpsWebResponse -Status 409 -Body @{ error = 'some of the selected changes are no longer waiting (committed, discarded or replaced) - reload' } -Audit @{ Target = 'PendingChange'; Outcome = 'refused'; OutcomeText = 'stale selection' } }
            # four-eyes (PIM's PendingSecondApprover): 'all' = nobody commits a change they staged themselves
            if ("$(Get-EpsSetting -ConnectionString $cs -Name 'CommitQueue.SecondApprover' -Default 'off')" -eq 'all') {
                $own = @($pend | Where-Object { [string]::Equals([string]$_.StagedBy, [string]$c.Caller.identity, [StringComparison]::OrdinalIgnoreCase) })
                if ($own.Count) { return New-EpsWebResponse -Status 403 -Body @{ error = "a second approver is required (CommitQueue.SecondApprover): another admin must commit your own change(s) #$(@($own.Id) -join ', #')" } -Audit @{ Target = 'PendingChange'; Outcome = 'refused'; OutcomeText = 'second approver required'; Guard = $true } }
            }
            $r = Invoke-EpsCommitQueue -Commit $c -Ids $ids -Reason "$($c.Body.reason)"
            $txt = "Committed $($r.Applied) change(s)$(if ($r.Failed) { ", $($r.Failed) FAILED (see the queue)" }). $(@($r.Runs | ForEach-Object text) -join ' ')"
            New-EpsWebResponse -Status $(if ($r.Applied) { 200 } else { 409 }) -Body @{ ok = [bool]$r.Applied; commitId = "$($r.CommitId)"; items = $r.Items; runs = $r.Runs; text = $txt; error = $(if (-not $r.Applied) { $txt }) } `
                -Audit @{ Target = "Commit|$($r.CommitId)"; After = @{ ids = $ids; applied = $r.Applied; failed = $r.Failed; runs = $r.Runs }; Outcome = $(if ($r.Failed -and -not $r.Applied) { 'error' } else { 'ok' }); OutcomeText = $txt } } }
        @{ Method = 'POST'; Pattern = '^/api/queue/discard$'; Summary = 'Discard staged changes. Nothing is written.'; Body = 'ids: the staged changes'; Public = $true
           Role = 'Admin'; Action = 'queue.discard'; NeedsReason = $true; Handler = { param($c, $m)
            $ids = @($c.Body.ids | Where-Object { "$_" -match '^\d{1,18}$' } | ForEach-Object { [long]$_ })
            if (-not $ids.Count) { return New-EpsWebResponse -Status 400 -Body @{ error = 'select at least one change to discard' } -Audit @{ Target = 'PendingChange'; Outcome = 'refused'; OutcomeText = 'nothing selected' } }
            $n = 0
            foreach ($id in $ids) { $n += [int](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters @{ id = $id; by = $c.Caller.identity; r = "$($c.Body.reason)" } -Query "UPDATE eps.PendingChange SET Status = 'Discarded', DiscardedBy = @by, DiscardedAtUtc = SYSUTCDATETIME(), DiscardReason = @r WHERE Id = @id AND Status IN ('Pending', 'Failed')") }
            New-EpsWebResponse -Body @{ ok = $true; text = "Discarded $n change(s). Nothing was written; they stay in the list as discarded." } -Audit @{ Target = "PendingChange|$($ids -join ',')"; After = @{ discarded = $n } } } }
        @{ Method = 'POST'; Pattern = '^/api/queue/discard-all$'; Summary = 'Discard every staged change at once.'; Body = 'expectedCount: how many you saw'; Public = $false
           Role = 'SuperAdmin'; Action = 'queue.discard-all'; NeedsReason = $true; Handler = { param($c, $m)
            $cs = $c.Ctx.ConnectionString
            $have = [int](Invoke-EpsSql -ConnectionString $cs -Scalar -Query "SELECT COUNT(*) FROM eps.PendingChange WHERE Status = 'Pending'")
            if ("$($c.Body.expectedCount)" -ne "$have") { return New-EpsWebResponse -Status 409 -Body @{ error = "the queue holds $have waiting change(s), not $($c.Body.expectedCount) - reload and look again" } -Audit @{ Target = 'PendingChange'; Outcome = 'refused'; OutcomeText = "expected $($c.Body.expectedCount), found $have" } }
            $n = [int](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters @{ by = $c.Caller.identity; r = "$($c.Body.reason)" } -Query "UPDATE eps.PendingChange SET Status = 'Discarded', DiscardedBy = @by, DiscardedAtUtc = SYSUTCDATETIME(), DiscardReason = @r WHERE Status = 'Pending'")
            New-EpsWebResponse -Body @{ ok = $true; text = "Discarded all $n waiting change(s)." } -Audit @{ Target = 'PendingChange|all'; After = @{ discarded = $n } } } }

        # ---- saved scopes (DESIGN §5.8): "pilot users" ----
        @{ Method = 'GET'; Pattern = '^/api/scopes$'; Summary = 'The saved scopes: named test groups for Preview and Apply.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT Name, ObjectType, Kind, Definition, UpdatedAtUtc FROM eps.Scope ORDER BY Name')) } } }
        @{ Method = 'PUT'; Pattern = '^/api/scopes/(?<sn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Create or change a saved scope.'; Body = 'objectType: User or Device; scope: { kind, values } or { kind, property, pattern }'; Public = $true
           Role = 'Admin'; Apply = 'Engine'; Action = 'scope.change'; NeedsReason = $true; Handler = { param($c, $m)
            $t = "Scope|$($m.sn)"; $ot = "$($c.Body.objectType)"
            if ($ot -notin 'User', 'Device') { return New-EpsWebResponse -Status 400 -Body @{ error = 'objectType is User or Device' } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = "objectType '$ot'" } }
            $v = ConvertTo-EpsScope -ObjectType $ot -Body $c.Body.scope
            if (-not $v.Ok -or -not $v.Scope) { $e = if ($v.Error) { $v.Error } else { 'a saved scope names objects or a filter (everyone needs no scope)' }; return New-EpsWebResponse -Status 400 -Body @{ error = $e } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $e } }
            $s = Save-EpsScope -ConnectionString $c.Ctx.ConnectionString -Name $m.sn -ObjectType $ot -Scope $v.Scope -Actor $c.Caller.identity
            New-EpsWebResponse -Body @{ ok = $true; text = "Scope $($m.sn) saved." } -Audit @{ Target = $t; Before = $(if ($s.Before) { $s.Before | ConvertFrom-Json }); After = ($s.After | ConvertFrom-Json) } } }
        @{ Method = 'DELETE'; Pattern = '^/api/scopes/(?<sn>[A-Za-z0-9_.-]{1,100})$'; Summary = 'Delete a saved scope.'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'scope.delete'; NeedsReason = $true; Handler = { param($c, $m)
            $s = Remove-EpsScope -ConnectionString $c.Ctx.ConnectionString -Name $m.sn -Actor $c.Caller.identity
            if ($s.Result -ne 'ok') { return New-EpsWebResponse -Status 404 -Body @{ error = 'no such scope' } -Audit @{ Target = "Scope|$($m.sn)"; Outcome = 'refused'; OutcomeText = 'missing' } }
            New-EpsWebResponse -Body @{ ok = $true; text = "Scope $($m.sn) deleted." } -Audit @{ Target = "Scope|$($m.sn)"; Before = ($s.Before | ConvertFrom-Json) } } }
        # the settings catalog (SETTING-INFO-1): the page renders from it, every save is validated against it
        @{ Method = 'GET'; Pattern = '^/api/settings$'; Summary = 'Every setting with its value, its default and its explanation.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m) New-EpsWebResponse -Body (Get-EpsSettingsView -ConnectionString $c.Ctx.ConnectionString) } }
        @{ Method = 'GET'; Pattern = '^/api/settings/(?<key>[A-Za-z.]{3,200})/history$'; Summary = 'The change history of one setting.'; Public = $false
           Role = 'Reader'; Handler = { param($c, $m)
            if (-not (Get-EpsSettingEntry $m.key)) { return New-EpsWebError 404 'no such setting' }
            New-EpsWebResponse -Body @{ key = $m.key; rows = @(ConvertTo-EpsWebValue (Get-EpsSettingHistory -ConnectionString $c.Ctx.ConnectionString -Key $m.key)) } } }
        @{ Method = 'PUT'; Pattern = '^/api/settings/(?<key>[A-Za-z.]{3,200})$'; Summary = 'Change a setting.'; Body = 'value; expected: the value as you saw it'; Public = $false
           Role = 'Admin'; Apply = 'Engine'; Action = 'setting.change'; NeedsReason = $true; Handler = { param($c, $m)
            $key = $m.key; $e = Get-EpsSettingEntry $key; $t = "Setting|$key"
            $no = { param($status, $text) New-EpsWebResponse -Status $status -Body @{ error = $text } -Audit @{ Target = $t; Outcome = 'refused'; OutcomeText = $text } }
            if (-not $e) { return & $no 404 'no such setting' }
            if (-not (Test-EpsWebRole -Have $c.Role -Need $e.role)) { return & $no 403 "this setting needs the $($e.role) role (you are $($c.Role))" }
            if ($e.editable -eq $false) { return & $no 400 "this setting is not changed here: it is set by $($e.setBy)" }
            $v = ConvertTo-EpsSettingValue -Entry $e -Value $c.Body.value
            if (-not $v.Ok) { return & $no 400 "$($e.label): $($v.Error)" }
            if ($e.dependsOn -and $v.Value -ne "$($e.offValue)") {
                foreach ($d in @($e.dependsOn)) { if (-not "$(Get-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Name $d -Default '')".Trim()) { return & $no 400 "$($e.label) = $($v.Value) needs '$((Get-EpsSettingEntry $d).label)' to be set first" } } }
            $s = Save-EpsSetting -ConnectionString $c.Ctx.ConnectionString -Entry $e -Value $v.Value -Actor $c.Caller.identity -CheckExpected:($c.Body.PSObject.Properties.Name -contains 'expected') -Expected $c.Body.expected
            if ($s.Conflict) { return & $no 409 'someone else changed this setting after you opened the page - reload and look again' }
            $before = if ($s.BeforeSet) { @{ value = $s.Before } } else { @{ value = $null; notSet = $true } }
            if (-not $s.Saved) { return New-EpsWebResponse -Body @{ ok = $true; changed = $false; value = $v.Value; text = 'No change: the setting already has this value.' } -Audit @{ Target = $t; Before = $before; OutcomeText = 'no change' } }
            New-EpsWebResponse -Body @{ ok = $true; changed = $true; value = $v.Value; text = "Saved: $($e.label)." } -Audit @{ Target = $t; Before = $before; After = @{ value = $v.Value } } } }
        @{ Method = 'GET'; Pattern = '^/api/worker$'; Summary = 'The hybrid workers and the work packages by state.'; Public = $true
           Role = 'Reader'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ workers = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT * FROM eps.WorkerHeartbeat ORDER BY WorkerName'))
                packages = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT Status, COUNT(*) AS Count FROM eps.WorkPackage GROUP BY Status') } } }
        @{ Method = 'GET'; Pattern = '^/api/access$'; Summary = 'Who has which role in this app.'; Public = $false
           Role = 'Admin'; Handler = { param($c, $m)
            New-EpsWebResponse -Body @{ rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Query 'SELECT Principal, ObjectId, Role, GrantedBy, GrantedAtUtc FROM eps.WebAccess ORDER BY Role DESC, Principal')) } } }
        @{ Method = 'PUT'; Pattern = '^/api/access$'; Summary = 'Give a person a role in this app.'; Body = 'principal: the UPN; role: Reader, Admin or SuperAdmin'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'access.grant'; NeedsReason = $true; Handler = { param($c, $m)
            $who = "$($c.Body.principal)".Trim().ToLowerInvariant(); $role = "$($c.Body.role)"
            if ($who -notmatch '^[^@\s''"]+@[^@\s''"]+\.[^@\s''"]+$') { return New-EpsWebResponse -Status 400 -Body @{ error = 'give the person''s user principal name' } -Audit @{ Target = "WebAccess|$who"; Outcome = 'refused'; OutcomeText = 'not a UPN' } }
            if ($role -notin 'SuperAdmin', 'Admin', 'Reader') { return New-EpsWebResponse -Status 400 -Body @{ error = 'role must be SuperAdmin, Admin or Reader' } -Audit @{ Target = "WebAccess|$who"; Outcome = 'refused'; OutcomeText = "role '$role'" } }
            $before = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ p = $who } -Query 'SELECT Principal, Role FROM eps.WebAccess WHERE Principal = @p')[0]
            if ($before.Role -eq 'SuperAdmin' -and $role -ne 'SuperAdmin' -and (Test-EpsLastSuperAdmin -ConnectionString $c.Ctx.ConnectionString -Principal $who)) { return New-EpsLastSuperAdminRefusal -Who $who }
            # SEC-AUDIT-1 S7: the grant is bound to the person's OBJECT ID now (the engine reads it from Entra), never to
            # whichever account first signs in with that name
            $oid = & $script:EpsResolveUserObjectId $who
            if (-not $oid) { return New-EpsWebResponse -Status 400 -Body @{ error = "no user '$who' in this tenant" } -Audit @{ Target = "WebAccess|$who"; Outcome = 'refused'; OutcomeText = 'no such user' } }
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters @{ p = $who; o = [guid]$oid; r = $role; by = $c.Caller.identity } -Query 'MERGE eps.WebAccess AS d USING (SELECT @p AS Principal) AS s ON d.Principal = s.Principal WHEN MATCHED THEN UPDATE SET Role = @r, ObjectId = @o, GrantedBy = @by, GrantedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Principal, ObjectId, Role, GrantedBy) VALUES (@p, @o, @r, @by);')
            New-EpsWebResponse -Body @{ ok = $true } -Audit @{ Target = "WebAccess|$who"; Before = $before; After = @{ Principal = $who; Role = $role } } } }
        @{ Method = 'DELETE'; Pattern = '^/api/access/(?<p>[^/]{3,320})$'; Summary = 'Take a person''s role away (they become a Reader).'; Public = $false
           Role = 'SuperAdmin'; Apply = 'Engine'; Action = 'access.revoke'; NeedsReason = $true; Handler = { param($c, $m)
            $who = [uri]::UnescapeDataString($m.p).ToLowerInvariant()
            $before = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters @{ p = $who } -Query 'SELECT Principal, Role FROM eps.WebAccess WHERE Principal = @p')[0]
            if (-not $before) { return New-EpsWebError 404 'no such person in the access list' }
            if ($before.Role -eq 'SuperAdmin' -and (Test-EpsLastSuperAdmin -ConnectionString $c.Ctx.ConnectionString -Principal $who)) { return New-EpsLastSuperAdminRefusal -Who $who }
            [void](Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -NonQuery -Parameters @{ p = $who } -Query 'DELETE FROM eps.WebAccess WHERE Principal = @p')
            New-EpsWebResponse -Body @{ ok = $true } -Audit @{ Target = "WebAccess|$who"; Before = $before } } }
        @{ Method = 'GET'; Pattern = '^/api/audit$'; Summary = 'The audit trail, newest first, one page at a time.'; Body = 'q; category; outcome; from, to (UTC); page; pageSize'; Public = $true
           Role = 'Admin'; Handler = { param($c, $m)
            $pg = Get-EpsWebPaging $c.Query; $f = Get-EpsWebAuditFilter $c.Query; $f.P.k = $pg.Skip; $f.P.n = $pg.Size
            New-EpsWebResponse -Body @{ total = Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Scalar -Parameters $f.P -Query "SELECT COUNT(*) FROM eps.AuditEvent $($f.Where)"
                rows = @(ConvertTo-EpsWebValue (Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $f.P -Query "SELECT Id, TsUtc, Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, RunId, WhatIf FROM eps.AuditEvent $($f.Where) ORDER BY Id DESC OFFSET @k ROWS FETCH NEXT @n ROWS ONLY")) } } }
        @{ Method = 'GET'; Pattern = '^/api/audit/export$'; Summary = 'The audit rows that match the filter as a CSV file (at most 200,000 rows).'; Body = 'q; category; outcome; from; to'; Public = $true
           Role = 'Admin'; Action = 'audit.export'; Handler = { param($c, $m)
            $f = Get-EpsWebAuditFilter $c.Query; $cols = 'Id', 'TsUtc', 'Action', 'Actor', 'ActorSource', 'Target', 'Reason', 'Outcome', 'OutcomeText', 'BeforeJson', 'AfterJson', 'CorrelationId', 'RunId', 'WhatIf'
            $rows = @(Invoke-EpsSql -ConnectionString $c.Ctx.ConnectionString -Parameters $f.P -Query "SELECT TOP (200001) $($cols -join ', ') FROM eps.AuditEvent $($f.Where) ORDER BY Id DESC")
            if ($rows.Count -gt 200000) { return New-EpsWebResponse -Status 413 -Body @{ error = 'more than 200,000 audit rows - narrow the filter' } -Audit @{ Target = 'AuditEvent'; Outcome = 'refused'; OutcomeText = 'over 200,000 rows' } }   # SEC-AUDIT-1 S9
            New-EpsWebResponse -Body (ConvertTo-EpsCsv -Rows $rows -Columns $cols) -ContentType 'text/csv; charset=utf-8' -Headers @{ 'Content-Disposition' = 'attachment; filename="eps-audit.csv"' } `
                -Audit @{ Target = 'AuditEvent'; After = @{ filter = $f.Echo; rows = $rows.Count } } } }
    )
}

# ---- the API reference (framework APIDOC-1) ---------------------------------------------------------------------------
# Generated from the route table, never a hand-kept list: every route carries Summary (plain words), where useful Body (its
# parameters) and Answer, and Public. Public is FAIL CLOSED (APIDOC-1 item 6, owner 2026-11-01: the public reference shows only what an
# integrator needs): absent = not public; a DELETE, a SuperAdmin route, or a route whose path, action or text
# names a forbidden area is never public, even when marked. The full reference is shown only in the signed-in GUI,
# filtered to the person's role; the public profile is what is handed to invardia.com.
$script:EpsApiPublicForbidden = '(?i)break.?glass|emergency|restore|backup|support|diagnos|bundle|token|secret|password|credential|sign.?in|sign.?out|signature|signed|auth|access|security|\bkey\b|api.?key|/me\b|setting'

function Get-EpsApiPublicForbidden { $script:EpsApiPublicForbidden }

function Test-EpsApiRoutePublic {
    # the one place that decides whether a route is in the public profile
    param([Parameter(Mandatory)]$Route)
    if ($Route.Public -ne $true) { return $false }
    if ($Route.Method -eq 'DELETE' -or $Route.Role -eq 'SuperAdmin') { return $false }
    "$($Route.Pattern) $($Route.Action) $($Route.Summary) $($Route.Body) $($Route.Answer)" -notmatch $script:EpsApiPublicForbidden
}

function ConvertTo-EpsApiPath {
    # '^/api/rules/(?<ot>User|Device)/(?<id>\d{1,9})$' -> @{ Path = '/api/rules/{objectType}/{id}'; Params = (name, what) }
    param([Parameter(Mandatory)][string]$Pattern)
    $names = @{ ot = 'objectType'; rid = 'requestId'; aid = 'analysisId'; mn = 'monitor'; pn = 'persona'; vid = 'viewId'; sn = 'scope'; p = 'principal'; cid = 'conditionType' }
    $params = [System.Collections.Generic.List[object]]::new()
    $path = [regex]::Replace(($Pattern -replace '^\^', '' -replace '\$$', ''), '\(\?<(\w+)>([^()]*)\)', {
        param($mm)
        $n = $mm.Groups[1].Value; $x = $mm.Groups[2].Value; $nn = if ($names[$n]) { $names[$n] } else { $n }
        $what = if ($x -match '^[A-Za-z]+(\|[A-Za-z]+)+$') { ($x -split '\|') -join ' or ' } elseif ($x -like '*{36}*') { 'an id (GUID)' } elseif ($x -match '^\\d') { 'a number' } else { 'a name' }
        $params.Add([ordered]@{ name = $nn; value = $what })
        '{' + $nn + '}' })
    @{ Path = $path; Params = @($params) }
}

function Get-EpsApiReference {
    <#
      -Audience Full   : every route (the signed-in GUI), with -Role only the routes that role may call
      -Audience Public : the public profile only (Test-EpsApiRoutePublic) - routine routes with plain summaries
      Per route: area, method, path, path parameters, role, summary, parameters (query or body), whether a reason is
      required, the answer, how it is applied, the errors and the audit action.
    #>
    param([ValidateSet('Full', 'Public')][string]$Audience = 'Full', [string]$Role, [string]$Version)
    $areas = [ordered]@{ overview = 'Overview'; rules = 'Rules'; identity = 'Identity report'; queue = 'Commit queue'; tagtypes = 'Tag types and conditions'; conditions = 'Tag types and conditions'
        jobs = 'Jobs'; requests = 'Jobs'; scopes = 'Jobs'; mail = 'Jobs'; runs = 'Runs and changes'; changes = 'Runs and changes'; ca = 'CA Policy Analyzer'; capolicies = 'Conditional Access'; tamper = 'Tamper'
        worker = 'Hybrid worker'; settings = 'Settings'; onboarding = 'Get started'; breakglass = 'Get started'; access = 'Access'; audit = 'Audit'; me = 'App'; version = 'App'; reference = 'App' }
    $errorText = [ordered]@{ '400' = 'the input is refused (the answer says why)'; '401' = 'not signed in'; '403' = 'not allowed'; '404' = 'not found'
        '409' = 'a conflict: it changed meanwhile, or it is not in a state that allows this - reload'; '413' = 'too large - narrow the filter or the file'; '500' = 'internal error (the answer carries a correlation id)' }
    $rows = foreach ($r in Get-EpsWebRoutes) {
        $isPublic = Test-EpsApiRoutePublic -Route $r
        if ($Audience -eq 'Public' -and -not $isPublic) { continue }
        if ($Audience -eq 'Full' -and $PSBoundParameters.ContainsKey('Role') -and -not (Test-EpsWebRole -Have $Role -Need $r.Role)) { continue }
        $code = "$($r.Handler) $($r.Stage)"
        $p = ConvertTo-EpsApiPath -Pattern $r.Pattern
        $seg = ($p.Path -split '/')[2]
        # the errors: what the handler answers, plus what every route of its kind can answer
        $err = [System.Collections.Generic.SortedSet[int]]::new()
        foreach ($mm in [regex]::Matches($code, '(?:-Status\s+|New-EpsWebError\s+|&\s*\$no\s+|\b[a-z]\w*\s*=\s*)([45]\d\d)\b')) { [void]$err.Add([int]$mm.Groups[1].Value) }
        if ($code -match 'New-EpsWebRuleRefusal') { [void]$err.Add(400) }
        if ($code -match 'New-EpsLastSuperAdminRefusal') { [void]$err.Add(409) }
        [void]$err.Add(500); if ($Audience -eq 'Full') { [void]$err.Add(401) }   # the public profile says nothing about the session
        if ($r.Role -ne 'Reader' -or $r.Method -ne 'GET' -or $r.Pattern -match 'export') { [void]$err.Add(403) }
        if ($r.Method -ne 'GET' -or $r.NeedsReason) { [void]$err.Add(400) }
        $answer = if ($r.Answer) { "$($r.Answer)" } elseif ($code -match 'text/csv') { 'CSV file' } elseif ($r.Apply -eq 'Engine' -or $code -match '-Status 202') { 'request (202 with a request id)' }
                  elseif ($r.Method -eq 'GET') { if ($code -match '\brows\s*=') { 'JSON list' } else { 'JSON object' } } else { 'JSON result' }
        $applied = if ($r.Apply -eq 'Engine') { 'applied by the engine within ~5 min (follow it with GET /api/requests/{requestId})' + $(if ($r.Stage) { '; while the commit queue is on it is staged first (202 with a pending id) and a commit applies it' }) }
                   elseif ($r.Method -eq 'GET') { 'read' } elseif ($answer -like 'request*') { 'queued for the engine (within ~5 min)' } else { 'at once' }
        $audit = @(if ($r.Action) { $r.Action }; if ($Audience -eq 'Full' -and $r.Apply -eq 'Engine') { 'config.request' }; if ($Audience -eq 'Full' -and $r.Stage) { 'queue.stage' })
        $o = [ordered]@{
            area = $(if ($areas[$seg]) { $areas[$seg] } else { 'Other' }); method = $r.Method; path = $p.Path; pathParams = @($p.Params)
            role = $(if ($r.Role) { $r.Role } else { 'Reader' }); summary = "$($r.Summary)"
            in = $(if ($r.Method -eq 'GET') { 'query' } else { 'body (JSON)' }); parameters = "$($r.Body)"; reason = $(if ($r.NeedsReason) { 'optional (a note for the audit trail)' } else { 'none' })
            answer = $answer; applied = $applied; errors = @($err); audit = $audit }
        if ($Audience -eq 'Full') { $o.public = $isPublic }
        [pscustomobject]$o
    }
    if ($Audience -eq 'Public') { $errorText.Remove('401') }
    [ordered]@{ product = 'EntraPolicySuite'; version = "$Version"; profile = $Audience; role = $(if ($Audience -eq 'Full' -and $PSBoundParameters.ContainsKey('Role')) { $Role })
        roles = @('Reader', 'Admin', 'SuperAdmin'); errorCodes = $errorText; routes = @($rows) }
}

function Get-EpsWebChangeFilter {
    param($Query)
    $p = @{ run = $(if ("$($Query.runId)" -match '^[0-9a-fA-F-]{36}$') { [guid]$Query.runId } else { [guid]::Empty }); st = "$($Query.status)"; q = "$($Query.q)" }
    @{ P = $p; Echo = @{ runId = "$($Query.runId)"; status = $p.st; q = $p.q }
       Where = "WHERE (@run = '00000000-0000-0000-0000-000000000000' OR RunId = @run) AND (@st = '' OR Status = @st) AND (@q = '' OR ObjectName LIKE '%' + @q + '%' OR NewValue LIKE '%' + @q + '%' OR OldValue LIKE '%' + @q + '%' OR Persona LIKE '%' + @q + '%')" }
}

function Get-EpsWebAuditFilter {
    # AUDIT-1.4: free text over actor / action / target / outcome / change, a time window (from / to, UTC ISO), a category
    param($Query)
    $d = { param($v) $x = [datetime]::MinValue; if ([datetime]::TryParse("$v", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$x)) { $x } else { $null } }
    $p = @{ q = "$($Query.q)"; cat = "$($Query.category)"; o = "$($Query.outcome)"; f = (& $d $Query.from); t = (& $d $Query.to) }
    @{ P = $p; Echo = @{ q = $p.q; category = $p.cat; outcome = $p.o; from = "$($Query.from)"; to = "$($Query.to)" }
       Where = "WHERE (@q = '' OR Actor LIKE '%' + @q + '%' OR Action LIKE '%' + @q + '%' OR Target LIKE '%' + @q + '%' OR Outcome LIKE '%' + @q + '%' OR AfterJson LIKE '%' + @q + '%' OR BeforeJson LIKE '%' + @q + '%') AND (@cat = '' OR Action LIKE @cat + '.%') AND (@o = '' OR Outcome = @o) AND (@f IS NULL OR TsUtc >= @f) AND (@t IS NULL OR TsUtc < @t)" }
}

function Test-EpsLastSuperAdmin {
    param([string]$ConnectionString, [string]$Principal)
    [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ p = $Principal } -Query "SELECT COUNT(*) FROM eps.WebAccess WHERE Role = 'SuperAdmin' AND Principal <> @p") -eq 0
}

function New-EpsLastSuperAdminRefusal {
    # the guard (GUARD-1): never zero SuperAdmins - nobody could grant access again without SQL admin rights
    param([string]$Who)
    New-EpsWebResponse -Status 409 -Body @{ error = "$Who is the last SuperAdmin. Make someone else SuperAdmin first." } -Audit @{ Target = "WebAccess|$Who"; Outcome = 'refused'; OutcomeText = 'guard: the last SuperAdmin'; Guard = $true }
}

function New-EpsWebRuleRefusal {
    # a save the broken-reference guard (DESIGN §5.9 guard 2) or the validation refuses: 400 with every reason, audited
    param([string]$Target, [string[]]$Errors)
    New-EpsWebResponse -Status 400 -Body @{ error = ($Errors -join '; '); errors = @($Errors) } -Audit @{ Target = $Target; Outcome = 'refused'; OutcomeText = ($Errors -join '; ') }
}

function Request-EpsAutoPreview {
    # DESIGN §5.8 step 1: a changed rule set is previewed on everyone automatically - one waiting preview covers every
    # change made before it starts, so a burst of edits queues ONE. Not while the feature is off (the tick would refuse it).
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType)
    # a commit from the queue requests the real run itself, once for the whole commit (Invoke-EpsCommitQueue)
    if ($Ctx.Replay) { return @{ queued = $false; text = '' } }
    $job = if ($ObjectType -eq 'User') { 'UserTagging' } else { 'DeviceTagging' }
    if ("$(Get-EpsSetting -ConnectionString $Ctx.Ctx.ConnectionString -Name "$job.Enabled" -Default 'false')" -ne 'true') { return @{ queued = $false; text = "No preview queued: $job is switched off (Settings)." } }
    $waiting = [int](Invoke-EpsSql -ConnectionString $Ctx.Ctx.ConnectionString -Scalar -Parameters @{ j = $job } -Query "SELECT COUNT(*) FROM eps.JobRequest WHERE Job = @j AND Mode = 'Preview' AND Scope IS NULL AND Status = 'Pending'")
    if ($waiting) { return @{ queued = $false; text = 'A preview on everyone is already waiting and will include this change.' } }
    $id = New-EpsSignedJobRequest -Ctx $Ctx -Job $job -Mode 'Preview'
    @{ queued = $true; requestId = $id; text = 'A preview on everyone is queued (the scheduler starts it within 5 minutes; nothing is written).' }
}

# ---- the commit queue (owner 2026-10-31: "so an admin can make changes and then we manually approve from a commit
# queue", "it must not instantly start when a single chg is made", "we have similar commit queue in pim, it must be same
# setup"). PIM's staged-edit lane: a save is STAGED (validated, with its before), a commit replays it through the SAME
# route handler (its validation, its journal, its audit) as the committer, then requests the tagging run once. Nothing is
# ever committed automatically; a row is never deleted.
function Test-EpsCommitQueueOn { param([Parameter(Mandatory)][string]$ConnectionString) "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'CommitQueue.Enabled' -Default 'true')" -eq 'true' }

function Add-EpsPendingChange {
    # stages one change; a Pending row for the same thing (Entity + key; never a new rule, a move or a batch) is Superseded
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Stage, [Parameter(Mandatory)][string]$Action,
          [Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body, [Parameter(Mandatory)][string]$By)
    $b = [ordered]@{}; if ($Body) { foreach ($p in $Body.PSObject.Properties) { $b[$p.Name] = $p.Value } }
    $reason = "$($b.reason)"
    $p = @{ o = $Stage.ObjectType; e = $Stage.Entity; k = [string]$Stage.Key; op = $Stage.Op; s = $Stage.Summary; a = $Action; m = $Method; pa = $Path
            bj = ($b | ConvertTo-Json -Compress -Depth 10); bf = $(if ($null -ne $Stage.Before) { if ($Stage.Before -is [string]) { $Stage.Before } else { $Stage.Before | ConvertTo-Json -Compress -Depth 10 } }); by = $By; r = $reason }
    $fold = if ($Stage.Key -notmatch '^(new|move|batch):') { "UPDATE eps.PendingChange SET Status = 'Superseded' WHERE Status = 'Pending' AND Entity = @e AND EntityKey = @k;" } else { '' }
    [long](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; $fold INSERT INTO eps.PendingChange (ObjectType, Entity, EntityKey, Op, Summary, Action, Method, Path, BodyJson, BeforeJson, StagedBy, StageReason) OUTPUT INSERTED.Id VALUES (@o, @e, @k, @op, @s, @a, @m, @pa, @bj, @bf, @by, @r); COMMIT;")
}

function Invoke-EpsWebReplay {
    # one staged change, through its own route handler as the committer; audited under the route's own action
    param([Parameter(Mandatory)]$Commit, [Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string]$CommitReason)
    $route = $null; $m = $null
    foreach ($r in Get-EpsWebRoutes) { if ($r.Method -eq $Row.Method -and $Row.Path -match $r.Pattern) { $route = $r; $m = $Matches; break } }
    if (-not $route) { return @{ Status = 500; Body = @{ error = "no route for $($Row.Method) $($Row.Path)" } } }
    $body = if ($Row.BodyJson) { $Row.BodyJson | ConvertFrom-Json } else { [pscustomobject]@{} }
    $why = "$($Row.StageReason) (committed from the queue, #$($Row.Id), staged by $($Row.StagedBy): $CommitReason)"
    $body | Add-Member -NotePropertyName reason -NotePropertyValue $why -Force
    $c = @{ Ctx = $Commit.Ctx; Caller = $Commit.Caller; Role = $Commit.Role; Query = @{}; Body = $body; Correlation = $Commit.Correlation; Replay = $true }
    # SEC-AUDIT-1 S8: the replay's exception text stays in the log (and the audit row); the queue shows a fixed text + an id
    $res = try { & $route.Handler $c $m } catch { $cid = [guid]::NewGuid(); Write-Host "  [web] ERROR replaying $($Row.Method) $($Row.Path) ($cid): $($_.Exception.Message)" -ForegroundColor Red; @{ Status = 500; Body = @{ error = "internal error while committing (reference $cid - see the web app log)" }; Audit = @{ Outcome = 'error'; OutcomeText = "$($_.Exception.Message) ($cid)" } } }
    $a = if ($res.Audit) { $res.Audit } else { @{} }
    $outcome = if ($a.Outcome) { $a.Outcome } elseif ($res.Status -ge 400) { 'error' } else { 'ok' }
    [void](Write-EpsAuditEvent -ConnectionString $Commit.Ctx.ConnectionString -Action $(if ($a.Guard) { 'guard.trip' } else { $route.Action }) -Actor $Commit.Caller.identity -Target $(if ($a.Target) { $a.Target } else { "$($Row.Method) $($Row.Path)" }) `
        -Reason $why -Outcome $outcome -OutcomeText $a.OutcomeText -Before $a.Before -After $a.After -CorrelationId $Commit.Correlation)
    $res
}

function Invoke-EpsCommitQueue {
    # commits the chosen Pending rows (oldest first); each one Applied or Failed with the save's own answer. Then ONE
    # tagging run per object type that changed, in the job's own mode (owner 2026-10-31: "Job's mode"), signed by the
    # committer. -Ids empty = refused (the GUI's Commit all sends every id it shows).
    param([Parameter(Mandatory)]$Commit, [long[]]$Ids = @(), [Parameter(Mandatory)][string]$Reason)
    $cs = $Commit.Ctx.ConnectionString
    $rows = @(Invoke-EpsSql -ConnectionString $cs -Query "SELECT * FROM eps.PendingChange WHERE Status = 'Pending' ORDER BY Id" | Where-Object { $Ids -contains [long]$_.Id })
    $commitId = [guid]::NewGuid(); $done = [System.Collections.Generic.List[object]]::new(); $types = @{}
    foreach ($r in $rows) {
        $res = Invoke-EpsWebReplay -Commit $Commit -Row $r -CommitReason $Reason
        $ok = $res.Status -lt 400
        $err = if (-not $ok) { "$(if ($res.Body.error) { $res.Body.error } else { "HTTP $($res.Status)" })" }
        [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Parameters @{ id = [long]$r.Id; s = $(if ($ok) { 'Applied' } else { 'Failed' }); c = $commitId; by = $Commit.Caller.identity; e = $err } `
            -Query "UPDATE eps.PendingChange SET Status = @s, CommitId = @c, CommittedBy = @by, CommittedAtUtc = SYSUTCDATETIME(), Error = @e WHERE Id = @id AND Status = 'Pending'")
        if ($ok) { $types[[string]$r.ObjectType] = $true }
        $done.Add([ordered]@{ id = [long]$r.Id; summary = [string]$r.Summary; applied = $ok; error = $err; text = "$($res.Body.text)" })
    }
    $runs = [System.Collections.Generic.List[object]]::new()
    foreach ($ot in @($types.Keys | Sort-Object)) {
        $job = "${ot}Tagging"
        if ("$(Get-EpsSetting -ConnectionString $cs -Name "$job.Enabled" -Default 'false')" -ne 'true') { $runs.Add([ordered]@{ job = $job; requested = $false; text = "$job is switched off (Settings): no run requested." }); continue }
        $mode = [string](Get-EpsSetting -ConnectionString $cs -Name "$job.Mode" -Default 'Preview'); if ($mode -notin 'Preview', 'Apply') { $mode = 'Preview' }
        $c2 = @{ Ctx = $Commit.Ctx; Caller = $Commit.Caller; Correlation = $Commit.Correlation; Body = [pscustomobject]@{ reason = "commit $commitId`: $Reason" } }
        $rq = New-EpsSignedJobRequest -Ctx $c2 -Job $job -Mode $mode
        $runs.Add([ordered]@{ job = $job; requested = $true; mode = $mode; requestId = $rq; text = "$job $mode on everyone requested: the scheduler starts it within 5 minutes." })
    }
    @{ CommitId = $commitId; Items = @($done); Runs = @($runs); Applied = @($done | Where-Object applied).Count; Failed = @($done | Where-Object { -not $_.applied }).Count }
}

function Get-EpsRuleCardById {
    param([string]$ConnectionString, [string]$ObjectType, [int]$RuleId)
    @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ObjectType -RuleId $RuleId)[0]
}

function Get-EpsRuleCardText {
    param($Card) if (-not $Card) { return '' }
    "$($Card.Persona) $($Card.TagType) = $(if ($Card.TagValueCloud) { $Card.TagValueCloud } else { $Card.TagValueAD }) when $(@($Card.Conditions | ForEach-Object { "$($_.ConditionType) $($_.Target)" }) -join ' AND ')"
}

function New-EpsSignedJobRequest {
    # one way (§12.11f): a request row carrying the caller's verified token and the time it was verified; the tick starts
    # the job, the job verifies the token again. Preview requests carry it too (harmless, and the engine can tell who).
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][string]$Mode, $Scope)
    $id = [guid]::NewGuid()
    [void](Invoke-EpsSql -ConnectionString $Ctx.Ctx.ConnectionString -NonQuery -Parameters @{
        # -Depth 12: a Config request carries a grid batch (body > ops > rule > conditions)
        id = $id; j = $Job; m = $Mode; s = $(if ($Scope) { $Scope | ConvertTo-Json -Compress -Depth 12 }); by = $Ctx.Caller.identity
        tok = $Ctx.Caller.token; at = $Ctx.Caller.verifiedAtUtc; c = $Ctx.Correlation; r = "$($Ctx.Body.reason)"
    } -Query 'INSERT INTO eps.JobRequest (RequestId, Job, Mode, Scope, RequestedBy, SignedToken, SignedVerifiedAtUtc, CorrelationId, Reason) VALUES (@id, @j, @m, @s, @by, @tok, @at, @c, @r)')
    "$id"
}

# ---- the identity report page (DESIGN §5.4; owner 2026-10-31: "gui view with filters", "that shows gaps", "similar to
# excel pivots", "save views like fx si can"). READ ONLY: the web app reads the snapshot the engine wrote. Filters follow
# framework LIST-1: columns from a CLOSED list (the snapshot's own columns), values only as parameters.
$script:EpsIdColumnCache = @{}
$script:EpsListOps = 'contains', 'notContains', 'equals', 'startsWith', 'anyOf', 'atLeast', 'atMost'

function Get-EpsIdentityLatestRun {
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$RunId)
    if ($RunId) { if ($RunId -notmatch '^[0-9a-fA-F-]{36}$') { return $null }; return @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = [guid]$RunId } -Query 'SELECT RunId, CreatedAtUtc, Users, Devices, ViewCountsJson, PivotsJson, NotesJson FROM eps.IdentitySnapshot WHERE RunId = @r')[0] }
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP 1 RunId, CreatedAtUtc, Users, Devices, ViewCountsJson, PivotsJson, NotesJson FROM eps.IdentitySnapshot ORDER BY CreatedAtUtc DESC')[0]
}

function Get-EpsIdentityColumns {
    # the closed column list of a snapshot's rows of one kind: name -> number | boolean | date | text (from a sample row)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$Kind)
    $key = "$RunId|$Kind"
    if ($script:EpsIdColumnCache.ContainsKey($key)) { return $script:EpsIdColumnCache[$key] }
    $cols = [ordered]@{}
    foreach ($s in Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $RunId; k = $Kind } -Query 'SELECT TOP 50 Data FROM eps.IdentityRow WHERE RunId = @r AND Kind = @k') {
        $o = $s.Data | ConvertFrom-Json -AsHashtable
        foreach ($n in $o.Keys) {
            if ($n -notmatch '^[A-Za-z][A-Za-z0-9_]{0,79}$') { continue }
            $v = $o[$n]; $t = if ($v -is [bool]) { 'boolean' } elseif ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { 'number' } elseif ($v -is [datetime] -or "$v" -match '^\d{4}-\d\d-\d\dT\d\d:\d\d') { 'date' } elseif ($null -eq $v) { $null } else { 'text' }
            if (-not $cols.Contains($n) -or ($null -eq $cols[$n] -and $t)) { $cols[$n] = $t }
        }
    }
    foreach ($n in @($cols.Keys)) { if (-not $cols[$n]) { $cols[$n] = 'text' } }
    if ($script:EpsIdColumnCache.Count -gt 20) { $script:EpsIdColumnCache.Clear() }
    $script:EpsIdColumnCache[$key] = $cols
    $cols
}

function ConvertTo-EpsListFilterSql {
    <#
    .SYNOPSIS
        LIST-1 filters + search -> a SQL condition over the JSON column, with parameters. Pure. @{ Ok; Sql; Parameters; Error }.
        -Columns: the closed list (name -> type). -Expr: the JSON column ('r.Data').
    #>
    param([object[]]$Filters = @(), [string]$Search, [Parameter(Mandatory)][System.Collections.IDictionary]$Columns, [string]$Expr = 'r.Data')
    $parts = [System.Collections.Generic.List[string]]::new(); $p = @{}; $i = 0
    $jv = { param($col) "JSON_VALUE($Expr, '$.`"$col`"')" }
    if ("$Search".Trim()) { $p.q = "$Search".Trim(); $parts.Add("$Expr LIKE '%' + @q + '%'") }
    if (@($Filters).Count -gt 30) { return @{ Ok = $false; Error = 'at most 30 filters' } }
    foreach ($f in @($Filters)) {
        if ($null -eq $f) { continue }
        $col = [string]$f.col; $op = [string]$f.op
        if ($op -notin $script:EpsListOps) { return @{ Ok = $false; Error = "unknown filter '$op'" } }
        if ($col -ne '*' -and -not $Columns.Contains($col)) { return @{ Ok = $false; Error = "unknown column '$col'" } }
        if ($op -in 'atLeast', 'atMost' -and ($col -eq '*' -or $Columns[$col] -ne 'number')) { return @{ Ok = $false; Error = "'$op' needs a number column" } }
        $x = if ($col -eq '*') { $Expr } else { & $jv $col }
        $n = "f$i"; $i++
        switch ($op) {
            'contains'    { $p[$n] = [string]$f.value; $parts.Add("$x LIKE '%' + @$n + '%'") }
            'notContains' { $p[$n] = [string]$f.value; $parts.Add("($x IS NULL OR $x NOT LIKE '%' + @$n + '%')") }
            'startsWith'  { $p[$n] = [string]$f.value; $parts.Add("$x LIKE @$n + '%'") }
            'equals'      { $v = [string]$f.value; if ($v -eq '' -or $v -eq '(empty)') { $parts.Add("($x IS NULL OR $x = '')") } else { $p[$n] = $v; $parts.Add("$x = @$n") } }
            'anyOf'       {
                $vals = @($f.values | ForEach-Object { [string]$_ }); if (-not $vals.Count) { continue }
                if ($vals.Count -gt 100) { return @{ Ok = $false; Error = 'at most 100 values in one filter' } }
                $or = [System.Collections.Generic.List[string]]::new(); $j = 0
                foreach ($v in $vals) { if ($v -eq '' -or $v -eq '(empty)') { $or.Add("$x IS NULL OR $x = ''") } else { $p["${n}_$j"] = $v; $or.Add("$x = @${n}_$j"); $j++ } }
                $parts.Add("($($or -join ' OR '))") }
            'atLeast'     { $d = 0.0; if (-not [double]::TryParse("$($f.value)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return @{ Ok = $false; Error = "'$($f.value)' is not a number" } }; $p[$n] = $d; $parts.Add("TRY_CAST($x AS float) >= @$n") }
            'atMost'      { $d = 0.0; if (-not [double]::TryParse("$($f.value)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return @{ Ok = $false; Error = "'$($f.value)' is not a number" } }; $p[$n] = $d; $parts.Add("TRY_CAST($x AS float) <= @$n") }
        }
    }
    @{ Ok = $true; Sql = $(if ($parts.Count) { ' AND ' + ($parts -join ' AND ') } else { '' }); Parameters = $p }
}

function Resolve-EpsIdentityQuery {
    # one grid / pivot / export request -> the FROM + WHERE over the snapshot, validated. @{ Ok; Error; Status; Run; View; Kind; Columns; From; Where; Parameters }
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Query)
    $run = Get-EpsIdentityLatestRun -ConnectionString $ConnectionString -RunId "$($Query.run)"
    if (-not $run) { return @{ Ok = $false; Status = 404; Error = 'no identity report yet - switch the report on (Settings) and run it (Run now)' } }
    $name = if ("$($Query.view)") { "$($Query.view)" } else { 'Users_ALL' }
    $view = @(Get-EpsIdentityViewCatalog | Where-Object Name -eq $name)[0]
    if (-not $view) { return @{ Ok = $false; Status = 400; Error = "unknown view '$name'" } }
    $cols = Get-EpsIdentityColumns -ConnectionString $ConnectionString -RunId $run.RunId -Kind $view.Kind
    $filters = @(); if ("$($Query.filters)") { try { $filters = @("$($Query.filters)" | ConvertFrom-Json) } catch { return @{ Ok = $false; Status = 400; Error = 'filters is not JSON' } } }
    $f = ConvertTo-EpsListFilterSql -Filters $filters -Search "$($Query.q)" -Columns $cols
    if (-not $f.Ok) { return @{ Ok = $false; Status = 400; Error = $f.Error } }
    $p = $f.Parameters + @{ run = [guid]$run.RunId; kind = $view.Kind }
    $from = 'FROM eps.IdentityRow r'
    if ($view.Group -ne 'Lists') { $p.view = $view.Name; $from += ' JOIN eps.IdentityViewMember m ON m.RunId = r.RunId AND m.Kind = r.Kind AND m.ObjectId = r.ObjectId AND m.ViewName = @view' }
    @{ Ok = $true; Run = $run; View = $view; Kind = $view.Kind; Columns = $cols; From = $from; Where = "WHERE r.RunId = @run AND r.Kind = @kind$($f.Sql)"; Parameters = $p }
}

function Get-EpsIdentityOrderBy {
    param($Columns, [string]$Sort, [string]$Dir)
    $d = if ("$Dir" -eq '-1' -or "$Dir" -eq 'desc') { 'DESC' } else { 'ASC' }
    if ($Sort -and $Columns.Contains($Sort)) {
        $x = "JSON_VALUE(r.Data, '$.`"$Sort`"')"
        if ($Columns[$Sort] -eq 'number') { $x = "TRY_CAST($x AS float)" }
        return "ORDER BY $x $d, r.Name, r.ObjectId"
    }
    'ORDER BY r.Name, r.ObjectId'
}

function Test-EpsSavedViewDefinition {
    # a saved view (LIST-1 layout + base view + pivot): @{ Ok; Error; Json }
    param($Definition)
    if ($null -eq $Definition) { return @{ Ok = $false; Error = 'definition is missing' } }
    $j = $Definition | ConvertTo-Json -Depth 8 -Compress
    if ($j.Length -gt 20000) { return @{ Ok = $false; Error = 'the view is too large (20,000 characters at most)' } }
    $d = $j | ConvertFrom-Json
    if ([int]$d.v -ne 1) { return @{ Ok = $false; Error = 'definition.v must be 1' } }
    if (-not @(Get-EpsIdentityViewCatalog | Where-Object Name -eq "$($d.base)")) { return @{ Ok = $false; Error = "unknown base view '$($d.base)'" } }
    foreach ($f in @($d.filters)) { if ($null -ne $f -and [string]$f.op -notin $script:EpsListOps) { return @{ Ok = $false; Error = "unknown filter '$($f.op)'" } } }
    foreach ($c in @($d.columns) + @($d.hidden) + @($d.pivot.rows, $d.pivot.columns, $d.sort.col)) { if ($c -and "$c" -notmatch '^[A-Za-z][A-Za-z0-9_]{0,79}$') { return @{ Ok = $false; Error = "'$c' is not a column name" } } }
    if ($d.pageSize -and [int]$d.pageSize -notin 0, 25, 50, 100, 200) { return @{ Ok = $false; Error = 'pageSize: 25, 50, 100 or 200' } }
    @{ Ok = $true; Json = $j }
}

function Invoke-EpsWebRequest {
    <#
      -Request @{ Method; Path; Query (hashtable); Headers (hashtable, case-insensitive); Body (string) }
      -Ctx     @{ ConnectionString; AuthConfig (Get-EpsWebAuthConfig); Version; StaticRoot }
      Returns  @{ Status; Body (object -> JSON, or a string); ContentType; Headers }
    #>
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Ctx)
    $method = "$($Request.Method)".ToUpperInvariant(); $path = "$($Request.Path)"
    $h = $Request.Headers
    $base = @{ 'X-EPS-Version' = $Ctx.Version; 'Cache-Control' = 'no-store' }
    $out = { param($r) foreach ($k in $base.Keys) { if (-not $r.Headers.ContainsKey($k)) { $r.Headers[$k] = $base[$k] } }; $r.Remove('Audit'); $r }
    if ($path -eq '/healthz' -and $method -in 'GET', 'HEAD') { return (& $out (New-EpsWebResponse -Body 'ok' -ContentType 'text/plain; charset=utf-8')) }

    # 2. the caller - on every path, pages and files too
    $caller = Resolve-EpsWebCaller -Authorization "$($h['Authorization'])" -Config $Ctx.AuthConfig
    if (-not $caller.trusted) {
        $key = "$($caller.reason)"; $now = [datetime]::UtcNow
        if (-not $script:EpsWebAuditThrottle[$key] -or ($now - $script:EpsWebAuditThrottle[$key]).TotalMinutes -ge 5) {
            $script:EpsWebAuditThrottle[$key] = $now
            [void](Write-EpsAuditEvent -ConnectionString $Ctx.ConnectionString -Action 'auth.request.refused' -Actor 'unknown' -Target "$method $path" -Outcome 'refused' -OutcomeText $caller.reason)
        }
        Write-Host "  [auth] REFUSED $method $path - $($caller.reason)" -ForegroundColor Red
        return (& $out (New-EpsWebResponse -Status 401 -Body @{ error = 'not signed in'; version = $Ctx.Version }))
    }
    $caller.verifiedAtUtc = [datetime]::UtcNow
    $role = Get-EpsWebRole -ConnectionString $Ctx.ConnectionString -Identity $caller.identity -ObjectId $caller.objectId
    # the first sign-in of a person named by UPN pins the row to their object id (a renamed UPN keeps its role; a new
    # account that takes the old UPN does not inherit it)

    if ($path -notlike '/api/*') {
        if ($method -notin 'GET', 'HEAD') { return (& $out (New-EpsWebError 405 'method not allowed')) }
        return (& $out (Get-EpsWebStaticFile -Ctx $Ctx -Path $path))
    }
    $route = $null; $m = $null
    foreach ($r in Get-EpsWebRoutes) { if ($r.Method -eq $method -and $path -match $r.Pattern) { $route = $r; $m = $Matches; break } }
    if (-not $route) { return (& $out (New-EpsWebError 404 'no such API')) }

    $correlation = [guid]::NewGuid()
    $refuse = { param($status, $text)
        [void](Write-EpsAuditEvent -ConnectionString $Ctx.ConnectionString -Action 'web.request.refused' -Actor $caller.identity -Target "$method $path" -Outcome 'refused' -OutcomeText $text -CorrelationId $correlation)
        & $out (New-EpsWebError $status $text) }
    $body = $null
    # SEC-AUDIT-1 S12: an export (a GET that writes an audit row and hands out data) only from this app's own page - another
    # site's link would be followed with the session cookie (SameSite=Lax)
    if ($method -eq 'GET' -and $route.Pattern -match 'export' -and "$($h['Sec-Fetch-Site'])" -and "$($h['Sec-Fetch-Site'])" -notin 'same-origin', 'none') {
        return (& $refuse 403 'refused: an export is started from this app''s own page')
    }
    if ($method -ne 'GET') {
        # 3. anti-forgery
        $site = "$($h['Sec-Fetch-Site'])"
        if ("$($h['X-EPS-Request'])" -ne '1' -or "$($h['Content-Type'])" -notmatch '^application/json' -or ($site -and $site -notin 'same-origin', 'none')) {
            return (& $refuse 403 'refused: not a request from this app''s own page')
        }
        try { $body = if ("$($Request.Body)".Trim()) { $Request.Body | ConvertFrom-Json } else { [pscustomobject]@{} } } catch { return (& $refuse 400 'the body is not JSON') }
    }
    # 4. the role
    if (-not (Test-EpsWebRole -Have $role -Need $route.Role)) { return (& $refuse 403 "this needs the $($route.Role) role (you are $role)") }
    # a reason is OPTIONAL (owner 2026-11-02: "things are too complex with all these reasons"): a note the audit trail keeps if given

    $c = @{ Ctx = $Ctx; Caller = $caller; Role = $role; Query = $(if ($Request.Query) { $Request.Query } else { @{} }); Body = $body; Correlation = $correlation }
    # the commit queue: a tagging-config save is validated and STAGED, not written (owner 2026-10-31); a commit replays it
    $stage = $route.Stage -and (Test-EpsCommitQueueOn -ConnectionString $Ctx.ConnectionString)
    try {
        if ($stage) {
            $st = & $route.Stage $c $m
            if ($st.Refusal) { $res = $st.Refusal }
            else {
                $pid0 = Add-EpsPendingChange -ConnectionString $Ctx.ConnectionString -Stage $st -Action $route.Action -Method $method -Path $path -Body $body -By $caller.identity
                $res = New-EpsWebResponse -Status 202 -Body @{ ok = $true; staged = $true; pendingId = $pid0; text = "Staged in the commit queue (#$pid0): $($st.Summary). Nothing changes until an admin commits it (Commit queue page)." } `
                    -Audit @{ Action = 'queue.stage'; Target = "PendingChange|$pid0 ($($st.Entity) $($st.Key))"; After = @{ op = $st.Op; summary = $st.Summary } }
            }
        }
        elseif ($route.Apply -eq 'Engine') {
            # SEC-AUDIT-1 S1: the web app never writes configuration - the engine applies it from the requester's signed
            # request (the same handler, validation, journal and audit, run by the engine as the requester)
            $rq = New-EpsSignedJobRequest -Ctx $c -Job 'Config' -Mode 'Apply' -Scope ([ordered]@{ method = $method; path = $path; body = $body })
            $res = New-EpsWebResponse -Status 202 -Body @{ ok = $true; queued = $true; requestId = $rq; text = 'Requested: the engine applies it within 5 minutes (Jobs > Requests shows the result).' } `
                -Audit @{ Action = 'config.request'; Target = "$method $path"; After = @{ requestId = $rq } }
        }
        else { $res = & $route.Handler $c $m }
    }
    catch {
        Write-Host "  [web] ERROR $method $path ($correlation): $($_.Exception.Message) $($_.ScriptStackTrace -split "`n" | Select-Object -First 1)" -ForegroundColor Red
        if ($route.Action) { [void](Write-EpsAuditEvent -ConnectionString $Ctx.ConnectionString -Action $route.Action -Actor $caller.identity -Target "$method $path" -Reason "$($body.reason)" -Outcome 'error' -OutcomeText 'internal error (see the web app log)' -CorrelationId $correlation) }
        return (& $out (New-EpsWebResponse -Status 500 -Body @{ error = 'internal error'; correlationId = "$correlation" }))
    }
    # 5. audited by construction
    if ($route.Action) {
        $a = if ($res.Audit) { $res.Audit } else { @{} }
        $outcome = if ($a.Outcome) { $a.Outcome } elseif ($res.Status -ge 400) { 'error' } else { 'ok' }
        [void](Write-EpsAuditEvent -ConnectionString $Ctx.ConnectionString -Action $(if ($a.Guard) { 'guard.trip' } elseif ($a.Action) { $a.Action } else { $route.Action }) -Actor $caller.identity -Target $(if ($a.Target) { $a.Target } else { "$method $path" }) `
            -Reason "$($body.reason)" -Outcome $outcome -OutcomeText $a.OutcomeText -Before $a.Before -After $a.After -CorrelationId $correlation -WhatIf:([bool]$a.WhatIf))
    }
    & $out $res
}

function Get-EpsWebStaticFile {
    # the page's own files only: no directory listing, no path outside the root, a closed list of types
    param([Parameter(Mandatory)]$Ctx, [string]$Path)
    $types = @{ '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'; '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.ico' = 'image/x-icon' }
    $rel = if ($Path -in '/', '') { 'index.html' } else { [uri]::UnescapeDataString($Path.TrimStart('/')) }
    if ($rel -match '\.\.|[\\:]' ) { return New-EpsWebError 404 'not found' }
    $root = [IO.Path]::GetFullPath($Ctx.StaticRoot)
    $full = [IO.Path]::GetFullPath((Join-Path $root $rel))
    $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or -not $types[$ext] -or -not (Test-Path -LiteralPath $full -PathType Leaf)) { return New-EpsWebError 404 'not found' }
    if ($ext -eq '.html') { return New-EpsWebResponse -Body ((Get-Content -LiteralPath $full -Raw).Replace('{{VERSION}}', [Net.WebUtility]::HtmlEncode($Ctx.Version))) -ContentType $types[$ext] -Headers @{ 'Cache-Control' = 'no-cache' } }
    New-EpsWebResponse -Body ([IO.File]::ReadAllBytes($full)) -ContentType $types[$ext] -Headers @{ 'Cache-Control' = 'no-cache' }
}
