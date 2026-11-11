# EntraPolicySuite -- SUP-02 (Invardia design 2026-11-07, framework §5.5 'support'; 2.0.101): Invardia Support reads a
# PRIVATE install through a fixed job inside its network - caj-eps-supportread, its own identity id-eps-support.
#   * Invardia puts ONE message on the job's own queue eps-supportread (the Support app holds only Message Sender there;
#     no ARM right on the job - a start right would accept a container override, EPS's S4 finding); KEDA starts the job.
#   * The message names ONE read from the shipped allow-list below - never SQL, never a script. An unknown name, a
#     message older than 15 minutes or one that is not for this job = refused, nothing runs.
#   * The result goes to the job's console only (Log Analytics, read through ARM), capped, no secret or token.
#   * Every message is audited in the install (support.read: who, reason, read, outcome).
#   * The identity reads only the tables these reads use (sql/eps-grants.json eps_supportread) and writes only the audit.
# Dot-source EPS-SqlStore, EPS-Scheduler (queue helpers) and EPS-Audit first.

Set-StrictMode -Off

$script:EpsSupportReadMaxRows = 200
$script:EpsSupportReadMaxChars = 30000
$script:EpsSupportReadMaxAgeMinutes = 15
# the allow-list: name -> what it shows + its one read-only query (no parameter from the message ever reaches SQL)
$script:EpsSupportReads = [ordered]@{
    'runs-last-7d'     = @{ What = 'The runs of the last 7 days: job, status, start, end, held reason'
                            Query = "SELECT TOP (200) Job, Mode, Status, StartedAtUtc, EndedAtUtc, LEFT(ISNULL(HeldReason, ''), 300) AS HeldReason FROM eps.Run WHERE StartedAtUtc > DATEADD(DAY, -7, SYSUTCDATETIME()) ORDER BY StartedAtUtc DESC" }
    'jobs-schedule'    = @{ What = 'Each job''s schedule, on / off and its last start'
                            Query = 'SELECT Job, Schedule, AcaJobName, Enabled, LastStartedUtc, LastStartResult FROM eps.JobSchedule ORDER BY Job' }
    'config-summary'   = @{ What = 'The stored settings (name and value - at most 200 characters each - when, by whom)'
                            Query = 'SELECT Name, Feature, LEFT(ISNULL(Value, N''''), 200) AS Value, UpdatedAtUtc, UpdatedBy FROM eps.Setting ORDER BY Name' }
    'licence-state'    = @{ What = 'The licence claim and request state (never the licence text)'
                            Query = 'SELECT ClaimAction, ClaimMessage, ClaimAtUtc, RequestStatus, RequestAtUtc, NextPollUtc, SupersededBy, UsersInScope, UsageState FROM eps.License WHERE Id = 1' }
    'worker-heartbeat' = @{ What = 'The hybrid workers: machine, version, last seen, last result, last update check'
                            Query = 'SELECT WorkerName, Machine, Version, LastSeenUtc, LEFT(ISNULL(LastResult, N''''), 300) AS LastResult, LEFT(ISNULL(UpdateResult, N''''), 300) AS UpdateResult, UpdateAtUtc FROM eps.WorkerHeartbeat ORDER BY LastSeenUtc DESC' }
    'update-state'     = @{ What = 'The last 20 update runs and what each said'
                            Query = "SELECT TOP (20) Status, StartedAtUtc, EndedAtUtc, LEFT(ISNULL(HeldReason, ''), 400) AS Summary FROM eps.Run WHERE Job = 'Update' ORDER BY StartedAtUtc DESC" }
    'setup-steps'      = @{ What = 'The update-now check and the setup markers the engine keeps'
                            Query = "SELECT Name, LEFT(ISNULL(Value, N''), 300) AS Value, UpdatedAtUtc FROM eps.Setting WHERE Name LIKE N'update-%'" }
}

function Test-EpsSupportReadRequest {
    <# PURE. The decoded message -> @{ Ok; Read; Reason; Who; Why }. Only a known read name, for this job, not older than
       15 minutes, with who and why (each capped). Nothing from the message is ever used as SQL. #>
    param([AllowNull()]$Message, [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($why) @{ Ok = $false; Read = ''; Reason = "$why"; Who = ''; Why = '' } }
    if ($null -eq $Message) { return (& $no 'the message could not be read') }
    $g = { param($k) if ($Message -is [System.Collections.IDictionary]) { $Message[$k] } else { $p = $Message.PSObject.Properties[$k]; if ($p) { $p.Value } } }
    if ("$(& $g 'job')" -ne 'caj-eps-supportread') { return (& $no 'not a message for the support read job') }
    $name = "$(& $g 'read')".Trim()
    if ($name -notmatch '^[a-z0-9-]{1,40}$' -or -not $script:EpsSupportReads.Contains($name)) { return (& $no "'$($name -replace '[^A-Za-z0-9 ._-]', '?')' is not a read this release ships (allowed: $(@($script:EpsSupportReads.Keys) -join ', '))") }
    $at = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse("$(& $g 'atUtc')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) { return (& $no 'the message has no readable time (atUtc)') }
    $age = ($NowUtc.ToUniversalTime() - $at.UtcDateTime).TotalMinutes
    if ($age -gt $script:EpsSupportReadMaxAgeMinutes) { return (& $no "the message is $([int]$age) minutes old (at most $script:EpsSupportReadMaxAgeMinutes)") }
    if ($age -lt -5) { return (& $no 'the message is dated in the future') }
    $cut = { param($s, $n) $t = ("$s" -replace '[\r\n\t]', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) } else { $t } }
    $who = & $cut (& $g 'requestedBy') 120; $why = & $cut (& $g 'reason') 300
    if (-not $who -or -not $why) { return (& $no 'a support read needs who asked (requestedBy) and why (reason)') }
    @{ Ok = $true; Read = $name; Reason = ''; Who = $who; Why = $why }
}

function Format-EpsSupportReadResult {
    <# PURE. Rows -> the capped text written to the console: one line per row, column=value, at most 200 rows and 30,000
       characters; a value that looks like a token or a key is masked. #>
    param([AllowNull()][object[]]$Rows, [string]$Read)
    $sb = [Text.StringBuilder]::new()
    $all = @($Rows | Where-Object { $_ })
    [void]$sb.AppendLine("support read '$Read': $($all.Count) row(s)$(if ($all.Count -gt $script:EpsSupportReadMaxRows) { " - the first $script:EpsSupportReadMaxRows shown" })")
    foreach ($r in @($all | Select-Object -First $script:EpsSupportReadMaxRows)) {
        $cols = @($r.PSObject.Properties | Where-Object { $_.Name -notin 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors' })
        $line = (@($cols | ForEach-Object {
            $v = if ($null -eq $_.Value -or $_.Value -is [DBNull]) { '' } elseif ($_.Value -is [datetime]) { $_.Value.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { "$($_.Value)" }
            $v = ($v -replace '[\r\n\t]', ' ') -replace '(?i)\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]+|inv-[A-Za-z0-9_-]{20,}|[A-Za-z0-9+/]{40,}={0,2})\b', '[masked]'
            "$($_.Name)=$v" }) -join ' | ')
        if ($sb.Length + $line.Length -gt $script:EpsSupportReadMaxChars) { [void]$sb.AppendLine('... (cut at 30,000 characters)'); break }
        [void]$sb.AppendLine($line)
    }
    $sb.ToString().TrimEnd()
}

function Invoke-EpsSupportReadJob {
    <# The job: take ONE message from its own queue (deleted at once), check it, run the named read, write the result to
       the console, audit it. -Message is the test seam (a decoded message); without it the queue is read. Returns
       @{ Outcome = ok | refused | none | error; Read; Text }. #>
    param([Parameter(Mandatory)][string]$ConnectionString, $Message, [switch]$HasMessage, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Say = { param($m) Write-Host $m })
    if (-not $HasMessage) {
        $sa = "$env:EPS_STORAGE_ACCOUNT"
        if (-not $sa) { throw 'the support read job needs EPS_STORAGE_ACCOUNT (its queue) - set by the install' }
        $q = Get-EpsJobQueueName 'caj-eps-supportread'
        $base = "https://$sa.queue.core.windows.net/$q/messages"
        $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://storage.azure.com/')"; 'x-ms-version' = '2021-08-06' }
        $r = & $script:EpsHttp 'GET' "$base`?numofmessages=1&visibilitytimeout=300" $h $null
        if ($r.Status -ge 300) { throw "queue $q`: HTTP $($r.Status)" }
        $x = "$($r.Body)"
        if ($x -notmatch '<MessageId>([^<]+)</MessageId>') { & $Say 'no message (another execution took it) - nothing to do'; return @{ Outcome = 'none'; Read = ''; Text = '' } }
        $id = $Matches[1]
        $pop = if ($x -match '<PopReceipt>([^<]+)</PopReceipt>') { $Matches[1] } else { '' }
        $txt = if ($x -match '<MessageText>([^<]*)</MessageText>') { $Matches[1] } else { '' }
        [void](& $script:EpsHttp 'DELETE' "$base/$id`?popreceipt=$([uri]::EscapeDataString([System.Net.WebUtility]::HtmlDecode($pop)))" $h $null)
        $Message = try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($txt)) | ConvertFrom-Json -AsHashtable } catch { $null }
    }
    $started = [datetime]::UtcNow
    $chk = Test-EpsSupportReadRequest -Message $Message -NowUtc $NowUtc
    $audit = { param($outcome, $text)
        [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.read' -Actor $(if ($chk.Who) { "Invardia Support ($($chk.Who))" } else { 'Invardia Support' }) -ActorSource 'job' -Target "support-read|$(if ($chk.Read) { $chk.Read } else { 'refused' })" -Reason $chk.Why -Outcome $outcome -OutcomeText $text) }
    $res = if (-not $chk.Ok) { & $Say "refused: $($chk.Reason) - nothing was read"; & $audit 'refused' $chk.Reason; @{ Outcome = 'refused'; Read = ''; Text = $chk.Reason } }
    else {
        try {
            $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $script:EpsSupportReads[$chk.Read].Query)
            $out = Format-EpsSupportReadResult -Rows $rows -Read $chk.Read
            & $Say "for $($chk.Who) ($($chk.Why)): $($script:EpsSupportReads[$chk.Read].What)"
            & $Say $out
            & $audit 'ok' "$(@($rows).Count) row(s)"
            @{ Outcome = 'ok'; Read = $chk.Read; Text = $out }
        } catch {
            $e = (("$($_.Exception.Message)") -split "`n")[0]
            & $Say "the read failed: $e"; & $audit 'error' $e
            @{ Outcome = 'error'; Read = $chk.Read; Text = $e }
        }
    }
    Write-EpsSupportReadRun -ConnectionString $ConnectionString -Result $res -StartedUtc $started -Say $Say
    $res
}

function Write-EpsSupportReadRun {
    <# Deterministic-failure gap (6) (Invardia 2026-11-08: "every job reports"): ONE finished eps.Run row per support read
       (INSERT only - the role may not change a run): ok = Succeeded, refused = Held (the check did its job), error = Failed.
       The read's result is never in it - only which read and the outcome. A failed write never fails the read. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Result, [datetime]$StartedUtc = [datetime]::UtcNow, [scriptblock]$Say = { param($m) Write-Host $m })
    $st = switch ("$($Result.Outcome)") { 'ok' { 'Succeeded' } 'refused' { 'Held' } 'error' { 'Failed' } default { $null } }
    if (-not $st) { return }
    $h = if ($st -eq 'Succeeded') { "read $($Result.Read)" } else { "$($Result.Text)" }
    if ($h.Length -gt 1000) { $h = $h.Substring(0, 997) + '...' }
    try {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [guid]::NewGuid(); t = $StartedUtc; s = $st; h = $h; a = $(if ($st -eq 'Succeeded') { 1 } else { 0 }); f = $(if ($st -eq 'Failed') { 1 } else { 0 }) } `
            -Query "INSERT INTO eps.Run (RunId, Job, Mode, StartedAtUtc, EndedAtUtc, Status, HeldReason, Applied, Failed) VALUES (@id, 'SupportRead', 'Preview', @t, SYSUTCDATETIME(), @s, @h, @a, @f)" | Out-Null
    } catch { & $Say "could not record the run: $((("$($_.Exception.Message)") -split "`n")[0])" }
}
