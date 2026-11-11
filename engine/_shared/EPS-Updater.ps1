# Entra Policy Suite -- the updater, phase 1: CHECK ONLY (REQUIREMENTS UPDATER-1, owner 2026-11-04 "Yes, build it now";
# Invardia's approved plan 2026-11-03: the Community channel, the same signer as SI / PIM, stage tracking from day one,
# "build order: check-only first").
#
# Every night the update job asks Invardia which release is approved for this install's ring, VERIFIES the answer with
# the shared verifier (InvardiaUpdate.verify.ps1, byte-identical to PIM's and SI's: embedded keys, product, kind, ring,
# version, SHA-256, sequence, size, https), asks the head call for "update now", reads the run gate, and reports what it
# would install - as an update run to Invardia (framework §8.8) and in its own run record. PHASE 2 (EPS-UpdateApply.ps1)
# then APPLIES it as the update job's own identity id-eps-updater - see that file.
# Dot-source EPS-SqlStore.ps1, EPS-Uplink.ps1 (the install key) and InvardiaUpdate.verify.ps1 first.

Set-StrictMode -Off
$script:EpsUpdateProduct = 'entrapolicysuite'
$script:EpsUpdateBase    = 'https://invardia.com'
$script:EpsUpdateKind    = 'community'
$script:EpsUpdateRunSteps = [ordered]@{ check = 'Check for a new version'; verify = 'Verify the release'; apply = 'Install the release' }

function Get-EpsUpdateRing {
    <# PURE. The ring this install takes updates from: EPS_RING (0-3, set by the install) - none = ring 3, the general
       Community release. A value outside 0-3 is never sent (Invardia answers 422): ring 3. #>
    param([AllowEmptyString()][AllowNull()][string]$Ring = $env:EPS_RING)
    $r = "$Ring".Trim()
    if ($r -match '^[0-3]$') { return [int]$r }
    return 3
}

function Invoke-EpsUpdateHttp {
    <# One request, never throws: @{ status; body; error }. 0 = not reached. The install key is never in 'error'. #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Url, $Body, [hashtable]$Headers = @{}, [int]$TimeoutSec = 30)
    $a = @{ Method = $Method; Uri = $Url; Headers = $Headers; TimeoutSec = $TimeoutSec; UseBasicParsing = $true; ContentType = 'application/json' }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        $b = $null; try { $t = "$($_.ErrorDetails.Message)".Trim(); if ($t.StartsWith('{')) { $b = $t | ConvertFrom-Json } } catch { $b = $null }
        $err = ((("$($_.Exception.Message)") -split "`n")[0])
        $k = "$($Headers['X-Invardia-Install-Key'])"; if ($k -and $err.Contains($k)) { $err = 'the request failed' }
        return @{ status = $code; body = $b; error = $err }
    }
}

function Get-EpsUpdateTarget {
    <#
      The check (no install key needed: the Community channel is anonymous). GET <base>/api/updates/entrapolicysuite/
      community/<ring>, then Test-InvardiaManifest (kind community, this ring, this product). Returns
      @{ State; Version; Sequence; Reason; Size; Sha256 } - State:
        current     nothing newer is approved for this ring (or nothing is released to it yet)
        available   a verified release newer than the running version
        held        verified, but it asks for a manual step or a newer starting version
        ahead       this install runs a newer version than the ring approves (a test install) - nothing to fetch
        refused     the answer did not verify - nothing moves
        unreachable Invardia could not be asked (network, 5xx, 429) - the next run asks again
    #>
    param([Parameter(Mandatory)][string]$RunningVersion, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [scriptblock]$Http,
          [string]$BaseUrl = $script:EpsUpdateBase, [int]$AppliedSequence = 0, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys)
    $res = @{ State = 'unreachable'; Version = ''; Sequence = 0; Reason = ''; Size = 0; Sha256 = ''; DownloadUrl = '' }
    $base = "$BaseUrl".Trim().TrimEnd('/')
    if ($base -notmatch '^(?i)https://') { $res.State = 'refused'; $res.Reason = 'the update address is not https'; return $res }
    $url = "$base/api/updates/$($script:EpsUpdateProduct)/$($script:EpsUpdateKind)/$Ring"
    $r = if ($Http) { & $Http 'GET' $url $null @{} } else { Invoke-EpsUpdateHttp -Method GET -Url $url }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -eq 204) { $res.State = 'current'; $res.Reason = "nothing is released to ring $Ring yet"; return $res }
    if ($st -ne 200) { $res.Reason = Get-InvardiaPullReason -Status $st -Body $r.body -ErrorText "$($r.error)"; if ($st -in 401, 403, 404, 422) { $res.State = 'refused' }; return $res }
    $v = Test-InvardiaManifest -Response $r.body -TrustedKeys $TrustedKeys -Kind $script:EpsUpdateKind -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Product $script:EpsUpdateProduct -Ring $Ring
    if (-not $v.ok) { $res.State = 'refused'; $res.Reason = $v.reason; return $res }
    $res.Version = "$($v.version)"; $res.Sequence = [int]$v.sequence; $res.Reason = $v.reason; $res.Size = [int64]$v.size; $res.Sha256 = "$($v.sha256)"; $res.DownloadUrl = "$($v.downloadUrl)"
    if ($v.hold) { $res.State = 'held'; return $res }
    $cmp = Compare-InvardiaReleaseVersion $v.version $RunningVersion
    if ($cmp -gt 0) { $res.State = 'available'; $res.Reason = "$($v.reason) - newer than $RunningVersion" }
    elseif ($cmp -lt 0) { $res.State = 'ahead'; $res.Reason = "$($v.reason) - this install runs $RunningVersion, newer than ring $Ring approves: nothing to fetch" }
    else { $res.State = 'current'; $res.Reason = "$($v.reason) - this install runs it" }
    return $res
}

function Get-EpsUpdateHead {
    <#
      "Update now" (framework §8.18): POST <base>/api/updates/entrapolicysuite/head { ring, kind: 'community' } with the
      per-install key. Read only on Invardia's side. No key = no call. @{ Status; Version; Expedite (apply/until/reason or
      $null); Reason }. Never throws; never returns the key.
    #>
    param([AllowEmptyString()][string]$InstallKey, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [scriptblock]$Http, [string]$BaseUrl = $script:EpsUpdateBase,
          # INSTALL-PRO: a Pro install asks for its Pro channel (kind 'code') with the licence in the body (PIM / SI's head)
          [AllowEmptyString()][string]$LicenceText = '',
          # UPD-03 (2.0.97): the tick asks without the licence, for its channel ('code' / 'community') as PIM's tick does
          [ValidateSet('', 'code', 'community')][string]$Kind = '')
    if (-not "$InstallKey".Trim()) { return @{ Status = 0; Version = ''; Expedite = $null; Reason = 'no install key: "update now" is not asked' } }
    if ("$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return @{ Status = 0; Version = ''; Expedite = $null; Reason = 'the install key is not in the expected format: "update now" is not asked' } }
    $url = "$("$BaseUrl".Trim().TrimEnd('/'))/api/updates/$($script:EpsUpdateProduct)/head"
    $h = @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    $b = if ("$LicenceText".Trim()) { [ordered]@{ ring = $Ring; kind = 'code'; licence = "$LicenceText" } } else { [ordered]@{ ring = $Ring; kind = $(if ($Kind) { $Kind } else { $script:EpsUpdateKind }) } }
    $r = if ($Http) { & $Http 'POST' $url $b $h } else { Invoke-EpsUpdateHttp -Method POST -Url $url -Body $b -Headers $h }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -ne 200) { return @{ Status = $st; Version = ''; Expedite = $null; Reason = $(if ($st -eq 403 -and $r.body.ringOnRecord -ne $null) { "Invardia has this install on ring $($r.body.ringOnRecord), not ring $Ring" } else { Get-InvardiaPullReason -Status $st -Body $r.body -ErrorText "$($r.error)" }) } }
    $ex = $null
    if ($r.body.expedite -and "$($r.body.expedite.apply)" -in 'now', 'window') { $ex = @{ Apply = "$($r.body.expedite.apply)"; Until = "$($r.body.expedite.until)"; Reason = "$($r.body.expedite.reason)" } }
    return @{ Status = 200; Version = "$($r.body.version)"; Expedite = $ex; Reason = $(if ($ex) { "update now asked ($($ex.Apply)): $($ex.Reason)" } else { 'no "update now" for this install' }) }
}

$script:EpsUpdateHeadSetting = 'update-head-check'   # written by the update job, read by the tick (UPD-03)

$script:EpsRollRetry = @{ EveryMinutes = 60; MaxHours = 24; GiveUp = 'waited \d{1,4} min for running jobs' }
function Get-EpsRollRetryDecision {
    <#
      PURE. ROLL-RETRY-1 (framework §3.6, Invardia 2026-11-11: "PIM lost a day at 5 installs"): an update that gave up
      because jobs were running is retried by the TICK, at most once an hour, until an update run installs or says up to
      date - never "the nightly covers it". -Runs: the update job's eps.Run rows, NEWEST FIRST (Status, HeldReason,
      StartedAtUtc, EndedAtUtc). @{ Start; Reason }:
        start  the newest finished update run gave up waiting for running jobs, the give-ups in a row began < 24 h ago,
               no update runs now and the last one started >= 60 min ago
        no     anything else (said why)
    #>
    param([object[]]$Runs = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($w) @{ Start = $false; Reason = $w } }
    $rs = @($Runs | Where-Object { $_ })
    if (@($rs | Where-Object { "$($_.Status)" -eq 'Running' -and $_.StartedAtUtc -and [datetime]$_.StartedAtUtc -gt $NowUtc.AddHours(-3) }).Count) { return (& $no 'an update runs now') }
    $fin = @($rs | Where-Object { "$($_.Status)" -ne 'Running' -and $_.EndedAtUtc -and $_.EndedAtUtc -isnot [DBNull] })
    if (-not $fin.Count) { return (& $no 'no update run yet') }
    if ("$($fin[0].HeldReason)" -notmatch $script:EpsRollRetry.GiveUp) { return (& $no 'the last update run did not give up waiting for running jobs') }
    $streak = @(); foreach ($r in $fin) { if ("$($r.HeldReason)" -match $script:EpsRollRetry.GiveUp) { $streak += $r } else { break } }
    $first = [datetime]$streak[-1].EndedAtUtc
    if ($first -lt $NowUtc.AddHours(-$script:EpsRollRetry.MaxHours)) { return (& $no "it has given up $($streak.Count) time(s) in a row since $($first.ToString('yyyy-MM-dd HH:mm'))Z - more than $($script:EpsRollRetry.MaxHours) h; Invardia has the repeat failure (run record + alert eps.job.repeat-failure from the 3rd give-up in a row), the nightly run tries again") }
    $lastStart = [datetime]$(if ($fin[0].StartedAtUtc) { $fin[0].StartedAtUtc } else { $fin[0].EndedAtUtc })
    if ($lastStart -gt $NowUtc.AddMinutes(-$script:EpsRollRetry.EveryMinutes)) { return (& $no "the last try started at $($lastStart.ToString('HH:mm'))Z - the next one from $($lastStart.AddMinutes($script:EpsRollRetry.EveryMinutes).ToString('HH:mm'))Z") }
    @{ Start = $true; Reason = "the update gave up waiting for running jobs $($streak.Count) time(s) in a row (first $($first.ToString('HH:mm'))Z) - tried again" }
}

function Sync-EpsUpdateHeadVersion {
    <#
      WORKER-UPD-2 (2.1.1): the version in update-head-check = the version that RUNS. The update job writes the version it
      started on, i.e. from BEFORE its apply, so after every night with an update the hybrid worker saw "the signed release
      of ring 0 is <new>, the install runs <old>" and waited another day - internal's worker stayed on 2.0.105 from
      2026-11-08 and never answered the AD delegation check (alignment gap, 2026-11-10). The TICK runs on the install's
      image every 5 minutes, so it corrects the version field when it differs (one UPDATE that matches nothing otherwise).
      Never fails the tick. Returns $true when it ran.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version)
    if ("$Version".Trim() -notmatch '^\d+\.\d+\.\d+$') { return $false }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $script:EpsUpdateHeadSetting; v = "$Version".Trim() } -Query @'
UPDATE eps.Setting SET Value = JSON_MODIFY(Value, '$.version', @v), UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = N'engine (tick)'
WHERE Name = @n AND ISJSON(Value) = 1 AND ISNULL(JSON_VALUE(Value, '$.version'), N'') <> @v
'@ | Out-Null
    $true
}

function Get-EpsUpdateExpediteDecision {
    <#
      PURE (UPD-03, 2.0.97; PIM's 15-minute expedite check). Invardia's head answer (Get-EpsUpdateHead) -> @{ Start;
      Version; Reason }. Start only when: HTTP 200, expedite.apply = 'now', the head's version is NEWER than the installed
      one, 'until' has not passed, and no "update now" start was made for that version before (-AlreadyStarted).
      'window' = the nightly run takes it.
    #>
    param([AllowNull()][object]$Head, [string]$InstalledVersion = '', [bool]$AlreadyStarted = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($why, $v) @{ Start = $false; Version = "$v"; Reason = "$why" } }
    if (-not $Head -or [int]$Head.Status -ne 200) { return (& $no "no answer to read$(if ($Head -and $Head.Reason) { ": $($Head.Reason)" })" '') }
    $v = "$($Head.Version)".Trim()
    if (-not $Head.Expedite) { return (& $no 'no "update now" for this install' $v) }
    if ("$($Head.Expedite.Apply)" -eq 'window') { return (& $no '"update now" within the agreed hours: the nightly run takes it' $v) }
    if ("$($Head.Expedite.Apply)" -ne 'now') { return (& $no 'an "update now" mark that cannot be read' $v) }
    $a = $null; $b = $null
    if (-not [version]::TryParse($v, [ref]$a) -or -not [version]::TryParse("$InstalledVersion".Trim(), [ref]$b)) { return (& $no 'a version that cannot be read' $v) }
    if ($a -le $b) { return (& $no "this install runs $InstalledVersion (the head is $v)" $v) }
    $u = "$($Head.Expedite.Until)".Trim()
    if ($u) {
        $until = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse($u, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$until)) { return (& $no "the mark's end ('$u') cannot be read" $v) }
        if ($NowUtc.ToUniversalTime() -gt $until.UtcDateTime) { return (& $no 'the "update now" mark has run out' $v) }
    }
    if ($AlreadyStarted) { return (& $no "an update was already started for $v by update now" $v) }
    $why = ("$($Head.Expedite.Reason)" -replace '\s+', ' ').Trim(); if ($why.Length -gt 200) { $why = $why.Substring(0, 197) + '...' }
    @{ Start = $true; Version = $v; Reason = $(if ($why) { $why } else { 'no reason given' }) }
}

function Invoke-EpsUpdateExpediteCheck {
    <#
      UPD-03 (Invardia review 2026-11-07, framework §8.18 "update now"): the TICK asks Invardia's head call once every 15
      minutes (the tick that runs in minutes 0-4, 15-19, 30-34, 45-49) and says whether the update job should start now.
      The ring, the channel and the Key Vault come from the setting the update job writes on every run (update-head-check);
      the install key from the Key Vault as the uplink reads it. Read only - never writes; the caller starts the job and
      records it in its run. Off (Checked = $false) when not due, without the setting, the key or a readable version.
      Never throws. -Http / -GetKey / -AlreadyStarted { param($v) } are seams. @{ Checked; Start; Version; Reason }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$InstalledVersion, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Http, [scriptblock]$GetKey, [scriptblock]$AlreadyStarted,
          # { } -> the stored licence text (the tick passes its own reader - its role reads only that column)
          [scriptblock]$GetLicence)
    $off = { param($why) @{ Checked = $false; Start = $false; Version = ''; Reason = "$why" } }
    try {
        if (($NowUtc.ToUniversalTime().Minute % 15) -ge 5) { return (& $off 'not due (every 15 minutes)') }
        $raw = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $script:EpsUpdateHeadSetting } -Query 'SELECT Value FROM eps.Setting WHERE Name = @n'
        if (-not "$raw".Trim()) { return (& $off 'the update job has not run on this release yet (no update-head-check)') }
        $hc = "$raw" | ConvertFrom-Json
        $ring = "$($hc.ring)"; $kind = "$($hc.kind)"
        if ($ring -notmatch '^[0-3]$' -or $kind -notin 'code', 'community') { return (& $off 'update-head-check cannot be read') }
        $k = if ($GetKey) { & $GetKey "$($hc.vault)" } else { Get-EpsUplinkKey -VaultName $(if ("$($hc.vault)" -match '^[A-Za-z0-9-]{3,24}$') { "$($hc.vault)" } else { Get-EpsUplinkVaultName }) }
        if (-not "$($k.Key)") { return (& $off "no install key ($($k.Reason))") }
        # a Pro install's head needs its licence (found live 2026-11-07 22:15Z: kind 'code' without it = "Invardia refused the
        # licence (unreadable)"); the tick reads only the licence TEXT (2.0.98 grant: SELECT(Id, LicenceText) on eps.License)
        $lic = ''
        if ($kind -eq 'code') {
            $lic = if ($GetLicence) { "$(& $GetLicence)".Trim() } else { "$(Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query 'SELECT LicenceText FROM eps.License WHERE Id = 1')".Trim() }
            if (-not $lic) { return (& $off 'a Pro install without a stored licence (the update job asks for it)') }
        }
        $h = if ($lic) { Get-EpsUpdateHead -InstallKey "$($k.Key)" -Ring ([int]$ring) -LicenceText $lic -Http $Http } else { Get-EpsUpdateHead -InstallKey "$($k.Key)" -Ring ([int]$ring) -Kind $kind -Http $Http }
        $done = $false
        if ($h.Status -eq 200 -and "$($h.Version)" -and $AlreadyStarted) { $done = [bool](& $AlreadyStarted "$($h.Version)") }
        $d = Get-EpsUpdateExpediteDecision -Head $h -InstalledVersion $InstalledVersion -AlreadyStarted $done -NowUtc $NowUtc
        @{ Checked = $true; Start = [bool]$d.Start; Version = "$($d.Version)"; Reason = "$($d.Reason)" }
    } catch { return (& $off "the check failed: $((("$($_.Exception.Message)") -split "`n")[0])") }
}

function Get-EpsUpdateRunGate {
    <# Read only in phase 1: would an update have to wait? Go when no work job is running (the tick and the update job
       itself do not count). @{ Go; Running (job names); Reason }. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT DISTINCT Job FROM eps.Run WHERE Status = 'Running' AND Job NOT IN ('Tick', 'Update')")
    $jobs = @($rows | ForEach-Object { "$($_.Job)" } | Where-Object { $_ })
    if ($jobs.Count) { return @{ Go = $false; Running = $jobs; Reason = "an update would wait for: $($jobs -join ', ')" } }
    return @{ Go = $true; Running = @(); Reason = 'no job is running: an update could start' }
}

# ---- UPD-HOLD (framework §8.18, owner 2026-11-05 "it can destroy schema"): an update never changes the database under a
# running run. It is installed BETWEEN runs and a waiting update goes FIRST: the update run marks itself as the hold
# (eps.Run Scope '{"updateHold":true}' on its own Running row - JSON, as the column is) -> the scheduler dispatches nothing new; the update then waits until
# no work job runs (eps.Run AND the Container Apps executions), at most 45 minutes, else it gives up until the next night.
# The hold ends with the run (Status leaves Running), is lifted in a finally, and expires on its own after 120 minutes (a
# crashed update never blocks the product). Nothing is ever cancelled.
$script:EpsUpdateHold = @{ Scope = '{"updateHold":true}'; ExpireMinutes = 120; WaitMinutes = 45; PollSeconds = 30; StuckMinutes = 120
    # always running or part of the update itself - never waited for: the scheduler (dispatches nothing while held), the
    # support-access job (no schema use beyond its own row), the setup job (the update's own migrate) and the update job
    NotWaitedFor = @('caj-eps-tick', 'caj-eps-engine', 'caj-eps-support', 'caj-eps-dbinit', 'caj-eps-update', 'caj-eps-updater') }

function Get-EpsUpdateHoldSql {
    <# PURE. The scheduler's read: is an update holding? (its own Running row, marked, not past the expiry). #>
    "SELECT COUNT(*) FROM eps.Run WHERE Job = N'Update' AND Status = N'Running' AND EndedAtUtc IS NULL AND Scope = N'$($script:EpsUpdateHold.Scope)' AND StartedAtUtc > DATEADD(MINUTE, -$([int]$script:EpsUpdateHold.ExpireMinutes), SYSUTCDATETIME())"
}

function Test-EpsUpdateHold {
    <# Is an update holding the dispatch? Never throws: a failed read = no hold (the product never stops on it). #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    try { return ([int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query (Get-EpsUpdateHoldSql)) -gt 0) } catch { return $false }
}

function Set-EpsUpdateHold {
    <# Marks (-On) or unmarks this update run as the hold. Never throws; returns $true when the row changed. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [switch]$On)
    try {
        $n = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $RunId; s = $(if ($On) { $script:EpsUpdateHold.Scope } else { [DBNull]::Value }) } `
            -Query "UPDATE eps.Run SET Scope = @s WHERE RunId = @id AND Job = N'Update'"
        return ([int]$n -eq 1)
    } catch { return $false }
}

function Get-EpsUpdateRunningWork {
    <#
      Which work jobs run now? eps.Run (Running, not Tick / Update) AND - with -Arm - the Container Apps executions in state
      Running of every job not in NotWaitedFor (an execution that started but has not written its run row yet). A job read
      that fails counts as RUNNING (never migrate on doubt). -Arm { param($path) } returns the ARM JSON; -Jobs the job names.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Arm, [string[]]$Jobs = @(),
          # UPD-STUCK-RUN (found live 2026-11-06 at internal: caj-eps-tamper 4w76v "Running" for 4.5 h with no run row held the
          # 2.0.90 update; framework UPD-06): an execution Running longer than -StuckMinutes while NO run row is Running at
          # all is STUCK - handed to -OnStuck { param($job, $execution, $startUtc) } (the updater stops it) and not waited for.
          # A long but real run always has its Running row, so it is still waited for.
          [int]$StuckMinutes = $script:EpsUpdateHold.StuckMinutes, [scriptblock]$OnStuck, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [System.Collections.Generic.List[string]]::new()
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Job, StartedAtUtc FROM eps.Run WHERE Status = 'Running' AND Job NOT IN ('Tick', 'Update')")
    foreach ($r in $rows) { if ("$($r.Job)" -and -not $out.Contains("$($r.Job)")) { $out.Add("$($r.Job)") } }
    if ($Arm) {
        foreach ($j in @($Jobs | Where-Object { $_ -and $_ -notin $script:EpsUpdateHold.NotWaitedFor })) {
            try {
                $ex = & $Arm $j
                $running = @(@($ex.value) | Where-Object { "$($_.properties.status)" -eq 'Running' })
                $live = 0
                foreach ($e in $running) {
                    $st = [datetime]::MinValue
                    $hasStart = [datetime]::TryParse("$($e.properties.startTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$st)
                    if ($StuckMinutes -gt 0 -and $hasStart -and -not $rows.Count -and ($NowUtc - $st).TotalMinutes -ge $StuckMinutes) {
                        if ($OnStuck) { try { & $OnStuck $j "$($e.name)" $st } catch { } }
                        continue
                    }
                    $live++
                }
                if ($live) { $out.Add($j) }
            } catch { $out.Add("$j (its executions could not be read: $((("$($_.Exception.Message)") -split "`n")[0].Substring(0, [Math]::Min(120, (("$($_.Exception.Message)") -split "`n")[0].Length))))") }
        }
    }
    return @($out | Select-Object -Unique)
}

function Wait-EpsUpdateQuiet {
    <#
      Waits until no work job runs: -Probe { } -> the running job names (Get-EpsUpdateRunningWork). Checks at once, then every
      -PollSeconds, at most -WaitMinutes. @{ Go; Waited (minutes); Running (the last names) }. -Sleep / -Now are seams.
    #>
    param([Parameter(Mandatory)][scriptblock]$Probe, [int]$WaitMinutes = $script:EpsUpdateHold.WaitMinutes, [int]$PollSeconds = $script:EpsUpdateHold.PollSeconds,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Log = { param($l, $m) })
    $start = & $Now; $last = @(); $said = ''
    while ($true) {
        $last = @(& $Probe)
        $mins = [math]::Round(((& $Now) - $start).TotalMinutes, 1)
        if (-not $last.Count) { return @{ Go = $true; Waited = $mins; Running = @() } }
        $txt = $last -join ', '
        if ($txt -ne $said) { & $Log 'Info' "update hold: waiting for $txt (the database is changed only between runs)"; $said = $txt }
        if (((& $Now) - $start).TotalMinutes -ge $WaitMinutes) { return @{ Go = $false; Waited = $mins; Running = $last } }
        & $Sleep $PollSeconds
    }
}

function Send-EpsUpdateRunTrack {
    <#
      Framework §8.8: an update run to Invardia (POST /api/install/runs kind 'update', then its events). Phase 1 reports the
      check and the verification as done and the install step as WAITING - this release only checks. Best effort, 10 s,
      never throws. @{ Ok; RunId; Reason }.
    #>
    param([AllowEmptyString()][string]$InstallKey, [Parameter(Mandatory)][int]$Ring, [Parameter(Mandatory)][string]$FromVersion,
          [Parameter(Mandatory)][string]$ToVersion, [string]$WaitReason = 'this release of the updater only checks: the install step comes with the next updater release',
          [scriptblock]$Http, [string]$BaseUrl = $script:EpsUpdateBase)
    if ("$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return @{ Ok = $false; RunId = ''; Reason = 'no install key: the update run is not reported' } }
    $base = "$BaseUrl".Trim().TrimEnd('/')
    $send = { param($m, $u, $b, $h) if ($Http) { & $Http $m $u $b $h } else { Invoke-EpsUpdateHttp -Method $m -Url $u -Body $b -Headers $h -TimeoutSec 10 } }
    $o = & $send 'POST' "$base/api/install/runs" ([ordered]@{ productId = $script:EpsUpdateProduct; kind = 'update'; ring = $Ring; fromVersion = $FromVersion; toVersion = $ToVersion }) @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    if ([int]$o.status -ne 201 -or -not "$($o.body.token)") { return @{ Ok = $false; RunId = ''; Reason = "Invardia did not open the update run (HTTP $([int]$o.status))" } }
    $hdr = if ("$($o.body.tokenHeader)" -match '^X-Invardia-[A-Za-z-]+$') { "$($o.body.tokenHeader)" } else { 'X-Invardia-Install-Token' }
    $ev = if ("$($o.body.eventsUrl)" -match '^https://') { "$($o.body.eventsUrl)" } else { "$base/api/install/events" }
    $now = [datetime]::UtcNow.ToString('o'); $seq = 0; $bad = 0
    foreach ($e in @(@{ id = 'check'; state = 'ok'; message = "$ToVersion is approved for ring $Ring" }, @{ id = 'verify'; state = 'ok'; message = 'the release information is genuine and complete' }, @{ id = 'apply'; state = 'waiting'; message = $WaitReason })) {
        $seq++
        $r = & $send 'POST' $ev ([ordered]@{ seq = $seq; step = @{ id = $e.id; title = $script:EpsUpdateRunSteps[$e.id] }; state = $e.state; at = $now; message = $e.message }) @{ $hdr = "$($o.body.token)" }
        if ([int]$r.status -notin 200, 201, 202, 204) { $bad++ }
    }
    return @{ Ok = ($bad -eq 0); RunId = "$($o.body.runId)"; Reason = $(if ($bad) { "$bad event(s) not taken" } else { 'reported' }) }
}

function Open-EpsUpdateRunTrack {
    <#
      Framework §8.8 for an APPLY: opens the update run (POST /api/install/runs kind 'update') and returns an emitter
      { param($step, $state, $message) } that posts each stage as it happens (SI's step ids: check, download, verify,
      build, migrate, apply, health, done, failed). Best effort, 10 s; the first refused event stops the tracking (SI's
      rule) - the update itself never waits on Invardia. @{ Ok; RunId; Emit; Reason }.
    #>
    param([AllowEmptyString()][string]$InstallKey, [Parameter(Mandatory)][int]$Ring, [Parameter(Mandatory)][string]$FromVersion, [Parameter(Mandatory)][string]$ToVersion,
          [scriptblock]$Http, [string]$BaseUrl = $script:EpsUpdateBase)
    $none = { param($s, $st, $m) }
    if ("$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return @{ Ok = $false; RunId = ''; Emit = $none; Reason = 'no install key: the update run is not reported' } }
    $base = "$BaseUrl".Trim().TrimEnd('/')
    $send = { param($m, $u, $b, $h) if ($Http) { & $Http $m $u $b $h } else { Invoke-EpsUpdateHttp -Method $m -Url $u -Body $b -Headers $h -TimeoutSec 10 } }.GetNewClosure()
    $o = & $send 'POST' "$base/api/install/runs" ([ordered]@{ productId = $script:EpsUpdateProduct; kind = 'update'; ring = $Ring; fromVersion = $FromVersion; toVersion = $ToVersion }) @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    if ([int]$o.status -ne 201 -or -not "$($o.body.token)") { return @{ Ok = $false; RunId = ''; Emit = $none; Reason = "Invardia did not open the update run (HTTP $([int]$o.status))" } }
    $st = @{ Seq = 0; Stopped = $false; Hdr = $(if ("$($o.body.tokenHeader)" -match '^X-Invardia-[A-Za-z-]+$') { "$($o.body.tokenHeader)" } else { 'X-Invardia-Install-Token' })
             Url = $(if ("$($o.body.eventsUrl)" -match '^https://') { "$($o.body.eventsUrl)" } else { "$base/api/install/events" }); Token = "$($o.body.token)"; Titles = $script:EpsUpdateApplySteps }
    $emit = {
        param($step, $state, $message)
        if ($st.Stopped) { return }
        $st.Seq++
        $r = & $send 'POST' $st.Url ([ordered]@{ seq = $st.Seq; step = @{ id = $step; title = $(if ($st.Titles -and $st.Titles.Contains($step)) { $st.Titles[$step] } else { $step }) }; state = $state; at = [datetime]::UtcNow.ToString('o'); message = "$message" }) @{ $st.Hdr = $st.Token }
        if ([int]$r.status -notin 200, 201, 202, 204) { $st.Stopped = $true }
    }.GetNewClosure()
    @{ Ok = $true; RunId = "$($o.body.runId)"; Emit = $emit; Reason = 'opened' }
}

function Invoke-EpsUpdateCheck {
    <#
      The update job's whole cycle: check, verify, "update now", the run gate - and (phase 2) the APPLY of an available
      release when the job has its updater identity and no work job runs (else it waits for the next night: owner "Give
      up, retry next night"). -Log { param($level, $msg) }. Seams: -Http, -InstallKey (else read from the Key Vault as the
      uplink does), -TrustedKeys, -UpdaterClientId (else EPS_UPDATER_CLIENT_ID), -ApplyTokenProvider, -Fetch, -CheckOnly.
      Returns @{ State; Version; Ring; Gate; Head; Track; Applied; Summary }. A version that is only reported (no apply)
      is reported to Invardia ONCE per version (the previous run's summary says it was).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Version, [scriptblock]$Log = { param($l, $m) },
          [scriptblock]$Http, [AllowNull()][object]$InstallKey = $null, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys,
          [AllowEmptyString()][AllowNull()][string]$Ring = $env:EPS_RING, [AllowNull()][object]$UpdaterClientId = $null, [switch]$CheckOnly,
          [scriptblock]$ApplyTokenProvider, [scriptblock]$Fetch, [int]$PollSeconds = 15,
          # UPD-HOLD: this update run's eps.Run row (the hold is marked on it; none = no hold, the apply waits as before),
          # -QuietProbe { } -> running work job names (default: eps.Run + the ARM executions), -WaitSleep { param($s) }
          [AllowNull()][object]$RunId = $null, [scriptblock]$QuietProbe, [scriptblock]$WaitSleep, [scriptblock]$WaitNow)
    $ringN = Get-EpsUpdateRing -Ring $Ring
    & $Log 'Info' "update cycle: running $Version, ring $ringN"
    $t = Get-EpsUpdateTarget -RunningVersion $Version -Ring $ringN -Http $Http -TrustedKeys $TrustedKeys
    & $Log $(if ($t.State -in 'refused', 'unreachable') { 'Warning' } else { 'Info' }) "release for ring $ringN`: $($t.State) - $($t.Reason)"
    # [object], not [string]: a [string] parameter turns $null into '' and the vault was never read (found live 2026-11-04)
    if ($null -eq $InstallKey) { $k = Get-EpsUplinkKey; $InstallKey = "$($k.Key)"; if (-not $InstallKey) { & $Log 'Info' "no install key ($($k.Reason)): update now and the update run report are skipped" } }
    $updater = if ($null -ne $UpdaterClientId) { "$UpdaterClientId" } else { "$env:EPS_UPDATER_CLIENT_ID" }
    if (-not $ApplyTokenProvider -and $updater) { $ApplyTokenProvider = { param($r) Get-EpsManagedIdentityToken -Resource $r -ClientId $updater }.GetNewClosure() }
    # INSTALL-PRO (2.0.86; SI / PIM's licence path): knock -> pull -> verify -> store (the install's Key Vault, as the
    # updater identity, framework §12.25) -> claim the install key (LIC-01) -> the SIGNED Pro channel (kind 'code', the
    # same verifier, the same sequence guard) instead of the Community channel. No licence = Community, exactly as before;
    # a Community install never knocks.
    $proLicence = ''; $proEdition = 'community'; $fromPro = $false; $licHttp = $Http
    if (Get-Command Invoke-EpsLicenceCycle -ErrorAction SilentlyContinue) {
        $licHttp = if ($Http) { $Http } else { { param($m, $u, $b, $hd) Invoke-EpsUpdateHttp -Method $m -Url $u -Body $b -Headers $hd } }
        $write = if ($CheckOnly -or -not $ApplyTokenProvider) { { param($n, $v) @{ Ok = $false; Reason = 'this run has no updater identity (id-eps-updater) to write the Key Vault' } } }
                 else { { param($n, $v) $s0 = $global:EPS_TokenProvider; $global:EPS_TokenProvider = $ApplyTokenProvider; try { Set-EpsInstallSecret -Name $n -Value $v } finally { $global:EPS_TokenProvider = $s0 } } }
        $lc = Invoke-EpsLicenceCycle -ConnectionString $ConnectionString -Version $Version -Http $licHttp -InstallKey "$InstallKey" -WriteSecret $write -Log $Log
        if ($lc.InstallKey) { $InstallKey = "$($lc.InstallKey)" }
        $proLicence = "$($lc.LicenceText)"; $proEdition = "$($lc.Edition)"
        if ($proEdition -ne 'community') {
            $pt = Get-EpsProUpdateTarget -RunningVersion $Version -Ring $ringN -Http $licHttp -InstallKey $InstallKey -LicenceText $proLicence -Edition $proEdition -TrustedKeys $TrustedKeys
            & $Log $(if ($pt.State -in 'refused', 'unreachable') { 'Warning' } else { 'Info' }) "Pro channel for ring $ringN`: $($pt.State) - $($pt.Reason)"
            if ($pt.State -ne 'community') { $t = $pt; $fromPro = $true }
        }
    }
    $h = Get-EpsUpdateHead -InstallKey $InstallKey -Ring $ringN -Http $Http -LicenceText $proLicence
    # UPD-03 (2.0.97): what the tick needs to ask "update now" every 15 minutes - the ring, the channel, the vault (no key,
    # no licence: the tick reads the key from the vault itself). Never fails the update.
    # WORKER-UPD (2.0.102, framework §5.5): + the version this install RUNS - the hybrid worker's daily update follows it
    try {
        $hcv = [ordered]@{ ring = $ringN; kind = $(if ($proEdition -ne 'community') { 'code' } else { 'community' }); vault = "$(Get-EpsUplinkVaultName)"; version = "$Version" } | ConvertTo-Json -Compress
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $script:EpsUpdateHeadSetting; v = $hcv } -Query @'
MERGE eps.Setting AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = N'engine (update job)'
WHEN NOT MATCHED THEN INSERT (Name, Feature, Value, UpdatedBy) VALUES (@n, 'Update', @v, N'engine (update job)');
'@ | Out-Null
    } catch { & $Log 'Warning' "update now: the tick's check could not be prepared ($((("$($_.Exception.Message)") -split "`n")[0]))" }
    # always said (found live 2026-11-04: a silent skip hid why no head call was made)
    & $Log $(if ($InstallKey -and $h.Status -ne 200) { 'Warning' } else { 'Info' }) "update now: $($h.Reason)$(if ($h.Status) { " (HTTP $($h.Status))" })"
    $g = Get-EpsUpdateRunGate -ConnectionString $ConnectionString
    & $Log 'Info' "run gate: $($g.Reason)"
    $track = $null; $applied = $null
    # PHASE 2 (UPDATER-1 apply): the update job has its own identity id-eps-updater (EPS_UPDATER_CLIENT_ID); without it
    # (an install made before it) the job only checks and reports, as phase 1 did
    # framework installer rule 11: EVERY run with the updater identity re-enforces + reads back a private install's vault shape
    $vault = $null
    if ($updater -and -not $CheckOnly -and (Get-Command Invoke-EpsVaultShapeCheck -ErrorAction SilentlyContinue)) {
        $saved0 = $global:EPS_TokenProvider; $global:EPS_TokenProvider = $ApplyTokenProvider
        try { $vault = Invoke-EpsVaultShapeCheck -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" } finally { $global:EPS_TokenProvider = $saved0 }
        & $Log $(if ($vault.State -eq 'failed') { 'Warning' } else { 'Info' }) "key vault shape (rule 11): $($vault.State) - $($vault.Reason)"
    }
    # framework §4.5 SQL-ADMIN-GROUP G2/G4/G5 (the owner: "both setup and upd"): EVERY run with the updater identity
    # converges the database setup identity's membership of the SQL admin group and renews a time-limited one ending
    # within 30 days; reports its own Graph roles and a non-role-assignable group (a finding). Never fails the run here:
    # a refusal is a warning (an update's apply converges again and does not start the database job without it).
    if ($updater -and -not $CheckOnly -and (Get-Command Invoke-EpsSqlAdminGroupConverge -ErrorAction SilentlyContinue)) {
        $saved2 = $global:EPS_TokenProvider; $global:EPS_TokenProvider = $ApplyTokenProvider
        try {
            $cv = Invoke-EpsSqlAdminGroupConverge -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP"
            foreach ($l in $cv.Lines) { & $Log $(if ($l -match '^(WARNING|FINDING)|WARNING:') { 'Warning' } else { 'Info' }) "SQL admin group: $l" }
        } catch { & $Log 'Warning' "SQL admin group: $((("$($_.Exception.Message)") -split "`n")[0])" }
        finally { $global:EPS_TokenProvider = $saved2 }
    }
    # SEC-10 (2.1.2): the Key Vault setup steps as read now -> eps.UplinkState 'setup.keyvault' (the heartbeat's setupSteps
    # keyvault-purge-protection / keyvault-secrets-only, how updater); a failed read leaves the last stored value
    if ($updater -and -not $CheckOnly -and (Get-Command Get-EpsKeyVaultSetupFact -ErrorAction SilentlyContinue)) {
        $saved3 = $global:EPS_TokenProvider; $global:EPS_TokenProvider = $ApplyTokenProvider
        try { $kvf = Get-EpsKeyVaultSetupFact -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" } finally { $global:EPS_TokenProvider = $saved3 }
        & $Log 'Info' "Key Vault (SEC-10): $($kvf.Reason)"
        if ($kvf.Fact) {
            try { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = ($kvf.Fact | ConvertTo-Json -Compress) } -Query "MERGE eps.UplinkState AS d USING (SELECT N'setup.keyvault' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (N'setup.keyvault', @v);" | Out-Null }
            catch { & $Log 'Warning' "Key Vault (SEC-10): not stored: $($_.Exception.Message)" }
        }
    }
    # framework rule 11g (5): the build pool as read now -> eps.UplinkState 'buildpool' (the uplink sends it); no pool = ''
    # (the heartbeat field is then left out); a failed read leaves the last stored value as it was
    if ($updater -and -not $CheckOnly -and (Get-Command Get-EpsBuildPoolFact -ErrorAction SilentlyContinue)) {
        $saved1 = $global:EPS_TokenProvider; $global:EPS_TokenProvider = $ApplyTokenProvider
        try { $bp = Get-EpsBuildPoolFact -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" } finally { $global:EPS_TokenProvider = $saved1 }
        & $Log 'Info' "build pool (rule 11g): $($bp.Reason)"
        if ($null -ne $bp.None) {
            $bv = if ($bp.None) { '' } else { ($bp.Fact | ConvertTo-Json -Compress) }
            try { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = $bv } -Query "MERGE eps.UplinkState AS d USING (SELECT N'buildpool' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (N'buildpool', @v);" | Out-Null }
            catch { & $Log 'Warning' "build pool: not stored: $($_.Exception.Message)" }
        }
    }
    # SECAUDIT-1a (Invardia ruling 2026-11-07): the web app registration's own settings, as its OWNER (the updater identity) -
    # every run, never fails the cycle; the install run hands the ownership over
    if ($updater -and -not $CheckOnly -and (Get-Command Sync-EpsWebRegistrationAsOwner -ErrorAction SilentlyContinue)) {
        $saved2 = $global:EPS_TokenProvider; if ($ApplyTokenProvider) { $global:EPS_TokenProvider = $ApplyTokenProvider } else { $global:EPS_TokenProvider = { param($r) Get-EpsManagedIdentityToken -Resource $r -ClientId $updater }.GetNewClosure() }
        try { $wr = Sync-EpsWebRegistrationAsOwner -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" } finally { $global:EPS_TokenProvider = $saved2 }
        foreach ($l in $wr.Lines) { & $Log $(if ($l -like 'WARNING*') { 'Warning' } else { 'Info' }) $l }
    }
    # IMAGE-PATCH-1 (2.0.120): a CURRENT install's sign-in front converges to the running release's pin (an older updater's
    # apply did not move the front) - as the updater identity, never fails the cycle
    if ($t.State -eq 'current' -and $updater -and -not $CheckOnly -and (Get-Command Invoke-EpsFrontConverge -ErrorAction SilentlyContinue)) {
        $saved3 = $global:EPS_TokenProvider; if ($ApplyTokenProvider) { $global:EPS_TokenProvider = $ApplyTokenProvider } else { $global:EPS_TokenProvider = { param($r) Get-EpsManagedIdentityToken -Resource $r -ClientId $updater }.GetNewClosure() }
        try { $fc = Invoke-EpsFrontConverge -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" -PollSeconds $PollSeconds } finally { $global:EPS_TokenProvider = $saved3 }
        foreach ($l in $fc.Lines) { & $Log $(if ($l -like 'WARNING*') { 'Warning' } else { 'Info' }) $l }
    }
    $quiet = $null
    if ($t.State -eq 'available' -and $updater -and -not $CheckOnly) {
        $saved = $global:EPS_TokenProvider
        # Azure as the UPDATER identity for the apply only (the engine identity holds no Azure right)
        if (-not $ApplyTokenProvider) { $ApplyTokenProvider = { param($r) Get-EpsManagedIdentityToken -Resource $r -ClientId $updater }.GetNewClosure() }
        $global:EPS_TokenProvider = $ApplyTokenProvider
        $held = $false
        try {
            # UPD-HOLD: hold the dispatch FIRST (a waiting update goes first), then wait until no work job runs
            if ($RunId) { $held = Set-EpsUpdateHold -ConnectionString $ConnectionString -RunId ([guid]"$RunId") -On; & $Log 'Info' "update hold: $(if ($held) { 'on - no new job starts until the update is done' } else { 'could not be set - the apply waits for running jobs only' })" }
            if (-not $QuietProbe) {
                $cs = $ConnectionString; $rgp = "/subscriptions/$env:EPS_SUBSCRIPTION_ID/resourceGroups/$env:EPS_RESOURCE_GROUP/providers/Microsoft.App/jobs"
                # the API version as a LOCAL value: a GetNewClosure() scriptblock does not see $script: variables (found live
                # 2026-11-05 at internal: "ApiVersion ... is an empty string" - the update stopped, nothing changed)
                $acaApi = if ($script:EpsApi -and "$($script:EpsApi.acajob)") { "$($script:EpsApi.acajob)" } else { '2024-03-01' }
                $holdLog = $Log; $stuckTold = @{}; $stuck = $null
                $QuietProbe = {
                    $names = @(); $arm = $null
                    if (Get-Command Invoke-EpsArm -ErrorAction SilentlyContinue) {
                        # EPS's own jobs only (another product's job in the same resource group never holds an EPS update)
                        $names = @(@((Invoke-EpsArm -Path $rgp -ApiVersion $acaApi).value) | ForEach-Object { "$($_.name)" } | Where-Object { $_ -like 'caj-eps-*' })
                        # copied to LOCALS first: a closure made inside this closure captures only local variables
                        $p0 = "$rgp"; $v0 = "$acaApi"
                        $arm = { param($j) Invoke-EpsArm -Path "$p0/$j/executions" -ApiVersion $v0 }.GetNewClosure()
                        # UPD-STUCK-RUN: a stuck execution is stopped (the updater holds Contributor on the resource group),
                        # said once in the run log (which reaches Invardia), and not waited for
                        $lg = $holdLog; $told = $stuckTold
                        $stuck = { param($j, $en, $st)
                            if ($told.ContainsKey("$j/$en")) { return }; $told["$j/$en"] = $true
                            try { Stop-EpsStuckJobExecution -JobsPath $p0 -Job $j -Execution $en -ApiVersion $v0; & $lg 'Warning' "update hold: $j execution $en has run since $($st.ToString('yyyy-MM-dd HH:mm'))Z with no run row - STUCK: stopped, not waited for (framework UPD-06)" }
                            catch { & $lg 'Warning' "update hold: $j execution $en has run since $($st.ToString('yyyy-MM-dd HH:mm'))Z with no run row - STUCK, not waited for; stopping it failed: $((("$($_.Exception.Message)") -split "`n")[0])" } }.GetNewClosure()
                    }
                    Get-EpsUpdateRunningWork -ConnectionString $cs -Arm $arm -Jobs $names -OnStuck $stuck
                }.GetNewClosure()
            }
            $wq = @{ Probe = $QuietProbe; Log = $Log }; if ($WaitSleep) { $wq.Sleep = $WaitSleep }; if ($WaitNow) { $wq.Now = $WaitNow }
            $quiet = Wait-EpsUpdateQuiet @wq
            if ($quiet.Go -and $quiet.Waited -gt 0) {
                # UPD-STALE-LINK (found live 2026-11-06 at internal, 2.0.89 -> 2.0.90): the signed download link is short-lived -
                # after a 21-min wait the Pro package answered 401. After ANY wait the release is read again for a fresh link;
                # the same version + SHA-256 = go on, anything else = nothing installed, the next run decides again
                $t2 = if ($fromPro) { Get-EpsProUpdateTarget -RunningVersion $Version -Ring $ringN -Http $licHttp -InstallKey $InstallKey -LicenceText $proLicence -Edition $proEdition -TrustedKeys $TrustedKeys }
                      else { Get-EpsUpdateTarget -RunningVersion $Version -Ring $ringN -Http $Http -TrustedKeys $TrustedKeys }
                if ($t2.State -eq 'available' -and "$($t2.Version)" -eq "$($t.Version)" -and "$($t2.Sha256)" -eq "$($t.Sha256)" -and "$($t2.DownloadUrl)") {
                    $t = $t2; & $Log 'Info' "update: the release read again after the wait (a fresh download link) - $($t2.Reason)"
                } else {
                    & $Log 'Warning' "update: the release read again after the wait is not the one this run planned ($($t2.State) - $($t2.Reason)) - nothing installed, the next run decides again"
                    $quiet = @{ Go = $false; Waited = $quiet.Waited; Running = @(); Stale = $true }
                }
            }
            if ($quiet.Go) {
                & $Log 'Info' "update hold: no work job runs$(if ($quiet.Waited -gt 0) { " (waited $($quiet.Waited) min)" }) - installing"
                $tr = Open-EpsUpdateRunTrack -InstallKey $InstallKey -Ring $ringN -FromVersion $Version -ToVersion $t.Version -Http $Http
                & $Log 'Info' "update run to Invardia: $($tr.Reason)"
                & $tr.Emit 'check' 'ok' "$($t.Version) is approved for ring $ringN"
                $applied = Invoke-EpsUpdateApply -Target @{ Version = $t.Version; Sha256 = $t.Sha256; Size = $t.Size; DownloadUrl = $t.DownloadUrl } -RunningVersion $Version `
                    -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" -Emit $tr.Emit -Log $Log -Fetch $Fetch -PollSeconds $PollSeconds
            }
        } finally {
            $global:EPS_TokenProvider = $saved
            if ($held) { [void](Set-EpsUpdateHold -ConnectionString $ConnectionString -RunId ([guid]"$RunId")); & $Log 'Info' 'update hold: lifted' }
        }
    }
    if ($quiet -and -not $quiet.Go) {
        # gave up: nothing changed; said in the run, to Invardia (the update run waits) and on the heartbeat (Update.waited)
        $why = "update to $($t.Version) waited $([int]$script:EpsUpdateHold.WaitMinutes) min for running jobs ($(@($quiet.Running) -join ', ')); tries again within the hour until it installs (ROLL-RETRY-1, at most 24 h)"
        & $Log 'Warning' $why
        $track = Send-EpsUpdateRunTrack -InstallKey $InstallKey -Ring $ringN -FromVersion $Version -ToVersion $t.Version -Http $Http -WaitReason $why
        $g = @{ Go = $false; Running = @($quiet.Running); Reason = $why }
    } elseif ($applied) {
        $track = @{ Ok = $tr.Ok; Reason = $tr.Reason }
        # AUD-01: the install changed (or stopped part way) - in the audit trail, not only in the run's log. A change no
        # person asked for: the job is the actor (AUDIT-1.1). Never fails the cycle.
        try {
            [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'update.apply' -Actor 'caj-eps-updater (ring approval)' -ActorSource 'job' `
                -Target "Release|$Version -> $($t.Version)" -Reason "approved for ring $ringN" -Outcome $(if ($applied.Ok) { 'ok' } else { 'error' }) `
                -OutcomeText $(if ($applied.Ok) { "$(@($applied.Rolled).Count) component(s) rolled" } else { "stopped at '$($applied.Step)': $($applied.Reason)" }) `
                -Before @{ version = $Version } -After @{ version = $t.Version; ring = $ringN; rolled = @($applied.Rolled); step = "$($applied.Step)" })
        } catch { & $Log 'Warning' "audit: update.apply could not be written: $($_.Exception.Message)" }
    } elseif ($t.State -eq 'available') {
        $prev =@(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT TOP (1) HeldReason FROM eps.Run WHERE Job = 'Update' AND Status = 'Succeeded' AND HeldReason IS NOT NULL ORDER BY StartedAtUtc DESC")[0]
        if ("$($prev.HeldReason)" -like "*reported $($t.Version) *") { & $Log 'Info' "update run for $($t.Version) already reported to Invardia" ; $track = @{ Ok = $true; Reason = 'already reported' } }
        else {
            $why = if (-not $updater) { 'this install has no updater identity yet (id-eps-updater): one install run with this release adds it' } elseif (-not $g.Go) { "$($g.Reason) - the next night tries again" } else { 'check only' }
            $track = Send-EpsUpdateRunTrack -InstallKey $InstallKey -Ring $ringN -FromVersion $Version -ToVersion $t.Version -Http $Http -WaitReason $why
            & $Log $(if ($track.Ok) { 'Info' } else { 'Warning' }) "update run to Invardia: $($track.Reason)"
        }
    }
    $sum = switch ($t.State) {
        'available' {
            if ($applied -and $applied.Ok) { "updated $Version -> $($t.Version) on ring $ringN ($(@($applied.Rolled).Count) components rolled)" }
            elseif ($applied) { "update to $($t.Version) on ring $ringN stopped at '$($applied.Step)': $($applied.Reason)" }
            else { "$($t.Version) is available on ring $ringN (running $Version); not installed$(if ($track.Ok) { " - reported $($t.Version) to Invardia" })" + $(if ($h.Expedite) { "; update now asked" }) + "; $($g.Reason)" }
        }
        'held'      { "$($t.Version) on ring $ringN is held: $($t.Reason)" }
        'current'   { "up to date on ring $ringN ($Version)" }
        'ahead'     { "running $Version, newer than ring $ringN approves ($($t.Version))" }
        default     { "the check did not complete: $($t.Reason)" }
    }
    # TEL-03: the heartbeat's setup step 'updater' reads this from the run's summary
    if (-not $updater) { $sum += ' - no updater identity (id-eps-updater): one install run with 2.0.60 or later adds it' }
    & $Log $(if ($applied -and -not $applied.Ok) { 'Warning' } else { 'Info' }) $sum
    return @{ State = $t.State; Version = $t.Version; Ring = $ringN; Gate = $g; Head = $h; Track = $track; Applied = $applied; Summary = $sum }
}
