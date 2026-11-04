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
    param([AllowEmptyString()][string]$InstallKey, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [scriptblock]$Http, [string]$BaseUrl = $script:EpsUpdateBase)
    if (-not "$InstallKey".Trim()) { return @{ Status = 0; Version = ''; Expedite = $null; Reason = 'no install key: "update now" is not asked' } }
    if ("$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return @{ Status = 0; Version = ''; Expedite = $null; Reason = 'the install key is not in the expected format: "update now" is not asked' } }
    $url = "$("$BaseUrl".Trim().TrimEnd('/'))/api/updates/$($script:EpsUpdateProduct)/head"
    $h = @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    $b = [ordered]@{ ring = $Ring; kind = $script:EpsUpdateKind }
    $r = if ($Http) { & $Http 'POST' $url $b $h } else { Invoke-EpsUpdateHttp -Method POST -Url $url -Body $b -Headers $h }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -ne 200) { return @{ Status = $st; Version = ''; Expedite = $null; Reason = $(if ($st -eq 403 -and $r.body.ringOnRecord -ne $null) { "Invardia has this install on ring $($r.body.ringOnRecord), not ring $Ring" } else { Get-InvardiaPullReason -Status $st -Body $r.body -ErrorText "$($r.error)" }) } }
    $ex = $null
    if ($r.body.expedite -and "$($r.body.expedite.apply)" -in 'now', 'window') { $ex = @{ Apply = "$($r.body.expedite.apply)"; Until = "$($r.body.expedite.until)"; Reason = "$($r.body.expedite.reason)" } }
    return @{ Status = 200; Version = "$($r.body.version)"; Expedite = $ex; Reason = $(if ($ex) { "update now asked ($($ex.Apply)): $($ex.Reason)" } else { 'no "update now" for this install' }) }
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
          [scriptblock]$ApplyTokenProvider, [scriptblock]$Fetch, [int]$PollSeconds = 15)
    $ringN = Get-EpsUpdateRing -Ring $Ring
    & $Log 'Info' "update cycle: running $Version, ring $ringN"
    $t = Get-EpsUpdateTarget -RunningVersion $Version -Ring $ringN -Http $Http -TrustedKeys $TrustedKeys
    & $Log $(if ($t.State -in 'refused', 'unreachable') { 'Warning' } else { 'Info' }) "release for ring $ringN`: $($t.State) - $($t.Reason)"
    # [object], not [string]: a [string] parameter turns $null into '' and the vault was never read (found live 2026-11-04)
    if ($null -eq $InstallKey) { $k = Get-EpsUplinkKey; $InstallKey = "$($k.Key)"; if (-not $InstallKey) { & $Log 'Info' "no install key ($($k.Reason)): update now and the update run report are skipped" } }
    $h = Get-EpsUpdateHead -InstallKey $InstallKey -Ring $ringN -Http $Http
    # always said (found live 2026-11-04: a silent skip hid why no head call was made)
    & $Log $(if ($InstallKey -and $h.Status -ne 200) { 'Warning' } else { 'Info' }) "update now: $($h.Reason)$(if ($h.Status) { " (HTTP $($h.Status))" })"
    $g = Get-EpsUpdateRunGate -ConnectionString $ConnectionString
    & $Log 'Info' "run gate: $($g.Reason)"
    $track = $null; $applied = $null
    # PHASE 2 (UPDATER-1 apply): the update job has its own identity id-eps-updater (EPS_UPDATER_CLIENT_ID); without it
    # (an install made before it) the job only checks and reports, as phase 1 did
    $updater = if ($null -ne $UpdaterClientId) { "$UpdaterClientId" } else { "$env:EPS_UPDATER_CLIENT_ID" }
    if ($t.State -eq 'available' -and $updater -and $g.Go -and -not $CheckOnly) {
        $tr = Open-EpsUpdateRunTrack -InstallKey $InstallKey -Ring $ringN -FromVersion $Version -ToVersion $t.Version -Http $Http
        & $Log 'Info' "update run to Invardia: $($tr.Reason)"
        & $tr.Emit 'check' 'ok' "$($t.Version) is approved for ring $ringN"
        $saved = $global:EPS_TokenProvider
        # Azure as the UPDATER identity for the apply only (the engine identity holds no Azure right)
        if (-not $ApplyTokenProvider) { $ApplyTokenProvider = { param($r) Get-EpsManagedIdentityToken -Resource $r -ClientId $updater }.GetNewClosure() }
        $global:EPS_TokenProvider = $ApplyTokenProvider
        try {
            $applied = Invoke-EpsUpdateApply -Target @{ Version = $t.Version; Sha256 = $t.Sha256; Size = $t.Size; DownloadUrl = $t.DownloadUrl } -RunningVersion $Version `
                -TenantId "$env:EPS_TENANT_ID" -SubscriptionId "$env:EPS_SUBSCRIPTION_ID" -ResourceGroup "$env:EPS_RESOURCE_GROUP" -Emit $tr.Emit -Log $Log -Fetch $Fetch -PollSeconds $PollSeconds
        } finally { $global:EPS_TokenProvider = $saved }
        $track = @{ Ok = $tr.Ok; Reason = $tr.Reason }
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
