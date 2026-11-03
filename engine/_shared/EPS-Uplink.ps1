# EntraPolicySuite -- the Invardia uplink (UPLINK-1; framework DOCS/REQUIREMENTS.md §8.4 Schema 2, §8.16, §8.17
# HEARTBEAT-FIELDS, §8.19 ALERT, SECAUDIT-1a). Owner 2026-11-01: "Yes, identified only" + "Install's Key Vault".
#
#   IDENTIFIED ONLY: EPS reports only with the per-install key Invardia issued. The key is the secret `uplink-key` in the
#   install's own Key Vault; only the engine identity may read THAT secret (Key Vault Secrets User on the secret). It is
#   read at send time, kept in memory, never logged, never stored, never in a job's env / config. No key = the uplink is
#   DISABLED: no call to Invardia at all (never anonymous, never the community code).
#
#   One cycle (the Uplink job, every 4 h from its own queue - not the tick, not a work job):
#     1. the heartbeat (liveness + the §8.17 fields EPS fills honestly; a field it cannot fill is omitted), due every 4 h;
#        an interval counts as sent only after a 2xx; a 4xx refusal is resent ONCE without the newer fields (§8.17);
#        the answer's support state (SECAUDIT-1a) is RECORDED and SHOWN - nothing is granted from it yet;
#     2. the alert records (Kind 'alert', §8.19) behind Uplink.Alerts.Enabled (default OFF: Invardia does not take the
#        kind yet) - one per AlertId per 24 h while open, at most 10 per cycle;
#     3. the run records of finished runs, one watermark per job, oldest first.
#   At most 20 POSTs per cycle, ~2.5 s apart; the cycle STOPS at the first non-ok answer; what was not sent is sent next
#   cycle (a watermark / an episode moves only after a 2xx). Never throws: a failure is ONE plain line.
#
# The rules of sync/_AitUplink.ps1 (redaction, the closed lists) are COPIED here on purpose (isolation beats DRY: sync/
# ships to every customer with no review step). Dot-source EPS-SqlStore, EPS-Graph (Get-EpsToken, $script:EpsHttp),
# EPS-Scheduler (Get-EpsSetting), EPS-Audit and EPS-Mail (Get-EpsEnvironmentName) first.

Set-StrictMode -Off

$script:EpsUplinkEndpoint   = 'https://invardia.com/api/uplink/v1/report'
$script:EpsUplinkProduct    = 'entrapolicysuite'
$script:EpsUplinkSecretName = 'uplink-key'
$script:EpsUplinkKvApi      = '7.4'
$script:EpsUplinkMaxPosts   = 20          # framework §8.4: ~20 per cycle (Invardia: 30 / min per client IP, shared behind a NAT)
$script:EpsUplinkPauseMs    = 2500
$script:EpsUplinkHeartbeatHours = 4       # owner 2026-10-10 "make it every 4 hr": a product constant, not a setting
$script:EpsUplinkAlertMax   = 10
$script:EpsUplinkAlertRepeatHours = 24
$script:EpsUplinkWorkerSilentMinutes = 60
$script:EpsUplinkFirstRunsHours = 24      # a job without a watermark: its runs of the last 24 h (no history dump)
$script:EpsUplinkSleep = { param([int]$Ms) if ($Ms -gt 0) { Start-Sleep -Milliseconds $Ms } }   # a test counts the pauses

# ---- the closed lists (Invardia packages/core/src/uplink.ts + heartbeatstate.ts; framework §8.17 / §8.19) ----
$script:EpsUplinkLists = @{
    Kind            = @('heartbeat', 'run', 'alert')
    Outcome         = @('ok', 'warning', 'failed')
    Edition         = @('community', 'pro', 'trial')
    Hosting         = @('container', 'vm', 'arc')
    RuntimeIdentity = @('mi-container', 'mi-vm', 'mi-arc', 'spn-certificate', 'spn-secret')
    FixKind         = @('customer-config', 'product-defect')
    ErrorClass      = @('held-guard', 'partly-failed', 'run-limit', 'permission', 'throttled', 'sql', 'timeout', 'upstream-error', 'unclassified')
    JobResult       = @('succeeded', 'failed', 'stopped', 'running')
    UpdaterResult   = @('succeeded', 'failed', 'nothing-to-do')
    MailJob         = @('present', 'missing')
    MailRestriction = @('verified', 'not-verified', 'failed')
    SignInLayer     = @('signin-front', 'easyauth', 'none')
    AlertId         = @('eps.tamper.foreign-change', 'eps.tamper.high', 'eps.ca.drift', 'eps.ca.policy-deleted', 'eps.ca.breakglass-exclusion-missing', 'eps.worker.silent')
    Severity        = @('critical', 'warning')
    Area            = @('tamper', 'ca', 'worker')
    AlertJob        = @('tampermonitor', 'caanalyzer', 'tick')
    MeasuredKey     = @('events', 'high', 'policies', 'accounts', 'minutesSilent')
    SetupState      = @('ok', 'missing', 'n/a', 'unknown')       # FLEET-STEPS (owner 2026-11-03 via Invardia, the field shared by SI, PIM and EPS)
    SetupHow        = @('updater', 'support-app', 'customer')
    EndpointKind    = @('webapp', 'api')                         # DELIVERY-CONTRACT A (framework §0.1 / §8.9): every address a person or Invardia opens
    LongRunState    = @('ok', 'long', 'stuck')
    LongRunAction   = @('none', 'cancel-update-restart')
}
# the fields each kind may carry - anything else is dropped before the send (Invardia refuses a whole record on one)
$script:EpsUplinkEnvelope = @('Schema', 'Kind', 'Product', 'Version', 'Edition', 'Hosting', 'RuntimeIdentity', 'ClaimedTenantId', 'LastSeenUtc')
$script:EpsUplinkFields = @{
    heartbeat = $script:EpsUplinkEnvelope + @('Outcome', 'Counts', 'EnvironmentName', 'Jobs', 'Update', 'Mail', 'SignIn', 'Database', 'SetupSteps', 'Endpoints', 'Pipeline')
    run       = $script:EpsUplinkEnvelope + @('Job', 'Outcome', 'DurationMs', 'ErrorClass', 'FixKind', 'ErrorText', 'Counts')
    # an alert carries Invardia's ALERT_FIELDS only (packages/core/src/uplinkalert.ts): NOT Hosting / RuntimeIdentity - a record with
    # them was refused 422 (internal, 2026-11-03 06:51, eps.tamper.foreign-change) and retried every run
    alert     = @($script:EpsUplinkEnvelope | Where-Object { $_ -notin 'Hosting', 'RuntimeIdentity' }) + @('AlertId', 'Severity', 'Measured', 'FirstSeenUtc', 'Count', 'Area', 'Job', 'ActionText', 'Link')
}
# the heartbeat fields newer than the liveness record (§8.17): left out on the one resend after a 4xx refusal
$script:EpsUplinkNewHeartbeatFields = @('EnvironmentName', 'Jobs', 'Update', 'Mail', 'SignIn', 'Database', 'SetupSteps', 'Endpoints', 'Pipeline')

function Get-EpsUplinkLists { $script:EpsUplinkLists }
function Get-EpsUplinkAllowedFields { param([Parameter(Mandatory)][string]$Kind) @($script:EpsUplinkFields[$Kind]) }

function Select-EpsUplinkEnum {
    # PURE. The value if it is in the closed list (case-insensitive, returned lower-case), else $null: never sent.
    param($Value, [Parameter(Mandatory)][string]$List)
    $v = "$Value".Trim()
    if (-not $v) { return $null }
    foreach ($x in $script:EpsUplinkLists[$List]) { if ($x -eq $v) { return $x } }
    $null
}

function ConvertTo-EpsUplinkRedacted {
    <# PURE. Secrets out of free text (the rules of sync/_AitUplink.ps1 ConvertTo-AitUplinkRedacted, copied) PLUS what
       names a person or an object: mail addresses / UPNs, GUIDs, quoted text, SIDs - the uplink carries numbers, not who.
       -Key: the install key, removed wherever it appears. -Max: the length kept. #>
    param([AllowNull()][string]$Text, [AllowNull()][string]$Key, [int]$Max = 500)
    $t = "$Text"
    if (-not $t) { return '' }
    if ("$Key".Trim().Length -ge 6) { $t = $t.Replace("$Key".Trim(), '[install-key]') }
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*', '[jwt]')
    $t = [regex]::Replace($t, '(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{10,}', '$1 [redacted]')
    $t = [regex]::Replace($t, '(?i)\b(client_secret|password|pwd|secret|apikey|api_key|accountkey|sharedaccesskey)\s*[=:]\s*("[^"]*"|''[^'']*''|[^\s;&,]+)', '$1=[redacted]')
    $t = [regex]::Replace($t, '(?i)([?&](sig|se|sv|sp|skoid|sktid)=)[^&\s]+', '$1[redacted]')
    $t = [regex]::Replace($t, '-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----', '[pem]')
    $t = [regex]::Replace($t, 'inv-[A-Za-z0-9_-]{20,}', '[install-key]')
    $t = [regex]::Replace($t, '(?i)\bX-Ait-Uplink-Code\s*[:=]\s*\S+', 'X-Ait-Uplink-Code: [install-key]')
    # who / what: never sent
    $t = [regex]::Replace($t, '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[name]')
    $t = [regex]::Replace($t, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[id]')
    $t = [regex]::Replace($t, '\bS-1-5-[0-9-]{6,}\b', '[sid]')
    $t = [regex]::Replace($t, '"[^"\r\n]{1,200}"|''[^''\r\n]{1,200}''', '[text]')
    $t = [regex]::Replace($t, '[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f<>]', ' ')
    $t = $t.Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) }
    $t
}

function ConvertTo-EpsUplinkIso {
    # PURE. A time as ISO-8601 UTC ('2026-11-01T10:00:00Z'), or $null
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        $d = if ($Value -is [datetime]) { $Value } else { [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
        if ($d.Kind -eq 'Local') { $d = $d.ToUniversalTime() }
        [datetime]::SpecifyKind($d, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    } catch { $null }
}

function Get-EpsUplinkJobId {
    # PURE. 'UserTagging' -> 'eps-usertagging' (stable, lower-case, the server's id shape)
    param([Parameter(Mandatory)][string]$Job)
    $s = ($Job.Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if ($s.Length -gt 56) { $s = $s.Substring(0, 56) }
    "eps-$s"
}

function Limit-EpsUplinkCounts {
    # PURE. Counts: safe camelCase keys, whole numbers >= 0, AT MOST 40 keys (more refuses the whole record) - kept in
    # the caller's priority order; a key whose value is unknown ($null) is OMITTED, never sent as 0.
    param([System.Collections.IDictionary]$Counts, [int]$Max = 40)
    $o = [ordered]@{}
    if (-not $Counts) { return $o }
    foreach ($k in @($Counts.Keys)) {
        if ($o.Count -ge $Max) { break }
        if ("$k" -cnotmatch '^[a-z][A-Za-z0-9]{0,30}$') { continue }
        $v = $Counts[$k]; if ($null -eq $v -or $v -is [DBNull]) { continue }
        $n = 0.0; if (-not [double]::TryParse("$v", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -or $n -lt 0 -or [double]::IsNaN($n)) { continue }
        $o["$k"] = [int64][math]::Floor($n)
    }
    $o
}

function Get-EpsUplinkVaultName {
    # The install's Key Vault: EPS_KEY_VAULT (set by the install on the Uplink job), else the install's own name rule
    # (kv-eps-<suffix of subscription + resource group>, as Get-EpsInstallNames) - a job made before 2.0.16 has no env.
    $v = "$env:EPS_KEY_VAULT".Trim()
    if ($v) { return $v }
    if (-not $env:EPS_SUBSCRIPTION_ID -or -not $env:EPS_RESOURCE_GROUP) { return '' }
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$($env:EPS_SUBSCRIPTION_ID)|$($env:EPS_RESOURCE_GROUP)".ToLowerInvariant()))
    "kv-eps-$(-join ($h[0..3] | ForEach-Object { $_.ToString('x2') }))"
}

function Get-EpsUplinkKey {
    <#
      The per-install key from the install's Key Vault: GET https://<vault>.vault.azure.net/secrets/uplink-key with the
      ENGINE identity's Key Vault token - that one secret, nothing else in the vault. Never throws, never logs the value.
      @{ Key ('' = none); Reason }: 404 / 403 = no key (Invardia has not written it, or the engine was not granted it) ->
      the uplink stays disabled.
    #>
    param([string]$VaultName = (Get-EpsUplinkVaultName))
    if ($VaultName -notmatch '^[A-Za-z0-9-]{3,24}$') { return @{ Key = ''; Reason = 'the install''s Key Vault is not known to this job' } }
    $uri = "https://$($VaultName.ToLowerInvariant()).vault.azure.net/secrets/$($script:EpsUplinkSecretName)?api-version=$($script:EpsUplinkKvApi)"
    try {
        $tok = Get-EpsToken -Resource 'https://vault.azure.net'
        $r = & $script:EpsHttp 'GET' $uri @{ Authorization = "Bearer $tok" } $null
    } catch { return @{ Key = ''; Reason = "the Key Vault could not be read: $(ConvertTo-EpsUplinkRedacted -Text "$($_.Exception.Message)" -Max 200)" } }
    if ($r.Status -eq 404) { return @{ Key = ''; Reason = "no Invardia key: the secret $($script:EpsUplinkSecretName) is not in the install's Key Vault" } }
    if ($r.Status -in 401, 403) { return @{ Key = ''; Reason = "no Invardia key: the engine may not read $($script:EpsUplinkSecretName) (HTTP $($r.Status)) - run the install again once the key is there" } }
    if ($r.Status -ge 300) { return @{ Key = ''; Reason = "the Key Vault answered HTTP $($r.Status)" } }
    $k = try { "$(($r.Body | ConvertFrom-Json).value)".Trim() } catch { '' }
    if ($k.Length -lt 10 -or $k.Length -gt 500 -or $k -match '[\s\u0000-\u001f]') { return @{ Key = ''; Reason = "the secret $($script:EpsUplinkSecretName) is not a key" } }
    @{ Key = $k; Reason = 'the install key' }
}

function New-EpsUplinkEnvelope {
    # PURE. Schema 2, identified: the fields every record carries
    param([Parameter(Mandatory)][string]$Kind, [string]$Version, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ Schema = 2; Kind = (Select-EpsUplinkEnum $Kind 'Kind'); Product = $script:EpsUplinkProduct }
    if ("$Version" -match '^[0-9A-Za-z.+-]{1,50}$') { $o.Version = "$Version" }
    $o.Edition = 'community'          # EntraPolicySuite is Community only for now (owner 2026-10-29)
    $o.Hosting = 'container'
    $o.RuntimeIdentity = 'mi-container'
    if ("$TenantId" -match '^[0-9a-fA-F-]{36}$') { $o.ClaimedTenantId = "$TenantId".ToLowerInvariant() }
    $o.LastSeenUtc = ConvertTo-EpsUplinkIso $NowUtc
    $o
}

function Select-EpsUplinkRecord {
    # PURE. Only the fields the kind may carry, none empty - the last gate before a record leaves the install
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Record)
    $allowed = @($script:EpsUplinkFields["$($Record.Kind)"])
    $o = [ordered]@{}
    foreach ($k in @($Record.Keys)) {
        if ($allowed -cnotcontains $k) { continue }
        $v = $Record[$k]
        if ($null -eq $v -or ($v -is [string] -and -not $v) -or ($v -is [System.Collections.IDictionary] -and -not $v.Count)) { continue }
        $o[$k] = $v
    }
    $o
}

# ---------------------------------------------------------------------------------------------------- the heartbeat
function New-EpsUplinkHeartbeat {
    <#
      PURE. The heartbeat from the facts Get-EpsUplinkHeartbeatFacts read. -WithoutNewFields: the liveness record only
      (envelope, Outcome, Counts) - the one resend after a 4xx refusal (§8.17).
      Facts: @{ Counts; EnvironmentName; Jobs = @(@{ Job; LastStart; LastEnd; Status; DurationMin; PrevDurationMin; TimeoutHours });
               Update = @{ Installed }; Mail = @{ Mode; LastSentUtc }; SignIn = @{ Layer; Version }; Database = @{ Tier } }
    #>
    param([Parameter(Mandatory)]$Facts, [string]$Version, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WithoutNewFields)
    $o = New-EpsUplinkEnvelope -Kind 'heartbeat' -Version $Version -TenantId $TenantId -NowUtc $NowUtc
    $o.Outcome = 'ok'
    $c = Limit-EpsUplinkCounts $Facts.Counts
    if ($c.Count) { $o.Counts = $c }
    if (-not $WithoutNewFields) {
        $en = ConvertTo-EpsUplinkRedacted -Text "$($Facts.EnvironmentName)" -Max 120
        if ($en) { $o.EnvironmentName = $en }
        $jobs = [System.Collections.Generic.List[object]]::new()
        foreach ($j in @($Facts.Jobs)) {
            if (-not $j -or $jobs.Count -ge 30) { continue }
            $res = Select-EpsUplinkEnum (ConvertTo-EpsUplinkJobResult $j.Status) 'JobResult'
            if (-not $res) { continue }   # its result is not in the closed list: the item is left out
            $it = [ordered]@{ name = (Get-EpsUplinkJobId $j.Job) }
            $ls = ConvertTo-EpsUplinkIso $j.LastStart; if ($ls) { $it.lastStartUtc = $ls }
            $le = ConvertTo-EpsUplinkIso $j.LastEnd; if ($le) { $it.lastEndUtc = $le }
            $it.lastResult = $res
            foreach ($p in @(@('durationMin', $j.DurationMin), @('prevDurationMin', $j.PrevDurationMin))) { if ($null -ne $p[1] -and [int64]$p[1] -ge 0) { $it[$p[0]] = [int64]$p[1] } }
            if ($null -ne $j.TimeoutHours -and [double]$j.TimeoutHours -ge 0) { $it.timeoutHours = [double]$j.TimeoutHours }
            $jobs.Add($it)
        }
        if ($jobs.Count) { $o.Jobs = @($jobs) }
        if ("$($Facts.Update.Installed)" -match '^[0-9A-Za-z.+-]{1,50}$') { $o.Update = [ordered]@{ installed = "$($Facts.Update.Installed)" } }
        if ($Facts.Mail) {
            # mailJob + restriction are required by the contract: the restriction of the mail sender is NOT checked by
            # the engine at run time, so it says so ('not-verified') - never a guess of 'verified'
            $m = [ordered]@{ mailJob = $(if ("$($Facts.Mail.Mode)" -and "$($Facts.Mail.Mode)" -ne 'none') { 'present' } else { 'missing' }); restriction = 'not-verified' }
            $ms = ConvertTo-EpsUplinkIso $Facts.Mail.LastSentUtc; if ($ms) { $m.lastSentUtc = $ms }
            $o.Mail = $m
        }
        $layer = if ($Facts.SignIn) { Select-EpsUplinkEnum $Facts.SignIn.Layer 'SignInLayer' }
        if ($layer) {
            $s = [ordered]@{ layer = $layer }
            if ($layer -eq 'signin-front' -and "$($Facts.SignIn.Version)" -match '^[0-9A-Za-z.+-]{1,50}$') { $s.version = "$($Facts.SignIn.Version)" }
            $o.SignIn = $s
        }
        if ("$($Facts.Database.Tier)" -match '^[A-Za-z0-9._-]{1,20}$') { $o.Database = [ordered]@{ tier = "$($Facts.Database.Tier)" } }
        # FLEET-STEPS: each one-time step of this install with its state from a real check (at most 40, closed lists)
        $steps = [System.Collections.Generic.List[object]]::new()
        foreach ($s in @($Facts.SetupSteps)) {
            if (-not $s -or $steps.Count -ge 40 -or "$($s.key)" -notmatch '^[a-z0-9-]{1,60}$') { continue }
            $st = Select-EpsUplinkEnum "$($s.state)" 'SetupState'; $how = Select-EpsUplinkEnum "$($s.how)" 'SetupHow'
            if (-not $st -or -not $how) { continue }
            $it = [ordered]@{ key = "$($s.key)"; title = (ConvertTo-EpsUplinkRedacted -Text "$($s.title)" -Max 120); state = $st }
            if ("$($s.since)" -match '^[0-9A-Za-z.+-]{1,50}$') { $it.since = "$($s.since)" }
            $it.how = $how
            $ca = ConvertTo-EpsUplinkIso $s.checkedAt; if ($ca) { $it.checkedAt = $ca }
            $dt = ConvertTo-EpsUplinkRedacted -Text "$($s.detail)" -Max 200; if ($dt) { $it.detail = $dt }
            $steps.Add($it)
        }
        if ($steps.Count) { $o.SetupSteps = @($steps) }
        # DELIVERY-CONTRACT A: the install's addresses - kind + url only (Invardia refuses the WHOLE list on an unknown key)
        $eps = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @($Facts.Endpoints)) {
            if (-not $e -or $eps.Count -ge 12) { continue }
            $k = Select-EpsUplinkEnum "$($e.kind)" 'EndpointKind'
            if ($k -and "$($e.url)" -match '^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$') { $eps.Add([ordered]@{ kind = $k; url = "$($e.url)" }) }
        }
        if ($eps.Count) { $o.Endpoints = @($eps) }
        # DELIVERY-CONTRACT A: a run that goes now, against its usual length (Invardia alerts at 2x)
        $lr = $Facts.LongRun
        if ($lr -and ($st = Select-EpsUplinkEnum "$($lr.state)" 'LongRunState')) {
            $l = [ordered]@{ usualMin = [double]$lr.usualMin; ageMin = [double]$lr.ageMin; ratio = [Math]::Round([double]$lr.ratio, 2); state = $st; newerWaiting = [bool]$lr.newerWaiting
                             action = $(if ($a = Select-EpsUplinkEnum "$($lr.action)" 'LongRunAction') { $a } else { 'none' }) }
            $at = ConvertTo-EpsUplinkIso $lr.at; if ($at) { $l.at = $at }
            $o.Pipeline = [ordered]@{ job = (Get-EpsUplinkJobId "$($lr.job)"); longRun = $l }
        }
    }
    Select-EpsUplinkRecord $o
}

function ConvertTo-EpsUplinkJobResult {
    # PURE. eps.Run.Status -> the §8.17 lastResult (a Held run stopped on purpose; partly failed = failed)
    param([string]$Status)
    switch ($Status) { 'Succeeded' { 'succeeded' } 'Failed' { 'failed' } 'PartlyFailed' { 'failed' } 'Held' { 'stopped' } 'Running' { 'running' } default { '' } }
}

function Get-EpsUplinkLongRun {
    <#
      DELIVERY-CONTRACT A (framework §0.1, Pipeline.longRun): the run that goes NOW with the largest ratio of its age to
      its usual length (the median of the job's last 10 finished runs; at least 1 minute). state: ok < 2x, long >= 2x,
      stuck >= 4x. newerWaiting / action: EPS's updater is not built yet - false / none. $null when nothing runs.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $run = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Job, StartedAtUtc FROM eps.Run WHERE Status = 'Running' AND Job <> 'Tick'")
        if (-not $run.Count) { return $null }
        $best = $null
        foreach ($r in $run) {
            $d = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ j = [string]$r.Job } -Query "SELECT TOP 10 DATEDIFF(second, StartedAtUtc, EndedAtUtc) / 60.0 AS M FROM eps.Run WHERE Job = @j AND EndedAtUtc IS NOT NULL AND Status IN ('Succeeded', 'PartlyFailed') ORDER BY StartedAtUtc DESC" | ForEach-Object { [double]$_.M } | Sort-Object)
            $usual = if ($d.Count) { [Math]::Max(1.0, $d[[int][Math]::Floor(($d.Count - 1) / 2)]) } else { 1.0 }
            $age = [Math]::Round(($NowUtc - [datetime]::SpecifyKind([datetime]$r.StartedAtUtc, 'Utc')).TotalMinutes, 1)
            $ratio = $age / $usual
            if (-not $best -or $ratio -gt $best.ratio) { $best = @{ job = [string]$r.Job; usualMin = [Math]::Round($usual, 1); ageMin = $age; ratio = $ratio; state = $(if ($ratio -ge 4) { 'stuck' } elseif ($ratio -ge 2) { 'long' } else { 'ok' }); newerWaiting = $false; action = 'none'; at = $NowUtc } }
        }
        $best
    } catch { $null }
}

function Get-EpsUplinkSignInLayer {
    <#
      §8.17 SignIn, read from the RUNNING web app (never a config file): the container app ca-eps-web through ARM - a
      container named signin-front = 'signin-front' + its image tag up to the first '-'; else Easy Auth on = 'easyauth';
      else 'none'. $null (the field omitted) when the read is refused or fails - the engine identity holds no ARM role
      by default (owner's call, UPLINK-1).
    #>
    param([string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID, [string]$ResourceGroup = $env:EPS_RESOURCE_GROUP, [string]$WebApp = 'ca-eps-web')
    if (-not $SubscriptionId -or -not $ResourceGroup) { return $null }
    $base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$WebApp"
    try {
        $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" }
        $r = & $script:EpsHttp 'GET' "$base`?api-version=2024-03-01" $h $null
        if ($r.Status -ne 200) { return $null }
        $app = $r.Body | ConvertFrom-Json -Depth 30
        $front = @($app.properties.template.containers | Where-Object { "$($_.name)" -eq 'signin-front' })[0]
        if ($front) { $tag = ("$($front.image)" -split ':')[-1]; return @{ Layer = 'signin-front'; Version = ($tag -split '-')[0] } }
        $a = & $script:EpsHttp 'GET' "$base/authConfigs/current?api-version=2024-03-01" $h $null
        if ($a.Status -eq 200 -and (($a.Body | ConvertFrom-Json -Depth 20).properties.platform.enabled -eq $true)) { return @{ Layer = 'easyauth'; Version = $null } }
        if ($a.Status -in 200, 404) { return @{ Layer = 'none'; Version = $null } }
        $null
    } catch { $null }
}

function Get-EpsUplinkHeartbeatFacts {
    # What the heartbeat says, read from the product's own database (and the running web app). Each part on its own:
    # a part that cannot be read is left out, never guessed.
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version)
    $q = { param($sql) try { Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query $sql } catch { $null } }
    $users = & $q "SELECT TOP (1) Objects FROM eps.Run WHERE Job = 'UserTagging' AND Scope IS NULL AND Status IN ('Succeeded', 'PartlyFailed', 'Held') ORDER BY StartedAtUtc DESC"
    $devices = & $q "SELECT TOP (1) Objects FROM eps.Run WHERE Job = 'DeviceTagging' AND Scope IS NULL AND Status IN ('Succeeded', 'PartlyFailed', 'Held') ORDER BY StartedAtUtc DESC"
    $ur = & $q 'SELECT COUNT(*) FROM eps.UserTagRule WHERE Enabled = 1'
    $dr = & $q 'SELECT COUNT(*) FROM eps.DeviceTagRule WHERE Enabled = 1'
    # the order is the priority (at most 40 keys)
    $counts = [ordered]@{
        users = $users; devices = $devices
        rules = $(if ($null -ne $ur -and $null -ne $dr) { [int]$ur + [int]$dr }); userRules = $ur; deviceRules = $dr
        tamperOpen = (& $q "SELECT COUNT(*) FROM eps.TamperEvent WHERE Status = 'Open'")
        tamperOpenHigh = (& $q "SELECT COUNT(*) FROM eps.TamperEvent WHERE Status = 'Open' AND Severity = 'High'")
        caFindingsOpen = (& $q "SELECT COUNT(*) FROM eps.CaFinding WHERE Status = 'Open'")
        caPoliciesAdopted = (& $q "SELECT COUNT(*) FROM eps.CaAdoption WHERE Status = 'Adopted'")
        workPackagesQueued = (& $q "SELECT COUNT(*) FROM eps.WorkPackage WHERE Status IN ('Queued', 'Claimed')")
        workers = (& $q 'SELECT COUNT(*) FROM eps.WorkerHeartbeat')
        sqlUsedMb = (& $q "SELECT CAST(SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT)) * 8 / 1024 AS BIGINT) FROM sys.database_files WHERE type = 0")
        sqlMaxMb = (& $q "SELECT CAST(CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS BIGINT) / 1048576 AS BIGINT)")
    }
    # the jobs: the last two runs of each (durations), the work jobs' 7-day limit, the tick's 30 minutes (the install's)
    $jobs = [System.Collections.Generic.List[object]]::new()
    try {
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Job, Status, StartedAtUtc, EndedAtUtc, rn FROM (SELECT Job, Status, StartedAtUtc, EndedAtUtc, ROW_NUMBER() OVER (PARTITION BY Job ORDER BY StartedAtUtc DESC) AS rn FROM eps.Run) x WHERE rn <= 2 ORDER BY Job, rn')
        foreach ($g in ($rows | Group-Object Job)) {
            $a = @($g.Group | Where-Object rn -eq 1)[0]; $b = @($g.Group | Where-Object rn -eq 2)[0]
            $min = { param($r) if ($r -and $r.EndedAtUtc -isnot [DBNull] -and $r.EndedAtUtc) { [int64][math]::Round(([datetime]$r.EndedAtUtc - [datetime]$r.StartedAtUtc).TotalMinutes) } }
            $jobs.Add(@{ Job = $g.Name; LastStart = $a.StartedAtUtc; LastEnd = $(if ($a.EndedAtUtc -isnot [DBNull]) { $a.EndedAtUtc }); Status = $a.Status
                         DurationMin = (& $min $a); PrevDurationMin = (& $min $b); TimeoutHours = $(if ($g.Name -eq 'Tick') { 0.5 } else { 168 }) })
        }
    } catch { }
    $mailMode = try { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Mail.Mode' -Default 'none')" } catch { $null }
    $lastMail = & $q 'SELECT MAX(t) FROM (SELECT MAX(AlertedAtUtc) AS t FROM eps.TamperEvent UNION ALL SELECT MAX(AlertedAtUtc) FROM eps.CaFinding) x'
    @{
        Counts = $counts
        EnvironmentName = (Get-EpsEnvironmentName -ConnectionString $ConnectionString)
        Jobs = @($jobs)
        Update = @{ Installed = $Version }
        Mail = $(if ($null -ne $mailMode) { @{ Mode = $mailMode; LastSentUtc = $(if ($lastMail -isnot [DBNull]) { $lastMail }) } })
        SignIn = (Get-EpsUplinkSignInLayer)
        Database = @{ Tier = "$(& $q "SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective') AS NVARCHAR(40))")" }
        Endpoints = $(if ("$env:EPS_WEB_URL" -match '^https://') { $u = "$env:EPS_WEB_URL".TrimEnd('/'); @(@{ kind = 'webapp'; url = $u }, @{ kind = 'api'; url = "$u/api" }) })
        LongRun = (Get-EpsUplinkLongRun -ConnectionString $ConnectionString)
        # FLEET-STEPS: the engine's rights read back now (its own app role assignments), never a remembered value
        SetupSteps = $(if (Get-Command Get-EpsSetupSteps -ErrorAction SilentlyContinue) { try { @(Get-EpsSetupSteps -Rights (Get-EpsEngineRightsState) -MailMode $mailMode) } catch { @() } })
    }
}

# ---------------------------------------------------------------------------------------------------- run records
function Get-EpsUplinkErrorClass {
    # PURE. eps.Run -> @{ Outcome; ErrorClass; FixKind } (closed lists). A held run is a warning (the guard did its job).
    param([string]$Status, [string]$Text)
    switch ($Status) {
        'Succeeded'    { return @{ Outcome = 'ok'; ErrorClass = ''; FixKind = '' } }
        'Held'         { return @{ Outcome = 'warning'; ErrorClass = 'held-guard'; FixKind = '' } }
        'PartlyFailed' { return @{ Outcome = 'warning'; ErrorClass = 'partly-failed'; FixKind = '' } }
    }
    $c = switch -Regex ("$Text") {
        '(?i)run limit'                                          { 'run-limit'; break }
        '(?i)\b(401|403)\b|forbidden|authoriz|insufficient privileges|access is denied|permission' { 'permission'; break }
        '(?i)\b429\b|throttl|too many requests'                  { 'throttled'; break }
        '(?i)\bsql\b|login failed|18456|deadlock|40613|40501'    { 'sql'; break }
        '(?i)time(d)? ?out'                                      { 'timeout'; break }
        '(?i)\b(500|502|503|504)\b|service unavailable|bad gateway' { 'upstream-error'; break }
        default                                                  { 'unclassified' }
    }
    @{ Outcome = 'failed'; ErrorClass = $c; FixKind = $(if ($c -eq 'permission') { 'customer-config' } else { '' }) }
}

function New-EpsUplinkRunRecord {
    # PURE. One finished eps.Run as a run record (job id eps-<job>; the counts; the reason redacted, only when not ok)
    param([Parameter(Mandatory)]$Run, [string]$Version, [string]$TenantId, [string]$Key, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = New-EpsUplinkEnvelope -Kind 'run' -Version $Version -TenantId $TenantId -NowUtc $NowUtc
    $o.Job = Get-EpsUplinkJobId "$($Run.Job)"
    $cls = Get-EpsUplinkErrorClass -Status "$($Run.Status)" -Text "$($Run.HeldReason)"
    $o.Outcome = Select-EpsUplinkEnum $cls.Outcome 'Outcome'
    if ($Run.StartedAtUtc -and $Run.EndedAtUtc -and $Run.EndedAtUtc -isnot [DBNull]) {
        $ms = [int64](([datetime]$Run.EndedAtUtc - [datetime]$Run.StartedAtUtc).TotalMilliseconds)
        if ($ms -ge 0) { $o.DurationMs = [int][math]::Min($ms, 2147483646) }
    }
    $o.ErrorClass = Select-EpsUplinkEnum $cls.ErrorClass 'ErrorClass'
    $o.FixKind = Select-EpsUplinkEnum $cls.FixKind 'FixKind'
    if ($o.Outcome -ne 'ok') { $o.ErrorText = ConvertTo-EpsUplinkRedacted -Text "$($Run.HeldReason)" -Key $Key -Max 2000 }
    $c = Limit-EpsUplinkCounts ([ordered]@{ objects = $Run.Objects; planned = $Run.Planned; overwrites = $Run.Overwrites; applied = $Run.Applied; failed = $Run.Failed; skipped = $Run.Skipped })
    if ($c.Count) { $o.Counts = $c }
    Select-EpsUplinkRecord $o
}

function Get-EpsUplinkRunPlan {
    <#
      PURE. The finished runs due, oldest first: a run counts when it ended after ITS job's watermark (-Watermarks
      @{ 'eps-<job>' = <datetime> }), else after -DefaultSinceUtc. One watermark PER JOB: a cycle cut short by the rate
      limit or a refusal sends some jobs' runs and not others' - nothing is skipped, nothing sent twice. The tick's
      successful runs (every 5 minutes) and the uplink job's own runs are not reported (the heartbeat says both).
    #>
    param([object[]]$Runs, [hashtable]$Watermarks = @{}, [Parameter(Mandatory)][datetime]$DefaultSinceUtc)
    @($Runs | Where-Object {
        $_ -and $_.EndedAtUtc -and $_.EndedAtUtc -isnot [DBNull] -and "$($_.Status)" -ne 'Running' -and "$($_.Job)" -ne 'Uplink' -and
        -not ("$($_.Job)" -eq 'Tick' -and "$($_.Status)" -eq 'Succeeded') -and
        ([datetime]$_.EndedAtUtc) -gt $(if ($Watermarks.ContainsKey((Get-EpsUplinkJobId "$($_.Job)"))) { [datetime]$Watermarks[(Get-EpsUplinkJobId "$($_.Job)")] } else { $DefaultSinceUtc })
    } | Sort-Object { [datetime]$_.EndedAtUtc })
}

# ---------------------------------------------------------------------------------------------------- alert records
function Get-EpsUplinkAlerts {
    <#
      The findings that are OPEN now, each as the §8.19 alert facts - numbers only, never a name or an id:
        eps.tamper.foreign-change (warning)  open tamper events            Measured events (+ high)
        eps.tamper.high (critical)           of them with a HIGH value     Measured events, high
        eps.ca.drift (warning)               adopted policies changed      Measured policies
        eps.ca.policy-deleted (warning)      adopted policies gone         Measured policies
        eps.ca.breakglass-exclusion-missing (critical) break glass not excluded  Measured policies
        eps.worker.silent (warning)          a worker that reported before, silent > 60 min   Measured minutesSilent
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [System.Collections.Generic.List[object]]::new()
    $t = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT COUNT(*) AS N, SUM(CASE WHEN Severity = 'High' THEN 1 ELSE 0 END) AS H, MIN(FoundAtUtc) AS F, MIN(CASE WHEN Severity = 'High' THEN FoundAtUtc END) AS FH FROM eps.TamperEvent WHERE Status = 'Open'")[0]
    $n = [int]$t.N; $h = if ($t.H -is [DBNull] -or $null -eq $t.H) { 0 } else { [int]$t.H }
    if ($n -gt 0) {
        $out.Add(@{ AlertId = 'eps.tamper.foreign-change'; Severity = 'warning'; Area = 'tamper'; Job = 'tampermonitor'; Measured = [ordered]@{ events = $n; high = $h }; FirstSeenUtc = $t.F; Page = 'tamper'
            ActionText = "$n change(s) to watched tag attributes were not made by EntraPolicySuite and are still open. Review them on the Tamper page: accept or restore each." })
    }
    if ($h -gt 0) {
        $out.Add(@{ AlertId = 'eps.tamper.high'; Severity = 'critical'; Area = 'tamper'; Job = 'tampermonitor'; Measured = [ordered]@{ events = $n; high = $h }; FirstSeenUtc = $t.FH; Page = 'tamper'
            ActionText = "$h open foreign change(s) set a high-severity tag value, which can change who Conditional Access applies to. Review them at once on the Tamper page." })
    }
    $text = @{
        Drift      = @('eps.ca.drift', 'warning', 'adopted Conditional Access policy(ies) changed in the tenant since they were adopted. Review the change on the Conditional Access page.')
        Missing    = @('eps.ca.policy-deleted', 'warning', 'adopted Conditional Access policy(ies) no longer exist in the tenant. Review on the Conditional Access page.')
        BreakGlass = @('eps.ca.breakglass-exclusion-missing', 'critical', 'Conditional Access policy(ies) do not exclude the break-glass accounts or group. Add the exclusion in the tenant.')
    }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Kind, COUNT(DISTINCT PolicyId) AS N, MIN(FirstSeenUtc) AS F FROM eps.CaFinding WHERE Status = 'Open' GROUP BY Kind")) {
        $x = $text["$($r.Kind)"]; if (-not $x -or [int]$r.N -lt 1) { continue }
        $out.Add(@{ AlertId = $x[0]; Severity = $x[1]; Area = 'ca'; Job = 'caanalyzer'; Measured = [ordered]@{ policies = [int]$r.N }; FirstSeenUtc = $r.F; Page = 'ca'; ActionText = "$([int]$r.N) $($x[2])" })
    }
    $seen = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query 'SELECT MAX(LastSeenUtc) FROM eps.WorkerHeartbeat'
    if ($seen -and $seen -isnot [DBNull]) {
        $mins = [int][math]::Floor(($NowUtc - [datetime]::SpecifyKind([datetime]$seen, 'Utc')).TotalMinutes)
        if ($mins -gt $script:EpsUplinkWorkerSilentMinutes) {
            $out.Add(@{ AlertId = 'eps.worker.silent'; Severity = 'warning'; Area = 'worker'; Job = 'tick'; Measured = [ordered]@{ minutesSilent = $mins }; FirstSeenUtc = ([datetime]$seen).AddMinutes($script:EpsUplinkWorkerSilentMinutes); Page = 'overview'
                ActionText = "The hybrid worker has not reported for $mins minutes. Changes for AD-synced users wait until it runs again; check the worker's scheduled task on its server." })
        }
    }
    @($out)
}

function New-EpsUplinkAlertRecord {
    # PURE. One alert (§8.19, the shape Invardia accepted 2026-11-01) - closed lists only, numbers only, the action text
    # redacted and at most 500 characters, the link https to the install's own page (left out when not known)
    param([Parameter(Mandatory)]$Alert, [int]$Count = 1, [string]$WebUrl, [string]$Version, [string]$TenantId, [string]$Key, [datetime]$NowUtc = [datetime]::UtcNow)
    $id = Select-EpsUplinkEnum $Alert.AlertId 'AlertId'; $sev = Select-EpsUplinkEnum $Alert.Severity 'Severity'
    if (-not $id -or -not $sev) { return $null }   # an id or severity outside the lists is never sent
    $o = New-EpsUplinkEnvelope -Kind 'alert' -Version $Version -TenantId $TenantId -NowUtc $NowUtc
    $o.AlertId = $id; $o.Severity = $sev
    $m = [ordered]@{}
    foreach ($k in @($Alert.Measured.Keys)) {
        if ($script:EpsUplinkLists.MeasuredKey -cnotcontains $k -or $m.Count -ge 10) { continue }
        $v = $Alert.Measured[$k]; if ($null -ne $v -and "$v" -match '^\d{1,9}$') { $m[$k] = [int64]$v }
    }
    if ($m.Count) { $o.Measured = $m }
    $o.FirstSeenUtc = ConvertTo-EpsUplinkIso $Alert.FirstSeenUtc
    $o.Count = [math]::Max(1, $Count)
    $o.Area = Select-EpsUplinkEnum $Alert.Area 'Area'
    $o.Job = Select-EpsUplinkEnum $Alert.Job 'AlertJob'
    $o.ActionText = ConvertTo-EpsUplinkRedacted -Text "$($Alert.ActionText)" -Key $Key -Max 500
    if ("$WebUrl" -match '^https://[A-Za-z0-9.-]+(:\d+)?/?$' -and "$($Alert.Page)" -match '^[a-z]{2,20}$') { $o.Link = "$("$WebUrl".TrimEnd('/'))/#$($Alert.Page)" }
    Select-EpsUplinkRecord $o
}

# ---------------------------------------------------------------------------------------------------- the send
function Send-EpsUplinkRecord {
    <#
      ONE POST of one record: https only, the key in X-Ait-Uplink-Code, never throws. @{ Ok (2xx); Status; Body (the
      parsed answer or $null); Reason (one plain line, the key never in it); Fields (what a refusal names) }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Record, [Parameter(Mandatory)][string]$Key, [string]$Endpoint = $script:EpsUplinkEndpoint)
    if ("$Endpoint" -notmatch '^https://') { return @{ Ok = $false; Status = 0; Body = $null; Reason = 'refused: the uplink endpoint must be https'; Fields = @() } }
    if (-not "$Key".Trim()) { return @{ Ok = $false; Status = 0; Body = $null; Reason = 'refused: no install key (there is no anonymous path)'; Fields = @() } }
    $max = if ($Record.Kind -eq 'heartbeat') { 48KB } else { 16KB }
    $json = $Record | ConvertTo-Json -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt $max) { return @{ Ok = $false; Status = 0; Body = $null; Reason = "refused: the $($Record.Kind) record is over $($max / 1KB) KB"; Fields = @() } }
    try {
        $r = & $script:EpsHttp 'POST' $Endpoint @{ 'X-Ait-Uplink-Code' = "$Key".Trim(); 'Content-Type' = 'application/json' } $json
    } catch { return @{ Ok = $false; Status = 0; Body = $null; Reason = "failed: $(ConvertTo-EpsUplinkRedacted -Text "$($_.Exception.Message)" -Key $Key -Max 200)"; Fields = @() } }
    $status = [int]$r.Status
    $body = $null; if ("$($r.Body)".Trim().StartsWith('{')) { $body = try { $r.Body | ConvertFrom-Json -Depth 10 } catch { $null } }
    if ($status -ge 200 -and $status -lt 300) { return @{ Ok = $true; Status = $status; Body = $body; Reason = "HTTP $status"; Fields = @() } }
    $fields = @(if ($body -and $body.fields) { @($body.fields) | ForEach-Object { ConvertTo-EpsUplinkRedacted -Text "$_" -Key $Key -Max 60 } | Where-Object { $_ } })
    @{ Ok = $false; Status = $status; Body = $body; Reason = "HTTP $status$(if ($fields) { " (fields: $($fields -join ', '))" })"; Fields = $fields }
}

function Get-EpsInvardiaEnvironment {
    <#
      NAM-02: Invardia is master of the environment name. GET https://<uplink host>/api/enrollments/environment with the
      same install-key header the uplink sends -> { environmentId, environmentName, kind, handle, tenantId, customer,
      managedBy, displayName }. Returns @{ Ok; Value (the fields EPS keeps, or $null); Reason }. Never throws; the key is
      never in Reason.
    #>
    param([Parameter(Mandatory)][string]$Key, [string]$Endpoint = $script:EpsUplinkEndpoint)
    if ("$Endpoint" -notmatch '^https://') { return @{ Ok = $false; Value = $null; Reason = 'refused: the uplink endpoint must be https' } }
    $url = "https://$(([uri]$Endpoint).Authority)/api/enrollments/environment"
    try { $r = & $script:EpsHttp 'GET' $url @{ 'X-Ait-Uplink-Code' = "$Key".Trim(); Accept = 'application/json' } $null }
    catch { return @{ Ok = $false; Value = $null; Reason = "failed: $(ConvertTo-EpsUplinkRedacted -Text "$($_.Exception.Message)" -Key $Key -Max 200)" } }
    $status = [int]$r.Status
    if ($status -lt 200 -or $status -ge 300) { return @{ Ok = $false; Value = $null; Reason = "HTTP $status" } }
    $b = try { "$($r.Body)" | ConvertFrom-Json } catch { $null }
    $name = if ($b) { ConvertTo-EpsUplinkRedacted -Text "$($b.displayName)" -Key $Key -Max 120 } else { '' }
    if (-not "$name".Trim()) { return @{ Ok = $false; Value = $null; Reason = "HTTP $status without a displayName" } }
    @{ Ok = $true; Reason = "HTTP $status"; Value = [ordered]@{ displayName = "$name".Trim(); environmentName = (ConvertTo-EpsUplinkRedacted -Text "$($b.environmentName)" -Key $Key -Max 120)
        handle = (ConvertTo-EpsUplinkRedacted -Text "$($b.handle)" -Key $Key -Max 80); kind = (ConvertTo-EpsUplinkRedacted -Text "$($b.kind)" -Key $Key -Max 40) } }
}

# ---------------------------------------------------------------------------------------------------- the support state
function ConvertFrom-EpsUplinkSupportAnswer {
    <#
      PURE. SECAUDIT-1a: the support state in the heartbeat ANSWER. Invardia's answer (apps/front/src/uplink.ts, 2026-11-01)
      carries `support: { state: 'open', level, maxUntil, reason, ticketNumber?, openedBy } | { state: 'closed' }` next to
      `environmentId`; the framework's event shape `{ environmentId, product, reason, ticketNumber?, openedBy, maxUntil }`
      is read too (as `supportEvents`, another product's skipped). Every value checked; maxUntil never more than 24 h
      ahead (Invardia's own ceiling). $null = the answer says nothing about support (keep what is recorded).
    #>
    param($Body, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Body) { return $null }
    try { if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return $null }; $Body = $Body | ConvertFrom-Json -Depth 10 } } catch { return $null }
    $plain = { param($v, $n) $s = "$v".Trim() -replace '[\u0000-\u001f\u007f<>]', ' '; if ($s.Length -gt $n) { $s = $s.Substring(0, $n) }; $s }
    $env = "$($Body.environmentId)".Trim().ToLowerInvariant(); if ($env -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $env = '' }
    $src = $Body.support
    if (-not $src -and $Body.supportEvents) {
        $mine = @(@($Body.supportEvents) | Where-Object { $_ -and (-not "$($_.product)" -or "$($_.product)".Trim().ToLowerInvariant() -eq $script:EpsUplinkProduct) })
        $src = @($mine | Sort-Object { if ($_.maxUntil -is [datetime]) { $_.maxUntil.ToUniversalTime().ToString('o') } else { "$($_.maxUntil)" } } -Descending)[0]
        if ($src -and -not $src.state) { $src | Add-Member -NotePropertyName state -NotePropertyValue 'open' -Force }
        if ($src -and -not $env -and "$($src.environmentId)" -match '^[0-9a-fA-F-]{36}$') { $env = "$($src.environmentId)".ToLowerInvariant() }
    }
    if (-not $src) { return $null }
    $state = "$($src.state)".Trim().ToLowerInvariant()
    if ($state -notin 'open', 'closed') { return $null }
    if ($state -eq 'closed') { return @{ State = 'closed'; EnvironmentId = $env; Level = ''; Reason = ''; TicketNumber = ''; OpenedBy = ''; MaxUntilUtc = $null } }
    # ConvertFrom-Json (PowerShell 7) already turns an ISO text into a [datetime] - take either, nothing else
    $mu = $null; $rawMu = $src.maxUntil
    if ($rawMu -is [datetime]) { $mu = if ($rawMu.Kind -eq 'Local') { $rawMu.ToUniversalTime() } else { [datetime]::SpecifyKind($rawMu, 'Utc') } }
    elseif ("$rawMu" -match '^\d{4}-\d{2}-\d{2}T') { try { $mu = [datetime]::Parse("$rawMu", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
    if (-not $mu) { return $null }   # an open without a valid maxUntil is not an open
    $ceil = $NowUtc.AddHours(24); if ($mu -gt $ceil) { $mu = $ceil }
    $lvl = "$($src.level)".Trim().ToLowerInvariant(); if ($lvl -notmatch '^[a-z][a-z0-9-]{1,49}$') { $lvl = '' }
    $tn = "$($src.ticketNumber)".Trim(); if ($tn -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,39}$') { $tn = '' }
    @{ State = 'open'; EnvironmentId = $env; Level = $lvl; Reason = (& $plain $src.reason 300); TicketNumber = $tn; OpenedBy = (& $plain $src.openedBy 200); MaxUntilUtc = [datetime]::SpecifyKind($mu, 'Utc') }
}

function Save-EpsSupportState {
    <#
      Records the support state (eps.SupportEvent): a change of state = a new row + an audit row (support.state.change);
      the same state again = only LastSeenUtc / MaxUntilUtc move. A 'closed' with nothing open before records nothing.
      NOTHING IS GRANTED here (TODO UPLINK-1: the just-in-time grant, an owner-proven step). Returns the plain line.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $last = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP (1) SupportEventId, State, AccessLevel, Reason, TicketNumber, OpenedBy, MaxUntilUtc FROM eps.SupportEvent ORDER BY SupportEventId DESC')[0]
    $same = $last -and "$($last.State)" -eq $State.State -and ($State.State -eq 'closed' -or ("$($last.TicketNumber)" -eq "$($State.TicketNumber)" -and "$($last.OpenedBy)" -eq "$($State.OpenedBy)" -and "$($last.AccessLevel)" -eq "$($State.Level)"))
    $nul = { param($s) if ("$s") { "$s" } else { $null } }
    if ($same) {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $last.SupportEventId; t = $NowUtc; m = $State.MaxUntilUtc } -Query 'UPDATE eps.SupportEvent SET LastSeenUtc = @t, MaxUntilUtc = @m WHERE SupportEventId = @id' | Out-Null
    } elseif ($State.State -eq 'closed' -and (-not $last -or "$($last.State)" -eq 'closed')) {
        return 'support: closed (nothing was open)'
    } else {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $NowUtc; s = $State.State; l = (& $nul $State.Level); r = (& $nul $State.Reason); n = (& $nul $State.TicketNumber); o = (& $nul $State.OpenedBy); m = $State.MaxUntilUtc; e = $(if ($State.EnvironmentId) { [guid]$State.EnvironmentId }) } `
            -Query 'INSERT INTO eps.SupportEvent (ReceivedAtUtc, LastSeenUtc, State, AccessLevel, Reason, TicketNumber, OpenedBy, MaxUntilUtc, EnvironmentId) VALUES (@t, @t, @s, @l, @r, @n, @o, @m, @e)' | Out-Null
        [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.state.change' -Actor 'Invardia (heartbeat answer)' -ActorSource 'job' -Target 'SupportEvent' `
            -Reason 'framework SECAUDIT-1a: recorded only - no access is granted from it yet' -Outcome 'ok' `
            -Before $(if ($last) { @{ state = "$($last.State)"; ticket = "$($last.TicketNumber)" } }) -After @{ state = $State.State; level = $State.Level; ticket = $State.TicketNumber; openedBy = $State.OpenedBy; maxUntilUtc = (ConvertTo-EpsUplinkIso $State.MaxUntilUtc) })
    }
    if ($State.State -eq 'open') { "support: OPEN until $(ConvertTo-EpsUplinkIso $State.MaxUntilUtc)$(if ($State.TicketNumber) { " (ticket $($State.TicketNumber))" })$(if ($State.Level) { ", level $($State.Level)" }) - recorded only, nothing granted" }
    else { 'support: closed - recorded' }
}

# ---------------------------------------------------------------------------------------------------- state
function Get-EpsUplinkState {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $h = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Value FROM eps.UplinkState')) { if ($r.Value -isnot [DBNull]) { $h["$($r.Name)"] = "$($r.Value)" } }
    $h
}
function Set-EpsUplinkState {
    # $Value untyped on purpose: a [string] parameter turns $null into '' - $null clears the row's value (NULL)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [AllowNull()]$Value)
    if ($null -ne $Value) { $Value = "$Value"; if ($Value.Length -gt 4000) { $Value = $Value.Substring(0, 4000) } }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $Name; v = $Value } `
        -Query 'MERGE eps.UplinkState AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (@n, @v);' | Out-Null
}
function ConvertFrom-EpsUplinkTime { param([string]$Text) try { [datetime]::Parse($Text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } }

# ---------------------------------------------------------------------------------------------------- the cycle
function Invoke-EpsUplinkCycle {
    <#
    .SYNOPSIS
        One uplink cycle (the Uplink job). Returns @{ Mode ('disabled' | 'identified'); Posts; Heartbeat; Runs; Alerts;
        Support; Stopped; Lines }. Never throws. -Log { param($level, $msg) } gets every line.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version, [string]$TenantId = $env:EPS_TENANT_ID, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$PauseMs = $script:EpsUplinkPauseMs, [string]$WebUrl = $env:EPS_WEB_URL, [string]$Endpoint = $script:EpsUplinkEndpoint, [scriptblock]$Log = { param($l, $m) })
    $res = @{ Mode = 'disabled'; Posts = 0; Heartbeat = ''; Environment = ''; Runs = 0; Alerts = 0; Support = ''; Stopped = ''; Lines = [System.Collections.Generic.List[string]]::new() }
    $say = { param($l, $m) $res.Lines.Add($m); & $Log $l $m }
    $finish = { param($line) try { Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'last' -Value "$(ConvertTo-EpsUplinkIso $NowUtc) $line" } catch { }; $res }
    try {
        if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Uplink.Enabled' -Default 'true')" -ne 'true') { & $say 'Info' 'uplink: switched off (Uplink.Enabled) - nothing sent'; return (& $finish 'disabled: switched off (Uplink.Enabled)') }
        $k = Get-EpsUplinkKey
        if (-not $k.Key) { & $say 'Info' "uplink: disabled - $($k.Reason); nothing sent (identified only, never anonymous)"; return (& $finish "disabled: $($k.Reason)") }
        $key = $k.Key; $res.Mode = 'identified'
        $host_ = ([uri]$Endpoint).Host
        $st = Get-EpsUplinkState -ConnectionString $ConnectionString
        $post = {
            param([System.Collections.IDictionary]$rec)
            if ($res.Posts -ge $script:EpsUplinkMaxPosts) { return @{ Ok = $false; Status = 0; Reason = 'budget'; Budget = $true } }
            if ($res.Posts -gt 0) { & $script:EpsUplinkSleep $PauseMs }
            $res.Posts++
            Send-EpsUplinkRecord -Record $rec -Key $key -Endpoint $Endpoint
        }
        $fail = { param($what, $r) $res.Stopped = "$what $($r.Reason)"; & $say 'Warning' "uplink: $what to $host_ (identified) failed: $($r.Reason) - the cycle stops; the rest goes next cycle" }

        # 1. the heartbeat (every 4 h; an interval is sent only on a 2xx)
        $lastHb = if ($st.heartbeat) { ConvertFrom-EpsUplinkTime $st.heartbeat }
        if (-not $lastHb -or ($NowUtc - $lastHb).TotalMinutes -ge ($script:EpsUplinkHeartbeatHours * 60 - 10)) {
            $facts = Get-EpsUplinkHeartbeatFacts -ConnectionString $ConnectionString -Version $Version
            $r = & $post (New-EpsUplinkHeartbeat -Facts $facts -Version $Version -TenantId $TenantId -NowUtc $NowUtc)
            if (-not $r.Ok -and $r.Status -in 400, 413, 422) {
                & $say 'Warning' "uplink: heartbeat refused ($($r.Reason)) - sent once more without the newer fields (§8.17)"
                $r = & $post (New-EpsUplinkHeartbeat -Facts $facts -Version $Version -TenantId $TenantId -NowUtc $NowUtc -WithoutNewFields)
                if ($r.Ok) { $res.Heartbeat = 'ok (without the newer fields)' }
            } elseif ($r.Ok) { $res.Heartbeat = 'ok' }
            if (-not $r.Ok) { $res.Heartbeat = 'failed'; & $fail 'heartbeat' $r; return (& $finish "identified: heartbeat FAILED ($($r.Reason))") }
            Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'heartbeat' -Value (ConvertTo-EpsUplinkIso $NowUtc)
            & $say 'Info' "uplink: heartbeat sent ($($res.Heartbeat))"
            $sup = ConvertFrom-EpsUplinkSupportAnswer -Body $r.Body -NowUtc $NowUtc
            if ($sup) { try { $res.Support = Save-EpsSupportState -ConnectionString $ConnectionString -State $sup -NowUtc $NowUtc; & $say 'Info' $res.Support } catch { & $say 'Warning' "uplink: the support state could not be recorded: $($_.Exception.Message)" } }
            # NAM-02: Invardia's environment name, read with each heartbeat; only a good answer replaces the kept one
            # (offline / refused = the last good name stays). Not a POST: outside the POST budget.
            $envr = Get-EpsInvardiaEnvironment -Key $key -Endpoint $Endpoint
            if ($envr.Ok) {
                $v = $envr.Value; $v.at = ConvertTo-EpsUplinkIso $NowUtc
                Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'environment' -Value ($v | ConvertTo-Json -Compress)
                $res.Environment = $v.displayName; & $say 'Info' "uplink: environment name from Invardia: $($v.displayName)"
            } else { & $say 'Info' "uplink: environment name not read ($($envr.Reason)) - the last one kept" }
        } else { $res.Heartbeat = 'not due'; & $say 'Info' "uplink: heartbeat not due (last $(ConvertTo-EpsUplinkIso $lastHb))" }

        # 2. the alerts (§8.19) - OFF by default: Invardia does not take the kind yet
        if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Uplink.Alerts.Enabled' -Default 'false')" -eq 'true') {
            $open = @(Get-EpsUplinkAlerts -ConnectionString $ConnectionString -NowUtc $NowUtc)
            $openIds = @($open | ForEach-Object { $_.AlertId })
            foreach ($name in @($st.Keys | Where-Object { $_ -like 'alert:*' })) { if ($openIds -notcontains $name.Substring(6)) { Set-EpsUplinkState -ConnectionString $ConnectionString -Name $name -Value $null } }   # closed: a new episode alerts at once
            $sentNow = 0
            foreach ($a in $open) {
                $ep = if ($st["alert:$($a.AlertId)"]) { try { $st["alert:$($a.AlertId)"] | ConvertFrom-Json } catch { $null } }
                $seen = if ($ep) { [int]$ep.seen + 1 } else { 1 }
                $lastSent = if ($ep) { ConvertFrom-EpsUplinkTime "$($ep.sentUtc)" }
                if ($lastSent -and ($NowUtc - $lastSent).TotalHours -lt $script:EpsUplinkAlertRepeatHours) {
                    Set-EpsUplinkState -ConnectionString $ConnectionString -Name "alert:$($a.AlertId)" -Value (@{ sentUtc = $ep.sentUtc; seen = $seen } | ConvertTo-Json -Compress); continue
                }
                if ($sentNow -ge $script:EpsUplinkAlertMax) { break }
                $rec = New-EpsUplinkAlertRecord -Alert $a -Count $seen -WebUrl $WebUrl -Version $Version -TenantId $TenantId -Key $key -NowUtc $NowUtc
                if (-not $rec) { continue }
                $r = & $post $rec
                if (-not $r.Ok) { if ($r.Budget) { $res.Stopped = 'budget' } else { & $fail "alert $($a.AlertId)" $r }; return (& $finish "identified: heartbeat $($res.Heartbeat), $($res.Alerts) alert(s), stopped ($($res.Stopped))") }
                Set-EpsUplinkState -ConnectionString $ConnectionString -Name "alert:$($a.AlertId)" -Value (@{ sentUtc = (ConvertTo-EpsUplinkIso $NowUtc); seen = 0 } | ConvertTo-Json -Compress)
                $sentNow++; $res.Alerts++
            }
            if ($res.Alerts) { & $say 'Info' "uplink: $($res.Alerts) alert record(s) sent" }
        }

        # 3. the run records, one watermark per job
        $wm = @{}; foreach ($name in @($st.Keys | Where-Object { $_ -like 'watermark:*' })) { $t = ConvertFrom-EpsUplinkTime $st[$name]; if ($t) { $wm[$name.Substring(10)] = $t } }
        $default = $NowUtc.AddHours(-$script:EpsUplinkFirstRunsHours)
        $since = @(@($wm.Values) + $default | Sort-Object)[0]
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ s = $since } -Query "SELECT TOP (500) RunId, Job, Status, StartedAtUtc, EndedAtUtc, HeldReason, Objects, Planned, Overwrites, Applied, Failed, Skipped FROM eps.Run WHERE EndedAtUtc IS NOT NULL AND EndedAtUtc > @s AND Status <> 'Running' ORDER BY EndedAtUtc")
        foreach ($run in (Get-EpsUplinkRunPlan -Runs $rows -Watermarks $wm -DefaultSinceUtc $default)) {
            $r = & $post (New-EpsUplinkRunRecord -Run $run -Version $Version -TenantId $TenantId -Key $key -NowUtc $NowUtc)
            if (-not $r.Ok) {
                if ($r.Budget) { $res.Stopped = 'budget'; & $say 'Info' "uplink: $($script:EpsUplinkMaxPosts) POSTs this cycle - the rest of the runs go next cycle" } else { & $fail "run record $(Get-EpsUplinkJobId $run.Job)" $r }
                break
            }
            Set-EpsUplinkState -ConnectionString $ConnectionString -Name "watermark:$(Get-EpsUplinkJobId $run.Job)" -Value ([datetime]::SpecifyKind([datetime]$run.EndedAtUtc, 'Utc').ToString('o', [Globalization.CultureInfo]::InvariantCulture))
            $res.Runs++
        }
        if ($res.Runs) { & $say 'Info' "uplink: $($res.Runs) run record(s) sent" }
        & $finish "identified: heartbeat $($res.Heartbeat), $($res.Alerts) alert(s), $($res.Runs) run(s)$(if ($res.Stopped) { ", stopped ($($res.Stopped))" })"
    } catch {
        $res.Stopped = 'error'
        & $say 'Warning' "uplink: the cycle failed: $(ConvertTo-EpsUplinkRedacted -Text "$($_.Exception.Message)" -Key $key -Max 300)"
        & $finish 'error: the cycle failed - see the job log'
    }
}
