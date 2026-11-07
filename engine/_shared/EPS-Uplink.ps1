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
#     2. the alert records (Kind 'alert', §8.19) behind Uplink.Alerts.Enabled (default ON since 2.0.51: Invardia takes all six EPS alert ids,
#        2026-11-04 - OPEN-17) - one per AlertId per 24 h while open, at most 10 per cycle;
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
# framework §8.4 "The contract for every product" (Invardia 2026-11-05, UPLINK-BACKLOG): ~20 POSTs is a RATE guard (30 / min
# per client IP, shared behind a NAT), not a cap - rounds of 20, 2.5 s apart, >= 65 s between rounds, up to 5 rounds (100)
# per cycle, stopping at the first non-ok answer. One round per cycle left internal's run records ~43 h behind.
$script:EpsUplinkRoundPosts = 20
$script:EpsUplinkMaxRounds  = 5
$script:EpsUplinkRoundWaitMs = 65000
$script:EpsUplinkMaxPosts   = $script:EpsUplinkRoundPosts * $script:EpsUplinkMaxRounds
# §8.4 (4) UplinkBacklog on the heartbeat: ON since 2.0.80 - Invardia 2026-11-05 ~11:10Z: "DEPLOYED (f0f2403b, deploy
# 42014508678 success). Switch it on in your next release" (2.0.79 built it OFF until then)
$script:EpsUplinkSendBacklog = $true
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
    ErrorClass      = @('held-guard', 'partly-failed', 'queue-start-timeout', 'run-limit', 'permission', 'throttled', 'sql', 'timeout', 'upstream-error', 'unclassified')
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
    heartbeat = $script:EpsUplinkEnvelope + @('Ring', 'Outcome', 'Counts', 'EnvironmentName', 'Jobs', 'Update', 'Mail', 'SignIn', 'Database', 'SetupSteps', 'Endpoints', 'Pipeline', 'SupportAccess', 'BuildPool', 'UplinkBacklog', 'LicenceState', 'LicenceId')
    run      = $script:EpsUplinkEnvelope + @('Job', 'Outcome', 'DurationMs', 'ErrorClass', 'FixKind', 'ErrorText', 'Counts')
    # an alert carries Invardia's ALERT_FIELDS only (packages/core/src/uplinkalert.ts): NOT Hosting / RuntimeIdentity - a record with
    # them was refused 422 (internal, 2026-11-03 06:51, eps.tamper.foreign-change) and retried every run
    alert     = @($script:EpsUplinkEnvelope | Where-Object { $_ -notin 'Hosting', 'RuntimeIdentity' }) + @('AlertId', 'Severity', 'Measured', 'FirstSeenUtc', 'Count', 'Area', 'Job', 'ActionText', 'Link')
}
# the heartbeat fields newer than the liveness record (§8.17): left out on the one resend after a 4xx refusal
$script:EpsUplinkNewHeartbeatFields = @('EnvironmentName', 'Jobs', 'Update', 'Mail', 'SignIn', 'Database', 'SetupSteps', 'Endpoints', 'Pipeline', 'SupportAccess', 'BuildPool', 'UplinkBacklog', 'LicenceState', 'LicenceId')

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
    # PURE. 'UserTagging' -> 'eps-usertagging' (stable, lower-case, the server's id shape). The scheduler ('Tick') reports
    # as eps-engine - the role word of framework §5.5 (Invardia 2026-11-07, SUP-2026-00438: "tick" is a word the owner
    # rejected; these labels reach his tickets). Azure job names at old installs are not touched.
    param([Parameter(Mandatory)][string]$Job)
    $s = ($Job.Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if ($s -eq 'tick') { $s = 'engine' }
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
    param([Parameter(Mandatory)][string]$Kind, [string]$Version, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Ring = $env:EPS_RING)
    $o = [ordered]@{ Schema = 2; Kind = (Select-EpsUplinkEnum $Kind 'Kind'); Product = $script:EpsUplinkProduct }
    if ("$Version" -match '^[0-9A-Za-z.+-]{1,50}$') { $o.Version = "$Version" }
    # TEL-01 (framework §8.4 / §8.17): the update ring as an INTEGER 0-10 - left out when the install has none (never null
    # or text: Invardia refuses the whole report). Only the heartbeat carries it (Select-EpsUplinkRecord drops it elsewhere).
    if ("$Ring".Trim() -match '^([0-9]|10)$') { $o.Ring = [int]"$Ring".Trim() }
    # INSTALL-PRO (2.0.86): the edition from the VERIFIED licence (Get-EpsLicenceUplinkFields, read once per cycle) -
    # community without one; the heartbeat also carries LicenceState + LicenceId (Select-EpsUplinkRecord keeps them there only)
    $lf = $script:EpsUplinkLicenceFields
    $o.Edition = if ($lf -and $lf.Edition) { Select-EpsUplinkEnum $lf.Edition 'Edition' } else { 'community' }
    $o.Hosting = 'container'
    $o.RuntimeIdentity = 'mi-container'
    if ("$TenantId" -match '^[0-9a-fA-F-]{36}$') { $o.ClaimedTenantId = "$TenantId".ToLowerInvariant() }
    $o.LastSeenUtc = ConvertTo-EpsUplinkIso $NowUtc
    if ($lf -and $lf.LicenceState) { $o.LicenceState = "$($lf.LicenceState)" }
    if ($lf -and $lf.LicenceId) { $o.LicenceId = "$($lf.LicenceId)" }
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
        # PSBase.Count = the number of entries: a plain .Count reads a KEY named 'count' first (BuildPool { count: 0 } was
        # taken for an empty dictionary and dropped - found by Test-EpsUplink 2026-11-05)
        if ($null -eq $v -or ($v -is [string] -and -not $v) -or ($v -is [System.Collections.IDictionary] -and -not $v.PSBase.Count)) { continue }
        $o[$k] = $v
    }
    $o
}

# ---------------------------------------------------------------------------------------------------- the heartbeat
function ConvertFrom-EpsUplinkBuildPool {
    <#
      PURE. The stored build-pool fact (eps.UplinkState 'buildpool', JSON) -> [ordered]@{ tier; count; building; checkedUtc }
      exactly, or $null (empty / not JSON / not this shape = the field is left out). Read with System.Text.Json, which keeps
      the time as the text it is (ConvertFrom-Json would turn it into a DateTime).
    #>
    param([AllowEmptyString()][string]$Text)
    if (-not "$Text".Trim()) { return $null }
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse("$Text")
        try {
            $r = $doc.RootElement
            $tier = $r.GetProperty('tier').GetString(); $count = $r.GetProperty('count').GetInt32()
            $building = $r.GetProperty('building').GetBoolean(); $at = $r.GetProperty('checkedUtc').GetString()
        } finally { $doc.Dispose() }
        if ("$tier" -notmatch '^[A-Za-z0-9]{1,10}$' -or $count -lt 0 -or $count -gt 100 -or "$at" -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { return $null }
        return [ordered]@{ tier = "$tier"; count = [int]$count; building = [bool]$building; checkedUtc = "$at" }
    } catch { return $null }
}

function ConvertTo-EpsUplinkUpdateWaited {
    <#
      PURE. The update run's give-up line ("update to 2.0.74 waited 45 min for running jobs (UserTagging, ...), retries next
      night") + when that run ended -> [ordered]@{ version; atUtc; minutes; job } (job = the FIRST job it waited for, as a
      slug: a-z 0-9 -, at most 60, 'eps-' + the job, e.g. eps-usertagging / eps-tamper). Anything else -> $null (left out).
    #>
    param([AllowEmptyString()][string]$Text, $AtUtc)
    $m = [regex]::Match("$Text", 'update to ([0-9A-Za-z.+-]{1,50}) waited (\d{1,4}) min for running jobs \(([^)]*?)(?:\)|$)')
    if (-not $m.Success -or $null -eq $AtUtc -or $AtUtc -is [DBNull]) { return $null }
    $first = ("$($m.Groups[3].Value)" -split ',')[0].Trim() -replace '\s*\(.*$', ''
    $slug = ($first.ToLowerInvariant() -replace '^caj-', '' -replace '[^a-z0-9-]', '-' -replace '-{2,}', '-').Trim('-')
    if (-not $slug) { return $null }
    if ($slug -notlike 'eps-*') { $slug = "eps-$slug" }
    if ($slug.Length -gt 60) { $slug = $slug.Substring(0, 60).TrimEnd('-') }
    $at = ([datetime]$AtUtc); if ($at.Kind -ne 'Utc') { $at = [datetime]::SpecifyKind($at, 'Utc') }
    [ordered]@{ version = $m.Groups[1].Value; atUtc = $at.ToString('yyyy-MM-ddTHH:mm:ssZ'); minutes = [int]$m.Groups[2].Value; job = $slug }
}

function New-EpsUplinkHeartbeat {
    <#
      PURE. The heartbeat from the facts Get-EpsUplinkHeartbeatFacts read. -WithoutNewFields: the liveness record only
      (envelope, Outcome, Counts) - the one resend after a 4xx refusal (§8.17).
      Facts: @{ Counts; EnvironmentName; Jobs = @(@{ Job; LastStart; LastEnd; Status; DurationMin; PrevDurationMin; TimeoutHours });
               Update = @{ Installed }; Mail = @{ Mode; LastSentUtc }; SignIn = @{ Layer; Version }; Database = @{ Tier } }
    #>
    param([Parameter(Mandatory)]$Facts, [string]$Version, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WithoutNewFields, [string[]]$Drop = @())
    $o = New-EpsUplinkEnvelope -Kind 'heartbeat' -Version $Version -TenantId $TenantId -NowUtc $NowUtc
    if ($WithoutNewFields) { $o.Remove('Ring') }   # the liveness-only resend carries the oldest field set
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
        if ("$($Facts.Update.Installed)" -match '^[0-9A-Za-z.+-]{1,50}$') {
            $o.Update = [ordered]@{ installed = "$($Facts.Update.Installed)" }
            # UPD-HOLD: the last update gave up waiting for running jobs (< 26 h) -> waited { version, atUtc, minutes, job } -
            # STRUCTURED (Invardia's contract takes no free text; Invardia writes the sentence). Else left out.
            $wv = ConvertTo-EpsUplinkUpdateWaited -Text "$($Facts.Update.Waited.Text)" -AtUtc $Facts.Update.Waited.AtUtc
            if ($wv) { $o.Update.waited = $wv }
        }
        if ($Facts.Mail) {
            # mailJob + restriction are required by the contract; the heartbeat reports only what the job itself has
            # read at run time, so restriction is the contract's 'not-verified' value - never a guess of 'verified'
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
        # OPEN-01 auto-check #4 (Invardia 2026-11-05): what the support-access job APPLIED and read back - level none |
        # read | troubleshoot; adminUntil = the end of the open session it gave admin for (null = no admin now; the job
        # never gives more than 8 h); readUser = the read user exists (read back); checkedUtc = its last run. Left out when
        # the job never ran (no row) - never a guessed value.
        $sa = $Facts.SupportAccess
        if ($sa -and "$($sa.Level)" -in 'none', 'read', 'troubleshoot') {
            $au = if ($sa.AdminNow -eq $true) { ConvertTo-EpsUplinkIso $sa.SessionUntil } else { $null }
            $x = [ordered]@{ level = "$($sa.Level)"; adminUntil = $au; readUser = ($sa.ReadUser -eq $true) }
            $ck = ConvertTo-EpsUplinkIso $sa.CheckedAtUtc; if ($ck) { $x.checkedUtc = $ck }
            $o.SupportAccess = $x
        }
        # framework rule 11g (5): BuildPool { tier, count, building, checkedUtc } as the update job last READ it (stored in
        # eps.UplinkState 'buildpool'). No pool / never read / not this shape = LEFT OUT (absent = "no pool, shared builders")
        $bpx = ConvertFrom-EpsUplinkBuildPool -Text "$($Facts.BuildPool)"
        if ($bpx) { $o.BuildPool = $bpx }
        # framework §8.4 (4) (Invardia 2026-11-05): UplinkBacklog { pending, oldestUtc, checkedUtc } - the run records not
        # sent yet as checked before this cycle sends; caught up = 0 and null. Left out only when it could not be read.
        $bl = $Facts.UplinkBacklog
        if ($bl -and $null -ne $bl.Pending -and [int]$bl.Pending -ge 0 -and (ConvertTo-EpsUplinkIso $bl.CheckedUtc)) {
            $o.UplinkBacklog = [ordered]@{ pending = [int]$bl.Pending; oldestUtc = $(if ([int]$bl.Pending -gt 0) { ConvertTo-EpsUplinkIso $bl.OldestUtc } else { $null }); checkedUtc = (ConvertTo-EpsUplinkIso $bl.CheckedUtc) }
        }        # FLEET-STEPS: each one-time step of this install with its state from a real check (at most 40, closed lists)
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
            # OPEN-13 (framework §8.8, Invardia's Pipeline contract): state 'running' (Invardia reads a Pipeline only then),
            # the run's start, the job as its step; longRun.newerWaiting is a VERSION or left out (EPS's updater applies
            # nothing yet, so it is left out), longRun.at = when this was judged
            $l = [ordered]@{ usualMin = [double]$lr.usualMin; ageMin = [double]$lr.ageMin; ratio = [Math]::Round([double]$lr.ratio, 2); state = $st
                             action = $(if ($a = Select-EpsUplinkEnum "$($lr.action)" 'LongRunAction') { $a } else { 'none' }) }
            if ("$($lr.newerWaiting)" -match '^\d+\.\d+\.\d+$') { $l.newerWaiting = "$($lr.newerWaiting)" }
            $l.at = ConvertTo-EpsUplinkIso $(if ($lr.at) { $lr.at } else { $NowUtc })
            $p = [ordered]@{ state = 'running'; step = (Get-EpsUplinkJobId "$($lr.job)") }
            $su = if ($lr.startedUtc) { ConvertTo-EpsUplinkIso $lr.startedUtc }
            if ($su) { $p.startedUtc = $su; $p.stepSinceUtc = $su }
            $p.longRun = $l
            $o.Pipeline = $p
        }
    }
    # a field Invardia named in its refusal (422 { fields }) is left out of the one resend - the rest still goes
    foreach ($d in @($Drop)) { if ("$d" -and $o.Contains("$d")) { $o.Remove("$d") } }
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
            if (-not $best -or $ratio -gt $best.ratio) { $best = @{ job = [string]$r.Job; startedUtc = [datetime]::SpecifyKind([datetime]$r.StartedAtUtc, 'Utc'); usualMin = [Math]::Round($usual, 1); ageMin = $age; ratio = $ratio; state = $(if ($ratio -ge 4) { 'stuck' } elseif ($ratio -ge 2) { 'long' } else { 'ok' }); newerWaiting = $false; action = 'none'; at = $NowUtc } }
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

function Get-EpsUplinkSignIn {
    # OPEN-15 (§12.11g): the running web app through ARM (Get-EpsUplinkSignInLayer) when the engine may read it; else the
    # front version the install read back from the running app at its last deploy (eps.UplinkState 'signin.front').
    # -Query: { param($sql) <scalar> }. $null when neither is known (the field is left out, never guessed).
    param([scriptblock]$Query)
    $si = Get-EpsUplinkSignInLayer
    if ($si -or -not $Query) { return $si }
    $fv = try { & $Query "SELECT Value FROM eps.UplinkState WHERE Name = N'signin.front'" } catch { $null }
    if ("$fv" -match '^[0-9A-Za-z.+]{1,50}$') { return @{ Layer = 'signin-front'; Version = "$fv" } }
    $null
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
        # UPD-HOLD: the last update run's give-up line ("... waited 45 min for running jobs ..., retries next night"), only
        # while it is the LATEST update run and under 26 h old - so it shows in Invardia's fleet view, never fails silently
        Update = @{ Installed = $Version; Waited = $(try { @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT TOP (1) CASE WHEN HeldReason LIKE N'%waited % min for running jobs%' AND StartedAtUtc > DATEADD(HOUR, -26, SYSUTCDATETIME()) THEN HeldReason END AS Text, EndedAtUtc AS AtUtc FROM eps.Run WHERE Job = N'Update' AND Status <> N'Running' ORDER BY StartedAtUtc DESC")[0] } catch { $null }) }
        Mail = $(if ($null -ne $mailMode) { @{ Mode = $mailMode; LastSentUtc = $(if ($lastMail -isnot [DBNull]) { $lastMail }) } })
        # OPEN-15: the running web app through ARM when the engine may read it; else what the install read back from the
        # running app at its last deploy (eps.UplinkState signin.front) - the engine holds no Azure right by default
        SignIn = (Get-EpsUplinkSignIn -Query $q)
        BuildPool = $(try { "$(& $q "SELECT Value FROM eps.UplinkState WHERE Name = N'buildpool'")" } catch { '' })   # rule 11g (5): as the update job last read it
        SupportAccess = $(try { @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Level, SessionUntil, ReadUser, AdminNow, CheckedAtUtc FROM eps.SupportAccess WHERE Id = 1')[0] } catch { $null })   # OPEN-01 #4: what caj-eps-support applied (read only)
        Database = @{ Tier = "$(& $q "SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective') AS NVARCHAR(40))")" }
        Endpoints = $(if ("$env:EPS_WEB_URL" -match '^https://') { $u = "$env:EPS_WEB_URL".TrimEnd('/'); @(@{ kind = 'webapp'; url = $u }, @{ kind = 'api'; url = "$u/api" }) })
        LongRun = (Get-EpsUplinkLongRun -ConnectionString $ConnectionString)
        # FLEET-STEPS: the engine's rights read back now (its own app role assignments), never a remembered value
        # OPEN-09: whether the Exchange role is needed at all, from the features that are on
        SetupSteps = $(if (Get-Command Get-EpsSetupSteps -ErrorAction SilentlyContinue) { try {
            $xn = if (Get-Command Get-EpsExchangeNeed -ErrorAction SilentlyContinue) { try { Get-EpsExchangeNeed -Row @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $script:EpsExchangeNeedSql)[0] } catch { $null } }
            # TEL-03 (SEC-08 / UPDATER-1): the database setup job's last record (it writes setup.dbjob) and what the last
            # update run said about its updater identity - both real records, never a remembered value
            $dbj = try { "$(& $q "SELECT Value FROM eps.UplinkState WHERE Name = N'setup.dbjob'")" } catch { $null }
            $upd = try { "$(& $q "SELECT TOP (1) HeldReason FROM eps.Run WHERE Job = N'Update' AND HeldReason IS NOT NULL ORDER BY StartedAtUtc DESC")" } catch { $null }
            @(Get-EpsSetupSteps -Rights (Get-EpsEngineRightsState) -MailMode $mailMode -ExchangeNeed $xn -DbJob $dbj -UpdateRun $upd) } catch { @() } })
    }
}

# ---------------------------------------------------------------------------------------------------- run records
function Get-EpsUplinkErrorClass {
    # PURE. eps.Run -> @{ Outcome; ErrorClass; FixKind } (closed lists). A held run is a warning (the guard did its job).
    param([string]$Status, [string]$Text, [string]$Job)
    switch ($Status) {
        'Succeeded'    { return @{ Outcome = 'ok'; ErrorClass = ''; FixKind = '' } }
        'Held'         { return @{ Outcome = 'warning'; ErrorClass = 'held-guard'; FixKind = '' } }
        'PartlyFailed' {
            # SUP-2026-00438 (Invardia 2026-11-07): a tick whose ONLY failures are job starts through the queue that timed
            # out = queue-start-timeout (a transient: the next tick starts the job); anything else stays partly-failed
            $parts = @("$Text" -split ';\s*' | Where-Object { "$_".Trim() })
            $qto = '^[A-Za-z][^:]{0,80}: queue eps-[a-z0-9-]{1,60}: .*(?i:time(d)? ?out)'
            $c = if ($Job -eq 'Tick' -and $parts.Count -and -not @($parts | Where-Object { $_.Trim() -notmatch $qto }).Count) { 'queue-start-timeout' } else { 'partly-failed' }
            return @{ Outcome = 'warning'; ErrorClass = $c; FixKind = '' }
        }
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
    $cls = Get-EpsUplinkErrorClass -Status "$($Run.Status)" -Text "$($Run.HeldReason)" -Job "$($Run.Job)"
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
    $due = @($Runs | Where-Object {
        $_ -and $_.EndedAtUtc -and $_.EndedAtUtc -isnot [DBNull] -and "$($_.Status)" -ne 'Running' -and "$($_.Job)" -ne 'Uplink' -and
        -not ("$($_.Job)" -eq 'Tick' -and "$($_.Status)" -eq 'Succeeded') -and
        ([datetime]$_.EndedAtUtc) -gt $(if ($Watermarks.ContainsKey((Get-EpsUplinkJobId "$($_.Job)"))) { [datetime]$Watermarks[(Get-EpsUplinkJobId "$($_.Job)")] } else { $DefaultSinceUtc })
    } | Sort-Object { [datetime]$_.EndedAtUtc })
    # framework §8.4 (Invardia 2026-11-05): a job that holds an Update run or a run that did not succeed goes FIRST -
    # that job's runs oldest-first from its own watermark (never the newest first: the watermark would pass runs not sent
    # yet); then every other job's runs, oldest-first as before
    $first = @($due | Where-Object { "$($_.Job)" -eq 'Update' -or "$($_.Status)" -ne 'Succeeded' } | ForEach-Object { Get-EpsUplinkJobId "$($_.Job)" } | Select-Object -Unique)
    @(@($due | Where-Object { $first -contains (Get-EpsUplinkJobId "$($_.Job)") } | Sort-Object { [array]::IndexOf($first, (Get-EpsUplinkJobId "$($_.Job)")) }, { [datetime]$_.EndedAtUtc }) +
      @($due | Where-Object { $first -notcontains (Get-EpsUplinkJobId "$($_.Job)") }))
}
function Get-EpsUplinkDueRuns {
    # the finished runs not reported yet (per job from its watermark in -State; a job without one: the last 24 h), in the
    # order they go (Get-EpsUplinkRunPlan). -Top bounds the read.
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$State = @{}, [datetime]$NowUtc = [datetime]::UtcNow, [int]$Top = 500)
    $wm = @{}; foreach ($name in @($State.Keys | Where-Object { $_ -like 'watermark:*' })) { $t = ConvertFrom-EpsUplinkTime $State[$name]; if ($t) { $wm[$name.Substring(10)] = $t } }
    # 2.0.93: the scheduler's runs were eps-tick, now eps-engine - the old watermark carries on (nothing sent twice)
    if (-not $wm.ContainsKey('eps-engine') -and $wm.ContainsKey('eps-tick')) { $wm['eps-engine'] = $wm['eps-tick'] }
    $default = $NowUtc.AddHours(-$script:EpsUplinkFirstRunsHours)
    $since = @(@($wm.Values) + $default | Sort-Object)[0]
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ s = $since } -Query "SELECT TOP ($([int]$Top)) RunId, Job, Status, StartedAtUtc, EndedAtUtc, HeldReason, Objects, Planned, Overwrites, Applied, Failed, Skipped FROM eps.Run WHERE EndedAtUtc IS NOT NULL AND EndedAtUtc > @s AND Status <> 'Running' ORDER BY EndedAtUtc")
    @(Get-EpsUplinkRunPlan -Runs $rows -Watermarks $wm -DefaultSinceUtc $default)
}
function Get-EpsUplinkBacklog {
    # §8.4 (4): the run records not sent yet, as checked now - @{ Pending; OldestUtc; CheckedUtc }; $null when unreadable
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$State = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $due = @(Get-EpsUplinkDueRuns -ConnectionString $ConnectionString -State $State -NowUtc $NowUtc -Top 5000)
        $old = @($due | ForEach-Object { [datetime]$_.EndedAtUtc } | Sort-Object)[0]
        @{ Pending = $due.Count; OldestUtc = $(if ($due.Count) { [datetime]::SpecifyKind($old, 'Utc') }); CheckedUtc = $NowUtc }
    } catch { $null }
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
            ActionText = "$n change(s) to watched tag attributes were not made by Entra Policy Suite and are still open. Review them on the Tamper page: accept or restore each." })
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
      install key in the header x-invardia-install-key (Invardia 2026-11-04: this route does NOT read the uplink's
      x-ait-uplink-code - the same key under that header answered 401 live) -> { environmentId, environmentName, kind, handle, tenantId, customer,
      managedBy, displayName }. Returns @{ Ok; Value (the fields EPS keeps, or $null); Reason }. Never throws; the key is
      never in Reason.
    #>
    param([Parameter(Mandatory)][string]$Key, [string]$Endpoint = $script:EpsUplinkEndpoint)
    if ("$Endpoint" -notmatch '^https://') { return @{ Ok = $false; Value = $null; Reason = 'refused: the uplink endpoint must be https' } }
    $url = "https://$(([uri]$Endpoint).Authority)/api/enrollments/environment"
    try { $r = & $script:EpsHttp 'GET' $url @{ 'X-Invardia-Install-Key' = "$Key".Trim(); Accept = 'application/json' } $null }
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

function ConvertFrom-EpsUplinkConsent {
    <#
      PURE. framework SUPPORT ACCESS point 2 (owner 2026-11-04 "none, read, troubleshoot/setup"): `supportConsent: { level,
      appId? }` in the heartbeat answer. level 'troubleshoot' | 'setup' -> 'troubleshoot' (one level: read + admin only
      during an open session); 'read' -> 'read'; anything else (incl. 'none' and unknown values) -> 'none'. appId only as a
      lower-case GUID. $null = the answer carries no consent (keep the last one).
    #>
    param($Body)
    if ($null -eq $Body) { return $null }
    try { if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return $null }; $Body = $Body | ConvertFrom-Json -Depth 10 } } catch { return $null }
    $c = $Body.supportConsent
    if ($null -eq $c) { return $null }
    $l = "$($c.level)".Trim().ToLowerInvariant()
    $level = if ($l -in 'troubleshoot', 'setup') { 'troubleshoot' } elseif ($l -eq 'read') { 'read' } else { 'none' }
    $app = "$($c.appId)".Trim().ToLowerInvariant(); if ($app -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $app = '' }
    @{ Level = $level; AppId = $app }
}

function Test-EpsSupportWithinConsent {
    <#
      PURE. A session can never exceed the consent (SUPPORT ACCESS point 2): an OPEN session is kept only while the kept
      consent ('<level>|<appId>') is troubleshoot; else it is recorded as a refused open (state 'refused', the reason said).
    #>
    param([Parameter(Mandatory)]$State, [AllowEmptyString()][string]$Consent)
    if ($State.State -ne 'open') { return $State }
    $lvl = ("$Consent".Split('|'))[0]
    if ($lvl -eq 'troubleshoot') { return $State }
    # treated as CLOSED (an earlier open one closes too), with the refusal audited by Save-EpsSupportState
    $why = "the customer's support consent is '$(if ($lvl) { $lvl } else { 'not received yet' })', not troubleshoot/setup"
    @{ State = 'closed'; EnvironmentId = $State.EnvironmentId; Level = ''; Reason = ''; TicketNumber = ''; OpenedBy = ''; MaxUntilUtc = $null
       Refused = @{ Why = $why; TicketNumber = $State.TicketNumber; OpenedBy = $State.OpenedBy; Level = $State.Level } }
}

function Save-EpsSupportState {
    <#
      Records the support state (eps.SupportEvent): a change of state = a new row + an audit row (support.state.change);
      the same state again = only LastSeenUtc / MaxUntilUtc move. A 'closed' with nothing open before records nothing.
      It records only - it grants no access. Returns the plain line.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $refusedLine = ''
    if ($State.Refused) {
        [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.session.refused' -Actor 'Invardia (heartbeat answer)' -ActorSource 'job' -Target 'SupportEvent' `
            -Reason "framework SUPPORT ACCESS: $($State.Refused.Why)" -Outcome 'refused' -After @{ ticket = $State.Refused.TicketNumber; openedBy = $State.Refused.OpenedBy; level = $State.Refused.Level })
        $refusedLine = "support: an open session was REFUSED ($($State.Refused.Why)); "
    }
    $last =@(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP (1) SupportEventId, State, AccessLevel, Reason, TicketNumber, OpenedBy, MaxUntilUtc FROM eps.SupportEvent ORDER BY SupportEventId DESC')[0]
    $same = $last -and "$($last.State)" -eq $State.State -and ($State.State -eq 'closed' -or ("$($last.TicketNumber)" -eq "$($State.TicketNumber)" -and "$($last.OpenedBy)" -eq "$($State.OpenedBy)" -and "$($last.AccessLevel)" -eq "$($State.Level)"))
    $nul = { param($s) if ("$s") { "$s" } else { $null } }
    if ($same) {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $last.SupportEventId; t = $NowUtc; m = $State.MaxUntilUtc } -Query 'UPDATE eps.SupportEvent SET LastSeenUtc = @t, MaxUntilUtc = @m WHERE SupportEventId = @id' | Out-Null
    } elseif ($State.State -eq 'closed' -and (-not $last -or "$($last.State)" -eq 'closed')) {
        return "$($refusedLine)support: closed (nothing was open)"
    } else {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $NowUtc; s = $State.State; l = (& $nul $State.Level); r = (& $nul $State.Reason); n = (& $nul $State.TicketNumber); o = (& $nul $State.OpenedBy); m = $State.MaxUntilUtc; e = $(if ($State.EnvironmentId) { [guid]$State.EnvironmentId }) } `
            -Query 'INSERT INTO eps.SupportEvent (ReceivedAtUtc, LastSeenUtc, State, AccessLevel, Reason, TicketNumber, OpenedBy, MaxUntilUtc, EnvironmentId) VALUES (@t, @t, @s, @l, @r, @n, @o, @m, @e)' | Out-Null
        [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.state.change' -Actor 'Invardia (heartbeat answer)' -ActorSource 'job' -Target 'SupportEvent' `
            -Reason 'framework SECAUDIT-1a: recorded only - no access is granted from it yet' -Outcome 'ok' `
            -Before $(if ($last) { @{ state = "$($last.State)"; ticket = "$($last.TicketNumber)" } }) -After @{ state = $State.State; level = $State.Level; ticket = $State.TicketNumber; openedBy = $State.OpenedBy; maxUntilUtc = (ConvertTo-EpsUplinkIso $State.MaxUntilUtc) })
    }
    if ($State.State -eq 'open') { "support: OPEN until $(ConvertTo-EpsUplinkIso $State.MaxUntilUtc)$(if ($State.TicketNumber) { " (ticket $($State.TicketNumber))" })$(if ($State.Level) { ", level $($State.Level)" }) - recorded only, nothing granted" }
    else { "$($refusedLine)support: closed - recorded" }
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
function ConvertFrom-EpsUplinkSupersededBy {
    <# PURE. The heartbeat answer's `supersededBy` (a licence id: letters, digits, . _ -), or '' (none / not a plain id). #>
    param([AllowNull()]$Body)
    try { if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return '' }; $Body = $Body | ConvertFrom-Json -Depth 10 } } catch { return '' }
    if ($null -eq $Body) { return '' }
    $v = $Body.PSObject.Properties['supersededBy']; if (-not $v -or $v.Value -isnot [string]) { return '' }
    $s = $v.Value.Trim(); if ($s -match '^[A-Za-z0-9._-]{1,100}$') { return $s }
    ''
}

function Invoke-EpsUplinkCycle {
    <#
    .SYNOPSIS
        One uplink cycle (the Uplink job). Returns @{ Mode ('disabled' | 'identified'); Posts; Heartbeat; Runs; Alerts;
        Support; Stopped; Lines }. Never throws. -Log { param($level, $msg) } gets every line.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version, [string]$TenantId = $env:EPS_TENANT_ID, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$PauseMs = $script:EpsUplinkPauseMs, [int]$RoundWaitMs = $script:EpsUplinkRoundWaitMs, [string]$WebUrl = $env:EPS_WEB_URL, [string]$Endpoint = $script:EpsUplinkEndpoint, [scriptblock]$Log = { param($l, $m) })
    $res = @{ Mode = 'disabled'; Posts = 0; Rounds = 1; Heartbeat = ''; Environment = ''; Runs = 0; Alerts = 0; Support = ''; Stopped = ''; Lines = [System.Collections.Generic.List[string]]::new() }
    $say = { param($l, $m) $res.Lines.Add($m); & $Log $l $m }
    $finish = { param($line) try { Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'last' -Value "$(ConvertTo-EpsUplinkIso $NowUtc) $line" } catch { }; $res }
    try {
        if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Uplink.Enabled' -Default 'true')" -ne 'true') { & $say 'Info' 'uplink: switched off (Uplink.Enabled) - nothing sent'; return (& $finish 'disabled: switched off (Uplink.Enabled)') }
        $k = Get-EpsUplinkKey
        if (-not $k.Key) { & $say 'Info' "uplink: disabled - $($k.Reason); nothing sent (identified only, never anonymous)"; return (& $finish "disabled: $($k.Reason)") }
        $key = $k.Key; $res.Mode = 'identified'
        # INSTALL-PRO: the licence fields once per cycle (a read failure = community, never a stop)
        $script:EpsUplinkLicenceFields = $null
        if (Get-Command Get-EpsLicence -ErrorAction SilentlyContinue) { try { $lv = Get-EpsLicence -ConnectionString $ConnectionString -TenantId "$TenantId".ToLowerInvariant() -Refresh; $script:EpsUplinkLicenceFields = Get-EpsLicenceUplinkFields -License $lv.License -TenantId "$TenantId".ToLowerInvariant() } catch { $script:EpsUplinkLicenceFields = $null } }
        $host_ = ([uri]$Endpoint).Host
        $st = Get-EpsUplinkState -ConnectionString $ConnectionString
        $post = {
            param([System.Collections.IDictionary]$rec)
            if ($res.Posts -ge $script:EpsUplinkMaxPosts) { return @{ Ok = $false; Status = 0; Reason = 'budget'; Budget = $true } }
            # a new round waits >= 65 s (the 30 / min limit has passed); inside a round 2.5 s apart
            if ($res.Posts -gt 0 -and ($res.Posts % $script:EpsUplinkRoundPosts) -eq 0) { & $script:EpsUplinkSleep $RoundWaitMs; $res.Rounds++ }
            elseif ($res.Posts -gt 0) { & $script:EpsUplinkSleep $PauseMs }
            $res.Posts++
            Send-EpsUplinkRecord -Record $rec -Key $key -Endpoint $Endpoint
        }
        $fail = { param($what, $r) $res.Stopped = "$what $($r.Reason)"; & $say 'Warning' "uplink: $what to $host_ (identified) failed: $($r.Reason) - the cycle stops; the rest goes next cycle" }

        # 1. the heartbeat (every 4 h; an interval is sent only on a 2xx)
        $lastHb = if ($st.heartbeat) { ConvertFrom-EpsUplinkTime $st.heartbeat }
        if (-not $lastHb -or ($NowUtc - $lastHb).TotalMinutes -ge ($script:EpsUplinkHeartbeatHours * 60 - 10)) {
            $facts = Get-EpsUplinkHeartbeatFacts -ConnectionString $ConnectionString -Version $Version
            if ($script:EpsUplinkSendBacklog) { $facts.UplinkBacklog = Get-EpsUplinkBacklog -ConnectionString $ConnectionString -State $st -NowUtc $NowUtc }
            $r = & $post (New-EpsUplinkHeartbeat -Facts $facts -Version $Version -TenantId $TenantId -NowUtc $NowUtc)
            if (-not $r.Ok -and $r.Status -in 400, 413, 422) {
                # Invardia names the refused fields (422 { error, fields }): only THOSE are left out of the one resend; a
                # refusal that names none (or names something else) - the liveness record only, as before (§8.17)
                $named = @(@($r.Fields) | ForEach-Object { "$_" } | Where-Object { $_ -match '^[A-Za-z]{1,40}$' })
                if ($named.Count -and -not @($named | Where-Object { $script:EpsUplinkNewHeartbeatFields -notcontains $_ }).Count) {
                    & $say 'Warning' "uplink: heartbeat refused ($($r.Reason)) - sent once more without $($named -join ', ') (Invardia named them)"
                    $r = & $post (New-EpsUplinkHeartbeat -Facts $facts -Version $Version -TenantId $TenantId -NowUtc $NowUtc -Drop $named)
                    if ($r.Ok) { $res.Heartbeat = "ok (without $($named -join ', '))" }
                } else {
                    & $say 'Warning' "uplink: heartbeat refused ($($r.Reason)) - sent once more without the newer fields (§8.17)"
                    $r = & $post (New-EpsUplinkHeartbeat -Facts $facts -Version $Version -TenantId $TenantId -NowUtc $NowUtc -WithoutNewFields)
                    if ($r.Ok) { $res.Heartbeat = 'ok (without the newer fields)' }
                }
            } elseif ($r.Ok) { $res.Heartbeat = 'ok' }
            if (-not $r.Ok) { $res.Heartbeat = 'failed'; & $fail 'heartbeat' $r; return (& $finish "identified: heartbeat FAILED ($($r.Reason))") }
            Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'heartbeat' -Value (ConvertTo-EpsUplinkIso $NowUtc)
            & $say 'Info' "uplink: heartbeat sent ($($res.Heartbeat))"
            # framework SUPPORT ACCESS point 2: the customer's consent level from THIS identified heartbeat's answer only
            # (TLS + the install key) - kept in eps.UplinkState (the web app may only read it); absent = the last one kept
            $con = ConvertFrom-EpsUplinkConsent -Body $r.Body
            if ($con) { try { Set-EpsUplinkState -ConnectionString $ConnectionString -Name 'support.consent' -Value "$($con.Level)|$($con.AppId)"; & $say 'Info' "uplink: support consent $($con.Level)$(if ($con.AppId) { " (Support app $($con.AppId))" }) - kept" } catch { & $say 'Warning' "uplink: the support consent could not be kept: $($_.Exception.Message)" } }
            $sup = ConvertFrom-EpsUplinkSupportAnswer -Body $r.Body -NowUtc $NowUtc
            # a session can never exceed the consent: with 'none' (or no consent ever received) an open session is recorded as refused
            if ($sup -and $sup.State -eq 'open') { $kept = try { "$((Get-EpsUplinkState -ConnectionString $ConnectionString)['support.consent'])" } catch { '' }; $sup = Test-EpsSupportWithinConsent -State $sup -Consent $kept }
            if ($sup) { try { $res.Support = Save-EpsSupportState -ConnectionString $ConnectionString -State $sup -NowUtc $NowUtc; & $say 'Info' $res.Support } catch { & $say 'Warning' "uplink: the support state could not be recorded: $($_.Exception.Message)" } }
            # INSTALL-PRO (§100.39 / framework §12.6b, as PIM-Uplink): Invardia re-issued the licence -> `supersededBy: <licence id>`
            # in the answer; kept for the update job, which knocks for the successor (verified like any delivery)
            $sb = ConvertFrom-EpsUplinkSupersededBy -Body $r.Body
            if ($sb -and (Get-Command Set-EpsLicenceSupersededBy -ErrorAction SilentlyContinue)) { try { Set-EpsLicenceSupersededBy -ConnectionString $ConnectionString -LicenceId $sb; & $say 'Info' "uplink: Invardia says the licence is superseded by $sb - the update job asks for it" } catch { & $say 'Warning' "uplink: supersededBy not kept: $($_.Exception.Message)" } }
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
        if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Uplink.Alerts.Enabled' -Default 'true')" -eq 'true') {
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
        foreach ($run in (Get-EpsUplinkDueRuns -ConnectionString $ConnectionString -State $st -NowUtc $NowUtc)) {
            $r = & $post (New-EpsUplinkRunRecord -Run $run -Version $Version -TenantId $TenantId -Key $key -NowUtc $NowUtc)
            if (-not $r.Ok) {
                if ($r.Budget) { $res.Stopped = 'budget'; & $say 'Info' "uplink: $($script:EpsUplinkMaxPosts) POSTs this cycle ($($script:EpsUplinkMaxRounds) rounds) - the rest of the runs go next cycle" } else { & $fail "run record $(Get-EpsUplinkJobId $run.Job)" $r }
                break
            }
            Set-EpsUplinkState -ConnectionString $ConnectionString -Name "watermark:$(Get-EpsUplinkJobId $run.Job)" -Value ([datetime]::SpecifyKind([datetime]$run.EndedAtUtc, 'Utc').ToString('o', [Globalization.CultureInfo]::InvariantCulture))
            $res.Runs++
        }
        if ($res.Runs) { & $say 'Info' "uplink: $($res.Runs) run record(s) sent in $($res.Rounds) round(s)" }
        & $finish "identified: heartbeat $($res.Heartbeat), $($res.Alerts) alert(s), $($res.Runs) run(s)$(if ($res.Stopped) { ", stopped ($($res.Stopped))" })"
    } catch {
        $res.Stopped = 'error'
        & $say 'Warning' "uplink: the cycle failed: $(ConvertTo-EpsUplinkRedacted -Text "$($_.Exception.Message)" -Key $key -Max 300)"
        & $finish 'error: the cycle failed - see the job log'
    }
}
