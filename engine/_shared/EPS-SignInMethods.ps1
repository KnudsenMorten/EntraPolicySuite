#Requires -Version 7.2
<#
    THE USERS' SIGN-IN METHODS, READ PER USER IN THE BACKGROUND AND CACHED PER USER - SecurityInsight's design (SI 3.0.49,
    SI-SignInMethodsChoice.ps1 / SI-AuthMethodsRead.ps1; owner 2026-11-09: "it is related to mfa auth details with a per user
    call" / "read how we does it in si" / "Both, as SI (Recommended)" / "remember to do the cachin, otherwise the colection
    will be very slow at some customers").

    TWO SOURCES
      the tenant-wide registration report (reports/authenticationMethods/userRegistrationDetails) - read by every identity
          report run for every user (one paged call). It gives each user's CHANGE KEY: its lastUpdatedDateTime + a SHA-256 of
          its registered methods (both: the timestamp can lag).
      the per-user read (GET /users/{id}/authentication/methods, in $batch of 20; the device behind a Windows Hello for
          Business / Microsoft Authenticator method with $expand=device) - every method in detail. Slow on a big tenant (one
          read per user, Microsoft throttles), so the identity report NEVER makes it:

    THE REPORT (Update-EpsSignInMethodsKeys, inside the identity report run - no per-user Graph call)
      records each user's work row in eps.UserSignInMethods in ONE statement per page (privileged or not, today's change
      key, seen now) and takes the saved detail of the users that were read: a user not read yet is UNKNOWN, never "no MFA".

    THE FILLER (Invoke-EpsSignInMethodsFill, its OWN job SignInMethods every 15 minutes)
      reads per user, for at most SignInMethods.FillMinutes (8) per run, 200 users per round, $batch of 20 with the bodies in flight together (adaptive, as SI: from 1, one more after a wave without a 429, half after a throttled wave), then stops and carries on next
      run (the scheduler's overlap guard: one run at a time). Who is read first (one SQL pick):
        1. privileged users (an admin as the last report saw it)
        2. users whose change key differs from the key their detail was read under, or whose devices were not read whole
        3. users never read
        4. users read SignInMethods.MaxAgeDays (90) ago or longer, oldest first
      A user tried in the last 10 minutes is not picked again (a throttled user waits); a user the report has not listed for
      14 days is not read, and is let go after 60.
    THE CHOICE (SignInMethods.Scope): all (default) | privileged.  SignInMethods.Enabled (off by default): the job itself.
    A phone number is kept MASKED (the last 4 digits): enough to recognise it, not a directory of numbers.
#>

$script:EpsSignInMethodsFill = @{ BatchSize = 200; RetryAfterMinutes = 10; ListedWithinDays = 14; KeepUnlistedDays = 60; GraphBatch = 20 }

# ---- PURE --------------------------------------------------------------------------------------------------------------
function Get-EpsSignInMethodsChangeKey {
    <# PURE. A user's change key from its registration report entry: @{ Stamp; Hash }, or $null without an entry. #>
    param([AllowNull()]$Entry)
    if ($null -eq $Entry) { return $null }
    $items = @(@($Entry.methodsRegistered) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $stamp = $null
    if ($Entry.lastUpdatedDateTime) { try { $stamp = ([datetime]$Entry.lastUpdatedDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } catch { $stamp = "$($Entry.lastUpdatedDateTime)" } }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($items -join ','))) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    [pscustomobject]@{ Stamp = $stamp; Hash = $hash }
}

function ConvertTo-EpsAuthMethodItem {
    <# PURE. One method from Graph as what EPS keeps: type, id, displayName, created, and per type its useful properties
       (a phone number masked to its last 4 digits); the device behind it when read. #>
    param([Parameter(Mandatory)]$Method)
    $type = ("$($Method.'@odata.type')" -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '')
    $o = [ordered]@{ type = $type; id = "$($Method.id)" }
    foreach ($k in 'displayName', 'createdDateTime', 'phoneType', 'smsSignInState', 'emailAddress', 'deviceTag', 'phoneAppVersion', 'model', 'aaGuid', 'attestationLevel', 'keyStrength', 'platform', 'lifetimeInMinutes', 'isUsable', 'isUsableOnce', 'startDateTime') {
        if ($Method.PSObject.Properties[$k] -and $null -ne $Method.$k -and "$($Method.$k)" -ne '') { $o[$k] = $Method.$k }
    }
    if ($Method.PSObject.Properties['phoneNumber'] -and "$($Method.phoneNumber)") { $p = "$($Method.phoneNumber)" -replace '\s', ''; $o.phoneNumber = $(if ($p.Length -gt 4) { ('*' * ($p.Length - 4)) + $p.Substring($p.Length - 4) } else { '****' }) }
    if ($Method.PSObject.Properties['device'] -and $Method.device) {
        $d = $Method.device
        $o.device = [ordered]@{ name = "$($d.displayName)"; os = "$($d.operatingSystem)"; osVersion = "$($d.operatingSystemVersion)"; compliant = $d.isCompliant; managed = $d.isManaged; trustType = "$($d.trustType)"; deviceId = "$($d.deviceId)"; lastSignIn = $d.approximateLastSignInDateTime }
    }
    [pscustomobject]$o
}

function Get-EpsSignInMethodsSummary {
    <# PURE. The saved detail (JSON text) -> @{ Types (sorted, once each, password left out); Count; Phishing (a passkey /
       FIDO2 / WHfB / platform credential); ReadAtUtc } for the report's row, or $null. #>
    param([AllowNull()][string]$Detail, $ReadAtUtc)
    if (-not "$Detail".Trim()) { return $null }
    $o = try { $Detail | ConvertFrom-Json } catch { $null }
    if (-not $o) { return $null }
    $types = @(@($o.methods) | ForEach-Object { "$($_.type)" } | Where-Object { $_ -and $_ -ne 'password' } | Sort-Object -Unique)
    @{ Types = ($types -join ','); Count = $types.Count; Phishing = [bool]@($types | Where-Object { $_ -in 'fido2', 'windowsHelloForBusiness', 'platformCredential', 'passkey' }).Count; ReadAtUtc = $ReadAtUtc }
}

# ---- SQL ---------------------------------------------------------------------------------------------------------------
function Update-EpsSignInMethodsKeys {
    <#
      The report's side, ONE statement per call: records each user's work row (@rows = [{ u; upn; p; s; h }]) and answers
      the saved detail of those that were read: UserId, ReadAtUtc, ReadStamp, ReadHash, CurrentStamp, CurrentHash, Detail.
      Never throws: a database that cannot (no table yet) answers @() and the report says so once.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object[]]$Rows)
    if (-not $Rows.Count) { return @() }
    $json = ConvertTo-Json -InputObject @($Rows) -Depth 3 -Compress
    Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ rows = $json } -Query @'
SET NOCOUNT ON;
DECLARE @r TABLE (UserId NVARCHAR(64) NOT NULL PRIMARY KEY, Upn NVARCHAR(320) NULL, Privileged BIT NOT NULL, Stamp NVARCHAR(64) NULL, Hash NVARCHAR(64) NULL);
INSERT @r (UserId, Upn, Privileged, Stamp, Hash)
SELECT LOWER(x.u), MAX(x.upn), MAX(CASE WHEN x.p = 1 THEN 1 ELSE 0 END), MAX(x.s), MAX(x.h)
FROM OPENJSON(@rows) WITH (u NVARCHAR(64), upn NVARCHAR(320), p BIT, s NVARCHAR(64), h NVARCHAR(64)) x
WHERE x.u IS NOT NULL AND x.u <> N'' GROUP BY LOWER(x.u);
MERGE eps.UserSignInMethods AS t USING @r AS s ON t.UserId = s.UserId
WHEN MATCHED THEN UPDATE SET Upn = s.Upn, Privileged = s.Privileged, CurrentStamp = s.Stamp, CurrentHash = s.Hash, SeenAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (UserId, Upn, Privileged, CurrentStamp, CurrentHash, SeenAtUtc) VALUES (s.UserId, s.Upn, s.Privileged, s.Stamp, s.Hash, SYSUTCDATETIME());
SELECT w.UserId, w.ReadAtUtc, w.ReadStamp, w.ReadHash, w.CurrentStamp, w.CurrentHash, w.Detail
FROM @r s JOIN eps.UserSignInMethods w ON w.UserId = s.UserId WHERE w.ReadAtUtc IS NOT NULL;
'@
}

function Get-EpsSignInMethodsPick {
    <# The filler's next @n users in priority order (header), marked tried now. -All $false = privileged only. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$Take = 200, [int]$MaxAgeDays = 90, [bool]$All = $true)
    $f = $script:EpsSignInMethodsFill
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ n = $Take; d = $MaxAgeDays; a = [bool]$All } -Query @"
SET NOCOUNT ON;
WITH due AS (
    SELECT TOP (@n) w.*
    FROM eps.UserSignInMethods w
    WHERE w.SeenAtUtc >= DATEADD(day, -$($f.ListedWithinDays), SYSUTCDATETIME())
      AND (@a = 1 OR w.Privileged = 1)      AND (w.LastTryAtUtc IS NULL OR w.LastTryAtUtc < DATEADD(minute, -$($f.RetryAfterMinutes), SYSUTCDATETIME()))
      AND (w.ReadAtUtc IS NULL OR ISNULL(w.ReadStamp, N'') <> ISNULL(w.CurrentStamp, N'') OR ISNULL(w.ReadHash, N'') <> ISNULL(w.CurrentHash, N'')
           OR w.DevicesRead = 0 OR w.ReadAtUtc < DATEADD(day, -@d, SYSUTCDATETIME()))
    ORDER BY w.Privileged DESC,
             CASE WHEN w.ReadAtUtc IS NOT NULL AND (ISNULL(w.ReadStamp, N'') <> ISNULL(w.CurrentStamp, N'') OR ISNULL(w.ReadHash, N'') <> ISNULL(w.CurrentHash, N'') OR w.DevicesRead = 0) THEN 0
                  WHEN w.ReadAtUtc IS NULL THEN 1 ELSE 2 END,
             ISNULL(w.LastTryAtUtc, '19000101'), w.ReadAtUtc, w.UserId
)
UPDATE due SET LastTryAtUtc = SYSUTCDATETIME()
OUTPUT inserted.UserId, inserted.CurrentStamp, inserted.CurrentHash, CAST(inserted.Privileged AS INT) AS Privileged,
       CASE WHEN inserted.ReadAtUtc IS NULL THEN N'never'
            WHEN ISNULL(inserted.ReadStamp, N'') <> ISNULL(inserted.CurrentStamp, N'') OR ISNULL(inserted.ReadHash, N'') <> ISNULL(inserted.CurrentHash, N'') OR inserted.DevicesRead = 0 THEN N'changed'
            ELSE N'maxage' END AS Reason;
"@)
}

function Save-EpsSignInMethods {
    <# Saves what the filler read: @rows = [{ u; s; h; d (detail JSON); dr (devices read) }] - JSON (no VARBINARY column: the store rule); a user the
       report has not listed for 60 days is let go (at most 500 per call). Answers the number written. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object[]]$Rows)
    $json = ConvertTo-Json -InputObject @($Rows) -Depth 3 -Compress
    [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ rows = $json } -Query @"
SET NOCOUNT ON;
UPDATE w SET ReadStamp = x.s, ReadHash = x.h, Detail = x.d, DevicesRead = x.dr, ReadAtUtc = SYSUTCDATETIME(), Error = NULL
FROM eps.UserSignInMethods w JOIN OPENJSON(@rows) WITH (u NVARCHAR(64), s NVARCHAR(64), h NVARCHAR(64), d NVARCHAR(MAX), dr BIT) x ON w.UserId = LOWER(x.u);
DECLARE @n INT = @@ROWCOUNT;
DELETE TOP (500) FROM eps.UserSignInMethods WHERE SeenAtUtc < DATEADD(day, -$($script:EpsSignInMethodsFill.KeepUnlistedDays), SYSUTCDATETIME());
SELECT @n;
"@)
}

# ---- GRAPH (the per-user read) - SecurityInsight's #874: $batch of 20, several $batch calls IN FLIGHT AT ONCE, adaptive ---
# (one more after a wave Microsoft answered without a 429, half after a throttled wave; owner 2026-11-09 "if it runs in
# the background, we need to increate this" / "dont invente something, ask how si does it"): EXACTLY SI's numbers - from 1, no ceiling.
$script:EpsSignInConcurrency = @{ Concurrency = 1; Max = [int]::MaxValue; Throttled = 0; Requests = 0; MaxSeen = 0; Slept = 0 }
# the seam: { param([string[]]$Bodies) } -> one @{ Status; RetryAfter; Body (parsed); Error } per body, in order. $null = the
# real one (Send-EpsGraphBatches: .NET HttpClient, every body in flight together)
$script:EpsBatchSend = $null

function Send-EpsGraphBatches {
    <# The $batch bodies sent to Microsoft Graph AT ONCE (.NET HttpClient, REST only): one outcome per body, in order. Never throws. #>
    param([string[]]$Bodies = @(), [int]$TimeoutSeconds = 100)
    $out = [System.Collections.Generic.List[object]]::new()
    if (-not @($Bodies).Count) { return , $out.ToArray() }
    $token = Get-EpsToken -Resource 'https://graph.microsoft.com'
    $client = [System.Net.Http.HttpClient]::new(); $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    try {
        $tasks = foreach ($b in $Bodies) {
            try {
                $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$($script:EpsGraphRoot.TrimEnd('/'))/v1.0/`$batch")
                $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
                $req.Content = [System.Net.Http.StringContent]::new([string]$b, [Text.Encoding]::UTF8, 'application/json')
                $client.SendAsync($req)
            } catch { $_.Exception }
        }
        foreach ($tk in @($tasks)) {
            if ($tk -is [System.Exception]) { $out.Add(@{ Status = 0; RetryAfter = $null; Body = $null; Error = $tk.Message }); continue }
            try {
                $resp = $tk.GetAwaiter().GetResult(); $st = [int]$resp.StatusCode; $ra = $null
                try { if ($resp.Headers.RetryAfter -and $null -ne $resp.Headers.RetryAfter.Delta) { $ra = [int][math]::Ceiling(([TimeSpan]$resp.Headers.RetryAfter.Delta).TotalSeconds) } } catch { }
                $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $out.Add(@{ Status = $st; RetryAfter = $ra; Body = $(if ($st -eq 200 -and $text) { try { $text | ConvertFrom-Json -Depth 20 } catch { $null } }); Error = $(if ($st -ne 200) { "$st $($resp.ReasonPhrase)" }) })
                $resp.Dispose()
            } catch { $out.Add(@{ Status = 0; RetryAfter = $null; Body = $null; Error = $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }) }) }
        }
    } finally { $client.Dispose() }
    , $out.ToArray()
}

function Invoke-EpsGraphBatchWaves {
    <#
      Many GETs (@{ key = '/relative/url' }) through $batch (20 per body), several bodies in flight per wave, ADAPTIVE: the
      next wave sends one more body after a wave without a 429, half after a throttled wave (Retry-After waited once per
      wave, capped at 60 s; 2^n without it). A throttled item is asked again in a later wave, at most -MaxTries times; what
      stays throttled answers 429 (the caller keeps it UNKNOWN). Answers @{ key = @{ Status; Body } }.
    #>
    param([Parameter(Mandatory)][hashtable]$Urls, [int]$MaxTries = 5)
    $st = $script:EpsSignInConcurrency
    $send = if ($script:EpsBatchSend) { $script:EpsBatchSend } else { { param([string[]]$Bodies) Send-EpsGraphBatches -Bodies $Bodies } }
    $out = @{}; $tries = @{}; $queue = [System.Collections.Generic.Queue[string]]::new(); foreach ($k in $Urls.Keys) { $queue.Enqueue([string]$k); $tries[[string]$k] = 0 }
    $wave = 0
    while ($queue.Count) {
        $wave++
        # this wave: up to Concurrency bodies of 20 items
        $bodies = [System.Collections.Generic.List[object]]::new()
        while ($queue.Count -and $bodies.Count -lt $st.Concurrency) {
            $items = [System.Collections.Generic.List[string]]::new(); while ($queue.Count -and $items.Count -lt $script:EpsSignInMethodsFill.GraphBatch) { $items.Add($queue.Dequeue()) }
            $bodies.Add(@{ Keys = $items.ToArray(); Json = (ConvertTo-Json -Compress -Depth 4 -InputObject @{ requests = @(for ($i = 0; $i -lt $items.Count; $i++) { @{ id = "$i"; method = 'GET'; url = $Urls[$items[$i]] } }) }) })
        }
        $st.Requests += $bodies.Count; $st.MaxSeen = [math]::Max($st.MaxSeen, $bodies.Count)
        $res = @(& $send @($bodies | ForEach-Object { $_.Json }))
        $throttled = $false; $wait = 0; $retry = [System.Collections.Generic.List[string]]::new()
        for ($b = 0; $b -lt $bodies.Count; $b++) {
            $r = $res[$b]; $keys = $bodies[$b].Keys
            if (-not $r -or $r.Status -ne 200) {
                # the whole body: throttled / unavailable = ask again later; anything else = every item failed with that status
                if ($r -and $r.Status -in 429, 503, 504 -or -not $r -or $r.Status -eq 0) { $throttled = $true; if ($r -and $r.RetryAfter) { $wait = [math]::Max($wait, [int]$r.RetryAfter) }; foreach ($k in $keys) { $retry.Add($k) } }
                else { foreach ($k in $keys) { $out[$k] = @{ Status = [int]$r.Status; Body = $null } } }
                continue
            }
            foreach ($x in @($r.Body.responses)) {
                $k = $keys[[int]$x.id]; $s = [int]$x.status
                if ($s -in 429, 503, 504) {
                    $throttled = $true; $retry.Add($k)
                    $ra = 0; if ($x.headers -and [int]::TryParse("$($x.headers.'Retry-After')", [ref]$ra)) { $wait = [math]::Max($wait, $ra) }
                } else { $out[$k] = @{ Status = $s; Body = $x.body } }
            }
        }
        # a refusal stops at once: no item is asked again (the caller says which right is missing)
        if (@($out.Values | Where-Object { $_.Status -in 401, 403 }).Count) { foreach ($k in $retry) { $out[$k] = @{ Status = 403; Body = $null } }; break }
        foreach ($k in $retry) { $tries[$k]++; if ($tries[$k] -lt $MaxTries) { $queue.Enqueue($k) } else { $out[$k] = @{ Status = 429; Body = $null } } }
        if ($throttled) {
            $st.Concurrency = [math]::Max(1, [int][math]::Floor($st.Concurrency / 2)); $st.Throttled++
            $sec = [math]::Min(60, [math]::Max(1, $(if ($wait) { $wait } else { [math]::Pow(2, [math]::Min(5, $st.Throttled)) })))
            $st.Slept += $sec; Start-Sleep -Seconds $sec
        } else { $st.Concurrency = [math]::Min($st.Max, $st.Concurrency + 1) }
    }
    $out
}

function Read-EpsUserSignInMethods {
    <#
      Per user (ids): every method, and the device behind a WHfB / Authenticator method (a second wave only for the users who
      hold one). Answers @{ userId = @{ Ok; Methods; DevicesRead; Error } }. A user that stays throttled or fails is
      Ok = $false (UNKNOWN). 401 / 403 stop the read (no right): @{ Refused = '<why>' }.
    #>
    param([Parameter(Mandatory)][string[]]$UserIds)
    $res = @{}
    $urls = @{}; foreach ($u in $UserIds) { $urls[$u] = "/users/$u/authentication/methods" }
    $ans = Invoke-EpsGraphBatchWaves -Urls $urls
    if (@($ans.Values | Where-Object { $_.Status -in 401, 403 }).Count) { return @{ Refused = 'Graph refused /users/{id}/authentication/methods (401 / 403) - the engine needs UserAuthenticationMethod.Read.All' } }
    $dev = @{}
    foreach ($u in $UserIds) {
        $a = $ans[$u]
        if (-not $a -or $a.Status -ge 300) { $res[$u] = @{ Ok = $false; Methods = @(); DevicesRead = $false; Error = "HTTP $(if ($a) { $a.Status } else { 'no answer' })" }; continue }
        $ms = @($a.Body.value)
        $res[$u] = @{ Ok = $true; Methods = @($ms | ForEach-Object { ConvertTo-EpsAuthMethodItem -Method $_ }); DevicesRead = $true; Error = $null }
        foreach ($t in 'windowsHelloForBusiness', 'microsoftAuthenticator') { if (@($ms | Where-Object { "$($_.'@odata.type')" -like "*$($t)AuthenticationMethod" }).Count) { $dev["$u|$t"] = "/users/$u/authentication/$($t)Methods?`$expand=device" } }
    }
    if ($dev.Count) {
        $ans2 = Invoke-EpsGraphBatchWaves -Urls $dev
        foreach ($k in $dev.Keys) {
            $u = $k.Split('|')[0]; $a = $ans2[$k]
            if (-not $a -or $a.Status -ge 300) { $res[$u].DevicesRead = $false; continue }
            foreach ($m in @($a.Body.value)) { $full = ConvertTo-EpsAuthMethodItem -Method $m; $res[$u].Methods = @(@($res[$u].Methods | Where-Object { $_.id -ne $full.id }) + $full) }
        }
    }
    $res
}
# ---- THE FILLER (the SignInMethods job) --------------------------------------------------------------------------------
function Invoke-EpsSignInMethodsFill {
    <#
      One run: rounds of up to 200 users in priority order until nothing is due or SignInMethods.FillMinutes (8) passed.
      Answers @{ Read; Unknown; Rounds; Refused; Stopped }. -Read is a seam (tests): { param([string[]]$Ids) } -> as
      Read-EpsUserSignInMethods.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Read, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Read) { $Read = { param([string[]]$Ids) Read-EpsUserSignInMethods -UserIds $Ids } }
    $scope = try { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'SignInMethods.Scope' -Default 'all')" } catch { 'all' }; if ($scope -notin 'all', 'privileged') { & $Log 'Warn' "SignInMethods.Scope '$scope' is not all or privileged - all is used"; $scope = 'all' }
    $maxAge = 90; [void][int]::TryParse($(try { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'SignInMethods.MaxAgeDays' -Default '90')" } catch { '90' }), [ref]$maxAge); $maxAge = [math]::Min(365, [math]::Max(1, $maxAge))
    $mins = 8; [void][int]::TryParse($(try { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'SignInMethods.FillMinutes' -Default '8')" } catch { '8' }), [ref]$mins); $mins = [math]::Min(25, [math]::Max(1, $mins))
    $until = [datetime]::UtcNow.AddMinutes($mins)
    $out = @{ Read = 0; Unknown = 0; Rounds = 0; Refused = $null; Stopped = '' }
    & $Log 'Info' "per-user sign-in methods: $scope users, re-read on change or after $maxAge days, for at most $mins minute(s) this run"
    while ([datetime]::UtcNow -lt $until) {
        $pick = @(Get-EpsSignInMethodsPick -ConnectionString $ConnectionString -Take $script:EpsSignInMethodsFill.BatchSize -MaxAgeDays $maxAge -All ($scope -eq 'all'))
        if (-not $pick.Count) { $out.Stopped = 'nothing is due'; break }
        $out.Rounds++
        $got = & $Read @($pick | ForEach-Object { "$($_.UserId)" })
        if ($got.Refused) { $out.Refused = $got.Refused; & $Log 'Error' $got.Refused; break }
        $save = foreach ($p in $pick) {
            $g = $got["$($p.UserId)"]
            if ($g -and $g.Ok) { [ordered]@{ u = "$($p.UserId)"; s = $p.CurrentStamp; h = $p.CurrentHash; d = (ConvertTo-Json -InputObject ([ordered]@{ methods = @($g.Methods); devicesRead = [bool]$g.DevicesRead }) -Depth 8 -Compress); dr = [bool]$g.DevicesRead } }
            else { $out.Unknown++ }
        }
        if (@($save).Count) { $out.Read += Save-EpsSignInMethods -ConnectionString $ConnectionString -Rows @($save) }
        & $Log 'Info' "round $($out.Rounds): $(@($save).Count) read, $($pick.Count - @($save).Count) still unknown (throttled or failed - tried again in 10 minutes)"
    }
    if (-not $out.Stopped -and -not $out.Refused) { $out.Stopped = "the $mins-minute budget is used - the next run carries on" }
    & $Log 'Info' "done: $($out.Read) user(s) read in $($out.Rounds) round(s), $($out.Unknown) unknown; $($out.Stopped)"
    # the pace, measured (owner 2026-11-09: "as fast as possible and self-healing"): what Microsoft let through this run
    $c = $script:EpsSignInConcurrency; & $Log 'Info' "pace: $($c.Requests) `$batch request(s) of up to 20 users, up to $($c.MaxSeen) in flight; Microsoft asked to slow down $($c.Throttled) time(s), $($c.Slept) s waited; ended at $([int]$c.Concurrency) in flight"
    $out
}
