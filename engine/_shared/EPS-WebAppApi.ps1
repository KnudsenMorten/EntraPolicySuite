# EntraPolicySuite -- the API for APPLICATIONS: /api/app/* (framework §12.31 SETTINGS-API-1 + §12.30 SUPPORT-FIX-API-1,
# owner 2026-11-16 "it should be possible to manage settings using code, not only gui" / "make sure security follows ms
# best practice for api"). A program of the customer's own tenant (or the Invardia Support app on a ticket) acts through
# the SAME handlers, validation, guards, journal and audit as a person - never a free-form write, never SQL.
#
# Microsoft's API security practice, as the framework's ten rules:
#   1-2  the token is checked HERE by Microsoft's library: v2, this tenant, this app, an APPLICATION token (idtyp=app,
#        no scp); a person's token is refused here and an application's token is refused on every person page
#   3-5  the Entra app role EPS.Api.Call (assignment required) AND EPS's own list: Security.ApiApps (a person's list,
#        Reader / Admin) or Security.SupportApp (the update's enrolment) - both layers, or 403
#   8    no CORS (a browser Origin is refused), a fixed schema per route (unknown fields refused), 64 KB, a rate limit per app
#   9    401 / 403 say nothing internal; every call audited with app id + tid + route + result; no token in any log
#   10   no token pass-through: after the checks EPS acts with its OWN identity (the engine applies the request)
# What each role may do per change is FIXED in EPS-ApiTiers.ps1 (tested by Test-EpsApiTiers).

Set-StrictMode -Off

$script:EpsAppApiMaxBody = 65536
$script:EpsAppApiPerMinute = 60
$script:EpsAppApiMassSettings = 10          # an import that changes more settings than this is HELD for a person (mass)
$script:EpsAppApiRate = @{}

function Test-EpsAppApiRate {
    # per calling app, a sliding minute (in memory: one web replica per install)
    param([Parameter(Mandatory)][string]$AppId, [datetime]$NowUtc = [datetime]::UtcNow)
    $q = $script:EpsAppApiRate[$AppId]
    if (-not $q) { $q = [System.Collections.Generic.Queue[datetime]]::new(); $script:EpsAppApiRate[$AppId] = $q }
    while ($q.Count -and ($NowUtc - $q.Peek()).TotalSeconds -ge 60) { [void]$q.Dequeue() }
    if ($q.Count -ge $script:EpsAppApiPerMinute) { return $false }
    $q.Enqueue($NowUtc); $true
}

function Test-EpsAppApiSchema {
    # the body's fields must be exactly from -Allowed (a fixed schema; unknown fields refused). '' = ok, else the reason.
    param($Body, [string[]]$Allowed, [string[]]$Required = @())
    if ($null -eq $Body -or $Body -isnot [System.Management.Automation.PSCustomObject]) { return 'the body must be a JSON object' }
    $names = @($Body.PSObject.Properties.Name)
    $extra = @($names | Where-Object { $Allowed -notcontains $_ }); if ($extra.Count) { return "unknown field(s): $($extra -join ', ')" }
    $miss = @($Required | Where-Object { $names -notcontains $_ -or -not "$($Body.$_)".Trim() }); if ($miss.Count) { return "missing: $($miss -join ', ')" }
    ''
}

function Test-EpsSettingRisky {
    <# A change the catalog asks a person to confirm (confirm: on / off / value / widen / narrow / raise / change) is a
       WEAKENING or risky change: from an application it is HELD for a person. PURE. #>
    param([Parameter(Mandatory)]$Entry, [AllowEmptyString()][string]$Before, [AllowEmptyString()][string]$After)
    foreach ($c in @($Entry.confirm | Where-Object { $_ })) {
        switch ("$($c.when)") {
            'on' { if ($After -eq 'true' -and $Before -ne 'true') { return $true } }
            'off' { if ($After -eq 'false' -and $Before -ne 'false') { return $true } }
            'value' { if ($After -eq "$($c.value)" -and $Before -ne "$($c.value)") { return $true } }
            'change' { if ($After -ne $Before) { return $true } }
            'raise' { $b = 0.0; $a = 0.0; if ([double]::TryParse($After, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$a) -and (-not [double]::TryParse($Before, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$b) -or $a -gt $b)) { return $true } }
            { $_ -in 'widen', 'narrow' } {
                $bl = @(try { $Before | ConvertFrom-Json } catch { @() }); $al = @(try { $After | ConvertFrom-Json } catch { @() })
                if ($c.when -eq 'widen' -and @($al | Where-Object { $bl -notcontains $_ }).Count) { return $true }
                if ($c.when -eq 'narrow' -and @($bl | Where-Object { $al -notcontains $_ }).Count) { return $true }
            }
        }
    }
    $false
}

function Get-EpsAppSettingsExport {
    # GET /api/app/settings/export: every setting of the catalog, its value, its tier; person-only ones read-only and
    # marked; a secret reference never carries its value (rule: never a secret value)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $vals = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Value FROM eps.Setting')) { $vals["$($r.Name)"] = "$($r.Value)" }
    $rows = foreach ($e in @((Get-EpsSettingsCatalog).Catalog.settings)) {
        $tier = Get-EpsApiTier -SettingKey $e.key
        $secret = "$($e.key)" -match 'Secret$'
        [ordered]@{ key = $e.key; group = $e.group; label = $e.label; type = $e.type
            value = $(if ($secret) { $null } elseif ($vals.ContainsKey("$($e.key)")) { $vals["$($e.key)"] } else { "$($e.default)" })
            valueOmitted = $secret; isDefault = -not $vals.ContainsKey("$($e.key)")
            tier = $tier; personOnly = ($tier -eq 'person'); personOnlyReason = $(if ($tier -eq 'person') { Get-EpsApiPersonOnlyReason "setting:$($e.key)" })
            heldForSuperAdmin = ($e.role -eq 'SuperAdmin'); editable = ($e.editable -ne $false) }
    }
    [ordered]@{ product = 'entrapolicysuite'; exportedAtUtc = [datetime]::UtcNow.ToString('o'); note = 'Import with POST /api/app/settings/import?preview=1 first: person-only settings are refused (403).'; settings = @($rows) }
}

function Get-EpsAppSettingsImportPlan {
    <# POST /api/app/settings/import body { settings: { key: value, ... }, reason }: per setting new / same / refused, and
       what happens to each change from THIS application (commit / hold). A person-only key refuses the whole import (403,
       named). PURE given -Current (key -> stored value) and the catalog. #>
    param([Parameter(Mandatory)]$Settings, [Parameter(Mandatory)][hashtable]$Current, [Parameter(Mandatory)][string]$Role)
    $items = [System.Collections.Generic.List[object]]::new(); $person = [System.Collections.Generic.List[string]]::new(); $bad = [System.Collections.Generic.List[string]]::new()
    if ($Settings -isnot [System.Management.Automation.PSCustomObject]) { return @{ Status = 400; Error = 'settings must be an object of key: value' } }
    foreach ($p in $Settings.PSObject.Properties) {
        $k = "$($p.Name)"; $e = Get-EpsSettingEntry $k
        if (-not $e) { $bad.Add("$k (no such setting)"); continue }
        if ((Get-EpsApiTier -SettingKey $k) -eq 'person') { $person.Add("$k ($(Get-EpsApiPersonOnlyReason "setting:$k"))"); continue }
        if ($e.editable -eq $false) { $bad.Add("$k (set by $($e.setBy))"); continue }
        $v = ConvertTo-EpsSettingValue -Entry $e -Value $p.Value
        if (-not $v.Ok) { $bad.Add("$k ($($v.Error))"); continue }
        $before = if ($Current.ContainsKey($k)) { $Current[$k] } else { "$($e.default)" }
        if ($before -eq $v.Value) { $items.Add([ordered]@{ key = $k; before = $before; after = $v.Value; change = 'same'; do = 'nothing' }); continue }
        $items.Add([ordered]@{ key = $k; before = $before; after = $v.Value; change = 'changed'; superAdmin = ($e.role -eq 'SuperAdmin'); risky = (Test-EpsSettingRisky -Entry $e -Before $before -After $v.Value) })
    }
    if ($person.Count) { return @{ Status = 403; Error = "person-only setting(s) are never imported by an application: $($person -join '; ')" } }
    if ($bad.Count) { return @{ Status = 400; Error = "refused: $($bad -join '; ')" } }
    $changed = @($items | Where-Object { $_.change -eq 'changed' })
    $mass = $changed.Count -gt $script:EpsAppApiMassSettings
    foreach ($i in $changed) {
        $d = Get-EpsApiDecision -Role $Role -Tier 'setting' -NeedsSuperAdmin:($i.superAdmin -or $i.risky -or $mass)
        $i.do = $d.Do; $i.why = $(if ($d.Do -eq 'hold' -and $mass) { "more than $script:EpsAppApiMassSettings settings at once: held for a person" } elseif ($d.Do -eq 'hold' -and $i.risky -and -not $i.superAdmin) { 'a change a person confirms (weakening or risky): held for a person' } else { $d.Why })
    }
    @{ Status = 200; Items = @($items); Changed = $changed.Count; Mass = $mass }
}

function Invoke-EpsAppApiRequest {
    <# One request on /api/app/*. -Request as Invoke-EpsWebRequest's; -Ctx the web app's. Returns a response (New-EpsWebResponse). #>
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Ctx)
    $method = "$($Request.Method)".ToUpperInvariant(); $path = "$($Request.Path)"; $h = $Request.Headers
    $cs = $Ctx.ConnectionString; $correlation = [guid]::NewGuid()
    $deny = { param($status, $public, $detail, $actor)
        [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'api.app.refused' -Actor $(if ($actor) { $actor } else { 'unknown' }) -Target "$method $path" -Outcome 'refused' -OutcomeText $detail -CorrelationId $correlation)
        New-EpsWebResponse -Status $status -Body @{ error = $public; correlationId = "$correlation" } }
    # rule 8: no CORS on /api/app/* - a browser (Origin) never calls it; a preflight is refused
    if ($method -eq 'OPTIONS' -or "$($h['Origin'])".Trim()) { return (& $deny 403 'refused' 'a browser request (Origin / preflight) on the API for applications') }
    # the application's OWN bearer token - never the platform's browser-session token
    $tok = if ("$($h['Authorization'])" -match '^\s*Bearer\s+(\S+)\s*$') { $Matches[1] } else { '' }
    $cfg = $Ctx.AuthConfig
    $t = Test-EpsAppAccessToken -Token $tok -Jwks (Get-EpsJwks -Config $cfg) -Config $cfg
    if (-not $t.trusted -and $t.unknownKid) { $t = Test-EpsAppAccessToken -Token $tok -Jwks (Get-EpsJwks -Config $cfg -Refresh) -Config $cfg }
    if (-not $t.trusted) { return (& $deny 401 'not signed in' "token: $($t.reason)") }
    $actor = $t.identity
    $role = Get-EpsApiAppRole -ConnectionString $cs -AppId $t.appId
    if (-not $role) { return (& $deny 403 'refused' 'the application is not on the API list (Security.ApiApps / Security.SupportApp)' $actor) }
    if (-not (Test-EpsAppApiRate -AppId $t.appId)) { return (& $deny 429 'too many requests - wait a minute' "over $script:EpsAppApiPerMinute requests a minute" $actor) }
    if ("$($Request.Body)".Length -gt $script:EpsAppApiMaxBody) { return (& $deny 413 'the body is too large' "body over $script:EpsAppApiMaxBody bytes" $actor) }
    $body = $null
    if ($method -ne 'GET') {
        if ("$($h['Content-Type'])" -notmatch '^application/json') { return (& $deny 415 'send application/json' 'not JSON' $actor) }
        try { $body = if ("$($Request.Body)".Trim()) { $Request.Body | ConvertFrom-Json } else { [pscustomobject]@{} } } catch { return (& $deny 400 'the body is not JSON' 'not JSON' $actor) }
    }
    # the caller as the person path builds it: EPS acts with its own identity; the token only travels into the engine's
    # own re-check of the request (the signed request), never to another service
    $caller = @{ trusted = $true; identity = $actor; objectId = $t.objectId; name = "application $($t.appId)"; token = $tok; verifiedAtUtc = [datetime]::UtcNow }
    $c = @{ Ctx = $Ctx; Caller = $caller; Role = $(if ($role -in 'Admin', 'Support') { 'Admin' } else { 'Reader' }); AppRole = $role; Query = $(if ($Request.Query) { $Request.Query } else { @{} }); Body = $body; Correlation = $correlation; Headers = $h; Via = 'app' }
    $need = { param($r) if ($role -notin $r) { & $deny 403 'refused' "needs the $($r -join ' or ') role (the application is $role)" $actor } }
    $res = $null
    try {
        switch -Regex ("$method $path") {
            '^GET /api/app/whoami$' { $res = New-EpsWebResponse -Body @{ appId = $t.appId; role = $role; tenantId = $cfg.TenantId; version = $Ctx.Version } ; break }
            '^GET /api/app/settings/export$' {
                $x = Get-EpsAppSettingsExport -ConnectionString $cs
                [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'api.app.settings.export' -Actor $actor -Target 'Settings' -After @{ settings = @($x.settings).Count } -CorrelationId $correlation)
                $res = New-EpsWebResponse -Body $x; break }
            '^POST /api/app/settings/import$' {
                if ($r = & $need @('Admin')) { return $r }
                if ($why = Test-EpsAppApiSchema -Body $body -Allowed 'settings', 'reason' -Required 'settings') { return (& $deny 400 $why $why $actor) }
                $cur = @{}; foreach ($r0 in @(Invoke-EpsSql -ConnectionString $cs -Query 'SELECT Name, Value FROM eps.Setting')) { $cur["$($r0.Name)"] = "$($r0.Value)" }
                $plan = Get-EpsAppSettingsImportPlan -Settings $body.settings -Current $cur -Role $role
                if ($plan.Status -ne 200) { return (& $deny $plan.Status $plan.Error $plan.Error $actor) }
                if ("$($c.Query['preview'])" -eq '1') {
                    [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'api.app.settings.import.check' -Actor $actor -Target 'Settings' -After @{ changed = $plan.Changed; mass = $plan.Mass } -WhatIf -CorrelationId $correlation)
                    $res = New-EpsWebResponse -Body @{ preview = $true; changed = $plan.Changed; items = $plan.Items; text = "$($plan.Changed) setting(s) would change; nothing was written." }; break
                }
                $out = foreach ($i in @($plan.Items | Where-Object { $_.change -eq 'changed' })) {
                    $p2 = "/api/settings/$($i.key)"; $b2 = [pscustomobject]@{ value = $i.after; reason = "$($body.reason)" }; if ($cur.ContainsKey($i.key)) { $b2 | Add-Member -NotePropertyName expected -NotePropertyValue $i.before }   # the stored value as read (a setting never saved has none)
                    if ($i.do -eq 'commit') {
                        $c2 = $c.Clone(); $c2.Body = $b2
                        $rq = New-EpsSignedJobRequest -Ctx $c2 -Job 'Config' -Mode 'Apply' -Scope ([ordered]@{ method = 'PUT'; path = $p2; body = $b2 })
                        [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'config.request' -Actor $actor -Target "PUT $p2" -Reason "$($body.reason)" -After @{ requestId = $rq } -CorrelationId $correlation)
                        [ordered]@{ key = $i.key; do = 'commit'; requestId = $rq; text = 'requested: the engine applies it within 5 minutes' }
                    } elseif ($i.do -eq 'hold') {
                        $st = @{ ObjectType = 'Setting'; Entity = 'Setting'; Key = $i.key; Op = 'Update'; Summary = "Setting $($i.key) = $($i.after) (from application $($t.appId))"; Before = $i.before }
                        $pid0 = Add-EpsPendingChange -ConnectionString $cs -Stage $st -Action 'setting.change' -Method 'PUT' -Path $p2 -Body $b2 -By $actor
                        [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'queue.stage' -Actor $actor -Target "PendingChange|$pid0 (Setting $($i.key))" -Reason "$($body.reason)" -After @{ op = 'Update'; why = $i.why } -CorrelationId $correlation)
                        [ordered]@{ key = $i.key; do = 'hold'; pendingId = $pid0; text = "held for a person in the commit queue (#$pid0): $($i.why)" }
                    } else { [ordered]@{ key = $i.key; do = 'refuse'; text = $i.why } }
                }
                $res = New-EpsWebResponse -Status 202 -Body @{ preview = $false; items = @($out); text = "$(@($out | Where-Object { $_.do -eq 'commit' }).Count) requested, $(@($out | Where-Object { $_.do -eq 'hold' }).Count) held for a person." }; break }
            '^POST /api/app/support/fix$' {
                if ($r = & $need @('Support')) { return $r }
                $res = Invoke-EpsAppSupportFix -Context $c -Correlation $correlation -Deny $deny; break }
            '^POST /api/app/proposals$' {
                if ($r = & $need @('Admin')) { return $r }
                $res = Invoke-EpsAppProposal -Context $c -Correlation $correlation -Deny $deny; break }
            default { $res = & $deny 404 'no such API' 'no such route' $actor }
        }
    } catch {
        Write-Host "  [app-api] ERROR $method $path ($correlation): $($_.Exception.Message)" -ForegroundColor Red
        $res = & $deny 500 'internal error' "internal error: $($_.Exception.Message)" $actor
    }
    [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'api.app.call' -Actor $actor -Target "$method $path" -Outcome $(if ($res.Status -ge 400) { 'refused' } else { 'ok' }) -After @{ tid = $cfg.TenantId; role = $role; status = $res.Status } -CorrelationId $correlation)
    $res
}

function Invoke-EpsAppSupportFix {
    <# POST /api/app/support/fix { failureId, itemKey, fixId, reason } (§12.30): ONLY a fix the catalog offers for that
       failure key, through that route's own handler (validation, journal, audit). The reason carries the SUP ticket id. #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][guid]$Correlation, [Parameter(Mandatory)][scriptblock]$Deny)
    $b = $Context.Body; $actor = $Context.Caller.identity; $cs = $Context.Ctx.ConnectionString
    if ($why = Test-EpsAppApiSchema -Body $b -Allowed 'failureId', 'itemKey', 'fixId', 'reason' -Required 'failureId', 'fixId', 'reason') { return (& $Deny 400 $why $why $actor) }
    if ("$($b.reason)" -notmatch '\bSUP-\d{4}-\d{5}\b') { return (& $Deny 400 'reason must name the SUP ticket (SUP-yyyy-nnnnn)' 'no SUP ticket id' $actor) }
    $fid = "$($b.fixId)"; $fx = $script:EpsSupportFixCatalog[$fid]
    if (-not $fx -or @(Get-EpsSupportFixes -FailureKey "$($b.failureId)") -notcontains $fid) { return (& $Deny 400 'this fix is not offered for this failure' "fix '$fid' not offered for '$($b.failureId)'" $actor) }
    if ((Get-EpsApiTier -Action $fx.Action) -ne 'setting') { return (& $Deny 403 'refused' "fix '$fid' is not tier 1" $actor) }
    $key = "$($b.itemKey)".Trim()
    if ($key -notmatch $fx.KeyPattern) { return (& $Deny 400 "itemKey: $($fx.Key)" "itemKey '$key' does not match $($fx.Key)" $actor) }
    # §12.32: a rate limit for the Support app at this install - at most 25 fixes an hour (more = refused, said; a person can act)
    $lastHour = [int](Invoke-EpsSql -ConnectionString $cs -Scalar -Parameters @{ a = $actor } -Query "SELECT COUNT(*) FROM eps.AuditEvent WHERE Action = 'support.fix' AND Actor = @a AND Outcome = 'ok' AND TsUtc > DATEADD(HOUR, -1, SYSUTCDATETIME())")
    if ($lastHour -ge $script:EpsSupportGrantRowsPerHour) { return (& $Deny 429 "more than $script:EpsSupportGrantRowsPerHour Support fixes in an hour at this install - wait, or a person acts in the app" "Support rate limit ($lastHour in the last hour)" $actor) }
    $path = $fx.Path.Replace('{key}', $key)
    $rb = [ordered]@{ reason = "$($b.reason)" }
    switch ($fid) {
        'worker.package.retry' { $rb.packageId = $key }
        'job.rerun' { $rb.mode = 'Apply' }   # only jobs that read the tenant are in the catalog (KeyPattern)
    }
    $route = $null; $m = $null
    foreach ($r in Get-EpsWebRoutes) { if ($r.Method -eq $fx.Method -and $path -match $r.Pattern -and $r.Action -eq $fx.Action) { $route = $r; $m = $Matches; break } }
    if (-not $route -or -not (Test-EpsWebRole -Have 'Admin' -Need $route.Role)) { return (& $Deny 500 'internal error' "the fix's route is missing or needs $($route.Role)" $actor) }
    $c2 = $Context.Clone(); $c2.Body = [pscustomobject]$rb
    # EVERY fix goes to the engine as ONE signed Config request: the engine checks it again (signature, enrolment, tier),
    # runs the route's own handler, and MAILS the install's admins (Send-EpsSupportActionMail) - one place for all fixes
    $rq = New-EpsSignedJobRequest -Ctx $c2 -Job 'Config' -Mode 'Apply' -Scope ([ordered]@{ method = $fx.Method; path = $path; body = $c2.Body })
    $res = New-EpsWebResponse -Status 202 -Body @{ ok = $true; queued = $true; requestId = $rq; text = 'Requested: the engine applies the fix within 5 minutes and mails your administrators.' }
    $ok = $res.Status -lt 400
    [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'support.fix' -Actor $actor -Target "$fid $($fx.Key)=$key" -Reason "$($b.reason)" -Outcome $(if ($ok) { 'ok' } else { 'refused' }) -OutcomeText "$($res.Body.error)" -After @{ failureId = "$($b.failureId)"; route = "$($fx.Method) $path"; status = $res.Status } -CorrelationId $Correlation)
    $res.Remove('Audit'); $res
}

function Invoke-EpsAppProposal {
    <# POST /api/app/proposals { method, path, body, reason } (§12.31 tier 2, PEOPLE-API-APPROVAL-1): an Admin application
       PROPOSES a grant (maker); it is staged in the commit queue and a PERSON commits it (checker) - never the app. Only a
       route whose change the queue can stage (the tagging configuration) takes a proposal; any other is refused. #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][guid]$Correlation, [Parameter(Mandatory)][scriptblock]$Deny)
    $b = $Context.Body; $actor = $Context.Caller.identity; $cs = $Context.Ctx.ConnectionString
    if ($why = Test-EpsAppApiSchema -Body $b -Allowed 'method', 'path', 'body', 'reason' -Required 'method', 'path') { return (& $Deny 400 $why $why $actor) }
    $pm = "$($b.method)".ToUpperInvariant(); $pp = "$($b.path)"
    if ($pm -notin 'POST', 'PUT', 'DELETE' -or $pp -notmatch '^/api/[A-Za-z0-9/_.%-]{1,300}$' -or $pp -like '/api/app/*') { return (& $Deny 400 'method and path of one change' "bad method/path '$pm $pp'" $actor) }
    $route = $null; $m = $null
    foreach ($r in Get-EpsWebRoutes) { if ($r.Method -eq $pm -and $pp -match $r.Pattern) { $route = $r; $m = $Matches; break } }
    if (-not $route) { return (& $Deny 404 'no such change' "no route for $pm $pp" $actor) }
    $tier = Get-EpsApiTier -Action $route.Action -Method $pm
    if ($tier -ne 'grant') { return (& $Deny 403 "not a proposal: this change is tier $tier$(if ($tier -eq 'setting') { ' (use settings/import)' })" "tier $tier on $pm $pp" $actor) }
    if (-not $route.Stage) { return (& $Deny 403 'a person makes this change in the app (it cannot be proposed yet)' "no Stage for $($route.Action)" $actor) }
    if ($route.Pro -and ($pd = Test-EpsProGate -ConnectionString $cs -Feature "$($route.Pro)")) { return $pd }
    $inner = if ($b.body -is [System.Management.Automation.PSCustomObject]) { $b.body.PSObject.Copy() } else { [pscustomobject]@{} }
    $inner | Add-Member -NotePropertyName reason -NotePropertyValue "$($b.reason)" -Force
    $c2 = $Context.Clone(); $c2.Body = $inner
    $st = & $route.Stage $c2 $m
    if ($st.Refusal) { $st.Refusal.Remove('Audit'); return $st.Refusal }
    $pid0 = Add-EpsPendingChange -ConnectionString $cs -Stage $st -Action $route.Action -Method $pm -Path $pp -Body $inner -By $actor
    [void](Write-EpsAuditEvent -ConnectionString $cs -Action 'queue.stage' -Actor $actor -Target "PendingChange|$pid0 ($($st.Entity) $($st.Key))" -Reason "$($b.reason)" -After @{ op = $st.Op; summary = $st.Summary; proposedBy = 'application' } -CorrelationId $Correlation)
    New-EpsWebResponse -Status 202 -Body @{ ok = $true; staged = $true; pendingId = $pid0; text = "Proposed (#$pid0): $($st.Summary). A person commits it on the Commit queue page; the application never does." }
}
