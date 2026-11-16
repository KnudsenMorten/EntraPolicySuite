# EntraPolicySuite -- who is calling the web app, and what may they do (DESIGN §2; framework §12.11g + §12.11f).
#
# 2.1.35 (owner 2026-11-14, superseding his 2026-10-30 "we are not using easy auth"): the web app runs behind
# Microsoft's BUILT-IN Container Apps sign-in. A browser session's access token for this app's own API scope arrives in
# the platform's X-MS-TOKEN-AAD-ACCESS-TOKEN (its token store); a script / MCP client sends its own 'Authorization:
# Bearer'. The platform's principal headers are never read. (An install not switched yet still runs behind the
# older sign-in front, which forwards the bearer.) Either way the app verifies the token ITSELF on every request (RS256
# against the tenant's keys, issuer pinned to the tenant, audience pinned to this app, exp / nbf, the scope) and refuses
# anything else. The older ID-token form (front < 1.4.0) is NOT accepted: a new product starts on the recommended one.
#
# The same verification is the engine's check of a SIGNED REQUEST (§12.11f item 2): the web app stores the caller's
# token with the time it verified it on every request that leads to an outside change; the job verifies it again
# (signature, issuer, audience, iat <= verified <= exp, the user's role) before it acts.
#
# 2.1.42: the token's form, signature, issuer and audience are checked by MICROSOFT's library (JsonWebTokenHandler) - EPS has no hand-written JWT code.

Set-StrictMode -Off

function Get-EpsWebAuthConfig {
    # What a token must say. Both pins are REQUIRED: with no issuer any tenant's token verifies (Entra's keys are shared),
    # with no audience any app's token for this tenant does. Missing = every request refused (fail closed).
    param([string]$TenantId = $env:EPS_TENANT_ID, [string]$ClientId = $env:EPS_WEB_CLIENT_ID, [string]$Scope = $(if ($env:EPS_WEB_SCOPE) { $env:EPS_WEB_SCOPE } else { 'user_impersonation' }))
    $t = "$TenantId".Trim(); $c = "$ClientId".Trim()
    [pscustomobject]@{
        TenantId  = $t
        Issuers   = @(if ($t) { "https://sts.windows.net/$t/"; "https://login.microsoftonline.com/$t/v2.0" })
        Audiences = @(if ($c) { $c; "api://$c" })
        Scope     = "$Scope".Trim()
        JwksUri   = $(if ($t) { "https://login.microsoftonline.com/$t/discovery/v2.0/keys" })
    }
}

$script:EpsJwksCache = @{ Keys = $null; At = [datetime]::MinValue; Refreshed = [datetime]::MinValue }
function Get-EpsJwks {
    # The tenant's signing keys, cached an hour; -Refresh (an unknown kid: Entra rolled its keys) at most every 5 min.
    param([Parameter(Mandatory)]$Config, [switch]$Refresh)
    $c = $script:EpsJwksCache; $now = [datetime]::UtcNow
    $stale = -not $c.Keys -or ($now - $c.At).TotalHours -ge 1 -or ($Refresh -and ($now - $c.Refreshed).TotalMinutes -ge 5)
    if ($stale -and $Config.JwksUri) {
        try {
            $r = if ($global:EPS_JwksOverride) { & $global:EPS_JwksOverride $Config.JwksUri } else { Invoke-RestMethod -Uri $Config.JwksUri -TimeoutSec 15 }
            if (@($r.keys).Count) { $c.Keys = $r; $c.At = $now }
        } catch { Write-Warning "[auth] the tenant's signing keys could not be read: $($_.Exception.Message)" }
        if ($Refresh) { $c.Refreshed = $now }
    }
    $c.Keys
}

$script:EpsIdentityModelFiles = @('Microsoft.IdentityModel.Abstractions', 'Microsoft.IdentityModel.Logging', 'Microsoft.IdentityModel.Tokens', 'Microsoft.IdentityModel.JsonWebTokens')
function Initialize-EpsIdentityModel {
    <#
      Loads Microsoft's token library once: the container image carries it pinned (EPS_IDENTITYMODEL_DIR, Dockerfile stage
      'idm', each file's SHA-256 checked at build); a .NET SDK's own copy is used where no folder is set (the test runner).
      Not loadable = $false and every token is refused (fail closed).
    #>
    if ('Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler' -as [type]) { return $true }
    $dirs = @(@("$env:EPS_IDENTITYMODEL_DIR") | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if (-not $dirs.Count) {
        $dirs = @(Get-ChildItem -Path '/usr/share/dotnet/sdk', "$env:ProgramFiles\dotnet\sdk" -Recurse -Filter 'Microsoft.IdentityModel.JsonWebTokens.dll' -ErrorAction SilentlyContinue |
                  Sort-Object { $_.VersionInfo.FileVersion } -Descending | Select-Object -First 1 | ForEach-Object { $_.DirectoryName })
    }
    foreach ($d in $dirs) {
        try {
            foreach ($n in $script:EpsIdentityModelFiles) { $f = Join-Path $d "$n.dll"; if (Test-Path -LiteralPath $f) { [void][System.Reflection.Assembly]::LoadFrom($f) } }
            if ('Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler' -as [type]) { return $true }
        } catch { Write-Warning "[auth] Microsoft's token library could not be loaded from $d`: $($_.Exception.Message)" }
    }
    $false
}

function Test-EpsTokenWithMicrosoft {
    <#
      The token checked by Microsoft's JsonWebTokenHandler against the tenant's keys: signed (RS256/384/512 only), the
      issuer and the audience pinned. The lifetime is the caller's step (it checks it at its own time). Returns
      @{ valid; reason; unknownKid; payload } - payload = the claims Microsoft read (exp, nbf, iat, tid, scp, oid, ...).
    #>
    param([Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)]$Jwks, [Parameter(Mandatory)]$Config)
    if (-not (Initialize-EpsIdentityModel)) { return @{ valid = $false; reason = 'Microsoft''s token library is not available (failing closed)' } }
    try {
        $ks = [Microsoft.IdentityModel.Tokens.JsonWebKeySet]::new(($Jwks | ConvertTo-Json -Depth 8 -Compress))
        $p = [Microsoft.IdentityModel.Tokens.TokenValidationParameters]::new()
        $p.ValidIssuers = [string[]]@($Config.Issuers); $p.ValidAudiences = [string[]]@($Config.Audiences)
        $p.IssuerSigningKeys = $ks.GetSigningKeys(); $p.ValidAlgorithms = [string[]]@('RS256', 'RS384', 'RS512')
        $p.ValidateIssuer = $true; $p.ValidateAudience = $true; $p.ValidateIssuerSigningKey = $true; $p.RequireSignedTokens = $true
        $p.ValidateLifetime = $false; $p.RequireExpirationTime = $true
        $r = [Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler]::new().ValidateTokenAsync($Token, $p).GetAwaiter().GetResult()
        if (-not $r.IsValid) {
            $ex = $r.Exception; $kind = if ($ex) { $ex.GetType().Name } else { 'invalid' }
            return @{ valid = $false; unknownKid = ($kind -eq 'SecurityTokenSignatureKeyNotFoundException'); reason = "Microsoft's token check refused it: $kind" }
        }
        $c = @{}; foreach ($k in $r.Claims.Keys) { $c[$k] = $r.Claims[$k] }
        @{ valid = $true; reason = 'verified by Microsoft''s token library'; payload = [pscustomobject]$c }
    } catch { @{ valid = $false; reason = "Microsoft's token check failed: $($_.Exception.GetType().Name)" } }
}

function Test-EpsIdentityModelSelfCheck {
    <#
      2.1.43 (Invardia 2026-11-15, the proof standard for a release of the web sign-in library): run at the web app's START,
      with no person. Loads Microsoft's library and sends three made-up credentials through the SAME path a request takes
      (Test-EpsAccessToken), with a throwaway key and made-up tenant / app ids that match nothing real:
        1. one made with the throwaway key  -> must be ACCEPTED (the library loads and the whole path works)
        2. one made with ANOTHER key        -> must be REFUSED by Microsoft's library
        3. one with alg none                -> must be REFUSED
      @{ ok; detail }. Not ok = the caller does not start (fail closed, shows as an unhealthy revision at ring 0).
    #>
    if (-not (Initialize-EpsIdentityModel)) { return @{ ok = $false; detail = 'Microsoft''s library could not be loaded' } }
    $b64u = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $tid = [guid]::NewGuid().ToString(); $app = [guid]::NewGuid().ToString()
    $cfg = Get-EpsWebAuthConfig -TenantId $tid -ClientId $app
    $good = [Security.Cryptography.RSA]::Create(2048); $other = [Security.Cryptography.RSA]::Create(2048)
    try {
        $rp = $good.ExportParameters($false)
        $jwks = @{ keys = @(@{ kid = 'selfcheck'; kty = 'RSA'; use = 'sig'; n = (& $b64u $rp.Modulus); e = (& $b64u $rp.Exponent) }) }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $body = & $b64u ([Text.Encoding]::UTF8.GetBytes(([ordered]@{ iss = "https://login.microsoftonline.com/$tid/v2.0"; tid = $tid; aud = $app; scp = $cfg.Scope
            oid = [guid]::NewGuid().ToString(); preferred_username = 'selfcheck@example.invalid'; name = 'self-check'; iat = $now - 60; nbf = $now - 60; exp = $now + 600 } | ConvertTo-Json -Compress)))
        $make = { param($key, $alg)
            $h = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ alg = $alg; typ = 'JWT'; kid = 'selfcheck' } | ConvertTo-Json -Compress)))
            if (-not $key) { return "$h.$body." }
            "$h.$body.$(& $b64u ($key.SignData([Text.Encoding]::ASCII.GetBytes("$h.$body"), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)))" }
        $r1 = Test-EpsAccessToken -Token (& $make $good 'RS256') -Jwks $jwks -Config $cfg
        if (-not $r1.trusted) { return @{ ok = $false; detail = "the accepted case was refused: $($r1.reason)" } }
        $r2 = Test-EpsAccessToken -Token (& $make $other 'RS256') -Jwks $jwks -Config $cfg
        if ($r2.trusted -or "$($r2.reason)" -notmatch 'Microsoft') { return @{ ok = $false; detail = "the other-key case was not refused by Microsoft's library: $($r2.reason)" } }
        $r3 = Test-EpsAccessToken -Token (& $make $null 'none') -Jwks $jwks -Config $cfg
        if ($r3.trusted) { return @{ ok = $false; detail = 'the alg none case was accepted' } }
        $v = ([Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler].Assembly.GetName().Version)
        @{ ok = $true; detail = "Microsoft's library $v loaded; 1 accepted, 2 refused as expected" }
    } catch { @{ ok = $false; detail = "the self-check failed: $($_.Exception.GetType().Name): $($_.Exception.Message)" } }
    finally { $good.Dispose(); $other.Dispose() }
}

function Test-EpsAccessToken {
    <#
      PURE given -Jwks: is this the front's access token for THIS app, from THIS tenant, now? @{ trusted; identity;
      objectId; name; reason; exp; iat }. Fails closed on: pins missing, no / malformed token, no keys, bad signature,
      issuer / tid / audience / exp / nbf, no scope or another scope, no user (an app-only token has no scp).
    #>
    param([string]$Token, $Jwks, [Parameter(Mandatory)]$Config, [datetime]$NowUtc = [datetime]::UtcNow, [int]$SkewSeconds = 300)
    $no = { param($why) @{ trusted = $false; identity = ''; objectId = ''; reason = $why } }
    if (-not $Config.Issuers.Count -or -not $Config.Audiences.Count -or -not $Config.Scope) { return (& $no 'the web app is not configured: EPS_TENANT_ID and EPS_WEB_CLIENT_ID must both be set (failing closed)') }
    if (-not "$Token".Trim()) { return (& $no 'no token on the request') }
    if (-not $Jwks) { return (& $no 'the tenant''s signing keys are not available (failing closed)') }
    # 2.1.42 (owner 2026-11-15 "ms standard authn, not our own code"; framework c5704c10, option A): the token's FORM, its
    # SIGNATURE against Entra's keys, the algorithm, the ISSUER and the AUDIENCE are checked by MICROSOFT's library
    # (Microsoft.IdentityModel.JsonWebTokens JsonWebTokenHandler) - no hand-written JWT parsing or signature code. EPS keeps
    # what is authorization or EPS-specific: the lifetime at a GIVEN time (the engine checks a queued request at the time
    # the web app verified it), the tenant id, the scope and that the token names a person.
    $ms = Test-EpsTokenWithMicrosoft -Token $Token -Jwks $Jwks -Config $Config
    if (-not $ms.valid) { $x = & $no $ms.reason; $x.unknownKid = [bool]$ms.unknownKid; return $x }
    $p = $ms.payload
    if ("$($p.exp)" -notmatch '^\d+$') { return (& $no 'no exp claim') }
    $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$p.exp).UtcDateTime
    if ($NowUtc -gt $exp.AddSeconds($SkewSeconds)) { return (& $no "expired at $($exp.ToString('o'))") }
    if ("$($p.nbf)" -match '^\d+$' -and $NowUtc -lt [DateTimeOffset]::FromUnixTimeSeconds([long]$p.nbf).UtcDateTime.AddSeconds(-$SkewSeconds)) { return (& $no 'not valid yet (nbf)') }
    if ($Config.Issuers -notcontains "$($p.iss)") { return (& $no "issuer '$($p.iss)' is not this tenant") }
    if ("$($p.tid)" -and "$($p.tid)" -ne $Config.TenantId) { return (& $no "tid '$($p.tid)' is not this tenant") }
    if (-not @(@($p.aud) | Where-Object { $Config.Audiences -contains "$_" }).Count) { return (& $no "audience '$(@($p.aud) -join ',')' is not this app") }
    $scp = @("$($p.scp)" -split '\s+' | Where-Object { $_ })
    if (-not $scp.Count) { return (& $no 'not a user''s access token (no scp - an ID token or an app-only token is refused)') }
    if ($scp -notcontains $Config.Scope) { return (& $no "scope '$($scp -join ' ')' is not '$($Config.Scope)'") }
    # never the email claim: anyone can be given any address (SEC-AUDIT-1 S7)
    $who = @('preferred_username', 'upn', 'unique_name' | ForEach-Object { "$($p.$_)".Trim() } | Where-Object { $_ })[0]
    if (-not $who -or -not "$($p.oid)") { return (& $no 'the token names no user (preferred_username / upn and oid)') }
    @{ trusted = $true; identity = $who.ToLowerInvariant(); objectId = "$($p.oid)".ToLowerInvariant(); name = "$($p.name)"; reason = 'access token verified'
       exp = $exp; iat = $(if ("$($p.iat)" -match '^\d+$') { [DateTimeOffset]::FromUnixTimeSeconds([long]$p.iat).UtcDateTime } else { $null }) }
}

# ---- an APPLICATION caller (framework §12.30 / §12.31, API security = Microsoft best practice, owner 2026-11-16) -------
# Two layers, both must agree: (1) Entra - the app role below on EPS's own registration, assignment required on its
# enterprise application, so only an ASSIGNED app gets a token at all; (2) EPS - the app's id in the allow-list
# (Security.ApiApps, a person's list: Reader / Admin; Security.SupportApp, the update's enrolment of the tag-found Invardia
# Support app). Only /api/app/* takes an application; the person pages keep refusing app-only tokens (Test-EpsAccessToken).
$script:EpsApiAppRoleValue = 'EPS.Api.Call'
# the fixed tiers (pure data) travel with the auth code, so every caller of the role check has them
. (Join-Path $PSScriptRoot 'EPS-ApiTiers.ps1')

function Test-EpsAppAccessToken {
    <#
      PURE given -Jwks: an APPLICATION's access token for THIS app, from THIS tenant, now (rules 1 + 2): Microsoft's library
      (signature, issuer, audience), a v2 token only, tid = this tenant, exp / nbf, idtyp = app REQUIRED, NO scp (a person's
      token is refused here), the Entra app role EPS.Api.Call, the calling app named (azp). @{ trusted; appId; objectId;
      identity ('app:<appId>'); reason; exp; iat }.
    #>
    param([string]$Token, $Jwks, [Parameter(Mandatory)]$Config, [datetime]$NowUtc = [datetime]::UtcNow, [int]$SkewSeconds = 300)
    $no = { param($why) @{ trusted = $false; appId = ''; identity = ''; objectId = ''; reason = $why } }
    if (-not $Config.TenantId -or -not $Config.Audiences.Count) { return (& $no 'the web app is not configured (failing closed)') }
    if (-not "$Token".Trim()) { return (& $no 'no token on the request') }
    if (-not $Jwks) { return (& $no 'the tenant''s signing keys are not available (failing closed)') }
    $ms = Test-EpsTokenWithMicrosoft -Token $Token -Jwks $Jwks -Config $Config
    if (-not $ms.valid) { $x = & $no $ms.reason; $x.unknownKid = [bool]$ms.unknownKid; return $x }
    $p = $ms.payload
    if ("$($p.iss)" -ne "https://login.microsoftonline.com/$($Config.TenantId)/v2.0") { return (& $no 'not a v2 token of this tenant') }
    if ("$($p.tid)" -ne $Config.TenantId) { return (& $no 'tid is not this tenant') }
    if (-not @(@($p.aud) | Where-Object { $Config.Audiences -contains "$_" }).Count) { return (& $no 'audience is not this app') }
    if ("$($p.exp)" -notmatch '^\d+$') { return (& $no 'no exp claim') }
    $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$p.exp).UtcDateTime
    if ($NowUtc -gt $exp.AddSeconds($SkewSeconds)) { return (& $no 'expired') }
    if ("$($p.nbf)" -match '^\d+$' -and $NowUtc -lt [DateTimeOffset]::FromUnixTimeSeconds([long]$p.nbf).UtcDateTime.AddSeconds(-$SkewSeconds)) { return (& $no 'not valid yet (nbf)') }
    if ("$($p.idtyp)" -ne 'app') { return (& $no 'not an application token (idtyp is not app)') }
    if ("$($p.scp)".Trim()) { return (& $no 'a delegated (person''s) token is refused on the API for applications') }
    if (@($p.roles) -notcontains $script:EpsApiAppRoleValue) { return (& $no "the application is not assigned the $script:EpsApiAppRoleValue role in Entra") }
    $appId = "$($p.azp)".Trim().ToLowerInvariant()
    if ($appId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return (& $no 'the token names no calling application (azp)') }
    @{ trusted = $true; appId = $appId; identity = "app:$appId"; objectId = "$($p.oid)".ToLowerInvariant(); reason = 'application token verified'; exp = $exp
       iat = $(if ("$($p.iat)" -match '^\d+$') { [DateTimeOffset]::FromUnixTimeSeconds([long]$p.iat).UtcDateTime } else { $null }) }
}

function Get-EpsApiAppRole {
    <# Layer 2: the role EPS gives this calling app - Security.SupportApp (the update's Support enrolment) = Support; an
       entry '<appId>:Reader|Admin' of Security.ApiApps (a person's list). Nothing = $null. A store that cannot be read =
       $null (fail closed). -Values: the two settings given (a test); otherwise read from the database. #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$AppId, [hashtable]$Values)
    $a = "$AppId".Trim().ToLowerInvariant(); if (-not $a) { return $null }
    try {
        $sup = if ($Values) { "$($Values['Security.SupportApp'])" } else { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Security.SupportApp' -Default '')" }
        $lst = if ($Values) { "$($Values['Security.ApiApps'])" } else { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Security.ApiApps' -Default '[]')" }
        if ($sup.Trim().ToLowerInvariant() -eq $a) { return 'Support' }
        $items = @(try { $lst | ConvertFrom-Json } catch { @() })
        $hit = @($items | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -match "^$([regex]::Escape($a)):(reader|admin)$" } | ForEach-Object { ($_ -split ':')[1] })
        if ($hit -contains 'admin') { return 'Admin' }; if ($hit -contains 'reader') { return 'Reader' }
        $null
    } catch { Write-Warning "[auth] the API application list could not be read ($($_.Exception.Message)) - refused"; $null }
}

function Resolve-EpsWebCaller {
    # The request's caller; an unknown kid re-reads the keys once (Entra rolls them). The token is the Authorization
    # header's bearer (a script / MCP client, or the sign-in front), else - 2.1.35, Microsoft's built-in Container Apps
    # sign-in (owner 2026-11-14) - the platform's X-MS-TOKEN-AAD-ACCESS-TOKEN from its token store (a browser session).
    # Either way the SAME verification below (signature, issuer, audience, time, scope): a header is never trusted as such.
    param([string]$Authorization, [string]$PlatformAccessToken, [Parameter(Mandatory)]$Config)
    $tok = if ("$Authorization" -match '^\s*Bearer\s+(\S+)\s*$') { $Matches[1] } elseif ("$PlatformAccessToken" -match '^\s*(\S+)\s*$') { $Matches[1] } else { '' }
    $r = Test-EpsAccessToken -Token $tok -Jwks (Get-EpsJwks -Config $Config) -Config $Config
    if (-not $r.trusted -and $r.unknownKid) { $r = Test-EpsAccessToken -Token $tok -Jwks (Get-EpsJwks -Config $Config -Refresh) -Config $Config }
    $r.token = $(if ($r.trusted) { $tok } else { '' })
    $r
}

# ---- roles (DESIGN §2: SuperAdmin / Admin / Reader, fail closed) ------------------------------------------------------
$script:EpsWebRoleRank = @{ Reader = 1; Admin = 2; SuperAdmin = 3 }

function Test-EpsWebRole {
    param([string]$Have, [Parameter(Mandatory)][string]$Need)
    [int]$script:EpsWebRoleRank["$Have"] -ge [int]$script:EpsWebRoleRank[$Need]
}

function Get-EpsWebRole {
    # Who may do what is a row in eps.WebAccess (by object id, else by UPN) - never a file, never an env value, never a
    # default that elevates: a verified user nobody named is a Reader. A store that cannot be read = Reader (fail closed).
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Identity, [string]$ObjectId)
    # §12.31: an application ('app:<appId>', never a person's UPN) has the role its enrolment gives - Admin for Admin and
    # Support (what each may do on top is EPS-ApiTiers' fixed tier), Reader for Reader, nothing enrolled = Reader. Never SuperAdmin.
    if ("$Identity" -like 'app:*') {
        $ar = Get-EpsApiAppRole -ConnectionString $ConnectionString -AppId ("$Identity".Substring(4))
        return $(if ($ar -in 'Admin', 'Support') { 'Admin' } else { 'Reader' })
    }
    try {
        $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ u = $Identity.ToLowerInvariant(); o = "$ObjectId".ToLowerInvariant() } `
            -Query "SELECT Role FROM eps.WebAccess WHERE (ObjectId IS NOT NULL AND LOWER(CONVERT(NVARCHAR(36), ObjectId)) = @o) OR (ObjectId IS NULL AND LOWER(Principal) = @u)")
        $best = @($r | ForEach-Object Role | Sort-Object { -[int]$script:EpsWebRoleRank["$_"] })[0]
        if ($best) { $best } else { 'Reader' }
    } catch { Write-Warning "[auth] eps.WebAccess could not be read ($($_.Exception.Message)) - Reader"; 'Reader' }
}

function Test-EpsSignedRequest {
    <#
      §12.11f item 2: a request that leads to an outside change carries the requester's token and the time the web app
      verified it. The engine checks, before it acts: the signature (the tenant's keys), issuer, audience, scope, that the
      web app's verification time lies inside the token's life (iat <= verified <= exp; NOT "is it valid now" - a queued
      request outlives its token), that the token names -RequestedBy, and that this user holds -NeedRole now.
      @{ valid; reason }.
    #>
    param([string]$Token, [Nullable[datetime]]$VerifiedAtUtc, [string]$RequestedBy, [Parameter(Mandatory)][string]$NeedRole, [Parameter(Mandatory)]$Config, $Jwks, [string]$ConnectionString)
    if (-not "$Token") { return @{ valid = $false; reason = 'the request is not signed (no token)' } }
    if (-not $VerifiedAtUtc) { return @{ valid = $false; reason = 'the request has no verification time' } }
    $v = [datetime]$VerifiedAtUtc   # not .Value: PowerShell hands a [Nullable[datetime]] parameter over as a plain DateTime
    if ("$RequestedBy" -like 'app:*') {
        # §12.31: an APPLICATION's request (tier 1, or a Support fix) - its own token at the verification time, the same app,
        # and BOTH layers now: still enrolled in EPS, with a role that covers Admin (an application never covers SuperAdmin)
        $t = Test-EpsAppAccessToken -Token $Token -Jwks $Jwks -Config $Config -NowUtc $v -SkewSeconds 30
        if (-not $t.trusted) { return @{ valid = $false; reason = "the application's token: $($t.reason)" } }
        if ($t.iat -and $v -lt $t.iat.AddSeconds(-60)) { return @{ valid = $false; reason = 'verified before the token was issued' } }
        if ($t.identity -ne "$RequestedBy".ToLowerInvariant()) { return @{ valid = $false; reason = "the token is $($t.identity)'s, the request names $RequestedBy" } }
        if ($NeedRole -eq 'SuperAdmin') { return @{ valid = $false; reason = 'an application never acts as SuperAdmin' } }
        if ($ConnectionString) {
            $ar = Get-EpsApiAppRole -ConnectionString $ConnectionString -AppId $t.appId
            if ($ar -notin 'Admin', 'Support' -and -not ($NeedRole -eq 'Reader' -and $ar -eq 'Reader')) { return @{ valid = $false; reason = "$($t.identity) is $(if ($ar) { $ar } else { 'not enrolled' }) now, the request needs $NeedRole" } }
        }
        return @{ valid = $true; reason = "signed by $($t.identity)"; identity = $t.identity; objectId = $t.objectId }
    }
    # $v is the DATABASE's time the row was written (schema 11 trigger), so an old token in a new row is out of its life
    $t = Test-EpsAccessToken -Token $Token -Jwks $Jwks -Config $Config -NowUtc $v -SkewSeconds 30
    if (-not $t.trusted) { return @{ valid = $false; reason = "the requester's token: $($t.reason)" } }
    if ($t.iat -and $v -lt $t.iat.AddSeconds(-60)) { return @{ valid = $false; reason = 'verified before the token was issued' } }
    if ($t.identity -ne "$RequestedBy".ToLowerInvariant()) { return @{ valid = $false; reason = "the token is $($t.identity)'s, the request names $RequestedBy" } }
    if ($ConnectionString) {
        $role = Get-EpsWebRole -ConnectionString $ConnectionString -Identity $t.identity -ObjectId $t.objectId
        if (-not (Test-EpsWebRole -Have $role -Need $NeedRole)) { return @{ valid = $false; reason = "$($t.identity) is $role now, the request needs $NeedRole" } }
    }
    @{ valid = $true; reason = "signed by $($t.identity)"; identity = $t.identity; objectId = $t.objectId }
}

function Confirm-EpsJobRequest {
    <#
      The engine's gate on a request it took (job entry). A request that changes nothing outside (Preview) needs no
      signature. Otherwise the signature is checked and the setting Security.SignedRequests decides: 'enforce' (the default
      since 2.0.7, SEC-AUDIT-1) refuses it; 'observe' runs it and says what enforce would have refused. @{ Allow; Text }. -NeedRole: Admin (every request the GUI writes needs Admin).
    #>
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)][string]$ConnectionString, [switch]$ChangesOutside, [string]$NeedRole = 'Admin', $Config = (Get-EpsWebAuthConfig))
    if (-not $ChangesOutside) { return @{ Allow = $true; Text = 'no outside change - no signature needed' } }
    $mode = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Security.SignedRequests' -Default 'enforce')".ToLowerInvariant()
    $jwks = if ($Request.SignedToken -and $Config.JwksUri) { Get-EpsJwks -Config $Config } else { $null }
    $v = Test-EpsSignedRequest -Token $Request.SignedToken -VerifiedAtUtc $Request.SignedVerifiedAtUtc -RequestedBy $Request.RequestedBy -NeedRole $NeedRole -Config $Config -Jwks $jwks -ConnectionString $ConnectionString
    if ($v.valid) { return @{ Allow = $true; Text = "signature ok: $($v.reason)"; Identity = $v.identity; ObjectId = $v.objectId; Verified = $true } }
    if ($mode -eq 'enforce') { return @{ Allow = $false; Text = "REFUSED (Security.SignedRequests = enforce): $($v.reason)" } }
    @{ Allow = $true; Text = "OBSERVE: enforce would refuse this request - $($v.reason)" }
}
