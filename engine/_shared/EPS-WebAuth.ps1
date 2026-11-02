# EntraPolicySuite -- who is calling the web app, and what may they do (DESIGN §2; framework §12.11g + §12.11f).
#
# The web app runs ONLY behind the shared sign-in front (FRAMEWORK/signin-front, 1.4.x): the front is the only thing the
# ingress reaches, this app listens on 127.0.0.1, and the front forwards exactly one identity - 'Authorization: Bearer
# <access token for this app's own API scope>'. No Easy Auth (owner 2026-10-30: "we are not using easy auth"), no
# X-MS-* header is ever read. The front's contract item 4: the app verifies that token ITSELF on every request (RS256
# against the tenant's keys, issuer pinned to the tenant, audience pinned to this app, exp / nbf, the scope) and refuses
# anything else. The older ID-token form (front < 1.4.0) is NOT accepted: a new product starts on the recommended one.
#
# The same verification is the engine's check of a SIGNED REQUEST (§12.11f item 2): the web app stores the caller's
# token with the time it verified it on every request that leads to an outside change; the job verifies it again
# (signature, issuer, audience, iat <= verified <= exp, the user's role) before it acts.
#
# The JWT primitives are PIM's (engine/_shared/PIM-HostedAuth.ps1), copied - not shared - on purpose (isolation over DRY).

Set-StrictMode -Off

function ConvertFrom-EpsBase64Url {
    param([string]$Text)
    $s = "$Text".Trim(); if (-not $s) { return $null }
    $s = $s.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { return $null } }
    try { [Convert]::FromBase64String($s) } catch { $null }
}

function Get-EpsJwtParts {
    # a compact JWS -> header, payload, signature, the exact signing input; $null unless well-formed
    param([string]$Token)
    $parts = "$Token".Trim() -split '\.'
    if ($parts.Count -ne 3 -or @($parts | Where-Object { -not $_ }).Count) { return $null }
    $seg = { param($p) $b = ConvertFrom-EpsBase64Url $p; if ($null -eq $b) { return $null }; try { [Text.Encoding]::UTF8.GetString($b) | ConvertFrom-Json } catch { $null } }
    $h = & $seg $parts[0]; $p = & $seg $parts[1]
    if ($null -eq $h -or $null -eq $p) { return $null }
    [pscustomobject]@{ header = $h; payload = $p; signature = $parts[2]; signingInput = "$($parts[0]).$($parts[1])" }
}

function Test-EpsJwtSignature {
    # RS256/384/512 against a JWKS (@{ keys = @(@{ kid; kty; n; e }) }). 'none' and HMAC are refused (alg confusion).
    param([Parameter(Mandatory)]$Jwt, $Jwks)
    $hash = switch ("$($Jwt.header.alg)".ToUpperInvariant()) { 'RS256' { [Security.Cryptography.HashAlgorithmName]::SHA256 } 'RS384' { [Security.Cryptography.HashAlgorithmName]::SHA384 } 'RS512' { [Security.Cryptography.HashAlgorithmName]::SHA512 } default { $null } }
    if (-not $hash) { return @{ valid = $false; reason = "alg '$($Jwt.header.alg)' refused (RS256/384/512 only)" } }
    $kid = "$($Jwt.header.kid)"
    $key = @(@($Jwks.keys) | Where-Object { $_ -and (-not $kid -or "$($_.kid)" -eq $kid) -and (-not "$($_.kty)" -or "$($_.kty)" -eq 'RSA') })[0]
    if (-not $key) { return @{ valid = $false; reason = "no key for kid '$kid'"; unknownKid = $true } }
    $n = ConvertFrom-EpsBase64Url "$($key.n)"; $e = ConvertFrom-EpsBase64Url "$($key.e)"; $sig = ConvertFrom-EpsBase64Url "$($Jwt.signature)"
    if ($null -eq $n -or $null -eq $e -or $null -eq $sig) { return @{ valid = $false; reason = 'key or signature unreadable' } }
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $prm = [Security.Cryptography.RSAParameters]::new(); $prm.Modulus = $n; $prm.Exponent = $e; $rsa.ImportParameters($prm)
        if ($rsa.VerifyData([Text.Encoding]::ASCII.GetBytes($Jwt.signingInput), $sig, $hash, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { return @{ valid = $true; reason = 'signature verified' } }
        @{ valid = $false; reason = 'signature verification FAILED' }
    } catch { @{ valid = $false; reason = "signature check errored: $($_.Exception.Message)" } } finally { $rsa.Dispose() }
}

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
    $jwt = Get-EpsJwtParts -Token $Token
    if (-not $jwt) { return (& $no 'the token is not a well-formed JWT') }
    if (-not $Jwks) { return (& $no 'the tenant''s signing keys are not available (failing closed)') }
    $sig = Test-EpsJwtSignature -Jwt $jwt -Jwks $Jwks
    if (-not $sig.valid) { $x = & $no "signature: $($sig.reason)"; $x.unknownKid = [bool]$sig.unknownKid; return $x }
    $p = $jwt.payload
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

function Resolve-EpsWebCaller {
    # The request's caller from its Authorization header; an unknown kid re-reads the keys once (Entra rolls them).
    param([string]$Authorization, [Parameter(Mandatory)]$Config)
    $tok = if ("$Authorization" -match '^\s*Bearer\s+(\S+)\s*$') { $Matches[1] } else { '' }
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
