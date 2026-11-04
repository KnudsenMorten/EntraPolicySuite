# EntraPolicySuite -- the PERSON's sign-in for the install and the support scripts (framework NO-AZ: no module, a
# browser sign-in, never device code). PIM's model (PIM-Rest.ps1): authorization code + PKCE on a loopback port,
# with Microsoft's Azure CLI public client - one sign-in serves ARM, Graph and SQL (each audience is minted from the
# one refresh token, which is kept in memory only, never on disk). In Cloud Shell the shell's own token broker
# (MSI_ENDPOINT) is the person.
# Sets $global:EPS_TokenProvider, which EPS-Graph / EPS-Exchange / EPS-Arm / EPS-SqlStore all use.

Set-StrictMode -Off
$script:EpsCliClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI (first-party public client)

function Test-EpsCloudShell { [bool]("$env:AZUREPS_HOST_ENVIRONMENT" -match '^cloud-shell' -or $env:ACC_CLOUD) }

function ConvertFrom-EpsJwt {
    # the claims of a token (no signature check: only to read tid / upn / oid / exp of a token we just received)
    param([Parameter(Mandatory)][string]$Token)
    $p = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

function Get-EpsInteractiveToken {
    <#
    .SYNOPSIS
        A token for -Resource as the signed-in person. The first call opens the browser (auth code + PKCE, loopback);
        later calls for any audience use the refresh token in memory. The token's tenant must be -TenantId.
    #>
    param([Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][string]$TenantId, [int]$TimeoutSeconds = 300)
    $aud = $Resource.TrimEnd('/')
    if (-not $script:EpsTokens) { $script:EpsTokens = @{} }
    $c = $script:EpsTokens["$aud|$TenantId"]
    if ($c -and $c.Expires -gt [datetime]::UtcNow.AddMinutes(2)) { return $c.Token }
    if ((Test-EpsCloudShell) -and $env:MSI_ENDPOINT) {
        $r = Invoke-RestMethod -Uri "$($env:MSI_ENDPOINT)?resource=$([uri]::EscapeDataString($aud))" -Headers @{ Metadata = 'true' } -TimeoutSec 30
        return (Save-EpsToken $aud $TenantId $r.access_token $r.expires_on)
    }
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $scope = "$aud/.default offline_access openid profile"
    if ($script:EpsRefresh -and $script:EpsRefresh.Tenant -eq $TenantId) {
        try {
            $r = Invoke-RestMethod -Method POST -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -Body @{
                client_id = $script:EpsCliClientId; grant_type = 'refresh_token'; refresh_token = $script:EpsRefresh.Token; scope = $scope }
            if ($r.refresh_token) { $script:EpsRefresh.Token = $r.refresh_token }
            return (Save-EpsToken $aud $TenantId $r.access_token ([datetime]::UtcNow.AddSeconds([int]$r.expires_in)))
        } catch { Write-Verbose "refresh failed, signing in again: $($_.Exception.Message)" }
    }
    # authorization code + PKCE on a loopback port (no device code: framework NO-AZ)
    $verifier = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $challenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $state = [guid]::NewGuid().ToString('N')
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $listener.Start()
    try {
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $redirect = "http://localhost:$port/"
        $url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$($script:EpsCliClientId)&response_type=code&response_mode=query" +
               "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state" +
               "&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
        Write-Host "Sign in in the browser window that opens (or open this address): $url" -ForegroundColor Cyan
        if ($env:EPS_SIGNIN_BROWSER -ne 'none') { try { Start-Process $url } catch { } }
        $task = $listener.AcceptTcpClientAsync()
        if (-not $task.Wait($TimeoutSeconds * 1000)) { throw "no sign-in within $TimeoutSeconds s" }
        $client = $task.Result
        try {
            $stream = $client.GetStream(); $reader = [IO.StreamReader]::new($stream)
            $line = $reader.ReadLine()
            $q = if ($line -match '^GET\s+/\?(\S*)\s') { $Matches[1] } else { '' }
            $kv = @{}; foreach ($pair in $q.Split('&')) { $p = $pair.Split('=', 2); if ($p.Count -eq 2) { $kv[$p[0]] = [uri]::UnescapeDataString($p[1]) } }
            $msg = if ($kv.code) { 'Signed in. You can close this window.' } else { "Sign-in failed: $($kv.error_description)" }
            $html = "<html><body style='font-family:sans-serif'><h3>Entra Policy Suite</h3><p>$([Net.WebUtility]::HtmlEncode($msg))</p></body></html>"
            $bytes = [Text.Encoding]::UTF8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $([Text.Encoding]::UTF8.GetByteCount($html))`r`nConnection: close`r`n`r`n$html")
            $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
        } finally { $client.Dispose() }
    } finally { $listener.Stop() }
    if ($kv.state -ne $state) { throw 'sign-in answer with a wrong state - refused' }
    if (-not $kv.code) { throw "sign-in failed: $($kv.error) $($kv.error_description)" }
    $r = Invoke-RestMethod -Method POST -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $script:EpsCliClientId; grant_type = 'authorization_code'; code = $kv.code; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    $claims = ConvertFrom-EpsJwt $r.access_token
    if ($claims.tid -ne $TenantId) { throw "signed in to tenant $($claims.tid), not $TenantId - refused" }
    $script:EpsRefresh = @{ Tenant = $TenantId; Token = $r.refresh_token }
    Save-EpsToken $aud $TenantId $r.access_token ([datetime]::UtcNow.AddSeconds([int]$r.expires_in))
}

function Save-EpsToken($aud, $tenant, $token, $expires) {
    $e = if ($expires -is [datetime]) { $expires } elseif ("$expires" -match '^\d+$') { [DateTimeOffset]::FromUnixTimeSeconds([long]$expires).UtcDateTime } else { [datetime]::UtcNow.AddMinutes(30) }
    $script:EpsTokens["$aud|$tenant"] = @{ Token = $token; Expires = $e }
    $token
}

function Connect-EpsSignedIn {
    # Makes the signed-in person the token source for every EPS library in this process, and returns who it is.
    param([Parameter(Mandatory)][string]$TenantId)
    $global:EPS_SignInTenant = $TenantId
    $global:EPS_TokenProvider = { param($Resource) Get-EpsInteractiveToken -Resource $Resource -TenantId $global:EPS_SignInTenant }
    $c = ConvertFrom-EpsJwt (& $global:EPS_TokenProvider 'https://management.azure.com')
    if (-not ($c.upn -or $c.unique_name -or $c.preferred_username)) { throw 'the install must be run by a person (a user token), not an app' }
    [pscustomobject]@{ TenantId = $c.tid; ObjectId = $c.oid; Upn = $(if ($c.upn) { $c.upn } elseif ($c.preferred_username) { $c.preferred_username } else { $c.unique_name }) }
}
