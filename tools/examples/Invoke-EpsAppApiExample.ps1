#Requires -Version 7.2
<#
.SYNOPSIS
    An example program for the Entra Policy Suite API for applications: it signs in as YOUR application with a certificate
    (or as a managed identity), reads who it is to Entra Policy Suite, exports the settings and - with -Preview - checks an
    import. No module: REST and .NET only. Never a client secret.
.DESCRIPTION
    Before it works, both layers must say yes:
      1. Entra: Set-EpsApiAuth.ps1 -AppId <this application's app id> assigns it the app role EPS.Api.Call.
      2. Entra Policy Suite: a SuperAdmin adds '<app id>:Reader' (or ':Admin') under Administration > Settings > Security >
         API applications.
    The calls: GET /api/app/whoami, GET /api/app/settings/export, POST /api/app/settings/import?preview=1 (Admin; nothing
    is written), POST /api/app/settings/import (Admin; tier 1 settings are requested, the rest held for a person),
    POST /api/app/proposals (Admin; staged for a person to commit). Security controls are never open to an application.
.EXAMPLE
    ./Invoke-EpsAppApiExample.ps1 -TenantId <tenant> -ClientId <your app id> -CertificateThumbprint <thumbprint> -EpsUrl https://<your eps web address> -EpsAppId <eps app id>
.EXAMPLE
    ./Invoke-EpsAppApiExample.ps1 -ManagedIdentity -EpsUrl https://<your eps web address> -EpsAppId <eps app id>
#>
[CmdletBinding(DefaultParameterSetName = 'Certificate')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Certificate')][guid]$TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Certificate')][guid]$ClientId,
    [Parameter(Mandatory, ParameterSetName = 'Certificate')][string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')][switch]$ManagedIdentity,
    [Parameter(ParameterSetName = 'ManagedIdentity')][string]$ManagedIdentityClientId,
    [Parameter(Mandatory)][ValidatePattern('^https://')][string]$EpsUrl,
    [Parameter(Mandatory)][guid]$EpsAppId,
    [hashtable]$Preview
)
$ErrorActionPreference = 'Stop'
$b64u = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-AppToken {
    $scope = "api://$EpsAppId/.default"
    if ($ManagedIdentity) {
        # a managed identity (Azure): the platform's token endpoint, no secret anywhere
        $u = "$env:IDENTITY_ENDPOINT`?api-version=2019-08-01&resource=api://$EpsAppId$(if ($ManagedIdentityClientId) { "&client_id=$ManagedIdentityClientId" })"
        return (Invoke-RestMethod -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER" }).access_token
    }
    # a certificate: a signed client assertion (RFC 7523), the private key never leaves the certificate store
    $cert = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $CertificateThumbprint.ToUpperInvariant())[0]
    if (-not $cert -or -not $cert.HasPrivateKey) { throw "no certificate with a private key for thumbprint $CertificateThumbprint" }
    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"; $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $h = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ alg = 'PS256'; typ = 'JWT'; 'x5t#S256' = (& $b64u $cert.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256)) } | ConvertTo-Json -Compress)))
    $p = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ aud = $aud; iss = "$ClientId"; sub = "$ClientId"; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = $now + 300 } | ConvertTo-Json -Compress)))
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $sig = & $b64u ($rsa.SignData([Text.Encoding]::ASCII.GetBytes("$h.$p"), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pss))
    (Invoke-RestMethod -Method POST -Uri $aud -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = "$ClientId"; scope = $scope; grant_type = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion = "$h.$p.$sig" }).access_token
}

$token = Get-AppToken
$hdr = @{ Authorization = "Bearer $token" }   # never logged, never passed on
$base = $EpsUrl.TrimEnd('/')
$me = Invoke-RestMethod -Uri "$base/api/app/whoami" -Headers $hdr
Write-Host "Signed in as application $($me.appId): role $($me.role) (Entra Policy Suite $($me.version))" -ForegroundColor Cyan
$x = Invoke-RestMethod -Uri "$base/api/app/settings/export" -Headers $hdr
Write-Host "$(@($x.settings).Count) settings; $(@($x.settings | Where-Object personOnly).Count) of them person-only (read only for an application)."
$x.settings | Select-Object key, value, tier | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
if ($Preview) {
    $r = Invoke-RestMethod -Method POST -Uri "$base/api/app/settings/import?preview=1" -Headers $hdr -ContentType 'application/json' -Body (@{ settings = $Preview; reason = 'checked by the example' } | ConvertTo-Json -Depth 5)
    Write-Host $r.text -ForegroundColor Yellow
    $r.items | Select-Object key, before, after, do, why | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
}
