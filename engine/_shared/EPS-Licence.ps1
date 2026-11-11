# Entra Policy Suite -- the Pro licence (INSTALL-PRO, Invardia GO 2026-11-05; owner: "it must be on par with other 2").
#
# The licence FORMAT and its verification are the framework's (LIC-1, sync/_AitLicense.ps1) - copied here, not shared,
# on purpose (isolation over DRY: sync/ is production for ~30 customers and must never be widened for one product):
#   file     { product, payloadB64, signature, signer }      extension .epslicense (Invardia catalogue)
#   payload  { licenseId, customer, sku, features[], tenantIds[], validFrom, validTo, graceDays, limits? }
#   RSA-SHA256 / PKCS#1 over the RAW payload bytes; trusted: the Invardia signer (CN=Invardia-Licensing) and the older
#   platform signer (CN=AutomateIT-Licensing-Service) - the same two public certificates SI and PIM embed.
# Features follow the EDITION, not the file (framework §12.6a): the licence names the edition (sku + an optional signed
# `limits` object = Pro Business); this file maps edition -> features. Everything Community has today stays Community
# (Invardia 2026-11-05: "All EXISTING features stay Community, so no install loses anything").
#
# Editions (Test-EpsProFeature's contract with the Pro builds):
#   community          no valid licence for THIS tenant
#   pro-single-tenant  sku Pro, no signed limits          (Invardia plan EPS-PRO = Pro Enterprise, single tenant)
#   pro-business       sku Pro-Business / signed limits   (plan EPS-BUS; the cap: limits.users = users in scope)
#   pro-enterprise     an MSP sku                          (Pro Enterprise with MSP)
#   trial              a trial sku (the 60-day trial)
# Feature names: api, mcp, passkey-tracker, licence-optimisation, stale-identities, policy-as-code, msp.
#   msp = Enterprise only (pro-single-tenant, pro-enterprise); every other = any valid Pro or trial.
# The Business cap is a WARNING, never a stop (as PIM's): collection and tagging never stop at the cap.

Set-StrictMode -Off

$script:EpsLicenceProduct   = 'EntraPolicySuite'
$script:EpsLicenceExtension = 'epslicense'
$script:EpsLicenceClaimProduct = 'entrapolicysuite'
$script:EpsLicenceBase      = 'https://invardia.com'
$script:EpsLicenceUpgradeUrl = 'invardia.com'
$script:EpsLicenceCacheSeconds = 60
$script:EpsProFeatures = @('api', 'mcp', 'passkey-tracker', 'licence-optimisation', 'stale-identities', 'policy-as-code', 'msp')
# what the License page calls them, and whether this release ships them (a licensed feature not shipped yet says so)
$script:EpsProFeatureLabels = @{
    'api' = @{ Label = 'API access (scripts)'; InRelease = $true }; 'mcp' = @{ Label = 'MCP server (AI assistants)'; InRelease = $true }
    'passkey-tracker' = @{ Label = 'Passkey rollout'; InRelease = $true }; 'licence-optimisation' = @{ Label = 'License optimization'; InRelease = $true }
    'stale-identities' = @{ Label = 'Stale identities'; InRelease = $true }; 'policy-as-code' = @{ Label = 'Policy as code'; InRelease = $true }
    'msp' = @{ Label = 'Several tenants (MSP)'; InRelease = $false } }

# PUBLIC halves only - byte-identical to the copies the framework verifier (sync/_AitLicense.ps1), PIM and SI embed.
$script:EpsLicenceAitCertB64 = 'MIIFFzCCAv+gAwIBAgIQNY8l3/KZOoxF7K1nXIXwazANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxBdXRvbWF0ZUlULUxpY2Vuc2luZy1TZXJ2aWNlMB4XDTI2MDgxMTEzMDY0NloXDTQ2MDgxMTEzMTE0NlowJzElMCMGA1UEAwwcQXV0b21hdGVJVC1MaWNlbnNpbmctU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALuth8WywLfudbaoZ6eR570apvs5LXzOeGfl5Z14z6Nl6DQgvwMLXG/8lZEHOCKsHWVtEnjZOZigsh4c16owJVhuW67OgY0Iy6OjmfeXzu+kcTICSdZ+Qj3ecsGp1Cz6Xo1AjYbgIORdqUBncy4BAuA1bxH0E+V+1zT+ltEk840xpLdWde+m7W8q7BrG9klh+xQl8xJTjeliyV0JN2mvBjI0JwB9t9vL2/luMWWtHp752/ZG4Icd9u6HyqSR/xEmlZIjkZwI7LEPLTICXV1iA3c3nFUEHkLhLlpDW6EQn3cip0Sijr7SVWEBH1fCA8vCo+PxIEgJc3RXaeRhqD4UOwPJIziHtrpy8+9L15zrhXnhIGZv2mUAHKiamUIOmKl9vj31vFp/vJx1chE0XA358T09HGu0jKgSbbC4afKQPKf3v+BHPU42T/xIOPMxDJWuFqKvr4anL7P5PEkTjycBRCkXnIPC5PlrXR/ZZz4oit4WKhbdzONYwb8CKnsF2Z9IVL9yviVJxAIr7kiGqRme9+H0t5A+hzAydxdFMQnop+R8Q02a0sei9WrdtCbwLempVVrXIS6N4hh5kvLqMouDi62b0h645UNk2cWahDIZWTKd/MYdlcdrtRt5muy2LOasHByVxUrZKwH7IetCmv+Kkm1BfMF6Fvi1Jh2Qgz4bo5XJAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT+IiWP1iqSIwaRLiV1somJAQ+ELjANBgkqhkiG9w0BAQsFAAOCAgEAFiDfl7nhDNIywkCZgu9iw0RtJUyJqiq8y+fXomucqowAQZKPhkpuHftZZjtDe09WM35TqjRgL7hqmJiEgqPlRrAv78FjE41RwMcANN2PVCrdcMcuDVdRbS40rObpp0B6+uVUiWY4+8MW6G8Wv+7CIBUEP8ypo3BhxQJZLpyJDKLNiPqnTVKOmYXe7BivfVz63F2Pg2dNXic1poQ7S6JTi/8FM4AV2Ge/zVQF+LaiIuBDJX3JjHnKXxNf1Zhk8PF6DeWaVSNyXtjESlaUfsz0U2Ue87UUZ8ELIuqjHTpG66HPInblBZme6VvR13n5QxmnvjPXdtmXAJzDzCf+76labSGQu9fMFxUoKwjAwT9vHrdFw8JEStappW7urXj+Oafp1wVafJOXzjd9utr8WT3AhaPeqMx3FYH20e2b7QNCI3owtm0ogHRg36neahe78PikiMe15AUpD3+BD6pKeLV7tsExeXZjxDxhFUSpScD0TrCOUEJdKL2Cfx8rM3ceISSiTTYmuJmU7fznQ122A6GNW58mpSk8miPYb3MzbLW0JFPRrEDiyT8dW1M9s98DL+7VR0z2QxgxhNMKyrVgBM7YgQtbtPLz26NBqAQsqG50rOdn7XmprzvnTmnb+r2PUQuqb6rCTAQFTJ3MjH7BviP3GkwJyvzMZ+S6OnUAGB2Fn3Y='
$script:EpsLicenceInvardiaCertB64 = 'MIIFQDCCAyigAwIBAgIQXXs1IY0ZQE2MwtugYutXwDANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwHhcNMjYxMDAzMTY1NDMxWhcNMzYxMDAzMTcwNDMxWjAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCn9X21WYLer9r3ojq9lCP3eGV5YK8UMHoyyGT/q8carwQK+ztBRweKAgHyg8rr67utZ1zZBDRei64T/63nXGZpC666efzNZjIU+Og7vtO0bTNjQm/yVD/Q4KFZachYbE5orU+99HQcgRrcwnmmltyazyun2MV2CTk2nUDeMX5IIFD/1yIT8SLNFa6b6Gy4Ms/TIlc4u3lEH3zjbTSF+phSrbv7J6ytz5Eq1ahRkKHWcdBoF9GJo2ynWP0vTGHWvvjNdeVpXP1rkGnLt9MAQj2Us/2XiTgZzf26QLNiXX9YeJeUA9IVdPWczJav+YYkcICyG4ynwhPCudI6S2iDeu8jyL54gfVT871/+RFebzKHq9teY2vB0aGsbaW9VOmV5dDQ2mVfQLFTkNd1ByeZKv9tR0vPfaiZCza+DedApF2LfoAa7Y34pb9WHGRJFAPVmG2WMSsTY90Y0VBYrktF4g4q712W2ZdQc+QIxtvP5nsz6bk1QBvJ1Hcsr/euiysxmkFxcl3NH7WM1EKzdzUaYDJpysoE9e0jkjdJpb9bNNmSE7V9IMTk7r/XOiYJ+8qOALTgwUIEyOLi/hfOihJDRn31aJ6aPvzCEYikueJV5oALrDxquiXbPi8z10aMuXLL4hfi6B7U0qo2kOTPQ9Qh/cJFVkV9pEXjtY+NwwI9EtxgaQIDAQABo3wwejAOBgNVHQ8BAf8EBAMCB4AwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUuZzWkYh3hkE0oJH42LneYVKXIzowHQYDVR0OBBYEFLmc1pGId4ZBNKCR+Ni53mFSlyM6MA0GCSqGSIb3DQEBCwUAA4ICAQCluVZnotzEyS5ux+4hMuz9mOfpSJCNg5nkS8XxIHySiE2AEjVT4ZFEyykZUFoROv5clLBkO5icvDDRBitkeKHvioZruRPtVGy0fs0VxJ4VMcOU/i5cVdJXBQeyUFE8o//4+7FXZp10ToVNv/drjdO7adcNHRVjsddm2mXPNyHmE07ErV6eInPj+r0/1dogPBW1knF+T53RTwT2O0Ppe5qK0QEdBfo5sf4nvjg7ONNXYlW38SzXGLsXy6TZphRWqxLq7u31HAwujQGy9syO+TPIzusH1WHkCsvjDDRXNI8iYhKcS2wq/P/O6O4Ebt/PFN0hxyzyuYx4kreXKKhqrfsEMDxzMUQNnUEjFgU4/4atLVJpBvoDmb/MuQDIzlhxz8obAJi5BuxyjyemR9jg6XMIE2IAhe1v+MN0ZY58tbZR3t5rF30tp541NRaJfn4DBpqNmAIFyDQMdM2FogkFoOV+Mo0IBmGzV/jyv/2z+sre1P5MncLP2qZhfFmu595gWnNoOsMdUZmEWMkbISMGvGzfpPRF3IBan+fymCZSsKNB00E3W50Sh/t2sopEYc3eSwpu6bhvPUgB2ZKU6KN49Al4Pf41uldHVY0aVVp+kpLmRntDFzkTNXUG4OWOwF5gHuGY8jIrwDR7pCPSNzDWrUf857O6DyWEsHXERWg5OPLNUg=='
$script:EpsLicenceTrustedCertsB64 = @($script:EpsLicenceInvardiaCertB64, $script:EpsLicenceAitCertB64)

function Test-EpsLicenceSignature {
    <# PURE. RSA-SHA256 / PKCS#1 over the raw payload bytes. Never throws: a tampered file is $false, never a crash. #>
    param([Parameter(Mandatory)][byte[]]$PayloadBytes, [Parameter(Mandatory)][byte[]]$SignatureBytes, [Parameter(Mandatory)][string]$PublicCertB64)
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($PublicCertB64))
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if (-not $rsa) { return $false }
        return $rsa.VerifyData($PayloadBytes, $SignatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { return $false }
}

function ConvertTo-EpsLicenceLimits {
    <# PURE (PIM's ConvertTo-PimLicenceLimits): the SIGNED payload's `limits` -> name (lower-case) -> int, or $null = none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $pairs = @()
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { $pairs += ,@("$k", $Value[$k]) } }
    elseif ($Value.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') { foreach ($pp in @($Value.PSObject.Properties)) { $pairs += ,@("$($pp.Name)", $pp.Value) } }
    else { return $null }
    $out = [ordered]@{}
    foreach ($pr in $pairs) { $n = "$($pr[0])".Trim().ToLowerInvariant(); $v = "$($pr[1])".Trim(); if ($n -and $v -match '^\d{1,9}$') { $out[$n] = [int]$v } }
    return $out
}

function Resolve-EpsLicenceStatus {
    <#
      PURE. The licence file text (or the parsed document) + a clock -> the verified licence:
        @{ Status = Missing | Invalid | NotYetValid | Valid | Grace | Expired; Reason; Customer; Sku; LicenseId; Features;
           TenantIds; ValidFrom; ValidTo; GraceUntil; Limits }
      Every rule is the framework verifier's (Resolve-AitLicenseStatus); EPS adds two: a file for ANOTHER product is
      Invalid, and `limits` is read only from the verified payload bytes (a `limits` outside the payload is never read).
    #>
    param([AllowNull()][object]$Document, [AllowNull()][string[]]$TrustedCertsB64, [AllowNull()][object]$Now)
    $r = [pscustomobject]@{ Status = 'Missing'; Reason = 'no licence'; Customer = ''; Sku = ''; LicenseId = ''; Features = @(); TenantIds = @()
                            ValidFrom = $null; ValidTo = $null; GraceUntil = $null; Limits = $null }
    if ($null -eq $Document -or ($Document -is [string] -and -not "$Document".Trim())) { return $r }
    $today = if ($Now) { ([datetime]$Now).Date } else { (Get-Date).Date }
    $certs = @($TrustedCertsB64 | Where-Object { $_ }); if (-not $certs.Count) { $certs = @($script:EpsLicenceTrustedCertsB64) }
    try {
        $doc = if ($Document -is [string]) { "$Document" | ConvertFrom-Json } else { $Document }
        if (-not $doc.payloadB64 -or -not $doc.signature) { throw 'not an Invardia licence file (payloadB64 / signature missing)' }
        if ("$($doc.product)".Trim() -and "$($doc.product)".Trim() -ine $script:EpsLicenceProduct) { $r.Status = 'Invalid'; $r.Reason = "a licence for $($doc.product), not for Entra Policy Suite"; return $r }
        $pb = [Convert]::FromBase64String("$($doc.payloadB64)"); $sb = [Convert]::FromBase64String("$($doc.signature)")
        $ok = $false; foreach ($c in $certs) { if (Test-EpsLicenceSignature -PayloadBytes $pb -SignatureBytes $sb -PublicCertB64 $c) { $ok = $true; break } }
        if (-not $ok) { $r.Status = 'Invalid'; $r.Reason = 'the signature does not verify (not issued by Invardia, or changed)'; return $r }
        $p = [System.Text.Encoding]::UTF8.GetString($pb) | ConvertFrom-Json
        $r.Customer = "$($p.customer)"; $r.Sku = "$($p.sku)"; $r.LicenseId = "$($p.licenseId)"
        $r.Features = @($p.features | Where-Object { $_ }); $r.TenantIds = @($p.tenantIds | Where-Object { $_ })
        if ($p.PSObject.Properties.Name -contains 'limits') { $r.Limits = ConvertTo-EpsLicenceLimits -Value $p.limits }
        $r.ValidFrom = [datetime]::Parse("$($p.validFrom)", [System.Globalization.CultureInfo]::InvariantCulture).Date
        $r.ValidTo = [datetime]::Parse("$($p.validTo)", [System.Globalization.CultureInfo]::InvariantCulture).Date
        $grace = 30; if ($p.PSObject.Properties.Name -contains 'graceDays' -and "$($p.graceDays)" -match '^\d+$') { $grace = [int]$p.graceDays }
        $r.GraceUntil = $r.ValidTo.AddDays($grace)
        if ($today -lt $r.ValidFrom) { $r.Status = 'NotYetValid'; $r.Reason = "the licence starts $($r.ValidFrom.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $r.ValidTo) { $r.Status = 'Valid'; $r.Reason = "valid until $($r.ValidTo.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $r.GraceUntil) { $r.Status = 'Grace'; $r.Reason = "ended $($r.ValidTo.ToString('yyyy-MM-dd')) - grace until $($r.GraceUntil.ToString('yyyy-MM-dd')), renew now" }
        else { $r.Status = 'Expired'; $r.Reason = "ended $($r.ValidTo.ToString('yyyy-MM-dd')) (grace ended $($r.GraceUntil.ToString('yyyy-MM-dd')))" }
    } catch { $r.Status = 'Invalid'; $r.Reason = "the licence could not be read: $((("$($_.Exception.Message)") -split "`n")[0])" }
    return $r
}

function Test-EpsLicenceTenant {
    <# PURE. Bound to this tenant? A licence that names NO tenant is valid in NO tenant (LIC anti-copy, 2026-10-03). #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId)
    if ($null -eq $License) { return $false }
    $ids = @($License.TenantIds | Where-Object { $_ }); if (-not $ids.Count -or -not "$TenantId".Trim()) { return $false }
    foreach ($i in $ids) { if ("$i".Trim() -ieq "$TenantId".Trim()) { return $true } }
    $false
}

function Get-EpsLicenceEdition {
    <# PURE. The edition THIS tenant has (see the header). Grace still counts (that is what grace is for). #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId)
    if ($null -eq $License -or "$($License.Status)" -notin 'Valid', 'Grace' -or -not (Test-EpsLicenceTenant -License $License -TenantId $TenantId)) { return 'community' }
    $sku = "$($License.Sku)".Trim()
    if ($sku -match '(?i)trial') { return 'trial' }
    if ($sku -match '(?i)msp') { return 'pro-enterprise' }
    if ($null -ne $License.Limits -or $sku -match '(?i)business') { return 'pro-business' }
    'pro-single-tenant'
}

function Get-EpsLicenceEditionText {
    param([string]$Edition)
    switch ($Edition) { 'pro-single-tenant' { 'Pro Enterprise' } 'pro-enterprise' { 'Pro Enterprise (MSP)' } 'pro-business' { 'Pro Business' } 'trial' { 'Pro (trial)' } default { 'Community' } }
}

function Test-EpsProFeatureForEdition {
    <# PURE. @{ Enabled; Edition; Why } for one feature name and an edition (the contract in the header). #>
    param([Parameter(Mandatory)][string]$Feature, [Parameter(Mandatory)][string]$Edition)
    $f = "$Feature".Trim().ToLowerInvariant()
    if ($script:EpsProFeatures -notcontains $f) { return @{ Enabled = $false; Edition = $Edition; Why = "'$Feature' is not a Pro feature of Entra Policy Suite" } }
    if ($Edition -eq 'community') { return @{ Enabled = $false; Edition = $Edition; Why = "$f needs a Pro licence or the trial (this install is Community)" } }
    if ($f -eq 'msp' -and $Edition -notin 'pro-single-tenant', 'pro-enterprise') { return @{ Enabled = $false; Edition = $Edition; Why = "msp is in Pro Enterprise only (this install is $(Get-EpsLicenceEditionText $Edition))" } }
    @{ Enabled = $true; Edition = $Edition; Why = "included in $(Get-EpsLicenceEditionText $Edition)" }
}

function Get-EpsLicenceUserCap {
    # PURE. The Business cap: the signed limits.users, or $null = no cap
    param([AllowNull()][object]$License)
    if ($null -eq $License -or $null -eq $License.Limits) { return $null }
    $l = $License.Limits; if ($l -is [System.Collections.IDictionary] -and $l.Contains('users')) { return [int]$l['users'] }
    $null
}

function Get-EpsLicenceUsage {
    <#
      PURE (PIM's Get-PimAdminLicenceUsage, for users in scope). A WARNING only, never a stop.
        @{ edition; editionText; cap ($null = none); count ($null = unknown); percent; state = none|ok|warn|at|over; message }
    #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId, [AllowNull()][object]$UsersInScope)
    $ed = Get-EpsLicenceEdition -License $License -TenantId $TenantId
    $cap = if ($ed -eq 'pro-business') { Get-EpsLicenceUserCap -License $License } else { $null }
    $count = if ($null -ne $UsersInScope -and "$UsersInScope" -match '^\d+$') { [int]$UsersInScope } else { $null }
    $o = [ordered]@{ edition = $ed; editionText = $(if ($null -ne $cap) { "Pro Business ($cap users)" } else { Get-EpsLicenceEditionText $ed }); cap = $cap; count = $count; percent = $null; state = 'none'; message = '' }
    if ($null -eq $cap -or $null -eq $count) { return $o }
    $pct = if ($cap -gt 0) { [int][math]::Floor(100.0 * $count / $cap) } else { 100 }
    $o.percent = $pct
    $covers = "Your Pro Business license covers $cap users in scope"
    if ($count -gt $cap) { $o.state = 'over'; $o.message = "$covers and $count are in scope. Nothing is switched off and tagging goes on - upgrade to Pro Enterprise at $script:EpsLicenceUpgradeUrl." }
    elseif ($count -eq $cap) { $o.state = 'at'; $o.message = "$covers and all $count are in scope. Upgrade to Pro Enterprise at $script:EpsLicenceUpgradeUrl before more users come in." }
    elseif ($cap -gt 0 -and ($count * 10) -ge ($cap * 9)) { $o.state = 'warn'; $o.message = "$covers and $count are in scope ($pct%). Upgrade to Pro Enterprise at $script:EpsLicenceUpgradeUrl before more come in." }
    else { $o.state = 'ok' }
    $o
}

# ---------------------------------------------------------------------------------------------------- the store (eps.License)
function Get-EpsStoredLicence {
    # the one row (no secret in it) or $null
    param([Parameter(Mandatory)][string]$ConnectionString)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT LicenceText, SetBy, SetAtUtc, ClaimAction, ClaimMessage, ClaimAtUtc, ClaimLicenceHash, RequestStatus, RequestMessage, RequestAtUtc, NextPollUtc, SupersededBy, UsersInScope, UsageState FROM eps.License WHERE Id = 1')[0]
    if (-not $r) { return $null }
    $n = { param($v) if ($null -eq $v -or $v -is [DBNull]) { $null } else { $v } }
    @{ Text = "$($r.LicenceText)"; SetBy = "$($r.SetBy)"; SetAtUtc = (& $n $r.SetAtUtc); ClaimAction = "$($r.ClaimAction)"; ClaimMessage = "$($r.ClaimMessage)"; ClaimAtUtc = (& $n $r.ClaimAtUtc); ClaimLicenceHash = "$($r.ClaimLicenceHash)"
       RequestStatus = "$($r.RequestStatus)"; RequestMessage = "$($r.RequestMessage)"; RequestAtUtc = (& $n $r.RequestAtUtc); NextPollUtc = (& $n $r.NextPollUtc); SupersededBy = "$($r.SupersededBy)"
       UsersInScope = (& $n $r.UsersInScope); UsageState = "$($r.UsageState)" }
}

function Get-EpsLicenceTenantId {
    # the tenant this install runs in (the install sets EPS_TENANT_ID on every component)
    if ("$env:EPS_TENANT_ID" -match '^[0-9a-fA-F-]{36}$') { return "$env:EPS_TENANT_ID".ToLowerInvariant() }
    ''
}

$script:EpsLicenceCache = @{ At = [datetime]::MinValue; Key = ''; Value = $null }
function Get-EpsLicence {
    <# The verified licence of this install (cached EpsLicenceCacheSeconds per process): @{ License; Edition; TenantId }. Never throws. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$TenantId = (Get-EpsLicenceTenantId), [switch]$Refresh)
    $now = [datetime]::UtcNow
    if (-not $Refresh -and $script:EpsLicenceCache.Key -eq "$ConnectionString|$TenantId" -and ($now - $script:EpsLicenceCache.At).TotalSeconds -lt $script:EpsLicenceCacheSeconds) { return $script:EpsLicenceCache.Value }
    $txt = ''; try { $s = Get-EpsStoredLicence -ConnectionString $ConnectionString; if ($s) { $txt = $s.Text } } catch { $txt = '' }
    $lic = Resolve-EpsLicenceStatus -Document $txt
    $v = @{ License = $lic; Edition = (Get-EpsLicenceEdition -License $lic -TenantId $TenantId); TenantId = $TenantId }
    $script:EpsLicenceCache = @{ At = $now; Key = "$ConnectionString|$TenantId"; Value = $v }
    $v
}

function Test-EpsProFeature {
    <# THE contract the Pro builds call: @{ Enabled; Edition; Why } from the verified licence (cached). Never throws. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Feature)
    $ed = 'community'; try { $ed = (Get-EpsLicence -ConnectionString $ConnectionString).Edition } catch { $ed = 'community' }
    Test-EpsProFeatureForEdition -Feature $Feature -Edition $ed
}

function Get-EpsUsersInScope {
    # the users the last user tagging run looked at (its Objects) - the number the Business cap counts; $null = unknown
    param([Parameter(Mandatory)][string]$ConnectionString)
    try { $n = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT TOP 1 Objects FROM eps.Run WHERE Job = 'UserTagging' AND Objects IS NOT NULL AND Scope IS NULL ORDER BY StartedAtUtc DESC"; if ($null -eq $n -or $n -is [DBNull]) { return $null }; return [int]$n } catch { return $null }
}

function Get-EpsLicenceView {
    <# What the Licence page / the Overview / the heartbeat show. Never throws; never returns the licence text. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$TenantId = (Get-EpsLicenceTenantId))
    $l = Get-EpsLicence -ConnectionString $ConnectionString -TenantId $TenantId -Refresh
    $lic = $l.License; $s = $null; try { $s = Get-EpsStoredLicence -ConnectionString $ConnectionString } catch { $s = $null }
    $n = if ($s -and $null -ne $s.UsersInScope) { $s.UsersInScope } else { Get-EpsUsersInScope -ConnectionString $ConnectionString }
    $u = Get-EpsLicenceUsage -License $lic -TenantId $TenantId -UsersInScope $n
    $bound = Test-EpsLicenceTenant -License $lic -TenantId $TenantId
    [ordered]@{
        status = "$($lic.Status)"; reason = $(if ($lic.Status -in 'Valid', 'Grace' -and -not $bound) { "the licence is for another tenant ($((@($lic.TenantIds)) -join ', ')), not this one ($TenantId)" } else { "$($lic.Reason)" })
        edition = $l.Edition; editionText = $u.editionText; customer = "$($lic.Customer)"; licenseId = "$($lic.LicenseId)"
        validFrom = $(if ($lic.ValidFrom) { $lic.ValidFrom.ToString('yyyy-MM-dd') }); validTo = $(if ($lic.ValidTo) { $lic.ValidTo.ToString('yyyy-MM-dd') }); graceUntil = $(if ($lic.GraceUntil) { $lic.GraceUntil.ToString('yyyy-MM-dd') })
        tenantId = $TenantId; boundHere = $bound; usage = $u
        # ADMIN-WALK Pro (2026-11-06): the page name an admin knows, and whether THIS release has it (api / mcp / msp: licensed, not shipped yet)
        features = @($script:EpsProFeatures | ForEach-Object { $t = Test-EpsProFeatureForEdition -Feature $_ -Edition $l.Edition; $m = $script:EpsProFeatureLabels[$_]
            [ordered]@{ name = $_; label = $(if ($m) { $m.Label } else { $_ }); inRelease = $(if ($m) { [bool]$m.InRelease } else { $true }); enabled = $t.Enabled; why = $t.Why } })
        setBy = $(if ($s) { $s.SetBy }); setAtUtc = $(if ($s) { $s.SetAtUtc })
        claim = $(if ($s -and $s.ClaimAction) { [ordered]@{ action = $s.ClaimAction; message = $s.ClaimMessage; atUtc = $s.ClaimAtUtc } })
        request = $(if ($s -and $s.RequestStatus) { [ordered]@{ status = $s.RequestStatus; message = $s.RequestMessage; atUtc = $s.RequestAtUtc; nextPollUtc = $s.NextPollUtc } })
        claimAgain = [bool]($s -and ($s.ClaimAction -in 'refused', 'retry' -or $s.RequestStatus -in 'Rejected', 'Error'))
        buyUrl = "https://$($script:EpsLicenceUpgradeUrl)"
        howTo = 'The license comes from Invardia: the update job asks for it, checks it and installs it. Nobody pastes or uploads a license. Pro and the 60-day trial are ordered at invardia.com.'
    }
}

function Get-EpsLicenceUplinkFields {
    <# PURE. The envelope fields from the verified licence: Edition (community | pro | trial), LicenceState, LicenceId. #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId)
    $ed = Get-EpsLicenceEdition -License $License -TenantId $TenantId
    $o = [ordered]@{ Edition = $(if ($ed -eq 'community') { 'community' } elseif ($ed -eq 'trial') { 'trial' } else { 'pro' }) }
    $st = "$($License.Status)"
    $o.LicenceState = if ($ed -eq 'community') { 'none' } elseif ($st -eq 'Grace') { 'grace' } elseif ($st -eq 'Valid') { 'valid' } else { 'expired' }
    if ($ed -ne 'community' -and "$($License.LicenseId)" -match '^[0-9a-fA-F-]{36}$') { $o.LicenceId = "$($License.LicenseId)".ToLowerInvariant() }
    $o
}

function Test-EpsLicenceForThisInstall {
    <# PURE. May this text be stored as THIS install's licence? @{ Ok; Reason; License } - Valid / Grace, for this product, bound here. #>
    param([AllowEmptyString()][string]$Text, [AllowNull()][string]$TenantId, [AllowNull()][object]$Now)
    $lic = Resolve-EpsLicenceStatus -Document $Text -Now $Now
    if ($lic.Status -notin 'Valid', 'Grace') { return @{ Ok = $false; Reason = "refused: $($lic.Reason)"; License = $lic } }
    if (-not (Test-EpsLicenceTenant -License $lic -TenantId $TenantId)) { return @{ Ok = $false; Reason = "refused: the licence names $((@($lic.TenantIds)) -join ', ') - not this install's tenant $TenantId"; License = $lic } }
    @{ Ok = $true; Reason = "$(Get-EpsLicenceEditionText (Get-EpsLicenceEdition -License $lic -TenantId $TenantId)) for $($lic.Customer), $($lic.Reason)"; License = $lic }
}

# ---------------------------------------------------------------------------------------------------- the claim + the Pro pull
function Invoke-EpsInstallKeyClaim {
    <#
      LIC-01 (PIM's Invoke-PimInstallKeyClaimCycle): with a Pro licence for this tenant, claim the install key -
        POST <base>/api/install-keys/claim { product; tenantId (the REAL one); licence (the file text) }
      -> 200 { installKey } -> -SetKey { param($key) } stores it (the install's Key Vault secret uplink-key); 403 = refused
      with Invardia's reason and not asked again until the licence changes; anything else = asked again next run.
      No Pro licence = nothing is sent. -Http { param($method, $url, $body, $headers) } -> @{ status; body; error }.
      Returns @{ action = none | claimed | refused | retry; message }. The key is never in a message.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [AllowEmptyString()][string]$LicenceText, [string]$TenantId, [string]$Edition,
          [scriptblock]$SetKey, [AllowNull()][object]$Previous, [string]$BaseUrl = $script:EpsLicenceBase)
    if ($Edition -eq 'community' -or -not "$LicenceText".Trim()) { return @{ action = 'none'; message = 'no Pro licence for this tenant - an install key is claimed with one'; hash = '' } }
    $lh = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$LicenceText"))).Replace('-', '').ToLowerInvariant()
    if ($Previous -and "$($Previous.ClaimAction)" -eq 'refused' -and "$($Previous.ClaimLicenceHash)" -eq $lh) { return @{ action = 'none'; message = "not asked again: $($Previous.ClaimMessage)"; hash = $lh } }
    if ($Previous -and "$($Previous.ClaimAction)" -eq 'claimed' -and "$($Previous.ClaimLicenceHash)" -eq $lh) { return @{ action = 'none'; message = 'the install key was claimed with this licence'; hash = $lh } }
    $base = "$BaseUrl".Trim().TrimEnd('/'); if ($base -notmatch '^(?i)https://') { return @{ action = 'retry'; message = 'the claim address is not https'; hash = $lh } }
    $r = & $Http 'POST' "$base/api/install-keys/claim" ([ordered]@{ product = $script:EpsLicenceClaimProduct; tenantId = "$TenantId".ToLowerInvariant(); licence = "$LicenceText" }) @{}
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -eq 200 -and "$($r.body.installKey)" -match '^inv-[A-Za-z0-9_-]{20,100}$') {
        $k = "$($r.body.installKey)"
        if ($SetKey) { $sk = & $SetKey $k; if ($sk -and -not $sk.Ok) { return @{ action = 'retry'; message = "claimed, but not stored: $($sk.Reason)"; hash = $lh; key = $k } } }
        return @{ action = 'claimed'; message = 'the install key was claimed and stored'; hash = $lh; key = $k }
    }
    if ($st -eq 200 -and $r.body.alreadyInstalled) { return @{ action = 'claimed'; message = 'Invardia has this tenant installed with a key already (the key in the install''s Key Vault stays)'; hash = $lh } }
    if ($st -eq 200) { return @{ action = 'retry'; message = 'Invardia answered without a usable install key'; hash = $lh } }
    if ($st -eq 403) { return @{ action = 'refused'; message = "Invardia refused the licence ($("$($r.body.reason)$($r.body.error)".Trim())) - the claim needs a valid Invardia-issued Pro licence for this tenant"; hash = $lh } }
    @{ action = 'retry'; message = "the claim did not answer (HTTP $st) - asked again next run"; hash = $lh }
}

$script:EpsCommunityClaimHash = 'community-opt-in'   # ClaimLicenceHash of a Community claim (no licence to hash)
function Invoke-EpsCommunityKeyClaim {
    <#
      OPT-IN-1 "claim on yes" (owner 2026-11-11 "Ask at install (opt-in)"; Invardia's Community claim route, live 2026-11-11):
      ONLY for a Community install whose user said yes at install (the caller checks EPS_CONNECT_INVARDIA = yes):
        POST <base>/api/install-keys/claim { product; tenantId; edition: 'community' } - NO licence
      -> 200 { installKey } (the Pro claim's shape) -> -SetKey stores it (uplink-key). With the key the support link sends
      its health reports and the head call (kind community) reads "update now".
      409 tenantKnown (the tenant belongs to a company with a licence: claim with the licence) and 409 keyExists (a key was
      issued already) are refused and NOT asked again until "Claim again"; 429 (the per-IP / daily cap) and anything else
      = asked again next run. Returns @{ action = none | claimed | refused | retry; message; hash }. The key is never in a message.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$TenantId, [scriptblock]$SetKey, [AllowNull()][object]$Previous, [string]$BaseUrl = $script:EpsLicenceBase)
    $h = $script:EpsCommunityClaimHash
    if ($Previous -and "$($Previous.ClaimLicenceHash)" -eq $h -and "$($Previous.ClaimAction)" -eq 'refused') { return @{ action = 'none'; message = "not asked again: $($Previous.ClaimMessage)"; hash = $h } }
    if ("$TenantId" -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return @{ action = 'none'; message = 'the tenant id is not known - nothing is sent'; hash = '' } }
    $base = "$BaseUrl".Trim().TrimEnd('/'); if ($base -notmatch '^(?i)https://') { return @{ action = 'retry'; message = 'the claim address is not https'; hash = $h } }
    $r = & $Http 'POST' "$base/api/install-keys/claim" ([ordered]@{ product = $script:EpsLicenceClaimProduct; tenantId = "$TenantId".ToLowerInvariant(); edition = 'community' }) @{}
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    $why = "$($r.body.error)$(if ($r.body.reason) { " $($r.body.reason)" })".Trim()
    if ($st -eq 200 -and "$($r.body.installKey)" -match '^inv-[A-Za-z0-9_-]{20,100}$') {
        $k = "$($r.body.installKey)"
        if ($SetKey) { $sk = & $SetKey $k; if ($sk -and -not $sk.Ok) { return @{ action = 'retry'; message = "claimed, but not stored: $($sk.Reason)"; hash = $h; key = $k } } }
        return @{ action = 'claimed'; message = 'the Community install key was claimed and stored (you said yes to connect this install to Invardia)'; hash = $h; key = $k }
    }
    if ($st -eq 200) { return @{ action = 'retry'; message = 'Invardia answered without a usable install key'; hash = $h } }
    if ($st -eq 409 -and $why -match 'tenantKnown') { return @{ action = 'refused'; message = 'Invardia knows this tenant as a licensed customer - the install key is claimed with the licence, not as Community'; hash = $h } }
    if ($st -eq 409 -and $why -match 'keyExists') { return @{ action = 'refused'; message = 'Invardia issued this install''s key already, but it is not in the install''s Key Vault - ask Invardia support, then use Claim again'; hash = $h } }
    if ($st -eq 429) { return @{ action = 'retry'; message = 'Invardia''s claim limit was reached - asked again next run'; hash = $h } }
    @{ action = 'retry'; message = "the claim did not answer (HTTP $st$(if ($why -match '^[\w .-]{1,80}$') { ", $why" })) - asked again next run"; hash = $h }
}

$script:EpsLicenceSecretName = 'eps-licence'   # the licence file in the install's Key Vault (framework §12.25: written by the update job only)
$script:EpsLicenceKvArmApi = '2023-07-01'
$script:EpsLicenceWritableSecrets = @('uplink-key', 'eps-licence')   # the ONLY secrets this product's code ever writes

function Set-EpsInstallSecret {
    <#
      Framework §12.25 SECRETS-WRITE: the UPDATE JOB writes one of the two Invardia-issued values into the install's own Key
      Vault - the claimed install key (uplink-key) or the verified licence file (eps-licence) - through ARM (control plane,
      Microsoft.KeyVault/vaults/secrets/write), as its own identity id-eps-updater, which holds Contributor on the install's
      resource group and NO Key Vault data-plane right: it can write these values, never read one back. No person and no
      other component writes a secret. Never throws, never logs the value: @{ Ok; Reason }.
    #>
    param([Parameter(Mandatory)][ValidateSet('uplink-key', 'eps-licence')][string]$Name, [Parameter(Mandatory)][string]$Value,
          [string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID, [string]$ResourceGroup = $env:EPS_RESOURCE_GROUP, [string]$VaultName = (Get-EpsUplinkVaultName))
    if ($script:EpsLicenceWritableSecrets -notcontains $Name) { return @{ Ok = $false; Reason = "$Name is not a secret this job writes" } }
    if ($VaultName -notmatch '^[A-Za-z0-9-]{3,24}$' -or "$SubscriptionId" -notmatch '^[0-9a-fA-F-]{36}$' -or "$ResourceGroup" -notmatch '^[\w.()-]{1,90}$') { return @{ Ok = $false; Reason = 'the install''s Key Vault is not known to this job' } }
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName/secrets/$Name"
    try {
        [void](Invoke-EpsArm -Method PUT -Path $path -ApiVersion $script:EpsLicenceKvArmApi -Body @{ properties = @{ value = $Value; contentType = $(if ($Name -eq 'eps-licence') { 'application/json' } else { 'text/plain' }) } } -MaxRetry 2)
    } catch {
        $m = ((("$($_.Exception.Message)") -split "`n")[0]); if ($Value -and $m.Contains($Value)) { $m = 'the write was refused' }
        return @{ Ok = $false; Reason = "$Name could not be written to $VaultName ($m)$(if ($m -match '\b40[13]\b|AuthorizationFailed') { ' - the update job needs Contributor on the install''s resource group: run the install again' })" }
    }
    @{ Ok = $true; Reason = "stored as $Name in $VaultName" }
}
function Set-EpsUplinkKey { param([Parameter(Mandatory)][string]$Key) Set-EpsInstallSecret -Name 'uplink-key' -Value $Key }

# ---------------------------------------------------------------------------------------------------- knock / pull (§95.2)
# PIM-LicenceRequest.ps1 / SI-LicenceRequest.ps1 (Invardia's LICENCE-REQUESTS contract), run by the UPDATE job:
#   KNOCK  when this install is meant to be Pro (a licence held, an install key, a superseded hint, or the Pro installer's
#          EPS_INSTALL_EDITION = pro) and no Pro licence is valid here, it ends within 30 days, or Invardia says it is
#          superseded: POST <base>/api/licence-requests { product; version; tenantId; installId; currentLicenceId?;
#          currentValidTo?; currentLicenceSha256? } (+ X-Invardia-Install-Key / X-Invardia-Install-Id) -> { requestId;
#          pullToken; status; pollAfterSeconds }. No edition is sent: a trial is just a licence (Invardia decides).
#   PULL   no faster than pollAfterSeconds: POST <base>/api/licence-requests/pull + X-Invardia-Pull-Token -> { status;
#          licence? = { fileName; sha256; contentBase64 } }
#   VERIFY offline (SHA-256, signature, product, THIS tenant, dates, a Pro edition), then store: the install's Key Vault
#          (eps-licence) and eps.License. A COMMUNITY install asks ONLY after its user said yes at install (EPS_CONNECT_INVARDIA=yes; owner 2026-11-11 opt-in), then with edition community (PRO-COMMUNITY-SAME): Invardia answers 200 { status: Community } - the free set, no request, no owner mail; asked again after pollAfterSeconds. A rejection is never re-requested by itself.
$script:EpsLicenceRenewDays = 30

function Get-EpsLicenceRequestDecision {
    <# PURE (PIM's Get-PimLicenceRequestDecision). @{ action = none|knock|pull; reason; clearHint }. #>
    param($License, [bool]$ProHere, $State, [bool]$HasToken, [datetime]$NowUtc, [string]$SupersededBy = '', [bool]$ProIntended = $false, [bool]$Connected = $false)
    $NowUtc = $NowUtc.ToUniversalTime()
    $hint = "$SupersededBy".Trim()
    $curId = if ($License) { "$($License.LicenseId)".Trim() } else { '' }
    $clear = [bool]($hint -and $curId -and $hint -ieq $curId)
    $st = "$($State.status)"
    if ($st -eq 'Pending' -and $HasToken) {
        $next = $null; try { if ("$($State.nextPollUtc)") { $next = ([datetime]"$($State.nextPollUtc)").ToUniversalTime() } } catch { }
        if ($next -and $NowUtc -lt $next) { return @{ action = 'none'; reason = "waiting for Invardia (next check $($next.ToString('u')))"; clearHint = $clear } }
        return @{ action = 'pull'; reason = 'a request is pending at Invardia'; clearHint = $clear }
    }
    if (-not $ProIntended) {
        # OWNER 2026-11-11 ("Ask at install (opt-in)"): a Community install stays ANONYMOUS - it sends NOTHING to Invardia,
        # not even this ask - unless its user said yes at install ("Connect this install to Invardia: health reports +
        # updates on request"; EPS_CONNECT_INVARDIA = yes on the update job). Without the yes: the free set, nothing sent.
        if (-not $Connected) { return @{ action = 'none'; reason = 'Community, anonymous: nothing is sent to Invardia (no yes to "Connect this install to Invardia" at install)'; clearHint = $clear } }
        # PRO-COMMUNITY-SAME (owner 2026-11-11 "it must be same pro community"): a Community install asks the SAME way, with
        # edition 'community'; Invardia answers 200 { status: 'Community' } (the free set, no request, no owner mail) and when
        # to ask again (pollAfterSeconds, 24 h). A licence or trial for the tenant still comes back as Pro.
        if ($st -eq 'Community') {
            $next = $null; try { if ("$($State.nextPollUtc)") { $next = ([datetime]"$($State.nextPollUtc)").ToUniversalTime() } } catch { }
            if ($next -and $NowUtc -lt $next) { return @{ action = 'none'; reason = "Community: Invardia answered the free set; asked again $($next.ToString('u'))"; clearHint = $clear } }
        }
        return @{ action = 'knock'; reason = 'Community: the same licence ask as Pro (Invardia answers which features)'; clearHint = $clear; community = $true }
    }
    $rejected = @{ action = 'none'; reason = "Invardia rejected the licence request$(if ("$($State.reason)") { ": $($State.reason)" }) - contact Invardia, then use Claim again on the Licence page"; clearHint = $clear }
    if ($st -eq 'Rejected' -and $hint -and -not $clear) { return $rejected }
    if ($hint -and $curId -and -not $clear) { return @{ action = 'knock'; reason = "Invardia re-issued the licence (superseded by $hint)"; clearHint = $false } }
    $validTo = $null; try { if ($License -and $License.ValidTo) { $validTo = ([datetime]$License.ValidTo) } } catch { }
    if ($ProHere -and "$($License.Status)" -eq 'Valid' -and $validTo -and $validTo -gt $NowUtc.AddDays($script:EpsLicenceRenewDays)) {
        return @{ action = 'none'; reason = "the licence is valid until $($validTo.ToString('yyyy-MM-dd'))"; clearHint = $clear }
    }
    if ($st -eq 'Rejected') { return $rejected }
    $why = if (-not $License -or "$($License.Status)" -eq 'Missing') { 'no licence is installed' }
           elseif (-not $ProHere) { 'the installed licence is not a Pro licence for this tenant' }
           else { "the licence ends $($validTo.ToString('yyyy-MM-dd')) (within $($script:EpsLicenceRenewDays) days)" }
    @{ action = 'knock'; reason = $why; clearHint = $clear }
}

function Get-EpsLicenceFileSha256 {
    # PURE. The SHA-256 (64 lower-case hex) of the licence file held - the proof of possession a renewal knock sends; '' = none
    param([AllowNull()][string]$LicenceText)
    $t = "$LicenceText".TrimStart([char]0xFEFF); if (-not $t.Trim()) { return '' }
    -join ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($t)) | ForEach-Object { $_.ToString('x2') })
}

function New-EpsLicenceKnockBody {
    <# PURE. The knock body (the contract's field names); empty optional fields left out; never an edition. #>
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$InstallId,
          [string]$CurrentLicenceId = '', $CurrentValidTo, [string]$CurrentLicenceSha256 = '', [string]$Edition = '')
    $b = [ordered]@{ product = $script:EpsLicenceClaimProduct; version = $Version; tenantId = "$TenantId".ToLowerInvariant(); installId = $InstallId }
    if ("$Edition" -eq 'community') { $b['edition'] = 'community' }   # PRO-COMMUNITY-SAME: a Community install says so (a Pro ask sends none - a trial is just a licence)
    if ("$CurrentLicenceId".Trim()) { $b['currentLicenceId'] = "$CurrentLicenceId".Trim() }
    $hs = "$CurrentLicenceSha256".Trim().ToLowerInvariant(); if ($hs -match '^[0-9a-f]{64}$') { $b['currentLicenceSha256'] = $hs }
    if ($CurrentValidTo) { try { $b['currentValidTo'] = ([datetime]$CurrentValidTo).ToString('yyyy-MM-dd') } catch { } }
    $b
}

function New-EpsLicenceKnockHeaders {
    # PURE. The install key (when there is one) and the install's lasting id as headers - never a made-up id
    param([AllowNull()][string]$InstallKey, [AllowNull()][string]$InstallId)
    $h = @{}
    if ("$InstallKey".Trim() -match '^inv-[A-Za-z0-9_-]{20,100}$') { $h['X-Invardia-Install-Key'] = "$InstallKey".Trim() }
    if ("$InstallId".Trim().ToLowerInvariant() -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $h['X-Invardia-Install-Id'] = "$InstallId".Trim().ToLowerInvariant() }
    $h
}

function Test-EpsLicenceDelivery {
    <#
      PURE (given the verifier). Is a delivered licence installable HERE? @{ ok; reason; text; licence }. The SHA-256 of the
      decoded bytes, the signature (the embedded signers), this product, a Pro edition (trial included) for THIS tenant, not
      expired. Never takes Invardia's word for any of it.
    #>
    param([Parameter(Mandatory)]$Delivery, [Parameter(Mandatory)][AllowEmptyString()][string]$TenantId, [string[]]$TrustedCertsB64, [AllowNull()][object]$Now)
    try { $bytes = [Convert]::FromBase64String("$($Delivery.contentBase64)") } catch { return @{ ok = $false; reason = 'the delivered licence is not base64' } }
    $h = -join ([Security.Cryptography.SHA256]::HashData($bytes) | ForEach-Object { $_.ToString('x2') })
    if ("$($Delivery.sha256)".Trim().ToLowerInvariant() -ne $h) { return @{ ok = $false; reason = 'the delivered licence does not match its SHA-256 - refused' } }
    $text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    $lic = Resolve-EpsLicenceStatus -Document $text -TrustedCertsB64 $TrustedCertsB64 -Now $Now
    if ("$($lic.Status)" -notin 'Valid', 'Grace') { return @{ ok = $false; reason = "the delivered licence is $($lic.Status): $($lic.Reason)" } }
    if (-not (Test-EpsLicenceTenant -License $lic -TenantId $TenantId)) { return @{ ok = $false; reason = "the delivered licence names $((@($lic.TenantIds)) -join ', '), not this tenant" } }
    if ((Get-EpsLicenceEdition -License $lic -TenantId $TenantId) -eq 'community') { return @{ ok = $false; reason = "the delivered licence ('$($lic.Sku)') is not an Entra Policy Suite Pro licence" } }
    @{ ok = $true; reason = ''; text = $text; licence = $lic }
}

function Invoke-EpsLicenceRequestCycle {
    <#
      One knock / pull step (the update job, every run). Seams: -Http { param($m, $u, $b, $h) } -> @{ status; body; error },
      -Store = @{ GetState {}; SetState { param($o) }; GetPull {} -> @{ Token; InstallId }; SetPull { param($token, $installId) };
      StoreLicence { param($text) } -> @{ Ok; Reason }; SetHint { param($id) } }. Returns @{ action; ok; state; message; stored }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Version,
          [AllowEmptyString()][string]$TenantId, [AllowEmptyString()][string]$LicenceText, [AllowEmptyString()][string]$InstallKey,
          [AllowEmptyString()][string]$SupersededBy = '', [AllowEmptyString()][string]$InstallEdition = '', [datetime]$NowUtc = [datetime]::UtcNow, [AllowEmptyString()][string]$Connect = '',
          [string]$BaseUrl = $script:EpsLicenceBase, [string[]]$TrustedCertsB64)
    $NowUtc = $NowUtc.ToUniversalTime()
    $base = "$BaseUrl".Trim().TrimEnd('/')
    $lic = if ("$LicenceText".Trim()) { Resolve-EpsLicenceStatus -Document $LicenceText -TrustedCertsB64 $TrustedCertsB64 -Now $NowUtc } else { $null }
    $proHere = [bool]($lic -and (Get-EpsLicenceEdition -License $lic -TenantId $TenantId) -ne 'community')
    $state = & $Store.GetState
    $pull = & $Store.GetPull; $token = "$($pull.Token)".Trim()
    $proIntended = [bool]("$LicenceText".Trim() -or "$InstallKey".Trim() -match '^inv-' -or "$SupersededBy".Trim() -or "$InstallEdition".Trim() -ieq 'pro')
    $d = Get-EpsLicenceRequestDecision -License $lic -ProHere $proHere -State $state -HasToken ([bool]$token) -NowUtc $NowUtc -SupersededBy $SupersededBy -ProIntended $proIntended -Connected ("$Connect".Trim() -ieq 'yes')
    if ($d.clearHint) { & $Store.SetHint '' }
    $save = { param($Status, $Msg, $Extra) $o = [ordered]@{ status = $Status; message = $Msg; requestId = "$($state.requestId)"; requestedUtc = "$($state.requestedUtc)"; nextPollUtc = "$($state.nextPollUtc)"; reason = '' }
              if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
              & $Store.SetState ([pscustomobject]$o); [pscustomobject]$o }
    if ($d.action -eq 'none') { return @{ action = 'none'; ok = $true; state = $state; message = $d.reason; stored = $false } }
    if ("$TenantId" -notmatch '^[0-9a-fA-F-]{36}$') { return @{ action = $d.action; ok = $false; state = $state; message = 'this install''s tenant is not known - no request is sent'; stored = $false } }
    if ($base -notmatch '^(?i)https://') { return @{ action = $d.action; ok = $false; state = $state; message = 'the licence address is not https - no request is sent'; stored = $false } }
    if ($d.action -eq 'knock') {
        $iid = "$($pull.InstallId)".Trim().ToLowerInvariant()
        if ($iid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $iid = [guid]::NewGuid().ToString('D'); & $Store.SetPull $token $iid; $iid = "$((& $Store.GetPull).InstallId)".Trim().ToLowerInvariant() }
        $body = New-EpsLicenceKnockBody -Version $Version -TenantId $TenantId -InstallId $(if ($iid) { $iid } else { [guid]::NewGuid().ToString('D') }) -CurrentLicenceId "$(if ($lic) { $lic.LicenseId })" -CurrentValidTo $(if ($lic) { $lic.ValidTo }) -CurrentLicenceSha256 (Get-EpsLicenceFileSha256 -LicenceText $LicenceText) -Edition $(if ($d.community) { 'community' } else { '' })
        $r = $null; try { $r = & $Http 'POST' "$base/api/licence-requests" $body (New-EpsLicenceKnockHeaders -InstallKey $InstallKey -InstallId $iid) } catch { $r = @{ status = 0; body = $null; error = 'the request failed' } }
        if ("$($r.status)" -eq '200' -and "$($r.body.status)" -eq 'Community') {
            # PRO-COMMUNITY-SAME: the free set - no request, no pull; asked again when Invardia says (24 h)
            $wait = [Math]::Max(3600, [int]"0$($r.body.pollAfterSeconds)")
            $st = & $save 'Community' "Community: Invardia answered the free set (no licence for this tenant) - asked again $($NowUtc.AddSeconds($wait).ToString('yyyy-MM-dd HH:mm')) UTC" ([ordered]@{ requestId = ''; requestedUtc = $NowUtc.ToString('o'); nextPollUtc = $NowUtc.AddSeconds($wait).ToString('o') })
            return @{ action = 'knock'; ok = $true; state = $st; message = $st.message; stored = $false; community = $true }
        }
        if ("$($r.status)" -notin '200', '201', '202' -or -not "$($r.body.pullToken)") {
            # Invardia's own reason (its error code / message - never a secret: the request carries the install key in a
            # header only) is kept, so a refusal can be acted on (found at the first live knock, 2026-11-05: a bare 422)
            $why = ''
            if ($r.body) { $e = $r.body; $why = "$(if ($e.error) { $e.error } elseif ($e.code) { $e.code })$(if ($e.message) { ': ' + $e.message } elseif ($e.reason) { ': ' + $e.reason })"; if (-not $why -and $e -is [string]) { $why = "$e" } }
            if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
            $st = & $save 'Error' "the licence request could not be sent (HTTP $([int]"0$($r.status)")$(if ($why) { " - Invardia: $why" })) - sent again on the next run" $null
            return @{ action = 'knock'; ok = $false; state = $st; message = $st.message; stored = $false }
        }
        $token = "$($r.body.pullToken)"; & $Store.SetPull $token $iid
        $wait = [Math]::Max(60, [int]"0$($r.body.pollAfterSeconds)")
        $st = & $save 'Pending' "licence requested $($NowUtc.ToString('yyyy-MM-dd')) ($($d.reason)), waiting for Invardia" ([ordered]@{ requestId = "$($r.body.requestId)"; requestedUtc = $NowUtc.ToString('o'); nextPollUtc = $NowUtc.AddSeconds($wait).ToString('o') })
        if ("$($r.body.status)" -ne 'Approved') { return @{ action = 'knock'; ok = $true; state = $st; message = $st.message; stored = $false } }
        $state = $st   # approved at once (a renewal / the trial): pull now
    }
    # an EMPTY JSON object, never no body (PIM, live 2026-10-04: no body = 400)
    $p = $null; try { $p = & $Http 'POST' "$base/api/licence-requests/pull" ([ordered]@{}) @{ 'X-Invardia-Pull-Token' = $token } } catch { $p = @{ status = 0; error = 'the request failed' } }
    if ("$($p.status)" -in '401', '410') { & $Store.SetPull '' "$($pull.InstallId)"; $st = & $save 'Expired' 'the request expired at Invardia - a new one is sent on the next run' $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message; stored = $false } }
    if ("$($p.status)" -notin '200', '202') { $st = & $save 'Pending' "Invardia could not be reached (HTTP $([int]"0$($p.status)")) - asked again on the next run" $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message; stored = $false } }
    switch ("$($p.body.status)") {
        'Rejected' { & $Store.SetPull '' "$($pull.InstallId)"; $st = & $save 'Rejected' "Invardia rejected the licence request$(if ("$($p.body.reason)") { ": $($p.body.reason)" }) - contact Invardia" ([ordered]@{ reason = "$($p.body.reason)" }); return @{ action = 'pull'; ok = $true; state = $st; message = $st.message; stored = $false } }
        'Approved' {
            if (-not $p.body.licence) { $st = & $save 'Pending' 'approved - the licence is being signed' $null; return @{ action = 'pull'; ok = $true; state = $st; message = $st.message; stored = $false } }
            $v = Test-EpsLicenceDelivery -Delivery $p.body.licence -TenantId $TenantId -TrustedCertsB64 $TrustedCertsB64 -Now $NowUtc
            if (-not $v.ok) { $st = & $save 'Error' "NOT installed: $($v.reason)" $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message; stored = $false } }
            $sr = & $Store.StoreLicence $v.text
            if ($sr -and -not $sr.Ok) { $st = & $save 'Error' "verified, but NOT stored: $($sr.Reason) - pulled again on the next run" $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message; stored = $false } }
            & $Store.SetPull '' "$($pull.InstallId)"
            if ("$SupersededBy".Trim()) { & $Store.SetHint '' }
            $st = & $save 'Installed' "installed: $(Get-EpsLicenceEditionText (Get-EpsLicenceEdition -License $v.licence -TenantId $TenantId)), valid to $(([datetime]$v.licence.ValidTo).ToString('yyyy-MM-dd'))" ([ordered]@{ nextPollUtc = '' })
            return @{ action = 'pull'; ok = $true; state = $st; message = $st.message; stored = $true; text = $v.text }
        }
        default {
            $wait = [Math]::Max(60, [int]"0$($p.body.pollAfterSeconds)")
            $st = & $save 'Pending' 'licence requested, waiting for Invardia' ([ordered]@{ nextPollUtc = $NowUtc.AddSeconds($wait).ToString('o') })
            return @{ action = 'pull'; ok = $true; state = $st; message = $st.message; stored = $false }
        }
    }
}

# ---------------------------------------------------------------------------------------------------- the update job's SQL
function Get-EpsLicenceRequestState {
    # the knock / pull state as the cycle reads it (eps.License); $null = none
    param([Parameter(Mandatory)][string]$ConnectionString)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT RequestStatus, RequestMessage, RequestId, RequestAtUtc, NextPollUtc FROM eps.License WHERE Id = 1')[0]
    if (-not $r -or -not "$($r.RequestStatus)") { return $null }
    $d = { param($v) if ($v -is [datetime]) { ([datetime]::SpecifyKind($v, 'Utc')).ToString('o') } else { '' } }
    [pscustomobject]@{ status = "$($r.RequestStatus)"; message = "$($r.RequestMessage)"; requestId = "$($r.RequestId)"; requestedUtc = (& $d $r.RequestAtUtc); nextPollUtc = (& $d $r.NextPollUtc); reason = $(if ("$($r.RequestStatus)" -eq 'Rejected') { "$($r.RequestMessage)" -replace '^Invardia rejected the licence request:?\s*', '' -replace '\s*-\s*contact Invardia$', '' } else { '' }) }
}

function Set-EpsLicenceRequestState {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$State)
    $dt = { param($v) $x = $null; if ("$v".Trim()) { try { $x = ([datetime]"$v").ToUniversalTime() } catch { $x = $null } }; if ($x) { $x } else { [DBNull]::Value } }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ s = "$($State.status)"; m = "$($State.message)"; i = "$($State.requestId)"; a = (& $dt $State.requestedUtc); n = (& $dt $State.nextPollUtc) } -Query @'
MERGE eps.License WITH (HOLDLOCK) AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id
WHEN MATCHED THEN UPDATE SET RequestStatus = @s, RequestMessage = LEFT(@m, 1000), RequestId = NULLIF(@i, ''), RequestAtUtc = @a, NextPollUtc = @n
WHEN NOT MATCHED THEN INSERT (Id, RequestStatus, RequestMessage, RequestId, RequestAtUtc, NextPollUtc) VALUES (1, @s, LEFT(@m, 1000), NULLIF(@i, ''), @a, @n);
'@)
}

function Get-EpsLicencePull {
    # the pull token and the install's lasting id (eps.LicensePull, which only the engine reads)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT PullToken, InstallId FROM eps.LicensePull WHERE Id = 1')[0]
    @{ Token = $(if ($r) { "$($r.PullToken)" } else { '' }); InstallId = $(if ($r) { "$($r.InstallId)" } else { '' }) }
}

function Set-EpsLicencePull {
    # the token is replaced; the install id is written only when none is held (created once, kept - INV-S16)
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowEmptyString()][string]$Token, [AllowEmptyString()][string]$InstallId)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = "$Token"; i = "$InstallId".Trim().ToLowerInvariant() } -Query @'
MERGE eps.LicensePull WITH (HOLDLOCK) AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id
WHEN MATCHED THEN UPDATE SET PullToken = NULLIF(@t, ''), InstallId = COALESCE(NULLIF(d.InstallId, ''), NULLIF(@i, '')), UpdatedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Id, PullToken, InstallId) VALUES (1, NULLIF(@t, ''), NULLIF(@i, ''));
'@)
}

function Save-EpsLicenceText {
    <# The verified licence into eps.License (the copy every component reads, re-verified on every read). Update job only. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Text, [string]$By = 'caj-eps-update (from Invardia)')
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $Text; b = $By } -Query @'
MERGE eps.License WITH (HOLDLOCK) AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id
WHEN MATCHED THEN UPDATE SET LicenceText = @t, SetBy = @b, SetAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Id, LicenceText, SetBy, SetAtUtc) VALUES (1, @t, @b, SYSUTCDATETIME());
'@)
    $script:EpsLicenceCache = @{ At = [datetime]::MinValue; Key = ''; Value = $null }
}

function Set-EpsLicenceSupersededBy {
    # the heartbeat answer's supersededBy (a licence id, or '' to clear) - the update job knocks for the successor
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowEmptyString()][string]$LicenceId)
    $v = "$LicenceId".Trim(); if ($v -and $v -notmatch '^[A-Za-z0-9._-]{1,100}$') { return }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = $v } -Query @'
MERGE eps.License WITH (HOLDLOCK) AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id
WHEN MATCHED THEN UPDATE SET SupersededBy = NULLIF(@v, '')
WHEN NOT MATCHED AND @v <> '' THEN INSERT (Id, SupersededBy) VALUES (1, @v);
'@)
}

function Set-EpsLicenceUsage {
    <# The Business cap noted after a user tagging run (users in scope + the state). A warning only - nothing ever stops. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][object]$Count, [string]$State = 'none')
    if ($State -notin 'none', 'ok', 'warn', 'at', 'over') { $State = 'none' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ c = $(if ($null -ne $Count) { [int]$Count } else { [DBNull]::Value }); s = $State } -Query @'
MERGE eps.License WITH (HOLDLOCK) AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id
WHEN MATCHED THEN UPDATE SET UsersInScope = @c, UsageState = @s
WHEN NOT MATCHED THEN INSERT (Id, UsersInScope, UsageState) VALUES (1, @c, @s);
'@)
}

function Invoke-EpsLicenceUsageNote {
    <#
      After a user tagging run: the users it looked at against the Business cap -> eps.License (Overview / Licence page /
      heartbeat) and ONE line on the run when at 90 % or more (SI-LicenceLimit, PIM's Get-PimAdminLicenceUsage). Never
      throws, never stops anything: @{ state; message }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][object]$UsersInScope, [scriptblock]$Log = { param($l, $m) })
    try {
        $l = Get-EpsLicence -ConnectionString $ConnectionString
        $u = Get-EpsLicenceUsage -License $l.License -TenantId $l.TenantId -UsersInScope $UsersInScope
        Set-EpsLicenceUsage -ConnectionString $ConnectionString -Count $UsersInScope -State $u.state
        if ($u.state -in 'warn', 'at', 'over') { & $Log 'Warning' "licence: $($u.message)" }
        return @{ state = $u.state; message = $u.message }
    } catch { return @{ state = 'none'; message = "the licence cap was not noted: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}

function Invoke-EpsLicenceCycle {
    <#
      The UPDATE job's licence step (every run, before the release check): knock / pull / verify / store the licence, then
      claim the install key with it (LIC-01). The licence and the key are written into the install's Key Vault as the
      update job's own identity (-WriteSecret { param($name, $value) } -> @{ Ok; Reason }, default Set-EpsInstallSecret);
      the licence also into eps.License. Returns @{ InstallKey; LicenceText; Edition; Lines }. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Version, [scriptblock]$Http,
          [AllowEmptyString()][string]$InstallKey, [scriptblock]$WriteSecret, [scriptblock]$Log = { param($l, $m) },
          [string]$TenantId = (Get-EpsLicenceTenantId), [string]$InstallEdition = $env:EPS_INSTALL_EDITION, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Connect = $env:EPS_CONNECT_INVARDIA,
          [string[]]$TrustedCertsB64)
    if (-not $Http) { $Http = { param($m, $u, $b, $h) Invoke-EpsUpdateHttp -Method $m -Url $u -Body $b -Headers $h } }
    if (-not $WriteSecret) { $WriteSecret = { param($n, $v) Set-EpsInstallSecret -Name $n -Value $v } }
    $out = @{ InstallKey = "$InstallKey"; LicenceText = ''; Edition = 'community' }
    $cs = $ConnectionString
    try {
        $row = Get-EpsStoredLicence -ConnectionString $cs
        $text = if ($row) { "$($row.Text)" } else { '' }
        $store = @{
            GetState = { Get-EpsLicenceRequestState -ConnectionString $cs }
            SetState = { param($o) Set-EpsLicenceRequestState -ConnectionString $cs -State $o }
            GetPull  = { Get-EpsLicencePull -ConnectionString $cs }
            SetPull  = { param($t, $i) Set-EpsLicencePull -ConnectionString $cs -Token $t -InstallId $i }
            SetHint  = { param($id) Set-EpsLicenceSupersededBy -ConnectionString $cs -LicenceId $id }
            StoreLicence = { param($t)
                $kv = & $WriteSecret 'eps-licence' $t
                if ($kv -and -not $kv.Ok) { return @{ Ok = $false; Reason = $kv.Reason } }
                Save-EpsLicenceText -ConnectionString $cs -Text $t
                @{ Ok = $true; Reason = 'stored' } }
        }
        $rq = Invoke-EpsLicenceRequestCycle -Http $Http -Store $store -Version $Version -TenantId $TenantId -LicenceText $text -InstallKey $InstallKey `
                -SupersededBy $(if ($row) { "$($row.SupersededBy)" } else { '' }) -InstallEdition $InstallEdition -NowUtc $NowUtc -Connect $Connect -TrustedCertsB64 $TrustedCertsB64
        & $Log $(if ($rq.ok) { 'Info' } else { 'Warning' }) "licence request: $($rq.action) - $($rq.message)"
        if ($rq.stored) { $text = "$($rq.text)" }
        $lic = Resolve-EpsLicenceStatus -Document $text -TrustedCertsB64 $TrustedCertsB64 -Now $NowUtc
        $out.Edition = Get-EpsLicenceEdition -License $lic -TenantId $TenantId
        $out.LicenceText = $(if ($out.Edition -ne 'community') { $text } else { '' })
        & $Log 'Info' "licence: $(Get-EpsLicenceEditionText $out.Edition)$(if ($out.Edition -ne 'community') { " for $($lic.Customer), $($lic.Reason)" } elseif ($text) { " ($($lic.Reason))" })"
        if ($out.Edition -ne 'community') {
            $prev = Get-EpsStoredLicence -ConnectionString $cs
            $hasKey = "$InstallKey".Trim() -match '^inv-[A-Za-z0-9_-]{20,100}$'
            # claim when there is no key yet, or the licence changed since the last claim (a renewal re-binds at Invardia)
            if (-not $hasKey -or ($prev -and "$($prev.ClaimLicenceHash)" -and "$($prev.ClaimLicenceHash)" -ne (Get-EpsLicenceFileSha256 -LicenceText $text))) {
                $cl = Invoke-EpsInstallKeyClaim -Http $Http -LicenceText $text -TenantId $TenantId -Edition $out.Edition -SetKey { param($k) & $WriteSecret 'uplink-key' $k } -Previous $prev
                & $Log $(if ($cl.action -in 'refused', 'retry') { 'Warning' } else { 'Info' }) "install key claim: $($cl.action) - $($cl.message)"
                if ($cl.action -ne 'none') { try { Set-EpsLicenceClaimState -ConnectionString $cs -Result $cl } catch { & $Log 'Warning' "the claim state was not stored: $((("$($_.Exception.Message)") -split "`n")[0])" } }
                if ($cl.key) { $out.InstallKey = "$($cl.key)" }   # also when it was not stored: this run still uses it
            }
        }
        # OPT-IN-1 "claim on yes": a Community install whose user said yes at install claims its Community key (no licence)
        if ($out.Edition -eq 'community' -and "$Connect".Trim() -ieq 'yes' -and "$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') {
            $cl = Invoke-EpsCommunityKeyClaim -Http $Http -TenantId $TenantId -SetKey { param($k) & $WriteSecret 'uplink-key' $k } -Previous (Get-EpsStoredLicence -ConnectionString $cs)
            & $Log $(if ($cl.action -in 'refused', 'retry') { 'Warning' } else { 'Info' }) "install key claim (Community, connected): $($cl.action) - $($cl.message)"
            if ($cl.action -ne 'none') { try { Set-EpsLicenceClaimState -ConnectionString $cs -Result $cl } catch { & $Log 'Warning' "the claim state was not stored: $((("$($_.Exception.Message)") -split "`n")[0])" } }
            if ($cl.key) { $out.InstallKey = "$($cl.key)" }
        }
    } catch { & $Log 'Warning' "licence: $((("$($_.Exception.Message)") -split "`n")[0]) - Community features stay on, the next run tries again" }
    $out
}

function Clear-EpsLicenceClaim {
    <# "Claim again" (Licence page, SuperAdmin): forgets a refused / failed claim and a rejected / failed request, so the next
       update run asks Invardia again. The licence itself is never touched. Returns the rows changed. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    [int](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query "UPDATE eps.License SET ClaimAction = NULL, ClaimMessage = NULL, ClaimAtUtc = NULL, ClaimLicenceHash = NULL, RequestStatus = CASE WHEN RequestStatus IN (N'Rejected', N'Error', N'Expired') THEN NULL ELSE RequestStatus END WHERE Id = 1")
}

function Set-EpsLicenceClaimState {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Result)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ a = "$($Result.action)"; m = "$($Result.message)"; h = "$($Result.hash)" } `
        -Query 'UPDATE eps.License SET ClaimAction = @a, ClaimMessage = LEFT(@m, 1000), ClaimAtUtc = SYSUTCDATETIME(), ClaimLicenceHash = @h WHERE Id = 1')
}

function Get-EpsProUpdateTarget {
    <#
      The Pro channel (kind 'code', PIM's Invoke-PimInvardiaManifestPull through the shared verifier): with a Pro licence
      AND an install key, POST <base>/api/updates/entrapolicysuite/manifest { kind: 'code'; licence; ring } + the key header
      -> the same verification as the Community answer (Test-InvardiaManifest: embedded keys, product, kind, ring, version,
      SHA-256, size, https). Without either: State 'community' (the Community channel stays the path).
      Returns @{ State; Version; Sequence; Reason; Size; Sha256; DownloadUrl } as Get-EpsUpdateTarget.
    #>
    param([Parameter(Mandatory)][string]$RunningVersion, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [scriptblock]$Http,
          [AllowEmptyString()][string]$InstallKey, [AllowEmptyString()][string]$LicenceText, [string]$Edition = 'community',
          [string]$BaseUrl = $script:EpsLicenceBase, [int]$AppliedSequence = 0, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys)
    $res = @{ State = 'community'; Version = ''; Sequence = 0; Reason = ''; Size = 0; Sha256 = ''; DownloadUrl = '' }
    if ($Edition -eq 'community' -or -not "$LicenceText".Trim()) { $res.Reason = 'no Pro licence: the Community channel'; return $res }
    if ("$InstallKey".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { $res.Reason = 'no install key yet (claimed with the licence): the Community channel'; return $res }
    $base = "$BaseUrl".Trim().TrimEnd('/'); if ($base -notmatch '^(?i)https://') { $res.State = 'refused'; $res.Reason = 'the update address is not https'; return $res }
    $url = "$base/api/updates/$($script:EpsLicenceClaimProduct)/manifest"
    $r = & $Http 'POST' $url ([ordered]@{ kind = 'code'; licence = "$LicenceText"; ring = $Ring }) @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -eq 204) { $res.State = 'current'; $res.Reason = "nothing Pro is released to ring $Ring yet"; return $res }
    if ($st -ne 200) { $res.State = $(if ($st -in 401, 403, 404, 422) { 'refused' } else { 'unreachable' }); $res.Reason = Get-InvardiaPullReason -Status $st -Body $r.body -ErrorText "$($r.error)"; return $res }
    $v = Test-InvardiaManifest -Response $r.body -TrustedKeys $TrustedKeys -Kind 'code' -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Product $script:EpsLicenceClaimProduct -Ring $Ring
    if (-not $v.ok) { $res.State = 'refused'; $res.Reason = $v.reason; return $res }
    $res.Version = "$($v.version)"; $res.Sequence = [int]$v.sequence; $res.Size = [int64]$v.size; $res.Sha256 = "$($v.sha256)"; $res.DownloadUrl = "$($v.downloadUrl)"
    if ($v.hold) { $res.State = 'held'; $res.Reason = $v.reason; return $res }
    $cmp = Compare-InvardiaReleaseVersion $v.version $RunningVersion
    $res.State = if ($cmp -gt 0) { 'available' } elseif ($cmp -lt 0) { 'ahead' } else { 'current' }
    $res.Reason = "$($v.reason) (the signed Pro package)"
    $res
}
