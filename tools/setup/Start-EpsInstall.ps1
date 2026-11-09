#Requires -Version 7.2
<#
.SYNOPSIS
    Downloads Entra Policy Suite 2.0 from its GitHub release and starts the install (the launcher is an asset of every
    release: https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1).
.DESCRIPTION
    Takes the latest v2 release of KnudsenMorten/EntraPolicySuite (or -Version), downloads its zip into a new temporary
    folder, checks it against the SHA-256 digest GitHub publishes for the asset (a mismatch, or no digest, deletes it and stops), unpacks
    it and runs its tools/setup/Install-EntraPolicySuite.ps1 with your parameters. v1 (the scripts) is on the v1 branch
    and is never downloaded or changed by this.
    Run it in PowerShell 7 or Azure Cloud Shell:
        Invoke-WebRequest https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1 -OutFile Start-EpsInstall.ps1
        ./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
    Add -WhatIf at the end of line 2 to see the plan first (nothing is created in Azure).
    Exit code: the installer's (0 done, 1 a step failed, 2 a check failed, 4 waiting for a step of yours - run again when done), 3 = the download failed or did not match.
.LINK
    https://invardia.com/docs/eps/scripts/Start-EpsInstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    # every other parameter is the installer's own and passed on only when you give it (the installer's defaults apply);
    # tools/setup/install-parameters.json lists them, a test keeps the three in step
    [string]$Location,
    [string]$ResourceGroup,
    [string]$StatePath,
    [string]$SqlLocation,
    [string]$SqlAdminGroupId,
    [string]$SqlAdminGroupName,
    [switch]$ReplaceSqlAdminGroup,
    [switch]$RenameJobs,
    [string]$Ring,
    [string[]]$ExcludeGraphRole,
    [switch]$Quiet,
    [string]$SupportAppId,
    [string]$SupportAccess,
    [switch]$Resume,
    # the private network install (NET-1)
    [switch]$PrivateNetwork,
    [string]$VnetId,
    [string]$VnetAddressPrefix,
    [string]$VnetName,
    [string]$AppsSubnetName,
    [string]$AppsSubnetPrefix,
    [string]$EndpointsSubnetName,
    [string]$EndpointsSubnetPrefix,
    [string]$PrivateDnsZonesResourceGroupId,
    [string]$HubVnetId,
    [switch]$LinkZonesToHub,
    [switch]$PeerToHub,
    [string[]]$InternalRanges,
    [string]$FirewallIp,
    [string]$WebAppAccess,
    [switch]$ConfirmedFromInside,
    [ValidatePattern('^$|^2\.\d+\.\d+$')][string]$Version,
    # test seams (as PIM's launcher): the release lookup, the download, the hand-over
    [scriptblock]$GetRelease, [scriptblock]$Download, [scriptblock]$RunInstaller,
    # the Pro copy's seams (INSTALL-PRO): Invardia's package answer, the sign-in, the package download
    [scriptblock]$ProHttp, [scriptblock]$ProToken, [scriptblock]$ProFetch
)
$ErrorActionPreference = 'Stop'
# INSTALL-PRO (2.0.86, PIM's INSTALL-CHANNEL): the GitHub copy says 'community' and takes the release from GitHub; the copy
# Invardia publishes (invardia.com/support/eps/) says 'pro' and takes the SIGNED Pro package from Invardia - never GitHub.
# Publish-EpsHandover changes only the quoted value below; a test keeps the two copies equal on every other byte.
$script:EpsInstallChannel = 'community'   # INSTALL-CHANNEL: community (GitHub) | pro (invardia.com) - stamped by Publish-EpsHandover

# ---- the Pro download (PRO-PACKAGE-FROM-INVARDIA, PIM's _PimInstallProPackage.ps1) ----------------------------------------
# 1. the person's browser sign-in for the TARGET tenant (auth code + PKCE on the loopback, the Azure CLI public client over
#    REST - no module, never device code), audience ARM; 2. GET https://invardia.com/api/install/entrapolicysuite/package
#    ?ring=<r>&tenantId=<t> with that token (Invardia checks the tenant); 3. the answer verified as the updater verifies a
#    release (the EMBEDDED Invardia keys, product, kind 'code', ring, version, SHA-256, size); 4. the zip into a NEW temp
#    folder, its size + SHA-256 the signed ones. Any failure: one calm line, exit 3, nothing else is tried.
$script:EpsProBase = 'https://invardia.com'; $script:EpsProProduct = 'entrapolicysuite'
function Get-EpsProSignInToken {
    param([Parameter(Mandatory)][string]$Tenant)
    $cid = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI (first-party public client), used over REST
    $scope = 'https://management.azure.com/.default offline_access openid profile'
    $verifier = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $challenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $state = [guid]::NewGuid().ToString('N')
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $listener.Start()
    try {
        $redirect = "http://localhost:$(([Net.IPEndPoint]$listener.LocalEndpoint).Port)/"
        $url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?client_id=$cid&response_type=code&response_mode=query&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
        Write-Host "Sign in as an administrator of tenant $Tenant (Entra Policy Suite Pro is downloaded from Invardia for that tenant): $url" -ForegroundColor Yellow
        if ($env:EPS_SIGNIN_BROWSER -ne 'none') { try { Start-Process $url -WhatIf:$false } catch { } }
        $task = $listener.AcceptTcpClientAsync(); if (-not $task.Wait(300000)) { throw 'no sign-in within 5 minutes' }
        $client = $task.Result
        try {
            $stream = $client.GetStream(); $line = [IO.StreamReader]::new($stream).ReadLine()
            $q = if ($line -match '^GET\s+/\?(\S*)\s') { $Matches[1] } else { '' }
            $kv = @{}; foreach ($pair in $q.Split('&')) { $p = $pair.Split('=', 2); if ($p.Count -eq 2) { $kv[$p[0]] = [uri]::UnescapeDataString($p[1]) } }
            $html = '<html><body style="font-family:sans-serif"><h3>Entra Policy Suite</h3><p>You can close this window.</p></body></html>'
            $bytes = [Text.Encoding]::UTF8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $([Text.Encoding]::UTF8.GetByteCount($html))`r`nConnection: close`r`n`r`n$html")
            $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
        } finally { $client.Dispose() }
    } finally { $listener.Stop() }
    if ($kv.state -ne $state -or -not $kv.code) { throw "the sign-in did not complete $($kv.error)" }
    $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        client_id = $cid; grant_type = 'authorization_code'; code = $kv.code; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    $p = "$($r.access_token)".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
    if ("$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid)".ToLowerInvariant() -ne $Tenant) { throw "you signed in to another tenant than $Tenant" }
    "$($r.access_token)"
}
function ConvertFrom-EpsProPackageAnswer {
    # PURE. THE one place that knows Invardia's answer (PIM's ConvertFrom-PimInstallProPackageAnswer): @{ ok; response; reason }
    param([int]$Status, $Body, [string]$ErrorText = '', [int]$Ring = 3)
    $why = "$($Body.message)".Trim(); if (-not $why) { $why = "$($Body.reason)$($Body.error)".Trim() }; if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    $w = if ($why) { " ($why)" } else { '' }
    switch ($Status) {
        200 { $o = $Body; if (-not "$($o.manifestB64)".Trim() -and $o.package) { $o = $o.package }
              if (-not "$($o.manifestB64)".Trim()) { return @{ ok = $false; reason = 'Invardia answered, but without a signed package' } }
              return @{ ok = $true; response = [pscustomobject]@{ manifestB64 = "$($o.manifestB64)"; signature = "$($o.signature)"; keyId = "$($o.keyId)"; downloadUrl = "$($o.downloadUrl)" }; reason = '' } }
        204 { return @{ ok = $false; reason = "Invardia has no Entra Policy Suite Pro release for ring $Ring yet" } }
        401 { return @{ ok = $false; reason = "Invardia refused the sign-in$w - sign in with an administrator account of the tenant you install into" } }
        403 { return @{ ok = $false; reason = "Invardia refused the download for this tenant$w" } }
        404 { return @{ ok = $false; reason = "Invardia has no Entra Policy Suite Pro package for this tenant and ring $Ring$w" } }
        0   { return @{ ok = $false; reason = "Invardia could not be reached$(if ("$ErrorText".Trim()) { " ($("$ErrorText".Trim()))" })" } }
        default { return @{ ok = $false; reason = "Invardia answered HTTP $Status$w" } }
    }
}
function Get-EpsProPackage {
    # the Pro copy's whole download, every outside call a seam: -GetToken { param($t) }, -Http { param($url, $token) }, -Fetch { param($url, $file) }
    param([Parameter(Mandatory)][string]$Tenant, [int]$Ring = 3, [string]$WantVersion = '', [scriptblock]$GetToken, [scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$Fetch,
          [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys, [string]$TempRoot = ([IO.Path]::GetTempPath()))
    $t = "$Tenant".Trim().ToLowerInvariant()
    if (-not $GetToken) { $GetToken = { param($x) Get-EpsProSignInToken -Tenant $x } }
    if (-not $Http) { $Http = { param($u, $k) try { $r = Invoke-WebRequest -Uri $u -Headers @{ Authorization = "Bearer $k"; 'User-Agent' = 'EntraPolicySuite-install' } -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop; @{ status = [int]$r.StatusCode; body = $(if ("$($r.Content)".Trim()) { "$($r.Content)" | ConvertFrom-Json }) } } catch { $c = 0; try { $c = [int]$_.Exception.Response.StatusCode } catch { }; $b = $null; try { $b = "$($_.ErrorDetails.Message)" | ConvertFrom-Json } catch { }; @{ status = $c; body = $b; error = 'the request failed' } } } }
    $tok = ''; try { $tok = "$(& $GetToken $t)" } catch { return @{ ok = $false; reason = "the sign-in for the download did not complete ($((("$($_.Exception.Message)") -split "`n")[0]))" } }
    if (-not $tok.Trim()) { return @{ ok = $false; reason = 'the sign-in for the download did not complete' } }
    $a = $null; try { $a = & $Http "$($script:EpsProBase)/api/install/$($script:EpsProProduct)/package?ring=$Ring&tenantId=$t" $tok } catch { $a = @{ status = 0; error = 'the request failed' } }
    $p = ConvertFrom-EpsProPackageAnswer -Status ([int]$a.status) -Body $a.body -ErrorText "$($a.error)" -Ring $Ring
    if (-not $p.ok) { return @{ ok = $false; reason = $p.reason } }
    $v = Test-InvardiaManifest -Response $p.response -TrustedKeys $TrustedKeys -Kind 'code' -Product $script:EpsProProduct -Ring $Ring
    if (-not $v.ok) { return @{ ok = $false; reason = "the package Invardia sent did not verify ($($v.reason)) - refused" } }
    if ($v.hold) { return @{ ok = $false; reason = "the release Invardia holds for ring $Ring cannot be installed by this command ($($v.reason))" } }
    if ("$WantVersion".Trim() -and "$($v.version)" -ne "$WantVersion".Trim()) { return @{ ok = $false; reason = "ring $Ring holds Entra Policy Suite Pro $($v.version), not $WantVersion" } }
    $dir = Join-Path $TempRoot "eps-pro-$($v.version)-$([guid]::NewGuid().ToString('N').Substring(0, 6))"; [void][IO.Directory]::CreateDirectory($dir)
    $zip = Join-Path $dir 'release.zip'
    try { & $Fetch "$($v.downloadUrl)" $zip } catch { }
    $chk = if (Test-Path -LiteralPath $zip -PathType Leaf) { Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size } else { @{ ok = $false; reason = 'the download did not complete' } }
    if (-not $chk.ok) { try { [IO.Directory]::Delete($dir, $true) } catch { }; return @{ ok = $false; reason = "$($chk.reason) - nothing was installed, the folder is removed" } }
    @{ ok = $true; reason = ''; dir = $dir; zip = $zip; version = "$($v.version)" }
}
# >>> INLINE engine/_shared/InvardiaUpdate.verify.ps1 (the shared verifier, byte for byte; a test keeps it equal) >>>
<#
.SYNOPSIS
  The product-NEUTRAL half of an Invardia update client: verify a signed update manifest and the archive it names.
  Framework contract UPDATE-1 (one signer for every product); Invardia docs/DESIGN.md §10 (the manifest + the pull).

.DESCRIPTION
  Copied BYTE-IDENTICAL into every product that takes updates from Invardia (PIM: engine/_shared/; SecurityInsight:
  engine/_shared/) and pinned there by a whole-file drift test. So: NO product names, settings, environment variables or
  layouts in this file -- the product is always PASSED IN (-Product). A change is made here first and copied.

  * the trusted update-signing public keys, EMBEDDED (a key fetched at run time is never trusted);
  * Test-InvardiaManifestSignature  RS256 (PKCS#1 v1.5, SHA-256) over the base64-DECODED manifest bytes;
  * Test-InvardiaManifest           signature + product + kind + version + SHA-256 + sequence (no replay) + https link;
                                    manualStep / minFromVersion HOLD;
  * Invoke-InvardiaManifestPull     POST <base>/api/updates/<product>/manifest {kind, licence, ring} + X-Invardia-Install-Key
                                    (+ X-Invardia-Install-Id when the product passes its lasting install id -- Invardia S16);
  * Save-InvardiaArchive / Test-InvardiaArchiveFile   the download is a zip of the SIGNED size + SHA-256.
  PS 5.1 + 7. No modules. Nothing here writes anything.
#>

$script:InvardiaUpdateDefaultBase = 'https://invardia.com'
# The trusted update-signing public keys (RSA, JWK n/e base64url), Invardia's list at GET /api/updates/keys, EMBEDDED.
# Add a key here -- never remove the old one in the same release.
# CN=Invardia-Updates (RSA 4096, valid to 2036-10-04, cert SHA-1 DDFF1C84930C290ECF234FB4C3F3C1D5B3F532F2), delivered by
# the Invardia session 2026-10-04 and checked here against Invardia's committed public certificate (modulus identical).
# Then verified against the LIVE GET https://invardia.com/api/updates/keys (same keyId, n and e).
$script:InvardiaUpdateTrustedKeys = @(
    @{ keyId = 'https://kv-invardia-gml64wkoe7np.vault.azure.net/keys/invardia-updates'; e = 'AQAB'
       n = 'tLDrlMq1et3H3vIomcjokhFXfkkyaYVT2F-BByLGk8Pa7lrN7xd-53AbJ3keqv0ZZSQG_V0rKFxbt5b0m7YTNKbBUXvsgLLFQQbouDu-Am-8blzNBjIyDKoQKYKYaYfCbL3Tjdil7RD5pFNV6Qt3wW54jzhPEmyArr2xRjVUOg2WYQe9CpD_pd6-ww9dFlGQwtT_VJvLs0xcXsJkitfxe5tJ7PV8BUKoDpXJQNl6j2M6iqILxAujBxFB3_fGHEfooDJGWu1jkqp2mW2yXots_3ZtKUlnAmwANQNAsVWAxLq-8bLy6b3VTIvMMWw9JyZubBhU8OriW3OBKK6O2k5CV_-O5b0zf_TaQSr64Mq2VPtKkzY1weiFRlwDzEfq-aiLzr-HWx1tB43QEISNoBkrdhC-G9wjCQRgWSoINWbnL--2HOnwdivT9GRaJ38Mng9gqPdrPFfrv6t2ZIn6g5X9GOz_ua1Fi0WyfRJ1ICzzQgiivB0bBdlUtxfV89b0TXwIT9JynV7VYS9uv5H56IXpcuDaWzIueq6bVlWqk6p-cEMviDKMdaME3JW_Q-qNBCF1Q-cCAGl269KtFWQt2aLU2f50JkwW8h5slY1I05PXbJaX26n-Zu9pdrq-us3la8D1v_V9ehsR2s6Xj4cKZRZAURd5ut42R8h7EIe7K17KeZE' }
)

function ConvertFrom-InvardiaBase64Url {
    <# PURE. base64url (or plain base64) text -> bytes. #>
    param([AllowEmptyString()][string]$Text)
    $t = "$Text".Trim().Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return [Convert]::FromBase64String($t)
}

function Compare-InvardiaReleaseVersion {
    <# PURE. -1 / 0 / 1 for two dotted numeric versions ('2.4.491'); a non-numeric part compares as 0. #>
    param([string]$A, [string]$B)
    $pa = @("$A".Trim() -split '\.'); $pb = @("$B".Trim() -split '\.')
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = 0; $y = 0
        if ($i -lt $pa.Count) { [void][int]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][int]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    return 0
}

function Test-InvardiaManifestSignature {
    <#
      PURE (crypto only). RS256 over the bytes behind -ManifestB64, signature base64, by the key -KeyId of -TrustedKeys
      (@( @{ keyId; n; e } )). Returns @{ ok; reason }. PS 5.1-safe: RSAParameters + ImportParameters, no ImportFromPem.
    #>
    param([string]$ManifestB64, [string]$Signature, [string]$KeyId, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys)
    $keys = @($TrustedKeys | Where-Object { $_ })
    if (-not $keys.Count) { return @{ ok = $false; reason = 'no trusted update-signing key is embedded in this version yet -- every manifest is refused until one is' } }
    $k = @($keys | Where-Object { "$($_.keyId)" -ceq "$KeyId" })[0]
    if (-not $k) { return @{ ok = $false; reason = "the manifest is signed by key '$KeyId', which this version does not trust" } }
    try {
        $data = [Convert]::FromBase64String("$ManifestB64".Trim())
        $sig = [Convert]::FromBase64String("$Signature".Trim())
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus = ConvertFrom-InvardiaBase64Url "$($k.n)"
        $p.Exponent = ConvertFrom-InvardiaBase64Url "$($k.e)"
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportParameters($p)
            $ok = $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } finally { $rsa.Dispose() }
        if ($ok) { return @{ ok = $true; reason = '' } }
        return @{ ok = $false; reason = 'the manifest signature does not verify' }
    } catch { return @{ ok = $false; reason = "the manifest signature could not be checked: $($_.Exception.Message)" } }
}

function Test-InvardiaManifest {
    <#
      PURE (given the trusted keys). Everything about a 200 answer, before anything is downloaded. Returns
      @{ ok; hold; reason; version; sequence; sha256; size; downloadUrl; manifest }.
        ok=$false            refused (signature, shape, product, kind, replay) -- nothing moves
        ok=$true, hold=$true  verified, but the release asks for a manual step or a newer starting version -- nothing moves
    #>
    # -Ring (framework UPDATE-1.7, 2026-10-06: the solution decides the ring, Invardia relays): the ring this environment
    # asked for (0-3; every product caller passes the installation's own ring). A manifest for another ring, or one that names
    # no ring, is refused. -1 = the caller names no ring.
    param([Parameter(Mandatory)][object]$Response, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys,
          [string]$Kind = 'code', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [Parameter(Mandatory)][string]$Product, [int]$Ring = -1)
    $no = { param($why) @{ ok = $false; hold = $false; reason = $why; version = ''; sequence = 0; sha256 = ''; size = 0; downloadUrl = ''; manifest = $null } }
    $g = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } }
    $b64 = "$(& $g $Response 'manifestB64')".Trim()
    if (-not $b64) { return (& $no 'the answer carries no manifest') }
    $sv = Test-InvardiaManifestSignature -ManifestB64 $b64 -Signature "$(& $g $Response 'signature')" -KeyId "$(& $g $Response 'keyId')" -TrustedKeys $TrustedKeys
    if (-not $sv.ok) { return (& $no $sv.reason) }
    # Only the SIGNED bytes are read; the answer's own 'manifest' object is ignored.
    $m = $null; try { $m = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json } catch { return (& $no 'the signed manifest is not JSON') }
    if ("$($m.product)" -cne $Product) { return (& $no "the manifest is for '$($m.product)', not $Product") }
    if ("$($m.kind)" -cne $Kind) { return (& $no "the manifest is kind '$($m.kind)', not $Kind") }
    if ($Ring -ge 0) {
        $mr = -1; if (-not [int]::TryParse("$($m.ring)", [ref]$mr)) { return (& $no "the manifest names no ring (this environment asked for ring $Ring)") }
        if ($mr -ne $Ring) { return (& $no "the manifest is for ring $mr, not ring $Ring that this environment asked for") }
    }
    $ver = "$($m.version)".Trim(); if ($ver -notmatch '^\d+\.\d+\.\d+$') { return (& $no "the manifest names no release version ('$ver')") }
    $sha = "$($m.sha256)".Trim().ToLowerInvariant(); if ($sha -notmatch '^[0-9a-f]{64}$') { return (& $no 'the manifest carries no SHA-256') }
    $seq = 0; if (-not [int]::TryParse("$($m.sequence)", [ref]$seq) -or $seq -lt 1) { return (& $no 'the manifest carries no sequence') }
    if ($seq -lt $AppliedSequence) { return (& $no "REPLAY refused: sequence $seq is lower than the $AppliedSequence already applied here") }
    # F4 (framework UPDATE-1.5, 2026-10-05): the SIGNED size is required -- a manifest without it (or with 0) is refused,
    # so the archive check below always compares the length, never only the hash.
    $size = [int64]0; if (-not [int64]::TryParse("$($m.size)", [ref]$size) -or $size -lt 1) { return (& $no 'the manifest carries no archive size') }
    $url = "$(& $g $Response 'downloadUrl')".Trim()
    if ($url -notmatch '^https://') { return (& $no 'the download link is not https') }
    $r = @{ ok = $true; hold = $false; reason = "signed manifest: $ver (ring $($m.ring), sequence $seq)"; version = $ver; sequence = $seq; sha256 = $sha; size = $size; downloadUrl = $url; manifest = $m }
    if ("$($m.manualStep)".Trim()) { $r.hold = $true; $r.reason = "HELD -- $ver asks for a manual step first: $("$($m.manualStep)".Trim())" ; return $r }
    $mf = "$($m.minFromVersion)".Trim()
    if ($mf -and "$RunningVersion".Trim() -and (Compare-InvardiaReleaseVersion "$RunningVersion" $mf) -lt 0) {
        $r.hold = $true; $r.reason = "HELD -- $ver can only be installed from $mf or later; this environment runs $RunningVersion"; return $r
    }
    return $r
}

function Get-InvardiaPullReason {
    <# PURE. The admin's sentence for a non-200 pull answer. #>
    param([int]$Status, [AllowNull()][object]$Body, [string]$ErrorText = '')
    $why = if ($Body -and $Body.PSObject.Properties['reason']) { " ($($Body.reason))" } else { '' }
    switch ($Status) {
        204 { return 'nothing is released to this environment''s ring yet' }
        401 { return 'Invardia refused the install key (revoked, reset or wrong) -- claim a new one, or set the install key again' }
        403 { return "Invardia refused the licence$why -- updates need a valid Invardia-issued Pro licence for this tenant" }
        404 { return 'Invardia does not know the product' }
        422 { return "Invardia refused the request$why -- the pull must carry this environment's ring (0-3)" }
        429 { return 'Invardia asked to wait (rate limit) -- the next run asks again' }
        0   { return "Invardia could not be reached: $ErrorText" }
        default { return "Invardia answered HTTP $Status$why" }
    }
}

function Invoke-InvardiaManifestPull {
    <# The pull. -Http { param($Method, $Url, $Body, $Headers) } -> @{ status; body; error } (the product's own HTTP helper). #>
    # -Ring (UPDATE-1.7): the environment's OWN ring (0-3), set in the product; Invardia answers with what the product
    # published for that ring (204 when nothing). Required -- Invardia answers 422 without it.
    # -InstallId (Invardia S16): the install's own LASTING id, kept by the product. Sent as X-Invardia-Install-Id only when it
    # is a GUID (lower-cased); '' = no header. Never made up here -- a wrong id would lock the install key.
    param([Parameter(Mandatory)][string]$Product, [Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [string]$Kind = 'code',
          [AllowEmptyString()][AllowNull()][string]$InstallId = '',
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:InvardiaUpdateDefaultBase }
    $h = @{ 'X-Invardia-Install-Key' = $InstallKey }
    $iid = "$InstallId".Trim().ToLowerInvariant()
    if ($iid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $h['X-Invardia-Install-Id'] = $iid }
    $r = & $Http 'POST' "$base/api/updates/$Product/manifest" @{ kind = $Kind; licence = $LicenceText; ring = $Ring } $h
    $pullStatus = [int]$r.status
    return @{ status = $pullStatus; body = $r.body; reason = $(if ($pullStatus -eq 200) { '' } else { Get-InvardiaPullReason -Status $pullStatus -Body $r.body -ErrorText "$($r.error)" }) }
}

function Save-InvardiaArchive {
    <# Download the release zip and prove it is the one the manifest names (zip magic, size, SHA-256). @{ ok; bytes; reason }. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0, [int]$TimeoutSeconds = 300)
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
    try { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop }
    catch { return @{ ok = $false; bytes = 0; reason = "download failed: $($_.Exception.Message -replace '\?t=[^\s''"]+', '?t=***')" } }
    return (Test-InvardiaArchiveFile -Path $OutFile -ExpectedSha256 $ExpectedSha256 -ExpectedSize $ExpectedSize)
}

function Test-InvardiaArchiveFile {
    <# PURE (file read). The downloaded file is a zip of the size and SHA-256 the SIGNED manifest names. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0)
    # F4: the signed size is REQUIRED -- no expected size = refused (a caller that has none must not skip the length check)
    if ($ExpectedSize -lt 1) { return @{ ok = $false; bytes = 0; reason = 'no signed archive size to check the download against -- refused' } }
    if (-not (Test-Path -LiteralPath $Path)) { return @{ ok = $false; bytes = 0; reason = 'the download produced no file' } }
    $len = (Get-Item -LiteralPath $Path).Length
    $magic = New-Object byte[] 2
    $fs = [System.IO.File]::OpenRead($Path); try { [void]$fs.Read($magic, 0, 2) } finally { $fs.Dispose() }
    if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) { return @{ ok = $false; bytes = $len; reason = 'the downloaded file is not a zip' } }
    if ($len -ne $ExpectedSize) { return @{ ok = $false; bytes = $len; reason = "the archive is $len bytes, the signed manifest says $ExpectedSize" } }
    $sha = [System.Security.Cryptography.SHA256]::Create(); $fh = [System.IO.File]::OpenRead($Path)
    try { $h = ([BitConverter]::ToString($sha.ComputeHash($fh))).Replace('-', '').ToLowerInvariant() } finally { $fh.Dispose(); $sha.Dispose() }
    if ($h -ne "$ExpectedSha256".Trim().ToLowerInvariant()) { return @{ ok = $false; bytes = $len; reason = "the archive's SHA-256 ($h) is not the one the signed manifest names -- refused" } }
    return @{ ok = $true; bytes = $len; reason = '' }
}
# <<< INLINE <<<
Write-Host $(if ($script:EpsInstallChannel -eq 'pro') { 'Entra Policy Suite Pro: the signed Pro package from Invardia. Documentation: https://invardia.com/docs/eps/scripts/Start-EpsInstall' } else { 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme' })   # INS-05 (2.0.97): the Pro copy names its own source
# -WhatIf is for the INSTALLER (its plan, nothing changed in Azure); the download, the check and the unpack into a temp
# folder are real, or there is nothing to run (2026-10-30: the preference reached New-Item / Copy-Item and nothing was
# downloaded)
$what = [bool]$WhatIfPreference
$WhatIfPreference = $false
# the PUBLIC repository the release (the zip and this launcher as assets) comes from (public since 2.0.20)
$repo = 'KnudsenMorten/EntraPolicySuite'
if (-not $GetRelease) { $GetRelease = { param($v) Invoke-RestMethod -Uri $(if ($v) { "https://api.github.com/repos/$repo/releases/tags/v$v" } else { "https://api.github.com/repos/$repo/releases?per_page=30" }) -Headers @{ 'User-Agent' = 'EntraPolicySuite-install' } } }
if (-not $Download) { $Download = { param($url, $file) Invoke-WebRequest -Uri $url -OutFile $file -Headers @{ 'User-Agent' = 'EntraPolicySuite-install' } } }
if (-not $RunInstaller) { $RunInstaller = { param($script, $params) & $script @params; $LASTEXITCODE } }

if ($script:EpsInstallChannel -eq 'pro') {
    # the Pro copy: the signed package from Invardia (never GitHub); the installer is then run exactly as below
    $pr = if ("$Ring" -match '^[0-3]$') { [int]$Ring } else { 3 }
    $pk = Get-EpsProPackage -Tenant "$TenantId" -Ring $pr -WantVersion "$Version" -Http $ProHttp -GetToken $ProToken -Fetch $(if ($ProFetch) { $ProFetch } else { { param($u, $f) Invoke-WebRequest -Uri $u -OutFile $f -Headers @{ 'User-Agent' = 'EntraPolicySuite-install' } } })
    if (-not $pk.ok) { Write-Host "Entra Policy Suite Pro: $($pk.reason)" -ForegroundColor Red; exit 3 }
    Write-Host "Entra Policy Suite Pro $($pk.version) (ring $pr, signed by Invardia, SHA-256 checked)"
    Expand-Archive -LiteralPath $pk.zip -DestinationPath $pk.dir -Force
    $installer = Get-ChildItem -LiteralPath $pk.dir -Recurse -Filter 'Install-EntraPolicySuite.ps1' -File | Select-Object -First 1
    if (-not $installer) { Write-Host 'The Pro package has no tools/setup/Install-EntraPolicySuite.ps1.' -ForegroundColor Red; exit 3 }
    $env:EPS_INSTALL_CHANNEL = 'pro'   # read by the installer (this process): the update job then asks Invardia for the licence
} else {
$rel = & $GetRelease $Version
# the latest v2 release (the repo's v1.0.x releases stay where they are and are never picked)
$rel = @($rel | Where-Object { $_.tag_name -match '^v2\.' -and -not $_.draft -and -not $_.prerelease } | Sort-Object { [version]($_.tag_name.TrimStart('v') -replace '[^0-9.].*$', '') } -Descending)[0]
if (-not $rel) { Write-Host "No Entra Policy Suite v2 release found in $repo$(if ($Version) { " for $Version" })." -ForegroundColor Red; exit 3 }
$asset = @($rel.assets | Where-Object { $_.name -match '^EntraPolicySuite-v2[0-9A-Za-z.+-]*\.zip$' })[0]
if (-not $asset) { Write-Host "Release $($rel.tag_name) has no EntraPolicySuite-v2*.zip asset." -ForegroundColor Red; exit 3 }

$dir = Join-Path ([IO.Path]::GetTempPath()) "eps-release-$($rel.tag_name)-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
New-Item -ItemType Directory -Path $dir | Out-Null
$zip = Join-Path $dir $asset.name
& $Download $asset.browser_download_url $zip
$got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$published = if ("$($asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' }
if (-not $published -or $got -ne $published) {
    [IO.Directory]::Delete($dir, $true)
    Write-Host "The download does not match the release's published SHA-256 ($(if ($published) { $published } else { 'none published' }) vs $got) - deleted, nothing run." -ForegroundColor Red
    exit 3
}
Write-Host "Release $($rel.tag_name): $($asset.name), SHA-256 $got (matches the release)"
Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
$installer = Get-ChildItem -LiteralPath $dir -Recurse -Filter 'Install-EntraPolicySuite.ps1' -File | Select-Object -First 1
if (-not $installer) { Write-Host 'The release has no tools/setup/Install-EntraPolicySuite.ps1.' -ForegroundColor Red; exit 3 }
}

$pass = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId }
# the installer's parameters as given (the launcher's own - the version and the test seams - stay here)
foreach ($k in @($PSBoundParameters.Keys)) { if ($k -notin 'TenantId', 'SubscriptionId', 'Version', 'GetRelease', 'Download', 'RunInstaller', 'ProHttp', 'ProToken', 'ProFetch', 'WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction') { $pass[$k] = $PSBoundParameters[$k] } }
if ($what) { $pass.WhatIf = $true }
exit (& $RunInstaller $installer.FullName $pass)
