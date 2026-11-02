# EntraPolicySuite -- the install's web app steps (DESIGN §2; framework §12.11g, the sign-in front's README "Setup"):
# the app registration the front signs people in with, the install's Key Vault (the front's wrap key only - owner
# 2026-10-30 "Yes, like PIM"), the front's state in the product database, the pinned front image, and ONE Container App
# with two containers (the front on the ingress, the GUI on 127.0.0.1). PIM's sequence (tools/setup/_PimInstallSigninFront
# + Set-PimManagerSigninFront), copied, not shared. Never Easy Auth, never a secret or certificate on the registration.
# The body builders are PURE and tested offline (tests/Test-EpsInstallWeb.ps1); the I/O is EPS-Arm / EPS-Graph /
# Invoke-EpsSetupSql, as in the other steps.

Set-StrictMode -Off
$script:EpsWeb = @{
    Scope = 'user_impersonation'
    FrontPort = 8080; UpstreamPort = 8081; SessionHours = 8
    KeyName = 'signin-front'
    CryptoUserRole = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'      # Key Vault Crypto Service Encryption User
    GraphAppId = '00000003-0000-0000-c000-000000000000'
    GraphUserRead = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'       # delegated User.Read (the front's silent ID-token refresh)
    DefaultAccess = '00000000-0000-0000-0000-000000000000'       # "default access" app role (assignment required)
    KvApi = '2023-07-01'
}

function Get-EpsSigninFrontPin {
    # the sign-in front version this release pins (framework §12.11g: products pin; 1.4.4 - never 1.3.0, 1.4.0, 1.4.1)
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $v = "$(Get-Content -LiteralPath (Join-Path $SolutionRoot 'tools\eps-web\signin-front.version') -Raw -ErrorAction SilentlyContinue)".Trim([char]0xFEFF).Trim()
    if ($v -notmatch '^\d+\.\d+\.\d+$') { throw 'this release pins no sign-in front version (tools/eps-web/signin-front.version)' }
    if ($v -in '1.3.0', '1.4.0', '1.4.1') { throw "sign-in front $v is a version the framework forbids (§12.11g item 10) - pin 1.4.2 or later" }
    $v
}

function Get-EpsSigninFrontSource {
    <#
      Where the front's source is: the release carries it at vendor/signin-front (src + VERSION, put there by the release
      build); a repository tree has it at <repo>/FRAMEWORK/signin-front. Built ONLY when its VERSION is the pinned one.
      @{ Ok; Src; Version; Reason }.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot, [Parameter(Mandatory)][string]$Pin, [string]$Root)
    $roots = if ($Root) { @($Root) } else { @((Join-Path $SolutionRoot 'vendor\signin-front'), (Join-Path (Split-Path -Parent (Split-Path -Parent $SolutionRoot)) 'FRAMEWORK\signin-front')) }
    foreach ($root in $roots) {
        $src = Join-Path $root 'src'
        if (-not (Test-Path -LiteralPath (Join-Path $src 'Dockerfile'))) { continue }
        $v = "$(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw -ErrorAction SilentlyContinue)".Trim([char]0xFEFF).Trim()
        if ($v -ne $Pin) { return @{ Ok = $false; Src = $src; Version = $v; Reason = "the sign-in front source here is $v, this release pins $Pin - not built (only the pinned version is ever built)" } }
        return @{ Ok = $true; Src = $src; Version = $v; Reason = "signin-front $v from $root" }
    }
    @{ Ok = $false; Src = ''; Version = ''; Reason = 'this copy of EntraPolicySuite carries no sign-in front source (vendor/signin-front)' }
}

function New-EpsFrontBuildContext {
    # the front's src folder (bin / obj left out) as a .tar.gz with its Dockerfile at the root; the in-box tar
    param([Parameter(Mandatory)][string]$Src, [string]$OutFile = (Join-Path ([IO.Path]::GetTempPath()) "eps-front-$([guid]::NewGuid().ToString('N')).tar.gz"))
    $stage = Join-Path ([IO.Path]::GetTempPath()) "eps-front-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        foreach ($d in Get-ChildItem -LiteralPath $Src -Force | Where-Object { $_.Name -notin 'bin', 'obj', '.vs' }) { Copy-Item -LiteralPath $d.FullName -Destination $stage -Recurse -Force }
        $tar = if ($IsWindows -and (Test-Path (Join-Path $env:SystemRoot 'System32\tar.exe'))) { Join-Path $env:SystemRoot 'System32\tar.exe' } else { 'tar' }
        & $tar -czf $OutFile -C $stage .
        if ($LASTEXITCODE) { throw "tar failed ($LASTEXITCODE)" }
    } finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    $OutFile
}

function New-EpsWebAppRegistrationBody {
    <#
      PURE. The sign-in registration (the front's README "Setup" 2): single tenant, Web platform with NO implicit grant
      (code flow only), no groups claim (the token never grows with the user's groups - who gets in is "assignment
      required"), the app's own delegated scope for the access token the GUI verifies, Graph User.Read for the front's
      silent refresh. No password, no key. The redirect URIs follow when the app's address is known.
    #>
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$Tag, [string]$ScopeId = ([guid]::NewGuid().ToString()))
    [ordered]@{
        displayName = $DisplayName; signInAudience = 'AzureADMyOrg'; tags = @($Tag); groupMembershipClaims = 'None'
        web = [ordered]@{ redirectUris = @(); implicitGrantSettings = [ordered]@{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } }
        api = [ordered]@{ oauth2PermissionScopes = @([ordered]@{ id = $ScopeId; value = $script:EpsWeb.Scope; type = 'Admin'; isEnabled = $true
            adminConsentDisplayName = 'Sign in to EntraPolicySuite'; adminConsentDescription = 'Lets the EntraPolicySuite sign-in front call the EntraPolicySuite web app for the signed-in user.'
            userConsentDisplayName = 'Sign in to EntraPolicySuite'; userConsentDescription = 'Lets the sign-in front call EntraPolicySuite for you.' }) }
        requiredResourceAccess = @([ordered]@{ resourceAppId = $script:EpsWeb.GraphAppId; resourceAccess = @(@{ id = $script:EpsWeb.GraphUserRead; type = 'Scope' }) })
        passwordCredentials = @(); keyCredentials = @()
    }
}

function Get-EpsFicSpec {
    # PURE. The federated credential: the web identity IS the registration's client credential (no secret)
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    [ordered]@{ name = 'eps-signin-front-web-identity'; issuer = "https://login.microsoftonline.com/$TenantId/v2.0"; subject = $PrincipalId; audiences = @('api://AzureADTokenExchange')
                description = 'EntraPolicySuite sign-in front: the web identity is the client credential - no secret.' }
}

function New-EpsKeyVaultBody {
    # PURE. The install's vault: Standard, RBAC, soft delete 90 days, purge protection (owner 2026-10-30, as PIM)
    # -Private (NET-1): created with public access off and no exception (it is reached through its private endpoint)
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$TenantId, [switch]$Private)
    $b = [ordered]@{ location = $Location; tags = [ordered]@{ product = 'EntraPolicySuite'; purpose = 'signin-front' }
        properties = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true
                                 enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true; publicNetworkAccess = 'Enabled' } }
    if ($Private) { $b.properties.publicNetworkAccess = 'Disabled'; $b.properties.networkAcls = [ordered]@{ defaultAction = 'Deny'; bypass = 'None' } }
    $b
}

function Get-EpsSigninStateSql {
    <#
      PURE. The front's place in the database (README "State"): schema signin owned by the web identity's user, CREATE
      TABLE for it (the front makes its two tables on first use). The user exists already (the access step, role eps_web);
      nothing in schema eps changes. Idempotent.
    #>
    param([Parameter(Mandatory)][string]$WebUser)
    if ($WebUser -notmatch '^[A-Za-z0-9-]{1,128}$') { throw "unsafe database user name '$WebUser'" }
    @(
        "IF SCHEMA_ID(N'signin') IS NULL EXEC (N'CREATE SCHEMA signin AUTHORIZATION [$WebUser]');"
        "IF (SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin') <> N'$WebUser' ALTER AUTHORIZATION ON SCHEMA::signin TO [$WebUser];"
        "IF NOT EXISTS (SELECT 1 FROM sys.database_permissions p WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'$WebUser') AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G', 'W')) GRANT CREATE TABLE TO [$WebUser];"
    ) -join "`n"
}

function Get-EpsFirstSuperAdminSql {
    # PURE. The installing person becomes the web app's first SuperAdmin (they are also assigned to the app) - audited
    param([Parameter(Mandatory)][string]$Upn, [Parameter(Mandatory)][string]$ObjectId)
    if ($Upn -notmatch '^[^@\s''"\]\[]+@[^@\s''"\]\[]+\.[^@\s''"\]\[]+$') { throw "'$Upn' is not a user principal name" }
    $o = [guid]$ObjectId; $u = $Upn.ToLowerInvariant()
    @"
IF NOT EXISTS (SELECT 1 FROM eps.WebAccess WHERE Role = 'SuperAdmin')
BEGIN
  MERGE eps.WebAccess AS d USING (SELECT N'$u' AS Principal) AS s ON d.Principal = s.Principal
  WHEN MATCHED THEN UPDATE SET Role = 'SuperAdmin', ObjectId = '$o', GrantedBy = N'install', GrantedAtUtc = SYSUTCDATETIME()
  WHEN NOT MATCHED THEN INSERT (Principal, ObjectId, Role, GrantedBy) VALUES (N'$u', '$o', 'SuperAdmin', N'install');
  INSERT INTO eps.AuditEvent (Action, Actor, ActorSource, Target, Reason, Outcome, AfterJson) VALUES ('access.grant', N'$u', 'setup', N'WebAccess|$u', N'the installing person is the first SuperAdmin', 'ok', N'{"Role":"SuperAdmin"}');
END
"@
}

function New-EpsWebAppBody {
    <#
      PURE. ONE Container App, one revision, two containers (framework §12.11g item 2):
        signin-front  the pinned front image - the ONLY thing the ingress reaches (target port 8080), probes on /healthz;
                      its state in the product's SQL database, its keys wrapped by the install's Key Vault key, the
                      access token for api://<client id>/user_impersonation forwarded to the GUI
        eps           the same image as the jobs, EPS_JOB = Web, on 127.0.0.1:8081 (no probe: nothing outside reaches it)
      The web identity is the only identity: the front's federated credential, its SQL / Key Vault access, the GUI's SQL
      login, the image pull. No secret anywhere. Scale 0..1: the front's state is in SQL, so a cold start signs nobody out.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$FrontImage, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$KeyId)
    $n = $Ctx.Names; $w = $Ctx.Identities.WebIdentity
    $fqdn = "$($n.SqlServer).database.windows.net"
    $envId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
    $probe = { param($t) [ordered]@{ type = $t; httpGet = [ordered]@{ path = '/healthz'; port = $script:EpsWeb.FrontPort; scheme = 'HTTP' }; initialDelaySeconds = 3; periodSeconds = 10; failureThreshold = 3; timeoutSeconds = 3 } }
    $e = { param([hashtable]$h) @($h.Keys | Sort-Object | ForEach-Object { [ordered]@{ name = $_; value = "$($h[$_])" } }) }
    [ordered]@{
        location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; role = 'web' }
        identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $w.Id = @{} } }
        properties = [ordered]@{ environmentId = $envId; workloadProfileName = 'Consumption'
            configuration = [ordered]@{ activeRevisionsMode = 'Single'
                ingress = [ordered]@{ external = $true; targetPort = $script:EpsWeb.FrontPort; transport = 'auto'; allowInsecure = $false; traffic = @(@{ latestRevision = $true; weight = 100 }) }
                registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = $w.Id }) }
            template = [ordered]@{
                containers = @(
                    [ordered]@{ name = 'signin-front'; image = $FrontImage; resources = @{ cpu = 0.25; memory = '0.5Gi' }; probes = @((& $probe 'Liveness'), (& $probe 'Readiness'))
                        env = & $e @{ SIGNIN_TENANT_ID = $Ctx.TenantId; SIGNIN_CLIENT_ID = $ClientId; SIGNIN_FIC_MI_CLIENT_ID = $w.ClientId; SIGNIN_UPSTREAM_PORT = $script:EpsWeb.UpstreamPort
                            SIGNIN_SESSION_HOURS = $script:EpsWeb.SessionHours; ASPNETCORE_HTTP_PORTS = $script:EpsWeb.FrontPort; SIGNIN_SQL_SERVER = $fqdn; SIGNIN_SQL_DATABASE = $n.Database
                            SIGNIN_KEYVAULT_KEY_ID = $KeyId; SIGNIN_UPSTREAM_SCOPE = "api://$ClientId/$($script:EpsWeb.Scope)" } }
                    [ordered]@{ name = 'eps'; image = $Image; resources = @{ cpu = 0.5; memory = '1Gi' }
                        env = & $e @{ EPS_JOB = 'Web'; EPS_SQL_CONNECTION = "Server=tcp:$fqdn,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
                            EPS_TENANT_ID = $Ctx.TenantId; EPS_WEB_CLIENT_ID = $ClientId; EPS_WEB_PORT = $script:EpsWeb.UpstreamPort; EPS_ManagedIdentityClientId = $w.ClientId } }
                )
                scale = @{ minReplicas = 0; maxReplicas = 1 }
            }
        }
    }
}

function Find-EpsWebAppRegistration {
    # the install's registration, found by its tag (a re-run finds the one it made; a display name is not unique)
    param([Parameter(Mandatory)][string]$Tag)
    @(Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:t eq '$Tag')&`$select=id,appId,displayName,identifierUris,api,web,requiredResourceAccess,passwordCredentials,keyCredentials" -All)[0]
}

function Invoke-EpsWithRetry {
    # a fresh object not visible yet (Graph 404 / Request_ResourceNotFound, ARM PrincipalNotFound): bounded waits
    param([Parameter(Mandatory)][scriptblock]$Action, [int[]]$Waits = @(10, 20, 30, 60, 60, 60))
    $i = 0
    while ($true) {
        try { return (& $Action) }
        catch {
            if ($i -ge $Waits.Count -or "$_" -notmatch '(?i)404|ResourceNotFound|does not exist|PrincipalNotFound|not found') { throw }
            Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $Waits[$i] }); $i++
        }
    }
}

function Invoke-EpsWebRegistrationStep {
    <#
      The registration: create (or find) it, api://<appId> + the scope, the service principal with assignment required,
      the admin consents (Graph User.Read + openid profile offline_access; the app's own scope to itself), the federated
      credential for the web identity, the installing person assigned. No secret: one found on the registration is
      refused (it was not made by this install). Sets $Ctx.Web.ClientId / AppObjectId / SpId.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $tag = "eps-install-$($n.Suffix)"
    $app = Find-EpsWebAppRegistration -Tag $tag
    if (-not $app) { $app = Invoke-EpsGraph -Method POST -Path 'v1.0/applications' -Body (New-EpsWebAppRegistrationBody -DisplayName $n.WebAppRegistration -Tag $tag) }
    if (@($app.passwordCredentials).Count -or @($app.keyCredentials).Count) { throw "the registration '$($app.displayName)' carries a secret or a certificate - the sign-in front needs none; remove it (it was not made by this install)" }
    $uri = "api://$($app.appId)"
    if (@($app.identifierUris) -notcontains $uri) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($app.id)" -Body @{ identifierUris = @($uri) }) } }
    # a service principal just made may not be readable yet, and an answer without its id is no service principal
    # (live, internal 2026-10-30: the consent query then went out with an empty id) - "not visible yet", retried
    $sp = Invoke-EpsWithRetry { $x = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id,appRoleAssignmentRequired" -All)[0]; if (-not $x) { $x = Invoke-EpsGraph -Method POST -Path 'v1.0/servicePrincipals' -Body @{ appId = $app.appId; appRoleAssignmentRequired = $true; tags = @('WindowsAzureActiveDirectoryIntegratedApp') } }
        if (-not "$($x.id)") { throw "the service principal of $($app.appId) does not exist yet (not found)" }; $x }
    if (-not $sp.appRoleAssignmentRequired) { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $true }) }
    $graphSp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($script:EpsWeb.GraphAppId)'&`$select=id" -All)[0]
    foreach ($g in @(@{ Resource = $graphSp.id; Scope = 'openid profile offline_access User.Read' }, @{ Resource = $sp.id; Scope = $script:EpsWeb.Scope })) {
        $have = @(Invoke-EpsGraph -Path "v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and resourceId eq '$($g.Resource)'" -All | Where-Object { $_.consentType -eq 'AllPrincipals' })[0]
        $missing = @($g.Scope -split ' ' | Where-Object { " $($have.scope) " -notmatch " $([regex]::Escape($_)) " })
        if (-not $have) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $g.Resource; scope = $g.Scope }) } }
        elseif ($missing) { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/oauth2PermissionGrants/$($have.id)" -Body @{ scope = ("$($have.scope) $($missing -join ' ')").Trim() }) }
    }
    $fic = Get-EpsFicSpec -TenantId $Ctx.TenantId -PrincipalId $Ctx.Identities.WebIdentity.PrincipalId
    $fics = @(Invoke-EpsGraph -Path "v1.0/applications/$($app.id)/federatedIdentityCredentials" -All)
    if (-not @($fics | Where-Object { $_.issuer -eq $fic.issuer -and $_.subject -eq $fic.subject }).Count) { [void](Invoke-EpsGraph -Method POST -Path "v1.0/applications/$($app.id)/federatedIdentityCredentials" -Body $fic) }
    # who gets in: assignment required + the installing person (a SuperAdmin adds others: Entra assignment + the Access page)
    if ("$($Ctx.Person.PrincipalType)" -in '', 'User' -and $Ctx.Person.ObjectId) {
        $as = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -All | Where-Object { $_.principalId -eq $Ctx.Person.ObjectId })
        if (-not $as.Count) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{ principalId = $Ctx.Person.ObjectId; resourceId = $sp.id; appRoleId = $script:EpsWeb.DefaultAccess }) } }
    }
    $Ctx.Web = @{ ClientId = [string]$app.appId; AppObjectId = [string]$app.id; SpId = [string]$sp.id }
}

function Invoke-EpsKeyVaultStep {
    # the vault, the RSA wrap key, and Crypto Service Encryption User for the web identity on THAT key only
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $sub = "/subscriptions/$($Ctx.SubscriptionId)"
    $vaultPath = "$sub/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)"
    $vault = Invoke-EpsArm -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
    if (-not $vault) {
        # a subscription-level check: with Owner on the resource group only it is refused (403) - then the PUT itself
        # says whether the name is free (a taken name fails there with Azure's own message)
        $av = try { Invoke-EpsArm -Method POST -Path "$sub/providers/Microsoft.KeyVault/checkNameAvailability" -ApiVersion $script:EpsWeb.KvApi -Body @{ name = $n.KeyVault; type = 'Microsoft.KeyVault/vaults' } } catch { if ("$_" -match '(?i)AuthorizationFailed|403') { $null } else { throw } }
        $body = New-EpsKeyVaultBody -Location $Ctx.Location -TenantId $Ctx.TenantId -Private:([bool]$Ctx.Network.Private)
        if ($av -and -not $av.nameAvailable) {
            # purge protection keeps a deleted vault (and its name) 90 days: THIS install's own vault, deleted with an earlier
            # install of the same resource group, is recovered - with its key - instead of failing the re-install
            $del = Invoke-EpsArm -Path "$sub/providers/Microsoft.KeyVault/locations/$($Ctx.Location)/deletedVaults/$($n.KeyVault)" -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
            if (-not $del -or "$($del.properties.vaultId)" -notlike "*/resourceGroups/$($n.ResourceGroup)/*") { throw "the Key Vault name '$($n.KeyVault)' is taken ($($av.reason)) and is not this install's deleted vault" }
            $body.properties.createMode = 'recover'
        }
        $vault = Invoke-EpsArm -Method PUT -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi -Body $body
    }
    # a new vault answers RegisteringDns for a while (live, internal 2026-10-30): its keys cannot be read or made until
    # it says Succeeded
    for ($w = 0; "$($vault.properties.provisioningState)" -and "$($vault.properties.provisioningState)" -ne 'Succeeded' -and $w -lt 30; $w++) {
        Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { 10 })
        $vault = Invoke-EpsArm -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi
    }
    if ("$($vault.properties.provisioningState)" -and "$($vault.properties.provisioningState)" -ne 'Succeeded') { throw "the Key Vault $($n.KeyVault) is still '$($vault.properties.provisioningState)' after 5 minutes - run the install again" }
    if (-not $vault.properties.enableRbacAuthorization -or -not $vault.properties.enablePurgeProtection) { throw "the Key Vault $($n.KeyVault) must use Azure RBAC with purge protection (it was not made by this install)" }
    $keyPath = "$vaultPath/keys/$($script:EpsWeb.KeyName)"
    $key = Invoke-EpsArm -Path $keyPath -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
    if (-not $key) { $key = Invoke-EpsArm -Method PUT -Path $keyPath -ApiVersion $script:EpsWeb.KvApi -Body @{ properties = @{ kty = 'RSA'; keySize = 2048; keyOps = @('wrapKey', 'unwrapKey') } } }
    Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope $keyPath -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsWeb.CryptoUserRole)" -PrincipalId $Ctx.Identities.WebIdentity.PrincipalId }
    $Ctx.Web.KeyId = $(if ("$($key.properties.keyUri)".Trim()) { "$($key.properties.keyUri)".Trim() } else { "https://$($n.KeyVault).vault.azure.net/keys/$($script:EpsWeb.KeyName)" })
}

function Invoke-EpsWebAppStep {
    # the app, then its address into the registration's redirect URIs; then the front must answer /healthz
    param([Parameter(Mandatory)]$Ctx, [int]$WaitSeconds = 300)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    $body = New-EpsWebAppBody -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)" -FrontImage "$($n.Registry).azurecr.io/signin-front:$($Ctx.Web.FrontVersion)" -ClientId $Ctx.Web.ClientId -KeyId $Ctx.Web.KeyId
    $app = Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -ApiVersion $script:EpsApi.aca -Body $body
    if (-not $app.properties.configuration.ingress.fqdn) { $app = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -ApiVersion $script:EpsApi.aca }
    $fqdn = "$($app.properties.configuration.ingress.fqdn)".Trim().ToLowerInvariant()
    if (-not $fqdn) { throw "the web app $($n.WebApp) has no address yet (provisioning $($app.properties.provisioningState))" }
    $reg = Invoke-EpsGraph -Path "v1.0/applications/$($Ctx.Web.AppObjectId)?`$select=web"
    $uris = @(@(@($reg.web.redirectUris) + "https://$fqdn/signin-oidc") | Where-Object { $_ } | Select-Object -Unique)
    [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($Ctx.Web.AppObjectId)" -Body @{ web = @{ redirectUris = $uris; logoutUrl = "https://$fqdn/signout-callback-oidc"; implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } } })
    $Ctx.Web.Fqdn = $fqdn
    $Ctx.Web.Url = "https://$fqdn/"
}

function Test-EpsWebAppAnswers {
    <#
      The proof the revision runs: the front answers /healthz (200), and a page without a session goes to Entra's sign-in
      (302 to login.microsoftonline.com) - never the GUI unauthenticated. @{ Ok; Health; Page; Reason }.
    #>
    param([Parameter(Mandatory)][string]$Fqdn, [int]$WaitSeconds = 300, [int]$PollSeconds = 10)
    # HttpClient with redirects OFF: Invoke-WebRequest -MaximumRedirection 0 THROWS on a 302 (found live, internal
    # 2026-10-30 - the right answer was reported as "no answer")
    $get = if ($global:EPS_WebProbeOverride) { $global:EPS_WebProbeOverride } else { { param($u)
        $hc = [System.Net.Http.HttpClient]::new([System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $false }); $hc.Timeout = [TimeSpan]::FromSeconds(20)
        try { $r = $hc.GetAsync($u).GetAwaiter().GetResult(); @{ Status = [int]$r.StatusCode; Location = "$($r.Headers.Location)" } }
        catch { @{ Status = 0; Location = ''; Error = "$($_.Exception.GetBaseException().Message)" } } finally { $hc.Dispose() } } }
    $sw = [Diagnostics.Stopwatch]::StartNew(); $h = $null
    while ($sw.Elapsed.TotalSeconds -lt $WaitSeconds) {
        $h = & $get "https://$Fqdn/healthz"
        if ($h.Status -eq 200) { break }
        Start-Sleep -Seconds $PollSeconds
    }
    if ($h.Status -ne 200) { return @{ Ok = $false; Health = $h.Status; Reason = "the sign-in front does not answer https://$Fqdn/healthz ($($h.Status) $($h.Error)) within $WaitSeconds s - see the app's log" } }
    $p = & $get "https://$Fqdn/"
    if ($p.Status -ne 302 -or $p.Location -notmatch '^https://login\.microsoftonline\.com/') { return @{ Ok = $false; Health = 200; Page = $p.Status; Reason = "a page without a session answered $($p.Status) ($($p.Location)) - expected a redirect to the Entra sign-in" } }
    @{ Ok = $true; Health = 200; Page = 302; Reason = 'the front answers, a page without a session goes to the Entra sign-in' }
}
