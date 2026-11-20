# EntraPolicySuite -- the install's web app steps (DESIGN §2; framework SECURE-WEB-1): the app registration people sign
# in with (no secret, no certificate: the web identity is its credential through a federated credential), the install's
# Key Vault (the Invardia support link's key only), and ONE Container App with ONE container behind Microsoft's built-in
# Container Apps sign-in (2.1.35, the section at the end of this file). 2.1.56 (FRONT-CODE-REMOVE): the retired sign-in
# front's pin, source, build, two-container template and state are gone; what stays of it is clean-up only (its old Key
# Vault key and schema removed, its stored images deleted by the updater). The body builders are PURE and tested offline;
# the I/O is EPS-Arm / EPS-Graph / Invoke-EpsSetupSql, as in the other steps.

Set-StrictMode -Off
$script:EpsWeb = @{
    Scope = 'user_impersonation'
    SessionHours = 8
    KeyName = 'signin-front'                                     # the RETIRED front's Key Vault key name - removal + leftover report only
    GraphAppId = '00000003-0000-0000-c000-000000000000'
    GraphUserRead = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'       # delegated User.Read (the sign-in's ID token)
    DefaultAccess = '00000000-0000-0000-0000-000000000000'       # "default access" app role (assignment required)
    AzCliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'          # Microsoft Azure CLI: pre-authorised for the app's own scope (2.0.90, the API / MCP token)
    KvApi = '2023-07-01'
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
            adminConsentDisplayName = 'Sign in to Entra Policy Suite'; adminConsentDescription = 'Lets the Entra Policy Suite sign-in front call the Entra Policy Suite web app for the signed-in user.'
            userConsentDisplayName = 'Sign in to Entra Policy Suite'; userConsentDescription = 'Lets the sign-in front call Entra Policy Suite for you.' }) }
        requiredResourceAccess = @([ordered]@{ resourceAppId = $script:EpsWeb.GraphAppId; resourceAccess = @(@{ id = $script:EpsWeb.GraphUserRead; type = 'Scope' }) })
        passwordCredentials = @(); keyCredentials = @()
    }
}

function Get-EpsWebPreAuthPatch {
    <#
      PURE. EPS 2.0.90 (Pro: API for scripts + MCP): the Azure CLI pre-authorised for the app's OWN scope, so a person who
      uses the CLI gets their own access token (az account get-access-token --scope api://<id>/user_impersonation) without
      a consent prompt. It grants nothing: the token only proves who the person is; assignment required still decides who
      gets one, and their role here what it may do. MERGES: every scope and pre-authorisation already there is kept.
      -> the PATCH body, or $null when nothing is missing (or the scope is not there yet).
    #>
    param($Api)
    $scopes = @(if ($Api -and $Api.oauth2PermissionScopes) { @($Api.oauth2PermissionScopes) })
    $sc = @($scopes | Where-Object { "$($_.value)" -eq $script:EpsWeb.Scope })[0]
    if (-not $sc) { return $null }
    $sid = "$($sc.id)"
    $pre = @(if ($Api.preAuthorizedApplications) { @($Api.preAuthorizedApplications) })
    $cli = @($pre | Where-Object { "$($_.appId)" -eq $script:EpsWeb.AzCliAppId })[0]
    if ($cli -and @($cli.delegatedPermissionIds) -contains $sid) { return $null }
    $pre = if ($cli) { @($pre | ForEach-Object { if ("$($_.appId)" -eq $script:EpsWeb.AzCliAppId) { [ordered]@{ appId = $_.appId; delegatedPermissionIds = @(@($_.delegatedPermissionIds) + $sid | Select-Object -Unique) } } else { $_ } }) }
           else { @($pre) + [ordered]@{ appId = $script:EpsWeb.AzCliAppId; delegatedPermissionIds = @($sid) } }
    [ordered]@{ api = [ordered]@{ oauth2PermissionScopes = @($scopes); preAuthorizedApplications = @($pre) } }
}

# §12.30 / §12.31 layer 1 (API security = Microsoft's practice, rules 2-4): ONE app role on the registration - "may call
# the API for applications at all" - for applications only; assignment required (already on its enterprise application);
# the idtyp claim in access tokens (app-only PROVEN); v2 tokens. The role's id is fixed, so every install has the same.
$script:EpsApiAppRoleId = '6b1f3c2e-8d4a-4f5e-9a7b-2c1d0e3f4a5b'
if (-not $script:EpsApiAppRoleValue) { $script:EpsApiAppRoleValue = 'EPS.Api.Call' }   # the same value as EPS-WebAuth's (the token check)
. (Join-Path $PSScriptRoot 'EPS-ApiTiers.ps1')   # $script:EpsAppApiOpen (closed: the install / update add no layer 1)

function Get-EpsWebApiAuthPatch {
    <#
      PURE. What the registration needs for the API for applications, MERGED with what is there (every role, claim, scope
      and pre-authorisation already on it is kept): the app role EPS.Api.Call (allowedMemberTypes Application only), the
      access token's optional claim idtyp, api.requestedAccessTokenVersion = 2. -> @{ Patch (the PATCH body, or $null when
      nothing is missing); Missing (what was missing, as text) }.
    #>
    param([Parameter(Mandatory)]$App)
    $missing = [System.Collections.Generic.List[string]]::new(); $patch = [ordered]@{}
    $roles = @(if ($App.appRoles) { @($App.appRoles) })
    $mine = @($roles | Where-Object { "$($_.value)" -eq $script:EpsApiAppRoleValue })[0]
    if (-not $mine -or $mine.isEnabled -ne $true -or (@($mine.allowedMemberTypes) -join ',') -ne 'Application') {
        $missing.Add("the app role $script:EpsApiAppRoleValue")
        $want = [ordered]@{ id = $(if ($mine) { "$($mine.id)" } else { $script:EpsApiAppRoleId }); value = $script:EpsApiAppRoleValue; allowedMemberTypes = @('Application'); isEnabled = $true
            displayName = 'Call the Entra Policy Suite API'; description = 'An application assigned this role may call the Entra Policy Suite API for applications. What it may do there is the role Entra Policy Suite gives it (Administration > Settings > API applications, or the Support enrolment).' }
        $patch.appRoles = @(@($roles | Where-Object { "$($_.value)" -ne $script:EpsApiAppRoleValue }) + $want)
    }
    $oc = $App.optionalClaims
    if (-not @(@($oc.accessToken) | Where-Object { "$($_.name)" -eq 'idtyp' }).Count) {
        $missing.Add('the access token claim idtyp')
        $patch.optionalClaims = [ordered]@{ idToken = @(@($oc.idToken) | Where-Object { $_ }); saml2Token = @(@($oc.saml2Token) | Where-Object { $_ })
            accessToken = @(@(@($oc.accessToken) | Where-Object { $_ }) + [ordered]@{ name = 'idtyp'; essential = $false; additionalProperties = @() }) }
    }
    if ("$($App.api.requestedAccessTokenVersion)" -ne '2') {
        $missing.Add('v2 access tokens')
        $patch.api = [ordered]@{ requestedAccessTokenVersion = 2; oauth2PermissionScopes = @(@($App.api.oauth2PermissionScopes) | Where-Object { $_ }); preAuthorizedApplications = @(@($App.api.preAuthorizedApplications) | Where-Object { $_ }) }
    }
    @{ Patch = $(if ($patch.Count) { $patch } else { $null }); Missing = @($missing) }
}

function Get-EpsWebRedirectUris {
    <#
      PURE. The sign-in addresses the web app registration must hold for this web app address: the sign-in front's
      /signin-oidc, and - owner 2026-11-14 ~21:10Z, Microsoft's built-in Container Apps sign-in replaces the front (framework
      SECURE-WEB-1 points 5-7, EPS point 5) - the built-in sign-in's /.auth/login/aad/callback, registered ONE RELEASE
      BEFORE the switch so switch day needs no admin step. Other addresses already on the registration are kept.
    #>
    param([Parameter(Mandatory)][string]$Fqdn, [string[]]$Existing = @())
    $f = "$Fqdn".Trim().ToLowerInvariant()
    # 2.1.40: the built-in sign-in's address only - /signin-oidc is a leftover of the old front (never added back)
    $want = @("https://$f/.auth/login/aad/callback")
    [pscustomobject]@{
        Want    = $want
        Missing = @($want | Where-Object { @($Existing) -notcontains $_ })
        All     = @(@(@($Existing) + $want) | Where-Object { $_ } | Select-Object -Unique)
    }
}

function Get-EpsFicSpec {
    # PURE. The federated credential: the web identity IS the registration's client credential (no secret)
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    [ordered]@{ name = 'eps-signin-front-web-identity'; issuer = "https://login.microsoftonline.com/$TenantId/v2.0"; subject = $PrincipalId; audiences = @('api://AzureADTokenExchange')
                description = 'Entra Policy Suite sign-in front: the web identity is the client credential - no secret.' }
}

function New-EpsKeyVaultBody {
    # PURE. The install's vault: Standard, RBAC, soft delete 90 days, purge protection (owner 2026-10-30, as PIM)
    # -Private (NET-1): created with public access off and no exception (it is reached through its private endpoint)
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$TenantId, [switch]$Private)
    $b = [ordered]@{ location = $Location; tags = [ordered]@{ product = 'EntraPolicySuite'; purpose = 'support-link' }
        properties = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true
                                 enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true; publicNetworkAccess = 'Enabled' } }
    # framework installer rule 11 (NET1-KV-ARM-KEY, the NET-1 re-run 2026-11-03; SI's setting at a private customer): private
    # from birth = public access off + Deny + bypass AzureServices (ARM's key operations - the wrap key - are refused
    # without it: 400 ForbiddenByConnection) + no IP / network rules; reached through its private endpoint
    if ($Private) { $b.properties.publicNetworkAccess = 'Disabled'; $b.properties.networkAcls = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } }
    $b
}

function Get-EpsSigninDropSql {
    <# PURE. 2.1.40: the old sign-in front's schema signin - its foreign keys, its tables, the schema - and the web user's
       CREATE TABLE, dropped. Idempotent (nothing there = nothing done). #>
    param([Parameter(Mandatory)][string]$WebUser)
    if ($WebUser -notmatch '^[A-Za-z0-9-]{1,128}$') { throw "unsafe database user name '$WebUser'" }
    @(
        "IF SCHEMA_ID(N'signin') IS NOT NULL"
        "BEGIN"
        "  DECLARE @fk NVARCHAR(MAX) = N''; SELECT @fk += N'ALTER TABLE signin.' + QUOTENAME(OBJECT_NAME(parent_object_id)) + N' DROP CONSTRAINT ' + QUOTENAME(name) + N';' FROM sys.foreign_keys WHERE schema_id = SCHEMA_ID(N'signin'); IF @fk <> N'' EXEC (@fk);"
        "  DECLARE @tb NVARCHAR(MAX) = N''; SELECT @tb += N'DROP TABLE signin.' + QUOTENAME(name) + N';' FROM sys.tables WHERE schema_id = SCHEMA_ID(N'signin'); IF @tb <> N'' EXEC (@tb);"
        "  DECLARE @ob NVARCHAR(MAX) = N''; SELECT @ob += CASE type WHEN 'V' THEN N'DROP VIEW ' WHEN 'P' THEN N'DROP PROCEDURE ' WHEN 'FN' THEN N'DROP FUNCTION ' WHEN 'IF' THEN N'DROP FUNCTION ' WHEN 'TF' THEN N'DROP FUNCTION ' ELSE N'' END + N'signin.' + QUOTENAME(name) + N';' FROM sys.objects WHERE schema_id = SCHEMA_ID(N'signin') AND type IN ('V', 'P', 'FN', 'IF', 'TF'); IF @ob <> N'' EXEC (@ob);"
        "  EXEC (N'DROP SCHEMA signin');"
        "END"
        "IF EXISTS (SELECT 1 FROM sys.database_permissions p WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'$WebUser') AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G', 'W')) REVOKE CREATE TABLE FROM [$WebUser];"
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

function Find-EpsWebAppRegistration {
    # the install's registration, found by its tag (a re-run finds the one it made; a display name is not unique)
    param([Parameter(Mandatory)][string]$Tag)
    @(Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:t eq '$Tag')&`$select=id,appId,displayName,identifierUris,api,web,requiredResourceAccess,passwordCredentials,keyCredentials,appRoles,optionalClaims" -All)[0]
}

function Wait-EpsGraphDisplayName {
    # a rename reads back through Graph's replicas: the old name can come back for a while after the PATCH (live,
    # internal 2026-11-04: the registration read the old name, then the new one a minute later). Waits up to ~2 min.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Want, [int[]]$Waits = @(5, 10, 15, 30, 60))
    $seen = ''
    foreach ($w in @(0) + $Waits) {
        if ($w) { Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $w }) }
        $x = Invoke-EpsGraph -Path "$Path`?`$select=id,displayName"; $seen = "$($x.displayName)"
        if ($seen -ceq $Want) { return $x }
    }
    throw "$Path still reads '$seen' after the rename to '$Want'"
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

function Invoke-EpsOwnedRegistrationWrite {
    # SECAUDIT-1a (Invardia 2026-11-07): a change to the registration's OWN settings. A run that may not make it (403: it is
    # not an owner - e.g. the Support app after the handoff, without Application.ReadWrite.All) does not stop: the updater
    # identity, the registration's owner, applies it on its next run (Sync-EpsWebRegistrationAsOwner). Said once per change.
    param([Parameter(Mandatory)][scriptblock]$Do, [Parameter(Mandatory)][string]$What)
    try { & $Do }
    catch {
        if ("$_" -notmatch '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges') { throw }
        Write-Warning "$($What): this run may not change the registration (it is not an owner) - id-eps-updater, its owner, applies it on its next run"
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
    # the display name (framework decision, Invardia 2026-11-04): the product name only - plus " (<handle>)" only when
    # several installs share one tenant (another EPS install's registration carries another eps-install-<suffix> tag);
    # the handle is the resource group. Checked every run, so a second install renames neither itself nor the first.
    $others = @(try { Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:startswith(t,'eps-install-'))&`$select=id,tags" -All } catch { @() }) |
        Where-Object { @($_.tags) -notcontains $tag -and @($_.tags | Where-Object { "$_" -like 'eps-install-*' }).Count }
    if ($others.Count -and $n.WebAppRegistration -notmatch '\)$') { $n.WebAppRegistration = "$($n.WebAppRegistration) ($($n.ResourceGroup))" }
    $app = Find-EpsWebAppRegistration -Tag $tag
    if (-not $app) { $app = Invoke-EpsGraph -Method POST -Path 'v1.0/applications' -Body (New-EpsWebAppRegistrationBody -DisplayName $n.WebAppRegistration -Tag $tag) }
    if (@($app.passwordCredentials).Count -or @($app.keyCredentials).Count) { throw "the registration '$($app.displayName)' carries a secret or a certificate - the sign-in front never uses one, and this install never adds one, so the install stops here and changes nothing (whoever added it decides what happens to it)" }
    # the standard name (framework §12.11c, owner 2026-11-04): an older install's "EntraPolicySuite (<rg>)" is renamed in
    # place - same object, same app id, found by its tag - and read back
    if ("$($app.displayName)" -cne $n.WebAppRegistration) {
        $was = "$($app.displayName)"
        Invoke-EpsOwnedRegistrationWrite -What "the registration's name '$($n.WebAppRegistration)'" -Do {
            Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($app.id)" -Body @{ displayName = $n.WebAppRegistration }) }
            $rb = Wait-EpsGraphDisplayName -Path "v1.0/applications/$($app.id)" -Want $n.WebAppRegistration
            $app.displayName = $rb.displayName
            if (-not $Ctx.Renamed) { $Ctx.Renamed = [System.Collections.Generic.List[string]]::new() }
            $Ctx.Renamed.Add("app registration '$was' -> '$($n.WebAppRegistration)'")
        }
    }
    $uri = "api://$($app.appId)"
    if (@($app.identifierUris) -notcontains $uri) { Invoke-EpsOwnedRegistrationWrite -What "the registration's address $uri" -Do { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($app.id)" -Body @{ identifierUris = @($uri) }) } } }
    # 2.0.90: the Azure CLI pre-authorised for the app's own scope (a person's own token for the API / MCP) - merged, kept;
    # a scope just created can refuse a pre-authorisation for a while (Graph replication): a few tries, then a warning -
    # never a stop (the sign-in does not need it; the next run of the install adds it)
    try {
        $preAuth = Get-EpsWebPreAuthPatch -Api (Invoke-EpsGraph -Path "v1.0/applications/$($app.id)?`$select=id,api").api
        foreach ($wait in 0, 10, 20, 40) {
            if (-not $preAuth) { break }
            if ($wait) { Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $wait }) }
            try { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($app.id)" -Body $preAuth); $preAuth = $null } catch { if ($wait -eq 40) { throw } }
        }
    } catch { Write-Warning "the Azure CLI could not be pre-authorised for $($script:EpsWeb.Scope) yet ($((("$($_.Exception.Message)") -split "`n")[0])) - the API / MCP token then asks for consent once; the next run of the install adds it" }
    # §12.30 / §12.31 layer 1: the app role for applications, the idtyp claim, v2 tokens (merged - nothing there is lost);
    # who is ASSIGNED the role is a person's step (Set-EpsApiAuth.ps1), never this run's
    # CLOSED (§12.35): nothing is added while the API for applications is off
    $apiAuth = if ($script:EpsAppApiOpen -eq $true) { Get-EpsWebApiAuthPatch -App (Invoke-EpsGraph -Path "v1.0/applications/$($app.id)?`$select=id,api,appRoles,optionalClaims") } else { @{ Patch = $null; Missing = @() } }
    if ($apiAuth.Patch) { Invoke-EpsOwnedRegistrationWrite -What "the registration's API for applications ($($apiAuth.Missing -join ', '))" -Do { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($app.id)" -Body $apiAuth.Patch) } } }
    # a service principal just made may not be readable yet, and an answer without its id is no service principal
    # (live, internal 2026-10-30: the consent query then went out with an empty id) - "not visible yet", retried
    $sp = Invoke-EpsWithRetry { $x = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id,appRoleAssignmentRequired,displayName" -All)[0]; if (-not $x) { $x = Invoke-EpsGraph -Method POST -Path 'v1.0/servicePrincipals' -Body @{ appId = $app.appId; appRoleAssignmentRequired = $true; tags = @('WindowsAzureActiveDirectoryIntegratedApp') } }
        if (-not "$($x.id)") { throw "the service principal of $($app.appId) does not exist yet (not found)" }; $x }
    if (-not $sp.appRoleAssignmentRequired) { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $true }) }
    # the enterprise application keeps the name it was made with: renamed with the registration, read back
    if ($sp.PSObject.Properties['displayName'] -and "$($sp.displayName)" -cne $n.WebAppRegistration) {
        Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/servicePrincipals/$($sp.id)" -Body @{ displayName = $n.WebAppRegistration }) }
        [void](Wait-EpsGraphDisplayName -Path "v1.0/servicePrincipals/$($sp.id)" -Want $n.WebAppRegistration)
        if (-not $Ctx.Renamed) { $Ctx.Renamed = [System.Collections.Generic.List[string]]::new() }
        $Ctx.Renamed.Add("enterprise application '$($sp.displayName)' -> '$($n.WebAppRegistration)'")
    }
    $graphSp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($script:EpsWeb.GraphAppId)'&`$select=id" -All)[0]
    foreach ($g in @(@{ Resource = $graphSp.id; Scope = 'openid profile offline_access User.Read' }, @{ Resource = $sp.id; Scope = $script:EpsWeb.Scope })) {
        # GRAPH-CONSENT-RETRY (the NET-1 re-run 2026-11-03): right after the service principal is made, this query can 404 ("Resource '' does
        # not exist ...") until Graph replicates it - the same bounded retry as the lookup above
        $have = Invoke-EpsWithRetry { @(Invoke-EpsGraph -Path "v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and resourceId eq '$($g.Resource)'" -All | Where-Object { $_.consentType -eq 'AllPrincipals' })[0] }
        $missing = @($g.Scope -split ' ' | Where-Object { " $($have.scope) " -notmatch " $([regex]::Escape($_)) " })
        if (-not $have) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $g.Resource; scope = $g.Scope }) } }
        elseif ($missing) { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/oauth2PermissionGrants/$($have.id)" -Body @{ scope = ("$($have.scope) $($missing -join ' ')").Trim() }) }
    }
    $fic = Get-EpsFicSpec -TenantId $Ctx.TenantId -PrincipalId $Ctx.Identities.WebIdentity.PrincipalId
    $fics = @(Invoke-EpsGraph -Path "v1.0/applications/$($app.id)/federatedIdentityCredentials" -All)
    if (-not @($fics | Where-Object { $_.issuer -eq $fic.issuer -and $_.subject -eq $fic.subject }).Count) { Invoke-EpsOwnedRegistrationWrite -What 'the web identity''s federated credential' -Do { [void](Invoke-EpsGraph -Method POST -Path "v1.0/applications/$($app.id)/federatedIdentityCredentials" -Body $fic) } }
    # who gets in: assignment required + the installing person (a SuperAdmin adds others: Entra assignment + the Access page)
    if ("$($Ctx.Person.PrincipalType)" -in '', 'User' -and $Ctx.Person.ObjectId) {
        $as = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -All | Where-Object { $_.principalId -eq $Ctx.Person.ObjectId })
        if (-not $as.Count) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{ principalId = $Ctx.Person.ObjectId; resourceId = $sp.id; appRoleId = $script:EpsWeb.DefaultAccess }) } }
    }
    $Ctx.Web = @{ ClientId = [string]$app.appId; AppObjectId = [string]$app.id; SpId = [string]$sp.id }
}

function Get-EpsRegistrationOwnerPlan {
    <#
      PURE. SECAUDIT-1a (Invardia ruling 2026-11-07): the registration's owner is EPS's OWN updater identity (id-eps-updater,
      a service principal), never the Support app. -Owners: the owner object ids today; -UpdaterId: the updater's service
      principal id; -CallerId: the install's own principal when it is an APP ('' for a person - a person who installs stays
      owner, as Entra makes them). @{ Add (the updater is not an owner yet); Remove (the calling app is an owner) }.
      The caller is removed only AFTER the updater reads back as owner (Invoke-EpsRegistrationOwnerHandoff).
    #>
    param([string[]]$Owners = @(), [string]$UpdaterId, [string]$CallerId)
    $o = @($Owners | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() })
    $u = "$UpdaterId".ToLowerInvariant(); $c = "$CallerId".ToLowerInvariant()
    @{ Add = [bool]($u -and $o -notcontains $u); Remove = [bool]($u -and $c -and $c -ne $u -and $o -contains $c) }
}

function Invoke-EpsRegistrationOwnerHandoff {
    <#
      SECAUDIT-1a (Invardia ruling 2026-11-07): on the app registration AND the enterprise application, id-eps-updater is
      made an owner and read back; then the calling app (an install run through the Invardia Support app) removes itself
      and reads that back. Every later change to the registration's own settings is the updater's (Sync-EpsWebRegistration-
      AsOwner). Never stops the install: a failure is a WARNING line, and the Support app stays owner when the updater
      could not be added. Returns the lines (shown at the end of the run).
    #>
    param([Parameter(Mandatory)]$Ctx)
    $lines = [System.Collections.Generic.List[string]]::new()
    $upd = "$($Ctx.Identities.UpdaterIdentity.PrincipalId)"; $un = "$($Ctx.Names.UpdaterIdentity)"
    if (-not $upd -or -not $Ctx.Web -or -not $Ctx.Web.AppObjectId) { $lines.Add("registration owner: no $un or no registration yet - left as it is"); return @($lines) }
    # the calling APP: 'ServicePrincipal', or 'Application' as the setup run names it for the SQL admin (live, internal
    # 2026-11-07 on 2.0.94: 'Application' was not recognised and the Support app stayed owner)
    $caller = if ("$($Ctx.Person.PrincipalType)" -in 'ServicePrincipal', 'Application') { "$($Ctx.Person.ObjectId)" } else { '' }
    foreach ($t in @(@{ What = 'app registration'; Path = "v1.0/applications/$($Ctx.Web.AppObjectId)" }, @{ What = 'enterprise application'; Path = "v1.0/servicePrincipals/$($Ctx.Web.SpId)" })) {
        if ($t.Path -match '/$') { continue }
        try {
            $read = { @(Invoke-EpsGraph -Path "$($t.Path)/owners?`$select=id" -All | ForEach-Object { "$($_.id)".ToLowerInvariant() }) }
            $p = Get-EpsRegistrationOwnerPlan -Owners (& $read) -UpdaterId $upd -CallerId $caller
            if ($p.Add) { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path "$($t.Path)/owners/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$upd" }) } }
            # Graph replicas: an owner just added can read back a while later (live, internal 2026-11-07: the enterprise
            # application's add read back only after the run) - a few waits before it counts as not done
            $now = & $read
            foreach ($w in 10, 20, 30) { if ($now -contains $upd.ToLowerInvariant()) { break }; Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $w }); $now = & $read }
            if ($now -notcontains $upd.ToLowerInvariant()) { $lines.Add("WARNING: $($t.What): $un is not an owner after the add - the calling app stays owner"); continue }
            if ($p.Add) { $lines.Add("$($t.What): $un is an owner (read back)") }
            if ($p.Remove) {
                [void](Invoke-EpsGraph -Method DELETE -Path "$($t.Path)/owners/$caller/`$ref")
                $after = & $read
                foreach ($w in 10, 20, 30) { if ($after -notcontains $caller.ToLowerInvariant()) { break }; Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $w }); $after = & $read }
                if ($after -contains $caller.ToLowerInvariant()) { $lines.Add("WARNING: $($t.What): the calling app is still an owner after the removal") }
                else { $lines.Add("$($t.What): the calling app (this install run) is no longer an owner (read back)") }
            }
        } catch { $lines.Add("WARNING: $($t.What): the owners could not be set ($((("$($_.Exception.Message)") -split "`n")[0])) - the next install run tries again") }
    }
    @($lines)
}

function Invoke-EpsKeyVaultStep {
    # the vault, the RSA wrap key, and Crypto Service Encryption User for the web identity on THAT key only
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $sub = "/subscriptions/$($Ctx.SubscriptionId)"
    $vaultPath = "$sub/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)"
    $vault = Invoke-EpsArm -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
    # framework rule 15: a vault left Failed / Canceled by an earlier run is made again (same body), never waited on
    if ($vault -and "$($vault.properties.provisioningState)" -in 'Failed', 'Canceled') { $vault = Invoke-EpsArm -Method PUT -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi -Body (New-EpsKeyVaultBody -Location $vault.location -TenantId $Ctx.TenantId -Private:([bool]$Ctx.Network.Private)) }
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
    # NET1-KV-RECOVER (NET-1 run 3, 2026-11-03): a vault RECOVERED from soft delete (or one an older release made) keeps its
    # old network rules - bypass None refuses the key below. A private install therefore makes the vault rule 11 on EVERY
    # path - created, recovered or already there - and reads it back before the key step.
    if ($Ctx.Network -and $Ctx.Network.Private) {
        $acl = $vault.properties.networkAcls
        if ("$($vault.properties.publicNetworkAccess)" -ne 'Disabled' -or "$($acl.defaultAction)" -ne 'Deny' -or "$($acl.bypass)" -ne 'AzureServices' -or @($acl.ipRules).Count -or @($acl.virtualNetworkRules).Count) {
            [void](Invoke-EpsArm -Method PATCH -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi -Body @{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = @{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } } })
            $vault = Invoke-EpsArm -Path $vaultPath -ApiVersion $script:EpsWeb.KvApi
            $acl = $vault.properties.networkAcls
            if ("$($vault.properties.publicNetworkAccess)" -ne 'Disabled' -or "$($acl.bypass)" -ne 'AzureServices' -or "$($acl.defaultAction)" -ne 'Deny') { throw "the Key Vault $($n.KeyVault) could not be set private (public access off, deny, bypass AzureServices): it reads back public '$($vault.properties.publicNetworkAccess)', bypass '$($acl.bypass)'" }
        }
    }
    # 2.1.35 (owner 2026-11-14, SECURE-WEB-1; Invardia: "the lateral movement to Key Vault edge is gone by rule"): the
    # internet-facing web identity holds NO Key Vault right. The sign-in front's wrap key is not made any more, and an
    # older install's Crypto Service Encryption User for the web identity is REMOVED here - wherever in the vault it is -
    # and read back. (The key itself is left: deleting a key is not needed to close the path.)
    Remove-EpsWebKeyVaultRights -Ctx $Ctx -VaultPath $vaultPath
    # 2.1.41 (SECURE-WEB-1 "who deletes what", Invardia 2026-11-15): the old sign-in front's key is a dormant leftover; it is
    # deleted HERE, in the person's install run, when the person may (Key Vault data plane: Key Vault Administrator / Crypto
    # Officer) - no product identity is given a Key Vault right for it. Refused = said, the install goes on (it is harmless)
    [void](Remove-EpsRetiredFrontKey -Ctx $Ctx)
}

function Remove-EpsRetiredFrontKey {
    # never throws; @{ State (removed | none | refused | error); Line }
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $kv = "https://$("$($n.KeyVault)".ToLowerInvariant()).vault.azure.net"
    $say = { param($c, $t) Write-Host "  $t" -ForegroundColor $c }
    try {
        $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://vault.azure.net')" }
        $g = & $script:EpsHttp 'GET' "$kv/keys/$($script:EpsWeb.KeyName)?api-version=7.4" $h $null
        if ([int]$g.Status -eq 404) { return @{ State = 'none'; Line = 'the old sign-in front key: none' } }
        if ([int]$g.Status -in 401, 403) { & $say 'Yellow' "note     the old sign-in front key '$($script:EpsWeb.KeyName)' is left (no right to remove it - a Key Vault Administrator can, in an install run; it is harmless: no one holds a role on it)"; return @{ State = 'refused'; Line = 'refused' } }
        $d = & $script:EpsHttp 'DELETE' "$kv/keys/$($script:EpsWeb.KeyName)?api-version=7.4" $h $null
        if ([int]$d.Status -in 401, 403) { & $say 'Yellow' "note     the old sign-in front key '$($script:EpsWeb.KeyName)' is left (no right to remove it - a Key Vault Administrator can, in an install run)"; return @{ State = 'refused'; Line = 'refused' } }
        if ([int]$d.Status -notin 200, 404) { return @{ State = 'error'; Line = "the old sign-in front key could not be removed (HTTP $($d.Status))" } }
        $b = & $script:EpsHttp 'GET' "$kv/keys/$($script:EpsWeb.KeyName)?api-version=7.4" $h $null
        & $say 'Green' "removed  the old sign-in front key '$($script:EpsWeb.KeyName)' (read back: $(if ([int]$b.Status -eq 404) { 'gone' } else { "HTTP $($b.Status)" }); soft-deleted for 90 days - purge protection)"
        @{ State = 'removed'; Line = 'removed' }
    } catch { & $say 'Yellow' "note     the old sign-in front key could not be read: $((("$($_.Exception.Message)") -split "`n")[0])"; @{ State = 'error'; Line = 'error' } }
}

function Remove-EpsWebKeyVaultRights {
    # every role assignment the web identity holds in the install's vault (the vault, its keys, its secrets) - removed,
    # read back; throws when one is still there (the install stops: a web identity with a Key Vault right is not shipped)
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$VaultPath)
    $wp = "$($Ctx.Identities.WebIdentity.PrincipalId)"
    if (-not $wp) { return }
    $list = { @(@((Invoke-EpsArm -Path "$VaultPath/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$wp'" -ApiVersion $script:EpsApi.rbac -AllowNotFound).value) | Where-Object { $_ -and "$($_.properties.principalId)" -eq $wp -and ("$($_.properties.scope)" -like "$VaultPath*" -or "$($_.id)" -like "$VaultPath*") }) }
    foreach ($ra in (& $list)) { [void](Invoke-EpsArm -Method DELETE -Path "$($ra.id)" -ApiVersion $script:EpsApi.rbac -AllowNotFound); Write-Host "  removed  $($Ctx.Names.WebIdentity): its Key Vault right at $(("$($ra.properties.scope)" -split '/providers/')[-1]) (2.1.35: the web identity holds no Key Vault right)" -ForegroundColor Yellow }
    $left = @(& $list)
    if ($left.Count) { throw "the web identity $($Ctx.Names.WebIdentity) still holds $($left.Count) Key Vault role assignment(s) after the removal - run the install again" }
}

function Invoke-EpsWebAppStep {
    <#
      2.1.35 - the web app behind Microsoft's built-in sign-in: the token container + the web identity's Storage Blob Data
      Contributor on THAT container only, the sign-in config (authConfigs/current), the app (one container), then its
      address into the registration (both sign-in addresses, ID-token issuance ON - Microsoft's sign-in starts with
      code + id_token - access-token issuance OFF; never turned off again by any step). The verify step proves it answers.
    #>
    param([Parameter(Mandatory)]$Ctx, [int]$WaitSeconds = 300)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"; $sub = "/subscriptions/$($Ctx.SubscriptionId)"
    $appPath = "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)"
    $contPath = "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)/blobServices/default/containers/$($script:EpsWeb.TokenContainer)"
    if (-not (Invoke-EpsArm -Path $contPath -ApiVersion $script:EpsApi.st -AllowNotFound)) { [void](Invoke-EpsArm -Method PUT -Path $contPath -ApiVersion $script:EpsApi.st -Body @{ properties = @{ publicAccess = 'None' } }) }
    Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope $contPath -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsWeb.BlobDataRole)" -PrincipalId $Ctx.Identities.WebIdentity.PrincipalId }
    # 2.1.36: the platform refuses a sign-in config whose setting the app does not hold yet (AuthConfigSecretRefNotFound,
    # internal 2026-11-14) - an EXISTING app gets the setting first, then the sign-in config (while its old front still
    # runs), then the new shape; a NEW app is made first (with the setting), then its sign-in config
    $authBody = New-EpsWebAuthConfigBody -TenantId $Ctx.TenantId -ClientId $Ctx.Web.ClientId -StorageAccount $n.Storage -WebIdentityId $Ctx.Identities.WebIdentity.Id
    $body = New-EpsBuiltInWebAppBody -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)" -ClientId $Ctx.Web.ClientId
    $had = Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { 10 })
    if ($had) {
        [void](Set-EpsWebFicSetting -AppPath $appPath -WebClientId "$($Ctx.Identities.WebIdentity.ClientId)")
        [void](Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { 10 }))
        [void](Invoke-EpsArmOn409 { Invoke-EpsArm -Method PUT -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -Body $authBody })
        $app = Invoke-EpsArmOn409 { Invoke-EpsArm -Method PUT -Path $appPath -ApiVersion $script:EpsApi.aca -Body $body }
    } else {
        $app = Invoke-EpsArm -Method PUT -Path $appPath -ApiVersion $script:EpsApi.aca -Body $body
        [void](Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { 10 }))
        [void](Invoke-EpsArmOn409 { Invoke-EpsArm -Method PUT -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -Body $authBody })
    }
    if (-not $app.properties.configuration.ingress.fqdn) { $app = Invoke-EpsArm -Path $appPath -ApiVersion $script:EpsApi.aca }
    $fqdn = "$($app.properties.configuration.ingress.fqdn)".Trim().ToLowerInvariant()
    if (-not $fqdn) { throw "the web app $($n.WebApp) has no address yet (provisioning $($app.properties.provisioningState))" }
    $reg = Invoke-EpsGraph -Path "v1.0/applications/$($Ctx.Web.AppObjectId)?`$select=web"
    $ru = Get-EpsWebRedirectUris -Fqdn $fqdn -Existing @($reg.web.redirectUris)
    if ($ru.Missing.Count -or "$($reg.web.logoutUrl)" -ne "https://$fqdn/.auth/logout" -or $reg.web.implicitGrantSettings.enableIdTokenIssuance -ne $true -or $reg.web.implicitGrantSettings.enableAccessTokenIssuance) {
        Invoke-EpsOwnedRegistrationWrite -What "the sign-in addresses $($ru.Want -join ' + ') and ID-token issuance" -Do { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($Ctx.Web.AppObjectId)" -Body @{ web = @{ redirectUris = $ru.All; logoutUrl = "https://$fqdn/.auth/logout"; implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } }) }
    }
    $Ctx.Web.Fqdn = $fqdn
    $Ctx.Web.Url = "https://$fqdn/"
    # OPEN-15 (owner 6479e15b 2026-11-06 "Yes, Reader on that one app"): the engine may READ this one container app, so the
    # heartbeat reports the sign-in front it really runs (Get-EpsUplinkSignInLayer) - scope = the app, never the group
    if ($Ctx.Identities.EngineIdentity.PrincipalId) {
        $sub = "/subscriptions/$($Ctx.SubscriptionId)"
        Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.Reader)" -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId }
    }
}

# ======================================================================================================================
# 2.1.35 - Microsoft's BUILT-IN Container Apps sign-in replaces the sign-in front (owner 2026-11-14 ~21:10Z, via
# Invardia: "are we only exposing entra + azure auth now to internet and no custom auth code ? give me certaintity that
# we follow ms best practice so i dont get another hit by defender"; framework SECURE-WEB-1 points 5-7). The shape was
# PROVEN live at internal 2026-11-14 (EPS ca-eps-authproof + PIM ca-pim-authproof): the web identity is the
# registration's client credential through its federated credential (no secret anywhere); the platform keeps the
# session and its tokens in ONE blob container the web identity alone may use (no SAS, no account key); an
# unauthenticated request never reaches EPS code (a browser page 302 to Entra, anything else 401). The app still verifies
# the access token itself on EVERY request (defence in depth, EPS-WebAuth) and the engine re-verifies it before a tenant
# change.
# ======================================================================================================================
$script:EpsWeb.TokenContainer = 'eps-signin-sessions'
$script:EpsWeb.BlobDataRole   = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'     # Storage Blob Data Contributor (the ONE token container)
$script:EpsWeb.FicSecretName  = 'override-use-mi-fic-assertion-client-id'  # lowercase: the App Service name fails on Container Apps
$script:EpsWeb.AuthApi        = '2024-10-02-preview'                       # the token store with a managed identity
$script:EpsWeb.AppPort        = 8080

function New-EpsBuiltInWebAppBody {
    <#
      PURE. ONE Container App, ONE container 'eps' (the same image as the jobs, EPS_JOB = Web) as the ingress target on
      8080, listening on all addresses (EPS_WEB_LISTEN = all) - the platform's sign-in stands in front of it. The only
      secret-like value is the web identity's CLIENT id (not a credential), under the name the platform's federated
      credential path reads. Probes on /healthz hit the replica directly (not through the ingress, so not the sign-in).
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$ClientId)
    $n = $Ctx.Names; $w = $Ctx.Identities.WebIdentity
    $fqdn = "$($n.SqlServer).database.windows.net"
    $envId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
    $port = $script:EpsWeb.AppPort
    $probe = { param($t) [ordered]@{ type = $t; httpGet = [ordered]@{ path = '/healthz'; port = $port; scheme = 'HTTP' }; initialDelaySeconds = 3; periodSeconds = 10; failureThreshold = 3; timeoutSeconds = 3 } }
    $e = { param([hashtable]$h) @($h.Keys | Sort-Object | ForEach-Object { [ordered]@{ name = $_; value = "$($h[$_])" } }) }
    [ordered]@{
        location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; role = 'web' }
        identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $w.Id = @{} } }
        properties = [ordered]@{ environmentId = $envId; workloadProfileName = 'Consumption'
            configuration = [ordered]@{ activeRevisionsMode = 'Single'
                ingress = [ordered]@{ external = $true; targetPort = $port; transport = 'auto'; allowInsecure = $false; traffic = @(@{ latestRevision = $true; weight = 100 }) }
                registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = $w.Id })
                secrets = @(@{ name = $script:EpsWeb.FicSecretName; value = "$($w.ClientId)" }) }
            template = [ordered]@{
                containers = @(
                    [ordered]@{ name = 'eps'; image = $Image; resources = @{ cpu = 0.5; memory = '1Gi' }; probes = @((& $probe 'Liveness'), (& $probe 'Readiness'))
                        env = & $e @{ EPS_JOB = 'Web'; EPS_SQL_CONNECTION = "Server=tcp:$fqdn,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
                            EPS_TENANT_ID = $Ctx.TenantId; EPS_STORAGE_ACCOUNT = $n.Storage; EPS_WEB_CLIENT_ID = $ClientId; EPS_WEB_PORT = $port; EPS_WEB_LISTEN = 'all'; EPS_ManagedIdentityClientId = $w.ClientId } }
                )
                scale = @{ minReplicas = 0; maxReplicas = 1 }
            }
        }
    }
}

function New-EpsWebAuthConfigBody {
    <#
      PURE. authConfigs/current (api 2024-10-02-preview) - the body proven at internal 2026-11-14, as PIM's: sign-in
      required on every path (a browser goes to Entra, anything else gets 401), the Entra v2.0 issuer, the registration's
      own client id with the web identity as its credential, the app's own scope requested so the access token EPS
      verifies comes back, the session 8 h, the token store in the install's storage account through the web identity.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][string]$WebIdentityId)
    [ordered]@{ properties = [ordered]@{
        platform = [ordered]@{ enabled = $true }
        globalValidation = [ordered]@{ unauthenticatedClientAction = 'RedirectToLoginPage'; redirectToProvider = 'azureactivedirectory' }
        identityProviders = [ordered]@{ azureActiveDirectory = [ordered]@{ enabled = $true
            registration = [ordered]@{ clientId = $ClientId; clientSecretSettingName = $script:EpsWeb.FicSecretName; openIdIssuer = "https://login.microsoftonline.com/$TenantId/v2.0" }
            validation = [ordered]@{ allowedAudiences = @("api://$ClientId", $ClientId) }
            login = [ordered]@{ loginParameters = @("scope=openid profile email offline_access api://$ClientId/$($script:EpsWeb.Scope)", 'prompt=select_account') } } }   # owner 2026-11-14: "many places we use an admin account, not the office user that the admin is logged in with" - Entra always shows the account picker
        login = [ordered]@{
            cookieExpiration = [ordered]@{ convention = 'FixedTime'; timeToExpiration = ('{0:00}:00:00' -f [int]$script:EpsWeb.SessionHours) }
            tokenStore = [ordered]@{ enabled = $true; azureBlobStorage = [ordered]@{ blobContainerUri = "https://$StorageAccount.blob.core.windows.net/$($script:EpsWeb.TokenContainer)"; managedIdentityResourceId = $WebIdentityId } } }
    } }
}

function Get-EpsWebSigninMode {
    <# PURE. Which sign-in the RUNNING web app has: 'builtin' (no front container, the platform sign-in on), 'front' (the
       sign-in front container, the platform sign-in off), 'partial' (anything else). #>
    param($App, $AuthConfig)
    $front = [bool]@($App.properties.template.containers | Where-Object { "$($_.name)" -eq 'signin-front' }).Count
    $on = ($AuthConfig.properties.platform.enabled -eq $true)
    if ($front -and -not $on) { 'front' } elseif (-not $front -and $on) { 'builtin' } else { 'partial' }
}

function Get-EpsBuiltInAuthReadiness {
    <#
      PURE. Whether an install may switch to the built-in sign-in NOW - every precondition read, nothing guessed. The
      updater holds no right to make any of them (no role-assignment write, no registration write - review G point 2):
      the install run (or Invardia support at an install it runs) makes them; until then the updater only says what is
      missing. @{ Ready; Missing (plain words) }.
    #>
    param($Registration, [string]$Fqdn, $Fics, $FicSpec, [bool]$ContainerExists, $RoleAssignments, [string]$WebPrincipalId, [string]$BlobRoleId)
    $miss = [System.Collections.Generic.List[string]]::new()
    $cb = "https://$("$Fqdn".ToLowerInvariant())/.auth/login/aad/callback"
    if (-not $Fqdn) { $miss.Add('the web app has no address') }
    elseif (@($Registration.web.redirectUris) -notcontains $cb) { $miss.Add("the sign-in address $cb on the registration") }
    if ($Registration.web.implicitGrantSettings.enableIdTokenIssuance -ne $true) { $miss.Add("ID-token issuance on the registration (Microsoft's sign-in starts with code + id_token)") }
    if ($Registration.web.implicitGrantSettings.enableAccessTokenIssuance -eq $true) { $miss.Add('access-token issuance OFF on the registration') }
    if (-not $FicSpec -or -not @(@($Fics) | Where-Object { $_.issuer -eq $FicSpec.issuer -and $_.subject -eq $FicSpec.subject }).Count) { $miss.Add("the web identity's federated credential on the registration") }
    if (-not $ContainerExists) { $miss.Add("the token container $($script:EpsWeb.TokenContainer)") }
    elseif (-not @(@($RoleAssignments) | Where-Object { "$($_.properties.principalId)" -eq $WebPrincipalId -and "$($_.properties.roleDefinitionId)" -like "*/$BlobRoleId" }).Count) { $miss.Add('Storage Blob Data Contributor for the web identity on the token container') }
    @{ Ready = ($miss.Count -eq 0); Missing = @($miss) }
}

function Get-EpsWebSigninCheckClient {
    # an HTTP GET with redirects OFF (a 302 is the answer, not an error); -Browser sends what a browser sends
    { param($u, [switch]$Browser)
        $hc = [System.Net.Http.HttpClient]::new([System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $false }); $hc.Timeout = [TimeSpan]::FromSeconds(20)
        try {
            $m = [System.Net.Http.HttpRequestMessage]::new('GET', $u)
            if ($Browser) { [void]$m.Headers.TryAddWithoutValidation('Accept', 'text/html,application/xhtml+xml'); [void]$m.Headers.TryAddWithoutValidation('User-Agent', 'Mozilla/5.0 (Entra Policy Suite sign-in check)') }
            else { [void]$m.Headers.TryAddWithoutValidation('Accept', 'application/json') }
            $r = $hc.SendAsync($m).GetAwaiter().GetResult(); @{ Status = [int]$r.StatusCode; Location = "$($r.Headers.Location)" }
        } catch { @{ Status = 0; Location = ''; Error = "$($_.Exception.GetBaseException().Message)" } } finally { $hc.Dispose() } }
}

function Test-EpsBuiltInSigninAnswers {
    <#
      The proof that the built-in sign-in stands in front of the app: a browser page without a session goes to Entra
      (302 to login.microsoftonline.com) and an API call without a token is refused (401) - by the platform, before EPS
      code. /healthz is NOT asked through the ingress: it is behind the sign-in like every path (the replica's probes use it).
    #>
    param([Parameter(Mandatory)][string]$Fqdn, [int]$WaitSeconds = 300, [int]$PollSeconds = 10)
    $get = if ($global:EPS_WebProbeOverride) { $global:EPS_WebProbeOverride } else { Get-EpsWebSigninCheckClient }
    $sw = [Diagnostics.Stopwatch]::StartNew(); $p = $null
    while ($true) {
        $p = & $get "https://$Fqdn/" -Browser
        if (($p.Status -eq 302 -and $p.Location -match '^https://login\.microsoftonline\.com/') -or $sw.Elapsed.TotalSeconds -ge $WaitSeconds) { break }
        Start-Sleep -Seconds $PollSeconds
    }
    if ($p.Status -ne 302 -or $p.Location -notmatch '^https://login\.microsoftonline\.com/') { return @{ Ok = $false; Page = $p.Status; Reason = "a browser page without a session answered $($p.Status) ($($p.Location)$($p.Error)) within $WaitSeconds s - expected a redirect to the Entra sign-in" } }
    $a = & $get "https://$Fqdn/api/me"
    if ($a.Status -ne 401) { return @{ Ok = $false; Page = 302; Api = $a.Status; Reason = "an API call without a token answered $($a.Status) - expected 401 from Microsoft's sign-in" } }
    @{ Ok = $true; Page = 302; Api = 401; Reason = "Microsoft's sign-in stands in front of the app: a page without a session goes to Entra, an API call without a token gets 401" }
}

function Wait-EpsWebAppSucceeded {
    <# 2.1.36 (Invardia review of 2.1.35 - SI's switch failed so right after an image roll): the app is changed only once it
       reads Succeeded (bounded); returns the app as read. Throws when it never settles (the caller says it, nothing changed). #>
    param([Parameter(Mandatory)][string]$AppPath, [int]$PollSeconds = 10, [int]$MaxPolls = 36)
    for ($i = 0; $i -le $MaxPolls; $i++) {
        $a = Invoke-EpsArm -Path $AppPath -ApiVersion $script:EpsApi.aca -AllowNotFound
        if (-not $a -or "$($a.properties.provisioningState)" -in 'Succeeded', 'Failed', 'Canceled') { return $a }
        if ($i -lt $MaxPolls) { Start-Sleep -Seconds $PollSeconds }
    }
    throw "the web app is still '$($a.properties.provisioningState)' after $($MaxPolls * $PollSeconds) s - not changed now"
}

function Invoke-EpsArmOn409 {
    <# 2.1.36: an ARM write the platform refuses with 409 (ContainerAppOperationInProgress - another operation still runs)
       is sent again after a back-off (default 20 / 40 / 60 s); any other error is thrown at once. #>
    param([Parameter(Mandatory)][scriptblock]$Do, [int[]]$Waits = @(20, 40, 60))
    foreach ($w in @($Waits) + @(-1)) {
        try { return (& $Do) } catch {
            if ($w -lt 0 -or "$($_.Exception.Message)" -notmatch '409|OperationInProgress|ContainerAppOperationInProgress') { throw }
            Start-Sleep -Seconds $(if ($null -ne $script:EpsRetrySeconds) { $script:EpsRetrySeconds } else { $w })
        }
    }
}

function Set-EpsWebFicSetting {
    <# 2.1.36 (the 2.1.35 switch at internal: AuthConfigSecretRefNotFound): the platform refuses a sign-in config whose
       clientSecretSettingName the app does not hold YET - so the setting (the web identity's CLIENT id, not a credential)
       goes on the app FIRST, keeping every setting the app has. Returns $true when it was added. #>
    param([Parameter(Mandatory)][string]$AppPath, [Parameter(Mandatory)][string]$WebClientId)
    $cur = @((Invoke-EpsArm -Method POST -Path "$AppPath/listSecrets" -ApiVersion $script:EpsApi.aca -Body @{}).value)
    $mine = @($cur | Where-Object { "$($_.name)" -ceq $script:EpsWeb.FicSecretName })[0]
    if ($mine -and "$($mine.value)" -eq $WebClientId) { return $false }
    $list = @(@($cur | Where-Object { "$($_.name)" -cne $script:EpsWeb.FicSecretName } | ForEach-Object { @{ name = "$($_.name)"; value = "$($_.value)" } }) + @(@{ name = $script:EpsWeb.FicSecretName; value = $WebClientId }))
    [void](Invoke-EpsArmOn409 { Invoke-EpsArm -Method PATCH -Path $AppPath -ApiVersion $script:EpsApi.aca -Body @{ properties = @{ configuration = @{ secrets = $list } } } })
    $true
}

function Invoke-EpsBuiltInAuthConverge {
    <#
      2.1.35, the UPDATER (Contributor on the install's resource group; no role-assignment write, no registration write):
      an install still behind the sign-in front is switched to Microsoft's built-in sign-in ONLY when every precondition
      reads true (Get-EpsBuiltInAuthReadiness) - otherwise NOTHING changes and the run log says what is missing (it reaches
      Invardia). The switch: the sign-in config first (for a moment the platform's sign-in stands in front of the front -
      nobody gets in unverified), then the app as ONE container (the eps image it runs now), then read back and proven.
      A switch that does not prove = a WARNING line (Invardia sees it). Never throws:
      @{ State (builtin | switched | waiting | error | none); Lines }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [int]$WaitSeconds = 300, [int]$PollSeconds = 10)
    try {
        $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $appPath = "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)"
        $app = Invoke-EpsArm -Path $appPath -ApiVersion $script:EpsApi.aca -AllowNotFound
        if (-not $app) { return @{ State = 'none'; Lines = @('sign-in: this install has no web app') } }
        $ac = Invoke-EpsArm -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -AllowNotFound
        if ((Get-EpsWebSigninMode -App $app -AuthConfig $ac) -eq 'builtin') { return @{ State = 'builtin'; Lines = @("sign-in: Microsoft's built-in sign-in is on; nothing to change") } }
        $fqdn = "$($app.properties.configuration.ingress.fqdn)".Trim().ToLowerInvariant()
        $wi = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n.WebIdentity)" -ApiVersion $script:EpsApi.mi -AllowNotFound
        $reg = Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)"
        if (-not $reg -or -not $wi) { return @{ State = 'waiting'; Lines = @("sign-in: still the sign-in front - $(if (-not $reg) { 'the web app registration' } else { "the identity $($n.WebIdentity)" }) is not found; nothing changed") } }
        $fics = @(Invoke-EpsGraph -Path "v1.0/applications/$($reg.id)/federatedIdentityCredentials" -All)
        $contPath = "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)/blobServices/default/containers/$($script:EpsWeb.TokenContainer)"
        $cont = Invoke-EpsArm -Path $contPath -ApiVersion $script:EpsApi.st -AllowNotFound
        $ras = if ($cont) { @((Invoke-EpsArm -Path "$contPath/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()" -ApiVersion $script:EpsApi.rbac).value) } else { @() }
        $pid0 = "$($wi.properties.principalId)"
        $ready = Get-EpsBuiltInAuthReadiness -Registration $reg -Fqdn $fqdn -Fics $fics -FicSpec (Get-EpsFicSpec -TenantId $TenantId -PrincipalId $pid0) -ContainerExists ([bool]$cont) -RoleAssignments $ras -WebPrincipalId $pid0 -BlobRoleId $script:EpsWeb.BlobDataRole
        if (-not $ready.Ready) { return @{ State = 'waiting'; Lines = @("sign-in: still the sign-in front - Microsoft's built-in sign-in waits for: $($ready.Missing -join '; '). One install run (or Invardia support) makes them; nothing changed") } }
        $img = "$(@($app.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
        if (-not $img) { return @{ State = 'error'; Lines = @('WARNING sign-in: the web app has no eps container - nothing changed') } }
        $ctx = @{ Names = $n; SubscriptionId = $SubscriptionId; TenantId = $TenantId; Location = "$($app.location)"
                  Identities = @{ WebIdentity = @{ Id = "$($wi.id)"; ClientId = "$($wi.properties.clientId)"; PrincipalId = $pid0 } } }
        # PIM's proven order (Invardia must-fix): the setting -> the sign-in config ON while the front still runs -> the app
        # without the front. Each write only once the app reads Succeeded; a 409 (an operation still running) is sent again.
        $app = Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $PollSeconds
        [void](Set-EpsWebFicSetting -AppPath $appPath -WebClientId "$($wi.properties.clientId)")
        $app = Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $PollSeconds
        [void](Invoke-EpsArmOn409 { Invoke-EpsArm -Method PUT -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -Body (New-EpsWebAuthConfigBody -TenantId $TenantId -ClientId "$($reg.appId)" -StorageAccount $n.Storage -WebIdentityId "$($wi.id)") })
        $app = Wait-EpsWebAppSucceeded -AppPath $appPath -PollSeconds $PollSeconds
        $put = Invoke-EpsArmOn409 { Invoke-EpsArm -Method PUT -Path $appPath -ApiVersion $script:EpsApi.aca -Body (New-EpsBuiltInWebAppBody -Ctx $ctx -Image $img -ClientId "$($reg.appId)") }
        for ($i = 0; "$($put.properties.provisioningState)" -in 'InProgress', 'Updating', '' -and $i -lt 40; $i++) { Start-Sleep -Seconds $PollSeconds; $put = Invoke-EpsArm -Path $appPath -ApiVersion $script:EpsApi.aca }
        $back = Get-EpsWebSigninMode -App $put -AuthConfig (Invoke-EpsArm -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -AllowNotFound)
        if ($back -ne 'builtin' -or "$($put.properties.provisioningState)" -ne 'Succeeded') { return @{ State = 'error'; Lines = @("WARNING sign-in: the switch to Microsoft's built-in sign-in reads back '$back' (provisioning $($put.properties.provisioningState)) - the next update run tries again") } }
        $proof = Test-EpsBuiltInSigninAnswers -Fqdn $fqdn -WaitSeconds $WaitSeconds -PollSeconds $PollSeconds
        if (-not $proof.Ok) { return @{ State = 'error'; Lines = @("WARNING sign-in: switched to Microsoft's built-in sign-in, but $($proof.Reason)") } }
        @{ State = 'switched'; Lines = @("sign-in: switched from the sign-in front to Microsoft's built-in sign-in (one container, $(("$img" -split '/')[-1])); read back; $($proof.Reason)") }
    } catch { @{ State = 'error'; Lines = @("WARNING sign-in: $((("$($_.Exception.Message)") -split "`n")[0]) - the next update run tries again") } }
}
