# EntraPolicySuite -- the install's steps (DESIGN §2): everything in the customer's own subscription, created over REST
# as the signed-in person (EPS-SignIn), no module, no az CLI. PIM's model (PIM-DeployAll.ps1): the step catalog is
# DATA; each step has a read-only CHECK (what exists) and an idempotent DO; -WhatIf runs the checks and stops; the
# journal (state.json) lets a failed install resume where it stopped.
# Dot-source EPS-SqlStore, EPS-Graph, EPS-Arm, EPS-Scheduler first.

Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'EPS-InstallWeb.ps1')   # the web app's steps (the sign-in front)
$script:EpsApi = @{ rg = '2021-04-01'; mi = '2023-01-31'; law = '2022-10-01'; acr = '2023-07-01'; sql = '2021-11-01'; aca = '2024-03-01'; acajob = '2025-01-01'; st = '2023-05-01'; rbac = '2022-04-01'; prov = '2021-04-01'; sub = '2022-12-01' }
$script:EpsRole = @{ AcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
    # SEC-AUDIT-1 S4 (2.0.9): the tick may only SEND to the job queues; the engine reads + deletes them (and KEDA counts)
    QueueSender = 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'; QueueProcessor = '8a0f0c08-91a1-4084-bc3d-661d67233fed'
    # Reader: KEDA reads the queue's properties to count its messages (found live 2026-11-01: 403 without it)
    QueueReader = '19e7f393-937e-4f77-808e-94535e297925'
    # UPLINK-1 (owner 2026-11-01 "Install's Key Vault"): the engine reads the ONE secret uplink-key, scoped to that secret
    KvSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6' }
$script:EpsUplinkSecret = 'uplink-key'

function Grant-EpsUplinkKeyAccess {
    <#
      UPLINK-1: the engine identity Key Vault Secrets User on the secret uplink-key ONLY (the scope is the secret's
      resource id, never the vault) - and only when the secret exists: Invardia writes the key; the install never creates
      the secret and never reads its value (an ARM read of a secret carries no value). No secret = nothing granted, the
      uplink stays disabled; a later run of the install grants it once the key is there. @{ Granted; Reason }.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $sub = "/subscriptions/$($Ctx.SubscriptionId)"
    $secret = "$sub/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)/secrets/$($script:EpsUplinkSecret)"
    $s = Invoke-EpsArm -Path $secret -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
    if (-not $s) { return @{ Granted = $false; Reason = "no secret $($script:EpsUplinkSecret) in $($n.KeyVault) yet: the uplink stays disabled until Invardia writes it (then run the install again)" } }
    Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope $secret -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.KvSecretsUser)" -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId }
    @{ Granted = $true; Reason = "$($n.EngineIdentity) may read the secret $($script:EpsUplinkSecret) (and nothing else in the vault)" }
}
# the engine's rights (the security pack lists the same): Graph app roles by VALUE (ids resolved from the tenant)
$script:EpsEngineGraphRoles = @('User.ReadWrite.All', 'Device.ReadWrite.All', 'GroupMember.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'DeviceManagementManagedDevices.Read.All', 'Application.Read.All')   # Application.Read.All: application names in the CA documentation, READ ONLY (owner 2026-11-01: "Grant Application.Read.All")   # Policy + RoleManagement: the CA Policy Analyzer, READ ONLY (it never writes a policy); DeviceManagementManagedDevices: the identity report's Intune devices, read only (owner 2026-10-31: "Yes, add both")   # AuditLog: the tamper monitor's "who"
function Get-EpsEngineGraphRoles {
    # the engine's Graph roles minus any the approver left out (-ExcludeGraphRole): a role not approved is never granted;
    # the feature that needs it reports its data as unavailable (e.g. Teams_Room_Like without Organization.Read.All)
    param($Ctx) @($script:EpsEngineGraphRoles | Where-Object { @($Ctx.ExcludeGraphRoles) -notcontains $_ })
}
$script:EpsExchangeAppId = '00000002-0000-0ff1-ce00-000000000000'      # Office 365 Exchange Online
$script:EpsExchangeRecipientAdminRole = '31392ffb-586c-42d1-9346-e59415a2cc4e'   # Entra role template: Exchange Recipient Administrator

function Get-EpsInstallNames {
    # One place for every name. Globally unique names (registry, SQL server) carry a short, stable suffix from the
    # subscription + resource group, so a re-run finds the same resources.
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$SubscriptionId|$ResourceGroup".ToLowerInvariant()))
    $s = (-join ($h[0..3] | ForEach-Object { $_.ToString('x2') }))
    [ordered]@{
        ResourceGroup = $ResourceGroup; Suffix = $s
        EngineIdentity = 'id-eps-engine'; TickIdentity = 'id-eps-tick'; WebIdentity = 'id-eps-web'
        Logs = 'log-eps'; Registry = "acreps$s"; Image = 'eps-engine'
        SqlServer = "sql-eps-$s"; Database = 'eps'
        Environment = 'cae-eps'; TickJob = 'caj-eps-tick'; Storage = "steps$s"
        JobStarterRole = "EntraPolicySuite job starter ($ResourceGroup)"
        WebApp = 'ca-eps-web'; KeyVault = "kv-eps-$s"; WebAppRegistration = "EntraPolicySuite ($ResourceGroup)"
    }
}

function Get-EpsInstallSteps {
    # The order is load-bearing: identities before the registry (AcrPull), the registry before the image, the image and
    # SQL before the jobs (a job pins its image; its env names the database), the jobs before their role assignments.
    @(
        [pscustomobject]@{ Id = 'resourcegroup'; Title = 'Resource group' }
        [pscustomobject]@{ Id = 'identities';    Title = 'Managed identities (engine, tick, web)' }
        [pscustomobject]@{ Id = 'logs';          Title = 'Log Analytics workspace' }
        [pscustomobject]@{ Id = 'registry';      Title = 'Container registry (Basic) + AcrPull for the identities' }
        [pscustomobject]@{ Id = 'image';         Title = 'The engine image, built in the registry' }
        [pscustomobject]@{ Id = 'sql';           Title = 'Azure SQL (Entra-only) + database' }
        [pscustomobject]@{ Id = 'schema';        Title = 'The database schema' }
        [pscustomobject]@{ Id = 'sqlaccess';     Title = 'The identities as database users, one least-privilege role each' }
        [pscustomobject]@{ Id = 'environment';   Title = 'Container Apps environment' }
        [pscustomobject]@{ Id = 'queues';        Title = 'The job queues (storage, no shared key): the tick may only send, the engine read' }
        # the registration BEFORE the jobs (2.0.18): the engine checks a person's signed request against the web app's
        # client id, so the engine jobs carry it (without it every GUI change was refused, fail closed)
        [pscustomobject]@{ Id = 'webregistration'; Title = 'The web sign-in registration (no secret; assignment required; you assigned)' }
        [pscustomobject]@{ Id = 'jobs';          Title = 'The tick + work jobs' }
        [pscustomobject]@{ Id = 'jobstarter';    Title = 'The tick may NOT start jobs (an older install''s job-starter role removed)' }
        [pscustomobject]@{ Id = 'graph';         Title = "The engine's Graph permissions" }
        [pscustomobject]@{ Id = 'exchange';      Title = "The engine's Exchange permission + role" }
        [pscustomobject]@{ Id = 'keyvault';      Title = "Key Vault for the sign-in front's wrap key" }
        [pscustomobject]@{ Id = 'webstate';      Title = "The sign-in front's state in the database; you as the first SuperAdmin" }
        [pscustomobject]@{ Id = 'frontimage';    Title = 'The sign-in front image (the pinned version), built in the registry' }
        [pscustomobject]@{ Id = 'webapp';        Title = 'The web app: the sign-in front + the GUI in one revision' }
        [pscustomobject]@{ Id = 'verify';        Title = 'Verify: read everything back, run the tick once' }
    )
}

function Get-EpsGuidFrom([string]$text) {
    # a stable GUID from a text (role definition / assignment names that a re-run must find again)
    $b = [Security.Cryptography.MD5]::HashData([Text.Encoding]::UTF8.GetBytes($text.ToLowerInvariant()))
    $b[6] = ($b[6] -band 0x0f) -bor 0x30; $b[8] = ($b[8] -band 0x3f) -bor 0x80
    [guid]::new($b).ToString()
}

function Get-EpsJobBodies {
    # The Container Apps Jobs (DESIGN §2, §4): the tick on a 5-minute schedule, one MANUAL job per implemented work job
    # (the tick starts it). No secret anywhere: each job signs in to SQL, Graph and Exchange with its managed identity.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Image)
    $n = $Ctx.Names
    $fqdn = "$($n.SqlServer).database.windows.net"
    $cs = "Server=tcp:$fqdn,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $envId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
    $mk = {
        param($name, $job, $identity, [string]$trigger, [int]$timeout, [string]$cpu, [string]$mem, [bool]$parallelJob)
        $miId = $Ctx.Identities[$identity].Id
        if (-not $miId) { $miId = "(the $($n[$identity]) identity, created by the install)" }   # a plan before the identities exist
        $config = [ordered]@{ triggerType = $trigger; replicaTimeout = $timeout; replicaRetryLimit = 0
                              registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = $miId }) }
        if ($trigger -eq 'Schedule') { $config.scheduleTriggerConfig = @{ cronExpression = '*/5 * * * *'; parallelism = 1; replicaCompletionCount = 1 } }
        elseif ($trigger -eq 'Event') {
            # SEC-AUDIT-1 S4 (2.0.9): started by a message on the job's own queue (the tick may only send to it); KEDA
            # counts the queue as the ENGINE identity - no connection string, no key. A parallel job (the analyzer) may run
            # up to 10 executions side by side; any other one at a time (the tick's overlap guard decides too).
            $config.eventTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1
                scale = @{ minExecutions = 0; maxExecutions = $(if ($parallelJob) { 10 } else { 1 }); pollingInterval = 30
                    rules = @(@{ name = 'queue'; type = 'azure-queue'; identity = $miId
                        metadata = @{ accountName = $n.Storage; queueName = (Get-EpsJobQueueName $name); queueLength = '1' } }) } }
        }
        else { $config.manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } }
        # the uplink job (UPLINK-1) also needs the NAME of the install's Key Vault (it reads the secret uplink-key from it
        # at send time - the key itself is never in a job's env or config) and the web app's address for alert links
        $extra = @()
        # every engine job checks signed requests against the web app's registration (issuer + audience pins): the client id
        if ($identity -eq 'EngineIdentity') {
            $wc = "$($Ctx.Web.ClientId)"
            if (-not $wc) { $wc = '(the web sign-in registration''s client id, created by the install)' }   # a plan before it exists
            $extra += @{ name = 'EPS_WEB_CLIENT_ID'; value = $wc }
        }
        if ($job -eq 'Uplink') {
            $extra += @{ name = 'EPS_KEY_VAULT'; value = $n.KeyVault }
            if ("$($Ctx.WebUrl)" -match '^https://') { $extra += @{ name = 'EPS_WEB_URL'; value = "$($Ctx.WebUrl)" } }
        }
        [ordered]@{
            Name = $name
            Body = [ordered]@{
                location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; job = $job }
                identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $miId = @{} } }
                properties = [ordered]@{ environmentId = $envId; workloadProfileName = 'Consumption'; configuration = $config
                    template = @{ containers = @(@{ name = 'eps'; image = $Image; resources = @{ cpu = [double]$cpu; memory = $mem }
                        env = @(
                            @{ name = 'EPS_JOB'; value = $job }
                            @{ name = 'EPS_SQL_CONNECTION'; value = $cs }
                            @{ name = 'EPS_TENANT_ID'; value = $Ctx.TenantId }
                            @{ name = 'EPS_SUBSCRIPTION_ID'; value = $Ctx.SubscriptionId }
                            @{ name = 'EPS_RESOURCE_GROUP'; value = $n.ResourceGroup }
                            @{ name = 'EPS_STORAGE_ACCOUNT'; value = $n.Storage }
                            @{ name = 'EPS_ACA_JOB'; value = $(if ($trigger -eq 'Event') { $name } else { '' }) }
                            @{ name = 'EPS_ManagedIdentityClientId'; value = $Ctx.Identities[$identity].ClientId }) + $extra }) } } }
        }
    }
    # the tick is short; a work job may run up to the 7-day limit (framework JOB-RUN-LIMIT) and holds 200,000 users
    # in memory (2.2 GB measured 2026-10-30), so it gets 4 GiB
    @(& $mk $n.TickJob 'Tick' 'TickIdentity' 'Schedule' 1800 '0.25' '0.5Gi') +
    @(foreach ($d in Get-EpsDefaultJobSchedule | Where-Object Implemented) { & $mk $d.AcaJobName $d.Job 'EngineIdentity' 'Event' 604800 '2.0' '4Gi' ([bool]$d.Parallel) })
}

function Add-EpsRoleAssignment {
    # idempotent: the assignment's name is a stable GUID of (scope, role, principal); 409 = it is there
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleDefinitionId, [Parameter(Mandatory)][string]$PrincipalId, [string]$PrincipalType = 'ServicePrincipal')
    $name = Get-EpsGuidFrom "$Scope|$RoleDefinitionId|$PrincipalId"
    try {
        [void](Invoke-EpsArm -Method PUT -Path "$Scope/providers/Microsoft.Authorization/roleAssignments/$name" -ApiVersion $script:EpsApi.rbac `
            -Body @{ properties = @{ roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId; principalType = $PrincipalType } })
    } catch { if ("$_" -notmatch 'RoleAssignmentExists|409') { throw } }
}

function Grant-EpsAppRoles {
    # app roles of a resource app (Graph, Exchange) to a managed identity: read what it has, add only what is missing
    # (a duplicate POST answers 400), read back.
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$ResourceAppId, [Parameter(Mandatory)][string[]]$Roles)
    $sp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$ResourceAppId'&`$select=id,appRoles" -All)[0]
    if (-not $sp) { throw "the tenant has no service principal for $ResourceAppId" }
    $byValue = @{}; foreach ($r in $sp.appRoles) { $byValue[[string]$r.value] = [string]$r.id }
    $have = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -All | Where-Object { $_.resourceId -eq $sp.id } | ForEach-Object { [string]$_.appRoleId })
    $added = @()
    foreach ($role in $Roles) {
        $rid = $byValue[$role]; if (-not $rid) { throw "app role '$role' does not exist on $ResourceAppId" }
        if ($have -contains $rid) { continue }
        try { [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -Body @{ principalId = $PrincipalId; resourceId = $sp.id; appRoleId = $rid }) }
        catch { if ("$_" -notmatch '(?i)already exists') { throw } }   # a re-run after a read that lagged: it is there
        $added += $role
    }
    # Graph is eventually consistent (found live 2026-10-30): a read right after the grant can miss it - poll the read-back
    for ($try = 0; $try -lt 9; $try++) {
        $now = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -All | Where-Object { $_.resourceId -eq $sp.id } | ForEach-Object { [string]$_.appRoleId })
        $missing = @($Roles | Where-Object { $now -notcontains $byValue[$_] })
        if (-not $missing.Count) { break }
        Start-Sleep -Seconds $(if ($script:EpsGraphReadBackSeconds -ne $null) { $script:EpsGraphReadBackSeconds } else { 15 })
    }
    if ($missing) { throw "still missing after the grant: $($missing -join ', ')" }
    $added
}

function ConvertTo-EpsSqlSid([string]$AppId) { '0x' + (-join (([guid]$AppId).ToByteArray() | ForEach-Object { $_.ToString('X2') })) }

function Get-EpsSqlUserScript {
    # A managed identity as a contained database user WITHOUT 'FROM EXTERNAL PROVIDER' (that makes SQL look the name up
    # in Graph as the server's identity - PIM found it fails): the user's SID is its app (client) id.
    # Framework §12.23 P3: the user is a member of ITS component role only (eps_engine / eps_tick / eps_web / eps_worker,
    # sql/eps-grants.json) - never db_datareader / db_datawriter / db_owner; a re-run takes those away if a user has them.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$Role)
    if ($Name -notmatch '^[A-Za-z0-9-]{1,128}$') { throw "unsafe database user name '$Name'" }
    if ($Role -notmatch '^eps_[a-z]{2,20}$') { throw "unsafe role name '$Role'" }
    $sid = ConvertTo-EpsSqlSid $ClientId
    $q = "[$Name]"
    $lines = @(
        "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Name' AND sid <> $sid) DROP USER $q;"
        "IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Name') CREATE USER $q WITH SID = $sid, TYPE = E;"
        "IF IS_ROLEMEMBER('$Role', N'$Name') = 0 ALTER ROLE [$Role] ADD MEMBER $q;"
    )
    foreach ($r in 'db_owner', 'db_datareader', 'db_datawriter', 'db_ddladmin') { $lines += "IF IS_ROLEMEMBER('$r', N'$Name') = 1 ALTER ROLE [$r] DROP MEMBER $q;" }
    $lines -join "`n"
}

function Get-EpsGrantList {
    param([string]$SolutionRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
    Get-Content -LiteralPath (Join-Path $SolutionRoot 'sql\eps-grants.json') -Raw | ConvertFrom-Json -AsHashtable
}

function Get-EpsGrantScript {
    <#
      The component roles exactly as the shipped grant list says (§12.23 P3): each role created if missing, each listed
      permission granted, and every OTHER object permission the role holds in schema eps revoked - so a re-run converges
      to the list, never only adds. Run as the server's Entra admin (setup); after the schema (the tables must exist).
    #>
    # A permission is SELECT / INSERT / UPDATE / DELETE on the table, or SELECT(col, ...) / UPDATE(col, ...) on named
    # columns only (SEC-AUDIT-1 S1 / S3: a component that only moves a status may not rewrite what was asked).
    param([Parameter(Mandatory)]$GrantList)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($role in $GrantList.roles.Keys | Sort-Object) {
        if ($role -notmatch '^eps_[a-z]{2,20}$') { throw "unsafe role name '$role'" }
        $lines.Add("IF DATABASE_PRINCIPAL_ID(N'$role') IS NULL CREATE ROLE [$role];")
        $want = [System.Collections.Generic.List[string]]::new()
        $grants = [System.Collections.Generic.List[string]]::new()
        foreach ($t in $GrantList.roles[$role].grants.Keys | Sort-Object) {
            if ($t -notmatch '^[A-Za-z]{2,60}$') { throw "unsafe table name '$t'" }
            foreach ($p in $GrantList.roles[$role].grants[$t]) {
                $g = ConvertFrom-EpsGrantEntry $p
                if (-not $g) { throw "permission '$p' on $t for $role is not SELECT / INSERT / UPDATE / DELETE, or SELECT(cols) / UPDATE(cols)" }
                if ($t -eq 'AuditEvent' -and $g.Permission -in 'UPDATE', 'DELETE') { throw "the audit trail is append-only: no $($g.Permission) on AuditEvent for $role" }
                if ($g.Columns.Count) {
                    $grants.Add("GRANT $($g.Permission) ($(($g.Columns | ForEach-Object { "[$_]" }) -join ', ')) ON eps.$t TO [$role];")
                    foreach ($c in $g.Columns) { $want.Add("'$t|$($g.Permission)|$c'") }
                } else { $grants.Add("GRANT $($g.Permission) ON eps.$t TO [$role];"); $want.Add("'$t|$($g.Permission)|'") }
            }
        }
        # revoke what the list does not name (object and column permissions in schema eps, granted to this role) - a
        # table-wide grant that became column-level goes, so a re-run converges to the list, never only adds.
        # The REVOKE runs BEFORE the GRANTs: revoking a table-wide permission also removes that permission's column grants
        # (2.0.7 live: the tick lost UPDATE(cols) on JobRequest that way), so granting first would be undone.
        $lines.Add(@"
DECLARE @r_$role NVARCHAR(MAX) = N'';
SELECT @r_$role = @r_$role + N'REVOKE ' + p.permission_name COLLATE DATABASE_DEFAULT + CASE WHEN p.minor_id > 0 THEN N' (' + QUOTENAME(COL_NAME(p.major_id, p.minor_id)) COLLATE DATABASE_DEFAULT + N')' ELSE N'' END + N' ON eps.' + QUOTENAME(o.name) COLLATE DATABASE_DEFAULT + N' TO [$role];'
FROM sys.database_permissions p JOIN sys.objects o ON o.object_id = p.major_id
WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'$role') AND p.class = 1 AND p.state IN ('G', 'W') AND SCHEMA_NAME(o.schema_id) = 'eps'
  AND (o.name COLLATE DATABASE_DEFAULT + '|' + p.permission_name COLLATE DATABASE_DEFAULT + '|' + CASE WHEN p.minor_id > 0 THEN COL_NAME(p.major_id, p.minor_id) COLLATE DATABASE_DEFAULT ELSE N'' END) NOT IN ($(if ($want.Count) { $want -join ', ' } else { "''" }));
EXEC (@r_$role);
"@)
        foreach ($x in $grants) { $lines.Add($x) }
    }
    $lines -join "`n"
}

function ConvertFrom-EpsGrantEntry {
    # 'UPDATE' -> @{ Permission = 'UPDATE'; Columns = @() }; 'UPDATE(Status, Error)' -> the columns; anything else $null
    param([string]$Entry)
    if ($Entry -match '^(SELECT|INSERT|UPDATE|DELETE)$') { return @{ Permission = $Matches[1]; Columns = @() } }
    if ($Entry -match '^(SELECT|UPDATE)\(\s*([A-Za-z][A-Za-z0-9_]{0,59}(\s*,\s*[A-Za-z][A-Za-z0-9_]{0,59})*)\s*\)$') {
        return @{ Permission = $Matches[1]; Columns = @($Matches[2] -split '\s*,\s*') }
    }
    $null
}

function Test-EpsInstallStep {
    # READ-ONLY: what the step would do. Returns @{ Action = 'create' | 'update' | 'exists' | 'run'; Detail }.
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    $has = { param($path, $api) [bool](Invoke-EpsArm -Path $path -ApiVersion $api -AllowNotFound) }
    switch ($Id) {
        'resourcegroup' { if (& $has $rg $script:EpsApi.rg) { @{ Action = 'exists'; Detail = $n.ResourceGroup } } else { @{ Action = 'create'; Detail = "$($n.ResourceGroup) in $($Ctx.Location)" } } }
        'identities'    { $m = @($n.EngineIdentity, $n.TickIdentity, $n.WebIdentity | Where-Object { -not (& $has "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$_" $script:EpsApi.mi) }); if ($m) { @{ Action = 'create'; Detail = $m -join ', ' } } else { @{ Action = 'exists'; Detail = 'all three' } } }
        'logs'          { if (& $has "$rg/providers/Microsoft.OperationalInsights/workspaces/$($n.Logs)" $script:EpsApi.law) { @{ Action = 'exists'; Detail = $n.Logs } } else { @{ Action = 'create'; Detail = $n.Logs } } }
        'registry'      { if (& $has "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" $script:EpsApi.acr) { @{ Action = 'update'; Detail = "$($n.Registry) (AcrPull checked)" } } else { @{ Action = 'create'; Detail = "$($n.Registry) (Basic)" } } }
        'image'         { @{ Action = 'run'; Detail = "build $($n.Image):$($Ctx.Version) in $($n.Registry)" } }
        'sql'           { if (& $has "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)/databases/$($n.Database)" $script:EpsApi.sql) { @{ Action = 'exists'; Detail = "$($n.SqlServer)/$($n.Database)" } } else { @{ Action = 'create'; Detail = "$($n.SqlServer) (Entra-only, admin $($Ctx.Person.Upn)) + $($n.Database) (S0)" } } }
        'sqlaccess'     { @{ Action = 'run'; Detail = "roles eps_engine, eps_tick, eps_web, eps_worker (sql/eps-grants.json, object-level); users $($n.EngineIdentity), $($n.TickIdentity), $($n.WebIdentity) - never db_datareader / db_datawriter" } }
        'schema'        { @{ Action = 'run'; Detail = 'sql/eps-schema.sql (idempotent, additive)' } }
        'environment'   { if (& $has "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" $script:EpsApi.aca) { @{ Action = 'exists'; Detail = $n.Environment } } else { @{ Action = 'create'; Detail = "$($n.Environment) (Consumption)" } } }
        'queues'        { if (& $has "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)" $script:EpsApi.st) { @{ Action = 'update'; Detail = "$($n.Storage) (queues + who may send / read checked)" } } else { @{ Action = 'create'; Detail = "$($n.Storage) (no shared key) + one queue per work job; the tick may send, the engine read" } } }
        'jobs'          { @{ Action = 'run'; Detail = ((Get-EpsJobBodies -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)") | ForEach-Object { $_.Name }) -join ', ' } }
        'jobstarter'    { @{ Action = 'run'; Detail = "remove role '$($n.JobStarterRole)' if an older install made it; read back: $($n.TickIdentity) holds no role on $($n.ResourceGroup)" } }
        'graph'         { @{ Action = 'run'; Detail = "$($n.EngineIdentity): $((Get-EpsEngineGraphRoles -Ctx $Ctx) -join ', ')$(if (@($Ctx.ExcludeGraphRoles).Count) { ' (left out, not approved: ' + (@($Ctx.ExcludeGraphRoles) -join ', ') + ')' })" } }
        'exchange'      { @{ Action = 'run'; Detail = "$($n.EngineIdentity): Exchange.ManageAsApp + Entra role Exchange Recipient Administrator" } }
        'webregistration' { $a = try { Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)" } catch { $null }; if ($a) { @{ Action = 'update'; Detail = "$($a.displayName) ($($a.appId)): api://, scope $($script:EpsWeb.Scope), consents, federated credential for $($n.WebIdentity)" } } else { @{ Action = 'create'; Detail = "app registration '$($n.WebAppRegistration)' (single tenant, code flow, no secret, assignment required, you assigned)" } } }
        'keyvault'      { $up = "; $($n.EngineIdentity) Key Vault Secrets User on the secret $($script:EpsUplinkSecret) only if Invardia has put it there (the install never creates or reads it)"
                          if (& $has "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)" $script:EpsWeb.KvApi) { @{ Action = 'exists'; Detail = "$($n.KeyVault) (key $($script:EpsWeb.KeyName) checked)$up" } } else { @{ Action = 'create'; Detail = "$($n.KeyVault) (Standard, RBAC, purge protection) + RSA key $($script:EpsWeb.KeyName); $($n.WebIdentity) Crypto Service Encryption User on that key$up" } } }
        'webstate'      { @{ Action = 'run'; Detail = "schema signin owned by $($n.WebIdentity) + CREATE TABLE; $($Ctx.Person.Upn) the first SuperAdmin (if there is none)" } }
        'frontimage'    { $pin = Get-EpsSigninFrontPin -SolutionRoot $Ctx.SolutionRoot; $s = Get-EpsSigninFrontSource -SolutionRoot $Ctx.SolutionRoot -Pin $pin -Root $Ctx.SigninFrontRoot; @{ Action = $(if ($s.Ok) { 'run' } else { 'blocked' }); Detail = "signin-front:$pin in $($n.Registry) - $($s.Reason)" } }
        'webapp'        { if (& $has "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" $script:EpsApi.aca) { @{ Action = 'update'; Detail = "$($n.WebApp) (the front + the GUI)" } } else { @{ Action = 'create'; Detail = "$($n.WebApp): signin-front on the ingress (8080), the GUI on 127.0.0.1:8081, as $($n.WebIdentity), scale 0-1" } } }
        'verify'        { @{ Action = 'run'; Detail = 'read back every resource and grant; start the tick once and wait for its run record; the web app answers and sends a page without a session to the Entra sign-in' } }
        default         { throw "unknown install step '$Id'" }
    }
}

function Invoke-EpsInstallStep {
    # The step's change. Idempotent: ARM PUT, read-before-add grants, IF NOT EXISTS SQL.
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $sub = "/subscriptions/$($Ctx.SubscriptionId)"; $rg = "$sub/resourceGroups/$($n.ResourceGroup)"
    $tags = @{ product = 'EntraPolicySuite'; version = $Ctx.Version }
    $loadMi = {
        if ($Ctx.Identities.EngineIdentity -and $Ctx.Identities.TickIdentity -and $Ctx.Identities.WebIdentity) { return }
        foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') {
            $m = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n[$k])" -ApiVersion $script:EpsApi.mi
            $Ctx.Identities[$k] = @{ Id = $m.id; ClientId = $m.properties.clientId; PrincipalId = $m.properties.principalId }
        }
    }
    # the web facts a resumed install no longer has in memory: read back, never remembered in the journal
    $loadWeb = {
        if (-not $Ctx.Web) { $Ctx.Web = @{} }
        if (-not $Ctx.Web.ClientId) {
            $a = Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)"
            if (-not $a) { throw 'the web sign-in registration is missing - run the webregistration step (resume from it)' }
            $sp0 = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($a.appId)'&`$select=id" -All)[0]
            $Ctx.Web.ClientId = [string]$a.appId; $Ctx.Web.AppObjectId = [string]$a.id; $Ctx.Web.SpId = [string]$sp0.id
        }
        if (-not $Ctx.Web.KeyId) {
            $k0 = Invoke-EpsArm -Path "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)/keys/$($script:EpsWeb.KeyName)" -ApiVersion $script:EpsWeb.KvApi -AllowNotFound
            if ($k0) { $Ctx.Web.KeyId = "$($k0.properties.keyUri)" }
        }
        if (-not $Ctx.Web.FrontVersion) { $Ctx.Web.FrontVersion = Get-EpsSigninFrontPin -SolutionRoot $Ctx.SolutionRoot }
        if (-not $Ctx.Web.Fqdn) {
            $w0 = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -ApiVersion $script:EpsApi.aca -AllowNotFound
            if ($w0) { $Ctx.Web.Fqdn = "$($w0.properties.configuration.ingress.fqdn)".ToLowerInvariant(); $Ctx.Web.Url = "https://$($Ctx.Web.Fqdn)/" }
        }
    }
    switch ($Id) {
        'resourcegroup' { [void](Invoke-EpsArm -Method PUT -Path $rg -ApiVersion $script:EpsApi.rg -Body @{ location = $Ctx.Location; tags = $tags }) }
        'identities' {
            foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') {
                $m = Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n[$k])" -ApiVersion $script:EpsApi.mi -Body @{ location = $Ctx.Location; tags = $tags }
                $Ctx.Identities[$k] = @{ Id = $m.id; ClientId = $m.properties.clientId; PrincipalId = $m.properties.principalId }
            }
        }
        'logs' { [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.OperationalInsights/workspaces/$($n.Logs)" -ApiVersion $script:EpsApi.law -Body @{ location = $Ctx.Location; tags = $tags; properties = @{ sku = @{ name = 'PerGB2018' }; retentionInDays = 30 } }) }
        'registry' {
            & $loadMi
            $acr = Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ApiVersion $script:EpsApi.acr -Body @{ location = $Ctx.Location; tags = $tags; sku = @{ name = 'Basic' }; properties = @{ adminUserEnabled = $false } }
            foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') { Add-EpsRoleAssignment -Scope $acr.id -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.AcrPull)" -PrincipalId $Ctx.Identities[$k].PrincipalId }
        }
        'image' {
            $ctxFile = New-EpsBuildContext -SolutionRoot $Ctx.SolutionRoot
            try {
                $b = Invoke-EpsAcrBuild -RegistryId "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ContextPath $ctxFile -DockerFile 'SOLUTIONS/EntraPolicySuite/tools/eps-engine/Dockerfile' -ImageName "$($n.Image):$($Ctx.Version)" -BuildArgs @{ EPS_CONTENT_HASH = $Ctx.Version } -PollSeconds ($Ctx.PollSeconds ?? 10)
                $Ctx.ImageDigest = $b.Digest
            } finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        }
        'sql' {
            $srv = "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)"
            # -SqlLocation: Azure SQL may refuse new servers in a region (North Europe, 2026-10-30) while the rest is fine there
            $sqlLoc = if ($Ctx.SqlLocation) { $Ctx.SqlLocation } else { $Ctx.Location }
            # the SQL server's Entra admin (framework §12.23 P5, owner 2026-11-01): an EXISTING server keeps the admin it has
            # (a re-run never takes the customer's admin group away - internal: the group 'EntraPolicySuite SQL admins');
            # a NEW server gets the customer's group (-SqlAdminGroupId) or else whoever installs: a person (sid = object
            # id) or, through the Invardia Support app, an application (sid = its client id)
            $old = Invoke-EpsArm -Path $srv -ApiVersion $script:EpsApi.sql -AllowNotFound
            $admin = if ($old -and $old.properties.administrators -and $old.properties.administrators.sid) {
                $a = $old.properties.administrators
                $k = @{ administratorType = 'ActiveDirectory'; azureADOnlyAuthentication = $true; login = $a.login; sid = $a.sid; tenantId = $a.tenantId }
                if ("$($a.principalType)") { $k.principalType = "$($a.principalType)" }   # older servers report none (live 2026-11-01)
                $k
            } elseif ($Ctx.SqlAdminGroup) {
                @{ administratorType = 'ActiveDirectory'; azureADOnlyAuthentication = $true; principalType = 'Group'; login = $Ctx.SqlAdminGroup.Name; sid = $Ctx.SqlAdminGroup.ObjectId; tenantId = $Ctx.TenantId }
            } else {
                @{ administratorType = 'ActiveDirectory'; azureADOnlyAuthentication = $true; principalType = $(if ($Ctx.Person.PrincipalType) { $Ctx.Person.PrincipalType } else { 'User' })
                   login = $Ctx.Person.Upn; sid = $(if ($Ctx.Person.Sid) { $Ctx.Person.Sid } else { $Ctx.Person.ObjectId }); tenantId = $Ctx.TenantId }
            }
            [void](Invoke-EpsArm -Method PUT -Path $srv -ApiVersion $script:EpsApi.sql -Body @{ location = $(if ($old) { $old.location } else { $sqlLoc }); tags = $tags; properties = @{ minimalTlsVersion = '1.2'; publicNetworkAccess = 'Enabled'; administrators = $admin } })
            # the jobs reach SQL from Azure (external exposure, DESIGN §2); the internal exposure (private endpoints) is a later slice
            [void](Invoke-EpsArm -Method PUT -Path "$srv/firewallRules/AllowAllWindowsAzureIps" -ApiVersion $script:EpsApi.sql -Body @{ properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } })
            [void](Invoke-EpsArm -Method PUT -Path "$srv/databases/$($n.Database)" -ApiVersion $script:EpsApi.sql -Body @{ location = $sqlLoc; tags = $tags; sku = @{ name = 'S0'; tier = 'Standard' } })
        }
        'sqlaccess' {
            & $loadMi
            # the roles first (a member needs its role), each user in its own role only
            $gl = Get-EpsGrantList -SolutionRoot $Ctx.SolutionRoot
            $roleOf = @{}; foreach ($r in $gl.roles.Keys) { $roleOf[$gl.roles[$r].identity] = $r }
            Invoke-EpsSetupSql -Ctx $Ctx -Script ((@(Get-EpsGrantScript -GrantList $gl) + @(foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') { Get-EpsSqlUserScript -Name $n[$k] -ClientId $Ctx.Identities[$k].ClientId -Role $roleOf[$k] })) -join "`n")
        }
        'schema' { Invoke-EpsSetupSql -Ctx $Ctx -Schema }
        'environment' {
            $law = Invoke-EpsArm -Path "$rg/providers/Microsoft.OperationalInsights/workspaces/$($n.Logs)" -ApiVersion $script:EpsApi.law
            $key = (Invoke-EpsArm -Method POST -Path "$($law.id)/sharedKeys" -ApiVersion $script:EpsApi.law -Body @{}).primarySharedKey
            [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" -ApiVersion $script:EpsApi.aca -Body @{ location = $Ctx.Location; tags = $tags
                properties = @{ workloadProfiles = @(@{ name = 'Consumption'; workloadProfileType = 'Consumption' })
                    appLogsConfiguration = @{ destination = 'log-analytics'; logAnalyticsConfiguration = @{ customerId = $law.properties.customerId; sharedKey = $key } } } })
        }
        'queues' {
            # SEC-AUDIT-1 S4 (2.0.9): one queue per work job in the install's own storage account - no shared key (Entra
            # only), TLS 1.2, no public blob. The tick: Message Sender on each queue (it cannot read, delete or start
            # anything); the engine: Message Processor on each queue (read + delete; KEDA counts with it).
            & $loadMi
            $st = "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)"
            [void](Invoke-EpsArm -Method PUT -Path $st -ApiVersion $script:EpsApi.st -Body @{ location = $Ctx.Location; tags = $tags; kind = 'StorageV2'; sku = @{ name = 'Standard_LRS' }
                properties = @{ allowSharedKeyAccess = $false; minimumTlsVersion = 'TLS1_2'; allowBlobPublicAccess = $false; supportsHttpsTrafficOnly = $true; defaultToOAuthAuthentication = $true } })
            $sw = [Diagnostics.Stopwatch]::StartNew()
            do { $sa = Invoke-EpsArm -Path $st -ApiVersion $script:EpsApi.st; if ("$($sa.properties.provisioningState)" -eq 'Succeeded') { break }; Start-Sleep -Seconds ($Ctx.PollSeconds ?? 5) } while ($sw.Elapsed.TotalSeconds -lt 300)
            if ($sa.properties.allowSharedKeyAccess -ne $false) { throw "the storage account $($n.Storage) allows shared keys - refused (Entra only)" }
            foreach ($d in Get-EpsDefaultJobSchedule | Where-Object Implemented) {
                $qp = "$st/queueServices/default/queues/$(Get-EpsJobQueueName $d.AcaJobName)"
                [void](Invoke-EpsArm -Method PUT -Path $qp -ApiVersion $script:EpsApi.st -Body @{ properties = @{} })
                Add-EpsRoleAssignment -Scope $qp -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.QueueSender)" -PrincipalId $Ctx.Identities.TickIdentity.PrincipalId
                Add-EpsRoleAssignment -Scope $qp -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.QueueProcessor)" -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId
                Add-EpsRoleAssignment -Scope $qp -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.QueueReader)" -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId
            }
        }
        'jobs' {
            & $loadMi
            # the web registration's client id (the engine's signed-request pin) - read back, never remembered in the journal
            if (-not $Ctx.Web) { $Ctx.Web = @{} }
            if (-not $Ctx.Web.ClientId) {
                $a = Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)"
                if (-not $a -or "$($a.appId)" -notmatch '^[0-9a-fA-F-]{36}$') { throw 'the web sign-in registration is missing - the engine jobs need its client id (run the webregistration step first)' }
                $Ctx.Web.ClientId = [string]$a.appId
            }
            $image = "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)"
            # the web app's address (alert links, UPLINK-1): its name in the environment's default domain - known before the app exists
            if (-not $Ctx.WebUrl) { $ce = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" -ApiVersion $script:EpsApi.aca -AllowNotFound; if ("$($ce.properties.defaultDomain)" -match '^[A-Za-z0-9.-]+$') { $Ctx.WebUrl = "https://$($n.WebApp).$($ce.properties.defaultDomain)/".ToLowerInvariant() } }
            # the jobs on 2025-01-01: the first version that takes an identity on a scale rule (2.0.9, S4)
            foreach ($j in Get-EpsJobBodies -Ctx $Ctx -Image $image) { [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -ApiVersion $script:EpsApi.acajob -Body $j.Body) }
        }
        'jobstarter' {
            # 2.0.10 (SEC-AUDIT-1 S4): the tick holds NO right to start jobs - the start API takes a container override,
            # so that right let the tick identity run any command as the engine (proven live 2026-11-01). The jobs start
            # from their own queues since 2.0.9 (proven live the same day); the old custom role is removed here: its
            # assignments first, then the definition. Read back: the tick holds nothing on the resource group.
            & $loadMi
            $defName = Get-EpsGuidFrom "$rg|eps-job-starter"
            $tick = $Ctx.Identities.TickIdentity.PrincipalId
            $all = @((Invoke-EpsArm -Path "$rg/providers/Microsoft.Authorization/roleAssignments" -ApiVersion $script:EpsApi.rbac).value)
            foreach ($a in $all | Where-Object { "$($_.properties.roleDefinitionId)" -like "*/roleDefinitions/$defName" }) { [void](Invoke-EpsArm -Method DELETE -Path $a.id -ApiVersion $script:EpsApi.rbac -AllowNotFound) }
            [void](Invoke-EpsArm -Method DELETE -Path "$rg/providers/Microsoft.Authorization/roleDefinitions/$defName" -ApiVersion $script:EpsApi.rbac -AllowNotFound)
            $left = @((Invoke-EpsArm -Path "$rg/providers/Microsoft.Authorization/roleAssignments" -ApiVersion $script:EpsApi.rbac).value | Where-Object { $_.properties.principalId -eq $tick -and "$($_.properties.scope)" -eq $rg })
            if ($left.Count) { throw "the tick still holds $($left.Count) role assignment(s) on $($n.ResourceGroup) - it must hold none (S4)" }
        }
        'graph'    { & $loadMi; [void](Grant-EpsAppRoles -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId -ResourceAppId '00000003-0000-0000-c000-000000000000' -Roles (Get-EpsEngineGraphRoles -Ctx $Ctx)) }
        'exchange' {
            & $loadMi
            [void](Grant-EpsAppRoles -PrincipalId $Ctx.Identities.EngineIdentity.PrincipalId -ResourceAppId $script:EpsExchangeAppId -Roles @('Exchange.ManageAsApp'))
            $p = $Ctx.Identities.EngineIdentity.PrincipalId
            $have = @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$p' and roleDefinitionId eq '$($script:EpsExchangeRecipientAdminRole)'" -All)
            if (-not $have.Count) { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/roleManagement/directory/roleAssignments' -Body @{ principalId = $p; roleDefinitionId = $script:EpsExchangeRecipientAdminRole; directoryScopeId = '/' }) }
        }
        'webregistration' { & $loadMi; Invoke-EpsWebRegistrationStep -Ctx $Ctx }
        'keyvault' { & $loadMi; & $loadWeb; Invoke-EpsKeyVaultStep -Ctx $Ctx; $Ctx.UplinkKey = Grant-EpsUplinkKeyAccess -Ctx $Ctx }
        'webstate' {
            $sqlText = Get-EpsSigninStateSql -WebUser $n.WebIdentity
            if ("$($Ctx.Person.PrincipalType)" -in '', 'User' -and $Ctx.Person.ObjectId) { $sqlText += "`n" + (Get-EpsFirstSuperAdminSql -Upn $Ctx.Person.Upn -ObjectId $Ctx.Person.ObjectId) }
            Invoke-EpsSetupSql -Ctx $Ctx -Script $sqlText
        }
        'frontimage' {
            $pin = Get-EpsSigninFrontPin -SolutionRoot $Ctx.SolutionRoot
            $s = Get-EpsSigninFrontSource -SolutionRoot $Ctx.SolutionRoot -Pin $pin -Root $Ctx.SigninFrontRoot
            if (-not $s.Ok) { throw $s.Reason }
            $ctxFile = New-EpsFrontBuildContext -Src $s.Src
            try { [void](Invoke-EpsAcrBuild -RegistryId "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ContextPath $ctxFile -DockerFile 'Dockerfile' -ImageName "signin-front:$pin" -PollSeconds ($Ctx.PollSeconds ?? 10)) }
            finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        }
        'webapp' { & $loadMi; & $loadWeb; Invoke-EpsWebAppStep -Ctx $Ctx }
        'verify' {
            $r = Confirm-EpsInstall -Ctx $Ctx -PollSeconds ($Ctx.PollSeconds ?? 15)
            # a tick that ran and FAILED is a failed install (2.0.7 live 2026-11-01: reported 'ok' with the tick failing)
            if ($r.Tick -ne 'Succeeded') { throw "the tick ($($r.Execution)) ran and ended '$($r.Tick)' - see its log in $($Ctx.Names.Logs); fix the cause and run the install again" }
            & $loadWeb
            $w = Test-EpsWebAppAnswers -Fqdn $Ctx.Web.Fqdn -PollSeconds ($Ctx.PollSeconds ?? 10)
            if (-not $w.Ok) { throw $w.Reason }
            $r.Web = $Ctx.Web.Url; $r
        }
        default { throw "unknown install step '$Id'" }
    }
}

function Invoke-EpsSetupSql {
    # SQL as the signed-in person (the server's Entra admin). On a public server a temporary firewall rule for this
    # machine is opened when the first login is refused with its address, and closed again on every way out.
    param([Parameter(Mandatory)]$Ctx, [string]$Script, [switch]$Schema, [switch]$Rows)
    $n = $Ctx.Names
    $cs = "Server=tcp:$($n.SqlServer).database.windows.net,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    # $global:EPS_SetupSqlOverride = { param($Ctx, $Script, $Schema) }: who runs the SQL - a test, or the Invardia Support
    # app's audited Invoke-InvardiaSupportSql. The firewall rule and the retries below apply to it as well.
    # -Rows: a query whose rows come back (the Azure Monitor deploy reads the product's settings)
    $run = if ($global:EPS_SetupSqlOverride) { { $o = & $global:EPS_SetupSqlOverride $Ctx $Script ([bool]$Schema); if ($Rows) { $o } } } else {
        {
            $global:EPS_SqlAccessToken = & $global:EPS_TokenProvider 'https://database.windows.net'
            if ($Schema) { [void](Install-EpsSchema -ConnectionString $cs -SchemaPath (Join-Path $Ctx.SolutionRoot 'sql\eps-schema.sql')) }
            elseif ($Rows) { Invoke-EpsSql -ConnectionString $cs -Query $Script }
            else { [void](Invoke-EpsSql -ConnectionString $cs -NonQuery -Query $Script) }
        }
    }
    $rule = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Sql/servers/$($n.SqlServer)/firewallRules/AllowSetupHost"
    $opened = $false
    try {
        for ($try = 0; $try -lt 8; $try++) {
            try {
                & $run
                return
            } catch {
                $m = "$($_.Exception.Message)"
                if (-not $opened -and $m -match "Client with IP address '([0-9a-fA-F.:]+)' is not allowed") {
                    [void](Invoke-EpsArm -Method PUT -Path $rule -ApiVersion $script:EpsApi.sql -Body @{ properties = @{ startIpAddress = $Matches[1]; endIpAddress = $Matches[1] } })
                    $opened = $true; Start-Sleep -Seconds ($Ctx.SqlRetrySeconds ?? 15); continue
                }
                # a new server admin, a new firewall rule: both take a little while to apply
                if ($m -match '(?i)Login failed|18456|not allowed to access the server|40615') { Start-Sleep -Seconds ($Ctx.SqlRetrySeconds ?? 20); continue }
                throw
            }
        }
        throw 'SQL could not be reached as the signed-in admin after 8 tries'
    } finally {
        if ($opened) { try { [void](Invoke-EpsArm -Method DELETE -Path $rule -ApiVersion $script:EpsApi.sql) } catch { Write-Warning "close the firewall rule AllowSetupHost on $($n.SqlServer) by hand: $($_.Exception.Message)" } }
        $global:EPS_SqlAccessToken = $null
    }
}

function Confirm-EpsInstall {
    # Read back what the install made, then run the tick once and wait for its run record - the whole chain (image,
    # identity, registry pull, SQL login, the scheduler) proven by one tick.
    param([Parameter(Mandatory)]$Ctx, [int]$TickWaitSeconds = 600, [int]$PollSeconds = 15)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    foreach ($j in Get-EpsJobBodies -Ctx $Ctx -Image 'x') {
        $r = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -ApiVersion $script:EpsApi.aca -AllowNotFound
        if (-not $r -or $r.properties.provisioningState -ne 'Succeeded') { throw "job $($j.Name) is not provisioned ($($r.properties.provisioningState))" }
    }
    $since = [datetime]::UtcNow
    $s = Start-EpsAcaJob -SubscriptionId $Ctx.SubscriptionId -ResourceGroup $n.ResourceGroup -Name $n.TickJob
    if (-not $s.Ok) { throw "the tick could not be started: $($s.Reason)" }
    $cs = "Server=tcp:$($n.SqlServer).database.windows.net,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TickWaitSeconds) {
        Start-Sleep -Seconds $PollSeconds
        $q = "SELECT TOP 1 Status FROM eps.Run WHERE Job = 'Tick' AND StartedAtUtc >= @t ORDER BY StartedAtUtc DESC"
        if ($global:EPS_SetupSqlOverride) { $st = & $global:EPS_SetupSqlOverride $Ctx $q $false }   # test seam
        else {
            $global:EPS_SqlAccessToken = & $global:EPS_TokenProvider 'https://database.windows.net'
            try { $st = Invoke-EpsSql -ConnectionString $cs -Scalar -Parameters @{ t = $since.AddMinutes(-1) } -Query $q } catch { $st = $null } finally { $global:EPS_SqlAccessToken = $null }
        }
        if ($st -and $st -ne 'Running') { return @{ Tick = $st; Execution = $s.Execution; Seconds = [math]::Round($sw.Elapsed.TotalSeconds) } }
    }
    throw "the tick ($($s.Execution)) wrote no finished run record within $TickWaitSeconds s - see its log in $($n.Logs)"
}

function Invoke-EpsInstall {
    <#
    .SYNOPSIS
        Runs the install's steps in order. -WhatIf: only the read-only checks, printed as a plan. -Completed: steps a
        previous run finished (the journal) are skipped. -OnStep { param($Event) } sees every step's start / end.
        Returns the list of finished step ids; a failing step throws after reporting itself (the journal keeps the rest).
    #>
    param([Parameter(Mandatory)]$Ctx, [switch]$WhatIf, [string[]]$Completed = @(), [scriptblock]$OnStep = { param($e) })
    $done = [System.Collections.Generic.List[string]]::new(); foreach ($c in $Completed) { $done.Add($c) }
    foreach ($s in Get-EpsInstallSteps) {
        if ($done.Contains($s.Id)) { & $OnStep @{ Step = $s; State = 'skipped'; Message = 'already done (resume)' }; continue }
        $t = Test-EpsInstallStep -Id $s.Id -Ctx $Ctx
        if ($WhatIf) { & $OnStep @{ Step = $s; State = 'plan'; Message = "$($t.Action): $($t.Detail)" }; continue }
        & $OnStep @{ Step = $s; State = 'running'; Message = "$($t.Action): $($t.Detail)" }
        try { $out = Invoke-EpsInstallStep -Id $s.Id -Ctx $Ctx }
        catch { & $OnStep @{ Step = $s; State = 'failed'; Message = "$($_.Exception.Message)" }; throw }
        $done.Add($s.Id)
        & $OnStep @{ Step = $s; State = 'ok'; Message = $(if ($out -is [hashtable] -and $out.Tick) { "tick $($out.Tick) after $($out.Seconds) s$(if ($out.Web) { "; the web app answers at $($out.Web)" })" } else { 'done' }); Completed = @($done) }
    }
    @($done)
}
