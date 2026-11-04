# EntraPolicySuite -- the install's steps (DESIGN §2): everything in the customer's own subscription, created over REST
# as the signed-in person (EPS-SignIn), no module, no az CLI. PIM's model (PIM-DeployAll.ps1): the step catalog is
# DATA; each step has a read-only CHECK (what exists) and an idempotent DO; -WhatIf runs the checks and stops; the
# journal (state.json) lets a failed install resume where it stopped.
# Dot-source EPS-SqlStore, EPS-Graph, EPS-Arm, EPS-Scheduler first.

Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'EPS-InstallWeb.ps1')   # the web app's steps (the sign-in front)
. (Join-Path $PSScriptRoot 'EPS-InstallNetwork.ps1')   # the private network install (NET-1) - used only with -PrivateNetwork
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
$script:EpsEngineGraphRoles = @('User.ReadWrite.All', 'Device.ReadWrite.All', 'GroupMember.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'DeviceManagementManagedDevices.Read.All', 'Application.Read.All', 'Policy.ReadWrite.ConditionalAccess')   # Policy.ReadWrite.ConditionalAccess: CA-LIFECYCLE, the stage buttons - a SuperAdmin moves ONE adopted policy ONE stage, applied by the engine from his request; nothing else writes a policy (owner 2026-11-03: 'Write on approval')   # Application.Read.All: application names in the CA documentation, READ ONLY (owner 2026-11-01: "Grant Application.Read.All")   # Policy + RoleManagement: the CA Policy Analyzer, READ ONLY (it never writes a policy); DeviceManagementManagedDevices: the identity report's Intune devices, read only (owner 2026-10-31: "Yes, add both")   # AuditLog: the tamper monitor's "who"
function Get-EpsEngineGraphRoles {
    # the engine's Graph roles minus any the approver left out (-ExcludeGraphRole): a role not approved is never granted;
    # the feature that needs it reports its data as unavailable (e.g. Teams_Room_Like without Organization.Read.All)
    param($Ctx) @($script:EpsEngineGraphRoles | Where-Object { @($Ctx.ExcludeGraphRoles) -notcontains $_ })
}
$script:EpsExchangeAppId = '00000002-0000-0ff1-ce00-000000000000'      # Office 365 Exchange Online
$script:EpsExchangeRecipientAdminRole = '31392ffb-586c-42d1-9346-e59415a2cc4e'   # Entra role template: Exchange Recipient Administrator

# Installer rule 9 (framework §0; EPS's live private proof 2026-11-03: westeurope, the default, refused every new resource
# in a test subscription - RequestDisallowedByAzure "The selected region is currently not accepting new customers"): the
# preflight asks ARM to VALIDATE one small resource in the chosen region - nothing is created. The regions offered instead.
$script:EpsRegionAlternatives = @('northeurope', 'swedencentral', 'westeurope', 'germanywestcentral', 'francecentral', 'uksouth', 'norwayeast')

function Get-EpsRegionCheckTemplate {
    # PURE. The template the region check validates (Invardia's spec, proven live by PIM 2026-11-03): one minimal resource
    # per service EntraPolicySuite creates, each in the region (SQL in -SqlLocation when given). Names are throwaway.
    param([Parameter(Mandatory)][string]$Location, [string]$SqlLocation, [string]$TenantId = '00000000-0000-0000-0000-000000000000')
    $x = ([guid]::NewGuid().ToString('N')).Substring(0, 8)
    @{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'; contentVersion = '1.0.0.0'; resources = @(
        @{ type = 'Microsoft.ManagedIdentity/userAssignedIdentities'; apiVersion = '2023-01-31'; name = "id-eps-rc-$x"; location = $Location }
        # the SAME settings the install's real storage account gets (2.0.39 live: a customer policy 'Storage Account to use the latest
        # TLS version' refused the bare one, so the check said nothing) - a policy that the real one passes passes the check too
        @{ type = 'Microsoft.Storage/storageAccounts'; apiVersion = '2023-01-01'; name = "stepsrc$x"; location = $Location; kind = 'StorageV2'; sku = @{ name = 'Standard_LRS' }
           properties = @{ allowSharedKeyAccess = $false; minimumTlsVersion = 'TLS1_2'; allowBlobPublicAccess = $false; supportsHttpsTrafficOnly = $true; defaultToOAuthAuthentication = $true } }
        @{ type = 'Microsoft.App/managedEnvironments'; apiVersion = '2024-03-01'; name = "cae-eps-rc-$x"; location = $Location; properties = @{} }
        @{ type = 'Microsoft.ContainerRegistry/registries'; apiVersion = '2023-07-01'; name = "acrepsrc$x"; location = $Location; sku = @{ name = 'Basic' }; properties = @{} }
        @{ type = 'Microsoft.Sql/servers'; apiVersion = '2023-08-01-preview'; name = "sql-eps-rc-$x"; location = $(if ($SqlLocation) { $SqlLocation } else { $Location })
           properties = @{ minimalTlsVersion = '1.2'; administrators = @{ administratorType = 'ActiveDirectory'; azureADOnlyAuthentication = $true; principalType = 'Group'; login = 'eps-region-check'; sid = '00000000-0000-0000-0000-000000000001'; tenantId = $TenantId } } }) }
}

function Test-EpsRegionAccepts {
    <#
      Installer rule 9: does -Location accept new resources in this subscription? ARM's deployment VALIDATE - nothing is
      made: with the resource group there, the services' minimal resources in it (Get-EpsRegionCheckTemplate); else the
      resource group itself at subscription scope. Refused = RequestDisallowedByAzure in error.code or ANY details[].code
      (Azure nests it - read the raw answer, not Invoke-EpsArm's one-line error).
      Returns @{ Accepts = $true | $false | $null (not known - never a stop); Reason }. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Location, [string]$SqlLocation, [string]$TenantId, [switch]$ResourceGroupExists)
    $name = "eps-region-check-$(([guid]::NewGuid().ToString('N')).Substring(0, 6))"
    if ($ResourceGroupExists) {
        $path = "subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.Resources/deployments/$name/validate"
        $body = @{ properties = @{ mode = 'Incremental'; template = (Get-EpsRegionCheckTemplate -Location $Location -SqlLocation $SqlLocation -TenantId $(if ($TenantId) { $TenantId } else { '00000000-0000-0000-0000-000000000000' })) } }
    } else {
        $path = "subscriptions/$SubscriptionId/providers/Microsoft.Resources/deployments/$name/validate"
        # RULE9-NEW-RG (the NET-1 re-run 2026-11-03; framework rule 9 corrected): a resource group ALONE validates 200 even in a
        # refused region - Azure refuses per RESOURCE. So the subscription-scope template carries the resource group AND a
        # nested deployment into it holding the services' minimal resources (SI's form, proven live the same day).
        $inner = Get-EpsRegionCheckTemplate -Location $Location -SqlLocation $SqlLocation -TenantId $(if ($TenantId) { $TenantId } else { '00000000-0000-0000-0000-000000000000' })
        $body = @{ location = $Location; properties = @{ mode = 'Incremental'; template = @{ '$schema' = 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'; contentVersion = '1.0.0.0'
            resources = @(
                @{ type = 'Microsoft.Resources/resourceGroups'; apiVersion = '2021-04-01'; name = $ResourceGroup; location = $Location }
                @{ type = 'Microsoft.Resources/deployments'; apiVersion = '2021-04-01'; name = 'eps-region-check-services'; resourceGroup = $ResourceGroup
                   dependsOn = @("[resourceId('Microsoft.Resources/resourceGroups', '$ResourceGroup')]"); properties = @{ mode = 'Incremental'; template = $inner } }) } } }
    }
    try {
        $r = & $script:EpsHttp 'POST' "$script:EpsArmRoot/$path`?api-version=2021-04-01" @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" } ($body | ConvertTo-Json -Depth 30 -Compress)
    } catch { return @{ Accepts = $null; Reason = "not checked: $($_.Exception.Message)" } }
    if ([int]$r.Status -ge 200 -and [int]$r.Status -lt 300) { return @{ Accepts = $true; Reason = 'validated' } }
    $err = try { ("$($r.Body)" | ConvertFrom-Json).error } catch { $null }
    $codes = [System.Collections.Generic.List[string]]::new(); $msgs = [System.Collections.Generic.List[string]]::new()
    $policies = [System.Collections.Generic.List[string]]::new()
    $walk = { param($x) if (-not $x) { return }; if ($x.code) { $codes.Add("$($x.code)") }; if ($x.message) { $msgs.Add("$($x.message)") }
        foreach ($ai in @($x.additionalInfo)) { $n = "$($ai.info.policyAssignmentDisplayName)"; if (-not $n) { $n = "$($ai.info.policyAssignmentName)" }; if ($n -and -not $policies.Contains($n)) { $policies.Add($n) } }
        foreach ($d in @($x.details)) { & $walk $d } }
    & $walk $err
    if ($codes -contains 'RequestDisallowedByAzure' -or (@($msgs) -join ' ') -match '(?i)not accepting new customers') {
        return @{ Accepts = $false; Reason = "$(@($msgs | Where-Object { $_ -match '(?i)not accepting|disallowed' })[0])" }
    }
    # REGION-CHECK-POLICY (the 2.0.38 internal deploy): an Azure Policy refused the check's throwaway resources - said in
    # plain words, the policy named when Azure names it. Never a stop: the real resources may comply where these did not.
    if ($codes -contains 'RequestDisallowedByPolicy' -or (@($msgs) -join ' ') -match '(?i)policy violation') {
        return @{ Accepts = $null; Reason = "not checked: an Azure Policy in your subscription refuses the check's test resources$(if ($policies.Count) { " ($($policies -join ', '))" })" }
    }
    @{ Accepts = $null; Reason = "not checked: HTTP $($r.Status) $(@($codes)[0]) $(@($msgs)[0])".Trim() }
}
$script:EpsDefaultResourceGroup = 'rg-eps'                    # framework §5.5 (owner 2026-11-04, OPEN-30): new installs
$script:EpsLegacyResourceGroup = 'rg-entrapolicysuite'        # installs made before 2.0.55 - they keep it

function Get-EpsInstallId {
    # PURE. The install id (framework §5.5, PIM's Get-PimInstallDerivedId): 'eps-' + 12 hex characters of the SHA-256 of
    # tenant | subscription | resource group (lower case). The same answers give the same id - a re-run and a resume find
    # the same names; another resource group gives another id.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(("{0}|{1}|{2}" -f "$TenantId".Trim(), "$SubscriptionId".Trim(), "$ResourceGroup".Trim()).ToLowerInvariant()))
    'eps-' + (-join ($h[0..5] | ForEach-Object { $_.ToString('x2') }))
}

function Get-EpsInstallToken {
    # PURE. The name token of globally unique names (framework §5.5, PIM's Get-PimInstallToken): 6 hex characters of the
    # SHA-256 of the install id.
    param([Parameter(Mandatory)][string]$InstallId)
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$InstallId".Trim().ToLowerInvariant()))
    -join ($h[0..2] | ForEach-Object { $_.ToString('x2') })
}

function Get-EpsLegacySuffix {
    # PURE. The suffix of an install made before 2.0.55: 8 hex characters of the SHA-256 of subscription | resource group
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$SubscriptionId|$ResourceGroup".ToLowerInvariant()))
    -join ($h[0..3] | ForEach-Object { $_.ToString('x2') })
}

function Resolve-EpsInstallNames {
    <#
      The names of THIS install, read from Azure: an install made before 2.0.55 (its registry acreps<8 hex> is in the
      resource group) keeps every name it has (Azure cannot rename; owner 2026-11-04 "it is too late now for existing
      instal"); anything else gets the framework §5.5 names. Reads only.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [switch]$Private)
    $old = "acreps$(Get-EpsLegacySuffix -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup)"
    $legacy = [bool](Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ContainerRegistry/registries/$old" -ApiVersion '2023-07-01' -AllowNotFound)
    Get-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Private:$Private -Legacy:$legacy
}

function Resolve-EpsResourceGroup {
    <#
      The resource group when -ResourceGroup was not given: rg-eps for a new install (framework §5.5); an existing install
      in the old default rg-entrapolicysuite keeps it (a re-run never starts a second install next to it). Both there =
      ambiguous, refused. @{ Ok; Name; Reason }. Reads only; a resource group that cannot be read counts as not there.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId)
    $has = { param($n) try { [bool](Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$n" -ApiVersion '2021-04-01' -AllowNotFound) } catch { $false } }
    $new = & $has $script:EpsDefaultResourceGroup; $old = & $has $script:EpsLegacyResourceGroup
    if ($new -and $old) { return @{ Ok = $false; Reason = "both $($script:EpsDefaultResourceGroup) and $($script:EpsLegacyResourceGroup) exist in this subscription - say which install with -ResourceGroup" } }
    if ($old) { return @{ Ok = $true; Name = $script:EpsLegacyResourceGroup; Reason = "the existing install in $($script:EpsLegacyResourceGroup) keeps its resource group and names" } }
    @{ Ok = $true; Name = $script:EpsDefaultResourceGroup; Reason = '' }
}

function Get-EpsInstallNames {
    # One place for every name (framework §5.5, owner 2026-11-04 "love the pim method", OPEN-30): <type>-eps[-<purpose>];
    # globally unique names (registry, SQL server, storage, Key Vault) add the install's token - 6 hex characters of the
    # SHA-256 of the install id (Get-EpsInstallToken) - stable across re-runs and resumes. -Legacy: an install made before
    # 2.0.55 keeps its 8-hex suffix of subscription + resource group (Resolve-EpsInstallNames decides from Azure).
    # -Private (NET-1): the environment inside the network is cae-eps-vnet - a Container Apps environment cannot move
    # into a network, so a public install converted to private gets a NEW one (the public cae-eps is removed after the
    # inside check), and a new private install uses the same name, so both read the same afterwards.
    param([string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [switch]$Private, [switch]$Legacy)
    if ($Legacy) { $s = Get-EpsLegacySuffix -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup; $iid = '' }
    else {
        if (-not "$TenantId".Trim()) { throw 'Get-EpsInstallNames: -TenantId is needed for the names of a new install (or -Legacy for one made before 2.0.55)' }
        $iid = Get-EpsInstallId -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup; $s = Get-EpsInstallToken -InstallId $iid
    }
    [ordered]@{
        ResourceGroup = $ResourceGroup; Suffix = $s; InstallId = $iid; Legacy = [bool]$Legacy
        EngineIdentity = 'id-eps-engine'; WebIdentity = 'id-eps-web'
        # framework §5.5 (owner 2026-11-04 "do it the same way as pim"): the scheduler IS the engine - caj-eps-engine signs in
        # as id-eps-engine (PIM: one job, the engine's identity). An install made before 2.0.55 keeps id-eps-tick until the
        # identity move. The tick's SQL role (eps_tick) and its queue Sender role then go to the engine identity.
        TickIdentity = $(if ($Legacy) { 'id-eps-tick' } else { 'id-eps-engine' })
        Logs = 'log-eps'; Registry = "acreps$s"; Image = 'eps-engine'
        SqlServer = "sql-eps-$s"; Database = 'eps'
        Environment = $(if ($Private) { 'cae-eps-vnet' } else { 'cae-eps' }); PublicEnvironment = 'cae-eps'; Storage = "steps$s"
        # framework §5.5 THE AGREED LIST: the scheduler job is caj-eps-engine, the update job caj-eps-updater (an install made
        # before 2.0.55 keeps caj-eps-tick / caj-eps-update - Azure cannot rename a job)
        TickJob = $(if ($Legacy) { 'caj-eps-tick' } else { 'caj-eps-engine' }); UpdateJob = $(if ($Legacy) { 'caj-eps-update' } else { 'caj-eps-updater' })
        AgentPool = 'epspool'; InsideCheckJob = 'caj-eps-insidecheck'
        JobStarterRole = "EntraPolicySuite job starter ($ResourceGroup)"
        WebApp = 'ca-eps-web'; KeyVault = "kv-eps-$s"
        # IDENTITY names follow the standard (framework §12.11c, owner 2026-11-04 "all identity names must be renamed to align
        # to standard - we can not have different names except for azure resources"): a re-run renames an older one in place
        WebAppRegistration = 'Entra Policy Suite'; LegacyWebAppRegistration = "EntraPolicySuite ($ResourceGroup)"
        SqlAdminGroup = 'grp-eps-sql-admins'; LegacySqlAdminGroup = 'EntraPolicySuite SQL admins'
    }
}

function Get-EpsAcaJobResourceName {
    # PURE. A work job's Azure resource name from its KEY (the schedule's AcaJobName): the update job is named per install
    # (Names.UpdateJob), every other work job is its key.
    param([Parameter(Mandatory)]$Names, [Parameter(Mandatory)][string]$Key)
    if ($Key -eq 'caj-eps-update' -and $Names.UpdateJob) { return $Names.UpdateJob }
    $Key
}

function Get-EpsInstallSteps {
    # The order is load-bearing: identities before the registry (AcrPull), the registry before the image, the image and
    # SQL before the jobs (a job pins its image; its env names the database), the jobs before their role assignments.
    # -Private: the private network install's own order (Get-EpsPrivateInstallSteps); the public order is unchanged.
    param([switch]$Private)
    if ($Private) { return (Get-EpsPrivateInstallSteps) }
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

function Get-EpsPrivateInstallSteps {
    <#
      The PRIVATE order (NET-1, DESIGN §2b) - load-bearing, each line for a reason:
      - the network right after the resource group (every endpoint and the environment need its subnets), then the
        privatelink zones (an endpoint's record is written into its zone);
      - each data resource is CREATED with public access off and gets its private endpoint + zone record IMMEDIATELY
        after it (registry, SQL, queues, Key Vault) - nothing data-side is reachable from the internet, not even during
        the install (customer policy may refuse a public Key Vault);
      - the web registration before the Key Vault (the vault step reads its facts); the environment (internal, in the
        apps subnet) and its own zone; the optional hub peering / zone links; then the hand-off list;
      - the DNS check from THIS machine before ANY data-plane read or write (the image upload, SQL) - it stops (exit 1,
        resumable) with the exact A records when a name does not resolve privately;
      - the registry's build pool inside the network before the image (ACR Tasks cannot reach a closed registry from
        outside); then the same image, SQL, jobs, grants and web app steps as the public install;
      - verify (the tick), then the INSIDE CHECK gates success; only then is the old public environment of a converted
        install removed, and LAST public access is read back as Disabled (lockdown) - never before the inside check.
    #>
    $t = @{}; foreach ($s in Get-EpsInstallSteps) { $t[$s.Id] = $s.Title }
    $mk = { param($id, $title) [pscustomobject]@{ Id = $id; Title = $(if ($title) { $title } else { $t[$id] }) } }
    @(
        & $mk 'resourcegroup'
        & $mk 'network'          'Network: the spoke, the apps subnet (Container Apps) and the endpoints subnet'
        & $mk 'dnszones'         'Private DNS zones (SQL, Key Vault, queues, registry), linked to the spoke'
        & $mk 'identities'
        & $mk 'logs'
        & $mk 'registry'         'Container registry (Premium, public access off) + AcrPull for the identities'
        & $mk 'registryendpoint' 'Private endpoint + DNS records: the registry (login server and data endpoint)'
        & $mk 'sql'              'Azure SQL (Entra-only, public access off) + database'
        & $mk 'sqlendpoint'      'Private endpoint + DNS record: Azure SQL'
        & $mk 'queues'           'The job queues (storage, no shared key, public access off)'
        & $mk 'queueendpoint'    'Private endpoint + DNS record: the job queues'
        & $mk 'webregistration'
        & $mk 'keyvault'         "Key Vault for the sign-in front's wrap key (public access off)"
        & $mk 'keyvaultendpoint' 'Private endpoint + DNS record: Key Vault'
        & $mk 'environment'      'Container Apps environment inside the network (internal: no public address)'
        & $mk 'environmentdns'   "The environment's own DNS zone (@, *, *.internal), linked to the spoke"
        & $mk 'hub'              'Hub peering / zone links to the hub (only with -PeerToHub / -LinkZonesToHub)'
        & $mk 'handoff'          "The network hand-off list (and the hub owner's script)"
        & $mk 'dnscheck'         'DNS check from this machine: every private name resolves to its endpoint'
        & $mk 'agentpool'        "The registry's build pool inside the network"
        & $mk 'image'
        & $mk 'schema'
        & $mk 'sqlaccess'
        & $mk 'jobs'
        & $mk 'jobstarter'
        & $mk 'graph'
        & $mk 'exchange'
        & $mk 'webstate'
        & $mk 'frontimage'
        & $mk 'webapp'
        & $mk 'verify'           'Verify: read everything back, run the tick once'
        & $mk 'insidecheck'      'Inside check: from inside the network - private DNS, the web app, every job queue'
        & $mk 'retireoldenv'     'Public -> private: the old public environment removed (after the inside check)'
        & $mk 'lockdown'         'Lockdown: public access read back as Disabled on SQL, Key Vault, storage and the registry'
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
        param($name, $job, $identity, [string]$trigger, [int]$timeout, [string]$cpu, [string]$mem, [bool]$parallelJob, [string]$key)
        # $key = the job's KEY (the schedule's AcaJobName): its queue and EPS_ACA_JOB - stable for every install; $name = the
        # Azure resource name, which may differ (framework §5.5: caj-eps-updater on a new install, caj-eps-update on an older one)
        if (-not $key) { $key = $name }
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
                        metadata = @{ accountName = $n.Storage; queueName = (Get-EpsJobQueueName $key); queueLength = '1' } }) } }
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
        # UPDATER-1: the update job reads the same install key (for "update now" and the update run) and needs the ring
        if ($job -in 'Uplink', 'Update') {
            $extra += @{ name = 'EPS_KEY_VAULT'; value = $n.KeyVault }
            if ("$($Ctx.WebUrl)" -match '^https://') { $extra += @{ name = 'EPS_WEB_URL'; value = "$($Ctx.WebUrl)" } }
            # TEL-01: the update ring on the heartbeat (framework §3, §8.17) - only a ring 0-10, never empty or text
            if ("$($Ctx.Ring)" -match '^([0-9]|10)$') { $extra += @{ name = 'EPS_RING'; value = "$($Ctx.Ring)" } }
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
                            @{ name = 'EPS_ACA_JOB'; value = $(if ($trigger -eq 'Event') { $key } else { '' }) }
                            @{ name = 'EPS_ManagedIdentityClientId'; value = $Ctx.Identities[$identity].ClientId }) + $extra }) } } }
        }
    }
    # the tick is short; a work job may run up to the 7-day limit (framework JOB-RUN-LIMIT) and holds 200,000 users
    # in memory (2.2 GB measured 2026-10-30), so it gets 4 GiB
    @(& $mk $n.TickJob 'Tick' 'TickIdentity' 'Schedule' 1800 '0.25' '0.5Gi') +
    @(foreach ($d in Get-EpsDefaultJobSchedule | Where-Object Implemented) { & $mk (Get-EpsAcaJobResourceName -Names $n -Key $d.AcaJobName) $d.Job 'EngineIdentity' 'Event' 604800 '2.0' '4Gi' ([bool]$d.Parallel) $d.AcaJobName })
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
    if ($Ctx.Network.Private) { $p = Test-EpsPrivateInstallStep -Id $Id -Ctx $Ctx; if ($p) { return $p } }
    switch ($Id) {
        'resourcegroup' { if (& $has $rg $script:EpsApi.rg) { @{ Action = 'exists'; Detail = $n.ResourceGroup } } else { @{ Action = 'create'; Detail = "$($n.ResourceGroup) in $($Ctx.Location)" } } }
        'identities'    { $m = @($n.EngineIdentity, $n.TickIdentity, $n.WebIdentity | Select-Object -Unique | Where-Object { -not (& $has "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$_" $script:EpsApi.mi) }); if ($m) { @{ Action = 'create'; Detail = $m -join ', ' } } else { @{ Action = 'exists'; Detail = 'all three' } } }
        'logs'          { if (& $has "$rg/providers/Microsoft.OperationalInsights/workspaces/$($n.Logs)" $script:EpsApi.law) { @{ Action = 'exists'; Detail = $n.Logs } } else { @{ Action = 'create'; Detail = $n.Logs } } }
        'registry'      { if (& $has "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" $script:EpsApi.acr) { @{ Action = 'update'; Detail = "$($n.Registry) (AcrPull checked)" } } else { @{ Action = 'create'; Detail = "$($n.Registry) (Basic)" } } }
        'image'         { @{ Action = 'run'; Detail = "build $($n.Image):$($Ctx.Version) in $($n.Registry)" } }
        'sql'           { if (& $has "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)/databases/$($n.Database)" $script:EpsApi.sql) { @{ Action = 'exists'; Detail = "$($n.SqlServer)/$($n.Database)" } } else { @{ Action = 'create'; Detail = "$($n.SqlServer) (Entra-only, admin $($Ctx.Person.Upn)) + $($n.Database) (S0)" } } }
        'sqlaccess'     { @{ Action = 'run'; Detail = "roles eps_engine, eps_tick, eps_web, eps_worker (sql/eps-grants.json, object-level); users $(@($n.EngineIdentity, $n.TickIdentity, $n.WebIdentity | Select-Object -Unique) -join ', ') - never db_datareader / db_datawriter" } }
        'schema'        { @{ Action = 'run'; Detail = 'sql/eps-schema.sql (idempotent, additive)' } }
        'environment'   { if (& $has "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" $script:EpsApi.aca) { @{ Action = 'exists'; Detail = $n.Environment } } else { @{ Action = 'create'; Detail = "$($n.Environment) (Consumption)" } } }
        'queues'        { if (& $has "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)" $script:EpsApi.st) { @{ Action = 'update'; Detail = "$($n.Storage) (queues + who may send / read checked)" } } else { @{ Action = 'create'; Detail = "$($n.Storage) (no shared key) + one queue per work job; the tick may send, the engine read" } } }
        'jobs'          { @{ Action = 'run'; Detail = ((Get-EpsJobBodies -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)") | ForEach-Object { $_.Name }) -join ', ' } }
        'jobstarter'    { @{ Action = 'run'; Detail = "remove role '$($n.JobStarterRole)' if an older install made it; read back: $($n.TickIdentity) holds no role on $($n.ResourceGroup)" } }
        'graph'         { @{ Action = 'run'; Detail = "$($n.EngineIdentity): $((Get-EpsEngineGraphRoles -Ctx $Ctx) -join ', ')$(if (@($Ctx.ExcludeGraphRoles).Count) { ' (left out, not approved: ' + (@($Ctx.ExcludeGraphRoles) -join ', ') + ')' })" } }
        'exchange'      { @{ Action = 'run'; Detail = "$($n.EngineIdentity): Exchange.ManageAsApp + Entra role Exchange Recipient Administrator - only while user tagging, the identity report or a mailbox condition is on (else removed)" } }
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
    $priv = [bool]$Ctx.Network.Private   # NET-1: the private network install (the public install never sets it)
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
        # RESUME-WEB-OBJECTID (NET-1 run 3): the jobs step on a resume fills ONLY ClientId - restore when ANY of the three is
        # missing, or the web-app step PATCHes applications/ with no id (Graph 405)
        if (-not $Ctx.Web.ClientId -or -not $Ctx.Web.AppObjectId -or -not $Ctx.Web.SpId) {
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
        'resourcegroup' {
            # NAM-01 (framework §5.5): every resource group carries product, ring, edition, hosting, tenant, owner, purpose.
            # A re-run MERGES: tags the customer set stay, an owner / ring already there is never overwritten by an empty one.
            $old = Invoke-EpsArm -Path $rg -ApiVersion $script:EpsApi.rg -AllowNotFound
            $t = [ordered]@{}; if ($old -and $old.tags) { foreach ($p in $old.tags.PSObject.Properties) { $t[$p.Name] = "$($p.Value)" } }
            foreach ($k in $tags.Keys) { $t[$k] = $tags[$k] }
            $t.edition = 'community'; $t.hosting = 'ca'; $t.tenant = "$($Ctx.TenantId)"
            $t.purpose = 'Entra Policy Suite: Conditional Access, user and device tagging, identity reporting'
            if ("$($Ctx.Ring)" -match '^([0-9]|10)$') { $t.ring = "r$($Ctx.Ring)" }
            if (-not $t.Contains('owner') -and "$($Ctx.Person.Upn)" -match '^[^\x00-\x1f<>%&\\?/]{1,200}$') { $t.owner = "$($Ctx.Person.Upn)" }
            [void](Invoke-EpsArm -Method PUT -Path $rg -ApiVersion $script:EpsApi.rg -Body @{ location = $(if ($old) { $old.location } else { $Ctx.Location }); tags = $t })
        }
        'identities' {
            foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') {
                $m = Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n[$k])" -ApiVersion $script:EpsApi.mi -Body @{ location = $Ctx.Location; tags = $tags }
                $Ctx.Identities[$k] = @{ Id = $m.id; ClientId = $m.properties.clientId; PrincipalId = $m.properties.principalId }
            }
        }
        'logs' { [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.OperationalInsights/workspaces/$($n.Logs)" -ApiVersion $script:EpsApi.law -Body @{ location = $Ctx.Location; tags = $tags; properties = @{ sku = @{ name = 'PerGB2018' }; retentionInDays = 30 } }) }
        'registry' {
            & $loadMi
            $acrBody = @{ location = $Ctx.Location; tags = $tags; sku = @{ name = 'Basic' }; properties = @{ adminUserEnabled = $false } }
            if ($priv) {
                # private: Premium (private endpoint, build pool); a NEW registry is created with public access off and no
                # exception; an existing one (public -> private) keeps its setting until the lockdown step
                $old = Invoke-EpsArm -Path "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ApiVersion $script:EpsApi.acr -AllowNotFound
                $acrBody.sku.name = 'Premium'
                $acrBody.properties.publicNetworkAccess = if ($old) { if ("$($old.properties.publicNetworkAccess)") { "$($old.properties.publicNetworkAccess)" } else { 'Enabled' } } else { 'Disabled' }
                $acrBody.properties.networkRuleBypassOptions = if ($old) { if ("$($old.properties.networkRuleBypassOptions)") { "$($old.properties.networkRuleBypassOptions)" } else { 'AzureServices' } } else { 'None' }
            }
            $acr = Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ApiVersion $script:EpsApi.acr -Body $acrBody
            foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') { Add-EpsRoleAssignment -Scope $acr.id -RoleDefinitionId "$sub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsRole.AcrPull)" -PrincipalId $Ctx.Identities[$k].PrincipalId }
        }
        'image' {
            $ctxFile = New-EpsBuildContext -SolutionRoot $Ctx.SolutionRoot
            try {
                # private: the build runs on the pool INSIDE the network; the digest comes from the build's own run record
                # (ARM), never from reading the registry afterwards - its data plane is closed then (PIM Setup-PimContainers)
                $b = Invoke-EpsAcrBuild -RegistryId "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ContextPath $ctxFile -DockerFile 'SOLUTIONS/EntraPolicySuite/tools/eps-engine/Dockerfile' -ImageName "$($n.Image):$($Ctx.Version)" -BuildArgs @{ EPS_CONTENT_HASH = $Ctx.Version } -PollSeconds ($Ctx.PollSeconds ?? 10) -AgentPoolName $(if ($priv) { $n.AgentPool } else { '' })
                $Ctx.ImageDigest = $b.Digest
            } finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        }
        'sql' {
            $srv = "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)"
            # -SqlLocation: Azure SQL may refuse new servers in a region (North Europe, 2026-10-30) while the rest is fine there
            $sqlLoc = if ($Ctx.SqlLocation) { $Ctx.SqlLocation } else { $Ctx.Location }
            # the SQL server's Entra admin (framework §12.23 P5, owner 2026-11-01): an EXISTING server keeps the admin it has
            # (a re-run never takes the customer's admin group away); a group still named with the old product name is renamed to the standard grp-eps-sql-admins in place (same object, same sid);
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
            # the standard group name (framework §12.11c, owner 2026-11-04): the admin group still named with the old product name
            # is renamed in place (same object id = same sid, so nobody loses access) and the server's admin entry follows it.
            # Only that exact old name: a customer's own group keeps the name the customer gave it. A refused rename (no right
            # to rename groups) never stops the install - it is said, and the next run tries again.
            if ("$($admin.principalType)" -in 'Group', '' -and "$($admin.login)" -eq $n.LegacySqlAdminGroup -and "$($admin.sid)" -match '^[0-9a-fA-F-]{36}$') {
                try {
                    $grp = Invoke-EpsGraph -Path "v1.0/groups/$($admin.sid)?`$select=id,displayName"
                    if ("$($grp.displayName)" -ceq $n.LegacySqlAdminGroup) {
                        Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/groups/$($admin.sid)" -Body @{ displayName = $n.SqlAdminGroup }) }
                        [void](Wait-EpsGraphDisplayName -Path "v1.0/groups/$($admin.sid)" -Want $n.SqlAdminGroup)
                        if (-not $Ctx.Renamed) { $Ctx.Renamed = [System.Collections.Generic.List[string]]::new() }
                        $Ctx.Renamed.Add("group '$($n.LegacySqlAdminGroup)' -> '$($n.SqlAdminGroup)' (the SQL server's Entra admin, same object)")
                    }
                    if ("$($grp.displayName)" -ceq $n.LegacySqlAdminGroup -or "$($grp.displayName)" -ceq $n.SqlAdminGroup) { $admin.login = $n.SqlAdminGroup }
                } catch { Write-Host "  note     the SQL admin group '$($admin.login)' was not renamed to $($n.SqlAdminGroup): $($_.Exception.Message) - the next run tries again" -ForegroundColor Yellow }
            }
            # private (NET-1): a NEW server is created with public access off and no firewall rule at all; an existing one
            # (public -> private) keeps its setting until the lockdown step, after the inside check
            $pna = if (-not $priv) { 'Enabled' } elseif ($old -and "$($old.properties.publicNetworkAccess)") { "$($old.properties.publicNetworkAccess)" } else { 'Disabled' }
            [void](Invoke-EpsArm -Method PUT -Path $srv -ApiVersion $script:EpsApi.sql -Body @{ location = $(if ($old) { $old.location } else { $sqlLoc }); tags = $tags; properties = @{ minimalTlsVersion = '1.2'; publicNetworkAccess = $pna; administrators = $admin } })
            # the jobs reach SQL from Azure (external exposure, DESIGN §2); a private install reaches it through its endpoint
            if (-not $priv) { [void](Invoke-EpsArm -Method PUT -Path "$srv/firewallRules/AllowAllWindowsAzureIps" -ApiVersion $script:EpsApi.sql -Body @{ properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } }) }
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
            if ($priv) {
                # inside the network (apps subnet, internal = no public address). An environment cannot move into a network:
                # a public install converted to private gets this NEW one; the public one is removed after the inside check
                Read-EpsNetworkFacts -Ctx $Ctx
                [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" -ApiVersion $script:EpsApi.aca -Body (New-EpsPrivateEnvironmentBody -Ctx $Ctx -LawCustomerId $law.properties.customerId -LawKey $key))
                $Ctx.Network.EnvDomain = $null
                break
            }
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
            $stProps = @{ allowSharedKeyAccess = $false; minimumTlsVersion = 'TLS1_2'; allowBlobPublicAccess = $false; supportsHttpsTrafficOnly = $true; defaultToOAuthAuthentication = $true }
            if ($priv) {
                # private: a NEW account is created with public access off and no exception (the queues are reached through
                # their private endpoint); an existing one (public -> private) keeps its setting until the lockdown step
                $old = Invoke-EpsArm -Path $st -ApiVersion $script:EpsApi.st -AllowNotFound
                if ($old) { if ("$($old.properties.publicNetworkAccess)") { $stProps.publicNetworkAccess = "$($old.properties.publicNetworkAccess)" }; if ($old.properties.networkAcls) { $stProps.networkAcls = $old.properties.networkAcls } }
                else { $stProps.publicNetworkAccess = 'Disabled'; $stProps.networkAcls = @{ defaultAction = 'Deny'; bypass = 'None' } }
            }
            [void](Invoke-EpsArm -Method PUT -Path $st -ApiVersion $script:EpsApi.st -Body @{ location = $Ctx.Location; tags = $tags; kind = 'StorageV2'; sku = @{ name = 'Standard_LRS' }
                properties = $stProps })
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
            # TEL-01: a re-run without -Ring keeps the ring the uplink job has (Invardia's word stays until it is changed)
            if ("$($Ctx.Ring)" -notmatch '^([0-9]|10)$') {
                $uj = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$(@(Get-EpsDefaultJobSchedule | Where-Object Job -eq 'Uplink')[0].AcaJobName)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
                $old = @($uj.properties.template.containers | ForEach-Object { $_.env } | Where-Object { $_.name -eq 'EPS_RING' })[0]
                if ("$($old.value)" -match '^([0-9]|10)$') { $Ctx.Ring = "$($old.value)" }
            }
            # the jobs on 2025-01-01: the first version that takes an identity on a scale rule (2.0.9, S4)
            foreach ($j in Get-EpsJobBodies -Ctx $Ctx -Image $image) {
                # public -> private: a job cannot move to another environment - one in the old environment is deleted and
                # re-created in the new one (same name, identity, queue and database; a queued message waits for it)
                if ($priv) { Remove-EpsAppInOtherEnvironment -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -EnvironmentId $j.Body.properties.environmentId }
                [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -ApiVersion $script:EpsApi.acajob -Body $j.Body)
            }
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
            $p = $Ctx.Identities.EngineIdentity.PrincipalId
            # OPEN-09 / SEC-02 (Invardia 2026-11-04): the Exchange rights only while a feature that uses Exchange is on (user
            # tagging, the identity report, a mailbox condition - Get-EpsExchangeNeed). A new install has every feature off,
            # so it grants none; an install whose features no longer need them has them REMOVED, read back. Not readable =
            # nothing changes on a guess.
            $need = $null
            if (Get-Command Get-EpsExchangeNeed -ErrorAction SilentlyContinue) {
                try {
                    $r = Invoke-EpsSetupSql -Ctx $Ctx -Script $script:EpsExchangeNeedSql -Rows
                    $rows = if ($r -and $r.PSObject.Properties['Rows']) { @($r.Rows) } else { @($r) }
                    $need = Get-EpsExchangeNeed -Row @($rows | Where-Object { $_ -and $_ -isnot [string] })[0]
                } catch { $need = @{ Known = $false; Needed = $false; Why = "the settings could not be read: $($_.Exception.Message)" } }
            } else { $need = @{ Known = $true; Needed = $true; Why = 'the need check is not loaded' } }
            $Ctx.ExchangeNeed = $need
            if ($need.Known -and $need.Needed) {
                [void](Grant-EpsAppRoles -PrincipalId $p -ResourceAppId $script:EpsExchangeAppId -Roles @('Exchange.ManageAsApp'))
                $have = @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$p' and roleDefinitionId eq '$($script:EpsExchangeRecipientAdminRole)'" -All)
                if (-not $have.Count) { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/roleManagement/directory/roleAssignments' -Body @{ principalId = $p; roleDefinitionId = $script:EpsExchangeRecipientAdminRole; directoryScopeId = '/' }) }
            } elseif ($need.Known -and (Get-Command Invoke-EpsEnginePermissionPlan -ErrorAction SilentlyContinue)) {
                $rows = @(Invoke-EpsEnginePermissionPlan -EngineObjectId $p -Request (Get-EpsEnginePermissionRequest -Exchange -Remove))
                $gone = @($rows | Where-Object { $_.Status -eq 'removed' })
                $bad = @($rows | Where-Object { $_.Status -eq 'refused' })
                if (-not $Ctx.Renamed) { $Ctx.Renamed = [System.Collections.Generic.List[string]]::new() }
                foreach ($x in $gone) { $Ctx.Renamed.Add("removed (not needed: $($need.Why)): $($x.What)") }
                foreach ($x in $bad) { Write-Host "  note     $($x.What) is not needed ($($need.Why)) but was not removed: $($x.Reason) - the next run tries again" -ForegroundColor Yellow }
            } else { Write-Host "  note     the Exchange rights were left as they are: $($need.Why)" -ForegroundColor Yellow }
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
            try { [void](Invoke-EpsAcrBuild -RegistryId "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ContextPath $ctxFile -DockerFile 'Dockerfile' -ImageName "signin-front:$pin" -PollSeconds ($Ctx.PollSeconds ?? 10) -AgentPoolName $(if ($priv) { $n.AgentPool } else { '' })) }
            finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        }
        'webapp' {
            & $loadMi
            if ($priv) {
                # public -> private: the app is re-created in the new environment (its address changes; the web app step adds
                # the new redirect URI, the retire step removes the old one)
                Remove-EpsAppInOtherEnvironment -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -EnvironmentId "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
                if ($Ctx.Web) { $Ctx.Web.Fqdn = $null; $Ctx.Web.Url = $null }
            }
            & $loadWeb; Invoke-EpsWebAppStep -Ctx $Ctx
        }
        # NET-1, the private network install's own steps (EPS-InstallNetwork.ps1)
        'network'          { Invoke-EpsNetworkStep -Ctx $Ctx }
        'dnszones'         { Invoke-EpsDnsZonesStep -Ctx $Ctx }
        'registryendpoint' { Invoke-EpsPrivateEndpointStep -Ctx $Ctx -Key 'registry' }
        'sqlendpoint'      { Invoke-EpsPrivateEndpointStep -Ctx $Ctx -Key 'sql' }
        'queueendpoint'    { Invoke-EpsPrivateEndpointStep -Ctx $Ctx -Key 'queue' }
        'keyvaultendpoint' { Invoke-EpsPrivateEndpointStep -Ctx $Ctx -Key 'vault' }
        'environmentdns'   { Invoke-EpsEnvironmentDnsStep -Ctx $Ctx }
        'hub'              { [void](Invoke-EpsHubStep -Ctx $Ctx) }
        'handoff'          { & $loadMi; Invoke-EpsHandoffStep -Ctx $Ctx }
        'dnscheck'         { [void](Invoke-EpsDnsCheckStep -Ctx $Ctx) }
        'agentpool'        { Invoke-EpsAgentPoolStep -Ctx $Ctx }
        'insidecheck'      { & $loadMi; & $loadWeb; [void](Invoke-EpsInsideCheckStep -Ctx $Ctx) }
        'retireoldenv'     { & $loadWeb; [void](Invoke-EpsRetireOldEnvStep -Ctx $Ctx) }
        'lockdown'         { [void](Invoke-EpsLockdownStep -Ctx $Ctx) }
        'verify' {
            $r = Confirm-EpsInstall -Ctx $Ctx -PollSeconds ($Ctx.PollSeconds ?? 15)
            # a tick that ran and FAILED is a failed install (2.0.7 live 2026-11-01: reported 'ok' with the tick failing)
            if ($r.Tick -ne 'Succeeded') { throw "the tick ($($r.Execution)) ran and ended '$($r.Tick)' - see its log in $($Ctx.Names.Logs); fix the cause and run the install again" }
            # private: the web app has no public address - it is proven from INSIDE the network by the next step
            if ($priv) { return $r }
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
                # a private install opens NO firewall rule (its server has no public access at all): the SQL steps run
                # from a machine inside the network, through the private endpoint (NET-1)
                if ($Ctx.Network.Private -and $m -match "Client with IP address '([0-9a-fA-F.:]+)' is not allowed|Deny Public Network Access|47073") {
                    throw "Azure SQL refused this machine ($($Matches[0])): a private install runs its database steps from a machine inside your network (its name must resolve to the private endpoint) - run the same command again from there; it resumes"
                }
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
    $Ctx.Completed = $done   # the steps that gate on an earlier one (lockdown, retireoldenv: only after the inside check) read it
    foreach ($s in Get-EpsInstallSteps -Private:([bool]$Ctx.Network.Private)) {
        if ($done.Contains($s.Id)) { & $OnStep @{ Step = $s; State = 'skipped'; Message = 'already done (resume)' }; continue }
        $t = Test-EpsInstallStep -Id $s.Id -Ctx $Ctx
        if ($WhatIf) { & $OnStep @{ Step = $s; State = 'plan'; Message = "$($t.Action): $($t.Detail)" }; continue }
        & $OnStep @{ Step = $s; State = 'running'; Message = "$($t.Action): $($t.Detail)" }
        $sw = [Diagnostics.Stopwatch]::StartNew()   # OVERHEAD (owner 2026-11-03): every step says how long it took
        try { $out = Invoke-EpsInstallStep -Id $s.Id -Ctx $Ctx }
        catch {
            # framework rule 14: a step that waits for something done later (DNS records, a check from inside the network)
            # reports 'waiting' with the reason - nothing failed; the same command resumes here
            $em = "$($_.Exception.Message)"
            if ($em.StartsWith('EPS-WAITING: ')) { & $OnStep @{ Step = $s; State = 'waiting'; Message = $em.Substring(13) }; throw }
            & $OnStep @{ Step = $s; State = 'failed'; Message = $em }; throw
        }
        $done.Add($s.Id)
        $took = " ($([int]$sw.Elapsed.TotalSeconds) s)"
        & $OnStep @{ Step = $s; State = 'ok'; Seconds = [int]$sw.Elapsed.TotalSeconds; Message = $(if ($out -is [hashtable] -and $out.Tick) { "tick $($out.Tick) after $($out.Seconds) s$(if ($out.Web) { "; the web app answers at $($out.Web)" })$took" } elseif ($out -is [hashtable] -and $out.Note) { "done - $($out.Note)$took" } else { "done$took" }); Completed = @($done) }
    }
    @($done)
}
