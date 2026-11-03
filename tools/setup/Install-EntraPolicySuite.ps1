#Requires -Version 7.2
<#
.SYNOPSIS
    Installs EntraPolicySuite 2.0 in your own Azure subscription (Container Apps + Azure SQL), as yourself, in a browser.
.DESCRIPTION
    Signs you in in a browser (no PowerShell module, no az CLI, works in Cloud Shell), checks the subscription, then
    creates - in one resource group - three managed identities (the engine, the engine's scheduler, the web app), a Log
    Analytics workspace, a container registry with the engine image built in it, Azure SQL (Entra-only) with the
    database and its schema, a Container Apps environment, the job queues and the jobs (the engine checks its schedules
    every 5 minutes; user and device tagging and the other jobs start from their own queues), the web app, and grants
    the engine identity exactly the rights it needs (Graph: User.ReadWrite.All, Device.ReadWrite.All and read-only
    rights; Exchange.ManageAsApp + the Entra role Exchange Recipient Administrator) and the scheduler identity only the
    right to put a run request on the job queues. Then it runs the engine's schedule check once.
    Every feature is OFF after the install, and a scheduled run only previews until you switch it to Apply.
    -WhatIf shows every step and what it would create, and changes nothing. A failed install resumes where it stopped.

    PUBLIC (the default): the web app has a public HTTPS address behind the Entra sign-in; Azure SQL, Key Vault, the job
    queues and the registry use their public endpoints, protected by Entra sign-in and managed identities.
    PRIVATE (-PrivateNetwork): everything runs in your virtual network. The Container Apps environment is created in its
    own subnet with no public address (the web app is reachable from your network only, still behind the sign-in);
    Azure SQL, Key Vault, the job queues and the registry (Premium) are CREATED with public access off and reached
    through private endpoints with private DNS zones. Run a private install from a machine INSIDE your network (or one
    that resolves its private names): the image upload and the database steps run from the machine that runs the
    install. Before them the install checks DNS from this machine and, when a name does not resolve to its private
    endpoint, stops and prints the exact A records your hub needs - run the same command again afterwards; it resumes.
    At the end a one-time check INSIDE the network (a job in the environment) proves private DNS, the web app and every
    job queue; only then is the install reported as done. The network hand-off list (peering, DNS zones and records, the
    outbound hosts, the check to run) is printed and written to network-hand-off.txt in the state folder, and with
    -HubVnetId a script for the hub owner (prepare-hub-entrapolicysuite.ps1) next to it.
    Outbound from the network the jobs reach graph.microsoft.com, login.microsoftonline.com, outlook.office365.com,
    management.azure.com and invardia.com (default outbound, or allow them on your firewall).
    PUBLIC -> PRIVATE: run the same command with -PrivateNetwork on a public install. A Container Apps environment cannot
    move into a network, so a new one (cae-eps-vnet) is created, the jobs and the web app are re-created in it (same
    identities, database and queues; the web app gets a new address), the data resources get their private endpoints,
    and only after the inside check is the old environment removed and public access turned off. -WhatIf shows the plan.
.PARAMETER TenantId
    Your Entra tenant id.
.PARAMETER SubscriptionId
    The Azure subscription to install in (you need Owner on it, and Global Administrator or Privileged Role
    Administrator in Entra for the Graph and Exchange grants).
.PARAMETER Location
    The Azure region. Default westeurope.
.PARAMETER ResourceGroup
    Default rg-entrapolicysuite.
.PARAMETER SqlLocation
    The Azure SQL server's region, when Azure SQL does not take new servers in -Location. Default: -Location.
.PARAMETER SqlAdminGroupId
    The object id of YOUR admin group (Entra security group) to be the Azure SQL server's Entra admin. Make sure you are
    a member of it (the install's SQL steps run as you). Without it a new server gets you as its admin. An EXISTING server
    always keeps the admin it has - a re-run never changes it.
.PARAMETER SqlAdminGroupName
    The display name of that group (shown as the SQL admin).
.PARAMETER ExcludeGraphRole
    A Graph role of the engine your approver did not approve. It is never granted; the feature that needs it reports
    its data as unavailable (Organization.Read.All: the licence lookup of the Teams Rooms rule condition).
.PARAMETER StatePath
    The install journal. Default ~/clouddrive/invardia/eps-<subscription> in Cloud Shell, else ~/invardia/eps-<subscription>.
.PARAMETER PrivateNetwork
    Install into your virtual network (see PRIVATE above). Off by default.
.PARAMETER VnetId
    Your existing virtual network (resource id), in the same region as the install. The install needs Network
    Contributor on it. Leave it empty to let the install make its own network from -VnetAddressPrefix.
.PARAMETER VnetAddressPrefix
    Only without -VnetId: the range of the network the install makes (at least a /25). Default 10.230.0.0/24.
.PARAMETER VnetName
    Only without -VnetId: the name of that network. Default vnet-eps.
.PARAMETER AppsSubnetName
    The subnet of the Container Apps environment (at least a /27, delegated to Microsoft.App/environments; an existing
    empty subnet is delegated). Default snet-eps-apps.
.PARAMETER AppsSubnetPrefix
    Its range, when the subnet is created. Default in a network the install makes: the first /26.
.PARAMETER EndpointsSubnetName
    The subnet of the private endpoints and the registry's build pool (no delegation). Default snet-eps-endpoints.
.PARAMETER EndpointsSubnetPrefix
    Its range, when the subnet is created. Default in a network the install makes: the second /26.
.PARAMETER PrivateDnsZonesResourceGroupId
    The resource group of your central private DNS zones (resource id). Its zones are USED, never created, and nothing
    is written there; a zone missing there is on the hand-off list. Empty: the zones are made in the install's resource
    group and linked to the network. The web app's own zone always stays in the install's resource group.
.PARAMETER HubVnetId
    Your hub network (resource id, may be in another subscription). Nothing is written in it unless -PeerToHub or
    -LinkZonesToHub is given; it makes the hand-off list exact and the hub owner's script possible.
.PARAMETER PeerToHub
    Peer the spoke with the hub, both directions - only when your rights on both networks allow it (checked before any
    change). Never half a peering: when the second side fails, the first is removed. Off by default.
.PARAMETER LinkZonesToHub
    Link the install's DNS zones to the hub - only when you may join the hub network (checked first). Off by default.
.PARAMETER WebAppAccess
    external (default, public install) or internal (your network only; -PrivateNetwork means internal).
.PARAMETER ConfirmedFromInside
    A private install that cannot be proven from inside (the inside job did not run and this machine cannot reach the
    web app): you checked the web app from a machine in your network yourself.
.EXAMPLE
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -WhatIf
.EXAMPLE
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
.EXAMPLE
    # private, in a network the install makes (10.230.0.0/24), the hub given for an exact hand-off list
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PrivateNetwork -HubVnetId <hub network id> -WhatIf
.EXAMPLE
    # private, in your own spoke network, your central DNS zones, the peering made by the install
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PrivateNetwork -VnetId <network id> `
        -AppsSubnetName snet-eps-apps -EndpointsSubnetName snet-eps-endpoints -PrivateDnsZonesResourceGroupId <zones resource group id> `
        -HubVnetId <hub network id> -PeerToHub
.LINK
    https://invardia.com/docs/eps/scripts/Install-EntraPolicySuite
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [ValidatePattern('^[a-z0-9]{3,30}$')][string]$Location = 'westeurope',
    [ValidatePattern('^[A-Za-z0-9._()-]{1,80}$')][string]$ResourceGroup = 'rg-entrapolicysuite',
    [string]$StatePath,
    # the Azure SQL server's region when it differs from -Location (Azure SQL can refuse new servers in a region that
    # takes everything else - North Europe, 2026-10-30). Default: -Location.
    [ValidatePattern('^$|^[a-z0-9]{3,30}$')][string]$SqlLocation = '',
    # the customer's admin group as the SQL server's Entra admin (framework §12.23 P5); an existing server keeps its admin
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$SqlAdminGroupId = '',
    [ValidatePattern('^$|^[^\x00-\x1f]{1,120}$')][string]$SqlAdminGroupName = '',
    # a Graph role of the engine that the approver did not approve: never granted (the feature that needs it then
    # reports its data as unavailable). e.g. -ExcludeGraphRole Organization.Read.All
    [ValidateSet('User.ReadWrite.All', 'Device.ReadWrite.All', 'GroupMember.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'DeviceManagementManagedDevices.Read.All', 'Application.Read.All', 'Policy.ReadWrite.ConditionalAccess')][string[]]$ExcludeGraphRole = @(),
    [switch]$Quiet,
    # ---- NET-1: the private network install (names as SecurityInsight's, so the products read the same) ----
    [switch]$PrivateNetwork,
    [string]$VnetId = '',
    [string]$VnetAddressPrefix = '10.230.0.0/24',
    [string]$VnetName = 'vnet-eps',
    [string]$AppsSubnetName = 'snet-eps-apps',
    [string]$AppsSubnetPrefix = '',
    [string]$EndpointsSubnetName = 'snet-eps-endpoints',
    [string]$EndpointsSubnetPrefix = '',
    [string]$PrivateDnsZonesResourceGroupId = '',
    [string]$HubVnetId = '',
    [switch]$LinkZonesToHub,
    [switch]$PeerToHub,
    [ValidateSet('external', 'internal')][string]$WebAppAccess = 'external',
    [switch]$ConfirmedFromInside
)
$ErrorActionPreference = 'Stop'
$docUrl = 'https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Install-EntraPolicySuite when EPS is public there (DOC-LINKS)
Write-Host "Documentation: $docUrl"
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim()
$what = [bool]$WhatIfPreference
$WhatIfPreference = $false   # the install decides what -WhatIf means: read, plan, change nothing (its own calls stay real reads)
function Finish([int]$code, [string]$msg) { if ($msg) { Write-Host $msg -ForegroundColor $(if ($code) { 'Red' } else { 'Green' }) }; exit $code }

# ---- the network parameters (NET-1): checked before the sign-in, a wrong range or id is refused (exit 2) ----
$netPlan = Get-EpsNetworkPlan -P @{ PrivateNetwork = [bool]$PrivateNetwork; VnetId = $VnetId; VnetAddressPrefix = $VnetAddressPrefix; VnetName = $VnetName
    AppsSubnetName = $AppsSubnetName; AppsSubnetPrefix = $AppsSubnetPrefix; EndpointsSubnetName = $EndpointsSubnetName; EndpointsSubnetPrefix = $EndpointsSubnetPrefix
    PrivateDnsZonesResourceGroupId = $PrivateDnsZonesResourceGroupId; HubVnetId = $HubVnetId; LinkZonesToHub = [bool]$LinkZonesToHub; PeerToHub = [bool]$PeerToHub
    WebAppAccess = $WebAppAccess; ConfirmedFromInside = [bool]$ConfirmedFromInside } -Bound @($PSBoundParameters.Keys)
if (-not $netPlan.Ok) { Finish 2 "Refused: $($netPlan.Reason)" }

# ---- sign in (a Support-app session or a test can provide the token source instead) ----
$person = if ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and (-not "$($global:EPS_SignInTenant)" -or "$($global:EPS_SignInTenant)" -eq "$TenantId")) { $global:EPS_InstallPerson } else { Connect-EpsSignedIn -TenantId "$TenantId" }
Write-Host "Signed in as $($person.Upn)" -ForegroundColor Cyan

# ---- checks (exit 2) ----
# Rights: Owner on the subscription, OR Owner on an EXISTING resource group only (internal 2026-10-30: the owner gave
# the Support app Owner on rg-entrapolicysuite and nothing at subscription level). With the resource group only, the
# subscription cannot be read: the tenant is then proven by reading the resource group with this tenant's token
# (ARM refuses a token of another tenant), and the resource providers must already be registered (they cannot be
# registered without a subscription right - a later step that needs one fails with Azure's MissingSubscriptionRegistration).
$rgOnly = $false
$subInfo = try { Invoke-EpsArm -Path "/subscriptions/$SubscriptionId" -ApiVersion '2022-12-01' } catch { if ("$_" -match '(?i)AuthorizationFailed|403') { $null } else { Finish 2 "Subscription $SubscriptionId cannot be read as $($person.Upn): $($_.Exception.Message)" } }
if (-not $subInfo) {
    $rgInfo = try { Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" -ApiVersion '2021-04-01' -AllowNotFound } catch { Finish 2 "Neither subscription $SubscriptionId nor resource group $ResourceGroup can be read as $($person.Upn): $($_.Exception.Message)" }
    if (-not $rgInfo) { Finish 2 "Subscription $SubscriptionId cannot be read as $($person.Upn), and resource group $ResourceGroup does not exist: with rights on a resource group only, it must exist first." }
    if ("$($rgInfo.location)" -ne $Location) { Finish 2 "Resource group $ResourceGroup is in '$($rgInfo.location)', not '$Location' - run with -Location $($rgInfo.location)." }
    $rgOnly = $true
    $subInfo = [pscustomobject]@{ tenantId = "$TenantId"; displayName = "(rights on $ResourceGroup only)" }
}
if ("$($subInfo.tenantId)" -ne "$TenantId") { Finish 2 "Subscription $SubscriptionId belongs to tenant $($subInfo.tenantId), not $TenantId - refused." }
$need = 'Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.Sql', 'Microsoft.OperationalInsights', 'Microsoft.ManagedIdentity', 'Microsoft.KeyVault'
if ($netPlan.Private) { $need += 'Microsoft.Network' }
$unregistered = if ($rgOnly) { @() } else { @(foreach ($p in $need) { $r = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/providers/$p" -ApiVersion '2021-04-01'; if ($r.registrationState -ne 'Registered') { $p } }) }
if ($rgOnly) { Write-Host "Rights on resource group $ResourceGroup only: the resource providers ($($need -join ', ')) are taken as registered (they cannot be checked or registered without a subscription right)." -ForegroundColor Yellow }

$names = Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup -Private:([bool]$netPlan.Private)
if (-not $netPlan.Private) {
    # a private install stays private: a run without -PrivateNetwork would put a public environment next to it
    $privEnv = (Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup -Private).Environment
    $pe = try { Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/managedEnvironments/$privEnv" -ApiVersion '2024-03-01' -AllowNotFound } catch { $null }
    if ($pe -and "$($pe.name)" -eq $privEnv) { Finish 2 "$ResourceGroup holds a PRIVATE install ($privEnv): run the same command with -PrivateNetwork (and its network parameters)." }
}
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Location = $Location; Names = $names; Version = $version; SolutionRoot = $sol; Person = $person; Identities = @{}; ExcludeGraphRoles = @($ExcludeGraphRole); SqlLocation = $SqlLocation
    SqlAdminGroup = $(if ($SqlAdminGroupId) { @{ ObjectId = $SqlAdminGroupId.ToLowerInvariant(); Name = $(if ($SqlAdminGroupName) { $SqlAdminGroupName } else { "group $SqlAdminGroupId" }) } }) }
# the web app's sign-in front is built from the source this release carries, at the version it pins - checked BEFORE
# anything is created, so an install never stops half-way for it
$front = Get-EpsSigninFrontSource -SolutionRoot $sol -Pin (Get-EpsSigninFrontPin -SolutionRoot $sol)
if (-not $front.Ok -and -not $what) { Finish 2 "The web app's sign-in front cannot be built: $($front.Reason). Use a complete EntraPolicySuite release." }

if (-not $StatePath) {
    $base = if ((Test-EpsCloudShell) -and (Test-Path (Join-Path $HOME 'clouddrive'))) { Join-Path $HOME 'clouddrive/invardia' } else { Join-Path $HOME 'invardia' }
    $StatePath = Join-Path $base "eps-$SubscriptionId"
}
$stateFile = Join-Path $StatePath 'state.json'
if ($netPlan.Private) { $ctx.Network = $netPlan; $ctx.Network.Notes = @(); $ctx.StatePath = $(if ($what) { '' } else { $StatePath }) }
$completed = @()
if (Test-Path -LiteralPath $stateFile) {
    $st = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    if ($st.resourceGroup -eq $ResourceGroup -and $st.version -eq $version) { $completed = @($st.completed) ; if ($completed) { Write-Host "Resuming: $($completed.Count) step(s) already done ($stateFile)" -ForegroundColor Cyan } }
}

Write-Host ''
Write-Host "EntraPolicySuite $version -> subscription $($subInfo.displayName) ($SubscriptionId), $ResourceGroup, $Location" -ForegroundColor Cyan
if ($unregistered) { Write-Host "Resource providers to register: $($unregistered -join ', ')" -ForegroundColor Yellow }
$print = { param($e) if (-not $Quiet) {
    $c = switch ($e.State) { 'ok' { 'Green' } 'failed' { 'Red' } 'plan' { 'Gray' } 'skipped' { 'DarkGray' } default { 'Cyan' } }
    Write-Host ("  {0,-8} {1,-60} {2}" -f $e.State, $e.Step.Title, $e.Message) -ForegroundColor $c } }

# Installer rule 9 (framework §0): the region accepts new resources in THIS subscription - a validate, nothing is made
$rgExists = [bool]$(if ($rgOnly) { $true } else { Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" -ApiVersion '2021-04-01' -AllowNotFound })
$reg = Test-EpsRegionAccepts -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Location $Location -SqlLocation $SqlLocation -TenantId $TenantId -ResourceGroupExists:$rgExists
if ($reg.Accepts -eq $false) {
    # Invardia's wording, word for word (framework §0 installer rule 9); the examples are regions that validate OK here
    $ok = @($script:EpsRegionAlternatives | Where-Object { $_ -ne $Location } | Where-Object { (Test-EpsRegionAccepts -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Location $_ -TenantId $TenantId -ResourceGroupExists:$rgExists).Accepts -eq $true } | Select-Object -First 3)
    Finish 2 ("`nAzure does not accept new resources in $Location for this subscription (the region is not taking new customers). Choose another region, for example $(if ($ok.Count) { $ok -join ', ' } else { 'northeurope or swedencentral' })." + $(if ($rgExists) { "`nResource group $ResourceGroup is in ${Location}: use another resource group (-ResourceGroup) with the new -Location." }) + "`nNOTHING was created.")
}if ($null -eq $reg.Accepts) { Write-Host "Region $Location`: $($reg.Reason) - the install goes on." -ForegroundColor DarkYellow }
# Installer rule 8 (framework §0, a real install 2026-11-03): every prerequisite of the chosen network options, checked
# BEFORE anything is created - ALL missing ones in one list, and nothing made (also with -WhatIf, so the plan shows it)
if ($netPlan.Private) {
    $pre = @(Test-EpsNetworkPrerequisites -Ctx $ctx)
    if ($pre.Count) { Finish 2 ("`nNot ready for the private network install - NOTHING was created. Missing ($($pre.Count)):`n" + (($pre | ForEach-Object { "  - $_" }) -join "`n") + "`nFix these (your network team creates them) and run the same command again." + $(if ($ctx.Network.ZonesRgId) { "`nOr leave out -PrivateDnsZonesResourceGroupId and the install makes and links its own private DNS zones." })) }
    Write-Host 'Private network: every prerequisite is there (network, subnets, hub, DNS zones).' -ForegroundColor Green
}
if ($what) {
    [void](Invoke-EpsInstall -Ctx $ctx -WhatIf -Completed $completed -OnStep $print)
    Finish 0 "`nWhatIf: nothing was changed. Run again without -WhatIf to install."
}

foreach ($p in $unregistered) { [void](Invoke-EpsArm -Method POST -Path "/subscriptions/$SubscriptionId/providers/$p/register" -ApiVersion '2021-04-01' -Body @{}); Write-Host "  registered $p" }
New-Item -ItemType Directory -Force -Path $StatePath | Out-Null
$journal = { param($e) & $print $e
    if ($e.State -eq 'ok') { [ordered]@{ schema = 1; product = 'EntraPolicySuite'; version = $version; resourceGroup = $ResourceGroup; completed = @($e.Completed); updatedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding utf8 } }
try { [void](Invoke-EpsInstall -Ctx $ctx -Completed $completed -OnStep $journal) }
catch {
    $m = "$($_.Exception.Message)"
    # found live 2026-10-30: a new subscription may be refused a region ("not accepting new customers")
    $hint = if ($m -match '(?i)Microsoft.Sql/servers.*not accepting creation') { "`nAzure SQL does not take new servers in '$(if ($SqlLocation) { $SqlLocation } else { $Location })' now: run again with -SqlLocation <another region> (e.g. swedencentral) - the steps already done are kept." } elseif ($m -match '(?i)locationineligible|not accepting new customers|SkuNotAvailable|LocationNotAvailableForResourceType') { "`nAzure does not take new resources in '$Location' for this subscription: run again with another -Location (e.g. northeurope, swedencentral) - the steps already done are kept." } else { '' }
    if ($ctx.Network.Private -and -not $ctx.Network.HandoffPath -and (Test-Path -LiteralPath (Join-Path $StatePath 'network-hand-off.txt'))) { $ctx.Network.HandoffPath = Join-Path $StatePath 'network-hand-off.txt' }
    if ($ctx.Network.HandoffPath) { $hint += "`nThe network hand-off for your network team: $($ctx.Network.HandoffPath)$(if ($ctx.Network.HubScriptPath) { " (and the hub owner's script $($ctx.Network.HubScriptPath))" })" }
    Finish 1 "`nThe install stopped: $m$hint`nFix the cause and run the same command again - it resumes ($stateFile)."
}
if ($ctx.Network.Private) {
    # written again at the end: it then shows the final state (a resumed run may have skipped the step)
    try { Invoke-EpsHandoffStep -Ctx $ctx } catch { Write-Warning "the network hand-off could not be written: $($_.Exception.Message)" }
    Write-Host "`n---- network hand-off ($($ctx.Network.HandoffPath)) ----" -ForegroundColor Cyan
    Write-Host $ctx.Network.HandoffText
    Write-Host "Proven from inside the network: $($ctx.Network.InsideCheck.How)" -ForegroundColor Cyan
}
# finished: the journal is only for resuming a STOPPED install - kept, a re-run of the same version would skip every
# step (2.0.7 live 2026-11-01: a re-run to re-apply the grants did nothing)
Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
$url = if ($ctx.Web -and $ctx.Web.Url) { "`nThe web app: $($ctx.Web.Url) - sign in as $($person.Upn) (its first SuperAdmin); others need an assignment to the '$($names.WebAppRegistration)' enterprise application and a role on the Access page." } else { '' }
Finish 0 "`nEntraPolicySuite $version is installed in $ResourceGroup. Every feature is off; switch one on in the settings, preview, then go live.$url"
