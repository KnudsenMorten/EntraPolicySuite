#Requires -Version 7.2
<#
.SYNOPSIS
    Installs Entra Policy Suite 2.0 in your own Azure subscription (Container Apps + Azure SQL), as yourself, in a browser.
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
    -WhatIf shows every step and what it would create, and changes nothing. A failed install resumes where it stopped. Exit code: 0 done, 1 a step failed, 2 a check failed (nothing was created), 4 waiting for a step of yours (DNS records, a check from inside your network) - run the same command again when it is done.

    PUBLIC (the default): the web app has a public HTTPS address behind the Entra sign-in; Azure SQL, Key Vault, the job
    queues and the registry use their public endpoints, protected by Entra sign-in and managed identities.
    PRIVATE (-PrivateNetwork): everything runs in your virtual network. The Container Apps environment is created in its
    own subnet with no public address (the web app is reachable from your network only, still behind the sign-in);
    Azure SQL, Key Vault, the job queues and the registry (Premium) are CREATED with public access off and reached
    through private endpoints with private DNS zones. Run a private install from a machine INSIDE your network (or one
    that resolves its private names): the image upload and the database steps run from the machine that runs the
    install. Before them the install checks DNS from this machine and, when a name does not resolve to its private
    endpoint, WAITS (exit 4) and prints the exact A records your hub needs - run the same command again afterwards; it resumes.
    At the end a one-time check INSIDE the network (a job in the environment) proves private DNS, the web app and every
    job queue; only then is the install reported as done. The network hand-off list (peering, DNS zones and records, the
    outbound hosts, the check to run) is printed and written to network-hand-off.txt in the state folder, and with
    -HubVnetId a script for the hub owner (prepare-hub-entrapolicysuite.ps1) next to it.
    Outbound from the network the jobs reach graph.microsoft.com, login.microsoftonline.com, outlook.office365.com,
    management.azure.com and invardia.com (default outbound, or allow them on your firewall). The registry's build pool
    runs in the endpoints subnet and needs a way out too (mcr.microsoft.com for the base images): a subnet the install
    makes has default outbound access on; your own subnet needs a NAT gateway, a 0.0.0.0/0 route to your firewall, or
    default outbound access - the install checks it before it creates anything.
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
    Default: rg-eps for a new install; an existing install in rg-entrapolicysuite (the default before 2.0.55) keeps it.
.PARAMETER SqlLocation
    The Azure SQL server's region, when Azure SQL does not take new servers in -Location. Default: -Location.
.PARAMETER SqlAdminGroupId
    The object id of YOUR admin group (Entra security group) to be the Azure SQL server's Entra admin. Without it a new
    server gets the group grp-eps-sql-admins (found, else created). Either way the install adds the database setup job's
    identity id-eps-dbinit to the group and the job does the database work - you need no SQL right. An EXISTING server
    always keeps the admin it has - a re-run never changes it (a group admin gets id-eps-dbinit added).
.PARAMETER SqlAdminGroupName
    The display name of that group (shown as the SQL admin).
.PARAMETER Ring
    The update ring this install belongs to (0-10; framework §3), reported on the heartbeat (TEL-01). Invardia tells you
    the ring. Empty: a re-run keeps the ring the install has; a first install reports none.
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
.PARAMETER InternalRanges
    Your internal address ranges (e.g. 10.0.0.0/8, 192.168.0.0/16) that reach the web app through your hub firewall.
    With -FirewallIp, on a network the install makes, it creates the route table rt-eps on the apps subnet: each range
    -> your firewall, so the replies go back the way the requests came (without it they time out). On your own network
    the route is on the network hand-off list.
.PARAMETER FirewallIp
    Your hub firewall's private address, the next hop of the return route (see -InternalRanges).
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
    # the install: two lines. The launcher downloads the release, checks it and runs this script with the same parameters
    # (add -WhatIf at the end of line 2 to see the plan first; nothing is created in Azure)
    Invoke-WebRequest https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1 -OutFile Start-EpsInstall.ps1
    ./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
.EXAMPLE
    # private, in a network the install makes (10.230.0.0/24), the hub given for an exact hand-off list (line 1 as above)
    ./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PrivateNetwork -HubVnetId <hub network id>
.EXAMPLE
    # private, in your own spoke network, your central DNS zones, the peering made by the install (line 1 as above)
    ./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PrivateNetwork -VnetId <network id> -AppsSubnetName snet-eps-apps -EndpointsSubnetName snet-eps-endpoints -PrivateDnsZonesResourceGroupId <zones resource group id> -HubVnetId <hub network id> -PeerToHub
.LINK
    https://invardia.com/docs/eps/scripts/Install-EntraPolicySuite
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [ValidatePattern('^[a-z0-9]{3,30}$')][string]$Location = 'westeurope',
    [ValidatePattern('^[A-Za-z0-9._()-]{0,80}$')][string]$ResourceGroup = '',
    [string]$StatePath,
    # the Azure SQL server's region when it differs from -Location (Azure SQL can refuse new servers in a region that
    # takes everything else - North Europe, 2026-10-30). Default: -Location.
    [ValidatePattern('^$|^[a-z0-9]{3,30}$')][string]$SqlLocation = '',
    # the customer's admin group as the SQL server's Entra admin (framework §12.23 P5); an existing server keeps its admin
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$SqlAdminGroupId = '',
    [ValidatePattern('^$|^[^\x00-\x1f]{1,120}$')][string]$SqlAdminGroupName = '',
    # the update ring (framework §3; TEL-01: the heartbeat's Ring) - empty = keep the install's, or none
    [ValidatePattern('^$|^([0-9]|10)$')][string]$Ring = '',
    # a Graph role of the engine that the approver did not approve: never granted (the feature that needs it then
    # reports its data as unavailable). e.g. -ExcludeGraphRole Organization.Read.All
    [ValidateSet('User.ReadWrite.All', 'Device.ReadWrite.All', 'GroupMember.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'DeviceManagementManagedDevices.Read.All', 'Application.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Group.ReadWrite.All', 'AdministrativeUnit.ReadWrite.All', 'Policy.ReadWrite.AuthenticationMethod')][string[]]$ExcludeGraphRole = @(),
    [switch]$Quiet,
    # the Invardia Support app, named by its client id - never found by name (as SI / PIM). It then starts with
    # -SupportAccess (default troubleshoot: read, plus admin only during an open support session); without it nothing is
    # granted at the install. From then on the level your organization sets in the Invardia portal applies.
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [ValidateSet('troubleshoot', 'setup', 'read', 'none')][string]$SupportAccess = 'troubleshoot',
    # continue an interrupted install with the same values (finished steps are skipped); refused when there is none
    [switch]$Resume,
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
    [string[]]$InternalRanges = @(),
    [string]$FirewallIp = '',
    [ValidateSet('external', 'internal')][string]$WebAppAccess = 'external',
    [switch]$ConfirmedFromInside
)
$ErrorActionPreference = 'Stop'
$docUrl = 'https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Install-EntraPolicySuite when EPS is public there (DOC-LINKS)
Write-Host "Documentation: $docUrl"
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-Onboarding', 'EPS-EnginePermissions') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim()
$what = [bool]$WhatIfPreference
$WhatIfPreference = $false   # the install decides what -WhatIf means: read, plan, change nothing (its own calls stay real reads)
function Finish([int]$code, [string]$msg) { if ($msg) { Write-Host $msg -ForegroundColor $(if ($code -eq 4) { 'Yellow' } elseif ($code) { 'Red' } else { 'Green' }) }; exit $code }

# ---- the network parameters (NET-1): checked before the sign-in, a wrong range or id is refused (exit 2) ----
$netPlan = Get-EpsNetworkPlan -P @{ PrivateNetwork = [bool]$PrivateNetwork; VnetId = $VnetId; VnetAddressPrefix = $VnetAddressPrefix; VnetName = $VnetName
    AppsSubnetName = $AppsSubnetName; AppsSubnetPrefix = $AppsSubnetPrefix; EndpointsSubnetName = $EndpointsSubnetName; EndpointsSubnetPrefix = $EndpointsSubnetPrefix
    PrivateDnsZonesResourceGroupId = $PrivateDnsZonesResourceGroupId; HubVnetId = $HubVnetId; LinkZonesToHub = [bool]$LinkZonesToHub; PeerToHub = [bool]$PeerToHub
    InternalRanges = @($InternalRanges); FirewallIp = $FirewallIp
    WebAppAccess = $WebAppAccess; ConfirmedFromInside = [bool]$ConfirmedFromInside } -Bound @($PSBoundParameters.Keys)
if (-not $netPlan.Ok) { Finish 2 "Refused: $($netPlan.Reason)" }

# ---- sign in (a Support-app session or a test can provide the token source instead) ----
$person = if ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and (-not "$($global:EPS_SignInTenant)" -or "$($global:EPS_SignInTenant)" -eq "$TenantId")) { $global:EPS_InstallPerson } else { Connect-EpsSignedIn -TenantId "$TenantId" }
Write-Host "Signed in as $($person.Upn)" -ForegroundColor Cyan
# framework §5.5 (owner 2026-11-04, OPEN-30): a new install goes in rg-eps; an install in the old default
# rg-entrapolicysuite keeps it, so a re-run without -ResourceGroup never starts a second install next to it
if (-not $ResourceGroup) {
    $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"
    if (-not $rgPick.Ok) { Finish 2 "Refused: $($rgPick.Reason)." }
    $ResourceGroup = $rgPick.Name
    if ($rgPick.Reason) { Write-Host "Resource group $ResourceGroup`: $($rgPick.Reason)." -ForegroundColor Cyan }
}

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

$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup -Private:([bool]$netPlan.Private)
if ($names.Legacy) { Write-Host "An install made before 2.0.55: it keeps its Azure resource names (suffix $($names.Suffix))." -ForegroundColor Cyan }
if (-not $netPlan.Private) {
    # a private install stays private: a run without -PrivateNetwork would put a public environment next to it
    $privEnv = (Get-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup -Private -Legacy:([bool]$names.Legacy)).Environment
    $pe = try { Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/managedEnvironments/$privEnv" -ApiVersion '2024-03-01' -AllowNotFound } catch { $null }
    if ($pe -and "$($pe.name)" -eq $privEnv) { Finish 2 "$ResourceGroup holds a PRIVATE install ($privEnv): run the same command with -PrivateNetwork (and its network parameters)." }
}
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Location = $Location; Names = $names; Version = $version; SolutionRoot = $sol; Person = $person; Identities = @{}; ExcludeGraphRoles = @($ExcludeGraphRole); Ring = $Ring; SqlLocation = $SqlLocation
    SqlAdminGroup = $(if ($SqlAdminGroupId) { @{ ObjectId = $SqlAdminGroupId.ToLowerInvariant(); Name = $(if ($SqlAdminGroupName) { $SqlAdminGroupName } else { "group $SqlAdminGroupId" }) } }) }
# the web app's sign-in front is built from the source this release carries, at the version it pins - checked BEFORE
# anything is created, so an install never stops half-way for it
$front = Get-EpsSigninFrontSource -SolutionRoot $sol -Pin (Get-EpsSigninFrontPin -SolutionRoot $sol)
if (-not $front.Ok -and -not $what) { Finish 2 "The web app's sign-in front cannot be built: $($front.Reason). Use a complete Entra Policy Suite release." }

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
# -Resume (as SI / PIM): only when an interrupted install of THIS version and resource group is there to continue
if ($Resume -and -not $completed.Count) { Write-Host "Nothing to resume: no interrupted install of $version in $ResourceGroup ($stateFile). Run the same command without -Resume to install." -ForegroundColor Red; exit 2 }
# the Invardia Support app's starting level (the database setup job writes it once, only when no level is there yet)
if ($SupportAppId) { $ctx.SupportSeed = @{ AppId = $SupportAppId.ToLowerInvariant(); Level = $(if ($SupportAccess -eq 'setup') { 'troubleshoot' } else { $SupportAccess }) } }

Write-Host ''
Write-Host "Entra Policy Suite $version -> subscription $($subInfo.displayName) ($SubscriptionId), $ResourceGroup, $Location" -ForegroundColor Cyan
if ($unregistered) { Write-Host "Resource providers to register: $($unregistered -join ', ')" -ForegroundColor Yellow }
$print = { param($e) if (-not $Quiet) {
    $c = switch ($e.State) { 'ok' { 'Green' } 'failed' { 'Red' } 'waiting' { 'Yellow' } 'plan' { 'Gray' } 'skipped' { 'DarkGray' } default { 'Cyan' } }
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
    foreach ($w in @($ctx.Network.Warnings)) { if ($w) { Write-Host "WARNING - a task for your network team: $w" -ForegroundColor Yellow } }
    Write-Host "Private network: every prerequisite is there (network, subnets, hub, DNS zones)$(if (@($ctx.Network.Warnings).Count) { ' - except the tasks above, which the install does not need to go on' })." -ForegroundColor Green
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
    # framework rule 14: waiting is not a failure - its own exit code (4), its own words
    if ($m.StartsWith('EPS-WAITING: ')) { Finish 4 "`nThe install is WAITING (nothing failed): $($m.Substring(13))$hint`nWhen that is done, run the same command again - it resumes here ($stateFile)." }
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
# the standard identity names (framework §12.11c): what this run renamed in place, read back
if ($ctx.Renamed -and $ctx.Renamed.Count) { Write-Host "`nChanged to the standard (each read back):" -ForegroundColor Cyan; foreach ($r in $ctx.Renamed) { Write-Host "  $r" } }
Finish 0 "`nEntra Policy Suite $version is installed in $ResourceGroup. Every feature is off; switch one on in the settings, preview, then go live.$url"
