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
.EXAMPLE
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -WhatIf
.EXAMPLE
    ./Install-EntraPolicySuite.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
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
    [ValidateSet('User.ReadWrite.All', 'Device.ReadWrite.All', 'GroupMember.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'DeviceManagementManagedDevices.Read.All', 'Application.Read.All')][string[]]$ExcludeGraphRole = @(),
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
$docUrl = 'https://invardia.com/docs/eps/scripts/Install-EntraPolicySuite'
Write-Host "Documentation: $docUrl"
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim()
$what = [bool]$WhatIfPreference
$WhatIfPreference = $false   # the install decides what -WhatIf means: read, plan, change nothing (its own calls stay real reads)
function Finish([int]$code, [string]$msg) { if ($msg) { Write-Host $msg -ForegroundColor $(if ($code) { 'Red' } else { 'Green' }) }; exit $code }

# ---- sign in (a Support-app session or a test can provide the token source instead) ----
$person = if ($global:EPS_TokenProvider -and $global:EPS_InstallPerson) { $global:EPS_InstallPerson } else { Connect-EpsSignedIn -TenantId "$TenantId" }
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
$unregistered = if ($rgOnly) { @() } else { @(foreach ($p in $need) { $r = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/providers/$p" -ApiVersion '2021-04-01'; if ($r.registrationState -ne 'Registered') { $p } }) }
if ($rgOnly) { Write-Host "Rights on resource group $ResourceGroup only: the resource providers ($($need -join ', ')) are taken as registered (they cannot be checked or registered without a subscription right)." -ForegroundColor Yellow }

$names = Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
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
    Finish 1 "`nThe install stopped: $m$hint`nFix the cause and run the same command again - it resumes ($stateFile)."
}
# finished: the journal is only for resuming a STOPPED install - kept, a re-run of the same version would skip every
# step (2.0.7 live 2026-11-01: a re-run to re-apply the grants did nothing)
Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
$url = if ($ctx.Web -and $ctx.Web.Url) { "`nThe web app: $($ctx.Web.Url) - sign in as $($person.Upn) (its first SuperAdmin); others need an assignment to the '$($names.WebAppRegistration)' enterprise application and a role on the Access page." } else { '' }
Finish 0 "`nEntraPolicySuite $version is installed in $ResourceGroup. Every feature is off; switch one on in the settings, preview, then go live.$url"
