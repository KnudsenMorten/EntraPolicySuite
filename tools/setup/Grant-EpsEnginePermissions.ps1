#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the Entra Policy Suite engine identity (id-eps-engine) the Microsoft Graph permissions and the Exchange right it
    is missing - or takes one away with -Remove. Every grant is read back.
.DESCRIPTION
    The install grants the engine its rights once. Run this when a right is missing afterwards (an approver granted it
    later, a feature is switched on that needs it, the install ran as an account that could not grant it) or to take a
    right away that a feature no longer needs. Only the rights Entra Policy Suite declares for its engine can be granted -
    anything else is refused.
    -GraphPermission: the Graph application permissions (none given: every one the engine needs). -Exchange: the
    Exchange right of the recipient conditions - the application permission Exchange.ManageAsApp plus the Entra role
    Exchange Recipient Administrator.
    You sign in in a browser (no module). -WhatIf: the plan - what is there, what would be granted or removed - nothing
    changed. It prints per right: granted / already there / removed / not there / refused (with the reason), and exits 1
    when anything was refused. A new grant reaches the engine's token within about 30 minutes.
.EXAMPLE
    ./Grant-EpsEnginePermissions.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.EXAMPLE
    ./Grant-EpsEnginePermissions.ps1 -TenantId <tenant> -SubscriptionId <sub> -GraphPermission Organization.Read.All
.EXAMPLE
    ./Grant-EpsEnginePermissions.ps1 -TenantId <tenant> -SubscriptionId <sub> -Exchange -Remove
.LINK
    https://invardia.com/docs/eps/scripts/Grant-EpsEnginePermissions
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = 'rg-entrapolicysuite',
    [string[]]$GraphPermission = @(),
    [switch]$Exchange,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Grant-EpsEnginePermissions when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-EnginePermissions') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false

# the request: only rights Entra Policy Suite declares for its engine (least privilege - never a free-form permission)
$req = Get-EpsEnginePermissionRequest -GraphPermission $GraphPermission -Exchange:$Exchange -Remove:$Remove
if (-not $req.Ok) { Write-Host $req.Reason -ForegroundColor Red; exit 2 }

# a Support-app session that already provides the sign-in for THIS tenant is used; otherwise the person signs in
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
$names = Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi -or "$($mi.properties.principalId)" -notmatch '^[0-9a-fA-F-]{36}$') { Write-Host "No engine identity $($names.EngineIdentity) in $ResourceGroup - is Entra Policy Suite installed there?" -ForegroundColor Red; exit 2 }
$engine = "$($mi.properties.principalId)"
Write-Host "Engine identity: $($names.EngineIdentity) (object id $engine) - $(if ($Remove) { 'remove' } else { 'grant' }): $(@($req.Items | ForEach-Object What) -join ', ')" -ForegroundColor Cyan

$rows = Invoke-EpsEnginePermissionPlan -EngineObjectId $engine -Request $req -PlanOnly:$what
Write-Host ''
Write-Host $(if ($what) { 'Plan (WhatIf - nothing was changed):' } else { 'Result:' }) -ForegroundColor Cyan
foreach ($r in $rows) {
    $c = switch -Regex ($r.Status) { '^refused' { 'Red' } '^(granted|removed)$' { 'Green' } '^would' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  {0,-16} {1}{2}" -f $r.Status, $r.What, $(if ($r.Reason) { " - $($r.Reason)" })) -ForegroundColor $c
}
if (@($rows | Where-Object Status -eq 'granted').Count) { Write-Host "`nA new grant reaches the engine's token within about 30 minutes." -ForegroundColor Yellow }
if (@($rows | Where-Object Status -eq 'refused').Count) { exit 1 }
