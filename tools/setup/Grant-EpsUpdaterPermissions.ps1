#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the Entra Policy Suite update identity (id-eps-updater) the Microsoft Graph permissions it is missing - or takes
    one away with -Remove. Every grant is read back.
.DESCRIPTION
    The install grants the update identity its rights once. The update job never grants itself a right, so run this
    when one is missing afterwards (the install ran as an account that could not grant it, or a release declares a new
    one). Only the rights Entra Policy Suite declares for its updater can be granted - anything else is refused:
    PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup and .Read.AzureADGroup, RoleManagementPolicy.Read.AzureADGroup
    (it keeps the database setup identity in the SQL admin group), GroupMember.Read.All and Application.Read.All (it reads
    them back) and Application.ReadWrite.OwnedBy (it keeps the web app's sign-in registration it owns as it should be).
    -GraphPermission: the permissions (none given: every one the updater needs).
    You sign in in a browser (no module). -WhatIf: the plan - what is there, what would be granted or removed - nothing
    changed. It prints per right: granted / already there / removed / not there / refused (with the reason), and exits 1
    when anything was refused. A new grant reaches the update identity's token within about 30 minutes.
.EXAMPLE
    ./Grant-EpsUpdaterPermissions.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.EXAMPLE
    ./Grant-EpsUpdaterPermissions.ps1 -TenantId <tenant> -SubscriptionId <sub> -GraphPermission Application.ReadWrite.OwnedBy
.LINK
    https://invardia.com/docs/eps/scripts/Grant-EpsUpdaterPermissions
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = '',
    [string[]]$GraphPermission = @(),
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Grant-EpsUpdaterPermissions when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-EnginePermissions') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false

# the request: only rights Entra Policy Suite declares for its updater (least privilege - never a free-form permission)
$req = Get-EpsUpdaterPermissionRequest -GraphPermission $GraphPermission -Remove:$Remove
if (-not $req.Ok) { Write-Host $req.Reason -ForegroundColor Red; exit 2 }

# a Support-app session that already provides the sign-in for THIS tenant is used; otherwise the person signs in
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.UpdaterIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi -or "$($mi.properties.principalId)" -notmatch '^[0-9a-fA-F-]{36}$') { Write-Host "No update identity $($names.UpdaterIdentity) in $ResourceGroup - is Entra Policy Suite installed there (2.0.60 or later)?" -ForegroundColor Red; exit 2 }
$updater = "$($mi.properties.principalId)"
Write-Host "Update identity: $($names.UpdaterIdentity) (object id $updater) - $(if ($Remove) { 'remove' } else { 'grant' }): $(@($req.Items | ForEach-Object What) -join ', ')" -ForegroundColor Cyan

$rows = Invoke-EpsEnginePermissionPlan -EngineObjectId $updater -Request $req -PlanOnly:$what
Write-Host ''
Write-Host $(if ($what) { 'Plan (WhatIf - nothing was changed):' } else { 'Result:' }) -ForegroundColor Cyan
foreach ($r in $rows) {
    $c = switch -Regex ($r.Status) { '^refused' { 'Red' } '^(granted|removed)$' { 'Green' } '^would' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  {0,-16} {1}{2}" -f $r.Status, $r.What, $(if ($r.Reason) { " - $($r.Reason)" })) -ForegroundColor $c
}
if (@($rows | Where-Object Status -eq 'granted').Count) { Write-Host "`nA new grant reaches the update identity's token within about 30 minutes." -ForegroundColor Yellow }
if (@($rows | Where-Object Status -eq 'refused').Count) { exit 1 }
