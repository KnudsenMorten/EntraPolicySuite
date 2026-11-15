#Requires -Version 7.2
<#
.SYNOPSIS
    Gives Entra Policy Suite's engine the least Exchange right it needs: write the tag attributes (CustomAttribute1-15)
    and read recipients - nothing else.
.DESCRIPTION
    Run it as an Exchange administrator. Step 1 (the default): creates the custom management role 'EPS Tag Writer'
    (from 'Mail Recipients', pared to Get-Recipient, Set-Mailbox and Set-MailUser, the two Set cmdlets limited to
    -Identity and -CustomAttribute1 to -CustomAttribute15), a role group 'EPS Tag Writers' with that role, and makes the
    engine's managed identity its member. Every step is read back. The engine's Entra role Exchange Recipient
    Administrator stays until step 2.
    Step 2 (-RemoveRecipientAdministrator): ONLY after the engine's next tag write went through - removes the engine's
    Entra role Exchange Recipient Administrator (organization-wide) and reads it back. From then on the engine can change
    nothing in Exchange but the tag attributes.
    You sign in in a browser (no module). -WhatIf: the plan, nothing changed.
.EXAMPLE
    ./Initialize-EpsExchangeTagRole.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.EXAMPLE
    ./Initialize-EpsExchangeTagRole.ps1 -TenantId <tenant> -SubscriptionId <sub> -RemoveRecipientAdministrator
.LINK
    https://invardia.com/docs/eps/scripts/Initialize-EpsExchangeTagRole
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = '',
    [switch]$RemoveRecipientAdministrator
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Exchange', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-ExchangeTagRole') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi) { throw "no engine identity $($names.EngineIdentity) in $ResourceGroup - is Entra Policy Suite installed there?" }
$appId = [string]$mi.properties.clientId; $oid = [string]$mi.properties.principalId

if ($RemoveRecipientAdministrator) {
    $ra = @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$oid' and roleDefinitionId eq '$($script:EpsExchangeRecipientAdminRole)'" -All)
    $st = Get-EpsTagRoleState -TenantId "$TenantId"; $plan = Get-EpsTagRolePlan -AppId $appId -ObjectId $oid -DisplayName $names.EngineIdentity -State $st
    if ($plan.Steps.Count) { throw "the role group '$($script:EpsTagRole.Group)' is not complete yet ($(@($plan.Steps | ForEach-Object What) -join '; ')) - run step 1 first; the Entra role is kept" }
    Write-Host "Remove $($names.EngineIdentity)'s Entra role Exchange Recipient Administrator ($($ra.Count) assignment(s))" -ForegroundColor Cyan
    if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }
    foreach ($a in $ra) { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/roleManagement/directory/roleAssignments/$($a.id)") }
    Start-Sleep -Seconds 15
    $left = @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$oid' and roleDefinitionId eq '$($script:EpsExchangeRecipientAdminRole)'" -All)
    if ($left.Count) { throw "the Entra role is still assigned after the removal ($($left.Count)) - run it again" }
    Write-Host "`nDone: $($names.EngineIdentity) holds no Entra Exchange role; it writes only the tag attributes through '$($script:EpsTagRole.Group)'." -ForegroundColor Green
    return
}

$st = Get-EpsTagRoleState -TenantId "$TenantId"
$plan = Get-EpsTagRolePlan -AppId $appId -ObjectId $oid -DisplayName $names.EngineIdentity -State $st
Write-Host "The engine's Exchange right for $($names.EngineIdentity) ($appId): role '$($script:EpsTagRole.Name)', group '$($script:EpsTagRole.Group)'" -ForegroundColor Cyan
if (-not $plan.Steps.Count) { Write-Host '  everything is in place' -ForegroundColor DarkGray }
foreach ($s in $plan.Steps) { Write-Host "  $($s.What)" }
if ($plan.Again) { Write-Host '  (then the role''s copied entries are pared - shown when the role exists)' -ForegroundColor DarkGray }
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }
$done = Invoke-EpsTagRolePlan -TenantId "$TenantId" -AppId $appId -ObjectId $oid -DisplayName $names.EngineIdentity
Write-Host "  $($done.Count) step(s) made and read back" -ForegroundColor DarkGray
Write-Host "`nStep 1 done. After the engine's next user tagging run wrote its tags, run this again with -RemoveRecipientAdministrator." -ForegroundColor Green
