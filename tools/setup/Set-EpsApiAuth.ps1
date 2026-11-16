#Requires -Version 7.2
<#
.SYNOPSIS
    Lets an application call the Entra Policy Suite API for applications - the Invardia Support app on a support ticket
    (-SupportApp), or one of your own programs (-AppId) - or stops it (-Remove). Every change is read back.
.DESCRIPTION
    Two layers decide whether an application may call the API, and both must agree:
      1. Entra (this script): the registration's app role EPS.Api.Call, assigned to the application. Only an assigned
         application gets a token at all ("assignment required" stays on).
      2. Entra Policy Suite: what that application may do there - for the Invardia Support app, the update enrols it by
         its InvardiaSupport tag (fixes only, on a ticket); for your own program, a SuperAdmin adds "<app id>:Reader" or
         "<app id>:Admin" under Administration > Settings > Security > API applications.
    Support fixes are ON REQUEST ONLY: run -SupportApp when you have asked Invardia to fix things for you, never by default.
    The script also makes sure the registration has what the API for applications needs (the app role, the idtyp claim,
    v2 tokens) - the same as an install run does. Your program signs in with a certificate, a managed identity or a
    federated credential - never a client secret.
    You sign in in a browser (no module). -WhatIf: what is there and what would change - nothing is changed.
.EXAMPLE
    ./Set-EpsApiAuth.ps1 -TenantId <tenant> -SubscriptionId <sub> -SupportApp
.EXAMPLE
    ./Set-EpsApiAuth.ps1 -TenantId <tenant> -SubscriptionId <sub> -AppId <your program's app id>
.EXAMPLE
    ./Set-EpsApiAuth.ps1 -TenantId <tenant> -SubscriptionId <sub> -SupportApp -Remove
.LINK
    https://invardia.com/docs/eps/scripts/Set-EpsApiAuth
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Support')]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = '',
    [Parameter(Mandatory, ParameterSetName = 'Support')][switch]$SupportApp,
    [Parameter(Mandatory, ParameterSetName = 'App')][guid]$AppId,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Set-EpsApiAuth when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-InstallWeb') { . (Join-Path $sol "engine\_shared\$f.ps1") }
# CLOSED (owner 2026-11-16): the API for applications is switched off in this release - nothing is set up or changed
if ($script:EpsAppApiOpen -ne $true) { Write-Host 'The API for applications is closed in this release of Entra Policy Suite - nothing is changed.' -ForegroundColor Yellow; exit 3 }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
$say = { param($status, $text, $color = 'Gray') Write-Host ("  {0,-18} {1}" -f $status, $text) -ForegroundColor $color }

if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup

# the Entra Policy Suite registration (found by the install's tag) and its enterprise application
$web = Find-EpsWebAppRegistration -Tag "eps-install-$($names.Suffix)"
if (-not $web) { Write-Host "No Entra Policy Suite registration (tag eps-install-$($names.Suffix)) in this tenant - is Entra Policy Suite installed in $ResourceGroup?" -ForegroundColor Red; exit 2 }
$epsSp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($web.appId)'&`$select=id,appRoleAssignmentRequired,displayName" -All)[0]
if (-not $epsSp) { Write-Host "The registration $($web.appId) has no enterprise application - run the install once." -ForegroundColor Red; exit 2 }
Write-Host "Entra Policy Suite: $($web.displayName) (app id $($web.appId))" -ForegroundColor Cyan
Write-Host $(if ($what) { 'Plan (WhatIf - nothing is changed):' } else { 'Result:' }) -ForegroundColor Cyan
$failed = $false

# layer 1 on the registration: the app role, the idtyp claim, v2 tokens; assignment required
$p = Get-EpsWebApiAuthPatch -App $web
if ($p.Patch) {
    if ($what) { & $say 'would set' "the registration: $($p.Missing -join ', ')" 'Yellow' }
    else {
        [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($web.id)" -Body $p.Patch)
        $back = $null; foreach ($w in 0, 5, 10, 20, 30) { if ($w) { Start-Sleep -Seconds $w }; $back = Get-EpsWebApiAuthPatch -App (Invoke-EpsGraph -Path "v1.0/applications/$($web.id)?`$select=id,api,appRoles,optionalClaims"); if (-not $back.Patch) { break } }
        if ($back.Patch) { & $say 'refused' "the registration still misses: $($back.Missing -join ', ')" 'Red'; $failed = $true } else { & $say 'set' "the registration: $($p.Missing -join ', ') (read back)" 'Green' }
    }
} else { & $say 'already there' "the registration: the app role $script:EpsApiAppRoleValue, the idtyp claim, v2 tokens" }
if (-not $epsSp.appRoleAssignmentRequired) {
    if ($what) { & $say 'would set' 'assignment required on the enterprise application' 'Yellow' }
    else { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/servicePrincipals/$($epsSp.id)" -Body @{ appRoleAssignmentRequired = $true }); & $say 'set' 'assignment required on the enterprise application' 'Green' }
} else { & $say 'already there' 'assignment required on the enterprise application' }
$web = Find-EpsWebAppRegistration -Tag "eps-install-$($names.Suffix)"
$roleId = "$(@(@($web.appRoles) | Where-Object { "$($_.value)" -eq $script:EpsApiAppRoleValue })[0].id)"
if (-not $roleId) { $roleId = $script:EpsApiAppRoleId }

# the application
$sel = '$select=id,appId,displayName,tags'
if ($SupportApp) {
    $t = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=tags/any(t:t eq 'InvardiaSupport')&$sel" -All)
    if (-not $t.Count) { foreach ($a in @(Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:t eq 'InvardiaSupport')&`$select=appId" -All)) { $t += @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($a.appId)'&$sel" -All) } }
    if ($t.Count -ne 1) { Write-Host $(if ($t.Count) { "$($t.Count) applications carry the InvardiaSupport tag - exactly one must. Remove the tag from the one that is not Invardia's, then run this again." } else { 'No application carries the InvardiaSupport tag: support is not enabled in this tenant yet (New-InvardiaSupportApp.ps1).' }) -ForegroundColor Red; exit 2 }
    $target = $t[0]
} else {
    $target = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$AppId'&$sel" -All)[0]
    if (-not $target) { Write-Host "No enterprise application for app id $AppId in this tenant." -ForegroundColor Red; exit 2 }
}
Write-Host "Application: $($target.displayName) (app id $($target.appId))" -ForegroundColor Cyan
$have = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($epsSp.id)/appRoleAssignedTo" -All | Where-Object { "$($_.principalId)" -eq "$($target.id)" -and "$($_.appRoleId)" -eq $roleId })
if ($Remove) {
    if (-not $have.Count) { & $say 'not there' "$script:EpsApiAppRoleValue for $($target.displayName)" }
    elseif ($what) { & $say 'would remove' "$script:EpsApiAppRoleValue for $($target.displayName)" 'Yellow' }
    else {
        foreach ($x in $have) { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/servicePrincipals/$($epsSp.id)/appRoleAssignedTo/$($x.id)") }
        $still = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($epsSp.id)/appRoleAssignedTo" -All | Where-Object { "$($_.principalId)" -eq "$($target.id)" -and "$($_.appRoleId)" -eq $roleId })
        if ($still.Count) { & $say 'refused' 'the assignment is still there' 'Red'; $failed = $true } else { & $say 'removed' "$script:EpsApiAppRoleValue for $($target.displayName) (read back) - its next token is refused" 'Green' }
    }
} else {
    if ($have.Count) { & $say 'already there' "$script:EpsApiAppRoleValue for $($target.displayName)" }
    elseif ($what) { & $say 'would assign' "$script:EpsApiAppRoleValue to $($target.displayName)" 'Yellow' }
    else {
        [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$($epsSp.id)/appRoleAssignedTo" -Body @{ principalId = $target.id; resourceId = $epsSp.id; appRoleId = $roleId })
        $back = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($epsSp.id)/appRoleAssignedTo" -All | Where-Object { "$($_.principalId)" -eq "$($target.id)" -and "$($_.appRoleId)" -eq $roleId })
        if ($back.Count) { & $say 'assigned' "$script:EpsApiAppRoleValue to $($target.displayName) (read back)" 'Green' } else { & $say 'refused' 'the assignment does not read back' 'Red'; $failed = $true }
    }
}
Write-Host ''
if ($Remove) { Write-Host 'Done. Entra Policy Suite refuses this application from its next token.' -ForegroundColor Yellow }
elseif ($SupportApp) { Write-Host 'Support fixes are switched on: the next update run enrols the Invardia Support app (it applies only the fixes Entra Policy Suite offers for a failure, on a ticket, audited and mailed). Undo: run again with -Remove.' -ForegroundColor Yellow }
else { Write-Host "Next: a SuperAdmin adds '$($target.appId):Reader' (or ':Admin') under Administration > Settings > Security > API applications. Both are needed." -ForegroundColor Yellow }
if ($failed) { exit 1 }
