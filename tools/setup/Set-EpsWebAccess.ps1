#Requires -Version 7.2
<#
.SYNOPSIS
    Names who may use the Entra Policy Suite web app: SuperAdmin, Admin or Reader. Used once to name the first SuperAdmin.
.DESCRIPTION
    The web app's access list (eps.WebAccess) is managed in the app itself by a SuperAdmin. When there is none - every
    SuperAdmin has left - this script names one: it starts the install's database setup job with that person (you need
    the right to start a job in the install's resource group, no database right); the job names a SuperAdmin only when
    there is none. An install made before 2.0.59 (no setup job) is changed directly, by a SQL administrator of the database.
    Anyone who signs in and is not named is a Reader. The change is written to the audit trail.
    You sign in in a browser (no module). -WhatIf: what it would write, nothing changed.
.EXAMPLE
    ./Set-EpsWebAccess.ps1 -TenantId <tenant> -SubscriptionId <sub> -UserPrincipalName admin@contoso.com -Role SuperAdmin -Reason 'first SuperAdmin after the install'
.LINK
    https://invardia.com/docs/eps/scripts/Set-EpsWebAccess
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [ValidateSet('SuperAdmin', 'Admin', 'Reader')][string]$Role = 'SuperAdmin',
    [Parameter(Mandatory)][string]$Reason,
    [string]$ResourceGroup = ''
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Set-EpsWebAccess when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
$upn = $UserPrincipalName.Trim().ToLowerInvariant()
if ($upn -notmatch '^[^@\s''"]+@[^@\s''"]+\.[^@\s''"]+$') { throw "'$UserPrincipalName' is not a user principal name" }
if ($Reason.Trim().Length -lt 3) { throw 'give a reason (it goes into the audit trail)' }
# a second run in the same window never takes the earlier run's sign-in (its tokens are gone, or another tenant): sign in
# again - unless a Support-app session provided the sign-in (EPS_InstallPerson) for THIS tenant (SI finding 2026-11-03)
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
$me = (Invoke-EpsGraph -Path 'v1.0/me?$select=userPrincipalName').userPrincipalName
$user = @(Invoke-EpsGraph -Path "v1.0/users?`$filter=userPrincipalName eq '$($upn.Replace("'", "''"))'&`$select=id,userPrincipalName,accountEnabled" -All)[0]
if (-not $user) { throw "no user $upn in this tenant" }
Write-Host "$upn ($($user.id)) becomes $Role in the Entra Policy Suite web app - by $me, reason: $Reason" -ForegroundColor Cyan
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }

# framework §5.5 (OPEN-30): rg-eps for an install made since 2.0.55, rg-entrapolicysuite for an older one; the names as the install made them
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
# SEC-08 row 6 (no person needs database admin rights): an install with the database setup job names the SuperAdmin
# through it - you only start the job (an Azure right on the resource group), no SQL right; it names one only when there
# is none. Admin and Reader are given in the web app's Access page by a SuperAdmin.
$dbJob = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$($names.DbInitJob)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
if ($dbJob) {
    if ($Role -ne 'SuperAdmin') { Write-Host "`n$Role is given in the web app's Access page by a SuperAdmin - this script names only a SuperAdmin when there is none." -ForegroundColor Yellow; exit 2 }
    $r = Invoke-EpsDbInitJob -Ctx $ctx -SuperAdmin @{ Upn = $upn; ObjectId = "$($user.id)" } -UseExisting
    Write-Host "`nThe database setup job ($($r.Execution)) finished: $upn is SuperAdmin if there was none (audited). If a SuperAdmin already exists, they grant it in the web app's Access page." -ForegroundColor Green
    return
}
$q ={ param($s) "N'$("$s".Replace("'", "''"))'" }
$after = (@{ Principal = $upn; ObjectId = $user.id; Role = $Role } | ConvertTo-Json -Compress)
Invoke-EpsSetupSql -Ctx $ctx -Script @"
MERGE eps.WebAccess AS d USING (SELECT $(& $q $upn) AS Principal) AS s ON d.Principal = s.Principal
WHEN MATCHED THEN UPDATE SET Role = $(& $q $Role), ObjectId = '$($user.id)', GrantedBy = $(& $q $me), GrantedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Principal, ObjectId, Role, GrantedBy) VALUES ($(& $q $upn), '$($user.id)', $(& $q $Role), $(& $q $me));
INSERT INTO eps.AuditEvent (Action, Actor, ActorSource, Target, Reason, Outcome, AfterJson) VALUES ('access.grant', $(& $q $me), 'setup', $(& $q "WebAccess|$upn"), $(& $q $Reason), 'ok', $(& $q $after));
"@
Write-Host "`n$upn is $Role. They sign in at the web app's address." -ForegroundColor Green
