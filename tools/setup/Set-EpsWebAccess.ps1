#Requires -Version 7.2
<#
.SYNOPSIS
    Names who may use the Entra Policy Suite web app: SuperAdmin, Admin or Reader. Used once to name the first SuperAdmin.
.DESCRIPTION
    The web app's access list (eps.WebAccess) is managed in the app itself by a SuperAdmin. Before there is one - right
    after the install, or when every SuperAdmin has left - a SQL administrator of the Entra Policy Suite database names one
    with this script. Anyone who signs in and is not named is a Reader. The change is written to the audit trail.
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
    [string]$ResourceGroup = 'rg-entrapolicysuite'
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

$names = Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
$q = { param($s) "N'$("$s".Replace("'", "''"))'" }
$after = (@{ Principal = $upn; ObjectId = $user.id; Role = $Role } | ConvertTo-Json -Compress)
Invoke-EpsSetupSql -Ctx $ctx -Script @"
MERGE eps.WebAccess AS d USING (SELECT $(& $q $upn) AS Principal) AS s ON d.Principal = s.Principal
WHEN MATCHED THEN UPDATE SET Role = $(& $q $Role), ObjectId = '$($user.id)', GrantedBy = $(& $q $me), GrantedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Principal, ObjectId, Role, GrantedBy) VALUES ($(& $q $upn), '$($user.id)', $(& $q $Role), $(& $q $me));
INSERT INTO eps.AuditEvent (Action, Actor, ActorSource, Target, Reason, Outcome, AfterJson) VALUES ('access.grant', $(& $q $me), 'setup', $(& $q "WebAccess|$upn"), $(& $q $Reason), 'ok', $(& $q $after));
"@
Write-Host "`n$upn is $Role. They sign in at the web app's address." -ForegroundColor Green
