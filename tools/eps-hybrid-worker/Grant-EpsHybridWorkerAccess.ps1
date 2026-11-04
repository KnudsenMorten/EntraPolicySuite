#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the hybrid worker's MANAGED IDENTITY access to the Entra Policy Suite database (or takes it away with -Remove).
.DESCRIPTION
    The worker signs in to SQL as its machine's managed identity (an Azure VM's, or an Azure Arc-enabled server's). This
    adds that identity to the database as the contained user 'eps-hybrid-worker' (WITH SID = its client id, never FROM
    EXTERNAL PROVIDER), in the role eps_worker only (sql/eps-grants.json: the work packages, its heartbeat, the AD group
    snapshots - framework §12.23, never db_datareader / db_datawriter). You sign in in a browser (no module). An install
    made since 2.0.59 does it through its database setup job: you need the right to start a job in the install's resource
    group, no database right; an older install needs you to be the SQL server's Entra admin. -WhatIf shows the T-SQL and
    runs nothing.
    The client id: Azure VM -> the VM's identity (portal: the VM > Identity); Arc -> the machine's enterprise application
    (Entra: Enterprise applications, the server's name) - its Application ID.
.EXAMPLE
    .\Grant-EpsHybridWorkerAccess.ps1 -TenantId <tenant> -SubscriptionId <sub> -WorkerClientId <client id> -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Grant-EpsHybridWorkerAccess
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$WorkerClientId,
    [string]$ResourceGroup = '',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Grant-EpsHybridWorkerAccess when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
$user = 'eps-hybrid-worker'
$sql = if ($Remove) { "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$user') DROP USER [$user];" } else { ((Get-EpsGrantScript -GrantList (Get-EpsGrantList -SolutionRoot $sol)), (Get-EpsSqlUserScript -Name $user -ClientId "$WorkerClientId" -Role 'eps_worker')) -join "`n" }
if (-not $global:EPS_TokenProvider) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
# framework §5.5 (OPEN-30): rg-eps for an install made since 2.0.55, rg-entrapolicysuite for an older one; the names as the install made them
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
Write-Host "Database: $($names.SqlServer).database.windows.net / $($names.Database)" -ForegroundColor Cyan
Write-Host $sql -ForegroundColor DarkGray
if ($what) { Write-Host "`nWhatIf: nothing was run." -ForegroundColor Cyan; return }
# SEC-08 row 7 (no person needs database admin rights): an install with the database setup job makes / removes the
# worker's user through it - you only start the job (an Azure right on the resource group), no SQL right
$dbJob = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$($names.DbInitJob)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
if ($dbJob) {
    $r = Invoke-EpsDbInitJob -Ctx @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol } -Worker $(if ($Remove) { 'remove' } else { "$WorkerClientId" }) -UseExisting
    Write-Host "`n$(if ($Remove) { "Removed the database user $user" } else { "The worker's identity ($WorkerClientId) is the database user $user (role eps_worker)" }) - done by the database setup job ($($r.Execution)), read back." -ForegroundColor Green
    return
}
Invoke-EpsSetupSql -Ctx @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol } -Script $sql
Write-Host "`n$(if ($Remove) { "Removed the database user $user." } else { "The worker's identity ($WorkerClientId) is the database user $user (role eps_worker)." })" -ForegroundColor Green
