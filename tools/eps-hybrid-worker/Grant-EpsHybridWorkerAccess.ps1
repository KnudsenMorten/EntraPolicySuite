#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the hybrid worker's MANAGED IDENTITY access to the EntraPolicySuite database (or takes it away with -Remove).
.DESCRIPTION
    The worker signs in to SQL as its machine's managed identity (an Azure VM's, or an Azure Arc-enabled server's). This
    adds that identity to the database as the contained user 'eps-hybrid-worker' (WITH SID = its client id, never FROM
    EXTERNAL PROVIDER), in the role eps_worker only (sql/eps-grants.json: the work packages, its heartbeat, the AD group
    snapshots - framework §12.23, never db_datareader / db_datawriter). You sign in in a browser as the SQL server's
    Entra admin (no module). -WhatIf shows the T-SQL and runs nothing.
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
    [string]$ResourceGroup = 'rg-entrapolicysuite',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://invardia.com/docs/eps/scripts/Grant-EpsHybridWorkerAccess'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
$user = 'eps-hybrid-worker'
$sql = if ($Remove) { "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$user') DROP USER [$user];" } else { ((Get-EpsGrantScript -GrantList (Get-EpsGrantList -SolutionRoot $sol)), (Get-EpsSqlUserScript -Name $user -ClientId "$WorkerClientId" -Role 'eps_worker')) -join "`n" }
$names = Get-EpsInstallNames -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
Write-Host "Database: $($names.SqlServer).database.windows.net / $($names.Database)" -ForegroundColor Cyan
Write-Host $sql -ForegroundColor DarkGray
if ($what) { Write-Host "`nWhatIf: nothing was run." -ForegroundColor Cyan; return }
if (-not $global:EPS_TokenProvider) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }
Invoke-EpsSetupSql -Ctx @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol } -Script $sql
Write-Host "`n$(if ($Remove) { "Removed the database user $user." } else { "The worker's identity ($WorkerClientId) is the database user $user (role eps_worker)." })" -ForegroundColor Green
