#Requires -Version 7.2
<#
.SYNOPSIS
    Deploys (or updates) Entra Policy Suite's EXTERNAL alarm in your Azure: an Azure Monitor rule set that keeps working
    even when the product does not (DESIGN §5.7a).
.DESCRIPTION
    Built from the product's own settings - the break-glass accounts of the break-glass module, the attributes of the
    enabled tag types, the engine's identity, the tamper monitor's allow list - so run it again after any of them
    change: the rules follow exactly the accounts in the module and an account that left takes its rules with it.
    It creates: the Entra diagnostic setting 'eps-entra-logs' (AuditLogs + sign-in logs -> the install's Log Analytics
    workspace) unless one already sends AuditLogs somewhere (that workspace is then used); the action group
    ag-eps-alarm (mail + SMS); the scheduled query rules eps-* (AuditLogs / SigninLogs / SecurityEvent data missing,
    Conditional Access policy changed, break-glass sign-ins and actions in Entra and AD, a watched tag changed by a
    foreign writer, the product's heartbeat stopped). You sign in in a browser; no module. -WhatIf shows the plan and
    changes nothing.
.PARAMETER Email
    Mail addresses the alarm goes to.
.PARAMETER InputFile
    The alarm inputs downloaded from the web app (Tamper monitor > Download the alarm inputs): the enabled break-glass
    accounts, the watched tag attributes and the tamper allow list. The script reads no database.
.PARAMETER Sms
    Phone numbers for SMS, as '+<country code> <number>' (e.g. '+45 12345678').
.EXAMPLE
    ./Deploy-EpsAzureMonitorAlerts.ps1 -TenantId <tenant> -SubscriptionId <sub> -Email soc@contoso.com -Sms '+45 12345678' -InputFile .\eps-alarm-inputs.json -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Deploy-EpsAzureMonitorAlerts
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = '',
    [string[]]$Email = @(),
    [string[]]$Sms = @(),
    [string]$WorkspaceResourceId,
    [Parameter(Mandatory)][string]$InputFile
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Deploy-EpsAzureMonitorAlerts when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-AzureMonitor') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
if (-not ($Email.Count + $Sms.Count)) { throw 'give -Email and / or -Sms: the alarm must reach someone' }
# a second run in the same window never takes the earlier run's sign-in (its tokens are gone, or another tenant): sign in
# again - unless a Support-app session provided the sign-in (EPS_InstallPerson) for THIS tenant (SI finding 2026-11-03)
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }

# framework §5.5 (OPEN-30): rg-eps for an install made since 2.0.55, rg-entrapolicysuite for an older one; the names as the install made them
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
$law = Invoke-EpsArm -Path "$rg/providers/Microsoft.OperationalInsights/workspaces/$($names.Logs)" -ApiVersion '2022-10-01' -AllowNotFound
if (-not $WorkspaceResourceId) { if (-not $law) { throw "no Log Analytics workspace $($names.Logs) in $ResourceGroup - is Entra Policy Suite installed there? (or give -WorkspaceResourceId)" }; $WorkspaceResourceId = $law.id }
$location = if ($law) { $law.location } else { 'westeurope' }
$engine = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound

# the product's inputs (SEC-08 row 10: no SQL) - the file the web app gives a SuperAdmin or Admin: Tamper monitor >
# "Download the alarm inputs" (GET /api/tamper/alarm-inputs). Run this again after the break-glass list, the tag types
# or the allow list change, with a fresh file.
$in = Read-EpsAlarmInputFile -Path $InputFile
if (-not $in.Ok) { throw $in.Reason }
$accounts = @($in.Accounts); $attrs = @($in.WatchedAttributes); $allow = @($in.AllowList)
Write-Host "Inputs: $InputFile (from the web app, $($in.CreatedUtc))" -ForegroundColor DarkGray

$rules = Get-EpsAzureMonitorRules -Accounts $accounts -WatchedAttributes $attrs -EngineAppId $engine.properties.clientId -AllowList $allow -TickJobName $names.TickJob
$plan = Get-EpsAzureMonitorPlan -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup -WorkspaceId $WorkspaceResourceId -Location $location -Rules $rules -Email $Email -Sms $Sms
Write-Host "Break-glass accounts: $(@($accounts | Where-Object Directory -ne 'AD').Count) Entra, $(@($accounts | Where-Object Directory -eq 'AD').Count) AD; watched attributes: $($attrs -join ', ')" -ForegroundColor Cyan
foreach ($s in $plan.Steps) { Write-Host ("  {0,-7} {1}" -f $s.Action, $s.What) -ForegroundColor $(if ($s.Action -eq 'remove') { 'Yellow' } elseif ($s.Action -eq 'exists') { 'DarkGray' } else { 'Gray' }) }
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }
Invoke-EpsAzureMonitorDeploy -Plan $plan
Write-Host "`nDeployed: $(@($rules).Count) rule(s), action group ag-eps-alarm. Test it: sign in once with each break-glass account and check the alert arrives (DESIGN §5.1a step 7)." -ForegroundColor Green
