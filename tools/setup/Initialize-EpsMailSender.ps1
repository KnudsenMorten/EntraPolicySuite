#Requires -Version 7.2
<#
.SYNOPSIS
    Sets up Entra Policy Suite's mail (framework MAIL-1): a shared mailbox the engine sends its alerts from - and the
    right to send as THAT mailbox only.
.DESCRIPTION
    Creates the shared mailbox (or uses the one you name), registers the engine's managed identity in Exchange, creates
    a management scope matching exactly that mailbox and gives the identity 'Application Mail.Send' on it - Exchange
    RBAC for applications, so the engine can send as this mailbox and as no other. A tenant-wide Graph Mail.Send grant
    on the identity is removed (it would win beside the scope). Every step is read back. Then it stores the mail
    settings (Mail.Mode = sharedMailbox, the sender, the recipients) in the Entra Policy Suite database.
    You sign in in a browser (no module). Needs an Exchange Online plan in the tenant. -WhatIf: the plan, nothing changed.
.EXAMPLE
    ./Initialize-EpsMailSender.ps1 -TenantId <tenant> -SubscriptionId <sub> -Sender eps-alerts@contoso.com -Recipients soc@contoso.com -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Initialize-EpsMailSender
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][string]$Sender,
    [Parameter(Mandatory)][string[]]$Recipients,
    [string]$ResourceGroup = '',
    [string]$EnvironmentName
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Initialize-EpsMailSender when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Exchange', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-MailSender') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
foreach ($r in $Recipients) { if ($r -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "recipient '$r' is not a mail address" } }
# a second run in the same window never takes the earlier run's sign-in (its tokens are gone, or another tenant): sign in
# again - unless a Support-app session provided the sign-in (EPS_InstallPerson) for THIS tenant (SI finding 2026-11-03)
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }

# framework §5.5 (OPEN-30): rg-eps for an install made since 2.0.55, rg-entrapolicysuite for an older one; the names as the install made them
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi) { throw "no engine identity $($names.EngineIdentity) in $ResourceGroup - is Entra Policy Suite installed there?" }
$appId = [string]$mi.properties.clientId; $oid = [string]$mi.properties.principalId

$state = Get-EpsMailSenderState -TenantId "$TenantId" -Sender $Sender -AppId $appId -ObjectId $oid
$plan = Get-EpsMailSenderPlan -Sender $Sender -AppId $appId -ObjectId $oid -DisplayName $names.EngineIdentity -State $state
Write-Host "Sender $Sender for $($names.EngineIdentity) ($appId), scope $($plan.ScopeName)" -ForegroundColor Cyan
if (-not $plan.Steps.Count) { Write-Host '  everything is in place' -ForegroundColor DarkGray }
foreach ($s in $plan.Steps) { Write-Host "  $($s.What)" }
$settings = [ordered]@{ 'Mail.Mode' = 'sharedMailbox'; 'Mail.Sender' = $Sender; 'Mail.Recipients' = (ConvertTo-Json @($Recipients) -Compress) }
if ($EnvironmentName) { $settings['Platform.EnvironmentName'] = $EnvironmentName }
Write-Host "  settings: $(($settings.Keys | ForEach-Object { "$_ = $($settings[$_])" }) -join '; ')"
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }

Invoke-EpsMailSenderPlan -TenantId "$TenantId" -ObjectId $oid -Plan $plan
# read back: a security control that was not read back is not a control
$after = Get-EpsMailSenderState -TenantId "$TenantId" -Sender $Sender -AppId $appId -ObjectId $oid
$left = Get-EpsMailSenderPlan -Sender $Sender -AppId $appId -ObjectId $oid -State $after
if (@($left.Steps | Where-Object { $_.Cmdlet -ne 'Enable-OrganizationCustomization' }).Count) { throw "not in place after the apply: $(@($left.Steps | ForEach-Object What) -join '; ')" }
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
$sql = (@(foreach ($k in $settings.Keys) { "MERGE eps.Setting AS d USING (SELECT N'$k' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = N'$($settings[$k].Replace("'", "''"))', UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Feature, Value) VALUES (N'$k', N'$($k.Split('.')[0])', N'$($settings[$k].Replace("'", "''"))');" }) -join "`n")
Invoke-EpsSetupSql -Ctx $ctx -Script $sql
Write-Host "`nMail is set up: the engine sends as $Sender only (scope $($plan.ScopeName)), to $($Recipients -join ', ')." -ForegroundColor Green
