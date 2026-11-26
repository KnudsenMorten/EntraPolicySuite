#Requires -Version 7.2
<#
.SYNOPSIS
    Sets up Entra Policy Suite's mail (framework MAIL-1, ONE-SENDER-1): the ONE sender mailbox the engine sends its alerts
    from - and the right to send as THAT mailbox only. Also the only way to change the sender.
.DESCRIPTION
    Shared mailbox (the default): creates the shared mailbox (or uses the one you name), registers the engine's managed
    identity in Exchange, creates a management scope matching exactly that mailbox ('<mailbox name>-SendScope') and gives
    the identity 'Application Mail.Send' on it ('<mailbox name>-<id>-MailSend') - Exchange RBAC for applications, so the
    engine can send as this mailbox and as no other. A tenant-wide Graph Mail.Send grant on the identity is removed (it
    would win beside the scope).
    Then Exchange's own test (Test-ServicePrincipalAuthorization) must say the identity may send as the new mailbox and
    may NOT send as a probe mailbox (you, by default) - and then the ENGINE ITSELF must be able to: one run of its job
    tries to send as the new mailbox with no recipient (nothing is delivered). Exchange can take up to 2 hours: the script
    waits (-WaitMinutes) and the engine keeps sending from the previous sender meanwhile. Only when the engine's own check
    passes are the settings switched and the previous sender's right (and its scope, when nothing else is on it) removed.
    When it does not pass in time, the new right is removed again: the engine keeps sending as before.
    -SmtpRelay: mail through your SMTP relay instead - no Exchange step (the relay decides who may send); the sender is
    still this one -Sender, the relay's sign-in user name (when it needs one) is -SmtpUser, its password a Key Vault secret.
    You sign in in a browser (no module). -WhatIf: the plan, nothing changed.
.EXAMPLE
    ./Initialize-EpsMailSender.ps1 -TenantId <tenant> -SubscriptionId <sub> -Sender eps-alerts@contoso.com -Recipients soc@contoso.com -WhatIf
.EXAMPLE
    ./Initialize-EpsMailSender.ps1 -TenantId <tenant> -SubscriptionId <sub> -Sender eps-alerts@contoso.com -Recipients soc@contoso.com -SmtpRelay smtp.contoso.com -SmtpPort 587
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
    [string]$EnvironmentName,
    # the mailbox the engine must NOT be able to send as (the read-back's proof of the restriction); default: you
    [string]$ProbeMailbox = '',
    # how long to wait for Exchange to apply a new send right (it can take up to 2 hours)
    [ValidateRange(1, 240)][int]$WaitMinutes = 120,
    # SMTP relay instead of a shared mailbox
    [string]$SmtpRelay = '', [ValidateRange(1, 65535)][int]$SmtpPort = 25, [bool]$SmtpUseTls = $true,
    [string]$SmtpUser = '', [string]$SmtpCredentialSecret = ''
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Initialize-EpsMailSender when EPS is public there (DOC-LINKS)
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Exchange', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-MailSender') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
$mailRx = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
if ($Sender -notmatch $mailRx) { throw "-Sender '$Sender' is not a mail address" }
foreach ($r in $Recipients) { if ($r -notmatch $mailRx) { throw "recipient '$r' is not a mail address" } }
if ($SmtpRelay -and $SmtpRelay -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,251}$') { throw "-SmtpRelay '$SmtpRelay' is not a host name" }
if ($SmtpUser -and -not $SmtpRelay) { throw '-SmtpUser is for -SmtpRelay only' }
# a second run in the same window never takes the earlier run's sign-in (its tokens are gone, or another tenant): sign in
# again - unless a Support-app session provided the sign-in (EPS_InstallPerson) for THIS tenant (SI finding 2026-11-03)
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }

# framework §5.5 (OPEN-30): rg-eps for an install made since 2.0.55, rg-entrapolicysuite for an older one; the names as the install made them
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi) { throw "no engine identity $($names.EngineIdentity) in $ResourceGroup - is Entra Policy Suite installed there?" }
$appId = [string]$mi.properties.clientId; $oid = [string]$mi.properties.principalId
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
if (-not $ProbeMailbox -and -not $SmtpRelay) { $ProbeMailbox = try { "$((Invoke-EpsGraph -Path 'v1.0/me?$select=userPrincipalName').userPrincipalName)" } catch { '' } }
if ($ProbeMailbox -and $ProbeMailbox -notmatch $mailRx) { throw "-ProbeMailbox '$ProbeMailbox' is not a mail address" }

# the settings this run writes (ONE-SENDER-1 A: Mail.Sender is the only From, in both modes)
$settings = [ordered]@{ 'Mail.Mode' = $(if ($SmtpRelay) { 'smtp' } else { 'sharedMailbox' }); 'Mail.Sender' = $Sender; 'Mail.Recipients' = @($Recipients) }
if ($SmtpRelay) {
    $settings['Mail.SmtpServer'] = $SmtpRelay; $settings['Mail.SmtpPort'] = "$SmtpPort"; $settings['Mail.SmtpUseTls'] = $(if ($SmtpUseTls) { 'true' } else { 'false' })
    $settings['Mail.SmtpUser'] = $SmtpUser; $settings['Mail.SmtpCredentialSecret'] = $SmtpCredentialSecret
} elseif ($ProbeMailbox) { $settings['Mail.ProbeMailbox'] = $ProbeMailbox }
if ($EnvironmentName) { $settings['Platform.EnvironmentName'] = $EnvironmentName }
$show = { ($settings.Keys | ForEach-Object { "$_ = $(if ($settings[$_] -is [array]) { $settings[$_] -join ', ' } else { $settings[$_] })" }) -join '; ' }

function Write-EpsMailSettings {
    # SEC-08 row 9 (no person needs database admin rights): an install with the database setup job writes the settings
    # through it (a fixed list of setting keys, each checked, audited) - you only start the job, no SQL right
    $dbJob = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$($names.DbInitJob)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
    if ($dbJob) {
        $me = try { "$((Invoke-EpsGraph -Path 'v1.0/me?$select=userPrincipalName').userPrincipalName)" } catch { 'Initialize-EpsMailSender' }
        $r = Invoke-EpsDbInitJob -Ctx $ctx -Settings $settings -By $me -UseExisting
        Write-Host "  settings written by the database setup job ($($r.Execution))" -ForegroundColor DarkGray
        return
    }
    $flat = [ordered]@{}; foreach ($k in $settings.Keys) { $flat[$k] = $(if ($k -eq 'Mail.Recipients') { ConvertTo-Json @($settings[$k]) -Compress } else { "$($settings[$k])" }) }
    $sql = (@(foreach ($k in $flat.Keys) { "MERGE eps.Setting AS d USING (SELECT N'$k' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = N'$($flat[$k].Replace("'", "''"))', UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Feature, Value) VALUES (N'$k', N'$($k.Split('.')[0])', N'$($flat[$k].Replace("'", "''"))');" }) -join "`n")
    Invoke-EpsSetupSql -Ctx $ctx -Script $sql
}

if ($SmtpRelay) {
    Write-Host "Mail through the SMTP relay $SmtpRelay`:$SmtpPort, from $Sender (no Exchange step: the relay decides who may send)" -ForegroundColor Cyan
    Write-Host "  settings: $(& $show)"
    if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }
    Write-EpsMailSettings
    Write-Host "`nMail is set up: the engine sends through $SmtpRelay from $Sender to $($Recipients -join ', '). Send a test mail from Settings > Alert mail." -ForegroundColor Green
    return
}

$state = Get-EpsMailSenderState -TenantId "$TenantId" -Sender $Sender -AppId $appId -ObjectId $oid
$plan = Get-EpsMailSenderPlan -Sender $Sender -AppId $appId -ObjectId $oid -DisplayName $names.EngineIdentity -State $state
Write-Host "Sender $Sender for $($names.EngineIdentity) ($appId), scope $($plan.ScopeName)$(if ($ProbeMailbox) { ", probe $ProbeMailbox" })" -ForegroundColor Cyan
if (-not $plan.Steps.Count) { Write-Host '  the send right for this mailbox is in place' -ForegroundColor DarkGray }
foreach ($s in $plan.Steps) { Write-Host "  $($s.What)" }
foreach ($s in $plan.Cleanup) { Write-Host "  after the new right reads back: $($s.What)" }
foreach ($k in $plan.Kept) { Write-Host "  kept (not removed on a guess): $k" -ForegroundColor Yellow }
Write-Host "  settings: $(& $show)"
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }

# 1. the NEW right first - the previous sender keeps working meanwhile
Invoke-EpsMailSenderPlan -TenantId "$TenantId" -ObjectId $oid -Plan $plan
# 2. read back: the objects are there, AND Exchange says the identity may send as the sender and NOT as the probe -
#    a security control that was not read back is not a control. Exchange can take up to 2 hours: PENDING until then.
$sw = [Diagnostics.Stopwatch]::StartNew(); $v = $null
while ($true) {
    $after = Get-EpsMailSenderState -TenantId "$TenantId" -Sender $Sender -AppId $appId -ObjectId $oid
    $left = Get-EpsMailSenderPlan -Sender $Sender -AppId $appId -ObjectId $oid -State $after
    $missing = @($left.Steps | Where-Object { $_.Cmdlet -ne 'Enable-OrganizationCustomization' })
    $v = if ($missing.Count) { @{ Verdict = 'pending'; Text = "not in place yet: $(@($missing | ForEach-Object What) -join '; ')" } } else { Test-EpsMailSenderAuthorization -TenantId "$TenantId" -AppId $appId -Sender $Sender -Probe $ProbeMailbox }
    # ONE-SENDER-1 C (framework, 2026-11-26): Exchange's own test is only the FIRST signal (internal 05:41Z: it said "in
    # scope" while the engine's real send was still refused). The switch is done only when the ENGINE'S OWN probe passes.
    if ($v.Verdict -eq 'verified') {
        $ep = Invoke-EpsEngineMailProbe -Ctx $ctx -Sender $Sender -Probe $ProbeMailbox
        if ($ep.Verdict -eq 'verified') { Write-Host "  the engine's own probe ($($ep.Execution)): it may send as $Sender$(if ($ProbeMailbox) { " and not as $ProbeMailbox" })" -ForegroundColor Green }
        else { $v = @{ Verdict = 'pending'; Text = "Exchange says in scope; $($ep.Reason)" } }
    }
    if ($v.Verdict -ne 'pending' -or $sw.Elapsed.TotalMinutes -ge $WaitMinutes) { break }
    Write-Host "  PENDING ($([int]$sw.Elapsed.TotalMinutes) of $WaitMinutes min): Exchange has not applied the send right for $Sender yet - the previous sender keeps sending meanwhile$(if ($v.Text) { " - $($v.Text)" })" -ForegroundColor Yellow
    Start-Sleep -Seconds $(if ("$($v.Text)" -like 'Exchange says in scope*') { 240 } else { 60 })
}
# PUT BACK (a change that did not work): the new right and scope go again, a removed tenant-wide Mail.Send is given back
# (review 2026-11-26), the settings are not touched - the engine keeps sending as before
function Invoke-EpsMailPutBack {
    $back = [System.Collections.Generic.List[object]]::new()
    if (@($plan.Steps | Where-Object Cmdlet -eq 'New-ManagementRoleAssignment').Count) { $back.Add([pscustomobject]@{ Cmdlet = 'Remove-ManagementRoleAssignment'; What = "remove the new right $($plan.AssignmentName)"; Parameters = @{ Identity = $plan.AssignmentName; Confirm = $false } }) }
    if ($plan.NewScope) { $back.Add([pscustomobject]@{ Cmdlet = 'Remove-ManagementScope'; What = "remove the new scope $($plan.ScopeName)"; Parameters = @{ Identity = $plan.ScopeName; Confirm = $false } }) }
    foreach ($pb in @($plan.PutBack)) { if ($pb) { $back.Add($pb) } }
    if ($back.Count) { Invoke-EpsMailSenderPlan -TenantId "$TenantId" -ObjectId $oid -Plan @{ Steps = @($back) } -RetrySeconds 30 -MaxWaitSeconds 900 }
    if ($back.Count) { @($back | ForEach-Object What) -join '; ' } else { 'nothing was added' }
}
if ($v.Verdict -ne 'verified') {
    # 3a. it did not work: PUT BACK
    $why = if ($v.Verdict -eq 'unrestricted') { "the engine could ALSO send as $ProbeMailbox - its right is not restricted to $Sender (another grant is in the tenant)" } else { "Exchange did not apply the send right for $Sender within $WaitMinutes minutes$(if ($v.Text) { " ($($v.Text))" })" }
    $done = Invoke-EpsMailPutBack
    throw "the sender was NOT changed: $why. Put back: $done; the engine keeps sending as before. Nothing else was changed."
}
Write-Host "  read back: the engine may send as $Sender$(if ($ProbeMailbox -and $ProbeMailbox -ne $Sender) { " and NOT as $ProbeMailbox" }) (Exchange's own test)" -ForegroundColor Green
# 3b. it works: the settings switch to the new sender, THEN the previous sender's right goes (ONE-SENDER-1 C). A settings
# write that reports a failure (review 2026-11-26, tools-pro reviewer 1 #9; 2.1.73 two-agent check B #4): the database
# setup job may still have written Mail.Sender (a slow run, or a later step failed) - so BOTH rights are KEPT and nothing is
# removed: whichever sender the setting names can send. Run the script again to finish.
try { Write-EpsMailSettings }
catch { throw "the settings write did not report success ($($_.Exception.Message)). BOTH send rights are kept (the old and the new mailbox), so the engine can send whichever the setting names; nothing was removed. Run the script again with -Sender $Sender to finish the change." }
if ($plan.Cleanup.Count) {
    # the sender has switched: a clean-up step Exchange refuses (its lag) is asked again for up to 15 min, and one that
    # still fails is NAMED below - never a failed switch (the new sender works; the old right is what is left)
    try { Invoke-EpsMailSenderPlan -TenantId "$TenantId" -ObjectId $oid -Plan @{ Steps = @($plan.Cleanup) } -RetrySeconds 30 -MaxWaitSeconds 900 }
    catch { Write-Host "  the previous sender's right could not all be removed yet: $($_.Exception.Message)" -ForegroundColor Yellow }
    $gone = Get-EpsMailSenderState -TenantId "$TenantId" -Sender $Sender -AppId $appId -ObjectId $oid
    # (an empty Cleanup is no step: member enumeration of an empty list gives $null, and @($null) counts 1 - the E proof
    # on internal printed "NOT removed:" with nothing after it, 2026-11-26 05:40Z)
    $still = @((Get-EpsMailSenderPlan -Sender $Sender -AppId $appId -ObjectId $oid -State $gone).Cleanup | Where-Object { $_ })
    if ($still.Count) { Write-Host "  NOT removed (remove by hand): $(@($still | ForEach-Object What) -join '; ')" -ForegroundColor Red }
    else { Write-Host "  the previous sender's right is removed: $(@($plan.Cleanup | ForEach-Object What) -join '; ')" -ForegroundColor Green }
}
foreach ($k in $plan.Kept) { Write-Host "  kept (its scope filter could not be read - check it by hand): $k" -ForegroundColor Yellow }
Write-Host "`nMail is set up: the engine sends as $Sender only (scope $($plan.ScopeName)), to $($Recipients -join ', ')." -ForegroundColor Green
