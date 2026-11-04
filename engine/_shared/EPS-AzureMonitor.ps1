# EntraPolicySuite -- the external alarm (DESIGN §5.7a, owner 2026-10-29: "possibiliti for a external azure monitor
# alerting which you can deploy"): an Azure Monitor rule set that does NOT depend on the product running. Built from
# the owner's own break-glass design (the rule table in DESIGN §5.7a), with every account / attribute / identity
# filled in from the PRODUCT's settings - no customer value is ever written into the product.
#   * the Entra diagnostic setting that sends AuditLogs + sign-in logs to Log Analytics (only if none does yet)
#   * an action group (mail + SMS, as the owner's design)
#   * the scheduled query rules - rebuilt from the settings on every deploy: an account that leaves the break-glass
#     module takes its rules with it, the AD rules exist only while AD break-glass accounts do
# The builder is pure (settings in, ARM bodies out); Invoke-EpsAzureMonitorDeploy applies a plan over ARM.

Set-StrictMode -Off
$script:EpsSqrApi = '2023-03-15-preview'; $script:EpsAgApi = '2023-01-01'; $script:EpsDiagApi = '2017-04-01'

function ConvertTo-EpsKqlString {
    # a value inside a KQL string literal: only the shapes the rules use are accepted (a UPN, a GUID, a SID, an
    # attribute name, an sAMAccountName) - anything else is refused, never escaped and hoped for
    param([AllowEmptyString()][string]$Value, [Parameter(Mandatory)][ValidateSet('Upn', 'Guid', 'Sid', 'Attribute', 'Name', 'JobName')][string]$Kind)
    $ok = switch ($Kind) {
        'Upn'       { $Value -match "^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$" -and $Value -notmatch "'" }
        'Guid'      { $Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' }
        'Sid'       { $Value -match '^S-1-[0-9]+(-[0-9]+)+$' }
        'Attribute' { $Value -match '^extensionAttribute([1-9]|1[0-5])$' }
        'Name'      { $Value -match '^[A-Za-z0-9._-]{1,64}$' }
        'JobName'   { $Value -match '^[a-z0-9-]{1,32}$' }
    }
    if (-not $ok) { throw "refused for a KQL rule: '$Value' is not a valid $Kind" }
    '"' + $Value + '"'
}

function Get-EpsAzureMonitorRules {
    <#
    .SYNOPSIS
        The rule set (DESIGN §5.7a table) for the given settings. Returns rule definitions:
        @{ Name; DisplayName; Description; Severity; Frequency; Window; Query; Operator; Threshold }.
    .PARAMETER Accounts
        The break-glass accounts: @{ Directory = 'Entra'; UserPrincipalName; ObjectId } or @{ Directory = 'AD'; Name; Sid }.
    #>
    param([object[]]$Accounts = @(), [string[]]$WatchedAttributes = @(), [string]$EngineAppId, [string[]]$AllowList = @(), [string]$TickJobName = 'caj-eps-tick')
    $entra = @($Accounts | Where-Object { $_.Directory -ne 'AD' }); $ad = @($Accounts | Where-Object { $_.Directory -eq 'AD' })
    $rules = [System.Collections.Generic.List[object]]::new()
    $add = { param($n, $dn, $desc, $sev, $freq, $win, $q, $op, $th) $rules.Add([pscustomobject]@{ Name = "eps-$n"; DisplayName = "Entra Policy Suite - $dn"; Description = $desc; Severity = $sev; Frequency = $freq; Window = $win; Query = $q; Operator = $op; Threshold = $th }) }
    # the alarm's own eyes: a log that stops arriving would blind every rule below
    & $add 'auditlogs-missing' 'AuditLogs data missing' 'No AuditLogs row in Log Analytics for a day: the other rules on AuditLogs are blind.' 2 'P1D' 'P1D' 'AuditLogs' 'LessThan' 1
    & $add 'signinlogs-missing' 'SigninLogs data missing' 'No SigninLogs row in Log Analytics for a day: the sign-in rules are blind.' 2 'P1D' 'P1D' 'SigninLogs' 'LessThan' 1
    if ($ad.Count) { & $add 'securityevent-missing' 'SecurityEvent data missing (AD)' 'No SecurityEvent row for a day: the AD break-glass rule is blind.' 2 'P1D' 'P1D' 'SecurityEvent' 'LessThan' 1 }
    & $add 'ca-policy-changed' 'Conditional Access policy changed' 'A Conditional Access policy was created, changed or deleted.' 1 'PT5M' 'PT5M' 'AuditLogs | where OperationName contains "Conditional Access policy"' 'GreaterThan' 0
    if ($entra.Count) {
        $upns = @($entra | Where-Object { $_.UserPrincipalName } | ForEach-Object { ConvertTo-EpsKqlString $_.UserPrincipalName Upn })
        $ids = @($entra | Where-Object { $_.ObjectId } | ForEach-Object { ConvertTo-EpsKqlString ([string]$_.ObjectId) Guid })
        $who = @(); if ($upns) { $who += "UserPrincipalName in~ ($($upns -join ', '))" }; if ($ids) { $who += "UserId in ($($ids -join ', '))" }
        $f = '(' + ($who -join ' or ') + ')'
        & $add 'bga-signin-interactive' 'Break-glass account interactive sign-in' 'A break-glass account signed in interactively.' 0 'PT5M' 'PT5M' "SigninLogs | where $f" 'GreaterThan' 0
        & $add 'bga-signin-noninteractive' 'Break-glass account non-interactive sign-in' 'A break-glass account signed in non-interactively.' 0 'PT5M' 'PT5M' "AADNonInteractiveUserSignInLogs | where $f" 'GreaterThan' 0
        $iw = @(); if ($upns) { $iw += "InitiatorUpn in~ ($($upns -join ', '))" }; if ($ids) { $iw += "InitiatorId in ($($ids -join ', '))" }
        & $add 'bga-acted' 'Break-glass account acted in Entra' 'A break-glass account made a change in Entra (it is meant to sign in only in an emergency).' 0 'PT5M' 'PT5M' `
            ("AuditLogs | extend InitiatorUpn = tostring(InitiatedBy.user.userPrincipalName), InitiatorId = tostring(InitiatedBy.user.id) | where " + ($iw -join ' or ')) 'GreaterThan' 0
    }
    if ($ad.Count) {
        $names = @($ad | Where-Object { $_.Name } | ForEach-Object { ConvertTo-EpsKqlString $_.Name Name })
        $sids = @($ad | Where-Object { $_.Sid } | ForEach-Object { ConvertTo-EpsKqlString $_.Sid Sid })
        $w = @(); if ($names) { $w += "SubjectUserName in~ ($($names -join ', '))"; $w += "TargetUserName in~ ($($names -join ', '))" }; if ($sids) { $w += "SubjectUserSid in ($($sids -join ', '))"; $w += "TargetUserSid in ($($sids -join ', '))" }
        # 4780 (the AdminSDHolder ACL reset) is excluded, as the owner's design
        & $add 'bga-ad-activity' 'Break-glass AD account activity' 'An AD break-glass account was used or changed (a domain controller or server event).' 0 'PT5M' 'PT5M' "SecurityEvent | where ($($w -join ' or ')) and EventID != 4780" 'GreaterThan' 0
    }
    if ($WatchedAttributes.Count) {
        $attrs = @($WatchedAttributes | Select-Object -Unique | ForEach-Object { ConvertTo-EpsKqlString $_ Attribute })
        $apps = @(@($EngineAppId) + @($AllowList | Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' }) | Where-Object { $_ } | ForEach-Object { ConvertTo-EpsKqlString $_ Guid })
        $allowUpns = @($AllowList | Where-Object { $_ -match '@' } | ForEach-Object { ConvertTo-EpsKqlString $_ Upn })
        $q = "AuditLogs | where OperationName in (`"Update user`", `"Update device`") | mv-expand T = TargetResources | mv-expand P = T.modifiedProperties" +
             " | where tostring(P.displayName) in~ ($($attrs -join ', '))" +
             " | extend InitiatorApp = tostring(InitiatedBy.app.appId), InitiatorUpn = tostring(InitiatedBy.user.userPrincipalName)" +
             $(if ($apps) { " | where InitiatorApp !in ($($apps -join ', '))" } else { '' }) +
             $(if ($allowUpns) { " | where InitiatorUpn !in~ ($($allowUpns -join ', '))" } else { '' }) +
             # AD-synced users' tags arrive through Entra Connect (its Sync_ account): the product's monitor checks those with the worker
             ' | where not(InitiatorUpn startswith "Sync_")'
        & $add 'tag-foreign-writer' 'Watched tag attribute changed by a foreign writer' 'A tag attribute that drives the dynamic groups and Conditional Access was changed by someone other than the Entra Policy Suite engine or an allowed writer.' 1 'PT5M' 'PT5M' $q 'GreaterThan' 0
    }
    & $add 'heartbeat-stopped' 'Product heartbeat stopped' 'The Entra Policy Suite tick wrote nothing for an hour: the product is not running, so its own monitor is not either.' 1 'PT1H' 'PT1H' `
        "ContainerAppConsoleLogs_CL | where column_ifexists(`"ContainerJobName_s`", `"`") == $(ConvertTo-EpsKqlString $TickJobName JobName)" 'LessThan' 1
    @($rules)
}

function New-EpsScheduledQueryRuleBody {
    param([Parameter(Mandatory)]$Rule, [Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$ActionGroupId, [Parameter(Mandatory)][string]$Location)
    [ordered]@{
        location = $Location; kind = 'LogAlert'; tags = @{ product = 'EntraPolicySuite' }
        properties = [ordered]@{
            displayName = $Rule.DisplayName; description = $Rule.Description; severity = $Rule.Severity; enabled = $true
            evaluationFrequency = $Rule.Frequency; windowSize = $Rule.Window; scopes = @($WorkspaceId)
            criteria = @{ allOf = @(@{ query = $Rule.Query; timeAggregation = 'Count'; operator = $Rule.Operator; threshold = $Rule.Threshold
                                       failingPeriods = @{ numberOfEvaluationPeriods = 1; minFailingPeriodsToAlert = 1 } }) }
            autoMitigate = $false; actions = @{ actionGroups = @($ActionGroupId) }
        }
    }
}

function New-EpsActionGroupBody {
    # mail + SMS (both, as the owner's design). Sms: '+<country code> <number>' each.
    param([string[]]$Email = @(), [string[]]$Sms = @())
    if (-not ($Email.Count + $Sms.Count)) { throw 'the action group needs at least one mail address or SMS number' }
    $i = 0
    # not "$sms": variable names are case-insensitive, so that IS the [string[]] parameter and the hashtables became strings
    $smsList = @(foreach ($s in $Sms) { if ($s -notmatch '^\+(\d{1,3})\s+([\d ]{4,20})$') { throw "SMS number '$s': give '+<country code> <number>'" }; $i++; @{ name = "sms$i"; countryCode = $Matches[1]; phoneNumber = ($Matches[2] -replace '\s', '') } })
    $i = 0
    $mail = @(foreach ($e in $Email) { if ($e -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "mail address '$e' is not valid" }; $i++; @{ name = "mail$i"; emailAddress = $e; useCommonAlertSchema = $true } })
    [ordered]@{ location = 'Global'; tags = @{ product = 'EntraPolicySuite' }; properties = [ordered]@{ groupShortName = 'EPSAlarm'; enabled = $true; emailReceivers = $mail; smsReceivers = $smsList } }
}

function Get-EpsAzureMonitorPlan {
    <#
    .SYNOPSIS
        What a deploy would do, READ-ONLY: the diagnostic setting (reuse one that already sends AuditLogs, else create
        'eps-entra-logs'), the action group, each rule (create / update), and the eps-* rules that are no longer wanted
        (remove). Returns @{ Steps; Rules; WorkspaceId; ActionGroupId }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][object[]]$Rules, [string[]]$Email = @(), [string[]]$Sms = @())
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $steps = [System.Collections.Generic.List[object]]::new()
    $diag = @((Invoke-EpsArm -Path '/providers/microsoft.aadiam/diagnosticSettings' -ApiVersion $script:EpsDiagApi -AllowNotFound).value | Where-Object { $_ })
    $useWs = $WorkspaceId
    $existing = $diag | Where-Object { $_.properties.workspaceId -and @($_.properties.logs | Where-Object { $_.category -eq 'AuditLogs' -and $_.enabled }).Count } | Select-Object -First 1
    if ($existing) { $useWs = [string]$existing.properties.workspaceId; $steps.Add(@{ Action = 'exists'; What = "Entra diagnostic setting '$($existing.name)' already sends AuditLogs to $useWs - the rules use that workspace" }) }
    else { $steps.Add(@{ Action = 'create'; What = "Entra diagnostic setting 'eps-entra-logs': AuditLogs, SignInLogs, NonInteractiveUserSignInLogs -> $WorkspaceId"; Do = 'diag' }) }
    $agId = "$rg/providers/Microsoft.Insights/actionGroups/ag-eps-alarm"
    $ag = Invoke-EpsArm -Path $agId -ApiVersion $script:EpsAgApi -AllowNotFound
    $steps.Add(@{ Action = $(if ($ag) { 'update' } else { 'create' }); What = "action group ag-eps-alarm: $(@($Email).Count) mail, $(@($Sms).Count) SMS"; Do = 'ag' })
    $have = @((Invoke-EpsArm -Path "$rg/providers/Microsoft.Insights/scheduledQueryRules" -ApiVersion $script:EpsSqrApi -AllowNotFound).value | Where-Object { $_.name -like 'eps-*' } | ForEach-Object { $_.name })
    foreach ($r in $Rules) { $steps.Add(@{ Action = $(if ($have -contains $r.Name) { 'update' } else { 'create' }); What = "rule $($r.Name): $($r.DisplayName) (every $($r.Frequency))"; Do = 'rule'; Rule = $r }) }
    foreach ($old in $have | Where-Object { $_ -notin @($Rules | ForEach-Object Name) }) { $steps.Add(@{ Action = 'remove'; What = "rule $old (no longer wanted - e.g. its account left the break-glass module)"; Do = 'remove'; Name = $old }) }
    @{ Steps = @($steps); WorkspaceId = $useWs; ActionGroupId = $agId; ResourceGroup = $rg; Location = $Location; Email = $Email; Sms = $Sms }
}

function Invoke-EpsAzureMonitorDeploy {
    param([Parameter(Mandatory)]$Plan)
    foreach ($s in $Plan.Steps) {
        switch ($s.Do) {
            'diag' {
                [void](Invoke-EpsArm -Method PUT -Path '/providers/microsoft.aadiam/diagnosticSettings/eps-entra-logs' -ApiVersion $script:EpsDiagApi -Body @{ properties = @{ workspaceId = $Plan.WorkspaceId
                    logs = @(foreach ($c in 'AuditLogs', 'SignInLogs', 'NonInteractiveUserSignInLogs') { @{ category = $c; enabled = $true } }) } })
            }
            'ag' { [void](Invoke-EpsArm -Method PUT -Path $Plan.ActionGroupId -ApiVersion $script:EpsAgApi -Body (New-EpsActionGroupBody -Email $Plan.Email -Sms $Plan.Sms)) }
            'rule' { [void](Invoke-EpsArm -Method PUT -Path "$($Plan.ResourceGroup)/providers/Microsoft.Insights/scheduledQueryRules/$($s.Rule.Name)" -ApiVersion $script:EpsSqrApi -Body (New-EpsScheduledQueryRuleBody -Rule $s.Rule -WorkspaceId $Plan.WorkspaceId -ActionGroupId $Plan.ActionGroupId -Location $Plan.Location)) }
            'remove' { [void](Invoke-EpsArm -Method DELETE -Path "$($Plan.ResourceGroup)/providers/Microsoft.Insights/scheduledQueryRules/$($s.Name)" -ApiVersion $script:EpsSqrApi) }
        }
    }
}
