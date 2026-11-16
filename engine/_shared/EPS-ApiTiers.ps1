# EntraPolicySuite -- what an API APPLICATION may do (framework §12.31 SETTINGS-API-1 + §12.30 SUPPORT-FIX-API-1, owner
# 2026-11-16 "it should be possible to manage settings using code, not only gui" / "All but security controls" / "Code +
# approver"). Pure data + functions, no I/O: the web app asks it before an app-only caller reaches a handler.
#
# The tier of each change is FIXED here and tested (tests/Test-EpsApiTiers.ps1):
#   read    - a GET or a check that writes nothing: role Reader (a check route needs Admin, as for a person)
#   setting - TIER 1: the product's own settings, no grant of access, no security control. An Admin app COMMITS through
#             the normal path; a setting a person changes only as SuperAdmin is HELD for a SuperAdmin (the app never approves).
#   grant   - TIER 2: anything that gives or changes access or writes the tenant (rules and tags drive groups and Conditional
#             Access, CA policies, groups, who may use EPS). The app PROPOSES (maker); a person approves (checker), always a
#             different principal. A route the commit queue cannot stage yet is refused to apps (a person does it in the app).
#   person  - TIER 3: person-only, never an application (the list below, a reason per entry).
# A change that is not mapped FAILS CLOSED as person-only, until a person classifies it here.

# CLOSED (owner 2026-11-16, framework §12.34 / §12.35 API-MCP-SECURE-DESIGN-1): the API for applications is OFF at every
# ring and on every new install - /api/app/* answers 404 before any sign-in check, the install and the update do not add
# its Entra layer (app role, idtyp, v2 tokens), the update enrols no Support app, Set-EpsApiAuth refuses. The code behind
# it stays (tested with this set to $true). Opening it again is a later, deliberate owner decision and a release.
$script:EpsAppApiOpen = $false
# The same for the MCP server and the API for scripts (/mcp, /mcp/api/*, /.well-known/oauth-protected-resource*), owner
# 2026-11-16 via Invardia: "close it now" - 404 before any sign-in check, at every install, until the §12.35 design and the
# owner's deliberate open of one install.
$script:EpsMcpOpen = $false
# §12.35 L7: a person's calls on /mcp* per sliding minute (in memory: one web replica per install)
$script:EpsMcpPerMinute = 60

$script:EpsApiTierRead = 'read'; $script:EpsApiTierSetting = 'setting'; $script:EpsApiTierGrant = 'grant'; $script:EpsApiTierPerson = 'person'

# PERSON-ONLY (framework §12.31): an application must never widen its own rights or reduce its accountability.
# Keys: 'action:<route action>' or 'setting:<setting key>'. ONE literal list; the overlap test reads it.
$script:EpsApiPersonOnly = [ordered]@{
    'setting:Security.SignedRequests'     = 'sign-in / approver: whether a change must carry the person''s signature'
    'setting:Security.ApiApps'            = 'the role allow-list of API applications itself (API-application enrolment)'
    'setting:Security.SupportApp'         = 'API-application enrolment: the Support application, set by the update only'
    'setting:CommitQueue.Enabled'         = 'second-person rules: the queue every change waits in'
    'setting:CommitQueue.SecondApprover'  = 'second-person rules: whether another admin must commit'
    'setting:Uplink.Enabled'              = 'the vendor connection (Invardia connect)'
    'setting:Uplink.Alerts.Enabled'       = 'the vendor connection (Invardia connect): alerts to support'
    'setting:Update.Enabled'              = 'the vendor connection: switching updates off stops security fixes'
    'setting:Log.KeepDays'                = 'an audit / retention setting that can shrink the trail'
    'setting:Log.Level.UserTagging'       = 'a log setting that can shrink the trail'
    'setting:Log.Level.DeviceTagging'     = 'a log setting that can shrink the trail'
    'setting:Log.Level.IdentityReport'    = 'a log setting that can shrink the trail'
    'setting:Log.Level.CAPolicyAnalyzer'  = 'a log setting that can shrink the trail'
    'setting:Log.Level.NamedLocations'    = 'a log setting that can shrink the trail'
    'setting:Log.Level.Uplink'            = 'a log setting that can shrink the trail'
    'setting:Log.Level.Update'            = 'a log setting that can shrink the trail'
    'setting:Log.Level.Backup'            = 'a log setting that can shrink the trail'
    'setting:TamperMonitor.Enabled'       = 'the change trail outside EPS: switching tamper detection off'
    'setting:TamperMonitor.AllowList'     = 'the change trail outside EPS: who may change without an alert'
    'setting:Mail.SmtpCredentialSecret'   = 'a secret reference (never handed to an application)'
    'setting:ProPolicyCode.TokenSecret'   = 'a secret reference (never handed to an application)'
    'action:breakglass.change'            = 'break-glass accounts'
    'action:onboarding.breakglass'        = 'break-glass accounts'
    'action:license.claim.again'          = 'licence / edition'
    'action:queue.commit'                 = 'approving: the checker is always a person'
    'action:queue.discard-all'            = 'approving: dropping everyone''s proposals is a person''s call'
    'action:tamper.event.accept.request'  = 'approving a change made outside EPS (the checker is a person)'
    'action:view.save'                    = 'a person''s own saved view'
    'action:view.delete'                  = 'a person''s own saved view'
}

# every route action that writes or requests, with its tier (GET routes without an action are 'read')
$script:EpsApiActionTier = @{
    # TIER 1 - operations and the product's own configuration (no access, no security control)
    'job.run.request' = 'setting'; 'job.schedule.change' = 'setting'; 'job.test.request' = 'setting'; 'ca.analyze.request' = 'setting'
    'ca.monitor.change' = 'setting'; 'ca.monitor.delete' = 'setting'; 'identity.run.request' = 'setting'; 'mail.test.request' = 'setting'
    'worker.test.request' = 'setting'; 'worker.retry' = 'setting'; 'queue.discard' = 'setting'; 'setting.change' = 'setting'
    'tamper.event.restore.request' = 'setting'
    # checks: write nothing (the plan a person sees first)
    'rule.batch.check' = 'read'; 'rule.import.plan' = 'read'; 'v1import.plan' = 'read'; 'ca.policy.edit.check' = 'read'
    'ca.policy.remove.check' = 'read'; 'ca.policy.restore.check' = 'read'; 'ca.object.restore.check' = 'read'
    'config.import.check' = 'read'; 'ca.directory.search' = 'read'; 'onboarding.check' = 'read'; 'ca.group.check' = 'read'
    'ca.group.validate' = 'read'
    # TIER 2 - grants: tagging config drives groups and Conditional Access, CA itself, groups, identities, access to EPS
    'rule.create' = 'grant'; 'rule.update' = 'grant'; 'rule.delete' = 'grant'; 'rule.move' = 'grant'; 'rule.batch' = 'grant'
    'tagtype.change' = 'grant'; 'tagtype.delete' = 'grant'; 'tagvalue.change' = 'grant'; 'tagvalue.remove' = 'grant'
    'condition.change' = 'grant'; 'condition.delete' = 'grant'; 'scope.change' = 'grant'; 'scope.delete' = 'grant'
    'job.golive.request' = 'grant'; 'v1import.apply' = 'grant'; 'job.run.undo' = 'grant'
    'ca.persona.change' = 'grant'; 'ca.persona.delete' = 'grant'; 'ca.template.take' = 'grant'
    'ca.policy.stage' = 'grant'; 'ca.policy.edit' = 'grant'; 'ca.policy.clone' = 'grant'; 'ca.policy.deploy' = 'grant'
    'ca.policy.newversion' = 'grant'; 'ca.policy.promote' = 'grant'; 'ca.policy.rollback' = 'grant'; 'ca.policy.removeold' = 'grant'
    'ca.policy.remove' = 'grant'; 'ca.policy.restore' = 'grant'; 'ca.object.restore' = 'grant'; 'ca.policy.undo' = 'grant'
    'ca.policy.adopt' = 'grant'; 'ca.policy.release' = 'grant'
    'onboarding.strengths' = 'grant'; 'onboarding.deniedcountries' = 'grant'; 'onboarding.trusted' = 'grant'
    'ca.group.editrule' = 'grant'; 'ca.group.create' = 'grant'; 'ca.group.rule' = 'grant'; 'ca.group.members' = 'grant'
    'ca.group.forceupdate' = 'grant'; 'ca.group.au' = 'grant'; 'identity.action.set' = 'grant'
    'access.grant' = 'grant'; 'access.revoke' = 'grant'
}

# SUPPORT-FIX-API-1 (§12.30): the ONLY fixes the Support role may apply, each through the named route's normal handler.
# A fix is always tier 1 (setting) and never person-only - the overlap test proves both.
# KEYED BY THE FAILURE KEY that raises the ticket (the uplink AlertId, or an item failure), so a ticket names its fixes.
$script:EpsSupportFixCatalog = [ordered]@{
    'worker.package.retry' = @{ FailureKeys = @('eps.worker.package-failed'); Action = 'worker.retry'; Method = 'POST'; Path = '/api/worker/retry'; Key = 'packageId'; KeyPattern = '^\d{1,18}$'; Text = 'Try a failed AD tag change again (a new change record and work package; the failed one stays as it was).' }
    'job.rerun'            = @{ FailureKeys = @('eps.job.repeat-failure'); Action = 'job.run.request'; Method = 'POST'; Path = '/api/jobs/{key}/run'; Key = 'job'; KeyPattern = '^(IdentityReport|Backup|CaOptions|SignInMethods|Uplink)$'; Text = 'Run one job now, as the Run button does (the run is recorded as any run). Only a job that READS the tenant: a tagging, named-location, tamper or policy job writes it, so re-running one is a person''s call.' }
}

function Get-EpsSupportFixes {
    # the fixes offered for one failure key (what a ticket for that failure may name)
    param([Parameter(Mandatory)][string]$FailureKey)
    @($script:EpsSupportFixCatalog.GetEnumerator() | Where-Object { @($_.Value.FailureKeys) -contains $FailureKey } | ForEach-Object { $_.Key })
}

function Get-EpsApiTier {
    <# The fixed tier of one change for an application. -SettingKey for a setting save; -Action for any other route.
       Person-only wins over every other entry; an unknown change is person-only (fails closed). #>
    param([string]$Action, [string]$SettingKey, [string]$Method = 'POST')
    if ($SettingKey) {
        if ($script:EpsApiPersonOnly.Contains("setting:$SettingKey")) { return $script:EpsApiTierPerson }
        return $script:EpsApiTierSetting
    }
    if (-not $Action) { return $(if ("$Method".ToUpperInvariant() -eq 'GET') { $script:EpsApiTierRead } else { $script:EpsApiTierPerson }) }
    if ($script:EpsApiPersonOnly.Contains("action:$Action")) { return $script:EpsApiTierPerson }
    if ($script:EpsApiActionTier.ContainsKey($Action)) { return $script:EpsApiActionTier[$Action] }
    return $script:EpsApiTierPerson
}

$script:EpsSupportGrantRowsPerHour = 25

function Get-EpsApiDecision {
    <# What one application caller may do with one change (framework §12.31 + SUPPORT-DIRECT-GRANT-1), PURE:
         -Role       the caller's role: Reader | Admin | Support (from the token's role AND the allow-list, both)
         -Tier       Get-EpsApiTier's answer
         -NeedsSuperAdmin  a setting a person changes only as SuperAdmin (the catalog's role) = held for a SuperAdmin
         -Ticket     the SUP ticket id on a Support call; -GrantRowsLastHour the Support grant rows at this install
       -> @{ Do = read | commit | hold | propose | refuse; Why }
       Support commits a grant DIRECTLY only on a ticket and under the rate limit (more = held); it never reaches tier 3. #>
    param([Parameter(Mandatory)][ValidateSet('Reader', 'Admin', 'Support')][string]$Role, [Parameter(Mandatory)][string]$Tier,
        [switch]$NeedsSuperAdmin, [string]$Ticket, [int]$GrantRowsLastHour = 0, [int]$Rows = 1)
    $no = { param($w) @{ Do = 'refuse'; Why = $w } }
    switch ($Tier) {
        'read' { return @{ Do = 'read'; Why = 'a read' } }
        'person' { return & $no 'person-only: a person does this in the app' }
        'setting' {
            if ($Role -eq 'Reader') { return & $no 'the Reader role reads only' }
            if ($Role -eq 'Support') { return & $no 'the Support role applies catalogued fixes only (POST /api/app/support/fix)' }
            if ($NeedsSuperAdmin) { return @{ Do = 'hold'; Why = 'a SuperAdmin setting: held for a SuperAdmin to approve' } }
            return @{ Do = 'commit'; Why = 'tier 1 setting' }
        }
        'grant' {
            if ($Role -eq 'Reader') { return & $no 'the Reader role reads only' }
            if ($Role -eq 'Admin') { return @{ Do = 'propose'; Why = 'tier 2: the application proposes, a person approves' } }
            if ("$Ticket" -notmatch '^SUP-\d{4}-\d{5}$') { return & $no 'a Support grant change needs a SUP ticket id (SUP-yyyy-nnnnn)' }
            if ($GrantRowsLastHour + $Rows -gt $script:EpsSupportGrantRowsPerHour) { return @{ Do = 'hold'; Why = "more than $script:EpsSupportGrantRowsPerHour Support grant rows in an hour: held for a person" } }
            return @{ Do = 'commit'; Why = 'SUPPORT-DIRECT-GRANT-1: on a ticket, mailed to the admins, audited' }
        }
    }
    & $no 'unknown tier: fails closed'
}

function Get-EpsApiPersonOnlyReason { param([string]$Key) "$($script:EpsApiPersonOnly[$Key])" }

function Test-EpsApiOverlap {
    <# §12.31 overlap test: what an Admin app may commit (tier 1) and the Support fix-catalog have ZERO intersection with
       the person-only list. Returns the clashes (empty = clean). #>
    param([string[]]$SettingKeys = @())
    $clash = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $script:EpsApiActionTier.Keys) {
        if ($script:EpsApiPersonOnly.Contains("action:$k")) { $clash.Add("action:$k is person-only and also tiered $($script:EpsApiActionTier[$k])") }
    }
    foreach ($f in $script:EpsSupportFixCatalog.GetEnumerator()) {
        $a = "$($f.Value.Action)"
        if ($script:EpsApiPersonOnly.Contains("action:$a")) { $clash.Add("fix $($f.Key) uses person-only action:$a") }
        elseif ((Get-EpsApiTier -Action $a) -ne $script:EpsApiTierSetting) { $clash.Add("fix $($f.Key) uses $a, which is not tier 1 (setting)") }
    }
    foreach ($s in $SettingKeys) {
        if ($s -match '^(Security|CommitQueue|Uplink|Log)\.' -and -not $script:EpsApiPersonOnly.Contains("setting:$s")) { $clash.Add("setting:$s is in a person-only group but not on the list") }
    }
    @($clash)
}
