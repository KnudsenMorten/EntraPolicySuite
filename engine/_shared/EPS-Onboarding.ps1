# EntraPolicySuite -- GET-STARTED, the onboarding check (DESIGN §5.10; owner 2026-11-03: "i also need a get started
# wizard to onboard fxbreak glass, auth methods, naming conv for groups etc. see all req in v1 scripts").
#
# The ENGINE reads the tenant (GETs only - this file writes nothing in the tenant) and stores one row per item
# (eps.OnboardingCheck); the web app's Get started page shows the stored rows. What v1's scripts set up before anything
# ran is data: engine/onboarding/defaults.json. The same check feeds the heartbeat's setupSteps (FLEET-STEPS, DESIGN §8).
# Creating what is missing ("Check + create on approval", owner 2026-11-03) comes step by step, each one a pinned engine
# write like the stage move (EPS-CaWrite.ps1) - none is in this file.

Set-StrictMode -Off

$script:EpsOnboardingDefaultsCache = $null
$script:EpsOnboardingSteps = @(
    [ordered]@{ key = 'rights';    title = 'Tenant and rights';                    what = 'The engine''s Microsoft Graph rights and the Exchange role, and the licences the templates need.' }
    [ordered]@{ key = 'breakglass'; title = 'Break-glass';                        what = 'The emergency accounts every Conditional Access policy excludes, their group, and the principles they must meet.' }
    [ordered]@{ key = 'auth';      title = 'Authentication methods and strengths'; what = 'The FIDO2 and Windows Hello strengths the templates name, and the methods the tenant allows.' }
    [ordered]@{ key = 'method';    title = 'Group targeting method and names';     what = 'How the policies target groups (v1''s three methods), and the group names that follow from it.' }
    [ordered]@{ key = 'targets';   title = 'Target groups';                       what = 'Every group the templates name: in the tenant, with members, its dynamic rule as stored.' }
    [ordered]@{ key = 'pilots';    title = 'Pilot and exclude groups';            what = 'For the templates of your adopted policies: the pilot and exclude groups.' }
    [ordered]@{ key = 'aus';       title = 'Administrative units';                what = 'The administrative units the Conditional Access groups belong in.' }
    [ordered]@{ key = 'locations'; title = 'Named locations';                     what = 'Denied countries, your trusted locations (office IPs) and the service tags.' }
    [ordered]@{ key = 'tags';      title = 'Tag attributes and rules';            what = 'Which extension attribute holds which tag, the rules, and the AD Connect sync account left out.' }
    [ordered]@{ key = 'mail';      title = 'Mail and alerts';                     what = 'Who the alerts are sent from and to.' }
    [ordered]@{ key = 'hybrid';    title = 'Hybrid AD';                           what = 'The worker that writes the tags of AD-synced users.' }
    [ordered]@{ key = 'reports';   title = 'Reports';                             what = 'The identity report''s AD OU patterns.' }
    [ordered]@{ key = 'templates'; title = 'Templates that need an input';        what = 'Templates that ship without a value only you can give.' }
)
$script:EpsOnboardingStates = @('ok', 'missing', 'check', 'info', 'unknown')

function Get-EpsOnboardingDefaults {
    if ($script:EpsOnboardingDefaultsCache) { return $script:EpsOnboardingDefaultsCache }
    $script:EpsOnboardingDefaultsCache = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'onboarding\defaults.json') -Raw | ConvertFrom-Json -AsHashtable
    $script:EpsOnboardingDefaultsCache
}
function Get-EpsOnboardingStepList { @($script:EpsOnboardingSteps) }

function Invoke-EpsOnboardingGraph {
    # one GET for the check: @{ Ok; Value; Denied; Error } - a refusal (403) says which right is missing, never throws
    param([Parameter(Mandatory)][string]$Path, [switch]$All, [switch]$Eventual)
    try { @{ Ok = $true; Value = $(if ($All) { @(Invoke-EpsGraph -Path $Path -All -Eventual:$Eventual) } else { Invoke-EpsGraph -Path $Path -Eventual:$Eventual }) } }
    catch { $m = "$($_.Exception.Message)"; @{ Ok = $false; Denied = [bool]($m -match '(?i)-> 403|Authorization_RequestDenied|Insufficient privileges'); Error = (($m -split '->')[-1]).Trim() } }
}

function Get-EpsEngineObjectId {
    # the engine identity's object id: the 'oid' of its own Graph token (no lookup, no extra right)
    $t = "$(Get-EpsToken -Resource 'https://graph.microsoft.com')"
    $p = ($t -split '\.')[1]; if (-not $p) { return $null }
    $p = $p.Replace('-', '+').Replace('_', '/'); switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    try { "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).oid)" } catch { $null }
}

function Get-EpsEngineRightsState {
    <#
      The engine's own rights, read back (Application.Read.All + RoleManagement.Read.Directory, both its own): every Graph
      role the install grants (defaults.json engineGraphRoles = EPS-Install's list) as granted / missing, and the Exchange
      role. Returns @{ Ok; Reason; Granted (role -> $true/$false); Exchange ($true / $false / $null) }.
    #>
    $d = Get-EpsOnboardingDefaults
    $oid = Get-EpsEngineObjectId
    if (-not $oid) { return @{ Ok = $false; Reason = 'the engine identity could not be read from its token' } }
    $g = Invoke-EpsOnboardingGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles"
    $a = Invoke-EpsOnboardingGraph -Path "v1.0/servicePrincipals/$oid/appRoleAssignments" -All
    if (-not $g.Ok -or -not $a.Ok) { return @{ Ok = $false; Reason = "the engine cannot read its own rights ($(if ($g.Ok) { $a.Error } else { $g.Error })) - it needs Application.Read.All" } }
    $sp = @($g.Value.value)[0]
    $byId = @{}; foreach ($r in @($sp.appRoles)) { $byId["$($r.id)"] = "$($r.value)" }
    $have = @($a.Value | Where-Object { "$($_.resourceId)" -eq "$($sp.id)" } | ForEach-Object { $byId["$($_.appRoleId)"] })
    $granted = [ordered]@{}; foreach ($r in @($d.engineGraphRoles) + @($d.engineGraphWriteRoles)) { $granted[$r] = $have -contains $r }
    $x = Invoke-EpsOnboardingGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$oid'" -All
    $ex = if ($x.Ok) { [bool](@($x.Value | Where-Object { "$($_.roleDefinitionId)" -eq $d.exchangeRole.templateId }).Count) } else { $null }
    @{ Ok = $true; Granted = $granted; Exchange = $ex; ObjectId = $oid }
}

# OPEN-09 / SEC-02 (framework §4.3-4.4, Invardia 2026-11-04): the engine's Exchange rights (Exchange.ManageAsApp + the
# Exchange Recipient Administrator role) only where a feature that uses Exchange is on: user tagging (a tag on a mailbox
# object is written through Exchange when Graph cannot), the identity report (mailbox types), or a rule with a mailbox
# condition (Mailbox_*). Mail does NOT use them (alerts go through Graph Mail.Send). One row, read as is.
$script:EpsExchangeNeedSql = @'
SELECT (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'UserTagging.Enabled') AS UserTagging,
       (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'IdentityReport.Enabled') AS IdentityReport,
       (SELECT COUNT(*) FROM eps.UserTagRuleCondition WHERE ConditionType LIKE 'Mailbox[_]%') AS MailboxConditions
'@

function Get-EpsExchangeNeed {
    <# PURE. The row of $script:EpsExchangeNeedSql -> @{ Known; Needed; Why }. No row (not readable) = not Known: nothing is
       granted or removed on a guess. A job's switch is off unless 'true' is stored (the tick's default for these jobs). #>
    param($Row)
    if ($null -eq $Row) { return @{ Known = $false; Needed = $false; Why = 'the settings could not be read' } }
    $g = { param($n) if ($Row -is [System.Collections.IDictionary]) { $Row[$n] } else { $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } } }
    $why = @()
    if ("$(& $g 'UserTagging')".Trim() -eq 'true') { $why += 'user tagging is on' }
    if ("$(& $g 'IdentityReport')".Trim() -eq 'true') { $why += 'the identity report is on' }
    $mc = 0; [void][int]::TryParse("$(& $g 'MailboxConditions')", [ref]$mc)
    if ($mc -gt 0) { $why += "$mc rule condition(s) read mailbox types" }
    @{ Known = $true; Needed = [bool]$why.Count; Why = $(if ($why.Count) { $why -join ', ' } else { 'no feature that uses Exchange is on' }) }
}

# SEC-02-GRAPH (owner e48f195e, 2026-11-07, 2.0.99): the engine's Graph WRITE rights only while a feature that writes is
# on - User.ReadWrite.All for user tagging and the tamper monitor's restore, Device.ReadWrite.All for device tagging
# (reading is User.Read.All / Device.Read.All, always granted). One row, read as is.
$script:EpsGraphWriteNeedSql = @'
SELECT (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'UserTagging.Enabled') AS UserTagging,
       (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'TamperMonitor.Enabled') AS TamperMonitor,
       (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'DeviceTagging.Enabled') AS DeviceTagging,
       (SELECT MAX(Value) FROM eps.Setting WHERE Name = 'ProStale.DisableEnabled') AS ProStaleDisable
'@

function Get-EpsGraphWriteNeed {
    <# PURE. The row of $script:EpsGraphWriteNeedSql -> @{ Known; Roles = @{ <role> = @{ Needed; Why } } }. No row = not
       Known: nothing is granted or removed on a guess. A switch is on only when 'true' is stored. #>
    param($Row)
    if ($null -eq $Row) { return @{ Known = $false; Roles = @{}; Why = 'the settings could not be read' } }
    $g = { param($n) if ($Row -is [System.Collections.IDictionary]) { $Row[$n] } else { $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } } }
    $on = { param($n) "$(& $g $n)".Trim() -eq 'true' }
    $u = @(); if (& $on 'UserTagging') { $u += 'user tagging is on' }; if (& $on 'TamperMonitor') { $u += 'the tamper monitor is on (it restores tags)' }
    # Pro's stale identity clean-up disables (and enables again) an account a SuperAdmin approved (the one place that does it is EPS-ProStaleWrite) -
    # only while its disable action is switched on (Invardia ruling 2026-11-07: the feature switch, never "a licence")
    if (& $on 'ProStaleDisable') { $u += 'the stale identity clean-up may disable accounts (ProStale.DisableEnabled)' }
    $d = @(); if (& $on 'DeviceTagging') { $d += 'device tagging is on' }
    @{ Known = $true; Why = ''
       Roles = [ordered]@{ 'User.ReadWrite.All' = @{ Needed = [bool]$u.Count; Why = $(if ($u.Count) { $u -join ', ' } else { 'none of user tagging, the tamper monitor or the stale identity clean-up''s disable action is on' }) }
                           'Device.ReadWrite.All' = @{ Needed = [bool]$d.Count; Why = $(if ($d.Count) { $d -join ', ' } else { 'device tagging is off' }) } } }
}

function Get-EpsSetupSteps {
    <#
      FLEET-STEPS (owner 2026-11-03, via Invardia: "it must be consistent across all"): the one-time steps of this install,
      each from a real check, in the heartbeat's shared shape (key, title, state ok | missing | n/a | unknown, since, how,
      checkedAt, detail). -Rights: Get-EpsEngineRightsState (read now). -Mail: Mail.Mode.
    #>
    # -ExchangeNeed: Get-EpsExchangeNeed (OPEN-09) - not given = the step as before (needed)
    # -DbJob: eps.UplinkState setup.dbjob (the version whose database setup job last read every principal back; $null =
    # not readable). -UpdateRun: the last update run's summary ($null = not readable, '' = none yet).
    # -GraphWriteNeed: Get-EpsGraphWriteNeed (SEC-02-GRAPH, 2.0.99) - not given = the write rights reported as needed
    param($Rights, [string]$MailMode, [datetime]$NowUtc = [datetime]::UtcNow, $ExchangeNeed = $null, [AllowNull()][object]$DbJob = $null, [AllowNull()][object]$UpdateRun = $null, $GraphWriteNeed = $null)
    $d = Get-EpsOnboardingDefaults
    $at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($d.engineGraphRoles)) {
        $st = if (-not $Rights -or -not $Rights.Ok) { 'unknown' } elseif ($Rights.Granted[$r]) { 'ok' } else { 'missing' }
        $out.Add([ordered]@{ key = "graph-$($r.ToLowerInvariant().Replace('.', '-'))"; title = "Engine has the Graph permission $r"; state = $st; since = "$($d.roleSince[$r])"; how = 'customer'; checkedAt = $at
                             detail = $(if ($st -eq 'unknown') { "$($Rights.Reason)" } else { "for $($d.roleFor[$r])" }) })
    }
    # SEC-02-GRAPH: a write right is needed only while a feature that writes is on - otherwise n/a (and one still held is extra)
    foreach ($r in @($d.engineGraphWriteRoles)) {
        $st = if (-not $Rights -or -not $Rights.Ok) { 'unknown' } elseif ($Rights.Granted[$r]) { 'ok' } else { 'missing' }
        $detail = if ($st -eq 'unknown') { "$($Rights.Reason)" } else { "for $($d.roleFor[$r])" }
        $need = if ($GraphWriteNeed -and $GraphWriteNeed.Known) { $GraphWriteNeed.Roles[$r] } else { $null }
        if ($need -and -not $need.Needed) {
            $detail = if ($st -eq 'ok') { "not needed ($($need.Why)) but still granted: the next install run removes it (or Grant-EpsEnginePermissions -GraphPermission $r -Remove)" } else { "not needed: $($need.Why)" }
            $st = 'n/a'
        } elseif ($need -and $need.Needed -and $st -eq 'missing') { $detail = "needed ($($need.Why)): grant it with Grant-EpsEnginePermissions -GraphPermission $r" }
        $out.Add([ordered]@{ key = "graph-$($r.ToLowerInvariant().Replace('.', '-'))"; title = "Engine has the Graph permission $r"; state = $st; since = "$($d.roleSince[$r])"; how = 'customer'; checkedAt = $at; detail = $detail })
    }
    $ex = if (-not $Rights -or -not $Rights.Ok -or $null -eq $Rights.Exchange) { 'unknown' } elseif ($Rights.Exchange) { 'ok' } else { 'missing' }
    $exDetail = "for $($d.exchangeRole.for)"
    # OPEN-09: needed only while a feature that uses Exchange is on - otherwise n/a, and a role still held is said to be extra
    if ($ExchangeNeed -and $ExchangeNeed.Known -and -not $ExchangeNeed.Needed) {
        $exDetail = if ($ex -eq 'ok') { "not needed ($($ExchangeNeed.Why)) but still granted: the next install or update run removes it (or Grant-EpsEnginePermissions -Exchange -Remove)" } else { "not needed: $($ExchangeNeed.Why)" }
        $ex = 'n/a'
    } elseif ($ExchangeNeed -and $ExchangeNeed.Known -and $ExchangeNeed.Needed -and $ex -eq 'missing') {
        $exDetail = "needed ($($ExchangeNeed.Why)): grant it with Grant-EpsEnginePermissions -Exchange"
    }
    $out.Add([ordered]@{ key = 'exchange-recipient-admin'; title = 'Engine holds the Exchange Recipient Administrator role'; state = $ex; since = '2.0.0'; how = 'customer'; checkedAt = $at; detail = $exDetail })
    $out.Add([ordered]@{ key = 'mail-sender'; title = 'An alert mail sender is set up'; state = $(if (-not $MailMode) { 'unknown' } elseif ($MailMode -eq 'none') { 'missing' } else { 'ok' }); since = '2.0.0'; how = 'customer'; checkedAt = $at; detail = 'set up once by an Exchange admin (the mail sender setup script), then Settings > Mail' })
    # SEC-08: no person needs database admin rights - the setup job did the database as its own identity
    $out.Add([ordered]@{ key = 'db-job'; title = 'The database setup job sets up the database (no person needs database admin rights)'; since = '2.0.59'; how = 'support-app'; checkedAt = $at
        state = $(if ($null -eq $DbJob) { 'unknown' } elseif ("$DbJob".Trim()) { 'ok' } else { 'missing' })
        detail = $(if ($null -eq $DbJob) { 'not readable' } elseif ("$DbJob".Trim()) { "last run by $("$DbJob".Trim())" } else { 'not run yet: one install run with 2.0.59 or later (as the server admin group''s owner) makes it' }) })
    # UPDATER-1: the update job installs approved releases as its own identity id-eps-updater
    $noUpd = "$UpdateRun" -match 'no updater identity'
    $out.Add([ordered]@{ key = 'updater'; title = 'The updater can install approved releases (its own identity, Contributor on the resource group)'; since = '2.0.60'; how = 'support-app'; checkedAt = $at
        state = $(if ($null -eq $UpdateRun) { 'unknown' } elseif (-not "$UpdateRun".Trim()) { 'unknown' } elseif ($noUpd) { 'missing' } else { 'ok' })
        detail = $(if ($null -eq $UpdateRun) { 'not readable' } elseif (-not "$UpdateRun".Trim()) { 'no update run yet' } elseif ($noUpd) { 'the update job has no updater identity: one install run with 2.0.60 or later adds it' } else { 'the last update run had its updater identity' }) })
    foreach ($s in $out) { if ($s.detail.Length -gt 200) { $s.detail = $s.detail.Substring(0, 200) } }
    @($out)
}

function Invoke-EpsOnboardingCheck {
    <#
      Every step's items, read now: @{ step; item; title; state (ok | missing | check | info | unknown); detail }. Reads
      only (Graph GETs with the engine's rights, SQL). A step that cannot be read says why (state unknown), never a guess.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Log = { param($l, $m) })
    $d = Get-EpsOnboardingDefaults; $cat = Get-EpsCaTemplateCatalog
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = { param($step, $item, $title, $state, $detail) $rows.Add([ordered]@{ step = $step; item = "$item"; title = "$title"; state = $state; detail = "$detail" }) }
    $set = { param($n, $def = '') try { "$(Get-EpsSetting -ConnectionString $ConnectionString -Name $n -Default $def)".Trim() } catch { $def } }
    $sql = { param($q, $p = @{}) @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query $q) }
    $ctx = Get-EpsCaStoredContext -ConnectionString $ConnectionString
    $method = $ctx.Method
    $groupInfo = @{}   # name -> @{ Found; Id; Rule; Members; Error }
    $lookupGroups = {
        param([string[]]$Names)
        $want = @($Names | Where-Object { $_ -and -not $groupInfo.ContainsKey($_) } | Select-Object -Unique)
        for ($i = 0; $i -lt $want.Count; $i += 15) {
            $chunk = @($want[$i..([Math]::Min($i + 14, $want.Count - 1))])
            $r = Invoke-EpsOnboardingGraph -Path "v1.0/groups?`$filter=displayName in ($((@($chunk) | ForEach-Object { "'$($_.Replace("'", "''"))'" }) -join ','))&`$select=id,displayName,membershipRule,groupTypes" -All
            foreach ($n in $chunk) {
                if (-not $r.Ok) { $groupInfo[$n] = @{ Found = $null; Error = $r.Error }; continue }
                $hit = @($r.Value | Where-Object { "$($_.displayName)" -ceq $n })
                $groupInfo[$n] = if ($hit.Count -eq 1) { @{ Found = $true; Id = "$($hit[0].id)"; Rule = "$($hit[0].membershipRule)"; Dynamic = (@($hit[0].groupTypes) -contains 'DynamicMembership') } } elseif ($hit.Count -gt 1) { @{ Found = $false; Error = "$($hit.Count) groups have this name" } } else { @{ Found = $false } }
            }
        }
        foreach ($n in $want) {
            $gi = $groupInfo[$n]; if (-not $gi.Found) { continue }
            $c = Invoke-EpsOnboardingGraph -Path "v1.0/groups/$($gi.Id)/members/`$count" -Eventual
            $gi.Members = if ($c.Ok) { [int]"$($c.Value)" } else { $null }
        }
    }

    # 1 rights
    $rights = Get-EpsEngineRightsState
    if (-not $rights.Ok) { & $add 'rights' 'graph' 'The engine''s Graph rights' 'unknown' $rights.Reason }
    else {
        foreach ($r in @($rights.Granted.Keys)) { & $add 'rights' "graph:$r" "Graph permission $r" $(if ($rights.Granted[$r]) { 'ok' } else { 'missing' }) $(if ($rights.Granted[$r]) { "granted - for $($d.roleFor[$r])" } else { "NOT granted - $($d.roleFor[$r]) does not work. Run the install again (or the approver left it out with -ExcludeGraphRole)." }) }
        & $add 'rights' 'exchange' $d.exchangeRole.name $(if ($null -eq $rights.Exchange) { 'unknown' } elseif ($rights.Exchange) { 'ok' } else { 'missing' }) $(if ($rights.Exchange) { "held - for $($d.exchangeRole.for)" } else { "not held - $($d.exchangeRole.for) cannot be read. Run the install again." })
    }
    $sk = Invoke-EpsOnboardingGraph -Path 'v1.0/subscribedSkus?$select=skuPartNumber,servicePlans' -All
    if ($sk.Ok) {
        $plans = @($sk.Value | ForEach-Object { @($_.servicePlans) | ForEach-Object { "$($_.servicePlanName)" } })
        foreach ($x in @(@('AAD_PREMIUM_P2', 'Entra ID P2 - the sign-in and user risk templates'), @('INTUNE_A', 'Intune - the compliant device and app protection templates'), @('ADALLOM_S_STANDALONE', 'Defender for Cloud Apps - the session control templates'))) {
            & $add 'rights' "licence:$($x[0])" $x[1] $(if ($plans -contains $x[0]) { 'ok' } else { 'check' }) $(if ($plans -contains $x[0]) { 'the tenant has it' } else { 'not found in the tenant''s licences: the templates that need it will not work as intended' })
        }
    } else { & $add 'rights' 'licences' 'Licences' 'unknown' $sk.Error }

    # 2 break-glass
    $acc = @($ctx.Accounts)
    & $add 'breakglass' 'accounts' 'Break-glass accounts' $(if ($acc.Count -ge 2) { 'ok' } elseif ($acc.Count) { 'check' } else { 'missing' }) $(if ($acc.Count) { "$($acc.Count) configured ($(@($acc | ForEach-Object Upn) -join ', ')); at least two are advised" } else { 'none configured - every Conditional Access policy must exclude them. Add them here.' })
    foreach ($a in $acc) {
        $u = Invoke-EpsOnboardingGraph -Path "v1.0/users/$([uri]::EscapeDataString($a.Upn))?`$select=id,accountEnabled,onPremisesSyncEnabled,passwordPolicies"
        if (-not $u.Ok) { & $add 'breakglass' "account:$($a.Upn)" $a.Upn $(if ($u.Error -match '404|not ?found|Request_ResourceNotFound') { 'missing' } else { 'unknown' }) $(if ($u.Error -match '404|not ?found|Request_ResourceNotFound') { 'not in the tenant' } else { $u.Error }); continue }
        $v = $u.Value; $why = [System.Collections.Generic.List[string]]::new()
        if (-not $v.accountEnabled) { $why.Add('disabled') }
        if ($v.onPremisesSyncEnabled -eq $true) { $why.Add('synced from AD (must be cloud-only)') }
        if ("$($v.passwordPolicies)" -notmatch 'DisablePasswordExpiration') { $why.Add('the password expires') }
        $ga = Invoke-EpsOnboardingGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($v.id)' and roleDefinitionId eq '$($d.globalAdministratorTemplateId)'" -All
        if ($ga.Ok -and -not @($ga.Value).Count) { $why.Add('not a Global Administrator') }
        & $add 'breakglass' "account:$($a.Upn)" "$($a.Upn) ($($a.Method))" $(if ($why.Count) { 'check' } else { 'ok' }) $(if ($why.Count) { $why -join '; ' } else { 'enabled, cloud-only, password never expires, Global Administrator' })
    }
    $bgRole = $cat.breakGlassGroupRole
    $bgNames = @(Get-EpsCaRoleGroupNames -Role $bgRole -Ctx @{ Method = 'Dynamic_Using_Tags'; TargetGroups = $ctx.TargetGroups } -Catalog $cat)
    & $lookupGroups $bgNames
    foreach ($n in $bgNames) { $gi = $groupInfo[$n]; & $add 'breakglass' "group:$n" "Break-glass group $n" $(if ($gi.Found) { if ($gi.Members -ge 1) { 'ok' } else { 'check' } } elseif ($null -eq $gi.Found) { 'unknown' } else { 'missing' }) $(if ($gi.Found) { "in the tenant, $($gi.Members) member(s); every template excludes it" } elseif ($gi.Error) { $gi.Error } else { 'not in the tenant - every template excludes it' }) }
    $bad = @(& $sql "SELECT DisplayName FROM eps.CaPolicy WHERE JSON_VALUE(ReviewJson, '$.breakGlass.ok') = 'false'" | ForEach-Object { "$($_.DisplayName)" })
    & $add 'breakglass' 'excluded' 'Excluded from every Conditional Access policy' $(if ($bad.Count) { 'missing' } else { 'ok' }) $(if ($bad.Count) { "$($bad.Count) policy(ies) do not exclude them: $(@($bad | Select-Object -First 5) -join ', ')$(if ($bad.Count -gt 5) { ', ...' })" } else { 'every policy read excludes the break-glass group or accounts (or is the break-glass policy)' })
    & $add 'breakglass' 'fido2' 'FIDO2 keys registered' 'unknown' 'read with the break-glass step (it needs UserAuthenticationMethod.Read.All, not granted yet)'

    # 3 authentication strengths and methods
    $sp = Invoke-EpsOnboardingGraph -Path 'v1.0/policies/authenticationStrengthPolicies?$filter=policyType eq ''custom''' -All
    foreach ($k in 'FIDO', 'WHfB') {
        $def = $d.authStrengths[$k]; $name = & $set $def.setting
        if (-not $name) { $name = "$($cat.authStrengthDefaults[$k])" }
        if (-not $sp.Ok) { & $add 'auth' "strength:$k" "Authentication strength $name" 'unknown' $sp.Error; continue }
        $hit = @($sp.Value | Where-Object { "$($_.displayName)" -eq $name })[0]
        if (-not $hit) { & $add 'auth' "strength:$k" "Authentication strength $name" 'missing' "not in the tenant - the templates that require it ($k) cannot be met. v1 created it: $(@($def.allowedCombinations) -join ' + ')"; continue }
        $why = [System.Collections.Generic.List[string]]::new()
        $have = @($hit.allowedCombinations | ForEach-Object { "$_" } | Sort-Object); $want = @($def.allowedCombinations | Sort-Object)
        if (($have -join ',') -ne ($want -join ',')) { $why.Add("allows $($have -join ' + '), v1 set $($want -join ' + ')") }
        if ($def.fido2AllowedAAGUIDs) {
            $cc = Invoke-EpsOnboardingGraph -Path "v1.0/policies/authenticationStrengthPolicies/$($hit.id)/combinationConfigurations" -All
            if ($cc.Ok) {
                $ag = @($cc.Value | ForEach-Object { @($_.allowedAAGUIDs) } | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
                $miss = @($def.fido2AllowedAAGUIDs | Where-Object { $ag -notcontains $_ })
                if (-not $ag.Count) { $why.Add('allows every FIDO2 key model (v1 allowed 11 named models)') } elseif ($miss.Count) { $why.Add("$($miss.Count) of v1's 11 key models are not allowed") }
            }
        }
        & $add 'auth' "strength:$k" "Authentication strength $name" $(if ($why.Count) { 'check' } else { 'ok' }) $(if ($why.Count) { $why -join '; ' } else { "in the tenant, as v1 set it ($(@($def.allowedCombinations) -join ' + '))" })
    }
    $mp = Invoke-EpsOnboardingGraph -Path 'v1.0/policies/authenticationMethodsPolicy'
    if ($mp.Ok) {
        foreach ($m in @($d.authMethods)) {
            $c = @($mp.Value.authenticationMethodConfigurations | Where-Object { "$($_.id)" -ieq $m })[0]
            & $add 'auth' "method:$m" "Authentication method $m" $(if ("$($c.state)" -eq 'enabled') { 'ok' } else { 'missing' }) $(if ("$($c.state)" -eq 'enabled') { 'switched on in the tenant' } else { 'switched off in the tenant''s authentication methods policy - the identities tagged for it cannot use it' })
        }
    } else { & $add 'auth' 'methods' 'Authentication methods policy' 'unknown' $mp.Error }
    $ssprNames = @(Get-EpsCaRoleGroupNames -Role 'SSPR_All' -Ctx @{ Method = 'Dynamic_Using_Tags'; TargetGroups = $ctx.TargetGroups } -Catalog $cat)
    & $lookupGroups $ssprNames
    foreach ($n in $ssprNames) { $gi = $groupInfo[$n]; & $add 'auth' "group:$n" "Registration group $n" $(if ($gi.Found) { 'ok' } elseif ($null -eq $gi.Found) { 'unknown' } else { 'missing' }) $(if ($gi.Found) { "in the tenant, $($gi.Members) member(s)" } elseif ($gi.Error) { $gi.Error } else { 'not in the tenant (v1 created it for the MFA / SSPR registration)' }) }

    # 4 targeting method and names
    $raw = & $set 'CA.GroupTargetingMethod'
    & $add 'method' 'method' 'Group targeting method' $(if ($method) { 'ok' } else { 'missing' }) $(if ($method) { "$method$(if ($raw -ne $method) { " (set as '$raw')" })" } else { 'not set - choose one of v1''s three methods; the pilot and target group names follow from it' })
    $t200 = $cat.ById['CA200']
    if ($t200) {
        $ex = @(foreach ($m in @($cat.groupTargetingMethods)) { "$m -> pilot $(@($t200.groups.pilot[$m])[0])" }) -join '; '
        & $add 'method' 'names' 'The group names (v1''s convention, fixed)' 'info' "for example CA200: $ex; exclude $($t200.groups.exclude)"
    }

    # 5 target groups
    $roles = @($cat.groupRoles.Keys | Where-Object { $_ -notlike 'BreakGlassAccounts*' -and $_ -ne 'SSPR_All' } | Sort-Object)
    if (-not $method) { & $add 'targets' 'method' 'Target groups' 'unknown' 'set the group targeting method first: it decides which names are checked' }
    else {
        $names = @(foreach ($r in $roles) { @(Get-EpsCaRoleGroupNames -Role $r -Ctx @{ Method = $method; TargetGroups = $ctx.TargetGroups } -Catalog $cat) })
        & $lookupGroups $names
        $stored = @{}; foreach ($t in @(& $sql 'SELECT DisplayName, GroupQuery FROM eps.TargetGroup')) { $stored["$($t.DisplayName)"] = "$($t.GroupQuery)" }
        $miss = 0; $empty = 0
        foreach ($n in ($names | Select-Object -Unique)) {
            $gi = $groupInfo[$n]
            $st = if ($null -eq $gi.Found) { 'unknown' } elseif (-not $gi.Found) { 'missing' } elseif ($gi.Members -eq 0) { 'check' } else { 'ok' }
            $why = if ($null -eq $gi.Found) { $gi.Error } elseif (-not $gi.Found) { $(if ($gi.Error) { $gi.Error } else { 'not in the tenant (v1 created it)' }) } else { "$($gi.Members) member(s)$(if ($gi.Members -eq 0) { ' - v1 stopped on an empty target group' })" }
            if ($gi.Found -and $gi.Dynamic -and $stored[$n] -and (($stored[$n] -replace '\s+', ' ').Trim() -ne ($gi.Rule -replace '\s+', ' ').Trim())) { $st = 'check'; $why += '; its rule differs from the one stored (v1''s)' }
            if ($st -eq 'missing') { $miss++ } elseif ($st -eq 'check') { $empty++ }
            & $add 'targets' "group:$n" $n $st $why
        }
    }

    # 6 pilot and exclude groups of the adopted policies' templates
    $tids = @(& $sql "SELECT DISTINCT TemplateId FROM eps.CaAdoption WHERE Status = 'Adopted' AND TemplateId IS NOT NULL" | ForEach-Object { "$($_.TemplateId)" })
    if (-not $tids.Count) { & $add 'pilots' 'none' 'Pilot and exclude groups' 'info' 'no adopted policy yet: adopt your policies on the Conditional Access page, then their groups are checked here' }
    elseif (-not $method) { & $add 'pilots' 'method' 'Pilot and exclude groups' 'unknown' 'set the group targeting method first' }
    else {
        $want = [ordered]@{}
        foreach ($id in $tids) { $t = $cat.ById[$id]; if (-not $t) { continue }; foreach ($n in @($t.groups.pilot[$method])) { $want[$n] = "pilot ($id)" }; if ($t.groups.exclude) { $want["$($t.groups.exclude)"] = "exclude ($id)" } }
        & $lookupGroups @($want.Keys)
        foreach ($n in $want.Keys) {
            $gi = $groupInfo[$n]
            & $add 'pilots' "group:$n" $n $(if ($null -eq $gi.Found) { 'unknown' } elseif (-not $gi.Found) { 'missing' } elseif ($want[$n] -like 'pilot*' -and $gi.Members -eq 0) { 'check' } else { 'ok' }) $(if ($null -eq $gi.Found) { $gi.Error } elseif (-not $gi.Found) { "$($want[$n]) - not in the tenant (v1 created it)" } else { "$($want[$n]) - $($gi.Members) member(s)$(if ($want[$n] -like 'pilot*') { "; $($d.pilotGroupSizes)" })" })
        }
    }

    # 7 administrative units
    $aus = @(& $sql 'SELECT DisplayName, Purpose FROM eps.AdminUnit')
    $au = Invoke-EpsOnboardingGraph -Path 'v1.0/directory/administrativeUnits?$select=id,displayName' -All
    if (-not $aus.Count) { & $add 'aus' 'none' 'Administrative units' 'info' 'none configured (v1 used three: target, pilot and exclude groups)' }
    foreach ($x in $aus) {
        $n = "$($x.DisplayName)"
        & $add 'aus' "au:$n" "$n ($($x.Purpose))" $(if (-not $au.Ok) { 'unknown' } elseif (@($au.Value | Where-Object { "$($_.displayName)" -eq $n }).Count) { 'ok' } else { 'missing' }) $(if (-not $au.Ok) { "cannot be read yet ($(if ($au.Denied) { 'it needs AdministrativeUnit.ReadWrite.All, which comes with the administrative-unit step' } else { $au.Error }))" } elseif (@($au.Value | Where-Object { "$($_.displayName)" -eq $n }).Count) { 'in the tenant' } else { 'not in the tenant (v1 created it)' })
    }

    # 8 named locations
    # inline GET (Test-EpsNoCaWrite: a Conditional Access URL stands only as the -Path of an Invoke-EpsGraph read)
    $nl = try { @{ Ok = $true; Value = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All) } } catch { @{ Ok = $false; Error = (("$($_.Exception.Message)" -split '->')[-1]).Trim() } }
    $dn = & $set $d.deniedCountries.setting; if (-not $dn) { $dn = "$($cat.namedLocationDefaults.DeniedCountries)" }
    if (-not $nl.Ok) { & $add 'locations' 'read' 'Named locations' 'unknown' $nl.Error }
    else {
        $den = @($nl.Value | Where-Object { "$($_.displayName)" -eq $dn })[0]
        if (-not $den) { & $add 'locations' 'denied' "Denied countries ($dn)" 'missing' "not in the tenant - CA001 blocks sign-ins from it. v1 created it with $(@($d.deniedCountries.countries) -join ', ') and unknown countries" }
        else {
            $have = @($den.countriesAndRegions | ForEach-Object { "$_" } | Sort-Object)
            $extra = @($d.deniedCountries.countries | Where-Object { $have -notcontains $_ })
            & $add 'locations' 'denied' "Denied countries ($dn)" $(if ($extra.Count) { 'check' } else { 'ok' }) "$($have.Count) countries$(if ($extra.Count) { "; not in it from v1's list: $($extra -join ', ')" })$(if ($den.includeUnknownCountriesAndRegions) { '; unknown countries included' })"
        }
        $trusted = @($nl.Value | Where-Object { "$($_.'@odata.type')" -match 'ipNamedLocation' -and $_.isTrusted })
        & $add 'locations' 'trusted' 'Trusted locations (office IPs)' $(if ($trusted.Count) { 'ok' } else { 'missing' }) $(if ($trusted.Count) { "$($trusted.Count): $(@($trusted | ForEach-Object displayName) -join ', ')" } else { 'none - about 90 template conditions use "all trusted locations"; v1 never made one, you add your office / NAT IPs' })
    }
    $tags = @(& $sql 'SELECT Tag FROM eps.ServiceTagLocation WHERE Enabled = 1')
    & $add 'locations' 'servicetags' 'Azure service tags as named locations' 'info' $(if ($tags.Count) { "$($tags.Count) tag(s): $(@($tags | ForEach-Object Tag) -join ', ') - $(if ((& $set 'NamedLocations.Enabled' 'false') -eq 'true') { 'the named-locations job keeps them daily (switched on)' } else { 'the named-locations job keeps them once NamedLocations.Enabled is on (it is off) - then switch v1''s job off' })" } else { 'none' })

    # 9 tag attributes and rules
    foreach ($t in @(& $sql "SELECT Name, ObjectType, Attribute, Enabled FROM eps.TagType ORDER BY ObjectType, Name")) {
        & $add 'tags' "tagtype:$($t.ObjectType):$($t.Name)" "$($t.ObjectType) tag $($t.Name)" $(if ($t.Attribute -and $t.Attribute -isnot [DBNull]) { 'ok' } else { 'missing' }) $(if ($t.Attribute -and $t.Attribute -isnot [DBNull]) { "in $($t.Attribute)$(if (-not $t.Enabled) { ' (switched off)' })" } else { 'no attribute set' })
    }
    $ur = @(& $sql 'SELECT COUNT(*) AS n FROM eps.UserTagRule WHERE Enabled = 1')[0].n; $dr = @(& $sql 'SELECT COUNT(*) AS n FROM eps.DeviceTagRule WHERE Enabled = 1')[0].n
    & $add 'tags' 'rules' 'Tag rules' $(if ([int]$ur -gt 0) { 'ok' } else { 'missing' }) "$ur user rule(s), $dr device rule(s) switched on$(if ([int]$ur -eq 0) { ' - import your v1 rule files or add rules on the Tagging Rules page' })"
    $exo = & $set 'UserTagging.ExcludeObjects' '[]'
    & $add 'tags' 'syncaccount' 'The AD Connect sync account is left out of tagging' $(if ($exo -match [regex]::Escape($d.syncAccountName) -or $exo -match '(?i)Sync_') { 'ok' } else { 'check' }) $(if ($exo -match [regex]::Escape($d.syncAccountName) -or $exo -match '(?i)Sync_') { 'left out (UserTagging.ExcludeObjects)' } else { "v1 skipped '$($d.syncAccountName)' - add it to UserTagging.ExcludeObjects" })

    # 10 mail
    $mm = & $set 'Mail.Mode' 'none'; $ms = & $set 'Mail.Sender'; $mr = & $set 'Mail.Recipients' '[]'
    & $add 'mail' 'sender' 'Alert mail sender' $(if ($mm -ne 'none' -and $ms) { 'ok' } else { 'missing' }) $(if ($mm -ne 'none' -and $ms) { "$ms ($mm)" } else { 'no mail is sent - set it up with Initialize-EpsMailSender.ps1 (an Exchange admin), then Settings > Mail' })
    & $add 'mail' 'recipients' 'Alert recipients' $(if ($mr -match '@') { 'ok' } else { 'missing' }) $(if ($mr -match '@') { $mr } else { 'nobody receives the alerts - Settings > Mail.Recipients' })

    # 11 hybrid
    $w = @(& $sql 'SELECT WorkerName, LastSeenUtc FROM eps.WorkerHeartbeat ORDER BY LastSeenUtc DESC')
    $adRules = @(& $sql "SELECT COUNT(*) AS n FROM eps.UserTagRule WHERE Enabled = 1 AND TagValueAD IS NOT NULL AND TagValueAD <> ''")[0].n
    if (-not $w.Count) { & $add 'hybrid' 'worker' 'Hybrid worker' $(if ([int]$adRules -gt 0) { 'missing' } else { 'info' }) $(if ([int]$adRules -gt 0) { "no worker reports, but $adRules rule(s) tag AD-synced users - install the hybrid worker" } else { 'not needed while no rule tags AD-synced users' }) }
    foreach ($x in $w) { $age = ([datetime]::UtcNow - [datetime]$x.LastSeenUtc).TotalMinutes; & $add 'hybrid' "worker:$($x.WorkerName)" "Hybrid worker $($x.WorkerName)" $(if ($age -le 60) { 'ok' } else { 'check' }) "last seen $([int]$age) minute(s) ago" }

    # 12 reports
    foreach ($k in 'User', 'ServiceAccount', 'SharedUser', 'SharedMailbox') { $v = & $set "IdentityReport.AdOu.$k"; & $add 'reports' "adou:$k" "Identity report AD OU for $k" $(if ($v) { 'ok' } else { 'info' }) $(if ($v) { $v } else { 'not set - the report''s AD validation view for these accounts stays empty (v1 kept it in Automation-DefaultVariables.psm1)' }) }

    # 13 templates that need an input
    foreach ($id in @($d.templatesNeedingInput.Keys | Sort-Object)) {
        $used = $tids -contains $id
        & $add 'templates' "template:$id" "$id $(if ($cat.ById[$id]) { $cat.ById[$id].name })" $(if ($used) { 'check' } else { 'info' }) "needs $($d.templatesNeedingInput[$id]) (it ships with none)$(if ($used) { ' - you adopted a policy of it: check its applications' })"
    }
    & $Log 'Info' "Get started check: $($rows.Count) item(s) - $(@($rows | Where-Object { $_.state -eq 'ok' }).Count) ok, $(@($rows | Where-Object { $_.state -eq 'missing' }).Count) missing, $(@($rows | Where-Object { $_.state -eq 'check' }).Count) to check"
    @{ Rows = @($rows); Rights = $rights }
}

function Save-EpsOnboardingCheck {
    # the check's rows replace the last ones, in one transaction (the engine writes, the web app reads)
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Rows = @(), [string]$Actor = 'engine')
    $json = if (@($Rows).Count) { ConvertTo-Json -InputObject @($Rows | ForEach-Object { [ordered]@{ s = $_.step; i = ("$($_.item)".Substring(0, [Math]::Min(200, "$($_.item)".Length))); t = $_.title; st = $_.state; d = $_.detail } }) -Compress -Depth 4 } else { '[]' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $json; by = $Actor } -Query @'
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.OnboardingCheck;
INSERT INTO eps.OnboardingCheck (Step, Item, Title, State, Detail, CheckedBy)
SELECT x.s, x.i, LEFT(x.t, 400), x.st, LEFT(x.d, 2000), @by FROM OPENJSON(@j) WITH (s NVARCHAR(40) '$.s', i NVARCHAR(200) '$.i', t NVARCHAR(MAX) '$.t', st NVARCHAR(20) '$.st', d NVARCHAR(MAX) '$.d') AS x;
COMMIT;
'@)
}

function Get-EpsOnboardingOverview {
    # the Get started page: every step with its stored items and a state per step (the worst of its items)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Step, Item, Title, State, Detail, CheckedAtUtc, CheckedBy FROM eps.OnboardingCheck ORDER BY CheckId')
    $rank = @{ missing = 4; check = 3; unknown = 2; ok = 1; info = 0 }
    $steps = @(foreach ($s in $script:EpsOnboardingSteps) {
        $it = @($rows | Where-Object { "$($_.Step)" -eq $s.key })
        $worst = if ($it.Count) { @($it | Sort-Object { $rank["$($_.State)"] } -Descending)[0].State } else { 'unknown' }
        [ordered]@{ key = $s.key; title = $s.title; what = $s.what; state = $(if ($worst -eq 'info') { 'ok' } else { "$worst" })
                    counts = [ordered]@{ ok = @($it | Where-Object State -eq 'ok').Count; missing = @($it | Where-Object State -eq 'missing').Count; check = @($it | Where-Object State -eq 'check').Count; unknown = @($it | Where-Object State -eq 'unknown').Count }
                    items = @($it | ForEach-Object { [ordered]@{ item = "$($_.Item)"; title = "$($_.Title)"; state = "$($_.State)"; detail = "$($_.Detail)" } }) } })
    @{ Steps = $steps; CheckedAtUtc = $(if ($rows.Count) { $rows[0].CheckedAtUtc }); CheckedBy = $(if ($rows.Count) { "$($rows[0].CheckedBy)" }) }
}

# ---- the break-glass account list, edited in the GUI (until now only the v1 import filled it) ------------------------------
function Save-EpsBreakGlassAccount {
    <#
      Adds or changes ONE break-glass account in EPS's list (eps.BreakGlassAccount) - the list every Conditional Access
      check and the stage move's break-glass check use. EPS's own data: nothing in the tenant changes (creating the account
      itself is the break-glass step's create, DESIGN §5.1a). Turning one off keeps it in the list (Enabled = 0).
      Journaled. Returns @{ Result = ok | unchanged; Before; After }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$UserPrincipalName, [string]$DisplayName, [string]$Method,
          [string]$Placement, [bool]$Enabled = $true, [Parameter(Mandatory)][string]$Actor)
    $upn = $UserPrincipalName.Trim().ToLowerInvariant()
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ u = $upn } -Query "SELECT UserPrincipalName, DisplayName, AuthenticationMethod, Placement, Enabled FROM eps.BreakGlassAccount WHERE UserPrincipalName = @u AND Directory = 'Entra'")[0]
    $before = if ($cur) { [ordered]@{ upn = [string]$cur.UserPrincipalName; displayName = $(if ($cur.DisplayName -isnot [DBNull]) { [string]$cur.DisplayName }); method = $(if ($cur.AuthenticationMethod -isnot [DBNull]) { [string]$cur.AuthenticationMethod }); placement = $(if ($cur.Placement -isnot [DBNull]) { [string]$cur.Placement }); enabled = [bool]$cur.Enabled } }
    $after = [ordered]@{ upn = $upn; displayName = $(if ($DisplayName) { $DisplayName.Trim() }); method = $(if ($Method) { $Method }); placement = $(if ($Placement) { $Placement.Trim() }); enabled = $Enabled }
    if ($before -and ($before | ConvertTo-Json -Compress) -eq ($after | ConvertTo-Json -Compress)) { return @{ Result = 'unchanged'; Before = $before; After = $after } }
    $p = @{ u = $upn; n = $(if ($after.displayName) { $after.displayName } else { [DBNull]::Value }); m = $(if ($after.method) { $after.method } else { [DBNull]::Value }); pl = $(if ($after.placement) { $after.placement } else { [DBNull]::Value }); e = $Enabled } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'BreakGlassAccount' -Key $upn -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before $(if ($before) { $before | ConvertTo-Json -Compress }) -After ($after | ConvertTo-Json -Compress))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
IF EXISTS (SELECT 1 FROM eps.BreakGlassAccount WHERE UserPrincipalName = @u)
    UPDATE eps.BreakGlassAccount SET DisplayName = @n, AuthenticationMethod = @m, Placement = @pl, Enabled = @e, UpdatedAtUtc = SYSUTCDATETIME() WHERE UserPrincipalName = @u;
ELSE
    INSERT INTO eps.BreakGlassAccount (UserPrincipalName, DisplayName, AuthenticationMethod, Placement, Enabled) VALUES (@u, @n, @m, @pl, @e);
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Before = $before; After = $after }
}

function Get-EpsBreakGlassAccounts {
    param([Parameter(Mandatory)][string]$ConnectionString)
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT UserPrincipalName, DisplayName, AuthenticationMethod, ClassificationTagValue, AuthenticationTagValue, Placement, Enabled, UpdatedAtUtc FROM eps.BreakGlassAccount WHERE Directory = 'Entra' ORDER BY UserPrincipalName")
}
