# EntraPolicySuite -- the CA Policy Analyzer (DESIGN §5.7; owner 2026-10-30: "ca policy analyzer", his "ca monitor").
# Ported 1:1 from v1 C:\SCRIPTS\Entra-Policy-Suite\CAPolicyEvaluator\CAPolicyEvaluator.ps1 - REST, no module.
#
# READ ONLY: it reads Conditional Access policies, users, groups, roles, risk, Intune compliance and sign-in logs, and
# calls Graph's What-If evaluate API (a simulation). It never writes a policy - DESIGN §5.1's hard rule holds.
#
# Two modes, per policy:
#   WhatIf      - PREDICTION: the policy's in-scope users, a simulated sign-in built from the policy's OWN conditions
#                 (+ each user's REAL user risk and REAL device compliance), POST /identity/conditionalAccess/evaluate
#                 per user in $batch of 20. BLOCKED / ALLOWED / NOT_IN_SCOPE / ERROR.
#   SignInLogs  - OBSERVATION: the real sign-ins of a window, fetched ONCE for every policy of the run; per user the
#                 LATEST outcome decides. BLOCKED / REGRESSED / CHALLENGED (impacted), RECOVERED / OK / NO_SIGNIN.
# Fixed against v1 (docs/REQUIREMENTS.md §2): device compliance is read with $batch (v1: one call per user); the batch
# counter counts what the worker writes; DeviceManagementManagedDevices.Read.All is in the rights list.

Set-StrictMode -Off

$script:EpsCaGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$script:EpsCaExchangeOnline = '00000002-0000-0ff1-ce00-000000000000'
$script:EpsCaImpacted = 'BLOCKED', 'REGRESSED', 'CHALLENGED', 'SPN_BLOCKED', 'SPN_REGRESSED', 'SPN_CHALLENGED'

function Get-EpsCaValue {
    # a property of a Graph object (PSCustomObject or hashtable), $null when missing
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $Object.$Name
}

# ---- which policies -------------------------------------------------------------------------------------------------
function Select-EpsCaPolicies {
    # ids (exact), names (exact, one match each), prefixes (CA006 -> CA006-Initial-..., CA006-Prod-..., never CA0060) and
    # wildcards (CA2* = a whole series; owner 2026-10-30 "ca2xx in one monitor") against the tenant's policy list.
    # Returns @{ Ids; Errors; Unmatched }.
    # + personas (owner 2026-11-02): every policy whose template is of that persona, resolved at each run
    param([object[]]$Policies, [string[]]$Ids = @(), [string[]]$Names = @(), [string[]]$Prefixes = @(), [string[]]$Patterns = @(), [string[]]$Personas = @())
    $out = [System.Collections.Generic.List[string]]::new(); $err = [System.Collections.Generic.List[string]]::new(); $miss = [System.Collections.Generic.List[string]]::new()
    $add = { param($id) if (-not $out.Contains($id)) { $out.Add($id) } }
    foreach ($id in $Ids) { if ($id -notmatch $script:EpsCaGuid) { $err.Add("'$id' is not a policy id"); continue }; if (@($Policies | Where-Object { $_.id -eq $id }).Count) { & $add $id } else { $miss.Add($id) } }
    foreach ($n in $Names) {
        $m = @($Policies | Where-Object { $_.displayName -ieq $n })
        if (-not $m.Count) { $miss.Add($n) } elseif ($m.Count -gt 1) { $err.Add("'$n' matches $($m.Count) policies - name it by id") } else { & $add $m[0].id }
    }
    foreach ($p in $Prefixes) {
        # a full policy number (CA006) takes its lifecycle variants and never a longer number (CA0060); a shorter series
        # (ca2, CA20) takes every policy that starts with it (owner 2026-11-02: "when i write fx ca2 it should show all ca2xx")
        $whole = $p -match '^(?i)CA\d{3}$'
        $m = @($Policies | Where-Object { $_.displayName -like "$([WildcardPattern]::Escape($p))*" -and (-not $whole -or $_.displayName.Length -eq $p.Length -or $_.displayName.Substring($p.Length, 1) -notmatch '[0-9A-Za-z]') } | Sort-Object displayName)
        if (-not $m.Count) { $miss.Add("$p*") } else { foreach ($x in $m) { & $add $x.id } }
    }
    foreach ($w in $Patterns) {
        $wp = [WildcardPattern]::new($w, [Management.Automation.WildcardOptions]::IgnoreCase)
        $m = @($Policies | Where-Object { $wp.IsMatch([string]$_.displayName) } | Sort-Object displayName)
        if (-not $m.Count) { $miss.Add($w) } else { foreach ($x in $m) { & $add $x.id } }
    }
    if (@($Personas).Count) {
        $cat = Get-EpsCaTemplateCatalog
        foreach ($pe in $Personas) {
            $m = @($Policies | Where-Object { (Get-EpsCaPersona -DisplayName ([string]$_.displayName) -Catalog $cat) -ieq $pe } | Sort-Object displayName)
            if (-not $m.Count) { $miss.Add("persona $pe") } else { foreach ($x in $m) { & $add $x.id } }
        }
    }
    @{ Ids = @($out); Errors = @($err); Unmatched = @($miss) }
}

# ---- who a policy targets -------------------------------------------------------------------------------------------
function Get-EpsCaTargeting {
    param([Parameter(Mandatory)]$Policy)
    $uc = Get-EpsCaValue (Get-EpsCaValue $Policy 'conditions') 'users'
    $iu = @((Get-EpsCaValue $uc 'includeUsers') | Where-Object { $_ }); $ig = @((Get-EpsCaValue $uc 'includeGroups') | Where-Object { $_ }); $ir = @((Get-EpsCaValue $uc 'includeRoles') | Where-Object { $_ })
    $ca = Get-EpsCaValue (Get-EpsCaValue $Policy 'conditions') 'clientApplications'
    $is = @((Get-EpsCaValue $ca 'includeServicePrincipals') | Where-Object { $_ -and $_ -ne 'None' })
    $users = (@($iu | Where-Object { $_ -ne 'None' }).Count + $ig.Count + $ir.Count) -gt 0
    @{ Users = $users; All = ($iu -contains 'All'); IncludeUsers = $iu; IncludeGroups = $ig; IncludeRoles = $ir
       ExcludeUsers = @((Get-EpsCaValue $uc 'excludeUsers') | Where-Object { $_ }); ExcludeGroups = @((Get-EpsCaValue $uc 'excludeGroups') | Where-Object { $_ }); ExcludeRoles = @((Get-EpsCaValue $uc 'excludeRoles') | Where-Object { $_ })
       Spns = ($is.Count -gt 0 -or $null -ne (Get-EpsCaValue $ca 'servicePrincipalFilter')); IncludeSpns = $is
       ExcludeSpns = @((Get-EpsCaValue $ca 'excludeServicePrincipals') | Where-Object { $_ }); SpnFilter = (Get-EpsCaValue $ca 'servicePrincipalFilter') }
}

function Get-EpsCaGroupUserIds { param([string]$GroupId) @(Invoke-EpsGraph -Path "v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999" -All | ForEach-Object { $_.id } | Where-Object { $_ }) }
function Get-EpsCaRoleUserIds {
    # a CA policy names a role by its template id; members of the ACTIVE directoryRole (a role never activated has none)
    param([string]$RoleTemplateId)
    $r = try { Invoke-EpsGraph -Path "v1.0/directoryRoles(roleTemplateId='$RoleTemplateId')?`$select=id" } catch { $null }
    if (-not $r) { return @() }
    @(Invoke-EpsGraph -Path "v1.0/directoryRoles/$($r.id)/members/microsoft.graph.user?`$select=id&`$top=999" -All | ForEach-Object { $_.id } | Where-Object { $_ })
}

function Get-EpsCaScopedUsers {
    # the policy's in-scope users: include users / groups (nested) / roles, minus the excludes; 'All' = the tenant.
    # Guests and disabled accounts are left out unless asked (v1's defaults).
    param([Parameter(Mandatory)]$Targeting, [switch]$IncludeGuests, [switch]$IncludeDisabled, [hashtable]$Notes)
    $sel = 'id,userPrincipalName,displayName,userType,accountEnabled'
    $keep = { param($u) ($IncludeGuests -or "$($u.userType)" -eq 'Member') -and ($IncludeDisabled -or $u.accountEnabled -ne $false) }
    if ($Targeting.All -or (-not @($Targeting.IncludeUsers | Where-Object { $_ -ne 'None' }).Count -and -not $Targeting.IncludeGroups.Count -and -not $Targeting.IncludeRoles.Count)) {
        $f = @(); if (-not $IncludeGuests) { $f += "userType eq 'Member'" }; if (-not $IncludeDisabled) { $f += 'accountEnabled eq true' }
        $q = "v1.0/users?`$select=$sel&`$top=999" + $(if ($f) { '&$filter=' + [uri]::EscapeDataString($f -join ' and ') })
        $all = @(Invoke-EpsGraph -Path $q -All -Eventual)
        $ex = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($u in $Targeting.ExcludeUsers) { if ($u -match $script:EpsCaGuid) { [void]$ex.Add($u) } }
        foreach ($g in $Targeting.ExcludeGroups) { foreach ($i in Get-EpsCaGroupUserIds $g) { [void]$ex.Add($i) } }
        foreach ($r in $Targeting.ExcludeRoles) { foreach ($i in Get-EpsCaRoleUserIds $r) { [void]$ex.Add($i) } }
        return @($all | Where-Object { -not $ex.Contains([string]$_.id) -and (& $keep $_) })
    }
    $inc = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $Targeting.IncludeUsers) { if ($u -match $script:EpsCaGuid) { [void]$inc.Add($u) } }
    if ($Targeting.IncludeUsers -contains 'GuestsOrExternalUsers' -and $Notes) { $Notes['guests'] = "the policy targets 'GuestsOrExternalUsers': guests are not enumerated one by one" }
    foreach ($g in $Targeting.IncludeGroups) { foreach ($i in Get-EpsCaGroupUserIds $g) { [void]$inc.Add($i) } }
    foreach ($r in $Targeting.IncludeRoles) { foreach ($i in Get-EpsCaRoleUserIds $r) { [void]$inc.Add($i) } }
    foreach ($u in $Targeting.ExcludeUsers) { [void]$inc.Remove($u) }
    foreach ($g in $Targeting.ExcludeGroups) { foreach ($i in Get-EpsCaGroupUserIds $g) { [void]$inc.Remove($i) } }
    foreach ($r in $Targeting.ExcludeRoles) { foreach ($i in Get-EpsCaRoleUserIds $r) { [void]$inc.Remove($i) } }
    $ids = @($inc)
    $out = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ids.Count; $i += 20) {
        $slice = $ids[$i..([Math]::Min($i + 19, $ids.Count - 1))]
        $reqs = @(for ($j = 0; $j -lt $slice.Count; $j++) { @{ id = "$j"; method = 'GET'; url = "/users/$($slice[$j])?`$select=$sel" } })
        $resp = Invoke-EpsGraph -Method POST -Path 'v1.0/$batch' -Body @{ requests = $reqs }
        foreach ($r in @($resp.responses)) { if ([int]$r.status -eq 200 -and $r.body -and (& $keep $r.body)) { $out.Add($r.body) } }
    }
    @($out)
}

# ---- the simulated sign-in (WhatIf) ---------------------------------------------------------------------------------
function New-EpsCaSignInConditions {
    # mirrors EXACTLY what the policy sets (a field the policy leaves unset is not sent - it would test a condition the
    # policy does not have); what cannot be simulated is listed, never guessed. -Simulate pins a scenario (v1's
    # -Simulate* parameters: country, ipAddress, devicePlatform, clientAppType, signInRiskLevel, userRiskLevel,
    # insiderRiskLevel, authenticationFlow, deviceCompliant, applicationIds).
    param([Parameter(Mandatory)]$Policy, [hashtable]$Simulate = @{})
    $c = Get-EpsCaValue $Policy 'conditions'
    $s = [ordered]@{}; $unresolved = [System.Collections.Generic.List[string]]::new(); $warn = [System.Collections.Generic.List[string]]::new()
    $apps = @((Get-EpsCaValue $c 'clientAppTypes') | Where-Object { $_ })
    if ($apps.Count -and -not ($apps.Count -eq 1 -and $apps[0] -eq 'all')) { $s.clientAppType = if ($apps.Count -eq 1 -and $apps[0] -eq 'browser') { 'browser' } else { 'mobileAppsAndDesktopClients' } }
    $plat = @((Get-EpsCaValue (Get-EpsCaValue $c 'platforms') 'includePlatforms') | Where-Object { $_ -and $_ -ne 'all' })
    if ($plat.Count) { $s.devicePlatform = [string]$plat[0] }
    $sr = @((Get-EpsCaValue $c 'signInRiskLevels') | Where-Object { $_ }); if ($sr.Count) { $s.signInRiskLevel = [string]$sr[0] }
    $ir = @((Get-EpsCaValue $c 'insiderRiskLevels') | Where-Object { $_ }); if ($ir.Count) { $s.insiderRiskLevel = [string]$ir[0] }
    $spr = @((Get-EpsCaValue $c 'servicePrincipalRiskLevels') | Where-Object { $_ }); if ($spr.Count) { $s.servicePrincipalRiskLevel = [string]$spr[0] }
    $tm = "$(Get-EpsCaValue (Get-EpsCaValue $c 'authenticationFlows') 'transferMethods')"
    $tm1 = @($tm -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })[0]; if ($tm1) { $s.authenticationFlow = @{ transferMethod = $tm1 } }
    $loc = @((Get-EpsCaValue (Get-EpsCaValue $c 'locations') 'includeLocations') | Where-Object { $_ })
    if ($loc.Count -and $loc -notcontains 'All') {
        $concrete = @($loc | Where-Object { $_ -ne 'AllTrusted' })
        $cc = @($concrete | Where-Object { $_ -match '^[A-Za-z]{2}$' })[0]
        if ($cc) { $s.country = $cc.ToUpperInvariant() } elseif ($concrete.Count) { $unresolved.Add("locations: the named / IP location '$($concrete[0])' cannot be reduced to one country or IP") }
    }
    if (Get-EpsCaValue (Get-EpsCaValue $c 'devices') 'deviceFilter') { $unresolved.Add('device filter: a device attribute rule the evaluate API cannot simulate') }
    $forceRisk = $false
    foreach ($k in 'country', 'ipAddress', 'devicePlatform', 'clientAppType', 'signInRiskLevel', 'insiderRiskLevel') { if ($Simulate[$k]) { $s[$k] = $(if ($k -eq 'country') { "$($Simulate[$k])".ToUpperInvariant() } else { [string]$Simulate[$k] }) } }
    if ($Simulate.authenticationFlow) { $s.authenticationFlow = @{ transferMethod = [string]$Simulate.authenticationFlow } }
    if ($null -ne $Simulate.deviceCompliant) { $s.deviceInfo = @{ isCompliant = [bool]$Simulate.deviceCompliant } }
    if ($Simulate.userRiskLevel) { $s.userRiskLevel = [string]$Simulate.userRiskLevel; $forceRisk = $true }
    # the app of the simulated sign-in: a real application id (suite aliases like Office365 are not accepted by the API)
    $appsIn = if (@($Simulate.applicationIds | Where-Object { $_ }).Count) { @($Simulate.applicationIds) } else {
        $raw = @((Get-EpsCaValue (Get-EpsCaValue $c 'applications') 'includeApplications') | Where-Object { $_ -and $_ -notin 'All', 'None' })
        $alias = @($raw | Where-Object { $_ -notmatch $script:EpsCaGuid })
        if ($alias.Count) { $warn.Add("the policy targets app alias(es) the evaluate API does not accept ($($alias -join ', ')): simulated against Exchange Online") }
        $g = @($raw | Where-Object { $_ -match $script:EpsCaGuid }); if ($g.Count) { $g } else { @($script:EpsCaExchangeOnline) }
    }
    @{ Conditions = $s; Unresolved = @($unresolved); Warnings = @($warn); Applications = @($appsIn); ForceUserRisk = $forceRisk
       TargetsUserRisk = [bool]@((Get-EpsCaValue $c 'userRiskLevels') | Where-Object { $_ }).Count
       TargetsCompliance = [bool](@((Get-EpsCaValue (Get-EpsCaValue $Policy 'grantControls') 'builtInControls')) -contains 'compliantDevice')
       ForceCompliance = ($null -ne $Simulate.deviceCompliant)
       Platform = $(if ($Simulate.devicePlatform) { "$($Simulate.devicePlatform)" } elseif ($plat.Count -eq 1) { "$($plat[0])" } else { '' }) }
}

function Get-EpsCaGrantOutcome {
    # "the policy applies" -> would the user get through? block never; compliantDevice only with a compliant device we
    # asserted; mfa and the other "require" controls can be satisfied at sign-in (v1: an unknown control too).
    # AND = every control must pass, OR = one.
    param([string[]]$Controls = @(), [string]$Operator = 'OR', $AssertedCompliant)
    $per = @(foreach ($x in $Controls) { switch ($x) { 'block' { $false } 'compliantDevice' { $AssertedCompliant -eq $true } default { $true } } })
    if (-not $per.Count) { return $true }
    if ($Operator -eq 'AND') { -not ($per -contains $false) } else { $per -contains $true }
}

function Get-EpsCaUserRisk {
    # users at risk NOW (riskState atRisk, a level): id (lower) -> level. Needs IdentityRiskyUser.Read.All + Entra P2;
    # without them it throws with the remedy (v1: silently assuming everyone at risk inflated the impact).
    $map = @{}
    try { foreach ($ru in @(Invoke-EpsGraph -Path 'v1.0/identityProtection/riskyUsers?$select=id,riskLevel,riskState&$top=500' -All)) {
        if ($ru.riskState -eq 'atRisk' -and $ru.riskLevel -and $ru.riskLevel -notin 'none', 'hidden') { $map[([string]$ru.id).ToLowerInvariant()] = [string]$ru.riskLevel } } }
    catch { throw "cannot read the risky users (Identity Protection): needs IdentityRiskyUser.Read.All and an Entra ID P2 licence - $($_.Exception.Message)" }
    $map
}

function Get-EpsCaDeviceCompliance {
    # per user: compliant / noncompliant (has a device on the policy's platform) / outofscope (no device on it - the user
    # does not sign in from that platform, so the policy does not hit them). $batch of 20 users per call (v1: one call
    # each). Needs DeviceManagementManagedDevices.Read.All.
    param([object[]]$Users, [string]$Platform)
    $os = switch ("$Platform".ToLowerInvariant()) { 'windows' { @('windows') } 'windowsphone' { @('windowsphone') } 'ios' { @('ios', 'ipados') } 'macos' { @('macmdm', 'macos') } 'android' { @('android', 'androidforwork', 'androidenterprise') } 'linux' { @('linux') } default { $null } }
    $map = @{}
    for ($i = 0; $i -lt $Users.Count; $i += 20) {
        $slice = @($Users[$i..([Math]::Min($i + 19, $Users.Count - 1))])
        $reqs = @(for ($j = 0; $j -lt $slice.Count; $j++) { @{ id = "$j"; method = 'GET'; url = "/users/$($slice[$j].id)/managedDevices?`$select=id,operatingSystem,complianceState&`$top=100" } })
        $resp = Invoke-EpsGraph -Method POST -Path 'v1.0/$batch' -Body @{ requests = $reqs }
        foreach ($r in @($resp.responses)) {
            $u = $slice[[int]$r.id]; $key = ([string]$u.id).ToLowerInvariant()
            $devs = if ([int]$r.status -eq 200) { @($r.body.value) } else { @() }
            $on = @($devs | Where-Object { -not $os -or ($_.operatingSystem -and @($os | Where-Object { "$($_.operatingSystem)".ToLowerInvariant() -like "*$_*" }).Count) })
            # (the inner $_ above is the os pattern; the device is matched by its operatingSystem)
            $on = @(foreach ($d in $devs) { $o = "$($d.operatingSystem)".ToLowerInvariant(); if (-not $os -or @($os | Where-Object { $o -like "*$_*" }).Count) { $d } })
            $map[$key] = if (-not $on.Count) { 'outofscope' } elseif (@($on | Where-Object { $_.complianceState -in 'compliant', 'inGracePeriod' }).Count) { 'compliant' } else { 'noncompliant' }
        }
    }
    $map
}

function ConvertFrom-EpsCaEvaluation {
    # one user's evaluate answer -> the record. The answer lists EVERY policy that applies: ours is picked by id.
    param([Parameter(Mandatory)]$User, $Body, [Parameter(Mandatory)][string]$PolicyId, [string]$Compliance)
    $base = [ordered]@{ UserId = [string]$User.id; UserPrincipalName = [string]$User.userPrincipalName; DisplayName = [string]$User.displayName; IsSpn = $false }
    $hit = @(@($Body.value) | Where-Object { $_ -and "$($_.id)" -ieq $PolicyId })[0]
    if (-not ($hit -and $hit.policyApplies -eq $true)) {
        $base.Classification = 'NOT_IN_SCOPE'; $base.Impacted = $false
        $base.Reason = if ($hit -and $hit.analysisReasons) { [string]$hit.analysisReasons } else { 'the policy does not apply' }
        return [pscustomobject]$base
    }
    $grant = @($hit.grantControls.builtInControls | Where-Object { $_ })
    $op = if ($hit.grantControls.operator) { [string]$hit.grantControls.operator } else { 'OR' }
    $base.GrantControls = $grant -join ', '
    $base.SessionControls = if ($hit.sessionControls) { (@($hit.sessionControls.PSObject.Properties | Where-Object { $null -ne $_.Value } | ForEach-Object Name) -join ', ') } else { '' }
    if ($Compliance -eq 'outofscope' -and $grant -contains 'compliantDevice') {
        $base.Classification = 'ALLOWED'; $base.Impacted = $false
        $base.Reason = "$($hit.analysisReasons) [no managed device on the policy's platform - the user does not sign in from it]"
        return [pscustomobject]$base
    }
    $asserted = switch ($Compliance) { 'compliant' { $true } 'noncompliant' { $false } default { $null } }
    $pass = Get-EpsCaGrantOutcome -Controls $grant -Operator $op -AssertedCompliant $asserted
    $base.Classification = if ($pass) { 'ALLOWED' } else { 'BLOCKED' }; $base.Impacted = -not $pass
    $extra = if (-not $pass -and $grant -contains 'block') { ' [the policy blocks]' } elseif (-not $pass -and $grant -contains 'compliantDevice') { if ($asserted -eq $false) { ' [no compliant managed device]' } else { ' [device compliance unknown - treated as non-compliant]' } } elseif ($pass -and $asserted -eq $true) { ' [has a compliant managed device]' } else { '' }
    $base.Reason = "$($hit.analysisReasons)$extra"
    [pscustomobject]$base
}

function Invoke-EpsCaWhatIf {
    # every in-scope user through the evaluate API, $batch of 20, a throttled user retried after the longest
    # Retry-After (or a backoff) until it resolves or makes no progress (then ERROR - never a silent "allowed").
    param([Parameter(Mandatory)]$Policy, [object[]]$Users = @(), [Parameter(Mandatory)]$Sim, [hashtable]$UserRisk, [hashtable]$Compliance, [int]$MaxNoProgress = 8, [int]$WaitCapSeconds = 300)
    $records = [System.Collections.Generic.List[object]]::new()
    $ctx = @{ '@odata.type' = '#microsoft.graph.applicationContext'; includeApplications = @($Sim.Applications) }
    for ($i = 0; $i -lt $Users.Count; $i += 20) {
        $pending = [System.Collections.Generic.List[object]]::new(); foreach ($u in @($Users[$i..([Math]::Min($i + 19, $Users.Count - 1))])) { $pending.Add($u) }
        $stall = 0; $last = -1; $tries = 0
        while ($pending.Count) {
            $tries++
            $reqs = @(for ($j = 0; $j -lt $pending.Count; $j++) {
                $u = $pending[$j]; $key = ([string]$u.id).ToLowerInvariant(); $cond = [ordered]@{}; foreach ($k in $Sim.Conditions.Keys) { $cond[$k] = $Sim.Conditions[$k] }
                if ($null -ne $UserRisk) { $cond.userRiskLevel = $(if ($UserRisk.ContainsKey($key)) { $UserRisk[$key] } else { 'none' }) }
                if ($null -ne $Compliance -and $Compliance[$key] -in 'compliant', 'noncompliant') { $cond.deviceInfo = @{ isCompliant = ($Compliance[$key] -eq 'compliant') } }
                @{ id = "$j"; method = 'POST'; url = '/identity/conditionalAccess/evaluate'; headers = @{ 'Content-Type' = 'application/json' }
                   body = @{ signInIdentity = @{ '@odata.type' = '#microsoft.graph.userSignIn'; userId = [string]$u.id }; signInContext = $ctx; signInConditions = $cond; appliedPoliciesOnly = $false } } })
            $resp = try { Invoke-EpsGraph -Method POST -Path 'v1.0/$batch' -Body @{ requests = $reqs } } catch { $e = "$($_.Exception.Message)"; foreach ($u in $pending) { $records.Add([pscustomobject]@{ UserId = [string]$u.id; UserPrincipalName = [string]$u.userPrincipalName; DisplayName = [string]$u.displayName; IsSpn = $false; Classification = 'ERROR'; Impacted = $false; Reason = $e }) }; $pending.Clear(); break }
            $still = [System.Collections.Generic.List[object]]::new(); $ra = 0
            foreach ($r in @($resp.responses)) {
                $u = $pending[[int]$r.id]; $st = [int]$r.status
                if ($st -eq 200) { $records.Add((ConvertFrom-EpsCaEvaluation -User $u -Body $r.body -PolicyId ([string]$Policy.id) -Compliance $(if ($Compliance) { $Compliance[([string]$u.id).ToLowerInvariant()] }))) }
                elseif ($st -in 429, 503) { $still.Add($u); $x = 0; if ([int]::TryParse([string]@((Get-EpsCaValue $r.headers 'Retry-After'))[0], [ref]$x) -and $x -gt $ra) { $ra = $x } }
                else { $records.Add([pscustomobject]@{ UserId = [string]$u.id; UserPrincipalName = [string]$u.userPrincipalName; DisplayName = [string]$u.displayName; IsSpn = $false; Classification = 'ERROR'; Impacted = $false; Reason = "HTTP ${st}: $($r.body.error.message)" }) }
            }
            $pending = $still
            if (-not $pending.Count) { break }
            if ($last -ge 0 -and $pending.Count -ge $last) { $stall++ } else { $stall = 0 }; $last = $pending.Count
            if ($stall -ge $MaxNoProgress -or $tries -gt 60) { foreach ($u in $pending) { $records.Add([pscustomobject]@{ UserId = [string]$u.id; UserPrincipalName = [string]$u.userPrincipalName; DisplayName = [string]$u.displayName; IsSpn = $false; Classification = 'ERROR'; Impacted = $false; Reason = 'still throttled (HTTP 429) after repeated retries' }) }; break }
            Start-Sleep -Seconds ([Math]::Min($WaitCapSeconds, $(if ($ra -gt 0) { $ra } else { [Math]::Max(5, [Math]::Pow(2, [Math]::Min($tries, 6))) })))
        }
    }
    @($records)
}

# ---- the sign-in logs (SignInLogs) ----------------------------------------------------------------------------------
function Split-EpsTimeWindow {
    # contiguous, non-overlapping slices; every slice is [start, end) except the last, which closes the window
    param([Parameter(Mandatory)][datetime]$Start, [Parameter(Mandatory)][datetime]$End, [int]$Hours = 0)
    if ($Hours -le 0 -or $End -le $Start) { return @(@{ Start = $Start; End = $End; IsLast = $true }) }
    $s = [System.Collections.Generic.List[hashtable]]::new(); $c = $Start
    while ($c -lt $End) { $e = $c.AddHours($Hours); $last = $e -ge $End; if ($last) { $e = $End }; $s.Add(@{ Start = $c; End = $e; IsLast = $last }); $c = $e }
    $s.ToArray()
}

function Get-EpsCaSignIns {
    # ONE fetch for every policy of the run: per kind (interactive user, non-interactive user, service principal), the
    # window in slices, every page, de-duplicated by id, kept only when it references one of the run's policies.
    # Returns @{ Rows = @{ kind -> list }; Scanned = n }.
    param([Parameter(Mandatory)][datetime]$Start, [Parameter(Mandatory)][datetime]$End, [Parameter(Mandatory)][string[]]$PolicyIds, [string[]]$Kinds = @('user-interactive'), [int]$SliceHours = 0)
    $ref = [System.Collections.Generic.HashSet[string]]::new([string[]]$PolicyIds, [StringComparer]::OrdinalIgnoreCase)
    $sel = 'id,createdDateTime,userId,userPrincipalName,userDisplayName,appDisplayName,ipAddress,clientAppUsed,conditionalAccessStatus,appliedConditionalAccessPolicies,location,deviceDetail,riskLevelDuringSignIn,riskState,resourceDisplayName,status,isInteractive'
    $types = @{ 'user-interactive' = @('interactiveUser', $sel); 'user-noninteractive' = @('nonInteractiveUser', $sel); 'spn' = @('servicePrincipal', $null) }
    $rows = @{}; $scanned = 0
    foreach ($k in $Kinds) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $keep = [System.Collections.Generic.List[object]]::new()
        foreach ($sl in (Split-EpsTimeWindow -Start $Start -End $End -Hours $SliceHours)) {
            $op = if ($sl.IsLast) { 'le' } else { 'lt' }
            $f = "createdDateTime ge $($sl.Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime $op $($sl.End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and signInEventTypes/any(t:t eq '$($types[$k][0])')"
            $q = "beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($f))&`$top=1000" + $(if ($types[$k][1]) { "&`$select=$($types[$k][1])" })
            foreach ($si in @(Invoke-EpsGraph -Path $q -All)) {
                if ($si.id -and -not $seen.Add([string]$si.id)) { continue }
                $scanned++
                if (@($si.appliedConditionalAccessPolicies | Where-Object { $_.id -and $ref.Contains([string]$_.id) }).Count) { $keep.Add($si) }
            }
        }
        $rows[$k] = $keep
    }
    @{ Rows = $rows; Scanned = $scanned }
}

function Measure-EpsCaSignIns {
    # one policy against the shared sign-ins: per user the latest outcome of THIS policy in THIS mode (report-only or
    # enforced - a result of the other mode, from before a state change, is left out and counted). Returns
    # @{ Records; MixedState; InScopeRefs }. Every in-scope user gets a row (NO_SIGNIN = no data, not "safe").
    param([Parameter(Mandatory)]$Policy, [object[]]$ScopedUsers = @(), [Parameter(Mandatory)]$SignIns, [Parameter(Mandatory)]$Targeting)
    $enforced = "$($Policy.state)" -eq 'enabled'
    $pid0 = [string]$Policy.id
    $stats = @{}; $spn = @{}; $mixed = 0; $refs = 0
    $scoped = @{}; foreach ($u in $ScopedUsers) { $scoped[[string]$u.id] = $u }
    $kinds = @(); if ($Targeting.Users) { $kinds += 'user-interactive', 'user-noninteractive' }; if ($Targeting.Spns) { $kinds += 'spn' }
    foreach ($k in $kinds) {
        foreach ($si in @($SignIns.Rows[$k])) {
            if ($null -eq $si) { continue }
            $ap = @($si.appliedConditionalAccessPolicies | Where-Object { "$($_.id)" -ieq $pid0 })[0]
            if (-not $ap) { continue }
            $res = [string]$ap.result
            $ro = $res -like 'reportOnly*'
            if ($enforced -and $ro) { $mixed++; continue }; if (-not $enforced -and $res -in 'success', 'failure') { $mixed++; continue }
            $isSpn = $k -eq 'spn'
            $id = if ($isSpn) { [string]$si.servicePrincipalId } else { [string]$si.userId }
            if (-not $id -or (-not $isSpn -and -not $scoped.ContainsKey($id))) { continue }
            if (-not $isSpn) { $refs++ }
            $fail = $res -in 'failure', 'reportOnlyFailure'; $intr = $res -eq 'reportOnlyInterrupted'; $ok = $res -in 'success', 'reportOnlySuccess'
            if (-not ($fail -or $intr -or $ok)) { continue }   # notApplied and the like
            $t = if ($isSpn) { $spn } else { $stats }
            if (-not $t.ContainsKey($id)) { $t[$id] = @{ Id = $id; Name = $(if ($isSpn) { [string]$si.servicePrincipalName } else { [string]$si.userPrincipalName }); Display = $(if ($isSpn) { [string]$si.servicePrincipalName } else { [string]$si.userDisplayName })
                Failures = 0; Successes = 0; Interrupted = 0; Count = 0; Last = [datetime]::MinValue; LastResult = ''; Controls = (@($ap.enforcedGrantControls) -join ', ')
                Countries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); Ips = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); Si = $null } }
            $r = $t[$id]
            if ($fail) { $r.Failures++ }; if ($ok) { $r.Successes++ }; if ($intr) { $r.Interrupted++ }; $r.Count++
            if ($si.location.countryOrRegion) { [void]$r.Countries.Add([string]$si.location.countryOrRegion) }; if ($si.ipAddress) { [void]$r.Ips.Add([string]$si.ipAddress) }
            # UTC always: ConvertFrom-Json may hand back a LOCAL DateTime for an ISO time
            $d0 = $si.createdDateTime; $when = if ($d0 -is [datetime]) { $d0.ToUniversalTime() } else { [DateTimeOffset]::Parse("$d0", [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
            if ($when -ge $r.Last) { $r.Last = $when; $r.LastResult = $res; $r.Si = $si }
        }
    }
    $records = [System.Collections.Generic.List[object]]::new()
    $row = { param($r, [bool]$isSpn, [bool]$inScope)
        $hard = $r.LastResult -in 'failure', 'reportOnlyFailure'; $ch = $r.LastResult -eq 'reportOnlyInterrupted'
        $cls = if ($hard) { if ($r.Successes) { 'REGRESSED' } else { 'BLOCKED' } } elseif ($ch) { 'CHALLENGED' } elseif ($r.Failures -or $r.Interrupted) { 'RECOVERED' } else { 'OK' }
        if ($isSpn) { $cls = "SPN_$cls" }
        $si = $r.Si
        [pscustomobject]@{ UserId = $r.Id; UserPrincipalName = $r.Name; DisplayName = $(if ($isSpn) { "$($r.Display) (service principal)" } else { $r.Display }); IsSpn = $isSpn
            Classification = $cls; Impacted = ($inScope -and ($hard -or $ch))
            Reason = "$cls`: latest $($r.LastResult) at $($r.Last.ToString('yyyy-MM-dd HH:mm')) UTC ($($si.appDisplayName)); $($r.Failures) failure(s), $($r.Interrupted) challenge(s), $($r.Successes) success(es) in the window"
            GrantControls = $r.Controls; LastSignInUtc = $r.Last; Country = [string]$si.location.countryOrRegion; City = [string]$si.location.city; IPAddress = [string]$si.ipAddress
            DeviceOS = [string]$si.deviceDetail.operatingSystem; Browser = [string]$si.deviceDetail.browser; ClientApp = [string]$si.clientAppUsed
            Application = $(if ($si.appDisplayName) { [string]$si.appDisplayName } else { [string]$si.resourceDisplayName }); RiskLevel = [string]$si.riskLevelDuringSignIn; RiskState = [string]$si.riskState
            CAResult = $r.LastResult; FailureReason = [string]$si.status.failureReason; SignInCount = $r.Count; CountriesSeen = (@($r.Countries) -join ', '); DistinctIPCount = $r.Ips.Count } }
    foreach ($u in $ScopedUsers) {
        $r = $stats[[string]$u.id]
        if (-not $r) { $records.Add([pscustomobject]@{ UserId = [string]$u.id; UserPrincipalName = [string]$u.userPrincipalName; DisplayName = [string]$u.displayName; IsSpn = $false; Classification = 'NO_SIGNIN'; Impacted = $false; Reason = 'in scope; no sign-in in the window (no data, not "safe")'; SignInCount = 0 }); continue }
        $records.Add((& $row $r $false $true))
    }
    foreach ($id in $spn.Keys) {
        $in = if ($Targeting.ExcludeSpns -contains $id) { $false } elseif ($Targeting.IncludeSpns -contains 'ServicePrincipalsInMyTenant' -or $Targeting.IncludeSpns -contains $id -or $null -ne $Targeting.SpnFilter) { $true } else { $false }
        $records.Add((& $row $spn[$id] $true $in))
    }
    @{ Records = @($records); MixedState = $mixed; InScopeRefs = $refs }
}

# ---- the run ---------------------------------------------------------------------------------------------------------
function Get-EpsCaSummary {
    param([object[]]$Records)
    $r = @($Records)
    $by = [ordered]@{}; foreach ($grp in ($r | Group-Object Classification | Sort-Object Name)) { $by[$grp.Name] = $grp.Count }
    [ordered]@{ InScope = @($r | Where-Object { -not $_.IsSpn }).Count; Impacted = @($r | Where-Object Impacted).Count
                NotImpacted = @($r | Where-Object { -not $_.Impacted -and $_.Classification -ne 'ERROR' }).Count; Errors = @($r | Where-Object Classification -eq 'ERROR').Count; ByClass = $by }
}

function Invoke-EpsCaPolicyAnalyzer {
    <#
    .SYNOPSIS
        One analyzer run: the tenant's policy list is refreshed (eps.CaPolicy), the request's policies are analysed in its
        mode, each analysis + its per-user rows are stored, and one alert mail goes out when users are impacted.
    .PARAMETER Request
        @{ Policies = @{ Ids; Names; Prefixes }; Mode = WhatIf | SignInLogs; LookbackHours (24); SliceHours (0);
           IncludeGuests; IncludeDisabled; IncludeNonInteractive; Simulate = @{...}; Monitor = <name>; ListOnly }
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][hashtable]$Request, [guid]$RunId = [guid]::NewGuid(), [string]$Version = '2.0.0', [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    # the WHOLE body of every policy (one paged GET): the analyzer needs id / name / state, Conditional Access management's
    # read-only review (EPS-CaManage: template, stage, diff, break-glass, the monitor) needs the rest
    $policies = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/policies' -All)
    & $Log 'Info' "read $($policies.Count) Conditional Access policies (read only - nothing is changed)"
    $inv = try { Update-EpsCaInventory -ConnectionString $ConnectionString -Policies $policies -Version $Version -Log $Log } catch { & $Log 'Warning' "the Conditional Access review failed (the analysis goes on): $($_.Exception.Message)"; $null }
    Save-EpsCaPolicyList -ConnectionString $ConnectionString -Policies $policies -Reviews $(if ($inv) { $inv.Reviews } else { @{} })
    if ($Request.ListOnly) { return @{ Analyses = @(); Impacted = 0 } }
    $sel = Select-EpsCaPolicies -Policies $policies -Ids @($Request.Policies.Ids) -Names @($Request.Policies.Names) -Prefixes @($Request.Policies.Prefixes) -Patterns @($Request.Policies.Patterns) -Personas @($Request.Policies.Personas)
    foreach ($e in $sel.Errors) { & $Log 'Warning' $e }; foreach ($u in $sel.Unmatched) { & $Log 'Warning' "no policy matches '$u'" }
    if (-not $sel.Ids.Count) { throw "no policy to analyse ($(@($sel.Errors + $sel.Unmatched) -join '; '))" }
    $mode = if ("$($Request.Mode)" -eq 'WhatIf') { 'WhatIf' } else { 'SignInLogs' }   # SignInLogs is the default (owner 2026-10-30)
    $full = @{}; foreach ($id in $sel.Ids) { $full[$id] = Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$id" }
    $shared = $null; $winStart = $null; $winEnd = [datetime]::UtcNow
    if ($mode -eq 'SignInLogs') {
        $hours = if ([int]$Request.LookbackHours -gt 0) { [int]$Request.LookbackHours } else { 24 }
        $winStart = $winEnd.AddHours(-$hours)
        $tg = @($full.Values | ForEach-Object { Get-EpsCaTargeting $_ })
        $kinds = @(); if (@($tg | Where-Object Users).Count) { $kinds += 'user-interactive'; if ($Request.IncludeNonInteractive) { $kinds += 'user-noninteractive' } }; if (@($tg | Where-Object Spns).Count) { $kinds += 'spn' }
        $shared = Get-EpsCaSignIns -Start $winStart -End $winEnd -PolicyIds $sel.Ids -Kinds $kinds -SliceHours ([int]$Request.SliceHours)
        & $Log 'Info' "sign-ins $($winStart.ToString('u')) .. $($winEnd.ToString('u')): $($shared.Scanned) scanned once for $($sel.Ids.Count) policy(ies) ($($kinds -join ', '))"
    }
    $analyses = [System.Collections.Generic.List[object]]::new(); $impactedTotal = 0
    foreach ($id in $sel.Ids) {
        $p = $full[$id]; $notes = @{}; $tg = Get-EpsCaTargeting $p
        $users = if ($tg.Users) { @(Get-EpsCaScopedUsers -Targeting $tg -IncludeGuests:([bool]$Request.IncludeGuests) -IncludeDisabled:([bool]$Request.IncludeDisabled) -Notes $notes) } else { @() }
        & $Log 'Info' "$($p.displayName) [$($p.state)]: $($users.Count) in-scope user(s), mode $mode"
        $cond = $null; $unres = @(); $warn = @()
        if ($mode -eq 'WhatIf') {
            if ("$($p.state)" -eq 'disabled') { $warn += 'the policy is DISABLED: the evaluate API does not simulate a disabled policy (every user comes back "policyNotEnabled") - set it to report-only to analyse it' }
            $sim = New-EpsCaSignInConditions -Policy $p -Simulate $(if ($Request.Simulate) { $Request.Simulate } else { @{} })
            $risk = if ($sim.TargetsUserRisk -and -not $sim.ForceUserRisk) { Get-EpsCaUserRisk } else { $null }
            $comp = if ($sim.TargetsCompliance -and -not $sim.ForceCompliance -and $users.Count) { Get-EpsCaDeviceCompliance -Users $users -Platform $sim.Platform } else { $null }
            $records = Invoke-EpsCaWhatIf -Policy $p -Users $users -Sim $sim -UserRisk $risk -Compliance $comp
            $cond = $sim.Conditions + @{ includeApplications = ($sim.Applications -join ', ') }; $unres = $sim.Unresolved; $warn += $sim.Warnings
            if ($sim.TargetsUserRisk) { $warn += $(if ($risk) { "risk-gated: each user evaluated at their ACTUAL user risk today ($($risk.Count) at risk)" } else { 'risk-gated: a fixed user risk was pinned for the scenario' }) }
        } else {
            $m = Measure-EpsCaSignIns -Policy $p -ScopedUsers $users -SignIns $shared -Targeting $tg; $records = $m.Records
            if ($m.MixedState) { $warn += "the policy's state changed in the window: $($m.MixedState) result(s) of the other mode left out" }
            if ("$($p.state)" -eq 'disabled') { $warn += 'the policy is DISABLED: it produces no sign-in results' }
        }
        if ($notes.guests) { $warn += $notes.guests }
        $sum = Get-EpsCaSummary $records
        $aid = Save-EpsCaAnalysis -ConnectionString $ConnectionString -RunId $RunId -Policy $p -Mode $mode -WindowStart $winStart -WindowEnd $(if ($mode -eq 'SignInLogs') { $winEnd }) -Summary $sum -Records $records -Conditions $cond -Unresolved $unres -Warnings $warn -Monitor ([string]$Request.Monitor)
        & $Log $(if ($sum.Impacted) { 'Warning' } else { 'Info' }) "  $($sum.InScope) in scope, $($sum.Impacted) IMPACTED, $($sum.NotImpacted) not, $($sum.Errors) error(s)$(if ($unres) { '; not simulated: ' + ($unres -join '; ') })"
        $impactedTotal += $sum.Impacted
        $analyses.Add([pscustomobject]@{ AnalysisId = $aid; PolicyId = $id; DisplayName = [string]$p.displayName; State = [string]$p.state; Mode = $mode; Summary = $sum })
    }
    $mail = $null
    if ($impactedTotal -gt 0) { $mail = Send-EpsCaAnalyzerAlert -ConnectionString $ConnectionString -Analyses @($analyses | Where-Object { $_.Summary.Impacted -gt 0 }) -Version $Version -Recipients @($Request.AlertTo) -Monitor ([string]$Request.Monitor); & $Log 'Info' "alert: $(if ($mail.Sent) { 'mailed' } else { 'NOT mailed - ' + $mail.Reason })" }
    @{ Analyses = @($analyses); Impacted = $impactedTotal; Mail = $mail }
}

function Send-EpsCaAnalyzerAlert {
    # one mail per run, only when users are impacted (v1's rule); the details are on the analysis pages
    # -Recipients: the monitor's own (owner 2026-11-02: "i need a way to cntrol the desination of the ca policy analyzer alerts
    # ... as it is different teams"); none = the install's Mail.Recipients. The sender stays the install's mailbox.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object[]]$Analyses, [string]$Version = '2.0.0', [string[]]$Recipients = @(), [string]$Monitor)
    $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
    $own = @($Recipients | Where-Object { "$_".Trim() })
    if ($own.Count) { $cfg.Recipients = $own }
    $n = ($Analyses | ForEach-Object { $_.Summary.Impacted } | Measure-Object -Sum).Sum
    $rows = @($Analyses | ForEach-Object { [pscustomobject]@{ Policy = $_.DisplayName; State = $_.State; Method = $(if ($_.Mode -eq 'WhatIf') { 'predicted (What-If)' } else { 'observed (sign-in logs)' }); 'In scope' = $_.Summary.InScope; Impacted = $_.Summary.Impacted; Errors = $_.Summary.Errors } })
    $subject = New-EpsMailSubject -Environment $cfg.Environment -What "CA Policy Analyzer$(if ($Monitor) { " ($Monitor)" }): $n impacted user(s) in $(@($Analyses).Count) policy(ies)" -Severity 'Warning'
    $html = New-EpsMailBody -Summary "The CA Policy Analyzer found $n user(s) a Conditional Access policy would block or challenge. Nothing was changed - the analyzer only reads." -Rows $rows -Columns @('Policy', 'State', 'Method', 'In scope', 'Impacted', 'Errors') `
        -WhatToDo 'Open the CA Policy Analyzer page for the users and the reason per user before changing the policy.' -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
    Send-EpsMail -Config $cfg -Subject $subject -Html $html
}

# ---- SQL --------------------------------------------------------------------------------------------------------------
function Save-EpsCaPolicyList {
    # the tenant's policies as last read (the GUI picks from it - the web app never calls Graph)
    # + the whole body and the engine's read-only review of it (-Reviews: "<id>" -> Get-EpsCaReview), schema v12
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Policies = @(), [hashtable]$Reviews = @{})
    $iso = { param($d) if ($d -is [datetime]) { $d.ToUniversalTime().ToString('o') } elseif ($d -is [datetimeoffset]) { $d.UtcDateTime.ToString('o') } else { [string]$d } }
    $json = ConvertTo-Json -InputObject @($Policies | ForEach-Object { $rv = $Reviews["$($_.id)".ToLowerInvariant()]
        @{ id = [string]$_.id; name = [string]$_.displayName; state = [string]$_.state; modified = (& $iso $(if ($_.modifiedDateTime) { $_.modifiedDateTime } else { $_.createdDateTime }))
           body = ($_ | ConvertTo-Json -Compress -Depth 20); review = $(if ($rv) { $rv | ConvertTo-Json -Compress -Depth 20 }) } }) -Compress -Depth 4
    if (-not @($Policies).Count) { $json = '[]' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $json } -Query @'
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM eps.CaPolicy;
INSERT INTO eps.CaPolicy (PolicyId, DisplayName, State, ModifiedAtUtc, BodyJson, ReviewJson)
SELECT CAST(x.id AS UNIQUEIDENTIFIER), x.name, x.state, TRY_CAST(x.modified AS DATETIMEOFFSET), x.body, x.review
FROM OPENJSON(@j) WITH (id NVARCHAR(64) '$.id', name NVARCHAR(256) '$.name', state NVARCHAR(60) '$.state', modified NVARCHAR(64) '$.modified',
                        body NVARCHAR(MAX) '$.body', review NVARCHAR(MAX) '$.review') AS x;   -- JSON_VALUE stops at 4,000 characters
COMMIT;
'@)
}

function Save-EpsCaAnalysis {
    param([Parameter(Mandatory)][string]$ConnectionString, [guid]$RunId, [Parameter(Mandatory)]$Policy, [string]$Mode, $WindowStart, $WindowEnd, [Parameter(Mandatory)]$Summary, [object[]]$Records = @(), $Conditions, [string[]]$Unresolved = @(), [string[]]$Warnings = @(), [string]$Monitor)
    $aid = [guid]::NewGuid()
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ a = $aid; r = $RunId; p = [guid][string]$Policy.id; n = [string]$Policy.displayName; s = [string]$Policy.state; m = $Mode
        ws = $WindowStart; we = $WindowEnd; i = [int]$Summary.InScope; im = [int]$Summary.Impacted; ni = [int]$Summary.NotImpacted; e = [int]$Summary.Errors
        c = $(if ($Conditions) { $Conditions | ConvertTo-Json -Compress -Depth 5 }); u = $(if ($Unresolved) { $Unresolved | ConvertTo-Json -Compress -AsArray }); w = $(if ($Warnings) { @($Warnings) | ConvertTo-Json -Compress -AsArray })
        b = ($Summary.ByClass | ConvertTo-Json -Compress); mo = $(if ($Monitor) { $Monitor }) } -Query @'
INSERT INTO eps.CaAnalysis (AnalysisId, RunId, PolicyId, DisplayName, PolicyState, Mode, WindowStartUtc, WindowEndUtc, InScope, Impacted, NotImpacted, Errors, ByClassJson, ConditionsJson, UnresolvedJson, WarningsJson, Monitor)
VALUES (@a, @r, @p, @n, @s, @m, @ws, @we, @i, @im, @ni, @e, @b, @c, @u, @w, @mo)
'@)
    if (-not @($Records).Count) { return $aid }
    $t = [System.Data.DataTable]::new()
    $cols = [ordered]@{ AnalysisId = [guid]; Seq = [int]; UserId = [string]; UserPrincipalName = [string]; DisplayName = [string]; IsSpn = [bool]; Classification = [string]; Impacted = [bool]; Reason = [string]
        GrantControls = [string]; SessionControls = [string]; LastSignInUtc = [datetime]; Country = [string]; City = [string]; IPAddress = [string]; DeviceOS = [string]; Browser = [string]; ClientApp = [string]
        Application = [string]; RiskLevel = [string]; RiskState = [string]; CAResult = [string]; FailureReason = [string]; SignInCount = [int]; CountriesSeen = [string]; DistinctIPCount = [int] }
    foreach ($k in $cols.Keys) { [void]$t.Columns.Add($k, $cols[$k]) }
    $seq = 0
    foreach ($r in $Records) {
        $seq++; $row = $t.NewRow(); $row.AnalysisId = $aid; $row.Seq = $seq
        foreach ($k in @($cols.Keys | Select-Object -Skip 2)) { $v = $r.$k; $row[$k] = if ($null -eq $v -or "$v" -eq '' -or ($v -is [datetime] -and $v -eq [datetime]::MinValue)) { [DBNull]::Value } elseif ($cols[$k] -eq [string]) { $s = [string]$v; if ($s.Length -gt 1000) { $s.Substring(0, 1000) } else { $s } } else { $v } }
        $t.Rows.Add($row)
    }
    $conn = New-EpsSqlConnection -ConnectionString $ConnectionString
    try {
        Open-EpsSqlConnection $conn
        $bc = (($conn.GetType().FullName -replace 'SqlConnection$', 'SqlBulkCopy') -as [type])::new($conn); $bc.DestinationTableName = 'eps.CaAnalysisResult'; $bc.BatchSize = 5000; $bc.BulkCopyTimeout = 600
        foreach ($c in $t.Columns) { [void]$bc.ColumnMappings.Add($c.ColumnName, $c.ColumnName) }
        $bc.WriteToServer($t)
    } finally { $conn.Dispose() }
    $aid
}

function ConvertTo-EpsCaRequest {
    # a request from the GUI / a saved monitor -> the analyzer's request, validated: @{ Ok; Request; Error }
    param($Body)
    $s = { param($v) @(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    # @(...) around each: a script block that returns an EMPTY array returns $null
    $ids = @(& $s $Body.policyIds); $names = @(& $s $Body.policyNames); $pre = @(& $s $Body.policyPrefixes); $pat = @(& $s $Body.policyPatterns); $per = @(& $s $Body.personas)
    $all = @($ids + $names + $pre + $pat + $per)
    if (-not $all.Count -and -not $Body.listOnly) { return @{ Ok = $false; Error = 'name at least one policy (an id, an exact name, a persona, a prefix such as CA006 or CA2, or a wildcard such as CA2*)' } }
    if ($all.Count -gt 200) { return @{ Ok = $false; Error = 'at most 200 policy names in one run' } }
    foreach ($x in $all) { if ($x -match '[\u0000-\u001f]' -or $x.Length -gt 256) { return @{ Ok = $false; Error = 'a policy name has a control character or is too long' } } }
    foreach ($x in $pat) { if ($x -match '^[*?]*$') { return @{ Ok = $false; Error = "'$x' would match every policy - name a series, e.g. CA2*" } } }
    $slice = 0; if ($null -ne $Body.sliceHours -and "$($Body.sliceHours)" -ne '') { if (-not [int]::TryParse("$($Body.sliceHours)", [ref]$slice) -or $slice -lt 0 -or $slice -gt 168) { return @{ Ok = $false; Error = 'sliceHours: 0 (one pass) to 168' } } }
    foreach ($x in $ids) { if ($x -notmatch $script:EpsCaGuid) { return @{ Ok = $false; Error = "'$x' is not a policy id" } } }
    # WhatIf is PARKED (owner 2026-10-30: "whatif mode is not really used today ... so maybe we skip the whatif. park it for now"):
    # its code stays, it is not offered - only SignInLogs is taken
    $mode = if ("$($Body.mode)" -in '', 'SignInLogs') { 'SignInLogs' } elseif ("$($Body.mode)" -eq 'WhatIf') { return @{ Ok = $false; Error = 'the What-If mode is parked for now - analyse the sign-in logs (put the policy in report-only first)' } } else { return @{ Ok = $false; Error = 'mode is SignInLogs' } }
    $h = 24; if ($null -ne $Body.lookbackHours -and "$($Body.lookbackHours)" -ne '') { if (-not [int]::TryParse("$($Body.lookbackHours)", [ref]$h) -or $h -lt 1 -or $h -gt 720) { return @{ Ok = $false; Error = 'lookbackHours: 1 to 720 (30 days, the sign-in log retention)' } } }
    # the monitor's own alert recipients (mail addresses, at most 20); none = the install's Mail.Recipients
    $to = @(& $s $Body.alertTo)
    if ($to.Count -gt 20) { return @{ Ok = $false; Error = 'at most 20 alert recipients' } }
    foreach ($x in $to) { if ($x -notmatch '^[^@\s<>"'',;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { return @{ Ok = $false; Error = "'$x' is not a mail address" } } }
    $sim = @{}
    if ($Body.simulate) {
        $allowed = @{ country = '^[A-Za-z]{2}$'; ipAddress = '^[0-9a-fA-F:.]{3,45}$'; devicePlatform = '^(android|iOS|windows|windowsPhone|macOS|linux|all)$'; clientAppType = '^(browser|mobileAppsAndDesktopClients)$'
                      signInRiskLevel = '^(none|low|medium|high)$'; userRiskLevel = '^(none|low|medium|high)$'; insiderRiskLevel = '^(minor|moderate|elevated)$'; authenticationFlow = '^(deviceCodeFlow|authenticationTransfer)$' }
        foreach ($p in $Body.simulate.PSObject.Properties) {
            if ($p.Name -eq 'deviceCompliant') { if ($null -ne $p.Value) { $sim.deviceCompliant = [bool]$p.Value }; continue }
            if ($p.Name -eq 'applicationIds') { $a = & $s $p.Value; if (@($a | Where-Object { $_ -notmatch $script:EpsCaGuid }).Count) { return @{ Ok = $false; Error = 'simulate.applicationIds: application ids (GUIDs) only' } }; $sim.applicationIds = $a; continue }
            if (-not $allowed.ContainsKey($p.Name)) { return @{ Ok = $false; Error = "simulate.$($p.Name) is not a scenario field" } }
            if ("$($p.Value)" -and "$($p.Value)" -notmatch $allowed[$p.Name]) { return @{ Ok = $false; Error = "simulate.$($p.Name) '$($p.Value)' is not valid" } }
            if ("$($p.Value)") { $sim[$p.Name] = "$($p.Value)" }
        }
    }
    @{ Ok = $true; Request = @{ Policies = @{ Ids = $ids; Names = $names; Prefixes = $pre; Patterns = $pat; Personas = $per }; Mode = $mode; LookbackHours = $h; SliceHours = $slice
                                IncludeGuests = [bool]$Body.includeGuests; IncludeDisabled = [bool]$Body.includeDisabled
                                IncludeNonInteractive = [bool]$Body.includeNonInteractive; Simulate = $sim; ListOnly = [bool]$Body.listOnly; AlertTo = $to } }
}
