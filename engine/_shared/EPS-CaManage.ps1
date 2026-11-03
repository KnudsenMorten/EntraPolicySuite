# EntraPolicySuite -- Conditional Access management, the READ-ONLY half (DESIGN §5.1, §5.1a; owner 2026-10-30).
#
#   THE HARD RULE (owner 2026-10-30): "dont touch any ca policy stuff as i dont know the consequence of what you have
#   implemented with ca policy ... it must not automatically do things i have not approved. otherwise i can be locked out
#   of my tenant !!"
#
# So NOTHING in this file writes a Conditional Access policy, a named location or an authentication strength - not here,
# and nowhere else but the one stage move in EPS-CaWrite.ps1 (CA-LIFECYCLE, owner 2026-11-03 "Write on approval"):
# tests/Test-EpsNoCaWrite.ps1 fails the build on any other write to identity/conditionalAccess/*. What is here:
#   * the template library (engine/ca/templates.json - v1's CA000-CA800 as data) and the match of a tenant policy to its
#     template by v1's naming (the CA number in the display name)
#   * the stage a policy is REALLY in, from its state and who it targets (Initial / Pilot1 / Pilot2 / Pilot3 / Prod)
#   * a structured diff of a policy against its template at that stage (conditions, grant, session; ids that are
#     settings compared by the NAME they resolve to)
#   * the break-glass exclusion check (every policy excludes the break-glass group / accounts but the break-glass policy)
#   * "Adopt" = a RECORD in eps.CaAdoption that the operator adopted a policy - nothing in the tenant changes
#   * the documentation (v1's Entra-CA-Policies-Documentation csv / xlsx) with the ids resolved to names
#   * the monitor (CA.Monitoring.Enabled, off by default): for ADOPTED policies a drift (the tenant's body differs from
#     the body recorded at adopt) and a missing break-glass exclusion are SHOWN and alerted - EPS never acts on them
#     (owner 2026-10-30: "newer desired state, but ok to show drifts, but this is 100% managed by customer, newer eps !!!")
# The engine runs it inside the CA Policy Analyzer's read of the policy list (no new job). The web app reads only what
# the engine stored: it never calls Graph.

Set-StrictMode -Off

$script:EpsCaCatalogCache = $null
$script:EpsCaGuidRx = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# the parts of a policy that are compared with the template; Kind says how a value is read (ids -> names)
$script:EpsCaComparePaths = [ordered]@{
    'conditions.users.includeUsers' = 'user'; 'conditions.users.excludeUsers' = 'user'
    'conditions.users.includeGroups' = 'group'; 'conditions.users.excludeGroups' = 'group'
    'conditions.users.includeRoles' = 'role'; 'conditions.users.excludeRoles' = 'role'
    'conditions.applications.includeApplications' = 'set'; 'conditions.applications.excludeApplications' = 'set'
    'conditions.applications.includeUserActions' = 'set'
    'conditions.clientAppTypes' = 'clientAppTypes'
    'conditions.platforms.includePlatforms' = 'set'; 'conditions.platforms.excludePlatforms' = 'set'
    'conditions.locations.includeLocations' = 'location'; 'conditions.locations.excludeLocations' = 'location'
    'conditions.signInRiskLevels' = 'set'; 'conditions.userRiskLevels' = 'set'; 'conditions.insiderRiskLevels' = 'scalar'
    'conditions.devices.deviceFilter.mode' = 'scalar'; 'conditions.devices.deviceFilter.rule' = 'scalar'
    'conditions.authenticationFlows.transferMethods' = 'scalar'
    'conditions.clientApplications.includeServicePrincipals' = 'set'; 'conditions.clientApplications.excludeServicePrincipals' = 'set'
    'grantControls.operator' = 'operator'; 'grantControls.builtInControls' = 'set'; 'grantControls.termsOfUse' = 'set'
    'grantControls.authenticationStrength.displayName' = 'scalar'
    'sessionControls.signInFrequency.isEnabled' = 'bool'; 'sessionControls.signInFrequency.value' = 'scalar'; 'sessionControls.signInFrequency.type' = 'scalar'
    'sessionControls.signInFrequency.authenticationType' = 'scalar'; 'sessionControls.signInFrequency.frequencyInterval' = 'scalar'
    'sessionControls.persistentBrowser.isEnabled' = 'bool'; 'sessionControls.persistentBrowser.mode' = 'scalar'
    'sessionControls.cloudAppSecurity.isEnabled' = 'bool'; 'sessionControls.cloudAppSecurity.cloudAppSecurityType' = 'scalar'
}

# ---- the template library ---------------------------------------------------------------------------------------------
function Get-EpsCaTemplateCatalog {
    # engine/ca/templates.json, shipped with the release (converted from v1 - internal/tools/ConvertFrom-EpsV1CaTemplates.ps1)
    param([switch]$Reload)
    if ($script:EpsCaCatalogCache -and -not $Reload) { return $script:EpsCaCatalogCache }
    $p = Join-Path (Split-Path -Parent $PSScriptRoot) 'ca\templates.json'
    $c = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json -AsHashtable
    $by = @{}; foreach ($t in $c.templates) { $by[$t.id] = $t }
    $c['ById'] = $by
    $script:EpsCaCatalogCache = $c
    $c
}

function Get-EpsCaV {
    # a value at a dotted path of a Graph object (PSCustomObject or hashtable); $null when any part is missing
    param($Object, [string]$Path)
    $o = $Object
    foreach ($s in $Path.Split('.')) {
        if ($null -eq $o) { return $null }
        $o = if ($o -is [System.Collections.IDictionary]) { $o[$s] } else { $o.$s }
    }
    if ($null -eq $o) { return $null }
    , $o   # an array stays ONE value (an empty list is not $null)
}

function Get-EpsCaList {
    # the non-empty string values at a path, as an array (a scalar becomes one item)
    param($Object, [string]$Path)
    $v = Get-EpsCaV $Object $Path
    if ($null -eq $v) { return , @() }
    , @(@($v) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
}

function ConvertTo-EpsCaPersonaName {
    # v1's two spelling slips folded into one persona each (the templates stay as v1 has them) - the persona IMPORT only.
    # (2.0.25: the template persona of a policy is no longer shown or used - the Persona column and the analyzer show the
    # MANAGED personas, Get-EpsCaPolicyPersonaMap; owner 2026-11-02 "templates is a import only feature")
    param([string]$Persona)
    switch -Regex ($Persona) { '^Users-Internals$' { 'Users-Internal' } '^Users-Internal-Developerss$' { 'Users-Internal-Developers' } default { $Persona } }
}

function Get-EpsCaNameMatch {
    # v1's naming: CAnnn-<stage>-<rest> (stage = Initial | Pilot1-3 | Prod | a version, e.g. CA000-v1.0-...), or CAnnn-<rest>
    param([string]$DisplayName, $Catalog = (Get-EpsCaTemplateCatalog))
    $m = [regex]::Match("$DisplayName", $Catalog.displayNamePattern)
    if ($m.Success) {
        $id = $m.Groups['id'].Value; $st = $m.Groups['stage'].Value
        return @{ TemplateId = $id; NameStage = $(if ($st -like 'v*') { $null } else { $st }); VersionCopy = $(if ($st -like 'v*') { $st }); Rest = $m.Groups['rest'].Value; Template = $Catalog.ById[$id] }
    }
    $m = [regex]::Match("$DisplayName", '^(CA\d{3})(?:-(.*))?$')
    if ($m.Success) { return @{ TemplateId = $m.Groups[1].Value; NameStage = $null; VersionCopy = $null; Rest = $m.Groups[2].Value; Template = $Catalog.ById[$m.Groups[1].Value] } }
    @{ TemplateId = $null; NameStage = $null; VersionCopy = $null; Rest = "$DisplayName"; Template = $null }
}

# ---- the stage a policy is really in ----------------------------------------------------------------------------------
function Get-EpsCaStage {
    <#
      From the policy's REAL state and who it targets (DESIGN §5.1 "Adopt" item 2), v1's convention:
        disabled                              -> Initial
        report-only                           -> Pilot1 (v1 also runs CA00x report-only for all users)
        on for the policy's pilot group(s)    -> Pilot2 / Pilot3 (an Assigned group's name says which; a dynamic
                                                 group's membership rule says it: _pilot2 / _pilot3 on extensionAttribute8)
        on for all users, or for its target   -> Prod (v1's Prod includes All, or the persona's own group)
        anything else                         -> Custom (with what was seen)
      -Names: "group|<id>" -> @{ Name; Detail (= membershipRule) }. Returns @{ Stage; Note }.
    #>
    param([Parameter(Mandatory)]$Policy, [hashtable]$Names = @{}, $Catalog = (Get-EpsCaTemplateCatalog))
    $state = "$(Get-EpsCaV $Policy 'state')"
    $iu = Get-EpsCaList $Policy 'conditions.users.includeUsers'; $ig = Get-EpsCaList $Policy 'conditions.users.includeGroups'; $ir = Get-EpsCaList $Policy 'conditions.users.includeRoles'
    $sp = Get-EpsCaList $Policy 'conditions.clientApplications.includeServicePrincipals'
    $name = { param($id) $Names["group|$("$id".ToLowerInvariant())"] }
    $pilot = @($ig | Where-Object { $n = & $name $_; $n -and "$($n.Name)" -match $Catalog.pilotGroupPattern })
    $unknown = @($ig | Where-Object { -not (& $name $_) })
    $all = $iu -contains 'All'
    if ($state -eq 'disabled') { return @{ Stage = 'Initial'; Note = 'off' } }
    if ($state -eq 'enabledForReportingButNotEnforced') { return @{ Stage = 'Pilot1'; Note = $(if ($all) { 'report-only for all users' } elseif ($pilot.Count) { 'report-only for the pilot group' } else { 'report-only' }) } }
    if ($state -ne 'enabled') { return @{ Stage = 'Custom'; Note = "state '$state'" } }
    if ($all) { return @{ Stage = 'Prod'; Note = 'on for all users' } }
    if ($ig.Count -and $pilot.Count -eq $ig.Count -and -not @($iu | Where-Object { $_ -ne 'None' }).Count -and -not $ir.Count) {
        $level = 0
        foreach ($g in $pilot) {
            $n = & $name $g; $l = 0
            if ("$($n.Name)" -match '(?i)-Pilot([123])-') { $l = [int]$Matches[1] }
            elseif ("$($n.Detail)" -match [regex]::Escape($Catalog.pilotRule.Pilot3)) { $l = 3 }
            elseif ("$($n.Detail)" -match [regex]::Escape($Catalog.pilotRule.Pilot2)) { $l = 2 }
            elseif ("$($n.Detail)" -match [regex]::Escape($Catalog.pilotRule.Pilot1)) { $l = 1 }
            if ($l -gt $level) { $level = $l }
        }
        if ($level -le 1) { return @{ Stage = 'Pilot1'; Note = 'ON (enforced) for the pilot1 group - v1''s override of report-only' } }
        return @{ Stage = "Pilot$level"; Note = 'on for the pilot group' }
    }
    if ($unknown.Count) { return @{ Stage = 'Custom'; Note = "on for $($unknown.Count) group(s) whose name could not be read" } }
    if ($pilot.Count) { return @{ Stage = 'Custom'; Note = 'on for a pilot group AND other users' } }
    if ($ig.Count -or $ir.Count -or @($iu | Where-Object { $_ -ne 'None' }).Count -or $sp.Count) { return @{ Stage = 'Prod'; Note = 'on for its target group(s)' } }
    @{ Stage = 'Custom'; Note = 'on, but targets nobody' }
}

# ---- the template at a stage, as NAMES ---------------------------------------------------------------------------------
function ConvertTo-EpsCaTargetingMethod {
    # v1's Group_Targeting_Method (the imported CA.GroupTargetingMethod); '' = not known (every method's names are accepted)
    param([string]$Value)
    $v = "$Value".Trim()
    if ($v -in 'Dynamic_Using_Tags', 'Manual_Assignment_Advanced', 'Manual_Assignment_Simple') { return $v }
    if ($v -match '(?i)^dynamic') { return 'Dynamic_Using_Tags' }
    if ($v -match '(?i)advanced') { return 'Manual_Assignment_Advanced' }
    if ($v -match '(?i)simple|manual|assigned') { return 'Manual_Assignment_Simple' }
    ''
}

function Get-EpsCaRoleGroupNames {
    # a v1 target group (VariableName) -> its display name(s) for the targeting method (the customer's imported
    # eps.TargetGroup first, the library's v1 names otherwise)
    param([string]$Role, $Ctx, $Catalog = (Get-EpsCaTemplateCatalog))
    $g = if ($Ctx.TargetGroups -and $Ctx.TargetGroups[$Role]) { $Ctx.TargetGroups[$Role] } else { $Catalog.groupRoles[$Role] }
    if (-not $g) { return , @() }
    $kinds = switch ($Ctx.Method) { 'Dynamic_Using_Tags' { @('Dynamic') } { $_ -like 'Manual_*' } { @('Assigned') } default { @('Dynamic', 'Assigned') } }
    , @($kinds | ForEach-Object { $g[$_] } | Where-Object { $_ })
}

function Resolve-EpsCaTemplateSlots {
    # one template value (a role reference or a literal) -> its SLOTS (a list): each slot = the names (string[]) that may
    # stand in that place. {breakGlassAccounts} is one slot per account.
    param([string]$Item, $Template, [string]$Stage, $Ctx, $Catalog = (Get-EpsCaTemplateCatalog))
    $out = [System.Collections.Generic.List[object]]::new()
    $one = { param($alts) $out.Add([string[]]@(@($alts) | Where-Object { $_ } | ForEach-Object { "$_" })) }
    switch -Regex ($Item) {
        '^\{policyPilotGroup\}$' {
            $ix = switch ($Stage) { 'Pilot2' { 1 } 'Pilot3' { 2 } default { 0 } }
            $methods = if ($Ctx.Method) { @($Ctx.Method) } else { @($Catalog.groupTargetingMethods) }
            & $one @(foreach ($m in $methods) { $l = @($Template.groups.pilot[$m]); if ($m -eq 'Dynamic_Using_Tags') { $l } elseif ($l.Count -gt $ix) { $l[$ix] } }); break }
        '^\{policyExcludeGroup\}$' { & $one @($Template.groups.exclude); break }
        '^\{breakGlassGroup\}$' { $g = Get-EpsCaRoleGroupNames -Role $Catalog.breakGlassGroupRole -Ctx $Ctx -Catalog $Catalog; & $one $g; break }
        '^\{group:(.+)\}$' { $g = Get-EpsCaRoleGroupNames -Role $Matches[1] -Ctx $Ctx -Catalog $Catalog; if (-not @($g).Count) { $g = @("$Item (unknown target group)") }; & $one $g; break }
        '^\{breakGlassAccounts(?::(\w+))?\}$' {
            $want = $Matches[1]
            $acc = @($Ctx.BreakGlass.Accounts | Where-Object { $_ -and (-not $want -or "$($_.Method)" -ieq $want) })
            if (-not $acc.Count) { & $one @("(no break-glass account$(if ($want) { " with $want" }) is configured)") }
            foreach ($a in $acc) { & $one @("$($a.Upn)".ToLowerInvariant()) }
            break }
        '^\{authStrength:(\w+)\}$' { $k = $Matches[1]; & $one @($(if ($Ctx.AuthStrength -and $Ctx.AuthStrength[$k]) { $Ctx.AuthStrength[$k] } else { $Catalog.authStrengthDefaults[$k] })); break }
        '^\{namedLocation:(\w+)\}$' { $k = $Matches[1]; & $one @($(if ($Ctx.NamedLocation -and $Ctx.NamedLocation[$k]) { $Ctx.NamedLocation[$k] } else { $Catalog.namedLocationDefaults[$k] })); break }
        '^\{.*\}$' { & $one @("$Item (not resolvable)"); break }
        default { & $one @($Item) }
    }
    , $out
}

function Get-EpsCaTemplateValue {
    # the template's value at a path for a stage (Prod applies the template's prod changes)
    param($Template, [string]$Path, [string]$Stage)
    if ($Stage -in 'Prod', 'Custom' -and $Template.prod -and $Template.prod.Contains($Path)) { return , $Template.prod[$Path] }
    Get-EpsCaV $Template.body $Path
}

function Get-EpsCaActualValues {
    # the tenant's value at a path, as names (a user by UPN, a group / role / location by its name; keywords as they are)
    param($Policy, [string]$Path, [string]$Kind, [hashtable]$Names = @{})
    $vals = Get-EpsCaList $Policy $Path
    if ($Kind -in 'user', 'group', 'role', 'location') {
        $vals = @(foreach ($v in $vals) {
            $n = $Names["$Kind|$("$v".ToLowerInvariant())"]
            if (-not $n) { $v } elseif ($Kind -eq 'user') { if ($n.Detail) { "$($n.Detail)".ToLowerInvariant() } else { $n.Name } } else { $n.Name } })
    }
    if ($Kind -eq 'clientAppTypes' -and (-not $vals.Count -or ($vals.Count -eq 1 -and $vals[0] -eq 'all'))) { $vals = @() }   # Graph: not set = all
    , @($vals)
}

function Compare-EpsCaPolicyToTemplate {
    <#
      The structured diff of a tenant policy against its template at a stage: one item per path that differs, with
      what the template wants (each place's acceptable names), what the tenant has, and what is missing / extra.
      Ids are compared by the NAME they resolve to (groups, users, roles, locations); application and service
      principal ids as they are. Lists are sets (order does not matter), keywords and controls case-insensitive.
    #>
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)]$Template, [string]$Stage = 'Initial', $Ctx = @{}, [hashtable]$Names = @{}, $Catalog = (Get-EpsCaTemplateCatalog))
    $diff = [System.Collections.Generic.List[object]]::new()
    $tb = Get-EpsCaTemplateValue $Template 'grantControls.builtInControls' $Stage; $ta = Get-EpsCaTemplateValue $Template 'grantControls.authenticationStrength.displayName' $Stage
    $ab = Get-EpsCaList $Policy 'grantControls.builtInControls'; $aa = Get-EpsCaV $Policy 'grantControls.authenticationStrength.displayName'
    $tCtl = @(@($tb) | Where-Object { $_ }).Count + $(if ($ta) { 1 } else { 0 }); $aCtl = @($ab).Count + $(if ($aa) { 1 } else { 0 })
    foreach ($path in $script:EpsCaComparePaths.Keys) {
        $kind = $script:EpsCaComparePaths[$path]
        $tv = Get-EpsCaTemplateValue $Template $path $Stage
        if ($kind -in 'scalar', 'bool', 'operator') {
            if ($kind -eq 'operator' -and $tCtl -le 1 -and $aCtl -le 1) { continue }   # one control: AND / OR means nothing
            $av = Get-EpsCaV $Policy $path
            if ($kind -eq 'bool') { $tv = [bool]$tv; $av = [bool]$av }
            $e = if ($null -eq $tv) { '' } elseif ("$tv" -match '^\{') { $rs = Resolve-EpsCaTemplateSlots -Item "$tv" -Template $Template -Stage $Stage -Ctx $Ctx -Catalog $Catalog; "$(@($rs[0])[0])" } else { "$tv" }
            $a = if ($null -eq $av) { '' } else { "$av" }
            if ($e -ine $a) { $diff.Add([ordered]@{ path = $path; expected = $e; actual = $a; missing = @(); extra = @() }) }
            continue
        }
        $slots = [System.Collections.Generic.List[object]]::new()
        foreach ($x in @(@($tv) | Where-Object { $null -ne $_ -and "$_" -ne '' })) { $rs = Resolve-EpsCaTemplateSlots -Item "$x" -Template $Template -Stage $Stage -Ctx $Ctx -Catalog $Catalog; foreach ($s in $rs) { $slots.Add($s) } }
        if ($kind -eq 'clientAppTypes' -and $slots.Count -eq 1 -and @($slots[0]) -contains 'all') { $slots.Clear() }
        $act = Get-EpsCaActualValues -Policy $Policy -Path $path -Kind $kind -Names $Names
        $used = [bool[]]::new($act.Count)
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $slots) {
            $hit = $false
            for ($i = 0; $i -lt $act.Count; $i++) { if (-not $used[$i] -and @($s | Where-Object { $_ -ieq $act[$i] }).Count) { $used[$i] = $true; $hit = $true; break } }
            if (-not $hit) { $missing.Add((@($s) -join ' or ')) }
        }
        $extra = @(for ($i = 0; $i -lt $act.Count; $i++) { if (-not $used[$i]) { $act[$i] } })
        if ($missing.Count -or $extra.Count) {
            $diff.Add([ordered]@{ path = $path; expected = (@($slots | ForEach-Object { @($_) -join ' or ' }) -join ', '); actual = ($act -join ', '); missing = @($missing); extra = @($extra) })
        }
    }
    $diff.ToArray()   # one item per difference (callers wrap it in @())
}

# ---- the break-glass exclusion (DESIGN §5.1a "every CA policy excludes the break-glass group except the break-glass policy")
function Test-EpsCaBreakGlassExclusion {
    <#
      -BreakGlass @{ GroupIds (the break-glass group(s)); RelatedGroupIds (every break-glass group, the break-glass
      policy targets one); Accounts @{ Upn; Method; Id } }. A policy passes when it excludes a break-glass group, or
      excludes EVERY break-glass account. The break-glass policy (it targets the accounts) is exempt. Nothing configured =
      the check cannot run, and it says so (never a silent pass). Returns @{ Ok ($true / $false / $null); Exempt; Text; Missing }.
    #>
    param([Parameter(Mandatory)]$Policy, $BreakGlass = @{}, [bool]$IsBreakGlassPolicy)
    $low = { param($a) @(@($a) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_".ToLowerInvariant() }) }
    $gids = & $low $BreakGlass.GroupIds; $rel = & $low (@($BreakGlass.RelatedGroupIds) + @($BreakGlass.GroupIds)); $acc = @($BreakGlass.Accounts | Where-Object { $_.Id })
    $aids = & $low ($acc | ForEach-Object { $_.Id })
    $iu = & $low (Get-EpsCaList $Policy 'conditions.users.includeUsers'); $ig = & $low (Get-EpsCaList $Policy 'conditions.users.includeGroups')
    if ($IsBreakGlassPolicy -or @($iu | Where-Object { $aids -contains $_ }).Count -or @($ig | Where-Object { $rel -contains $_ }).Count) {
        return @{ Ok = $true; Exempt = $true; Text = 'the break-glass policy itself (it targets the break-glass accounts)'; Missing = @() }
    }
    if (-not $gids.Count -and -not $aids.Count) { return @{ Ok = $null; Exempt = $false; Text = 'no break-glass group or account is known (import the v1 configuration, or set the accounts up) - the check cannot run'; Missing = @() } }
    $xg = & $low (Get-EpsCaList $Policy 'conditions.users.excludeGroups'); $xu = & $low (Get-EpsCaList $Policy 'conditions.users.excludeUsers')
    if (@($xg | Where-Object { $gids -contains $_ }).Count) { return @{ Ok = $true; Exempt = $false; Text = 'excludes the break-glass group'; Missing = @() } }
    $miss = @($acc | Where-Object { $xu -notcontains "$($_.Id)".ToLowerInvariant() } | ForEach-Object { $_.Upn })
    if ($aids.Count -and -not $miss.Count) { return @{ Ok = $true; Exempt = $false; Text = 'excludes every break-glass account'; Missing = @() } }
    @{ Ok = $false; Exempt = $false; Missing = @($miss)
       Text = "does NOT exclude the break-glass group$(if ($miss.Count) { ", nor $($miss.Count) break-glass account(s): $($miss -join ', ')" }) - a lock-out risk" }
}

# ---- the drift baseline: the policy's body, canonical ------------------------------------------------------------------
function ConvertTo-EpsCaCanonical {
    # what an operator means by "the policy": name, state, conditions, grant and session - keys sorted, lists of values
    # sorted, empty / null left out, read-only noise (@odata, created / modified times, the strength's own details) dropped
    param([Parameter(Mandatory)]$Policy)
    $walk = $null
    $walk = {
        param($v, [string]$key)
        if ($null -eq $v) { return $null }
        if ($v -is [string] -or $v -is [ValueType]) { if ($v -is [string] -and $v -eq '') { return $null }; return $v }
        $isMap = $v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject]
        if ($isMap) {
            $keys = if ($v -is [System.Collections.IDictionary]) { @($v.Keys) } else { @($v.PSObject.Properties.Name) }
            if ($key -eq 'authenticationStrength') { $keys = @($keys | Where-Object { $_ -in 'id', 'displayName' }) }
            $o = [ordered]@{}
            foreach ($k in @($keys | Sort-Object { "$_" } -CaseSensitive)) {
                if ("$k" -like '@odata*' -or "$k" -in 'createdDateTime', 'modifiedDateTime', 'id', 'templateId') { if (-not ($key -eq 'authenticationStrength' -and "$k" -eq 'id')) { continue } }
                $x = & $walk $(if ($v -is [System.Collections.IDictionary]) { $v[$k] } else { $v.$k }) "$k"
                if ($null -ne $x) { $o["$k"] = $x }
            }
            if (-not $o.Count) { return $null }
            return $o
        }
        if ($v -is [System.Collections.IEnumerable]) {
            $items = @(foreach ($i in $v) { $x = & $walk $i $key; if ($null -ne $x) { , $x } })
            if (-not $items.Count) { return $null }
            if (-not @($items | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] }).Count) { $items = @($items | Sort-Object { "$_" } -CaseSensitive) }
            return , @($items)
        }
        $v
    }
    $out = [ordered]@{}
    foreach ($k in 'conditions', 'displayName', 'grantControls', 'sessionControls', 'state') {
        $x = & $walk (Get-EpsCaV $Policy $k) $k
        if ($null -ne $x) { $out[$k] = $x }
    }
    $out
}

function Get-EpsCaBodyHash {
    param([Parameter(Mandatory)]$Policy)
    $j = (ConvertTo-EpsCaCanonical $Policy) | ConvertTo-Json -Compress -Depth 20
    -join ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($j)) | ForEach-Object { $_.ToString('x2') })
}

function Compare-EpsCaCanonical {
    # the paths where two canonical bodies differ: @{ path; before; after } (values as compact JSON)
    param($Before, $After, [string]$Prefix = '')
    $out = [System.Collections.Generic.List[object]]::new()
    $isMap = { param($x) $x -is [System.Collections.IDictionary] }
    if ((& $isMap $Before) -and (& $isMap $After)) {
        foreach ($k in @(@($Before.Keys) + @($After.Keys) | Select-Object -Unique | Sort-Object)) {
            foreach ($d in (Compare-EpsCaCanonical -Before $Before[$k] -After $After[$k] -Prefix $(if ($Prefix) { "$Prefix.$k" } else { "$k" }))) { $out.Add($d) }
        }
        return $out.ToArray()
    }
    $ja = if ($null -eq $Before) { '' } else { ConvertTo-Json -InputObject $Before -Compress -Depth 20 }
    $jb = if ($null -eq $After) { '' } else { ConvertTo-Json -InputObject $After -Compress -Depth 20 }
    if ($ja -cne $jb) { $out.Add([ordered]@{ path = $Prefix; before = $ja; after = $jb }) }
    $out.ToArray()
}

function Format-EpsCaIds {
    # a text with ids -> the same text with each known id followed by its name
    param([string]$Text, [hashtable]$Names = @{})
    if (-not $Text) { return $Text }
    $byId = @{}; foreach ($k in $Names.Keys) { $id = ($k -split '\|', 2)[1]; if ($id -and -not $byId.ContainsKey($id)) { $n = $Names[$k]; $byId[$id] = $(if ($n.Kind -eq 'user' -and $n.Detail) { $n.Detail } else { $n.Name }) } }
    [regex]::Replace($Text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', { param($m) $n = $byId[$m.Value.ToLowerInvariant()]; if ($n) { "$($m.Value) ($n)" } else { $m.Value } })
}

# ---- the review of one policy (stored by the engine; the page shows it) --------------------------------------------------
function Get-EpsCaReview {
    <#
      Template match, stage (from the name and from the real state), the diff against the template at the real stage,
      the break-glass exclusion, the canonical hash. Pure: -Names and -Ctx come from the engine's read.
    #>
    param([Parameter(Mandatory)]$Policy, [hashtable]$Names = @{}, $Ctx = @{}, $Catalog = (Get-EpsCaTemplateCatalog))
    $nm = Get-EpsCaNameMatch -DisplayName "$(Get-EpsCaV $Policy 'displayName')" -Catalog $Catalog
    $st = Get-EpsCaStage -Policy $Policy -Names $Names -Catalog $Catalog
    $t = $nm.Template
    $diff = @(); $notes = [System.Collections.Generic.List[string]]::new()
    if ($t) {
        $diff = @(Compare-EpsCaPolicyToTemplate -Policy $Policy -Template $t -Stage $st.Stage -Ctx $Ctx -Names $Names -Catalog $Catalog)
        $want = "$($t.name)".Substring([Math]::Min("$($t.name)".Length, 6))
        if (-not $nm.VersionCopy -and $nm.Rest -and $want -and $nm.Rest -ine $want) { $diff = @($diff) + @([ordered]@{ path = 'displayName'; expected = "$($nm.TemplateId)-<stage>-$want"; actual = "$(Get-EpsCaV $Policy 'displayName')"; missing = @(); extra = @() }) }
        if ($t.incomplete) { $notes.Add("template $($t.id) is incomplete in v1 ($(@($t.gaps) -join '; '))") }
        if ($st.Stage -eq 'Custom') { $notes.Add('the stage is not one of v1''s: compared with the template''s Prod body') }
    } elseif ($nm.TemplateId) { $notes.Add("$($nm.TemplateId) is not in the template library") }
    else { $notes.Add('the name does not carry a CA number (CAnnn-...): no template to compare with') }
    if (-not $Ctx.Method) { $notes.Add('the group-targeting method is not known (CA.GroupTargetingMethod): the names of every method are accepted') }
    $bg = Test-EpsCaBreakGlassExclusion -Policy $Policy -BreakGlass $Ctx.BreakGlass -IsBreakGlassPolicy ([bool]($t -and $t.breakGlassPolicy))
    [ordered]@{
        templateId = $nm.TemplateId; templateVersion = $(if ($t) { $t.version }); templateName = $(if ($t) { $t.name }); inLibrary = [bool]$t; incomplete = [bool]($t -and $t.incomplete)
        nameStage = $nm.NameStage; versionCopy = $nm.VersionCopy; stage = $st.Stage; stageNote = $st.Note
        stageMismatch = [bool]($nm.NameStage -and $nm.NameStage -ne $st.Stage)
        matches = [bool]($t -and -not @($diff).Count); diffCount = @($diff).Count; diff = @($diff)
        breakGlass = [ordered]@{ ok = $bg.Ok; exempt = [bool]$bg.Exempt; text = $bg.Text; missing = @($bg.Missing) }
        hash = (Get-EpsCaBodyHash $Policy); notes = @($notes)
    }
}

# ---- CA-LIFECYCLE: move ONE adopted policy to any stage (owner 2026-11-03, was one stage) - the PLAN (pure; owner 2026-11-03 "in ca policy i need buttons to
# easily controll and movevto another lufecycle phase like pilot1, pilot2", "Write on approval", "SuperAdmin only").
# Nothing here writes: the plan says, in NAMES, what the move changes - the page shows it, and the engine
# (EPS-CaWrite.ps1, Invoke-EpsCaStageMove) recomputes it from the live policy before its one write.
# v1's modes 1:1 (CA-Scripts-Active\CAnnn.ps1): Pilot1 = the pilot group, report-only; Pilot2 / Pilot3 = the pilot group
# (Pilot2 / Pilot3 for an assigned method; the one dynamic group, whose rule v1 widens), on; Prod = the template's Prod
# targets, on; Disable = only the state. The name follows the stage (CAnnn-<stage>-<rest>), as v1 renames it.
$script:EpsCaStageOrder = @('Initial', 'Pilot1', 'Pilot2', 'Pilot3', 'Prod')
$script:EpsCaStateWord = @{ disabled = 'off'; enabledForReportingButNotEnforced = 'report-only'; enabled = 'on' }
$script:EpsCaUserKeywords = @('All', 'None', 'GuestsOrExternalUsers')

function Get-EpsCaStageMoves {
    # the moves from a stage (owner 2026-11-03: "the move should allow me to move to any lifecycle phase" / "not just one
    # back"): ANY of Pilot1 / Pilot2 / Pilot3 / Prod but the one it is at, and Disable (= off, v1's Initial) from any
    # stage but Initial. A policy at no template stage (Custom) only Disables.
    param([string]$Stage)
    $o = $script:EpsCaStageOrder; $i = [array]::IndexOf($o, $Stage)
    $m = [System.Collections.Generic.List[string]]::new()
    if ($i -ge 0) { foreach ($s in $o) { if ($s -ne 'Initial' -and $s -ne $Stage) { $m.Add($s) } } }
    if ($Stage -and $Stage -ne 'Initial') { $m.Add('Disabled') }
    $m.ToArray()   # callers wrap it in @()
}

function Get-EpsCaStagePlan {
    <#
      What moving ONE policy to -To changes, in names: @{ ok; reason; from; to; templateId; displayNameBefore / After;
      stateBefore / After; changes = @{ field; before; after }; set = path -> @{ kind; values (names / keywords) };
      notes; breakGlass (the review's) }. Refused (ok = $false, reason) when -To is not a move from its stage, the policy has
      no template, is a test copy, or a value cannot be named exactly (the targeting method not set, a group role or a
      break-glass account missing). -Policy: the body (hashtable); -Review: Get-EpsCaReview's.
    #>
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)]$Review, [Parameter(Mandatory)][string]$To, $Ctx = @{}, [hashtable]$Names = @{}, $Catalog = (Get-EpsCaTemplateCatalog))
    $from = "$($Review.stage)"; $dn = "$(Get-EpsCaV $Policy 'displayName')"; $st = "$(Get-EpsCaV $Policy 'state')"
    $plan = [ordered]@{ ok = $false; reason = $null; from = $from; to = $To; templateId = $Review.templateId; displayNameBefore = $dn; displayNameAfter = $dn; stateBefore = $st; stateAfter = $st
                        changes = [System.Collections.Generic.List[object]]::new(); set = [ordered]@{}; notes = [System.Collections.Generic.List[string]]::new(); breakGlass = $Review.breakGlass }
    $no = { param($why) $plan.reason = $why; $plan.changes = @($plan.changes); $plan.notes = @($plan.notes); $plan }
    $moves = @(Get-EpsCaStageMoves $from)
    if ($To -notin $moves) { return & $no $(if ($moves.Count) { "from $from it moves to $($moves -join ', ')" } else { "the policy is at $from - there is no move from there" }) }
    $fi = [array]::IndexOf($script:EpsCaStageOrder, $from); $ti = [array]::IndexOf($script:EpsCaStageOrder, $To)
    if ($fi -ge 0 -and $ti -ge 0 -and [math]::Abs($ti - $fi) -gt 1) {
        $skip = @($script:EpsCaStageOrder[([math]::Min($fi, $ti) + 1)..([math]::Max($fi, $ti) - 1)] | Where-Object { $_ -ne 'Initial' })
        if ($skip.Count) { $plan.notes.Add("This skips $($skip -join ', '): the policy goes from $from straight to $To.") }
    }
    $word = { param($s) if ($script:EpsCaStateWord[$s]) { $script:EpsCaStateWord[$s] } else { "$s" } }
    if ($To -eq 'Disabled') {
        $plan.stateAfter = 'disabled'
        $plan.changes.Add([ordered]@{ field = 'state'; before = (& $word $st); after = 'off' })
        $plan.notes.Add('Disable (v1''s Disable_Policy): only the state changes - the policy is off for everyone; its name and targets stay, so it can move up again.')
        $plan.ok = $true; $plan.changes = @($plan.changes); $plan.notes = @($plan.notes); return $plan
    }
    $nm = Get-EpsCaNameMatch -DisplayName $dn -Catalog $Catalog; $t = $nm.Template
    if (-not $t) { return & $no 'the policy has no template in the library: it cannot move by the template''s stages' }
    if ($nm.VersionCopy) { return & $no "a test copy ($($nm.TemplateId)-$($nm.VersionCopy)-...) does not move through the stages" }
    if (-not $Ctx.Method) { return & $no 'the group-targeting method is not set (Settings > Conditional Access > CA.GroupTargetingMethod): the pilot and target groups cannot be named' }
    $plan.displayNameAfter = "$($nm.TemplateId)-$To-$($nm.Rest)"
    $plan.stateAfter = "$($Catalog.stageState[$To])"
    $paths = if ($To -eq 'Prod') { @($t.prod.Keys) } else { @('conditions.users.includeUsers', 'conditions.users.includeGroups') }
    foreach ($path in $paths) {
        $kind = $script:EpsCaComparePaths[$path]
        $vals = [System.Collections.Generic.List[string]]::new()
        foreach ($x in @(@(Get-EpsCaTemplateValue $t $path $To) | Where-Object { $null -ne $_ -and "$_" -ne '' })) {
            if ("$x" -notmatch '^\{') { $vals.Add("$x"); continue }
            foreach ($s in (Resolve-EpsCaTemplateSlots -Item "$x" -Template $t -Stage $To -Ctx $Ctx -Catalog $Catalog)) {
                $s = @($s)
                if ($s.Count -ne 1 -or "$($s[0])" -match '\((not resolvable|unknown target group|no break-glass account)') { return & $no "$path cannot be named exactly: $(@($s) -join ' or ')" }
                $vals.Add("$($s[0])")
            }
        }
        $before = Get-EpsCaActualValues -Policy $Policy -Path $path -Kind $kind -Names $Names   # NOT @(...): the function returns its list whole (", @()"), a second @() nested it - "System.Object[]" in the preview and every list "changed" (owner 2026-11-03)
        $a = (@($before | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join '|'); $b = (@($vals | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join '|')
        if ($a -ne $b) { $plan.changes.Add([ordered]@{ field = (($path -replace '^conditions\.users\.', '') -creplace '([a-z])([A-Z])', '$1 $2').ToLowerInvariant(); before = $(if ($before.Count) { $before -join ', ' } else { '(none)' }); after = $(if ($vals.Count) { $vals -join ', ' } else { '(none)' }) }) }
        $plan.set[$path] = [ordered]@{ kind = $kind; values = @($vals) }
    }
    if ($plan.stateAfter -ne $st) { $plan.changes.Insert(0, [ordered]@{ field = 'state'; before = (& $word $st); after = (& $word $plan.stateAfter) }) }
    if ($plan.displayNameAfter -cne $dn) { $plan.changes.Insert(0, [ordered]@{ field = 'name'; before = $dn; after = $plan.displayNameAfter }) }
    switch ($To) {
        'Pilot1' { $plan.notes.Add('Pilot1 is report-only: the policy is evaluated and logged for the pilot group, nothing is enforced. The CA Policy Analyzer shows who it would have blocked or challenged.') }
        { $_ -in 'Pilot2', 'Pilot3' } { $plan.notes.Add("$To ENFORCES the policy for the members of the pilot group.") }
        'Prod' { $plan.notes.Add("Prod ENFORCES the policy for its targets: $(@(@($plan.set['conditions.users.includeUsers'].values) + @($plan.set['conditions.users.includeGroups'].values) | Where-Object { $_ }) -join ', ').") }
    }
    if ($Ctx.Method -eq 'Dynamic_Using_Tags' -and $To -like 'Pilot*') {
        $g = "$(@($plan.set['conditions.users.includeGroups'].values)[0])"; $n = [int]$To.Substring(5)
        $want = (@(1..$n | ForEach-Object { $Catalog.pilotRule["Pilot$_"] }) -join ', ')
        $rule = @($Names.Values | Where-Object { $_.Kind -eq 'group' -and "$($_.Name)" -ieq $g } | ForEach-Object { "$($_.Detail)" })[0]
        $takes = 0; foreach ($i in 1..3) { if ($rule -and $rule -match [regex]::Escape($Catalog.pilotRule["Pilot$i"])) { $takes = $i } }
        $plan.notes.Add($(if ($null -eq $rule) { "The pilot group $g is dynamic: v1 widens its rule to take $want on $($Catalog.pilotRule.attribute). EntraPolicySuite does not change groups - check its rule in Entra." }
            elseif ($takes -eq $n) { "The pilot group $g already takes $want." }
            else { "The pilot group $g is dynamic and its rule takes $(if ($takes) { "up to $($Catalog.pilotRule["Pilot$takes"])" } else { 'no pilot value' }) now: v1 changes it to take $want on $($Catalog.pilotRule.attribute). EntraPolicySuite does not change groups - change its rule in Entra yourself." }))
    }
    if ($Ctx.Method -eq 'Dynamic_Using_Tags' -and $To -eq 'Prod') { $plan.notes.Add('v1 also pauses the dynamic pilot group''s rule at Prod. EntraPolicySuite leaves the group as it is.') }
    if ($Ctx.Method -like 'Manual_*' -and $To -like 'Pilot*') { $plan.notes.Add("The policy applies to the members of $(@($plan.set['conditions.users.includeGroups'].values)[0]): check the group has the right members.") }
    if (-not $plan.changes.Count) { return & $no "the policy is already as $To wants it" }
    $plan.ok = $true; $plan.changes = @($plan.changes); $plan.notes = @($plan.notes)
    $plan
}

function Get-EpsCaStagePlanFromStore {
    # the web app's preview: the plan from what the engine last read (eps.CaPolicy) - no Graph. Returns the plan, or $null
    # when the policy is not in the last read.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)][string]$To)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT BodyJson, ReviewJson FROM eps.CaPolicy WHERE PolicyId = @p')[0]
    if (-not $r -or -not $r.BodyJson -or $r.BodyJson -is [DBNull] -or -not $r.ReviewJson -or $r.ReviewJson -is [DBNull]) { return $null }
    $names = Get-EpsCaNameMap -ConnectionString $ConnectionString
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -NoGraph
    $rv = $r.ReviewJson | ConvertFrom-Json -AsHashtable -Depth 20
    $plan = Get-EpsCaStagePlan -Policy ($r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 20) -Review $rv -To $To -Ctx $ctx -Names $names
    $plan.expected = $rv.hash
    $plan
}

# ---- the documentation (v1: Entra-CA-Policies-Documentation[-with-IDs].csv / .xlsx) --------------------------------------
$script:EpsCaDocColumns = @('Template', 'Stage', 'DisplayName', 'State', 'IncludeUsers', 'ExcludeUsers', 'IncludeGroups', 'ExcludeGroups', 'IncludeRoles', 'ExcludeRoles',
    'IncludeApplications', 'ExcludeApplications', 'UserActions', 'AuthenticationContexts', 'ClientAppTypes', 'IncludePlatforms', 'ExcludePlatforms', 'IncludeLocations', 'ExcludeLocations',
    'SignInRiskLevels', 'UserRiskLevels', 'InsiderRiskLevels', 'DeviceFilter', 'AuthenticationFlows', 'IncludeServicePrincipals', 'ExcludeServicePrincipals',
    'GrantOperator', 'GrantControls', 'AuthenticationStrength', 'TermsOfUse', 'SessionControls', 'Created', 'Modified', 'PolicyId')
function Get-EpsCaDocColumns { $script:EpsCaDocColumns }

function Get-EpsCaDocumentationRows {
    <#
      One row per policy with every id resolved to a name where the engine could read it (users by UPN; groups, roles,
      named locations, applications by name); an id it could not read stays an id. -WithIds keeps the id next to the
      name (v1's "-with-IDs" file). -Rows: eps.CaPolicy rows with BodyJson / ReviewJson; -Names: Get-EpsCaNameMap.
    #>
    param([object[]]$Rows = @(), [hashtable]$Names = @{}, [switch]$WithIds)
    $fmt = { param([string]$kind, $vals)
        (@(foreach ($v in @($vals)) { if ($null -eq $v -or "$v" -eq '') { continue }
            $n = $Names["$kind|$("$v".ToLowerInvariant())"]
            $label = if (-not $n) { if ($kind -eq 'application' -and "$v" -match $script:EpsCaGuidRx -and $Names['note|application']) { "$v ($($Names['note|application'].Name))" } else { "$v" } } elseif ($kind -eq 'user' -and $n.Detail) { "$($n.Detail)" } elseif ($n.Name) { "$($n.Name)" } else { "$v" }
            if ($WithIds -and -not $label.StartsWith("$v")) { "$label ($v)" } else { $label } }) -join '; ') }
    foreach ($r in @($Rows)) {
        if (-not $r.BodyJson) { continue }
        $p = $r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 20
        $rv = if ($r.ReviewJson) { $r.ReviewJson | ConvertFrom-Json -AsHashtable -Depth 20 } else { @{} }
        $L = { param($path) Get-EpsCaList $p $path }
        $sc = Get-EpsCaV $p 'sessionControls'; $s = [System.Collections.Generic.List[string]]::new()
        if (Get-EpsCaV $sc 'signInFrequency.isEnabled') { $s.Add("sign-in frequency: $(if ("$(Get-EpsCaV $sc 'signInFrequency.frequencyInterval')" -eq 'everyTime') { 'every time' } else { "$(Get-EpsCaV $sc 'signInFrequency.value') $(Get-EpsCaV $sc 'signInFrequency.type')" }) ($(Get-EpsCaV $sc 'signInFrequency.authenticationType'))") }
        if (Get-EpsCaV $sc 'persistentBrowser.isEnabled') { $s.Add("persistent browser: $(Get-EpsCaV $sc 'persistentBrowser.mode')") }
        if (Get-EpsCaV $sc 'cloudAppSecurity.isEnabled') { $s.Add("app control: $(Get-EpsCaV $sc 'cloudAppSecurity.cloudAppSecurityType')") }
        if (Get-EpsCaV $sc 'applicationEnforcedRestrictions.isEnabled') { $s.Add('app enforced restrictions') }
        if (Get-EpsCaV $sc 'disableResilienceDefaults') { $s.Add('resilience defaults off') }
        if ("$(Get-EpsCaV $sc 'continuousAccessEvaluation.mode')") { $s.Add("continuous access evaluation: $(Get-EpsCaV $sc 'continuousAccessEvaluation.mode')") }
        if (Get-EpsCaV $sc 'secureSignInSession.isEnabled') { $s.Add('token protection') }
        $df = Get-EpsCaV $p 'conditions.devices.deviceFilter'
        $as = Get-EpsCaV $p 'grantControls.authenticationStrength'
        [pscustomobject][ordered]@{
            Template = "$($rv.templateId)"; Stage = "$($rv.stage)"; DisplayName = "$(Get-EpsCaV $p 'displayName')"; State = "$(Get-EpsCaV $p 'state')"
            IncludeUsers = & $fmt 'user' (& $L 'conditions.users.includeUsers'); ExcludeUsers = & $fmt 'user' (& $L 'conditions.users.excludeUsers')
            IncludeGroups = & $fmt 'group' (& $L 'conditions.users.includeGroups'); ExcludeGroups = & $fmt 'group' (& $L 'conditions.users.excludeGroups')
            IncludeRoles = & $fmt 'role' (& $L 'conditions.users.includeRoles'); ExcludeRoles = & $fmt 'role' (& $L 'conditions.users.excludeRoles')
            IncludeApplications = & $fmt 'application' (& $L 'conditions.applications.includeApplications'); ExcludeApplications = & $fmt 'application' (& $L 'conditions.applications.excludeApplications')
            UserActions = (& $L 'conditions.applications.includeUserActions') -join '; '; AuthenticationContexts = (& $L 'conditions.applications.includeAuthenticationContextClassReferences') -join '; '
            ClientAppTypes = (& $L 'conditions.clientAppTypes') -join '; '
            IncludePlatforms = (& $L 'conditions.platforms.includePlatforms') -join '; '; ExcludePlatforms = (& $L 'conditions.platforms.excludePlatforms') -join '; '
            IncludeLocations = & $fmt 'location' (& $L 'conditions.locations.includeLocations'); ExcludeLocations = & $fmt 'location' (& $L 'conditions.locations.excludeLocations')
            SignInRiskLevels = (& $L 'conditions.signInRiskLevels') -join '; '; UserRiskLevels = (& $L 'conditions.userRiskLevels') -join '; '; InsiderRiskLevels = (& $L 'conditions.insiderRiskLevels') -join '; '
            DeviceFilter = $(if ($df) { "$(Get-EpsCaV $df 'mode'): $(Get-EpsCaV $df 'rule')" } else { '' }); AuthenticationFlows = "$(Get-EpsCaV $p 'conditions.authenticationFlows.transferMethods')"
            IncludeServicePrincipals = & $fmt 'servicePrincipal' (& $L 'conditions.clientApplications.includeServicePrincipals'); ExcludeServicePrincipals = & $fmt 'servicePrincipal' (& $L 'conditions.clientApplications.excludeServicePrincipals')
            GrantOperator = "$(Get-EpsCaV $p 'grantControls.operator')"; GrantControls = (& $L 'grantControls.builtInControls') -join '; '
            AuthenticationStrength = $(if ($as) { $n = "$(Get-EpsCaV $as 'displayName')"; if ($WithIds -and (Get-EpsCaV $as 'id')) { "$n ($(Get-EpsCaV $as 'id'))" } else { $n } } else { '' })
            TermsOfUse = (& $L 'grantControls.termsOfUse') -join '; '; SessionControls = ($s -join '; ')
            Created = "$(Get-EpsCaV $p 'createdDateTime')"; Modified = "$(Get-EpsCaV $p 'modifiedDateTime')"; PolicyId = "$($r.PolicyId)"
        }
    }
}

# ---- SQL reads (the web app and the engine) ---------------------------------------------------------------------------
function Get-EpsCaNameMap {
    # eps.CaDirectoryName -> "kind|id" -> @{ Kind; Name; Detail }
    param([Parameter(Mandatory)][string]$ConnectionString)
    $m = @{}
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Kind, ObjectId, Name, Detail FROM eps.CaDirectoryName')) { $m["$($r.Kind)|$("$($r.ObjectId)".ToLowerInvariant())"] = @{ Kind = [string]$r.Kind; Name = [string]$r.Name; Detail = $(if ($r.Detail -is [DBNull]) { $null } else { [string]$r.Detail }) } }
    $m
}

function Get-EpsCaOverview {
    # the Conditional Access page: every policy as last read with the engine's review, the adoption record, open findings
    param([Parameter(Mandatory)][string]$ConnectionString)
    $adopt = @{}; foreach ($a in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT PolicyId, Status, TemplateId, StageAtAdopt, AdoptedBy, AdoptedAtUtc, ReleasedBy, ReleasedAtUtc FROM eps.CaAdoption')) { $adopt["$($a.PolicyId)".ToLowerInvariant()] = $a }
    $open = @{}; foreach ($f in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT PolicyId, Kind FROM eps.CaFinding WHERE Status = 'Open'")) { $k = "$($f.PolicyId)".ToLowerInvariant(); $open[$k] = @($open[$k]) + @([string]$f.Kind) | Where-Object { $_ } }
    $pol = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT PolicyId, DisplayName, State, ModifiedAtUtc, SeenAtUtc, ReviewJson FROM eps.CaPolicy ORDER BY DisplayName')
    # the MANAGED personas that take each policy now (CA-LIMITS fix 3; none = "no persona") - eps.CaPersona, never the templates
    $inPer = Get-EpsCaPolicyPersonaMap -ConnectionString $ConnectionString -Policies @($pol | ForEach-Object { [pscustomobject]@{ id = "$($_.PolicyId)".ToLowerInvariant(); displayName = "$($_.DisplayName)" } })
    $rows = @(foreach ($r in $pol) {
        $rv = if ($r.ReviewJson -and $r.ReviewJson -isnot [DBNull]) { $r.ReviewJson | ConvertFrom-Json -AsHashtable -Depth 20 } else { @{} }
        $k = "$($r.PolicyId)".ToLowerInvariant(); $a = $adopt[$k]
        [pscustomobject][ordered]@{
            PolicyId = "$($r.PolicyId)"; DisplayName = [string]$r.DisplayName; State = [string]$r.State; ModifiedAtUtc = $r.ModifiedAtUtc; SeenAtUtc = $r.SeenAtUtc
            TemplateId = $rv.templateId; Persona = $(if ($inPer[$k]) { @($inPer[$k]) -join ', ' } else { 'no persona' }); TemplateVersion = $rv.templateVersion; InLibrary = [bool]$rv.inLibrary; NameStage = $rv.nameStage; Stage = $rv.stage; StageNote = $rv.stageNote
            StageMismatch = [bool]$rv.stageMismatch; Matches = $(if ($rv.inLibrary) { [bool]$rv.matches } else { $null }); DiffCount = [int]$rv.diffCount
            BreakGlass = $(if ($null -eq $rv.breakGlass) { 'unknown' } elseif ($rv.breakGlass.exempt) { 'exempt' } elseif ($rv.breakGlass.ok -eq $true) { 'excluded' } elseif ($rv.breakGlass.ok -eq $false) { 'MISSING' } else { 'unknown' })
            BreakGlassText = $(if ($rv.breakGlass) { $rv.breakGlass.text }); Hash = $rv.hash
            Adoption = $(if ($a) { [string]$a.Status } else { 'Not adopted' }); AdoptedBy = $(if ($a -and $a.Status -eq 'Adopted') { [string]$a.AdoptedBy }); AdoptedAtUtc = $(if ($a -and $a.Status -eq 'Adopted') { $a.AdoptedAtUtc })
            Findings = (@($open[$k]) | Where-Object { $_ }) -join ', '
        } })
    $findings = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT FindingId, PolicyId, DisplayName, Kind, Detail, Status, FirstSeenUtc, LastSeenUtc, ClearedAtUtc, AlertedAtUtc FROM eps.CaFinding WHERE Status = 'Open' OR ClearedAtUtc >= DATEADD(day, -30, SYSUTCDATETIME()) ORDER BY Status DESC, LastSeenUtc DESC")
    @{ Rows = $rows; Findings = $findings }
}

function Get-EpsCaPolicyDetail {
    # one policy: its body (with the names), the engine's review (the diff), the adoption record, its findings
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT PolicyId, DisplayName, State, ModifiedAtUtc, SeenAtUtc, BodyJson, ReviewJson FROM eps.CaPolicy WHERE PolicyId = @p')[0]
    if (-not $r) { return $null }
    $names = Get-EpsCaNameMap -ConnectionString $ConnectionString
    $a = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT PolicyId, DisplayName, TemplateId, TemplateVersion, StageAtAdopt, Status, AdoptedBodyHash, AdoptedBy, AdoptedAtUtc, AdoptReason, ReleasedBy, ReleasedAtUtc, ReleaseReason FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    $f = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT TOP 100 FindingId, Kind, Detail, DetailJson, Status, FirstSeenUtc, LastSeenUtc, ClearedAtUtc, AlertedAtUtc FROM eps.CaFinding WHERE PolicyId = @p ORDER BY LastSeenUtc DESC')
    $body = if ($r.BodyJson -and $r.BodyJson -isnot [DBNull]) { $r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 20 }
    $used = @{}
    if ($body) {
        foreach ($path in $script:EpsCaComparePaths.Keys) { $kind = $script:EpsCaComparePaths[$path]; if ($kind -notin 'user', 'group', 'role', 'location') { continue }
            foreach ($v in (Get-EpsCaList $body $path)) { $n = $names["$kind|$("$v".ToLowerInvariant())"]; if ($n) { $used[$v] = $(if ($kind -eq 'user' -and $n.Detail) { $n.Detail } else { $n.Name }) } } }
        foreach ($v in @(Get-EpsCaList $body 'conditions.applications.includeApplications') + @(Get-EpsCaList $body 'conditions.applications.excludeApplications')) { $n = $names["application|$("$v".ToLowerInvariant())"]; if ($n) { $used[$v] = $n.Name } }
    }
    # CA-LIFECYCLE: the stage moves made from here (newest first)
    $mv = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT TOP 50 MoveId, DisplayName, FromStage, ToStage, Result, ResultText, RequestedBy, Reason, MovedAtUtc FROM eps.CaStageMove WHERE PolicyId = @p ORDER BY MovedAtUtc DESC')
    @{ Policy = $r; Body = $body; Names = $used; Review = $(if ($r.ReviewJson -and $r.ReviewJson -isnot [DBNull]) { $r.ReviewJson | ConvertFrom-Json -Depth 20 }); Adoption = $a; Findings = $f; Moves = $mv
       Documentation = @(Get-EpsCaDocumentationRows -Rows @($r) -Names $names)[0] }
}

# ---- adopt / release: a RECORD, applied by the engine from the operator's signed request -----------------------------------
function Save-EpsCaAdoption {
    <#
      Records that the operator adopted ONE policy, as it is (owner 2026-10-30: "adopt them into eps"). The body as the
      engine last read it becomes the drift baseline. -Expected = the review hash the operator saw: a policy that changed
      since (a newer read) is refused - he adopts what he looked at, nothing else. NOTHING in the tenant changes.
      Returns @{ Result = ok | missing | changed | already; Before; After }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [string]$Expected, [Parameter(Mandatory)][string]$Actor, [string]$Reason)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT PolicyId, DisplayName, BodyJson, ReviewJson FROM eps.CaPolicy WHERE PolicyId = @p')[0]
    if (-not $r -or -not $r.BodyJson -or $r.BodyJson -is [DBNull]) { return @{ Result = 'missing' } }
    $body = $r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 20
    $rv = if ($r.ReviewJson -and $r.ReviewJson -isnot [DBNull]) { $r.ReviewJson | ConvertFrom-Json -AsHashtable -Depth 20 } else { @{} }
    $hash = Get-EpsCaBodyHash $body
    if ($Expected -and $Expected -ne $hash) { return @{ Result = 'changed' } }
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT Status, AdoptedBy, AdoptedAtUtc FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    if ($cur -and $cur.Status -eq 'Adopted') { return @{ Result = 'already'; By = $cur.AdoptedBy } }
    $canon = (ConvertTo-EpsCaCanonical $body) | ConvertTo-Json -Compress -Depth 20
    $after = [ordered]@{ policyId = "$PolicyId"; displayName = [string]$r.DisplayName; templateId = $rv.templateId; templateVersion = $rv.templateVersion; stage = $rv.stage; hash = $hash; status = 'Adopted' }
    $p = @{ p = $PolicyId; n = [string]$r.DisplayName; t = $rv.templateId; tv = $rv.templateVersion; s = $rv.stage; b = $canon; h = $hash; by = $Actor; rs = $Reason } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaAdoption' -Key "$PolicyId" -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before $(if ($cur) { @{ status = [string]$cur.Status } | ConvertTo-Json -Compress }) -After ($after | ConvertTo-Json -Compress))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
MERGE eps.CaAdoption AS x USING (SELECT @p AS PolicyId) AS s ON x.PolicyId = s.PolicyId
WHEN MATCHED THEN UPDATE SET DisplayName = @n, TemplateId = @t, TemplateVersion = @tv, StageAtAdopt = @s, Status = 'Adopted', AdoptedBodyJson = @b, AdoptedBodyHash = @h, AdoptedBy = @by, AdoptedAtUtc = SYSUTCDATETIME(), AdoptReason = @rs, ReleasedBy = NULL, ReleasedAtUtc = NULL, ReleaseReason = NULL
WHEN NOT MATCHED THEN INSERT (PolicyId, DisplayName, TemplateId, TemplateVersion, StageAtAdopt, Status, AdoptedBodyJson, AdoptedBodyHash, AdoptedBy, AdoptReason) VALUES (@p, @n, @t, @tv, @s, 'Adopted', @b, @h, @by, @rs);
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Before = $(if ($cur) { @{ status = [string]$cur.Status } }); After = $after }
}

function Save-EpsCaRelease {
    # the operator stops managing an adopted policy in EPS ("leave it"): the record says so, its monitor findings are
    # cleared. NOTHING in the tenant changes. Returns @{ Result = ok | missing; Before }.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)][string]$Actor, [string]$Reason)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT Status, DisplayName, TemplateId, AdoptedBy FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    if (-not $cur -or $cur.Status -ne 'Adopted') { return @{ Result = 'missing' } }
    $before = [ordered]@{ status = 'Adopted'; displayName = [string]$cur.DisplayName; adoptedBy = [string]$cur.AdoptedBy }
    $p = @{ p = $PolicyId; by = $Actor; rs = $Reason } + (New-EpsJournalParameters -Actor $Actor -Entity 'CaAdoption' -Key "$PolicyId" -Action 'Update' -Before ($before | ConvertTo-Json -Compress) -After (@{ status = 'Released' } | ConvertTo-Json -Compress))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
UPDATE eps.CaAdoption SET Status = 'Released', ReleasedBy = @by, ReleasedAtUtc = SYSUTCDATETIME(), ReleaseReason = @rs WHERE PolicyId = @p AND Status = 'Adopted';
UPDATE eps.CaFinding SET Status = 'Cleared', ClearedAtUtc = SYSUTCDATETIME() WHERE PolicyId = @p AND Status = 'Open';
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Before = $before }
}

# ---- the engine: names, the inventory, the monitor (READ ONLY towards the tenant) --------------------------------------------
function Resolve-EpsCaDirectoryNames {
    # every id the policies name -> its name, by GET only, with the rights the engine already has; what it cannot read
    # is said in -Notes and stays an id (never a guess). Returns "kind|id" -> @{ Kind; Name; Detail }.
    param([object[]]$Policies = @(), [System.Collections.Generic.List[string]]$Notes)
    $note = { param($m) if ($null -ne $Notes) { $Notes.Add($m) } }
    $ids = @{ user = [System.Collections.Generic.HashSet[string]]::new(); group = [System.Collections.Generic.HashSet[string]]::new(); application = [System.Collections.Generic.HashSet[string]]::new(); servicePrincipal = [System.Collections.Generic.HashSet[string]]::new() }
    $add = { param($kind, $vals) foreach ($v in @($vals)) { if ("$v" -match $script:EpsCaGuidRx) { [void]$ids[$kind].Add("$v".ToLowerInvariant()) } } }
    foreach ($p in @($Policies)) {
        & $add 'user' ((Get-EpsCaList $p 'conditions.users.includeUsers') + (Get-EpsCaList $p 'conditions.users.excludeUsers'))
        & $add 'group' ((Get-EpsCaList $p 'conditions.users.includeGroups') + (Get-EpsCaList $p 'conditions.users.excludeGroups'))
        & $add 'application' ((Get-EpsCaList $p 'conditions.applications.includeApplications') + (Get-EpsCaList $p 'conditions.applications.excludeApplications'))
        & $add 'servicePrincipal' ((Get-EpsCaList $p 'conditions.clientApplications.includeServicePrincipals') + (Get-EpsCaList $p 'conditions.clientApplications.excludeServicePrincipals'))
    }
    $names = @{}
    $put = { param($kind, $id, $name, $detail) if ($id) { $names["$kind|$("$id".ToLowerInvariant())"] = @{ Kind = $kind; Name = [string]$name; Detail = $(if ($null -ne $detail -and "$detail" -ne '') { [string]$detail }) } } }
    # chunks of 15 ids (Graph's "in" filter); a List, so one chunk is still ONE item when it is looped over
    $chunks = { param($set) $a = @($set); $l = [System.Collections.Generic.List[object]]::new(); for ($i = 0; $i -lt $a.Count; $i += 15) { $l.Add([string[]]@($a[$i..([Math]::Min($i + 14, $a.Count - 1))])) }; , $l }
    try { foreach ($c in (& $chunks $ids.group)) { foreach ($g in @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=id in ($((@($c) | ForEach-Object { "'$_'" }) -join ','))&`$select=id,displayName,membershipRule" -All)) { & $put 'group' $g.id $g.displayName $g.membershipRule } } }
    catch { & $note "group names could not be read: $($_.Exception.Message)" }
    try { foreach ($c in (& $chunks $ids.user)) { foreach ($u in @(Invoke-EpsGraph -Path "v1.0/users?`$filter=id in ($((@($c) | ForEach-Object { "'$_'" }) -join ','))&`$select=id,displayName,userPrincipalName" -All)) { & $put 'user' $u.id $u.displayName $u.userPrincipalName } } }
    catch { & $note "user names could not be read: $($_.Exception.Message)" }
    try { foreach ($r in @(Invoke-EpsGraph -Path 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId' -All)) { & $put 'role' $r.id $r.displayName $null; if ($r.templateId) { & $put 'role' $r.templateId $r.displayName $null } } }
    catch { & $note "role names could not be read: $($_.Exception.Message)" }
    try { foreach ($l in @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All)) { & $put 'location' $l.id $l.displayName $(if ($l.'@odata.type') { ($l.'@odata.type' -replace '^#microsoft\.graph\.', '') }) } }
    catch { & $note "named location names could not be read: $($_.Exception.Message)" }
    # application names: Application.Read.All, read only (owner 2026-11-01: "Grant Application.Read.All"). An install that
    # does not have it (yet) is refused: the ids stay, and the documentation says why (the 'note|application' entry)
    try { foreach ($c in (& $chunks $ids.application)) { foreach ($s in @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId in ($((@($c) | ForEach-Object { "'$_'" }) -join ','))&`$select=appId,displayName" -All)) { & $put 'application' $s.appId $s.displayName $null } } }
    catch { & $note "application names could not be read (the engine needs Application.Read.All) - the ids are shown ($($_.Exception.Message))"; & $put 'note' 'application' 'name not readable: the engine needs Application.Read.All' $null }
    try { foreach ($c in (& $chunks $ids.servicePrincipal)) { foreach ($s in @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=id in ($((@($c) | ForEach-Object { "'$_'" }) -join ','))&`$select=id,displayName" -All)) { & $put 'servicePrincipal' $s.id $s.displayName $null } } }
    catch { & $note "service principal names could not be read with the engine's rights - the ids are shown ($($_.Exception.Message))" }
    foreach ($p in @($Policies)) { $as = Get-EpsCaV $p 'grantControls.authenticationStrength'; if ($as -and (Get-EpsCaV $as 'id')) { & $put 'authStrength' (Get-EpsCaV $as 'id') (Get-EpsCaV $as 'displayName') $null } }
    $names
}

function Get-EpsCaStoredContext {
    # the SQL part of the context (the web app's stage plan reads it too): the group-targeting method, the target groups
    # (the v1 import), the break-glass accounts as stored (their id when known), the authentication strength and named
    # location names. Returns @{ Method; TargetGroups; AuthStrength; NamedLocation; Accounts (Upn; Method; Id) }.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $set = { param($n) "$(Get-EpsSetting -ConnectionString $ConnectionString -Name $n -Default '')".Trim() }
    $tg = @{}
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT DisplayName, VariableName, Assignment FROM eps.TargetGroup')) {
        if (-not $tg[$r.VariableName]) { $tg[[string]$r.VariableName] = @{ Dynamic = $null; Assigned = $null } }
        $tg[[string]$r.VariableName][$(if ($r.Assignment -eq 'Dynamic') { 'Dynamic' } else { 'Assigned' })] = [string]$r.DisplayName
    }
    $acc = @(foreach ($a in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT UserPrincipalName, AuthenticationMethod, ObjectId FROM eps.BreakGlassAccount WHERE Enabled = 1 AND Directory = 'Entra'")) {
        @{ Upn = ([string]$a.UserPrincipalName).ToLowerInvariant(); Method = $(if ($a.AuthenticationMethod -is [DBNull]) { '' } else { [string]$a.AuthenticationMethod }); Id = $(if ($a.ObjectId -and $a.ObjectId -isnot [DBNull]) { "$($a.ObjectId)" }) } })
    @{ Method = (ConvertTo-EpsCaTargetingMethod (& $set 'CA.GroupTargetingMethod')); TargetGroups = $tg; Accounts = $acc
       AuthStrength = @{ FIDO = (& $set 'CA.AuthStrengthFidoName'); WHfB = (& $set 'CA.AuthStrengthWhfbName') }; NamedLocation = @{ DeniedCountries = (& $set 'CA.DeniedCountriesLocationName') } }
}

function Get-EpsCaContext {
    # the inputs the templates name, as the customer set them (Get-EpsCaStoredContext), with the break-glass group(s) and
    # accounts resolved to ids by GET. -Names gets the break-glass group(s) too. Returns @{ Method; TargetGroups; BreakGlass; AuthStrength; NamedLocation }.
    # -NoGraph (the web app's stage plan): no lookup - the accounts' stored ids only, no break-glass group id.
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$Names = @{}, [System.Collections.Generic.List[string]]$Notes, $Catalog = (Get-EpsCaTemplateCatalog), [switch]$NoGraph)
    $note = { param($m) if ($null -ne $Notes) { $Notes.Add($m) } }
    $s = Get-EpsCaStoredContext -ConnectionString $ConnectionString
    $tg = $s.TargetGroups
    $ctx = @{ Method = $s.Method; TargetGroups = $tg; AuthStrength = $s.AuthStrength; NamedLocation = $s.NamedLocation }
    # the break-glass group(s): the target group the templates exclude, both its Dynamic and its Assigned name
    $bgNames = @{}; $relNames = @{}
    foreach ($role in @($Catalog.groupRoles.Keys) + @($tg.Keys) | Select-Object -Unique) {
        if ($role -notlike 'BreakGlassAccounts*') { continue }
        $g = if ($tg[$role]) { $tg[$role] } else { $Catalog.groupRoles[$role] }
        foreach ($n in @($g.Dynamic, $g.Assigned) | Where-Object { $_ }) { $relNames[$n] = 1; if ($role -eq $Catalog.breakGlassGroupRole) { $bgNames[$n] = 1 } }
    }
    $gids = [System.Collections.Generic.List[string]]::new(); $rel = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($relNames.Keys)) {
        if ($NoGraph) { break }
        try {
            foreach ($g in @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$($n.Replace("'", "''"))'&`$select=id,displayName,membershipRule" -All)) {
                $Names["group|$("$($g.id)".ToLowerInvariant())"] = @{ Kind = 'group'; Name = [string]$g.displayName; Detail = $(if ($g.membershipRule) { [string]$g.membershipRule }) }
                $rel.Add([string]$g.id); if ($bgNames.ContainsKey($n)) { $gids.Add([string]$g.id) }
            }
        } catch { & $note "break-glass group '$n' could not be read: $($_.Exception.Message)" }
    }
    $acc = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($s.Accounts)) {
        $id = $a.Id
        if (-not $id -and -not $NoGraph) { try { $id = [string](Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString([string]$a.Upn))?`$select=id").id } catch { & $note "break-glass account $($a.Upn) could not be read: $($_.Exception.Message)" } }
        if ($id) { $Names["user|$($id.ToLowerInvariant())"] = @{ Kind = 'user'; Name = [string]$a.Upn; Detail = [string]$a.Upn } }
        $acc.Add(@{ Upn = $a.Upn; Method = $a.Method; Id = $id })
    }
    if (-not $acc.Count) { & $note 'no break-glass account is configured (eps.BreakGlassAccount): the break-glass check uses the group only' }
    $ctx.BreakGlass = @{ GroupIds = @($gids); RelatedGroupIds = @($rel); Accounts = @($acc) }
    $ctx
}

function Update-EpsCaInventory {
    <#
      The engine, inside the CA Policy Analyzer's read of the policy list (no job of its own): resolves the names, reviews
      every policy (template, stage, diff, break-glass), stores the names, runs the monitor when it is on. READ ONLY
      towards the tenant: GETs only. Returns @{ Reviews ("<id>" -> review); Names; Notes; Monitor }.
      A failure here never fails the analyzer: the reviews it could not make are left out, and said.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Policies = @(), [string]$Version = '2.0.0', [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $notes = [System.Collections.Generic.List[string]]::new()
    $names = Resolve-EpsCaDirectoryNames -Policies $Policies -Notes $notes
    $cat = Get-EpsCaTemplateCatalog
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -Notes $notes -Catalog $cat
    $reviews = @{}
    foreach ($p in @($Policies)) {
        try { $reviews["$($p.id)".ToLowerInvariant()] = Get-EpsCaReview -Policy $p -Names $names -Ctx $ctx -Catalog $cat }
        catch { $notes.Add("$($p.displayName): the review failed - $($_.Exception.Message)") }
    }
    Save-EpsCaDirectoryNames -ConnectionString $ConnectionString -Names $names
    $matched = @($reviews.Values | Where-Object { $_.inLibrary }).Count
    & $Log 'Info' "Conditional Access review (read only): $(@($Policies).Count) policies, $matched matched to a template, $(@($reviews.Values | Where-Object { $_.inLibrary -and $_.matches }).Count) as the template, $(@($reviews.Values | Where-Object { $_.breakGlass.ok -eq $false }).Count) without the break-glass exclusion"
    foreach ($n in $notes) { & $Log 'Warning' "  $n" }
    $mon = $null
    try { $mon = Invoke-EpsCaMonitorCheck -ConnectionString $ConnectionString -Policies $Policies -Reviews $reviews -Names $names -Version $Version -Log $Log }
    catch { & $Log 'Error' "the CA monitor failed: $($_.Exception.Message)" }
    @{ Reviews = $reviews; Names = $names; Notes = @($notes); Monitor = $mon }
}

function Save-EpsCaDirectoryNames {
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$Names = @{})
    $rows = @(foreach ($k in $Names.Keys) { $n = $Names[$k]; $id = ($k -split '\|', 2)[1]; @{ k = $n.Kind; i = $id; n = $n.Name; d = $n.Detail } })
    $json = if ($rows.Count) { ConvertTo-Json -InputObject @($rows) -Compress -Depth 4 } else { '[]' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $json } -Query @'
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaDirectoryName;
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail)
SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@j) WITH (k NVARCHAR(20) '$.k', i NVARCHAR(100) '$.i', n NVARCHAR(MAX) '$.n', d NVARCHAR(MAX) '$.d') AS x;
COMMIT;
'@)
}

function Invoke-EpsCaMonitorCheck {
    <#
      CA.Monitoring.Enabled (off by default): for every ADOPTED policy - Drift (its body differs from the body recorded at
      adopt), Missing (it is no longer in the tenant), BreakGlass (it does not exclude the break-glass group / accounts).
      A finding is SHOWN (eps.CaFinding, the Conditional Access page) and alerted once (one mail per run for the new
      ones); a finding that is no longer true is cleared. EPS never acts on a finding (owner 2026-10-30).
      Returns @{ Enabled; Adopted; Open; New; Mail }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Policies = @(), [hashtable]$Reviews = @{}, [hashtable]$Names = @{}, [string]$Version = '2.0.0', [scriptblock]$Log = { param($l, $m) })
    if ("$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'CA.Monitoring.Enabled' -Default 'false')" -ne 'true') { return @{ Enabled = $false } }
    $byId = @{}; foreach ($p in @($Policies)) { $byId["$($p.id)".ToLowerInvariant()] = $p }
    $now = @{}   # "<policyId>|<kind>" -> @{ Detail; Json; Hash }
    $adopted = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT PolicyId, DisplayName, AdoptedBodyJson, AdoptedBodyHash FROM eps.CaAdoption WHERE Status = 'Adopted'")
    foreach ($a in $adopted) {
        $k = "$($a.PolicyId)".ToLowerInvariant(); $p = $byId[$k]
        if (-not $p) { $now["$k|Missing"] = @{ Name = [string]$a.DisplayName; Detail = 'the adopted policy is no longer in the tenant (deleted, or the engine cannot read it)'; Json = $null; Hash = 'missing' }; continue }
        $h = Get-EpsCaBodyHash $p
        if ($h -ne "$($a.AdoptedBodyHash)") {
            $before = $a.AdoptedBodyJson | ConvertFrom-Json -AsHashtable -Depth 20
            $after = (ConvertTo-EpsCaCanonical $p) | ConvertTo-Json -Compress -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 20
            $d = @(Compare-EpsCaCanonical -Before $before -After $after | ForEach-Object { [ordered]@{ path = $_.path; before = (Format-EpsCaIds $_.before $Names); after = (Format-EpsCaIds $_.after $Names) } })
            $now["$k|Drift"] = @{ Name = [string]$p.displayName; Detail = "changed since it was adopted: $(@($d | ForEach-Object { $_.path }) -join ', ')"; Json = (ConvertTo-Json -InputObject @($d) -Compress -Depth 6); Hash = $h }
        }
        $rv = $Reviews[$k]
        if ($rv -and $rv.breakGlass.ok -eq $false) { $now["$k|BreakGlass"] = @{ Name = [string]$p.displayName; Detail = "$($rv.breakGlass.text)"; Json = (ConvertTo-Json -InputObject @($rv.breakGlass.missing) -Compress); Hash = "bg:$(@($rv.breakGlass.missing) -join ',')" } }
    }
    $open = @{}; foreach ($f in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT FindingId, PolicyId, Kind, DetailJson FROM eps.CaFinding WHERE Status = 'Open'")) { $open["$("$($f.PolicyId)".ToLowerInvariant())|$($f.Kind)"] = $f }
    $new = 0
    foreach ($key in $now.Keys) {
        $pid0, $kind = $key -split '\|', 2; $x = $now[$key]
        $j = ConvertTo-Json -InputObject @{ hash = $x.Hash; detail = $(if ($x.Json) { $x.Json | ConvertFrom-Json }) } -Compress -Depth 8
        if ($open[$key]) {
            # the same finding: refreshed; a drift that changed AGAIN (another hash) is alerted again
            $same = try { ($open[$key].DetailJson | ConvertFrom-Json).hash -eq $x.Hash } catch { $false }
            [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [long]$open[$key].FindingId; d = $x.Detail.Substring(0, [Math]::Min(2000, $x.Detail.Length)); j = $j; re = [bool](-not $same) } -Query 'UPDATE eps.CaFinding SET Detail = @d, DetailJson = @j, LastSeenUtc = SYSUTCDATETIME(), AlertedAtUtc = CASE WHEN @re = 1 THEN NULL ELSE AlertedAtUtc END WHERE FindingId = @id')
        } else {
            $new++
            [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ p = [guid]$pid0; n = $x.Name; k = $kind; d = $x.Detail.Substring(0, [Math]::Min(2000, $x.Detail.Length)); j = $j } -Query 'INSERT INTO eps.CaFinding (PolicyId, DisplayName, Kind, Detail, DetailJson) VALUES (@p, @n, @k, @d, @j)')
        }
    }
    foreach ($key in @($open.Keys | Where-Object { -not $now.ContainsKey($_) })) {
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [long]$open[$key].FindingId } -Query "UPDATE eps.CaFinding SET Status = 'Cleared', ClearedAtUtc = SYSUTCDATETIME() WHERE FindingId = @id AND Status = 'Open'")
    }
    & $Log $(if ($now.Count) { 'Warning' } else { 'Info' }) "CA monitor: $($adopted.Count) adopted policy(ies), $($now.Count) open finding(s), $new new - shown and alerted only, nothing is changed"
    $mail = Send-EpsCaMonitorAlert -ConnectionString $ConnectionString -Version $Version
    if ($mail.Findings) { & $Log 'Info' "  alert: $($mail.Findings) finding(s), $(if ($mail.Sent) { 'mailed' } else { "NOT mailed - $($mail.Reason); tried again next run" })" }
    @{ Enabled = $true; Adopted = $adopted.Count; Open = $now.Count; New = $new; Mail = $mail }
}

function Send-EpsCaMonitorAlert {
    # ONE mail for the open findings not alerted yet (MAIL-1 / MAIL-3, the tamper alert's pattern); each is alerted once,
    # a failed send is tried again by the next run. Never throws. Returns @{ Findings; Sent; Reason }.
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version = '2.0.0')
    $open = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT FindingId, DisplayName, Kind, Detail, FirstSeenUtc FROM eps.CaFinding WHERE Status = 'Open' AND AlertedAtUtc IS NULL ORDER BY CASE Kind WHEN 'BreakGlass' THEN 0 WHEN 'Missing' THEN 1 ELSE 2 END, FirstSeenUtc")
    if (-not $open.Count) { return @{ Findings = 0; Sent = $false; Reason = 'nothing new to alert' } }
    $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
    $bg = @($open | Where-Object { $_.Kind -ne 'Drift' }).Count
    $what = "Conditional Access: $($open.Count) finding(s) on adopted policies$(if ($bg) { ", $bg break-glass / missing" })"
    $rows = @(foreach ($f in $open) { [pscustomobject]@{ Finding = $(switch ($f.Kind) { 'Drift' { 'changed since adopted' } 'BreakGlass' { 'break-glass NOT excluded' } default { 'no longer in the tenant' } }); Policy = $f.DisplayName; Detail = $f.Detail; Found = ([datetime]$f.FirstSeenUtc).ToString('yyyy-MM-dd HH:mm') + ' UTC' } })
    $html = New-EpsMailBody -Summary "The EntraPolicySuite CA monitor found $($open.Count) finding(s) on Conditional Access policies you adopted. EntraPolicySuite changed nothing and will not: what happens next is your decision." `
        -Rows $rows -Columns 'Finding', 'Policy', 'Detail', 'Found' `
        -WhatToDo 'Open the Conditional Access page for the details. A change you made yourself: adopt the policy again (its new body becomes the baseline). A missing break-glass exclusion is a lock-out risk: fix it in the tenant yourself.' `
        -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
    $r = Send-EpsMail -Config $cfg -Subject (New-EpsMailSubject -Environment $cfg.Environment -What $what -Severity $(if ($bg) { 'Action needed' } else { 'Warning' })) -Html $html -Importance $(if ($bg) { 'high' } else { 'normal' })
    if ($r.Sent) { [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query "UPDATE eps.CaFinding SET AlertedAtUtc = SYSUTCDATETIME() WHERE FindingId IN ($((@($open | ForEach-Object { [long]$_.FindingId })) -join ','))") }
    @{ Findings = $open.Count; Sent = $r.Sent; Reason = $r.Reason }
}
