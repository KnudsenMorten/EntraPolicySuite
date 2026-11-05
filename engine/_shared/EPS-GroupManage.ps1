# EntraPolicySuite -- CA-GROUPS: the groups the Conditional Access policies use, as v1 creates them (DESIGN §5.10
# "Groups"; owner 2026-11-05: "make sure to also include the underlying groups that must be provisioned and managed", he
# chose "Yes, Group.ReadWrite.All"; V1-PARITY: "solution must be min 1:1 on pair with the old eps script solution").
#
# This file READS only: what the groups should be (engine/onboarding/groups.json = v1's definitions, a customer's
# imported eps.TargetGroup / eps.AdminUnit first), what the engine last read in the tenant (eps.ManagedGroup), and the
# PLAN of a change. The web app loads it for the page and the preview. The one place that changes a group or an
# administrative unit is EPS-GroupWrite.ps1, which only the engine loads (tests/Test-EpsGroups.ps1 pins it).

Set-StrictMode -Off

$script:EpsGroupDefaultsCache = $null
$script:EpsGroupActions = @('create', 'rule', 'editrule', 'members', 'forceupdate', 'au')
# GROUPS-ACTIONS: Graph's limit for a membership rule (3072 characters)
$script:EpsGroupRuleMax = 3072
$script:EpsGroupMemberKinds = @('pilot', 'exclude', 'breakglass')

function Get-EpsGroupDefaults {
    if ($script:EpsGroupDefaultsCache) { return $script:EpsGroupDefaultsCache }
    $script:EpsGroupDefaultsCache = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'onboarding\groups.json') -Raw | ConvertFrom-Json -AsHashtable
    $script:EpsGroupDefaultsCache
}

function ConvertTo-EpsGroupRuleText {
    # a membership rule as compared: whitespace folded (v1's own rules carry double spaces)
    param([string]$Rule)
    ("$Rule" -replace '\s+', ' ').Trim()
}

function Get-EpsGroupMailNickname {
    # v1's EntraGroup -AutomaticMailNickname: the name without spaces; longer than 64 = the first 50 + a random number
    param([Parameter(Mandatory)][string]$Name)
    $n = $Name.Replace(' ', '')
    if ($n.Length -gt 64) { $n = $n.Substring(0, 50) + (Get-Random -Minimum 100000 -Maximum 10000000) }
    $n
}

function Get-EpsPilotStageRule {
    <#
      PURE. The dynamic pilot group's rule and processing for a policy stage, as v1's CAnnn.ps1 sets them (Pilot1 / 2 / 3
      widen _pilot1.._pilot3, Prod pauses the rule): @{ Rule; Processing; Stage }. -Pilot = groups.json templates.<id>.pilotDynamic.
    #>
    param($Pilot, [string]$Stage)
    $r = $Pilot.rules
    $s = switch ($Stage) { 'Pilot2' { 'Pilot2' } 'Pilot3' { 'Pilot3' } 'Prod' { 'Prod' } default { 'Pilot1' } }
    $rule = switch ($s) { 'Pilot2' { $r.Pilot2 } { $_ -in 'Pilot3', 'Prod' } { $r.Pilot3 } default { $(if ($r.Pilot1) { $r.Pilot1 } else { $r.Initial }) } }
    @{ Rule = $rule; Processing = $(if ($s -eq 'Prod' -and "$($Pilot.prod)" -eq 'Paused') { 'Paused' } else { 'On' }); Stage = $s }
}

function Get-EpsCustomPilotRule {
    <#
      PURE (GROUPS-ACTIONS). A dynamic pilot group whose rule the operator set: that rule is its Pilot1 base, and a stage
      widens it as v1 widens its own (CAnnn.ps1): every "(<attribute> -contains "_pilot1")" in it becomes "_pilot1 or
      _pilot2" at Pilot2 and "_pilot1 or _pilot2 or _pilot3" at Pilot3 / Prod; Prod pauses the rule when v1 pauses it. A
      custom rule without a "_pilot1" clause is kept as it is at every stage (only the pause at Prod applies).
      @{ Rule; Processing; Stage; Widened }.
    #>
    param([Parameter(Mandatory)][string]$Rule, [string]$Stage, [string]$ProdProcessing = 'Paused')
    $s = switch ($Stage) { 'Pilot2' { 'Pilot2' } 'Pilot3' { 'Pilot3' } 'Prod' { 'Prod' } default { 'Pilot1' } }
    $levels = switch ($s) { 'Pilot2' { 2 } { $_ -in 'Pilot3', 'Prod' } { 3 } default { 1 } }
    $rx = '\(\s*(user\.\w+)\s+-contains\s+"_pilot1"\s*\)'
    $widened = [regex]::IsMatch($Rule, $rx)
    $out = if ($levels -gt 1 -and $widened) {
        [regex]::Replace($Rule, $rx, { param($m) $a = $m.Groups[1].Value; '(' + ((1..$levels | ForEach-Object { "($a -contains `"_pilot$_`")" }) -join ' or ') + ')' })
    } else { $Rule }
    @{ Rule = $out; Processing = $(if ($s -eq 'Prod' -and "$ProdProcessing" -eq 'Paused') { 'Paused' } else { 'On' }); Stage = $s; Widened = $widened }
}

function Get-EpsGroupRuleOverrides {
    # GROUPS-ACTIONS: the rules the operator set (eps.GroupRuleOverride): name -> @{ rule; by; at; reason }
    param([Parameter(Mandatory)][string]$ConnectionString)
    $o = @{}
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, MembershipRule, SetBy, Reason, SetAtUtc FROM eps.GroupRuleOverride')) {
        $o["$($r.Name)"] = @{ rule = "$($r.MembershipRule)"; by = "$($r.SetBy)"; at = $r.SetAtUtc; reason = $(if ($r.Reason -is [DBNull]) { '' } else { "$($r.Reason)" }) }
    }
    $o
}

function Get-EpsManagedGroups {
    <#
      Every group EntraPolicySuite manages, from SQL + the shipped data (no Graph): @{ Method; Groups (ordered name -> def);
      AdminUnits (Target / Pilot / Exclude -> @{ name; description }); InUse (template id -> stage) }.
      def = @{ name; kind (breakglass | sspr | target | pilot | exclude); assignment (Dynamic | Assigned); description; rule;
               processing (On | Paused, dynamic); au (Target | Pilot | Exclude); templates; role; level (assigned pilot 1-3) }
      -Templates adds templates that are not adopted (a deploy); by default: the templates of the adopted policies.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string[]]$Templates = @(), [string]$Method)
    $d = Get-EpsGroupDefaults; $cat = Get-EpsCaTemplateCatalog
    if (-not $PSBoundParameters.ContainsKey('Method')) { $Method = ConvertTo-EpsCaTargetingMethod "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'CA.GroupTargetingMethod' -Default '')" }
    $groups = [ordered]@{}
    $add = { param($def) if ($def.name -and -not $groups.Contains($def.name)) { $groups[$def.name] = $def } elseif ($def.name) { $groups[$def.name].templates = @(@($groups[$def.name].templates) + @($def.templates) | Select-Object -Unique) } }
    # the administrative units: the customer's (v1 import) first, v1's names otherwise
    $aus = [ordered]@{}; foreach ($k in 'Target', 'Pilot', 'Exclude') { $aus[$k] = @{ name = "$($d.adminUnits[$k].name)"; description = "$($d.adminUnits[$k].description)" } }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT DisplayName, Purpose, Description FROM eps.AdminUnit')) { if ($aus.Contains("$($r.Purpose)")) { $aus["$($r.Purpose)"] = @{ name = "$($r.DisplayName)"; description = $(if ($r.Description -is [DBNull]) { '' } else { "$($r.Description)" }) } } }
    # the break-glass group: always, dynamic (E-CM L159-188)
    & $add @{ name = $d.breakGlass.name; kind = 'breakglass'; assignment = 'Dynamic'; description = $d.breakGlass.description; rule = $d.breakGlass.rule; processing = 'On'; au = 'Target'; templates = @(); role = $cat.breakGlassGroupRole }
    # the target groups of the targeting method (E-CM L400-428), the customer's imported definitions first
    $imp = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT DisplayName, VariableName, Assignment, Description, GroupQuery FROM eps.TargetGroup')) { $imp["$($r.Assignment)|$($r.VariableName)"] = $r }
    $kinds = switch -Wildcard ($Method) { 'Dynamic_Using_Tags' { @('Dynamic') } 'Manual_*' { @('Assigned') } default { @() } }
    foreach ($k in $kinds) {
        foreach ($g in @($d.targetGroups[$k])) {
            $i = $imp["$k|$($g.role)"]
            $nv = { param($a, $b) if ($null -ne $a -and $a -isnot [DBNull] -and "$a") { "$a" } else { $b } }
            & $add @{ name = (& $nv $i.DisplayName $g.name); kind = $(if ($g.role -eq $cat.breakGlassGroupRole) { 'breakglass' } elseif ($g.role -eq 'SSPR_All') { 'sspr' } else { 'target' }); assignment = $k
                      description = (& $nv $i.Description $g.description); rule = $(if ($k -eq 'Dynamic') { & $nv $i.GroupQuery $g.rule }); processing = $(if ($k -eq 'Dynamic') { 'On' }); au = 'Target'; templates = @(); role = $g.role }
        }
    }
    # the SSPR registration group (dynamic, v1's locked config) - checked by Get started whatever the method
    $ss = @($d.targetGroups.Dynamic | Where-Object { $_.role -eq 'SSPR_All' })[0]
    if ($ss) { $i = $imp["Dynamic|SSPR_All"]; & $add @{ name = $(if ($i) { "$($i.DisplayName)" } else { $ss.name }); kind = 'sspr'; assignment = 'Dynamic'; description = $ss.description; rule = $(if ($i -and $i.GroupQuery -isnot [DBNull] -and "$($i.GroupQuery)") { "$($i.GroupQuery)" } else { $ss.rule }); processing = 'On'; au = 'Target'; templates = @(); role = 'SSPR_All' } }
    # the per-policy groups of the templates in use (CAnnn.ps1 -Mode Initial_Setup), the dynamic pilot rule by the stage
    $inUse = [ordered]@{}
    $order = @{ Initial = 0; Pilot1 = 1; Pilot2 = 2; Pilot3 = 3; Prod = 4; Custom = 0 }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT a.TemplateId, JSON_VALUE(p.ReviewJson, '$.stage') AS Stage FROM eps.CaAdoption a LEFT JOIN eps.CaPolicy p ON p.PolicyId = a.PolicyId WHERE a.Status = 'Adopted' AND a.TemplateId IS NOT NULL")) {
        $id = "$($r.TemplateId)"; $st = if ($r.Stage -is [DBNull] -or -not "$($r.Stage)") { 'Initial' } else { "$($r.Stage)" }
        if (-not $inUse.Contains($id) -or $order[$st] -gt $order[$inUse[$id]]) { $inUse[$id] = $st }
    }
    foreach ($t in $Templates) { if ($t -and -not $inUse.Contains($t)) { $inUse[$t] = 'Initial' } }
    foreach ($id in $inUse.Keys) {
        $tg = $d.templates[$id]; $lib = $cat.ById[$id]
        if (-not $tg -and -not $lib) { continue }
        $ex = if ($tg.exclude) { $tg.exclude } else { @{ name = "$($lib.groups.exclude)"; description = "Excluded Users for Policy $($lib.name)" } }
        & $add @{ name = $ex.name; kind = 'exclude'; assignment = 'Assigned'; description = $ex.description; au = 'Exclude'; templates = @($id) }
        if ($Method -eq 'Dynamic_Using_Tags') {
            $pd = $tg.pilotDynamic
            $pn = if ($pd) { $pd.name } else { @($lib.groups.pilot.Dynamic_Using_Tags)[0] }
            $sr = if ($pd) { Get-EpsPilotStageRule -Pilot $pd -Stage $inUse[$id] } else { @{ Rule = $null; Processing = 'On'; Stage = $inUse[$id] } }
            & $add @{ name = $pn; kind = 'pilot'; assignment = 'Dynamic'; description = $(if ($pd) { $pd.description } else { "Pilot Users for $pn" }); rule = $sr.Rule; processing = $sr.Processing; stage = $sr.Stage; au = 'Pilot'; templates = @($id) }
        } elseif ($Method -like 'Manual_*') {
            $pa = $tg.pilotAssigned[$Method]
            $names = if ($pa) { @($pa.names) } else { @($lib.groups.pilot[$Method]) }
            for ($l = 0; $l -lt $names.Count; $l++) { & $add @{ name = $names[$l]; kind = 'pilot'; assignment = 'Assigned'; description = $(if ($pa) { $pa.description } else { "Pilot Users for $($names[$l])" }); au = 'Pilot'; templates = @($id); level = $l + 1 } }
        }
    }
    # GROUPS-ACTIONS: a rule the operator set wins over v1's (v1Rule keeps v1's, for "back to v1's rule"); a dynamic pilot
    # group's custom rule is its Pilot1 base, widened for the policy's stage
    $ov = Get-EpsGroupRuleOverrides -ConnectionString $ConnectionString
    foreach ($n in @($ov.Keys)) {
        if (-not $groups.Contains($n) -or $groups[$n].assignment -ne 'Dynamic') { continue }
        $g = $groups[$n]; $g.v1Rule = $g.rule; $g.custom = $true; $g.customBy = $ov[$n].by; $g.customAt = $ov[$n].at; $g.customBase = $ov[$n].rule
        if ($g.kind -eq 'pilot') { $cr = Get-EpsCustomPilotRule -Rule $ov[$n].rule -Stage "$($g.stage)" -ProdProcessing $(if ("$($g.stage)" -eq 'Prod') { "$($g.processing)" } else { 'Paused' }); $g.rule = $cr.Rule; $g.processing = $cr.Processing }
        else { $g.rule = $ov[$n].rule }
    }
    @{ Method = $Method; Groups = $groups; AdminUnits = $aus; InUse = $inUse }
}

function Get-EpsManagedGroupState {
    # what the engine last read (eps.ManagedGroup): name -> row
    param([Parameter(Mandatory)][string]$ConnectionString)
    $s = @{}
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, ObjectId, Found, Dynamic, RuleInTenant, Processing, Members, AdminUnit, Error, CheckedAtUtc FROM eps.ManagedGroup')) { $s["$($r.Name)"] = $r }
    $s
}

function Read-EpsManagedGroupState {
    <#
      ENGINE (Graph GETs only): each named group as it is in the tenant, and the administrative units -> rows for
      eps.ManagedGroup: @{ Name; ObjectId; Found ($true / $false / $null); Dynamic; RuleInTenant; Processing; Members;
      AdminUnit (the AU it is in, by name; $null = not readable); Error }. AU rows are named 'au:<name>'.
    #>
    param([AllowEmptyCollection()][string[]]$Names = @(), $AdminUnits = @{})
    $rows = [ordered]@{}
    $want = @($Names | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $want.Count; $i += 15) {
        $chunk = @($want[$i..([Math]::Min($i + 14, $want.Count - 1))])
        $r = try { @{ Ok = $true; Value = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName in ($((@($chunk) | ForEach-Object { "'$($_.Replace("'", "''"))'" }) -join ','))&`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState" -All) } } catch { @{ Ok = $false; Error = (("$($_.Exception.Message)" -split '->')[-1]).Trim() } }
        foreach ($n in $chunk) {
            if (-not $r.Ok) { $rows[$n] = @{ Name = $n; Found = $null; Error = $r.Error }; continue }
            $hit = @($r.Value | Where-Object { "$($_.displayName)" -ceq $n })
            if ($hit.Count -gt 1) { $rows[$n] = @{ Name = $n; Found = $false; Error = "$($hit.Count) groups have this name" }; continue }
            if (-not $hit.Count) { $rows[$n] = @{ Name = $n; Found = $false }; continue }
            $g = $hit[0]
            $c = try { [int]"$(Invoke-EpsGraph -Path "v1.0/groups/$($g.id)/members/`$count" -Eventual)" } catch { $null }
            $rows[$n] = @{ Name = $n; ObjectId = "$($g.id)"; Found = $true; Dynamic = (@($g.groupTypes) -contains 'DynamicMembership'); RuleInTenant = "$($g.membershipRule)"; Processing = "$($g.membershipRuleProcessingState)"; Members = $c }
        }
    }
    # the administrative units and their group members (AdministrativeUnit.ReadWrite.All; a refusal leaves AdminUnit unknown)
    if (-not @($AdminUnits.Keys).Count) { return @($rows.Values) }
    $auRead = try { @{ Ok = $true; Value = @(Invoke-EpsGraph -Path 'v1.0/directory/administrativeUnits?$select=id,displayName' -All) } } catch { @{ Ok = $false; Error = (("$($_.Exception.Message)" -split '->')[-1]).Trim() } }
    foreach ($k in @($AdminUnits.Keys)) {
        $an = "$($AdminUnits[$k].name)"; if (-not $an) { continue }
        if (-not $auRead.Ok) { $rows["au:$an"] = @{ Name = "au:$an"; Found = $null; Error = $auRead.Error }; continue }
        $au = @($auRead.Value | Where-Object { "$($_.displayName)" -ceq $an })
        if ($au.Count -ne 1) { $rows["au:$an"] = @{ Name = "au:$an"; Found = $false; Error = $(if ($au.Count -gt 1) { "$($au.Count) administrative units have this name" }) }; continue }
        $mem = try { @(Invoke-EpsGraph -Path "v1.0/directory/administrativeUnits/$($au[0].id)/members?`$select=id" -All | ForEach-Object { "$($_.id)".ToLowerInvariant() }) } catch { $null }
        $rows["au:$an"] = @{ Name = "au:$an"; ObjectId = "$($au[0].id)"; Found = $true; Members = $(if ($null -ne $mem) { $mem.Count }) }
        if ($null -ne $mem) { foreach ($x in $rows.Values) { if ($x.ObjectId -and $mem -contains "$($x.ObjectId)".ToLowerInvariant() -and "$($x.Name)" -notlike 'au:*') { $x.AdminUnit = $an } } }
    }
    if ($auRead.Ok) { foreach ($x in $rows.Values) { if ("$($x.Name)" -notlike 'au:*' -and $x.Found -and -not $x.AdminUnit) { $x.AdminUnit = '' } } }
    @($rows.Values)
}

function Save-EpsManagedGroupState {
    # -Replace: the rows replace every stored row (a full read); else each row replaces its own (after a change)
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Rows = @(), [switch]$Replace)
    $json = ConvertTo-Json -InputObject @(@($Rows) | ForEach-Object { [ordered]@{ n = "$($_.Name)"; o = $_.ObjectId; f = $_.Found; d = $_.Dynamic; r = $_.RuleInTenant; p = $_.Processing; m = $_.Members; a = $_.AdminUnit; e = $(if ($_.Error) { "$($_.Error)".Substring(0, [Math]::Min(400, "$($_.Error)".Length)) }) } }) -Compress -Depth 4
    if (-not @($Rows).Count) { $json = '[]' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $json } -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
$(if ($Replace) { 'DELETE FROM eps.ManagedGroup;' } else { "DELETE FROM eps.ManagedGroup WHERE Name IN (SELECT n FROM OPENJSON(@j) WITH (n NVARCHAR(300) '`$.n'));" })
INSERT INTO eps.ManagedGroup (Name, ObjectId, Found, Dynamic, RuleInTenant, Processing, Members, AdminUnit, Error)
SELECT n, o, f, d, r, p, m, a, e FROM OPENJSON(@j) WITH (n NVARCHAR(300) '`$.n', o NVARCHAR(64) '`$.o', f BIT '`$.f', d BIT '`$.d', r NVARCHAR(MAX) '`$.r', p NVARCHAR(20) '`$.p', m INT '`$.m', a NVARCHAR(256) '`$.a', e NVARCHAR(400) '`$.e');
COMMIT;
"@)
}

function Get-EpsGroupOverview {
    <# The Groups page: every managed group with what the engine last read, and what may be done with it (no Graph). #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $m = Get-EpsManagedGroups -ConnectionString $ConnectionString
    $st = Get-EpsManagedGroupState -ConnectionString $ConnectionString
    $nv = { param($v) if ($v -is [DBNull]) { $null } else { $v } }
    $rows = foreach ($g in $m.Groups.Values) {
        $s = $st[$g.name]
        $found = if ($s) { & $nv $s.Found } else { $null }
        $ruleOk = if ($g.assignment -ne 'Dynamic' -or -not $found) { $null } else { (ConvertTo-EpsGroupRuleText (& $nv $s.RuleInTenant)) -eq (ConvertTo-EpsGroupRuleText $g.rule) -and ("$(& $nv $s.Processing)" -eq "$($g.processing)" -or -not "$(& $nv $s.Processing)") }
        $auName = "$($m.AdminUnits[$g.au].name)"; $inAu = if (-not $s -or $null -eq (& $nv $s.AdminUnit)) { $null } else { "$($s.AdminUnit)" -eq $auName }
        [ordered]@{ name = $g.name; kind = $g.kind; assignment = $g.assignment; description = $g.description; rule = $g.rule; processing = $g.processing; templates = @($g.templates); level = $g.level
            inTenant = $(if ($null -eq $found) { 'unknown' } elseif ($found) { 'yes' } else { 'missing' }); members = $(if ($s) { & $nv $s.Members }); ruleInTenant = $(if ($s) { & $nv $s.RuleInTenant }); processingInTenant = $(if ($s) { & $nv $s.Processing })
            ruleOk = $ruleOk; adminUnit = $auName; inAdminUnit = $inAu; error = $(if ($s) { & $nv $s.Error })
            objectId = $(if ($s) { & $nv $s.ObjectId }); stage = $g.stage
            # GROUPS-ACTIONS: the operator's own rule (v1Rule = v1's, for "back to v1's rule")
            custom = [bool]$g.custom; customBase = $g.customBase; v1Rule = $(if ($g.custom) { $g.v1Rule } else { $g.rule }); customBy = $g.customBy; customAt = $g.customAt
            # the actions, offered on every row (owner 2026-11-05 "should i see buttn here like edit ... or create or
            # validate"): not read yet = the engine's plan decides (a group that is there is skipped)
            canCheck = $true
            canCreate = ($found -ne $true -and ($g.assignment -ne 'Dynamic' -or [bool]$g.rule)); canRule = ($found -eq $true -and $g.assignment -eq 'Dynamic' -and $ruleOk -eq $false -and [bool]$g.rule)
            canEditRule = ($found -ne $false -and $g.assignment -eq 'Dynamic')
            canMembers = ($found -ne $false -and $g.assignment -eq 'Assigned' -and $script:EpsGroupMemberKinds -contains $g.kind) }
    }
    $aus = foreach ($k in $m.AdminUnits.Keys) { $s = $st["au:$($m.AdminUnits[$k].name)"]; [ordered]@{ purpose = $k; name = $m.AdminUnits[$k].name; description = $m.AdminUnits[$k].description; inTenant = $(if (-not $s -or $null -eq (& $nv $s.Found)) { 'unknown' } elseif ($s.Found) { 'yes' } else { 'missing' }); error = $(if ($s) { & $nv $s.Error }) } }
    $at = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT MAX(CheckedAtUtc) AS At FROM eps.ManagedGroup')[0].At
    @{ Method = $m.Method; Rows = @($rows); AdminUnits = @($aus); InUse = $m.InUse; CheckedAtUtc = $(if ($at -is [DBNull]) { $null } else { $at }) }
}

function Get-EpsGroupPlan {
    <#
      PURE. What a group action would do, from the definitions and a state (the stored one for the preview, the live one
      in the engine): @{ ok; reason; action; items (@{ name; do (create | rule | add | remove | update | place | skip |
      refused); detail; body }); summary }.
        create      -Names: each missing group, made as v1 makes it (type, rule, description); a group that is there is skipped
        rule        -Names: a dynamic group's rule and processing set to EntraPolicySuite's (v1's -ForceUpdate; the operator's
                    own rule when he set one - GROUPS-ACTIONS)
        editrule    -Names (one dynamic group) -Rule: the operator's own rule, written now and kept as this install's rule
                    for the group (a pilot group's: its Pilot1 base, widened for the policy's stage); -Back: v1's rule
                    again, the custom rule dropped (GROUPS-ACTIONS)
        members     -Names (one) -Add / -Remove (UPNs): an ASSIGNED pilot, exclude or break-glass group only; a break-glass
                    account never leaves the break-glass group
        forceupdate -Template: v1's GroupForceUpdate - the exclude group's description, the dynamic pilot group back to
                    its Pilot1 rule (On); a missing one is created
        au          the administrative units made, and each managed group placed in its unit
      A name EntraPolicySuite does not manage is refused - it never touches another group.
    #>
    param([Parameter(Mandatory)]$Managed, [hashtable]$State = @{}, [Parameter(Mandatory)][string]$Action, [string[]]$Names = @(), [string[]]$Add = @(), [string[]]$Remove = @(),
          [string]$Template, [string[]]$BreakGlassUpns = @(), [string]$Rule, [switch]$Back)
    $items = [System.Collections.Generic.List[object]]::new()
    # an empty list may arrive as one empty value
    $Names = @($Names | Where-Object { "$_".Trim() }); $Add = @($Add | Where-Object { "$_".Trim() }); $Remove = @($Remove | Where-Object { "$_".Trim() })
    $nv = { param($v) if ($v -is [DBNull]) { $null } else { $v } }
    $found = { param($n) $s = $State[$n]; if ($s) { & $nv $s.Found } else { $null } }
    $out = { param($ok, $reason) @{ ok = $ok; reason = $reason; action = $Action; items = @($items); summary = (@($items | Group-Object do | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ') } }
    if ($Action -notin $script:EpsGroupActions) { return & $out $false "action: one of $($script:EpsGroupActions -join ', ')" }
    $body = { param($g) $b = [ordered]@{ displayName = $g.name; description = $g.description; mailEnabled = $false; mailNickname = (Get-EpsGroupMailNickname -Name $g.name); securityEnabled = $true; groupTypes = @() }
        if ($g.assignment -eq 'Dynamic') { $b.groupTypes = @('DynamicMembership'); $b.membershipRule = $g.rule; $b.membershipRuleProcessingState = $(if ($g.processing) { $g.processing } else { 'On' }) }; $b }
    $unknown = @($Names | Where-Object { $_ -and -not $Managed.Groups.Contains($_) })
    if ($unknown.Count) { return & $out $false "not a group Entra Policy Suite manages: $($unknown -join ', ') - it changes no other group" }
    switch ($Action) {
        'create' {
            if (-not @($Names).Count) { return & $out $false 'names: the groups to create' }
            foreach ($n in $Names) {
                $g = $Managed.Groups[$n]; $f = & $found $n
                if ($f -eq $true) { $items.Add(@{ name = $n; do = 'skip'; detail = 'already in the tenant - not changed' }); continue }
                if ($g.assignment -eq 'Dynamic' -and -not $g.rule) { $items.Add(@{ name = $n; do = 'refused'; detail = 'v1 has no membership rule for it - create it by hand' }); continue }
                $items.Add(@{ name = $n; do = 'create'; detail = "$($g.assignment)$(if ($g.rule) { ", rule $($g.rule)$(if ($g.processing -eq 'Paused') { ' (paused - the policy is in Prod)' })" }); administrative unit $($Managed.AdminUnits[$g.au].name)"; body = (& $body $g) })
            }
        }
        'rule' {
            foreach ($n in $Names) {
                $g = $Managed.Groups[$n]; $s = $State[$n]
                if ($g.assignment -ne 'Dynamic') { $items.Add(@{ name = $n; do = 'refused'; detail = 'an assigned group has no rule' }); continue }
                if ((& $found $n) -ne $true) { $items.Add(@{ name = $n; do = 'refused'; detail = 'not in the tenant - create it' }); continue }
                if (-not $g.rule) { $items.Add(@{ name = $n; do = 'refused'; detail = 'v1 has no membership rule for it' }); continue }
                if ((ConvertTo-EpsGroupRuleText (& $nv $s.RuleInTenant)) -eq (ConvertTo-EpsGroupRuleText $g.rule) -and "$(& $nv $s.Processing)" -eq "$($g.processing)") { $items.Add(@{ name = $n; do = 'skip'; detail = 'the rule is already as it should be' }); continue }
                $items.Add(@{ name = $n; do = 'rule'; detail = "now: $(& $nv $s.RuleInTenant) ($(& $nv $s.Processing)); after: $($g.rule) ($($g.processing))"; body = [ordered]@{ membershipRule = $g.rule; membershipRuleProcessingState = $g.processing } })
            }
        }
        'editrule' {
            if (@($Names).Count -ne 1) { return & $out $false 'name: ONE dynamic group' }
            $n = $Names[0]; $g = $Managed.Groups[$n]; $s = $State[$n]
            if ($g.assignment -ne 'Dynamic') { return & $out $false "$n is an assigned group: it has no membership rule (change its members)" }
            if ((& $found $n) -ne $true) { return & $out $false "$n is not in the tenant - create it first" }
            if ($Back) {
                if (-not $g.custom) { return & $out $false "$n has no rule of yours - it already uses v1's rule" }
                $base = $g.v1Rule
                if (-not $base) { return & $out $false "v1 has no membership rule for $n - set your own instead" }
                $pdv = if ($g.kind -eq 'pilot') { (Get-EpsGroupDefaults).templates[@($g.templates)[0]].pilotDynamic }
                $want = if ($pdv) { Get-EpsPilotStageRule -Pilot $pdv -Stage "$($g.stage)" } else { @{ Rule = $base; Processing = 'On' } }
                $items.Add(@{ name = $n; do = 'editrule'; back = $true; detail = "back to v1's rule: $($want.Rule) ($($want.Processing)); your rule is dropped"; body = [ordered]@{ membershipRule = $want.Rule; membershipRuleProcessingState = $want.Processing } })
            } else {
                $new = ConvertTo-EpsGroupRuleText $Rule
                if (-not $new) { return & $out $false 'rule: the membership rule' }
                if ($new.Length -gt $script:EpsGroupRuleMax) { return & $out $false "rule: at most $($script:EpsGroupRuleMax) characters (Microsoft Entra's limit)" }
                if ($new -notmatch '(?i)\b(user|device)\.\w+') { return & $out $false 'rule: a membership rule names user.<property> or device.<property>, e.g. (user.department -eq "Sales")' }
                $want = if ($g.kind -eq 'pilot') { Get-EpsCustomPilotRule -Rule $new -Stage "$($g.stage)" -ProdProcessing $(if ("$($g.stage)" -eq 'Prod') { "$($g.processing)" } else { 'Paused' }) } else { @{ Rule = $new; Processing = 'On' } }
                $note = if ($g.kind -eq 'pilot' -and "$($g.stage)" -in 'Pilot2', 'Pilot3', 'Prod') { $(if ($want.Widened) { " (your rule is the Pilot1 base; the policy is at $($g.stage), so it is widened to $($want.Rule))" } else { " (no `"_pilot1`" clause in it: kept as it is at every stage)" }) } else { '' }
                if ((ConvertTo-EpsGroupRuleText (& $nv $s.RuleInTenant)) -eq (ConvertTo-EpsGroupRuleText $want.Rule) -and "$(& $nv $s.Processing)" -eq $want.Processing -and $g.custom -and (ConvertTo-EpsGroupRuleText $g.customBase) -eq $new) { return & $out $false 'nothing to change: that is already the rule' }
                $items.Add(@{ name = $n; do = 'editrule'; customRule = $new; detail = "now: $(& $nv $s.RuleInTenant) ($(& $nv $s.Processing)); after: $($want.Rule) ($($want.Processing))$note"; body = [ordered]@{ membershipRule = $want.Rule; membershipRuleProcessingState = $want.Processing } })
            }
        }
        'members' {
            if (@($Names).Count -ne 1) { return & $out $false 'name: ONE group' }
            $n = $Names[0]; $g = $Managed.Groups[$n]
            if ($g.assignment -ne 'Assigned' -or $script:EpsGroupMemberKinds -notcontains $g.kind) { return & $out $false "$n is $($g.assignment.ToLower()) ($($g.kind)): only the members of an ASSIGNED pilot, exclude or break-glass group are managed here" }
            if ((& $found $n) -ne $true) { return & $out $false "$n is not in the tenant - create it first" }
            $bad = @(@($Add) + @($Remove) | Where-Object { "$_" -notmatch '^[^@\s]{1,200}@[A-Za-z0-9.-]{3,100}$' })
            if ($bad.Count) { return & $out $false "not a user principal name: $($bad -join ', ')" }
            if (-not (@($Add).Count + @($Remove).Count)) { return & $out $false 'add or remove: at least one user' }
            $bg = @($BreakGlassUpns | ForEach-Object { "$_".ToLowerInvariant() })
            foreach ($u in $Add) { $items.Add(@{ name = $n; do = 'add'; detail = "$u".ToLowerInvariant() }) }
            foreach ($u in $Remove) {
                if ($g.kind -eq 'breakglass' -and $bg -contains "$u".ToLowerInvariant()) { return & $out $false "$u is a break-glass account: it never leaves the break-glass group (every policy excludes that group)" }
                $items.Add(@{ name = $n; do = 'remove'; detail = "$u".ToLowerInvariant() })
            }
        }
        'forceupdate' {
            if (-not $Template) { return & $out $false 'template: the policy''s template (CAnnn)' }
            $mine = @($Managed.Groups.Values | Where-Object { @($_.templates) -contains $Template -and $_.kind -in 'exclude', 'pilot' })
            if (-not $mine.Count) { return & $out $false "$Template is not the template of an adopted policy - adopt the policy first" }
            foreach ($g in $mine) {
                $f = & $found $g.name; $s = $State[$g.name]
                if ($f -ne $true) {
                    if ($g.assignment -eq 'Dynamic' -and -not $g.rule) { $items.Add(@{ name = $g.name; do = 'refused'; detail = 'missing, and v1 has no rule for it' }); continue }
                    $c = $g.Clone(); if ($g.kind -eq 'pilot' -and $g.assignment -eq 'Dynamic') { $c.rule = $(if ($g.custom) { $g.customBase } else { (Get-EpsPilotStageRule -Pilot (Get-EpsGroupDefaults).templates[$Template].pilotDynamic -Stage 'Pilot1').Rule }); $c.processing = 'On' }
                    $items.Add(@{ name = $g.name; do = 'create'; detail = 'missing - made as v1 makes it'; body = (& $body $c) }); continue
                }
                $b = [ordered]@{ description = $g.description }
                if ($g.kind -eq 'pilot' -and $g.assignment -eq 'Dynamic') {
                    # GROUPS-ACTIONS: the operator's own rule is kept - its Pilot1 base is what a force update puts back
                    $pd = (Get-EpsGroupDefaults).templates[$Template].pilotDynamic
                    if (-not $pd -and -not $g.custom) { $items.Add(@{ name = $g.name; do = 'refused'; detail = 'v1 has no rule for it' }); continue }
                    $b.membershipRule = $(if ($g.custom) { $g.customBase } else { (Get-EpsPilotStageRule -Pilot $pd -Stage 'Pilot1').Rule }); $b.membershipRuleProcessingState = 'On'
                }
                $items.Add(@{ name = $g.name; do = 'update'; detail = "description$(if ($b.membershipRule) { "; the rule back to Pilot1: $($b.membershipRule) (On)$(if ($g.stage -and $g.stage -ne 'Pilot1') { " - the policy is at $($g.stage): its pilot group shrinks to the Pilot1 users" })" })"; body = $b })
            }
        }
        'au' {
            foreach ($k in $Managed.AdminUnits.Keys) {
                $a = $Managed.AdminUnits[$k]; $f = & $found "au:$($a.name)"
                if ($null -eq $f) { $items.Add(@{ name = "au:$($a.name)"; do = 'refused'; detail = 'the administrative units could not be read (the engine needs AdministrativeUnit.ReadWrite.All - run the install again)' }); continue }
                if ($f -eq $false) { $items.Add(@{ name = "au:$($a.name)"; do = 'create'; detail = "administrative unit for the $($k.ToLower()) groups"; body = [ordered]@{ displayName = $a.name; description = $a.description } }) }
            }
            foreach ($g in $Managed.Groups.Values) {
                $s = $State[$g.name]
                if ((& $found $g.name) -ne $true) { continue }
                $want = "$($Managed.AdminUnits[$g.au].name)"; $now = & $nv $s.AdminUnit
                if ($null -eq $now) { continue }
                if ("$now" -eq $want) { continue }
                $items.Add(@{ name = $g.name; do = 'place'; detail = "into $want$(if ("$now") { " (it is in $now - left there too)" })"; au = $want })
            }
        }
    }
    $refused = @($items | Where-Object { $_.do -eq 'refused' })
    $todo = @($items | Where-Object { $_.do -notin 'skip', 'refused' })
    & $out ([bool]$todo.Count) $(if (-not $todo.Count) { if ($refused.Count) { ($refused | ForEach-Object { "$($_.name): $($_.detail)" }) -join '; ' } else { 'nothing to change' } })
}
