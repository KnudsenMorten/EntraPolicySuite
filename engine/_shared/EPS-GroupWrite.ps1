# EntraPolicySuite -- the ONE place that changes a group or an administrative unit (CA-GROUPS, DESIGN §5.10 "Groups").
#
#   Owner 2026-11-05: "make sure to also include the underlying groups that must be provisioned and managed" (he chose
#   "Yes, Group.ReadWrite.All"); "solution must be min 1:1 on pair with the old eps script solution" (V1-PARITY); and the
#   CA rule that holds for every write: "it is always 100% opeator controlled" - each change only after a SuperAdmin saw
#   the plan and gave a reason; no schedule, job, tick or monitor calls anything here.
#
# Loaded by the ENGINE only (tools/eps-engine/job-entry.ps1): the web app never loads this file. Callers: the routes
# POST /api/groups/{create|rule|members|forceupdate|au} (the engine runs them from the SuperAdmin's signed request) and
# the stage move (Invoke-EpsCaStageMove sets the dynamic pilot group's rule for the stage, as v1's CAnnn.ps1 does).
# tests/Test-EpsGroups.ps1 pins it.

Set-StrictMode -Off

function Invoke-EpsGroupChangeItems {
    # the writes of ONE plan, each read back; returns the items with result / readback
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Managed, [hashtable]$Live = @{}, [scriptblock]$Log = { param($l, $m) })
    $auId = { param($n) $x = $Live["au:$n"]; if ($x -and $x.Found) { "$($x.ObjectId)" } }
    $done = [System.Collections.Generic.List[object]]::new()
    $members = @{}   # group id -> current member ids (lower case)
    foreach ($it in @($Plan.items)) {
        $r = @{ name = $it.name; do = $it.do; detail = $it.detail; result = 'skipped' }
        if ($it.do -in 'skip', 'refused') { $done.Add($r); continue }
        try {
            switch ($it.do) {
                'create' {
                    if ("$($it.name)" -like 'au:*') {
                        [void](Invoke-EpsGraph -Method POST -Path 'v1.0/directory/administrativeUnits' -Body $it.body)
                        $back = @(Invoke-EpsGraph -Path "v1.0/directory/administrativeUnits?`$filter=displayName eq '$("$($it.body.displayName)".Replace("'", "''"))'&`$select=id,displayName" -All)
                        if ($back.Count -ne 1) { throw "read back: $($back.Count) administrative units with this name" }
                        $Live[$it.name] = @{ Name = $it.name; ObjectId = "$($back[0].id)"; Found = $true }
                        $r.result = 'done'; $r.after = @{ id = "$($back[0].id)" }; break
                    }
                    [void](Invoke-EpsGraph -Method POST -Path 'v1.0/groups' -Body $it.body)
                    $back = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$("$($it.name)".Replace("'", "''"))'&`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState" -All)
                    if ($back.Count -ne 1) { throw "read back: $($back.Count) groups with this name" }
                    $g = $back[0]
                    if ($it.body.membershipRule -and (ConvertTo-EpsGroupRuleText "$($g.membershipRule)") -ne (ConvertTo-EpsGroupRuleText $it.body.membershipRule)) { throw "read back: its rule is $($g.membershipRule)" }
                    $r.result = 'done'; $r.after = @{ id = "$($g.id)"; groupTypes = @($g.groupTypes); membershipRule = "$($g.membershipRule)" }
                    # E-CM L1005-1158: a CA group goes into its administrative unit (when the unit is there)
                    $def = $Managed.Groups[$it.name]; $an = "$($Managed.AdminUnits[$def.au].name)"; $aid = & $auId $an
                    if ($aid) {
                        try { [void](Invoke-EpsGraph -Method POST -Path "v1.0/directory/administrativeUnits/$aid/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" }); $r.detail += "; placed in $an" }
                        catch { $r.detail += "; NOT placed in $an ($((("$($_.Exception.Message)") -split '->')[-1].Trim()))" }
                    }
                }
                { $_ -in 'rule', 'update' } {
                    $id = "$($Live[$it.name].ObjectId)"
                    $r.before = @{ membershipRule = "$($Live[$it.name].RuleInTenant)"; membershipRuleProcessingState = "$($Live[$it.name].Processing)" }
                    [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/groups/$id" -Body $it.body)
                    $g = Invoke-EpsGraph -Path "v1.0/groups/$id`?`$select=id,description,membershipRule,membershipRuleProcessingState"
                    if ($it.body.membershipRule -and (ConvertTo-EpsGroupRuleText "$($g.membershipRule)") -ne (ConvertTo-EpsGroupRuleText $it.body.membershipRule)) { throw "read back: its rule is $($g.membershipRule)" }
                    if ($it.body.membershipRuleProcessingState -and "$($g.membershipRuleProcessingState)" -ne $it.body.membershipRuleProcessingState) { throw "read back: its rule processing is $($g.membershipRuleProcessingState)" }
                    $r.result = 'done'; $r.after = @{ membershipRule = "$($g.membershipRule)"; membershipRuleProcessingState = "$($g.membershipRuleProcessingState)"; description = "$($g.description)" }
                }
                { $_ -in 'add', 'remove' } {
                    $id = "$($Live[$it.name].ObjectId)"
                    if (-not $members.ContainsKey($id)) { $members[$id] = @(Invoke-EpsGraph -Path "v1.0/groups/$id/members?`$select=id" -All | ForEach-Object { "$($_.id)".ToLowerInvariant() }) }
                    $u = try { Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString("$($it.detail)"))?`$select=id,userPrincipalName" } catch { $null }
                    if (-not $u) { $r.result = 'failed'; $r.error = "$($it.detail) is not a user in the tenant"; break }
                    $uid = "$($u.id)".ToLowerInvariant(); $isIn = $members[$id] -contains $uid
                    if ($it.do -eq 'add') {
                        if ($isIn) { $r.detail += ' - already a member'; break }
                        [void](Invoke-EpsGraph -Method POST -Path "v1.0/groups/$id/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$uid" })
                    } else {
                        if (-not $isIn) { $r.detail += ' - not a member'; break }
                        [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/groups/$id/members/$uid/`$ref")
                    }
                    $members[$id] = @(Invoke-EpsGraph -Path "v1.0/groups/$id/members?`$select=id" -All | ForEach-Object { "$($_.id)".ToLowerInvariant() })
                    if (($members[$id] -contains $uid) -ne ($it.do -eq 'add')) { throw "read back: $($it.detail) is $(if ($members[$id] -contains $uid) { 'still' } else { 'not' }) a member" }
                    $r.result = 'done'
                }
                'place' {
                    $aid = & $auId $it.au; $gid = "$($Live[$it.name].ObjectId)"
                    if (-not $aid) { $r.result = 'failed'; $r.error = "the administrative unit $($it.au) is not in the tenant"; break }
                    [void](Invoke-EpsGraph -Method POST -Path "v1.0/directory/administrativeUnits/$aid/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$gid" })
                    $r.result = 'done'
                }
            }
        } catch { $r.result = 'failed'; $r.error = (("$($_.Exception.Message)" -split '->')[-1]).Trim(); if ($r.error -match '(?i)403|Authorization_RequestDenied|privilege') { $r.error += ' (the engine needs Group.ReadWrite.All / AdministrativeUnit.ReadWrite.All - run the install again to grant them)' } }
        & $Log $(if ($r.result -eq 'failed') { 'Warning' } else { 'Info' }) "  group $($it.do) $($it.name): $($r.result)$(if ($r.error) { " - $($r.error)" })"
        $done.Add($r)
    }
    , @($done)
}

function Invoke-EpsGroupChange {
    <#
      ONE operator request (the engine runs it from a SuperAdmin's signed request):
        1. the managed groups (SQL) and the groups AS THEY ARE NOW (Graph GET) - the plan is made again from the live state
        2. refused when the plan is (a name EPS does not manage, a break-glass account out of the break-glass group, ...)
        3. the writes, each read back; one journal row per group changed (eps.ConfigChange, Entity Group / AdminUnit)
        4. what was read back stored for the Groups page (eps.ManagedGroup)
      Returns @{ Result = ok | partial | refused | failed; Reason; Items; Text }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Action, [string[]]$Names = @(), [string[]]$Add = @(), [string[]]$Remove = @(),
          [string]$Template, [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $m = Get-EpsManagedGroups -ConnectionString $ConnectionString
    $read = switch ($Action) { 'forceupdate' { @($m.Groups.Values | Where-Object { @($_.templates) -contains $Template } | ForEach-Object name) } 'au' { @($m.Groups.Keys) } default { @($Names | Where-Object { $m.Groups.Contains($_) }) } }
    $live = @{}; foreach ($x in @(Read-EpsManagedGroupState -Names @($read) -AdminUnits $m.AdminUnits)) { $live["$($x.Name)"] = $x }
    $bg = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT UserPrincipalName FROM eps.BreakGlassAccount' | ForEach-Object { "$($_.UserPrincipalName)" })
    $plan = Get-EpsGroupPlan -Managed $m -State $live -Action $Action -Names $Names -Add $Add -Remove $Remove -Template $Template -BreakGlassUpns $bg
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Items = @($plan.items) } }
    & $Log 'Info' "Groups: $Action ($($plan.summary)), requested by $Actor"
    $items = Invoke-EpsGroupChangeItems -Plan $plan -Managed $m -Live $live -Log $Log
    # read back what was touched, store it, journal it
    $touched = @($items | Where-Object { $_.result -eq 'done' -and "$($_.name)" -notlike 'au:*' } | ForEach-Object name | Select-Object -Unique)
    if ($touched.Count -or @($items | Where-Object { "$($_.name)" -like 'au:*' -and $_.result -eq 'done' }).Count) {
        $now = @(Read-EpsManagedGroupState -Names @($touched) -AdminUnits $m.AdminUnits)
        Save-EpsManagedGroupState -ConnectionString $ConnectionString -Rows $now
    }
    foreach ($it in @($items | Where-Object { $_.result -eq 'done' })) {
        $ent = if ("$($it.name)" -like 'au:*') { 'AdminUnit' } else { 'Group' }
        $act = switch ($it.do) { 'create' { 'Create' } default { 'Update' } }
        $p = New-EpsJournalParameters -Actor $Actor -Entity $ent -Key ("$($it.name)" -replace '^au:', '') -Action $act -Before $(if ($it.before) { $it.before | ConvertTo-Json -Compress } else { $null }) -After ([ordered]@{ do = $it.do; detail = $it.detail; after = $it.after; reason = $Reason } | ConvertTo-Json -Compress -Depth 5)
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query (Get-EpsJournalSql))
    }
    $failed = @($items | Where-Object { $_.result -eq 'failed' }); $ok = @($items | Where-Object { $_.result -eq 'done' })
    $res = if (-not $failed.Count) { 'ok' } elseif ($ok.Count) { 'partial' } else { 'failed' }
    @{ Result = $res; Reason = (@($failed | ForEach-Object { "$($_.name): $($_.error)" }) -join '; '); Items = @($items)
       Text = "$($ok.Count) done$(if ($failed.Count) { ", $($failed.Count) failed: $(@($failed | ForEach-Object { "$($_.name) ($($_.error))" }) -join '; ')" })$(if (@($items | Where-Object { $_.do -eq 'skip' }).Count) { ", $(@($items | Where-Object { $_.do -eq 'skip' }).Count) already as they should be" })." }
}

function Set-EpsPilotGroupForStage {
    <#
      P3 (V1-PARITY, CAnnn.ps1 Pilot1 / Pilot2 / Pilot3 / Prod with Dynamic_Using_Tags): before a stage move changes the
      policy, the policy's dynamic pilot group takes the stage's rule (Pilot1 _pilot1; Pilot2 + _pilot2; Pilot3 + _pilot3;
      Prod: the rule paused). Called ONLY by Invoke-EpsCaStageMove. Returns @{ Result = ok | unchanged | n/a | refused |
      failed; Reason; Before; After }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$TemplateId, [Parameter(Mandatory)][string]$To, [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) })
    if ($To -notin 'Pilot1', 'Pilot2', 'Pilot3', 'Prod') { return @{ Result = 'n/a'; Reason = 'no pilot group change for this move' } }
    $method = ConvertTo-EpsCaTargetingMethod "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'CA.GroupTargetingMethod' -Default '')"
    if ($method -ne 'Dynamic_Using_Tags') { return @{ Result = 'n/a'; Reason = 'assigned pilot groups: the policy names the stage''s group' } }
    $pd = (Get-EpsGroupDefaults).templates[$TemplateId].pilotDynamic
    if (-not $pd) { return @{ Result = 'n/a'; Reason = "v1 has no dynamic pilot group for $TemplateId" } }
    $want = Get-EpsPilotStageRule -Pilot $pd -Stage $To
    $live = @(Read-EpsManagedGroupState -Names @($pd.name))[0]
    if ($null -eq $live.Found) { return @{ Result = 'failed'; Reason = "the pilot group $($pd.name) could not be read: $($live.Error)" } }
    if (-not $live.Found) { return @{ Result = 'refused'; Reason = "the pilot group $($pd.name) is not in the tenant - create it on Conditional Access > Groups first" } }
    $before = [ordered]@{ membershipRule = "$($live.RuleInTenant)"; membershipRuleProcessingState = "$($live.Processing)" }
    if ((ConvertTo-EpsGroupRuleText $live.RuleInTenant) -eq (ConvertTo-EpsGroupRuleText $want.Rule) -and "$($live.Processing)" -eq $want.Processing) { return @{ Result = 'unchanged'; Before = $before; After = $before } }
    & $Log 'Info' "  the pilot group $($pd.name) for $To`: $($want.Rule) ($($want.Processing))"
    try {
        [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/groups/$($live.ObjectId)" -Body ([ordered]@{ membershipRule = $want.Rule; membershipRuleProcessingState = $want.Processing }))
        $g = Invoke-EpsGraph -Path "v1.0/groups/$($live.ObjectId)`?`$select=id,membershipRule,membershipRuleProcessingState"
    } catch { return @{ Result = 'failed'; Reason = "the tenant refused the pilot group's rule: $((("$($_.Exception.Message)") -split '->')[-1].Trim())$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Group.ReadWrite.All - run the install again to grant it)' })" } }
    $after = [ordered]@{ membershipRule = "$($g.membershipRule)"; membershipRuleProcessingState = "$($g.membershipRuleProcessingState)" }
    if ((ConvertTo-EpsGroupRuleText $after.membershipRule) -ne (ConvertTo-EpsGroupRuleText $want.Rule) -or $after.membershipRuleProcessingState -ne $want.Processing) { return @{ Result = 'failed'; Reason = "read back, the pilot group's rule is $($after.membershipRule) ($($after.membershipRuleProcessingState))"; Before = $before; After = $after } }
    $p = New-EpsJournalParameters -Actor $Actor -Entity 'Group' -Key $pd.name -Action 'Update' -Before ($before | ConvertTo-Json -Compress) -After ([ordered]@{ do = "stage $To"; after = $after; reason = $Reason } | ConvertTo-Json -Compress -Depth 4)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query (Get-EpsJournalSql))
    Save-EpsManagedGroupState -ConnectionString $ConnectionString -Rows @(@{ Name = $pd.name; ObjectId = $live.ObjectId; Found = $true; Dynamic = $true; RuleInTenant = $after.membershipRule; Processing = $after.membershipRuleProcessingState; Members = $live.Members; AdminUnit = $live.AdminUnit })
    @{ Result = 'ok'; Before = $before; After = $after }
}
