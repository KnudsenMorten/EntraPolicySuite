# Entra Policy Suite -- SQLADMIN-PERSON-1 (framework, Invardia decision 2026-11-24 for every product): a PERSON who is a
# standing member of the SQL server's admin group is reported on the customer's own Overview page - a COUNT only, never a
# name; report only, nothing is changed. Once a day, in the backup job, as the engine identity (GroupMember.Read.All,
# RoleManagement.Read.Directory, PrivilegedAssignmentSchedule.Read.AzureADGroup - no new right).
#   1. the install's database setup identity, found by its Azure resource id (the managed identity's alternativeNames) -
#      never by a name alone (another install in the tenant may use the same name);
#   2. the groups it is a member of, read from ITS side (memberOf: a role-assignable group's own member list can leave
#      service principals out) - the SQL server's admin group is the one the install puts it in;
#   3. per group: the direct members that are USERS (GET /groups/{id}/members) and the active PIM-for-Groups member
#      assignments of users (assignmentSchedules). Counted: a user who is a direct member or has a STANDING ('assigned')
#      assignment. Not counted: service principals (the install's own identities among them), an eligible-only person (an
#      eligibility is not read at all), and a person who is a member only through a just-in-time ACTIVATION.
# Dot-source EPS-Graph (Invoke-EpsGraph) first; -Graph { param($path) } is the test seam.

Set-StrictMode -Off
$script:EpsSqlAdminPersonsState = 'health.sqladmin-persons'

function Get-EpsSqlAdminPersonCount {
    <# @{ Checked; Count; Groups; Reason } - Checked = $false (with the reason) when the identity or its groups cannot be read. Never throws. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$DbInitName, [scriptblock]$Graph)
    $get = if ($Graph) { $Graph } else { { param($path) @(Invoke-EpsGraph -Path $path -All) } }
    $no = { param($why) @{ Checked = $false; Count = 0; Groups = 0; Reason = "$why" } }
    $type = { param($o) "$($o.'@odata.type')" }
    try {
        $rid = "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$DbInitName".ToLowerInvariant()
        $name = $DbInitName.Replace("'", "''")
        $sp = @(& $get "v1.0/servicePrincipals?`$filter=displayName eq '$name'&`$select=id,alternativeNames" | Where-Object { @($_.alternativeNames | ForEach-Object { "$_".ToLowerInvariant() }) -contains $rid })
        if ($sp.Count -ne 1) { return (& $no "the database setup identity $DbInitName of this install was $(if ($sp.Count) { 'found more than once' } else { 'not found' }) in the directory") }
        $groups = @(& $get "v1.0/servicePrincipals/$($sp[0].id)/memberOf?`$select=id" | Where-Object { (& $type $_) -eq '#microsoft.graph.group' })
        if (-not $groups.Count) { return (& $no "the database setup identity is in no group - nothing to check (the install puts it in the SQL admin group)") }
        $persons = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($g in $groups) {
            $gid = "$($g.id)"
            $direct = @(& $get "v1.0/groups/$gid/members?`$select=id" | Where-Object { (& $type $_) -eq '#microsoft.graph.user' } | ForEach-Object { "$($_.id)" })
            $sched = @(& $get "v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$gid'&`$expand=principal" | Where-Object { "$($_.accessId)" -eq 'member' -and (& $type $_.principal) -eq '#microsoft.graph.user' })
            $standing = @($sched | Where-Object { "$($_.assignmentType)" -ne 'activated' } | ForEach-Object { "$($_.principalId)" })
            $activatedOnly = @($sched | Where-Object { "$($_.assignmentType)" -eq 'activated' } | ForEach-Object { "$($_.principalId)" } | Where-Object { $standing -notcontains $_ })
            foreach ($u in @($direct | Where-Object { $activatedOnly -notcontains $_ }) + $standing) { if ($u) { [void]$persons.Add($u) } }
        }
        @{ Checked = $true; Count = $persons.Count; Groups = $groups.Count; Reason = "$($persons.Count) person(s) with standing membership in $($groups.Count) group(s) of the database setup identity" }
    } catch { return (& $no "the check failed: $((("$($_.Exception.Message)") -split "`n")[0])") }
}

function Save-EpsSqlAdminPersonCount {
    <# The result as ONE eps.UplinkState row (count, groups, when, reason - never a name); the Overview page reads it. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Result, [datetime]$NowUtc = [datetime]::UtcNow)
    $v = [ordered]@{ checked = [bool]$Result.Checked; count = [int]$Result.Count; groups = [int]$Result.Groups; checkedUtc = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); reason = "$($Result.Reason)" } | ConvertTo-Json -Compress
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $script:EpsSqlAdminPersonsState; v = $v } -Query @'
MERGE eps.UplinkState WITH (HOLDLOCK) AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (@n, @v);
'@)
}
