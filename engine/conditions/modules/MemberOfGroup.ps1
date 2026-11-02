# Condition module MemberOfGroup (DESIGN §5.6b kind 2). v1 1:1: a synced user is checked against the AD group's
# recursive user members by UPN (read by the hybrid worker), a cloud user against the Entra group's members by object id.
# The target is the group's display name (AD: its name), as in v1.
@{
    Id          = 'MemberOfGroup'
    ObjectType  = 'User'
    Description = 'the user is a member of the group (AD group for synced users, Entra group for cloud users)'
    Select      = @('id', 'userPrincipalName', 'onPremisesSyncEnabled')
    Needs       = @('EntraGroupMembers', 'AdGroupMembers')
    Validate    = { param($Target) if ([string]::IsNullOrWhiteSpace($Target)) { 'a group name is required' } }
    Evaluate    = {
        param($Object, $Target, $Context)
        $synced = [bool](Get-EpsValue $Object 'onPremisesSyncEnabled')
        if ($synced) {
            if ($null -eq $Context.AdGroupMembers) { return @{ Met = $false; Unavailable = 'AD group membership was not read (no hybrid worker)' } }
            # the worker reads a group on its next cycle after a job first asks for it: until then it is unknown, not "no member"
            if (-not $Context.AdGroupMembers.ContainsKey($Target)) { return @{ Met = $false; Unavailable = "AD group '$Target' has no snapshot from the hybrid worker yet" } }
            $set = $Context.AdGroupMembers[$Target]
            $who = [string](Get-EpsValue $Object 'userPrincipalName')
            $met = [bool]($set -and $who -and $set.Contains($who))
            return @{ Met = $met; Actual = "AD group '$Target' $(if ($set) { "has $($set.Count) user(s)" } else { 'not found' }), user $who $(if ($met) { 'is' } else { 'is not' }) a member" }
        }
        if ($null -eq $Context.EntraGroupMembers) { return @{ Met = $false; Unavailable = 'Entra group membership was not read' } }
        $set = $Context.EntraGroupMembers[$Target]
        $id  = [string](Get-EpsValue $Object 'id')
        $met = [bool]($set -and $id -and $set.Contains($id))
        @{ Met = $met; Actual = "Entra group '$Target' $(if ($set) { "has $($set.Count) member(s)" } else { 'not found' }), user $(if ($met) { 'is' } else { 'is not' }) a member" }
    }
}
