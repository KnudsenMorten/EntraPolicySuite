Function Check-GroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

$MembersCount = 0
    try {
        # Attempt to retrieve the first member of the group
        $members = Get-MgGroupMember -GroupId $GroupId

        if ($members) {
            $MembersCount = $Members.count
            Write-verbose "Group with ID $GroupId has members."
        } else {
            $MembersCount = 0
            Write-verbose "Group with ID $GroupId has no members."
        }
    } catch {
        Write-Error "Error retrieving members for group with ID GroupId: $_"
    }

    Return $MembersCount
}

