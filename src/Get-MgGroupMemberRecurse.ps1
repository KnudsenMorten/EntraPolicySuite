function Get-MgGroupMemberRecurse 
{
    param(
            [Parameter()]
                [string]$GroupUPN,
            [Parameter()]
                [string]$GroupId
        )
 
    $Members = @()
    
    if ($GroupUPN)
        {
            # find group
            $Group = Get-MgGroup -Filter "startsWith(userPrincipalName, $GroupUPN)"
        }
    ElseIf ($GroupId)
        {
            # find group
            $Group = Get-MgGroup -Filter "id eq '$GroupId'"
        }

        If ($Group)
            {
                $GroupMembers = Get-MgGroupMember -GroupId $Group.Id | select * -ExpandProperty additionalProperties | Select-Object @(
                    'id'
                    @{  Name       = 'userPrincipalName'
                        Expression = { $_.AdditionalProperties["userPrincipalName"] }
                    }
                    @{  Name       = 'type'
                        Expression = { $_.AdditionalProperties["@odata.type"] }
                    }
                )

                If ($GroupMembers)
                    {
                        ForEach ($Member in $GroupMembers)
                            {
                                if ($Member.type -eq "#microsoft.graph.user") {
                                    $Members += $Member
                                }
                                if ($Member.type -eq "#microsoft.graph.group") {
                                    $Members += @(Get-MgGroupMemberRecurse -GroupUPN $_.userPrincipalName)
                                }
                            }
                    }
            }
return $Members
}
