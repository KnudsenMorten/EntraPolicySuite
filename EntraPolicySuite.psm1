Function AddGroupMemberOf_GMSA_Group_AD {
    param(
         [Parameter(Mandatory)]
         [string]$GroupMemberOf,

         [Parameter(Mandatory)]
         [string]$GroupName,

         [Parameter(Mandatory)]
         [string]$DomainController
     )

    # Add Members to Group
        Add-ADGroupMember -Identity $GroupMemberOf -Members $GroupName -Server $DomainController
}




Function AddMembers_GMSA_Group_AD {
    param(
         [Parameter(Mandatory)]
         [string]$GroupName,

         [Parameter(Mandatory)]
         [array]$GroupMembers,

         [Parameter(Mandatory)]
         [string]$DomainController
     )

    # Add Members to Group
        ForEach ($Member in $GroupMembers)
            {
                Add-ADGroupMember -Identity $GroupName -Members $Member -Server $DomainController
            }
}




Function BreakGlassValidation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$BreakGlassAccountsGroup,
        [Parameter()]
        [object]$BreakGlassAccounts

    )

    If (!($BreakGlassAccountsGroup))
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is OK !"
            Write-host ""
        }


    If (!($BreakGlassAccounts))
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is OK !"
            Write-host ""
        }
}




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




Function CheckAccountConditions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$User,
        [Parameter(Mandatory)] [string]$Persona,
        [Parameter(Mandatory)] [string]$TagType,
        [Parameter(Mandatory)] [string]$TagValueAD,
        [Parameter(Mandatory)] [string]$TagValueCloud,
        [Parameter(Mandatory)] [string]$ConditionsType,
        [Parameter()] [AllowNull()] [string]$ConditionGroup,
        [Parameter(Mandatory)] [array]$Target,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled,
        [Parameter()] [object]$MailboxInfo,
        [Parameter()] [object]$TeamsRoom
    )

    [boolean]$ConditionMet = $false
    $ModifiedTagValue = $null

    Write-Verbose ""
    Write-Verbose "Checking ..."
    Write-Verbose "ConditionsType   : $($ConditionsType)"
    Write-Verbose "Target           : $($Target)"
    Write-Verbose "ConditionGroup   : $($ConditionGroup)"

    switch ($ConditionsType) {
        "UPN_Like" {
            if ($User.UserPrincipalName -Like "$($Target)") {
                write-verbose $User.UserPrincipalName
                Write-Verbose "UPN_Like $($Target) = true"
                $ConditionMet = $true
            }
        }
        "UPN_NotLike" {
            if ($User.UserPrincipalName -Notlike "$($Target)") {
                write-verbose $User.UserPrincipalName
                Write-Verbose "UPN_NotLike $($Target) = true"
                $ConditionMet = $true
            }
        }
        "MemberOfGroup" {
            If ($User.OnPremisesSyncEnabled) {
                $GroupMembers = $global:AD_Group_Members_HashTable[$Target]
                if ($GroupMembers) {
                    if ($User.UserPrincipalName -in $GroupMembers.Members.UserPrincipalName) {
                        Write-Verbose "MemberOfGroup $($Filter) = true"
                        $ConditionMet = $true
                    }
                }
            } Else {
                $GroupMembers = $global:Entra_Group_Members_HashTable[$Target]
                if ($GroupMembers) {
                    if ($User.Id -in $GroupMembers.members.id) {
                        Write-Verbose "MemberOfGroup $($Filter) = true"
                        $ConditionMet = $true
                    }
                }
            }
            
        }
        "AD_OU_DN_Like" {
            if ($User.OnPremisesDistinguishedName -Like "$($Target)") {
                write-verbose $User.OnPremisesDistinguishedName
                Write-Verbose "AD_OU_DN_Like $($Filter) = true"
                $ConditionMet = $true
            }
        }
        "AD_OU_DN_NotLike" {
            if ( ($User.OnPremisesDistinguishedName -NotLike "$($Target)") -and ($User.OnPremisesDistinguishedName) ) {
                write-verbose $User.OnPremisesDistinguishedName
                Write-Verbose "AD_OU_DN_NotLike $($Filter) = true"
                $ConditionMet = $true
            }
        }
        "OnPremisesSyncEnabled" {
                if ( ($Target -match "TRUE") -and ($User.OnPremisesSyncEnabled) ) {
                    Write-Verbose "OnPremisesSyncEnabled $($Filter) = true"
                    $ConditionMet = $true
                } elseif ( ($Target -match "FALSE") -and (-not $User.OnPremisesSyncEnabled) )  {
                    # Write-Host "NOT OnPremisesSyncEnabled $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "MobilePhone_Like" {
                if ( ($User.MobilePhone -Like "$($Target)") -and ($User.MobilePhone -ne $null) ) {
                    write-verbose $User.MobilePhone
                    Write-Verbose "MobilePhone_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "GivenName_Like" {
                if ( ($User.GivenName -Like "$($Target)") -and ($User.GivenName -ne $null) ) {
                    write-verbose $User.GivenName
                    Write-Verbose "GivenName $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "SurName_Like" {
                if ( ($User.SurName -Like "$($Target)") -and ($User.SurName -ne $null) ) {
                    write-verbose $User.SurName
                    Write-Verbose "SurName_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "UserType_Like" {
                if ( ($User.UserType -Like "$($Target)") -and ($User.UserType -ne $null) ) {
                    write-verbose $User.UserType
                    Write-Verbose "UserType_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "UserType_NotLike" {
                if ( ($User.UserType -NotLike "$($Target)") -and ($User.UserType -ne $null) ) {
                    write-verbose $User.UserType
                    Write-Verbose "UserType_NotLike $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "EmployeeType_Like" {
                if ( ($User.EmployeeType -Like "$($Target)") -and ($User.EmployeeType -ne $null) ) {
                    write-verbose $User.EmployeeType
                    Write-Verbose "EmployeeType_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Teams_Room_Like" {
                if ( ($Target -match "TRUE") -and ($TeamsRoom) ) {
                    Write-Verbose "Teams_Room_Like $($Filter) = true"
                    $ConditionMet = $true
                } elseif ( ($Target -match "FALSE") -and (-not $TeamsRoom) )  {
                    Write-Verbose "Teams_Room_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_Like" {
                if ( ($MailboxInfo.RecipientTypeDetails -Like "$($Target)") -and ($MailBOxInfo.RecipientTypeDetails -ne $null) ) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_NotLike" {
                if ( ($MailboxInfo.RecipientTypeDetails -NotLike "$($Target)") -and ($MailBOxInfo.RecipientTypeDetails -ne $null) ) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_NotLike $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_ModifiedTagValue_Classification" {
                If ($MailboxInfo.RecipientTypeDetails) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_ModifiedTagValue $($Filter) = true"
                    $ConditionMet = $true
                    $ModifiedTagValue = "Exchange_" + $MailboxInfo.RecipientTypeDetails
                }
        }
        "Mailbox_RecipientTypeDetails_ModifiedTagValue_Authentication" {
                If ($MailboxInfo.RecipientTypeDetails) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_ModifiedTagValue $($Filter) = true"
                    $ConditionMet = $true
                    $ModifiedTagValue = "Exchange_" + $MailboxInfo.RecipientTypeDetails + "_NoSignin"
                }
        }
        default {
            Write-Host "Unknown condition type: $ConditionsType"
        }
    }

    # write-host $ConditionMet
    Return $ConditionMet,$ModifiedTagValue
}




Function CheckAccountTagUserAuthentication {
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [object]$User,
            [Parameter()]
                [AllowNull()]
                [array]$Account_StartsWith,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Named,
            [Parameter()]
                [string]$PropertyKeyAD,
            [Parameter()]
                [string]$TagValueAD,
            [Parameter()]
                [string]$PropertyKeyCloud,
            [Parameter()]
                [string]$TagValueCloud,
            [Parameter(mandatory)]
                [AllowNull()]
                [array]$OnPremisesSyncEnabled
         )

If ($Global:FoundAuthentication -eq $False)
    {
        # StartsWith
        If ($Account_StartsWith)
            {
                ForEach ($Classification in $Account_StartsWith)
                    {
                        If ($User.UserPrincipalName -like "$($Classification)*")
                            {
                                $Global:FoundAuthentication = $True
                            }
                    }
            }


        # Contains_And
        If ($Account_Contains_And)
            {
                ForEach ($Classification in $Account_Contains_And)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundAuthentication = $True
                            }
                        Else
                            {
                                $Global:FoundAuthentication = $false
                            }
                    }
            }

        If ($Account_Contains_And_Exclude)
            {
                ForEach ($Classification in $Account_Contains_And_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundAuthentication = $false
                            }
                    }
            }


        # Contains_Or
        If ($Account_Contains_Or)
            {
                ForEach ($Classification in $Account_Contains_Or)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundAuthentication = $True
                            }
                    }
            }

        If ($Account_Contains_Or_Exclude)
            {
                ForEach ($Classification in $Account_Contains_Or_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundAuthentication = $false
                            }
                    }
            }

        # Named
        If ($Account_Named)
            {
                ForEach ($Classification in $Account_Named)
                    {
                        If ($User.UserPrincipalName -eq $Classification)
                            {
                                $Global:FoundAuthentication = $True
                            }
                    }
            }

        If ( ($Global:FoundAuthentication) -and ($User.UserType -ne "Guest") )
            {
                $Global:Type = $null
                $Global:Type = $TagValueCloud

                # Get existing tag-values
                    $ExistingTagValue = $null
                    $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

                # Cloud-only Account (use Microsoft Graph to update)
                If (!($OnPremisesSyncEnabled))
                    {

                        # Modify property, cloud-only user
                            If ($ExistingTagValue -ne $TagValueCloud)
                                {
                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                            Try
                                                {
                                                    Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                                }
                                            Catch
                                                {
                                                    write-host ""
                                                    write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                                    # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                                    # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                                    switch ($PropertyKeyCloud)
                                                        {
                                                            'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        }
                                                }

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }

                                }
                    }

                ElseIf ($OnPremisesSyncEnabled)
                    {
                        # Modify property, AD-synced user
                            If ($ExistingTagValue -ne $TagValueAD)
                                {

                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                            $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                            Try
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                    } Else {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                    }
                                                }
                                            Catch
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                    } Else {
                                                        Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                    }
                                                }
                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"
                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                }                
                    }
            }
    }
}




Function CheckAccountTagUserCAPilot {
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [object]$User,
            [Parameter()]
                [AllowNull()]
                [array]$Account_StartsWith,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Named,
            [Parameter()]
                [AllowNull()]
                [array]$Account_MemberOfGroup,
            [Parameter()]
                [string]$PropertyKeyAD,
            [Parameter()]
                [string]$TagValueAD,
            [Parameter()]
                [string]$PropertyKeyCloud,
            [Parameter()]
                [string]$TagValueCloud,
            [Parameter(mandatory)]
                [AllowNull()]
                [array]$OnPremisesSyncEnabled
         )


If ($Global:FoundCAPilot -eq $False)
    {
        # StartsWith
        If ($Account_StartsWith)
            {
                ForEach ($CAPilot in $Account_StartsWith)
                    {
                        If ($User.UserPrincipalName -like "$($CAPilot)*")
                            {
                                $Global:FoundCAPilot = $True
                            }
                    }
            }


        # Contains_And
        If ($Account_Contains_And)
            {
                ForEach ($CAPilot in $Account_Contains_And)
                    {
                        If ($User.UserPrincipalName -like "$($CAPilot)*")
                            {
                                $Global:FoundCAPilot = $True
                            }
                        Else
                            {
                                $Global:FoundCAPilot = $false
                            }
                    }
            }

        If ($Account_Contains_And_Exclude)
            {
                ForEach ($CAPilot in $Account_Contains_And_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($CAPilot)*")
                            {
                                $Global:FoundCAPilot = $false
                            }
                    }
            }


        # Contains_Or
        If ($Account_Contains_Or)
            {
                ForEach ($CAPilot in $Account_Contains_Or)
                    {
                        If ($User.UserPrincipalName -like "*$($CAPilot)*")
                            {
                                $Global:FoundCAPilot = $True
                            }
                    }
            }

        If ($Account_Contains_Or_Exclude)
            {
                ForEach ($CAPilot in $Account_Contains_Or_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($CAPilot)*")
                            {
                                $Global:FoundCAPilot = $false
                            }
                    }
            }

        # Named
        If ($Account_Named)
            {
                ForEach ($CAPilot in $Account_Named)
                    {
                        If ($User.UserPrincipalName -eq $CAPilot)
                            {
                                $Global:FoundCAPilot = $True
                            }
                    }
            }


        # MemberOf
        If ($Account_MemberOfGroup)
            {
                ForEach ($GroupInfo in $Account_MemberOfGroup)
                    {
                        if ($groupInfo -like "*@*")  # UPN
                            {
                                $GroupMembers = Get-MgGroupMemberRecurse -GroupUPN $GroupInfo
                            }
                        ElseIf ($GroupInfo -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$')  # Object GUID
                            {
                                $GroupMembers = Get-MgGroupMemberRecurse -GroupId $GroupInfo
                            }

                        If ($GroupMembers)
                            {
                                If ($User.UserPrincipalName -in $GroupMembers.userPrincipalName)
                                    {
                                        $Global:FoundCAPilot = $True
                                    }
                            }
                    }
            }

        If ( ($Global:FoundCAPilot) -and ($User.UserType -ne "Guest") )
            {
                # Get existing tag-values
                    $ExistingTagValue = $null
                    $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

                # Cloud-only Account (use Microsoft Graph to update)
                If ($OnPremisesSyncEnabled -eq $null)
                    {
                        # Modify property, cloud-only user
                            If ($ExistingTagValue -ne $TagValueCloud)
                                {
                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                            Try
                                                {
                                                    Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                                }
                                            Catch
                                                {
                                                    write-host ""
                                                    write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                                    # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                                    # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                                    switch ($PropertyKeyCloud)
                                                        {
                                                            'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        }
                                                }

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                }
                    }

                ElseIf ($OnPremisesSyncEnabled)
                    {
                        # Modify property, AD-synced user
                            If ($ExistingTagValue -ne $TagValueAD)
                                {
                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                            $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                            Try
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                    } Else {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                    }
                                                }
                                            Catch
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD     -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials -ErrorAction SilentlyContinue
                                                    } Else {
                                                        Set-ADUser -identity $UserAD     -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -ErrorAction SilentlyContinue
                                                    }
                                                }

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                }                
                    }
            }
    }
}




Function CheckAccountTagUserClassification {
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [object]$User,
            [Parameter()]
                [AllowNull()]
                [array]$Account_StartsWith,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_And_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Contains_Or_Exclude,
            [Parameter()]
                [AllowNull()]
                [array]$Account_Named,
            [Parameter()]
                [string]$PropertyKeyAD,
            [Parameter()]
                [string]$TagValueAD,
            [Parameter()]
                [string]$PropertyKeyCloud,
            [Parameter()]
                [string]$TagValueCloud,
            [Parameter(mandatory)]
                [AllowNull()]
                [array]$OnPremisesSyncEnabled
         )


If ($Global:FoundClassification -eq $False)
    {

        # StartsWith
        If ($Account_StartsWith)
            {
                ForEach ($Classification in $Account_StartsWith)
                    {
                        If ($User.UserPrincipalName -like "$($Classification)*")
                            {
                                $Global:FoundClassification = $True
                            }
                    }
            }


        # Contains_And
        If ($Account_Contains_And)
            {
                ForEach ($Classification in $Account_Contains_And)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundClassification = $True
                            }
                        Else
                            {
                                $Global:FoundClassification = $false
                            }
                    }
            }

        If ($Account_Contains_And_Exclude)
            {
                ForEach ($Classification in $Account_Contains_And_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundClassification = $false
                            }
                    }
            }


        # Contains_Or
        If ($Account_Contains_Or)
            {
                ForEach ($Classification in $Account_Contains_Or)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundClassification = $True
                            }
                    }
            }

        If ($Account_Contains_Or_Exclude)
            {
                ForEach ($Classification in $Account_Contains_Or_Exclude)
                    {
                        If ($User.UserPrincipalName -like "*$($Classification)*")
                            {
                                $Global:FoundClassification = $false
                            }
                    }
            }

        # Named
        If ($Account_Named)
            {
                ForEach ($Classification in $Account_Named)
                    {
                        If ($User.UserPrincipalName -eq $Classification)
                            {
                                $Global:FoundClassification = $True
                            }
                    }
            }

        If ( ($Global:FoundClassification) -and ($User.UserType -ne "Guest") )
            {

                # Get existing tag-values
                    $ExistingTagValue = $null
                    $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

                # Cloud-only Account (use Microsoft Graph to update)
                If (!($OnPremisesSyncEnabled))
                    {

                        # Modify property, cloud-only user
                            If ($ExistingTagValue -ne $TagValueCloud)
                                {

                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                            Try
                                                {
                                                    Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                                }
                                            Catch
                                                {

                                                    write-host ""
                                                    write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                                    # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                                    # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                                    switch ($PropertyKeyCloud)
                                                        {
                                                            'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                            'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        }
                                                }

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                }
                    }

                ElseIf ($OnPremisesSyncEnabled)
                    {
                        # Modify property, AD-synced user
                            If ($ExistingTagValue -ne $TagValueAD)
                                {

                                    If (!($global:EnableWhatIf))
                                        {
                                            write-host ""
                                            write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                            $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                            Try
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                    } Else {
                                                        Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                    }
                                                }
                                            Catch
                                                {
                                                    If ($global:SecureCredentials) {
                                                        Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                    } Else {
                                                        Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                    }
                                                }

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                    Else
                                        {
                                            write-host ""
                                            write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                            ################################################################################
                                            $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                        }

                                            $Result = $Global:ModificationsLog.add($LogEntry) 
                                            ################################################################################
                                        }
                                }                
                    }
            }
    }
}




Function CheckDeviceConditions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$TagType,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValue,
        [Parameter(Mandatory)] [string]$ConditionsType,
        [Parameter()] [AllowNull()] [string]$ConditionGroup,
        [Parameter(Mandatory)] [array]$Target,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    [boolean]$ConditionMet = $false
    $ModifiedTagValue = $null

    Write-Verbose "Checking condition $ConditionsType against device $($Device.DisplayName)..."

    # https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0
    switch ($ConditionsType) {
        "AccountEnabled" {
            if (($Target -eq "TRUE" -and $Device.AccountEnabled) -or ($Target -eq "FALSE" -and -not $Device.AccountEnabled)) {
                Write-Verbose "AccountEnabled matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceCategory_Like" {
            if ($Device.DeviceCategory -Like $Target) {
                Write-Verbose "DeviceCategory matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceCategory_NotLike" {
            if ($Device.DeviceCategory -NotLike $Target) {
                Write-Verbose "DeviceCategory matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceId" {
            if ($Device.DeviceId -eq $Target) {
                Write-Verbose "DeviceId matches $Target"
                $ConditionMet = $true
            }
        }

        # unknown, company, personal
        "DeviceOwnership_Like" {
            if ($Device.DeviceOwnership -like $Target) {
                Write-Verbose "DeviceOwnership matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceOwnership_NotLike" {
            if ($Device.DeviceOwnership -NotLike $Target) {
                Write-Verbose "DeviceOwnership doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "DisplayName_Like" {
            if ($Device.DisplayName -like "$($Target)") {
                Write-Verbose "DisplayName matches $Target"
                $ConditionMet = $true
            }
        }
        "DisplayName_NotLike" {
            if ($Device.DisplayName -Notlike "$($Target)") {
                Write-Verbose "DisplayName doesn't match $Target"
                $ConditionMet = $true
            }
        }

        #Apple Device Enrollment Profile, Device enrollment - Corporate device identifiers, or Windows Autopilot profile name.
        "EnrollmentProfileName_Like" {
            if ($Device.EnrollmentProfileName -Like $Target) {
                Write-Verbose "EnrollmentProfileName matches $Target"
                $ConditionMet = $true
            }
        }
        "EnrollmentProfileName_NotLike" {
            if ($Device.EnrollmentProfileName -NotLike $Target) {
                Write-Verbose "EnrollmentProfileName doesn't match $Target"
                $ConditionMet = $true
            }
        }

        # unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, 
        # windowsBulkAzureDomainJoin, windowsCoManagement, windowsAzureADJoinUsingDeviceAuth,appleUserEnrollment, appleUserEnrollmentWithServiceAccount.
        "EnrollmentType_Like" {
            if ($Device.EnrollmentType -Like $Target) {
                Write-Verbose "EnrollmentType matches $Target"
                $ConditionMet = $true
            }
        }
        "EnrollmentType_NotLike" {
            if ($Device.EnrollmentType -NotLike $Target) {
                Write-Verbose "EnrollmentType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "Id" {
            if ($Device.Id -eq $Target) {
                Write-Verbose "Id matches $Target"
                $ConditionMet = $true
            }
        }
        "IsCompliant" {
            if (($Target -eq "TRUE" -and $Device.IsCompliant) -or ($Target -eq "FALSE" -and -not $Device.IsCompliant)) {
                Write-Verbose "Device compliance matches $Target"
                $ConditionMet = $true
            }
        }
        "IsManaged" {
            if (($Target -eq "TRUE" -and $Device.IsManaged) -or ($Target -eq "FALSE" -and -not $Device.IsManaged)) {
                Write-Verbose "Device management status matches $Target"
                $ConditionMet = $true
            }
        }
        "Manufacturer_Like" {
            if ($Device.Manufacturer -Like $Target) {
                Write-Verbose "Manufacturer matches $Target"
                $ConditionMet = $true
            }
        }
        "Manufacturer_NotLike" {
            if ($Device.Manufacturer -NotLike $Target) {
                Write-Verbose "Manufacturer doesn't match $Target"
                $ConditionMet = $true
            }
        }
        
        # eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, 
        # configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController
        "ManagementType_Like" {
            if ($Device.ManagementType -Like $Target) {
                Write-Verbose "ManagementType matches $Target"
                $ConditionMet = $true
            }
        }
        "ManagementType_NotLike" {
            if ($Device.ManagementType -NotLike $Target) {
                Write-Verbose "ManagementType doesn't match $Target"
                $ConditionMet = $true
            }
        }

        "mdmAppId_Like" {
            if ($Device.mdmAppId -Like $Target) {
                Write-Verbose "mdmAppId matches $Target"
                $ConditionMet = $true
            }
        }
        "mdmAppId_NotLike" {
            if ($Device.mdmAppId -NotLike $Target) {
                Write-Verbose "mdmAppId doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "Model_Like" {
            if ($Device.Model -Like $Target) {
                Write-Verbose "Model matches $Target"
                $ConditionMet = $true
            }
        }
        "Model_NotLike" {
            if ($Device.Model -NotLike $Target) {
                Write-Verbose "Model doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "OnPremisesSyncEnabled" {
            if (($Target -eq "TRUE" -and $Device.OnPremisesSyncEnabled) -or ($Target -eq "FALSE" -and -not $Device.OnPremisesSyncEnabled)) {
                Write-Verbose "OnPremisesSyncEnabled matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystem_Like" {
            if ($Device.OperatingSystem -like "$($Target)") {
                Write-Verbose "OperatingSystem matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystem_NotLike" {
            if ($Device.OperatingSystem -Notlike "$($Target)") {
                Write-Verbose "OperatingSystem doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystemVersion_Like" {
            if ($Device.OperatingSystemVersion -like "$($Target)") {
                Write-Verbose "OperatingSystemVersion matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystemVersion_NotLike" {
            if ($Device.OperatingSystemVersion -Notlike "$($Target)") {
                Write-Verbose "OperatingSystemVersion doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "PhysicalIds_Contains" {
            if ($Device.PhysicalIds -contains $Target) {
                Write-Verbose "PhysicalIDs contains $Target"
                $ConditionMet = $true
            }
        }
        "PhysicalIds_NotContains" {
            if (-not ($Device.PhysicalIds -contains $Target)) {
                Write-Verbose "PhysicalIDs doesn't contain $Target"
                $ConditionMet = $true
            }
        }
        
        # RegisteredDevice (default), SecureVM, Printer, Shared, IoT.
        "ProfileType_Like" {
            if ($Device.ProfileType -Like $Target) {
                Write-Verbose "ProfileType matches $Target"
                $ConditionMet = $true
            }
        }
        "ProfileType_NotLike" {
            if ($Device.ProfileType -NotLike $Target) {
                Write-Verbose "ProfileType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "SystemLabels_Contains" {
            if ($Device.SystemLabels -contains $Target) {
                Write-Verbose "SystemLabels contains $Target"
                $ConditionMet = $true
            }
        }
        "SystemLabels_NotContains" {
            if (-not ($Device.SystemLabels -contains $Target)) {
                Write-Verbose "SystemLabels doesn't contain $Target"
                $ConditionMet = $true
            }
        }
        "TrustType_Like" {
            if ($Device.TrustType -Like $Target) {
                Write-Verbose "TrustType matches $Target"
                $ConditionMet = $true
            }
        }
        "TrustType_NotLike" {
            if ($Device.TrustType -NotLike $Target) {
                Write-Verbose "TrustType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        default {
            Write-Warning "Unknown condition type: $ConditionsType"
        }
    }

    return $ConditionMet, $ModifiedTagValue
}




function ConvertTo-HashTable() {
<#
 .Synopsis
  Convert PSCustomObject to HashTable
 .Description
  Convert PSCustomObject to HashTable
 .Example
  Get-Content "test.json" | ConvertFrom-Json | ConvertTo-HashTable
#>
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)]
        $object,
        [switch] $recurse
    )
    $ht = @{}
    if ($object -is [System.Collections.Specialized.OrderedDictionary] -or $object -is [hashtable]) {
        $object.Keys | ForEach-Object {
            if ($recurse -and ($object."$_" -is [System.Collections.Specialized.OrderedDictionary] -or $object."$_" -is [hashtable] -or $object."$_" -is [PSCustomObject])) {
                $ht[$_] = ConvertTo-HashTable $object."$_" -recurse
            }
            else {
                $ht[$_] = $object."$_"
            }
        }
    }
    elseif ($object -is [PSCustomObject]) {
        $object.PSObject.Properties | ForEach-Object {
            if ($recurse -and ($_.Value -is [System.Collections.Specialized.OrderedDictionary] -or $_.Value -is [hashtable] -or $_.Value -is [PSCustomObject])) {
                $ht[$_.Name] = ConvertTo-HashTable $_.Value -recurse
            }
            else {
                $ht[$_.Name] = $_.Value
            }
        }
    }
    $ht
}




Function Create_GMSA_Account {
    param(
         [Parameter(Mandatory)]
         [string]$AccountName,

         [Parameter(Mandatory)]
         [string]$DNSHostName,

         [Parameter(Mandatory)]
         [string]$AccountDescription,

         [Parameter(Mandatory)]
         [int]$AccountPasswordChangeFrequencyDays,

         [Parameter(Mandatory)]
         [string]$OUPathLDAP,

         [Parameter(Mandatory)]
         [string]$GroupPrincipalsAllowedGroupName,

         [Parameter(Mandatory)]
         [string]$KerberosEncryptionType,

         [Parameter(Mandatory)]
         [string]$DomainController
     )

    # Create GMSA Account
    New-ADServiceAccount -Name $AccountName `
                         -DNSHostName $DNSHostName `
                         -Description $AccountDescription `
                         -DisplayName $AccountDescription `
                         -KerberosEncryptionType $KerberosEncryptionType `
                         -ManagedPasswordIntervalInDays $AccountPasswordChangeFrequencyDays `
                         -PrincipalsAllowedToRetrieveManagedPassword @($GroupPrincipalsAllowedGroupName) `
                         -SamAccountName $AccountName `
                         -Path $OUPathLDAP `
                         -Server $DomainController
                     

    Set-ADServiceAccount -Identity $AccountName -Description $AccountDescription -DisplayName $AccountDescription

    $AccountInfo = Get-ADServiceAccount -Identity $AccountName -Properties *
    write-host $AccountInfo
}




Function Create_GMSA_Group_AD {
    param(
         [Parameter(Mandatory)]
         [string]$GroupName,

         [Parameter(Mandatory)]
         [string]$GroupDescription,


         [Parameter(Mandatory)]
         [string]$Notes,

         [Parameter(Mandatory)]
         [string]$OUPath,

         [Parameter(Mandatory)]
         [string]$DomainController
     )

    # Create Group
        $groupParams = @{
            Name           = $GroupName
            SamAccountName = $GroupName
            DisplayName    = $GroupName
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Description    = $GroupDescription
            Path           = $OUPath
            Server         = $DomainController
        }

        New-ADGroup @groupParams
        Set-ADGroup -Identity $GroupName -Replace @{info="$($Notes)"} -Description $GroupDescription
}




Function Create_GMSA_OU {
    param(
         [Parameter(Mandatory)]
         [string]$OUPathParentLDAP,

         [Parameter(Mandatory)]
         [string]$OUPathName,

         [Parameter(Mandatory)]
         [string]$DomainController
     )

    # Create OU
        New-ADOrganizationalUnit -Name $OUPathName -Path $OUPathParentLDAP -Server $DomainController
}




function EntraAuthenticationStrength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        
        [Parameter()]
        [string]$Description = "",  # Default to an empty string if not provided
        
        [Parameter()]
        [ValidateSet("MFA", "windowsHelloForBusiness", "fido2", "temporaryAccessPassOneTime")]
        [array]$AllowedCombinations,
        
        [Parameter()]
        [string[]]$CombinationConfigurations,
        
        [Parameter()]
        [ValidateSet("custom")]
        [string]$PolicyType,

        [Parameter()]
        [ValidateSet("mfa")]
        [string]$RequirementsSatisfied,

        [Parameter()]
        [switch]$ViewOnly,
        
        [Parameter()]
        [switch]$CreateOnly,
        
        [Parameter()]
        [switch]$ForceUpdate
    )

# Get all existing authentication strength policies
$ExistingPolicies = Get-MgPolicyAuthenticationStrengthPolicy

# Check if the policy already exists
$ExistingPolicy = $ExistingPolicies | Where-Object { $_.displayName -eq $PolicyName }

if ($ViewOnly) {
    return $ExistingPolicy
}

# Building the policy parameters hashtable
    $PolicyParams = @{
        displayName = $PolicyName
    }

    if ($PSBoundParameters.ContainsKey('Description')) {
        $PolicyParams.description = $Description
    }

    if ($PSBoundParameters.ContainsKey('RequirementsSatisfied')) {
        $PolicyParams.requirementsSatisfied = $RequirementsSatisfied
    }

    if ($PSBoundParameters.ContainsKey('AllowedCombinations')) {
        $PolicyParams.allowedCombinations = $AllowedCombinations
    }

    if ($PSBoundParameters.ContainsKey('CombinationConfigurations')) {
        $PolicyParams.combinationConfigurations = $CombinationConfigurations
    }

    if ($ExistingPolicy) {
        if ($ForceUpdate) {
            Write-Host "Updating existing authentication strength policy: $PolicyName"
            Update-MgPolicyAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $ExistingPolicy.id -BodyParameter $PolicyParams
        } else {
            Write-Host "Policy already exists. Use -ForceUpdate to modify it."
        }
    } elseif ($CreateOnly) {
        Write-Host "Creating new authentication strength policy: $PolicyName"
        New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $PolicyParams
    }
}




Function EntraCAPolicy {
#region function parameters

    [CmdletBinding()]
    param(
            [Parameter()]
                [switch]$ViewOnly,
            [Parameter()]
                [switch]$CreateOnly,
            [Parameter()]
                [switch]$CreateUpdate,
            [Parameter()]
                [ValidateSet("enabled","disabled","enabledForReportingButNotEnforced")]
                [string]$State = "Off",
            [Parameter()]
                [string]$CAPolicyPrefix,
            [Parameter()]
                [array]$CAPolicyPrefixArray,
            [Parameter()]
                [string]$DisplayName,

    # applications - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_App_IncludeApplications,      # list, All, Office365, MicrosoftAdminPortals
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_App_ExcludeApplications,    # list, All, Office365, MicrosoftAdminPortals
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_App_ApplicationFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_App_ApplicationFilter_Rule,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("urn:user:registersecurityinfo","urn:user:registerdevice")]
                [string[]]$Cond_App_IncludeUserActions,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("c1","c2","c3","c4","c5","c6","c7","c8","c9","c10","c11","c12","c13","c14","c15","c16","c17","c18","c19","c20","c21","c22","c23","c24","c25")]
                [string[]]$Cond_App_IncludeAuthenticationContextClassReferences,

    # authenticationFlows - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","deviceCodeFlow","authenticationTransfer","unknownFutureValue")]
                [string]$Cond_AuthenticationFlows_TransferMethods,

    # users - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeUsers,    # list, None, All, GuestsOrExternalUsers.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeUsers,    # list, GuestsOrExternalUsers
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeGroups,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeGroups,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeRoles,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeRoles,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
          # "@odata.type": "#microsoft.graph.conditionalAccessGuestsOrExternalUsers",
          # "externalTenants": {
          #   "@odata.type": "microsoft.graph.conditionalAccessExternalTenants"
          #  },
          # "guestOrExternalUserTypes": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","internalGuest","b2bCollaborationGuest","b2bCollaborationMember","b2bDirectConnectUser","otherExternalUser","otherExternalUser","unknownFutureValue")]
                [string[]]$Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes,

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","internalGuest","b2bCollaborationGuest","b2bCollaborationMember","b2bDirectConnectUser","otherExternalUser","otherExternalUser","unknownFutureValue")]
                [string[]]$Cond_Users_ExcludeGuestsOrExternalUsers_GuestOrExternalUserTypes,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
           # "@odata.type": "#microsoft.graph.conditionalAccessExternalTenants",
           # "membershipKind": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind,

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_ExcludeGuestsOrExternalUsers_ExternalTenants_MembershipKind,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessenumeratedexternaltenants?view=graph-rest-beta
           # "@odata.type": "#microsoft.graph.conditionalAccessEnumeratedExternalTenants"
           #  "members": ["String"],
           #  "membershipKind": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_IncludeGuestsOrExternalUsers_EnumeratedExternalTenants_MembershipKind,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeGuestsOrExternalUsers_EnumeratedExternalTenants_Members,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_ExcludeGuestsOrExternalUsers_EnumeratedExternalTenants_MembershipKind,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeGuestsOrExternalUsers_EnumeratedExternalTenants_Members,

    # clientApplications - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
          # "@odata.type": "#microsoft.graph.conditionalAccessClientApplications",
          # "includeServicePrincipals": [
          #  "String"
          # ],
          # "excludeServicePrincipals": [
          #  "String"
          # ],
          # "servicePrincipalFilter": {"@odata.type": "microsoft.graph.conditionalAccessFilter"},


            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_ClientApp_includeServicePrincipals,    # Client applications (service principals and workload identities)
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_ClientApp_excludeServicePrincipals,    # Client applications (service principals and workload identities)
         
         # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessfilter?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_ClientApp_servicePrincipalFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_ClientApp_servicePrincipalFilter_Rule,

    # clientAppTypes - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
    # [ValidateSet("none","all","browser","mobileAppsAndDesktopClients","exchangeActiveSync","other")]

            [Parameter()]
                [AllowEmptyString()]
                [AllowEmptyCollection()]
                [AllowNull()]
                [array]$Cond_ClientAppTypes,

    # devices - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_Devices_DeviceFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_Devices_DeviceFilter_Rule,

    # Locations - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Locations_IncludeLocations,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Locations_ExcludeLocations,

    # platforms - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","all","android","iOS","windows","windowsPhone","macOS","linux","unknownFutureValue")]
                [string[]]$Cond_Platforms_IncludePlatforms,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","all","android","iOS","windows","windowsPhone","macOS","linux","unknownFutureValue")]
                [string[]]$Cond_Platforms_ExcludePlatforms,

    # servicePrincipalRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [string[]]$Cond_servicePrincipalRiskLevels,


    # signInRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","hidden","none","unknownFutureValue")]
                [string[]]$Cond_SignInRiskLevels,

    # UserRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [string[]]$Cond_UserRiskLevels,

    # insiderRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("minor","moderate","elevated","none","unknownFutureValue")]
                [string]$Cond_InsiderRiskLevels,

    # grantControls - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$GC_Operator,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$GC_BuiltInControls,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string[]]$GC_TermsOfUse,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$GC_authenticationStrength,

    # sessionControls - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_Value,   # The number of days or hours
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_AuthenticationType,   # primaryAndSecondaryAuthentication, secondaryAuthentication, unknownFutureValue
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_FrequencyInterval,  # #timeBased, everyTime, unknownFutureValue. Sign-in frequency of everyTime is available for risky users, risky sign-ins, Intune device enrollment, any application, authentication context, and user actions.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_Type,   # days, hours, or null if frequencyInterval is everyTime
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_ContinuousAccessEvaluation_Mode,  # strictEnforcement, disabled, unknownFutureValue, strictLocation.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_ApplicationEnforcedRestrictions_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_DisableResilienceDefaults,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_PersistentBrowser_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_PersistentBrowser_Mode,   # always, never
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SecureSignInSession_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [boolean]$SC_CloudAppSecurity_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_CloudAppSecurity_CloudAppSecurity_Type   # mcasConfigured, monitorOnly, blockDownloads
    )
#endregion

    If ( (-not ($PSBoundParameters.ContainsKey('ViewOnly')) -and (-not ($PSBoundParameters.ContainsKey('CreateUpdate')) )) -and (-not ($PSBoundParameters.ContainsKey('CreateOnly')) ) )
        {
            Write-host "Missing switch. You need to add either -ViewOnly, -CreateOnly or -CreateUpdate"
            Break
        }

    ElseIf ( ($PSBoundParameters.ContainsKey('ViewOnly')) -or ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
        {
            $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
            $ConditionalAccessPolicies_ALL = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

            If ( ($PSBoundParameters.ContainsKey('DisplayName')) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefix')) )
                {
                    write-host "Using CAPolicyPrefix to find policy (scenario 1)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                }
            ElseIf ( (!($PSBoundParameters.ContainsKey('DisplayName'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefix')) -or (!($PSBoundParameters.ContainsKey('CAPolicyPrefixArray'))) )
                {
                    write-host "Using CAPolicyPrefix to find policy (scenario 2)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                }
            ElseIf ( ($PSBoundParameters.ContainsKey('DisplayName')) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefixArray')) )
                {
                    write-host "Using CAPolicyPrefixArray to find policy (scenario 3)"
                    $FoundPol = $false
                    ForEach ($CAPolicyPrefix in $CAPolicyPrefixArray)
                        {
                            If (!($FoundPol))
                                {
                                    $CAPolicyChk = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                                    If ($CAPolicyChk)
                                        {
                                            $FoundPol = $true
                                            $CAPolicy = $CAPolicyChk
                                        }
                                }
                        }
                }
            ElseIf ( (!($PSBoundParameters.ContainsKey('DisplayName'))) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefixArray')) )
                {
                    write-host "Using CAPolicyPrefixArray to find policy (scenario 4)"
                    $FoundPol = $false
                    ForEach ($CAPolicyPrefix in $CAPolicyPrefixArray)
                        {
                            If (!($FoundPol))
                                {
                                    $CAPolicyChk = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                                    If ($CAPolicyChk)
                                        {
                                            $FoundPol = $true
                                            $CAPolicy = $CAPolicyChk
                                        }
                                }
                        }
                }
            ElseIf ( ($PSBoundParameters.ContainsKey('DisplayName')) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefixArray'))) )
                {
                    write-host "Using DisplayName to find policy (scenario 5)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -eq $DisplayName }
                }

            If (!($CAPolicy))
                {
                    write-host ""
                    write-host "Policy not found ... creating new !"
                    $PolicyFound = $false
                    $CAPolicy = [PSCustomObject]@{}
                }
            ElseIf ( ($CAPolicy) -and ($PSBoundParameters.ContainsKey('ViewOnly')) )
                {
                    $PolicyFound = $true
                    $PolicyId = $CAPolicy.Id
                    $PolicyDisplayName = $CAPolicy.DisplayName

                    $CAPolicy | ConvertTo-Json -Depth 20
                }
            ElseIf ( ($CAPolicy) -and ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
                {
                    $PolicyFound = $true
                    $PolicyId = $CAPolicy.Id
                    $PolicyDisplayName = $CAPolicy.DisplayName
                    write-host ""
                    write-host "Existing values (Begin)"
                    write-host ""
                    $CAPolicy | ConvertTo-Json -Depth 20
                    write-host ""
                    write-host "Existing values (End)"
                    write-host ""
                }
        }


    If ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')))
        {
            $CAPolicyAuthStrengthOdata = $CAPolicy.grantControls.'authenticationStrength@odata.context'
            
            # Resetting value to ensure only updated values are applied
            $CAPolicy = [PSCustomObject]@{}

            ###############################################################################
            # displayName
            ###############################################################################

#region displayName
                $InputVariable = $DisplayName
                $ExistingData  = $CAPolicy.displayName
                $FunctionArg   = 'displayName'

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy | add-member -MemberType NoteProperty -Name "displayName" -Value $InputVariable -Force
                    }
#endregion

            ###############################################################################
            # state
            ###############################################################################

#region state
                $InputVariable = $state
                $ExistingData  = $CAPolicy.state
                $FunctionArg   = 'state'

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy | add-member -MemberType NoteProperty -Name "state" -Value $InputVariable -Force
                    }

#endregion
    
            ###############################################################################
            # conditions.applications.IncludeApplications (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeApplications (array)
                $InputVariable = $Cond_App_IncludeApplications
                $ExistingData  = $CAPolicy.conditions.applications.includeApplications
                $FunctionArg   = 'Cond_App_IncludeApplications'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "IncludeApplications" -Value $nestedObject -Force
                            }
                    }
        
                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.includeApplications = $InputVariable
                    }
#endregion

            ###############################################################################
            # conditions.applications.ExcludeApplications (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.ExcludeApplications (array)

                $InputVariable = $Cond_App_ExcludeApplications
                $ExistingData  = $CAPolicy.conditions.applications.excludeApplications
                $FunctionArg   = 'Cond_App_ExcludeApplications'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.ExcludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "ExcludeApplications" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.excludeApplications = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.applications.applicationFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.applicationFilter.mode (value)

                $InputVariable = $Cond_App_ApplicationFilter_Mode
                $ExistingData  = $CAPolicy.conditions.applications.ApplicationFilter
                $FunctionArg   = 'Cond_App_ApplicationFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.applicationFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "applicationFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.applicationFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.applications.applicationFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.applicationFilter.rule (value)

                $InputVariable = $Cond_App_ApplicationFilter_Rule
                $ExistingData  = $CAPolicy.conditions.applications.ApplicationFilter
                $FunctionArg   = 'Cond_App_ApplicationFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "applicationFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.applicationFilter += @{ Rule = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.applications.IncludeUserActions (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeUserActions (array)

                $InputVariable = $Cond_App_IncludeUserActions
                $ExistingData  = $CAPolicy.conditions.applications.IncludeUserActions
                $FunctionArg   = 'Cond_App_IncludeUserActions'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeUserActions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "IncludeUserActions" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.IncludeUserActions = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.applications.IncludeAuthenticationContextClassReferences (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeAuthenticationContextClassReferences (array)

                $InputVariable = $Cond_App_IncludeAuthenticationContextClassReferences
                $ExistingData  = $CAPolicy.conditions.applications.IncludeAuthenticationContextClassReferences
                $FunctionArg   = 'Cond_App_IncludeAuthenticationContextClassReferences'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.includeAuthenticationContextClassReferences.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "includeAuthenticationContextClassReferences" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.includeAuthenticationContextClassReferences = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.authenticationFlows (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-beta
            ###############################################################################

#region conditions.authenticationFlows (value)

                $InputVariable = $Cond_AuthenticationFlows_TransferMethods
                $ExistingData  = $CAPolicy.conditions.AuthenticationFlows
                $FunctionArg   = 'Cond_AuthenticationFlows_TransferMethods'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.authenticationFlows.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "authenticationFlows" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.authenticationFlows += @{ transferMethods = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.includeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeUsers (array)

                $InputVariable = $Cond_Users_IncludeUsers
                $ExistingData  = $CAPolicy.conditions.users.includeUsers
                $FunctionArg   = 'Cond_Users_IncludeUsers'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.includeusers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "includeUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeUsers = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeUsers (array)
 
                $InputVariable = $Cond_Users_excludeUsers
                $ExistingData  = $CAPolicy.conditions.users.excludeUsers
                $FunctionArg   = 'Cond_Users_ExcludeUsers'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.excludeusers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeUsers = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeUsers (array)

                $InputVariable = $Cond_Users_IncludeGroups
                $ExistingData  = $CAPolicy.conditions.users.includegroups
                $FunctionArg   = 'Cond_Users_IncludeGroups'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGroups.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeGroups" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGroups = $InputVariable
                    }


#endregion

            ###############################################################################
            # conditions.users.excludeGroups (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGroups (array)

                $InputVariable = $Cond_Users_excludeGroups
                $ExistingData  = $CAPolicy.conditions.users.excludegroups
                $FunctionArg   = 'Cond_Users_ExcludeGroups'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGroups.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGroups" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGroups = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeRoles (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeRoles (array)

                $InputVariable = $Cond_Users_IncludeRoles
                $ExistingData  = $CAPolicy.conditions.users.includeroles
                $FunctionArg   = 'Cond_Users_IncludeRoles'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeRoles.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeRoles" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeRoles = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeRoles (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeRoles (array)

                $InputVariable = $Cond_Users_excludeRoles
                $ExistingData  = $CAPolicy.conditions.users.excluderoles
                $FunctionArg   = 'Cond_Users_ExcludeRoles'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeRoles.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeRoles" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeRoles = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
            ###############################################################################


#region conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes (value)

                $InputVariable = $Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes
                $ExistingData  = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers
                $FunctionArg   = 'Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.includeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "includeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGuestsOrExternalUsers += @{ guestOrExternalUserTypes = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.includeGuestsOrExternalUsers.externalTenants.membershipKind (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeGuestsOrExternalUsers.externalTenants.membershipKind (value)

                $InputVariable = $Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind
                $ExistingData  = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.ExternalTenants
                $FunctionArg   = 'Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.externalTenants.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers | add-member -MemberType NoteProperty -Name "externalTenants" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGuestsOrExternalUsers.externalTenants += @{ 
                                                                                                        '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
                                                                                                        membershipKind = $InputVariable
                                                                                                    }
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes (value)

                $InputVariable = $Cond_Users_excludeGuestsOrExternalUsers_GuestOrExternalUserTypes
                $ExistingData  = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers
                $FunctionArg   = 'Cond_Users_excludeGuestsOrExternalUsers_GuestOrExternalUserTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGuestsOrExternalUsers += @{ guestOrExternalUserTypes = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind (value)

                $InputVariable = $Cond_Users_excludeGuestsOrExternalUsers_ExternalTenants_MembershipKind
                $ExistingData  = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.ExternalTenants
                $FunctionArg   = 'Cond_Users_excludeGuestsOrExternalUsers_ExternalTenants_MembershipKind'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.externalTenants.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers | add-member -MemberType NoteProperty -Name "externalTenants" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGuestsOrExternalUsers.externalTenants += @{ 
                                                                                                        '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
                                                                                                        membershipKind = $InputVariable
                                                                                                   }
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.includeServicePrincipals (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################


#region conditions.clientApplications.includeServicePrincipals (array)

                $InputVariable = $Cond_ClientApp_includeServicePrincipals
                $ExistingData  = $CAPolicy.conditions.ClientApplications.includeServicePrincipals
                $FunctionArg   = 'Cond_ClientApp_includeServicePrincipals'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.includeServicePrincipals.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "includeServicePrincipals" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.includeServicePrincipals = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.excludeServicePrincipals (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.excludeServicePrincipals (array)

                $InputVariable = $Cond_ClientApp_excludeServicePrincipals
                $ExistingData  = $CAPolicy.conditions.ClientApplications.excludeServicePrincipals
                $FunctionArg   = 'Cond_ClientApp_ExcludeServicePrincipals'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.ExcludeServicePrincipals.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "ExcludeServicePrincipals" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.excludeServicePrincipals = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.servicePrincipalFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.servicePrincipalFilter.mode (value)

                $InputVariable = $Cond_ClientApp_servicePrincipalFilter_Mode
                $ExistingData  = $CAPolicy.conditions.ClientApplications.servicePrincipalFilter
                $FunctionArg   = 'Cond_ClientApp_servicePrincipalFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.servicePrincipalFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "servicePrincipalFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.servicePrincipalFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.servicePrincipalFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.servicePrincipalFilter.rule (value)

                $InputVariable = $Cond_ClientApp_servicePrincipalFilter_Rule
                $ExistingData  = $CAPolicy.conditions.ClientApplications.servicePrincipalFilter
                $FunctionArg   = 'Cond_ClientApp_servicePrincipalFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.servicePrincipalFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "servicePrincipalFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.servicePrincipalFilter += @{ rule = $InputVariable }
                    }
#endregion

            ###############################################################################
            # conditions.clientAppTypes (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            # Possible values are: all, browser, mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other
            ###############################################################################

#region conditions.clientAppTypes (array)

                $InputVariable = $Cond_ClientAppTypes
                $ExistingData  = $CAPolicy.conditions.ClientAppTypes
                $FunctionArg   = 'Cond_ClientAppTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientAppTypes.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientAppTypes" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientAppTypes = $InputVariable
                    }

#endregion


            ###############################################################################
            # conditions.devices.deviceFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.deviceFilter.mode (value)

                $InputVariable = $Cond_Devices_DeviceFilter_Mode
                $ExistingData  = $CAPolicy.conditions.Devices.DeviceFilter
                $FunctionArg   = 'Cond_Devices_DeviceFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.deviceFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "deviceFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.deviceFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.devices.deviceFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.deviceFilter.rule (value)

                $InputVariable = $Cond_Devices_DeviceFilter_Rule
                $ExistingData  = $CAPolicy.conditions.Devices.DeviceFilter
                $FunctionArg   = 'Cond_Devices_DeviceFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.deviceFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "deviceFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.deviceFilter += @{ rule = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.locations.IncludeLocations (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            ###############################################################################

#region conditions.locations.IncludeLocations (array)
                $InputVariable = $Cond_Locations_IncludeLocations
                $ExistingData  = $CAPolicy.conditions.Locations.IncludeLocations
                $FunctionArg   = 'Cond_Locations_IncludeLocations'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Locations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "Locations" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.locations.IncludeLocations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.locations | add-member -MemberType NoteProperty -Name "IncludeLocations" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.locations.IncludeLocations = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.locations.excludeLocations (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            ###############################################################################

#region conditions.locations.excludeLocations (array)

                $InputVariable = $Cond_Locations_excludeLocations
                $ExistingData  = $CAPolicy.conditions.Locations.excludeLocations
                $FunctionArg   = 'Cond_Locations_excludeLocations'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Locations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "Locations" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.locations.ExcludeLocations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.locations | add-member -MemberType NoteProperty -Name "ExcludeLocations" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.locations.excludeLocations = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.platforms.includePlatforms (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta
            ###############################################################################

#region conditions.platforms.includePlatforms (array)

                $InputVariable = $Cond_Platforms_IncludePlatforms
                $ExistingData  = $CAPolicy.conditions.platforms.includePlatforms
                $FunctionArg   = 'Cond_Platforms_IncludePlatforms'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Platforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "platforms" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.IncludePlatforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.platforms | add-member -MemberType NoteProperty -Name "IncludePlatforms" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.platforms.includePlatforms = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.platforms.excludePlatforms (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta
            ###############################################################################

#region conditions.platforms.excludePlatforms (array)

                $InputVariable = $Cond_Platforms_excludePlatforms
                $ExistingData  = $CAPolicy.conditions.platforms.excludePlatforms
                $FunctionArg   = 'Cond_Platforms_excludePlatforms'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "platforms" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.ExcludePlatforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.platforms | add-member -MemberType NoteProperty -Name "ExcludePlatforms" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.platforms.excludePlatforms = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.servicePrincipalRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.servicePrincipalRiskLevels (array)

                $InputVariable = $Cond_servicePrincipalRiskLevels
                $ExistingData  = $CAPolicy.conditions.servicePrincipalRiskLevels
                $FunctionArg   = 'Cond_servicePrincipalRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.servicePrincipalRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "servicePrincipalRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.servicePrincipalRiskLevels = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.signInRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.signInRiskLevels (array)

                $InputVariable = $Cond_signInRiskLevels
                $ExistingData  = $CAPolicy.conditions.signInRiskLevels
                $FunctionArg   = 'Cond_signInRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.signInRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "signInRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.signInRiskLevels = $InputVariable
                    }


#endregion

            ###############################################################################
            # conditions.UserRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.UserRiskLevels (array)

                $InputVariable = $Cond_UserRiskLevels
                $ExistingData  = $CAPolicy.conditions.UserRiskLevels
                $FunctionArg   = 'Cond_UserRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.UserRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "UserRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.UserRiskLevels = $InputVariable
                    }
#endregion

            ###############################################################################
            # conditions.insiderRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.insiderRiskLevels (array)

                $InputVariable = $Cond_insiderRiskLevels
                $ExistingData  = $CAPolicy.conditions.insiderRiskLevels
                $FunctionArg   = 'Cond_insiderRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.insiderRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "insiderRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.insiderRiskLevels = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.operator (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            ###############################################################################

#region grantControls.operator (value)

                $InputVariable = $GC_operator
                $ExistingData  = $CAPolicy.grantControls
                $FunctionArg   = 'GC_operator'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls = @{ operator = $InputVariable }
                    }

#endregion

            ###############################################################################
            # grantControls.builtInControls (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            # Possible values: AND, OR
            ###############################################################################

#region grantControls.builtInControls (array)

                $InputVariable = $GC_builtInControls
                $ExistingData  = $CAPolicy.grantControls
                $FunctionArg   = 'GC_builtInControls'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.builtInControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "builtInControls" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls.builtInControls = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.termsOfUse (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            # Possible values: block, mfa, compliantDevice, domainJoinedDevice, approvedApplication, compliantApplication, passwordChange, unknownFutureValue
            ###############################################################################

#region grantControls.termsOfUse (array)

                $InputVariable = $GC_termsOfUse
                $ExistingData  = $CAPolicy.grantControls.termsOfUse
                $FunctionArg   = 'GC_termsOfUse'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.termsOfUse.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "termsOfUse" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls.termsOfUse = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.authenticationStrength (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            ###############################################################################

#region grantControls.authenticationStrength (array)

                $InputVariable = $GC_authenticationStrength
                $ExistingData  = $CAPolicy.grantControls.authenticationStrength
                $FunctionArg   = 'GC_authenticationStrength'


                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.authenticationStrength.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "authenticationStrength" -Value $NestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        If ($InputVariable)
                            {
                                $AuthenticationStrengths = Get-MgPolicyAuthenticationStrengthPolicy
    
                                $authStrengthPolicy = $AuthenticationStrengths | Where-Object { ( ($_.DisplayName -eq "$($InputVariable)") -or ($_.DisplayName -like "*$($InputVariable)*") -or ($_.Id -eq "$($InputVariable)") ) }

                                If ($authStrengthPolicy)
                                    {
                                        $authStrengthPolicyid = $authStrengthPolicy.id

                                        $CAPolicy.grantControls += @{
                                                                        'authenticationStrength@odata.context' = $CAPolicyAuthStrengthOdata
                                                                        authenticationStrength = @{ 
                                                                                                    id = $authStrengthPolicyId
                                                                                                  }
                                                                    }
                                    }
                            }
                        Else
                            {
                                write-host "AuthenticationStrength is being set to null"
                                $NullAuthStrength = [PSCustomObject]@{}
                    
                                $NestedObject = [PSCustomObject]@{}
                                $NullAuthStrength | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                    
                                $NullAuthStrength.grantControls | add-member -MemberType NoteProperty -Name "authenticationStrength" -Value $null -Force
                                $NullAuthStrengthHash = ConvertTo-Hashtable $NullAuthStrength -recurse

                                $Result = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($PolicyId)" -Body $NullAuthStrengthHash
                            }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.Value (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.Value (value)

                $InputVariable = $SC_SignInFrequency_Value
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.value
                $FunctionArg   = 'SC_SignInFrequency_Value'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ value = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.AuthenticationType (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.AuthenticationType (value)

                $InputVariable = $SC_SignInFrequency_AuthenticationType
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.AuthenticationType
                $FunctionArg   = 'SC_SignInFrequency_AuthenticationType'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ AuthenticationType = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.Type (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.Type (value)

                $InputVariable = $SC_SignInFrequency_Type
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.Type
                $FunctionArg   = 'SC_SignInFrequency_Type'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ Type = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.isEnabled (value)

                $InputVariable = $SC_SignInFrequency_IsEnabled
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.IsEnabled
                $FunctionArg   = 'SC_SignInFrequency_IsEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ isEnabled = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.FrequencyInterval (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.FrequencyInterval (value)

                $InputVariable = $SC_SignInFrequency_frequencyInterval
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.frequencyInterval
                $FunctionArg   = 'SC_SignInFrequency_frequencyInterval'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ frequencyInterval = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.persistentBrowser.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.persistentBrowser.isEnabled (value)

                $InputVariable = $SC_persistentBrowser_IsEnabled
                $ExistingData  = $CAPolicy.sessionControls.persistentBrowser.isEnabled
                $FunctionArg   = 'SC_persistentBrowser_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.persistentBrowser.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "persistentBrowser" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.persistentBrowser += @{ IsEnabled = $InputVariable }
                    }
#endregion

            ###############################################################################
            # sessionControls.persistentBrowser.Mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            # Possible values are: always, never
            ###############################################################################

#region sessionControls.persistentBrowser.Mode (value)

                $InputVariable = $SC_persistentBrowser_Mode
                $ExistingData  = $CAPolicy.sessionControls.persistentBrowser.Mode
                $FunctionArg   = 'SC_persistentBrowser_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.persistentBrowser.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "persistentBrowser" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.persistentBrowser += @{ Mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.disableResilienceDefaults (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.disableResilienceDefaults (value)

                $InputVariable = $SC_disableResilienceDefaults
                $ExistingData  = $CAPolicy.sessionControls.disableResilienceDefaults
                $FunctionArg   = 'SC_disableResilienceDefaults'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls += @{ disableResilienceDefaults = $InputVariable }
                    }
#endregion

            ###############################################################################
            # sessionControls.continuousAccessEvaluation.Mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.continuousAccessEvaluation.Mode (value)

                $InputVariable = $SC_continuousAccessEvaluation_Mode
                $ExistingData  = $CAPolicy.sessionControls.continuousAccessEvaluation.Mode
                $FunctionArg   = 'SC_continuousAccessEvaluation_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.continuousAccessEvaluation.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "continuousAccessEvaluation" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.continuousAccessEvaluation = @{ Mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.cloudAppSecurity.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.cloudAppSecurity.isEnabled (value)

                $InputVariable = $SC_cloudAppSecurity_isEnabled
                $ExistingData  = $CAPolicy.sessionControls.cloudAppSecurity.isEnabled
                $FunctionArg   = 'SC_cloudAppSecurity_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.cloudAppSecurity.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "cloudAppSecurity" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.cloudAppSecurity += @{ IsEnabled = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.cloudAppSecurity.cloudAppSecurityType (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.cloudAppSecurity.cloudAppSecurityType (value)

                $InputVariable = $SC_CloudAppSecurity_CloudAppSecurity_Type
                $ExistingData  = $CAPolicy.sessionControls.cloudAppSecurity.cloudAppSecurityType
                $FunctionArg   = 'SC_CloudAppSecurity_CloudAppSecurity_Type'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.cloudAppSecurity.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "cloudAppSecurity" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.cloudAppSecurity += @{ cloudAppSecurityType = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.applicationEnforcedRestrictions.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/applicationenforcedrestrictionssessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.applicationEnforcedRestrictions.isEnabled (value)

                $InputVariable = $SC_applicationEnforcedRestrictions_isEnabled
                $ExistingData  = $CAPolicy.sessionControls.applicationEnforcedRestrictions.isEnabled
                $FunctionArg   = 'SC_applicationEnforcedRestrictions_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.applicationEnforcedRestrictions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "applicationEnforcedRestrictions" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.applicationEnforcedRestrictions += @{ isEnabled = $InputVariable }
                    }
#endregion

            #--------------------------------------------------------------------------------------------------------------------
            $CAPolicyNew = $CAPolicy

            write-host ""
            write-host "New values (Begin)"
            write-host ""
            $CAPolicyNew | ConvertTo-Json -Depth 20
            write-host ""
            write-host "New values (End)"
            write-host ""

            $CAPolicyNewHash = ConvertTo-Hashtable $CAPolicyNew -recurse

            if ( ($PolicyFound) -and ($PSBoundParameters.ContainsKey('CreateUpdate')) )
                {
                    Try
                        {
                            write-host ""
                            write-host "Updating existing CA policy ( $($PolicyDisplayName) ) "
                            Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -BodyParameter $CAPolicyNewHash
                        }
                    Catch
                        {
                            $_
                        }
                }
            ElseIf ( (!($PolicyFound)) -and ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly'))) )
                {
                    Try
                        {
                            write-host ""
                            write-host "Creating new CA policy"
                            New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $CAPolicyNewHash
                        }
                    Catch
                        {
                            $_
                        }
                }
        }

    # Return
    If ($PSBoundParameters.ContainsKey('ViewOnly'))
        {
            If ($CAPolicy)
                {
                    Return $CAPolicy
                }
        }
    ElseIf ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
        {
            If ($CAPolicyNew)
                {
                    Return $CAPolicyNew
                }
        }
}




Function EntraGroup {
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$EntraGroupsHashTable,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Description,
        [Parameter()]
        [ValidateSet("Assigned", "DynamicMembership")]
        [string]$GroupType,
        [Parameter()]
        [switch]$AutomaticMailNickname,
        [Parameter()]
        [string]$MailNickname,
        [Parameter()]
        [string]$GroupQuery,
        [Parameter()]
        [boolean]$MailEnabled,
        [Parameter()]
        [boolean]$SecurityEnabled,
        [Parameter()]
        [string]$AdministrativeUnitPlacement,
        [Parameter()]
        [ValidateSet("On", "Paused")]
        [string]$MembershipRuleProcessingState,
        [Parameter()]
        [switch]$CreateOnly,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Retrieve all Entra Groups and populate hash table if not provided
    if (-not $EntraGroupsHashTable) {
        $EntraGroupsHashTable = [ordered]@{}
        Get-MgGroup -All | ForEach-Object { $EntraGroupsHashTable[$_.DisplayName] = $_ }
    }

    if ($EntraGroupsHashTable.Count -eq 0) {
        Write-host ""
        Write-Host "No Entra Groups found."
        Write-host ""
        return
    }

    # Build hash for group properties
    $CmdToRun_Hash = @{}
    if ($PSBoundParameters.ContainsKey('Description')) { $CmdToRun_Hash['description'] = $Description }
    if ($PSBoundParameters.ContainsKey('DisplayName')) { $CmdToRun_Hash['displayName'] = $DisplayName }
    if ($GroupType -eq "DynamicMembership") { $CmdToRun_Hash['GroupType'] = $GroupType }
    if ($PSBoundParameters.ContainsKey('GroupQuery')) { $CmdToRun_Hash['MembershipRule'] = $GroupQuery }
    if ($PSBoundParameters.ContainsKey('MailEnabled')) { $CmdToRun_Hash['MailEnabled'] = $MailEnabled }
    if ($PSBoundParameters.ContainsKey('SecurityEnabled')) { $CmdToRun_Hash['SecurityEnabled'] = $SecurityEnabled }
    if ($PSBoundParameters.ContainsKey('MembershipRuleProcessingState')) { $CmdToRun_Hash['membershipRuleProcessingState'] = $MembershipRuleProcessingState }

    # Handle MailNickname
    if ($PSBoundParameters.ContainsKey('MailNickname') -and -not $AutomaticMailNickname) {
        $MailNickname = $MailNickname.Replace(" ", "")
        if ($MailNickname.Length -gt 64) {
            $MailNickname = $MailNickname.Substring(0, 50) + (Get-Random -Minimum 100000 -Maximum 10000000)
        }
        $CmdToRun_Hash['MailNickname'] = $MailNickname
    }

    if ($AutomaticMailNickname) {
        $MailNickname = $DisplayName.Replace(" ", "")
        if ($MailNickname.Length -gt 64) {
            $MailNickname = $MailNickname.Substring(0, 50) + (Get-Random -Minimum 100000 -Maximum 10000000)
        }
        $CmdToRun_Hash['MailNickname'] = $MailNickname
    }

    # Check if group exists and handle accordingly
    if ($EntraGroupsHashTable.ContainsKey($DisplayName)) {
        $GroupExist = $EntraGroupsHashTable[$DisplayName]

        if ($PSBoundParameters.ContainsKey('ForceUpdate')) {
            $CmdToRun_Hash['GroupId'] = $GroupExist.Id
            Write-host "----------------------------"
            Write-Host "Updating group: $DisplayName"
            Write-host ""
            try {
                $Result = Update-MgGroup @CmdToRun_Hash
            } catch {
                $Result = New-MgGroup @CmdToRun_Hash
            }
        } else {
            Write-host "----------------------------"
            Write-Host "Group already exists: $DisplayName"
            Write-host ""
            $Result = $GroupExist
        }
    } elseif ( ($PSBoundParameters.ContainsKey('CreateOnly')) -or (-not ($EntraGroupsHashTable.ContainsKey($DisplayName)))) {
        Write-host "----------------------------"
        Write-Host "Creating group: $DisplayName"
        Write-host ""
        try {
            $Result = New-MgGroup @CmdToRun_Hash
            Write-host ""
            Write-Host "Group created successfully."
            Write-host ""
        } catch {
            Write-host ""
            Write-Host "Error creating group: $_"
            Write-host ""
        }
    } else {
        Write-host ""
        Write-Host "Group does not exist. Use -Create to create a new group."
        Write-host ""
        return
    }

    # Perform a final check to ensure the group was created/updated correctly
    Write-host ""
    Write-Host "Verifying the group with DisplayName: $DisplayName"
    Write-host ""
    $finalCheckGroups = Get-MgGroup -Filter "displayName eq '$DisplayName'"

    # Check for multiple records
    if ($finalCheckGroups.Count -gt 1) {
        throw "More than one group found with DisplayName: $DisplayName"
        break
    }

    # Return the result of the final check
    Write-host ""
    return $finalCheckGroups
}




Function EntraGroupsAsHashtable {
    $Entra_ID_Groups_ALL = Get-MgGroup -All

    # order Groups into hash
    $EntraGroupsHashTable = [ordered]@{}
    $Entra_ID_Groups_ALL | ForEach-Object { $EntraGroupsHashTable.add($_.DisplayName,$_) }
    Return $EntraGroupsHashTable
}




Function EntraNamedLocation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$DisplayName,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$ip4Range,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$ip6Range,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$countriesAndRegions,
        [Parameter()]
        [switch]$countryNamedLocation,
        [Parameter()]
        [switch]$ipNamedLocation,
        [Parameter()]
        [boolean]$includeUnknownCountriesAndRegions,
        [Parameter()]
        [switch]$ListALL,
        [Parameter()]
        [switch]$AppendExisting,
        [Parameter()]
        [boolean]$isTrusted,
        [Parameter()]
        [string]$countryLookupMethod,
        [Parameter()]
        [switch]$Create,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Get all Entra Named Locations
    $Entra_Named_Locations_ALL = Get-MgIdentityConditionalAccessNamedLocation
    If (($Entra_Named_Locations_ALL) -and ($PSBoundParameters.ContainsKey('ListALL'))) {
        Return $Entra_Named_Locations_ALL
    }

    If ($DisplayName) {
        # Check if Named Location exists
        $Named_Location = $Entra_Named_Locations_ALL | Where-Object { $_.displayName -eq $DisplayName }

        # countryNamedLocation
        If ($PSBoundParameters.ContainsKey('countryNamedLocation')) {
            If ($countriesAndRegions) {
                If ($PSBoundParameters.ContainsKey('AppendExisting')) {
                    $NewcountriesAndRegions = @()
                    $NewcountriesAndRegions += $Named_Location.countriesAndRegions
                    $NewcountriesAndRegions += $countriesAndRegions
                    # Remove duplicates
                    $NewcountriesAndRegions = $NewcountriesAndRegions | Sort-Object -Unique
                } Else {
                    $NewcountriesAndRegions = @()
                    $NewcountriesAndRegions += $countriesAndRegions
                }

                $Params = @{
                    '@odata.type' = '#microsoft.graph.countryNamedLocation'
                    displayName = $DisplayName
                    isTrusted = $isTrusted
                    countriesAndRegions = $NewcountriesAndRegions
                    includeUnknownCountriesAndRegions = $includeUnknownCountriesAndRegions
                    countryLookupMethod = $countryLookupMethod
                }
            } Else {
                Write-host ""
                Write-Host "Syntax error countryNamedLocation. You need to define a list in two-letter format specified by ISO 3166-2"
                Write-host ""
                Break
            }
        }

        # ipNamedLocation
        If ($PSBoundParameters.ContainsKey('ipNamedLocation')) {
            If (($ip4Range) -or ($ip6Range)) {
                If ($PSBoundParameters.ContainsKey('AppendExisting')) {
                    $Newip4Range = @()
                    $Newip4Range += $Named_Location.ipRanges | Where-Object { $_.odata.type -eq '#microsoft.graph.iPv4CidrRange' }
                    $Newip4Range += $ip4Range

                    $Newip6Range = @()
                    $Newip6Range += $Named_Location.ipRanges | Where-Object { $_.odata.type -eq '#microsoft.graph.iPv6CidrRange' }
                    $Newip6Range += $ip6Range

                    # Remove duplicates
                    $Newip4Range = $Newip4Range | Sort-Object -Unique
                    $Newip6Range = $Newip6Range | Sort-Object -Unique
                } Else {
                    $Newip4Range = $ip4Range | Sort-Object -Unique
                    $Newip6Range = $ip6Range | Sort-Object -Unique
                }

                $Params = @{
                    '@odata.type' = '#microsoft.graph.ipNamedLocation'
                    displayName = $DisplayName
                    isTrusted = $isTrusted
                    ipRanges = @()
                }

                If ($Newip4Range) {
                    $Params.ipRanges += $Newip4Range | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.iPv4CidrRange'
                            cidrAddress = $_
                        }
                    }
                }

                If ($Newip6Range) {
                    $Params.ipRanges += $Newip6Range | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.iPv6CidrRange'
                            cidrAddress = $_
                        }
                    }
                }
            } Else {
                Write-host ""
                Write-Host "Syntax error ipNamedLocation. You need to define a list in IPv4 CIDR format (e.g., 1.2.3.4/32) or any allowable IPv6 format from IETF RFC596"
                Write-host ""
                Break
            }
        }

        If ($Named_Location) { # found -> Update or View existing
            If ($ForceUpdate) {
                Write-host ""
                Write-Host "Updating Named Location"
                Write-host ""
                Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Named_Location.id -BodyParameter $Params
            } Else {
                Return $Named_Location
            }
        } Else {
            If ($Create) {
                Write-host ""
                Write-Host "Creating Named Location"
                Write-host ""
                New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Params
            } Else {
                Write-host ""
                Write-Host "Named Location does not exist. Use -Create to create a new named location."
                Write-host ""
            }
        }
    } Else {
        Write-host ""
        Write-Host "DisplayName is required to create, update, or view a named location."
        Write-host ""
    }

    # Return Parameters
    $NamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq '$displayName'"
    Return $NamedLocation
}




Function EntraUser {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$DisplayName,
        [Parameter()]
        [string]$UserPrincipalName,
        [Parameter()]
        [string]$MailNickname,
        [Parameter()]
        [string]$Password,
        [Parameter()]
        [string]$GivenName,
        [Parameter()]
        [string]$Surname,
        [Parameter()]
        [string]$JobTitle,
        [Parameter()]
        [string]$Department,
        [Parameter()]
        [string]$MobilePhone,
        [Parameter()]
        [string]$OfficeLocation,
        [Parameter()]
        [switch]$Create,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Function to get user by UserPrincipalName
    Function Get-MgUserByUPN {
        param (
            [Parameter(Mandatory)]
            [string]$UPN
        )
        try {
            $User = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
            return $User
        } catch {
            return $null
        }
    }

    # Function to get user by DisplayName
    Function Get-MgUserByDisplayName {
        param (
            [Parameter(Mandatory)]
            [string]$DisplayName
        )
        try {
            $User = Get-MgUser -Filter "displayName eq '$DisplayName'"
            return $User
        } catch {
            return $null
        }
    }

    # Check if the user already exists
    $ExistingUserByUPN = if ($UserPrincipalName) { Get-MgUserByUPN -UPN $UserPrincipalName } else { $null }
    $ExistingUserByDisplayName = if ($DisplayName) { Get-MgUserByDisplayName -DisplayName $DisplayName } else { $null }

    $ExistingUser = if ($null -ne $ExistingUserByUPN) { $ExistingUserByUPN } elseif ($null -ne $ExistingUserByDisplayName) { $ExistingUserByDisplayName } else { $null }

    if ($null -ne $ExistingUser) {
        if ($ForceUpdate) {
            # Update existing user
            Write-host ""
            Write-Host "Updating user: $DisplayName"
            Write-host ""
            $UpdateParams = @{}
            if ($PSBoundParameters.ContainsKey('DisplayName')) { $UpdateParams.displayName = $DisplayName }
            if ($PSBoundParameters.ContainsKey('MailNickname')) { $UpdateParams.mailNickname = $MailNickname }
            if ($PSBoundParameters.ContainsKey('GivenName')) { $UpdateParams.givenName = $GivenName }
            if ($PSBoundParameters.ContainsKey('Surname')) { $UpdateParams.surname = $Surname }
            if ($PSBoundParameters.ContainsKey('JobTitle')) { $UpdateParams.jobTitle = $JobTitle }
            if ($PSBoundParameters.ContainsKey('Department')) { $UpdateParams.department = $Department }
            if ($PSBoundParameters.ContainsKey('MobilePhone')) { $UpdateParams.mobilePhone = $MobilePhone }
            if ($PSBoundParameters.ContainsKey('OfficeLocation')) { $UpdateParams.officeLocation = $OfficeLocation }

            try {
                Update-MgUser -UserId $ExistingUser.id -BodyParameter $UpdateParams
                Write-host ""
                Write-Host "User updated successfully."
                Write-host ""
                return $ExistingUser
            } catch {
                Write-host ""
                Write-Host "Error updating user: $_"
                Write-host ""
            }
        } else {
            Write-Host "User already exists: $($ExistingUser.displayName)"
            return $ExistingUser
        }
    } else {
        if ($Create) {
            # Ensure DisplayName and UserPrincipalName are provided for creation
            if (-not $DisplayName -or -not $UserPrincipalName) {
                Write-Host "DisplayName and UserPrincipalName are required to create a new user."
                Write-host ""
                return
            }

            # Create new user
            Write-host ""
            Write-Host "Creating new user: $DisplayName"
            $UserParams = @{
                accountEnabled = $true
                displayName = $DisplayName
                userPrincipalName = $UserPrincipalName
            }

            if ($PSBoundParameters.ContainsKey('MailNickname')) { $UserParams.mailNickname = $MailNickname }
            if ($PSBoundParameters.ContainsKey('Password')) {
                $UserParams.passwordProfile = @{
                    forceChangePasswordNextSignIn = $true
                    password = $Password
                }
            }
            if ($PSBoundParameters.ContainsKey('GivenName')) { $UserParams.givenName = $GivenName }
            if ($PSBoundParameters.ContainsKey('Surname')) { $UserParams.surname = $Surname }
            if ($PSBoundParameters.ContainsKey('JobTitle')) { $UserParams.jobTitle = $JobTitle }
            if ($PSBoundParameters.ContainsKey('Department')) { $UserParams.department = $Department }
            if ($PSBoundParameters.ContainsKey('MobilePhone')) { $UserParams.mobilePhone = $MobilePhone }
            if ($PSBoundParameters.ContainsKey('OfficeLocation')) { $UserParams.officeLocation = $OfficeLocation }

            try {
                $NewUser = New-MgUser -BodyParameter $UserParams
                Write-host ""
                Write-Host "User created successfully: $($NewUser.id)"
                Write-host ""
                return $NewUser
            } catch {
                Write-host ""
                Write-Host "Error creating user: $_"
                Write-host ""
            }
        } else {
            Write-Host "User does not exist. Use -Create to create a new user."
            Write-host ""
        }
    }
}




function Generate-RandomString {
    param (
        [int]$Length = 20
    )
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $randomString = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
    return $randomString
}




Function Generate-SecurePassword {
    param (
        [int]$length = 16
    )
    # Define the characters to use in the password
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?'
    # Generate the password
    $password = -join ((1..$length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    return $password
}




function Get-MgGroupMemberRecurse {
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




Function Install_GMSA_Account {
    param(
         [Parameter(Mandatory)]
         [string]$AccountName
     )

    # install account on fx. automation server
        Install-ADServiceAccount $AccountName

    # Test - should return TRUE
        Test-ADServiceAccount $AccountName
}




 Function Invoke-ADSDPropagation {
<#
.SYNOPSIS
    Invoke a SDProp task on the PDCe.
.DESCRIPTION
    Make an LDAP call to trigger SDProp.
.EXAMPLE
    Invoke-ADSDPropagation
    By default, RunProtectAdminGroupsTask is used.
.EXAMPLE
    Invoke-ADSDPropagation -TaskName FixUpInheritance
    Use the legacy FixUpInheritance task name for Windows Server 2003 and earlier.
.PARAMETER TaskName
    Name of the task to use.
        - FixUpInheritance for legacy OS
        - RunProtectAdminGroupsTask for recent OS
.NOTES
    You can track progress with:
    Get-Counter -Counter '\directoryservices(ntds)\ds security descriptor propagator runtime queue' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
.LINK
    http://ItForDummies.net
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,
        HelpMessage='Name of the domain where to force SDProp to run',
        Position=0)]
    [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
    [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,

    [ValidateSet('RunProtectAdminGroupsTask','FixUpInheritance')]
    [String]$TaskName = 'RunProtectAdminGroupsTask'
)

    try
        {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('domain',$DomainName)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
    
            Write-Verbose -Message "Detected PDCe is $($DomainObject.PdcRoleOwner.Name)."
            $RootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainObject.PdcRoleOwner.Name)/RootDSE") 
            $RootDSE.UsePropertyCache = $false 
            $RootDSE.Put($TaskName, "1") # RunProtectAdminGroupsTask & fixupinheritance
            $RootDSE.SetInfo()
        }
    catch
        {
            throw "Can't invoke SDProp on $($DomainObject.PdcRoleOwner.Name) !"
        }
}




Function TagDeviceConditionsTrue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$PropertyKey,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValue,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    # Get existing tag-values
    $ExistingTagValue = $Device.ExtensionAttributes.$PropertyKey

    if ($TagValue -eq "") { $TagValue = $null }

    Write-Verbose "PropertyKey      : $PropertyKey"
    Write-Verbose "ExistingValue    : $ExistingTagValue"
    Write-Verbose "TagValue         : $TagValue"

    if ($ExistingTagValue -eq $TagValue) {
        Write-Verbose "Skipping as value is already set correctly on device."
    } else {
        if (-not $global:EnableWhatIf) {
            Write-Host "Modifying device $($Device.DisplayName) in Microsoft Graph ($PropertyKey = $TagValue)"

            try {
                Update-MgBetaDevice -DeviceId $Device.Id -ExtensionAttributes @{"$PropertyKey"="$TagValue"} -ErrorAction Stop
            } catch {
                Write-Warning "Failed to update device $($Device.DisplayName) in Graph."
            }

            $LogEntry = [PSCustomObject]@{ 
                DeviceName = $Device.DisplayName
                DeviceId = $Device.Id
                PropertyKey = $PropertyKey
                TagValue = $TagValue
                ExistingTagValue = $ExistingTagValue
            }
            $Result = $Global:ModificationsLog.Add($LogEntry)
        } else {
            Write-Host "WhatIf - Modifying device $($Device.DisplayName) ($PropertyKey = $TagValue)"

            $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKey = $PropertyKey
                    TagValue = $TagValue
                    ExistingTagValue = $ExistingTagValue
                }
            $Result = $Global:ModificationsLog.Add($LogEntry)
        }
    }
}




Function TagUser {
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [object]$User,
            [Parameter()]
                [string]$PropertyKeyAD,
            [Parameter()]
                [string]$TagValueAD,
            [Parameter()]
                [string]$PropertyKeyCloud,
            [Parameter()]
                [string]$TagValueCloud,
            [Parameter(mandatory)]
                [AllowNull()]
                [array]$OnPremisesSyncEnabled,
            [Parameter()]
                [AllowNull()]
                [object]$MailBoxInfo
         )


    # Get existing tag-values
        $ExistingTagValue = $null
        $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

    # Cloud-only Account (use Microsoft Graph to update)
    If ( (!($OnPremisesSyncEnabled)) -and ($MailboxInfo) )
        {
            # Modify property, cloud-only user
                If ($ExistingTagValue -ne $TagValueCloud)
                    {
                        If ($MailboxInfo)
                            {
                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        Switch ($PropertyKeyCloud)
                                            {
                                                'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                            }

                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"
                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                            }
                        Else
                            {

                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        Try
                                            {
                                                Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                            }
                                        Catch
                                            {

                                                write-host ""
                                                write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                                # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                                # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                                switch ($PropertyKeyCloud)
                                                    {
                                                        'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                    }
                                                    
                                            }

                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                            }
                    }
        }

    If ( (!($OnPremisesSyncEnabled)) -and (!($MailboxInfo)) )
        {
            # Modify property, cloud-only user
                If ($ExistingTagValue -ne $TagValueCloud)
                    {

                        If (!($global:EnableWhatIf))
                            {
                                write-host ""
                                write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                Try
                                    {
                                        Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                    }
                                Catch
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                        # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                        switch ($PropertyKeyCloud)
                                            {
                                                'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                            }
                                    }

                                ################################################################################
                                $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                            }
                                $Result = $Global:ModificationsLog.add($LogEntry) 
                                ################################################################################
                            }
                        Else
                            {
                                write-host ""
                                write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                ################################################################################
                                $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                            }

                                $Result = $Global:ModificationsLog.add($LogEntry) 
                                ################################################################################
                            }
                    }
        }

    ElseIf ( ($OnPremisesSyncEnabled) -and ($MailboxInfo) )
        {
            # Modify property, AD-synced user
                If ($ExistingTagValue -ne $TagValueAD)
                    {
                        If ($MailboxInfo)
                            {

                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                        $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                        Try
                                            {
                                                If ($global:SecureCredentials) {
                                                    Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                } Else {
                                                    Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                }
                                            }
                                        Catch
                                            {
                                                If ($global:SecureCredentials) {
                                                    Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                } Else {
                                                    Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                }
                                            }
                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"
                                        ################################################################################
                                        $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                                    }

                                        $Result = $Global:ModificationsLog.add($LogEntry) 
                                        ################################################################################
                                    }
                            }
                    }                
        }

    ElseIf ( ($OnPremisesSyncEnabled) -and (!($MailboxInfo)) )
        {
            # Modify property, AD-synced user
                If ($ExistingTagValue -ne $TagValueAD)
                    {

                        If (!($global:EnableWhatIf))
                            {
                                write-host ""
                                write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                Try
                                    {
                                        If ($global:SecureCredentials) {
                                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                        } Else {
                                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                        }
                                    }
                                Catch
                                    {
                                        If ($global:SecureCredentials) {
                                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                        } Else {
                                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                        }
                                    }

                                ################################################################################
                                $LogEntry = $null
                                $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                            }

                                $Result = $Global:ModificationsLog.add($LogEntry) 
                                ################################################################################
                            }
                        Else
                            {
                                write-host ""
                                write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                ################################################################################
                                $LogEntry = $null
                                $LogEntry = [PSCustomObject]@{ 
                                                                            UserUPN = $User.UserPrincipalName
                                                                            UserDisplayName = $User.DisplayName
                                                                            OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                                                                            PropertyKeyAD = $PropertyKeyAD
                                                                            TagValueAD = $TagValueAD
                                                                            PropertyKeyCloud = $PropertyKeyCloud
                                                                            TagValueCloud = $TagValueCloud
                                                                            ExistingTagValue = $ExistingTagValue
                                                            }

                                $Result = $Global:ModificationsLog.add($LogEntry)
                                ################################################################################
                            }
                    }                
        }
}




Function TagUserConditionsTrue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$User,
        [Parameter(Mandatory)] [string]$PropertyKeyAD,
        [Parameter(Mandatory)] [string]$PropertyKeyCloud,
        [Parameter(Mandatory)] [string]$TagValueAD,
        [Parameter(Mandatory)] [string]$TagValueCloud,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    # Get existing tag-values
    $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

    # Cloud-only Account (use Microsoft Graph to update)
    if ([string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {
        write-verbose ""
        write-Verbose "PropertyKeyCloud : $($PropertyKeyCloud)"
        write-Verbose "ExistingValue    : $($ExistingTagValue)"
        write-Verbose "TagValueCloud    : $($TagValueCloud)"

        if ($ExistingTagValue -eq $TagValueCloud) {
        write-verbose ""
        write-Verbose "Skipping as value is already set correctly on user !!!"
                
        } elseIf ($ExistingTagValue -ne $TagValueCloud) {
            if (-not $global:EnableWhatIf) {
                Write-Host ""
                Write-Host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                try {
                    Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                } catch {
                    Write-Host ""
                    Write-Host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"
                            
                    # Handle updates via Exchange Online cmdlets
                    switch ($PropertyKeyCloud) {
                        'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue }
                    }
                }

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            } else {
                Write-Host ""
                Write-Host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            }
        }
            
    } elseif (-not [string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {

        write-verbose ""
        write-Verbose "PropertyKeyAD    : $($PropertyKeyAD)"
        write-Verbose "ExistingValue    : $($ExistingTagValue)"
        write-Verbose "TagValueAD       : $($TagValueAD)"
                                
        if ($ExistingTagValue -eq $TagValueAD) {
        write-verbose ""
        write-Verbose "Skipping as value is already set correctly on user !!!"
                
        } elseIf ($ExistingTagValue -ne $TagValueAD) {
            if (-not $global:EnableWhatIf) {
                Write-Host ""
                Write-Host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                try {
                        If ($global:SecureCredentials) {
                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                        } Else {
                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                        }
                } catch {
                        If ($global:SecureCredentials) {
                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                        } Else {
                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                        }
                }

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            } else {
                Write-Host ""
                Write-Host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            }
        }
    }
}





# SIG # Begin signature block
# MIIXHgYJKoZIhvcNAQcCoIIXDzCCFwsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCg4f+b5drLpPhn
# gOM4aSnHNJpAASthKeboR89JsASK36CCE1kwggVyMIIDWqADAgECAhB2U/6sdUZI
# k/Xl10pIOk74MA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDAzMTgwMDAwMDBaFw00NTAzMTgwMDAwMDBaMFMx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQD
# EyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALYtxTDdeuirkD0DcrA6S5kWYbLl/6VnHTcc5X7s
# k4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LYS8lKA/Oof2qPimEnvaFE0P31PyLC
# o0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5QOkHM8KCwex1N0qhYOJbp3/kbkbuL
# ECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/rlX7hPCA/oRM1+K6vcR1oW+9YRB0
# RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xVuBZwXCR4ICXrZ2eIq7pONJhrcBHe
# OMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/ugk3PWdssUVcGWGrQYP1rB3rdw1G
# R3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWbEsSegHI9k9yMlN87ROYmgPzSwwPw
# jAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZkobacgSFOK8ZtaJSGxpl0c2cxepHy
# 1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FXBhcSJMDEMXOhmDVXR34QOkXZLaRR
# kJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pAsufSxPrJ0PBQdnRZ+o1tFzK++Ol+
# A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e+MuNrRan097VmxinxpI68YJj8S4O
# JGTfAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzANBgkqhkiG9w0BAQwFAAOCAgEA
# Xiu6dJc0RF92SChAhJPuAW7pobPWgCXme+S8CZE9D/x2rdfUMCC7j2DQkdYc8pzv
# eBorlDICwSSWUlIC0PPR/PKbOW6Z4R+OQ0F9mh5byV2ahPwm5ofzdHImraQb2T07
# alKgPAkeLx57szO0Rcf3rLGvk2Ctdq64shV464Nq6//bRqsk5e4C+pAfWcAvXda3
# XaRcELdyU/hBTsz6eBolSsr+hWJDYcO0N6qB0vTWOg+9jVl+MEfeK2vnIVAzX9Rn
# m9S4Z588J5kD/4VDjnMSyiDN6GHVsWbcF9Y5bQ/bzyM3oYKJThxrP9agzaoHnT5C
# JqrXDO76R78aUn7RdYHTyYpiF21PiKAhoCY+r23ZYjAf6Zgorm6N1Y5McmaTgI0q
# 41XHYGeQQlZcIlEPs9xOOe5N3dkdeBBUO27Ql28DtR6yI3PGErKaZND8lYUkqP/f
# obDckUCu3wkzq7ndkrfxzJF0O2nrZ5cbkL/nx6BvcbtXv7ePWu16QGoWzYCELS/h
# AtQklEOzFfwMKxv9cW/8y7x1Fzpeg9LJsy8b1ZyNf1T+fn7kVqOHp53hWVKUQY9t
# W76GlZr/GnbdQNJRSnC0HzNjI3c/7CceWeQIh+00gkoPP/6gHcH1Z3NFhnj0qinp
# J4fGGdvGExTDOUmHTaCX4GUT9Z13Vunas1jHOvLAzYIwggbmMIIEzqADAgECAhB3
# vQ4DobcI+FSrBnIQ2QRHMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8w
# LQYDVQQDEyZHbG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcgQ0EgMjAyMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANZCTfnjT8Yj9GwdgaYw90g9
# z9DljeUgIpYHRDVdBs8PHXBg5iZU+lMjYAKoXwIC947Jbj2peAW9jvVPGSSZfM8R
# Fpsfe2vSo3toZXer2LEsP9NyBjJcW6xQZywlTVYGNvzBYkx9fYYWlZpdVLpQ0LB/
# okQZ6dZubD4Twp8R1F80W1FoMWMK+FvQ3rpZXzGviWg4QD4I6FNnTmO2IY7v3Y2F
# QVWeHLw33JWgxHGnHxulSW4KIFl+iaNYFZcAJWnf3sJqUGVOU/troZ8YHooOX1Re
# veBbz/IMBNLeCKEQJvey83ouwo6WwT/Opdr0WSiMN2WhMZYLjqR2dxVJhGaCJedD
# CndSsZlRQv+hst2c0twY2cGGqUAdQZdihryo/6LHYxcG/WZ6NpQBIIl4H5D0e6lS
# TmpPVAYqgK+ex1BC+mUK4wH0sW6sDqjjgRmoOMieAyiGpHSnR5V+cloqexVqHMRp
# 5rC+QBmZy9J9VU4inBDgoVvDsy56i8Te8UsfjCh5MEV/bBO2PSz/LUqKKuwoDy3K
# 1JyYikptWjYsL9+6y+JBSgh3GIitNWGUEvOkcuvuNp6nUSeRPPeiGsz8h+WX4VGH
# aekizIPAtw9FbAfhQ0/UjErOz2OxtaQQevkNDCiwazT+IWgnb+z4+iaEW3VCzYkm
# eVmda6tjcWKQJQ0IIPH/AgMBAAGjggGuMIIBqjAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
# 2rONwCSQo2t30wygWd0hZ2R2C3gwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lW
# ULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2Nz
# cC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKG
# Omh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5n
# cm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFYGA1UdIARPME0wQQYJKwYB
# BAGgMgEyMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t
# L3JlcG9zaXRvcnkvMAgGBmeBDAEEATANBgkqhkiG9w0BAQsFAAOCAgEACIhyJsav
# +qxfBsCqjJDa0LLAopf/bhMyFlT9PvQwEZ+PmPmbUt3yohbu2XiVppp8YbgEtfjr
# y/RhETP2ZSW3EUKL2Glux/+VtIFDqX6uv4LWTcwRo4NxahBeGQWn52x/VvSoXMNO
# Ca1Za7j5fqUuuPzeDsKg+7AE1BMbxyepuaotMTvPRkyd60zsvC6c8YejfzhpX0FA
# Z/ZTfepB7449+6nUEThG3zzr9s0ivRPN8OHm5TOgvjzkeNUbzCDyMHOwIhz2hNab
# XAAC4ShSS/8SS0Dq7rAaBgaehObn8NuERvtz2StCtslXNMcWwKbrIbmqDvf+28rr
# vBfLuGfr4z5P26mUhmRVyQkKwNkEcUoRS1pkw7x4eK1MRyZlB5nVzTZgoTNTs/Z7
# KtWJQDxxpav4mVn945uSS90FvQsMeAYrz1PYvRKaWyeGhT+RvuB4gHNU36cdZytq
# tq5NiYAkCFJwUPMB/0SuL5rg4UkI4eFb1zjRngqKnZQnm8qjudviNmrjb7lYYuA2
# eDYB+sGniXomU6Ncu9Ky64rLYwgv/h7zViniNZvY/+mlvW1LWSyJLC9Su7UpkNpD
# R7xy3bzZv4DB3LCrtEsdWDY3ZOub4YUXmimi/eYI0pL/oPh84emn0TCOXyZQK8ei
# 4pd3iu/YTT4m65lAYPM8Zwy2CHIpNVOBNNwwggb1MIIE3aADAgECAgx5Y9ljauM7
# cdkFAm4wDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEds
# b2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0NDIFI0NSBDb2Rl
# U2lnbmluZyBDQSAyMDIwMB4XDTIzMDMyNzEwMjEzNFoXDTI2MDMyMzE2MTgxOFow
# YzELMAkGA1UEBhMCREsxEDAOBgNVBAcTB0tvbGRpbmcxEDAOBgNVBAoTBzJsaW5r
# SVQxEDAOBgNVBAMTBzJsaW5rSVQxHjAcBgkqhkiG9w0BCQEWD21va0AybGlua2l0
# Lm5ldDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMykjWtM6hY5IRPe
# VIVB+yX+3zcMJQR2gjTZ81LnGVRE94Zk2GLFAwquGYWt1shoTHTV5j6Ef2AXYBDV
# kNruisJVJ17UsMGdsU8upwdZblFbLNzLw+qBXVC/OUVua9M0cub7CfUNkn/Won4D
# 7i41QyuDXdZFOIfRhZ3qnCYCJCSgYLoUXAS6xei2tPkkk1w8aXEFxybyy7eRqQjk
# HqIS5N4qH3YQkz+SbSlz/yj6mD65H5/Ts+lZxX2xL/8lgJItpdaJx+tarprv/tT+
# +n9a13P53YNzCWOmyhd376+7DMXxxSzT24kq13Ks3xnUPGoWUx2UPRnJHjTWoBfg
# Y7Zd3MffrdO0QEoDC9X5F5boh6oankVSOdSPRFns085KI+vkbt3bdG62MIeUbNtS
# v7mZBX8gcYv0szlo0ey7bbOJWoiZFT2fB+pBVvxDhpYP0/3aFveM1wfhshaJBhxx
# /2GCswYYBHH7B3+8j4BT8N8S030q4snys2Qt9tdFIHvSV7lIw/yorT1WM1cr+Lqo
# 74eR+Hi982db0k68p2BGdCOY0QhhaNqxufwbK+gVWrQY57GIX/1cUrBt0akMsli2
# 19xVmUGhIw85ZF7wcQplhslbUxyNUilY+c93q1bsIFjaOnjjvo56g+kyKICm5zsG
# FQLRVaXUSLY+i8NSiH8fd64etaptAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMC
# B4AwgZsGCCsGAQUFBwEBBIGOMIGLMEoGCCsGAQUFBzAChj5odHRwOi8vc2VjdXJl
# Lmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0NWNvZGVzaWduY2EyMDIwLmNy
# dDA9BggrBgEFBQcwAYYxaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2Ny
# NDVjb2Rlc2lnbmNhMjAyMDBWBgNVHSAETzBNMEEGCSsGAQQBoDIBMjA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAI
# BgZngQwBBAEwCQYDVR0TBAIwADBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFNqzjcAkkKNrd9MMoFndIWdkdgt4
# MB0GA1UdDgQWBBQxxpY2q5yrKa7VFODTZhTfPKmyyTANBgkqhkiG9w0BAQsFAAOC
# AgEAe38NgZR4IV9u264/n/jiWlHbBu847j1vpN6dovxMvdUQZ780eH3JzcvG8fo9
# 1uO1iDIZksSigiB+d8Sj5Yvh+oXlfYEffjIQCwcIlWNciOzWYZzl9qPHXgdTnaIu
# JA5cR846TepQLVMXc1Yb72Z7OGjldmRIxGjRimDsmzY+TdTu15lF4IkUj0VJhr8F
# PYOdEVZVOXHtPmUjPqsq9M7WpALYbc0pUawcy0FOOwXqzaCk7O3vMXej4Oycm6RB
# GfRH3JPOCvH2ddiIfPq2Lce4nhTuLsgumBJE2vOalVddIfTBjE9PpMub15lHyp1m
# fW0ZJvXOghPvRqufMT3SjPTHt6PV8LwhQD8BiGSZ9rp94js4xTnGexSOFKLLMxWE
# PTr5EPe3kmtspGgKCqLEZvsMYz7JlWNuaHBy+vdQZWV3376luwV4IHfGT+1wxe0E
# 90dMRI+9SNIKkVvKV3FUtToZUh3Np4cCIHJLQ1eslXFzIJa6wrjVsnWM/3OyedpQ
# JERGNYXlVmxdgGFjrY1I6UWII0Y1iZW3t+JvhXosUaha8i/YSxaDH+5H/Klad2OZ
# Xq4Eg39QxkCELbmJmSU0sUYNnl0JTEu6jJY9UJMFikzf5s3p2ZuKdyMbRgN5GNNV
# 883meI/X5KVHBJDG1epigMer7fFXMVZUGoI12iIz/gOolQExggMbMIIDFwIBATBp
# MFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYD
# VQQDEyZHbG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMeWPZ
# Y2rjO3HZBQJuMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBXGWK3R1V94UitzuQSBQqU0
# Dp+iQZ1Rw8okjXooV42kMA0GCSqGSIb3DQEBAQUABIICAHJMmos+upkFO4ibwcYr
# Y0crRILJ/yysxdKciLqsP0pJoFhqVURlDKxrkvjeSOvr8IYzqf66UtacWO0Mi/ia
# vsRU3gUzPM7chCacVwTQ72HC+SwpdlrC5cep8OH/rjItyU8CqCkyNMnl3kU0arby
# 2sHW7nONiXJtQk0Rq+8fx6rdUZ1AJqlawchYL0Y8GcdwI5VLyhozjs5E+T65jRgx
# K/z5cT97/U5cJiC3Xxx/Dr/11AcwTiZ2lQ8C3JKVkH2crm3MjB3PKztgg2lOjEyT
# BLlTfD6ul+jO1xLwNt9hPoka1cNdSlkXKg6kSXFSGtZNI5KRPq7Nwpt0bbGH/am8
# gZOO1C5u7cEWfiuNUz1gl64gkWNieCVCdS8U1t5u8cliS3aV6/Is3LjxqGtOkLbY
# Yji4fTYIMTSnbQshBVq+S9hHi0X+gxe9SPSmzr96cDclNnEWhhouoxUravl0yfiD
# aHa7KQMvVp2PlnDk5u6L8cstIWuWn/4WtDVQ8PNC8UMrDau5yKBrxleAogD+3Bgi
# nnB1EJ+QnrsqqdgidQFik8oIpifEPNzty4AQVe65X9KltaMJekTLU0GViBcDJs9+
# bcBTb7hFGcrH9MfrAUNoF1TH9O8faMSwnB2OsJgLpGlC3VGmSjjnOTa5VVjMaDQd
# WHpcpDP8O/U4fzt+FaF0RXSE
# SIG # End signature block
