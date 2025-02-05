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
