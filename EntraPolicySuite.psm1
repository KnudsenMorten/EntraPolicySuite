Function AddGroupMemberOf_GMSA_Group_AD



Function AddMembers_GMSA_Group_AD



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



Function CheckAccountTagUserAuthentication



Function CheckAccountTagUserCAPilot



Function CheckAccountTagUserClassification



Function CheckDeviceConditions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$Persona,
        [Parameter(Mandatory)] [string]$TagType,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueAD,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueCloud,
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



Function Create_GMSA_Account



Function Create_GMSA_Group_AD



Function Create_GMSA_OU



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



Function EntraCAPolicy



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



# Function to generate a random alphanumeric string of specified length
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


function Generate-RandomString {
    param (
        [int]$Length = 20
    )
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $randomString = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
    return $randomString
}



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


function Get-MgGroupMemberRecurse 



Function Install_GMSA_Account



Function Invoke-ADSDPropagation
{
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



 Function Invoke-ADSDPropagation



Function TagDeviceConditionsTrue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$PropertyKeyAD,
        [Parameter(Mandatory)] [string]$PropertyKeyCloud,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueAD,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueCloud,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    # Get existing tag-values
    $ExistingTagValue = $Device.ExtensionAttributes.$PropertyKeyCloud

    if ($TagValueAD -eq "") { $TagValueAD = $null }
    if ($TagValueCloud -eq "") { $TagValueCloud = $null }

    # Cloud-only device
    if ([string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {
        Write-Verbose "PropertyKeyCloud : $PropertyKeyCloud"
        Write-Verbose "ExistingValue    : $ExistingTagValue"
        Write-Verbose "TagValueCloud    : $TagValueCloud"

        if ($ExistingTagValue -eq $TagValueCloud) {
            Write-Verbose "Skipping as value is already set correctly on device."
        } else {
            if (-not $global:EnableWhatIf) {
                Write-Host "Modifying device $($Device.DisplayName) in Microsoft Graph ($PropertyKeyCloud = $TagValueCloud)"

                try {
                    Update-MgBetaDevice -DeviceId $Device.Id -ExtensionAttributes @{"$PropertyKeyCloud"="$TagValueCloud"} -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to update device $($Device.DisplayName) in Graph."
                }

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            } else {
                Write-Host "WhatIf - Modifying device $($Device.DisplayName) ($PropertyKeyCloud = $TagValueCloud)"

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            }
        }
    } else {
        # Device is Hybrid AD joined (on-prem sync enabled)
        Write-Verbose "PropertyKeyAD : $PropertyKeyAD"
        Write-Verbose "ExistingValue : $ExistingTagValue"
        Write-Verbose "TagValueAD    : $TagValueAD"

        if ($ExistingTagValue -eq $TagValueAD) {
            Write-Verbose "Skipping as value is already set correctly on device."
        } else {
            if (-not $global:EnableWhatIf) {
                Write-Host "Modifying device $($Device.DisplayName) in Active Directory ($PropertyKeyAD = $TagValueAD)"

                $DeviceAD = Get-ADComputer -Filter { Name -eq $Device.DisplayName }
                try {
                    if ($global:SecureCredentials) {
                        Set-ADComputer -Identity $DeviceAD -Replace @{"$PropertyKeyAD"="$TagValueAD"} -Credential $global:SecureCredentials
                    } else {
                        Set-ADComputer -Identity $DeviceAD -Replace @{"$PropertyKeyAD"="$TagValueAD"}
                    }
                } catch {
                    try {
                        if ($global:SecureCredentials) {
                            Set-ADComputer -Identity $DeviceAD -Add @{"$PropertyKeyAD"="$TagValueAD"} -Credential $global:SecureCredentials
                        } else {
                            Set-ADComputer -Identity $DeviceAD -Add @{"$PropertyKeyAD"="$TagValueAD"}
                        }
                    } catch {
                        Write-Warning "Failed to modify device $($Device.DisplayName) in AD."
                    }
                }

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            } else {
                Write-Host "WhatIf - Modifying device $($Device.DisplayName) in AD ($PropertyKeyAD = $TagValueAD)"

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            }
        }
    }
}



Function TagUser



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



