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

