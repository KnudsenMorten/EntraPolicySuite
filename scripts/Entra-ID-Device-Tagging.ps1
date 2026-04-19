<#
.SYNOPSIS
    Entra-ID-Device-Tagging - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : Entra-ID-Device-Tagging.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Tagging of Devices in Entra ID based on type"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@2linkit.net | 40 178 179"
Write-Output "***********************************************************************************************"

#------------------------------------------------------------------------------------------------------------
# Loading Functions, Connectivity & Default variables
#------------------------------------------------------------------------------------------------------------
    $ScriptDirectory = $PSScriptRoot
    $global:PathScripts = Split-Path -parent $ScriptDirectory
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
    # One call to Initialize-PlatformAutomationFramework does cert-based
    # Connect-AzAccount, fetches Modern secrets from KV, populates
    # $global:HighPriv_* / $global:AzureTenantId (public contract), and
    # dot-sources Layer-1 platform-defaults.ps1. Zero v1 module imports.
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
    }
    $global:PathScripts = $repoRoot
    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets


######################################################################################################
# Entra Policy Suite Functions
######################################################################################################

    # Loading functions
    Import-Module "$($global:PathScripts)\FUNCTIONS\EntraPolicySuite.psm1" -Global -force -WarningAction SilentlyContinue


#############################################################################################
# Main Program
#############################################################################################

Write-Host "Getting Entra ID device information ... Please Wait!"
$EntraID_Devices_ALL = Get-MgBetaDevice -All
$EntraID_Devices_ALL_Scoped = $EntraID_Devices_ALL

# EXTRA CHECK | TERMINATE IF VARIABLES ARE EMPTY !!!
If ($EntraID_Devices_ALL_Scoped.Count -eq 0) {
    Write-Host "Exiting as there is a critical error .... Critical variable is empty!"
    Exit 1
}

# Build hashtable of all Entra ID devices
$global:Entra_Devices_HashTable = [ordered]@{}
$EntraID_Devices_ALL | ForEach-Object { $global:Entra_Devices_HashTable.add($_.Id, $_) }

Write-Host "Getting all Groups from Entra ID ... Please Wait!"
$AllGroups_Entra = Get-MgGroup -All

Write-Host "Getting Tag Conditions from CSV-file ... Please Wait!"
$Tag_Conditions = Import-Csv -Path "$($global:PathScripts)\DATA\Device_Tagging.csv" -Delimiter ";" -Encoding UTF8

$Tag_Conditions_AccountInfo = @()
$Tag_Conditions_AccountInfo = Import-Csv -Path "$($global:PathScripts)\DATA\Device_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

# Remove empty lines
If ($Tag_Conditions) {
    $Tag_Conditions = $Tag_Conditions | Where-Object { ($_.TagType -notlike "") -and ($_.TagType -ne $null) }
}
If ($Tag_Conditions_AccountInfo) {
    $Tag_Conditions_AccountInfo = $Tag_Conditions_AccountInfo | Where-Object { ($_.TagType -notlike "") -and ($_.TagType -ne $null) }
}

$Tag_Conditions_Array = @()
$Tag_Conditions_Array += $Tag_Conditions
$Tag_Conditions_Array += $Tag_Conditions_AccountInfo

$Tag_Conditions_MemberOf = $Tag_Conditions_Array | Where-Object { ($_.ConditionType -like "*MemberOf*") }

Write-Host "Scope Entra ID Groups to check for members (MemberOf) ... Please Wait!"
$Entra_MemberOf_Scope = $AllGroups_Entra | Where-Object { $_.DisplayName -in $Tag_Conditions_MemberOf.Target }

Write-Host "Getting Group Members from Entra ID Groups in scope of MemberOf ... Please Wait!"

# Initialize an empty array to store group and member information
$Entra_Group_Members = [System.Collections.ArrayList]@()

# Loop through each group and retrieve members
foreach ($group in $Entra_MemberOf_Scope) {
    $members = Get-MgGroupMember -GroupId $group.Id -All

    # Filter devices only
    $deviceMembers = $members | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }

    # Create a custom object for each group with its device members
    $groupInfo = [PSCustomObject]@{
        GroupName = $group.DisplayName
        Members   = $deviceMembers
    }

    $Result = $Entra_Group_Members.Add($groupInfo)
}

# Build hashtable of all Entra ID groups
$global:Entra_Groups_HashTable = [ordered]@{}
$AllGroups_Entra | ForEach-Object { $global:Entra_Groups_HashTable.add($_.DisplayName, $_) }

# Build hashtable of all Entra ID group members
$global:Entra_Group_Members_HashTable = [ordered]@{}
$Entra_Group_Members | ForEach-Object { $global:Entra_Group_Members_HashTable.add($_.GroupName, $_) }
   
#########################################################################################################################

    # Set variable to true, if you only want to write-out the result and NOT apply the setting !! 
    # Setting to $false will enforce the properties to be updated on all users in scope

    $global:EnableWhatIf = $false

<# 
    # Testing Only
    $EntraID_Devices_ALL_Scoped = $EntraID_Devices_ALL

    $EntraID_Devices_ALL_Scoped = $EntraID_Devices_ALL | where-Object { ($_.DisplayName -like "acw-iphone*") }

    $EntraID_Devices_ALL_Scoped = $EntraID_Devices_ALL | Where-Object { ($_.DisplayName -like "ev-x*") -or ($_.DisplayName -like "anped*") -or ($_.DisplayName -like "x-mowa*") }
    $EntraID_Devices_ALL_Scoped = $EntraID_Devices_ALL | Where-Object { $_.DisplayName -like "invoices*" }

    # Troubleshooting
    $VerbosePreference = "Continue"
    $DebugPreference = "Continue"

    $VerbosePreference = "SilentlyContinue"
    $DebugPreference = "SilentlyContinue"


#>

#########################################################################################################################

$Global:ModificationsLog = [System.Collections.ArrayList]@()
$Global:CompleteLog = [System.Collections.ArrayList]@()

Write-Host "Getting Tag Conditions from CSV-file ... Please Wait!"
$Tag_Conditions = Import-Csv -Path "$($global:PathScripts)\DATA\Device_Tagging.csv" -Delimiter ";" -Encoding UTF8
$Tag_Conditions_AccountInfo = @()
$Tag_Conditions_AccountInfo = Import-Csv -Path "$($global:PathScripts)\DATA\Device_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

# Remove empty lines
If ($Tag_Conditions) {
    $Tag_Conditions = $Tag_Conditions | Where-Object { ($_.TagType -notlike "") -and ($_.TagType -ne $null) }
}
If ($Tag_Conditions_AccountInfo) {
    $Tag_Conditions_AccountInfo = $Tag_Conditions_AccountInfo | Where-Object { ($_.TagType -notlike "") -and ($_.TagType -ne $null) }
}

$Tag_Conditions_Array = @()
$Tag_Conditions_Array += $Tag_Conditions
$Tag_Conditions_Array += $Tag_Conditions_AccountInfo

# Handle blank ConditionGroup and assign random value
$Tag_Conditions_Fixed = @()
foreach ($item in $Tag_Conditions_Array) {
    $newItem = $item.PSObject.Copy()
    if ([string]::IsNullOrEmpty($newItem.ConditionGroup)) {
        $newItem.ConditionGroup = Generate-RandomString
    }
    $Tag_Conditions_Fixed += $newItem
}

$Tag_Conditions_Array = $Tag_Conditions_Fixed | Group-Object -Property TagType,TagValue,ConditionGroup

#################################################
# Loop
#################################################
$DevicesTotal = $EntraID_Devices_ALL_Scoped.Count

$EntraID_Devices_ALL_Scoped | ForEach-Object -Begin {
    $i = 0
} -Process {

    # Default values
    $Device = $_

    Write-Host ""
    Write-Host "Processing $($Device.DisplayName) ($($Device.Id))"

    $TagTypes = [System.Collections.ArrayList]@()
    $OnPremisesSyncEnabled = $Device.OnPremisesSyncEnabled

    foreach ($ConditionGroupArray in $Tag_Conditions_Array) {

        $DeviceConditionMet = [System.Collections.ArrayList]@()

        foreach ($Condition in $ConditionGroupArray.Group) {

            # Scoping Tag Types
            switch ($Condition.TagType) {
                "DeviceCategory" {
                    $PropertyKey = "ExtensionAttribute6"
                    break
                }
            }

            # Values from Condition
            $TagType = $Condition[0].TagType
            $TagValue = $Condition[0].TagValue
            $ConditionsType = $Condition[0].ConditionType
            $Target = $Condition.Target
            $ConditionGroup = $Condition.ConditionGroup

            Write-Debug ""
            Write-Debug "TagType        : $TagType"
            Write-Debug "TagValue       : $TagValue"
            Write-Debug "ConditionsType : $ConditionsType"
            Write-Debug "Target         : $Target"
            Write-Debug "ConditionGroup : $ConditionGroup"

            if ($TagValue -eq "") { $TagValue = $null }

            if ($TagType) {
                $ConditionMet = CheckDeviceConditions -Device $Device `
                                                        -TagType $TagType `
                                                        -TagValue $TagValue `
                                                        -ConditionsType $ConditionsType `
                                                        -ConditionGroup $ConditionGroup `
                                                        -Target $Target `
                                                        -OnPremisesSyncEnabled $OnPremisesSyncEnabled

                if ($ConditionMet[1]) {
                    $ModifiedTagValue = $ConditionMet[1]
                } else {
                    $ModifiedTagValue = $null
                }

                $ConditionMet = $ConditionMet[0]

                if ($ConditionGroup) {
                    Write-Verbose ""
                    Write-Verbose "ConditionMet     : $ConditionMet"
                    $Result = $DeviceConditionMet.Add($ConditionMet)
                } else {
                    Write-Verbose ""
                    Write-Verbose "ConditionMet     : $ConditionMet"
                    $DeviceConditionMet = [System.Collections.ArrayList]@()
                    $Result = $DeviceConditionMet.Add($ConditionMet)
                }
            }
        }

        if ($DeviceConditionMet -contains $false) {
            Write-Verbose ""
            Write-Verbose "Skipping - Conditions check completed but FALSE values detected!"
        } else {
            Write-Verbose ""
            Write-Verbose "SUCCESS - Conditions check completed... Now checking tagging!"

            $TagTypes_String = ($TagTypes -join ",")

            if ($TagTypes_String -notlike "*$TagType*") {
                if ($ModifiedTagValue) {
                    $index = $ModifiedTagValue.IndexOf("_")
                    if ($index -ge 0) {
                        $TagValue = $ModifiedTagValue.Substring(0, $index + 1) + "Cloud_" + $ModifiedTagValue.Substring($index + 1)
                    } else {
                        $TagValue = $ModifiedTagValue
                    }

                    if ($TagValue -eq "") { $TagValue = $null }
                }

                if ($TagValue -eq "") { $TagValue = $null }

                TagDeviceConditionsTrue -Device $Device `
                                        -PropertyKey $PropertyKey `
                                        -TagValue $TagValue `
                                        -OnPremisesSyncEnabled $OnPremisesSyncEnabled

                $Result = $TagTypes.Add($TagType)
            }
        }
    }

    $TagTypes_String = ($TagTypes -join ",")

    # remove extension5 value - set to $null
    <#
        $PropertyKey = "extensionAttribute5"
        $TagValue = $null

        TagDeviceConditionsTrue -Device $Device `
                                -PropertyKey $PropertyKey `
                                -TagValue $TagValue `
                                -OnPremisesSyncEnabled $OnPremisesSyncEnabled
    #>

    if ($TagTypes_String -notlike "*DeviceCategory*") {
        $PropertyKey = "extensionAttribute6"
        $TagValue = "Unknown_DeviceCategory"

        TagDeviceConditionsTrue -Device $Device `
                                -PropertyKey $PropertyKey `
                                -TagValue $TagValue `
                                -OnPremisesSyncEnabled $OnPremisesSyncEnabled
    }

#>

    Write-Verbose ""
    Write-Verbose "---------------------------------------------------------------------------------------"

    $i = $i+1

    # Determine the completion percentage
    $Completed = ($i/$DevicesTotal) * 100

    Write-Progress -Activity "Tagging Devices" -Status "Progress:" -PercentComplete $Completed
} -End {
    Write-Progress -Activity "Tagging Devices" -Status "Ready" -Completed
}

################################################################################################
# Export Values
################################################################################################


# Get all devices
$devices = Get-MgBetaDevice -All

# Filter for devices where ExtensionAttribute6 has a value
$filteredDevices = foreach ($device in $devices) {
    $ext6 = $device.ExtensionAttributes.ExtensionAttribute6
    if ($ext6) {
        [PSCustomObject]@{
            Id                  = $device.Id
            DisplayName         = $device.DisplayName
            ExtensionAttribute6 = $ext6
        }
    }
}

# Output results
$filteredDevices | Format-Table -AutoSize