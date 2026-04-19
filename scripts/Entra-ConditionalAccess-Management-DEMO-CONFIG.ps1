<#
.SYNOPSIS
    Entra-ConditionalAccess-Management-DEMO-CONFIG - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : Entra-ConditionalAccess-Management-DEMO-CONFIG.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Onboard Entra Conditional Access Policies concept"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@2linkit.net | 40 178 179"
Write-Output "***********************************************************************************************"
#------------------------------------------------------------------------------------------------

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


########################################################################################################################################
# Entra Policy Suite Functions
########################################################################################################################################
    Import-Module "$($global:PathScripts)\FUNCTIONS\EntraPolicySuite.psm1" -Global -force -WarningAction SilentlyContinue


########################################################################################################################################
# Debug
########################################################################################################################################
   
<#

    # Enable DEBUG
    $DebugPreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

    # Disable DEBUG
    $DebugPreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

#>


########################################################################################################################################
# Step 1: READING CONFIGURATIONS FROM CONFIG-FILE
########################################################################################################################################

    Write-host ""
    Write-host "Step 1: Getting Configurations from config-files"

    ###############################################
    # Get data from CUSTOM CONFIG-file
    ###############################################

        # Set the path to the custom config file
        $configFilePath = "$($global:PathScripts)\DATA\Entra_Policy_Suite_custom.config"

        # Check if the config file exists
        if (-Not (Test-Path $configFilePath)) {
            Write-host ""
            Write-host "Entra_Policy_Suite_custom.config was not found in the DATA directory. Terminating !" -ForegroundColor DarkYellow
            break
        }

        # Read the config file
        $configData = Get-Content $configFilePath | ConvertFrom-Json

        # Get Paths to CA-files
        $Path_CA_Scripts_Active = $($global:PathScripts) + "\Entra-Policy-Suite" + "\" + $configData.Path_CA_Scripts_Active
        $Path_CA_Scripts_Github_Latest_Inbound = $($global:PathScripts) + "\Entra-Policy-Suite" + "\" + $configData.Path_CA_Scripts_Github_Latest_Inbound

        # Get all BreakGlassAccounts
        $BreakGlassAccounts_CFG = $configData.BreakGlassAccounts

        # Get all BreakGlassAccounts with MFA authentication
        $BreakGlassAccounts_CFG_MFA = $configData.BreakGlassAccounts | Where-Object { $_.AuthenticationMethod -eq 'MFA' }

        # Get all BreakGlassAccounts with FIDO authentication
        $BreakGlassAccounts_CFG_FIDO = $configData.BreakGlassAccounts | Where-Object { $_.AuthenticationMethod -eq 'FIDO' }

        # Get the Group Targeting Method
        $Group_Targeting_Method = $configData.Group_Targeting_Method

        # Get the default name of authentication strength to use for FIDO authentication
        $Authentication_Strength_Default_FIDO_Name_CFG = $configData.Authentication_Strength_Default_FIDO_Name

        # Get the default name of authentication strength to use for WHfB authentication
        $Authentication_Strength_Default_WHfB_Name_CFG = $configData.Authentication_Strength_Default_WHfB_Name

        # Get the default name of Named Location for Denied Countries
        $Named_Location_Denied_Countries_CFG = $configData.Named_Locations_Denied_Countries_Name

        # Get the administrative units for CA Groups
        $AdministrativeUnits_CA_TargetGroups_CFG = $configData.AdministrativeUnits_CA_TargetGroups
        $AdministrativeUnits_CA_PilotGroups_CFG = $configData.AdministrativeUnits_CA_PilotGroups
        $AdministrativeUnits_CA_ExcludeGroups_CFG = $configData.AdministrativeUnits_CA_ExcludeGroups

        Write-host ""
        Write-host "Group Targeting Method            : $($Group_Targeting_Method)"

        Write-host ""
        Write-host "Authentication_Strength_FIDO_Name : $($Authentication_Strength_Default_FIDO_Name_CFG)"

        Write-host ""
        Write-host "Authentication_Strength_WHfB_Name : $($Authentication_Strength_Default_WHfB_Name_CFG)"

        Write-host ""
        Write-host "Named Location Denied_Countries   : $($Named_Location_Denied_Countries_CFG)"


    ###############################################
    # Get data from LOCKED CONFIG-file
    ###############################################

        # Set the path to the custom config file
        $configFilePath = "$($global:PathScripts)\DATA\Entra_Policy_Suite_locked.config"

        # Check if the config file exists
        if (-Not (Test-Path $configFilePath)) {
            Write-host ""
            Write-host "Entra_Policy_Suite_locked.config was not found in the DATA directory. Terminating !" -ForegroundColor DarkYellow
            break
        }

        # Read the config file
        $configData = Get-Content $configFilePath | ConvertFrom-Json

        # Get the Target Groups for Dynamic Assignment
        $Target_Groups_Dynamic_Assignment_CFG = $configData.Target_Groups_Dynamic_Assignment

        # Get the Target Groups for Manual Assignment
        $Target_Groups_Manual_Assignment_CFG = $configData.Target_Groups_Manual_Assignment


########################################################################################################################################
# Step 2: CREATE CRITICAL CONFIGURATIONS, IF MISSING (BREAK GLASS ACCOUNTS, TARGET GROUPS, NAMED LOCATION, ETC)
########################################################################################################################################

    Write-host ""
    Write-host "Step 2: Create Critical Configurations (if missing)"

    # Build Entra ID Groups as Hashtable
    $EntraGroupsHashTable = EntraGroupsAsHashtable

    #######################################################
    # Create Break Class Accounts Group, if missing
    #######################################################

        Write-host ""
        Write-host "  Break Glass Accounts"

        $BreakGlassAccountsGroup = EntraGroup -DisplayName "Entra-CA-BreakGlassAccounts-All-Dynamic" `
                                              -EntraGroupsHashTable $EntraGroupsHashTable `
                                              -Description "All Break Glass Accounts" `
                                              -AutomaticMailNickName `
                                              -MailEnabled $false `
                                              -SecurityEnabled $true `
                                              -MembershipRuleProcessingState On `
                                              -GroupType DynamicMembership `
                                              -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute6 -in ["Break_Glass_Account"])'
        If ($BreakGlassAccountsGroup)
            {
                $BreakGlassAccountsGroup
                $Policy_BreakGlassAccount_Group_DisplayName = $BreakGlassAccountsGroup.DisplayName
            }
        Else
            {
                $BreakGlassAccountsGroup = EntraGroup -DisplayName "Entra-CA-BreakGlassAccounts-All-Dynamic" `
                                                      -EntraGroupsHashTable $EntraGroupsHashTable `
                                                      -Description "All Break Glass Accounts" `
                                                      -AutomaticMailNickName `
                                                      -MailEnabled $false `
                                                      -SecurityEnabled `
                                                      -MembershipRuleProcessingState On `
                                                      -GroupType DynamicMembership `
                                                      -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute6 -in ["Break_Glass_Account"])' `
                                                      -CreateOnly

                $BreakGlassAccountsGroup
                $Policy_BreakGlassAccount_Group_DisplayName = $BreakGlassAccountsGroup.DisplayName
            }


    #######################################################
    # Create Break Class Accounts, if missing
    #######################################################
        
        # Create Break Glass Accounts, only if missing !!

            ForEach ($User in $BreakGlassAccounts_CFG) {

                $GivenName = $User.UserPrincipalName.Split('@')[0]

                $BreakGlassPassword = Generate-SecurePassword -length 16

                EntraUser -DisplayName $User.DisplayName `
                          -UserPrincipalName $User.UserPrincipalName `
                          -MailNickname $GivenName `
                          -Password $BreakGlassPassword `
                          -GivenName $GivenName `
                          -Create
            }

        # Build Array of Break Glass Accounts

            $BreakGlassAccounts_MFA   = @()
            ForEach ($User in $BreakGlassAccounts_CFG_MFA) {
                $BreakGlassAccounts_MFA += EntraUser -UserPrincipalName $User.UserPrincipalName
            }

            $BreakGlassAccounts_FIDO  = @()
            ForEach ($User in $BreakGlassAccounts_CFG_FIDO) {
                $BreakGlassAccounts_FIDO += EntraUser -UserPrincipalName $User.UserPrincipalName
            }

            $BreakGlassAccounts       = @()
            ForEach ($User in $BreakGlassAccounts_CFG) {
                $BreakGlassAccounts += EntraUser -UserPrincipalName $User.UserPrincipalName
            }

            If ($BreakGlassAccounts)
               {
                  $BreakGlassAccounts | Select-Object DisplayName, UserPrincipalName
               }
            Else
               {
                  Break
               }


    #######################################################
    # Break Class Accounts Validation
    #######################################################

        BreakGlassValidation -BreakGlassAccountsGroup $BreakGlassAccountsGroup -BreakGlassAccounts $BreakGlassAccounts


    #######################################################
    # Create Authentication Strengths, if missing
    #######################################################

        Write-host ""
        Write-host "  Processing Authentication Strengths .... Pleae Wait "

        $Authentication_Strength_Default_WHfB_Name = EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_WHfB_Name_CFG -ViewOnly
        If (!($Authentication_Strength_Default_WHfB_Name))
            {
                # Create recommended authentication strength "WHfB + TAP"
                EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_WHfB_Name_CFG `
                                            -Description "Allow Windows Hello for Business (WHfB) + Temporary Access Password (one-time)" `
                                            -CreateOnly `
                                            -AllowedCombinations windowsHelloForBusiness, temporaryAccessPassOneTime `
                                            -PolicyType custom `
                                            -RequirementsSatisfied mfa

                $Authentication_Strength_Default_WHfB_Name = EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_WHfB_Name_CFG -ViewOnly
            }

        $Authentication_Strength_Default_FIDO_Name = EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_FIDO_Name_CFG -ViewOnly
        If (!($Authentication_Strength_Default_FIDO_Name))
            {
                # Create recommended authentication strength "FIDO Security Key & TAP"
                EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_FIDO_Name_CFG `
                                            -Description "Allow Feitian & Yubi FIDO keys and TAP for onboarding and recovery" `
                                            -CreateOnly `
                                            -AllowedCombinations fido2, temporaryAccessPassOneTime `
                                            -PolicyType custom `
                                            -RequirementsSatisfied mfa `
                                            -CombinationConfigurations @(
                                                                            @{
                                                                                "@odata.type" = "#microsoft.graph.fido2CombinationConfiguration"
                                                                                appliesToCombinations = @("fido2")
                                                                                allowedAAGUIDs = @("833b721a-ff5f-4d00-bb2e-bdda3ec01e29", `
                                                                                                   "ee041bce-25e5-4cdb-8f86-897fd6418464", `
                                                                                                   "310b2830-bd4a-4da5-832e-9a0dfc90abf2", `
                                                                                                   "77010bd7-212a-4fc9-b236-d2ca5e9d4084", `
                                                                                                   "b6ede29c-3772-412c-8a78-539c1f4c62d2", `
                                                                                                   "12ded745-4bed-47d4-abaa-e713f51d6393", `
                                                                                                   "3e22415d-7fdf-4ea4-8a0c-dd60c4249b9d", `
                                                                                                   "2c0df832-92de-4be1-8412-88a8f074df4a", `
                                                                                                   "8c97a730-3f7b-41a6-87d6-1e9b62bda6f0", `
                                                                                                   "c5ef55ff-ad9a-4b9f-b580-adebafe026d0", `
                                                                                                   "ee882879-721c-4913-9775-3dfcce97072a" `
                                                                                                  )
                                                                             }
                                                                        )

                $Authentication_Strength_Default_FIDO_Name = EntraAuthenticationStrength -PolicyName $Authentication_Strength_Default_FIDO_Name_CFG -ViewOnly
            }


    #######################################################
    # Create Named Location Denied Countries, if missing
    #######################################################

#region Named Location Syntax Help
    #######################################################
    # IP-based Named Location (SYNTAX)
    #######################################################

        <#
            EntraNamedLocation -ipNamedLocation `
                               -DisplayName "test location2" `
                               -ip4Range @("128.94.11.177/32") `
                               -ip6Range @() `
                               -isTrusted:$true
        #>


    #######################################################
    # Country-based Named Location (Syntax)
    #######################################################

        <#
            List of country codes (ISO) -> https://www.iso.org/iso-3166-country-codes.html

            Recommended Countries:
            AF (Afghanistan): Known for harboring cybercriminal activities.
            BY (Belarus): High levels of cyber espionage and hacking attempts.
            CN (China): Frequently implicated in state-sponsored cyber attacks.
            CU (Cuba): Known for cyber espionage activities.
            IR (Iran): State-sponsored cyber attacks and cyber espionage.
            KP (North Korea): Known for state-sponsored hacking groups.
            RU (Russia): High levels of cybercriminal activities and state-sponsored attacks.
            SY (Syria): Known for cyber espionage.
            UA (Ukraine): Certain regions have a high level of cyber attacks.
            VE (Venezuela): Known for cyber espionage activities.

            # Create new
                EntraNamedLocation -countryNamedLocation `
                                   -DisplayName "Denied Countries sign-ins" `
                                   -countriesAndRegions @("AF", "BY", "CN", "CU", "IR", "KP", "RU", "SY", "UA", "VE") `
                                   -includeUnknownCountriesAndRegions:$true `
                                   -isTrusted:$false `
                                   -countryLookupMethod "clientIpAddress" `
                                   -CreateOnly


            # Update existing
                EntraNamedLocation -countryNamedLocation `
                                   -DisplayName "Denied Countries sign-ins" `
                                   -countriesAndRegions @("AF", "BY", "CN", "CU", "IR", "KP", "RU", "SY", "UA", "VE") `
                                   -includeUnknownCountriesAndRegions:$false `
                                   -isTrusted:$false `
                                   -countryLookupMethod "clientIpAddress" `
                                   -ForceUpdate

 
             # Example usage:
                EntraNamedLocation -ListALL

                EntraNamedLocation -DisplayName "Office Network" -ip4Range "192.168.1.0/24" -isTrusted $true -ipNamedLocation -CreateOnly
                EntraNamedLocation -DisplayName "Office Network" -ip4Range "192.168.1.0/24" -isTrusted $true -ipNamedLocation -ForceUpdate
                EntraNamedLocation -DisplayName "Office Network"

                $Existing = EntraNamedLocation -DisplayName "Denied Countries sign-ins"
                $Existing | convertTo-Json -depth 5
                
        #>


#endregion

        Write-host ""
        Write-host "  Denied Countries (named location)"

        # Validating if Denied Countries Named Location exist !
        $DeniedCountriesNamedLocation = EntraNamedLocation -DisplayName $Named_Location_Denied_Countries_CFG
        If (!($DeniedCountriesNamedLocation))
            {
                EntraNamedLocation -countryNamedLocation `
                                    -DisplayName "Denied Countries sign-ins" `
                                    -countriesAndRegions @("AF", "BY", "CN", "CU", "IR", "KP", "RU", "SY", "UA", "VE") `
                                    -includeUnknownCountriesAndRegions:$true `
                                    -isTrusted:$false `
                                    -countryLookupMethod "clientIpAddress" `
                                    -Create

                $DeniedCountriesNamedLocation = EntraNamedLocation -DisplayName "Denied Countries sign-ins"
            }

    #######################################################
    # Create/Update Target Groups for CA Prod Policies
    #######################################################

        Write-host ""
        Write-host "  Target Groups for CA Prod Policies"

        # Rebuild Entra Groups as HashTable
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # create target groups used for "Dynamic_Using_Tags"
        if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

            ForEach ($Group in $Target_Groups_Dynamic_Assignment_CFG) {
                EntraGroup -DisplayName $Group.DisplayName `
                           -Description $Group.Description `
                           -EntraGroupsHashTable $EntraGroupsHashTable `
                           -AutomaticMailNickName `
                           -MailEnabled $false `
                           -SecurityEnabled $true `
                           -GroupType DynamicMembership `
                           -GroupQuery $Group.GroupQuery `
                           -MembershipRuleProcessingState On `
                           -ForceUpdate
            }
        }

        # create target groups used for "Manual_Assignment_Advanced" or "Manual_Assignment_Simple"
        elseif ( ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") -or ($Group_Targeting_Method -eq "Manual_Assignment_Simple") ) {

            ForEach ($Group in $Target_Groups_Manual_Assignment_CFG) {
                EntraGroup -DisplayName $Group.DisplayName `
                           -Description $Group.Description `
                           -EntraGroupsHashTable $EntraGroupsHashTable `
                           -AutomaticMailNickName `
                           -MailEnabled $false `
                           -SecurityEnabled $true `
                           -ForceUpdate
            }
        }


    #######################################################
    # Get target groups variables, based on Entra Group IDs
    #######################################################

    $EntraGroupsHashTable = EntraGroupsAsHashtable

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Initialize the array to store information about groups
        $groupDetailsArray = @()

        # Iterate through each group detail entry and populate variables dynamically
        foreach ($group in $Target_Groups_Dynamic_Assignment_CFG) {
    
            write-host "Processing variable $($group.VariableName)"

            Set-Variable -Name $group.VariableName -Value $EntraGroupsHashTable[$group.DisplayName]

            $groupInfo = $EntraGroupsHashTable[$group.DisplayName]

            If ($GroupInfo) {

                # Create custom object for each group
                $groupDetail = [PSCustomObject]@{
                    GroupId = $groupInfo.Id
                    DisplayName = $groupInfo.DisplayName
                    MembersCount = Check-GroupMembers $groupInfo.Id
                }
            }

            # Add the custom object to the array
            $groupDetailsArray += $groupDetail
        }
    }

    Elseif ( ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") -or ($Group_Targeting_Method -eq "Manual_Assignment_Simple") ) {

        # Initialize the array to store information about groups
        $groupDetailsArray = @()

        # Iterate through each group detail entry and populate variables dynamically
        foreach ($group in $Target_Groups_Manual_Assignment_CFG) {
    
            write-host "Processing variable $($group.VariableName)"

            Set-Variable -Name $group.VariableName -Value $EntraGroupsHashTable[$group.DisplayName]

            $groupInfo = $EntraGroupsHashTable[$group.DisplayName]

            If ($GroupInfo) {

                # Create custom object for each group
                $groupDetail = [PSCustomObject]@{
                    GroupId = $groupInfo.Id
                    DisplayName = $groupInfo.DisplayName
                    MembersCount = Check-GroupMembers $groupInfo.Id
                }
            }

            # Add the custom object to the array
            $groupDetailsArray += $groupDetail
        }
    }


################################################################################################
# Step 3: VALIDATE TARGET GROUPS HAVE MEMBERS
################################################################################################

Write-host ""
Write-host "Step 3: Validate Target Groups have members"

$Verify_List = @()

$Verify_List = $groupDetailsArray | Where-Object { $_.MembersCount -eq 0 }
If ($Verify_List.count -gt 0) {

    $Verify_List | Format-Table -AutoSize

    Write-host ""
    Write-host "Some Target groups have 0 members. Please verify this is true, before continuing !!"
    Write-host ""
    Write-host "If list looks correct, you may proceed to step #3"
    Write-host ""

    Break    
}

pause


################################################################################################
# Step 5A: DEMO - CONFIGURATION OF CA799 POLICY
################################################################################################

<#  DOCUMENTATION

    $MODE-values
        ROLLOUT LIFECYCLE:
         "Initial_Setup"                   =  Create policy in DISABLED state. It will create policy, even though a similar policy exists (same name) !
                                              Necessary groups including exclude group and pilot group will also be created
                                              By default the target will be set for PILOT1 target group, but policy is DISABLED
         "Pilot1"                          =  It will change targeting to PILOT1, typically a small group of 1-2 users + set state to REPORTING
         "Pilot2"                          =  It will change targeting to PILOT2, typically a smaller group of 5-10 users + set state to ENABLED
         "Pilot3"                          =  It will change targeting to PILOT3, typically a larger group of 30-50 users
         "Prod"                            =  It will change targeting to PROD, which will target the TARGET group defines in Include-Group

        MAINTENANCE:
         "GroupForceUpdate"                =  It will reset required groups back to PILOT1 state. It wil create goups if missing
         "Update_Prod_Policy_To_Latest"    =  It will update the latest policy settings into PROD policy (overwrite!!!)
         "Install_Latest_Policy_Disabled"  =  It will install latest configuration from the downloaded CAxxx.ps1 file from EPS repo.
                                              Policy will include VersionNumber in DisplayName. Policy will be in DISABLED state
         "Disable_Policy"                  =  It will DISABLE the policy


    TROUBLESHOOTING
    
        # Enable VERBOSE: 
        $VerbosePreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable VERBOSE: 
        $VerbosePreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

        # Enable DEBUG: 
        $DebugPreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable DEBUG: 
        $DebugPreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue
#>

    ################################################################################################
    # CA799 - Dynamic Assignment of Members of Entra Groups via Tagging on Users
    ################################################################################################

    # Initial setup - session time is 30 days
        $EntraGroupsHashTable = EntraGroupsAsHashtable
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Initial_Setup -Group_Targeting_Method Dynamic_Using_Tags

    #------------------------------------------------------------------------------------------------------

    # Change policy to 60 days
    EntraCAPolicy -CAPolicyPrefix "CA799-Initial" `
                  -SC_SignInFrequency_Value 60 `
                  -SC_SignInFrequency_Type "days" `
                  -SC_SignInFrequency_AuthenticationType "primaryAndSecondaryAuthentication" `
                  -SC_SignInFrequency_FrequencyInterval "timeBased" `
                  -SC_SignInFrequency_IsEnabled $true `
                  -CreateUpdate

    #------------------------------------------------------------------------------------------------------
    <# SAMPLES

        # CA003-Prod-Global-AllApps-AnyPlatform-LegacyAuthentication-ExchangeActiveSyncClients-Block
        EntraCAPolicy -CAPolicyPrefix "CA003-Initial" `
                      -DisplayName "CA003-Initial-Global-AllApps-AnyPlatform-LegacyAuthentication-ExchangeActiveSyncClients-Block" `
                      -Cond_Users_IncludeUsers @() `
                      -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                      -Cond_Users_ExcludeGroups @(($BreakGlassAccountsGroup.id), ($PolicyExcludeGroup.id)) `
                      -Cond_Users_ExcludeUsers @(($BreakGlassAccounts.id)) `
                      -Cond_App_includeApplications @("All") `
                      -Cond_ClientAppTypes @("exchangeActiveSync") `
                      -GC_Operator "OR" `
                      -GC_BuiltInControls @("Block") `
                      -State disabled `
                      -CreateOnly

        # CA155-Prod-Admins-External-AllApps-AnyPlatform-FIDO-Enforce
        EntraCAPolicy -CAPolicyPrefix "CA155-Initial" `
                      -DisplayName "CA155-Initial-Admins-External-AllApps-AnyPlatform-FIDO-Enforce" `
                      -Cond_Users_IncludeUsers @() `
                      -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                      -Cond_Users_ExcludeGroups @(($BreakGlassAccountsGroup.id), ($PolicyExcludeGroup.id)) `
                      -Cond_Users_ExcludeUsers @(($BreakGlassAccounts.id)) `
                      -Cond_App_includeApplications @("All") `
                      -GC_Operator "OR" `
                      -GC_BuiltInControls @() `
                      -GC_authenticationStrength "FIDO Security Key & TAP" `
                      -State disabled `
                      -CreateOnly

        # CA203-Prod-Users-Internal-Office365-MacOS-CompliantDevice-Enforce
        EntraCAPolicy -CAPolicyPrefix "CA203-Initial" `
                      -DisplayName "CA203-Initial-Users-Internal-Office365-MacOS-CompliantDevice-Enforce" `
                      -Cond_Users_IncludeUsers @() `
                      -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                      -Cond_Users_ExcludeGroups @(($BreakGlassAccountsGroup.id), ($PolicyExcludeGroup.id)) `
                      -Cond_Users_ExcludeUsers @(($BreakGlassAccounts.id)) `
                      -Cond_App_includeApplications @("Office365") `
                      -Cond_Platforms_includePlatforms @("macOS") `
                      -GC_Operator "OR" `
                      -GC_BuiltInControls "compliantDevice" `
                      -State disabled `
                      -CreateOnly
    #>

    #------------------------------------------------------------------------------------------------------

    # Staged Implementation (pilot 1-3 + prod) | Targeting method: Dynamic_Using_Tags'

        # PILOT1
        $EntraGroupsHashTable = EntraGroupsAsHashtable
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Pilot1 -Group_Targeting_Method Dynamic_Using_Tags

        # PILOT2
        $EntraGroupsHashTable = EntraGroupsAsHashtable
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Pilot2 -Group_Targeting_Method Dynamic_Using_Tags

        # PILOT3
        $EntraGroupsHashTable = EntraGroupsAsHashtable
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Pilot3 -Group_Targeting_Method Dynamic_Using_Tags

        # PROD
        $EntraGroupsHashTable = EntraGroupsAsHashtable
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Prod -Group_Targeting_Method Dynamic_Using_Tags

    # Disable Policy
        & "$($Path_CA_Scripts_Active)\ca799.ps1" -Mode Disable_Policy

    # Delete DEMO CA799 Policy
        $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
        $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject
        $ConditionalAccessPolicies_Scoped = $ConditionalAccessPolicies | Where-Object { $_.DisplayName -like "CA799*" }

        ForEach ($Policy in $ConditionalAccessPolicies_Scoped)
            {
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.id
            }



################################################################################################
# Step 5B: INITIAL SETUP OF RECOMMENDED POLICIES
################################################################################################

#Region Help
<#  DOCUMENTATION

    $MODE-values
        ROLLOUT LIFECYCLE:
            "Initial_Setup"                   =  Create policy in DISABLED state. It will create policy, even though a similar policy exists (same name) !
                                                 Necessary groups including exclude group and pilot group will also be created
                                                 By default the target will be set for PILOT1 target group, but policy is DISABLED
            "Pilot1"                          =  It will change targeting to PILOT1, typically a small group of 1-2 users + set state to REPORTING
            "Pilot2"                          =  It will change targeting to PILOT2, typically a smaller group of 5-10 users + set state to ENABLED
            "Pilot3"                          =  It will change targeting to PILOT3, typically a larger group of 30-50 users
            "Prod"                            =  It will change targeting to PROD, which will target the TARGET group defines in Include-Group

        MAINTENANCE:
            "GroupForceUpdate"                =  It will reset required groups back to PILOT1 state. It wil create goups if missing
            "Update_Prod_Policy_To_Latest"    =  It will update the latest policy settings into PROD policy (overwrite!!!)
            "Install_Latest_Policy_Disabled"  =  It will install latest configuration from the downloaded CAxxx.ps1 file from EPS repo.
                                                 Policy will include VersionNumber in DisplayName. Policy will be in DISABLED state
            "Disable_Policy"                  =  It will DISABLE the policy


    TROUBLESHOOTING
    
        # Enable VERBOSE: 
        $VerbosePreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable VERBOSE: 
        $VerbosePreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

        # Enable DEBUG: 
        $DebugPreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable DEBUG: 
        $DebugPreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue
#>
#EndRegion

<#
    # Rebuild Entra Groups as HashTable
    $EntraGroupsHashTable = EntraGroupsAsHashtable

    $PolicyScope = @(
        "CA000",
        "CA001",
        "CA002",
        "CA003",
        "CA004",
        "CA006",
        "CA007",
        "CA096",
        "CA097",
        "CA098",
        "CA099",
        "CA100",
        "CA101",
        "CA102",
        "CA103",
        "CA104",
        "CA105",
        "CA150",
        "CA151",
        "CA152",
        "CA153",
        "CA154",
        "CA155",
        "CA200",
        "CA201",
        "CA202",
        "CA203",
        "CA204",
        "CA205",
        "CA206",
        "CA207",
        "CA208",
        "CA209",
        "CA210",
        "CA211",
        "CA212",
        "CA250",
        "CA250",
        "CA251",
        "CA252",
        "CA253",
        "CA254",
        "CA255",
        "CA256",
        "CA257",
        "CA258",
        "CA259",
        "CA260",
        "CA261",
        "CA262",
        "CA300",
        "CA301",
        "CA302",
        "CA303",
        "CA304",
        "CA350",
        "CA351",
        "CA352",
        "CA353",
        "CA354",
        "CA355",
        "CA356",
        "CA357",
        "CA358",
        "CA359",
        "CA360",
        "CA361",
        "CA362",
        "CA400",
        "CA401",
        "CA402",
        "CA403",
        "CA404",
        "CA500",
        "CA501",
        "CA502",
        "CA503",
        "CA504",
        "CA505",
        "CA506",
        "CA507",
        "CA508",
        "CA509",
        "CA510",
        "CA540",
        "CA541",
        "CA542",
        "CA543",
        "CA544",
        "CA545",
        "CA546",
        "CA547",
        "CA548",
        "CA549",
        "CA550",
        "CA551",
        "CA552",
        "CA553",
        "CA554",
        "CA555",
        "CA556",
        "CA557",
        "CA558",
        "CA600",
        "CA601",
        "CA602",
        "CA603",
        "CA604",
        "CA605",
        "CA606",
        "CA750",
        "CA751",
        "CA752",
        "CA753",
        "CA754",
        "CA755",
        "CA756",
        "CA800"
    )

    ForEach ($PolicyNumber in $PolicyScope) {

        # Rebuild Entra Groups as HashTable
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        $Mode = "Initial_Setup"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"

        write-host "Group_Targeting_Method: $($Group_Targeting_Method)"
        write-host ""

        # Paths to use
        #  $Path_CA_Scripts_Active
        #  $Path_CA_Scripts_Github_Latest_Inbound

        & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

        write-host ""
        Write-host "Running this cmdlet:"
        write-host "`"$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1`" -Mode $($Mode) -Group_Targeting_Method $($Group_Targeting_Method)"
        write-host ""

        # Sleeping to let Entra sync-up !
        Start-Sleep -Seconds 5
    }
#>

###################################################################################################################
# Step 6: POLICIES THAT REQUIRE EXTRA CONFIGURATION, COMMUNICATION AND COULD REQUIRE EXCEPTIONS (MANUAL CREATION)
###################################################################################################################

<#  OPTIONAL CONFIGURATION & DECISIONS:

        DECISSION NEEDED DUE TO CONVENIENCE IMPACT (LOW):
           CA201-Users-Internal-AllApps-AnyPlatform-PersistentBrowser-Enforce (require re-authenticate in every browser sessions, when using SAML or tenant apps - https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime)
           CA212-Users-Internal-AllApps-AnyPlatform-SigninFrequency-Enforce (re-authenticate every 30 days)

        RECOMMENDATION - IMPLEMENT HIGHER SECURITY ON NON-MANAGED DEVICES (consider if some users needs to be excluded, before enabling)
           CA204-Users-Internal-AllApps-WindowsMacOS-UnmanagedDevices-SigninFrequency-Enforce (daily re-authentication from unmanaged Windows/Mac devices, like home computer)
           CA207-Users-Internal-Office365-AnyPlatform-Unmanaged-AppEnforcedRestrictions-BlockDownload (block Office 365 download from all unmanaged devices - https://learn.microsoft.com/en-gb/defender-cloud-apps/proxy-intro-aad#supported-apps-and-clients)

        DECISSION NEEDED DUE TO HIGH IMPACT:
           CA202-Users-Internal-Office365-Windows-CompliantDevice-Enforce (Office365 - require compliant device, otherwise block access device - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)
           CA252-Users-Internal-Developers-Office365-Windows-CompliantDevice-Enforce (Office365 - require compliant device, otherwise block access device - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)
           CA253-Users-Internal-Developers-Office365-MacOS-CompliantDevice-Enforce (Office365 - require compliant device, otherwise block access device - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)
           CA352-Users-External-Developers-Office365-Windows-CompliantDevice-Enforce (Office365 - require compliant device, otherwise block access device - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)
           CA353-Users-External-Developers-Office365-MacOS-CompliantDevice-Enforce (Office365 - require compliant device, otherwise block access device - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant)

        EXTRA CONFIGURATION NEEDED:
           CA208-Users-Internal-Office365-iOSAndroid-Unmanaged-RequireAppProtection (Require app protection policy on non-managed devices - Intune AppProtection policy must be assigned - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-app-protection-policy)
           CA209-Users-Internal-SelectedApps-AnyPlatform-Block (define which apps to block ? - App(s) must be added in CA209.ps1 file - replace -Cond_App_includeApplications @("None"))
           CA259-Users-Internal-Developers-SelectedApps-AnyPlatform-Block (define which apps to block ? - App(s) must be added in CA209.ps1 file - replace -Cond_App_includeApplications @("None"))
           CA304-Users-External-SelectedApps-AnyPlatform-Block (define which apps to block ? - App(s) must be added in CA209.ps1 file - replace -Cond_App_includeApplications @("None"))
           CA359-Users-External-Developers-SelectedApps-AnyPlatform-Block (define which apps to block ? - App(s) must be added in CA209.ps1 file - replace -Cond_App_includeApplications @("None"))
           CA404-Guests-SelectedApps-AnyPlatform-Block (define which apps to block ? - App(s) must be added in CA209.ps1 file - replace -Cond_App_includeApplications @("None"))

        SPECIAL FOR WORKLOAD PROTECTION:
        CA700-Prod-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block (this is a sample policy. Requirements are: Named location with PIPs of break-out IPs + ObjectID(s) of Apps
           Change DisplayName (CA700-Prod-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block)
           Change -Cond_Locations_ExcludeLocations @("051db179-a8d4-415d-8d65-e44c7f7b8f96") -> EntraNamedLocation -DisplayName "<Named location>" - example EntraNamedLocation -DisplayName "Denied Countries sign-ins"
           Change -Cond_ClientApp_includeServicePrincipals @("05bdd1ed-7245-462c-b7e1-e911261ecd71", "d6570a1a-a05b-4902-8af4-19cf846cb686", "067a8ff5-e3d4-4e67-a68c-12ba9daa8c7e")  <-- ObjectID(s) of Apps

#>
#region Parameter Help & Troubleshooting
<#  DOCUMENTATION

    $MODE-values
        ROLLOUT LIFECYCLE:
         "Initial_Setup"                   =  Create policy in DISABLED state. It will create policy, even though a similar policy exists (same name) !
                                              Necessary groups including exclude group and pilot group will also be created
                                              By default the target will be set for PILOT1 target group, but policy is DISABLED
         "Pilot1"                          =  It will change targeting to PILOT1, typically a small group of 1-2 users + set state to REPORTING
         "Pilot2"                          =  It will change targeting to PILOT2, typically a smaller group of 5-10 users + set state to ENABLED
         "Pilot3"                          =  It will change targeting to PILOT3, typically a larger group of 30-50 users
         "Prod"                            =  It will change targeting to PROD, which will target the TARGET group defines in Include-Group

        MAINTENANCE:
         "GroupForceUpdate"                =  It will reset required groups back to PILOT1 state. It wil create goups if missing
         "Update_Prod_Policy_To_Latest"    =  It will update the latest policy settings into PROD policy (overwrite!!!)
         "Install_Latest_Policy_Disabled"  =  It will install latest configuration from the downloaded CAxxx.ps1 file from EPS repo.
                                              Policy will include VersionNumber in DisplayName. Policy will be in DISABLED state
         "Disable_Policy"                  =  It will DISABLE the policy


    TROUBLESHOOTING
    
        # Enable VERBOSE: 
        $VerbosePreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable VERBOSE: 
        $VerbosePreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

        # Enable DEBUG: 
        $DebugPreference = "Continue"  # Stop, Inquire, Continue, SilentlyContinue

        # Disable DEBUG: 
        $DebugPreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

#>
#endregion

<#

    write-host "Group_Targeting_Method: $($Group_Targeting_Method)"
    write-host ""

    $PolicyNumber = "CA799"

    # Rebuild Entra Groups as HashTable
    $EntraGroupsHashTable = EntraGroupsAsHashtable

    $Mode = "Initial_Setup"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
    & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

    $Mode = "Pilot1"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
    & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

    $Mode = "Pilot2"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
    & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

    $Mode = "Pilot3"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
    & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

    $Mode = "prod"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
    & "$($Path_CA_Scripts_Active)\$($PolicyNumber).ps1" -Mode $Mode -Group_Targeting_Method $Group_Targeting_Method

#>

#####################################################################################################################
# OPTIONAL: REMOVE CA POLICIES
#####################################################################################################################


<#
    $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject
    $ConditionalAccessPolicies_Scoped = $ConditionalAccessPolicies | Where-Object { $_.DisplayName -like "*-initial*" }
#    $ConditionalAccessPolicies_Scoped = $ConditionalAccessPolicies | Where-Object { $_.DisplayName -notlike "*" }


    ForEach ($Policy in $ConditionalAccessPolicies_Scoped)
        {
            Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.id
        }

    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject
#>

###############################################################################
# Move any groups with naming Entra-CA-xxx and Entra-SSPR-xxx into the AUs
###############################################################################

        ########################################################################
        # Create AU, if missing
        ########################################################################

        # Get all administrative units and display their display names and IDs
        write-host "Get Entra Administrative Units including members ... Please Wait !"
        $AllAUs_Entra = Get-MgDirectoryAdministrativeUnit -All

        # create array with members of AUs
        $administrativeUnitsDetails = @()

        # Loop through each administrative unit to get members and build the array
        foreach ($au in $AllAUs_Entra) {
            # Fetch members of the administrative unit
            $members = @()
            try {
                $membersRaw = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
                foreach ($member in $membersRaw) {
                    $members += @{
                        DisplayName = $member.DisplayName
                        UserType = $member['@odata.type'] -replace '#microsoft.graph.', ''
                        Id = $member.Id
                    }
                }
            } catch {
                Write-Output "Error retrieving members for administrative unit $($au.DisplayName): $_"
            }

            # Create a custom object for the AU and add it to the array
            $auDetails = [PSCustomObject]@{
                Id = $au.Id
                DisplayName = $au.DisplayName
                Members = $members
            }
            $administrativeUnitsDetails += $auDetails
        }

        $AUs_All = @()
        $AUs_All += $AdministrativeUnits_CA_TargetGroups_CFG
        $AUs_All += $AdministrativeUnits_CA_ExcludeGroups_CFG
        $AUs_All += $AdministrativeUnits_CA_PilotGroups_CFG

        # Process AU $AdministrativeUnits_CA_TargetGroups_CFG
    
        ForEach ($AU in $AUs_All) {

            $AUInfo = $AllAUs_Entra | where-object { $_.DisplayName -eq $AU.DisplayName }

            If (!($AUInfo)) {

                # Create a new Administrative Unit
                $adminUnitParams = @{
                    DisplayName = $AU.DisplayName
                    Description = $AU.Description
                }

                # Using Microsoft Graph to create the Administrative Unit
                write-host ""
                Write-host "Creating Administrative Unit: $($newAdminUnit.DisplayName)"
                $newAdminUnit = New-MgDirectoryAdministrativeUnit -BodyParameter $adminUnitParams
            }
        }

        ########################################################################
        # Move Groups to AUs
        ########################################################################

        $EntraGroupsHashTable = EntraGroupsAsHashtable

        write-host "Getting All Groups from Entra ID ... Please Wait !"
        $AllGroups_Entra = Get-MgGroup -All

            ##################
            # Target Groups
            ##################

            $Entra_CA_TargetGroups_Placement = $AllGroups_Entra | Where-Object { ( ($_.DisplayName -like "Entra-CA-*") -and `
                                                                                   ($_.DisplayName -notLike "*-Excluded-Assignment") -and `
                                                                                   ($_.DisplayName -notLike "*-Pilot-*") ) -or `
                                                                               
                                                                                   ($_.DisplayName -Like "Entra-SSPR-*") `
                                                                               }

            $AUScope = $administrativeUnitsDetails | Where-Object { $_.DisplayName -eq $AdministrativeUnits_CA_TargetGroups_CFG.DisplayName }
            If ($AUScope) {

                ForEach ($Group in $Entra_CA_TargetGroups_Placement) {

                    If ($Group.Id -notin $AUScope.Members.id) {
                        Write-host "Moving $($Group.id) to AU $($AUScope.DisplayName)"

                        $params = @{
	                        "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.id)"
                        }

                        New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $AUScope.id -BodyParameter $params
                    }
                }
            }
        
            ##################
            # Exclude Groups
            ##################

            $Entra_CA_ExcludeGroups_Placement = $AllGroups_Entra | Where-Object { ($_.DisplayName -like "Entra-CA-*") -and `
                                                                                  ($_.DisplayName -Like "*-Excluded-Assignment") -and `
                                                                                  ($_.DisplayName -notLike "*-Pilot-*")
                                                                                }

            $AUScope = $administrativeUnitsDetails | Where-Object { $_.DisplayName -eq $AdministrativeUnits_CA_ExcludeGroups_CFG.DisplayName }
            If ($AUScope) {

                ForEach ($Group in $Entra_CA_ExcludeGroups_Placement) {

                    If ($Group.Id -notin $AUScope.Members.id) {
                        Write-host "Moving $($Group.id) to AU $($AUScope.DisplayName)"

                        $params = @{
	                        "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.id)"
                        }

                        New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $AUScope.id -BodyParameter $params
                    }
                }
            }

            ##################
            # Pilot Groups
            ##################
            $Entra_CA_PilotGroups_Placement = $AllGroups_Entra | Where-Object { ($_.DisplayName -like "Entra-CA-*") -and `
                                                                                ($_.DisplayName -notLike "*-Excluded-Assignment") -and `
                                                                                ($_.DisplayName -Like "*-Pilot-*")
                                                                              }

            $AUScope = $administrativeUnitsDetails | Where-Object { $_.DisplayName -eq $AdministrativeUnits_CA_ExcludeGroups_CFG.DisplayName }
            If ($AUScope) {

                ForEach ($Group in $Entra_CA_PilotGroups_Placement) {

                    If ($Group.Id -notin $AUScope.Members.id) {
                        Write-host "Moving $($Group.id) to AU $($AUScope.DisplayName)"

                        $params = @{
	                        "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.id)"
                        }

                        New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $AUScope.id -BodyParameter $params
                    }
                }
            }
