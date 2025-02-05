########################################################################################################################################
# Policy Prefix         : CA549
# Policy Name           : CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce
# Policy Persona Target : Teams-Rooms
# -------------------------------------------------------------------------------------------------------------------------------------
# PS Functions Lib      : EntraPolicySuite, developed by Microsoft MVP Morten Knudsen (blog: aka.ms/morten - mok@mortenknudsen.net)
# Github Repo           : https://github.com/KnudsenMorten/EntraPolicySuite
# -------------------------------------------------------------------------------------------------------------------------------------
# File Purpose          : This file act as a sub-file and is called from the EntraPolicySuite (EPS) main file using relevant parameters
#                         In case of features-changes in Entra, or new recommendations, will this file be updated and downloaded.
#                         All changes will be documented in the change log below and the version will be incremented
# -------------------------------------------------------------------------------------------------------------------------------------
# Policy Change Log     : v1.0 - Initial Version 
########################################################################################################################################

param(
    [ValidateSet("Update_Prod_Policy_To_Latest", "Install_Latest_Policy_Disabled", "Initial_Setup", "Pilot1", "Pilot2", "Pilot3", "Prod", "GroupForceUpdate", "Disable_Policy")]
    [string]$Mode,
    [ValidateSet("Manual_Assignment_Simple", "Manual_Assignment_Advanced", "Dynamic_Using_Tags")]
    [string]$Group_Targeting_Method
)

##################################
# Variables
##################################

$PolicyVersion = 'v1.0'


##################################
# Critical Config Checks (PreReq)
##################################

# Validation of critical variables contain information about Break Glass Accounts and Break Glass Accounts group
BreakGlassValidation -BreakGlassAccountsGroup $BreakGlassAccountsGroup -BreakGlassAccounts $BreakGlassAccounts

########################################
# Implementation Stage: Initial Setup
########################################
if ($Mode -eq "Initial_Setup") {

    # Create exclude group for policy, if missing
    EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce-Excluded-Assigned" `
               -Description "Excluded Users for Policy CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
               -EntraGroupsHashTable $EntraGroupsHashTable `
               -AutomaticMailNickName `
               -MailEnabled $false `
               -SecurityEnabled $true `
               -GroupType Assigned `
               -CreateOnly

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {
        
        # Create pilot group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" `
                   -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -GroupType DynamicMembership `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -in ["Teams_Room_Req_MFA_Pilot1"])' `
                   -MembershipRuleProcessingState On `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {
        foreach ($pilot in 1..3) {

            # Create pilot group, if missing
            EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot$pilot-Assigned" `
                       -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
                       -EntraGroupsHashTable $EntraGroupsHashTable `
                       -AutomaticMailNickName `
                       -MailEnabled $false `
                       -SecurityEnabled $true `
                       -CreateOnly
        }

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot1-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {
        foreach ($pilot in 1..3) {

            # Create pilot group, if missing
            EntraGroup -DisplayName "Entra-CA-Teams-Rooms-Pilot$pilot-Assigned" `
                       -Description "Pilot Users for Entra-CA-Teams-Rooms" `
                       -EntraGroupsHashTable $EntraGroupsHashTable `
                       -AutomaticMailNickName `
                       -MailEnabled $false `
                       -SecurityEnabled $true `
                       -CreateOnly
        }

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Pilot1-Assigned"]
    }

    # Find group info in hash table
    $PolicyExcludeGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce-Excluded-Assigned"]

    # Configure initial policy - see policy documentation on https://github.com/KnudsenMorten/EntraPolicySuite
    EntraCAPolicy -CAPolicyPrefix "CA549-Initial" `
                  -DisplayName "CA549-Initial-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                  -Cond_Users_ExcludeGroups @(($BreakGlassAccountsGroup.id), ($PolicyExcludeGroup.id)) `
                  -Cond_Users_ExcludeUsers @(($BreakGlassAccounts.id)) `
                  -Cond_App_includeApplications @("All") `
                  -Cond_Locations_IncludeLocations @("All") `
                  -Cond_Locations_excludeLocations @("AllTrusted") `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls @("mfa") `
                  -State disabled `
                  -CreateOnly
}

########################################
# Implementation Stage 1: Pilot 1
########################################
elseif ($Mode -eq "Pilot1") {

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -in ["Teams_Room_Req_MFA_Pilot1"])' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot1-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot1-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-Teams-Rooms-Pilot1-Assigned" `
                   -Description "Pilot Users for Entra-CA-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Pilot1-Assigned"]
    }

    # Change to pilot 1 configuration, look for any stages using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA549-Initial", "CA549-Pilot1", "CA549-Pilot2", "CA549-Pilot3", "CA549-Prod") `
                  -DisplayName "CA549-Pilot1-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                  -State enabledForReportingButNotEnforced `
                  -CreateUpdate
}

########################################
# Implementation Stage 2: Pilot 2
########################################
elseif ($Mode -eq "Pilot2") {

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -in ["Teams_Room_Req_MFA_Pilot1","Teams_Room_Req_MFA_Pilot2"])' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot2-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot2-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-Teams-Rooms-Pilot2-Assigned" `
                   -Description "Pilot Users for Entra-CA-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Pilot2-Assigned"]
    }

    # Change to pilot 2 configuration, look for any policies using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA549-Initial", "CA549-Pilot1", "CA549-Pilot2", "CA549-Pilot3", "CA549-Prod") `
                  -DisplayName "CA549-Pilot2-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                  -State enabled `
                  -CreateUpdate
}

########################################
# Implementation Stage 3: Pilot 3
########################################
elseif ($Mode -eq "Pilot3") {

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -in ["Teams_Room_Req_MFA_Pilot1","Teams_Room_Req_MFA_Pilot2","Teams_Room_Req_MFA_Pilot3"])' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {
        
        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot3-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly
        
        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot3-Assigned"]

    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-Teams-Rooms-Pilot3-Assigned" `
                   -Description "Pilot Users for Entra-CA-Teams-Rooms" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Pilot3-Assigned"]
    }

    # Change to pilot 3 configuration, look for any policies using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA549-Initial", "CA549-Pilot1", "CA549-Pilot2", "CA549-Pilot3", "CA549-Prod") `
                  -DisplayName "CA549-Pilot3-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                  -CreateUpdate
}

########################################
# Implementation Stage 4: Prod
########################################
elseif ($Mode -eq "Prod") {

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Find group info in hash table
        $ADConnect_All                 = $EntraGroupsHashTable["Entra-CA-ADConnect-Accounts-All-Dynamic"]

        $BreakGlassAccounts_All        = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-All-Dynamic"]
        $BreakGlassAccounts_MFA_All    = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-Req-MFA-All-Dynamic"]
        $BreakGlassAccounts_FIDO_All   = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-Req-FIDO-All-Dynamic"]

        $Admins_All                    = $EntraGroupsHashTable["Entra-CA-Admins-All-Dynamic"]
        $Admins_External_All           = $EntraGroupsHashTable["Entra-CA-Admins-External-All-Dynamic"]
        $Admins_External_MFA_All       = $EntraGroupsHashTable["Entra-CA-Admins-External-Req-MFA-All-Dynamic"]
        $Admins_External_FIDO_All      = $EntraGroupsHashTable["Entra-CA-Admins-External-Req-FIDO-All-Dynamic"]
        $Admins_Internal_All           = $EntraGroupsHashTable["Entra-CA-Admins-Internal-All-Dynamic"]
        $Admins_Internal_MFA_All       = $EntraGroupsHashTable["Entra-CA-Admins-Internal-Req-MFA-All-Dynamic"]
        $Admins_Internal_FIDO_All      = $EntraGroupsHashTable["Entra-CA-Admins-Internal-Req-FIDO-All-Dynamic"]

        $Guests_All                    = $EntraGroupsHashTable["Entra-CA-Guests-All-Dynamic"]
        $Guests_MFA_All                = $EntraGroupsHashTable["Entra-CA-Guests-Req-MFA-All-Dynamic"]

        $ServiceAccounts_All           = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-All-Dynamic"]
        $ServiceAccounts_Pwd_All       = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-Pwd-All-Dynamic"]
        $ServiceAccounts_FIDO_All      = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-FIDO-All-Dynamic"]
        $ServiceAccounts_MFA_All       = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-MFA-All-Dynamic"]

        $Shared_Device_Users_All       = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-All-Dynamic"]
        $Shared_Device_Users_Pwd_All   = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-Pwd-All-Dynamic"]
        $Shared_Device_Users_FIDO_All  = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-FIDO-All-Dynamic"]
        $Shared_Device_Users_WHfB_All  = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-WHfB-All-Dynamic"]
        $Shared_Device_Users_MFA_All   = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-MFA-All-Dynamic"]

        $Teams_Rooms_All               = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-All-Dynamic"]
        $Teams_Rooms_Pwd_All           = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-Pwd-All-Dynamic"]
        $Teams_Rooms_FIDO_All          = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-FIDO-All-Dynamic"]
        $Teams_Rooms_WHfB_All          = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-WHfB-All-Dynamic"]
        $Teams_Rooms_MFA_All           = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-MFA-All-Dynamic"]

        $Shared_Mail_Users_All         = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-All-Dynamic"]
        $Shared_Mail_Users_Pwd_All     = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-Pwd-All-Dynamic"]
        $Shared_Mail_Users_MFA_All     = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-MFA-All-Dynamic"]
        $Shared_Mail_Users_FIDO_All    = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-FIDO-All-Dynamic"]
        $Shared_Mail_Users_WHfB_All    = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-WHfB-All-Dynamic"]

        $AppSystem_Test_Users_All      = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-All-Dynamic"]
        $AppSystem_Test_Users_Pwd_All  = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-Pwd-All-Dynamic"]
        $AppSystem_Test_Users_MFA_All  = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-MFA-All-Dynamic"]
        $AppSystem_Test_Users_FIDO_All = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-FIDO-All-Dynamic"]
        $AppSystem_Test_Users_WHfB_All = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-WHfB-All-Dynamic"]

        $Users_All                     = $EntraGroupsHashTable["Entra-CA-Users-All-Dynamic"]
        $Users_Internal_All            = $EntraGroupsHashTable["Entra-CA-Users-Internal-All-Dynamic"]
        $Users_Internal_MFA_All        = $EntraGroupsHashTable["Entra-CA-Users-Internal-Req-MFA-All-Dynamic"]
        $Users_External_All            = $EntraGroupsHashTable["Entra-CA-Users-External-All-Dynamic"]
        $Users_External_MFA_All        = $EntraGroupsHashTable["Entra-CA-Users-External-Req-MFA-All-Dynamic"]
        $Users_Non_Managed_All         = $EntraGroupsHashTable["Entra-CA-Users-Non-Managed-All-Dynamic"]
        $Users_Non_Managed_MFA_All     = $EntraGroupsHashTable["Entra-CA-Users-Non-Managed-Req-MFA-All-Dynamic"]

        # Pause Dynamic Membership Rule Processing
        EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" -GroupType DynamicMembership -MembershipRuleProcessingState Paused -ForceUpdate
    }

    if ( ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") -or ($Group_Targeting_Method -eq "Manual_Assignment_Simple") ) {

        # Find group info in hash table
        $ADConnect_All                 = $EntraGroupsHashTable["Entra-CA-ADConnect-Accounts-All-Assigned"]

        $BreakGlassAccounts_All        = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-All-Assigned"]
        $BreakGlassAccounts_MFA_All    = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-Req-MFA-All-Assigned"]
        $BreakGlassAccounts_FIDO_All   = $EntraGroupsHashTable["Entra-CA-BreakGlassAccounts-Req-FIDO-All-Assigned"]

        $Admins_All                    = $EntraGroupsHashTable["Entra-CA-Admins-All-Assigned"]
        $Admins_External_All           = $EntraGroupsHashTable["Entra-CA-Admins-External-All-Assigned"]
        $Admins_External_MFA_All       = $EntraGroupsHashTable["Entra-CA-Admins-External-Req-MFA-All-Assigned"]
        $Admins_External_FIDO_All      = $EntraGroupsHashTable["Entra-CA-Admins-External-Req-FIDO-All-Assigned"]
        $Admins_Internal_All           = $EntraGroupsHashTable["Entra-CA-Admins-Internal-All-Assigned"]
        $Admins_Internal_MFA_All       = $EntraGroupsHashTable["Entra-CA-Admins-Internal-Req-MFA-All-Assigned"]
        $Admins_Internal_FIDO_All      = $EntraGroupsHashTable["Entra-CA-Admins-Internal-Req-FIDO-All-Assigned"]

        $Guests_All                    = $EntraGroupsHashTable["Entra-CA-Guests-All-Assigned"]
        $Guests_MFA_All                = $EntraGroupsHashTable["Entra-CA-Guests-Req-MFA-All-Assigned"]

        $ServiceAccounts_All           = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-All-Assigned"]
        $ServiceAccounts_Pwd_All       = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-Pwd-All-Assigned"]
        $ServiceAccounts_FIDO_All      = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-FIDO-All-Assigned"]
        $ServiceAccounts_MFA_All       = $EntraGroupsHashTable["Entra-CA-ServiceAccounts-Req-MFA-All-Assigned"]

        $Shared_Device_Users_All       = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-All-Assigned"]
        $Shared_Device_Users_Pwd_All   = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-Pwd-All-Assigned"]
        $Shared_Device_Users_FIDO_All  = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-FIDO-All-Assigned"]
        $Shared_Device_Users_WHfB_All  = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-WHfB-All-Assigned"]
        $Shared_Device_Users_MFA_All   = $EntraGroupsHashTable["Entra-CA-Shared-Device-Users-Req-MFA-All-Assigned"]

        $Teams_Rooms_All               = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-All-Assigned"]
        $Teams_Rooms_Pwd_All           = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-Pwd-All-Assigned"]
        $Teams_Rooms_FIDO_All          = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-FIDO-All-Assigned"]
        $Teams_Rooms_WHfB_All          = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-WHfB-All-Assigned"]
        $Teams_Rooms_MFA_All           = $EntraGroupsHashTable["Entra-CA-Teams-Rooms-Req-MFA-All-Assigned"]

        $Shared_Mail_Users_All         = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-All-Assigned"]
        $Shared_Mail_Users_Pwd_All     = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-Pwd-All-Assigned"]
        $Shared_Mail_Users_MFA_All     = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-MFA-All-Assigned"]
        $Shared_Mail_Users_FIDO_All    = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-FIDO-All-Assigned"]
        $Shared_Mail_Users_WHfB_All    = $EntraGroupsHashTable["Entra-CA-Shared-Mail-Users-Req-WHfB-All-Assigned"]

        $AppSystem_Test_Users_All      = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-All-Assigned"]
        $AppSystem_Test_Users_Pwd_All  = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-Pwd-All-Assigned"]
        $AppSystem_Test_Users_MFA_All  = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-MFA-All-Assigned"]
        $AppSystem_Test_Users_FIDO_All = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-FIDO-All-Assigned"]
        $AppSystem_Test_Users_WHfB_All = $EntraGroupsHashTable["Entra-CA-AppSystem-Test-Users-Req-WHfB-All-Assigned"]

        $Users_All                     = $EntraGroupsHashTable["Entra-CA-Users-All-Assigned"]
        $Users_Internal_All            = $EntraGroupsHashTable["Entra-CA-Users-Internal-All-Assigned"]
        $Users_Internal_MFA_All        = $EntraGroupsHashTable["Entra-CA-Users-Internal-Req-MFA-All-Assigned"]
        $Users_External_All            = $EntraGroupsHashTable["Entra-CA-Users-External-All-Assigned"]
        $Users_External_MFA_All        = $EntraGroupsHashTable["Entra-CA-Users-External-Req-MFA-All-Assigned"]
        $Users_Non_Managed_All         = $EntraGroupsHashTable["Entra-CA-Users-Non-Managed-All-Assigned"]
        $Users_Non_Managed_MFA_All     = $EntraGroupsHashTable["Entra-CA-Users-Non-Managed-Req-MFA-All-Assigned"]
    }

    # Enforce Conditional Access Policy
    EntraCAPolicy -CAPolicyPrefixArray @("CA549-Initial", "CA549-Pilot1", "CA549-Pilot2", "CA549-Pilot3", "CA549-Prod") `
                  -DisplayName "CA549-Prod-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($Teams_Rooms_MFA_All.id)) `
                  -State enabled `
                  -CreateUpdate
}

#######################################################
# Maintenance: Install Latest Policy (state: Disabled)
#######################################################
elseif ($Mode -eq "Install_Latest_Policy_Disabled") {

    # Find group info in hash table
    $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic"]
    $PolicyExcludeGroup = $EntraGroupsHashTable["Entra-CA-CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce-Excluded-Assigned"]

    # Setup latest version of policy in disabled state. Policy will include PolicyVersion. Policy can be used for testing
    EntraCAPolicy -CAPolicyPrefix "CA549-$($PolicyVersion)" `
                  -DisplayName "CA549-$($PolicyVersion)-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
                  -Cond_Users_IncludeUsers @() `
                  -Cond_Users_IncludeGroups @(($PolicyPilotGroup.id)) `
                  -Cond_Users_ExcludeGroups @(($BreakGlassAccountsGroup.id), ($PolicyExcludeGroup.id)) `
                  -Cond_Users_ExcludeUsers @(($BreakGlassAccounts.id)) `
                  -Cond_App_includeApplications @("All") `
                  -Cond_Locations_IncludeLocations @("All") `
                  -Cond_Locations_excludeLocations @("AllTrusted") `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls @("mfa") `
                  -State disabled `
                  -CreateOnly
}

#######################################################
# Maintenance: Update Prod Policy To Latest (overwrite)
#######################################################
elseif ($Mode -eq "Update_Prod_Policy_To_Latest") {

    # Update existing PROD policy with latest recommended configuration
    # WARNING: This command will overwrite critical configuration, but will not change the targetting of the group - or state (enabled, disabled, reporting)
    EntraCAPolicy -CAPolicyPrefix "CA549-Prod" `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls @("mfa") `
                  -CreateUpdate

}

#######################################################
# Maintenance: Group Force Update
#######################################################
elseif ($Mode -eq "GroupForceUpdate") {

    # Update group info, based on the defined parameters
    EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce-Excluded-Assigned" `
               -Description "Excluded Users for Policy CA549-Teams-Rooms-AllApps-TrustedLocations-MFA-Enforce" `
               -EntraGroupsHashTable $EntraGroupsHashTable `
               -AutomaticMailNickName `
               -MailEnabled $false `
               -SecurityEnabled $true `
               -GroupType Assigned `
               -ForceUpdate

    # Update group info, based on the defined parameters
    EntraGroup -DisplayName "Entra-CA-CA549-Teams-Rooms-Pilot-Dynamic" `
               -Description "Pilot Users for Entra-CA-CA549-Teams-Rooms" `
               -EntraGroupsHashTable $EntraGroupsHashTable `
               -AutomaticMailNickName `
               -MailEnabled $false `
               -SecurityEnabled $true `
               -GroupType DynamicMembership `
               -GroupQuery '$DynamicPilotQuery1' `
               -MembershipRuleProcessingState On `
               -ForceUpdate
}

#######################################################
# Disable policy
#######################################################
elseif ($Mode -eq "Disable_Policy") {

    # Disable policy found by looking for policies defined in prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA549-Initial", "CA549-Pilot1", "CA549-Pilot2", "CA549-Pilot3", "CA549-Prod") `
                  -State disabled `
                  -CreateUpdate
}
