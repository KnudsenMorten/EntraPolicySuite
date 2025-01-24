########################################################################################################################################
# Policy Prefix         : CA700
# Policy Name           : CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block
# Policy Persona Target : WorkloadIdentities
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
    EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block-Excluded-Assigned" `
               -Description "Excluded Users for Policy CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
               -EntraGroupsHashTable $EntraGroupsHashTable `
               -AutomaticMailNickName `
               -MailEnabled $false `
               -SecurityEnabled $true `
               -GroupType Assigned `
               -CreateOnly

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {
        
        # Create pilot group, if missing
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" `
                   -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -GroupType DynamicMembership `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -startsWith "Workload_Identities") and (user.extensionAttribute8 -contains "_pilot1")' `
                   -MembershipRuleProcessingState On `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {
        foreach ($pilot in 1..3) {

            # Create pilot group, if missing
            EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot$pilot-Assigned" `
                       -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
                       -EntraGroupsHashTable $EntraGroupsHashTable `
                       -AutomaticMailNickName `
                       -MailEnabled $false `
                       -SecurityEnabled $true `
                       -CreateOnly
        }

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot1-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {
        foreach ($pilot in 1..3) {

            # Create pilot group, if missing
            EntraGroup -DisplayName "Entra-CA-WorkloadIdentities-Pilot$pilot-Assigned" `
                       -Description "Pilot Users for Entra-CA-WorkloadIdentities" `
                       -EntraGroupsHashTable $EntraGroupsHashTable `
                       -AutomaticMailNickName `
                       -MailEnabled $false `
                       -SecurityEnabled $true `
                       -CreateOnly
        }

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-WorkloadIdentities-Pilot1-Assigned"]
    }

    # Find group info in hash table
    $PolicyExcludeGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block-Excluded-Assigned"]

    # Configure initial policy - see policy documentation on https://github.com/KnudsenMorten/EntraPolicySuite
    EntraCAPolicy -CAPolicyPrefix "CA700-Initial" `
                  -DisplayName "CA700-Initial-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
                  -Cond_Users_IncludeUsers @("None") `
                  -Cond_Users_IncludeGroups @() `
                  -Cond_App_includeApplications @("All") `
                  -Cond_Locations_IncludeLocations @("All") `
                  -Cond_Locations_ExcludeLocations @("051db179-a8d4-415d-8d65-e44c7f7b8f96") `
                  -Cond_ClientApp_includeServicePrincipals @("05bdd1ed-7245-462c-b7e1-e911261ecd71", "d6570a1a-a05b-4902-8af4-19cf846cb686", "067a8ff5-e3d4-4e67-a68c-12ba9daa8c7e") `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls "block" `
                  -State disabled `
                  -CreateOnly
}

########################################
# Implementation Stage 1: Pilot 1
########################################
elseif ($Mode -eq "Pilot1") {

    if ($Group_Targeting_Method -eq "Dynamic_Using_Tags") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -startsWith "Workload_Identities") and (user.extensionAttribute8 -contains "_pilot1")' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot1-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot1-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-WorkloadIdentities-Pilot1-Assigned" `
                   -Description "Pilot Users for Entra-CA-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-WorkloadIdentities-Pilot1-Assigned"]
    }

    # Change to pilot 1 configuration, look for any stages using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA700-Initial", "CA700-Pilot1", "CA700-Pilot2", "CA700-Pilot3", "CA700-Prod") `
                  -DisplayName "CA700-Pilot1-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
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
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -startsWith "Workload_Identities") and ((user.extensionAttribute8 -contains "_pilot1") or (user.extensionAttribute8 -contains "_pilot2"))' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot2-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot2-Assigned"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-WorkloadIdentities-Pilot2-Assigned" `
                   -Description "Pilot Users for Entra-CA-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-WorkloadIdentities-Pilot2-Assigned"]
    }

    # Change to pilot 2 configuration, look for any policies using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA700-Initial", "CA700-Pilot1", "CA700-Pilot2", "CA700-Pilot3", "CA700-Prod") `
                  -DisplayName "CA700-Pilot2-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
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
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" `
                   -GroupQuery '(user.accountEnabled -eq true) and (user.extensionAttribute8 -startsWith "Workload_Identities") and ((user.extensionAttribute8 -contains "_pilot1") or (user.extensionAttribute8 -contains "_pilot2") or (user.extensionAttribute8 -contains "_pilot3"))' `
                   -MembershipRuleProcessingState On `
                   -ForceUpdate

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic"]
    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Advanced") {
        
        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot3-Assigned" `
                   -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly
        
        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot3-Assigned"]

    }
    elseif ($Group_Targeting_Method -eq "Manual_Assignment_Simple") {

        # Create pilot target group, if missing
        EntraGroup -DisplayName "Entra-CA-WorkloadIdentities-Pilot3-Assigned" `
                   -Description "Pilot Users for Entra-CA-WorkloadIdentities" `
                   -EntraGroupsHashTable $EntraGroupsHashTable `
                   -AutomaticMailNickName `
                   -MailEnabled $false `
                   -SecurityEnabled $true `
                   -CreateOnly

        # Get all Entra Groups and build group info as hashTable, just in case that group was just created
        $EntraGroupsHashTable = EntraGroupsAsHashtable

        # Find group info in hash table
        $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-WorkloadIdentities-Pilot3-Assigned"]
    }

    # Change to pilot 3 configuration, look for any policies using prefix array
    EntraCAPolicy -CAPolicyPrefixArray @("CA700-Initial", "CA700-Pilot1", "CA700-Pilot2", "CA700-Pilot3", "CA700-Prod") `
                  -DisplayName "CA700-Pilot3-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
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
        EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" -GroupType DynamicMembership -MembershipRuleProcessingState Paused -ForceUpdate
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
    EntraCAPolicy -CAPolicyPrefixArray @("CA700-Initial", "CA700-Pilot1", "CA700-Pilot2", "CA700-Pilot3", "CA700-Prod") `
                  -DisplayName "CA700-Prod-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
                  -Cond_Users_IncludeUsers @("None") `
                  -Cond_Users_IncludeGroups @() `
                  -Cond_App_includeApplications @("All") `
                  -Cond_Locations_IncludeLocations @("All") `
                  -Cond_Locations_ExcludeLocations @("051db179-a8d4-415d-8d65-e44c7f7b8f96") `
                  -Cond_ClientApp_includeServicePrincipals @("05bdd1ed-7245-462c-b7e1-e911261ecd71", "d6570a1a-a05b-4902-8af4-19cf846cb686", "067a8ff5-e3d4-4e67-a68c-12ba9daa8c7e") `
                  -State enabled `
                  -CreateUpdate
}

#######################################################
# Maintenance: Install Latest Policy (state: Disabled)
#######################################################
elseif ($Mode -eq "Install_Latest_Policy_Disabled") {

    # Find group info in hash table
    $PolicyPilotGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic"]
    $PolicyExcludeGroup = $EntraGroupsHashTable["Entra-CA-CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block-Excluded-Assigned"]

    # Setup latest version of policy in disabled state. Policy will include PolicyVersion. Policy can be used for testing
    EntraCAPolicy -CAPolicyPrefix "CA700-$($PolicyVersion)" `
                  -DisplayName "CA700-$($PolicyVersion)-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
                  -Cond_Users_IncludeUsers @("None") `
                  -Cond_Users_IncludeGroups @() `
                  -Cond_App_includeApplications @("All") `
                  -Cond_Locations_IncludeLocations @("All") `
                  -Cond_Locations_ExcludeLocations @("051db179-a8d4-415d-8d65-e44c7f7b8f96") `
                  -Cond_ClientApp_includeServicePrincipals @("05bdd1ed-7245-462c-b7e1-e911261ecd71", "d6570a1a-a05b-4902-8af4-19cf846cb686", "067a8ff5-e3d4-4e67-a68c-12ba9daa8c7e") `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls "block" `
                  -State disabled `
                  -CreateOnly
}

#######################################################
# Maintenance: Update Prod Policy To Latest (overwrite)
#######################################################
elseif ($Mode -eq "Update_Prod_Policy_To_Latest") {

    # Update existing PROD policy with latest recommended configuration
    # WARNING: This command will overwrite critical configuration, but will not change the targetting of the group - or state (enabled, disabled, reporting)
    EntraCAPolicy -CAPolicyPrefix "CA700-Prod" `
                  -GC_Operator "OR" `
                  -GC_BuiltInControls "block" `
                  -CreateUpdate

}

#######################################################
# Maintenance: Group Force Update
#######################################################
elseif ($Mode -eq "GroupForceUpdate") {

    # Update group info, based on the defined parameters
    EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block-Excluded-Assigned" `
               -Description "Excluded Users for Policy CA700-WorkloadIdentities-Automation-2LINKIT-AnyPlatform-NonTrustedLocations-Block" `
               -EntraGroupsHashTable $EntraGroupsHashTable `
               -AutomaticMailNickName `
               -MailEnabled $false `
               -SecurityEnabled $true `
               -GroupType Assigned `
               -ForceUpdate

    # Update group info, based on the defined parameters
    EntraGroup -DisplayName "Entra-CA-CA700-WorkloadIdentities-Pilot-Dynamic" `
               -Description "Pilot Users for Entra-CA-CA700-WorkloadIdentities" `
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
    EntraCAPolicy -CAPolicyPrefixArray @("CA700-Initial", "CA700-Pilot1", "CA700-Pilot2", "CA700-Pilot3", "CA700-Prod") `
                  -State disabled `
                  -CreateUpdate
}
