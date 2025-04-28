#Requires -Version 5.0

<#
    .NAME
    Entra Policy Suite (EPS) | Tagging of Users

    .SYNOPSIS

    .NOTES
    
    .VERSION
    1.0
    
    .AUTHOR
    Morten Knudsen, Microsoft MVP - https://mortenknudsen.net

    .LICENSE
    Licensed under the MIT license.

    .PROJECTURI
    https://github.com/KnudsenMorten/EntraPolicySuite


    .WARRANTY
    Use at your own risk, no warranty given!
#>

########################################################################################################################################
# Entra Policy Suite Functions
########################################################################################################################################

# Define module name and fallback local file
$ModuleName = "EntraPolicySuite"
$FunctionFile = ".\EntraPolicySuite.psm1"

# Check if the module is already available
if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
    Write-Host ""
    Write-Host "EntraPolicySuite is not installed. Attempting to install from PowerShell Gallery..." -ForegroundColor Yellow

    try {
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "Module '$ModuleName' installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to install module '$ModuleName' from PowerShell Gallery." -ForegroundColor Red
        
        # Try to import from local fallback if available
        if (Test-Path $FunctionFile) {
            Write-Host "Attempting to load EntraPolicySuite.psm1 from local directory..." -ForegroundColor Yellow
            try {
                Import-Module $FunctionFile -Global -Force -WarningAction SilentlyContinue
                Write-Host "Local EntraPolicySuite.psm1 loaded successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to load local EntraPolicySuite.psm1. Terminating!" -ForegroundColor Red
                break
            }
        }
        else {
            Write-Host "Local EntraPolicySuite.psm1 not found. Cannot continue." -ForegroundColor Red
            break
        }
    }
}
else {
    # Module is already installed — import it
    Write-Host "Module '$ModuleName' is already installed. Importing..." -ForegroundColor Cyan
    try {
        Import-Module $ModuleName -Global -Force -WarningAction SilentlyContinue
        Write-Host "Module '$ModuleName' imported successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to import installed module '$ModuleName'!" -ForegroundColor Red
        break
    }
}

########################################################################################################################################
# Connectivity
########################################################################################################################################
<#
    # PreReq: Initial onboarding must have been completed (Entra-Public-Suite-Onboarding.ps1)

    # Microsoft Graph connect with AzApp & Secret
    Connect-MicrosoftGraphPS -AppId "xxxx" `
                             -AppSecret ""xxxx"" `
                             -TenantId "xxxx"

    # Microsoft Graph connect with AzApp & CertificateThumprint
    Connect-MicrosoftGraphPS -AppId "xxxx" `
                             -CertificateThumbprint "xxxx" `
                             -TenantId "xxxx"

    # Show Permissions in the current context
    Connect-MicrosoftGraphPS -ShowMgContextExpandScopes

    # Show context of current Microsoft Graph context
    Connect-MicrosoftGraphPS -ShowMgContext

    # Microsoft Graph connect with interactive login with the permission defined in the scopes
    $Scopes = @("User.ReadWrite.All",`
                "Group.ReadWrite.All",`
                "Policy.Read.All"
                "Policy.ReadWrite.ConditionalAccess"
                "Policy.ReadWrite.AuthenticationMethod"
               )

    Connect-MicrosoftGraphPS -Scopes $Scopes


    ############################################
    # Connectivity to Exchange
    ############################################

    Connect-ExchangeOnline -CertificateThumbprint "xxx" `
                           -AppId "xxxx" `
                           -ShowProgress $false `
                           -Organization "xxxx" `
                           -ShowBanner


    ############################################
    # Connectivity to AD
    ############################################

    VisualCron / Task Scheduler:
    <domain>\gMSA-AUTM-L1-T0$ - sample: myaddomain.local\gMSA-AUTM-L1-T0$

    Interactive login with Powershell ISE and PSExec:
    %~dp0\PsExec.exe -h -e -s -i "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

#>



######################################################################################################
# Documentation
######################################################################################################
<#
Classification | Extension6 | Type of User for Classification Purpose - used for targetting of licenses and policies
 Internal_User                                        Internal employee, user account
 Internal_Admin                                       Internal employee, admin account
 External_User                                        External, User
 External_Admin                                       External, Admin
 External_Guest                                       External, Guest
 Internal_User_Developer                              Internal employee, developer account
 External_User_Developer                              External employee, developer account
 AppSystem_Test_User                                  App & System Test User
 Service_Account                                      Service Account
 Shared_Mail_User                                     Shared Mail User (Exch User Maibox, but with shared usage)
 Teams_Room                                           Teams Room
 Shared_Device_User                                   Shared Device User
 Break_Glass_Account                                  Break Glass Account
 NonManaged_Cloud_User                                Cloud-only User in Entra ID (NonManaged)
 NonManaged_AD_Synced_User                            AD-synced User in Entra ID (NonManaged)
 Contact                                              Contact
 FacilityAccessOnly                                   Facility Access Only
 Exchange_LinkedMailBox                               Exchange, Linked Mailbox
 Exchange_SharedMailbox                               Exchange, Shared Mailbox
 Exchange_LegacyMailbox                               Exchange, Legacy Mailbox
 Exchange_RoomMailbox                                 Exchange, Room Mailbox
 Exchange_EquipmentMailbox                            Exchange, Equipment Mailbox
 Exchange_MailContact                                 Exchange, Mail Contact
 Exchange_MailUser                                    Exchange, Mail User
 Exchange_SystemAttendant                             Exchange, System Attendant
 Exchange_SystemMailbox                               Exchange, System Mailbox
 Exchange_MailForestContact                           Exchange, Mail Forest Contact
 Exchange_Contact                                     Exchange, Contact
 Exchange_ArbitrationMailBox                          Exchange, Arbitration Mailbox
 Exchange_DiscoveryMailBox                            Exchange, Discovery Mailbox
 Exchange_RemoteRoomMailbox                           Exchange, Remote Room Mailbox
 Exchange_RemoteSchedulingMailbox                     Exchange, Remote Scheduling Mailbox
 Exchange_RemoteSharedMailbox                         Exchange, Remote Shared Mailbox
 Exchange_TeamMailBox                                 Exchange, Team Mailbox

 -------------------------------------------------------------------------------------------------------------

AuthenticationMethod | Extension7 | Type of User for Authentication Purpose - used for Conditional Access

Users
 Internal_User_AD_Synced_MFA                          Internal User (AD-synced) with MFA
 Internal_User_Cloud_MFA                              Internal User (Cloud) with MFA
 External_User_AD_Synced_MFA                          External User (AD-synced) with MFA
 External_User_Cloud_MFA                              External User (Cloud) with MFA
 Internal_Developer_AD_Synced_MFA                     Internal User with developer role (AD-synced) with MFA
 Internal_Developer_Cloud_MFA                         Internal User with developer role (Cloud) with MFA
 External_Developer_AD_Synced_MFA                     Internal User with developer role (AD-synced) with MFA
 External_Developer_Cloud_MFA                         Internal User with developer role (Cloud) with MFA
 NonManaged_User_AD_Synced_Pwd                       Non-Managed User (AD-synced) with Userid & password + trusted location
 NonManaged_User_AD_Synced_MFA                       Non-Managed User (AD-synced) with MFA
 NonManaged_User_Cloud_Pwd                           Non-Managed User (Cloud) with Userid & password + trusted location
 NonManaged_User_Cloud_MFA                           Non-Managed User (Cloud) with MFA

Admin Accounts
 Internal_Admin_AD_Synced_MFA                         Internal Admin Account with Userid/password + MFA
 Internal_Admin_AD_Synced_FIDO                        Internal Admin, high priv Account with FIDO Security Key
 Internal_Admin_Cloud_MFA                             Internal Admin Account with Userid/password + MFA
 Internal_Admin_Cloud_FIDO                            Internal Admin, high priv Account with FIDO Security Key
 External_Admin_AD_Synced_MFA                         External Admin Account with Userid/password + MFA
 External_Admin_AD_Synced_FIDO                        External Admin, high priv Account with FIDO Security Key
 External_Admin_Cloud_MFA                             External Admin Account with Userid/password + MFA
 External_Admin_Cloud_FIDO                            External Admin, high priv Account with FIDO Security Key

App & System Test Users
 AppSystem_Test_User_AD_Synced_Pwd                    AD-synced User in Entra ID - no mailbox with Userid & password + trusted location
 AppSystem_Test_User_AD_Synced_MFA                    AD-synced User in Entra ID - no mailbox with Userid/password + MFA
 AppSystem_Test_User_AD_Synced_FIDO                   AD-synced User in Entra ID - no mailbox with FIDO
 AppSystem_Test_User_AD_Synced_WHfB                   AD-synced User in Entra ID - no mailbox with WHfB (pin)
 AppSystem_Test_User_Cloud_Pwd                        Cloud-only User in Entra ID - no mailbox with Userid & password + trusted location
 AppSystem_Test_User_Cloud_MFA                        Cloud-only User in Entra ID - no mailbox with Userid/password + MFA
 AppSystem_Test_User_Cloud_FIDO                       Cloud-only User in Entra ID - no mailbox with FIDO
 AppSystem_Test_User_Cloud_WHfB                       Cloud-only User in Entra ID - no mailbox with WHfB (pin)

Guest
 Guest_MFA                                            Guest with Userid/password + MFA

Teams Room
 Teams_Room_AD_Synced_Pwd                             Teams Room, cloud with Userid & password + trusted location
 Teams_Room_AD_Synced_MFA                             Teams Room, cloud with MFA
 Teams_Room_AD_Synced_FIDO                            Teams Room, cloud with FIDO Security Key 
 Teams_Room_AD_Synced_WHfB                            Teams Room, cloud with Windows Hello for Business (pin)
 Teams_Room_Cloud_Pwd                                 Teams Room, cloud with Userid & password + trusted location
 Teams_Room_Cloud_MFA                                 Teams Room, cloud with MFA
 Teams_Room_Cloud_FIDO                                Teams Room, cloud with FIDO Security Key 
 Teams_Room_Cloud_WHfB                                Teams Room, cloud with Windows Hello for Business (pin)

Shared device Users
 Shared_Device_User_AD_Synced_Pwd                     Shared device user, AD-synced with Userid & password + trusted location
 Shared_Device_User_AD_Synced_MFA                     Shared device user, AD-synced with MFA
 Shared_Device_User_AD_Synced_FIDO                    Shared device user, AD-synced with FIDO Security Key
 Shared_Device_User_AD_Synced_WHfB                    Shared device user, AD-synced with Windows Hello for Business (pin)
 Shared_Device_User_Cloud_Pwd                         Shared device user, Cloud with Userid & password + trusted location
 Shared_Device_User_Cloud_MFA                         Shared device user, Cloud with MFA
 Shared_Device_User_Cloud_FIDO                        Shared device user, Cloud with FIDO Security Key
 Shared_Device_User_Cloud_WHfB                        Shared device user, Cloud with Windows Hello for Business (pin)

Shared Mail User
 Shared_Mail_User_AD_Synced_FIDO                      Shared mail user, AD-synced with FIDO Security Key
 Shared_Mail_User_AD_Synced_Pwd                       Shared mail user, AD-synced with Userid & password + trusted location
 Shared_Mail_User_AD_Synced_WHfB                      Shared mail user, AD-synced with Windows Hello for Business (pin)
 Shared_Mail_User_AD_Synced_MFA                       Shared mail user, AD-synced with Userid/password + MFA
 Shared_Mail_User_Cloud_FIDO                          Shared mail user, Cloud with FIDO Security Key
 Shared_Mail_User_Cloud_Pwd                           Shared mail user, Cloud with Userid & password + trusted location
 Shared_Mail_User_Cloud_WHfB                          Shared mail user, Cloud with Windows Hello for Business (pin)
 Shared_Mail_User_Cloud_MFA                           Shared mail user, Cloud with Userid/password + MFA

Service Account
 Service_Account_AD_Synced_FIDO                       Service Account, AD-synced with FIDO Security Key
 Service_Account_AD_Synced_Pwd                        Service Account, AD-synced with Userid & password + trusted location
 Service_Account_AD_Synced_MFA                        Service Account, AD-synced with Userid & password + MFA
 Service_Account_Cloud_FIDO                           Service Account, Cloud with FIDO Security Key
 Service_Account_Cloud_Pwd                            Service Account, Cloud with Userid & password + trusted location
 Service_Account_Cloud_MFA                            Service Account, Cloud with Userid & password + MFA

Break Glass Account
 Break_Glass_Account_Cloud_MFA                        Break Glass Account, cloud with MFA
 Break_Glass_Account_Cloud_FIDO                       Break Glass Account, cloud with FIDO Security Key

No Sign-in
 Contact_NoSignin                                     No Sign-in, contacts
 FacilityAccess_NoSignin                              No Sign-in, facility access only

Exchange / Users / Shared Mailboxes
 Exchange_AD_Synced_LinkedMailbox_NoSignin            Exchange Linked Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_SharedMailbox_NoSignin            Exchange Shared Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_LegacyMailbox_NoSignin            Exchange Legacy Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_RoomMailbox_NoSignin              Exchange Room Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_EquipmentMailbox_NoSignin         Exchange Equipment Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_MailContact_NoSignin              Exchange Mail Contact (AD-synced) - no sign-in
 Exchange_AD_Synced_MailUser_NoSignin                 Exchange Mail User (AD-synced) - no sign-in
 Exchange_AD_Synced_SystemAttendantMailbox_NoSignin   Exchange SystemAttendance Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_SystemMailbox_NoSignin            Exchange System Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_MailForestContact_NoSignin        Exchange MailForestContact (AD-synced) - no sign-in
 Exchange_AD_Synced_Contact_NoSignin                  Exchange Contact (AD-synced) - no sign-in
 Exchange_AD_Synced_ArbitrationMailbox_NoSignin       Exchange Arbitration Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_DiscoveryMailbox_NoSignin         Exchange Discovery Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_RemoteRoomMailbox_NoSignin        Exchange Remote Room Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_RemoteEquipmentMailbox_NoSignin   Exchange Remote Equipment Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_RemoteSharedMailbox_NoSignin      Exchange Remote Shared Mailbox (AD-synced) - no sign-in
 Exchange_AD_Synced_TeamMailbox_NoSignin              Exchange Team Mailbox (AD-synced) - no sign-in
 Exchange_Cloud_LinkedMailbox_NoSignin                Exchange Linked Mailbox (Cloud) - no sign-in
 Exchange_Cloud_SharedMailbox_NoSignin                Exchange Shared Mailbox (Cloud) - no sign-in
 Exchange_Cloud_LegacyMailbox_NoSignin                Exchange Legacy Mailbox (Cloud) - no sign-in
 Exchange_Cloud_RoomMailbox_NoSignin                  Exchange Room Mailbox (Cloud) - no sign-in
 Exchange_Cloud_EquipmentMailbox_NoSignin             Exchange Equipment Mailbox (Cloud) - no sign-in
 Exchange_Cloud_MailContact_NoSignin                  Exchange Mail Contact (Cloud) - no sign-in
 Exchange_Cloud_MailUser_NoSignin                     Exchange Mail User (Cloud) - no sign-in
 Exchange_Cloud_SystemAttendantMailbox_NoSignin       Exchange SystemAttendance Mailbox (Cloud) - no sign-in
 Exchange_Cloud_SystemMailbox_NoSignin                Exchange System Mailbox (Cloud) - no sign-in
 Exchange_Cloud_MailForestContact_NoSignin            Exchange MailForestContact (Cloud) - no sign-in
 Exchange_Cloud_Contact_NoSignin                      Exchange Contact (Cloud) - no sign-in
 Exchange_Cloud_ArbitrationMailbox_NoSignin           Exchange Arbitration Mailbox (Cloud) - no sign-in
 Exchange_Cloud_DiscoveryMailbox_NoSignin             Exchange Discovery Mailbox (Cloud) - no sign-in
 Exchange_Cloud_RemoteRoomMailbox_NoSignin            Exchange Remote Room Mailbox (Cloud) - no sign-in
 Exchange_Cloud_RemoteEquipmentMailbox_NoSignin       Exchange Remote Equipment Mailbox (Cloud) - no sign-in
 Exchange_Cloud_RemoteSharedMailbox_NoSignin          Exchange Remote Shared Mailbox (Cloud) - no sign-in
 Exchange_Cloud_TeamMailbox_NoSignin                  Exchange Team Mailbox (Cloud) - no sign-in

#>


#############################################################################################
# Main Program
#############################################################################################

    # Set the path to the data file
    $DataFile = ".\Identity_Tagging.csv"

    # Check if the config file exists
    if (-Not (Test-Path $DataFilePath)) {
        Write-host ""
        Write-host "Identity_Tagging.csv was not found in current directory. Terminating !" -ForegroundColor DarkYellow
        break
    }

    # Set the path to the data file
    $DataFile = ".\Identity_Tagging_AccountInfo.csv"

    # Check if the config file exists
    if (-Not (Test-Path $DataFilePath)) {
        Write-host ""
        Write-host "Identity_Tagging_AccountInfo.csv was not found in current directory. Terminating !" -ForegroundColor DarkYellow
        break
    }


    write-host "Getting Exchange information ... Please Wait !"
    Try {
        $ExchangeUsers_ALL = Get-EXORecipient -PropertySet Minimum -ResultSize unlimited
    } 
    Catch {
        # Try again as it sometimes fails on first run, probably a bug in Get-EXORecipient
        Write-Output "Connecting to Exchange Online using High Privilege Account using Modern method (certificate)"
        Connect-ExchangeOnline -CertificateThumbprint $HighPriv_Modern_CertificateThumbprint_O365 -AppId $HighPriv_Modern_ApplicationID_O365 -ShowProgress $false -Organization $TenantNameOrganization -ShowBanner

        $ExchangeUsers_ALL = Get-EXORecipient -PropertySet Minimum -ResultSize unlimited
      }

    $ExchangeUsers_ALL_HashTable = [ordered]@{}
    $ExchangeUsers_ALL | ForEach-Object { $ExchangeUsers_ALL_HashTable.add($_.ExternalDirectoryObjectId,$_)}

    write-host "Getting Entra ID information ... Please Wait !"
    $EntraID_Users_ALL = Get-MgBetaUser -All
    $EntraID_Users_ALL_Scoped = $EntraID_Users_ALL | where-Object { ($_.DisplayName -ne "On-Premises Directory Synchronization Service Account") }

    # EXTRA CHECK | TERMINATE IF VARIABLES ARE EMPTY !!!
    If ( ($EntraID_Users_ALL_Scoped.Count -eq 0) -or ($Global:ExchangeUsers_ALL.Count -eq 0) )
        {
            Write-host "Exiting as there is a critical error .... Critical variable is empty !"
            Exit 1
        }

    # build hashtable of all Entra ID users
    $global:Entra_Users_HashTable = [ordered]@{}
    $EntraID_Users_ALL | ForEach-Object { $global:Entra_Users_HashTable.add($_.id,$_)}

    write-host "Getting All Groups from Entra ID ... Please Wait !"
    $AllGroups_Entra = Get-MgGroup -All

    write-host "Getting Tag Conditions from CSV-file ... Please Wait !"
    $Tag_Conditions = import-csv -Path ".\Identity_Tagging.csv" -Delimiter ";" -Encoding UTF8

    $Tag_Conditions_AccountInfo = @()
    $Tag_Conditions_AccountInfo = import-csv -Path ".\Identity_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

    # Remove empty lines
    If ($Tag_Conditions) {
        $Tag_Conditions = $Tag_Conditions | Where-Object { ($_.Persona -notlike "") -and ($_.Persona -ne $null) }
    }
    If ($Tag_Conditions_AccountInfo) {
        $Tag_Conditions_AccountInfo = $Tag_Conditions_AccountInfo | Where-Object { ($_.Persona -notlike "") -and ($_.Persona -ne $null) }
    }
    
    $Tag_Conditions_Array = @()
    $Tag_Conditions_Array += $Tag_Conditions
    $Tag_Conditions_Array += $Tag_Conditions_AccountInfo

    $Tag_Conditions_MemberOf = $Tag_Conditions_Array | Where-Object { ($_.ConditionType -like "*MemberOf*") }

    write-host "Scope Entra ID Group to check for members (MemberOf) ... Please Wait !"
    $Entra_MemberOf_Scope = $AllGroups_Entra | Where-Object { $_.DisplayName -in $Tag_Conditions_MemberOf.Target }

    write-host "Getting Group Members from Entra ID Groups in scope of MemberOf ... Please Wait !"

    # Initialize an empty array to store group and member information
    $Entra_Group_Members = [System.Collections.ArrayList]@()

    # Loop through each group and retrieve members
    foreach ($group in $Entra_MemberOf_Scope) {
        $members = Get-MgGroupMember -GroupId $group.Id -All
    
        # Create a custom object for each group with its members
        $groupInfo = [PSCustomObject]@{
            GroupName = $group.DisplayName
            Members   = $members
        }

        $Result = $Entra_Group_Members.add($groupInfo)
    }

    # build hashtable of all Entra ID groups
    $global:Entra_Groups_HashTable = [ordered]@{}
    $AllGroups_Entra | ForEach-Object { $global:Entra_Groups_HashTable.add($_.DisplayName,$_)}

    # build hashtable of all Entra ID group members
    $global:Entra_Group_Members_HashTable = [ordered]@{}
    $Entra_Group_Members | ForEach-Object { $global:Entra_Group_Members_HashTable.add($_.GroupName,$_)}

    #--------------
    # Getting All Groups from Active Directory ... Please Wait !

    $global:AD_Groups_HashTable = [ordered]@{}
    Try
        {
            $AllGroups_AD = Get-ADGroup -Filter * -ErrorAction SilentlyContinue
        }
    Catch
        {
        }

    If ($AllGroups_AD) {
        write-host "Scope AD Groups to check for members (MemberOf) ... Please Wait !"
        $AD_MemberOf_Scope = $AllGroups_AD | Where-Object { $_.Name -in $Tag_Conditions_MemberOf.Target }

        write-host "Getting Group Members from Active Directory Groups in scope of MemberOf ... Please Wait !"

        # Initialize an empty array to store group and member information
        $AD_Group_Members = [System.Collections.ArrayList]@()

        # Loop through each group and retrieve members
        foreach ($group in $AD_MemberOf_Scope) {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive |
                       Where-Object { $_.objectClass -eq 'user' } | `
                       ForEach-Object { Get-ADUser -Identity $_.DistinguishedName -Properties UserPrincipalName } |
                       Select-Object Name, UserPrincipalName
    
            # Create a custom object for each group with its members
            $groupInfo = [PSCustomObject]@{
                GroupName = $group.Name
                Members   = $members
            }
    
            # Add the group info to the final array
            $Result = $AD_Group_Members.add($groupInfo)
        }

        # build hashtable of all AD groups
											  
        $AllGroups_AD | ForEach-Object { $global:AD_Groups_HashTable.add($_.Name,$_)}

        # build hashtable of all AD group members
        $global:AD_Group_Members_HashTable = [ordered]@{}
        $AD_Group_Members | ForEach-Object { $global:AD_Group_Members_HashTable.add($_.GroupName,$_)}
    }
#########################################################################################################################

    # Set variable to true, if you only want to write-out the result and NOT apply the setting !! 
    # Setting to $false will enforce the properties to be updated on all users in scope

    $global:EnableWhatIf = $false

<#

    # Testing Only 

        $EntraID_Users_ALL_Scoped = $EntraID_Users_ALL | where-Object { ($_.DisplayName -ne "On-Premises Directory Synchronization Service Account") }


        $EntraID_Users_ALL_Scoped = $EntraID_Users_ALL | where-Object { ($_.DisplayName -ne "On-Premises Directory Synchronization Service Account") -and `
                                                                        ($_.UserPrincipalName -like "abkje*") }

        $EntraID_Users_ALL_Scoped = $EntraID_Users_ALL | Where-Object { ($_.UserPrincipalName -like "ev-x*") -or ($_.UserPrincipalName -like "anped*") -or ($_.UserPrincipalName -like "x-mowa*") }

        $EntraID_Users_ALL_Scoped = $EntraID_Users_ALL | Where-Object { $_.UserPrincipalName -like "invoices*" }

    # Troubeshooting

        # Enable Verbose
        $VerbosePreference = "Continue"

        # Disable Verbose
        $VerbosePreference = "SilentlyContinue"

        # Enable Debug
        $DebugPreference = "Continue"

        # Disable Debug
        $DebugPreference = "SilentlyContinue"

    #>

#########################################################################################################################

$Global:ModificationsLog = [System.Collections.ArrayList]@()
$Global:CompleteLog = [System.Collections.ArrayList]@()

write-host "Getting Tag Conditions from CSV-file ... Please Wait !"
$Tag_Conditions = import-csv -Path ".\Identity_Tagging.csv" -Delimiter ";" -Encoding UTF8
$Tag_Conditions_AccountInfo = @()
$Tag_Conditions_AccountInfo = import-csv -Path ".\Identity_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

# Remove empty lines
If ($Tag_Conditions) {
    $Tag_Conditions = $Tag_Conditions | Where-Object { ($_.Persona -notlike "") -and ($_.Persona -ne $null) }
}
If ($Tag_Conditions_AccountInfo) {
    $Tag_Conditions_AccountInfo = $Tag_Conditions_AccountInfo | Where-Object { ($_.Persona -notlike "") -and ($_.Persona -ne $null) }
}

$Tag_Conditions_Array = @()
$Tag_Conditions_Array += $Tag_Conditions
$Tag_Conditions_Array += $Tag_Conditions_AccountInfo

# Handle blank ConditionGroup and randomize a number & letters into ConditionGroup to solve blank ConditionGroup are not handled together !
$Tag_Conditions_Fixed = @()
foreach ($item in $Tag_Conditions_Array) {
    $newItem = $item.PSObject.Copy()  # Create a copy of the object
    if ([string]::IsNullOrEmpty($newItem.ConditionGroup)) {
        $newItem.ConditionGroup = Generate-RandomString  # Set random string if blank
    }
    $Tag_Conditions_Fixed += $newItem
}

$Tag_Conditions_Array = $Tag_Conditions_Fixed | Group-Object -Property Persona,TagType,TagValueAD,TagValueCloud,ConditionGroup
#################################################
# Loop
#################################################
$UsersTotal = $EntraID_Users_ALL_Scoped.count

$EntraID_Users_ALL_Scoped | ForEach-Object -Begin  {
        $i = 0
} -Process {
            
    # Default values
    $User = $_

    write-host ""
    write-host "Processing $($User.DisplayName) ($($User.UserPrincipalName))"

    # default
    $TagTypes = [System.Collections.ArrayList]@()

    # Getting values
    $OnPremisesSyncEnabled = $User.OnPremisesSyncEnabled

    # Check for an Exchange mailbox
    $MailboxInfo = $ExchangeUsers_ALL_HashTable[$User.Id]

    $LicenseAssignments = Get-MgUserLicenseDetail -UserId $User.id
    $TeamsRoom = $LicenseAssignments | Where-Object { $_.skuPartNumber -like "*Microsoft_Teams_Rooms_Pro*" }

    # Defining values
    foreach ($ConditionGroupArray in $Tag_Conditions_Array) {

        # default
        $UserConditionMet = [System.Collections.ArrayList]@()

        ForEach ($Condition in $ConditionGroupArray.group) {

                # Scoping
                switch ($Condition.TagType) {
                    "AccountInfo" {
                        $PropertyKeyAD     = "extensionAttribute5"
                        $PropertyKeyCloud  = "extensionAttribute5"
                        break
                    }								   
                    "Classification" {
                        $PropertyKeyAD     = "extensionAttribute6"
                        $PropertyKeyCloud  = "extensionAttribute6"
                        break
                    }
                    "Authentication" {
                        $PropertyKeyAD     = "extensionAttribute7"
                        $PropertyKeyCloud  = "extensionAttribute7"
                        break
                    }
                    "Pilot" {
                        $PropertyKeyAD     = "extensionAttribute8"
                        $PropertyKeyCloud  = "extensionAttribute8"
                        break
                    }
                }

                # Scoping
                $Persona          = $Condition[0].Persona
                $TagType          = $Condition[0].TagType
                $TagValueAD       = $Condition[0].TagValueAD
                $TagValueCloud    = $Condition[0].TagValueCloud
                $ConditionsType   = $Condition[0].ConditionType
                $Target           = $Condition.Target
                $ConditionGroup   = $Condition.ConditionGroup

                write-Debug ""
                Write-Debug "Persona        : $($Persona)"
                Write-Debug "TagType        : $($TagType)"
                Write-Debug "TagValueAD     : $($TagValueAD)"
                Write-Debug "TagValueCloud  : $($TagValueCloud)"
                Write-Debug "ConditionsType : $($ConditionsType)"
                Write-Debug "Target         : $($Target)"
                Write-Debug "ConditionGroup : $($ConditionGroup)"
                Write-Debug "MailBoxInfo    : $($MailBoxInfo)"
                Write-Debug "TeamsRoom      : $($TeamsRoom)"

                If ($Persona) {
                    $ConditionMet = CheckAccountConditions -User $User `
                                                           -Persona $Persona `
                                                           -TagType $TagType `
                                                           -TagValueAD $TagValueAD `
                                                           -TagValueCloud $TagValueCloud `
                                                           -ConditionsType $ConditionsType `
                                                           -ConditionGroup $ConditionGroup `
                                                           -Target $Target `
                                                           -OnPremisesSyncEnabled $OnPremisesSyncEnabled `
                                                           -MailBoxInfo $MailboxInfo `
                                                           -TeamsRoom $TeamsRoom
                    # take right variable
                    If ($ConditionMet[1]) {
                        $ModifiedTagValue = $ConditionMet[1]
                    } Else {
                        $ModifiedTagValue = $null
                    }
                    $ConditionMet     = $ConditionMet[0]

                    If ($ConditionGroup) {
                        Write-Verbose ""
                        write-Verbose "ConditionMet     : $($ConditionMet)"
                        $Result = $UserConditionMet.add($ConditionMet)
                        $UserConditionMet_String = ($UserConditionMet -join ",")
                        write-Verbose "UserConditionMet : $($UserConditionMet_String)"

                    } Else {
                        Write-Verbose ""
                        write-Verbose "ConditionMet     : $($ConditionMet)"
                        $UserConditionMet = [System.Collections.ArrayList]@()
                        $Result = $UserConditionMet.add($ConditionMet)
                        $UserConditionMet_String = ($UserConditionMet -join ",")
                        write-Verbose "UserConditionMet : $($UserConditionMet_String)"
                    }
                }
            }


        # write-host $UserConditionMet
        If ($UserConditionMet -contains $false) {

            # skip as one or more of the conditions are not TRUE
            write-verbose ""
            write-verbose "Skipping - Conditions check was completed, but FALSE values were detected !!"
        }
        Else {
            write-verbose ""
            write-verbose "SUCCESS - Conditions check completed .... Now checking if any value must be set or it exists already !"

            $TagTypes_String = ($TagTypes -join ",")
            write-verbose ""
            write-verbose $TagTypes_String

            If ($TagTypes_string -notLike "*$($TagType)*") {
                if ($ModifiedTagValue) {
                    $index = $ModifiedTagValue.IndexOf("_")

                    # If '_' is found, insert 'AD_Synced'
                    if ($index -ge 0) {
                        $TagValueAD = $ModifiedTagValue.Substring(0, $index + 1) + "AD_Synced_" + $ModifiedTagValue.Substring($index + 1)
                    } else {
                        # If '_' is not found, keep the original string
                        $TagValueAD = $ModifiedTagValue
                    }

                    # If '_' is found, insert 'AD_Synced'
                    if ($index -ge 0) {
                        $TagValueCloud = $ModifiedTagValue.Substring(0, $index + 1) + "Cloud_" + $ModifiedTagValue.Substring($index + 1)
                    } else {
                        # If '_' is not found, keep the original string
                        $TagValueCloud = $ModifiedTagValue
                    }
                }

                TagUserConditionsTrue -User $User `
                                      -PropertyKeyAD $PropertyKeyAD `
                                      -PropertyKeyCloud $PropertyKeyCloud `
                                      -TagValueAD $TagValueAD `
                                      -TagValueCloud $TagValueCloud `
                                      -OnPremisesSyncEnabled $OnPremisesSyncEnabled

                $Result = $TagTypes.add($TagType)
            }
        }
    }

    $TagTypes_String = ($TagTypes -join ",")
    write-verbose ""
    write-verbose $TagTypes_String

    If ($TagTypes_string -notLike "*Classification*") {

        # Script didn't find any conditions, setting user as non-managed user !
        $PropertyKeyAD     = "extensionAttribute6"
        $PropertyKeyCloud  = "extensionAttribute6"
        $TagValueAD        = "NonManaged_User_AD_Synced"
        $TagValueCloud     = "NonManaged_User_Cloud"

        TagUserConditionsTrue -User $User `
                              -PropertyKeyAD $PropertyKeyAD `
                              -PropertyKeyCloud $PropertyKeyCloud `
                              -TagValueAD $TagValueAD `
                              -TagValueCloud $TagValueCloud `
                              -OnPremisesSyncEnabled $OnPremisesSyncEnabled
    }

    If ($TagTypes_string -notLike "*Authentication*") {

        # Script didn't find any conditions, setting user as non-managed user !
        $PropertyKeyAD     = "extensionAttribute7"
        $PropertyKeyCloud  = "extensionAttribute7"
        $TagValueAD        = "NonManaged_User_AD_Synced_MFA"
        $TagValueCloud     = "NonManaged_User_Cloud_MFA"

        TagUserConditionsTrue -User $User `
                              -PropertyKeyAD $PropertyKeyAD `
                              -PropertyKeyCloud $PropertyKeyCloud `
                              -TagValueAD $TagValueAD `
                              -TagValueCloud $TagValueCloud `
                              -OnPremisesSyncEnabled $OnPremisesSyncEnabled
    }
    write-verbose ""
    write-verbose "---------------------------------------------------------------------------------------"


    # Increment the $i counter variable which is used to create the progress bar.
    $i = $i+1

    # Determine the completion percentage
    $Completed = ($i/$UsersTotal) * 100
    Write-Progress -Activity "Tagging Users" -Status "Progress:" -PercentComplete $Completed
    } -End {
        Write-Progress -Activity "Tagging Users" -Status "Ready" -Completed
}

