######################################################################################
# OUTPUT ENCODING  -  ALWAYS UTF-8
######################################################################################

<#  Everything this script emits is forced to UTF-8, on both Windows PowerShell 5.1
    and PowerShell 7, so Danish characters survive the trip to VisualCron.

    Why this is needed:
      PS 5.1 leaves [Console]::OutputEncoding at the OEM codepage (CP850 / CP865 in DK),
      so a name like Str<oe>b<ae>k goes out as bytes 9B / 91. Anything reading that stream
      as Windows-1252 renders it as  Str>b`k .  PS 7 already defaults to UTF-8, which is
      why the two versions disagreed.

    IMPORTANT - the receiving end must agree:
      Set the VisualCron Task > Main Settings > Encoding property to UTF-8 as well.
      Forcing UTF-8 here while VisualCron still decodes Windows-1252 will show
      Str<A-tilde><...>b<A-tilde><...>k instead. Both halves have to be UTF-8.

      If this runs as a VisualCron *PowerShell* Task (in-process runspace) rather than an
      *Execute* Task launching powershell.exe, there is no console to configure - the
      [Console] lines below fail silently and only the VisualCron Encoding property applies.
#>

    $global:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    # Console / stdout - what VisualCron captures
    Try { [Console]::OutputEncoding = $global:Utf8NoBom } Catch { }
    Try { [Console]::InputEncoding  = $global:Utf8NoBom } Catch { }

    # Encoding used when piping to native executables
    $global:OutputEncoding = $global:Utf8NoBom

    # File writes (Out-File, Set-Content, Export-Csv, Add-Content ...)
    # -Encoding UTF8 means WITH BOM on 5.1 but WITHOUT BOM on 7 - pin it so files are
    # detected as UTF-8 identically on both versions (BOM keeps Excel and Notepad happy).
    If ($PSVersionTable.PSVersion.Major -ge 6) {
        $PSDefaultParameterValues['*:Encoding'] = 'utf8BOM'
    } Else {
        $PSDefaultParameterValues['*:Encoding'] = 'UTF8'
    }

    Write-Verbose "PSVersion       -> $($PSVersionTable.PSVersion)"
    Write-Verbose "OutputEncoding  -> $([Console]::OutputEncoding.WebName)"

#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Tagging of Users in Entra ID based on type"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@2linkit.net | 40 178 179"
Write-Output "***********************************************************************************************"

<#  Automation-DefaultVariables.psm1

    #############################################################################
    # Entra Policy Suite | Extension Management
    #############################################################################

        $global:EntraPolicySuite_Tagging_User_AccountInfo               = "extensionAttribute5"
        $global:EntraPolicySuite_Tagging_User_Classification            = "extensionAttribute6"
        $global:EntraPolicySuite_Tagging_User_Authentication            = "extensionAttribute7"
        $global:EntraPolicySuite_Tagging_User_Pilot                     = "extensionAttribute8"
#>

#------------------------------------------------------------------------------------------------------------
# Loading Functions, Connectivity & Default variables
#------------------------------------------------------------------------------------------------------------
    $ScriptDirectory = $PSScriptRoot
    $global:PathScripts = Split-Path -parent $ScriptDirectory
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # Loading function modules (2LINKIT)
    Import-Module "$($global:PathScripts)\FUNCTIONS\2LINKIT-Functions.psm1" -Global -force  -WarningAction SilentlyContinue

    Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-ConnectDetails.psm1" -Global -force -WarningAction SilentlyContinue
    ConnectDetails
    
    Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-DefaultVariables.psm1" -Global -force -WarningAction SilentlyContinue
    Default_Variables

    # Connecting using modern authentication
    & "$($global:PathScripts)\FUNCTIONS\Connect_Azure.ps1"

    # Exchange Online
    Write-Output "Connecting to Exchange Online using High Privilege Account using Modern method (certificate)"
    Connect-ExchangeOnline -CertificateThumbprint $HighPriv_Modern_CertificateThumbprint_O365 -AppId $HighPriv_Modern_ApplicationID_O365 -ShowProgress $false -Organization $TenantNameOrganization -ShowBanner


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


######################################################################################################
# Entra Policy Suite Functions
######################################################################################################

    # Loading functions
    Import-Module "$($global:PathScripts)\FUNCTIONS\EntraPolicySuite.psm1" -Global -force -WarningAction SilentlyContinue


######################################################################################
## ENVIRONMENT (PARAMETER)
######################################################################################

    If ($args[0])
        {
            Write-Output "Arg -> $($args[0])"

            If ($args[0] -eq "Internal_Prod")
                {
                    $global:Environment              = "Internal_Prod"
                    $global:SecureCredentials        = $global:HighPriv_Legacy_SecureCredentials_Internal_Prod
                    $global:AD_LDAP_SearchBase_CN    = $global:AD_LDAP_SearchBase_Internal_Prod_CN
                    $global:AD_LDAP_SearchBase_OU    = $global:AD_LDAP_SearchBase_Internal_Prod_OU
                    $global:AD_Domain                = $global:AD_Domain_Internal_Prod 
                }
            ElseIf ($args[0] -eq "DMZ_Prod")
                {
                    $global:Environment              = "DMZ_Prod"
                    $global:SecureCredentials        = $global:HighPriv_Legacy_SecureCredentials_DMZ_Prod
                    $global:AD_LDAP_SearchBase_CN    = $global:AD_LDAP_SearchBase_DMZ_Prod_CN
                    $global:AD_LDAP_SearchBase_OU    = $global:AD_LDAP_SearchBase_DMZ_Prod_OU
                    $global:AD_Domain                = $global:AD_Domain_DMZ_Prod
                }
            ElseIf ($args[0] -eq "Internal_Dev")
                {
                    $global:Environment              = "Internal_Dev"
                    $global:SecureCredentials        = $global:HighPriv_Legacy_SecureCredentials_Internal_Dev
                    $global:AD_LDAP_SearchBase_CN    = $global:AD_LDAP_SearchBase_Internal_Dev_CN
                    $global:AD_LDAP_SearchBase_OU    = $global:AD_LDAP_SearchBase_Internal_Dev_OU
                    $global:AD_Domain                = $global:AD_Domain_Internal_Dev
                }
            ElseIf ($args[0] -eq "Internal_Test")
                {
                    $global:Environment              = "Internal_Test"
                    $global:SecureCredentials        = $global:HighPriv_Legacy_SecureCredentials_Internal_Test
                    $global:AD_LDAP_SearchBase_CN    = $global:AD_LDAP_SearchBase_Internal_Test_CN
                    $global:AD_LDAP_SearchBase_OU    = $global:AD_LDAP_SearchBase_Internal_Test_OU
                    $global:AD_Domain                = $global:AD_Domain_Internal_Test 
                }

        }
    Else
        {
            Write-Output ""
            Write-Output "Defaulting to INTERNAL_PROD environment ....."
            $global:Environment              = "Internal_Prod"
            $global:SecureCredentials        = $global:HighPriv_Legacy_SecureCredentials_Internal_Prod
            $global:AD_LDAP_SearchBase_CN    = $global:AD_LDAP_SearchBase_Internal_Prod_CN
            $global:AD_LDAP_SearchBase_OU    = $global:AD_LDAP_SearchBase_Internal_Prod_OU
            $global:AD_Domain                = $global:AD_Domain_Internal_Prod 
        }


#############################################################################################
# Main Program
#############################################################################################

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
<#
    $EntraID_Users_ALL_Scoped.Count
    $ExchangeUsers_ALL.Count
#>
    If ( ($EntraID_Users_ALL_Scoped.Count -eq 0) -or ($ExchangeUsers_ALL.Count -eq 0) )
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
    $Tag_Conditions = import-csv -Path "$($global:PathScripts)\DATA\Identity_Tagging.csv" -Delimiter ";" -Encoding UTF8

    $Tag_Conditions_AccountInfo = @()
    $Tag_Conditions_AccountInfo = import-csv -Path "$($global:PathScripts)\DATA\Identity_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

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
                                                                        ($_.UserPrincipalName -like "tho@*") }

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

Start-Transcript -Path "$($global:PathScripts)\OUTPUT\IdentityTagging_debug.log"

$Global:ModificationsLog = [System.Collections.ArrayList]@()
$Global:CompleteLog = [System.Collections.ArrayList]@()

write-host "Getting Tag Conditions from CSV-file ... Please Wait !"
$Tag_Conditions = import-csv -Path "$($global:PathScripts)\DATA\Identity_Tagging.csv" -Delimiter ";" -Encoding UTF8
$Tag_Conditions_AccountInfo = @()
$Tag_Conditions_AccountInfo = import-csv -Path "$($global:PathScripts)\DATA\Identity_Tagging_AccountInfo.csv" -Delimiter ";" -Encoding UTF8

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

#------------------------------------------------------------------------------------------------------------
# Building condition groups  (replaces Group-Object - see note below)
#------------------------------------------------------------------------------------------------------------

<#  IMPORTANT - do NOT replace this block with Group-Object !

    Group-Object behaves DIFFERENTLY between Windows PowerShell 5.1 and PowerShell 7:

      PS 5.1 : returns the groups in the order they first appear in the source  (= CSV row order)
      PS 7   : returns the groups SORTED alphabetically by the grouping properties

    This script is first-match-wins per TagType (see the '$TagTypes_String -notLike' check further down),
    so the ORDER of the groups decides which rule wins when a user matches more than one persona.

    Example - a guest matches BOTH the 'Guests' persona and the catch-all 'Exchange_Mailboxes' persona
    (RecipientTypeDetails 'GuestMailUser' is -NotLike 'UserMailbox'):

      PS 5.1 -> Guests (CSV row 127) is evaluated first   -> External_Guest / Guest_MFA
      PS 7   -> Exchange_Mailboxes sorts before Guests    -> Exchange_Cloud_GuestMailUser

    The same applies to Contacts, Teams_Rooms, FacilityAccess and any other persona that overlaps
    with the Exchange_Mailboxes catch-all, and it also flips the write order of the extensionAttributes
    (PS 7 sorts 'Authentication' before 'Classification').

    Secondly, PS 7's sort is UNSTABLE for rows with identical grouping keys, so it can also re-order
    the conditions INSIDE a group. That matters because $ModifiedTagValue is overwritten on every
    condition iteration - the '..._ModifiedTagValue_...' condition MUST be evaluated last, otherwise
    the value is reset to $null.

    The ordered hashtable below reproduces the Group-Object output shape (.Name / .Count / .Group),
    but preserves CSV order BETWEEN groups and INSIDE each group - identically on 5.1 and 7.
    [ordered]@{} is case-insensitive, which matches Group-Object's default behaviour.
#>

$Tag_Conditions_GroupTable = [ordered]@{}

foreach ($item in $Tag_Conditions_Fixed) {

    $GroupKey = "{0}|{1}|{2}|{3}|{4}" -f $item.Persona, `
                                         $item.TagType, `
                                         $item.TagValueAD, `
                                         $item.TagValueCloud, `
                                         $item.ConditionGroup

    If (-not $Tag_Conditions_GroupTable.Contains($GroupKey)) {
        $Tag_Conditions_GroupTable[$GroupKey] = [System.Collections.ArrayList]@()
    }

    $Result = $Tag_Conditions_GroupTable[$GroupKey].Add($item)
}

$Tag_Conditions_Array = @(
    foreach ($GroupKey in $Tag_Conditions_GroupTable.Keys) {
        [PSCustomObject]@{
            Name  = $GroupKey
            Count = $Tag_Conditions_GroupTable[$GroupKey].Count
            Group = $Tag_Conditions_GroupTable[$GroupKey]
        }
    }
)

write-host "Condition groups built (CSV/source order preserved) -> $($Tag_Conditions_Array.Count) groups"
write-verbose "PSVersion -> $($PSVersionTable.PSVersion)"


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
                        if ($global:EntraPolicySuite_Tagging_User_AccountInfo) {
                            $PropertyKeyAD    = $global:EntraPolicySuite_Tagging_User_AccountInfo
                            $PropertyKeyCloud = $global:EntraPolicySuite_Tagging_User_AccountInfo

                            $AccountInfoExtension = $global:EntraPolicySuite_Tagging_User_AccountInfo
                        } else {
                            $PropertyKeyAD    = "extensionAttribute5"
                            $PropertyKeyCloud = "extensionAttribute5"

                            $AccountInfoExtension = "extensionAttribute5"
                        }
                        break
                    }
                    "Classification" {
                        if ($global:EntraPolicySuite_Tagging_User_Classification) {
                            $PropertyKeyAD    = $global:EntraPolicySuite_Tagging_User_Classification
                            $PropertyKeyCloud = $global:EntraPolicySuite_Tagging_User_Classification

                            $ClassificationExtension = $global:EntraPolicySuite_Tagging_User_Classification
                        } else {
                            $PropertyKeyAD    = "extensionAttribute6"
                            $PropertyKeyCloud = "extensionAttribute6"

                            $ClassificationExtension = "extensionAttribute6"
                        }
                        break
                    }
                    "Authentication" {
                        if ($global:EntraPolicySuite_Tagging_User_Authentication) {
                            $PropertyKeyAD    = $global:EntraPolicySuite_Tagging_User_Authentication
                            $PropertyKeyCloud = $global:EntraPolicySuite_Tagging_User_Authentication

                            $AuthenticationExtension = $global:EntraPolicySuite_Tagging_User_Authentication
                        } else {
                            $PropertyKeyAD    = "extensionAttribute7"
                            $PropertyKeyCloud = "extensionAttribute7"

                            $AuthenticationExtension = "extensionAttribute7"
                        }
                        break
                    }
                    "Pilot" {
                        if ($global:EntraPolicySuite_Tagging_User_Pilot) {
                            $PropertyKeyAD    = $global:EntraPolicySuite_Tagging_User_Pilot
                            $PropertyKeyCloud = $global:EntraPolicySuite_Tagging_User_Pilot

                            $PilotExtension = $global:EntraPolicySuite_Tagging_User_Pilot
                        } else {
                            $PropertyKeyAD    = "extensionAttribute8"
                            $PropertyKeyCloud = "extensionAttribute8"

                            $PilotExtension = "extensionAttribute8"
                        }
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
            write-verbose "TagType_String -> $TagTypes_String"
            write-verbose "Tagtype -> $TagType"

            If ($TagTypes_String -notLike "*$($TagType)*") {
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
        $PropertyKeyAD     = $ClassificationExtension
        $PropertyKeyCloud  = $ClassificationExtension
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
        $PropertyKeyAD     = $AuthenticationExtension
        $PropertyKeyCloud  = $AuthenticationExtension
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

Stop-Transcript
