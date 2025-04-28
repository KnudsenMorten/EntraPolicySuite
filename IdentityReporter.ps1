#Requires -Version 5.0

<#
    .NAME
    Entra Policy Suite (EPS) | Identity Reporting

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

    # Set the path to the custom config file
    $FunctionFile = ".\EntraPolicySuite.psm1"

    # Check if the config file exists
    if (-Not (Test-Path $configFilePath)) {
        Write-host ""
        Write-host "EntraPolicySuite.psm1 was not found in current directory. Terminating !" -ForegroundColor DarkYellow
        break
    }

    Import-Module $FunctionFile -Global -force -WarningAction SilentlyContinue

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


#############################################################################################
# Main Program
#############################################################################################

    write-host "Getting Exchange information ... Please Wait !"
    $Global:ExchangeUsers_ALL = Get-EXORecipient -PropertySet Minimum -ResultSize unlimited
    
    #-------------------------------------------------------------------
    # Authentication Details
    #-------------------------------------------------------------------
        write-host "Getting Authentication Methods .... Please Wait !"

        # Fetch user registration detail report from Microsoft Graph
        $UsersAuthMethods_ALL = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All

        # Create custom PowerShell object and populate it with the desired properties
        $UsersAuthMethods_Array = foreach ($User in $UsersAuthMethods_ALL) {
            [pscustomobject]@{
                Id                                           = $User.Id
                UserPrincipalName                            = $User.UserPrincipalName
                UserDisplayName                              = $User.UserDisplayName
                IsAdmin                                      = $User.IsAdmin
                DefaultMfaMethod                             = $User.DefaultMfaMethod
                MethodsRegistered                            = $User.MethodsRegistered -join ','
                IsMfaCapable                                 = $User.IsMfaCapable
                IsMfaRegistered                              = $User.IsMfaRegistered
                IsPasswordlessCapable                        = $User.IsPasswordlessCapable
                IsSsprCapable                                = $User.IsSsprCapable
                IsSsprEnabled                                = $User.IsSsprEnabled
                IsSsprRegistered                             = $User.IsSsprRegistered
                IsSystemPreferredAuthenticationMethodEnabled = $User.IsSystemPreferredAuthenticationMethodEnabled
                LastUpdatedDateTime                          = $User.LastUpdatedDateTime
            }
        }
 
    #-------------------------------------------------------------------
    # Active Directory - Get Last Logon by Querying all DCs
    #-------------------------------------------------------------------
        $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

        $results = @()

        # Iterate through each domain controller and retrieve users
        foreach ($DC in $domainControllers) {
             $users = Get-ADUser -Filter * -SearchBase ((Get-ADRootDSE).defaultNamingContext) -Properties SamAccountName, UserPrincipalName, LastLogonDate, Enabled, LockedOut, PasswordNeverExpires, CannotChangePassword, whenCreated, AccountExpirationDate, description |
                 Select-Object SamAccountName, UserPrincipalName, @{Name="LastLogin"; Expression={$_.LastLogonDate}}, Enabled, LockedOut, PasswordNeverExpires, CannotChangePassword , whenCreated, AccountExpirationDate, description
            $results += $users
        }

        $AD_Last_Logon = $results | Select-Object * -Unique


    #-------------------------------------------------------------------
    # Get license details from Microsoft
    #-------------------------------------------------------------------
        $LicenseTranslationTable = Invoke-WebRequest -Method Get -UseBasicParsing -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv
        #$LicenseTranslationTable."???Product_Display_Name"

        # License SKUs
        # https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

    #-------------------------------------------------------------------
    # Get all user properties
    #-------------------------------------------------------------------

        $Users_ALL = Get-MgBetaUser -All -property AccountEnabled, id, givenname, surname, userprincipalname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Description, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesDistinguishedName, OnPremisesSyncEnabled, displayname, signinactivity, OnPremisesExtensionAttributes `
                                      | select-object id, givenname, surname, userprincipalname, OnPremisesDistinguishedName, AccountEnabled, description, displayname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesSyncEnabled, OnPremisesExtensionAttributes, `
                                        @{name='LastSignInDateTime'; expression = {$_.signinactivity.lastsignindatetime}}, `
                                        @{name='LastNonInteractiveSignInDateTime'; expression = {$_.signinactivity.LastNonInteractiveSignInDateTime}}, `
                                        @{name='AuthPhoneMethods'; expression = {$_.authentication.PhoneMethods}}, `
                                        @{name='AuthMSAuthenticator'; expression = {$_.authentication.MicrosoftAuthenticatorMethods}}, `
                                        @{name='AuthPassword'; expression = {$_.authentication.PasswordMethods}}, `
                                        @{name='UserClassification'; expression = {$_.OnPremisesExtensionAttributes.ExtensionAttribute6}},
                                        @{name='UserAuthMethodType'; expression = {$_.OnPremisesExtensionAttributes.ExtensionAttribute7}}


#####################################################################
# Correlating data & Building Array
#####################################################################

# Filtering large arrays to arrays containing only needed data
    $Users_Scoped = $Users_ALL | Select-Object DisplayName,OnPremisesDistinguishedName,OnPremisesSyncEnabled,OnPremisesExtensionAttributes,UserPrincipalName,MobilePhone,Department,UsageLocation,Id,AssignedLicenses,AssignedPlans,UserAuthMethodType,GivenName,Surname,AccountEnabled,UserClassification,Mail,LastSignInDateTime,LastNonInteractiveSignInDateTime,PasswordPolicies, Description

    $Exchange_Scoped = $Global:ExchangeUsers_ALL | Select-Object ExternalDirectoryObjectId,RecipientTypeDetails | Sort-Object -Property ExternalDirectoryObjectId

    $UsersAuthMethods_scoped = $UsersAuthMethods_Array | Select-Object UserPrincipalName,IsAdmin,DefaultMfaMethod,MethodsRegistered,IsMfaCapable,IsMfaRegistered,IsPasswordlessCapable,IsSsprCapable,IsSsprEnabled,IsSsprRegistered,IsSystemPreferredAuthenticationMethodEnabled,LastUpdatedDateTime | sort-object -Property UserPrincipalName

# Creating Hash
    $Exchange_Scoped_Hash = [ordered]@{}
    $Exchange_Scoped | ForEach-Object { $Exchange_Scoped_Hash.add($_.ExternalDirectoryObjectId,$_)}

    $UsersAuthMethods_scoped_Hash = [ordered]@{}
    $UsersAuthMethods_scoped | ForEach-Object { $UsersAuthMethods_scoped_Hash.add($_.UserPrincipalName,$_)}

# Looping
    $UserInfoArray = [System.Collections.ArrayList]@()
    $UsersTotal = ($Users_Scoped | Measure-Object).count

    $Users_Scoped | ForEach-Object -Begin  {
            $i = 0
    } -Process {
            
            # Default values
            $User = $_
            $SignInsDetected = $false
            $AuthMethods = $null

            write-host "  Processing $($User.DisplayName)"

            #------------------------------------------------------------------------------------------------
            # Authentication Methods
                
                If ($UsersAuthMethods_scoped)
                    {
                        $AuthMethods = $UsersAuthMethods_scoped_Hash[$user.UserPrincipalName]
                    }

            #------------------------------------------------------------------------------------------------
            # Last Logon - AD & Cloud

                # Default values
                $AD_User_LastLoginInfo = $null
                $AD_User_LastLogin = $null
                $AD_User_Enabled = $null
                $AD_User_LockedOut = $null
                $AD_User_PasswordNeverExpires = $null
                $AD_User_CannotChangePassword = $null
                $AD_User_AccountExpirationDate = $null
                $AD_User_description = $null

                If ($User.OnPremisesSyncEnabled)
                    {
                        $AD_User_LastLoginInfo = $AD_Last_Logon | where { $_.UserPrincipalName -eq $user.UserPrincipalName }
                        
                            If ($AD_User_LastLoginInfo)
                                {
                                    $AD_User_LastLogin = $AD_User_LastLoginInfo.LastLogin
                                    $AD_User_Enabled = $AD_User_LastLoginInfo.Enabled
                                    $AD_User_LockedOut = $AD_User_LastLoginInfo.LockedOut
                                    $AD_User_PasswordNeverExpires = $AD_User_LastLoginInfo.PasswordNeverExpires
                                    $AD_User_CannotChangePassword = $AD_User_LastLoginInfo.CannotChangePassword
                                    $AD_User_AccountExpirationDate = $AD_User_LastLoginInfo.AccountExpirationDate
                                    $AD_User_description = $AD_User_LastLoginInfo.description
                                }
                    }


            #------------------------------------------------------------------------------------------------
            # Cross-check Validation

                ##################################
                # AD-synced Users
                ##################################
                    # Default
                        $UserIsADValidated = $false
                        $ServiceAccountIsADValidated = $false
                        $SharedUserIsADValidated = $false
                        $SharedMailboxIsADValidated = $false

                        If ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_UserADSynced_AD_OU_Match)
                            {
                                $UserIsADValidated = $true
                            }
                        If ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_ServiceAccountADSynced_AD_OU_Match)
                            {
                                $ServiceAccountIsADValidated = $true
                            }
                        If ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_SharedUserADSynced_AD_OU_Match)
                            {
                                $SharedUserIsADValidated = $true
                            }
                        If ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_SharedMailboxADSynced_AD_OU_Match)
                            {
                                $SharedMailboxIsADValidated = $true
                            }



                ##################################
                # Cloud Users
                ##################################

                    # Default
                        $UserIsCloudValidated = $false

                    If ( ($User.MobilePhone) -and ($User.Department) -and ($User.UsageLocation) )
                        {
                            $UserIsCloudValidated = $true
                        }


            #------------------------------------------------------------------------------------------------
            # MAILBOX
                $MailBoxInfo = $Exchange_Scoped_Hash[$User.ID]
                If ($MailBoxInfo)
                    {
                        $MailType = $MailBoxInfo.RecipientTypeDetails
                    }
                Else
                    {
                        $MailType = $null
                    }

            #------------------------------------------------------------------------------------------------
            # Get Licenses

                # Default
                $IsLicenseOverProvisioned = $false
                $HasMinimumNeededLicense  = $false
                $UserLicenseInfo_List = ""

                # Get user licenses
                    $LicenseInfo = @()
                    ForEach ($License in $User.AssignedLicenses)
                        {
                            $LicenseInfo += $LicenseTranslationTable | where { $_.Guid -eq $License.SkuID }
                        }
                    If ($LicenseInfo)
                        {
                            $UserLicenseInfo_List = (($LicenseInfo."???Product_Display_Name" | Sort-Object -Unique) -join ",")
                        }

                    $LicenseInfo = $LicenseInfo.String_ID | Sort-Object -Unique
                    $UserAssignedPlans = $User.AssignedPlans

            #-----------------------------------------
            # License Check

                # https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

                #------------------------------------------------------------------------------------------
                # No License needed (Shared Mailboxes)

                If ($User.UserClassification -like "*SharedMailbox*")
                    {
                        $MinimumPlanNeeded_SKU        = ""
                        $MinimumPlanNeeded            = ""

                        $OverProvisionedLicenses_SKUs = @("AAD_PREMIUM","AAD_PREMIUM_P2","SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","O365_w/o Teams Bundle_M3","SPE_F1")

                        ForEach ($License in $LicenseInfo)
                            {
                                If ($License -in $OverProvisionedLicenses_SKUs)
                                    {
                                        $IsLicenseOverProvisioned = $true 
                                    }
                            }
                    }

                #------------------------------------------------------------------------------------------
                # ENTRA P1

                If ( ($User.UserClassification -like "Service_Account") -or ($User.UserClassification -like "Break_Glass_Account") -or ($User.UserClassification -like "NonManaged_User_AD_Synced") -or ($User.UserClassification -like "NonManaged_User_Cloud") -or ($User.UserClassification -like "Shared_Mail_User") -or ($User.UserClassification -like "AppSystem_Test_User") )
                    {
                        $MinimumPlanNeeded_SKU        = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
                        $MinimumPlanNeeded            = "Entra ID P1"
                        $OverProvisionedLicenses_SKUs = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")

                        If ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId)
                            {
                                $HasMinimumNeededLicense = $true
                            }

                        ForEach ($License in $LicenseInfo)
                            {
                                If ($License -in $OverProvisionedLicenses_SKUs)
                                    {
                                        $IsLicenseOverProvisioned = $true 
                                    }
                            }
                    }

                #------------------------------------------------------------------------------------------
                # EMS P5

                If ( ($User.UserClassification -like "Shared_Device_User") -or ($User.UserClassification -like "Teams_Room") ) 
                    {
                        $MinimumLicenseNeeded_SKU     = "EMSPREMIUM"
                        $MinimumLicenseNeeded         = "Enterprise Mobility + Security E5"
                        $OverProvisionedLicenses_SKU  = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")

                        If ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId)
                            {
                                $HasMinimumNeededLicense = $true
                            }

                        ForEach ($License in $LicenseInfo)
                            {
                                If ($License -in $OverProvisionedLicenses_SKUs)
                                    {
                                        $IsLicenseOverProvisioned = $true 
                                    }
                            }
                    }

                #------------------------------------------------------------------------------------------
                # EMS P5 (recommended) - or Entra ID P2 (minimum) 

                If ( ($User.UserClassification -like "Internal_Admin") -or ($User.UserClassification -like "External_Admin") ) 
                    {
                        $MinimumPlanNeeded_SKU        = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
                        $MinimumPlanNeeded            = "Entra ID P2 or EMS E5"
                        $OverProvisionedLicenses_SKUs = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")

                        If ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId)
                            {
                                $HasMinimumNeededLicense = $true
                            }

                        ForEach ($License in $LicenseInfo)
                            {
                                If ($License -in $OverProvisionedLicenses_SKUs)
                                    {
                                        $IsLicenseOverProvisioned = $true 
                                    }
                            }
                    }

                #---------------------------------------------------------------------------------
                # MS Package (E3 or E5, Biz Std or Biz Prem)

                If ( ($User.UserClassification -like "Internal_User") -or ($User.UserClassification -like "Internal_User_Developer") -or ($User.UserClassification -like "External_User") )
                    {
                        $MinimumPlanNeeded_SKUs       = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB")
                        $MinimumPlanNeeded            = "M365 E3, O365 E3, M365 E5, BizPrem, BizStd"

                        ForEach ($License in $LicenseInfo)
                            {
                                If ($License -in $MinimumPlanNeeded_SKUs)
                                    {
                                        $HasMinimumNeededLicense = $true
																		  
                                    }
                            }

                    }

            If (!($MinimumPlanNeeded)) {
                $IsLicenseOverProvisioned = $null
                $HasMinimumNeededLicense  = $null
            }

            #------------------------------------------------------------------------------------------------
            # Building array

            $Object = [PSCustomObject]@{
                                            Id                                           = $User.Id
                                            GivenName                                    = $User.GivenName
                                            SurName                                      = $User.Surname
                                            UserPrincipalName                            = $User.UserPrincipalName
                                            DisplayName                                  = $User.DisplayName
                                            Description_AD                               = $AD_User_description
                                            AccountEnabled                               = $User.AccountEnabled
                                            UserClassification                           = $User.UserClassification
                                            UserAuthMethodType                           = $User.UserAuthMethodType
                                            Mail                                         = $User.Mail
                                            IsAdmin                                      = $AuthMethods.IsAdmin
                                            MailType                                     = $MailType
                                            DefaultMfaMethod                             = $AuthMethods.DefaultMfaMethod
                                            MethodsRegistered                            = $AuthMethods.MethodsRegistered -join ','
                                            IsMfaCapable                                 = $AuthMethods.IsMfaCapable
                                            IsMfaRegistered                              = $AuthMethods.IsMfaRegistered
                                            IsPasswordlessCapable                        = $AuthMethods.IsPasswordlessCapable
                                            IsSsprCapable                                = $AuthMethods.IsSsprCapable
                                            IsSsprEnabled                                = $AuthMethods.IsSsprEnabled
                                            IsSsprRegistered                             = $AuthMethods.IsSsprRegistered
                                            IsSystemPreferredAuthenticationMethodEnabled = $AuthMethods.IsSystemPreferredAuthenticationMethodEnabled
                                            AuthMethodsLastUpdatedDateTime               = $AuthMethods.LastUpdatedDateTime
                                            extensionAttribute2                          = $User.OnPremisesExtensionAttributes.ExtensionAttribute2
                                            Cloud_LastSignInDateTime                     = $User.LastSignInDateTime
                                            Cloud_LastNonInteractiveSignInDateTime       = $User.LastNonInteractiveSignInDateTime
                                            AD_LastSignInDateTime                        = $AD_User_LastLogin
                                            AD_CannotChangePassword                      = $AD_User_CannotChangePassword
                                            AD_AccountExpirationDate                     = $AD_User_AccountExpirationDate
                                            AD_OnPremisesSyncEnabled                     = $User.OnPremisesSyncEnabled
                                            Cloud_PasswordPolicies                       = $User.PasswordPolicies
                                            AD_PasswordNeverExpires                      = $AD_User_PasswordNeverExpires
                                            UserIsADValidated                            = $UserIsADValidated
                                            ServiceAccountIsADValidated                  = $ServiceAccountIsADValidated
                                            SharedUserIsADValidated                      = $SharedUserIsADValidated
                                            SharedMailboxIsADValidated                   = $SharedMailboxIsADValidated
                                            IsLicenseOverProvisioned                     = $IsLicenseOverProvisioned
                                            HasMinimumNeededLicense                      = $HasMinimumNeededLicense
                                            MinimumPlanNeeded                            = $MinimumPlanNeeded
                                            ADDN                                         = $User.OnPremisesDistinguishedName
                                            UserLicenseList                              = $UserLicenseInfo_List
                                        }
            $Result = $UserInfoArray.add($object)

            # Increment the $i counter variable which is used to create the progress bar.
            $i = $i+1

            # Determine the completion percentage
            $Completed = ($i/$UsersTotal) * 100
            Write-Progress -Activity "Correlating User Info" -Status "Progress:" -PercentComplete $Completed
            } -End {
                
                Write-Progress -Activity "Correlating User Info" -Status "Ready" -Completed
            }


#####################################################################
# Building output arrays
#####################################################################

    write-host ""
    Write-host "Buildin output array .... Please Wait !"

    # Building arrays
    $UserInfoArray = $UserInfoArray | where-object { $_.DisplayName -ne  "On-Premises Directory Synchronization Service Account" }
    $UserInfoArray = $UserInfoArray | Sort-Object UserTypeTagValue

    #--------------------------------------------------------------------------------------------------------
    # License validation
        $OverProvisionedUsers = $UserInfoArray | Where-Object { $_.IsLicenseOverprovisioned -eq $true }

        $IncompliantUsers_License_Missing = $UserInfoArray | Where-Object { $_.HasMinimumNeededLicense -eq $false }
        $IncompliantUsers_License_Missing = $IncompliantUsers_License_Missing | Select-Object DisplayName,UserPrincipalName,HasMinimumNeededLicense,MinimumPlanNeeded,UserLicenseList

    #--------------------------------------------------------------------------------------------------------
    # Authentication - MFA

        $CompliantMFAAuth = $UserInfoArray | Where-Object {   ($_.UserAuthMethodType -Like "*MFA") -and `
                                                              ($_.UserAuthMethodType -NotLike "Guest_MFA") -and `
                                                              ($_.IsMFARegistered -eq $true) -and `
                                                              ($_.IsSSPRRegistered -eq $true) -and `
                                                            ( ($_.MethodsRegistered -match "microsoftAuthenticatorPush") -or `
                                                              ($_.MethodsRegistered -match "windowshello") `
                                                            ) `
                                                          }

        #-----------------------------------

        $IncompliantMFAAuth = $UserInfoArray | Where-Object {  ($_.UserAuthMethodType -like "*MFA") -and `
                                                               ($_.UserAuthMethodType -NotLike "Guest_MFA") -and `
                                                               ($_.IsMFARegistered -ne $true) -or `
                                                               ($_.IsSSPRRegistered -ne $true) -or `
                                                               ( ($_.IsMFARegistered -eq $true) -and `
                                                                 ($_.IsSSPRRegistered -eq $true) -and `
                                                                 ( ($_.MethodsRegistered -notmatch "microsoftAuthenticatorPush") -and ($_.MethodsRegistered -notmatch "windowshello") ) `
                                                               ) `
                                                            }


    #--------------------------------------------------------------------------------------------------------
    # Authentication - PassKeys

        $CompliantPasskeysAuth = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "*FIDO") -and `
                                                                 ($_.MethodsRegistered -match "passKeyDeviceBound") }

        #-----------------------------------

        $IncompliantPasskeysAuth = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "*FIDO") -and `
                                                                   ($_.MethodsRegistered -notmatch "passKeyDeviceBound") }

    #--------------------------------------------------------------------------------------------------------
    # Active Directory Validation based on OU-placement

        $Users_AD_Validation_Compliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced") -or `
                                                                         ($_.UserAuthMethodType -like "Internal_User_AD_Synced*") -or `
                                                                         ($_.UserAuthMethodType -like "External_User_AD_Synced*") -or `
                                                                         ($_.UserAuthMethodType -like "Internal_Developer_AD_Synced*") -or `
                                                                         ($_.UserAuthMethodType -like "External_Developer_AD_Synced*") -or `
                                                                         ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced*") -and `
                                                                         ($_.UserIsADValidated -eq $true) `
                                                                       }

        $Users_AD_Validation_Incompliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced") -or `
                                                                           ($_.UserAuthMethodType -like "Internal_User_AD_Synced*") -or `
                                                                           ($_.UserAuthMethodType -like "External_User_AD_Synced*") -or `
                                                                           ($_.UserAuthMethodType -like "Internal_Developer_AD_Synced*") -or `
                                                                           ($_.UserAuthMethodType -like "External_Developer_AD_Synced*") -or `
                                                                           ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced*") -and `
                                                                           ($_.UserIsADValidated -eq $false) `
                                                                         }

        #-----------------------------------

        $SharedUsers_AD_Validation_Compliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Shared_Device_User_AD_Synced*") -and `
                                                                               ($_.UserIsADValidated -eq $true) `
                                                                             }

        $SharedUsers_AD_Validation_Incompliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Shared_Device_User_AD_Synced*") -and `
                                                                                 ($_.UserIsADValidated -eq $false) `
                                                                               }

        #-----------------------------------

        $ServiceAccount_AD_Validation_Compliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Service_Account_AD_Synced*") -and `
                                                                                  ($_.ServiceAccountIsADValidated -eq $true) `
                                                                                }

        $ServiceAccount_AD_Validation_Incompliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Service_Account_AD_Synced*") -and `
                                                                                    ($_.ServiceAccountIsADValidated -eq $false) `
                                                                                  }

    #--------------------------------------------------------------------------------------------------------
    # Accounts that should be disabled - no login last 90 days with tags

        $DisableAccountDate = (Get-date) - (New-TimeSpan -Days 90)
        $LastSign90DaysOrNoSignIn = $UserInfoArray | Where-Object { ( ($_.AD_LastSignInDateTime -lt $DisableAccountDate) -or ($_.AD_LastSignInDateTime -eq $null) ) -and ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) )}
        $ActiveLastSign90DaysOrNoSignIn = $LastSign90DaysOrNoSignIn | Where-Object { ($_.UserClassification -like "NonManaged_User_AD_Synced") -or `
                                                                                     ($_.UserClassification -like "NonManaged_User_Cloud") -or `
                                                                                     ($_.UserClassification -like "Internal_User") -or `
                                                                                     ($_.UserClassification -like "External_User") -or `
                                                                                     ($_.UserClassification -like "Internal_Developer") -or `
                                                                                     ($_.UserClassification -like "External_Developer") -and `
                                                                                     ($_.AccountEnabled) `
                                                                                   }

    #--------------------------------------------------------------------------------------------------------
    # Accounts that should be disabled - no login last 365 days with tags

        $DisableAccountDate = (Get-date) - (New-TimeSpan -Days 365)
        $LastSignXDaysOrNoSignIn = $UserInfoArray | Where-Object { ( ($_.AD_LastSignInDateTime -lt $DisableAccountDate) -or ($_.AD_LastSignInDateTime -eq $null) ) -and ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) )}
        $ActiveLastSignXDaysOrNoSignIn = $LastSignXDaysOrNoSignIn | Where-Object { ($_.UserClassification -like "NonManaged_User_AD_Synced") -or `
                                                                                   ($_.UserClassification -like "NonManaged_User_Cloud") -or `
                                                                                   ($_.UserClassification -like "Internal_User") -or `
                                                                                   ($_.UserClassification -like "External_User") -or `
                                                                                   ($_.UserClassification -like "Internal_Developer") -or `
                                                                                   ($_.UserClassification -like "External_Developer") -and `
                                                                                   ($_.AccountEnabled) `
                                                                                 }

    #--------------------------------------------------------------------------------------------------------
    # Accounts that have no MFA and are Active

        $GapDateHired = (Get-date).AddDays(7)
        $GapDateHired = (Get-date $GapDateHired -format yyyy-MM-dd)

        $Active_NoMFA = $UserInfoArray | Where-Object {  ( ($_.AccountEnabled) -and `
                                                           ($_.UserAuthMethodType -NotLike "Guest_MFA") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_FIDO") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_Pwd") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_WHfB") -and `
                                                           ($_.DefaultMFAMethod -like "*none*") -and `
                                                           ($_.ExtensionAttribute2) -and `
                                                           ( (Get-date $_.ExtensionAttribute2) -lt (Get-date $GapDateHired) ) `
                                                         ) -or `
                                                         ( ($_.AccountEnabled) -and `
                                                           ($_.UserAuthMethodType -NotLike "Guest_MFA") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_FIDO") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_Pwd") -and `
                                                           ($_.UserAuthMethodType -NotLike "*_WHfB") -and `
                                                           ($_.DefaultMFAMethod -like "*none*") -and `
                                                           ($_.ExtensionAttribute2 -eq $null) `
                                                         ) `
                                                      }

    #--------------------------------------------------------------------------------------------------------
    # Active Accounts that only have AD-login - should NOT be synced to cloud
        $ActiveOnlyADSignIn = $UserInfoArray | Where-Object { ($_.AD_LastSignInDateTime) -and `
                                                              ($_.Cloud_LastSignInDateTime -eq $null) -and `
                                                              ($_.AccountEnabled) `
                                                            }

    #--------------------------------------------------------------------------------------------------------
    # Shared Mailboxes that has Sign-in enabled
        $SharedMailboxSignInEnabled = $UserInfoArray | Where-Object { ($_.AccountEnabled) -and `
                                                                      ($_.UserClassification -like "Exchange_Shared*") `
                                                                    }

    #--------------------------------------------------------------------------------------------------------
    # Guests with no sign-in last 90 days
        $DisableAccountDate = (Get-date) - (New-TimeSpan -Days 90)
        $GuestsNoSignInLast90Days = $UserInfoArray | Where-Object { ($_.AccountEnabled) -and `
                                                                    ($_.UserClassification -like "External_Guest") -and `
                                                                    ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) ) `
                                                                  }


#####################################################################
# Exporting Information
#####################################################################

    $FileOutput = ".\Users.xlsx"
    If (Test-Path $FileOutput)
        {
            Remove-Item $FileOutput -Force
        }

    $FileOutputCSV = ".\Users.CSV"
    If (Test-Path $FileOutput)
        {
            Remove-Item $FileOutput -Force
        }

    write-host ""
    Write-host "Exporting to Excel file .... Please Wait !"
    write-host ""
    Write-host $FileOutput
    write-host ""


    ##########################
    # Export to Excel
    ##########################

        $Target = "Users_ALL"
        $UserInfoArray | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9
        $UserInfoArray | Export-CSV  -Path $FileOutputCSV -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation

    #--------------------------------------------------------------------------------------------------------
    # Accounts that should be disabled - no login last 365 days - no tags - MailType = $null, UserMailbox, MailUser

        $Target = "ActiveLastSignXDaysOrNoSignIn"
        $ActiveLastSignXDaysOrNoSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Active Accounts that should be disabled - no login last 90 days

        $Target = "ActiveLastSign90DaysOrNoSignIn"
        $ActiveLastSign90DaysOrNoSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Active Accounts with NO MFA

        $Target = "Active_NoMFA"
        $Active_NoMFA | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Active Accounts with NO Cloud SignIn but AD sign-ins exist ! Should NOT be synced to cloud)

        $Target = "ActiveOnlyADSignIn"
        $ActiveOnlyADSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Active Shared Mailboxes with SignIn enabled - Should be disabled

        $Target = "SharedMailboxSignInEnabled"
        $SharedMailboxSignInEnabled | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Active Guests with No SignIn Last 90 days

        $Target = "GuestsNoSignInLast90Days"
        $GuestsNoSignInLast90Days | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9
 
    #--------------------------------------------------------------------------------------------------------
    # Authentication - MFA

        $Target = "CompliantMFAAuth"
        $CompliantMFAAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "IncompliantMFAAuth"
        $IncompliantMFAAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Authentication - PassKeys

        $Target = "CompliantPasskeysAuth"
        $CompliantPasskeysAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "IncompliantPasskeysAuth"
        $IncompliantPasskeysAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

    #--------------------------------------------------------------------------------------------------------
    # Licenses

        $Target = "OverProvisionedUsers"
        $OverProvisionedUsers | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "IncompliantUsers_LicenseMissing"
        $IncompliantUsers_License_Missing | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9


    #--------------------------------------------------------------------------------------------------------
    # Active Directory Validation based on OU-placement

        $Target = "Users_AD_Validated"
        $Users_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "Users_AD_NoValidation"
        $Users_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        #-----------------------------------

        $Target = "SharedUsers_AD_Validated"
        $SharedUsers_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "SharedUsers_AD_NoValidation"
        $SharedUsers_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        #-----------------------------------

        $Target = "ServiceAccount_AD_Validated"
        $ServiceAccount_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9

        $Target = "ServiceAccount_AD_NoValidation"
        $ServiceAccount_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle Medium9
