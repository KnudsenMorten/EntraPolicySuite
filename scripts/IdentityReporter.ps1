<#
.SYNOPSIS
    IdentityReporter - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : IdentityReporter.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Identity Reporter"
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
$global:PathScripts = Split-Path -Parent $ScriptDirectory
Write-Output ""
Write-Output ("Script Directory -> {0}" -f $global:PathScripts)

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

# Exchange Online
Write-Output "Connecting to Exchange Online using High Privilege Account using Modern method (certificate)"
Connect-ExchangeOnline -CertificateThumbprint $HighPriv_Modern_CertificateThumbprint_O365 -AppId $HighPriv_Modern_ApplicationID_O365 -ShowProgress:$false -Organization $TenantNameOrganization -ShowBanner

######################################################################################
## ENVIRONMENT (PARAMETER)
######################################################################################
If ($args[0]) {
    Write-Output ("Arg -> {0}" -f $args[0])

    If ($args[0] -eq "Internal_Prod") {
        $global:Environment           = "Internal_Prod"
        $global:SecureCredentials     = $global:HighPriv_Legacy_SecureCredentials_Internal_Prod
        $global:AD_LDAP_SearchBase_CN = $global:AD_LDAP_SearchBase_Internal_Prod_CN
        $global:AD_LDAP_SearchBase_OU = $global:AD_LDAP_SearchBase_Internal_Prod_OU
        $global:AD_Domain             = $global:AD_Domain_Internal_Prod 
    } ElseIf ($args[0] -eq "DMZ_Prod") {
        $global:Environment           = "DMZ_Prod"
        $global:SecureCredentials     = $global:HighPriv_Legacy_SecureCredentials_DMZ_Prod
        $global:AD_LDAP_SearchBase_CN = $global:AD_LDAP_SearchBase_DMZ_Prod_CN
        $global:AD_LDAP_SearchBase_OU = $global:AD_LDAP_SearchBase_DMZ_Prod_OU
        $global:AD_Domain             = $global:AD_Domain_DMZ_Prod
    } ElseIf ($args[0] -eq "Internal_Dev") {
        $global:Environment           = "Internal_Dev"
        $global:SecureCredentials     = $global:HighPriv_Legacy_SecureCredentials_Internal_Dev
        $global:AD_LDAP_SearchBase_CN = $global:AD_LDAP_SearchBase_Internal_Dev_CN
        $global:AD_LDAP_SearchBase_OU = $global:AD_LDAP_SearchBase_Internal_Dev_OU
        $global:AD_Domain             = $global:AD_Domain_Internal_Dev
    } ElseIf ($args[0] -eq "Internal_Test") {
        $global:Environment           = "Internal_Test"
        $global:SecureCredentials     = $global:HighPriv_Legacy_SecureCredentials_Internal_Test
        $global:AD_LDAP_SearchBase_CN = $global:AD_LDAP_SearchBase_Internal_Test_CN
        $global:AD_LDAP_SearchBase_OU = $global:AD_LDAP_SearchBase_Internal_Test_OU
        $global:AD_Domain             = $global:AD_Domain_Internal_Test 
    }
} Else {
    Write-Output ""
    Write-Output "Defaulting to INTERNAL_PROD environment ....."
    $global:Environment           = "Internal_Prod"
    $global:SecureCredentials     = $global:HighPriv_Legacy_SecureCredentials_Internal_Prod
    $global:AD_LDAP_SearchBase_CN = $global:AD_LDAP_SearchBase_Internal_Prod_CN
    $global:AD_LDAP_SearchBase_OU = $global:AD_LDAP_SearchBase_Internal_Prod_OU
    $global:AD_Domain             = $global:AD_Domain_Internal_Prod 
}

#############################################################################################
# Main Program
#############################################################################################

# Get Extension Attribute Info
   # AccountInfo
    if ($global:EntraPolicySuite_Tagging_User_AccountInfo) {
        $AccountInfoExtension = $global:EntraPolicySuite_Tagging_User_AccountInfo
    } else {
        $AccountInfoExtension = "extensionAttribute5"
    }
   # Classification
    if ($global:EntraPolicySuite_Tagging_User_Classification) {
        $ClassificationExtension = $global:EntraPolicySuite_Tagging_User_Classification
    } else {
        $ClassificationExtension = "extensionAttribute6"
    }

   # Authentication
    if ($global:EntraPolicySuite_Tagging_User_Authentication) {
        $AuthenticationExtension = $global:EntraPolicySuite_Tagging_User_Authentication
    } else {
        $AuthenticationExtension = "extensionAttribute7"
    }
   # Pilot
    if ($global:EntraPolicySuite_Tagging_User_Pilot) {
        $PilotExtension = $global:EntraPolicySuite_Tagging_User_Pilot
    } else {
        $PilotExtension = "extensionAttribute8"
    }


# --- Device sync lookback window (days) for COUNTING ONLY (Devices worksheet shows ALL devices) ---
$DeviceLastSyncDaysFilter = 30
$DeviceSyncCutoff = (Get-Date).AddDays(-[int]$DeviceLastSyncDaysFilter)

Write-Host "Getting Exchange information ... Please Wait !"
$Global:ExchangeUsers_ALL = Get-EXORecipient -PropertySet Minimum -ResultSize Unlimited

#-------------------------------------------------------------------
# Authentication Details (Graph Reports)
#-------------------------------------------------------------------
Write-Host "Getting Authentication Methods .... Please Wait !"
$UsersAuthMethods_ALL = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All

# Create simplified array
$UsersAuthMethods_Array = foreach ($User in $UsersAuthMethods_ALL) {
    [pscustomobject]@{
        Id                                           = $User.Id
        UserPrincipalName                            = $User.UserPrincipalName
        UserDisplayName                              = $User.UserDisplayName
        IsAdmin                                      = $User.IsAdmin
        DefaultMfaMethod                             = $User.DefaultMfaMethod
        MethodsRegistered                            = ($User.MethodsRegistered -join ',')
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
# Intune (Endpoint Manager) – Managed Devices
#   * Devices worksheet includes ALL devices
#   * Per-user device COUNT columns are based ONLY on devices with LastSyncDateTime within X days
#-------------------------------------------------------------------
Write-Host "Getting Intune managed device inventory ... Please wait!"
# Requires Microsoft.Graph.Beta and appropriate permissions.
$ManagedDevices = Get-MgBetaDeviceManagementManagedDevice -All  # ALL devices for Devices sheet

# ---- Filtered view for counts only ----
$ManagedDevicesForCounts = $ManagedDevices | Where-Object {
    $_.LastSyncDateTime -and ([datetime]$_.LastSyncDateTime) -ge $DeviceSyncCutoff
}

# ---- Build per-user counts hash from filtered list ----
$DeviceCountsHash = @{}
foreach ($d in $ManagedDevicesForCounts) {
    $upn = $d.userPrincipalName
    if ([string]::IsNullOrWhiteSpace($upn)) { continue }

    if (-not $DeviceCountsHash.ContainsKey($upn)) {
        $DeviceCountsHash[$upn] = [pscustomobject]@{
            DeviceCount_iPhone_Corp      = 0
            DeviceCount_iPhone_Personal  = 0
            DeviceCount_iPad_Corp        = 0
            DeviceCount_iPad_Personal    = 0
            DeviceCount_Android_Corp     = 0
            DeviceCount_Android_Personal = 0
            DeviceCount_Windows_Corp     = 0
            DeviceCount_Windows_Personal = 0
        }
    }

    $isCorp = ($d.managedDeviceOwnerType -eq 'company')
    $os    = $d.operatingSystem
    $model = $d.model

    # Map to {iPhone|iPad|Android|Windows}
    $platform = $null
    switch -Regex ($os) {
        'Android' { $platform = 'Android'; break }
        'Windows' { $platform = 'Windows'; break }
        'iPadOS'  { $platform = 'iPad';    break }
        'iOS'     { if ($model -match 'iPad') { $platform = 'iPad' } else { $platform = 'iPhone' }; break }
        default   { $platform = $null }
    }
    if (-not $platform) { continue }

    $bucket = if ($isCorp) { "DeviceCount_{0}_Corp" -f $platform } else { "DeviceCount_{0}_Personal" -f $platform }
    if ($DeviceCountsHash[$upn].PSObject.Properties.Name -contains $bucket) {
        $DeviceCountsHash[$upn].$bucket++
    }
}

# ---- Helper scriptblocks (avoid function-slot exhaustion) ----
$ConvertAnyToText = {
    param([Parameter(ValueFromPipeline=$true)]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or
        $Value -is [int] -or
        $Value -is [long] -or
        $Value -is [double] -or
        $Value -is [decimal] -or
        $Value -is [bool]) {
        return $Value
    }

    if ($Value -is [datetime]) {
        return (Get-Date $Value -Format 'yyyy-MM-ddTHH:mm:ss')
    }

    if ($Value -is [array]) {
        $parts = foreach ($i in $Value) { & $ConvertAnyToText $i }
        return ($parts -join '; ')
    }

    if ($Value -is [System.Collections.IDictionary] -or
        $Value -is [hashtable] -or
        $Value -is [psobject]) {
        try { return ($Value | ConvertTo-Json -Compress -Depth 10) }
        catch { return ($Value | Out-String).Trim() }
    }

    return ($Value | Out-String).Trim()
}

$GetPlatformNormalized = {
    param([string]$OperatingSystem, [string]$Model)
    if ($OperatingSystem -match 'Android') { return 'Android' }
    if ($OperatingSystem -match 'Windows') { return 'Windows' }
    if ($OperatingSystem -match 'iPadOS')  { return 'iPad' }
    if ($OperatingSystem -match 'iOS') {
        if ($Model -match 'iPad') { return 'iPad' } else { return 'iPhone' }
    }
    return $OperatingSystem
}

# ---- Build Devices worksheet from ALL devices (flatten to text) ----
$DevicesTable = foreach ($d in $ManagedDevices) {
    $row = [ordered]@{
        Id                        = $d.Id
        UserPrincipalName         = $d.UserPrincipalName
        UserDisplayName           = $d.UserDisplayName
        DeviceName                = $d.DeviceName
        ManagedDeviceOwnerType    = $d.ManagedDeviceOwnerType
        OwnershipNormalized       = if ($d.ManagedDeviceOwnerType -eq 'company') { 'Corp' } else { if ($d.ManagedDeviceOwnerType) { 'Personal' } else { $null } }
        OperatingSystem           = $d.OperatingSystem
        OSVersion                 = $d.OSVersion
        Model                     = $d.Model
        Manufacturer              = $d.Manufacturer
        SerialNumber              = $d.SerialNumber
        JoinType                  = $d.JoinType
        DeviceEnrollmentType      = $d.DeviceEnrollmentType
        ManagementState           = $d.ManagementState
        ManagementAgent           = $d.ManagementAgent
        ComplianceState           = $d.ComplianceState
        DeviceCategoryDisplayName = $d.DeviceCategoryDisplayName
        LastSyncDateTime          = & $ConvertAnyToText $d.LastSyncDateTime
        EnrolledDateTime          = & $ConvertAnyToText $d.EnrolledDateTime
        AzureAdDeviceId           = $d.AzureAdDeviceId
        EmailAddress              = $d.EmailAddress
        PhoneNumber               = $d.PhoneNumber
        WiFiMacAddress            = $d.WiFiMacAddress
        EthernetMacAddress        = $d.EthernetMacAddress
        WindowsActiveMalwareCount    = $d.WindowsActiveMalwareCount
        WindowsRemediatedMalwareCount = $d.WindowsRemediatedMalwareCount
        PlatformNormalized        = & $GetPlatformNormalized -OperatingSystem $d.OperatingSystem -Model $d.Model
        # Visibility of count window (counts only)
        CountSyncWindowDays       = $DeviceLastSyncDaysFilter
        CountSyncCutoffUtc        = (Get-Date $DeviceSyncCutoff.ToUniversalTime() -Format 'yyyy-MM-ddTHH:mm:ssZ')
    }
    foreach ($p in $d.PSObject.Properties) {
        if (-not $row.Contains($p.Name)) { $row[$p.Name] = & $ConvertAnyToText $p.Value }
    }
    [pscustomobject]$row
}
$DevicesTable = $DevicesTable | Sort-Object UserPrincipalName, DeviceName

#-------------------------------------------------------------------
# Active Directory - Get Last Logon by Querying all DCs
#-------------------------------------------------------------------
$DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

$results = @()
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
# $LicenseTranslationTable."???Product_Display_Name"

#-------------------------------------------------------------------
# Get all user properties (Graph Beta)
#-------------------------------------------------------------------
$Users_ALL = Get-MgBetaUser -All -Property AccountEnabled, id, givenname, surname, userprincipalname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Description, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesDistinguishedName, OnPremisesSyncEnabled, displayname, signinactivity, OnPremisesExtensionAttributes `
    | Select-Object id, givenname, surname, userprincipalname, OnPremisesDistinguishedName, AccountEnabled, description, displayname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesSyncEnabled, OnPremisesExtensionAttributes, `
        @{name='LastSignInDateTime'; expression = {$_.signinactivity.lastsignindatetime}}, `
        @{name='LastNonInteractiveSignInDateTime'; expression = {$_.signinactivity.LastNonInteractiveSignInDateTime}}, `
        @{name='AuthPhoneMethods'; expression = {$_.authentication.PhoneMethods}}, `
        @{name='AuthMSAuthenticator'; expression = {$_.authentication.MicrosoftAuthenticatorMethods}}, `
        @{name='AuthPassword'; expression = {$_.authentication.PasswordMethods}}, `
        @{name='AccountInfo'; expression = {$_.OnPremisesExtensionAttributes.$AccountInfoExtension}}, `
        @{name='UserClassification'; expression = {$_.OnPremisesExtensionAttributes.$ClassificationExtension}}, `
        @{name='UserAuthMethodType'; expression = {$_.OnPremisesExtensionAttributes.$AuthenticationExtension}},
        @{name='PilotInfo'; expression = {$_.OnPremisesExtensionAttributes.$PilotExtension}}

#####################################################################
# Correlating data & Building Array
#####################################################################
$Users_Scoped = $Users_ALL | Select-Object DisplayName,OnPremisesDistinguishedName,OnPremisesSyncEnabled,OnPremisesExtensionAttributes,UserPrincipalName,MobilePhone,Department,UsageLocation,Id,AssignedLicenses,AssignedPlans,UserAuthMethodType,GivenName,Surname,AccountEnabled,UserClassification,Mail,LastSignInDateTime,LastNonInteractiveSignInDateTime,PasswordPolicies, Description
$Exchange_Scoped = $Global:ExchangeUsers_ALL | Select-Object ExternalDirectoryObjectId,RecipientTypeDetails | Sort-Object -Property ExternalDirectoryObjectId
$UsersAuthMethods_scoped = $UsersAuthMethods_Array | Select-Object UserPrincipalName,IsAdmin,DefaultMfaMethod,MethodsRegistered,IsMfaCapable,IsMfaRegistered,IsPasswordlessCapable,IsSsprCapable,IsSsprEnabled,IsSsprRegistered,IsSystemPreferredAuthenticationMethodEnabled,LastUpdatedDateTime | Sort-Object -Property UserPrincipalName

# Hashes for fast lookups
$Exchange_Scoped_Hash = [ordered]@{}
$Exchange_Scoped | ForEach-Object { $Exchange_Scoped_Hash.Add($_.ExternalDirectoryObjectId,$_) }

$UsersAuthMethods_scoped_Hash = [ordered]@{}
$UsersAuthMethods_scoped | ForEach-Object { $UsersAuthMethods_scoped_Hash.Add($_.UserPrincipalName,$_) }

$UserInfoArray = New-Object System.Collections.ArrayList
$UsersTotal = ($Users_Scoped | Measure-Object).Count

$Users_Scoped | ForEach-Object -Begin { $i = 0 } -Process {
    $User = $_
    $AuthMethods = $null

    Write-Host ("  Processing {0}" -f $User.DisplayName)

    # Authentication Methods
    if ($UsersAuthMethods_scoped) {
        $AuthMethods = $UsersAuthMethods_scoped_Hash[$user.UserPrincipalName]
    }

    # Last Logon - AD & Cloud
    $AD_User_LastLoginInfo = $null
    $AD_User_LastLogin = $null
    $AD_User_Enabled = $null
    $AD_User_LockedOut = $null
    $AD_User_PasswordNeverExpires = $null
    $AD_User_CannotChangePassword = $null
    $AD_User_AccountExpirationDate = $null
    $AD_User_description = $null

    if ($User.OnPremisesSyncEnabled) {
        $AD_User_LastLoginInfo = $AD_Last_Logon | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
        if ($AD_User_LastLoginInfo) {
            $AD_User_LastLogin = $AD_User_LastLoginInfo.LastLogin
            $AD_User_Enabled = $AD_User_LastLoginInfo.Enabled
            $AD_User_LockedOut = $AD_User_LastLoginInfo.LockedOut
            $AD_User_PasswordNeverExpires = $AD_User_LastLoginInfo.PasswordNeverExpires
            $AD_User_CannotChangePassword = $AD_User_LastLoginInfo.CannotChangePassword
            $AD_User_AccountExpirationDate = $AD_User_LastLoginInfo.AccountExpirationDate
            $AD_User_description = $AD_User_LastLoginInfo.description
        }
    }

    # Cross-check Validation (AD OUs)
    $UserIsADValidated = $false
    $ServiceAccountIsADValidated = $false
    $SharedUserIsADValidated = $false
    $SharedMailboxIsADValidated = $false

    if ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_UserADSynced_AD_OU_Match) { $UserIsADValidated = $true }
    if ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_ServiceAccountADSynced_AD_OU_Match) { $ServiceAccountIsADValidated = $true }
    if ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_SharedUserADSynced_AD_OU_Match) { $SharedUserIsADValidated = $true }
    if ($User.OnPremisesDistinguishedName -match $Global:IdentityReporter_SharedMailboxADSynced_AD_OU_Match) { $SharedMailboxIsADValidated = $true }

    # Cloud Users validation
    $UserIsCloudValidated = $false
    if ($User.MobilePhone -and $User.Department -and $User.UsageLocation) { $UserIsCloudValidated = $true }

    # MAILBOX
    $MailBoxInfo = $Exchange_Scoped_Hash[$User.ID]
    if ($MailBoxInfo) { $MailType = $MailBoxInfo.RecipientTypeDetails } else { $MailType = $null }

    # Licenses
    $IsLicenseOverProvisioned = $false
    $HasMinimumNeededLicense  = $false
    $UserLicenseInfo_List = ""

    $LicenseInfo = @()
    foreach ($License in $User.AssignedLicenses) {
        $LicenseInfo += $LicenseTranslationTable | Where-Object { $_.Guid -eq $License.SkuID }
    }
    if ($LicenseInfo) {
        $UserLicenseInfo_List = (($LicenseInfo."???Product_Display_Name" | Sort-Object -Unique) -join ",")
    }
    $LicenseInfo = $LicenseInfo.String_ID | Sort-Object -Unique
    $UserAssignedPlans = $User.AssignedPlans

    # License Check (min/over)  [unchanged from your logic]
    if ($User.UserClassification -like "*SharedMailbox*") {
        $MinimumPlanNeeded_SKU        = ""
        $MinimumPlanNeeded            = ""
        $OverProvisionedLicenses_SKUs = @("AAD_PREMIUM","AAD_PREMIUM_P2","SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","O365_w/o Teams Bundle_M3","SPE_F1")
        foreach ($License in $LicenseInfo) { if ($License -in $OverProvisionedLicenses_SKUs) { $IsLicenseOverProvisioned = $true } }
    }

    if ( ($User.UserClassification -like "Service_Account") -or ($User.UserClassification -like "Break_Glass_Account") -or ($User.UserClassification -like "NonManaged_User_AD_Synced") -or ($User.UserClassification -like "NonManaged_User_Cloud") -or ($User.UserClassification -like "Shared_Mail_User") -or ($User.UserClassification -like "AppSystem_Test_User") ) {
        $MinimumPlanNeeded_SKU        = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
        $MinimumPlanNeeded            = "Entra ID P1"
        $OverProvisionedLicenses_SKUs = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")
        if ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId) { $HasMinimumNeededLicense = $true }
        foreach ($License in $LicenseInfo) { if ($License -in $OverProvisionedLicenses_SKUs) { $IsLicenseOverProvisioned = $true } }
    }

    if ( ($User.UserClassification -like "Shared_Device_User") -or ($User.UserClassification -like "Teams_Room") ) {
        $MinimumPlanNeeded_SKU        = "EMSPREMIUM"
        $MinimumPlanNeeded            = "Enterprise Mobility + Security E5"
        $OverProvisionedLicenses_SKUs = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")
        if ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId) { $HasMinimumNeededLicense = $true }
        foreach ($License in $LicenseInfo) { if ($License -in $OverProvisionedLicenses_SKUs) { $IsLicenseOverProvisioned = $true } }
    }

    if ( ($User.UserClassification -like "Internal_Admin") -or ($User.UserClassification -like "External_Admin") ) {
        $MinimumPlanNeeded_SKU        = "eec0eb4f-6444-4b95-aba0-50c24d67f998"
        $MinimumPlanNeeded            = "Entra ID P2 or EMS E5"
        $OverProvisionedLicenses_SKUs = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB","Microsoft 365 E3","Microsoft 365 E5")
        if ($MinimumPlanNeeded_SKU -in $UserAssignedPlans.ServicePlanId) { $HasMinimumNeededLicense = $true }
        foreach ($License in $LicenseInfo) { if ($License -in $OverProvisionedLicenses_SKUs) { $IsLicenseOverProvisioned = $true } }
    }

    if ( ($User.UserClassification -like "Internal_User") -or ($User.UserClassification -like "Internal_User_Developer") -or ($User.UserClassification -like "External_User") ) {
        $MinimumPlanNeeded_SKUs       = @("SPE_E3","SPE_E5","O365_w/o Teams Bundle_M3","O365_BUSINESS_PREMIUM","Microsoft_365_Business_Standard_EEA_(no_Teams)","SPB")
        $MinimumPlanNeeded            = "M365 E3, O365 E3, M365 E5, BizPrem, BizStd"
        foreach ($License in $LicenseInfo) { if ($License -in $MinimumPlanNeeded_SKUs) { $HasMinimumNeededLicense = $true } }
    }

    if (-not $MinimumPlanNeeded) {
        $IsLicenseOverProvisioned = $null
        $HasMinimumNeededLicense  = $null
    }

    # Intune Device Counts for this user (from filtered list)
    $DevCounts = $DeviceCountsHash[$User.UserPrincipalName]
    if (-not $DevCounts) {
        $DevCounts = [pscustomobject]@{
            DeviceCount_iPhone_Corp      = 0
            DeviceCount_iPhone_Personal  = 0
            DeviceCount_iPad_Corp        = 0
            DeviceCount_iPad_Personal    = 0
            DeviceCount_Android_Corp     = 0
            DeviceCount_Android_Personal = 0
            DeviceCount_Windows_Corp     = 0
            DeviceCount_Windows_Personal = 0
        }
    }

    # --- New: Smartphone active within last $DeviceLastSyncDaysFilter days (iPhone or Android; corp or personal) ---
    $SmartPhoneActive = (
        ($DevCounts.DeviceCount_iPhone_Corp      + `
         $DevCounts.DeviceCount_iPhone_Personal  + `
         $DevCounts.DeviceCount_Android_Corp     + `
         $DevCounts.DeviceCount_Android_Personal) -gt 0
    )

    # Corp-only smartphone active within last $DeviceLastSyncDaysFilter days
    $SmartPhoneActive_CorpOnly = (
        ($DevCounts.DeviceCount_iPhone_Corp +
         $DevCounts.DeviceCount_Android_Corp) -gt 0
    )

    # Build output object
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
        UserPilotInfo                                = $User.PilotInfo
        UserAccountInfo                              = $User.AccountInfo
        Mail                                         = $User.Mail
        IsAdmin                                      = if ($AuthMethods) { $AuthMethods.IsAdmin } else { $null }
        MailType                                     = $MailType
        DefaultMfaMethod                             = if ($AuthMethods) { $AuthMethods.DefaultMfaMethod } else { $null }
        MethodsRegistered                            = if ($AuthMethods) { $AuthMethods.MethodsRegistered } else { $null }
        IsMfaCapable                                 = if ($AuthMethods) { $AuthMethods.IsMfaCapable } else { $null }
        IsMfaRegistered                              = if ($AuthMethods) { $AuthMethods.IsMfaRegistered } else { $null }
        IsPasswordlessCapable                        = if ($AuthMethods) { $AuthMethods.IsPasswordlessCapable } else { $null }
        IsSsprCapable                                = if ($AuthMethods) { $AuthMethods.IsSsprCapable } else { $null }
        IsSsprEnabled                                = if ($AuthMethods) { $AuthMethods.IsSsprEnabled } else { $null }
        IsSsprRegistered                             = if ($AuthMethods) { $AuthMethods.IsSsprRegistered } else { $null }
        IsSystemPreferredAuthenticationMethodEnabled = if ($AuthMethods) { $AuthMethods.IsSystemPreferredAuthenticationMethodEnabled } else { $null }
        AuthMethodsLastUpdatedDateTime               = if ($AuthMethods) { $AuthMethods.LastUpdatedDateTime } else { $null }
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

        # --- Intune device count columns (filtered by $DeviceLastSyncDaysFilter) ---
        DeviceCount_iPhone_Corp                      = $DevCounts.DeviceCount_iPhone_Corp
        DeviceCount_iPhone_Personal                  = $DevCounts.DeviceCount_iPhone_Personal
        DeviceCount_iPad_Corp                        = $DevCounts.DeviceCount_iPad_Corp
        DeviceCount_iPad_Personal                    = $DevCounts.DeviceCount_iPad_Personal
        DeviceCount_Android_Corp                     = $DevCounts.DeviceCount_Android_Corp
        DeviceCount_Android_Personal                 = $DevCounts.DeviceCount_Android_Personal
        DeviceCount_Windows_Corp                     = $DevCounts.DeviceCount_Windows_Corp
        DeviceCount_Windows_Personal                 = $DevCounts.DeviceCount_Windows_Personal

        # --- New column ---
        Device_SmartPhoneActive                      = $SmartPhoneActive
        Device_SmartPhoneActive_CorpOnly             = $SmartPhoneActive_CorpOnly

    }

    [void]$UserInfoArray.Add($Object)

    # Progress
    $i = $i + 1
    $Completed = ($i / $UsersTotal) * 100
    Write-Progress -Activity "Correlating User Info" -Status "Progress:" -PercentComplete $Completed
} -End {
    Write-Progress -Activity "Correlating User Info" -Status "Ready" -Completed
}

#####################################################################
# Building output arrays
#####################################################################
Write-Host ""
Write-Host "Building output array .... Please Wait !"

# Filter & sort
$UserInfoArray = $UserInfoArray | Where-Object { $_.DisplayName -ne "On-Premises Directory Synchronization Service Account" }
$UserInfoArray = $UserInfoArray | Sort-Object UserTypeTagValue  # kept as in your script

# License validation
$OverProvisionedUsers = $UserInfoArray | Where-Object { $_.IsLicenseOverprovisioned -eq $true }

$IncompliantUsers_License_Missing = $UserInfoArray | Where-Object { $_.HasMinimumNeededLicense -eq $false } |
    Select-Object DisplayName,UserPrincipalName,HasMinimumNeededLicense,MinimumPlanNeeded,UserLicenseList

# Active users with NO MFA and at least one corp smartphone (Android/iPhone) synced in last $DeviceLastSyncDaysFilter days
$ActiveNoMFACorpSmartDevice = $UserInfoArray | Where-Object {
    ($_.AccountEnabled) -and
    ( ($null -eq $_.MailType) -or ($_.MailType -eq '') -or ($_.MailType -in @('MailUser','UserMailbox')) ) -and
    ($_.DefaultMfaMethod -like '*none*') -and
    ($_.Device_SmartPhoneActive_CorpOnly -eq $true)
}


# Authentication - MFA (compliant)
$CompliantMFAAuth = $UserInfoArray | Where-Object {
    ($_.UserAuthMethodType -like "*MFA") -and
    ($_.UserAuthMethodType -notlike "*Guest*") -and
    ($_.IsMFARegistered -eq $true) -and
    ($_.IsSSPRRegistered -eq $true) -and
    ( ($_.MethodsRegistered -match "microsoftAuthenticatorPush") -or
      ($_.MethodsRegistered -match "windowshello") )
}

# Authentication - MFA (incompliant)
$IncompliantMFAAuth = $UserInfoArray | Where-Object {
    ( ($_.UserAuthMethodType -like "*MFA") -and
      ($_.UserAuthMethodType -notlike "*Guest*") -and
      ($_.IsMFARegistered -ne $true) ) -or
    ($_.IsSSPRRegistered -ne $true) -or
    ( ($_.IsMFARegistered -eq $true) -and
      ($_.IsSSPRRegistered -eq $true) -and
      ( ($_.MethodsRegistered -notmatch "microsoftAuthenticatorPush") -and ($_.MethodsRegistered -notmatch "windowshello") ) )
}

# Authentication - PassKeys
$CompliantPasskeysAuth = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "*FIDO") -and ($_.MethodsRegistered -match "passKeyDeviceBound") }
$IncompliantPasskeysAuth = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "*FIDO") -and ($_.MethodsRegistered -notmatch "passKeyDeviceBound") }

# AD Validation based on OU-placement
$Users_AD_Validation_Compliant = $UserInfoArray | Where-Object {
    ( ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced") -or
      ($_.UserAuthMethodType -like "Internal_User_AD_Synced*") -or
      ($_.UserAuthMethodType -like "External_User_AD_Synced*") -or
      ($_.UserAuthMethodType -like "Internal_Developer_AD_Synced*") -or
      ($_.UserAuthMethodType -like "External_Developer_AD_Synced*") -or
      ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced*") ) -and
    ($_.UserIsADValidated -eq $true)
}

$Users_AD_Validation_Incompliant = $UserInfoArray | Where-Object {
    ( ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced") -or
      ($_.UserAuthMethodType -like "Internal_User_AD_Synced*") -or
      ($_.UserAuthMethodType -like "External_User_AD_Synced*") -or
      ($_.UserAuthMethodType -like "Internal_Developer_AD_Synced*") -or
      ($_.UserAuthMethodType -like "External_Developer_AD_Synced*") -or
      ($_.UserAuthMethodType -like "NonManaged_User_AD_Synced*") ) -and
    ($_.UserIsADValidated -eq $false)
}

$SharedUsers_AD_Validation_Compliant   = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Shared_Device_User_AD_Synced*") -and ($_.UserIsADValidated -eq $true) }
$SharedUsers_AD_Validation_Incompliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Shared_Device_User_AD_Synced*") -and ($_.UserIsADValidated -eq $false) }

$ServiceAccount_AD_Validation_Compliant   = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Service_Account_AD_Synced*") -and ($_.ServiceAccountIsADValidated -eq $true) }
$ServiceAccount_AD_Validation_Incompliant = $UserInfoArray | Where-Object { ($_.UserAuthMethodType -like "Service_Account_AD_Synced*") -and ($_.ServiceAccountIsADValidated -eq $false) }

# Accounts that should be disabled - no login last 90 days with tags
$DisableAccountDate = (Get-Date).AddDays(-90)
$LastSign90DaysOrNoSignIn = $UserInfoArray | Where-Object {
    ( ($_.AD_LastSignInDateTime -lt $DisableAccountDate) -or ($_.AD_LastSignInDateTime -eq $null) ) -and
    ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) )
}
$ActiveLastSign90DaysOrNoSignIn = $LastSign90DaysOrNoSignIn | Where-Object {
    ( ($_.UserClassification -like "NonManaged_User_AD_Synced") -or
      ($_.UserClassification -like "NonManaged_User_Cloud") -or
      ($_.UserClassification -like "Internal_User") -or
      ($_.UserClassification -like "External_User") -or
      ($_.UserClassification -like "Internal_Developer") -or
      ($_.UserClassification -like "External_Developer") ) -and
    ($_.AccountEnabled)
}

# Accounts that should be disabled - no login last 365 days with tags
$DisableAccountDate = (Get-Date).AddDays(-365)
$LastSignXDaysOrNoSignIn = $UserInfoArray | Where-Object {
    ( ($_.AD_LastSignInDateTime -lt $DisableAccountDate) -or ($_.AD_LastSignInDateTime -eq $null) ) -and
    ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) )
}
$ActiveLastSignXDaysOrNoSignIn = $LastSignXDaysOrNoSignIn | Where-Object {
    ( ($_.UserClassification -like "NonManaged_User_AD_Synced") -or
      ($_.UserClassification -like "NonManaged_User_Cloud") -or
      ($_.UserClassification -like "Internal_User") -or
      ($_.UserClassification -like "External_User") -or
      ($_.UserClassification -like "Internal_Developer") -or
      ($_.UserClassification -like "External_Developer") ) -and
    ($_.AccountEnabled)
}

# Accounts that have no MFA and are Active
$GapDateHired = (Get-Date).AddDays(7)
$GapDateHired = (Get-Date $GapDateHired -Format yyyy-MM-dd)

$Active_NoMFA = $UserInfoArray | Where-Object {
    ( ($_.AccountEnabled) -and
      ($_.UserAuthMethodType -notlike "*Guest*") -and
      ($_.UserAuthMethodType -notlike "*_FIDO") -and
      ($_.UserAuthMethodType -notlike "*_Pwd") -and
      ($_.UserAuthMethodType -notlike "*_WHfB") -and
      ($_.DefaultMFAMethod -like "*none*") -and
      ($_.ExtensionAttribute2) -and
      ( (Get-Date $_.ExtensionAttribute2) -lt (Get-Date $GapDateHired) ) ) -or
    ( ($_.AccountEnabled) -and
      ($_.UserAuthMethodType -notlike "*Guest*") -and
      ($_.UserAuthMethodType -notlike "*_FIDO") -and
      ($_.UserAuthMethodType -notlike "*_Pwd") -and
      ($_.UserAuthMethodType -notlike "*_WHfB") -and
      ($_.DefaultMFAMethod -like "*none*") -and
      ($_.ExtensionAttribute2 -eq $null) )
}

# Active Accounts that only have AD-login - should NOT be synced to cloud
$ActiveOnlyADSignIn = $UserInfoArray | Where-Object {
    ($_.AD_LastSignInDateTime) -and
    ($_.Cloud_LastSignInDateTime -eq $null) -and
    ($_.AccountEnabled)
}

# Shared Mailboxes that has Sign-in enabled
$SharedMailboxSignInEnabled = $UserInfoArray | Where-Object {
    ($_.AccountEnabled) -and
    ($_.UserClassification -like "*SharedMailbox*")
}

# Guests with no sign-in last 90 days
$DisableAccountDate = (Get-Date).AddDays(-90)
$GuestsNoSignInLast90Days = $UserInfoArray | Where-Object {
    ($_.AccountEnabled) -and
    ($_.UserClassification -like "*Guest*") -and
    ( ($_.Cloud_LastSignInDateTime -lt $DisableAccountDate) -or ($_.Cloud_LastSignInDateTime -eq $null) )
}

#####################################################################
# Exporting Information
#####################################################################
$FileOutput = Join-Path $global:PathScripts "OUTPUT\Users.xlsx"
If (Test-Path $FileOutput) { Remove-Item $FileOutput -Force }

$FileOutputCSV = Join-Path $global:PathScripts "OUTPUT\Users.csv"
If (Test-Path $FileOutputCSV) { Remove-Item $FileOutputCSV -Force }

Write-Host ""
Write-Host "Exporting to Excel file .... Please Wait !"
Write-Host ""
Write-Host $FileOutput
Write-Host ""

##########################
# Export to Excel / CSV
##########################
$Target = "Users_ALL"
$UserInfoArray | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9
$UserInfoArray | Export-Csv  -Path $FileOutputCSV -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation

$Target = "ActiveNoMFACorpSmartDevice"
$ActiveNoMFACorpSmartDevice | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Devices (Intune) – ALL devices, flattened
$Target = "Devices"
$DevicesTable | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Accounts that should be disabled - no login last 365 days
$Target = "ActiveLastSignXDaysOrNoSignIn"
$ActiveLastSignXDaysOrNoSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Active Accounts no login last 90 days
$Target = "ActiveLastSign90DaysOrNoSignIn"
$ActiveLastSign90DaysOrNoSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Active Accounts with NO MFA
$Target = "Active_NoMFA"
$Active_NoMFA | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Active Accounts with NO Cloud SignIn but AD sign-ins exist
$Target = "ActiveOnlyADSignIn"
$ActiveOnlyADSignIn | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Active Shared Mailboxes with SignIn enabled
$Target = "SharedMailboxSignInEnabled"
$SharedMailboxSignInEnabled | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Active Guests with No SignIn Last 90 days
$Target = "GuestsNoSignInLast90Days"
$GuestsNoSignInLast90Days | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# MFA
$Target = "CompliantMFAAuth"
$CompliantMFAAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "IncompliantMFAAuth"
$IncompliantMFAAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Passkeys
$Target = "CompliantPasskeysAuth"
$CompliantPasskeysAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "IncompliantPasskeysAuth"
$IncompliantPasskeysAuth | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# Licenses
$Target = "OverProvisionedUsers"
$OverProvisionedUsers | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "IncompliantUsers_LicenseMissing"
$IncompliantUsers_License_Missing | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

# AD Validation based on OU-placement
$Target = "Users_AD_Validated"
$Users_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "Users_AD_NoValidation"
$Users_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "SharedUsers_AD_Validated"
$SharedUsers_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "SharedUsers_AD_NoValidation"
$SharedUsers_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "ServiceAccount_AD_Validated"
$ServiceAccount_AD_Validation_Compliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

$Target = "ServiceAccount_AD_NoValidation"
$ServiceAccount_AD_Validation_Incompliant | Export-Excel -Path $FileOutput -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -TableName $Target -TableStyle Medium9

############################################################
# Send Mail with Report
############################################################
$TitleAlert       = "Identity Overview" 
$BodyAlert        = "<font color=red>Identity Overview</font><br><br>"
$BodyAlert       += "Attached you will find the overview of identities<br><br>"

$TitleMoreInfo    = "Identity Overview" 
$SubtitleMoreInfo = "Recommendations" 
$BodyMoreInfo     = "<font color=blue>(1) Please go through the identities and validate if any should be disabled</font><br>"

$Attachments            = @($FileOutput)
$Channel                = 'Identity'
$MessageClassification  = 'Investigations'     # Alert | Investigations | ProductChanges | ProductInfo | AutomationInfo | Info
$AlertImpactUrgency     = 'P1'

If ($global:Mail_SendAnonymous -eq $true) {
    If ($global:Mail_Identity_Maintenance_SendMail -eq $true) {
        $To = $global:Mail_Identity_Maintenance_TO
        SendAlertAsMailAnonymous
    }
} ElseIf ($global:Mail_SendAnonymous -eq $false) {
    If ($global:Mail_Identity_Maintenance_SendMail -eq $true) {
        $To = $global:Mail_Identity_Maintenance_TO
        SendAlertAsMailUsingSecureCredentials
    }
}

##################################################################################################
# Send to LogAnalytics table using DCR
##################################################################################################
<#
    #############################################################################
    # Entra Policy Suite Integration with Azure LogAnalytics
    #############################################################################
        $Global:EPSAzDceNameSrv                        = "dce-log-platform-management-security-p"
        $global:EPSAzDcrResourceGroupSrv               = "rg-dcr-log-platform-management-security-p" 
        $global:EPSIntegration                         = $true
#>

If ( ($global:EPSIntegration) -and ($global:EPSIntegration -eq $true)) {
    # Variables for LogAnalytics upload using DCR / DCE / Log Ingestion API
    $TenantId                                   = $global:AzureTenantID 
    $LogIngestAppId                             = $global:HighPriv_Modern_ApplicationID_LogIngestion_DCR 
    $LogIngestAppSecret                         = $global:HighPriv_Modern_Secret_LogIngestion_DCR

    $DceName                                    = $Global:EPSAzDceNameSrv 
    $LogAnalyticsWorkspaceResourceId            = $global:MainLogAnalyticsWorkspaceResourceId

    $AzDcrResourceGroup                         = $global:EPSAzDcrResourceGroupSrv 
    $AzDcrPrefix                                = "entra"
    $AzDcrSetLogIngestApiAppPermissionsDcrLevel = $false
    $AzDcrLogIngestServicePrincipalObjectId     = $Global:AzDcrLogIngestServicePrincipalObjectId 
    $AzLogDcrTableCreateFromReferenceMachine    = @()
    $AzLogDcrTableCreateFromAnyMachine          = $true
    $LogHubUploadPath                           = $global:LogHubUploadPath

    $DNSName         = (Get-CimInstance win32_computersystem).DNSHostName + "." + (Get-CimInstance win32_computersystem).Domain
    $ComputerName    = (Get-CimInstance win32_computersystem).DNSHostName
    [datetime]$CollectionTime = ( Get-Date ([datetime]::Now.ToUniversalTime()) -Format "yyyy-MM-ddTHH:mm:ssK" )

    $TableName  = 'EntraUsersMetadata'   # must not contain _CL
    $DcrName    = "dcr-" + $AzDcrPrefix + "-" + $TableName + "_CL"

    # Data (Scope)
    $DataVariable = $UserInfoArray

    # Preparing data structure
    $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable -Verbose:$Verbose
    $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name ComputerFqdn -Column2Data $DnsName -Verbose:$Verbose
    $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$Verbose
    $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable -Verbose:$Verbose

    # Create/Update Schema for LogAnalytics Table & DCR
    $ResultMgmt = CheckCreateUpdate-TableDcr-Structure -AzLogWorkspaceResourceId $LogAnalyticsWorkspaceResourceId -EnableUploadViaLogHub $false `
                    -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId -Verbose:$Verbose `
                    -DceName $DceName -DcrName $DcrName -DcrResourceGroup $AzDcrResourceGroup -TableName $TableName -Data $DataVariable `
                    -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                    -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                    -AzLogDcrTableCreateFromAnyMachine $AzLogDcrTableCreateFromAnyMachine `
                    -AzLogDcrTableCreateFromReferenceMachine $AzLogDcrTableCreateFromReferenceMachine

    # Upload data via Log Ingestion API
    $ResultPost = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output -DceName $DceName -DcrName $DcrName -Data $DataVariable -TableName $TableName -EnableUploadViaLogHub $false -LogHubPath $LogHubUploadPath `
                    -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId -Verbose:$Verbose -BatchAmount 1
}