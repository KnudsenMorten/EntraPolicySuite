#Requires -Version 5.0

<#
    .NAME
    Entra Policy Suite (EPS) | Onboarding of Entra Conditional Access Policies

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
        $configFilePath = ".\Entra_Policy_Suite_custom.config"

        # Check if the config file exists
        if (-Not (Test-Path $configFilePath)) {
            Write-host ""
            Write-host "Entra_Policy_Suite_custom.config was not found in current directory. Terminating !" -ForegroundColor DarkYellow
            break
        }

        # Read the config file
        $configData = Get-Content $configFilePath | ConvertFrom-Json

        # Get Paths to CA-files
        $Path_CA_Scripts_Active = $PSScriptRoot + "\" + $configData.Path_CA_Scripts_Active
        $Path_CA_Scripts_Github_Latest_Inbound = $PSScriptRoot + "\" + $configData.Path_CA_Scripts_Github_Latest_Inbound

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
        $configFilePath = ".\Entra_Policy_Suite_locked.config"

        # Check if the config file exists
        if (-Not (Test-Path $configFilePath)) {
            Write-host ""
            Write-host "Entra_Policy_Suite_locked.config was not found in current directory. Terminating !" -ForegroundColor DarkYellow
            break
        }

        # Read the config file
        $configData = Get-Content $configFilePath | ConvertFrom-Json

        # Get the Target Groups for Dynamic Assignment
        $Target_Groups_Dynamic_Assignment_CFG = $configData.Target_Groups_Dynamic_Assignment

        # Get the Target Groups for Dynamic Assignment
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
        Write-host "  Authentication Strengths"
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
# Step 4: DOWNLOAD LATEST CA-POLICY CONFIG FILES FROM GITHUB
################################################################################################

Write-host ""
Write-host "Step 4: Download latest CA-policy Config Files from Github"
# Parameters
$owner             = "KnudsenMorten"
$repo              = "EntraPolicySuite"
$path              = "files"
$destinationFolder = $Path_CA_Scripts_Github_Latest_Inbound

# Base URL for GitHub API
$baseUrl = "https://api.github.com/repos/$owner/$repo/contents/$path"

# Ensure the destination folder exists
if (-Not (Test-Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder
}

# Function to download file if needed
function Download-File($url, $localPath, $remoteSize, $remoteDate) {
    $download = $true
    if (Test-Path $localPath) {
        $localFile = Get-Item $localPath
        $localSize = $localFile.Length
        $localModified = $localFile.LastWriteTime

        # Compare file size and last modified dates
        if ($localSize -eq $remoteSize -and $remoteDate -ne $null -and $localModified -ge [DateTime]$remoteDate) {
            Write-Host "No changes detected (size and date match): $localPath"
            $download = $false
        }
    }
    if ($download) {
        Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing
        Write-Host "Downloaded updated file: $localPath"
        # Only update the last write time if remoteDate is not null
        if ($remoteDate -ne $null) {
            (Get-Item $localPath).LastWriteTime = [DateTime]$remoteDate
        }
    }
}

# Fetch files from GitHub
$files = Invoke-RestMethod -Uri $baseUrl -Headers @{ Accept = "application/vnd.github.v3+json" }

foreach ($file in $files) {
    if ($file.type -eq "file") {
        $fileUrl = $file.download_url
        $localFilePath = Join-Path -Path $destinationFolder -ChildPath $file.name

        # For last modified date, use commit date from the file's SHA (proxy for last modified)
        $commitUrl = "https://api.github.com/repos/$owner/$repo/commits?path=$($file.path)&sha=$($file.sha)"
        $commitInfo = Invoke-RestMethod -Uri $commitUrl -Headers @{ Accept = "application/vnd.github.v3+json" }

        # Check if commit info is available
        $lastModifiedDate = $null
        if ($commitInfo -and $commitInfo.Count -gt 0) {
            $lastModifiedDate = $commitInfo[0].commit.committer.date
        }

        # Download the file if different
        Download-File -url $fileUrl -localPath $localFilePath -remoteSize $file.size -remoteDate $lastModifiedDate
    }
}


################################################################################################
# Step 5A: SAMPLES - CONFIGURATION OF CA100 POLICY
################################################################################################
#region Samples - manually configuration of CA100 policy using all 3 targeting methods

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


    ################################################################################################
    # CA100 - Dynamic Assignment of Members of Entra Groups via Tagging on Users
    ################################################################################################

    # Initial setup
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Initial_Setup -Group_Targeting_Method Dynamic_Using_Tags

    # Staged Implementation (pilot 1-3 + prod) | Targeting method: Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot1 -Group_Targeting_Method Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot2 -Group_Targeting_Method Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot3 -Group_Targeting_Method Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Prod -Group_Targeting_Method Dynamic_Using_Tags

    # Maintenance | Targeting method: Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Install_Latest_Policy -Group_Targeting_Method Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Update_Prod_Policy_To_Latest -Group_Targeting_Method Dynamic_Using_Tags
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode GroupForceUpdate -Group_Targeting_Method Dynamic_Using_Tags

    # Disable Policy
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Disable_Policy



    ################################################################################################
    # CA100 - Manual Assignment of Members of Entra Groups - Simple targeting for Pilot deployment
    ################################################################################################

    # Initial setup
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Initial_Setup -Group_Targeting_Method Manual_Assignment_Simple

    # Staged Implementation (pilot 1-3 + prod) | Targeting method: Manual_Assignment_Advanced
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot1 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot2 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot3 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Prod -Group_Targeting_Method Manual_Assignment_Simple

    # Maintenance | Targeting method: Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Install_Latest_Policy -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Update_Prod_Policy_To_Latest -Group_Targeting_Method Manual_Assignment_Simple

    # Disable Policy
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Disable_Policy



    ################################################################################################
    # CA100 - Manual Assignment of Members of Entra Groups - Advanced targeting for Pilot deployment
    ################################################################################################

    # Initial setup
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Initial_Setup -Group_Targeting_Method Manual_Assignment_Advanced

    # Staged Implementation (pilot 1-3 + prod) | Targeting method: Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot1 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot2 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Pilot3 -Group_Targeting_Method Manual_Assignment_Simple
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Prod -Group_Targeting_Method Manual_Assignment_Simple

    # Maintenance | Targeting method: Manual_Assignment_Advanced
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Install_Latest_Policy -Group_Targeting_Method Manual_Assignment_Advanced
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Update_Prod_Policy_To_Latest -Group_Targeting_Method Manual_Assignment_Advanced

    # Disable Policy
    & $($Path_CA_Scripts_Active)\ca100.ps1 -Mode Disable_Policy

#>

#endregion



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

    $PolicyNumber = "CA304"

    # Rebuild Entra Groups as HashTable
    $EntraGroupsHashTable = EntraGroupsAsHashtable

    $Mode = "Initial_Setup"     # "Initial_Setup","Pilot1","Pilot2","Pilot3","Prod","Disable_Policy","Install_Latest_Policy_Disabled","Update_Prod_Policy_To_Latest","GroupForceUpdate"
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
#####################################################################################################################
# Export Entra ID Conditional Access Policies as JSON
#####################################################################################################################

    $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $ConditionalAccessPoliciesJSON = $ConditionalAccessPolicies | ConvertTo-Json -Depth 20

    $OutPutPath = ".\CAPolicies"
    MD $OutPutPath -ErrorAction SilentlyContinue

    $ConditionalAccessPoliciesArray = $ConditionalAccessPoliciesJSON | ConvertFrom-Json
    ForEach ($Policy in $ConditionalAccessPoliciesArray)
        {
            $PolicyName = $Policy.displayName
            $PolicyName.Replace("`\","-")
            $PolicyName.Replace("/","-")

            $PolicyJson = $Policy | ConvertTo-Json -Depth 20
            
            $FileNamePath = $OutputPath + "\" + "$($PolicyName)" + ".json"
            
            $PolicyJson | Out-File $FileNamePath -Encoding utf8 -Force
        }


#####################################################################################################################
# Export Entra Conditional Access Policies to Excel XLSX + CSV (FULL)
#####################################################################################################################

    Write-host "Retrieving information from Entra ID ... Please Wait !"
    $Users = Get-MgUser -All
    $Groups = Get-MgGroup -All
        
    $Roles = Get-MgRoleManagementDirectoryRoleDefinition -All
    $SPs = Get-MgServicePrincipal -All

    $Uri = "https://graph.microsoft.com/v1.0/applications"
    $Applications = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $ConditionalAccessArray = @()
    ForEach ($CA in $ConditionalAccessPolicies)
        {
            $Id                                                   = $CA.Id
            $DisplayName                                          = $CA.DisplayName
            $State                                                = $CA.State
            If ($CA.createdDateTime -eq $Null)         {  $createdDateTime  = "" }
            ElseIf ($CA.createdDateTime)               {  $createdDateTime  = $CA.createdDateTime    }

            If ($CA.modifiedDateTime -eq $Null)        {  $modifiedDateTime  = "" }
            ElseIf ($CA.modifiedDateTime)              {  $modifiedDateTime  = $CA.modifiedDateTime    }

            $sessionControls                                      = $CA.sessionControls

            $Conditions_SignInRiskLevels                          = $CA.Conditions.signInRiskLevels
            $Conditions_clientAppTypes                            = $CA.Conditions.clientAppTypes

            If ($CA.Conditions.locations.includelocations -eq $Null)    {  $Conditions_locations_includelocations  = "" }
            ElseIf ($CA.Conditions.locations.includelocations)          {  $Conditions_locations_includelocations  = $CA.Conditions.locations.includelocations    }
        
            If ($CA.Conditions.locations.excludelocations -eq $Null)    {  $Conditions_locations_excludelocations  = "" }
            ElseIf ($CA.Conditions.locations.excludelocations)          {  $Conditions_locations_excludelocations  = $CA.Conditions.locations.excludelocations    }

            $Conditions_deviceStates                              = $CA.Conditions.deviceStates
            $Conditions_devices                                   = $CA.Conditions.devices
            $Conditions_applications_includeApplications          = $CA.Conditions.applications.includeApplications
            $Conditions_applications_excludeApplications          = $CA.Conditions.applications.excludeApplications
            $Conditions_applications_includeUserActions           = $CA.Conditions.applications.includeUserActions

            $Conditions_users_includeUsers                        = $CA.Conditions.users.includeUsers
            $Conditions_users_excludeUsers                        = $CA.Conditions.users.excludeUsers
            $Conditions_users_includeUsers_id                     = $CA.Conditions.users.includeUsers
            $Conditions_users_excludeUsers_id                     = $CA.Conditions.users.excludeUsers

            $Conditions_users_includeGroups                       = $CA.Conditions.users.includeGroup
            $Conditions_users_excludeGroups                       = $CA.Conditions.users.excludeGroups
            $Conditions_users_includeGroups_id                    = $CA.Conditions.users.includeGroup
            $Conditions_users_excludeGroups_id                    = $CA.Conditions.users.excludeGroups

            $Conditions_users_includeRoles                        = $CA.Conditions.users.includeRoles
            $Conditions_users_excludeRoles                        = $CA.Conditions.users.excludeRoles
            $Conditions_users_includeRoles_id                     = $CA.Conditions.users.includeRoles
            $Conditions_users_excludeRoles_id                     = $CA.Conditions.users.excludeRoles

            $Conditions_platforms_includePlatform                 = $CA.Conditions.platforms.includePlatforms
            $Conditions_platforms_excludePlatform                 = $CA.Conditions.platforms.excludePlatforms

            $grantControls_operator                               = $CA.grantControls.operator
            $grantControls_builtInControls                        = $CA.grantControls.builtInControls
            $grantControls_customAuthenticationFactors            = $CA.grantControls.customAuthenticationFactors
            $grantControls_termsOfUse                             = $CA.grantControls.termsOfuse

            Write-Output "---------------------------------------------------------------------------------"
            Write-Output "Conditional Access ID   : $($CA.ID)"
            Write-Output "DisplayName             : $($CA.DisplayName)"
            Write-Output "State                   : $($CA.State)"
            Write-Output ""
        

            #----------------------
            # USERS
            #----------------------
            ForEach ($User in $Conditions_users_includeUsers)
                    {
                        If ( ($User -ne "All") -and ($User -ne "GuestsOrExternalUsers") )
                            {
                                # $UserInfo = Get-AzureADUser -ObjectId $User
                                $UserInfo = $Users | Where-Object { $_.Id -eq $User }

                                Write-output "Replacing $($UserInfo.Id) with $($UserInfo.DisplayName)"
                                $Conditions_users_includeUsers = $Conditions_users_includeUsers -replace $UserInfo.Id, $UserInfo.DisplayName
                            }
                    }

            ForEach ($User in $Conditions_users_excludeUsers)
                    {
                        If ( ($User -ne "All") -and ($User -ne "GuestsOrExternalUsers") )
                            {
                                $UserInfo = $Users | Where-Object { $_.Id -eq $User }
                                Write-output "Replacing $($UserInfo.Id) with $($UserInfo.DisplayName)"
                                $Conditions_users_excludeUsers = $Conditions_users_excludeUsers -replace $UserInfo.Id, $UserInfo.DisplayName
                            }
                    }

            #----------------------
            # Groups
            #----------------------
            ForEach ($Group in $Conditions_users_includeGroups)
                    {
                        If ( ($Group -ne "All") -and ($Group -ne "GuestsOrExternalUsers") )
                            {
                                $GroupInfo = $Groups | Where-Object { $_.Id -eq $Group }
                                Write-output "Replacing $($GroupInfo.Id) with $($GroupInfo.DisplayName)"
                                $Conditions_users_includeGroups = $Conditions_users_includeGroups -replace $GroupInfo.Id, $GroupInfo.DisplayName
                            }
                    }

            ForEach ($Group in $Conditions_users_excludeGroups)
                    {
                        If ( ($Group -ne "All") -and ($Group -ne "GuestsOrExternalUsers") )
                            {
                                $GroupInfo = $Groups | Where-Object { $_.Id -eq $Group }
                                Write-output "Replacing $($GroupInfo.Id) with $($GroupInfo.DisplayName)"
                                $Conditions_users_excludeGroups = $Conditions_users_excludeGroups -replace $GroupInfo.Id, $GroupInfo.DisplayName
                            }
                    }
            #----------------------
            # ROLES
            #----------------------
            ForEach ($Role in $Roles)
                {
                    $Conditions_users_includeRoles_id = $Conditions_users_includeRoles -replace $Role.Id, $Role.DisplayName
                    $Conditions_users_excludeRoles = $Conditions_users_excludeRoles -replace $Role.Id, $Role.DisplayName
                }

            #----------------------
            # Azure App reg.
            #----------------------
            ForEach ($CloudApp in $Applications)
                {
                    $Conditions_applications_includeApplications = $Conditions_applications_includeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                    $Conditions_applications_excludeApplications = $Conditions_applications_excludeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                }

            #----------------------
            # SPs
            #----------------------
            ForEach ($CloudApp in $SPs)
                {
                    $Conditions_applications_includeApplications = $Conditions_applications_includeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                    $Conditions_applications_excludeApplications = $Conditions_applications_excludeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                }


            $ConditionalAccessHash = [PSCustomObject]@{
                Id                                                   = $Id
                DisplayName                                          = $DisplayName
                State                                                = $State
                createdDateTime                                      = $CreatedDateTime
                modifiedDateTime                                     = $modifiedDateTime
                sessionControls                                      = ($SessionControls -join ',')
                Conditions_SignInRiskLevels                          = ($Conditions_signInRiskLevels -join ',')
                Conditions_clientAppTypes                            = ($Conditions_clientAppTypes -join ',')
                Conditions_locations_includelocations                = ($Conditions_locations_includelocations -join ',')
                Conditions_locations_excludelocations                = ($Conditions_locations_excludelocations -join ',')
        
                Conditions_deviceStates                              = ($Conditions_deviceStates -join ',')
                Conditions_devices                                   = ($Conditions_devices -join ',')
                Conditions_applications_includeApplications          = ($Conditions_applications_includeApplications -join ',')
                Conditions_applications_excludeApplications          = ($Conditions_applications_excludeApplications -join ',')
                Conditions_applications_includeUserActions           = ($Conditions_applications_includeUserActions -join ',')

                Conditions_users_includeUsers_id                     = ($Conditions_users_includeUsers_id -join ',')
                Conditions_users_includeUsers                        = ($Conditions_users_includeUsers -join ',')
                Conditions_users_excludeUsers_id                     = ($Conditions_users_excludeUsers_id -join ',')
                Conditions_users_excludeUsers                        = ($Conditions_users_excludeUsers -join ',')

                Conditions_users_includeGroups_id                    = ($Conditions_users_includeGroup_id -join ',')
                Conditions_users_includeGroups                       = ($Conditions_users_includeGroup -join ',')
                Conditions_users_excludeGroups_id                    = ($Conditions_users_excludeGroups_id -join ',')
                Conditions_users_excludeGroups                       = ($Conditions_users_excludeGroups -join ',')

                Conditions_users_includeRoles_id                     = ($Conditions_users_includeRoles_id -join ',')
                Conditions_users_includeRoles                        = ($Conditions_users_includeRoles -join ',')
                Conditions_users_excludeRoles_id                     = ($Conditions_users_excludeRoles_id -join ',')
                Conditions_users_excludeRoles                        = ($Conditions_users_excludeRoles -join ',')

                Conditions_platforms_includePlatform                 = ($Conditions_platforms_includePlatforms -join ',')
                Conditions_platforms_excludePlatform                 = ($Conditions_platforms_excludePlatforms -join ',')

                grantControls_operator                               = ($grantControls_operator -join ',')
                grantControls_builtInControls                        = ($grantControls_builtInControls -join ',')
                grantControls_customAuthenticationFactors            = ($grantControls_customAuthenticationFactors -join ',')
                grantControls_termsOfUse                             = ($grantControls_termsOfuse -join ',')
            }
        
            $ConditionalAccessArray += $ConditionalAccessHash
        }

$FileCSV   = ".\Entra-CA-Policies-Documentation-with-IDs.csv"
$FileExcel = ".\Entra-CA-Policies-Documentation-with-IDs.xlsx"

$ConditionalAccessArray | export-csv $FileCSV -Encoding UTF8 -Delimiter ";" -NoTypeInformation
$ConditionalAccessArray | Export-Excel -Path $FileExcel -AutoSize

#-----------------------------------------------------------------------------------
# Export Entra Conditional Access Policies to Excel XLSX + CSV (Clean)
#-----------------------------------------------------------------------------------

    Write-host "Retrieving information from Entra ID ... Please Wait !"
    $Users = Get-MgUser -All
    $Groups = Get-MgGroup -All
        
    $Roles = Get-MgRoleManagementDirectoryRoleDefinition -All
    $SPs = Get-MgServicePrincipal -All

    $Uri = "https://graph.microsoft.com/v1.0/applications"
    $Applications = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $ConditionalAccessArray = @()
    ForEach ($CA in $ConditionalAccessPolicies)
        {
            $Id                                                   = $CA.Id
            $DisplayName                                          = $CA.DisplayName
            $State                                                = $CA.State
            If ($CA.createdDateTime -eq $Null)         {  $createdDateTime  = "" }
            ElseIf ($CA.createdDateTime)               {  $createdDateTime  = $CA.createdDateTime    }

            If ($CA.modifiedDateTime -eq $Null)        {  $modifiedDateTime  = "" }
            ElseIf ($CA.modifiedDateTime)              {  $modifiedDateTime  = $CA.modifiedDateTime    }

            $sessionControls                                      = $CA.sessionControls

            $Conditions_SignInRiskLevels                          = $CA.Conditions.signInRiskLevels
            $Conditions_clientAppTypes                            = $CA.Conditions.clientAppTypes

            If ($CA.Conditions.locations.includelocations -eq $Null)    {  $Conditions_locations_includelocations  = "" }
            ElseIf ($CA.Conditions.locations.includelocations)          {  $Conditions_locations_includelocations  = $CA.Conditions.locations.includelocations    }
        
            If ($CA.Conditions.locations.excludelocations -eq $Null)    {  $Conditions_locations_excludelocations  = "" }
            ElseIf ($CA.Conditions.locations.excludelocations)          {  $Conditions_locations_excludelocations  = $CA.Conditions.locations.excludelocations    }

            $Conditions_deviceStates                              = $CA.Conditions.deviceStates
            $Conditions_devices                                   = $CA.Conditions.devices
            $Conditions_applications_includeApplications          = $CA.Conditions.applications.includeApplications
            $Conditions_applications_excludeApplications          = $CA.Conditions.applications.excludeApplications
            $Conditions_applications_includeUserActions           = $CA.Conditions.applications.includeUserActions

            $Conditions_users_includeUsers                        = $CA.Conditions.users.includeUsers
            $Conditions_users_excludeUsers                        = $CA.Conditions.users.excludeUsers
            $Conditions_users_includeUsers_id                     = $CA.Conditions.users.includeUsers
            $Conditions_users_excludeUsers_id                     = $CA.Conditions.users.excludeUsers

            $Conditions_users_includeGroups                       = $CA.Conditions.users.includeGroup
            $Conditions_users_excludeGroups                       = $CA.Conditions.users.excludeGroups
            $Conditions_users_includeGroups_id                    = $CA.Conditions.users.includeGroup
            $Conditions_users_excludeGroups_id                    = $CA.Conditions.users.excludeGroups

            $Conditions_users_includeRoles                        = $CA.Conditions.users.includeRoles
            $Conditions_users_excludeRoles                        = $CA.Conditions.users.excludeRoles
            $Conditions_users_includeRoles_id                     = $CA.Conditions.users.includeRoles
            $Conditions_users_excludeRoles_id                     = $CA.Conditions.users.excludeRoles

            $Conditions_platforms_includePlatform                 = $CA.Conditions.platforms.includePlatforms
            $Conditions_platforms_excludePlatform                 = $CA.Conditions.platforms.excludePlatforms

            $grantControls_operator                               = $CA.grantControls.operator
            $grantControls_builtInControls                        = $CA.grantControls.builtInControls
            $grantControls_customAuthenticationFactors            = $CA.grantControls.customAuthenticationFactors
            $grantControls_termsOfUse                             = $CA.grantControls.termsOfuse

            Write-Output "---------------------------------------------------------------------------------"
            Write-Output "Conditional Access ID   : $($CA.ID)"
            Write-Output "DisplayName             : $($CA.DisplayName)"
            Write-Output "State                   : $($CA.State)"
            Write-Output ""
        

            #----------------------
            # USERS
            #----------------------
            ForEach ($User in $Conditions_users_includeUsers)
                    {
                        If ( ($User -ne "All") -and ($User -ne "GuestsOrExternalUsers") )
                            {
                                # $UserInfo = Get-AzureADUser -ObjectId $User
                                $UserInfo = $Users | Where-Object { $_.Id -eq $User }

                                Write-output "Replacing $($UserInfo.Id) with $($UserInfo.DisplayName)"
                                $Conditions_users_includeUsers = $Conditions_users_includeUsers -replace $UserInfo.Id, $UserInfo.DisplayName
                            }
                    }

            ForEach ($User in $Conditions_users_excludeUsers)
                    {
                        If ( ($User -ne "All") -and ($User -ne "GuestsOrExternalUsers") )
                            {
                                $UserInfo = $Users | Where-Object { $_.Id -eq $User }
                                Write-output "Replacing $($UserInfo.Id) with $($UserInfo.DisplayName)"
                                $Conditions_users_excludeUsers = $Conditions_users_excludeUsers -replace $UserInfo.Id, $UserInfo.DisplayName
                            }
                    }

            #----------------------
            # Groups
            #----------------------
            ForEach ($Group in $Conditions_users_includeGroups)
                    {
                        If ( ($Group -ne "All") -and ($Group -ne "GuestsOrExternalUsers") )
                            {
                                $GroupInfo = $Groups | Where-Object { $_.Id -eq $Group }
                                Write-output "Replacing $($GroupInfo.Id) with $($GroupInfo.DisplayName)"
                                $Conditions_users_includeGroups = $Conditions_users_includeGroups -replace $GroupInfo.Id, $GroupInfo.DisplayName
                            }
                    }

            ForEach ($Group in $Conditions_users_excludeGroups)
                    {
                        If ( ($Group -ne "All") -and ($Group -ne "GuestsOrExternalUsers") )
                            {
                                $GroupInfo = $Groups | Where-Object { $_.Id -eq $Group }
                                Write-output "Replacing $($GroupInfo.Id) with $($GroupInfo.DisplayName)"
                                $Conditions_users_excludeGroups = $Conditions_users_excludeGroups -replace $GroupInfo.Id, $GroupInfo.DisplayName
                            }
                    }
            #----------------------
            # ROLES
            #----------------------
            ForEach ($Role in $Roles)
                {
                    $Conditions_users_includeRoles_id = $Conditions_users_includeRoles -replace $Role.Id, $Role.DisplayName
                    $Conditions_users_excludeRoles = $Conditions_users_excludeRoles -replace $Role.Id, $Role.DisplayName
                }

            #----------------------
            # Azure App reg.
            #----------------------
            ForEach ($CloudApp in $Applications)
                {
                    $Conditions_applications_includeApplications = $Conditions_applications_includeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                    $Conditions_applications_excludeApplications = $Conditions_applications_excludeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                }

            #----------------------
            # SPs
            #----------------------
            ForEach ($CloudApp in $SPs)
                {
                    $Conditions_applications_includeApplications = $Conditions_applications_includeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                    $Conditions_applications_excludeApplications = $Conditions_applications_excludeApplications -replace $CloudApp.AppID, $CloudApp.DisplayName
                }


            $ConditionalAccessHash = [PSCustomObject]@{
                DisplayName                                          = $DisplayName
                State                                                = $State
                sessionControls                                      = ($SessionControls -join ',')
                Conditions_SignInRiskLevels                          = ($Conditions_signInRiskLevels -join ',')
                Conditions_clientAppTypes                            = ($Conditions_clientAppTypes -join ',')
                Conditions_locations_includelocations                = ($Conditions_locations_includelocations -join ',')
                Conditions_locations_excludelocations                = ($Conditions_locations_excludelocations -join ',')
        
                Conditions_deviceStates                              = ($Conditions_deviceStates -join ',')
                Conditions_devices                                   = ($Conditions_devices -join ',')
                Conditions_applications_includeApplications          = ($Conditions_applications_includeApplications -join ',')
                Conditions_applications_excludeApplications          = ($Conditions_applications_excludeApplications -join ',')
                Conditions_applications_includeUserActions           = ($Conditions_applications_includeUserActions -join ',')

                Conditions_users_includeUsers                        = ($Conditions_users_includeUsers -join ',')
                Conditions_users_excludeUsers                        = ($Conditions_users_excludeUsers -join ',')

                Conditions_users_includeGroups                       = ($Conditions_users_includeGroup -join ',')
                Conditions_users_excludeGroups                       = ($Conditions_users_excludeGroups -join ',')

                Conditions_users_includeRoles                        = ($Conditions_users_includeRoles -join ',')
                Conditions_users_excludeRoles                        = ($Conditions_users_excludeRoles -join ',')

                Conditions_platforms_includePlatform                 = ($Conditions_platforms_includePlatforms -join ',')
                Conditions_platforms_excludePlatform                 = ($Conditions_platforms_excludePlatforms -join ',')

                grantControls_operator                               = ($grantControls_operator -join ',')
                grantControls_builtInControls                        = ($grantControls_builtInControls -join ',')
                grantControls_customAuthenticationFactors            = ($grantControls_customAuthenticationFactors -join ',')
                grantControls_termsOfUse                             = ($grantControls_termsOfuse -join ',')
            }
        
            $ConditionalAccessArray += $ConditionalAccessHash
        }

$FileCSV   = ".\Entra-CA-Policies-Documentation.csv"
$FileExcel = ".\Entra-CA-Policies-Documentation.xlsx"

$ConditionalAccessArray | export-csv $FileCSV -Encoding UTF8 -Delimiter ";" -NoTypeInformation
$ConditionalAccessArray | Export-Excel -Path $FileExcel -AutoSize

