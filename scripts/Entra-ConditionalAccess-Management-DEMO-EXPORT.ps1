<#
.SYNOPSIS
    Entra-ConditionalAccess-Management-DEMO-EXPORT - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : Entra-ConditionalAccess-Management-DEMO-EXPORT.ps1
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


#####################################################################################################################
# Export Entra ID Conditional Access Policies as JSON
#####################################################################################################################

    $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
    $ConditionalAccessPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

    $ConditionalAccessPoliciesJSON = $ConditionalAccessPolicies | ConvertTo-Json -Depth 20


    $OutPutPath = $global:PathScripts + "\OUTPUT" + "\" + "CAPolicies"
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

$FileCSV   = $global:PathScripts + "\OUTPUT" + "\" + "Entra-CA-Policies-Documentation-with-IDs.csv"
$FileExcel = $global:PathScripts + "\OUTPUT" + "\" + "Entra-CA-Policies-Documentation-with-IDs.xlsx"

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

$FileCSV   = $global:PathScripts + "\OUTPUT" + "\" + "Entra-CA-Policies-Documentation.csv"
$FileExcel = $global:PathScripts + "\OUTPUT" + "\" + "Entra-CA-Policies-Documentation.xlsx"

$ConditionalAccessArray | export-csv $FileCSV -Encoding UTF8 -Delimiter ";" -NoTypeInformation
$ConditionalAccessArray | Export-Excel -Path $FileExcel -AutoSize
