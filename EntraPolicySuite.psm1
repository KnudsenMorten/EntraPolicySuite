Function BreakGlassValidation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$BreakGlassAccountsGroup,
        [Parameter()]
        [object]$BreakGlassAccounts

    )

    If (!($BreakGlassAccountsGroup))
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is OK !"
            Write-host ""
        }


    If (!($BreakGlassAccounts))
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is OK !"
            Write-host ""
        }
}


function ConvertTo-HashTable() {
<#
 .Synopsis
  Convert PSCustomObject to HashTable
 .Description
  Convert PSCustomObject to HashTable
 .Example
  Get-Content "test.json" | ConvertFrom-Json | ConvertTo-HashTable
#>
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)]
        $object,
        [switch] $recurse
    )
    $ht = @{}
    if ($object -is [System.Collections.Specialized.OrderedDictionary] -or $object -is [hashtable]) {
        $object.Keys | ForEach-Object {
            if ($recurse -and ($object."$_" -is [System.Collections.Specialized.OrderedDictionary] -or $object."$_" -is [hashtable] -or $object."$_" -is [PSCustomObject])) {
                $ht[$_] = ConvertTo-HashTable $object."$_" -recurse
            }
            else {
                $ht[$_] = $object."$_"
            }
        }
    }
    elseif ($object -is [PSCustomObject]) {
        $object.PSObject.Properties | ForEach-Object {
            if ($recurse -and ($_.Value -is [System.Collections.Specialized.OrderedDictionary] -or $_.Value -is [hashtable] -or $_.Value -is [PSCustomObject])) {
                $ht[$_.Name] = ConvertTo-HashTable $_.Value -recurse
            }
            else {
                $ht[$_.Name] = $_.Value
            }
        }
    }
    $ht
}



Function EntraAuthenticationStrength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Description,
        [Parameter(Mandatory)]
        [ValidateSet("Password", "MFA", "Biometric", "WindowsHelloForBusiness", "FIDO2", "Combination")]
        [string[]]$RequiredStrengths,
        [Parameter()]
        [string[]]$CombinationConfigurations,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Get all existing authentication strength policies
    $ExistingPolicies = Get-MgAuthenticationStrengthPolicy -All

    # Check if the policy already exists
    $ExistingPolicy = $ExistingPolicies | Where-Object { $_.displayName -eq $PolicyName }

    # Build the hash table for the policy parameters
    $PolicyParams = @{
        displayName = $PolicyName
        policyType = "authenticationStrength"
        requiredStrengths = $RequiredStrengths
    }

    if ($PSBoundParameters.ContainsKey('Description')) {
        $PolicyParams.description = $Description
    }

    if ($PSBoundParameters.ContainsKey('CombinationConfigurations')) {
        $PolicyParams.combinationConfigurations = $CombinationConfigurations
    }

    if ($ExistingPolicy) {
        if ($ForceUpdate) {
            Write-Host "Updating existing authentication strength policy: $PolicyName"
            Update-MgAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $ExistingPolicy.id -BodyParameter $PolicyParams
        } else {
            Write-Host "Policy $PolicyName already exists. Use -ForceUpdate to update the existing policy."
        }
    } else {
        Write-Host "Creating new authentication strength policy: $PolicyName"
        New-MgAuthenticationStrengthPolicy -BodyParameter $PolicyParams
    }
}


Function EntraCAPolicy
{
#region function parameters

    [CmdletBinding()]
    param(
            [Parameter()]
                [switch]$ViewOnly,
            [Parameter()]
                [switch]$CreateOnly,
            [Parameter()]
                [switch]$CreateUpdate,
            [Parameter()]
                [ValidateSet("enabled","disabled","enabledForReportingButNotEnforced")]
                [string]$State = "Off",
            [Parameter()]
                [string]$CAPolicyPrefix,
            [Parameter()]
                [array]$CAPolicyPrefixArray,
            [Parameter()]
                [string]$DisplayName,

    # applications - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_App_IncludeApplications,      # list, All, Office365, MicrosoftAdminPortals
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_App_ExcludeApplications,    # list, All, Office365, MicrosoftAdminPortals
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_App_ApplicationFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_App_ApplicationFilter_Rule,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("urn:user:registersecurityinfo","urn:user:registerdevice")]
                [string[]]$Cond_App_IncludeUserActions,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("c1","c2","c3","c4","c5","c6","c7","c8","c9","c10","c11","c12","c13","c14","c15","c16","c17","c18","c19","c20","c21","c22","c23","c24","c25")]
                [string[]]$Cond_App_IncludeAuthenticationContextClassReferences,

    # authenticationFlows - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","deviceCodeFlow","authenticationTransfer","unknownFutureValue")]
                [string]$Cond_AuthenticationFlows_TransferMethods,

    # users - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeUsers,    # list, None, All, GuestsOrExternalUsers.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeUsers,    # list, GuestsOrExternalUsers
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeGroups,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeGroups,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeRoles,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeRoles,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
          # "@odata.type": "#microsoft.graph.conditionalAccessGuestsOrExternalUsers",
          # "externalTenants": {
          #   "@odata.type": "microsoft.graph.conditionalAccessExternalTenants"
          #  },
          # "guestOrExternalUserTypes": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","internalGuest","b2bCollaborationGuest","b2bCollaborationMember","b2bDirectConnectUser","otherExternalUser","otherExternalUser","unknownFutureValue")]
                [string[]]$Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes,

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","internalGuest","b2bCollaborationGuest","b2bCollaborationMember","b2bDirectConnectUser","otherExternalUser","otherExternalUser","unknownFutureValue")]
                [string[]]$Cond_Users_ExcludeGuestsOrExternalUsers_GuestOrExternalUserTypes,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
           # "@odata.type": "#microsoft.graph.conditionalAccessExternalTenants",
           # "membershipKind": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind,

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_ExcludeGuestsOrExternalUsers_ExternalTenants_MembershipKind,

        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessenumeratedexternaltenants?view=graph-rest-beta
           # "@odata.type": "#microsoft.graph.conditionalAccessEnumeratedExternalTenants"
           #  "members": ["String"],
           #  "membershipKind": "String"

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_IncludeGuestsOrExternalUsers_EnumeratedExternalTenants_MembershipKind,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_IncludeGuestsOrExternalUsers_EnumeratedExternalTenants_Members,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all","enumerated","unknownFutureValue")]
                [string]$Cond_Users_ExcludeGuestsOrExternalUsers_EnumeratedExternalTenants_MembershipKind,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Users_ExcludeGuestsOrExternalUsers_EnumeratedExternalTenants_Members,

    # clientApplications - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
          # "@odata.type": "#microsoft.graph.conditionalAccessClientApplications",
          # "includeServicePrincipals": [
          #  "String"
          # ],
          # "excludeServicePrincipals": [
          #  "String"
          # ],
          # "servicePrincipalFilter": {"@odata.type": "microsoft.graph.conditionalAccessFilter"},


            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_ClientApp_includeServicePrincipals,    # Client applications (service principals and workload identities)
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_ClientApp_excludeServicePrincipals,    # Client applications (service principals and workload identities)
         
         # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessfilter?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_ClientApp_servicePrincipalFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_ClientApp_servicePrincipalFilter_Rule,

    # clientAppTypes - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
    # [ValidateSet("none","all","browser","mobileAppsAndDesktopClients","exchangeActiveSync","other")]

            [Parameter()]
                [AllowEmptyString()]
                [AllowEmptyCollection()]
                [AllowNull()]
                [array]$Cond_ClientAppTypes,

    # deviceStates - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevicestates?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all")]
                [Array]$Cond_DeviceStates_IncludeStates,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("Compliant","DomainJoined")]
                [Array]$Cond_DeviceStates_ExcludeStates,

    # devices - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("all")]
                [Array]$Cond_Devices_IncludeDevices,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("Compliant","DomainJoined")]
                [Array]$Cond_Devices_ExcludeDevices,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("include","exclude")]
                [string]$Cond_Devices_DeviceFilter_Mode,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$Cond_Devices_DeviceFilter_Rule,

    # Locations - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Locations_IncludeLocations,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$Cond_Locations_ExcludeLocations,

    # platforms - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","all","android","iOS","windows","windowsPhone","macOS","linux","unknownFutureValue")]
                [string[]]$Cond_Platforms_IncludePlatforms,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("none","all","android","iOS","windows","windowsPhone","macOS","linux","unknownFutureValue")]
                [string[]]$Cond_Platforms_ExcludePlatforms,

    # servicePrincipalRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [string[]]$Cond_servicePrincipalRiskLevels,


    # signInRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [string[]]$Cond_SignInRiskLevels,

    # UserRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [Array]$Cond_UserRiskLevels,

    # insiderRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [Array]$Cond_InsiderRiskLevels,

    # grantControls - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$GC_Operator,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$GC_BuiltInControls,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string[]]$GC_TermsOfUse,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$GC_authenticationStrength,

    # sessionControls - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_Value,   # The number of days or hours
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_AuthenticationType,   # primaryAndSecondaryAuthentication, secondaryAuthentication, unknownFutureValue
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_FrequencyInterval,  # #timeBased, everyTime, unknownFutureValue. Sign-in frequency of everyTime is available for risky users, risky sign-ins, Intune device enrollment, any application, authentication context, and user actions.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SignInFrequency_Type,   # days, hours, or null if frequencyInterval is everyTime
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_ContinuousAccessEvaluation_Mode,  # strictEnforcement, disabled, unknownFutureValue, strictLocation.
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_ApplicationEnforcedRestrictions_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [Array]$SC_DisableResilienceDefaults,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_PersistentBrowser_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_PersistentBrowser_Mode,   # always, never
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_SecureSignInSession_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [boolean]$SC_CloudAppSecurity_IsEnabled,
            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [string]$SC_CloudAppSecurity_CloudAppSecurity_Type   # mcasConfigured, monitorOnly, blockDownloads
    )
#endregion

    If ( (-not ($PSBoundParameters.ContainsKey('ViewOnly')) -and (-not ($PSBoundParameters.ContainsKey('CreateUpdate')) )) -and (-not ($PSBoundParameters.ContainsKey('CreateOnly')) ) )
        {
            Write-host "Missing switch. You need to add either -ViewOnly, -CreateOnly or -CreateUpdate"
            Break
        }

    ElseIf ( ($PSBoundParameters.ContainsKey('ViewOnly')) -or ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
        {
            $Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
            $ConditionalAccessPolicies_ALL = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

            If ( ($PSBoundParameters.ContainsKey('DisplayName')) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefix')) )
                {
                    write-host "Using CAPolicyPrefix to find policy (scenario 1)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                }
            ElseIf ( (!($PSBoundParameters.ContainsKey('DisplayName'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefix')) -or (!($PSBoundParameters.ContainsKey('CAPolicyPrefixArray'))) )
                {
                    write-host "Using CAPolicyPrefix to find policy (scenario 2)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                }
            ElseIf ( ($PSBoundParameters.ContainsKey('DisplayName')) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefixArray')) )
                {
                    write-host "Using CAPolicyPrefixArray to find policy (scenario 3)"
                    $FoundPol = $false
                    ForEach ($CAPolicyPrefix in $CAPolicyPrefixArray)
                        {
                            If (!($FoundPol))
                                {
                                    $CAPolicyChk = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                                    If ($CAPolicyChk)
                                        {
                                            $FoundPol = $true
                                            $CAPolicy = $CAPolicyChk
                                        }
                                }
                        }
                }
            ElseIf ( (!($PSBoundParameters.ContainsKey('DisplayName'))) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and ($PSBoundParameters.ContainsKey('CAPolicyPrefixArray')) )
                {
                    write-host "Using CAPolicyPrefixArray to find policy (scenario 4)"
                    $FoundPol = $false
                    ForEach ($CAPolicyPrefix in $CAPolicyPrefixArray)
                        {
                            If (!($FoundPol))
                                {
                                    $CAPolicyChk = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -like "$($CAPolicyPrefix)*" }
                                    If ($CAPolicyChk)
                                        {
                                            $FoundPol = $true
                                            $CAPolicy = $CAPolicyChk
                                        }
                                }
                        }
                }
            ElseIf ( ($PSBoundParameters.ContainsKey('DisplayName')) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefix'))) -and (!($PSBoundParameters.ContainsKey('CAPolicyPrefixArray'))) )
                {
                    write-host "Using DisplayName to find policy (scenario 5)"
                    $CAPolicy = $ConditionalAccessPolicies_ALL | Where-Object { $_.DisplayName -eq $DisplayName }
                }

            If (!($CAPolicy))
                {
                    write-host ""
                    write-host "Policy not found ... creating new !"
                    $PolicyFound = $false
                    $CAPolicy = [PSCustomObject]@{}
                }
            ElseIf ( ($CAPolicy) -and ($PSBoundParameters.ContainsKey('ViewOnly')) )
                {
                    $PolicyFound = $true
                    $PolicyId = $CAPolicy.Id
                    $PolicyDisplayName = $CAPolicy.DisplayName

                    $CAPolicy | ConvertTo-Json -Depth 20
                }
            ElseIf ( ($CAPolicy) -and ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
                {
                    $PolicyFound = $true
                    $PolicyId = $CAPolicy.Id
                    $PolicyDisplayName = $CAPolicy.DisplayName
                    write-host ""
                    write-host "Existing values (Begin)"
                    write-host ""
                    $CAPolicy | ConvertTo-Json -Depth 20
                    write-host ""
                    write-host "Existing values (End)"
                    write-host ""
                }
        }


    If ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')))
        {
            $CAPolicyAuthStrengthOdata = $CAPolicy.grantControls.'authenticationStrength@odata.context'
            
            # Resetting value to ensure only updated values are applied
            $CAPolicy = [PSCustomObject]@{}

            ###############################################################################
            # displayName
            ###############################################################################

#region displayName
                $InputVariable = $DisplayName
                $ExistingData  = $CAPolicy.displayName
                $FunctionArg   = 'displayName'

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy | add-member -MemberType NoteProperty -Name "displayName" -Value $InputVariable -Force
                    }
#endregion

            ###############################################################################
            # state
            ###############################################################################

#region state
                $InputVariable = $state
                $ExistingData  = $CAPolicy.state
                $FunctionArg   = 'state'

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy | add-member -MemberType NoteProperty -Name "state" -Value $InputVariable -Force
                    }

#endregion
    
            ###############################################################################
            # conditions.applications.IncludeApplications (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeApplications (array)
                $InputVariable = $Cond_App_IncludeApplications
                $ExistingData  = $CAPolicy.conditions.applications.includeApplications
                $FunctionArg   = 'Cond_App_IncludeApplications'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "IncludeApplications" -Value $nestedObject -Force
                            }
                    }
        
                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.includeApplications = $InputVariable
                    }
#endregion

            ###############################################################################
            # conditions.applications.ExcludeApplications (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.ExcludeApplications (array)

                $InputVariable = $Cond_App_ExcludeApplications
                $ExistingData  = $CAPolicy.conditions.applications.excludeApplications
                $FunctionArg   = 'Cond_App_ExcludeApplications'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.ExcludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "ExcludeApplications" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.excludeApplications = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.applications.applicationFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.applicationFilter.mode (value)

                $InputVariable = $Cond_App_ApplicationFilter_Mode
                $ExistingData  = $CAPolicy.conditions.applications.ApplicationFilter
                $FunctionArg   = 'Cond_App_ApplicationFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.applicationFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "applicationFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.applicationFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.applications.applicationFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.applicationFilter.rule (value)

                $InputVariable = $Cond_App_ApplicationFilter_Rule
                $ExistingData  = $CAPolicy.conditions.applications.ApplicationFilter
                $FunctionArg   = 'Cond_App_ApplicationFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "applicationFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.applicationFilter += @{ Rule = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.applications.IncludeUserActions (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeUserActions (array)

                $InputVariable = $Cond_App_IncludeUserActions
                $ExistingData  = $CAPolicy.conditions.applications.IncludeUserActions
                $FunctionArg   = 'Cond_App_IncludeUserActions'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.IncludeUserActions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "IncludeUserActions" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.IncludeUserActions = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.applications.IncludeAuthenticationContextClassReferences (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.applications.IncludeAuthenticationContextClassReferences (array)

                $InputVariable = $Cond_App_IncludeAuthenticationContextClassReferences
                $ExistingData  = $CAPolicy.conditions.applications.IncludeAuthenticationContextClassReferences
                $FunctionArg   = 'Cond_App_IncludeAuthenticationContextClassReferences'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "applications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.applications.includeAuthenticationContextClassReferences.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.applications | add-member -MemberType NoteProperty -Name "includeAuthenticationContextClassReferences" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.applications.includeAuthenticationContextClassReferences = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.authenticationFlows (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-beta
            ###############################################################################

#region conditions.authenticationFlows (value)

                $InputVariable = $Cond_AuthenticationFlows_TransferMethods
                $ExistingData  = $CAPolicy.conditions.AuthenticationFlows
                $FunctionArg   = 'Cond_AuthenticationFlows_TransferMethods'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.authenticationFlows.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "authenticationFlows" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.authenticationFlows += @{ transferMethods = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.includeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeUsers (array)

                $InputVariable = $Cond_Users_IncludeUsers
                $ExistingData  = $CAPolicy.conditions.users.includeUsers
                $FunctionArg   = 'Cond_Users_IncludeUsers'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.includeusers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "includeUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeUsers = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeUsers (array)
 
                $InputVariable = $Cond_Users_excludeUsers
                $ExistingData  = $CAPolicy.conditions.users.excludeUsers
                $FunctionArg   = 'Cond_Users_ExcludeUsers'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.excludeusers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeUsers = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeUsers (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeUsers (array)

                $InputVariable = $Cond_Users_IncludeGroups
                $ExistingData  = $CAPolicy.conditions.users.includegroups
                $FunctionArg   = 'Cond_Users_IncludeGroups'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGroups.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeGroups" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGroups = $InputVariable
                    }


#endregion

            ###############################################################################
            # conditions.users.excludeGroups (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGroups (array)

                $InputVariable = $Cond_Users_excludeGroups
                $ExistingData  = $CAPolicy.conditions.users.excludegroups
                $FunctionArg   = 'Cond_Users_ExcludeGroups'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGroups.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGroups" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGroups = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeRoles (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeRoles (array)

                $InputVariable = $Cond_Users_IncludeRoles
                $ExistingData  = $CAPolicy.conditions.users.includeroles
                $FunctionArg   = 'Cond_Users_IncludeRoles'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeRoles.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeRoles" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeRoles = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeRoles (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeRoles (array)

                $InputVariable = $Cond_Users_excludeRoles
                $ExistingData  = $CAPolicy.conditions.users.excluderoles
                $FunctionArg   = 'Cond_Users_ExcludeRoles'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeRoles.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeRoles" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeRoles = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
            ###############################################################################


#region conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes (value)

                $InputVariable = $Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes
                $ExistingData  = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers
                $FunctionArg   = 'Cond_Users_IncludeGuestsOrExternalUsers_GuestOrExternalUserTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.includeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "includeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGuestsOrExternalUsers += @{ guestOrExternalUserTypes = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.includeGuestsOrExternalUsers.externalTenants.membershipKind (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
            ###############################################################################

#region conditions.users.includeGuestsOrExternalUsers.externalTenants.membershipKind (value)

                $InputVariable = $Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind
                $ExistingData  = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.ExternalTenants
                $FunctionArg   = 'Cond_Users_IncludeGuestsOrExternalUsers_ExternalTenants_MembershipKind'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "IncludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers.externalTenants.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users.IncludeGuestsOrExternalUsers | add-member -MemberType NoteProperty -Name "externalTenants" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.includeGuestsOrExternalUsers.externalTenants += @{ 
                                                                                                        '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
                                                                                                        membershipKind = $InputVariable
                                                                                                    }
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes (value)

                $InputVariable = $Cond_Users_excludeGuestsOrExternalUsers_GuestOrExternalUserTypes
                $ExistingData  = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers
                $FunctionArg   = 'Cond_Users_excludeGuestsOrExternalUsers_GuestOrExternalUserTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGuestsOrExternalUsers += @{ guestOrExternalUserTypes = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-beta
            ###############################################################################

#region conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind (value)

                $InputVariable = $Cond_Users_excludeGuestsOrExternalUsers_ExternalTenants_MembershipKind
                $ExistingData  = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.ExternalTenants
                $FunctionArg   = 'Cond_Users_excludeGuestsOrExternalUsers_ExternalTenants_MembershipKind'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "users" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.users | add-member -MemberType NoteProperty -Name "ExcludeGuestsOrExternalUsers" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers.externalTenants.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.users.ExcludeGuestsOrExternalUsers | add-member -MemberType NoteProperty -Name "externalTenants" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.users.excludeGuestsOrExternalUsers.externalTenants += @{ 
                                                                                                        '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
                                                                                                        membershipKind = $InputVariable
                                                                                                   }
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.includeServicePrincipals (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################


#region conditions.clientApplications.includeServicePrincipals (array)

                $InputVariable = $Cond_ClientApp_includeServicePrincipals
                $ExistingData  = $CAPolicy.conditions.ClientApplications.includeServicePrincipals
                $FunctionArg   = 'Cond_ClientApp_includeServicePrincipals'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.includeServicePrincipals.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "includeServicePrincipals" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.includeServicePrincipals = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.excludeServicePrincipals (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.excludeServicePrincipals (array)

                $InputVariable = $Cond_ClientApp_excludeServicePrincipals
                $ExistingData  = $CAPolicy.conditions.ClientApplications.excludeServicePrincipals
                $FunctionArg   = 'Cond_ClientApp_ExcludeServicePrincipals'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.ExcludeServicePrincipals.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "ExcludeServicePrincipals" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.excludeServicePrincipals = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.servicePrincipalFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.servicePrincipalFilter.mode (value)

                $InputVariable = $Cond_ClientApp_servicePrincipalFilter_Mode
                $ExistingData  = $CAPolicy.conditions.ClientApplications.servicePrincipalFilter
                $FunctionArg   = 'Cond_ClientApp_servicePrincipalFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.servicePrincipalFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "servicePrincipalFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.servicePrincipalFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.clientApplications.servicePrincipalFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta
            ###############################################################################

#region conditions.clientApplications.servicePrincipalFilter.rule (value)

                $InputVariable = $Cond_ClientApp_servicePrincipalFilter_Rule
                $ExistingData  = $CAPolicy.conditions.ClientApplications.servicePrincipalFilter
                $FunctionArg   = 'Cond_ClientApp_servicePrincipalFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientApplications" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientApplications.servicePrincipalFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.clientApplications | add-member -MemberType NoteProperty -Name "servicePrincipalFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientApplications.servicePrincipalFilter += @{ rule = $InputVariable }
                    }
#endregion

            ###############################################################################
            # conditions.clientAppTypes (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            # Possible values are: all, browser, mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other
            ###############################################################################

#region conditions.clientAppTypes (array)

                $InputVariable = $Cond_ClientAppTypes
                $ExistingData  = $CAPolicy.conditions.ClientAppTypes
                $FunctionArg   = 'Cond_ClientAppTypes'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.clientAppTypes.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "clientAppTypes" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.clientAppTypes = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.deviceStates.includeStates (array)
            ###############################################################################

#region conditions.deviceStates.includeStates (array)

                $InputVariable = $Cond_DeviceStates_IncludeStates
                $ExistingData  = $CAPolicy.conditions.DeviceStates.IncludeStates
                $FunctionArg   = 'Cond_DeviceStates_IncludeStates'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devicestates.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devicestates" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devicestates.IncludeStates.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.devicestates | add-member -MemberType NoteProperty -Name "IncludeStates" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.deviceStates.IncludeStates = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.deviceStates.excludeStates (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevicestates?view=graph-rest-beta
            ###############################################################################

#region conditions.deviceStates.excludeStates (array)

                $InputVariable = $Cond_DeviceStates_excludeStates
                $ExistingData  = $CAPolicy.conditions.DeviceStates.excludeStates
                $FunctionArg   = 'Cond_DeviceStates_excludeStates'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devicestates.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devicestates" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devicestates.ExcludeStates.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.devicestates | add-member -MemberType NoteProperty -Name "ExcludeStates" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.deviceStates.excludeStates = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.devices.includeDevices (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.includeDevices (array)

                $InputVariable = $Cond_Devices_IncludeDevices
                $ExistingData  = $CAPolicy.conditions.Devices.IncludeDevices
                $FunctionArg   = 'Cond_Devices_IncludeDevices'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.IncludeDevices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "IncludeDevices" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.includeDevices = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.devices.excludeDevices (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.excludeDevices (array)

                $InputVariable = $Cond_Devices_excludeDevices
                $ExistingData  = $CAPolicy.conditions.Devices.excludeDevices
                $FunctionArg   = 'Cond_Devices_excludeDevices'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.ExcludeDevices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "ExcludeDevices" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.excludeDevices = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.devices.deviceFilter.mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.deviceFilter.mode (value)

                $InputVariable = $Cond_Devices_DeviceFilter_Mode
                $ExistingData  = $CAPolicy.conditions.Devices.DeviceFilter
                $FunctionArg   = 'Cond_Devices_DeviceFilter_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.deviceFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "deviceFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.deviceFilter += @{ mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.devices.deviceFilter.rule (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
            ###############################################################################

#region conditions.devices.deviceFilter.rule (value)

                $InputVariable = $Cond_Devices_DeviceFilter_Rule
                $ExistingData  = $CAPolicy.conditions.Devices.DeviceFilter
                $FunctionArg   = 'Cond_Devices_DeviceFilter_Rule'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "devices" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.devices.deviceFilter.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.conditions.devices | add-member -MemberType NoteProperty -Name "deviceFilter" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.devices.deviceFilter += @{ rule = $InputVariable }
                    }

#endregion

            ###############################################################################
            # conditions.locations.IncludeLocations (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            ###############################################################################

#region conditions.locations.IncludeLocations (array)
                $InputVariable = $Cond_Locations_IncludeLocations
                $ExistingData  = $CAPolicy.conditions.Locations.IncludeLocations
                $FunctionArg   = 'Cond_Locations_IncludeLocations'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Locations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "Locations" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.locations.IncludeLocations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.locations | add-member -MemberType NoteProperty -Name "IncludeLocations" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.locations.IncludeLocations = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.locations.excludeLocations (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-beta
            ###############################################################################

#region conditions.locations.excludeLocations (array)

                $InputVariable = $Cond_Locations_excludeLocations
                $ExistingData  = $CAPolicy.conditions.Locations.excludeLocations
                $FunctionArg   = 'Cond_Locations_excludeLocations'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Locations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "Locations" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.locations.ExcludeLocations.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.locations | add-member -MemberType NoteProperty -Name "ExcludeLocations" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.locations.excludeLocations = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.platforms.includePlatforms (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta
            ###############################################################################

#region conditions.platforms.includePlatforms (array)

                $InputVariable = $Cond_Platforms_IncludePlatforms
                $ExistingData  = $CAPolicy.conditions.platforms.includePlatforms
                $FunctionArg   = 'Cond_Platforms_IncludePlatforms'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Platforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "platforms" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.IncludePlatforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.platforms | add-member -MemberType NoteProperty -Name "IncludePlatforms" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.platforms.includePlatforms = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.platforms.excludePlatforms (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-beta
            ###############################################################################

#region conditions.platforms.excludePlatforms (array)

                $InputVariable = $Cond_Platforms_excludePlatforms
                $ExistingData  = $CAPolicy.conditions.platforms.excludePlatforms
                $FunctionArg   = 'Cond_Platforms_excludePlatforms'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "platforms" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.platforms.ExcludePlatforms.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions.platforms | add-member -MemberType NoteProperty -Name "ExcludePlatforms" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.platforms.excludePlatforms = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.servicePrincipalRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.servicePrincipalRiskLevels (array)

                $InputVariable = $Cond_servicePrincipalRiskLevels
                $ExistingData  = $CAPolicy.conditions.servicePrincipalRiskLevels
                $FunctionArg   = 'Cond_servicePrincipalRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.servicePrincipalRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "servicePrincipalRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.servicePrincipalRiskLevels = $InputVariable
                    }

#endregion

            ###############################################################################
            # conditions.signInRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.signInRiskLevels (array)

                $InputVariable = $Cond_signInRiskLevels
                $ExistingData  = $CAPolicy.conditions.signInRiskLevels
                $FunctionArg   = 'Cond_signInRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.signInRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "signInRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.signInRiskLevels = $InputVariable
                    }


#endregion

            ###############################################################################
            # conditions.UserRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.UserRiskLevels (array)

                $InputVariable = $Cond_UserRiskLevels
                $ExistingData  = $CAPolicy.conditions.UserRiskLevels
                $FunctionArg   = 'Cond_UserRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.UserRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "UserRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.UserRiskLevels = $InputVariable
                    }
#endregion

            ###############################################################################
            # conditions.insiderRiskLevels (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta
            ###############################################################################

#region conditions.insiderRiskLevels (array)

                $InputVariable = $Cond_insiderRiskLevels
                $ExistingData  = $CAPolicy.conditions.insiderRiskLevels
                $FunctionArg   = 'Cond_insiderRiskLevels'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "conditions" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.conditions.insiderRiskLevels.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.conditions | add-member -MemberType NoteProperty -Name "insiderRiskLevels" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.conditions.insiderRiskLevels = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.operator (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            ###############################################################################

#region grantControls.operator (value)

                $InputVariable = $GC_operator
                $ExistingData  = $CAPolicy.grantControls
                $FunctionArg   = 'GC_operator'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls = @{ operator = $InputVariable }
                    }

#endregion

            ###############################################################################
            # grantControls.builtInControls (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            # Possible values: AND, OR
            ###############################################################################

#region grantControls.builtInControls (array)

                $InputVariable = $GC_builtInControls
                $ExistingData  = $CAPolicy.grantControls
                $FunctionArg   = 'GC_builtInControls'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.builtInControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "builtInControls" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls.builtInControls = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.termsOfUse (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            # Possible values: block, mfa, compliantDevice, domainJoinedDevice, approvedApplication, compliantApplication, passwordChange, unknownFutureValue
            ###############################################################################

#region grantControls.termsOfUse (array)

                $InputVariable = $GC_termsOfUse
                $ExistingData  = $CAPolicy.grantControls.termsOfUse
                $FunctionArg   = 'GC_termsOfUse'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.termsOfUse.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "termsOfUse" -Value $nestedObject -Force
                            }
                    }

                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.grantControls.termsOfUse = $InputVariable
                    }

#endregion

            ###############################################################################
            # grantControls.authenticationStrength (array)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-beta
            ###############################################################################

#region grantControls.authenticationStrength (array)

                $InputVariable = $GC_authenticationStrength
                $ExistingData  = $CAPolicy.grantControls.authenticationStrength
                $FunctionArg   = 'GC_authenticationStrength'


                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.grantControls.authenticationStrength.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy.grantControls | add-member -MemberType NoteProperty -Name "authenticationStrength" -Value $NestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        If ($InputVariable)
                            {
                                $AuthenticationStrengths = Get-MgPolicyAuthenticationStrengthPolicy
    
                                $authStrengthPolicy = $AuthenticationStrengths | Where-Object { ( ($_.DisplayName -eq "$($InputVariable)") -or ($_.DisplayName -like "*$($InputVariable)*") -or ($_.Id -eq "$($InputVariable)") ) }

                                If ($authStrengthPolicy)
                                    {
                                        $authStrengthPolicyid = $authStrengthPolicy.id

                                        $CAPolicy.grantControls += @{
                                                                        'authenticationStrength@odata.context' = $CAPolicyAuthStrengthOdata
                                                                        authenticationStrength = @{ 
                                                                                                    id = $authStrengthPolicyId
                                                                                                  }
                                                                    }
                                    }
                            }
                        Else
                            {
                                write-host "AuthenticationStrength is being set to null"
                                $NullAuthStrength = [PSCustomObject]@{}
                    
                                $NestedObject = [PSCustomObject]@{}
                                $NullAuthStrength | add-member -MemberType NoteProperty -Name "grantControls" -Value $nestedObject -Force
                    
                                $NullAuthStrength.grantControls | add-member -MemberType NoteProperty -Name "authenticationStrength" -Value $null -Force
                                $NullAuthStrengthHash = ConvertTo-Hashtable $NullAuthStrength -recurse

                                $Result = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($PolicyId)" -Body $NullAuthStrengthHash
                            }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.Value (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.Value (value)

                $InputVariable = $SC_SignInFrequency_Value
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.value
                $FunctionArg   = 'SC_SignInFrequency_Value'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ value = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.AuthenticationType (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.AuthenticationType (value)

                $InputVariable = $SC_SignInFrequency_AuthenticationType
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.AuthenticationType
                $FunctionArg   = 'SC_SignInFrequency_AuthenticationType'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ AuthenticationType = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.Type (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.Type (value)

                $InputVariable = $SC_SignInFrequency_Type
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.Type
                $FunctionArg   = 'SC_SignInFrequency_Type'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ Type = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.isEnabled (value)

                $InputVariable = $SC_SignInFrequency_IsEnabled
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.IsEnabled
                $FunctionArg   = 'SC_SignInFrequency_IsEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ isEnabled = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.SignInFrequency.FrequencyInterval (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.SignInFrequency.FrequencyInterval (value)

                $InputVariable = $SC_SignInFrequency_frequencyInterval
                $ExistingData  = $CAPolicy.sessionControls.SignInFrequency.frequencyInterval
                $FunctionArg   = 'SC_SignInFrequency_frequencyInterval'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.SignInFrequency.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "SignInFrequency" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.SignInFrequency += @{ frequencyInterval = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.persistentBrowser.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.persistentBrowser.isEnabled (value)

                $InputVariable = $SC_persistentBrowser_IsEnabled
                $ExistingData  = $CAPolicy.sessionControls.persistentBrowser.isEnabled
                $FunctionArg   = 'SC_persistentBrowser_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.persistentBrowser.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "persistentBrowser" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.persistentBrowser += @{ IsEnabled = $InputVariable }
                    }
#endregion

            ###############################################################################
            # sessionControls.persistentBrowser.Mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            # Possible values are: always, never
            ###############################################################################

#region sessionControls.persistentBrowser.Mode (value)

                $InputVariable = $SC_persistentBrowser_Mode
                $ExistingData  = $CAPolicy.sessionControls.persistentBrowser.Mode
                $FunctionArg   = 'SC_persistentBrowser_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.persistentBrowser.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "persistentBrowser" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.persistentBrowser += @{ Mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.disableResilienceDefaults (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.disableResilienceDefaults (value)

                $InputVariable = $SC_disableResilienceDefaults
                $ExistingData  = $CAPolicy.sessionControls.disableResilienceDefaults
                $FunctionArg   = 'SC_disableResilienceDefaults'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls += @{ disableResilienceDefaults = $InputVariable }
                    }
#endregion

            ###############################################################################
            # sessionControls.continuousAccessEvaluation.Mode (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.continuousAccessEvaluation.Mode (value)

                $InputVariable = $SC_continuousAccessEvaluation_Mode
                $ExistingData  = $CAPolicy.sessionControls.continuousAccessEvaluation.Mode
                $FunctionArg   = 'SC_continuousAccessEvaluation_Mode'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.continuousAccessEvaluation.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "continuousAccessEvaluation" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.continuousAccessEvaluation = @{ Mode = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.cloudAppSecurity.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.cloudAppSecurity.isEnabled (value)

                $InputVariable = $SC_cloudAppSecurity_isEnabled
                $ExistingData  = $CAPolicy.sessionControls.cloudAppSecurity.isEnabled
                $FunctionArg   = 'SC_cloudAppSecurity_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.cloudAppSecurity.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "cloudAppSecurity" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.cloudAppSecurity += @{ IsEnabled = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.cloudAppSecurity.cloudAppSecurityType (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.cloudAppSecurity.cloudAppSecurityType (value)

                $InputVariable = $SC_CloudAppSecurity_CloudAppSecurity_Type
                $ExistingData  = $CAPolicy.sessionControls.cloudAppSecurity.cloudAppSecurityType
                $FunctionArg   = 'SC_CloudAppSecurity_CloudAppSecurity_Type'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.cloudAppSecurity.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "cloudAppSecurity" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.cloudAppSecurity += @{ cloudAppSecurityType = $InputVariable }
                    }

#endregion

            ###############################################################################
            # sessionControls.applicationEnforcedRestrictions.isEnabled (value)
            # https://learn.microsoft.com/en-us/graph/api/resources/applicationenforcedrestrictionssessioncontrol?view=graph-rest-beta
            ###############################################################################

#region sessionControls.applicationEnforcedRestrictions.isEnabled (value)

                $InputVariable = $SC_applicationEnforcedRestrictions_isEnabled
                $ExistingData  = $CAPolicy.sessionControls.applicationEnforcedRestrictions.isEnabled
                $FunctionArg   = 'SC_applicationEnforcedRestrictions_isEnabled'

                If ( (!($ExistingData)) -and ($PSBoundParameters.ContainsKey($FunctionArg)) )  # variable was defined explicitly !
                    {
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = [PSCustomObject]@{}
                                $CAPolicy | add-member -MemberType NoteProperty -Name "sessionControls" -Value $nestedObject -Force
                            }
                        #-----------------------------------------------------------------------------------------------------------
                        Try 
                            { 
                                $Result = $CAPolicy.sessionControls.applicationEnforcedRestrictions.Gettype()
                            }   
                        Catch 
                            { 
                                $NestedObject = @{}
                                $CAPolicy.sessionControls | add-member -MemberType NoteProperty -Name "applicationEnforcedRestrictions" -Value $nestedObject -Force
                            }
                    }


                If ($PSBoundParameters.ContainsKey($FunctionArg))
                    {
                        $CAPolicy.sessionControls.applicationEnforcedRestrictions += @{ isEnabled = $InputVariable }
                    }
#endregion

            #--------------------------------------------------------------------------------------------------------------------
            $CAPolicyNew = $CAPolicy

            write-host ""
            write-host "New values (Begin)"
            write-host ""
            $CAPolicyNew | ConvertTo-Json -Depth 20
            write-host ""
            write-host "New values (End)"
            write-host ""

            $CAPolicyNewHash = ConvertTo-Hashtable $CAPolicyNew -recurse

            if ( ($PolicyFound) -and ($PSBoundParameters.ContainsKey('CreateUpdate')) )
                {
                    Try
                        {
                            write-host ""
                            write-host "Updating existing CA policy ( $($PolicyDisplayName) ) "
                            Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -BodyParameter $CAPolicyNewHash
                        }
                    Catch
                        {
                            $_
                        }
                }
            ElseIf ( (!($PolicyFound)) -and ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly'))) )
                {
                    Try
                        {
                            write-host ""
                            write-host "Creating new CA policy"
                            New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $CAPolicyNewHash
                        }
                    Catch
                        {
                            $_
                        }
                }
        }

    # Return
    If ($PSBoundParameters.ContainsKey('ViewOnly'))
        {
            If ($CAPolicy)
                {
                    Return $CAPolicy
                }
        }
    ElseIf ( ($PSBoundParameters.ContainsKey('CreateUpdate')) -or ($PSBoundParameters.ContainsKey('CreateOnly')) )
        {
            If ($CAPolicyNew)
                {
                    Return $CAPolicyNew
                }
        }
}



Function EntraGroup {
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$EntraGroupsHashTable,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Description,
        [Parameter()]
        [ValidateSet("Assigned", "DynamicMembership")]
        [string]$GroupType,
        [Parameter()]
        [switch]$AutomaticMailNickname,
        [Parameter()]
        [string]$MailNickname,
        [Parameter()]
        [string]$GroupQuery,
        [Parameter()]
        [boolean]$MailEnabled,
        [Parameter()]
        [boolean]$SecurityEnabled,
        [Parameter()]
        [string]$AdministrativeUnitPlacement,
        [Parameter()]
        [ValidateSet("On", "Paused")]
        [string]$MembershipRuleProcessingState,
        [Parameter()]
        [switch]$CreateOnly,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Retrieve all Entra Groups and populate hash table if not provided
    if (-not $EntraGroupsHashTable) {
        $EntraGroupsHashTable = [ordered]@{}
        Get-MgGroup -All | ForEach-Object { $EntraGroupsHashTable[$_.DisplayName] = $_ }
    }

    if ($EntraGroupsHashTable.Count -eq 0) {
        Write-host ""
        Write-Host "No Entra Groups found."
        Write-host ""
        return
    }

    # Build hash for group properties
    $CmdToRun_Hash = @{}
    if ($PSBoundParameters.ContainsKey('Description')) { $CmdToRun_Hash['description'] = $Description }
    if ($PSBoundParameters.ContainsKey('DisplayName')) { $CmdToRun_Hash['displayName'] = $DisplayName }
    if ($GroupType -eq "DynamicMembership") { $CmdToRun_Hash['GroupType'] = $GroupType }
    if ($PSBoundParameters.ContainsKey('GroupQuery')) { $CmdToRun_Hash['MembershipRule'] = $GroupQuery }
    if ($PSBoundParameters.ContainsKey('MailEnabled')) { $CmdToRun_Hash['MailEnabled'] = $MailEnabled }
    if ($PSBoundParameters.ContainsKey('SecurityEnabled')) { $CmdToRun_Hash['SecurityEnabled'] = $SecurityEnabled }
    if ($PSBoundParameters.ContainsKey('MembershipRuleProcessingState')) { $CmdToRun_Hash['membershipRuleProcessingState'] = $MembershipRuleProcessingState }

$global:test = $CmdToRun_Hash

    # Handle MailNickname
    if ($PSBoundParameters.ContainsKey('MailNickname') -and -not $AutomaticMailNickname) {
        $MailNickname = $MailNickname.Replace(" ", "")
        if ($MailNickname.Length -gt 64) {
            $MailNickname = $MailNickname.Substring(0, 50) + (Get-Random -Minimum 100000 -Maximum 10000000)
        }
        $CmdToRun_Hash['MailNickname'] = $MailNickname
    }

    if ($AutomaticMailNickname) {
        $MailNickname = $DisplayName.Replace(" ", "")
        if ($MailNickname.Length -gt 64) {
            $MailNickname = $MailNickname.Substring(0, 50) + (Get-Random -Minimum 100000 -Maximum 10000000)
        }
        $CmdToRun_Hash['MailNickname'] = $MailNickname
    }

    # Check if group exists and handle accordingly
    if ($EntraGroupsHashTable.ContainsKey($DisplayName)) {
        $GroupExist = $EntraGroupsHashTable[$DisplayName]

        if ($PSBoundParameters.ContainsKey('ForceUpdate')) {
            $CmdToRun_Hash['GroupId'] = $GroupExist.Id
            Write-host "----------------------------"
            Write-Host "Updating group: $DisplayName"
            Write-host ""
            try {
                $Result = Update-MgGroup @CmdToRun_Hash
            } catch {
                Write-host ""
                Write-Host "Error updating group: $_"
                Write-host ""
            }
        } else {
            Write-host "----------------------------"
            Write-Host "Group already exists: $DisplayName"
            Write-host ""
            $Result = $GroupExist
        }
    } elseif ($PSBoundParameters.ContainsKey('CreateOnly')) {
        Write-host "----------------------------"
        Write-Host "Creating group: $DisplayName"
        Write-host ""
        try {
            $Result = New-MgGroup @CmdToRun_Hash
            Write-host ""
            Write-Host "Group created successfully."
            Write-host ""
        } catch {
            Write-host ""
            Write-Host "Error creating group: $_"
            Write-host ""
        }
    } else {
        Write-host ""
        Write-Host "Group does not exist. Use -Create to create a new group."
        Write-host ""
        return
    }

    # Perform a final check to ensure the group was created/updated correctly
    Write-host ""
    Write-Host "Verifying the group with DisplayName: $DisplayName"
    Write-host ""
    $finalCheckGroups = Get-MgGroup -Filter "displayName eq '$DisplayName'"

    # Check for multiple records
    if ($finalCheckGroups.Count -gt 1) {
        throw "More than one group found with DisplayName: $DisplayName"
        break
    }

    # Return the result of the final check
    Write-host ""
    return $finalCheckGroups
}


Function EntraGroupsAsHashtable {

$Entra_ID_Groups_ALL = Get-MgGroup -All

# order Groups into hash
$EntraGroupsHashTable = [ordered]@{}
$Entra_ID_Groups_ALL | ForEach-Object { $EntraGroupsHashTable.add($_.DisplayName,$_) }
Return $EntraGroupsHashTable
}


Function EntraNamedLocation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$DisplayName,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$ip4Range,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$ip6Range,
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [array]$countriesAndRegions,
        [Parameter()]
        [switch]$countryNamedLocation,
        [Parameter()]
        [switch]$ipNamedLocation,
        [Parameter()]
        [boolean]$includeUnknownCountriesAndRegions,
        [Parameter()]
        [switch]$ListALL,
        [Parameter()]
        [switch]$AppendExisting,
        [Parameter()]
        [boolean]$isTrusted,
        [Parameter()]
        [string]$countryLookupMethod,
        [Parameter()]
        [switch]$Create,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Get all Entra Named Locations
    $Entra_Named_Locations_ALL = Get-MgIdentityConditionalAccessNamedLocation
    If (($Entra_Named_Locations_ALL) -and ($PSBoundParameters.ContainsKey('ListALL'))) {
        Return $Entra_Named_Locations_ALL
    }

    If ($DisplayName) {
        # Check if Named Location exists
        $Named_Location = $Entra_Named_Locations_ALL | Where-Object { $_.displayName -eq $DisplayName }

        # countryNamedLocation
        If ($PSBoundParameters.ContainsKey('countryNamedLocation')) {
            If ($countriesAndRegions) {
                If ($PSBoundParameters.ContainsKey('AppendExisting')) {
                    $NewcountriesAndRegions = @()
                    $NewcountriesAndRegions += $Named_Location.countriesAndRegions
                    $NewcountriesAndRegions += $countriesAndRegions
                    # Remove duplicates
                    $NewcountriesAndRegions = $NewcountriesAndRegions | Sort-Object -Unique
                } Else {
                    $NewcountriesAndRegions = @()
                    $NewcountriesAndRegions += $countriesAndRegions
                }

                $Params = @{
                    '@odata.type' = '#microsoft.graph.countryNamedLocation'
                    displayName = $DisplayName
                    isTrusted = $isTrusted
                    countriesAndRegions = $NewcountriesAndRegions
                    includeUnknownCountriesAndRegions = $includeUnknownCountriesAndRegions
                    countryLookupMethod = $countryLookupMethod
                }
            } Else {
                Write-host ""
                Write-Host "Syntax error countryNamedLocation. You need to define a list in two-letter format specified by ISO 3166-2"
                Write-host ""
                Break
            }
        }

        # ipNamedLocation
        If ($PSBoundParameters.ContainsKey('ipNamedLocation')) {
            If (($ip4Range) -or ($ip6Range)) {
                If ($PSBoundParameters.ContainsKey('AppendExisting')) {
                    $Newip4Range = @()
                    $Newip4Range += $Named_Location.ipRanges | Where-Object { $_.odata.type -eq '#microsoft.graph.iPv4CidrRange' }
                    $Newip4Range += $ip4Range

                    $Newip6Range = @()
                    $Newip6Range += $Named_Location.ipRanges | Where-Object { $_.odata.type -eq '#microsoft.graph.iPv6CidrRange' }
                    $Newip6Range += $ip6Range

                    # Remove duplicates
                    $Newip4Range = $Newip4Range | Sort-Object -Unique
                    $Newip6Range = $Newip6Range | Sort-Object -Unique
                } Else {
                    $Newip4Range = $ip4Range | Sort-Object -Unique
                    $Newip6Range = $ip6Range | Sort-Object -Unique
                }

                $Params = @{
                    '@odata.type' = '#microsoft.graph.ipNamedLocation'
                    displayName = $DisplayName
                    isTrusted = $isTrusted
                    ipRanges = @()
                }

                If ($Newip4Range) {
                    $Params.ipRanges += $Newip4Range | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.iPv4CidrRange'
                            cidrAddress = $_
                        }
                    }
                }

                If ($Newip6Range) {
                    $Params.ipRanges += $Newip6Range | ForEach-Object {
                        @{
                            '@odata.type' = '#microsoft.graph.iPv6CidrRange'
                            cidrAddress = $_
                        }
                    }
                }
            } Else {
                Write-host ""
                Write-Host "Syntax error ipNamedLocation. You need to define a list in IPv4 CIDR format (e.g., 1.2.3.4/32) or any allowable IPv6 format from IETF RFC596"
                Write-host ""
                Break
            }
        }

        If ($Named_Location) { # found -> Update or View existing
            If ($ForceUpdate) {
                Write-host ""
                Write-Host "Updating Named Location"
                Write-host ""
                Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Named_Location.id -BodyParameter $Params
            } Else {
                Return $Named_Location
            }
        } Else {
            If ($Create) {
                Write-host ""
                Write-Host "Creating Named Location"
                Write-host ""
                New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Params
            } Else {
                Write-host ""
                Write-Host "Named Location does not exist. Use -Create to create a new named location."
                Write-host ""
            }
        }
    } Else {
        Write-host ""
        Write-Host "DisplayName is required to create, update, or view a named location."
        Write-host ""
    }

    # Return Parameters
    $NamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq '$displayName'"
    Return $NamedLocation
}


Function EntraUser {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$DisplayName,
        [Parameter()]
        [string]$UserPrincipalName,
        [Parameter()]
        [string]$MailNickname,
        [Parameter()]
        [string]$Password,
        [Parameter()]
        [string]$GivenName,
        [Parameter()]
        [string]$Surname,
        [Parameter()]
        [string]$JobTitle,
        [Parameter()]
        [string]$Department,
        [Parameter()]
        [string]$MobilePhone,
        [Parameter()]
        [string]$OfficeLocation,
        [Parameter()]
        [switch]$Create,
        [Parameter()]
        [switch]$ForceUpdate
    )

    # Function to get user by UserPrincipalName
    Function Get-MgUserByUPN {
        param (
            [Parameter(Mandatory)]
            [string]$UPN
        )
        try {
            $User = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
            return $User
        } catch {
            return $null
        }
    }

    # Function to get user by DisplayName
    Function Get-MgUserByDisplayName {
        param (
            [Parameter(Mandatory)]
            [string]$DisplayName
        )
        try {
            $User = Get-MgUser -Filter "displayName eq '$DisplayName'"
            return $User
        } catch {
            return $null
        }
    }

    # Check if the user already exists
    $ExistingUserByUPN = if ($UserPrincipalName) { Get-MgUserByUPN -UPN $UserPrincipalName } else { $null }
    $ExistingUserByDisplayName = if ($DisplayName) { Get-MgUserByDisplayName -DisplayName $DisplayName } else { $null }

    $ExistingUser = if ($null -ne $ExistingUserByUPN) { $ExistingUserByUPN } elseif ($null -ne $ExistingUserByDisplayName) { $ExistingUserByDisplayName } else { $null }

    if ($null -ne $ExistingUser) {
        if ($ForceUpdate) {
            # Update existing user
            Write-host ""
            Write-Host "Updating user: $DisplayName"
            Write-host ""
            $UpdateParams = @{}
            if ($PSBoundParameters.ContainsKey('DisplayName')) { $UpdateParams.displayName = $DisplayName }
            if ($PSBoundParameters.ContainsKey('MailNickname')) { $UpdateParams.mailNickname = $MailNickname }
            if ($PSBoundParameters.ContainsKey('GivenName')) { $UpdateParams.givenName = $GivenName }
            if ($PSBoundParameters.ContainsKey('Surname')) { $UpdateParams.surname = $Surname }
            if ($PSBoundParameters.ContainsKey('JobTitle')) { $UpdateParams.jobTitle = $JobTitle }
            if ($PSBoundParameters.ContainsKey('Department')) { $UpdateParams.department = $Department }
            if ($PSBoundParameters.ContainsKey('MobilePhone')) { $UpdateParams.mobilePhone = $MobilePhone }
            if ($PSBoundParameters.ContainsKey('OfficeLocation')) { $UpdateParams.officeLocation = $OfficeLocation }

            try {
                Update-MgUser -UserId $ExistingUser.id -BodyParameter $UpdateParams
                Write-host ""
                Write-Host "User updated successfully."
                Write-host ""
                return $ExistingUser
            } catch {
                Write-host ""
                Write-Host "Error updating user: $_"
                Write-host ""
            }
        } else {
            Write-Host "User already exists: $($ExistingUser.displayName)"
            return $ExistingUser
        }
    } else {
        if ($Create) {
            # Ensure DisplayName and UserPrincipalName are provided for creation
            if (-not $DisplayName -or -not $UserPrincipalName) {
                Write-Host "DisplayName and UserPrincipalName are required to create a new user."
                Write-host ""
                return
            }

            # Create new user
            Write-host ""
            Write-Host "Creating new user: $DisplayName"
            $UserParams = @{
                accountEnabled = $true
                displayName = $DisplayName
                userPrincipalName = $UserPrincipalName
            }

            if ($PSBoundParameters.ContainsKey('MailNickname')) { $UserParams.mailNickname = $MailNickname }
            if ($PSBoundParameters.ContainsKey('Password')) {
                $UserParams.passwordProfile = @{
                    forceChangePasswordNextSignIn = $true
                    password = $Password
                }
            }
            if ($PSBoundParameters.ContainsKey('GivenName')) { $UserParams.givenName = $GivenName }
            if ($PSBoundParameters.ContainsKey('Surname')) { $UserParams.surname = $Surname }
            if ($PSBoundParameters.ContainsKey('JobTitle')) { $UserParams.jobTitle = $JobTitle }
            if ($PSBoundParameters.ContainsKey('Department')) { $UserParams.department = $Department }
            if ($PSBoundParameters.ContainsKey('MobilePhone')) { $UserParams.mobilePhone = $MobilePhone }
            if ($PSBoundParameters.ContainsKey('OfficeLocation')) { $UserParams.officeLocation = $OfficeLocation }

            try {
                $NewUser = New-MgUser -BodyParameter $UserParams
                Write-host ""
                Write-Host "User created successfully: $($NewUser.id)"
                Write-host ""
                return $NewUser
            } catch {
                Write-host ""
                Write-Host "Error creating user: $_"
                Write-host ""
            }
        } else {
            Write-Host "User does not exist. Use -Create to create a new user."
            Write-host ""
        }
    }
}


Function Generate-SecurePassword {
    param (
        [int]$length = 16
    )
    # Define the characters to use in the password
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?'
    # Generate the password
    $password = -join ((1..$length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    return $password
}


Function Get-MgAuthenticationStrengthPolicy {
    param(
        [Parameter()]
        [string]$All
    )
    # Replace with actual call to Microsoft Graph API to get authentication strength policies
    @()
}


Function New-MgAuthenticationStrengthPolicy {
    param(
        [Parameter(Mandatory)]
        [hashtable]$BodyParameter
    )
    # Replace with actual call to Microsoft Graph API to create new authentication strength policies
}


Function Update-MgAuthenticationStrengthPolicy {
    param(
        [Parameter(Mandatory)]
        [string]$AuthenticationStrengthPolicyId,
        [Parameter(Mandatory)]
        [hashtable]$BodyParameter
    )
    # Replace with actual call to Microsoft Graph API to update authentication strength policies
}



# SIG # Begin signature block
# MIIaigYJKoZIhvcNAQcCoIIaezCCGncCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDVwslkpOQxi3yI
# f9GZ6Rr/EJXXa5h4ecTV6nbXJjV4zKCCFsUwggNfMIICR6ADAgECAgsEAAAAAAEh
# WFMIojANBgkqhkiG9w0BAQsFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3Qg
# Q0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2ln
# bjAeFw0wOTAzMTgxMDAwMDBaFw0yOTAzMTgxMDAwMDBaMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# zCV2kHkGeCIW9cCDtoTKKJ79BXYRxa2IcvxGAkPHsoqdBF8kyy5L4WCCRuFSqwyB
# R3Bs3WTR6/Usow+CPQwrrpfXthSGEHm7OxOAd4wI4UnSamIvH176lmjfiSeVOJ8G
# 1z7JyyZZDXPesMjpJg6DFcbvW4vSBGDKSaYo9mk79svIKJHlnYphVzesdBTcdOA6
# 7nIvLpz70Lu/9T0A4QYz6IIrrlOmOhZzjN1BDiA6wLSnoemyT5AuMmDpV8u5BJJo
# aOU4JmB1sp93/5EU764gSfytQBVI0QIxYRleuJfvrXe3ZJp6v1/BE++bYvsNbOBU
# aRapA9pu6YOTcXbGaYWCFwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
# AQH/BAUwAwEB/zAdBgNVHQ4EFgQUj/BLf6guRSSuTVD6Y5qL3uLdG7wwDQYJKoZI
# hvcNAQELBQADggEBAEtA28BQqv7IDO/3llRFSbuWAAlBrLMThoYoBzPKa+Z0uboA
# La6kCtP18fEPir9zZ0qDx0R7eOCvbmxvAymOMzlFw47kuVdsqvwSluxTxi3kJGy5
# lGP73FNoZ1Y+g7jPNSHDyWj+ztrCU6rMkIrp8F1GjJXdelgoGi8d3s0AN0GP7URt
# 11Mol37zZwQeFdeKlrTT3kwnpEwbc3N29BeZwh96DuMtCK0KHCz/PKtVDg+Rfjbr
# w1dJvuEuLXxgi8NBURMjnc73MmuUAaiZ5ywzHzo7JdKGQM47LIZ4yWEvFLru21Vv
# 34TuBQlNvSjYcs7TYlBlHuuSl4Mx2bO1ykdYP18wggWiMIIEiqADAgECAhB4AxhC
# RXCKQc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNp
# Z24gUm9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH
# bG9iYWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEds
# b2JhbFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE
# 9aNDm5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GN
# swWyKIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLH
# Qx2iCXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH
# 4nSr/2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+
# ocCc4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/
# vZWV7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF
# 1i7nj5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlu
# fKa7fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmg
# BzfEZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeH
# dZrUSpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8C
# AwEAAaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86W
# OzAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRu
# MGwwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
# MzA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNl
# cnQvcm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggr
# BgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8w
# DQYJKoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti
# 2eEYXLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qo
# Lao89uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gu
# p7EL4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mo
# fnrekw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDU
# swarAGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wgga/MIIEp6ADAgEC
# AhEAgU5CF6Epf+1azNQX+JGtdTANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2ln
# biBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwHhcNMjQwNjE5MDMyNTExWhcNMzgwNzI4
# MDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
# YTEvMC0GA1UEAxMmR2xvYmFsU2lnbiBHQ0MgUjQ1IENvZGVTaWduaW5nIENBIDIw
# MjAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDWQk3540/GI/RsHYGm
# MPdIPc/Q5Y3lICKWB0Q1XQbPDx1wYOYmVPpTI2ACqF8CAveOyW49qXgFvY71Txkk
# mXzPERabH3tr0qN7aGV3q9ixLD/TcgYyXFusUGcsJU1WBjb8wWJMfX2GFpWaXVS6
# UNCwf6JEGenWbmw+E8KfEdRfNFtRaDFjCvhb0N66WV8xr4loOEA+COhTZ05jtiGO
# 792NhUFVnhy8N9yVoMRxpx8bpUluCiBZfomjWBWXACVp397CalBlTlP7a6GfGB6K
# Dl9UXr3gW8/yDATS3gihECb3svN6LsKOlsE/zqXa9FkojDdloTGWC46kdncVSYRm
# giXnQwp3UrGZUUL/obLdnNLcGNnBhqlAHUGXYoa8qP+ix2MXBv1mejaUASCJeB+Q
# 9HupUk5qT1QGKoCvnsdQQvplCuMB9LFurA6o44EZqDjIngMohqR0p0eVfnJaKnsV
# ahzEaeawvkAZmcvSfVVOIpwQ4KFbw7MueovE3vFLH4woeTBFf2wTtj0s/y1Kiirs
# KA8tytScmIpKbVo2LC/fusviQUoIdxiIrTVhlBLzpHLr7jaep1EnkTz3ohrM/Ifl
# l+FRh2npIsyDwLcPRWwH4UNP1IxKzs9jsbWkEHr5DQwosGs0/iFoJ2/s+PomhFt1
# Qs2JJnlZnWurY3FikCUNCCDx/wIDAQABo4IBhjCCAYIwDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0O
# BBYEFNqzjcAkkKNrd9MMoFndIWdkdgt4MB8GA1UdIwQYMBaAFB8Av0aACvx4Obel
# tEPZVlC7zpY7MIGTBggrBgEFBQcBAQSBhjCBgzA5BggrBgEFBQcwAYYtaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1MEYGCCsGAQUF
# BzAChjpodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9jb2Rlc2ln
# bmluZ3Jvb3RyNDUuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1LmNybDAuBgNVHSAEJzAlMAgG
# BmeBDAEEATALBgkrBgEEAaAyATIwDAYKKwYBBAGgMgoEAjANBgkqhkiG9w0BAQsF
# AAOCAgEAMhDkvBelgxBAndOp/SfPRXKpxR9LM1lvLDIxeXGE1jZn1at0/NTyBjpu
# tdbL8UKDlr193pUsGu1q40EcpsiJMcJZbIm8KiMDWVBHSf1vUw4qKMxIVO/zIxhb
# kjZOvKNj1MP7AA+A0SDCyuWWuvCaW6qkJXoZ2/rbe1NP+baj2WPVdV8BpSjbthgp
# FGV5nNu064iYFFNQYDEMZrNR427JKSZk8BTRc3jEhI0+FKWSWat5QUbqNM+BdkY6
# kXgZc77+BvXXwYQ5oHBMCjUAXtgqMCQfMne24Xzfs0ZB4fptjePjC58vQNmlOg1k
# yb6M0RrJZSA64gD6TnohN0FwmZ1QH5l7dZB0c01FpU5Yf912apBYiWaTZKP+VPdN
# quvlIO5114iyHQw8vKGSoFbkR/xnD+p4Kd+Po8fZ4zF4pwsplGscJ10hJ4fio+/I
# QJAuXBcoJdMBRBergNp8lKhbI/wgnpuRoZD/sw3lckQsRxXz1JFyJvnyBeMBZ/dp
# td4Ftv4okIx/oSk7tyzaZCJplsT001cNKoXGu2horIvxUktkbqq4t+xNFBz6qBQ4
# zuwl6+Ri3TX5uHsHXRtDZwIIaz2/JSODgZZzB+7+WFo8N9qg21/SnDpGkpzEJhwJ
# MNol5A4dkHPUHodOaYSBkc1lfuc1+oOAatM0HUaneAimeDIlZnowggb1MIIE3aAD
# AgECAgx5Y9ljauM7cdkFAm4wDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24g
# R0NDIFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwMB4XDTIzMDMyNzEwMjEzNFoXDTI2
# MDMyMzE2MTgxOFowYzELMAkGA1UEBhMCREsxEDAOBgNVBAcTB0tvbGRpbmcxEDAO
# BgNVBAoTBzJsaW5rSVQxEDAOBgNVBAMTBzJsaW5rSVQxHjAcBgkqhkiG9w0BCQEW
# D21va0AybGlua2l0Lm5ldDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AMykjWtM6hY5IRPeVIVB+yX+3zcMJQR2gjTZ81LnGVRE94Zk2GLFAwquGYWt1sho
# THTV5j6Ef2AXYBDVkNruisJVJ17UsMGdsU8upwdZblFbLNzLw+qBXVC/OUVua9M0
# cub7CfUNkn/Won4D7i41QyuDXdZFOIfRhZ3qnCYCJCSgYLoUXAS6xei2tPkkk1w8
# aXEFxybyy7eRqQjkHqIS5N4qH3YQkz+SbSlz/yj6mD65H5/Ts+lZxX2xL/8lgJIt
# pdaJx+tarprv/tT++n9a13P53YNzCWOmyhd376+7DMXxxSzT24kq13Ks3xnUPGoW
# Ux2UPRnJHjTWoBfgY7Zd3MffrdO0QEoDC9X5F5boh6oankVSOdSPRFns085KI+vk
# bt3bdG62MIeUbNtSv7mZBX8gcYv0szlo0ey7bbOJWoiZFT2fB+pBVvxDhpYP0/3a
# FveM1wfhshaJBhxx/2GCswYYBHH7B3+8j4BT8N8S030q4snys2Qt9tdFIHvSV7lI
# w/yorT1WM1cr+Lqo74eR+Hi982db0k68p2BGdCOY0QhhaNqxufwbK+gVWrQY57GI
# X/1cUrBt0akMsli219xVmUGhIw85ZF7wcQplhslbUxyNUilY+c93q1bsIFjaOnjj
# vo56g+kyKICm5zsGFQLRVaXUSLY+i8NSiH8fd64etaptAgMBAAGjggGxMIIBrTAO
# BgNVHQ8BAf8EBAMCB4AwgZsGCCsGAQUFBwEBBIGOMIGLMEoGCCsGAQUFBzAChj5o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0NWNvZGVz
# aWduY2EyMDIwLmNydDA9BggrBgEFBQcwAYYxaHR0cDovL29jc3AuZ2xvYmFsc2ln
# bi5jb20vZ3NnY2NyNDVjb2Rlc2lnbmNhMjAyMDBWBgNVHSAETzBNMEEGCSsGAQQB
# oDIBMjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9y
# ZXBvc2l0b3J5LzAIBgZngQwBBAEwCQYDVR0TBAIwADBFBgNVHR8EPjA8MDqgOKA2
# hjRodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1Y29kZXNpZ25jYTIw
# MjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFNqzjcAkkKNr
# d9MMoFndIWdkdgt4MB0GA1UdDgQWBBQxxpY2q5yrKa7VFODTZhTfPKmyyTANBgkq
# hkiG9w0BAQsFAAOCAgEAe38NgZR4IV9u264/n/jiWlHbBu847j1vpN6dovxMvdUQ
# Z780eH3JzcvG8fo91uO1iDIZksSigiB+d8Sj5Yvh+oXlfYEffjIQCwcIlWNciOzW
# YZzl9qPHXgdTnaIuJA5cR846TepQLVMXc1Yb72Z7OGjldmRIxGjRimDsmzY+TdTu
# 15lF4IkUj0VJhr8FPYOdEVZVOXHtPmUjPqsq9M7WpALYbc0pUawcy0FOOwXqzaCk
# 7O3vMXej4Oycm6RBGfRH3JPOCvH2ddiIfPq2Lce4nhTuLsgumBJE2vOalVddIfTB
# jE9PpMub15lHyp1mfW0ZJvXOghPvRqufMT3SjPTHt6PV8LwhQD8BiGSZ9rp94js4
# xTnGexSOFKLLMxWEPTr5EPe3kmtspGgKCqLEZvsMYz7JlWNuaHBy+vdQZWV3376l
# uwV4IHfGT+1wxe0E90dMRI+9SNIKkVvKV3FUtToZUh3Np4cCIHJLQ1eslXFzIJa6
# wrjVsnWM/3OyedpQJERGNYXlVmxdgGFjrY1I6UWII0Y1iZW3t+JvhXosUaha8i/Y
# SxaDH+5H/Klad2OZXq4Eg39QxkCELbmJmSU0sUYNnl0JTEu6jJY9UJMFikzf5s3p
# 2ZuKdyMbRgN5GNNV883meI/X5KVHBJDG1epigMer7fFXMVZUGoI12iIz/gOolQEx
# ggMbMIIDFwIBATBpMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMS8wLQYDVQQDEyZHbG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcg
# Q0EgMjAyMAIMeWPZY2rjO3HZBQJuMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKuMVexz
# rfUAowD83qyCAVZ5VbtBgC+VuZlZLYf6FpN9MA0GCSqGSIb3DQEBAQUABIICAL2a
# NKnxcVZ65erVDMmmtLkjR7byhzqLlxaaw1eD3qg01RLCISkENoIyYINnU8PB8/89
# 0ZVjr4G1b71xJkHjk4aMLjwvBtHRaNfGYzKl5k2IfI1wRvd1k7jlfks1/428IYCU
# h1ysh3tDHqK1BOkv3Zr3sAbRRQFMFFO9+95tPXN3ek9YapSlhVcq/BA3jf7GVeBA
# Cu1J4leGif96O5jNrkGtnx1EDhaI4Fu/G4yWPM8zo4MYniha0hSruKshHe9gtv1U
# NJ2h9P8lrLG7FnKnZfyPxaC/YW41kgX5gvmfz0pl5eQpbQ7CbddwBFGiC+eLXvyT
# 66gqxUQ7mylxjRGOJarPiZvrn6ntBV2Cigl4rFhtlQovDZ0H2kxMNXl0In2xv9uK
# f5EvTPdgfrsfUZPiKU/oRT+v2USbvCj8J8zsUYPbS6rGr1gN4Yi8vBc4i3IBM9lG
# v8MAwcYkDMGo8G/cTeZCPoDxImE+Sn2dENCnFHfA9ZkhKMrLNJmJX4TfbzTZZ9Sh
# gghZVaDlBqVbjN5l/OhZrh4JzZLZINYu0D0+IafCm7brEXMWvLxMUpodKCyuOjVl
# guZfgRwxFYvNA6a8F+kl8sWMa/Bzik/L7ccc9ml2lZKy5zRnhly+0xf82Q47HWvW
# CQqORM2GNVNcMK+57Y12+yTrWcLfR31q9lKzdQS8
# SIG # End signature block
