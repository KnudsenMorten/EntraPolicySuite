Function EntraCAPolicy {
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

    # devices - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-beta
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
                [ValidateSet("low","medium","high","hidden","none","unknownFutureValue")]
                [string[]]$Cond_SignInRiskLevels,

    # UserRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("low","medium","high","none","unknownFutureValue")]
                [string[]]$Cond_UserRiskLevels,

    # insiderRiskLevels - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta

            [Parameter()]
                [AllowEmptyString()]
                [AllowNull()]
                [ValidateSet("minor","moderate","elevated","none","unknownFutureValue")]
                [string]$Cond_InsiderRiskLevels,

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



# SIG # Begin signature block
# MIIRgwYJKoZIhvcNAQcCoIIRdDCCEXACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUb12OiKcQBT/35apJd9ZfNqyw
# 7amggg3jMIIG5jCCBM6gAwIBAgIQd70OA6G3CPhUqwZyENkERzANBgkqhkiG9w0B
# AQsFADBTMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEp
# MCcGA1UEAxMgR2xvYmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwHhcNMjAw
# NzI4MDAwMDAwWhcNMzAwNzI4MDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsU2lnbiBHQ0MgUjQ1
# IENvZGVTaWduaW5nIENBIDIwMjAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDWQk3540/GI/RsHYGmMPdIPc/Q5Y3lICKWB0Q1XQbPDx1wYOYmVPpTI2AC
# qF8CAveOyW49qXgFvY71TxkkmXzPERabH3tr0qN7aGV3q9ixLD/TcgYyXFusUGcs
# JU1WBjb8wWJMfX2GFpWaXVS6UNCwf6JEGenWbmw+E8KfEdRfNFtRaDFjCvhb0N66
# WV8xr4loOEA+COhTZ05jtiGO792NhUFVnhy8N9yVoMRxpx8bpUluCiBZfomjWBWX
# ACVp397CalBlTlP7a6GfGB6KDl9UXr3gW8/yDATS3gihECb3svN6LsKOlsE/zqXa
# 9FkojDdloTGWC46kdncVSYRmgiXnQwp3UrGZUUL/obLdnNLcGNnBhqlAHUGXYoa8
# qP+ix2MXBv1mejaUASCJeB+Q9HupUk5qT1QGKoCvnsdQQvplCuMB9LFurA6o44EZ
# qDjIngMohqR0p0eVfnJaKnsVahzEaeawvkAZmcvSfVVOIpwQ4KFbw7MueovE3vFL
# H4woeTBFf2wTtj0s/y1KiirsKA8tytScmIpKbVo2LC/fusviQUoIdxiIrTVhlBLz
# pHLr7jaep1EnkTz3ohrM/Ifll+FRh2npIsyDwLcPRWwH4UNP1IxKzs9jsbWkEHr5
# DQwosGs0/iFoJ2/s+PomhFt1Qs2JJnlZnWurY3FikCUNCCDx/wIDAQABo4IBrjCC
# AaowDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFNqzjcAkkKNrd9MMoFndIWdkdgt4MB8GA1Ud
# IwQYMBaAFB8Av0aACvx4ObeltEPZVlC7zpY7MIGTBggrBgEFBQcBAQSBhjCBgzA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY29kZXNpZ25p
# bmdyb290cjQ1MEYGCCsGAQUFBzAChjpodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3J0MEEGA1UdHwQ6MDgwNqA0
# oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1
# LmNybDBWBgNVHSAETzBNMEEGCSsGAQQBoDIBMjA0MDIGCCsGAQUFBwIBFiZodHRw
# czovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBBAEwDQYJ
# KoZIhvcNAQELBQADggIBAAiIcibGr/qsXwbAqoyQ2tCywKKX/24TMhZU/T70MBGf
# j5j5m1Ld8qIW7tl4laaafGG4BLX468v0YREz9mUltxFCi9hpbsf/lbSBQ6l+rr+C
# 1k3MEaODcWoQXhkFp+dsf1b0qFzDTgmtWWu4+X6lLrj83g7CoPuwBNQTG8cnqbmq
# LTE7z0ZMnetM7LwunPGHo384aV9BQGf2U33qQe+OPfup1BE4Rt886/bNIr0TzfDh
# 5uUzoL485HjVG8wg8jBzsCIc9oTWm1wAAuEoUkv/EktA6u6wGgYGnoTm5/DbhEb7
# c9krQrbJVzTHFsCm6yG5qg73/tvK67wXy7hn6+M+T9uplIZkVckJCsDZBHFKEUta
# ZMO8eHitTEcmZQeZ1c02YKEzU7P2eyrViUA8caWr+JlZ/eObkkvdBb0LDHgGK89T
# 2L0SmlsnhoU/kb7geIBzVN+nHWcrarauTYmAJAhScFDzAf9Eri+a4OFJCOHhW9c4
# 0Z4Kip2UJ5vKo7nb4jZq42+5WGLgNng2AfrBp4l6JlOjXLvSsuuKy2MIL/4e81Yp
# 4jWb2P/ppb1tS1ksiSwvUru1KZDaQ0e8ct282b+Awdywq7RLHVg2N2Trm+GFF5op
# ov3mCNKS/6D4fOHpp9Ewjl8mUCvHouKXd4rv2E0+JuuZQGDzPGcMtghyKTVTgTTc
# MIIG9TCCBN2gAwIBAgIMeWPZY2rjO3HZBQJuMA0GCSqGSIb3DQEBCwUAMFkxCzAJ
# BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZH
# bG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMzAzMjcx
# MDIxMzRaFw0yNjAzMjMxNjE4MThaMGMxCzAJBgNVBAYTAkRLMRAwDgYDVQQHEwdL
# b2xkaW5nMRAwDgYDVQQKEwcybGlua0lUMRAwDgYDVQQDEwcybGlua0lUMR4wHAYJ
# KoZIhvcNAQkBFg9tb2tAMmxpbmtpdC5uZXQwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQDMpI1rTOoWOSET3lSFQfsl/t83DCUEdoI02fNS5xlURPeGZNhi
# xQMKrhmFrdbIaEx01eY+hH9gF2AQ1ZDa7orCVSde1LDBnbFPLqcHWW5RWyzcy8Pq
# gV1QvzlFbmvTNHLm+wn1DZJ/1qJ+A+4uNUMrg13WRTiH0YWd6pwmAiQkoGC6FFwE
# usXotrT5JJNcPGlxBccm8su3kakI5B6iEuTeKh92EJM/km0pc/8o+pg+uR+f07Pp
# WcV9sS//JYCSLaXWicfrWq6a7/7U/vp/Wtdz+d2DcwljpsoXd++vuwzF8cUs09uJ
# KtdyrN8Z1DxqFlMdlD0ZyR401qAX4GO2XdzH363TtEBKAwvV+ReW6IeqGp5FUjnU
# j0RZ7NPOSiPr5G7d23RutjCHlGzbUr+5mQV/IHGL9LM5aNHsu22ziVqImRU9nwfq
# QVb8Q4aWD9P92hb3jNcH4bIWiQYccf9hgrMGGARx+wd/vI+AU/DfEtN9KuLJ8rNk
# LfbXRSB70le5SMP8qK09VjNXK/i6qO+Hkfh4vfNnW9JOvKdgRnQjmNEIYWjasbn8
# GyvoFVq0GOexiF/9XFKwbdGpDLJYttfcVZlBoSMPOWRe8HEKZYbJW1McjVIpWPnP
# d6tW7CBY2jp4476OeoPpMiiApuc7BhUC0VWl1Ei2PovDUoh/H3euHrWqbQIDAQAB
# o4IBsTCCAa0wDgYDVR0PAQH/BAQDAgeAMIGbBggrBgEFBQcBAQSBjjCBizBKBggr
# BgEFBQcwAoY+aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nn
# Y2NyNDVjb2Rlc2lnbmNhMjAyMC5jcnQwPQYIKwYBBQUHMAGGMWh0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1Y29kZXNpZ25jYTIwMjAwVgYDVR0gBE8w
# TTBBBgkrBgEEAaAyATIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQQBMAkGA1UdEwQCMAAwRQYDVR0f
# BD4wPDA6oDigNoY0aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2djY3I0NWNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBTas43AJJCja3fTDKBZ3SFnZHYLeDAdBgNVHQ4EFgQUMcaWNqucqymu1RTg02YU
# 3zypsskwDQYJKoZIhvcNAQELBQADggIBAHt/DYGUeCFfbtuuP5/44lpR2wbvOO49
# b6TenaL8TL3VEGe/NHh9yc3LxvH6PdbjtYgyGZLEooIgfnfEo+WL4fqF5X2BH34y
# EAsHCJVjXIjs1mGc5fajx14HU52iLiQOXEfOOk3qUC1TF3NWG+9mezho5XZkSMRo
# 0Ypg7Js2Pk3U7teZReCJFI9FSYa/BT2DnRFWVTlx7T5lIz6rKvTO1qQC2G3NKVGs
# HMtBTjsF6s2gpOzt7zF3o+DsnJukQRn0R9yTzgrx9nXYiHz6ti3HuJ4U7i7ILpgS
# RNrzmpVXXSH0wYxPT6TLm9eZR8qdZn1tGSb1zoIT70arnzE90oz0x7ej1fC8IUA/
# AYhkmfa6feI7OMU5xnsUjhSiyzMVhD06+RD3t5JrbKRoCgqixGb7DGM+yZVjbmhw
# cvr3UGVld9++pbsFeCB3xk/tcMXtBPdHTESPvUjSCpFbyldxVLU6GVIdzaeHAiBy
# S0NXrJVxcyCWusK41bJ1jP9zsnnaUCRERjWF5VZsXYBhY62NSOlFiCNGNYmVt7fi
# b4V6LFGoWvIv2EsWgx/uR/ypWndjmV6uBIN/UMZAhC25iZklNLFGDZ5dCUxLuoyW
# PVCTBYpM3+bN6dmbincjG0YDeRjTVfPN5niP1+SlRwSQxtXqYoDHq+3xVzFWVBqC
# NdoiM/4DqJUBMYIDCjCCAwYCAQEwaTBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsU2lnbiBHQ0MgUjQ1IENv
# ZGVTaWduaW5nIENBIDIwMjACDHlj2WNq4ztx2QUCbjAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# w68Hif/eUTAJV6m4MuNS/MrRggQwDQYJKoZIhvcNAQEBBQAEggIAkSJHpuHZYDux
# wAhQlurlrrymzPOUGwFER1AQ1PQ4Hqv0HFjZsyXhmkF3tXxCGjHCjb93js7ecSNH
# gRis2VaFImxg9WVr11i5LKV0wQ7tfBXS8y6DcIrXGDRS9u78a2USmPKY3GFZDVW4
# VXJ2waiZJmHxxeDmPo6tvuGTfQi6cyRfq+97GkyamRJM24Tq7XeTYRBQ9o68RrVU
# o7MwQx4KyyLyLjl3WO55H6e5KEffwCdEe9MFJmTrrBFLMQcg4i9rqU9RY3p7wzM/
# UxVn/ShkPcSQJvVdjO+LQbkywrOEbzqpuQNFYWZn4rrAtXQhwkvmowdKTYOCDu0C
# ygmh7qux9yqKz8NvyorIe77jjCo4lh2sBWuoap4H/GOhzJoiSIeaSxrDi3eDm9Xk
# NCWhA1ESb3yTbK2AwP7+ZvRW9L6v7f05LM6YI6t3nrhkGTUyocSunWHDMus1R1Za
# OKizUbG1bGZ1cSsjcRxAf60QSM83ZUsQASTw7yGjz8GvnSOKH3ThSMnE2POHwmNK
# 7TdIAgwbq+VMJJKZAvO2xE8JwkD70zjGFBshKV0rZxqfWGYMkolUq+tPJWtaPvlQ
# zAqYbcqEXIaywav7oUWVXt65Ro/xYG2s2U7/Fw3ripsgTf0RlfjcTHqJGBjqIpvp
# Ho5BJskpkuXtqX1rM/Uj9qhm+4VcaV4=
# SIG # End signature block
