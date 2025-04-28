Function TagUserConditionsTrue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$User,
        [Parameter(Mandatory)] [string]$PropertyKeyAD,
        [Parameter(Mandatory)] [string]$PropertyKeyCloud,
        [Parameter(Mandatory)] [string]$TagValueAD,
        [Parameter(Mandatory)] [string]$TagValueCloud,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    # Get existing tag-values
    $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

    # Cloud-only Account (use Microsoft Graph to update)
    if ([string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {
        write-verbose ""
        write-Verbose "PropertyKeyCloud : $($PropertyKeyCloud)"
        write-Verbose "ExistingValue    : $($ExistingTagValue)"
        write-Verbose "TagValueCloud    : $($TagValueCloud)"

        if ($ExistingTagValue -eq $TagValueCloud) {
        write-verbose ""
        write-Verbose "Skipping as value is already set correctly on user !!!"
                
        } elseIf ($ExistingTagValue -ne $TagValueCloud) {
            if (-not $global:EnableWhatIf) {
                Write-Host ""
                Write-Host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                try {
                    Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                } catch {
                    Write-Host ""
                    Write-Host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"
                            
                    # Handle updates via Exchange Online cmdlets
                    switch ($PropertyKeyCloud) {
                        'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue }
                        'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue }
                    }
                }

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            } else {
                Write-Host ""
                Write-Host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            }
        }
            
    } elseif (-not [string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {

        write-verbose ""
        write-Verbose "PropertyKeyAD    : $($PropertyKeyAD)"
        write-Verbose "ExistingValue    : $($ExistingTagValue)"
        write-Verbose "TagValueAD       : $($TagValueAD)"
                                
        if ($ExistingTagValue -eq $TagValueAD) {
        write-verbose ""
        write-Verbose "Skipping as value is already set correctly on user !!!"
                
        } elseIf ($ExistingTagValue -ne $TagValueAD) {
            if (-not $global:EnableWhatIf) {
                Write-Host ""
                Write-Host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                try {
                        If ($global:SecureCredentials) {
                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                        } Else {
                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                        }
                } catch {
                        If ($global:SecureCredentials) {
                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                        } Else {
                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                        }
                }

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            } else {
                Write-Host ""
                Write-Host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                # Log entry
                $LogEntry = [PSCustomObject]@{ 
                    UserUPN = $User.UserPrincipalName
                    UserDisplayName = $User.DisplayName
                    OnPremisesSyncEnabled = [string]$OnPremisesSyncEnabled
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }

                $Result = $Global:ModificationsLog.add($LogEntry) 
            }
        }
    }
}

