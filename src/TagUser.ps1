Function TagUser
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [object]$User,
            [Parameter()]
                [string]$PropertyKeyAD,
            [Parameter()]
                [string]$TagValueAD,
            [Parameter()]
                [string]$PropertyKeyCloud,
            [Parameter()]
                [string]$TagValueCloud,
            [Parameter(mandatory)]
                [AllowNull()]
                [array]$OnPremisesSyncEnabled,
            [Parameter()]
                [AllowNull()]
                [object]$MailBoxInfo
         )


    # Get existing tag-values
        $ExistingTagValue = $null
        $ExistingTagValue = $User.OnPremisesExtensionAttributes.$PropertyKeyCloud

    # Cloud-only Account (use Microsoft Graph to update)
    If ( (!($OnPremisesSyncEnabled)) -and ($MailboxInfo) )
        {
            # Modify property, cloud-only user
                If ($ExistingTagValue -ne $TagValueCloud)
                    {
                        If ($MailboxInfo)
                            {
                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        Switch ($PropertyKeyCloud)
                                            {
                                                'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                            }

                                        ################################################################################
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
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"
                                        ################################################################################
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
                                        ################################################################################
                                    }
                            }
                        Else
                            {

                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        Try
                                            {
                                                Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                            }
                                        Catch
                                            {

                                                write-host ""
                                                write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                                # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                                # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                                switch ($PropertyKeyCloud)
                                                    {
                                                        'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                        'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                                                    }
                                                    
                                            }

                                        ################################################################################
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
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                        ################################################################################
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
                                        ################################################################################
                                    }
                            }
                    }
        }

    If ( (!($OnPremisesSyncEnabled)) -and (!($MailboxInfo)) )
        {
            # Modify property, cloud-only user
                If ($ExistingTagValue -ne $TagValueCloud)
                    {

                        If (!($global:EnableWhatIf))
                            {
                                write-host ""
                                write-host "   Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"

                                Try
                                    {
                                        Update-MgBetaUser -UserId $User.Id -OnPremisesExtensionAttributes @{"$($PropertyKeyCloud)"="$($TagValueCloud)"} -ErrorAction Stop
                                    }
                                Catch
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Exchange Online ($($PropertyKeyCloud) = $($TagValueCloud))"

                                        # We can be getting error "Unable to update the specified properties for objects that have originated within an external service"
                                        # Reason: Object is managed by Exchange - and we need to manage using Exchange cmdlets instead of Microsoft Graph
                                        switch ($PropertyKeyCloud)
                                            {
                                                'extensionAttribute1'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute2'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute2 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute3'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute3 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute4'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute4 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute5'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute5 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute6'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute6 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute7'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute7 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute8'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute8 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute9'  { set-mailuser -identity $User.UserPrincipalName -CustomAttribute9 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute10' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute10 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute11' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute11 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute12' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute12 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute13' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute13 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute14' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute14 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                                'extensionAttribute15' { set-mailuser -identity $User.UserPrincipalName -CustomAttribute15 $TagValueCloud -WarningAction SilentlyContinue; set-mailbox -identity $User.UserPrincipalName -CustomAttribute1 $TagValueCloud -WarningAction SilentlyContinue }
                                            }
                                    }

                                ################################################################################
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
                                ################################################################################
                            }
                        Else
                            {
                                write-host ""
                                write-host "   WhatIf - Modifying $($User.DisplayName) using Microsoft Graph ($($PropertyKeyCloud) = $($TagValueCloud))"
                                ################################################################################
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
                                ################################################################################
                            }
                    }
        }

    ElseIf ( ($OnPremisesSyncEnabled) -and ($MailboxInfo) )
        {
            # Modify property, AD-synced user
                If ($ExistingTagValue -ne $TagValueAD)
                    {
                        If ($MailboxInfo)
                            {

                                If (!($global:EnableWhatIf))
                                    {
                                        write-host ""
                                        write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                        $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                        Try
                                            {
                                                If ($global:SecureCredentials) {
                                                    Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                } Else {
                                                    Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                }
                                            }
                                        Catch
                                            {
                                                If ($global:SecureCredentials) {
                                                    Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                                } Else {
                                                    Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                                }
                                            }
                                        ################################################################################
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
                                        ################################################################################
                                    }
                                Else
                                    {
                                        write-host ""
                                        write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"
                                        ################################################################################
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
                                        ################################################################################
                                    }
                            }
                    }                
        }

    ElseIf ( ($OnPremisesSyncEnabled) -and (!($MailboxInfo)) )
        {
            # Modify property, AD-synced user
                If ($ExistingTagValue -ne $TagValueAD)
                    {

                        If (!($global:EnableWhatIf))
                            {
                                write-host ""
                                write-host "   Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                $UserAD = Get-ADUser -Filter 'UserPrincipalName -eq $User.OnPremisesUserPrincipalName'
                                Try
                                    {
                                        If ($global:SecureCredentials) {
                                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                        } Else {
                                            Set-ADUser -identity $UserAD -Replace @{"$PropertyKeyAD"="$($TagValueAD)"}
                                        }
                                    }
                                Catch
                                    {
                                        If ($global:SecureCredentials) {
                                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"} -Credential $global:SecureCredentials
                                        } Else {
                                            Set-ADUser -identity $UserAD -Add @{"$PropertyKeyAD"="$($TagValueAD)"}
                                        }
                                    }

                                ################################################################################
                                $LogEntry = $null
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
                                ################################################################################
                            }
                        Else
                            {
                                write-host ""
                                write-host "   WhatIf - Modifying $($User.DisplayName) using Active Directory ($($PropertyKeyAD) = $($TagValueAD))"

                                ################################################################################
                                $LogEntry = $null
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
                                ################################################################################
                            }
                    }                
        }
}

# SIG # Begin signature block
# MIIXAgYJKoZIhvcNAQcCoIIW8zCCFu8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUP57UmwrP2aspgPrOH66VPEzq
# i22gghNiMIIFojCCBIqgAwIBAgIQeAMYQkVwikHPbwG47rSpVDANBgkqhkiG9w0B
# AQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UE
# ChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAw
# MDBaFw0yOTAzMTgwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBS
# b290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALYtxTDdeuir
# kD0DcrA6S5kWYbLl/6VnHTcc5X7sk4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LY
# S8lKA/Oof2qPimEnvaFE0P31PyLCo0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5Q
# OkHM8KCwex1N0qhYOJbp3/kbkbuLECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/
# rlX7hPCA/oRM1+K6vcR1oW+9YRB0RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xV
# uBZwXCR4ICXrZ2eIq7pONJhrcBHeOMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/
# ugk3PWdssUVcGWGrQYP1rB3rdw1GR3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWb
# EsSegHI9k9yMlN87ROYmgPzSwwPwjAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZk
# obacgSFOK8ZtaJSGxpl0c2cxepHy1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FX
# BhcSJMDEMXOhmDVXR34QOkXZLaRRkJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pA
# sufSxPrJ0PBQdnRZ+o1tFzK++Ol+A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e
# +MuNrRan097VmxinxpI68YJj8S4OJGTfAgMBAAGjggF3MIIBczAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQUHwC/RoAK/Hg5t6W0Q9lWULvOljswHwYDVR0jBBgwFoAUj/BLf6guRSSu
# TVD6Y5qL3uLdG7wwegYIKwYBBQUHAQEEbjBsMC0GCCsGAQUFBzABhiFodHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9yb290cjMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9z
# ZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjMuY3J0MDYGA1UdHwQv
# MC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yMy5jcmww
# RwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmds
# b2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IBAQCs98wV
# izB5qB0LKIgZCdccf/6GvXtaM24NZw57YtnhGFywvRNdHSOuOVB2N6pE/V8BI1mG
# VkzMrbxkExQwpCCo4D/onHLcfvPYDCO6qC2qPPbsn4cxB2X1OadRgnXh8i+X9tHh
# ZZaDZP6hHVH7tSSb9dJ3abyFLFz6WHfRrqexC+LWd7uptDRKqW899PMNlV3m+XpF
# sCUXMS7b9w9o5oMfqffl1J2YjNNhSy/DKH563pMOtH2gCm2SxLRmP32nWO6s9+zD
# CAGrOPwKHKnFl7KIyAkCGfZcmhrxTWww1LMGqwBgSA14q88XrZKTYiB3dWy9yDK0
# 3E3r2d/BkJYpvcF/MIIGvzCCBKegAwIBAgIRAIFOQhehKX/tWszUF/iRrXUwDQYJ
# KoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1
# MB4XDTI0MDYxOTAzMjUxMVoXDTM4MDcyODAwMDAwMFowWTELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24g
# R0NDIFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA1kJN+eNPxiP0bB2BpjD3SD3P0OWN5SAilgdENV0Gzw8dcGDm
# JlT6UyNgAqhfAgL3jsluPal4Bb2O9U8ZJJl8zxEWmx97a9Kje2hld6vYsSw/03IG
# MlxbrFBnLCVNVgY2/MFiTH19hhaVml1UulDQsH+iRBnp1m5sPhPCnxHUXzRbUWgx
# Ywr4W9DeullfMa+JaDhAPgjoU2dOY7Yhju/djYVBVZ4cvDfclaDEcacfG6VJbgog
# WX6Jo1gVlwAlad/ewmpQZU5T+2uhnxgeig5fVF694FvP8gwE0t4IoRAm97Lzei7C
# jpbBP86l2vRZKIw3ZaExlguOpHZ3FUmEZoIl50MKd1KxmVFC/6Gy3ZzS3BjZwYap
# QB1Bl2KGvKj/osdjFwb9Zno2lAEgiXgfkPR7qVJOak9UBiqAr57HUEL6ZQrjAfSx
# bqwOqOOBGag4yJ4DKIakdKdHlX5yWip7FWocxGnmsL5AGZnL0n1VTiKcEOChW8Oz
# LnqLxN7xSx+MKHkwRX9sE7Y9LP8tSooq7CgPLcrUnJiKSm1aNiwv37rL4kFKCHcY
# iK01YZQS86Ry6+42nqdRJ5E896IazPyH5ZfhUYdp6SLMg8C3D0VsB+FDT9SMSs7P
# Y7G1pBB6+Q0MKLBrNP4haCdv7Pj6JoRbdULNiSZ5WZ1rq2NxYpAlDQgg8f8CAwEA
# AaOCAYYwggGCMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTas43AJJCja3fTDKBZ3SFnZHYL
# eDAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEE
# gYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2Nv
# ZGVzaWduaW5ncm9vdHI0NTBGBggrBgEFBQcwAoY6aHR0cDovL3NlY3VyZS5nbG9i
# YWxzaWduLmNvbS9jYWNlcnQvY29kZXNpZ25pbmdyb290cjQ1LmNydDBBBgNVHR8E
# OjA4MDagNKAyhjBodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5n
# cm9vdHI0NS5jcmwwLgYDVR0gBCcwJTAIBgZngQwBBAEwCwYJKwYBBAGgMgEyMAwG
# CisGAQQBoDIKBAIwDQYJKoZIhvcNAQELBQADggIBADIQ5LwXpYMQQJ3Tqf0nz0Vy
# qcUfSzNZbywyMXlxhNY2Z9WrdPzU8gY6brXWy/FCg5a9fd6VLBrtauNBHKbIiTHC
# WWyJvCojA1lQR0n9b1MOKijMSFTv8yMYW5I2TryjY9TD+wAPgNEgwsrllrrwmluq
# pCV6Gdv623tTT/m2o9lj1XVfAaUo27YYKRRleZzbtOuImBRTUGAxDGazUeNuySkm
# ZPAU0XN4xISNPhSlklmreUFG6jTPgXZGOpF4GXO+/gb118GEOaBwTAo1AF7YKjAk
# HzJ3tuF837NGQeH6bY3j4wufL0DZpToNZMm+jNEayWUgOuIA+k56ITdBcJmdUB+Z
# e3WQdHNNRaVOWH/ddmqQWIlmk2Sj/lT3Tarr5SDuddeIsh0MPLyhkqBW5Ef8Zw/q
# eCnfj6PH2eMxeKcLKZRrHCddISeH4qPvyECQLlwXKCXTAUQXq4DafJSoWyP8IJ6b
# kaGQ/7MN5XJELEcV89SRcib58gXjAWf3abXeBbb+KJCMf6EpO7cs2mQiaZbE9NNX
# DSqFxrtoaKyL8VJLZG6quLfsTRQc+qgUOM7sJevkYt01+bh7B10bQ2cCCGs9vyUj
# g4GWcwfu/lhaPDfaoNtf0pw6RpKcxCYcCTDaJeQOHZBz1B6HTmmEgZHNZX7nNfqD
# gGrTNB1Gp3gIpngyJWZ6MIIG9TCCBN2gAwIBAgIMeWPZY2rjO3HZBQJuMA0GCSqG
# SIb3DQEBCwUAMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
# LXNhMS8wLQYDVQQDEyZHbG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcgQ0Eg
# MjAyMDAeFw0yMzAzMjcxMDIxMzRaFw0yNjAzMjMxNjE4MThaMGMxCzAJBgNVBAYT
# AkRLMRAwDgYDVQQHEwdLb2xkaW5nMRAwDgYDVQQKEwcybGlua0lUMRAwDgYDVQQD
# EwcybGlua0lUMR4wHAYJKoZIhvcNAQkBFg9tb2tAMmxpbmtpdC5uZXQwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDMpI1rTOoWOSET3lSFQfsl/t83DCUE
# doI02fNS5xlURPeGZNhixQMKrhmFrdbIaEx01eY+hH9gF2AQ1ZDa7orCVSde1LDB
# nbFPLqcHWW5RWyzcy8PqgV1QvzlFbmvTNHLm+wn1DZJ/1qJ+A+4uNUMrg13WRTiH
# 0YWd6pwmAiQkoGC6FFwEusXotrT5JJNcPGlxBccm8su3kakI5B6iEuTeKh92EJM/
# km0pc/8o+pg+uR+f07PpWcV9sS//JYCSLaXWicfrWq6a7/7U/vp/Wtdz+d2Dcwlj
# psoXd++vuwzF8cUs09uJKtdyrN8Z1DxqFlMdlD0ZyR401qAX4GO2XdzH363TtEBK
# AwvV+ReW6IeqGp5FUjnUj0RZ7NPOSiPr5G7d23RutjCHlGzbUr+5mQV/IHGL9LM5
# aNHsu22ziVqImRU9nwfqQVb8Q4aWD9P92hb3jNcH4bIWiQYccf9hgrMGGARx+wd/
# vI+AU/DfEtN9KuLJ8rNkLfbXRSB70le5SMP8qK09VjNXK/i6qO+Hkfh4vfNnW9JO
# vKdgRnQjmNEIYWjasbn8GyvoFVq0GOexiF/9XFKwbdGpDLJYttfcVZlBoSMPOWRe
# 8HEKZYbJW1McjVIpWPnPd6tW7CBY2jp4476OeoPpMiiApuc7BhUC0VWl1Ei2PovD
# Uoh/H3euHrWqbQIDAQABo4IBsTCCAa0wDgYDVR0PAQH/BAQDAgeAMIGbBggrBgEF
# BQcBAQSBjjCBizBKBggrBgEFBQcwAoY+aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
# LmNvbS9jYWNlcnQvZ3NnY2NyNDVjb2Rlc2lnbmNhMjAyMC5jcnQwPQYIKwYBBQUH
# MAGGMWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1Y29kZXNpZ25j
# YTIwMjAwVgYDVR0gBE8wTTBBBgkrBgEEAaAyATIwNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQQBMAkG
# A1UdEwQCMAAwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9nc2djY3I0NWNvZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEF
# BQcDAzAfBgNVHSMEGDAWgBTas43AJJCja3fTDKBZ3SFnZHYLeDAdBgNVHQ4EFgQU
# McaWNqucqymu1RTg02YU3zypsskwDQYJKoZIhvcNAQELBQADggIBAHt/DYGUeCFf
# btuuP5/44lpR2wbvOO49b6TenaL8TL3VEGe/NHh9yc3LxvH6PdbjtYgyGZLEooIg
# fnfEo+WL4fqF5X2BH34yEAsHCJVjXIjs1mGc5fajx14HU52iLiQOXEfOOk3qUC1T
# F3NWG+9mezho5XZkSMRo0Ypg7Js2Pk3U7teZReCJFI9FSYa/BT2DnRFWVTlx7T5l
# Iz6rKvTO1qQC2G3NKVGsHMtBTjsF6s2gpOzt7zF3o+DsnJukQRn0R9yTzgrx9nXY
# iHz6ti3HuJ4U7i7ILpgSRNrzmpVXXSH0wYxPT6TLm9eZR8qdZn1tGSb1zoIT70ar
# nzE90oz0x7ej1fC8IUA/AYhkmfa6feI7OMU5xnsUjhSiyzMVhD06+RD3t5JrbKRo
# CgqixGb7DGM+yZVjbmhwcvr3UGVld9++pbsFeCB3xk/tcMXtBPdHTESPvUjSCpFb
# yldxVLU6GVIdzaeHAiByS0NXrJVxcyCWusK41bJ1jP9zsnnaUCRERjWF5VZsXYBh
# Y62NSOlFiCNGNYmVt7fib4V6LFGoWvIv2EsWgx/uR/ypWndjmV6uBIN/UMZAhC25
# iZklNLFGDZ5dCUxLuoyWPVCTBYpM3+bN6dmbincjG0YDeRjTVfPN5niP1+SlRwSQ
# xtXqYoDHq+3xVzFWVBqCNdoiM/4DqJUBMYIDCjCCAwYCAQEwaTBZMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFs
# U2lnbiBHQ0MgUjQ1IENvZGVTaWduaW5nIENBIDIwMjACDHlj2WNq4ztx2QUCbjAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUIjzF9NDWsZu66JPD9S5BMlUqI04wDQYJKoZIhvcNAQEB
# BQAEggIAZDC/aGbu+M2psyTiGj0nvqBi9O0KrYu5kxYWvney9RqJU7doLhzFF3oh
# C7dNqW10yqtAzTVKaSnd67vpVdUb6AFHPWzDkMDhIXduSXSqASOGuyui0KCKtHIZ
# aEuOv2keWlqcfU9hXxuspN1nJnqSc7C74YZRDd4CYqeCQzcSXzOSnwZx4WYhYOsr
# jT/s6kEmHNTfJNdmPYseDKg7OCKzxM6AU6A3vjZeBTP46DP9F3/iqABPmE4aPMaO
# KQdrNvAh/mq/QtnHYL6L6mWvjm4ZL8MknzfthMB0XnqEyKwMCRcg4IBspn4y4lhu
# JrvCK2ef/eySXGuduLkW/VxspG6WVlKCylNUtS2M5QSRq1Z5sinMZ2d02fo+7FQs
# RGnA6vwd+tEN+h80yxmPCRm/SgqZO0YyXh0bmbj/hqj54icJZAz2ujVawR0GX6Rb
# x4iweuuhj+63+sVyLVCA1rZUf0enMZXfbArd127tWpfep1Ei1y7A6IKWXeqkCCnP
# Lvt7N9Johsa0qExq4oBTbX8Sz4sbh36Rccx9oGtFtw6gulJtu/vbHBTXRtuVE2Ne
# R2sCfi8IVS3koRJd/gAFarfR2uQjb/Scf0rB+dzFCE8uID9fc9orLbDGwa33g0G4
# jltPPNxS3bSQraxGvmqiZMXXl7iuotU76oaA19nVM0JkUnE0t6E=
# SIG # End signature block
