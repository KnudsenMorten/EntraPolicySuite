Function TagDeviceConditionsTrue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$PropertyKeyAD,
        [Parameter(Mandatory)] [string]$PropertyKeyCloud,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueAD,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueCloud,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    # Get existing tag-values
    $ExistingTagValue = $Device.ExtensionAttributes.$PropertyKeyCloud

    if ($TagValueAD -eq "") { $TagValueAD = $null }
    if ($TagValueCloud -eq "") { $TagValueCloud = $null }

    # Cloud-only device
    if ([string]::IsNullOrEmpty($OnPremisesSyncEnabled)) {
        Write-Verbose "PropertyKeyCloud : $PropertyKeyCloud"
        Write-Verbose "ExistingValue    : $ExistingTagValue"
        Write-Verbose "TagValueCloud    : $TagValueCloud"

        if ($ExistingTagValue -eq $TagValueCloud) {
            Write-Verbose "Skipping as value is already set correctly on device."
        } else {
            if (-not $global:EnableWhatIf) {
                Write-Host "Modifying device $($Device.DisplayName) in Microsoft Graph ($PropertyKeyCloud = $TagValueCloud)"

                try {
                    Update-MgBetaDevice -DeviceId $Device.Id -ExtensionAttributes @{"$PropertyKeyCloud"="$TagValueCloud"} -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to update device $($Device.DisplayName) in Graph."
                }

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            } else {
                Write-Host "WhatIf - Modifying device $($Device.DisplayName) ($PropertyKeyCloud = $TagValueCloud)"

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            }
        }
    } else {
        # Device is Hybrid AD joined (on-prem sync enabled)
        Write-Verbose "PropertyKeyAD : $PropertyKeyAD"
        Write-Verbose "ExistingValue : $ExistingTagValue"
        Write-Verbose "TagValueAD    : $TagValueAD"

        if ($ExistingTagValue -eq $TagValueAD) {
            Write-Verbose "Skipping as value is already set correctly on device."
        } else {
            if (-not $global:EnableWhatIf) {
                Write-Host "Modifying device $($Device.DisplayName) in Active Directory ($PropertyKeyAD = $TagValueAD)"

                $DeviceAD = Get-ADComputer -Filter { Name -eq $Device.DisplayName }
                try {
                    if ($global:SecureCredentials) {
                        Set-ADComputer -Identity $DeviceAD -Replace @{"$PropertyKeyAD"="$TagValueAD"} -Credential $global:SecureCredentials
                    } else {
                        Set-ADComputer -Identity $DeviceAD -Replace @{"$PropertyKeyAD"="$TagValueAD"}
                    }
                } catch {
                    try {
                        if ($global:SecureCredentials) {
                            Set-ADComputer -Identity $DeviceAD -Add @{"$PropertyKeyAD"="$TagValueAD"} -Credential $global:SecureCredentials
                        } else {
                            Set-ADComputer -Identity $DeviceAD -Add @{"$PropertyKeyAD"="$TagValueAD"}
                        }
                    } catch {
                        Write-Warning "Failed to modify device $($Device.DisplayName) in AD."
                    }
                }

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            } else {
                Write-Host "WhatIf - Modifying device $($Device.DisplayName) in AD ($PropertyKeyAD = $TagValueAD)"

                $LogEntry = [PSCustomObject]@{ 
                    DeviceName = $Device.DisplayName
                    DeviceId = $Device.Id
                    PropertyKeyAD = $PropertyKeyAD
                    TagValueAD = $TagValueAD
                    PropertyKeyCloud = $PropertyKeyCloud
                    TagValueCloud = $TagValueCloud
                    ExistingTagValue = $ExistingTagValue
                }
                $Result = $Global:ModificationsLog.Add($LogEntry)
            }
        }
    }
}

