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
                $Result = New-MgGroup @CmdToRun_Hash
            }
        } else {
            Write-host "----------------------------"
            Write-Host "Group already exists: $DisplayName"
            Write-host ""
            $Result = $GroupExist
        }
    } elseif ( ($PSBoundParameters.ContainsKey('CreateOnly')) -or (-not ($EntraGroupsHashTable.ContainsKey($DisplayName)))) {
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

