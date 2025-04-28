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

