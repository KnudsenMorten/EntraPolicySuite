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

