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

# SIG # Begin signature block
# MIIXAgYJKoZIhvcNAQcCoIIW8zCCFu8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUehmQkSKm/brnsBBsRsep95JU
# uIagghNiMIIFojCCBIqgAwIBAgIQeAMYQkVwikHPbwG47rSpVDANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUIw9RT48JNjHvwaQOB66Pxp2NiP4wDQYJKoZIhvcNAQEB
# BQAEggIAgXO3UVn4HpQ9kWlo2OkCoUPNehW5BUuK6l5M8qy5T9xydwDh6SIf6pYc
# jPVQbBkJfhReyy8wx45JBOXwLUTqDozGhGVKzgVIDOH2iLqa653Y56r0t0yVOMeO
# 7uvdHay25ImnGIAD37GJHFFuTXwNUppaeertNwomIJnCNqSO0XLvl9KycE3ex8oG
# wqzizIeBBGcjhuD9cFf8xESPVdIWFlWEoQSFfyWS6OLfWtcFUmusVXIeu7lTZtiY
# 5DCR/z0ALXBfQv6mFGI7QTl9VMrHIVeDZLGekgjDiMYkY3iRb/fdwWpwp0FiUiuZ
# e4pWbb9i83ChKdT/K+OEns4zkH5/0RyKLdybVE0CeF6BGhmdswECht5nDv3TSbaT
# j/hB1R6x05xVaTkavzHLHEBXDaGU8HF4zJPaCnLuvg+Ge7t9jMsBoIW4r5ORaSM6
# BnPqoTLkkfZGQ+ou8Ftb700II7opl4YHDxVOhnL1s/zKj0an/vyM9VdMQf4yguAw
# mcleu7G9j9xkNTmCAxpKwUx+OvoHe25ypl9y9Us55v8NsFLTPQPNBJeF9IUsTZg6
# jkB/GzV+aqE927E7Xa7dhIm+C0O8aQI+jCpRwnV0a4XPxfdfbvJbHInJQFQ/qyog
# uwiRwsQMaiSq69oIga32qlmY+Xvlu9fo8htIbrOpxiMrl7SJlLI=
# SIG # End signature block
