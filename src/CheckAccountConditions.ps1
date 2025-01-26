Function CheckAccountConditions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$User,
        [Parameter(Mandatory)] [string]$Persona,
        [Parameter(Mandatory)] [string]$TagType,
        [Parameter(Mandatory)] [string]$TagValueAD,
        [Parameter(Mandatory)] [string]$TagValueCloud,
        [Parameter(Mandatory)] [string]$ConditionsType,
        [Parameter()] [AllowNull()] [string]$ConditionGroup,
        [Parameter(Mandatory)] [array]$Target,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled,
        [Parameter()] [object]$MailboxInfo,
        [Parameter()] [object]$TeamsRoom
    )

    [boolean]$ConditionMet = $false
    $ModifiedTagValue = $null

    Write-Verbose ""
    Write-Verbose "Checking ..."
    Write-Verbose "ConditionsType   : $($ConditionsType)"
    Write-Verbose "Target           : $($Target)"
    Write-Verbose "ConditionGroup   : $($ConditionGroup)"

    switch ($ConditionsType) {
        "UPN_Like" {
            if ($User.UserPrincipalName -Like "$($Target)") {
                write-verbose $User.UserPrincipalName
                Write-Verbose "UPN_Like $($Target) = true"
                $ConditionMet = $true
            }
        }
        "UPN_NotLike" {
            if ($User.UserPrincipalName -Notlike "$($Target)") {
                write-verbose $User.UserPrincipalName
                Write-Verbose "UPN_NotLike $($Target) = true"
                $ConditionMet = $true
            }
        }
        "MemberOfGroup" {
            If ($User.OnPremisesSyncEnabled) {
                $GroupMembers = $global:AD_Group_Members_HashTable[$Target]
                if ($GroupMembers) {
                    if ($User.UserPrincipalName -in $GroupMembers.Members.UserPrincipalName) {
                        Write-Verbose "MemberOfGroup $($Filter) = true"
                        $ConditionMet = $true
                    }
                }
            } Else {
                $GroupMembers = $global:Entra_Group_Members_HashTable[$Target]
                if ($GroupMembers) {
                    if ($User.Id -in $GroupMembers.members.id) {
                        Write-Verbose "MemberOfGroup $($Filter) = true"
                        $ConditionMet = $true
                    }
                }
            }
            
        }
        "AD_OU_DN_Like" {
            if ($User.OnPremisesDistinguishedName -Like "$($Target)") {
                write-verbose $User.OnPremisesDistinguishedName
                Write-Verbose "AD_OU_DN_Like $($Filter) = true"
                $ConditionMet = $true
            }
        }
        "OnPremisesSyncEnabled" {
                if ( ($Target -match "TRUE") -and ($User.OnPremisesSyncEnabled) ) {
                    Write-Verbose "OnPremisesSyncEnabled $($Filter) = true"
                    $ConditionMet = $true
                } elseif ( ($Target -match "FALSE") -and (-not $User.OnPremisesSyncEnabled) )  {
                    # Write-Host "NOT OnPremisesSyncEnabled $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "MobilePhone_Like" {
                if ( ($User.MobilePhone -Like "$($Target)") -and ($User.MobilePhone -ne $null) ) {
                    write-verbose $User.MobilePhone
                    Write-Verbose "MobilePhone_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "GivenName_Like" {
                if ( ($User.GivenName -Like "$($Target)") -and ($User.GivenName -ne $null) ) {
                    write-verbose $User.GivenName
                    Write-Verbose "GivenName $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "SurName_Like" {
                if ( ($User.SurName -Like "$($Target)") -and ($User.SurName -ne $null) ) {
                    write-verbose $User.SurName
                    Write-Verbose "SurName_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "UserType_Like" {
                if ( ($User.UserType -Like "$($Target)") -and ($User.UserType -ne $null) ) {
                    write-verbose $User.UserType
                    Write-Verbose "UserType_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "UserType_NotLike" {
                if ( ($User.UserType -NotLike "$($Target)") -and ($User.UserType -ne $null) ) {
                    write-verbose $User.UserType
                    Write-Verbose "UserType_NotLike $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "EmployeeType_Like" {
                if ( ($User.EmployeeType -Like "$($Target)") -and ($User.EmployeeType -ne $null) ) {
                    write-verbose $User.EmployeeType
                    Write-Verbose "EmployeeType_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Teams_Room_Like" {
                if ( ($Target -match "TRUE") -and ($TeamsRoom) ) {
                    Write-Verbose "Teams_Room_Like $($Filter) = true"
                    $ConditionMet = $true
                } elseif ( ($Target -match "FALSE") -and (-not $TeamsRoom) )  {
                    Write-Verbose "Teams_Room_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_Like" {
                if ( ($MailboxInfo.RecipientTypeDetails -Like "$($Target)") -and ($MailBOxInfo.RecipientTypeDetails -ne $null) ) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_Like $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_NotLike" {
                if ( ($MailboxInfo.RecipientTypeDetails -NotLike "$($Target)") -and ($MailBOxInfo.RecipientTypeDetails -ne $null) ) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_NotLike $($Filter) = true"
                    $ConditionMet = $true
                }
        }
        "Mailbox_RecipientTypeDetails_ModifiedTagValue_Classification" {
                If ($MailboxInfo.RecipientTypeDetails) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_ModifiedTagValue $($Filter) = true"
                    $ConditionMet = $true
                    $ModifiedTagValue = "Exchange_" + $MailboxInfo.RecipientTypeDetails
                }
        }
        "Mailbox_RecipientTypeDetails_ModifiedTagValue_Authentication" {
                If ($MailboxInfo.RecipientTypeDetails) {
                    write-verbose $MailboxInfo.RecipientTypeDetails
                    Write-Verbose "Mailbox_RecipientTypeDetails_ModifiedTagValue $($Filter) = true"
                    $ConditionMet = $true
                    $ModifiedTagValue = "Exchange_" + $MailboxInfo.RecipientTypeDetails + "_NoSignin"
                }
        }
        default {
            Write-Host "Unknown condition type: $ConditionsType"
        }
    }

    # write-host $ConditionMet
    Return $ConditionMet,$ModifiedTagValue
}

# SIG # Begin signature block
# MIIXAgYJKoZIhvcNAQcCoIIW8zCCFu8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9duR1OURW77j6+E72jpPZFZi
# LUCgghNiMIIFojCCBIqgAwIBAgIQeAMYQkVwikHPbwG47rSpVDANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUoJ0coh4bxjCEJkyWYiWAX//pw/0wDQYJKoZIhvcNAQEB
# BQAEggIAKsJWEn/BarxdU/9HHM6wvC7SgycOzg5qAYWWEu0MfspYy5v3uw2n1/Zc
# 9lurswn+GAAGsBgpEsZkN++15gdX/68zhbDjfFlenjcOIi0CsxhOe2HrZqikXBxG
# DCFH2tEAaXHDEjYYNch0g+9lYK6ilCo7rQwbUsz8sER3gdnrwRy6lNPtGzTPX5zq
# 2YWY2JwdfPX1ms3+DMm+PqpVUHIfLLwjZSxfjc6nqntiA/ePDbolG/BmSQaKd6SV
# YbncpWjBcesEMVsEqGkdwOyiv7Z/ANAuQQQW+rkYJyBgJsxyuRSMWrcNCsIbFebI
# gC1ZGSgKb0Asw556ctvBo/2TckwKlAiZIUBMAT8Ygsan6FfyWpSmCNvRBuxUUNLP
# ThILWWhBWFKJNGKfN13KJmaQw37iimPC0ocq4bGrDkqQSnshZKPaHTWlai8kJHL2
# LapU7D6zK0NgGH8lU/dRY3bmsQCSVkhe+Yb+oCNySYUrrHKkdk/6SrP0QntQO3SE
# w3BQO5v5g3pfwGTO7grGqL8Vtp7Y5Keq6i/Sx+7mf8h5FznIluoirOQiy3XqqVsJ
# 8II/yL2JDJ5CrJGOY7YIlRGyCafwntcXgR7VtEgl3HAhf+4Gf5c1+Ww+09LuBGjy
# r6X9MT6vyPsop0y4bEjrRCq1Q2dtMDaWCaRBLpG2Ar5rkksrOQk=
# SIG # End signature block
