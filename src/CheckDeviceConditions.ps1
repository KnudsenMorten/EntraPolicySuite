Function CheckDeviceConditions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Device,
        [Parameter(Mandatory)] [string]$Persona,
        [Parameter(Mandatory)] [string]$TagType,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueAD,
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string]$TagValueCloud,
        [Parameter(Mandatory)] [string]$ConditionsType,
        [Parameter()] [AllowNull()] [string]$ConditionGroup,
        [Parameter(Mandatory)] [array]$Target,
        [Parameter()] [AllowNull()] [string]$OnPremisesSyncEnabled
    )

    [boolean]$ConditionMet = $false
    $ModifiedTagValue = $null

    Write-Verbose "Checking condition $ConditionsType against device $($Device.DisplayName)..."

    # https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0
    switch ($ConditionsType) {
        "AccountEnabled" {
            if (($Target -eq "TRUE" -and $Device.AccountEnabled) -or ($Target -eq "FALSE" -and -not $Device.AccountEnabled)) {
                Write-Verbose "AccountEnabled matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceCategory_Like" {
            if ($Device.DeviceCategory -Like $Target) {
                Write-Verbose "DeviceCategory matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceCategory_NotLike" {
            if ($Device.DeviceCategory -NotLike $Target) {
                Write-Verbose "DeviceCategory matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceId" {
            if ($Device.DeviceId -eq $Target) {
                Write-Verbose "DeviceId matches $Target"
                $ConditionMet = $true
            }
        }

        # unknown, company, personal
        "DeviceOwnership_Like" {
            if ($Device.DeviceOwnership -like $Target) {
                Write-Verbose "DeviceOwnership matches $Target"
                $ConditionMet = $true
            }
        }
        "DeviceOwnership_NotLike" {
            if ($Device.DeviceOwnership -NotLike $Target) {
                Write-Verbose "DeviceOwnership doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "DisplayName_Like" {
            if ($Device.DisplayName -like "$($Target)") {
                Write-Verbose "DisplayName matches $Target"
                $ConditionMet = $true
            }
        }
        "DisplayName_NotLike" {
            if ($Device.DisplayName -Notlike "$($Target)") {
                Write-Verbose "DisplayName doesn't match $Target"
                $ConditionMet = $true
            }
        }

        #Apple Device Enrollment Profile, Device enrollment - Corporate device identifiers, or Windows Autopilot profile name.
        "EnrollmentProfileName_Like" {
            if ($Device.EnrollmentProfileName -Like $Target) {
                Write-Verbose "EnrollmentProfileName matches $Target"
                $ConditionMet = $true
            }
        }
        "EnrollmentProfileName_NotLike" {
            if ($Device.EnrollmentProfileName -NotLike $Target) {
                Write-Verbose "EnrollmentProfileName doesn't match $Target"
                $ConditionMet = $true
            }
        }

        # unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, 
        # windowsBulkAzureDomainJoin, windowsCoManagement, windowsAzureADJoinUsingDeviceAuth,appleUserEnrollment, appleUserEnrollmentWithServiceAccount.
        "EnrollmentType_Like" {
            if ($Device.EnrollmentType -Like $Target) {
                Write-Verbose "EnrollmentType matches $Target"
                $ConditionMet = $true
            }
        }
        "EnrollmentType_NotLike" {
            if ($Device.EnrollmentType -NotLike $Target) {
                Write-Verbose "EnrollmentType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "Id" {
            if ($Device.Id -eq $Target) {
                Write-Verbose "Id matches $Target"
                $ConditionMet = $true
            }
        }
        "IsCompliant" {
            if (($Target -eq "TRUE" -and $Device.IsCompliant) -or ($Target -eq "FALSE" -and -not $Device.IsCompliant)) {
                Write-Verbose "Device compliance matches $Target"
                $ConditionMet = $true
            }
        }
        "IsManaged" {
            if (($Target -eq "TRUE" -and $Device.IsManaged) -or ($Target -eq "FALSE" -and -not $Device.IsManaged)) {
                Write-Verbose "Device management status matches $Target"
                $ConditionMet = $true
            }
        }
        "Manufacturer_Like" {
            if ($Device.Manufacturer -Like $Target) {
                Write-Verbose "Manufacturer matches $Target"
                $ConditionMet = $true
            }
        }
        "Manufacturer_NotLike" {
            if ($Device.Manufacturer -NotLike $Target) {
                Write-Verbose "Manufacturer doesn't match $Target"
                $ConditionMet = $true
            }
        }
        
        # eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, 
        # configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController
        "ManagementType_Like" {
            if ($Device.ManagementType -Like $Target) {
                Write-Verbose "ManagementType matches $Target"
                $ConditionMet = $true
            }
        }
        "ManagementType_NotLike" {
            if ($Device.ManagementType -NotLike $Target) {
                Write-Verbose "ManagementType doesn't match $Target"
                $ConditionMet = $true
            }
        }

        "mdmAppId_Like" {
            if ($Device.mdmAppId -Like $Target) {
                Write-Verbose "mdmAppId matches $Target"
                $ConditionMet = $true
            }
        }
        "mdmAppId_NotLike" {
            if ($Device.mdmAppId -NotLike $Target) {
                Write-Verbose "mdmAppId doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "Model_Like" {
            if ($Device.Model -Like $Target) {
                Write-Verbose "Model matches $Target"
                $ConditionMet = $true
            }
        }
        "Model_NotLike" {
            if ($Device.Model -NotLike $Target) {
                Write-Verbose "Model doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "OnPremisesSyncEnabled" {
            if (($Target -eq "TRUE" -and $Device.OnPremisesSyncEnabled) -or ($Target -eq "FALSE" -and -not $Device.OnPremisesSyncEnabled)) {
                Write-Verbose "OnPremisesSyncEnabled matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystem_Like" {
            if ($Device.OperatingSystem -like "$($Target)") {
                Write-Verbose "OperatingSystem matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystem_NotLike" {
            if ($Device.OperatingSystem -Notlike "$($Target)") {
                Write-Verbose "OperatingSystem doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystemVersion_Like" {
            if ($Device.OperatingSystemVersion -like "$($Target)") {
                Write-Verbose "OperatingSystemVersion matches $Target"
                $ConditionMet = $true
            }
        }
        "OperatingSystemVersion_NotLike" {
            if ($Device.OperatingSystemVersion -Notlike "$($Target)") {
                Write-Verbose "OperatingSystemVersion doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "PhysicalIds_Contains" {
            if ($Device.PhysicalIds -contains $Target) {
                Write-Verbose "PhysicalIDs contains $Target"
                $ConditionMet = $true
            }
        }
        "PhysicalIds_NotContains" {
            if (-not ($Device.PhysicalIds -contains $Target)) {
                Write-Verbose "PhysicalIDs doesn't contain $Target"
                $ConditionMet = $true
            }
        }
        
        # RegisteredDevice (default), SecureVM, Printer, Shared, IoT.
        "ProfileType_Like" {
            if ($Device.ProfileType -Like $Target) {
                Write-Verbose "ProfileType matches $Target"
                $ConditionMet = $true
            }
        }
        "ProfileType_NotLike" {
            if ($Device.ProfileType -NotLike $Target) {
                Write-Verbose "ProfileType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        "SystemLabels_Contains" {
            if ($Device.SystemLabels -contains $Target) {
                Write-Verbose "SystemLabels contains $Target"
                $ConditionMet = $true
            }
        }
        "SystemLabels_NotContains" {
            if (-not ($Device.SystemLabels -contains $Target)) {
                Write-Verbose "SystemLabels doesn't contain $Target"
                $ConditionMet = $true
            }
        }
        "TrustType_Like" {
            if ($Device.TrustType -Like $Target) {
                Write-Verbose "TrustType matches $Target"
                $ConditionMet = $true
            }
        }
        "TrustType_NotLike" {
            if ($Device.TrustType -NotLike $Target) {
                Write-Verbose "TrustType doesn't match $Target"
                $ConditionMet = $true
            }
        }
        default {
            Write-Warning "Unknown condition type: $ConditionsType"
        }
    }

    return $ConditionMet, $ModifiedTagValue
}



# SIG # Begin signature block
# MIIRgwYJKoZIhvcNAQcCoIIRdDCCEXACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSpMR+6fJUqN5olP9ljgocAAR
# P9qggg3jMIIG5jCCBM6gAwIBAgIQd70OA6G3CPhUqwZyENkERzANBgkqhkiG9w0B
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
# aOJdUnZl6xJoizT7ozSkGDJTeTswDQYJKoZIhvcNAQEBBQAEggIAT8rayV4Guj+2
# O1PqcGyEshSIfzgrwGMTjaevkSvwOljfDliXgMjAwjWNNVOSMYDAsgnEXzSuNdoP
# pk6aHXDO204pmDOH7R8hWY6KvAUefLnyIu9ZzNUp0aTSlSEej0jnJUJlF3o/SkOU
# Sec4HqLW6goWmhyDsEXDJNPC1r664QoCQwdwP9mx/hDYd02EnXzEnuwUcGQKHZ6O
# zNO3T+ukZa0IiKrghUJ2sfJ6qB6flvfbcBDcCgI3qLJUNrOZcjxb14mqUFi5GZ8w
# +9i8cJDUocrq2i28v3SbdWvM5xQOiTyfvGYks8eJH+UcW6gPGt6Aai9o9DWMdAch
# nYY0hV9l3GG5LlNKirthFlMqmuW9Vu/z9eEaezyJxut5qlORxkqhA085D54GzDDS
# COKX+FYqsqRyJXyN0MCFtKPm+1h793nc6UD4u05p5Ej2IwoQ1c6t2PUO3ILbpcA6
# 6kgeQ7d5THejLbrWhFVQsHLKrVPI3mQppq9+Py1m5eR/jN1kgqXyOKTn/H9kjzUC
# y7c0CB+gbd65a6M9rG+oWU7N3N96EDv3djpDW5LmpSFQvty5733zgThlA21hLaqv
# y6MRSoCQGVFWzggzh5mBv8U/GOXSdWunal1GEMVFRQv0NDn/LNfdfHLY2p9K4PhK
# R49T/uTBVp1tM8DYS9F/km0Ce7HRWlY=
# SIG # End signature block
