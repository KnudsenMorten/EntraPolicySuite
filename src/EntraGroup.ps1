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



# SIG # Begin signature block
# MIIRgwYJKoZIhvcNAQcCoIIRdDCCEXACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYM1n0qUTQlXyO6XBZ/MmDVUg
# oViggg3jMIIG5jCCBM6gAwIBAgIQd70OA6G3CPhUqwZyENkERzANBgkqhkiG9w0B
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
# Qr1MgJUzavAXGOpPGFYqfdryLWowDQYJKoZIhvcNAQEBBQAEggIAXpVnJncASGYz
# qwHEy3iGo0Cli2LrBuZ04kB0Y8vl7gtqr/ZXEAek2DoyepklHke1LgzUz7HHTVEg
# fuOmR8dJIuuOyfWgmfGxS2Tef1VMEDcWBME9IewVeRVrfPyqSHHtTseZcTI5VKDi
# snffrmPXfAnJ1SB8J3rRAxeaNpNwUNEmkI6gMR77NCH8xgLOe4+F/7eGawyPzy+M
# MNkjXbI1UhtqV4k9ZgQWuo6yykPx+DNH7vZbnUZjfHXCBpsI3d0Tb9UH/AySiBAR
# pHP8AcVGtZseGYe4i3SmbaxCZRBnPTL5iqgChYoWPo9ayUYcbU2s19FRFIUglKEe
# 2x1shnse55mcHaOhM5yGLqcY66NxNGjM5v6EBK4f0A3OHLSP12PzCqkqlt2twRhV
# I0bUhL4VNYI9rW9f8hE5cz4qsmqxhiQfQUzWLZY5c7HD1PzumqdJvav8pwVojq/v
# IIkN/70tE/7EPKenpy23lrwVXFic+1HZv25JX19XCfLfi0FIENXP2ep9S754llvD
# IjOtyU5SjcKtOBmI6gR2YhiQM3SfUfzQ8PhICuE7mtfPI+tKO9ooDAu7tTFOxEai
# SB3UtJBwoDPeJXNnpCZeVcvbln7O082jiOe3RxtPAsu3THy1fMZOV8soMzWR+4xt
# 22KGBrtNCdpZsA3BHCazoeCLKS2PRNs=
# SIG # End signature block
