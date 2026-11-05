# EntraPolicySuite -- the identity report (DESIGN §5.4): v1's IdentityReporter.ps1 1:1 - the user list (one row per user:
# tags, MFA / passwordless / SSPR state, sign-in dates cloud + AD, licences and over-provisioning, AD validation, devices
# per platform), the Devices list and the views (no MFA, inactive 90 / 365 days, shared mailboxes with sign-in, ...).
#   collect (Graph, Exchange, the hybrid worker's AD snapshot) -> correlate (ConvertTo-EpsIdentityRows, pure)
#   -> views (Get-EpsIdentityViews, pure) -> workbook (ConvertTo-EpsXlsx, .NET only, no ImportExcel)
# READ ONLY: nothing in the tenant or in AD is changed.
#
# v1 bugs fixed here (D3), each covered by tests/Test-EpsIdentityReport.ps1:
#  B1 the licence variables were not reset per user: a user no licence rule matched inherited the previous user's
#     "minimum plan" and over-provisioning verdict;
#  B2 a shared mailbox's over-provisioning was computed and then thrown away (its empty "minimum plan" nulled both
#     verdicts), so over-licensed shared mailboxes were never reported;
#  B3 Shared_Device_User / Teams_Room compared the SKU part number EMSPREMIUM with service PLAN ids - never true, so
#     every one of them was reported as missing its licence; rules now match part numbers OR plan ids explicitly;
#  B4 v1's over-provisioned lists also held "Microsoft 365 E3" / "Microsoft 365 E5" (display names, never equal to a
#     part number) - dropped, they never matched;
#  B5 AD last logon: the "every DC" loop never passed -Server (the same DC N times) and read the replicated
#     LastLogonDate anyway; each synced user was then found by a Where-Object over all AD users (O(n^2)) by UPN, which
#     misses a user whose cloud UPN differs from AD's. Now: one AD snapshot by the worker, joined on the SID;
#  B6 MFA registration was joined by UPN (a renamed user lost it until the report refreshed): joined on the object id;
#  B7 IncompliantMFAAuth: an operator-precedence slip ("... -or IsSSPRRegistered -ne $true -or ...") put EVERY user
#     without SSPR in the view - guests, service accounts, rooms. Now the view holds only the MFA-tagged, non-guest
#     users, as its name and its sibling CompliantMFAAuth say (owner to confirm);
#  B8 Active_NoMFA: a hire-date attribute that is not a date threw inside the filter and the user silently fell out of
#     the view; now it counts as "no hire date" (the user is shown) and the row says so;
#  B9 sorted by "UserTypeTagValue", a property that does not exist (no order): sorted by display name.

Set-StrictMode -Off

$script:EpsIdTagColumns = [ordered]@{ AccountInfo = 'UserAccountInfo'; Classification = 'UserClassification'; Authentication = 'UserAuthMethodType'; Pilot = 'UserPilotInfo'; Company = 'Company' }
$script:EpsIdPlatforms = 'iPhone', 'iPad', 'Android', 'Windows'

function Get-EpsIdentityReportConfig {
    <#
    .SYNOPSIS
        The report's settings (catalog: IdentityReport.*) with v1's values as defaults, the licence rules and the user tag
        types (each a column). -Settings: name -> value text (what eps.Setting holds); missing = the default.
    #>
    param([hashtable]$Settings = @{}, [object[]]$TagTypes = @(), [string]$LicenseRulesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'settings\identity-license-rules.json'))
    $g = { param($n, $d) if ($Settings.ContainsKey($n) -and "$($Settings[$n])" -ne '') { "$($Settings[$n])" } else { $d } }
    $list = { param($n, $d) @((& $g $n $d) | ConvertFrom-Json) }
    $tags = [System.Collections.Generic.List[object]]::new()
    foreach ($t in @($TagTypes | Where-Object { $_.ObjectType -eq 'User' -and $_.Attribute } | Sort-Object { $i = @($script:EpsIdTagColumns.Keys).IndexOf($_.Name); if ($i -lt 0) { 99 } else { $i } }, Name)) {
        $col = if ($script:EpsIdTagColumns.Contains($t.Name)) { $script:EpsIdTagColumns[$t.Name] } else { "Tag_$($t.Name -replace '[^A-Za-z0-9_]', '_')" }
        $tags.Add([pscustomobject]@{ TagType = $t.Name; Attribute = [string]$t.Attribute; Column = $col; ExportColumn = ('{0}_{1}' -f $col, ($t.Attribute -replace '^extensionAttribute', 'ext')) })
    }
    [pscustomobject]@{
        DeviceCountWindowDays = [int](& $g 'IdentityReport.DeviceCountWindowDays' '30')
        InactiveDays          = [int](& $g 'IdentityReport.InactiveDays' '90')
        LongInactiveDays      = [int](& $g 'IdentityReport.LongInactiveDays' '365')
        GuestInactiveDays     = [int](& $g 'IdentityReport.GuestInactiveDays' '90')
        NewHireGraceDays      = [int](& $g 'IdentityReport.NewHireGraceDays' '7')
        HireDateAttribute     = [string](& $g 'IdentityReport.HireDateAttribute' 'extensionAttribute2')
        AdOuUser              = [string](& $g 'IdentityReport.AdOu.User' '')
        AdOuServiceAccount    = [string](& $g 'IdentityReport.AdOu.ServiceAccount' '')
        AdOuSharedUser        = [string](& $g 'IdentityReport.AdOu.SharedUser' '')
        AdOuSharedMailbox     = [string](& $g 'IdentityReport.AdOu.SharedMailbox' '')
        ExcludeObjects        = @(& $list 'IdentityReport.ExcludeObjects' '["On-Premises Directory Synchronization Service Account"]')
        LicenseRules          = @((Get-Content -LiteralPath $LicenseRulesPath -Raw | ConvertFrom-Json).rules)
        Tags                  = $tags.ToArray()
    }
}

function Get-EpsIdentityUserSelect {
    # the user fields the report reads (Graph v1.0; signInActivity needs AuditLog.Read.All and Entra ID P1)
    'id', 'givenName', 'surname', 'userPrincipalName', 'displayName', 'accountEnabled', 'mail', 'mobilePhone', 'department', 'companyName',
    'usageLocation', 'userType', 'assignedLicenses', 'assignedPlans', 'onPremisesDistinguishedName', 'onPremisesSyncEnabled',
    'onPremisesSecurityIdentifier', 'onPremisesExtensionAttributes', 'passwordPolicies', 'signInActivity', 'createdDateTime'
}

function Read-EpsIdentitySources {
    <#
    .SYNOPSIS
        Everything the report correlates, read once per run (live; tests build the same hashtable by hand). AdUsers comes
        from the hybrid worker's snapshot (SID -> AD row) - $null when there is no worker: the AD columns then say so.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [hashtable]$AdUsers, [scriptblock]$Log = { param($l, $m) })
    & $Log 'Info' 'reading users (Graph)'
    $users = @(Invoke-EpsGraph -Path "v1.0/users?`$select=$((Get-EpsIdentityUserSelect) -join ',')&`$top=999" -All)
    & $Log 'Info' "$($users.Count) user(s); reading the MFA registration details"
    $reg = @(Invoke-EpsGraph -Path 'v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' -All)
    & $Log 'Info' "$($reg.Count) registration row(s); reading the Intune managed devices"
    # the Intune devices need DeviceManagementManagedDevices.Read.All: without it (403) the report runs without devices and
    # says so - the device counts, the smartphone views and the device gaps stay empty, nothing else is lost
    $devices = @(); $noIntune = $null
    try { $devices = @(Invoke-EpsGraph -Path 'v1.0/deviceManagement/managedDevices?$top=999' -All) }
    catch {
        if ("$_" -notmatch '-> (401|403)') { throw }
        $why = "$_"; if ($why -match '"Message"\s*:\s*"([^"]+)"') { $why = $Matches[1] -replace ' - Operation ID.*$', '' } else { $why = $why -replace '^.*-> ', '' }
        $noIntune = "the Intune devices could not be read ($why) - the engine needs DeviceManagementManagedDevices.Read.All (a new grant can take up to 24 h to reach the engine's token); the device counts and device gaps are empty this run"
    }
    & $Log 'Info' "$($devices.Count) managed device(s); reading the Exchange recipients"
    $recipients = Get-EpsExchangeRecipients -TenantId $TenantId
    $skus = @{}; foreach ($s in (Invoke-EpsGraph -Path 'v1.0/subscribedSkus?$select=skuId,skuPartNumber' -All)) { $skus[[string]$s.skuId] = [string]$s.skuPartNumber }
    @{ Users = $users; Registration = $reg; Devices = $devices; Recipients = $recipients; Skus = $skus; SkuNames = (Get-EpsLicenseDisplayNames -Log $Log); AdUsers = $AdUsers; Notes = @($noIntune | Where-Object { $_ }) }
}

function Get-EpsLicenseDisplayNames {
    # skuId -> the product's display name, from Microsoft's published licensing CSV (as v1). Not reachable: an empty map,
    # the report then shows the part number instead - the run does not fail for a display name.
    param([string]$Uri = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv', [scriptblock]$Log = { param($l, $m) })
    $map = @{}
    try {
        $csv = (Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 60).Content
        if ($csv -is [byte[]]) { $csv = [Text.Encoding]::UTF8.GetString($csv) }
        # SEC-AUDIT-1 S11: a bounded, recognisable file only (it is Microsoft's, but it is fetched at run time)
        if ($csv.Length -gt 10MB) { throw "the file is $([math]::Round($csv.Length / 1MB)) MB - more than the 10 MB expected" }
        $head = ($csv.TrimStart([char]0xFEFF) -split "\r?\n", 2)[0]
        if ($head -notmatch '(^|,)"?GUID"?(,|$)' -or $head -notmatch 'Product_Display_Name') { throw 'the file does not have the GUID / Product_Display_Name columns' }
        foreach ($r in ($csv.TrimStart([char]0xFEFF) | ConvertFrom-Csv)) { if ($r.GUID -and -not $map.ContainsKey($r.GUID)) { $map[[string]$r.GUID] = [string]$r.Product_Display_Name } }
    } catch { & $Log 'Warn' "the licence display names could not be read ($($_.Exception.Message)) - part numbers are shown instead" }
    $map
}

function ConvertFrom-EpsGraphDate($v) {
    # Graph's ISO text (or a [datetime] ConvertFrom-Json made of it) -> UTC [datetime], or $null
    if ($null -eq $v -or "$v" -eq '') { return $null }
    if ($v -is [datetime]) { return $v.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$v", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function Get-EpsDevicePlatform([string]$OperatingSystem, [string]$Model) {
    if ($OperatingSystem -match 'Android') { return 'Android' }
    if ($OperatingSystem -match 'Windows') { return 'Windows' }
    if ($OperatingSystem -match 'iPadOS') { return 'iPad' }
    if ($OperatingSystem -match 'iOS') { if ($Model -match 'iPad') { return 'iPad' } else { return 'iPhone' } }
    $null
}

function Get-EpsMfaStrength([string]$Methods, [bool]$Known) {
    # the strongest method registered: Phishing-resistant (passkey / FIDO2 / Windows Hello for Business) > App (Authenticator,
    # OTP) > Phone / mail only > None; Unknown = no registration row for the user (e.g. a guest the report does not cover)
    if (-not $Known) { return 'Unknown' }
    if ($Methods -match 'passKey|fido2|windowsHello') { return 'Phishing-resistant' }
    if ($Methods -match 'microsoftAuthenticator|softwareOneTimePasscode|hardwareOneTimePasscode') { return 'App' }
    if ($Methods -match 'mobilePhone|officePhone|alternateMobilePhone|email') { return 'Phone or mail only' }
    'None'
}

function Get-EpsSignInRecency($Last, [datetime]$NowUtc) {
    if (-not $Last) { return 'Never' }
    $d = ($NowUtc - $Last).TotalDays
    if ($d -le 30) { return '0-30 days' }; if ($d -le 90) { return '31-90 days' }; if ($d -le 365) { return '91-365 days' }
    'Over a year'
}

function Test-EpsLikeAny([string]$Value, [object[]]$Patterns) {
    if (-not $Value) { return $false }
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    $false
}

function Get-EpsLicenseVerdict {
    # B1-B4: a fresh verdict per user. @{ Minimum (label or $null); HasMinimum ($true/$false/$null); OverProvisioned }
    param([string]$Classification, [string[]]$SkuPartNumbers = @(), [string[]]$ServicePlanIds = @(), [object[]]$Rules = @())
    $rule = $Rules | Where-Object { Test-EpsLikeAny $Classification @($_.classifications) } | Select-Object -First 1
    if (-not $rule) { return @{ Minimum = $null; HasMinimum = $null; OverProvisioned = $null } }
    $min = $rule.minimum
    $needs = @($min.skuPartNumbers).Count -or @($min.servicePlanIds).Count
    $has = if (-not $needs) { $null } else {
        [bool](@($SkuPartNumbers | Where-Object { $_ -in @($min.skuPartNumbers) }).Count -or @($ServicePlanIds | Where-Object { $_ -in @($min.servicePlanIds) }).Count)
    }
    $over = if (@($rule.overProvisioned).Count) { [bool]@($SkuPartNumbers | Where-Object { $_ -in @($rule.overProvisioned) }).Count } else { $null }
    @{ Minimum = $(if ($needs) { [string]$min.label } else { 'none (no licence needed)' }); HasMinimum = $has; OverProvisioned = $over }
}

function ConvertTo-EpsIdentityRows {
    <#
    .SYNOPSIS
        The correlation (pure): one row per user in v1's columns and order, plus the Devices rows. Returns
        @{ Users; Devices; Notes }. -NowUtc fixes "now" for tests.
    #>
    param([Parameter(Mandatory)][hashtable]$Sources, [Parameter(Mandatory)]$Config, [datetime]$NowUtc = [datetime]::UtcNow)
    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($Sources.Notes)) { if ($n) { $notes.Add([string]$n) } }   # what the collection could not read
    $cutoff = $NowUtc.AddDays(-$Config.DeviceCountWindowDays)

    # registration details by object id (B6)
    $reg = @{}; foreach ($r in @($Sources.Registration)) { if ($r.id) { $reg[[string]$r.id] = $r } }

    # device counts per user (only devices synced inside the window count; the Devices list keeps every device)
    $counts = @{}; $deviceRows = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($Sources.Devices)) {
        $platform = Get-EpsDevicePlatform $d.operatingSystem $d.model
        $owner = if ($d.managedDeviceOwnerType -eq 'company') { 'Corp' } elseif ($d.managedDeviceOwnerType) { 'Personal' } else { $null }
        $sync = ConvertFrom-EpsGraphDate $d.lastSyncDateTime
        $upn = [string]$d.userPrincipalName
        if ($platform -and $owner -and $upn -and $sync -and $sync -ge $cutoff) {
            $k = $upn.ToLowerInvariant(); if (-not $counts.ContainsKey($k)) { $counts[$k] = @{} }
            $b = "DeviceCount_${platform}_$owner"; $counts[$k][$b] = 1 + [int]$counts[$k][$b]
        }
        $row = [ordered]@{
            Id = $d.id; UserPrincipalName = $d.userPrincipalName; UserDisplayName = $d.userDisplayName; DeviceName = $d.deviceName
            ManagedDeviceOwnerType = $d.managedDeviceOwnerType; OwnershipNormalized = $owner; OperatingSystem = $d.operatingSystem; OSVersion = $d.osVersion
            Model = $d.model; Manufacturer = $d.manufacturer; SerialNumber = $d.serialNumber; JoinType = $d.joinType; DeviceEnrollmentType = $d.deviceEnrollmentType
            ManagementState = $d.managementState; ManagementAgent = $d.managementAgent; ComplianceState = $d.complianceState
            DeviceCategoryDisplayName = $d.deviceCategoryDisplayName; LastSyncDateTime = $(if ($sync) { $sync.ToString('yyyy-MM-ddTHH:mm:ss') })
            EnrolledDateTime = $(if ($e = ConvertFrom-EpsGraphDate $d.enrolledDateTime) { $e.ToString('yyyy-MM-ddTHH:mm:ss') }); AzureAdDeviceId = $d.azureADDeviceId
            EmailAddress = $d.emailAddress; PhoneNumber = $d.phoneNumber; WiFiMacAddress = $d.wiFiMacAddress; EthernetMacAddress = $d.ethernetMacAddress
            PlatformNormalized = $(if ($platform) { $platform } else { $d.operatingSystem })
            CountSyncWindowDays = $Config.DeviceCountWindowDays; CountSyncCutoffUtc = $cutoff.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        # v1 added every other property Graph returned, flattened to text
        foreach ($p in $d.PSObject.Properties) {
            $n = $p.Name.Substring(0, 1).ToUpperInvariant() + $p.Name.Substring(1)
            if ($n -like '@odata*' -or $row.Contains($n) -or $row.Contains($p.Name)) { continue }
            $row[$n] = ConvertTo-EpsCellText $p.Value
        }
        $deviceRows.Add([pscustomobject]$row)
    }

    $exclude = @($Config.ExcludeObjects)
    $haveAd = $null -ne $Sources.AdUsers
    if (-not $haveAd) { $notes.Add('no AD snapshot (no hybrid worker, or it has not read AD yet): the AD_* columns are empty and AD-only sign-ins are not seen') }
    $badHire = 0
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($Sources.Users)) {
        if ((Test-EpsLikeAny $u.displayName $exclude) -or (Test-EpsLikeAny $u.userPrincipalName $exclude)) { continue }
        $ext = $u.onPremisesExtensionAttributes
        $tagVal = @{}; foreach ($t in $Config.Tags) { $tagVal[$t.Column] = [string]$ext.($t.Attribute) }
        $cls = $tagVal['UserClassification']
        $ad = if ($haveAd -and $u.onPremisesSyncEnabled -and $u.onPremisesSecurityIdentifier) { $Sources.AdUsers[[string]$u.onPremisesSecurityIdentifier] }
        $a = $reg[[string]$u.id]
        $dn = [string]$u.onPremisesDistinguishedName
        $ouMatch = { param($rx) [bool]($rx -and $dn -and $dn -match $rx) }
        $parts = @($u.assignedLicenses | ForEach-Object { $Sources.Skus[[string]$_.skuId] } | Where-Object { $_ } | Sort-Object -Unique)
        $plans = @($u.assignedPlans | Where-Object { $_.capabilityStatus -ne 'Deleted' } | ForEach-Object { [string]$_.servicePlanId })
        $names = @($u.assignedLicenses | ForEach-Object { $s = [string]$_.skuId; if ($Sources.SkuNames -and $Sources.SkuNames[$s]) { $Sources.SkuNames[$s] } elseif ($Sources.Skus[$s]) { $Sources.Skus[$s] } else { $s } } | Sort-Object -Unique)
        $lic = Get-EpsLicenseVerdict -Classification $cls -SkuPartNumbers $parts -ServicePlanIds $plans -Rules $Config.LicenseRules
        $dc = $counts[([string]$u.userPrincipalName).ToLowerInvariant()]; if (-not $dc) { $dc = @{} }
        $hireText = [string]$ext.($Config.HireDateAttribute); $hire = $null
        if ($hireText) { $hire = ConvertFrom-EpsGraphDate $hireText; if (-not $hire) { $badHire++ } }   # B8
        $row = [ordered]@{
            Id = $u.id; GivenName = $u.givenName; SurName = $u.surname; UserPrincipalName = $u.userPrincipalName; DisplayName = $u.displayName
            Description_AD = $(if ($ad) { $ad.Description }); AccountEnabled = [bool]$u.accountEnabled
        }
        foreach ($t in $Config.Tags) { $row[$t.Column] = $tagVal[$t.Column] }
        $row.CompanyName = $u.companyName; $row.Mail = $u.mail; $row.UserType = $u.userType
        $row.IsAdmin = $a.isAdmin
        $row.MailType = $(if ($Sources.Recipients) { $Sources.Recipients[[string]$u.id] })
        $row.DefaultMfaMethod = $a.defaultMfaMethod
        $row.MethodsRegistered = $(if ($a) { @($a.methodsRegistered) -join ',' })
        foreach ($f in 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprCapable', 'isSsprEnabled', 'isSsprRegistered', 'isSystemPreferredAuthenticationMethodEnabled') { $row[$f.Substring(0, 1).ToUpperInvariant() + $f.Substring(1)] = $a.$f }
        $row.AuthMethodsLastUpdatedDateTime = $(if ($x = ConvertFrom-EpsGraphDate $a.lastUpdatedDateTime) { $x })
        $row.HireDate = $hireText
        $row.HireDateValid = $(if ($hireText) { [bool]$hire })
        $row.Cloud_LastSignInDateTime = ConvertFrom-EpsGraphDate $u.signInActivity.lastSignInDateTime
        $row.Cloud_LastNonInteractiveSignInDateTime = ConvertFrom-EpsGraphDate $u.signInActivity.lastNonInteractiveSignInDateTime
        $row.AD_LastSignInDateTime = $(if ($ad) { ConvertFrom-EpsGraphDate $ad.LastLogon })
        $row.AD_Enabled = $(if ($ad) { $ad.Enabled }); $row.AD_LockedOut = $(if ($ad) { $ad.LockedOut })
        $row.AD_CannotChangePassword = $(if ($ad) { $ad.CannotChangePassword })
        $row.AD_AccountExpirationDate = $(if ($ad) { ConvertFrom-EpsGraphDate $ad.AccountExpires })
        $row.AD_OnPremisesSyncEnabled = $u.onPremisesSyncEnabled
        $row.Cloud_PasswordPolicies = $u.passwordPolicies
        $row.AD_PasswordNeverExpires = $(if ($ad) { $ad.PasswordNeverExpires })
        $row.UserIsADValidated = & $ouMatch $Config.AdOuUser
        $row.ServiceAccountIsADValidated = & $ouMatch $Config.AdOuServiceAccount
        $row.SharedUserIsADValidated = & $ouMatch $Config.AdOuSharedUser
        $row.SharedMailboxIsADValidated = & $ouMatch $Config.AdOuSharedMailbox
        $row.UserIsCloudValidated = [bool]($u.mobilePhone -and $u.department -and $u.usageLocation)
        $row.IsLicenseOverProvisioned = $lic.OverProvisioned; $row.HasMinimumNeededLicense = $lic.HasMinimum; $row.MinimumPlanNeeded = $lic.Minimum
        $row.ADDN = $dn; $row.UserLicenseList = $names -join ','
        foreach ($p in $script:EpsIdPlatforms) { foreach ($o in 'Corp', 'Personal') { $row["DeviceCount_${p}_$o"] = [int]$dc["DeviceCount_${p}_$o"] } }
        $row.Device_SmartPhoneActive = ($row.DeviceCount_iPhone_Corp + $row.DeviceCount_iPhone_Personal + $row.DeviceCount_Android_Corp + $row.DeviceCount_Android_Personal) -gt 0
        $row.Device_SmartPhoneActive_CorpOnly = ($row.DeviceCount_iPhone_Corp + $row.DeviceCount_Android_Corp) -gt 0
        # new in v2 (the gap views and the pivots): how strong the registered methods are, how recent the last sign-in is
        $row.CreatedDateTime = ConvertFrom-EpsGraphDate $u.createdDateTime
        $row.MfaStrength = Get-EpsMfaStrength $row.MethodsRegistered $(if ($a) { $true } else { $false })
        $last = @($row.Cloud_LastSignInDateTime, $row.Cloud_LastNonInteractiveSignInDateTime, $row.AD_LastSignInDateTime | Where-Object { $_ } | Sort-Object -Descending)[0]
        $row.LastSignInAny = $last
        $row.SignInRecency = Get-EpsSignInRecency $last $NowUtc
        $rows.Add([pscustomobject]$row)
    }
    if ($badHire) { $notes.Add("$badHire user(s) have a hire date in $($Config.HireDateAttribute) that is not a date - counted as 'no hire date' (shown in Active_NoMFA)") }
    @{ Users = @($rows | Sort-Object DisplayName, UserPrincipalName); Devices = @($deviceRows | Sort-Object UserPrincipalName, DeviceName); Notes = $notes.ToArray() }   # B9
}

function ConvertTo-EpsCellText($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [string] -or $v -is [ValueType]) { if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') }; return $v }
    if ($v -is [array]) { return (@($v | ForEach-Object { ConvertTo-EpsCellText $_ }) -join '; ') }
    try { $v | ConvertTo-Json -Compress -Depth 10 } catch { "$v" }
}

function Get-EpsIdentityViewHelpers {
    # the helpers the views' tests share - passed IN ($C.H): a test runs long after the catalog function returned, so it
    # cannot see that function's variables
    $act = 'NonManaged_User_AD_Synced', 'NonManaged_User_Cloud', 'Internal_User', 'External_User', 'Internal_Developer', 'External_Developer'
    $adSynced = 'NonManaged_User_AD_Synced', 'Internal_User_AD_Synced*', 'External_User_AD_Synced*', 'Internal_Developer_AD_Synced*', 'External_Developer_AD_Synced*', 'NonManaged_User_AD_Synced*'
    $isGuest = { param($r) "$($r.UserClassification)" -like '*Guest*' -or $r.UserType -eq 'Guest' }
    $isMailboxOnly = { param($r) $r.MailType -in 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox' -or "$($r.UserClassification)" -like '*SharedMailbox*' }
    $quiet = { param($r, $days, $C) $d = $C.Now.AddDays(-$days); (-not $r.AD_LastSignInDateTime -or $r.AD_LastSignInDateTime -lt $d) -and (-not $r.Cloud_LastSignInDateTime -or $r.Cloud_LastSignInDateTime -lt $d) }
    $mfaUser = { param($r) "$($r.UserAuthMethodType)" -like '*MFA' -and "$($r.UserAuthMethodType)" -notlike '*Guest*' }
    $strong = { param($r) $r.MethodsRegistered -match 'microsoftAuthenticatorPush' -or $r.MethodsRegistered -match 'windowsHello' }
    $noMfaCandidate = { param($r) $x = "$($r.UserAuthMethodType)"; $r.AccountEnabled -and $x -notlike '*Guest*' -and $x -notlike '*_FIDO' -and $x -notlike '*_Pwd' -and $x -notlike '*_WHfB' -and "$($r.DefaultMfaMethod)" -like '*none*' }
    @{ act = $act; adSynced = $adSynced; isGuest = $isGuest; isMailboxOnly = $isMailboxOnly; quiet = $quiet; mfaUser = $mfaUser; strong = $strong; noMfaCandidate = $noMfaCandidate }
}
function Get-EpsIdentityViewCatalog {
    <#
    .SYNOPSIS
        The views (owner 2026-10-31: "make lots of relevant views", "that shows gaps", "similar to excel pivots"). Each one:
        Name (stable id; v1's sheet names kept), Group (the page's sections), Kind (User | Device), Severity (High | Medium |
        Low | Info for a gap; '' for a plain list), Title, What (what it means), Fix (how to close it), Columns (the grid's
        default columns; every column can be added), V1 (one of v1's sheets), Test (the filter: param($r, $C)).
        $C = @{ Now; Config; H } - the run's "now", settings and the shared helpers (Get-EpsIdentityViewHelpers).
    #>
    $u0 = 'DisplayName', 'UserPrincipalName', 'UserClassification', 'UserAuthMethodType', 'AccountEnabled'
    $d0 = 'DeviceName', 'UserPrincipalName', 'PlatformNormalized', 'OwnershipNormalized', 'ComplianceState', 'LastSyncDateTime'
    $V = {
        param($Name, $Group, $Kind, $Severity, $Title, $What, $Fix, $Columns, $Test, [switch]$V1)
        [pscustomobject]@{ Name = $Name; Group = $Group; Kind = $Kind; Severity = $Severity; Title = $Title; What = $What; Fix = $Fix; Columns = @($Columns); V1 = [bool]$V1; Test = $Test }
    }
    @(
        # ---- the lists ----
        & $V 'Users_ALL' 'Lists' 'User' '' 'All users' 'Every user with every column.' '' ($u0 + 'MailType', 'MfaStrength', 'SignInRecency', 'UserLicenseList') { param($r, $C) $true } -V1
        & $V 'Devices' 'Lists' 'Device' '' 'All devices (Intune)' 'Every Intune managed device. The per-user device counts only count devices synced in the device window.' '' $d0 { param($r, $C) $true } -V1

        # ---- MFA and authentication ----
        & $V 'Admins_NoMfa' 'MFA and authentication' 'User' 'High' 'Admins without MFA' 'Users with an admin role who are not registered for MFA.' 'Register MFA for each admin now (Temporary Access Pass + a passkey); until then they are one password away from a tenant takeover.' ($u0 + 'IsAdmin', 'IsMfaRegistered', 'MethodsRegistered') { param($r, $C) $r.IsAdmin -eq $true -and $r.AccountEnabled -and $r.IsMfaRegistered -ne $true }
        & $V 'Admins_NotPhishingResistant' 'MFA and authentication' 'User' 'High' 'Admins without phishing-resistant MFA' 'Enabled admins without a passkey, FIDO2 key or Windows Hello for Business.' 'Give every admin a passkey (or FIDO2 key) and require phishing-resistant MFA for admin roles in Conditional Access.' ($u0 + 'IsAdmin', 'MfaStrength', 'MethodsRegistered') { param($r, $C) $r.IsAdmin -eq $true -and $r.AccountEnabled -and $r.MfaStrength -ne 'Phishing-resistant' }
        & $V 'Active_NoMFA' 'MFA and authentication' 'User' 'High' 'Active without MFA' 'Enabled users (not guests, not FIDO / password-only / WHfB tagged) whose default MFA method is none - except new hires starting after the grace period.' 'Have them register MFA; if they cannot, check their Authentication tag.' ($u0 + 'DefaultMfaMethod', 'HireDate', 'HireDateValid', 'SignInRecency') {
            param($r, $C) if (-not (& $C.H.noMfaCandidate $r)) { return $false }
            $h = if ($r.HireDateValid) { ConvertFrom-EpsGraphDate $r.HireDate }; -not $h -or $h -lt $C.Now.Date.AddDays($C.Config.NewHireGraceDays) } -V1
        & $V 'ActiveNoMFACorpSmartDevice' 'MFA and authentication' 'User' 'High' 'No MFA, but a company smartphone' 'Enabled users (no mailbox, or a user mailbox / mail user) whose default MFA method is none, with a company iPhone or Android synced in the device window - they can register Authenticator today.' 'Ask them to register the Authenticator app on their company phone.' ($u0 + 'DefaultMfaMethod', 'DeviceCount_iPhone_Corp', 'DeviceCount_Android_Corp') { param($r, $C) $r.AccountEnabled -and (-not $r.MailType -or $r.MailType -in 'MailUser', 'UserMailbox') -and "$($r.DefaultMfaMethod)" -like '*none*' -and $r.Device_SmartPhoneActive_CorpOnly } -V1
        & $V 'Mfa_WeakMethodsOnly' 'MFA and authentication' 'User' 'Medium' 'MFA by phone or mail only' 'Enabled users whose only registered methods are SMS, voice or e-mail - the methods SIM swap and phishing defeat.' 'Move them to the Authenticator app or a passkey, then disable SMS / voice in the authentication methods policy.' ($u0 + 'MfaStrength', 'MethodsRegistered') { param($r, $C) $r.AccountEnabled -and $r.MfaStrength -eq 'Phone or mail only' }
        & $V 'Mfa_NotCapable' 'MFA and authentication' 'User' 'Medium' 'Cannot do MFA' 'Enabled user accounts (not guests, not shared / room mailboxes) with no method that can satisfy MFA.' 'Register a method, or tag the account for what it is (service account, shared mailbox) so the right policy applies.' ($u0 + 'IsMfaCapable', 'MethodsRegistered', 'MailType') { param($r, $C) $r.AccountEnabled -and $r.IsMfaCapable -eq $false -and -not (& $C.H.isGuest $r) -and -not (& $C.H.isMailboxOnly $r) }
        & $V 'CompliantMFAAuth' 'MFA and authentication' 'User' 'Info' 'MFA users - compliant' 'MFA-tagged users (not guests) registered for MFA and SSPR, with Authenticator push or Windows Hello.' '' ($u0 + 'IsMfaRegistered', 'IsSsprRegistered', 'MethodsRegistered') { param($r, $C) (& $C.H.mfaUser $r) -and $r.IsMfaRegistered -eq $true -and $r.IsSsprRegistered -eq $true -and (& $C.H.strong $r) } -V1
        & $V 'IncompliantMFAAuth' 'MFA and authentication' 'User' 'Medium' 'MFA users - not compliant' 'MFA-tagged users (not guests) not registered for MFA, not for SSPR, or with neither Authenticator push nor Windows Hello.' 'Have them complete the combined registration (Authenticator + SSPR).' ($u0 + 'IsMfaRegistered', 'IsSsprRegistered', 'MethodsRegistered') { param($r, $C) (& $C.H.mfaUser $r) -and ($r.IsMfaRegistered -ne $true -or $r.IsSsprRegistered -ne $true -or -not (& $C.H.strong $r)) } -V1   # B7
        & $V 'CompliantPasskeysAuth' 'MFA and authentication' 'User' 'Info' 'Passkey users - compliant' 'FIDO-tagged users with a device-bound passkey.' '' ($u0 + 'MethodsRegistered') { param($r, $C) "$($r.UserAuthMethodType)" -like '*FIDO' -and $r.MethodsRegistered -match 'passKeyDeviceBound' } -V1
        & $V 'IncompliantPasskeysAuth' 'MFA and authentication' 'User' 'High' 'Passkey users without a passkey' 'FIDO-tagged users without a device-bound passkey - the policy for them expects one.' 'Issue a Temporary Access Pass and have them register a passkey.' ($u0 + 'MethodsRegistered') { param($r, $C) "$($r.UserAuthMethodType)" -like '*FIDO' -and $r.MethodsRegistered -notmatch 'passKeyDeviceBound' } -V1
        & $V 'Sspr_NotRegistered' 'MFA and authentication' 'User' 'Low' 'SSPR on, not registered' 'Enabled users who may reset their own password but have not registered for it - they call the help desk instead.' 'Use the registration campaign (or combined registration) to collect it.' ($u0 + 'IsSsprEnabled', 'IsSsprRegistered') { param($r, $C) $r.AccountEnabled -and $r.IsSsprEnabled -eq $true -and $r.IsSsprRegistered -ne $true }
        & $V 'SystemPreferredMfa_Off' 'MFA and authentication' 'User' 'Low' 'System-preferred MFA off' 'MFA-registered users for whom Entra does not pick the strongest method at sign-in.' 'Enable system-preferred MFA in the authentication methods policy.' ($u0 + 'IsSystemPreferredAuthenticationMethodEnabled', 'DefaultMfaMethod') { param($r, $C) $r.IsMfaRegistered -eq $true -and $r.IsSystemPreferredAuthenticationMethodEnabled -eq $false }

        # ---- sign-in and lifecycle ----
        & $V 'ActiveLastSign90DaysOrNoSignIn' 'Sign-in and lifecycle' 'User' 'Medium' 'No sign-in for 90 days' 'Enabled users of the active classifications with no sign-in (cloud nor AD) in the inactivity window.' 'Confirm with the manager, then disable; delete after your retention period.' ($u0 + 'Cloud_LastSignInDateTime', 'AD_LastSignInDateTime', 'SignInRecency') { param($r, $C) (& $C.H.quiet $r $C.Config.InactiveDays $C) -and "$($r.UserClassification)" -in $C.H.act -and $r.AccountEnabled } -V1
        & $V 'ActiveLastSignXDaysOrNoSignIn' 'Sign-in and lifecycle' 'User' 'High' 'No sign-in for a year' 'Enabled users of the active classifications with no sign-in (cloud nor AD) in the long inactivity window - almost certainly orphaned.' 'Disable now; delete after your retention period.' ($u0 + 'Cloud_LastSignInDateTime', 'AD_LastSignInDateTime', 'SignInRecency') { param($r, $C) (& $C.H.quiet $r $C.Config.LongInactiveDays $C) -and "$($r.UserClassification)" -in $C.H.act -and $r.AccountEnabled } -V1
        & $V 'NeverSignedIn' 'Sign-in and lifecycle' 'User' 'Medium' 'Never signed in' 'Enabled users created more than the inactivity window ago who have never signed in (cloud, non-interactive nor AD).' 'Find out why it exists; disable it if nobody claims it.' ($u0 + 'CreatedDateTime', 'UserLicenseList') { param($r, $C) $r.AccountEnabled -and $r.SignInRecency -eq 'Never' -and $r.CreatedDateTime -and $r.CreatedDateTime -lt $C.Now.AddDays(-$C.Config.InactiveDays) -and -not (& $C.H.isMailboxOnly $r) }
        & $V 'ActiveOnlyADSignIn' 'Sign-in and lifecycle' 'User' 'Low' 'Signs in to AD only' 'Enabled users with an AD sign-in but never a cloud sign-in - candidates to stop syncing to the cloud.' 'Scope them out of the Entra Connect sync (fewer cloud identities to protect).' ($u0 + 'AD_LastSignInDateTime', 'Cloud_LastSignInDateTime') { param($r, $C) $r.AD_LastSignInDateTime -and -not $r.Cloud_LastSignInDateTime -and $r.AccountEnabled } -V1
        & $V 'Disabled_StillLicensed' 'Licences' 'User' 'Medium' 'Disabled but licensed' 'Disabled users who still hold licences.' 'Remove the licences (or convert the mailbox to shared) - it is money spent on nobody.' ($u0 + 'UserLicenseList') { param($r, $C) -not $r.AccountEnabled -and $r.UserLicenseList }
        & $V 'PasswordNeverExpires' 'Sign-in and lifecycle' 'User' 'Low' 'Password never expires' 'Enabled users whose password never expires, in Entra or in AD.' 'Fine with passwordless / strong MFA; otherwise make sure the password is long and unique, or move the account to a managed identity.' ($u0 + 'Cloud_PasswordPolicies', 'AD_PasswordNeverExpires') { param($r, $C) $r.AccountEnabled -and ("$($r.Cloud_PasswordPolicies)" -match 'DisablePasswordExpiration' -or $r.AD_PasswordNeverExpires -eq $true) }

        # ---- guests ----
        & $V 'GuestsNoSignInLast90Days' 'Guests' 'User' 'Medium' 'Guests without a recent sign-in' 'Enabled guests with no cloud sign-in in the guest inactivity window.' 'Remove them, or run an access review on guests.' ($u0 + 'Cloud_LastSignInDateTime', 'SignInRecency') { param($r, $C) $d = $C.Now.AddDays(-$C.Config.GuestInactiveDays); $r.AccountEnabled -and "$($r.UserClassification)" -like '*Guest*' -and (-not $r.Cloud_LastSignInDateTime -or $r.Cloud_LastSignInDateTime -lt $d) } -V1
        & $V 'Guests_Admin' 'Guests' 'User' 'High' 'Guests with an admin role' 'Guest accounts that hold an admin role - an outside identity you do not manage.' 'Remove the role, or replace the guest with a managed account (or PIM-eligible with approval).' ($u0 + 'IsAdmin', 'MfaStrength') { param($r, $C) (& $C.H.isGuest $r) -and $r.IsAdmin -eq $true }
        & $V 'Guests_Licensed' 'Guests' 'User' 'Low' 'Guests with a licence' 'Guest accounts with an assigned licence.' 'Check it is needed; most guests need none.' ($u0 + 'UserLicenseList') { param($r, $C) (& $C.H.isGuest $r) -and $r.UserLicenseList }

        # ---- licences ----
        & $V 'OverProvisionedUsers' 'Licences' 'User' 'Low' 'More licence than needed' 'Users holding a licence their classification does not need (the licence rules).' 'Assign the licence the classification needs instead.' ($u0 + 'MinimumPlanNeeded', 'UserLicenseList') { param($r, $C) $r.IsLicenseOverProvisioned -eq $true } -V1
        & $V 'IncompliantUsers_LicenseMissing' 'Licences' 'User' 'Medium' 'Missing the licence they need' 'Users without the minimum licence their classification needs - features the policies rely on may not apply to them.' 'Assign the minimum licence (group-based licensing by classification).' ('DisplayName', 'UserPrincipalName', 'HasMinimumNeededLicense', 'MinimumPlanNeeded', 'UserLicenseList') { param($r, $C) $r.HasMinimumNeededLicense -eq $false } -V1

        # ---- tagging coverage ----
        & $V 'Untagged_Classification' 'Tagging coverage' 'User' 'Medium' 'No Classification tag' 'Enabled users without a Classification - the Conditional Access policies that target classifications do not see them.' 'Add a rule (Rules page) that classifies them, or a fallback on the tag type.' ($u0 + 'ADDN', 'MailType') { param($r, $C) $r.AccountEnabled -and -not $r.UserClassification }
        & $V 'Untagged_Authentication' 'Tagging coverage' 'User' 'Medium' 'No Authentication tag' 'Enabled users without an Authentication tag - no authentication policy targets them.' 'Add a rule (Rules page) for their authentication method.' ($u0 + 'MfaStrength') { param($r, $C) $r.AccountEnabled -and -not $r.UserAuthMethodType }
        & $V 'Cloud_NotValidated' 'Tagging coverage' 'User' 'Low' 'Cloud users missing HR data' 'Enabled cloud-only users (not guests) without a mobile phone, department or usage location - v1 computed it, now a view.' 'Fill the fields from HR, or check whether the account is a real person.' ($u0 + 'UserIsCloudValidated') { param($r, $C) $r.AccountEnabled -and -not $r.AD_OnPremisesSyncEnabled -and -not (& $C.H.isGuest $r) -and -not (& $C.H.isMailboxOnly $r) -and $r.UserIsCloudValidated -eq $false }

        # ---- AD hygiene ----
        & $V 'Ad_DisabledButCloudEnabled' 'AD hygiene' 'User' 'High' 'Disabled in AD, enabled in Entra' 'AD-synced users disabled in AD but still enabled in Entra - the sync has not caught up, or the account was re-enabled in the cloud.' 'Check Entra Connect; disable the cloud account.' ($u0 + 'AD_Enabled', 'ADDN') { param($r, $C) $r.AD_Enabled -eq $false -and $r.AccountEnabled }
        & $V 'Ad_ExpiredButEnabled' 'AD hygiene' 'User' 'High' 'Expired in AD, still enabled' 'AD accounts past their expiry date that are still enabled in Entra - an expiry in AD does not stop a cloud sign-in.' 'Disable the account (Entra and AD).' ($u0 + 'AD_AccountExpirationDate', 'ADDN') { param($r, $C) $r.AD_AccountExpirationDate -and $r.AD_AccountExpirationDate -lt $C.Now -and $r.AccountEnabled }
        & $V 'Ad_LockedOut' 'AD hygiene' 'User' 'Info' 'Locked out in AD' 'AD accounts that are locked out right now - a password spray shows up here first.' 'Look for a pattern (many at once = an attack).' ($u0 + 'AD_LockedOut', 'ADDN') { param($r, $C) $r.AD_LockedOut -eq $true }
        & $V 'Users_AD_Validated' 'AD hygiene' 'User' 'Info' 'AD users in the right OU' 'AD-synced users (by Authentication tag) whose AD location matches the user OU pattern.' '' ($u0 + 'ADDN') { param($r, $C) (Test-EpsLikeAny "$($r.UserAuthMethodType)" $C.H.adSynced) -and $r.UserIsADValidated } -V1
        & $V 'Users_AD_NoValidation' 'AD hygiene' 'User' 'Low' 'AD users in the wrong OU' 'AD-synced users (by Authentication tag) whose AD location does not match the user OU pattern - GPOs and delegation meant for users miss them.' 'Move them to the user OU (or fix the pattern in Settings).' ($u0 + 'ADDN') { param($r, $C) (Test-EpsLikeAny "$($r.UserAuthMethodType)" $C.H.adSynced) -and -not $r.UserIsADValidated } -V1
        & $V 'SharedUsers_AD_Validated' 'AD hygiene' 'User' 'Info' 'Shared device users in the right OU' 'AD-synced shared device users whose AD location matches the user OU pattern.' '' ($u0 + 'ADDN') { param($r, $C) "$($r.UserAuthMethodType)" -like 'Shared_Device_User_AD_Synced*' -and $r.UserIsADValidated } -V1
        & $V 'SharedUsers_AD_NoValidation' 'AD hygiene' 'User' 'Low' 'Shared device users in the wrong OU' 'AD-synced shared device users whose AD location does not match the user OU pattern.' 'Move them to the right OU.' ($u0 + 'ADDN') { param($r, $C) "$($r.UserAuthMethodType)" -like 'Shared_Device_User_AD_Synced*' -and -not $r.UserIsADValidated } -V1
        & $V 'ServiceAccount_AD_Validated' 'AD hygiene' 'User' 'Info' 'Service accounts in the right OU' 'AD-synced service accounts whose AD location matches the service account OU pattern.' '' ($u0 + 'ADDN') { param($r, $C) "$($r.UserAuthMethodType)" -like 'Service_Account_AD_Synced*' -and $r.ServiceAccountIsADValidated } -V1
        & $V 'ServiceAccount_AD_NoValidation' 'AD hygiene' 'User' 'Medium' 'Service accounts in the wrong OU' 'AD-synced service accounts outside the service account OU - their hardening GPOs do not apply.' 'Move them to the service account OU.' ($u0 + 'ADDN') { param($r, $C) "$($r.UserAuthMethodType)" -like 'Service_Account_AD_Synced*' -and -not $r.ServiceAccountIsADValidated } -V1
        & $V 'SharedMailboxSignInEnabled' 'AD hygiene' 'User' 'Medium' 'Shared mailboxes that can sign in' 'Shared mailbox accounts that are enabled - nobody should sign in to a shared mailbox.' 'Block sign-in on the account (the mailbox keeps working).' ($u0 + 'MailType') { param($r, $C) $r.AccountEnabled -and "$($r.UserClassification)" -like '*SharedMailbox*' } -V1

        # ---- devices ----
        & $V 'Byod_Only' 'Devices' 'User' 'Info' 'Personal smartphone only' 'Enabled users whose only active smartphones are personal (BYOD).' 'Check app protection policies cover them.' ($u0 + 'DeviceCount_iPhone_Personal', 'DeviceCount_Android_Personal') { param($r, $C) $r.AccountEnabled -and $r.Device_SmartPhoneActive -and -not $r.Device_SmartPhoneActive_CorpOnly }
        & $V 'Devices_NonCompliant' 'Devices' 'Device' 'High' 'Non-compliant devices' 'Managed devices Intune reports as not compliant.' 'Fix the failing settings; a compliant-device policy in Conditional Access blocks them meanwhile.' ($d0 + 'OSVersion') { param($r, $C) "$($r.ComplianceState)" -in 'noncompliant', 'error', 'conflict' }
        & $V 'Devices_ActiveMalware' 'Devices' 'Device' 'High' 'Devices with active malware' 'Windows devices with active malware reported.' 'Isolate and remediate in Defender for Endpoint.' ($d0 + 'WindowsActiveMalwareCount') { param($r, $C) [int]"0$($r.WindowsActiveMalwareCount)" -gt 0 }
        & $V 'Devices_Jailbroken' 'Devices' 'Device' 'High' 'Jailbroken or rooted devices' 'Devices Intune reports as jailbroken / rooted.' 'Retire the device from management; block it with a compliance policy.' ($d0 + 'JailBroken') { param($r, $C) "$($r.JailBroken)" -eq 'True' }
        & $V 'Devices_NotEncrypted' 'Devices' 'Device' 'Medium' 'Devices not encrypted' 'Managed devices that report no disk encryption.' 'Enforce BitLocker / FileVault / device encryption with a compliance policy.' ($d0 + 'IsEncrypted') { param($r, $C) "$($r.IsEncrypted)" -eq 'False' }
        & $V 'Devices_Stale' 'Devices' 'Device' 'Low' 'Stale devices' 'Managed devices that have not synced in the device window.' 'Retire / delete devices not used any more (Intune device clean-up rules).' ($d0) { param($r, $C) $s = ConvertFrom-EpsGraphDate $r.LastSyncDateTime; -not $s -or $s -lt $C.Now.AddDays(-$C.Config.DeviceCountWindowDays) }
        & $V 'Devices_NoPrimaryUser' 'Devices' 'Device' 'Low' 'Devices without a user' 'Managed devices with no primary user.' 'Set the primary user, or confirm it is a shared / kiosk device.' ($d0) { param($r, $C) -not $r.UserPrincipalName }
    )
}

function Get-EpsIdentityViews {
    <#
    .SYNOPSIS
        Every view of the catalog (pure): name -> rows, in catalog order. v1's views 1:1 except B7 / B8.
    #>
    param([Parameter(Mandatory)][hashtable]$Report, [Parameter(Mandatory)]$Config, [datetime]$NowUtc = [datetime]::UtcNow)
    $C = @{ Now = $NowUtc; Config = $Config; H = (Get-EpsIdentityViewHelpers) }
    $v = [ordered]@{}
    foreach ($d in Get-EpsIdentityViewCatalog) {
        $src = if ($d.Kind -eq 'Device') { @($Report.Devices) } else { @($Report.Users) }
        $t = $d.Test
        $v[$d.Name] = @($src | Where-Object { & $t $_ $C })   # full rows (the snapshot keeps the ids); the workbook cuts v1's five-column sheet
    }
    $v
}

function Get-EpsIdentityPivotCatalog {
    # the ready-made pivots (owner 2026-10-31: "similar to excel pivots"): rows x columns over a view's rows
    @(
        [pscustomobject]@{ Name = 'MfaByClassification';      Title = 'MFA strength by classification';      View = 'Users_ALL'; Kind = 'User';   Rows = 'UserClassification'; Columns = 'MfaStrength';         Filter = { param($r) $r.AccountEnabled } }
        [pscustomobject]@{ Name = 'SignInByClassification';   Title = 'Last sign-in by classification';      View = 'Users_ALL'; Kind = 'User';   Rows = 'UserClassification'; Columns = 'SignInRecency';       Filter = { param($r) $r.AccountEnabled } }
        [pscustomobject]@{ Name = 'LicenceByClassification';  Title = 'Licence fit by classification';       View = 'Users_ALL'; Kind = 'User';   Rows = 'UserClassification'; Columns = 'LicenceFit';          Filter = { param($r) $true } }
        [pscustomobject]@{ Name = 'AuthTagByMfaStrength';     Title = 'Authentication tag vs MFA strength';  View = 'Users_ALL'; Kind = 'User';   Rows = 'UserAuthMethodType'; Columns = 'MfaStrength';         Filter = { param($r) $r.AccountEnabled } }
        [pscustomobject]@{ Name = 'DevicesByPlatform';        Title = 'Devices by platform and ownership';   View = 'Devices';   Kind = 'Device'; Rows = 'PlatformNormalized'; Columns = 'OwnershipNormalized'; Filter = { param($r) $true } }
        [pscustomobject]@{ Name = 'ComplianceByPlatform';     Title = 'Device compliance by platform';       View = 'Devices';   Kind = 'Device'; Rows = 'PlatformNormalized'; Columns = 'ComplianceState';     Filter = { param($r) $true } }
    )
}

function Get-EpsIdentityPivot {
    <#
    .SYNOPSIS
        A pivot (pure): counts of -Rows x -Columns (or only -Rows) over the rows. Empty values count as '(empty)'.
        @{ RowKey; ColumnKey; Columns (values, sorted by count); Rows (@{ Value; Counts @{col -> n}; Total }); Total }
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][string]$RowKey, [string]$ColumnKey)
    $val = { param($r, $k) if ($k -eq 'LicenceFit') { if ($r.HasMinimumNeededLicense -eq $false) { 'Missing' } elseif ($r.IsLicenseOverProvisioned -eq $true) { 'Over-provisioned' } elseif ($null -eq $r.MinimumPlanNeeded) { 'No rule' } else { 'OK' } } else { $x = $r.$k; if ($null -eq $x -or "$x" -eq '') { '(empty)' } else { "$x" } } }
    $cells = @{}; $rowTot = @{}; $colTot = @{}
    foreach ($r in $Rows) {
        $a = & $val $r $RowKey; $b = if ($ColumnKey) { & $val $r $ColumnKey } else { 'Count' }
        if (-not $cells.ContainsKey($a)) { $cells[$a] = @{} }
        $cells[$a][$b] = 1 + [int]$cells[$a][$b]; $rowTot[$a] = 1 + [int]$rowTot[$a]; $colTot[$b] = 1 + [int]$colTot[$b]
    }
    $cols = @($colTot.Keys | Sort-Object @{ e = { $colTot[$_] }; Descending = $true }, @{ e = { $_ } })
    [pscustomobject]@{
        RowKey = $RowKey; ColumnKey = $ColumnKey; Columns = $cols; Total = @($Rows).Count
        Rows = @($rowTot.Keys | Sort-Object @{ e = { $rowTot[$_] }; Descending = $true }, @{ e = { $_ } } | ForEach-Object { [pscustomobject]@{ Value = $_; Counts = $cells[$_]; Total = $rowTot[$_] } })
    }
}

function Rename-EpsIdentityTagColumns {
    # the exported sheets / CSV name a tag column with its attribute, e.g. UserClassification_ext6 (as v1)
    param([object[]]$Rows, $Config)
    $map = @{}; foreach ($t in $Config.Tags) { $map[$t.Column] = $t.ExportColumn }
    foreach ($r in $Rows) {
        $o = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $o[$(if ($map.ContainsKey($p.Name)) { $map[$p.Name] } else { $p.Name })] = $p.Value }
        [pscustomobject]$o
    }
}

function ConvertTo-EpsXlsx {
    <#
    .SYNOPSIS
        A workbook from -Sheets (ordered name -> rows), .NET only (no ImportExcel). Each sheet: a bold, frozen header row
        and an AutoFilter; booleans as booleans, numbers as numbers, dates as yyyy-MM-dd HH:mm:ss text. An empty view still
        gets its sheet (header-less), so the workbook always has every view. Returns the bytes.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Sheets)
    $esc = { param($s) $t = [System.Security.SecurityElement]::Escape([string]$s); [regex]::Replace($t, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '') }
    $col = { param([int]$i) $n = ''; $i++; while ($i -gt 0) { $m = ($i - 1) % 26; $n = [char](65 + $m) + $n; $i = [int](($i - $m) / 26) }; $n }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $ms = [IO.MemoryStream]::new()
    $zip = [IO.Compression.ZipArchive]::new($ms, [IO.Compression.ZipArchiveMode]::Create, $true)
    $put = { param($name, $text) $e = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal); $w = [IO.StreamWriter]::new($e.Open(), [Text.UTF8Encoding]::new($false)); $w.Write($text); $w.Dispose() }
    $names = [System.Collections.Generic.List[string]]::new(); $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Sheets.Keys) {
        $n = ([string]$k -replace '[\[\]\*\?/\\:]', '_'); if ($n.Length -gt 31) { $n = $n.Substring(0, 31) }
        $b = $n; $i = 2; while (-not $seen.Add($n)) { $n = $b.Substring(0, [math]::Min($b.Length, 28)) + "~$i"; $i++ }
        $names.Add($n)
    }
    $idx = 0
    foreach ($k in $Sheets.Keys) {
        $idx++; $rows = @($Sheets[$k]); $sb = [Text.StringBuilder]::new()
        [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
        $cols = @(if ($rows.Count) { $rows[0].PSObject.Properties.Name })
        if ($cols.Count) { [void]$sb.Append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>') }
        [void]$sb.Append('<sheetData>')
        if ($cols.Count) {
            [void]$sb.Append('<row r="1">')
            for ($c = 0; $c -lt $cols.Count; $c++) { [void]$sb.Append("<c r=`"$(& $col $c)1`" t=`"inlineStr`" s=`"1`"><is><t>$(& $esc $cols[$c])</t></is></c>") }
            [void]$sb.Append('</row>')
            $r = 1
            foreach ($row in $rows) {
                $r++; [void]$sb.Append("<row r=`"$r`">")
                for ($c = 0; $c -lt $cols.Count; $c++) {
                    $v = $row.($cols[$c]); if ($null -eq $v -or "$v" -eq '') { continue }
                    $ref = "$(& $col $c)$r"
                    if ($v -is [bool]) { [void]$sb.Append("<c r=`"$ref`" t=`"b`"><v>$([int]$v)</v></c>") }
                    elseif ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { [void]$sb.Append("<c r=`"$ref`"><v>$(([double]$v).ToString('R', $inv))</v></c>") }
                    else {
                        $t = if ($v -is [datetime]) { $v.ToString('yyyy-MM-dd HH:mm:ss', $inv) } else { [string](ConvertTo-EpsCellText $v) }
                        if ($t.Length -gt 32767) { $t = $t.Substring(0, 32767) }
                        [void]$sb.Append("<c r=`"$ref`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$(& $esc $t)</t></is></c>")
                    }
                }
                [void]$sb.Append('</row>')
            }
        }
        [void]$sb.Append('</sheetData>')
        if ($cols.Count) { [void]$sb.Append("<autoFilter ref=`"A1:$(& $col ($cols.Count - 1))$([math]::Max(1, $rows.Count + 1))`"/>") }
        [void]$sb.Append('</worksheet>')
        & $put "xl/worksheets/sheet$idx.xml" $sb.ToString()
    }
    $ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    $wb = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
    $rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    $dn = '<definedNames>'
    for ($i = 1; $i -le $names.Count; $i++) {
        $ct += "<Override PartName=`"/xl/worksheets/sheet$i.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>"
        $wb += "<sheet name=`"$(& $esc $names[$i - 1])`" sheetId=`"$i`" r:id=`"rId$i`"/>"
        $rels += "<Relationship Id=`"rId$i`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$i.xml`"/>"
    }
    $rels += "<Relationship Id=`"rId$($names.Count + 1)`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles`" Target=`"styles.xml`"/></Relationships>"
    & $put '[Content_Types].xml' ($ct + '</Types>')
    & $put '_rels/.rels' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    & $put 'xl/workbook.xml' ($wb + '</sheets></workbook>')
    & $put 'xl/_rels/workbook.xml.rels' $rels
    & $put 'xl/styles.xml' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'
    $zip.Dispose()
    , $ms.ToArray()   # one byte[] (a bare return would enumerate it into object[])
}

function ConvertTo-EpsIdentityCsv {
    # v1's Users.csv: ';'-separated, UTF-8, every value quoted
    param([object[]]$Rows)
    if (-not @($Rows).Count) { return '' }
    (@($Rows | ForEach-Object {
        $o = [ordered]@{}; foreach ($p in $_.PSObject.Properties) { $o[$p.Name] = if ($p.Value -is [datetime]) { $p.Value.ToString('yyyy-MM-dd HH:mm:ss') } else { $p.Value } }
        [pscustomobject]$o
    } | ConvertTo-Csv -Delimiter ';' -NoTypeInformation -UseQuotes Always)) -join "`r`n"
}

function New-EpsIdentityWorkbook {
    # the workbook (owner 2026-10-31: "excel is optional output"): v1's sheets in v1's order, then the new gap views;
    # tag columns named with their attribute; v1's licence-missing sheet with its five columns. Returns the bytes.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Views, [Parameter(Mandatory)]$Config)
    $cat = @(Get-EpsIdentityViewCatalog)
    $v1 = 'Users_ALL', 'ActiveNoMFACorpSmartDevice', 'Devices', 'ActiveLastSignXDaysOrNoSignIn', 'ActiveLastSign90DaysOrNoSignIn', 'Active_NoMFA', 'ActiveOnlyADSignIn', 'SharedMailboxSignInEnabled', 'GuestsNoSignInLast90Days', 'CompliantMFAAuth', 'IncompliantMFAAuth', 'CompliantPasskeysAuth', 'IncompliantPasskeysAuth', 'OverProvisionedUsers', 'IncompliantUsers_LicenseMissing', 'Users_AD_Validated', 'Users_AD_NoValidation', 'SharedUsers_AD_Validated', 'SharedUsers_AD_NoValidation', 'ServiceAccount_AD_Validated', 'ServiceAccount_AD_NoValidation'   # v1's sheet order
    $sheets = [ordered]@{}
    foreach ($d in @($v1 | ForEach-Object { $n = $_; $cat | Where-Object Name -eq $n }) + @($cat | Where-Object { -not $_.V1 })) {
        $rows = @($Views[$d.Name])
        if ($d.Name -eq 'IncompliantUsers_LicenseMissing') { $rows = @($rows | Select-Object DisplayName, UserPrincipalName, HasMinimumNeededLicense, MinimumPlanNeeded, UserLicenseList) }
        $sheets[$d.Name] = @(if ($d.Kind -eq 'User') { Rename-EpsIdentityTagColumns -Rows $rows -Config $Config } else { $rows })
    }
    , (ConvertTo-EpsXlsx -Sheets $sheets)
}

function Read-EpsAdUserSnapshotForReport {
    # asks the hybrid worker for a fresh AD snapshot (it reads AD on its next cycle) and returns the one it has, if it is
    # younger than -FreshHours: SID -> the fields the correlation reads. $null = none (the run says so).
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$FreshHours = 36, [datetime]$NowUtc = [datetime]::UtcNow)
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $NowUtc } -Query 'MERGE eps.AdUserSnapshotInfo AS d USING (SELECT 1 AS Id) AS s ON d.Id = s.Id WHEN MATCHED THEN UPDATE SET RequestedAtUtc = @t WHEN NOT MATCHED THEN INSERT (Id, RequestedAtUtc) VALUES (1, @t);' | Out-Null
    $info = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT RefreshedAtUtc FROM eps.AdUserSnapshotInfo WHERE Id = 1')[0]
    if (-not $info -or $info.RefreshedAtUtc -is [DBNull] -or -not $info.RefreshedAtUtc -or ([datetime]$info.RefreshedAtUtc) -lt $NowUtc.AddHours(-$FreshHours)) { return $null }
    $n = { param($v) if ($v -is [DBNull]) { $null } else { $v } }
    $map = @{}
    foreach ($r in Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Sid, Enabled, LockedOut, PasswordNeverExpires, CannotChangePassword, LastLogonUtc, AccountExpiresUtc, Description FROM eps.AdUserSnapshot') {
        $map[[string]$r.Sid] = @{ Enabled = & $n $r.Enabled; LockedOut = & $n $r.LockedOut; PasswordNeverExpires = & $n $r.PasswordNeverExpires; CannotChangePassword = & $n $r.CannotChangePassword
            LastLogon = & $n $r.LastLogonUtc; AccountExpires = & $n $r.AccountExpiresUtc; Description = & $n $r.Description }
    }
    $map
}

function Write-EpsIdentitySnapshot {
    # one run's snapshot: the rows (JSON), the gap view membership, the counts and pivots; then the oldest beyond -Keep go
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [Parameter(Mandatory)][hashtable]$Report,
          [Parameter(Mandatory)][System.Collections.IDictionary]$Views, [object[]]$Pivots = @(), $Config, [int]$Keep = 7)
    $counts = [ordered]@{}; foreach ($k in $Views.Keys) { $counts[$k] = @($Views[$k]).Count }
    $cfgJson = if ($Config) { $Config | Select-Object * -ExcludeProperty LicenseRules, Tags | ConvertTo-Json -Compress -Depth 4 }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $RunId; u = @($Report.Users).Count; d = @($Report.Devices).Count
        v = ($counts | ConvertTo-Json -Compress); p = (ConvertTo-Json -InputObject @($Pivots) -Depth 6 -Compress); n = (ConvertTo-Json -InputObject @($Report.Notes) -Compress); c = $cfgJson } `
        -Query 'INSERT INTO eps.IdentitySnapshot (RunId, Users, Devices, ViewCountsJson, PivotsJson, NotesJson, ConfigJson) VALUES (@r, @u, @d, @v, @p, @n, @c)' | Out-Null
    $rows = [System.Data.DataTable]::new(); foreach ($c in 'RunId', 'Kind', 'ObjectId', 'Name', 'Data') { $col = $rows.Columns.Add($c); if ($c -eq 'RunId') { $col.DataType = [guid] } }
    foreach ($pair in @(@('User', $Report.Users, 'DisplayName'), @('Device', $Report.Devices, 'DeviceName'))) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in @($pair[1])) {
            if (-not $x.Id -or -not $seen.Add([string]$x.Id)) { continue }
            $r = $rows.NewRow(); $r.RunId = $RunId; $r.Kind = $pair[0]; $r.ObjectId = [string]$x.Id; $r.Name = [string]$x.($pair[2]); $r.Data = ($x | ConvertTo-Json -Compress -Depth 4); $rows.Rows.Add($r)
        }
    }
    $mem = [System.Data.DataTable]::new(); foreach ($c in 'RunId', 'ViewName', 'Kind', 'ObjectId') { $col = $mem.Columns.Add($c); if ($c -eq 'RunId') { $col.DataType = [guid] } }
    foreach ($d in Get-EpsIdentityViewCatalog) {
        if ($d.Group -eq 'Lists' -or -not $Views.Contains($d.Name)) { continue }   # a list is every row of its kind
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in @($Views[$d.Name])) { if ($x.Id -and $seen.Add([string]$x.Id)) { $r = $mem.NewRow(); $r.RunId = $RunId; $r.ViewName = $d.Name; $r.Kind = $d.Kind; $r.ObjectId = [string]$x.Id; $mem.Rows.Add($r) } }
    }
    try {
        Write-EpsBulk -ConnectionString $ConnectionString -Table 'eps.IdentityRow' -Data $rows
        Write-EpsBulk -ConnectionString $ConnectionString -Table 'eps.IdentityViewMember' -Data $mem
    } catch {
        # never a half snapshot: its rows and members go with it (cascade); the page keeps showing the previous one
        try { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $RunId } -Query 'DELETE FROM eps.IdentitySnapshot WHERE RunId = @r' | Out-Null } catch { }
        throw
    }
    # keep the newest -Keep snapshots (the rows and members go with them: ON DELETE CASCADE)
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ k = [math]::Max(1, $Keep) } -Query 'DELETE FROM eps.IdentitySnapshot WHERE RunId IN (SELECT RunId FROM eps.IdentitySnapshot ORDER BY CreatedAtUtc DESC OFFSET @k ROWS)' | Out-Null
    @{ Rows = $rows.Rows.Count; Members = $mem.Rows.Count; Counts = $counts }
}

function Write-EpsBulk {
    # a DataTable into a table (SqlBulkCopy; a test replaces this function with an in-memory one)
    # (the table names are literal, so the SQL-access test sees what this writes)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('eps.IdentityRow', 'eps.IdentityViewMember')][string]$Table, [Parameter(Mandatory)][System.Data.DataTable]$Data)
    if (-not $Data.Rows.Count) { return }
    $conn = New-EpsSqlConnection -ConnectionString $ConnectionString
    try {
        Open-EpsSqlConnection $conn
        # CheckConstraints: the tables have CHECK / FOREIGN KEY constraints - without the option SQL wants ALTER TABLE on them
        # (found live 2026-10-31: the engine role has INSERT only, as it should)
        $bcType = ($conn.GetType().FullName -replace 'SqlConnection$', 'SqlBulkCopy') -as [type]
        $bc = $bcType::new($conn, [Enum]::ToObject((($bcType.FullName + 'Options') -as [type]), 2), $null); $bc.BatchSize = 2000; $bc.BulkCopyTimeout = 600   # 2 = CheckConstraints
        if ($Table -eq 'eps.IdentityRow') { $bc.DestinationTableName = 'eps.IdentityRow' } else { $bc.DestinationTableName = 'eps.IdentityViewMember' }
        foreach ($c in $Data.Columns) { [void]$bc.ColumnMappings.Add($c.ColumnName, $c.ColumnName) }
        $bc.WriteToServer($Data)
    } finally { $conn.Dispose() }
}

function Invoke-EpsIdentityReportJob {
    <#
    .SYNOPSIS
        The identity report run (job IdentityReport): READ ONLY towards the tenant and AD. Settings -> collect -> correlate
        -> views + pivots -> the snapshot the GUI reads -> optionally the workbook by mail (IdentityReport.MailWorkbook).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [string]$TenantId = $env:EPS_TENANT_ID,
          [string]$Version = '2.0.0', [scriptblock]$Log = { param($l, $m) }, [datetime]$NowUtc = [datetime]::UtcNow, [hashtable]$Sources)
    $settings = @{}; foreach ($s in Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Name, Value FROM eps.Setting WHERE Name LIKE 'IdentityReport.%'") { $settings[[string]$s.Name] = [string]$s.Value }
    $cfg = Get-EpsIdentityReportConfig -Settings $settings -TagTypes @((Read-EpsTagTypes -ConnectionString $ConnectionString).Values | ForEach-Object { [pscustomobject]$_ })
    $ad = Read-EpsAdUserSnapshotForReport -ConnectionString $ConnectionString -NowUtc $NowUtc
    & $Log 'Info' $(if ($null -eq $ad) { 'no fresh AD snapshot yet (the hybrid worker reads AD on its next cycle) - the AD columns stay empty this run' } else { "AD snapshot: $($ad.Count) user(s)" })
    $src = if ($Sources) { $Sources.AdUsers = $ad; $Sources } else { Read-EpsIdentitySources -TenantId $TenantId -AdUsers $ad -Log $Log }   # -Sources: a test's data
    $rep = ConvertTo-EpsIdentityRows -Sources $src -Config $cfg -NowUtc $NowUtc
    foreach ($n in $rep.Notes) { & $Log 'Warn' $n }
    $views = Get-EpsIdentityViews -Report $rep -Config $cfg -NowUtc $NowUtc
    $pivots = foreach ($p in Get-EpsIdentityPivotCatalog) {
        $f = $p.Filter; $pv = Get-EpsIdentityPivot -Rows @($views[$p.View] | Where-Object { & $f $_ }) -RowKey $p.Rows -ColumnKey $p.Columns
        [pscustomobject]@{ Name = $p.Name; Title = $p.Title; View = $p.View; Kind = $p.Kind; Rows = $p.Rows; Columns = $p.Columns; Pivot = $pv }
    }
    $keep = [int]$(if ($settings['IdentityReport.KeepRuns']) { $settings['IdentityReport.KeepRuns'] } else { '7' })
    $w = Write-EpsIdentitySnapshot -ConnectionString $ConnectionString -RunId $RunId -Report $rep -Views $views -Pivots @($pivots) -Config $cfg -Keep $keep
    $gaps = @(Get-EpsIdentityViewCatalog | Where-Object { $_.Severity -in 'High', 'Medium' -and $w.Counts[$_.Name] -gt 0 })
    & $Log 'Info' "snapshot: $(@($rep.Users).Count) user(s), $(@($rep.Devices).Count) device(s), $($gaps.Count) open High / Medium gap view(s)"
    # V1-PARITY P11: the users to Log Analytics (EntraUsersMetadata_CL) + v1's exposure lists - when switched on; never
    # fails the run (the engine loads EPS-LogAnalytics.ps1; nothing else runs this)
    $la = if (Get-Command Invoke-EpsIdentityLogAnalytics -ErrorAction SilentlyContinue) { Invoke-EpsIdentityLogAnalytics -ConnectionString $ConnectionString -RunId $RunId -Users @($rep.Users) -Config $cfg -NowUtc $NowUtc -Log $Log }
    $mail = $null
    if ("$($settings['IdentityReport.MailWorkbook'])" -eq 'true') {
        $bytes = New-EpsIdentityWorkbook -Views $views -Config $cfg
        $mc = Get-EpsMailConfig -ConnectionString $ConnectionString
        # V1-PARITY P12: the report's own recipients (v1's Mail_Identity_Maintenance_TO); none = the alert recipients
        $own = @(try { @("$($settings['IdentityReport.MailRecipients'])" | ConvertFrom-Json) } catch { @() }) | Where-Object { "$_".Trim() }
        if (@($own).Count) { $mc.Recipients = @($own) }
        # MAIL-3 subject + the MAIL-2 body (BRAND-2 header, the button to the Identity page, the footer) - was hand-made HTML
        $rows = @($gaps | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; 'Open gap' = $_.Title; Count = $w.Counts[$_.Name] } })
        $html = New-EpsMailBody -Summary "The identity report of $($mc.Environment), $($NowUtc.ToString('yyyy-MM-dd HH:mm')) UTC: $(@($rep.Users).Count) users, $(@($rep.Devices).Count) devices, $($gaps.Count) open High / Medium gap view(s). The workbook is attached." `
            -Rows $rows -Columns 'Severity', 'Open gap', 'Count' -WhatToDo 'Every view, filter and pivot is on the Identity page of the web app.' `
            -ButtonText 'Open the identity report' -ButtonPage 'identity' -Footer @{ Environment = $mc.Environment; TenantName = $mc.TenantName; TenantId = $mc.TenantId; Version = $Version }
        $mail = Send-EpsMail -Config $mc -Subject (New-EpsMailSubject -Environment $mc.Environment -What 'Identity report') -Html $html -Attachments @(@{ Name = "Users-$($NowUtc.ToString('yyyyMMdd')).xlsx"; Bytes = $bytes; ContentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
        & $Log $(if ($mail.Sent) { 'Info' } else { 'Warn' }) "workbook mail: $($mail.Reason)"
    }
    [pscustomobject]@{ Users = @($rep.Users).Count; Devices = @($rep.Devices).Count; Gaps = $gaps.Count; Counts = $w.Counts; Mail = $mail; Notes = $rep.Notes; LogAnalytics = $la }
}

# ---- ID-ACTIONS: an action per user (owner 2026-11-03: "we need a way to add 4 fields per user: notes + action
# (dropdwn) like disable, delete, investigate, remove sync cloud + ActionWho (text field) + ActionStatus (not started, in
# progress, closed). it must be possible to do multiselect ..."). A record for follow-up - EPS never acts on it.
$script:EpsIdentityActionValues = @('Disable', 'Delete', 'Investigate', 'Remove from cloud sync')
$script:EpsIdentityActionStates = @('Not started', 'In progress', 'Closed')
$script:EpsIdentityActionColumns = [ordered]@{ Action = 'text'; ActionStatus = 'text'; ActionWho = 'text'; Notes = 'text' }
function Get-EpsIdentityActionLists { @{ actions = @($script:EpsIdentityActionValues); states = @($script:EpsIdentityActionStates) } }

function Test-EpsIdentityActionSet {
    # the fields to set: each one present = set it ('' clears it), absent = left as it is. @{ Ok; Error; Set (field -> value | $null) }
    param($Set)
    if ($null -eq $Set) { return @{ Ok = $false; Error = 'set: which fields to change (notes, action, actionWho, actionStatus)' } }
    $names = @(if ($Set -is [System.Collections.IDictionary]) { $Set.Keys } else { $Set.PSObject.Properties.Name })
    $get = { param($n) if ($Set -is [System.Collections.IDictionary]) { $Set[$n] } else { $Set.$n } }
    $out = [ordered]@{}
    foreach ($n in $names) {
        $v = & $get $n; $s = if ($null -eq $v) { '' } else { "$v".Trim() }
        switch ($n) {
            'action'       { if ($s -and $s -notin $script:EpsIdentityActionValues) { return @{ Ok = $false; Error = "action: one of $($script:EpsIdentityActionValues -join ', ') (or empty to clear)" } }; $out.Action = $(if ($s) { $s }) }
            'actionStatus' { if ($s -and $s -notin $script:EpsIdentityActionStates) { return @{ Ok = $false; Error = "actionStatus: one of $($script:EpsIdentityActionStates -join ', ') (or empty to clear)" } }; $out.ActionStatus = $(if ($s) { $s }) }
            'actionWho'    { if ($s.Length -gt 200) { return @{ Ok = $false; Error = 'actionWho: at most 200 characters' } }; $out.ActionWho = $(if ($s) { $s }) }
            'notes'        { if ($s.Length -gt 2000) { return @{ Ok = $false; Error = 'notes: at most 2000 characters' } }; $out.Notes = $(if ($s) { $s }) }
            default        { return @{ Ok = $false; Error = "set.$($n): not a field (notes, action, actionWho, actionStatus)" } }
        }
    }
    if (-not $out.Count) { return @{ Ok = $false; Error = 'set: nothing to change' } }
    @{ Ok = $true; Set = $out }
}

function Save-EpsIdentityActions {
    <#
      Sets the given fields on many users at once (the others stay as they are); a user whose four fields end up empty
      loses his row. Only users in the latest snapshot. One journal entry for the whole change. Returns @{ Count; Unknown }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string[]]$ObjectIds, [Parameter(Mandatory)]$Set, [Parameter(Mandatory)][string]$Actor)
    $run = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP 1 RunId FROM eps.IdentitySnapshot ORDER BY CreatedAtUtc DESC')[0]
    if (-not $run) { return @{ Count = 0; Unknown = @($ObjectIds) } }
    $ids = @($ObjectIds | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    $idj = ConvertTo-Json -InputObject @($ids) -Compress
    $known = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = [guid]$run.RunId; j = $idj } -Query "SELECT r.ObjectId, r.Name FROM eps.IdentityRow r JOIN OPENJSON(@j) AS x ON LOWER(r.ObjectId) = x.[value] WHERE r.RunId = @r AND r.Kind = 'User'")
    $unknown = @($ids | Where-Object { @($known | ForEach-Object { "$($_.ObjectId)".ToLowerInvariant() }) -notcontains $_ })
    if (-not $known.Count) { return @{ Count = 0; Unknown = $unknown } }
    $rows = ConvertTo-Json -InputObject @($known | ForEach-Object { @{ i = "$($_.ObjectId)"; n = $(if ($_.Name -isnot [DBNull]) { "$($_.Name)" }) } }) -Compress
    $has = { param($f) $Set.Contains($f) }
    $p = @{ j = $rows; by = $Actor
            hn = [bool](& $has 'Notes'); vn = $(if ($Set.Notes) { $Set.Notes } else { [DBNull]::Value })
            ha = [bool](& $has 'Action'); va = $(if ($Set.Action) { $Set.Action } else { [DBNull]::Value })
            hw = [bool](& $has 'ActionWho'); vw = $(if ($Set.ActionWho) { $Set.ActionWho } else { [DBNull]::Value })
            hs = [bool](& $has 'ActionStatus'); vs = $(if ($Set.ActionStatus) { $Set.ActionStatus } else { [DBNull]::Value }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'IdentityAction' -Key "$($known.Count) user(s)" -Action 'Update' -Before $null -After (@{ users = @($known | ForEach-Object { "$($_.ObjectId)" }); set = $Set } | ConvertTo-Json -Compress -Depth 4))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
MERGE eps.IdentityAction AS t
USING (SELECT x.i AS ObjectId, x.n AS Name FROM OPENJSON(@j) WITH (i NVARCHAR(64) '`$.i', n NVARCHAR(400) '`$.n') AS x) AS s
ON t.Kind = 'User' AND t.ObjectId = s.ObjectId
WHEN MATCHED THEN UPDATE SET Name = s.Name,
    Notes = CASE WHEN @hn = 1 THEN @vn ELSE t.Notes END, Action = CASE WHEN @ha = 1 THEN @va ELSE t.Action END,
    ActionWho = CASE WHEN @hw = 1 THEN @vw ELSE t.ActionWho END, ActionStatus = CASE WHEN @hs = 1 THEN @vs ELSE t.ActionStatus END,
    UpdatedBy = @by, UpdatedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Kind, ObjectId, Name, Notes, Action, ActionWho, ActionStatus, UpdatedBy)
    VALUES ('User', s.ObjectId, s.Name, CASE WHEN @hn = 1 THEN @vn END, CASE WHEN @ha = 1 THEN @va END, CASE WHEN @hw = 1 THEN @vw END, CASE WHEN @hs = 1 THEN @vs END, @by);
DELETE FROM eps.IdentityAction WHERE Kind = 'User' AND Notes IS NULL AND Action IS NULL AND ActionWho IS NULL AND ActionStatus IS NULL;
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Count = $known.Count; Unknown = $unknown }
}

# ---- V1-PARITY P11: the identity report in Log Analytics + v1's two exposure reports (owner 2026-11-05: "solution must
# be min 1:1 on pair with the old eps script solution"). v1: IdentityReporter.ps1 L858-913 uploads EVERY user row to the
# custom table EntraUsersMetadata_CL through a data collection endpoint + rule ($global:EPSIntegration); the exposure
# reports (CAPolicyEvaluator\ExposureSigninReports-ServiceAccounts.ps1 / -SharedDeviceUsers.ps1, Kusto-Queries.ps1) read
# that table with SigninLogs + AADNonInteractiveUserSignInLogs. The PURE parts live here (every component loads this
# file: the web app reads the stored results); the calls (upload, query, setup) are in EPS-LogAnalytics.ps1 (engine and
# the setup script only).
$script:EpsLaTable = 'EntraUsersMetadata_CL'          # v1's table (v1: $TableName 'EntraUsersMetadata' + _CL)
$script:EpsLaStream = 'Custom-EntraUsersMetadata_CL'  # the DCR's input stream
$script:EpsLaDcrName = 'dcr-entra-EntraUsersMetadata_CL'   # v1's name: "dcr-" + $AzDcrPrefix ("entra") + "-" + table
$script:EpsLaMaxBatchBytes = 900000                   # the Logs Ingestion API takes at most 1 MB per call
$script:EpsLaMaxBatchRecords = 2000

function Get-EpsLaColumns {
    <#
      PURE. v1's columns of EntraUsersMetadata_CL, in v1's order (IdentityReporter.ps1's $Object, then its extra tag
      columns, then Add-CollectionTimeToAllEntriesInArray + Add-ColumnDataToAllEntriesInArray Computer / ComputerFqdn),
      each with its type. -Tags: the report config's tag columns (Company only when its tag type exists, as v1 removed
      it when EntraPolicySuite_Tagging_Company was not set; any other tag type is v1's extra column). Returns an ordered
      name -> type (string | boolean | int | datetime).
    #>
    param([object[]]$Tags = @())
    $c = [ordered]@{}
    foreach ($n in 'Id', 'GivenName', 'SurName', 'UserPrincipalName', 'DisplayName', 'Description_AD') { $c[$n] = 'string' }
    $c.AccountEnabled = 'boolean'
    $tagCols = @($Tags | ForEach-Object { "$($_.Column)" })
    foreach ($n in 'UserClassification', 'UserAuthMethodType', 'UserPilotInfo', 'UserAccountInfo') { $c[$n] = 'string' }   # v1 always had these four
    if ($tagCols -contains 'Company') { $c.Company = 'string' }
    foreach ($n in 'CompanyName', 'Mail') { $c[$n] = 'string' }
    $c.IsAdmin = 'boolean'
    foreach ($n in 'MailType', 'DefaultMfaMethod', 'MethodsRegistered') { $c[$n] = 'string' }
    foreach ($n in 'IsMfaCapable', 'IsMfaRegistered', 'IsPasswordlessCapable', 'IsSsprCapable', 'IsSsprEnabled', 'IsSsprRegistered', 'IsSystemPreferredAuthenticationMethodEnabled') { $c[$n] = 'boolean' }
    $c.AuthMethodsLastUpdatedDateTime = 'datetime'
    $c.extensionAttribute2 = 'string'
    foreach ($n in 'Cloud_LastSignInDateTime', 'Cloud_LastNonInteractiveSignInDateTime', 'AD_LastSignInDateTime') { $c[$n] = 'datetime' }
    $c.AD_CannotChangePassword = 'boolean'; $c.AD_AccountExpirationDate = 'datetime'; $c.AD_OnPremisesSyncEnabled = 'boolean'
    $c.Cloud_PasswordPolicies = 'string'; $c.AD_PasswordNeverExpires = 'boolean'
    foreach ($n in 'UserIsADValidated', 'ServiceAccountIsADValidated', 'SharedUserIsADValidated', 'SharedMailboxIsADValidated', 'IsLicenseOverProvisioned', 'HasMinimumNeededLicense') { $c[$n] = 'boolean' }
    foreach ($n in 'MinimumPlanNeeded', 'ADDN', 'UserLicenseList') { $c[$n] = 'string' }
    foreach ($p in $script:EpsIdPlatforms) { foreach ($o in 'Corp', 'Personal') { $c["DeviceCount_${p}_$o"] = 'int' } }
    $c.Device_SmartPhoneActive = 'boolean'; $c.Device_SmartPhoneActive_CorpOnly = 'boolean'
    foreach ($n in $tagCols) { if (-not $c.Contains($n)) { $c[$n] = 'string' } }   # v1's extra EntraPolicySuite_Tagging_* columns
    $c.CollectionTime = 'datetime'; $c.Computer = 'string'; $c.ComputerFqdn = 'string'
    $c
}

function ConvertTo-EpsLaValue($v, [string]$Type) {
    # PURE. One cell in the type the table has for it (a table v1 made earlier may hold a column as string: then text)
    if ($null -eq $v -or $v -is [DBNull] -or ("$v" -eq '' -and $Type -ne 'string')) { return $null }
    switch ($Type) {
        'boolean' { if ($v -is [bool]) { return $v }; $s = "$v".Trim(); if ($s -in 'True', 'true', '1') { return $true }; if ($s -in 'False', 'false', '0') { return $false }; return $null }
        'int' { $n = 0; if ([long]::TryParse("$v", [ref]$n)) { return $n }; return $null }
        'datetime' {
            $d = if ($v -is [datetime]) { $v } else { ConvertFrom-EpsGraphDate $v }
            if (-not $d) { return $null }
            return ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }
        default {
            if ($v -is [datetime]) { return ([datetime]$v).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($v -is [bool]) { return $(if ($v) { 'True' } else { 'False' }) }
            return "$v"
        }
    }
}

function ConvertTo-EpsLaRecords {
    <#
      PURE. The report's user rows -> v1's EntraUsersMetadata_CL records: only v1's columns, each in the table's type
      (-Columns: name -> type, Get-EpsLaColumns or the existing table's), plus CollectionTime / Computer / ComputerFqdn.
      extensionAttribute2 is v1's raw attribute: the report keeps it as HireDate when the hire-date attribute is
      extensionAttribute2 (v1's default), else it is empty (the row does not carry it).
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][System.Collections.IDictionary]$Columns, [Parameter(Mandatory)][datetime]$CollectionTime,
          [string]$Computer = [Environment]::MachineName, [string]$ComputerFqdn = [Environment]::MachineName, [string]$HireDateAttribute = 'extensionAttribute2')
    $ct = $CollectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    @(foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $o = [ordered]@{}
        foreach ($k in $Columns.Keys) {
            $v = switch ($k) {
                'CollectionTime' { $ct }
                'Computer' { $Computer }
                'ComputerFqdn' { $ComputerFqdn }
                'extensionAttribute2' { if ($HireDateAttribute -eq 'extensionAttribute2') { $r.HireDate } else { $null } }
                default { $r.$k }
            }
            $o[$k] = if ($k -eq 'CollectionTime') { $ct } else { ConvertTo-EpsLaValue $v $Columns[$k] }
        }
        $o
    })
}

function Split-EpsLaBatches {
    # PURE. The records in calls the Logs Ingestion API takes: each call's JSON below -MaxBytes and at most -MaxRecords.
    # A single record over the limit is returned in .TooLarge (never sent - the API would refuse the whole call).
    # Each batch: @{ Json; Count }.
    param([object[]]$Records = @(), [int]$MaxBytes = $script:EpsLaMaxBatchBytes, [int]$MaxRecords = $script:EpsLaMaxBatchRecords)
    $batches = [System.Collections.Generic.List[object]]::new(); $big = [System.Collections.Generic.List[object]]::new()
    $cur = [System.Collections.Generic.List[string]]::new(); $size = 2
    foreach ($r in @($Records)) {
        $j = $r | ConvertTo-Json -Compress -Depth 4
        $n = [Text.Encoding]::UTF8.GetByteCount($j) + 1
        if ($n + 2 -gt $MaxBytes) { $big.Add($r); continue }
        if ($cur.Count -and ($size + $n -gt $MaxBytes -or $cur.Count -ge $MaxRecords)) { $batches.Add(@{ Json = '[' + ($cur -join ',') + ']'; Count = $cur.Count }); $cur = [System.Collections.Generic.List[string]]::new(); $size = 2 }
        $cur.Add($j); $size += $n
    }
    if ($cur.Count) { $batches.Add(@{ Json = '[' + ($cur -join ',') + ']'; Count = $cur.Count }) }
    @{ Batches = $batches.ToArray(); TooLarge = $big.ToArray() }
}

function Get-EpsExposureQueryCatalog {
    <#
      PURE. v1's exposure queries (Kusto-Queries.ps1; ExposureSigninReports-ServiceAccounts.ps1 / -SharedDeviceUsers.ps1),
      one per sheet, v1's sheet names. The classification values are v1's ("Service_Account", "Shared_Device_Users").
      Changed from v1, each on purpose:
        - v1 compared the LOWER-cased sign-in UPN with the account list as stored (mixed case) - an account with a capital
          letter in its UPN was never found; both sides are lower-cased here (the NoSignins queries already did that);
        - the "Show" queries return the sign-in columns a person reads (v1 returned every column of the log tables);
        - every query returns at most 5,000 rows (the page and the workbook say when a list was cut).
    #>
    $mk = { param($cls) @"
let Accounts = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime, *) by UserPrincipalName
| where tostring(UserClassification) =~ "$cls"
| project UPN = tolower(UserPrincipalName);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Accounts)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
"@ }
    $none = { param($cls) @"
let Accounts = EntraUsersMetadata_CL
| summarize arg_max(CollectionTime, *) by UserPrincipalName
| where tostring(UserClassification) =~ "$cls"
| project UPN = tolower(UserPrincipalName);
let Signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| project UPN = tolower(UserPrincipalName);
Accounts
| join kind=leftanti (Signins) on UPN
| order by UPN
| take 5000
"@ }
    $show = '| project TimeGenerated, UserDisplayName, UserPrincipalName, AppDisplayName, ResourceDisplayName, IP, Location, ClientAppUsed, ConditionalAccessStatus, TrustedLocation, TrustedName, Category' + "`n| order by TimeGenerated desc`n| take 5000"
    $list = "| distinct UserDisplayName, UserPrincipalName`n| take 5000"
    foreach ($s in @(@{ Set = 'service'; Prefix = 'Svc'; Class = 'Service_Account'; Who = 'Service accounts' }, @{ Set = 'shared'; Prefix = 'Shared'; Class = 'Shared_Device_Users'; Who = 'Shared device users' })) {
        $base = & $mk $s.Class
        [pscustomobject]@{ Name = "$($s.Prefix)_Trusted"; Set = $s.Set; Who = $s.Who; Title = "$($s.Who) signing in from a trusted location (90 days)"; Kql = "$base| where IsTrusted == 1`n| where Result == `"Success`"`n$list" }
        [pscustomobject]@{ Name = "$($s.Prefix)_NonTrusted"; Set = $s.Set; Who = $s.Who; Title = "$($s.Who) signing in from a NON-trusted location (90 days)"; Kql = "$base| where IsTrusted == 0`n| where Result == `"Success`"`n$list" }
        [pscustomobject]@{ Name = "$($s.Prefix)_NonTrusted_Show"; Set = $s.Set; Who = $s.Who; Title = "$($s.Who): their sign-ins from a NON-trusted location (90 days)"; Kql = "$base| where IsTrusted == 0`n| where Result == `"Success`"`n$show" }
        [pscustomobject]@{ Name = "$($s.Prefix)_NoSignins"; Set = $s.Set; Who = $s.Who; Title = "$($s.Who) with NO sign-in in 90 days"; Kql = (& $none $s.Class) }
    }
}

function Read-EpsIdentityExposure {
    # the latest stored Log Analytics result (upload + the exposure lists) of a report run (or the newest that has one)
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$RunId = '')
    $q = if ($RunId -match '^[0-9a-fA-F-]{36}$') { 'SELECT TOP 1 l.RunId, l.CheckedAtUtc, l.UploadRows, l.UploadSent, l.UploadOk, l.UploadText, l.TablesJson, l.ExposureJson, l.Note FROM eps.IdentityLaRun l WHERE l.RunId = @r' }
         else { 'SELECT TOP 1 l.RunId, l.CheckedAtUtc, l.UploadRows, l.UploadSent, l.UploadOk, l.UploadText, l.TablesJson, l.ExposureJson, l.Note FROM eps.IdentityLaRun l JOIN eps.IdentitySnapshot s ON s.RunId = l.RunId ORDER BY l.CheckedAtUtc DESC, s.CreatedAtUtc DESC' }   # two runs with the same "now": the later snapshot
    $p = if ($RunId -match '^[0-9a-fA-F-]{36}$') { @{ r = [guid]$RunId } } else { @{} }
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query $q)[0]
}
