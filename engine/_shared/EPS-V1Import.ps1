# EntraPolicySuite -- reads a v1 install (DATA folder + the two configs) into the v2 model (DESIGN §3 "Import").
# Read-only on the v1 side: it never writes to the v1 folder. The plan is built here; tools/setup/Import-EpsV1Data.ps1
# shows it (since 2.0.69 it never writes SQL). The write is the product's (SEC-08 row 8: no person needs database rights):
# the web app's Import v1 page uploads the files, POST /api/v1import/check shows the plan (Read-EpsV1Upload +
# Get-EpsV1ImportPlan), a SuperAdmin approves, and the ENGINE writes it from the signed Config request (Write-EpsV1Import
# in EPS-SqlStore.ps1). Dot-source EPS-Conditions.ps1 first.
#
# Demo material is never migrated (owner 2026-10-29): Identity_Tagging_Demo_Reset.csv and the demo scripts are not read.

Set-StrictMode -Off

function Get-EpsDefaultTagTypes {
    # The shipped defaults = today's v1 types (DESIGN §5.6a), with v1's attributes and fallbacks. -Attributes overrides
    # the attribute per type name (a v1 customer who moved a tag to another extensionAttribute).
    param([hashtable]$Attributes = @{})
    $d = @(
        @{ Name = 'AccountInfo';    ObjectType = 'User';   Attribute = 'extensionAttribute5'; AllowMultiple = $true;  Description = 'free text about the account (e.g. its documentation reference)' }
        @{ Name = 'Classification'; ObjectType = 'User';   Attribute = 'extensionAttribute6'; AllowMultiple = $false; Description = 'who the identity is: internal user, admin, guest, service account ...'; FallbackAD = 'NonManaged_User_AD_Synced'; FallbackCloud = 'NonManaged_User_Cloud' }
        @{ Name = 'Authentication'; ObjectType = 'User';   Attribute = 'extensionAttribute7'; AllowMultiple = $false; Description = 'how the identity must authenticate'; FallbackAD = 'NonManaged_User_AD_Synced_MFA'; FallbackCloud = 'NonManaged_User_Cloud_MFA' }
        @{ Name = 'Pilot';          ObjectType = 'User';   Attribute = 'extensionAttribute8'; AllowMultiple = $false; Description = 'the pilot ring of the identity for Conditional Access' }
        @{ Name = 'Company';        ObjectType = 'User';   Attribute = 'extensionAttribute9'; AllowMultiple = $true;  Description = 'the company (or cost centre codes) the identity belongs to'; FallbackFromProperty = 'companyName' }
        @{ Name = 'DeviceCategory'; ObjectType = 'Device'; Attribute = 'extensionAttribute6'; AllowMultiple = $false; Description = 'what kind of device it is'; FallbackAD = 'Unknown_DeviceCategory'; FallbackCloud = 'Unknown_DeviceCategory' }
    )
    $out = @{}
    foreach ($t in $d) {
        $t.ValueMode = 'First'; $t.Enabled = $true; $t.Shipped = $true
        if ($Attributes[$t.Name]) { $t.Attribute = $Attributes[$t.Name] }
        $out["$($t.ObjectType):$($t.Name)"] = $t
    }
    $out
}

function Get-EpsV1AttributeMap {
    # v1 kept the attribute per tag type in globals ($global:EntraPolicySuite_Tagging_User_*): in the user tagging script
    # and in Automation-DefaultVariables.psm1 (V1-PARITY P15). -ScriptPath can name both; a later file wins (the script
    # runs after the module is imported, so its globals are the ones in force).
    param([string[]]$ScriptPath)
    $map = @{}
    foreach ($sp in @($ScriptPath | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $sp)) { continue }
        $src = Get-Content -LiteralPath $sp -Raw
        foreach ($pair in @(@('AccountInfo', 'User_AccountInfo'), @('Classification', 'User_Classification'), @('Authentication', 'User_Authentication'), @('Pilot', 'User_Pilot'), @('Company', 'Company'))) {
            $m = [regex]::Match($src, "(?im)^\s*\`$global:EntraPolicySuite_Tagging_$($pair[1])\s*=\s*[`"'](extensionAttribute\d{1,2})[`"']")
            if ($m.Success) { $map[$pair[0]] = $m.Groups[1].Value }
        }
    }
    $map
}

function Read-EpsV1Globals {
    # V1-PARITY P15: the values of NAMED globals in a v1 PowerShell file ($global:Name = value), read as text - the file is
    # never run, and no other line of it is kept (Automation-DefaultVariables.psm1 also holds other products' values).
    # A value is $true / $false, a quoted string, a number or @("a", "b"); anything else is left out.
    # Returns name -> [string] | [bool] | [string[]].
    param([string]$Path, [Parameter(Mandatory)][string[]]$Names)
    $out = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $out }
    $src = Get-Content -LiteralPath $Path -Raw
    foreach ($n in $Names) {
        $ms = [regex]::Matches($src, "(?im)^[ \t]*\`$global:$([regex]::Escape($n))[ \t]*=[ \t]*(?<v>@\([^)\r\n]*\)|`"[^`"\r\n]*`"|'[^'\r\n]*'|\`$true|\`$false|\d+)")
        if (-not $ms.Count) { continue }
        $v = $ms[$ms.Count - 1].Groups['v'].Value   # the last assignment is the one in force
        $out[$n] = if ($v -ieq '$true') { $true } elseif ($v -ieq '$false') { $false }
                   elseif ($v.StartsWith('@(')) { ,@([regex]::Matches($v, "`"([^`"]*)`"|'([^']*)'") | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } } | Where-Object { $_ }) }
                   elseif ($v -match '^["''](.*)["'']$') { $Matches[1] } else { $v }
    }
    $out
}

function ConvertFrom-EpsV1DefaultVariables {
    # V1-PARITY P15: Automation-DefaultVariables.psm1 -> the EPS settings it fills, and what is not moved (and why).
    # Returns @{ Settings = ordered; NotMigrated = string[] }.
    param([string]$Path)
    $g = Read-EpsV1Globals -Path $Path -Names 'Mail_Identity_Maintenance_TO', 'Mail_Identity_Maintenance_SendMail', 'SMTPserver', 'SMTPPort', 'SMTP_UseSSL', 'SMTPUser', 'Mail_SendAnonymous',
        'IdentityReporter_AD_Searchbase', 'IdentityReporter_UserADSynced_AD_OU_Match', 'IdentityReporter_ServiceAccountADSynced_AD_OU_Match', 'IdentityReporter_SharedUserADSynced_AD_OU_Match', 'IdentityReporter_SharedMailboxADSynced_AD_OU_Match'
    $s = [ordered]@{}; $nm = [System.Collections.Generic.List[string]]::new()
    if ($g.ContainsKey('Mail_Identity_Maintenance_TO')) { $to = @(@($g['Mail_Identity_Maintenance_TO']) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' }); if ($to.Count) { $s['IdentityReport.MailRecipients'] = ConvertTo-Json -InputObject @($to) -Compress } }
    if ($g['Mail_Identity_Maintenance_SendMail'] -is [bool]) { $s['IdentityReport.MailWorkbook'] = $(if ($g['Mail_Identity_Maintenance_SendMail']) { 'true' } else { 'false' }) }
    if ("$($g['SMTPserver'])" -match '^[A-Za-z0-9][A-Za-z0-9.-]{0,251}$') { $s['Mail.SmtpServer'] = "$($g['SMTPserver'])" }
    if ("$($g['SMTPPort'])" -match '^\d{1,5}$' -and [int]"$($g['SMTPPort'])" -in 1..65535) { $s['Mail.SmtpPort'] = "$([int]"$($g['SMTPPort'])")" }
    if ($g['SMTP_UseSSL'] -is [bool]) { $s['Mail.SmtpUseTls'] = $(if ($g['SMTP_UseSSL']) { 'true' } else { 'false' }) }
    if ("$($g['SMTPUser'])" -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $s['Mail.SmtpFrom'] = "$($g['SMTPUser'])" }
    foreach ($p in @(@('IdentityReporter_UserADSynced_AD_OU_Match', 'User'), @('IdentityReporter_ServiceAccountADSynced_AD_OU_Match', 'ServiceAccount'), @('IdentityReporter_SharedUserADSynced_AD_OU_Match', 'SharedUser'), @('IdentityReporter_SharedMailboxADSynced_AD_OU_Match', 'SharedMailbox'))) {
        if ("$($g[$p[0]])".Trim()) { $s["IdentityReport.AdOu.$($p[1])"] = "$($g[$p[0]])".Trim() }
    }
    if ($s.Contains('Mail.SmtpServer')) { $nm.Add("v1's mail relay $($s['Mail.SmtpServer']) is imported as the SMTP settings; Alert mail is not switched to smtp - choose it in Settings > Alert mail") }
    if ($g['Mail_SendAnonymous'] -eq $false) { $nm.Add("v1 signed in to its mail relay with its stored credential (`$global:SecureCredentials): a password is never imported - put it in a Key Vault secret and set 'SMTP password (Key Vault secret)'") }
    if ("$($g['IdentityReporter_AD_Searchbase'])".Trim()) { $nm.Add("IdentityReporter_AD_Searchbase ($($g['IdentityReporter_AD_Searchbase'])): the hybrid worker reads its own domain - no setting needed") }
    @{ Settings = $s; NotMigrated = @($nm) }
}

function Read-EpsV1Csv {
    param([string]$Path, [string]$KeyColumn)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    # v1 reads with Import-Csv -Delimiter ';' -Encoding UTF8 and drops rows whose key column is empty
    # each row carries where it came from (file + line, header = line 1), so a hint can point at the customer's own row
    $file = Split-Path -Leaf $Path; $line = 1
    @(foreach ($r in Import-Csv -LiteralPath $Path -Delimiter ';' -Encoding UTF8) {
        $line++
        if ([string]::IsNullOrEmpty($r.$KeyColumn)) { continue }
        $r | Add-Member -NotePropertyName V1Ref -NotePropertyValue "${file}:$line" -PassThru
    })
}

# ConvertTo-EpsRuleCards (v1 rows -> cards) and Resolve-EpsV1ValueModes live in EPS-Rules.ps1 since 2.0.8 (RULES-GRID):
# the GUI's v1 upload uses them too - one grouping, one set of value-mode hints.
# the rule hints (Get-EpsRuleHints) live with the rule editing - the import and the GUI show the same ones
# loaded once: the web app and the engine have it already (a second dot-source would reset its script state)
if (-not (Get-Command ConvertTo-EpsRuleCards -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'EPS-Rules.ps1') }

function Read-EpsV1Data {
    <#
    .SYNOPSIS
        Reads a v1 install into the v2 model. Never writes to it.
    .PARAMETER Path
        The v1 DATA folder, or its parent (C:\SCRIPTS, with DATA\ under it).
    .PARAMETER UserTaggingScript
        v1's Entra-ID-User-Tagging.ps1, for the attribute per tag type. Default: <root>\Entra-Policy-Suite\.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$UserTaggingScript, [string]$DefaultVariablesPath, [hashtable]$Catalog)
    $data = if (Test-Path -LiteralPath (Join-Path $Path 'DATA') -PathType Container) { Join-Path $Path 'DATA' } else { $Path }
    if (-not (Test-Path -LiteralPath $data -PathType Container)) { throw "v1 folder not found: $Path" }
    $root = Split-Path -Parent $data
    if (-not $UserTaggingScript) { $UserTaggingScript = Join-Path $root 'Entra-Policy-Suite\Entra-ID-User-Tagging.ps1' }
    # V1-PARITY P15: v1's shared variables module (C:\SCRIPTS\FUNCTIONS) - the report mail, the mail relay, the identity
    # report's OUs and the tag attributes; only those named values are read
    if (-not $DefaultVariablesPath) { $DefaultVariablesPath = Join-Path $root 'FUNCTIONS\Automation-DefaultVariables.psm1' }
    if (-not $Catalog) { $Catalog = Import-EpsConditionCatalog }

    $files = [ordered]@{}
    foreach ($f in 'Identity_Tagging.csv', 'Identity_Tagging_AccountInfo.csv', 'Device_Tagging.csv', 'Device_Tagging_AccountInfo.csv', 'EntraNamedLocations_AzureNetworkServiceTags.csv', 'Entra_Policy_Suite_custom.config', 'Entra_Policy_Suite_locked.config') {
        $files[$f] = Test-Path -LiteralPath (Join-Path $data $f)
    }
    $files['Automation-DefaultVariables.psm1'] = Test-Path -LiteralPath $DefaultVariablesPath
    $attrMap = Get-EpsV1AttributeMap -ScriptPath @($DefaultVariablesPath, $UserTaggingScript)
    $tagTypes = Get-EpsDefaultTagTypes -Attributes $attrMap
    $hints = [System.Collections.Generic.List[object]]::new()

    # v1 order: the main CSV, then the AccountInfo CSV appended after it
    $userRows = @(Read-EpsV1Csv (Join-Path $data 'Identity_Tagging.csv') 'Persona') + @(Read-EpsV1Csv (Join-Path $data 'Identity_Tagging_AccountInfo.csv') 'Persona')
    $deviceRows = @(Read-EpsV1Csv (Join-Path $data 'Device_Tagging.csv') 'TagType') + @(Read-EpsV1Csv (Join-Path $data 'Device_Tagging_AccountInfo.csv') 'TagType')

    $vm = Resolve-EpsV1ValueModes -Rows $userRows -TagTypes $tagTypes -ObjectType 'User'
    foreach ($h in $vm.Hints) { $hints.Add($h) }
    foreach ($k in $vm.Modes.Keys) { $t = $tagTypes["User:$k"]; if ($t) { $t.ValueMode = $vm.Modes[$k] } }

    $userCards = @(ConvertTo-EpsRuleCards -Rows $userRows -ObjectType 'User')
    $deviceCards = @(ConvertTo-EpsRuleCards -Rows $deviceRows -ObjectType 'Device')
    foreach ($h in (Get-EpsRuleHints -Cards ($userCards + $deviceCards) -Catalog $Catalog -TagTypes $tagTypes)) { $hints.Add($h) }

    # the closed value list per tag type = every value the rules use + the fallback; generated Exchange values as a pattern
    $values = @{}
    foreach ($c in $userCards + $deviceCards) {
        $k = "$($c.ObjectType):$($c.TagType)"; if (-not $tagTypes[$k]) { continue }
        if (-not $values[$k]) { $values[$k] = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
        foreach ($v in @($c.TagValueAD, $c.TagValueCloud)) { if ($v) { [void]$values[$k].Add($v) } }
        if ($c.Conditions | Where-Object { $_.ConditionType -like '*ModifiedTagValue*' }) { [void]$values[$k].Add('Exchange_*') }
    }
    foreach ($k in $tagTypes.Keys) {
        $t = $tagTypes[$k]
        if (-not $values[$k]) { $values[$k] = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
        foreach ($v in @($t.FallbackAD, $t.FallbackCloud)) { if ($v) { [void]$values[$k].Add($v) } }
    }
    $tagValues = foreach ($k in $values.Keys) { foreach ($v in $values[$k]) {
        @{ ObjectType = $k.Split(':')[0]; TagType = $k.Split(':')[1]; Value = $v; IsPattern = ($v -match '[*?]') } } }

    $settings = [ordered]@{}; $breakGlass = @(); $adminUnits = @(); $targetGroups = @(); $notMigrated = @()
    $customPath = Join-Path $data 'Entra_Policy_Suite_custom.config'
    if ($files['Entra_Policy_Suite_custom.config']) {
        $cfg = Get-Content -LiteralPath $customPath -Raw | ConvertFrom-Json
        $map = [ordered]@{ Group_Targeting_Method = 'CA.GroupTargetingMethod'; Authentication_Strength_Default_FIDO_Name = 'CA.AuthStrengthFidoName'
                           Authentication_Strength_Default_WHfB_Name = 'CA.AuthStrengthWhfbName'; Named_Locations_Denied_Countries_Name = 'CA.DeniedCountriesLocationName' }
        foreach ($p in $cfg.PSObject.Properties) {
            if ($map.Contains($p.Name)) { $settings[$map[$p.Name]] = [string]$p.Value }
            elseif ($p.Name -like 'Path_*') { $notMigrated += "$($p.Name) (a v1 file path - v2 keeps the templates in SQL)" }
        }
        $breakGlass = @(foreach ($b in @($cfg.BreakGlassAccounts)) { if ($b.UserPrincipalName) {
            @{ UserPrincipalName = [string]$b.UserPrincipalName; DisplayName = [string]$b.DisplayName; AuthenticationMethod = [string]$b.AuthenticationMethod
               ClassificationTagValue = [string]$b.ClassificationTagValue; AuthenticationTagValue = [string]$b.AuthenticationTagValue } } })
        foreach ($pair in @(@('AdministrativeUnits_CA_TargetGroups', 'Target'), @('AdministrativeUnits_CA_PilotGroups', 'Pilot'), @('AdministrativeUnits_CA_ExcludeGroups', 'Exclude'))) {
            $adminUnits += @(foreach ($a in @($cfg.($pair[0]))) { if ($a.DisplayName) { @{ DisplayName = [string]$a.DisplayName; Purpose = $pair[1]; Description = [string]$a.Description } } })
        }
    }
    if ($files['Entra_Policy_Suite_locked.config']) {
        $lk = Get-Content -LiteralPath (Join-Path $data 'Entra_Policy_Suite_locked.config') -Raw | ConvertFrom-Json
        $targetGroups = @(
            foreach ($g in @($lk.Target_Groups_Dynamic_Assignment)) { if ($g.DisplayName) { @{ DisplayName = [string]$g.DisplayName; VariableName = [string]$g.VariableName; Assignment = 'Dynamic'; Description = [string]$g.Description; GroupQuery = [string]$g.GroupQuery } } }
            foreach ($g in @($lk.Target_Groups_Manual_Assignment)) { if ($g.DisplayName) { @{ DisplayName = [string]$g.DisplayName; VariableName = [string]$g.VariableName; Assignment = 'Assigned'; Description = [string]$g.Description; GroupQuery = $null } } }
        )
    }
    if ($files['Automation-DefaultVariables.psm1']) {
        $dv = ConvertFrom-EpsV1DefaultVariables -Path $DefaultVariablesPath
        foreach ($k in $dv.Settings.Keys) { $settings[$k] = $dv.Settings[$k] }
        $notMigrated += @($dv.NotMigrated)
    }
    $serviceTags = @(Read-EpsV1Csv (Join-Path $data 'EntraNamedLocations_AzureNetworkServiceTags.csv') 'Tag' | ForEach-Object { @{ Tag = ([string]$_.Tag).Trim() } })
    if ($serviceTags.Count) { $settings['NamedLocations.Region'] = 'westeurope' }   # v1 hard-coded it (D4: today's value is the default)

    [pscustomobject]@{
        Source = $data; Files = $files; AttributeMap = $attrMap
        TagTypes = @($tagTypes.Values); TagValues = @($tagValues)
        UserRules = $userCards; DeviceRules = $deviceCards
        UserRowCount = $userRows.Count; DeviceRowCount = $deviceRows.Count
        Settings = $settings; BreakGlassAccounts = $breakGlass; AdminUnits = $adminUnits; TargetGroups = $targetGroups; ServiceTags = $serviceTags
        NotMigrated = $notMigrated; Hints = @($hints)
    }
}

# ---- the Import v1 page (SEC-08 row 8, 2.0.69): the files come as an upload, not a folder -----------------------------
# the closed list of files the page takes: v1's DATA files + the user tagging script (for the attribute per tag type).
# Demo material is never read (owner 2026-10-29).
$script:EpsV1UploadNames = @('Identity_Tagging.csv', 'Identity_Tagging_AccountInfo.csv', 'Device_Tagging.csv', 'Device_Tagging_AccountInfo.csv',
    'EntraNamedLocations_AzureNetworkServiceTags.csv', 'Entra_Policy_Suite_custom.config', 'Entra_Policy_Suite_locked.config', 'Entra-ID-User-Tagging.ps1',
    # V1-PARITY P15: v1's shared variables (C:\SCRIPTS\FUNCTIONS) - only the named values are read, the rest is dropped
    'Automation-DefaultVariables.psm1')

function Get-EpsV1UploadNames { $script:EpsV1UploadNames }

function Read-EpsV1Upload {
    <#
    .SYNOPSIS
        The uploaded v1 files ([ { name; text } ]) -> the same model Read-EpsV1Data makes from a folder: they are written to
        a private temporary folder in v1's layout (DATA + Entra-Policy-Suite), read there, and the folder is removed. The
        user tagging script is only searched for its attribute lines - never run. Returns @{ Model; Files } or @{ Error }.
    #>
    param([object[]]$Files)
    $files = @(@($Files) | Where-Object { $null -ne $_ })
    if (-not $files.Count) { return @{ Error = 'choose the v1 files to read (from v1''s DATA folder)' } }
    if ($files.Count -gt $script:EpsV1UploadNames.Count) { return @{ Error = "at most $($script:EpsV1UploadNames.Count) files" } }
    $seen = [ordered]@{}; $total = 0
    foreach ($f in $files) {
        $nm = [IO.Path]::GetFileName("$($f.name)")
        if ($nm -match '(?i)demo') { return @{ Error = "$nm is demo material - it is never read" } }
        $known = @($script:EpsV1UploadNames | Where-Object { $_ -ieq $nm })[0]
        if (-not $known) { return @{ Error = "'$nm' is not a v1 file this import reads ($($script:EpsV1UploadNames -join ', '))" } }
        if ($seen.Contains($known)) { return @{ Error = "$known is there twice" } }
        $seen[$known] = "$($f.text)"; $total += "$($f.text)".Length
    }
    if ($total -gt 900000) { return @{ Error = 'the files are larger than 900 KB together' } }
    if (-not @($seen.Keys | Where-Object { $_ -notin 'Entra-ID-User-Tagging.ps1', 'Automation-DefaultVariables.psm1' }).Count) { return @{ Error = 'choose at least one file from v1''s DATA folder' } }
    $root = Join-Path ([IO.Path]::GetTempPath()) "eps-v1-$([guid]::NewGuid().ToString('N'))"
    $out = $null
    try {
        $data = Join-Path $root 'DATA'; $scr = Join-Path $root 'Entra-Policy-Suite'; $fn = Join-Path $root 'FUNCTIONS'
        foreach ($d in $data, $scr, $fn) { [void](New-Item -ItemType Directory -Path $d -Force) }
        foreach ($k in $seen.Keys) { [IO.File]::WriteAllText((Join-Path $(if ($k -like '*.ps1') { $scr } elseif ($k -like '*.psm1') { $fn } else { $data }) $k), $seen[$k], [Text.UTF8Encoding]::new($false)) }
        try {
            $m = Read-EpsV1Data -Path $root -UserTaggingScript (Join-Path $scr 'Entra-ID-User-Tagging.ps1') -DefaultVariablesPath (Join-Path $fn 'Automation-DefaultVariables.psm1')
            $m.Source = 'upload: ' + (@($seen.Keys) -join ', ')
            $out = @{ Model = $m; Files = @($seen.Keys) }
        } catch { $out = @{ Error = "the files could not be read: $($_.Exception.Message.Replace($root, 'upload'))" } }
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    $out
}

function Get-EpsV1ImportPlan {
    <#
    .SYNOPSIS
        What writing a Read-EpsV1Data model would do to THIS database (reads only): per area what is added, what changes
        (old -> new) and what is already so. Rules: an import replaces the rules the previous v1 import made; rules made
        in the app are never touched.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Model)
    $q = { param($sql) @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $sql) }
    $areas = [System.Collections.Generic.List[object]]::new()
    $area = { param($name, $items, $extra = @{})
        $it = @($items)
        $a = [ordered]@{ area = $name; add = @($it | Where-Object { $_.state -eq 'add' }).Count; change = @($it | Where-Object { $_.state -eq 'change' }).Count
            same = @($it | Where-Object { $_.state -eq 'same' }).Count; items = @($it | Where-Object { $_.state -ne 'same' } | Select-Object -First 200) }
        foreach ($k in $extra.Keys) { $a[$k] = $extra[$k] }
        $areas.Add($a) }
    $cmp = { param($key, $cur, $new, [string[]]$fields)
        if (-not $cur) { return [ordered]@{ key = $key; state = 'add'; text = '' } }
        $d = @(foreach ($f in $fields) {
            $a = if ($cur.$f -is [bool]) { "$([bool]$cur.$f)" } else { "$($cur.$f)" }
            $b = if ($cur.$f -is [bool]) { "$([bool]$new.$f)" } else { "$($new.$f)" }
            if ($a -cne $b) { "$f`: '$a' -> '$b'" } })
        [ordered]@{ key = $key; state = $(if ($d.Count) { 'change' } else { 'same' }); text = ($d -join '; ') } }

    $tt = @{}; foreach ($r in (& $q 'SELECT * FROM eps.TagType')) { $tt["$($r.ObjectType):$($r.Name)"] = $r }
    & $area 'Tag types' @(foreach ($t in $Model.TagTypes) { & $cmp "$($t.ObjectType) $($t.Name)" $tt["$($t.ObjectType):$($t.Name)"] ([pscustomobject]$t) @('Attribute', 'ValueMode', 'AllowMultiple', 'FallbackAD', 'FallbackCloud', 'FallbackFromProperty', 'Description') })
    $tv = @{}; foreach ($r in (& $q 'SELECT ObjectType, TagType, Value FROM eps.TagValue')) { $tv["$($r.ObjectType):$($r.TagType):$($r.Value)".ToLowerInvariant()] = $true }
    & $area 'Tag values' @(foreach ($v in $Model.TagValues) { [ordered]@{ key = "$($v.ObjectType) $($v.TagType) = $($v.Value)"; state = $(if ($tv["$($v.ObjectType):$($v.TagType):$($v.Value)".ToLowerInvariant()]) { 'same' } else { 'add' }); text = '' } })
    $rc = @(& $q "SELECT 'User' AS ObjectType, Source, COUNT(*) AS N FROM eps.UserTagRule GROUP BY Source UNION ALL SELECT 'Device', Source, COUNT(*) FROM eps.DeviceTagRule GROUP BY Source")
    foreach ($ot in 'User', 'Device') {
        $old = 0; $mine = 0
        foreach ($r in @($rc | Where-Object { $_.ObjectType -eq $ot })) { if ($r.Source -eq 'v1-import') { $old += [int]$r.N } else { $mine += [int]$r.N } }
        & $area "$ot rules" @(foreach ($r in @($Model."$($ot)Rules")) {
            [ordered]@{ key = "$($r.TagType) = $(if ($r.TagValueCloud) { $r.TagValueCloud } else { $r.TagValueAD })$(if ($r.Persona) { " ($($r.Persona))" })"; state = 'add'; text = (@($r.V1Rows) -join ', ') } }) @{ replaces = $old; keeps = $mine }
    }
    $st = @{}; foreach ($r in (& $q 'SELECT Name, Value FROM eps.Setting')) { $st[[string]$r.Name] = $r }
    & $area 'Settings' @(foreach ($k in $Model.Settings.Keys) { & $cmp $k $st[$k] ([pscustomobject]@{ Value = [string]$Model.Settings[$k] }) @('Value') })
    $bg = @{}; foreach ($r in (& $q 'SELECT * FROM eps.BreakGlassAccount')) { $bg[([string]$r.UserPrincipalName).ToLowerInvariant()] = $r }
    & $area 'Break-glass accounts' @(foreach ($b in $Model.BreakGlassAccounts) { & $cmp $b.UserPrincipalName $bg[([string]$b.UserPrincipalName).ToLowerInvariant()] ([pscustomobject]$b) @('DisplayName', 'AuthenticationMethod', 'ClassificationTagValue', 'AuthenticationTagValue') })
    $au = @{}; foreach ($r in (& $q 'SELECT * FROM eps.AdminUnit')) { $au[([string]$r.DisplayName).ToLowerInvariant()] = $r }
    & $area 'Administrative units' @(foreach ($a in $Model.AdminUnits) { & $cmp $a.DisplayName $au[([string]$a.DisplayName).ToLowerInvariant()] ([pscustomobject]$a) @('Purpose', 'Description') })
    $tg = @{}; foreach ($r in (& $q 'SELECT * FROM eps.TargetGroup')) { $tg[([string]$r.DisplayName).ToLowerInvariant()] = $r }
    & $area 'Target groups' @(foreach ($g in $Model.TargetGroups) { & $cmp $g.DisplayName $tg[([string]$g.DisplayName).ToLowerInvariant()] ([pscustomobject]$g) @('VariableName', 'Assignment', 'Description', 'GroupQuery') })
    $sv = @{}; foreach ($r in (& $q 'SELECT Tag FROM eps.ServiceTagLocation')) { $sv[([string]$r.Tag).ToLowerInvariant()] = $true }
    & $area 'Service tags' @(foreach ($t in $Model.ServiceTags) { [ordered]@{ key = $t.Tag; state = $(if ($sv[([string]$t.Tag).ToLowerInvariant()]) { 'same' } else { 'add' }); text = '' } })
    $sum = @(foreach ($a in $areas) { "$($a.area): $($a.add) new, $($a.change) changed$(if ($a.Contains('replaces')) { ", replaces $($a.replaces) from an earlier v1 import, keeps $($a.keeps) made in the app" })" }) -join '; '
    [ordered]@{ source = "$($Model.Source)"; areas = @($areas); hints = @(foreach ($h in @($Model.Hints)) { "$($h.Message)" }); notMoved = @($Model.NotMigrated); summary = $sum }
}
