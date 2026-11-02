# EntraPolicySuite -- reads a v1 install (DATA folder + the two configs) into the v2 model (DESIGN §3 "Import").
# Read-only on the v1 side: it never writes to the v1 folder. The plan is built here; tools/setup/Import-EpsV1Data.ps1
# shows it and, with -Apply, writes it to SQL (EPS-SqlStore.ps1). Dot-source EPS-Conditions.ps1 first.
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
    # v1 kept the attribute per tag type in the user tagging script's globals ($global:EntraPolicySuite_Tagging_User_*).
    param([string]$ScriptPath)
    $map = @{}
    if (-not $ScriptPath -or -not (Test-Path -LiteralPath $ScriptPath)) { return $map }
    $src = Get-Content -LiteralPath $ScriptPath -Raw
    foreach ($pair in @(@('AccountInfo', 'User_AccountInfo'), @('Classification', 'User_Classification'), @('Authentication', 'User_Authentication'), @('Pilot', 'User_Pilot'), @('Company', 'Company'))) {
        $m = [regex]::Match($src, "(?im)^\s*\`$global:EntraPolicySuite_Tagging_$($pair[1])\s*=\s*[`"'](extensionAttribute\d{1,2})[`"']")
        if ($m.Success) { $map[$pair[0]] = $m.Groups[1].Value }
    }
    $map
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
. (Join-Path $PSScriptRoot 'EPS-Rules.ps1')

function Read-EpsV1Data {
    <#
    .SYNOPSIS
        Reads a v1 install into the v2 model. Never writes to it.
    .PARAMETER Path
        The v1 DATA folder, or its parent (C:\SCRIPTS, with DATA\ under it).
    .PARAMETER UserTaggingScript
        v1's Entra-ID-User-Tagging.ps1, for the attribute per tag type. Default: <root>\Entra-Policy-Suite\.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$UserTaggingScript, [hashtable]$Catalog)
    $data = if (Test-Path -LiteralPath (Join-Path $Path 'DATA') -PathType Container) { Join-Path $Path 'DATA' } else { $Path }
    if (-not (Test-Path -LiteralPath $data -PathType Container)) { throw "v1 folder not found: $Path" }
    $root = Split-Path -Parent $data
    if (-not $UserTaggingScript) { $UserTaggingScript = Join-Path $root 'Entra-Policy-Suite\Entra-ID-User-Tagging.ps1' }
    if (-not $Catalog) { $Catalog = Import-EpsConditionCatalog }

    $files = [ordered]@{}
    foreach ($f in 'Identity_Tagging.csv', 'Identity_Tagging_AccountInfo.csv', 'Device_Tagging.csv', 'Device_Tagging_AccountInfo.csv', 'EntraNamedLocations_AzureNetworkServiceTags.csv', 'Entra_Policy_Suite_custom.config', 'Entra_Policy_Suite_locked.config') {
        $files[$f] = Test-Path -LiteralPath (Join-Path $data $f)
    }
    $attrMap = Get-EpsV1AttributeMap -ScriptPath $UserTaggingScript
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
