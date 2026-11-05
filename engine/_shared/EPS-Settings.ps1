# EntraPolicySuite -- the settings catalog (framework §12.9 SETTING-INFO-1, DESIGN §5.8): every setting the product reads,
# its type and limits, who may change it, and the "More info" text. ONE source: the web app renders the Settings page
# from it, every save is validated against it here, and tests/Test-EpsSettings.ps1 fails when the code reads a setting
# the catalog does not have or an entry misses an info field.
#
# A save is one transaction: the value (eps.Setting) and its journal row (eps.ConfigChange, CONFIG-1 - the history and
# undo) together, with the value the person saw checked first, so two people saving at once cannot overwrite each other
# unseen. Undo = saving the earlier value again (a new journal row, never a rewrite of history).

Set-StrictMode -Off

$script:EpsSettingsCatalog = $null
$script:EpsSettingInfoFields = 'what', 'enabled', 'disabled', 'risk', 'requires', 'recommended', 'docUrl'
$script:EpsSettingTypes = 'boolean', 'enum', 'int', 'number', 'text', 'timezone', 'list'
$script:EpsSettingConfirmWhen = 'on', 'off', 'value', 'widen', 'narrow', 'raise', 'change'

function Get-EpsSettingsCatalog {
    param([string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'settings\catalog.json'), [switch]$Reload)
    if ($Reload -or -not $script:EpsSettingsCatalog -or $script:EpsSettingsCatalog.Path -ne $Path) {
        $c = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $byKey = @{}; foreach ($s in @($c.settings)) { $byKey[$s.key] = $s }
        $script:EpsSettingsCatalog = @{ Path = $Path; Catalog = $c; ByKey = $byKey }
    }
    $script:EpsSettingsCatalog
}

function Get-EpsSettingEntry { param([string]$Key) (Get-EpsSettingsCatalog).ByKey[$Key] }

function Test-EpsSettingsCatalog {
    # every problem in the catalog, as text; none = the catalog is complete
    param($Catalog = (Get-EpsSettingsCatalog).Catalog)
    $groups = @($Catalog.groups | ForEach-Object id)
    $seen = @{}
    foreach ($s in @($Catalog.settings)) {
        $k = "$($s.key)"
        if ($k -notmatch '^[A-Z][A-Za-z]+(\.[A-Z][A-Za-z]+)+$') { "'$k': not a setting key (Feature.Name)"; continue }
        if ($seen[$k]) { "'$k': listed twice" }; $seen[$k] = 1
        if (-not $s.label) { "${k}: no label" }
        if ($groups -notcontains $s.group) { "${k}: group '$($s.group)' is not in the groups list" }
        if ($k.Split('.')[0] -ne $s.group) { "${k}: the group is not the key's feature ($($s.group))" }
        if ($script:EpsSettingTypes -notcontains $s.type) { "${k}: type '$($s.type)' is unknown" }
        if ($s.role -notin 'Admin', 'SuperAdmin') { "${k}: role must be Admin or SuperAdmin" }
        foreach ($f in $script:EpsSettingInfoFields) { if (-not "$($s.info.$f)".Trim()) { "${k}: info.$f is missing" } }
        if ($s.info.docUrl -and $s.info.docUrl -ne "$($Catalog.docBase)$k/") { "${k}: info.docUrl must be $($Catalog.docBase)$k/" }
        if ($null -eq $s.default) { "${k}: no default" }
        elseif ($s.editable -ne $false) { $d = ConvertTo-EpsSettingValue -Entry $s -Value $s.default; if (-not $d.Ok) { "${k}: the default is not valid ($($d.Error))" } }
        if ($s.type -eq 'enum' -and @($s.values).Count -lt 2) { "${k}: an enum needs at least two values" }
        if ($s.editable -eq $false -and -not $s.setBy) { "${k}: not editable, but no setBy says where it is set" }
        foreach ($c in @($s.confirm)) {
            if (-not $c) { continue }
            if ($script:EpsSettingConfirmWhen -notcontains $c.when) { "${k}: confirm.when '$($c.when)' is unknown" }
            if (-not $c.title -or -not $c.body) { "${k}: a confirmation needs a title and a body" }
            if ($c.when -eq 'value' -and @($s.values) -notcontains $c.value) { "${k}: confirm value '$($c.value)' is not one of the values" }
            if ($c.when -in 'on', 'off' -and $s.type -ne 'boolean') { "${k}: confirm '$($c.when)' is for a boolean" }
            if ($c.when -in 'widen', 'narrow' -and $s.type -ne 'list') { "${k}: confirm '$($c.when)' is for a list" }
            if ($c.when -eq 'raise' -and $s.type -notin 'int', 'number') { "${k}: confirm 'raise' is for a number" }
        }
        foreach ($d in @($s.dependsOn)) { if ($d -and -not ($Catalog.settings | Where-Object key -eq $d)) { "${k}: dependsOn '$d' is not in the catalog" } }
        if ($s.dependsOnByValue) {
            foreach ($p in $s.dependsOnByValue.PSObject.Properties) {
                if (@($s.values) -notcontains $p.Name) { "${k}: dependsOnByValue '$($p.Name)' is not one of the values" }
                foreach ($d in @($p.Value)) { if ($d -and -not ($Catalog.settings | Where-Object key -eq $d)) { "${k}: dependsOnByValue '$d' is not in the catalog" } }
            }
        }
    }
}

function ConvertTo-EpsSettingValue {
    # validate + normalise one value for its entry: @{ Ok; Value (the stored text); Error }
    param([Parameter(Mandatory)]$Entry, $Value)
    $bad = { param($t) @{ Ok = $false; Value = $null; Error = $t } }
    $good = { param($v) @{ Ok = $true; Value = $v; Error = $null } }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($Entry.type -ne 'list' -and ($Value -is [array] -or $Value -is [Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject])) { return & $bad 'a single value is expected' }
    # ConvertFrom-Json made an ISO-looking text a DateTime: give the text back (round-trip form)
    if ($Value -is [datetime]) { $Value = $Value.ToString('o', $inv) }
    $s = if ($null -eq $Value) { '' } else { "$Value" }
    if ($Entry.type -ne 'list' -and $s -match '[\u0000-\u001f\u007f]') { return & $bad 'control characters are not allowed' }
    switch ($Entry.type) {
        'boolean' { if ($Value -is [bool]) { return & $good $(if ($Value) { 'true' } else { 'false' }) }
                    if ($s -in 'true', 'false') { return & $good $s.ToLowerInvariant() }; return & $bad 'true or false' }
        'enum'    { $m = @($Entry.values | Where-Object { $_ -eq $s }); if ($m.Count) { return & $good "$($m[0])" }; return & $bad "one of: $(@($Entry.values) -join ', ')" }
        'int'     { $n = [long]0; if (-not [long]::TryParse($s.Trim(), [Globalization.NumberStyles]::Integer, $inv, [ref]$n)) { return & $bad 'a whole number' }
                    if (($null -ne $Entry.min -and $n -lt $Entry.min) -or ($null -ne $Entry.max -and $n -gt $Entry.max)) { return & $bad "from $($Entry.min) to $($Entry.max)" }
                    return & $good $n.ToString($inv) }
        'number'  { $n = [double]0; if (-not [double]::TryParse($s.Trim(), [Globalization.NumberStyles]::Float, $inv, [ref]$n) -or [double]::IsNaN($n) -or [double]::IsInfinity($n)) { return & $bad 'a number (with . as the decimal point)' }
                    if (($null -ne $Entry.min -and $n -lt $Entry.min) -or ($null -ne $Entry.max -and $n -gt $Entry.max)) { return & $bad "from $($Entry.min) to $($Entry.max)" }
                    return & $good $n.ToString('R', $inv) }
        'text'    { $t = $s.Trim(); if ($Entry.maxLength -and $t.Length -gt $Entry.maxLength) { return & $bad "at most $($Entry.maxLength) characters" }
                    if ($Entry.pattern -and $t -and $t -notmatch $Entry.pattern) { return & $bad 'not in the expected format' }
                    return & $good $t }
        'timezone' { $t = $s.Trim(); if (-not $t -or $t.Length -gt 64) { return & $bad 'a time zone id' }
                     try { [void][TimeZoneInfo]::FindSystemTimeZoneById($t); return & $good $t } catch { return & $bad "'$t' is not a time zone this server knows (e.g. Europe/Copenhagen or UTC)" } }
        'list'    {
            $items = if ($null -eq $Value) { @() } elseif ($Value -is [string]) {
                if (-not $Value.Trim()) { @() } else { try { @($Value | ConvertFrom-Json -NoEnumerate) } catch { return & $bad 'a list (JSON array of text)' } }
            } else { @($Value) }
            if ($items.Count -eq 1 -and $items[0] -is [array]) { $items = @($items[0]) }
            $out = [System.Collections.Generic.List[string]]::new(); $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($i in $items) {
                if ($null -ne $i -and $i -isnot [string] -and $i -isnot [ValueType]) { return & $bad 'each item is a piece of text' }
                $t = "$i".Trim(); if (-not $t) { continue }
                if ($t -match '[\u0000-\u001f\u007f]') { return & $bad 'control characters are not allowed' }
                if ($Entry.itemMaxLength -and $t.Length -gt $Entry.itemMaxLength) { return & $bad "'$t' is longer than $($Entry.itemMaxLength) characters" }
                if ($Entry.itemPattern -and $t -notmatch $Entry.itemPattern) { return & $bad "'$t' is not $(if ($Entry.itemHint) { $Entry.itemHint } else { 'in the expected format' })" }
                if ($seen.Add($t)) { $out.Add($t) }
            }
            if ($Entry.maxItems -and $out.Count -gt $Entry.maxItems) { return & $bad "at most $($Entry.maxItems) items" }
            return & $good (ConvertTo-Json -InputObject @($out) -Compress) }
    }
    & $bad "unknown type '$($Entry.type)'"
}

function Get-EpsSettingsView {
    # the Settings page: every catalog entry with its current value, plus any stored setting the catalog does not know
    # (shown read-only, so nothing is hidden)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $cat = Get-EpsSettingsCatalog
    $stored = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Value, UpdatedAtUtc, UpdatedBy FROM eps.Setting')) { $stored[$r.Name] = $r }
    $at = { param($d) if ($d -is [datetime]) { [datetime]::SpecifyKind($d, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") } }
    $rows = foreach ($s in @($cat.Catalog.settings)) {
        $r = $stored[$s.key]
        [ordered]@{ key = $s.key; group = $s.group; label = $s.label; type = $s.type; values = $s.values; min = $s.min; max = $s.max; maxLength = $s.maxLength
            maxItems = $s.maxItems; itemHint = $s.itemHint; default = $s.default; role = $s.role; editable = ($s.editable -ne $false); setBy = $s.setBy; pick = $s.pick
            active = ($s.active -ne $false); confirm = @($s.confirm | Where-Object { $_ }); info = $s.info
            value = $(if ($r) { $r.Value } else { $null }); isSet = [bool]$r; updatedAtUtc = $(if ($r) { & $at $r.UpdatedAtUtc }); updatedBy = $(if ($r) { $r.UpdatedBy }) }
    }
    $unknown = foreach ($k in @($stored.Keys | Sort-Object)) { if (-not $cat.ByKey[$k]) { $r = $stored[$k]; [ordered]@{ key = $k; value = $r.Value; updatedAtUtc = (& $at $r.UpdatedAtUtc); updatedBy = $r.UpdatedBy } } }
    @{ groups = @($cat.Catalog.groups); rows = @($rows); unknown = @($unknown) }
}

function Save-EpsSetting {
    # one transaction: check the value the person saw (-Expected; $null = not set), write it, journal it.
    # Returns @{ Saved; Conflict; Before; BeforeSet; After }.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
          [Parameter(Mandatory)][string]$Actor, [switch]$CheckExpected, $Expected, [string]$Source = 'gui')
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ n = $Entry.key; f = $Entry.group; v = $Value; a = $Actor; chk = [bool]$CheckExpected; exp = $(if ($null -ne $Expected) { "$Expected" }); src = $Source } -Query @'
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @had BIT = 0, @before NVARCHAR(MAX) = NULL, @conflict BIT = 0;
SELECT @had = 1, @before = Value FROM eps.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = @n;
IF @chk = 1 AND NOT ((@had = 0 AND @exp IS NULL) OR (@had = 1 AND @exp IS NOT NULL AND ISNULL(@before, N'') = @exp)) SET @conflict = 1;
IF @conflict = 0 AND (@had = 0 OR ISNULL(@before, N'') <> @v COLLATE Latin1_General_BIN2)
BEGIN
    MERGE eps.Setting AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = @a WHEN NOT MATCHED THEN INSERT (Name, Feature, Value, UpdatedBy) VALUES (@n, @f, @v, @a);
    INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source)
    VALUES (@a, 'Setting', @n, CASE WHEN @had = 1 THEN 'Update' ELSE 'Create' END,
            CASE WHEN @had = 1 THEN (SELECT @before AS value FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
            (SELECT @v AS value FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), @src);
    COMMIT;
    SELECT CAST(1 AS BIT) AS Saved, @conflict AS Conflict, @had AS BeforeSet, @before AS Before;
END
ELSE
BEGIN
    ROLLBACK;
    SELECT CAST(0 AS BIT) AS Saved, @conflict AS Conflict, @had AS BeforeSet, @before AS Before;
END
'@)[0]
    @{ Saved = [bool]$r.Saved; Conflict = [bool]$r.Conflict; Before = $r.Before; BeforeSet = [bool]$r.BeforeSet; After = $Value }
}

function Get-EpsSettingHistory {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Key, [int]$Top = 50)
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ k = $Key; t = $Top } -Query "SELECT TOP (@t) ChangeId, AtUtc, Actor, Action, BeforeJson, AfterJson, Source FROM eps.ConfigChange WHERE Entity = 'Setting' AND EntityKey = @k ORDER BY ChangeId DESC")
}
