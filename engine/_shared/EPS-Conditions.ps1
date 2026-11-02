# EntraPolicySuite -- the condition catalog (DESIGN §5.6b). The rule engine knows no field by name: every condition type
# is either a PROPERTY condition (data in engine/conditions/catalog.json, or the customer's own in eps.ConditionType) or
# a MODULE (one file in engine/conditions/modules/ implementing the contract below). Adding either never touches the
# engine.
#
# Module contract - the file returns a hashtable:
#   Id, ObjectType (User | Device), Description
#   Select   = the Graph properties it reads (the engine fetches every field the enabled rules need in ONE pass)
#   Needs    = run context it reads (EntraGroupMembers, AdGroupMembers, Mailboxes, SkuPartNumbers)
#   Validate = { param($Target) -> an error text, or nothing }              (optional)
#   Evaluate = { param($Object, $Target, $Context) -> @{ Met; Actual; Modified; Unavailable } }
#   ModifiesValue = $true when Evaluate may return Modified (v1's ModifiedTagValue conditions)
# 'Unavailable' = the data source could not be read (no licence, no permission, no worker): the rule is skipped with
# that reason in the run report - never a silent "no match" (DESIGN §5.6b).

Set-StrictMode -Off

function Get-EpsValue {
    # One property (or a dotted path) of a Graph object - a PSCustomObject from ConvertFrom-Json or a dictionary -
    # case-insensitively, as v1's PowerShell property access was. $null when any step is missing.
    param($Object, [string]$Path)
    # fast path, the common case (one property of a Graph object): PowerShell's own member access is case-insensitive
    if ($Path.IndexOf('.') -lt 0 -and $Object -is [System.Management.Automation.PSCustomObject]) { return , $Object.$Path }
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Management.Automation.PSCustomObject]) { $cur = $cur.$part; continue }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($part)) { $cur = $cur[$part]; continue }
            $hit = $null; $found = $false
            foreach ($k in $cur.Keys) { if ([string]::Equals([string]$k, $part, [StringComparison]::OrdinalIgnoreCase)) { $hit = $cur[$k]; $found = $true; break } }
            if (-not $found) { return $null }
            $cur = $hit
        } else {
            $p = $cur.PSObject.Properties[$part]
            if ($null -eq $p) { return $null }
            $cur = $p.Value
        }
    }
    , $cur
}

function Import-EpsConditionCatalog {
    # Loads the shipped catalog + modules, plus the customer's own property conditions (rows shaped like the catalog's,
    # from eps.ConditionType). Returns a hashtable keyed '<ObjectType>:<Id>' (OnPremisesSyncEnabled exists for both).
    param(
        [string]$Root = (Join-Path (Split-Path -Parent $PSScriptRoot) 'conditions'),
        [object[]]$CustomConditions = @()
    )
    $cat = @{}
    $json = Get-Content -LiteralPath (Join-Path $Root 'catalog.json') -Raw | ConvertFrom-Json
    $all = @($json.conditions) + @($CustomConditions | Where-Object { $_ })
    foreach ($c in $all) {
        if ($c.operator -notin 'like', 'notlike', 'equals', 'boolMatch', 'boolEquals', 'contains', 'notcontains') { throw "condition '$($c.id)': unknown operator '$($c.operator)'" }
        if ($c.guard -and $c.guard -notin 'none', 'notNull', 'notEmpty', 'emptyMatches') { throw "condition '$($c.id)': unknown guard '$($c.guard)'" }
        $cat["$($c.objectType):$($c.id)"] = @{
            Id = [string]$c.id; ObjectType = [string]$c.objectType; Kind = 'Property'; Description = [string]$c.description
            Property = [string]$c.property; Operator = [string]$c.operator; Guard = $(if ($c.guard) { [string]$c.guard } else { 'none' })
            Select = @(([string]$c.property).Split('.')[0]); Needs = @(); Shipped = -not $c.custom
        }
    }
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $Root 'modules') -Filter '*.ps1' -File | Sort-Object Name) {
        $m = & $f.FullName
        foreach ($k in 'Id', 'ObjectType', 'Evaluate') { if (-not $m.$k) { throw "condition module $($f.Name): '$k' is missing" } }
        if ($m.Id -ne $f.BaseName) { throw "condition module $($f.Name): Id '$($m.Id)' must equal the file name" }
        $m.Kind = 'Module'; $m.Shipped = $true
        if (-not $m.Select) { $m.Select = @() }; if (-not $m.Needs) { $m.Needs = @() }
        $cat["$($m.ObjectType):$($m.Id)"] = $m
    }
    $cat
}

$script:EpsWildcards = @{}
function Get-EpsWildcard {
    # -like semantics exactly (case-insensitive, * ? [ ]), compiled once per target.
    param([string]$Pattern)
    $w = $script:EpsWildcards[$Pattern]
    if (-not $w) { $w = [System.Management.Automation.WildcardPattern]::new($Pattern, [System.Management.Automation.WildcardOptions]::IgnoreCase); $script:EpsWildcards[$Pattern] = $w }
    $w
}

function Invoke-EpsCondition {
    # Evaluates one condition of a rule for one object. Returns @{ Met; Actual; Modified; Unavailable }.
    # An unknown condition type never matches, as in v1, and says so.
    param([hashtable]$Catalog, [string]$ObjectType, [string]$ConditionType, [string]$Target, $Object, [hashtable]$Context)
    $def = $Catalog["${ObjectType}:$ConditionType"]
    if (-not $def) { return @{ Met = $false; Unavailable = "unknown condition type '$ConditionType'" } }
    Test-EpsCondition $def $Target $Object $Context $true
}

function Test-EpsCondition {
    # The engine's hot path: a definition already looked up (once per run, not per object), positional parameters, and
    # the explanation text built only when asked for (-Explain = a trace / the troubleshooting view).
    param($def, [string]$Target, $Object, $Context, [bool]$Explain)
    if ($def.Kind -eq 'Module') { return (& $def.Evaluate $Object $Target $Context) }
    $raw = Get-EpsValue $Object $def.Property
    $s = if ($null -eq $raw) { '' } else { [string]$raw }
    $actual = if ($Explain) { "$($def.Property) is " + $(if ($null -eq $raw) { '(empty)' } elseif ($raw -is [array]) { '[' + ($raw -join ', ') + ']' } else { "'$raw'" }) }
    switch ($def.Guard) {
        'notNull'      { if ($null -eq $raw) { return @{ Met = $false; Actual = $actual } } }
        'notEmpty'     { if ($s.Length -eq 0) { return @{ Met = $false; Actual = $actual } } }
        'emptyMatches' { if ($s.Length -eq 0) { return @{ Met = $true; Actual = $actual } } }
    }
    $met = switch ($def.Operator) {
        'like'        { (Get-EpsWildcard $Target).IsMatch($s) }
        'notlike'     { -not (Get-EpsWildcard $Target).IsMatch($s) }
        'equals'      { [string]::Equals($s, $Target, [StringComparison]::OrdinalIgnoreCase) }
        # v1 user conditions: $Target -match "TRUE" (a regex: case-insensitive, anywhere in the target)
        'boolMatch'   { ($Target -match 'TRUE' -and [bool]$raw) -or ($Target -match 'FALSE' -and -not [bool]$raw) }
        # v1 device conditions: $Target -eq "TRUE" (case-insensitive equality)
        'boolEquals'  { ($Target -eq 'TRUE' -and [bool]$raw) -or ($Target -eq 'FALSE' -and -not [bool]$raw) }
        'contains'    { @($raw) -contains $Target }
        'notcontains' { -not (@($raw) -contains $Target) }
    }
    @{ Met = [bool]$met; Actual = $actual }
}

function Get-EpsConditionSelect {
    # The Graph $select for one object type: the base fields the engine always needs + every field the rules' condition
    # types read - one pass per object type, no extra call per rule (DESIGN §5.6b "Fetch").
    param([hashtable]$Catalog, [string]$ObjectType, [object[]]$Rules, [string[]]$Base = @())
    $set = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $Base) { [void]$set.Add($b) }
    foreach ($r in $Rules) { foreach ($c in $r.Conditions) {
        $def = $Catalog["${ObjectType}:$($c.ConditionType)"]
        if ($def) { foreach ($p in $def.Select) { [void]$set.Add($p) } }
    } }
    @($set)
}
