# EntraPolicySuite -- the EDITING side of the rules (DESIGN §5.2, §5.3, §5.6a, §5.6b, §5.8, §5.9): rule cards, tag types
# and their values, the customer's own property condition types, saved scopes. What the web app calls; the engine only
# reads these tables. Dot-source EPS-SqlStore and EPS-Conditions first.
#
# The rules of §5.9, in code:
#   * a rule is ONE card (no ConditionGroup to forget); Duplicate makes a new card right after the original
#   * a save that would leave a BROKEN REFERENCE is refused, saying what: an unknown or disabled tag type, a value that
#     is not on the tag type's list, an unknown condition type, a target its condition type rejects; removing a tag
#     value, a tag type or a condition type that a rule still uses; a second tag type on one attribute
#   * everything else is a HINT on the card, never in the way: a contradiction, the same condition twice, cloned v1 rows
#     that kept their group, a rule an earlier (First) / later (Last) rule of the same tag type always beats (shadowed)
#   * every change is ONE transaction with its eps.ConfigChange journal row (before + after), checked against the
#     version the person loaded - two people editing the same card cannot overwrite each other unseen
#   * the journal row's JSON is the card itself, so "restore this version" saves it again (a new row, history kept)

Set-StrictMode -Off

$script:EpsRuleSet = 'default'   # the rule set the engine runs (Read-EpsTagRules)
$script:EpsMaxConditions = 50

function Get-EpsRuleTable { param([ValidateSet('User', 'Device')][string]$ObjectType) if ($ObjectType -eq 'User') { 'UserTagRule' } else { 'DeviceTagRule' } }

function Test-EpsPlainText {
    # one line of text: no control characters, at most $Max; $null when fine, else the error
    param([string]$Text, [int]$Max, [string]$What)
    if ($Text -match '[\u0000-\u001f\u007f]') { return "$What has a control character (a new line?)" }
    if ($Text.Length -gt $Max) { return "$What is longer than $Max characters" }
    $null
}

# ---- hints (never blocking) -------------------------------------------------------------------------------------------
function Get-EpsRuleHints {
    # The HINTS of DESIGN §5.9 for rule cards - shown on the card and in the import preview, never blocking.
    # Message = with the rule named (the import preview); Text = without (the card itself).
    param([object[]]$Cards, [hashtable]$Catalog, [hashtable]$TagTypes)
    $hints = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $Cards) {
        $where = "rule $($c.RuleId) ($($c.Persona) / $($c.TagType)$(if (@($c.V1Rows).Count) { ', ' + (@($c.V1Rows) -join ', ') }))"
        $add = { param($code, $text) $hints.Add(@{ Code = $code; RuleId = $c.RuleId; Message = "${where}: $text"; Text = $text }) }
        if (-not $TagTypes["$($c.ObjectType):$($c.TagType)"]) { & $add 'UnknownTagType' "tag type '$($c.TagType)' does not exist - the rule never runs" }
        $seen = @{}
        foreach ($k in $c.Conditions) {
            $def = $Catalog["$($c.ObjectType):$($k.ConditionType)"]
            if (-not $def) { & $add 'UnknownConditionType' "condition type '$($k.ConditionType)' is unknown - the rule never matches"; continue }
            if ($def.Validate) { $err = & $def.Validate $k.Target; if ($err) { & $add 'InvalidTarget' "$($k.ConditionType): $err" } }
            $sig = "$($k.ConditionType)|$($k.Target)".ToLowerInvariant()
            if ($seen[$sig]) { & $add 'SameConditionTwice' "'$($k.ConditionType) $($k.Target)' is in the rule twice" }
            $seen[$sig] = $true
        }
        $conds = @($c.Conditions)
        foreach ($k in $conds) {
            if ($k.ConditionType -match '^(.+)_Like$') {
                $neg = "$($Matches[1])_NotLike"
                if ($conds | Where-Object { $_.ConditionType -eq $neg -and $_.Target -eq $k.Target }) { & $add 'Contradiction' "'$($k.ConditionType) $($k.Target)' and '$neg $($k.Target)' together can never match" }
            }
        }
        foreach ($t in @('OnPremisesSyncEnabled', 'Teams_Room_Like', 'IsCompliant', 'IsManaged', 'AccountEnabled')) {
            $vals = @($conds | Where-Object ConditionType -eq $t | ForEach-Object { if ($_.Target -match '(?i)TRUE') { 'T' } elseif ($_.Target -match '(?i)FALSE') { 'F' } })
            if ($vals -contains 'T' -and $vals -contains 'F') { & $add 'Contradiction' "'$t' is both TRUE and FALSE - the rule can never match" }
        }
        # the owner's case (2026-10-29): rows cloned with a new target but the ORIGINAL ConditionGroup are ANDed into
        # the original rule - two different patterns on the same field rarely both match, so the rule quietly changes.
        if ($c.V1ConditionGroup) {
            $byType = $conds | Where-Object { $_.ConditionType -match '_Like$' } | Group-Object ConditionType
            foreach ($g in $byType) {
                $targets = @(@($g.Group).Target | Select-Object -Unique)
                if ($targets.Count -gt 1) { & $add 'ClonedRowsSuspect' "rows $(@(@($g.Group).V1Row) -join ', ') share ConditionGroup '$($c.V1ConditionGroup)' and are ANDed: $($g.Name) must match ALL of $($targets -join ' AND ') - cloned rows that kept the group?" }
            }
        }
    }
    $hints
}

function Get-EpsRuleShadowHints {
    # A rule that can never win: ValueMode First = the FIRST matching enabled rule of a tag type wins, so an earlier rule
    # whose conditions are a subset of this one's always beats it (it matches whenever this one does); Last = a later
    # one. Multiple has no winner, so nothing is shadowed. Cards in run order (Order, RuleId).
    param([object[]]$Cards, [hashtable]$TagTypes)
    # the leading comma: a set returned from a script block would be unrolled into its strings
    $sig = { param($c) , [System.Collections.Generic.HashSet[string]]::new([string[]]@($c.Conditions | ForEach-Object { "$($_.ConditionType)|$($_.Target)".ToLowerInvariant() }), [StringComparer]::Ordinal) }
    $on = @($Cards | Where-Object { $_.Enabled -ne $false })
    foreach ($g in ($on | Group-Object { "$($_.RuleSet)|$($_.ObjectType):$($_.TagType)" })) {
        $mode = "$($TagTypes[$g.Name.Split('|', 2)[1]].ValueMode)"; if ($mode -notin 'First', 'Last') { continue }
        $list = @($g.Group); if ($mode -eq 'Last') { [array]::Reverse($list) }
        for ($i = 1; $i -lt $list.Count; $i++) {
            $mine = & $sig $list[$i]
            for ($j = 0; $j -lt $i; $j++) {
                $theirs = & $sig $list[$j]
                if ($theirs.IsSubsetOf($mine)) {
                    $b = $list[$j]
                    $text = "never wins: rule $($b.RuleId)$(if ($b.Persona -and $b.Persona -ne $b.TagType) { " ($($b.Persona))" }) $(if ($mode -eq 'First') { 'above' } else { 'below' }) it sets $($list[$i].TagType) whenever this one matches ($($list[$i].TagType) takes the $($mode.ToLowerInvariant()) match)"
                    @{ Code = 'Shadowed'; RuleId = $list[$i].RuleId; Message = "rule $($list[$i].RuleId): $text"; Text = $text }
                    break
                }
            }
        }
    }
}

# ---- what the editor reads --------------------------------------------------------------------------------------------
function Get-EpsEditContext {
    # the tag types (with values), the condition catalog (shipped + the customer's, enabled ones only take part)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $types = @{}
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT * FROM eps.TagType')) { $types["$($r.ObjectType):$($r.Name)"] = $r }
    $values = @{}
    foreach ($v in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, TagType, Value, IsPattern, Description FROM eps.TagValue')) {
        $k = "$($v.ObjectType):$($v.TagType)"; if (-not $values[$k]) { $values[$k] = [System.Collections.Generic.List[object]]::new() }; $values[$k].Add($v) }
    $custom = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Id, ObjectType, Property, Operator, Guard, Description, Enabled FROM eps.ConditionType')
    $catalog = Import-EpsConditionCatalog -CustomConditions @($custom | Where-Object Enabled | ForEach-Object { [pscustomobject]@{ id = $_.Id; objectType = $_.ObjectType; property = $_.Property; operator = $_.Operator; guard = $_.Guard; description = $_.Description; custom = $true } })
    @{ TagTypes = $types; Values = $values; Catalog = $catalog; Custom = $custom }
}

function Read-EpsRuleCardsForEdit {
    # every card of one object type (every rule set), in run order, with its version (UpdatedAtUtc)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [int]$RuleId)
    $t = Get-EpsRuleTable $ObjectType
    $w = if ($RuleId) { 'WHERE r.RuleId = @id' } else { '' }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $RuleId } -Query "SELECT r.*, c.Seq, c.ConditionType, c.Target FROM eps.$t r LEFT JOIN eps.${t}Condition c ON c.RuleId = r.RuleId $w ORDER BY r.RuleSet, r.[Order], r.RuleId, c.Seq")
    $cards = [ordered]@{}
    foreach ($r in $rows) {
        $k = [string]$r.RuleId
        if (-not $cards.Contains($k)) {
            $cards[$k] = [ordered]@{ RuleId = [int]$r.RuleId; ObjectType = $ObjectType; RuleSet = $r.RuleSet; Order = [int]$r.Order
                Persona = $(if ($ObjectType -eq 'User') { $r.Persona } else { $r.TagType }); TagType = $r.TagType
                TagValueAD = $(if ($ObjectType -eq 'User') { $r.TagValueAD } else { $r.TagValue }); TagValueCloud = $(if ($ObjectType -eq 'User') { $r.TagValueCloud } else { $r.TagValue })
                TagValue = $(if ($ObjectType -eq 'Device') { $r.TagValue }); Enabled = [bool]$r.Enabled; Source = $r.Source; V1ConditionGroup = $r.V1ConditionGroup
                Notes = $r.Notes; UpdatedAtUtc = $r.UpdatedAtUtc; Conditions = [System.Collections.Generic.List[object]]::new() }
        }
        if ($r.ConditionType) { $cards[$k].Conditions.Add([ordered]@{ ConditionType = $r.ConditionType; Target = $r.Target }) }
    }
    @($cards.Values)
}

function ConvertTo-EpsRuleJournal {
    # the card as the journal keeps it = the shape the editor sends back on a restore
    param($Card, [string]$ObjectType)
    $o = [ordered]@{ ruleId = $Card.RuleId; ruleSet = $Card.RuleSet; order = $Card.Order }
    if ($ObjectType -eq 'User') { $o.persona = $Card.Persona; $o.tagType = $Card.TagType; $o.tagValueAD = $Card.TagValueAD; $o.tagValueCloud = $Card.TagValueCloud }
    else { $o.tagType = $Card.TagType; $o.tagValue = $Card.TagValue }
    $o.enabled = [bool]$Card.Enabled; $o.notes = $Card.Notes
    $o.conditions = @($Card.Conditions | ForEach-Object { [ordered]@{ conditionType = $_.ConditionType; target = $_.Target } })
    $o | ConvertTo-Json -Compress -Depth 5
}

# ---- validation of one card (the broken-reference guard) ------------------------------------------------------------
function Test-EpsTagValueAllowed {
    # a tag type with a value list allows a value on it (case-insensitive) or one a pattern value matches (v1 Exchange_*);
    # a tag type without a list is free text (AccountInfo)
    param($Values, [string]$Value)
    if (-not $Value) { return $true }
    $list = @($Values | Where-Object { $null -ne $_ })   # no list at all arrives as $null, which @() would count as one
    if (-not $list.Count) { return $true }
    foreach ($v in $list) { if ([string]::Equals([string]$v.Value, $Value, [StringComparison]::OrdinalIgnoreCase)) { return $true }; if ($v.IsPattern -and (Get-EpsWildcard ([string]$v.Value)).IsMatch($Value)) { return $true } }
    $false
}

function ConvertTo-EpsRuleCard {
    # the editor's body -> a card to store, or the errors that refuse it: @{ Ok; Card; Errors }
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)]$Body, [Parameter(Mandatory)]$Context)
    $err = [System.Collections.Generic.List[string]]::new()
    $s = { param($v) if ($null -eq $v) { '' } elseif ($v -is [string] -or $v -is [ValueType]) { "$v".Trim() } else { $err.Add('a field holds an object where text is expected'); '' } }
    $card = [ordered]@{ ObjectType = $ObjectType; RuleSet = $script:EpsRuleSet; TagType = (& $s $Body.tagType); Enabled = $(if ($null -eq $Body.enabled) { $true } else { [bool]$Body.enabled }); Notes = (& $s $Body.notes) }
    if ($ObjectType -eq 'User') { $card.Persona = (& $s $Body.persona); $card.TagValueAD = (& $s $Body.tagValueAD); $card.TagValueCloud = (& $s $Body.tagValueCloud) }
    else { $card.TagValue = (& $s $Body.tagValue); $card.Persona = $card.TagType }
    foreach ($f in @(@('Persona', 200, 'the persona'), @('TagType', 60, 'the tag type'), @('Notes', 1000, 'the notes'), @('TagValueAD', 1024, 'the AD value'), @('TagValueCloud', 1024, 'the cloud value'), @('TagValue', 1024, 'the value'))) {
        if ($card.Contains($f[0])) { $e = Test-EpsPlainText -Text $card[$f[0]] -Max $f[1] -What $f[2]; if ($e) { $err.Add($e) } } }
    if ($ObjectType -eq 'User' -and -not $card.Persona) { $err.Add('give the rule a persona (the name people know it by, e.g. Internal_Admin)') }
    $tt = $Context.TagTypes["${ObjectType}:$($card.TagType)"]
    if (-not $card.TagType) { $err.Add('pick a tag type') }
    elseif (-not $tt) { $err.Add("tag type '$($card.TagType)' does not exist for $($ObjectType.ToLowerInvariant())s") }
    elseif (-not $tt.Enabled) { $err.Add("tag type '$($card.TagType)' is switched off - switch it on first, on the Tag types page") }
    else { $card.TagType = $tt.Name }
    $conds = [System.Collections.Generic.List[object]]::new()
    foreach ($k in @($Body.conditions)) {
        if ($null -eq $k) { continue }
        $ct = & $s $k.conditionType; $tg = & $s $k.target
        if (-not $ct) { continue }
        $def = $Context.Catalog["${ObjectType}:$ct"]
        if (-not $def) { $err.Add("condition type '$ct' does not exist for $($ObjectType.ToLowerInvariant())s"); continue }
        $e = Test-EpsPlainText -Text $tg -Max 1024 -What "the target of $ct"; if ($e) { $err.Add($e); continue }
        if ($def.Validate) { $e = & $def.Validate $tg; if ($e) { $err.Add("${ct}: $e"); continue } }
        if ($def.Kind -eq 'Property' -and $def.Operator -in 'boolMatch', 'boolEquals' -and $tg -notmatch '^(?i)(TRUE|FALSE)$') { $err.Add("${ct}: the target must be TRUE or FALSE"); continue }
        $conds.Add([ordered]@{ ConditionType = $def.Id; Target = $tg })
    }
    if (-not $conds.Count -and -not $err.Count) { $err.Add('a rule needs at least one condition (a rule for everyone is the tag type''s fallback value)') }
    if ($conds.Count -gt $script:EpsMaxConditions) { $err.Add("at most $script:EpsMaxConditions conditions in one rule") }
    $card.Conditions = $conds
    if ($tt) {
        $vals = $Context.Values["${ObjectType}:$($tt.Name)"]
        $modifies = [bool]@($conds | Where-Object { $Context.Catalog["${ObjectType}:$($_.ConditionType)"].ModifiesValue }).Count
        $pairs = if ($ObjectType -eq 'User') { @(@('TagValueAD', 'the AD value'), @('TagValueCloud', 'the cloud value')) } else { @(@('TagValue', 'the value')) }
        foreach ($p in $pairs) { if (-not (Test-EpsTagValueAllowed -Values $vals -Value $card[$p[0]])) { $err.Add("$($p[1]) '$($card[$p[0]])' is not on the list of $($tt.Name) values - add it on the Tag types page first") } }
        if ($ObjectType -eq 'User' -and -not $card.TagValueAD -and -not $card.TagValueCloud -and -not $modifies) { $err.Add('give a value for AD-synced users, cloud users, or both') }
    }
    @{ Ok = -not $err.Count; Card = $card; Errors = @($err) }
}

# ---- the journal ---------------------------------------------------------------------------------------------------
function Get-EpsJournalSql { "INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@ja, @je, @jk, @jact, @jb, @jaf, 'gui');" }
function New-EpsJournalParameters { param([string]$Actor, [string]$Entity, [string]$Key, [string]$Action, $Before, $After) @{ ja = $Actor; je = $Entity; jk = $Key; jact = $Action; jb = $Before; jaf = $After } }

function Get-EpsConfigHistory {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [string]$Key, [int]$Top = 100)
    $w = if ($Key) { 'AND EntityKey = @k' } else { '' }
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ e = $Entity; k = $Key; t = $Top } -Query "SELECT TOP (@t) ChangeId, AtUtc, Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source FROM eps.ConfigChange WHERE Entity = @e $w ORDER BY ChangeId DESC")
}

# ---- rule cards: save / delete / move -------------------------------------------------------------------------------
function Save-EpsRuleCard {
    # create (-RuleId 0; -InsertAfter = put it right after that rule, else last) or update (-Expected = the version the
    # person loaded). Returns @{ Result = ok | conflict | missing; RuleId; Before; After }.
    # -Source: where a NEW card came from (gui, or v1-import for the GUI's v1 upload - so a later "replace the imported
    # rules" finds them); an update keeps the card's own
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Card, [int]$RuleId, [int]$InsertAfter, [string]$Expected, [Parameter(Mandatory)][string]$Actor, [ValidateSet('gui', 'v1-import')][string]$Source = 'gui')
    $ot = $Card.ObjectType; $t = Get-EpsRuleTable $ot
    $p = @{ s = $Card.RuleSet; t = $Card.TagType; e = [bool]$Card.Enabled; n = $(if ($Card.Notes) { $Card.Notes }); src = $Source }
    $cols = if ($ot -eq 'User') { $p.p = $Card.Persona; $p.va = $(if ($Card.TagValueAD) { $Card.TagValueAD }); $p.vc = $(if ($Card.TagValueCloud) { $Card.TagValueCloud }); 'Persona = @p, TagValueAD = @va, TagValueCloud = @vc' }
            else { $p.v = $(if ($Card.TagValue) { $Card.TagValue }); 'TagValue = @v' }
    $ins = if ($ot -eq 'User') { @('Persona, TagValueAD, TagValueCloud', '@p, @va, @vc') } else { @('TagValue', '@v') }
    $cv = @(for ($i = 0; $i -lt $Card.Conditions.Count; $i++) { $p["ct$i"] = $Card.Conditions[$i].ConditionType; $p["tg$i"] = $(if ($Card.Conditions[$i].Target) { $Card.Conditions[$i].Target } else { '' }); "(@id, $($i + 1), @ct$i, @tg$i)" })
    $condSql = if ($cv.Count) { "INSERT INTO eps.${t}Condition (RuleId, Seq, ConditionType, Target) VALUES $($cv -join ', ');" } else { '' }
    $before = $null
    if ($RuleId) {
        $cur = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ot -RuleId $RuleId)[0]
        if (-not $cur) { return @{ Result = 'missing' } }
        if ($Expected -and (ConvertTo-EpsWebTime $cur.UpdatedAtUtc) -ne $Expected) { return @{ Result = 'conflict'; Before = $cur } }
        $before = ConvertTo-EpsRuleJournal -Card $cur -ObjectType $ot
        $Card.RuleSet = $cur.RuleSet; $Card.Order = $cur.Order; $p.s = $cur.RuleSet
        $p.id = $RuleId; $p.v0 = $cur.UpdatedAtUtc
        $Card.RuleId = $RuleId
        $after = ConvertTo-EpsRuleJournal -Card $Card -ObjectType $ot
        $p += New-EpsJournalParameters -Actor $Actor -Entity $t -Key "$RuleId" -Action 'Update' -Before $before -After $after
        $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM eps.$t WITH (UPDLOCK, HOLDLOCK) WHERE RuleId = @id AND UpdatedAtUtc = @v0)
BEGIN ROLLBACK; SELECT 'conflict' AS Result; RETURN; END
UPDATE eps.$t SET TagType = @t, $cols, Enabled = @e, Notes = @n, UpdatedAtUtc = SYSUTCDATETIME() WHERE RuleId = @id;
DELETE FROM eps.${t}Condition WHERE RuleId = @id;
$condSql
$(Get-EpsJournalSql)
COMMIT;
SELECT 'ok' AS Result;
"@)[0]
        return @{ Result = $r.Result; RuleId = $RuleId; Before = $before; After = $after }
    }
    # create: the position, then the row, its conditions and the journal - one transaction
    $p.after = $InsertAfter
    $Card.RuleId = 0; $Card.Order = 0
    $after0 = ConvertTo-EpsRuleJournal -Card $Card -ObjectType $ot
    $p += New-EpsJournalParameters -Actor $Actor -Entity $t -Key '' -Action 'Create' -Before $null -After $after0
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @pos INT = NULL, @id INT;
IF @after > 0 SELECT @pos = [Order] + 1 FROM eps.$t WITH (UPDLOCK, HOLDLOCK) WHERE RuleId = @after AND RuleSet = @s;
IF @after > 0 AND @pos IS NULL BEGIN ROLLBACK; SELECT 'missing' AS Result; RETURN; END
IF @pos IS NULL SELECT @pos = ISNULL(MAX([Order]), 0) + 10 FROM eps.$t WITH (UPDLOCK, HOLDLOCK) WHERE RuleSet = @s;
ELSE UPDATE eps.$t SET [Order] = [Order] + 1 WHERE RuleSet = @s AND [Order] >= @pos;
INSERT INTO eps.$t (RuleSet, [Order], TagType, $($ins[0]), Enabled, Source, Notes) VALUES (@s, @pos, @t, $($ins[1]), @e, @src, @n);
SET @id = CAST(SCOPE_IDENTITY() AS INT);
$condSql
-- the new id and position into the journal's card: LOCAL variables of full length (a parameter keeps the length of the
-- value it was given, so writing a longer text into @jaf / @jk would cut it short)
DECLARE @key NVARCHAR(400) = CAST(@id AS NVARCHAR(20)), @card NVARCHAR(MAX) = JSON_MODIFY(JSON_MODIFY(CAST(@jaf AS NVARCHAR(MAX)), '$.ruleId', @id), '$.order', @pos);
INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES (@ja, @je, @key, @jact, NULL, @card, 'gui');
COMMIT;
SELECT 'ok' AS Result, @id AS RuleId, @card AS After;
"@)[0]
    @{ Result = $r.Result; RuleId = [int]$r.RuleId; Before = $null; After = $r.After }
}

function Remove-EpsRuleCard {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][int]$RuleId, [string]$Expected, [Parameter(Mandatory)][string]$Actor)
    $t = Get-EpsRuleTable $ObjectType
    $cur = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ObjectType -RuleId $RuleId)[0]
    if (-not $cur) { return @{ Result = 'missing' } }
    if ($Expected -and (ConvertTo-EpsWebTime $cur.UpdatedAtUtc) -ne $Expected) { return @{ Result = 'conflict' } }
    $before = ConvertTo-EpsRuleJournal -Card $cur -ObjectType $ObjectType
    $p = @{ id = $RuleId; v0 = $cur.UpdatedAtUtc } + (New-EpsJournalParameters -Actor $Actor -Entity $t -Key "$RuleId" -Action 'Delete' -Before $before -After $null)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM eps.$t WITH (UPDLOCK, HOLDLOCK) WHERE RuleId = @id AND UpdatedAtUtc = @v0)
BEGIN ROLLBACK; SELECT 'conflict' AS Result; RETURN; END
DELETE FROM eps.${t}Condition WHERE RuleId = @id;
DELETE FROM eps.$t WHERE RuleId = @id;
$(Get-EpsJournalSql)
COMMIT;
SELECT 'ok' AS Result;
"@)[0]
    @{ Result = $r.Result; Before = $before }
}

function Move-EpsRuleCard {
    # one place up or down in its rule set: the set is renumbered 10, 20, 30 ... in the new order (v1 imports can share
    # an Order), every changed row in one transaction, one journal row
    # -Ids / -To / -Ref (RULES-GRID, owner 2026-11-01 "move"): a SELECTION of cards moves as one block, kept in its run
    # order, to the top, the bottom, or before / after another card - one transaction, one journal row per moved card
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [int]$RuleId, [ValidateSet('up', 'down')][string]$Direction,
          [int[]]$Ids, [ValidateSet('top', 'bottom', 'before', 'after')][string]$To, [int]$Ref, [Parameter(Mandatory)][string]$Actor)
    $t = Get-EpsRuleTable $ObjectType
    $block = $null -ne $Ids -and @($Ids | Where-Object { $null -ne $_ }).Count -gt 0
    $first = if ($block) { [int]@($Ids)[0] } else { $RuleId }
    $me = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $first } -Query "SELECT RuleSet, [Order] FROM eps.$t WHERE RuleId = @id")[0]
    if (-not $me) { return @{ Result = 'missing' } }
    $list = [System.Collections.Generic.List[int]]::new([int[]]@(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ s = $me.RuleSet } -Query "SELECT RuleId FROM eps.$t WHERE RuleSet = @s ORDER BY [Order], RuleId" | ForEach-Object { [int]$_.RuleId }))
    $old = [System.Collections.Generic.List[int]]::new($list)
    if ($block) {
        if (-not $To) { return @{ Result = 'edge' } }
        foreach ($x in $Ids) { if (-not $list.Contains([int]$x)) { return @{ Result = 'missing' } } }
        if ($To -in 'before', 'after' -and (-not $list.Contains($Ref) -or @($Ids) -contains $Ref)) { return @{ Result = 'missing' } }
        $moving = @($list | Where-Object { @($Ids) -contains $_ })
        $rest = [System.Collections.Generic.List[int]]::new([int[]]@($list | Where-Object { @($Ids) -notcontains $_ }))
        $at = switch ($To) { 'top' { 0 } 'bottom' { $rest.Count } 'before' { $rest.IndexOf($Ref) } 'after' { $rest.IndexOf($Ref) + 1 } }
        $rest.InsertRange($at, [int[]]$moving); $list = $rest
        $p = @{ s = $me.RuleSet; cnt = $list.Count; sum = [long](($list | Measure-Object -Sum).Sum); ja = $Actor; je = $t }
        $jr = @(for ($k = 0; $k -lt $moving.Count; $k++) { $id = [int]$moving[$k]
            $p["jk$k"] = "$id"; $p["jb$k"] = (@{ order = $old.IndexOf($id) + 1 } | ConvertTo-Json -Compress); $p["jaf$k"] = ([ordered]@{ order = $list.IndexOf($id) + 1; to = $To; ref = $(if ($To -in 'before', 'after') { $Ref }) } | ConvertTo-Json -Compress)
            "(@ja, @je, @jk$k, 'Move', @jb$k, @jaf$k, 'gui')" })
        $journal = "INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source) VALUES $($jr -join ', ');"
    } else {
        $i = $list.IndexOf($RuleId); $j = if ($Direction -eq 'up') { $i - 1 } else { $i + 1 }
        if ($j -lt 0 -or $j -ge $list.Count) { return @{ Result = 'edge' } }
        $list[$i] = $list[$j]; $list[$j] = $RuleId
        $p = @{ s = $me.RuleSet; cnt = $list.Count; sum = [long](($list | Measure-Object -Sum).Sum) } + (New-EpsJournalParameters -Actor $Actor -Entity $t -Key "$RuleId" -Action 'Move' -Before (@{ order = $i + 1 } | ConvertTo-Json -Compress) -After (@{ order = $j + 1; direction = $Direction } | ConvertTo-Json -Compress))
        $journal = Get-EpsJournalSql
    }
    $sets = @(for ($k = 0; $k -lt $list.Count; $k++) { "WHEN $([int]$list[$k]) THEN $(($k + 1) * 10)" })
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
-- a card added or deleted since the list was read: the new order would be wrong
IF (SELECT COUNT(*) FROM eps.$t WITH (UPDLOCK, HOLDLOCK) WHERE RuleSet = @s) <> @cnt OR (SELECT SUM(CAST(RuleId AS BIGINT)) FROM eps.$t WHERE RuleSet = @s) <> @sum
BEGIN ROLLBACK; SELECT 'conflict' AS Result; RETURN; END
UPDATE eps.$t SET [Order] = CASE RuleId $($sets -join ' ') END WHERE RuleSet = @s;
$journal
COMMIT;
SELECT 'ok' AS Result;
"@)[0]
    if ($block) { return @{ Result = $r.Result; Position = $list.IndexOf([int]$moving[0]) + 1; Moved = $moving.Count } }
    @{ Result = $r.Result; Position = $j + 1 }
}

# ---- the grid: batches, CSV, the v1 upload (RULES-GRID, owner 2026-11-01: "does the rules support things like multi
# select, duplicate, copy paste values search move" / "like excel edits") ------------------------------------------------
# A grid edit, a paste, a fill-down, a bulk action or an import is ONE batch of the four card changes (create, update,
# delete, move a block): validated here against the rules as they are NOW (every card through ConvertTo-EpsRuleCard - the
# same broken-reference guard as one save), staged as ONE queue entry, and applied by the engine in order through the same
# Save / Remove / Move functions as one save (each with its own journal row). The hints are those of the RESULT.
$script:EpsMaxBatchOps = 2000

function Get-EpsRuleConditionText { param($Conditions) (@(@($Conditions) | Where-Object { $null -ne $_ } | ForEach-Object { ("$($_.ConditionType) $($_.Target)").Trim() }) -join ' AND ') }

function Get-EpsRuleFlat {
    # one card as the grid's columns (the diff of a batch is made of these)
    param($Card, [string]$ObjectType)
    $o = [ordered]@{}
    if ($ObjectType -eq 'User') { $o.Persona = "$($Card.Persona)" }
    $o.TagType = "$($Card.TagType)"
    if ($ObjectType -eq 'User') { $o.TagValueAD = "$($Card.TagValueAD)"; $o.TagValueCloud = "$($Card.TagValueCloud)" } else { $o.TagValue = "$($Card.TagValue)" }
    $o.Enabled = if ($Card.Enabled -eq $false) { 'FALSE' } else { 'TRUE' }
    $o.Notes = "$($Card.Notes)"; $o.Conditions = Get-EpsRuleConditionText $Card.Conditions
    $o
}

function ConvertTo-EpsRuleBody {
    # a card -> the body the rule routes take
    param($Card, [string]$ObjectType)
    $b = [ordered]@{ tagType = "$($Card.TagType)"; enabled = ($Card.Enabled -ne $false); notes = "$($Card.Notes)"
        conditions = @(@($Card.Conditions) | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ conditionType = "$($_.ConditionType)"; target = "$($_.Target)" } }) }
    if ($ObjectType -eq 'User') { $b.persona = "$($Card.Persona)"; $b.tagValueAD = "$($Card.TagValueAD)"; $b.tagValueCloud = "$($Card.TagValueCloud)" } else { $b.tagValue = "$($Card.TagValue)" }
    $b
}

function Test-EpsRuleBatch {
    <#
    .SYNOPSIS
        Checks a batch of rule changes against the rules as they are NOW, in order, and says what it would do.
        Ops: @{ op = create; rule = <body>; insertAfter = <rule id> | 'prev' (the previous new rule) | 0 (last); source }
             @{ op = update; id; expected = <the version loaded>; rule = <body> }   @{ op = delete; id; expected }
             @{ op = move; ids = @(..); to = top | bottom | before | after; ref = <rule id> }
             @{ op = addvalue; tagType; value; description }   (a plain value added to a tag type's list; the ops after it
             may set it - the v1 import's "add the missing values", applied through Save-EpsTagValue)
        Returns @{ Ok; Errors; Items (per op: errors, changes field / before / after, hints, unchanged); Counts; Summary;
        Before (the touched cards as they are); Valid (per op index: the validated card / move) }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, $Ops, $Context, $Current)
    if (-not $Context) { $Context = Get-EpsEditContext -ConnectionString $ConnectionString }
    $cur = if ($null -ne $Current) { @($Current) } else { @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ObjectType) }
    $ops = @(@($Ops) | Where-Object { $null -ne $_ })
    # an addvalue op changes the value lists the LATER ops are checked against: a copy of the context, never the caller's
    if (@($ops | Where-Object { "$($_.op)".Trim() -ieq 'addvalue' }).Count) {
        $vc = @{}; foreach ($k in @($Context.Values.Keys)) { $vc[$k] = $Context.Values[$k] }
        $Context = @{ TagTypes = $Context.TagTypes; Values = $vc; Catalog = $Context.Catalog; Custom = $Context.Custom }
    }
    $errs = [System.Collections.Generic.List[string]]::new(); $items = [System.Collections.Generic.List[object]]::new(); $valid = @{}
    $counts = [ordered]@{ create = 0; update = 0; delete = 0; move = 0; value = 0; unchanged = 0 }
    $addedValues = @{}
    if (-not $ops.Count) { $errs.Add('the batch holds no change') }
    if ($ops.Count -gt $script:EpsMaxBatchOps) { $errs.Add("at most $script:EpsMaxBatchOps changes in one batch (this one has $($ops.Count))"); $ops = @() }
    $byId = @{}; foreach ($k in $cur) { $byId["$($k.RuleId)"] = $k }
    $sim = [System.Collections.Generic.List[object]]::new(); foreach ($k in $cur) { $sim.Add(@{ Id = "$($k.RuleId)"; Card = $k; Set = "$($k.RuleSet)"; New = $false }) }
    $find = { param($id) foreach ($x in $sim) { if ($x.Id -eq "$id") { return $x } }; $null }
    $done = @{}; $lastNew = $null; $n = 0; $before = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ops.Count; $i++) {
        $o = $ops[$i]; $e = [System.Collections.Generic.List[string]]::new()
        $kind = "$($o.op)".Trim().ToLowerInvariant()
        $it = [ordered]@{ index = $i; op = $kind; ruleId = $null; row = $(if ($o.row) { "$($o.row)" }); errors = @(); changes = @(); hints = @(); unchanged = $false }
        $idTxt = "$($o.id)".Trim(); $card = $null
        if ($kind -in 'update', 'delete') {
            $it.ruleId = $idTxt
            if ($idTxt -match '^\d{1,9}$') { $card = $byId[$idTxt] }
            if (-not $card) { $e.Add("rule '$idTxt' does not exist (deleted?) - reload") }
            elseif ($done[$idTxt]) { $e.Add("rule $idTxt is changed twice in this batch ($($done[$idTxt]) and $kind)"); $card = $null }
            else {
                $done[$idTxt] = $kind
                if (-not (ConvertTo-EpsExpectedText $o.expected)) { $e.Add("the version of rule $idTxt you loaded is missing - reload") }
                elseif ((ConvertTo-EpsWebTime $card.UpdatedAtUtc) -ne (ConvertTo-EpsExpectedText $o.expected)) { $e.Add("rule $idTxt was changed after you loaded it - reload and look again") }
            }
        }
        switch ($kind) {
            'create' {
                $v = ConvertTo-EpsRuleCard -ObjectType $ObjectType -Body $(if ($o.rule) { $o.rule } else { [pscustomobject]@{} }) -Context $Context
                foreach ($x in $v.Errors) { $e.Add($x) }
                $src = if ("$($o.source)") { "$($o.source)" } else { 'gui' }
                if ($src -cnotin 'gui', 'v1-import') { $e.Add("source '$src' is not gui or v1-import") }
                $ia = "$($o.insertAfter)".Trim(); $pos = $sim.Count
                if ($ia -eq 'prev') { if ($lastNew) { $pos = $sim.IndexOf($lastNew) + 1 } else { $e.Add('"after the previous new rule", but no new rule comes before it') } }
                elseif ($ia -match '^\d{1,9}$' -and [int]$ia -gt 0) { $a = & $find $ia; if ($a -and -not $a.New) { $pos = $sim.IndexOf($a) + 1 } else { $e.Add("the rule to put it after ($ia) does not exist, or this batch deletes it") } }
                elseif ($ia -and $ia -ne '0') { $e.Add("insertAfter '$ia' is not a rule id or 'prev'") }
                $n++; $it.ruleId = "new$n"
                $entry = @{ Id = "new$n"; Card = $v.Card; Set = $script:EpsRuleSet; New = $true }; $sim.Insert($pos, $entry); $lastNew = $entry
                $valid[$i] = @{ Card = $v.Card; Source = $src }
                $it.changes = @(foreach ($kv in (Get-EpsRuleFlat $v.Card $ObjectType).GetEnumerator()) { [ordered]@{ field = $kv.Key; before = $null; after = "$($kv.Value)" } })
                $counts.create++
            }
            'update' {
                $v = ConvertTo-EpsRuleCard -ObjectType $ObjectType -Body $(if ($o.rule) { $o.rule } else { [pscustomobject]@{} }) -Context $Context
                foreach ($x in $v.Errors) { $e.Add($x) }
                $valid[$i] = @{ Card = $v.Card }
                if ($card) {
                    $fb = Get-EpsRuleFlat $card $ObjectType; $fa = Get-EpsRuleFlat $v.Card $ObjectType
                    $it.changes = @(foreach ($k in @($fb.Keys)) { if ("$($fb[$k])" -cne "$($fa[$k])") { [ordered]@{ field = $k; before = "$($fb[$k])"; after = "$($fa[$k])" } } })
                    if (-not $it.changes.Count) { $it.unchanged = $true; $counts.unchanged++ } else { $counts.update++ }
                    $before.Add((ConvertTo-EpsRuleJournal -Card $card -ObjectType $ObjectType | ConvertFrom-Json))
                    $x0 = & $find $idTxt; if ($x0) { $x0.Card = $v.Card }
                }
            }
            'delete' {
                if ($card) {
                    $it.changes = @(foreach ($kv in (Get-EpsRuleFlat $card $ObjectType).GetEnumerator()) { [ordered]@{ field = $kv.Key; before = "$($kv.Value)"; after = $null } })
                    $before.Add((ConvertTo-EpsRuleJournal -Card $card -ObjectType $ObjectType | ConvertFrom-Json))
                    $x0 = & $find $idTxt; if ($x0) { [void]$sim.Remove($x0) }
                }
                $counts.delete++
            }
            'move' {
                $ids = @(@($o.ids) | Where-Object { $null -ne $_ } | ForEach-Object { "$_".Trim() })
                $to = "$($o.to)".Trim().ToLowerInvariant(); $ref = "$($o.ref)".Trim()
                $it.ruleId = $ids -join ','
                if (-not $ids.Count) { $e.Add('pick the rules to move') }
                if ($ids.Count -ne @($ids | Select-Object -Unique).Count) { $e.Add('a rule is named twice in the move') }
                if ($to -notin 'top', 'bottom', 'before', 'after') { $e.Add("move to the top, the bottom, or before / after a rule (not '$to')") }
                $ents = @(foreach ($x in $ids) { if ($x -notmatch '^\d{1,9}$') { $e.Add("'$x' is not a rule id"); continue }; $f = & $find $x; if (-not $f -or $f.New) { $e.Add("rule $x does not exist, or this batch deletes it") } else { $f } })
                $refE = $null
                if ($to -in 'before', 'after') {
                    if ($ref -notmatch '^\d{1,9}$') { $e.Add('name the rule to move them before / after') }
                    elseif ($ids -contains $ref) { $e.Add("rule $ref is one of the rules that move") }
                    else { $refE = & $find $ref; if (-not $refE -or $refE.New) { $e.Add("rule $ref does not exist, or this batch deletes it"); $refE = $null } }
                }
                if (@(@($ents) + @($refE | Where-Object { $_ }) | ForEach-Object { $_.Set } | Select-Object -Unique).Count -gt 1) { $e.Add('the rules are in different rule sets') }
                if (-not $e.Count) {
                    $old = @{}; for ($k = 0; $k -lt $sim.Count; $k++) { $old[$sim[$k].Id] = $k + 1 }
                    $moving = @($sim | Where-Object { $ents -contains $_ })
                    foreach ($x in $moving) { [void]$sim.Remove($x) }
                    $at = switch ($to) { 'top' { 0 } 'bottom' { $sim.Count } 'before' { $sim.IndexOf($refE) } 'after' { $sim.IndexOf($refE) + 1 } }
                    $sim.InsertRange($at, [object[]]$moving)
                    $it.changes = @(foreach ($x in $moving) { [ordered]@{ field = "Position of rule $($x.Id)"; before = "$($old[$x.Id])"; after = "$($sim.IndexOf($x) + 1)" } })
                    $valid[$i] = @{ Ids = [int[]]@($ids); To = $to; Ref = $(if ($refE) { [int]$ref } else { 0 }) }
                }
                $counts.move++
            }
            'addvalue' {
                # a value added to a tag type's list IN the batch (the v1 import's missing values): the rules of
                # PUT /api/tagtypes/{ot}/{name}/values (Save-EpsTagValue applies it at commit) - a plain value only, the
                # tag type of this batch's object type; the ops after it may set the value
                $tn = "$($o.tagType)".Trim(); $val = "$($o.value)".Trim(); $desc = "$($o.description)".Trim()
                $it.ruleId = $null; $it.tagType = $tn; $it.value = $val
                $tt = $null
                if ($tn -notmatch '^[A-Za-z][A-Za-z0-9_]{1,59}$') { $e.Add("tag type '$tn' is not a tag type name") }
                else { $tt = $Context.TagTypes["${ObjectType}:$tn"]; if (-not $tt) { $e.Add("tag type '$tn' does not exist for $($ObjectType.ToLowerInvariant())s") } }
                if (-not $val) { $e.Add('give the value') }
                foreach ($x in @((Test-EpsPlainText -Text $val -Max 1024 -What 'the value'), (Test-EpsPlainText -Text $desc -Max 1000 -What 'the description'))) { if ($x) { $e.Add($x) } }
                if ($o.isPattern -eq $true) { $e.Add('a batch adds plain values only - a pattern value is added on the Tag types page') }
                if ($tt -and $val -and -not $e.Count) {
                    $k = "${ObjectType}:$($tt.Name)"; $dk = "$k|$val".ToLowerInvariant()
                    $list = @($Context.Values[$k] | Where-Object { $null -ne $_ })
                    if ($addedValues[$dk]) { $e.Add("the value '$val' of $($tt.Name) is added twice in this batch") }
                    elseif (@($list | Where-Object { [string]::Equals([string]$_.Value, $val, [StringComparison]::OrdinalIgnoreCase) }).Count) { $it.unchanged = $true; $counts.unchanged++ }
                    else {
                        $addedValues[$dk] = $true
                        $Context.Values[$k] = @($list) + @([pscustomobject]@{ ObjectType = $ObjectType; TagType = $tt.Name; Value = $val; IsPattern = $false; Description = $desc })
                        $valid[$i] = @{ TagType = [string]$tt.Name; Value = $val; Description = $desc }
                        $it.changes = @([ordered]@{ field = "$($tt.Name) value"; before = $null; after = $val })
                        $counts.value++
                    }
                }
            }
            default { $e.Add("unknown change '$kind' (create, update, delete, move or addvalue)") }
        }
        $it.errors = @($e)
        if ($e.Count) { $errs.Add("change $($i + 1)$(if ($it.row) { " (row $($it.row))" })$(if ($it.ruleId) { " (rule $($it.ruleId))" }): $($e -join '; ')") }
        $items.Add($it)
    }
    if (-not $errs.Count -and -not ($counts.create + $counts.update + $counts.delete + $counts.move + $counts.value)) { $errs.Add('nothing changes: every row is as the rule already is') }
    # the hints of the RESULT (DESIGN §5.9 - never blocking), for the rules this batch touches
    $final = @(for ($k = 0; $k -lt $sim.Count; $k++) { $c0 = $sim[$k].Card; $cc = [ordered]@{}; foreach ($key in @($c0.Keys)) { $cc[$key] = $c0[$key] }
        $cc.RuleId = $sim[$k].Id; $cc.Order = $k + 1; $cc.ObjectType = $ObjectType; if (-not $cc.RuleSet) { $cc.RuleSet = $script:EpsRuleSet }; $cc })
    $hints = @(Get-EpsRuleHints -Cards $final -Catalog $Context.Catalog -TagTypes $Context.TagTypes) + @(Get-EpsRuleShadowHints -Cards $final -TagTypes $Context.TagTypes)
    $hb = $hints | Group-Object { "$($_.RuleId)" } -AsHashTable -AsString
    foreach ($it in $items) { if ($it.op -in 'delete', 'addvalue') { continue }; foreach ($rid in @("$($it.ruleId)" -split ',')) { if ($hb -and $rid -and $hb[$rid]) { $it.hints = @($it.hints) + @($hb[$rid] | ForEach-Object { "rule $rid`: $($_.Text)" }) } } }
    $parts = @(); if ($counts.update) { $parts += "$($counts.update) changed" }; if ($counts.create) { $parts += "$($counts.create) new" }; if ($counts.delete) { $parts += "$($counts.delete) deleted" }
    if ($counts.move) { $parts += "$($counts.move) move$(if ($counts.move -gt 1) { 's' })" }; if ($counts.value) { $parts += "$($counts.value) tag value$(if ($counts.value -gt 1) { 's' }) added" }; if ($counts.unchanged) { $parts += "$($counts.unchanged) unchanged (left out)" }
    @{ Ok = -not $errs.Count; Errors = @($errs); Items = @($items); Counts = $counts; Summary = $(if ($parts) { $parts -join ', ' } else { 'nothing changes' }); Before = @($before); Valid = $valid; Final = @($final) }
}

function ConvertTo-EpsRuleBatchView {
    # what the page sees of a check (never the validated cards themselves)
    param($Check)
    [ordered]@{ ok = [bool]$Check.Ok; errors = @($Check.Errors); summary = $Check.Summary; counts = $Check.Counts; items = @($Check.Items) }
}

function Invoke-EpsRuleBatch {
    # applies a batch (the ENGINE, from a commit or a Config request): checked again first - a rule someone changed since
    # refuses the whole batch, nothing written - then each change in order through the one-card functions. Returns
    # @{ Result = ok | refused | partial; Applied; Created; Values (the tag values added, TagType=Value); FailedAt; Why; Check }.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, $Ops, [Parameter(Mandatory)][string]$Actor)
    $chk = Test-EpsRuleBatch -ConnectionString $ConnectionString -ObjectType $ObjectType -Ops $Ops
    if (-not $chk.Ok) { return @{ Result = 'refused'; Errors = $chk.Errors; Applied = 0; Check = $chk } }
    $ops = @(@($Ops) | Where-Object { $null -ne $_ }); $applied = 0; $created = [System.Collections.Generic.List[int]]::new(); $lastNew = 0; $values = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $ops.Count; $i++) {
        $o = $ops[$i]; $v = $chk.Valid[$i]; $it = $chk.Items[$i]
        $res = switch ($it.op) {
            'create' {
                $ia = "$($o.insertAfter)".Trim(); $after = if ($ia -eq 'prev') { $lastNew } elseif ($ia -match '^\d{1,9}$') { [int]$ia } else { 0 }
                $s = Save-EpsRuleCard -ConnectionString $ConnectionString -Card $v.Card -InsertAfter $after -Actor $Actor -Source $v.Source
                if ($s.Result -eq 'ok') { $lastNew = [int]$s.RuleId; $created.Add([int]$s.RuleId) }
                $s.Result }
            'update' { if ($it.unchanged) { 'skip' } else { (Save-EpsRuleCard -ConnectionString $ConnectionString -Card $v.Card -RuleId ([int]"$($o.id)") -Expected (ConvertTo-EpsExpectedText $o.expected) -Actor $Actor).Result } }
            'delete' { (Remove-EpsRuleCard -ConnectionString $ConnectionString -ObjectType $ObjectType -RuleId ([int]"$($o.id)") -Expected (ConvertTo-EpsExpectedText $o.expected) -Actor $Actor).Result }
            'move' { (Move-EpsRuleCard -ConnectionString $ConnectionString -ObjectType $ObjectType -Ids $v.Ids -To $v.To -Ref $v.Ref -Actor $Actor).Result }
            # the same function as PUT /api/tagtypes/{ot}/{name}/values: its own journal row (Entity TagValue)
            'addvalue' { if ($it.unchanged) { 'skip' } else {
                $s = Save-EpsTagValue -ConnectionString $ConnectionString -ObjectType $ObjectType -TagType $v.TagType -Body @{ value = $v.Value; description = $v.Description; isPattern = $false } -Actor $Actor
                if ($s.Result -eq 'ok') { $values.Add("$($v.TagType)=$($v.Value)") }
                $s.Result } }
        }
        if ($res -eq 'skip') { continue }
        if ($res -ne 'ok') { return @{ Result = 'partial'; Applied = $applied; FailedAt = $i + 1; Why = "$res"; Created = @($created); Values = @($values); Check = $chk } }
        $applied++
    }
    @{ Result = 'ok'; Applied = $applied; Created = @($created); Values = @($values); Check = $chk }
}

# ---- CSV: the v2 shape (the export) and back ----------------------------------------------------------------------------
function ConvertTo-EpsRuleCsvTable {
    # the rules in run order, one row per rule, its conditions as Condition<n>Type / Condition<n>Target column pairs
    param($Cards, [ValidateSet('User', 'Device')][string]$ObjectType)
    $max = 3; foreach ($c in @($Cards)) { $max = [Math]::Max($max, @($c.Conditions).Count) }
    $cols = @('RuleId', 'Order', 'Enabled') + $(if ($ObjectType -eq 'User') { @('Persona', 'TagType', 'TagValueAD', 'TagValueCloud') } else { @('TagType', 'TagValue') }) + @('Notes', 'Source') + @(1..$max | ForEach-Object { "Condition${_}Type"; "Condition${_}Target" })
    $n = 0
    $rows = foreach ($c in @($Cards)) {
        $n++
        $o = [ordered]@{ RuleId = $c.RuleId; Order = $n; Enabled = $(if ($c.Enabled -eq $false) { 'FALSE' } else { 'TRUE' }) }
        if ($ObjectType -eq 'User') { $o.Persona = $c.Persona; $o.TagType = $c.TagType; $o.TagValueAD = $c.TagValueAD; $o.TagValueCloud = $c.TagValueCloud } else { $o.TagType = $c.TagType; $o.TagValue = $c.TagValue }
        $o.Notes = $c.Notes; $o.Source = $c.Source
        $k = 0; foreach ($x in @($c.Conditions)) { $k++; $o["Condition${k}Type"] = $x.ConditionType; $o["Condition${k}Target"] = $x.Target }
        [pscustomobject]$o
    }
    @{ Columns = $cols; Rows = @($rows) }
}

function ConvertFrom-EpsCsvCell {
    # undoes the export's Excel defuse (a cell that starts with = + - @ was written with a leading ')
    param($Value)
    $s = if ($null -eq $Value) { '' } else { "$Value".Trim() }
    if ($s -match "^'[=+\-@]") { $s = $s.Substring(1) }
    $s
}

function ConvertFrom-EpsRuleCsv {
    # the v2 CSV (the export's shape, comma or semicolon) -> a batch: a row with a RuleId updates that rule, a row without
    # one is a new rule placed after the row above it (after the last rule when it is the first row); -DeleteMissing
    # deletes the rules the file leaves out. Returns @{ Ops; Errors; Rows }.
    param([string]$Text, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [object[]]$Current, [switch]$DeleteMissing)
    $err = [System.Collections.Generic.List[string]]::new(); $ops = [System.Collections.Generic.List[object]]::new()
    $t = "$Text".TrimStart([char]0xFEFF)
    if (-not $t.Trim()) { return @{ Ops = @(); Errors = @('the file is empty'); Rows = 0 } }
    $head = ($t -split "`r?`n", 2)[0]
    $delim = if ($head -match ';' -and $head -notmatch ',') { ';' } else { ',' }
    $rows = @($t | ConvertFrom-Csv -Delimiter $delim)
    if (-not $rows.Count) { return @{ Ops = @(); Errors = @('the file has a header but no rule rows'); Rows = 0 } }
    $names = @($rows[0].PSObject.Properties.Name)
    $known = @('RuleId', 'Order', 'Enabled', 'TagType', 'Notes', 'Source') + $(if ($ObjectType -eq 'User') { @('Persona', 'TagValueAD', 'TagValueCloud') } else { @('TagValue') })
    $unknown = @($names | Where-Object { $_ -and $known -notcontains $_ -and $_ -notmatch '^(?i)Condition\d{1,2}(Type|Target)$' })
    if ($unknown.Count) { return @{ Ops = @(); Errors = @("unknown column(s) $($unknown -join ', ') - this is not a $($ObjectType.ToLowerInvariant()) rules export (columns: $($known -join ', '), Condition1Type, Condition1Target, ...)"); Rows = $rows.Count } }
    foreach ($req in @('TagType') + $(if ($ObjectType -eq 'User') { @('Persona') } else { @() })) { if ($names -notcontains $req) { return @{ Ops = @(); Errors = @("the column $req is missing"); Rows = $rows.Count } } }
    $condN = @($names | ForEach-Object { if ($_ -match '^(?i)Condition(\d{1,2})(Type|Target)$') { [int]$Matches[1] } } | Sort-Object -Unique)
    $byId = @{}; foreach ($c in @($Current)) { $byId["$($c.RuleId)"] = $c }
    $seen = @{}; $line = 1; $prev = $null
    foreach ($r in $rows) {
        $line++
        if (-not (@($names | ForEach-Object { "$($r.$_)" }) -join '').Trim()) { continue }   # an empty row Excel left
        $rid = ConvertFrom-EpsCsvCell $r.RuleId; $en = ConvertFrom-EpsCsvCell $r.Enabled; $enabled = $true
        if ($en) { if ($en -match '^(?i)(true|1|yes|on)$') { $enabled = $true } elseif ($en -match '^(?i)(false|0|no|off)$') { $enabled = $false } else { $err.Add("row ${line}: Enabled is TRUE or FALSE, not '$en'"); continue } }
        $bad = $false
        $conds = @(foreach ($k in $condN) { $ct = ConvertFrom-EpsCsvCell $r."Condition${k}Type"; $tg = ConvertFrom-EpsCsvCell $r."Condition${k}Target"
            if ($ct) { [ordered]@{ conditionType = $ct; target = $tg } } elseif ($tg) { $err.Add("row ${line}: Condition${k}Target without a Condition${k}Type"); $bad = $true } })
        if ($bad) { continue }
        $body = [ordered]@{ tagType = (ConvertFrom-EpsCsvCell $r.TagType); enabled = $enabled; notes = (ConvertFrom-EpsCsvCell $r.Notes); conditions = $conds }
        if ($ObjectType -eq 'User') { $body.persona = ConvertFrom-EpsCsvCell $r.Persona; $body.tagValueAD = ConvertFrom-EpsCsvCell $r.TagValueAD; $body.tagValueCloud = ConvertFrom-EpsCsvCell $r.TagValueCloud } else { $body.tagValue = ConvertFrom-EpsCsvCell $r.TagValue }
        if ($rid) {
            if ($rid -notmatch '^\d{1,9}$' -or -not $byId[$rid]) { $err.Add("row ${line}: rule '$rid' does not exist (deleted?) - clear RuleId to add the row as a new rule"); continue }
            if ($seen[$rid]) { $err.Add("row ${line}: rule $rid is in the file twice (rows $($seen[$rid]) and $line)"); continue }
            $seen[$rid] = $line
            $ops.Add([ordered]@{ op = 'update'; id = [int]$rid; expected = (ConvertTo-EpsWebTime $byId[$rid].UpdatedAtUtc); rule = $body; row = $line })
            $prev = $rid
        } else {
            $ops.Add([ordered]@{ op = 'create'; rule = $body; insertAfter = $(if ($prev -eq 'new') { 'prev' } elseif ($prev) { [int]$prev } else { 0 }); row = $line })
            $prev = 'new'
        }
    }
    if ($DeleteMissing) { foreach ($c in @($Current)) { if (-not $seen["$($c.RuleId)"]) { $ops.Add([ordered]@{ op = 'delete'; id = [int]$c.RuleId; expected = (ConvertTo-EpsWebTime $c.UpdatedAtUtc) }) } } }
    @{ Ops = @($ops); Errors = @($err); Rows = $rows.Count }
}

# ---- the v1 CSV, read from TEXT (the GUI's upload; tools/setup reads the files) ------------------------------------------
function ConvertFrom-EpsV1CsvText {
    # v1's Import-Csv -Delimiter ';' on text, rows without the key column dropped, each row naming its file and line
    param([string]$Text, [string]$FileName, [string]$KeyColumn)
    $t = "$Text".TrimStart([char]0xFEFF); if (-not $t.Trim()) { return @() }
    $line = 1
    @(foreach ($r in @($t | ConvertFrom-Csv -Delimiter ';')) {
        $line++
        if ([string]::IsNullOrEmpty($r.$KeyColumn)) { continue }
        $r | Add-Member -NotePropertyName V1Ref -NotePropertyValue "${FileName}:$line" -PassThru
    })
}

function ConvertFrom-EpsV1Upload {
    # the GUI's v1 import: the customer's Identity_Tagging*.csv / Device_Tagging*.csv (never a demo file - owner
    # 2026-10-29) -> the v1 cards (v1's grouping 1:1, ConvertTo-EpsRuleCards), their hints, the values this install's tag
    # types do not list yet, and a batch that adds them (append, or replace the rules an earlier v1 import made)
    param([object[]]$Files, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)]$Context, [object[]]$Current, [ValidateSet('append', 'replace-imported')][string]$Mode = 'append', [switch]$AddValues)
    $files =@(@($Files) | Where-Object { $null -ne $_ })
    if (-not $files.Count) { return @{ Error = 'choose the v1 CSV file(s) to read' } }
    if ($files.Count -gt 4) { return @{ Error = 'at most 4 files at a time' } }
    $want = if ($ObjectType -eq 'User') { 'Identity_Tagging*.csv' } else { 'Device_Tagging*.csv' }
    $pat = if ($ObjectType -eq 'User') { '^(?i)Identity_Tagging[A-Za-z0-9_ ()-]*\.csv$' } else { '^(?i)Device_Tagging[A-Za-z0-9_ ()-]*\.csv$' }
    foreach ($f in $files) {
        $nm = "$($f.name)"
        if ($nm -match '(?i)demo') { return @{ Error = "$nm is demo material - it is never read" } }
        if ($nm -notmatch $pat) { return @{ Error = "'$nm' is not a v1 $want file" } }
    }
    # v1's order: the main file first, then the AccountInfo file appended after it
    $sorted = @($files | Sort-Object { if ("$($_.name)" -match '^(?i)(Identity|Device)_Tagging\.csv$') { 0 } else { 1 } }, { "$($_.name)" })
    $key = if ($ObjectType -eq 'User') { 'Persona' } else { 'TagType' }
    $rows = @(foreach ($f in $sorted) { ConvertFrom-EpsV1CsvText -Text "$($f.text)" -FileName "$($f.name)" -KeyColumn $key })
    if (-not $rows.Count) { return @{ Error = 'no rule rows in the file(s) (a v1 file is ; separated, with its header line)' } }
    $req = if ($ObjectType -eq 'User') { 'Persona', 'TagType', 'TagValueAD', 'TagValueCloud', 'ConditionType', 'Target' } else { 'TagType', 'TagValue', 'ConditionType', 'Target' }
    $miss = @($req | Where-Object { @($rows[0].PSObject.Properties.Name) -notcontains $_ })
    if ($miss.Count) { return @{ Error = "the v1 column(s) $($miss -join ', ') are missing - is it a $want file?" } }
    $hints = [System.Collections.Generic.List[string]]::new()
    if ($ObjectType -eq 'User') {
        $vm = Resolve-EpsV1ValueModes -Rows $rows -TagTypes $Context.TagTypes -ObjectType 'User'
        foreach ($h in $vm.Hints) { $hints.Add($h.Message) }
        foreach ($k in $vm.Modes.Keys) { $tt = $Context.TagTypes["User:$k"]; if ($tt -and "$($tt.ValueMode)" -ne $vm.Modes[$k]) { $hints.Add("v1 sets ValueMode $($vm.Modes[$k]) for $k; this install uses $($tt.ValueMode) - change it on the Tag types page if v1 is right") } }
    }
    $cards = @(ConvertTo-EpsRuleCards -Rows $rows -ObjectType $ObjectType)
    if ($ObjectType -eq 'Device') { foreach ($c in $cards) { $c.TagValue = $c.TagValueAD } }
    foreach ($h in @(Get-EpsRuleHints -Cards $cards -Catalog $Context.Catalog -TagTypes $Context.TagTypes)) { $hints.Add($h.Message) }
    # a value the rules set that this install's tag type does not list: the save refuses it - add it on the Tag types page
    $need = [ordered]@{}
    foreach ($c in $cards) {
        $tt = $Context.TagTypes["${ObjectType}:$($c.TagType)"]; if (-not $tt) { continue }
        $vals = $Context.Values["${ObjectType}:$($tt.Name)"]
        foreach ($v in @(@($c.TagValueAD, $c.TagValueCloud) | Where-Object { $_ } | Select-Object -Unique)) {
            if (-not (Test-EpsTagValueAllowed -Values $vals -Value $v)) { $k = "$($tt.Name)|$v".ToLowerInvariant(); if (-not $need.Contains($k)) { $need[$k] = [ordered]@{ tagType = $tt.Name; value = $v; rules = 0 } }; $need[$k].rules++ }
        }
    }
    $ops = [System.Collections.Generic.List[object]]::new()
    # -AddValues (RULES-GRID): the values above are added to their tag types IN the same batch, before the rules that set
    # them - only these values (what the import needs), plain values (a pattern stays as the install has it)
    if ($AddValues) { foreach ($x in $need.Values) { $ops.Add([ordered]@{ op = 'addvalue'; tagType = $x.tagType; value = $x.value; description = 'added by the v1 import' }) } }
    if ($Mode -eq 'replace-imported') { foreach ($c in @(@($Current) | Where-Object { "$($_.Source)" -eq 'v1-import' })) { $ops.Add([ordered]@{ op = 'delete'; id = [int]$c.RuleId; expected = (ConvertTo-EpsWebTime $c.UpdatedAtUtc) }) } }
    $first = $true
    foreach ($c in $cards) {
        $b = ConvertTo-EpsRuleBody -Card $c -ObjectType $ObjectType
        $b.notes = "v1: $(@($c.V1Rows) -join ', ')"; if ($b.notes.Length -gt 1000) { $b.notes = $b.notes.Substring(0, 997) + '...' }
        $ops.Add([ordered]@{ op = 'create'; rule = $b; insertAfter = $(if ($first) { 0 } else { 'prev' }); source = 'v1-import'; row = "$(@($c.V1Rows)[0])" })
        $first = $false
    }
    @{ Ops = @($ops); Info = [ordered]@{ files = @($sorted | ForEach-Object { "$($_.name)" }); rows = $rows.Count; cards = $cards.Count; mode = $Mode; hints = @($hints); missingValues = @($need.Values); addValues = [bool]$AddValues } }
}

# ---- v1 rows -> cards (moved here from EPS-V1Import in 2.0.8: the setup import AND the GUI's v1 upload use them) ----
function ConvertTo-EpsRuleCards {
    # v1 rows -> rule cards. The grouping is v1's exactly: Persona|TagType|TagValueAD|TagValueCloud|ConditionGroup,
    # case-insensitive, first-appearance order between and inside cards; a blank ConditionGroup is a card of its own.
    param([object[]]$Rows, [ValidateSet('User', 'Device')][string]$ObjectType, [string]$Source = 'v1-import')
    $cards = [ordered]@{}; $n = 0
    foreach ($r in $Rows) {
        $n++
        $vAD = if ($ObjectType -eq 'User') { [string]$r.TagValueAD } else { [string]$r.TagValue }
        $vCloud = if ($ObjectType -eq 'User') { [string]$r.TagValueCloud } else { [string]$r.TagValue }
        $grp = [string]$r.ConditionGroup
        $key = if ([string]::IsNullOrEmpty($grp)) { "#row$n" } else { ('{0}|{1}|{2}|{3}|{4}' -f $r.Persona, $r.TagType, $vAD, $vCloud, $grp).ToLowerInvariant() }
        if (-not $cards.Contains($key)) {
            $cards[$key] = @{
                Order = 10 * ($cards.Count + 1); ObjectType = $ObjectType
                Persona = $(if ($ObjectType -eq 'User') { [string]$r.Persona } else { [string]$r.TagType })
                TagType = [string]$r.TagType; TagValueAD = $vAD; TagValueCloud = $vCloud; Enabled = $true; Source = $Source
                V1ConditionGroup = $(if ($grp) { $grp }); V1Rows = [System.Collections.Generic.List[string]]::new()
                Conditions = [System.Collections.Generic.List[object]]::new()
            }
        }
        $c = $cards[$key]
        $ref = if ($r.V1Ref) { [string]$r.V1Ref } else { "row $n" }
        $c.V1Rows.Add($ref)
        $c.Conditions.Add(@{ ConditionType = [string]$r.ConditionType; Target = [string]$r.Target; V1Row = $ref; V1ValueMode = [string]$r.ValueMode })
    }
    $i = 0
    foreach ($c in $cards.Values) { $i++; $c.RuleId = "$($ObjectType.Substring(0,1))$i"; $c }
}

function Resolve-EpsV1ValueModes {
    # v1's ValueMode column: per TAG TYPE, the first non-blank value wins; unknown values, Multiple on a single-valued
    # type, and disagreeing rows are ignored with a hint.
    param([object[]]$Rows, [hashtable]$TagTypes, [string]$ObjectType = 'User')
    $modes = @{}; $hints = [System.Collections.Generic.List[object]]::new(); $n = 0
    foreach ($r in $Rows) {
        $n++
        $ref = if ($r.V1Ref) { [string]$r.V1Ref } else { "row $n" }
        $m = ([string]$r.ValueMode).Trim()
        if (-not $m) { continue }
        $norm = @('First', 'Last', 'Multiple') | Where-Object { $_ -eq $m }
        $tt = $TagTypes["${ObjectType}:$($r.TagType)"]
        if (-not $norm) { $hints.Add(@{ Code = 'ValueModeUnknown'; Row = $n; Message = "${ref}: ValueMode '$m' is unknown (First, Last, Multiple) - ignored" }); continue }
        if ($norm -eq 'Multiple' -and -not ($tt -and $tt.AllowMultiple)) { $hints.Add(@{ Code = 'MultipleNotAllowed'; Row = $n; Message = "${ref}: ValueMode Multiple is not allowed for tag type '$($r.TagType)' (single-valued: Conditional Access reads it) - ignored" }); continue }
        if (-not $modes.ContainsKey($r.TagType)) { $modes[$r.TagType] = $norm }
        elseif ($modes[$r.TagType] -ne $norm) { $hints.Add(@{ Code = 'ValueModeConflict'; Row = $n; Message = "${ref}: ValueMode '$norm' conflicts with '$($modes[$r.TagType])' already set for '$($r.TagType)' - keeping '$($modes[$r.TagType])'" }) }
    }
    @{ Modes = $modes; Hints = $hints }
}

# ---- tag types and their values (DESIGN §5.6a) ----------------------------------------------------------------------
function Get-EpsTagTypeUse {
    # the rules that use a tag type (and which value), for the broken-reference guard and the page's "used by"
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$TagType)
    $q = if ($ObjectType -eq 'User') { 'SELECT RuleId, Persona, TagValueAD, TagValueCloud FROM eps.UserTagRule WHERE TagType = @t' } else { 'SELECT RuleId, TagType AS Persona, TagValue AS TagValueAD, TagValue AS TagValueCloud FROM eps.DeviceTagRule WHERE TagType = @t' }
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ t = $TagType } -Query $q)
}

function ConvertTo-EpsTagType {
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Body)
    $err = [System.Collections.Generic.List[string]]::new()
    $s = { param($v) if ($null -eq $v) { '' } else { "$v".Trim() } }
    $t = [ordered]@{ ObjectType = $ObjectType; Name = $Name; Description = (& $s $Body.description); Attribute = (& $s $Body.attribute); ValueMode = (& $s $Body.valueMode)
                     FallbackAD = (& $s $Body.fallbackAD); FallbackCloud = (& $s $Body.fallbackCloud); Enabled = $(if ($null -eq $Body.enabled) { $true } else { [bool]$Body.enabled }); AllowMultiple = [bool]$Body.allowMultiple }
    if ($Name -notmatch '^[A-Za-z][A-Za-z0-9_]{1,59}$') { $err.Add('the name: letters, digits and _ (2-60), starting with a letter') }
    if ($t.Attribute -notmatch '^extensionAttribute([1-9]|1[0-5])$') { $err.Add('the attribute must be extensionAttribute1 ... extensionAttribute15') }
    if (-not $t.ValueMode) { $t.ValueMode = 'First' }
    $vm = @('First', 'Last', 'Multiple') | Where-Object { $_ -eq $t.ValueMode }
    if (-not $vm) { $err.Add('the value mode is First, Last or Multiple') } else { $t.ValueMode = @($vm)[0] }
    if ($t.ValueMode -eq 'Multiple' -and -not $t.AllowMultiple) { $err.Add('Multiple needs "allow several values" (a single-valued tag is what Conditional Access reads)') }
    foreach ($f in @(@('Description', 1000), @('FallbackAD', 1024), @('FallbackCloud', 1024))) { $e = Test-EpsPlainText -Text $t[$f[0]] -Max $f[1] -What "the $($f[0])"; if ($e) { $err.Add($e) } }
    @{ Ok = -not $err.Count; TagType = $t; Errors = @($err) }
}

function Save-EpsTagType {
    # create or update; the attribute of a type that rules use is not moved here (DESIGN §5.6: a planned move job)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$TagType, [string]$Expected, [Parameter(Mandatory)][string]$Actor)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $TagType.ObjectType; n = $TagType.Name } -Query 'SELECT * FROM eps.TagType WHERE ObjectType = @o AND Name = @n')[0]
    if ($cur -and $Expected -and (ConvertTo-EpsWebTime $cur.UpdatedAtUtc) -ne $Expected) { return @{ Result = 'conflict' } }
    if (-not $cur -and $Expected) { return @{ Result = 'conflict' } }
    $other = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $TagType.ObjectType; n = $TagType.Name; a = $TagType.Attribute } -Query 'SELECT Name FROM eps.TagType WHERE ObjectType = @o AND Attribute = @a AND Name <> @n')[0]
    if ($other) { return @{ Result = 'refused'; Text = "$($TagType.Attribute) is already the attribute of tag type '$($other.Name)' - two tag types on one attribute would overwrite each other" } }
    if ($cur -and $cur.Attribute -ne $TagType.Attribute -and @(Get-EpsTagTypeUse -ConnectionString $ConnectionString -ObjectType $TagType.ObjectType -TagType $TagType.Name).Count) {
        return @{ Result = 'refused'; Text = "rules use '$($TagType.Name)': moving its tags from $($cur.Attribute) to $($TagType.Attribute) is a planned move (written, verified, then the old one cleared) - not a save" } }
    $snap = { param($x) if ($x) { [ordered]@{ name = $x.Name; description = $x.Description; attribute = $x.Attribute; valueMode = $x.ValueMode; allowMultiple = [bool]$x.AllowMultiple; fallbackAD = $x.FallbackAD; fallbackCloud = $x.FallbackCloud; enabled = [bool]$x.Enabled } | ConvertTo-Json -Compress } }
    $after = & $snap ([pscustomobject]$TagType)
    $p = @{ o = $TagType.ObjectType; n = $TagType.Name; d = $(if ($TagType.Description) { $TagType.Description }); a = $TagType.Attribute; m = $TagType.ValueMode; mu = [bool]$TagType.AllowMultiple
            fa = $(if ($TagType.FallbackAD) { $TagType.FallbackAD }); fc = $(if ($TagType.FallbackCloud) { $TagType.FallbackCloud }); e = [bool]$TagType.Enabled; v0 = $(if ($cur) { $cur.UpdatedAtUtc }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'TagType' -Key "$($TagType.ObjectType):$($TagType.Name)" -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before (& $snap $cur) -After $after)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
IF (@v0 IS NULL AND EXISTS (SELECT 1 FROM eps.TagType WITH (UPDLOCK, HOLDLOCK) WHERE ObjectType = @o AND Name = @n))
   OR (@v0 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM eps.TagType WITH (UPDLOCK, HOLDLOCK) WHERE ObjectType = @o AND Name = @n AND UpdatedAtUtc = @v0))
BEGIN ROLLBACK; SELECT 'conflict' AS Result; RETURN; END
MERGE eps.TagType AS d USING (SELECT @o AS ObjectType, @n AS Name) AS s ON d.ObjectType = s.ObjectType AND d.Name = s.Name WHEN MATCHED THEN UPDATE SET Description = @d, Attribute = @a, ValueMode = @m, AllowMultiple = @mu, FallbackAD = @fa, FallbackCloud = @fc, Enabled = @e, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ObjectType, Description, Attribute, ValueMode, AllowMultiple, FallbackAD, FallbackCloud, Enabled, Shipped) VALUES (@n, @o, @d, @a, @m, @mu, @fa, @fc, @e, 0);
$(Get-EpsJournalSql)
COMMIT;
SELECT 'ok' AS Result;
"@)[0]
    @{ Result = $r.Result; Before = (& $snap $cur); After = $after; Created = -not $cur }
}

function Remove-EpsTagType {
    # only a type of the customer's own, with no rule and no value left (values are removed first, each one guarded)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Actor)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType; n = $Name } -Query 'SELECT * FROM eps.TagType WHERE ObjectType = @o AND Name = @n')[0]
    if (-not $cur) { return @{ Result = 'missing' } }
    if ($cur.Shipped) { return @{ Result = 'refused'; Text = "'$Name' is shipped with the product - switch it off instead" } }
    $use = @(Get-EpsTagTypeUse -ConnectionString $ConnectionString -ObjectType $ObjectType -TagType $Name)
    if ($use.Count) { return @{ Result = 'refused'; Text = "$($use.Count) rule(s) use '$Name' (rule $(@($use | Select-Object -First 5 | ForEach-Object RuleId) -join ', ')) - change or delete them first" } }
    $p = @{ o = $ObjectType; n = $Name } + (New-EpsJournalParameters -Actor $Actor -Entity 'TagType' -Key "${ObjectType}:$Name" -Action 'Delete' -Before (@{ name = $Name; attribute = $cur.Attribute } | ConvertTo-Json -Compress) -After $null)
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query @"
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM eps.TagValue WITH (UPDLOCK, HOLDLOCK) WHERE ObjectType = @o AND TagType = @n)
BEGIN ROLLBACK; SELECT 'hasValues' AS Result; RETURN; END
DELETE FROM eps.TagType WHERE ObjectType = @o AND Name = @n;
$(Get-EpsJournalSql)
COMMIT;
SELECT 'ok' AS Result;
"@)[0]
    if ($r.Result -eq 'hasValues') { return @{ Result = 'refused'; Text = "'$Name' still has allowed values - remove them first" } }
    @{ Result = $r.Result }
}

function Save-EpsTagValue {
    # add a value (or change its description / pattern flag)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$TagType, [Parameter(Mandatory)]$Body, [Parameter(Mandatory)][string]$Actor)
    $v = "$($Body.value)".Trim(); $d = "$($Body.description)".Trim()
    $e = (Test-EpsPlainText -Text $v -Max 1024 -What 'the value'), (Test-EpsPlainText -Text $d -Max 1000 -What 'the description') | Where-Object { $_ }
    if (-not $v) { $e = @('give the value') + @($e) }
    if ($e) { return @{ Result = 'invalid'; Text = (@($e) -join '; ') } }
    if (-not [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $ObjectType; t = $TagType } -Query 'SELECT COUNT(*) FROM eps.TagType WHERE ObjectType = @o AND Name = @t')) { return @{ Result = 'missing' } }
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType; t = $TagType; v = $v } -Query 'SELECT Value, IsPattern, Description FROM eps.TagValue WHERE ObjectType = @o AND TagType = @t AND Value = @v')[0]
    $after = @{ value = $v; isPattern = [bool]$Body.isPattern; description = $d } | ConvertTo-Json -Compress
    $p = @{ o = $ObjectType; t = $TagType; v = $v; ip = [bool]$Body.isPattern; d = $(if ($d) { $d }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'TagValue' -Key "${ObjectType}:${TagType}:$v" -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before $(if ($cur) { @{ value = $cur.Value; isPattern = [bool]$cur.IsPattern; description = $cur.Description } | ConvertTo-Json -Compress }) -After $after)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON;
BEGIN TRAN;
MERGE eps.TagValue AS x USING (SELECT @o AS ObjectType, @t AS TagType, @v AS Value) AS s ON x.ObjectType = s.ObjectType AND x.TagType = s.TagType AND x.Value = s.Value WHEN MATCHED THEN UPDATE SET IsPattern = @ip, Description = @d WHEN NOT MATCHED THEN INSERT (ObjectType, TagType, Value, IsPattern, Description) VALUES (@o, @t, @v, @ip, @d);
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Created = -not $cur; Value = $v; After = $after }
}

function Remove-EpsTagValue {
    # the broken-reference guard: a value a rule sets cannot be removed (the rule would set a value nobody allows)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$TagType, [Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Actor)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType; t = $TagType; v = $Value } -Query 'SELECT Value, IsPattern, Description FROM eps.TagValue WHERE ObjectType = @o AND TagType = @t AND Value = @v')[0]
    if (-not $cur) { return @{ Result = 'missing' } }
    # ADMIN-WALK-2 N5: a value the tag type sets as its FALLBACK (what most objects carry) is in use - never removable
    $tt = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType; t = $TagType } -Query 'SELECT FallbackAD, FallbackCloud FROM eps.TagType WHERE ObjectType = @o AND Name = @t')[0]
    $fb = @(foreach ($k in 'FallbackAD', 'FallbackCloud') { if ($tt -and [string]::Equals("$($tt.$k)", $Value, 'OrdinalIgnoreCase')) { $(if ($k -eq 'FallbackAD') { 'AD-synced' } else { 'cloud' }) } })
    if ($fb.Count) { return @{ Result = 'fallback'; Text = "'$Value' is the $($fb -join ' and ') fallback of $TagType - every object no rule decides gets it. Change the fallback (Edit the tag type) first." } }
    $use = @(Get-EpsTagTypeUse -ConnectionString $ConnectionString -ObjectType $ObjectType -TagType $TagType | Where-Object { [string]::Equals("$($_.TagValueAD)", $Value, 'OrdinalIgnoreCase') -or [string]::Equals("$($_.TagValueCloud)", $Value, 'OrdinalIgnoreCase') })
    if ($use.Count) { return @{ Result = 'refused'; Text = "$($use.Count) rule(s) set '$Value' (rule $(@($use | Select-Object -First 5 | ForEach-Object RuleId) -join ', ')) - change them first. Dynamic groups and Conditional Access policies that read this value are not checked here: look before you remove it." } }
    $p = @{ o = $ObjectType; t = $TagType; v = $Value } + (New-EpsJournalParameters -Actor $Actor -Entity 'TagValue' -Key "${ObjectType}:${TagType}:$Value" -Action 'Delete' -Before (@{ value = $cur.Value; isPattern = [bool]$cur.IsPattern; description = $cur.Description } | ConvertTo-Json -Compress) -After $null)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; DELETE FROM eps.TagValue WHERE ObjectType = @o AND TagType = @t AND Value = @v; $(Get-EpsJournalSql) COMMIT;")
    @{ Result = 'ok'; Before = $cur }
}

# ---- the customer's own property condition types (DESIGN §5.6b kind 1: data, no code) -------------------------------
function Save-EpsConditionType {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Body, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Actor)
    $err = [System.Collections.Generic.List[string]]::new()
    $prop = "$($Body.property)".Trim(); $op = "$($Body.operator)".Trim(); $g = "$($Body.guard)".Trim(); $d = "$($Body.description)".Trim()
    if (-not $g) { $g = 'none' }
    if ($Id -notmatch '^[A-Za-z][A-Za-z0-9_]{2,99}$') { $err.Add('the id: letters, digits and _ (3-100), starting with a letter') }
    $shipped = $Context.Catalog["${ObjectType}:$Id"]
    if ($shipped -and $shipped.Shipped) { $err.Add("'$Id' is a shipped condition type - pick another id") }
    if ($prop -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){0,3}$' -or $prop.Length -gt 200) { $err.Add('the property: a Graph property path, e.g. department or employeeOrgData.division') }
    $ops = @('like', 'notlike', 'equals', 'boolMatch', 'boolEquals', 'contains', 'notcontains') | Where-Object { $_ -eq $op }
    if (-not $ops) { $err.Add('the operator: like, notlike, equals, boolMatch, boolEquals, contains or notcontains') } else { $op = @($ops)[0] }
    $gs = @('none', 'notNull', 'notEmpty', 'emptyMatches') | Where-Object { $_ -eq $g }
    if (-not $gs) { $err.Add('the empty-value rule: none, notNull, notEmpty or emptyMatches') } else { $g = @($gs)[0] }
    $e = Test-EpsPlainText -Text $d -Max 1000 -What 'the description'; if ($e) { $err.Add($e) }
    if ($err.Count) { return @{ Result = 'invalid'; Text = ($err -join '; ') } }
    $cur = @($Context.Custom | Where-Object { $_.ObjectType -eq $ObjectType -and $_.Id -eq $Id })[0]
    $snap = { param($x) if ($x) { [ordered]@{ id = $x.Id; property = $x.Property; operator = $x.Operator; guard = $x.Guard; description = $x.Description; enabled = [bool]$x.Enabled } | ConvertTo-Json -Compress } }
    $after = & $snap ([pscustomobject]@{ Id = $Id; Property = $prop; Operator = $op; Guard = $g; Description = $d; Enabled = $(if ($null -eq $Body.enabled) { $true } else { [bool]$Body.enabled }) })
    $p = @{ o = $ObjectType; i = $Id; pr = $prop; op = $op; g = $g; d = $(if ($d) { $d }); e = $(if ($null -eq $Body.enabled) { $true } else { [bool]$Body.enabled }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'ConditionType' -Key "${ObjectType}:$Id" -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before (& $snap $cur) -After $after)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON;
BEGIN TRAN;
MERGE eps.ConditionType AS x USING (SELECT @o AS ObjectType, @i AS Id) AS s ON x.ObjectType = s.ObjectType AND x.Id = s.Id WHEN MATCHED THEN UPDATE SET Property = @pr, Operator = @op, Guard = @g, Description = @d, Enabled = @e WHEN NOT MATCHED THEN INSERT (Id, ObjectType, Property, Operator, Guard, Description, Enabled) VALUES (@i, @o, @pr, @op, @g, @d, @e);
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Created = -not $cur; Before = (& $snap $cur); After = $after }
}

function Remove-EpsConditionType {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Actor)
    $t = Get-EpsRuleTable $ObjectType
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType; i = $Id } -Query 'SELECT * FROM eps.ConditionType WHERE ObjectType = @o AND Id = @i')[0]
    if (-not $cur) { return @{ Result = 'missing' } }
    $use = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ i = $Id } -Query "SELECT DISTINCT RuleId FROM eps.${t}Condition WHERE ConditionType = @i")
    if ($use.Count) { return @{ Result = 'refused'; Text = "$($use.Count) rule(s) use '$Id' (rule $(@($use | Select-Object -First 5 | ForEach-Object RuleId) -join ', ')) - change them first, or switch the condition type off" } }
    $p = @{ o = $ObjectType; i = $Id } + (New-EpsJournalParameters -Actor $Actor -Entity 'ConditionType' -Key "${ObjectType}:$Id" -Action 'Delete' -Before (@{ id = $Id; property = $cur.Property; operator = $cur.Operator } | ConvertTo-Json -Compress) -After $null)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; DELETE FROM eps.ConditionType WHERE ObjectType = @o AND Id = @i; $(Get-EpsJournalSql) COMMIT;")
    @{ Result = 'ok' }
}

# ---- scopes (DESIGN §5.8): test on one user or a subset -------------------------------------------------------------
function ConvertTo-EpsScope {
    # the scopes the engine runs (Get-EpsScopedObjects): Objects (ids / UPNs / names), Filter (a property pattern), and
    # since TAG-TEST (2.0.82) Group (the direct members of up to 5 Entra groups, by name - the engine reads them) and OU
    # (users whose on-premises distinguished name is in one of up to 5 OUs - AD-synced users carry it in Entra)
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, $Body)
    if ($null -eq $Body) { return @{ Ok = $true; Scope = $null } }
    $kind = "$($Body.kind)"
    if ($kind -eq 'Everyone' -or -not $kind) { return @{ Ok = $true; Scope = $null } }
    if ($kind -eq 'Objects') {
        $vals = [System.Collections.Generic.List[string]]::new(); $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($v in @($Body.values)) { $x = "$v".Trim(); if (-not $x) { continue }; if (Test-EpsPlainText -Text $x -Max 320 -What 'x') { return @{ Ok = $false; Error = 'an object has a control character or is too long' } }; if ($seen.Add($x)) { $vals.Add($x) } }
        if (-not $vals.Count) { return @{ Ok = $false; Error = 'name at least one object (object id, UPN or display name)' } }
        if ($vals.Count -gt 1000) { return @{ Ok = $false; Error = 'at most 1,000 objects in a scope (use a filter for more)' } }
        return @{ Ok = $true; Scope = [ordered]@{ Kind = 'Objects'; Values = @($vals) } }
    }
    if ($kind -eq 'Filter') {
        $prop = "$($Body.property)".Trim(); $pat = "$($Body.pattern)".Trim()
        if ($prop -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){0,3}$') { return @{ Ok = $false; Error = 'the filter property: a property path, e.g. userPrincipalName or department' } }
        if (-not $pat -or (Test-EpsPlainText -Text $pat -Max 400 -What 'x')) { return @{ Ok = $false; Error = 'the filter pattern, e.g. *@pilot.contoso.com' } }
        if ($pat -match '^\*+$') { return @{ Ok = $false; Error = 'a filter of only * is everyone - run it without a scope' } }
        return @{ Ok = $true; Scope = [ordered]@{ Kind = 'Filter'; Property = $prop; Pattern = $pat } }
    }
    if ($kind -in 'Group', 'OU') {
        if ($kind -eq 'OU' -and $ObjectType -ne 'User') { return @{ Ok = $false; Error = 'an OU scope is for users (an AD-synced user carries its OU); for devices use a list, a filter or a group' } }
        $vals = [System.Collections.Generic.List[string]]::new(); $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($v in @($Body.values)) {
            $x = "$v".Trim(); if (-not $x) { continue }
            if (Test-EpsPlainText -Text $x -Max $(if ($kind -eq 'OU') { 1024 } else { 256 }) -What 'x') { return @{ Ok = $false; Error = "a $(if ($kind -eq 'OU') { 'OU' } else { 'group name' }) has a control character or is too long" } }
            if ($kind -eq 'OU' -and $x -notmatch '^(OU|CN)=[^,]+(,(OU|CN)=[^,]+)*,DC=[^,]+(,DC=[^,]+)*$') { return @{ Ok = $false; Error = "'$x' is not an OU's distinguished name, e.g. OU=Pilot,OU=Users,DC=contoso,DC=com" } }
            if ($seen.Add($x)) { $vals.Add($x) }
        }
        if (-not $vals.Count) { return @{ Ok = $false; Error = $(if ($kind -eq 'OU') { 'name at least one OU (its distinguished name)' } else { 'name at least one group (its display name)' }) } }
        if ($vals.Count -gt 5) { return @{ Ok = $false; Error = "at most 5 $(if ($kind -eq 'OU') { 'OUs' } else { 'groups' }) in a scope" } }
        return @{ Ok = $true; Scope = [ordered]@{ Kind = $kind; Values = @($vals) } }
    }
    @{ Ok = $false; Error = "scope kind '$kind': Objects, Filter, Group or OU" }
}

$script:EpsTagTestTraceMax = 200   # TAG-TEST: a test run records the whole decision of its first 200 objects

function Get-EpsRuleCardsHash {
    # TAG-TEST (owner 2026-11-05): ONE hash of everything that decides a tag of this object type - the rule cards in run
    # order (their POSITION, tag type, on / off, persona, values, each condition in order) and the tag types (attribute,
    # value mode, fallbacks, on / off). By content and position, never by rule id (ADMIN-WALK 2026-11-05): a test of the
    # STAGED rules and the same rules once committed (new rules get their ids only then) have the same hash.
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, $Cards, $TagTypeRows)
    $s = { param($v) if ($null -eq $v -or $v -is [DBNull]) { '' } else { "$v" } }
    $lines = [System.Collections.Generic.List[string]]::new(); $k = 0
    foreach ($c in @($Cards | Where-Object { $_ })) {
        $k++
        $vals = if ($ObjectType -eq 'User') { "$(& $s $c.TagValueAD)|$(& $s $c.TagValueCloud)" } else { "$(& $s $(if ($c.Contains('TagValue') -and $null -ne $c.TagValue) { $c.TagValue } else { $c.TagValueAD }))|" }
        $per = if ($ObjectType -eq 'User') { & $s $c.Persona } else { '' }
        $lines.Add("R|$k|$(& $s $c.TagType)|$([int][bool]$c.Enabled)|$per|$vals")
        $q = 0; foreach ($x in @($c.Conditions)) { if ($x -and $x.ConditionType) { $q++; $lines.Add("C|$q|$(& $s $x.ConditionType)|$(& $s $x.Target)") } }
    }
    foreach ($y in @($TagTypeRows)) {
        $lines.Add("T|$(& $s $y.Name)|$(& $s $y.Attribute)|$(& $s $y.ValueMode)|$([int][bool]$y.AllowMultiple)|$(& $s $y.FallbackAD)|$(& $s $y.FallbackCloud)|$(& $s $y.FallbackFromProperty)|$([int][bool]$y.Enabled)")
    }
    $h = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))
    (-join ($h | ForEach-Object { $_.ToString('x2') }))
}

function Get-EpsTagTypeRowsForHash {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType)
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ o = $ObjectType } -Query 'SELECT * FROM eps.TagType WHERE ObjectType = @o ORDER BY Name')
}

function Get-EpsTagRuleSetHash {
    # the hash of the rules as COMMITTED (see Get-EpsRuleCardsHash). A test run records it; Go live is refused when the
    # rules are no longer the ones the test proved.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [string]$RuleSet = 'default')
    $cards = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ObjectType | Where-Object { "$($_.RuleSet)" -eq $RuleSet })
    Get-EpsRuleCardsHash -ObjectType $ObjectType -Cards $cards -TagTypeRows (Get-EpsTagTypeRowsForHash -ConnectionString $ConnectionString -ObjectType $ObjectType)
}

function Get-EpsStagedRuleCards {
    <#
      ADMIN-WALK (owner 2026-11-05 "think as an it admin"): "Test these staged changes" - the rules as they WOULD be once the
      commit queue's waiting rule changes of this object type are committed, oldest first, computed in memory (nothing is
      written): each waiting POST / PUT / DELETE / move / batch is turned into batch ops and simulated by Test-EpsRuleBatch on
      the result of the ones before it, as the commit replays them. A change the commit would refuse is left out and named.
      Returns @{ Cards (the edit-shaped cards of the rule set, in run order); Hash; Applied (pending ids); Skipped (id + why);
      Count (waiting changes of this object type) }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [string]$RuleSet = 'default')
    $ctx = Get-EpsEditContext -ConnectionString $ConnectionString
    $cur = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ObjectType | Where-Object { "$($_.RuleSet)" -eq $RuleSet })
    $stamp = [datetime]::new(2000, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $pend = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ e = "${ObjectType}TagRule" } -Query "SELECT Id, Method, Path, BodyJson FROM eps.PendingChange WHERE Status = 'Pending' AND Entity = @e ORDER BY Id")
    $applied = [System.Collections.Generic.List[long]]::new(); $skipped = [System.Collections.Generic.List[object]]::new(); $gen = 0
    foreach ($p in $pend) {
        $b = if ($p.BodyJson) { $p.BodyJson | ConvertFrom-Json } else { [pscustomobject]@{} }
        $exp = { param($id) $c0 = @($cur | Where-Object { "$($_.RuleId)" -eq "$id" })[0]; if ($c0) { ConvertTo-EpsWebTime $c0.UpdatedAtUtc } }
        $ops = switch -Regex ("$($p.Method) $($p.Path)") {
            "^POST /api/rules/$ObjectType$" { @(@{ op = 'create'; rule = $b; insertAfter = $(if ("$($b.insertAfter)" -match '^\d+$') { "$($b.insertAfter)" } else { '0' }) }) }
            "^PUT /api/rules/$ObjectType/(\d+)$" { $id = $Matches[1]; @(@{ op = 'update'; id = $id; expected = (& $exp $id); rule = $b }) }
            "^DELETE /api/rules/$ObjectType/(\d+)$" { $id = $Matches[1]; @(@{ op = 'delete'; id = $id; expected = (& $exp $id) }) }
            "^POST /api/rules/$ObjectType/(\d+)/move$" {
                $id = $Matches[1]; $ix = -1; for ($i = 0; $i -lt $cur.Count; $i++) { if ("$($cur[$i].RuleId)" -eq $id) { $ix = $i } }
                $nb = if ("$($b.direction)" -eq 'up') { $ix - 1 } else { $ix + 1 }
                if ($ix -ge 0 -and $nb -ge 0 -and $nb -lt $cur.Count) { @(@{ op = 'move'; ids = @($id); to = $(if ("$($b.direction)" -eq 'up') { 'before' } else { 'after' }); ref = "$($cur[$nb].RuleId)" }) } else { @() } }
            "^POST /api/rules/$ObjectType/batch$" {
                @(foreach ($o in @($b.ops)) { if (-not $o) { continue }
                    $h = @{}; foreach ($pp in $o.PSObject.Properties) { $h[$pp.Name] = $pp.Value }
                    if ("$($h.op)" -in 'update', 'delete') { $h.expected = (& $exp $h.id) }
                    $h }) }
            default { $null }
        }
        if ($null -eq $ops) { continue }
        if (-not @($ops).Count) { $skipped.Add(@{ id = [long]$p.Id; why = 'the move has no rule to pass' }); continue }
        foreach ($c0 in $cur) { if (-not $c0.UpdatedAtUtc) { $c0.UpdatedAtUtc = $stamp } }
        $chk = Test-EpsRuleBatch -ConnectionString $ConnectionString -ObjectType $ObjectType -Ops @($ops) -Context $ctx -Current $cur
        if (-not $chk.Ok -and -not ($chk.Errors.Count -eq 1 -and "$($chk.Errors[0])" -like 'nothing changes*')) { $skipped.Add(@{ id = [long]$p.Id; why = (@($chk.Errors) -join '; ') }); continue }
        $gen++
        # the simulated set becomes the base of the next change; a new rule gets a staged id (never a number: a later
        # staged change cannot name it, as a commit could not)
        $cur = @(foreach ($c1 in @($chk.Final)) { if ("$($c1.RuleId)" -notmatch '^\d+$' -and "$($c1.RuleId)" -notlike 'staged*') { $c1.RuleId = "staged$gen-$($c1.RuleId)" }; if (-not $c1.UpdatedAtUtc) { $c1.UpdatedAtUtc = $stamp }; $c1 })
        $applied.Add([long]$p.Id)
    }
    @{ Cards = @($cur); Hash = (Get-EpsRuleCardsHash -ObjectType $ObjectType -Cards $cur -TagTypeRows (Get-EpsTagTypeRowsForHash -ConnectionString $ConnectionString -ObjectType $ObjectType))
       Applied = @($applied); Skipped = @($skipped); Count = $pend.Count }
}

function ConvertTo-EpsTagJobCards {
    # the edit-shaped cards (Read-EpsRuleCardsForEdit / a simulation) -> the shape the tag engine plans with (Read-EpsTagRules)
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, $Cards)
    $k = 0
    @(foreach ($c in @($Cards | Where-Object { $_ })) {
        $k++
        $v = if ($ObjectType -eq 'Device') { $(if ($c.Contains('TagValue') -and $null -ne $c.TagValue) { $c.TagValue } else { $c.TagValueAD }) }
        $conds = [System.Collections.Generic.List[object]]::new(); foreach ($x in @($c.Conditions)) { if ($x -and $x.ConditionType) { $conds.Add(@{ ConditionType = $x.ConditionType; Target = $x.Target }) } }
        @{ RuleId = [string]$c.RuleId; Order = $k; Persona = $(if ($ObjectType -eq 'User') { $c.Persona } else { $c.TagType }); TagType = $c.TagType
           TagValueAD = $(if ($ObjectType -eq 'User') { $c.TagValueAD } else { $v }); TagValueCloud = $(if ($ObjectType -eq 'User') { $c.TagValueCloud } else { $v })
           Enabled = [bool]$c.Enabled; Conditions = $conds }
    })
}

function Get-EpsRuleMatched {
    <#
      RULES-MATCHED (owner 2026-11-03: "what is this matched. maybe give more context here which users are in scope like a
      list" / "i like the matched" / "but a button with more context"): for ONE rule, the run its Matched count comes from
      (the newest run on everyone, or -RunId), WHO it decided in that run (eps.TagRuleHit, paged and searchable), and -
      when it decided nobody - why: off, its tag type off, changed after the run, never wins (an earlier rule takes every
      match), or no object met all its conditions, with the closest misses from the newest test run that traced them.
      Read only. Returns $null when the rule does not exist.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType,
          [Parameter(Mandatory)][int]$RuleId, [string]$RunId, [string]$Search, [int]$Page = 1, [int]$PageSize = 100, [switch]$All)
    $cs = $ConnectionString; $job = "${ObjectType}Tagging"
    $t = if ($ObjectType -eq 'User') { 'UserTagRule' } else { 'DeviceTagRule' }
    $rule = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ id = $RuleId } -Query "SELECT RuleId, TagType, Enabled, UpdatedAtUtc FROM eps.$t WHERE RuleId = @id")[0]
    if (-not $rule) { return $null }
    $runSql = "SELECT TOP 1 RunId, Mode, Status, Scope, StartedAtUtc, SummaryJson FROM eps.Run WHERE Job = @j"
    $run = if ($RunId) { @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ j = $job; r = [guid]$RunId } -Query "$runSql AND RunId = @r")[0] }
           else { @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ j = $job } -Query "$runSql AND Scope IS NULL AND Status IN ('Succeeded', 'PartlyFailed', 'Held') AND SummaryJson LIKE '%`"Matched`"%' ORDER BY StartedAtUtc DESC")[0] }
    $sum = if ($run -and $run.SummaryJson -is [string]) { try { $run.SummaryJson | ConvertFrom-Json } catch { $null } }
    $total = if ($sum -and $sum.Matched) { [int]($sum.Matched."$RuleId") } else { 0 }
    $traced = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($sum.Traces | Where-Object { $_ })) { [void]$traced.Add("$($x.ObjectId)") }
    $rows = @(); $stored = 0
    if ($run) {
        $p = @{ r = [guid]$run.RunId; id = $RuleId; q = $(if ($Search) { "%$($Search.Replace('[', '[[]').Replace('%', '[%]').Replace('_', '[_]'))%" } else { '' }) }
        $where = 'WHERE RunId = @r AND RuleId = @id AND (@q = N'''' OR ObjectName LIKE @q OR Value LIKE @q)'
        $stored = [int](Invoke-EpsSql -ConnectionString $cs -Scalar -Parameters $p -Query "SELECT COUNT(*) FROM eps.TagRuleHit $where")
        $page0 = [math]::Max(1, $Page); $size = if ($All) { 100000 } else { [math]::Min(500, [math]::Max(1, $PageSize)) }
        $p.o = ($page0 - 1) * $size; $p.n = $size
        $rows = @(foreach ($h in @(Invoke-EpsSql -ConnectionString $cs -Parameters $p -Query "SELECT ObjectId, ObjectName, TagType, Value, CurrentValue, Changed FROM eps.TagRuleHit $where ORDER BY ObjectName, ObjectId OFFSET @o ROWS FETCH NEXT @n ROWS ONLY")) {
            [ordered]@{ objectId = "$($h.ObjectId)"; name = $(if ($h.ObjectName -is [string]) { $h.ObjectName } else { '' }); tagType = "$($h.TagType)"
                value = $(if ($h.Value -is [string]) { $h.Value } else { '' }); current = $(if ($h.CurrentValue -is [string]) { $h.CurrentValue } else { '' })
                changed = [bool]$h.Changed; traced = $traced.Contains("$($h.ObjectId)") } })
    }
    # nobody decided: why
    $why = [System.Collections.Generic.List[string]]::new()
    $tt = @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ o = $ObjectType; n = "$($rule.TagType)" } -Query 'SELECT Enabled FROM eps.TagType WHERE ObjectType = @o AND Name = @n')[0]
    if (-not $run) { $why.Add("no run on everyone has finished yet - the count comes with the next scheduled run (or Jobs > Run now)") }
    if (-not [bool]$rule.Enabled) { $why.Add('the rule is switched off') }
    if (-not $tt) { $why.Add("its tag type '$($rule.TagType)' does not exist") } elseif (-not [bool]$tt.Enabled) { $why.Add("its tag type '$($rule.TagType)' is switched off") }
    if ($run -and $rule.UpdatedAtUtc -is [datetime] -and $run.StartedAtUtc -is [datetime] -and $rule.UpdatedAtUtc -gt $run.StartedAtUtc) { $why.Add('the rule was changed after that run - the next run counts it as it is now') }
    if (-not $total) {
        $ctx = Get-EpsEditContext -ConnectionString $cs
        $cards = @(Read-EpsRuleCardsForEdit -ConnectionString $cs -ObjectType $ObjectType)
        foreach ($h in @(Get-EpsRuleShadowHints -Cards $cards -TagTypes $ctx.TagTypes | Where-Object { "$($_.RuleId)" -eq "$RuleId" })) { $why.Add("it never wins: $($h.Text -replace '^never wins: ', '')") }
        if ($run -and -not $why.Count) { $why.Add("in that run no $($ObjectType.ToLowerInvariant()) met all of its conditions") }
    }
    # the closest misses: the newest test run that traced this rule - the traced objects with the most conditions met
    $misses = @(); $missRun = $null
    if (-not $total) {
        foreach ($tr in @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ j = $job } -Query "SELECT TOP (5) RunId, StartedAtUtc, SummaryJson FROM eps.Run WHERE Job = @j AND ISJSON(Scope) = 1 AND JSON_VALUE(Scope, '$.Test') = 'true' AND Status IN ('Succeeded', 'PartlyFailed') ORDER BY StartedAtUtc DESC")) {
            $ts = try { $tr.SummaryJson | ConvertFrom-Json } catch { $null }
            $cand = @(foreach ($o in @($ts.Traces | Where-Object { $_ })) {
                $rr = @(@($o.Rules) | Where-Object { $_ -and "$($_.RuleId)" -eq "$RuleId" -and "$($_.Result)" -eq 'NotMatched' })[0]
                if (-not $rr) { continue }
                $cs0 = @($rr.Conditions | Where-Object { $_ })
                [ordered]@{ objectId = "$($o.ObjectId)"; name = "$($o.Name)"; met = @($cs0 | Where-Object { $_.Met }).Count; of = $cs0.Count
                    failed = @($cs0 | Where-Object { -not $_.Met } | ForEach-Object { "$($_.ConditionType) wants $($_.Target)$(if ($_.Unavailable) { " - not available: $($_.Unavailable)" } else { " - is $(if ("$($_.Actual)") { "$($_.Actual)" } else { '(empty)' })" })" }) } })
            if ($cand.Count) { $misses = @($cand | Sort-Object { - $_.met }, { $_.name } | Select-Object -First 5); $missRun = [ordered]@{ runId = "$($tr.RunId)"; startedAtUtc = (ConvertTo-EpsWebTime $tr.StartedAtUtc) }; break }
        }
    }
    # the runs that kept a list, for the run picker (newest first)
    $runs = @(foreach ($x in @(Invoke-EpsSql -ConnectionString $cs -Parameters @{ j = $job } -Query "SELECT TOP (10) r.RunId, r.Mode, r.Status, r.Scope, r.StartedAtUtc FROM eps.Run r WHERE r.Job = @j AND EXISTS (SELECT 1 FROM eps.TagRuleHit h WHERE h.RunId = r.RunId) ORDER BY r.StartedAtUtc DESC")) {
        [ordered]@{ runId = "$($x.RunId)"; mode = "$($x.Mode)"; status = "$($x.Status)"; everyone = -not ($x.Scope -is [string]); test = ($x.Scope -is [string] -and $x.Scope -match '"Test"\s*:\s*true'); startedAtUtc = (ConvertTo-EpsWebTime $x.StartedAtUtc) } })
    [ordered]@{
        ruleId = $RuleId; tagType = "$($rule.TagType)"; objectType = $ObjectType
        run = $(if ($run) { [ordered]@{ runId = "$($run.RunId)"; mode = "$($run.Mode)"; status = "$($run.Status)"; everyone = -not ($run.Scope -is [string]); test = [bool]$sum.Test; startedAtUtc = (ConvertTo-EpsWebTime $run.StartedAtUtc) } })
        total = $total; stored = $stored; hitMax = $(if ($sum -and $sum.HitMax) { [int]$sum.HitMax } else { $null })
        capped = [bool]@($sum.HitsCapped | Where-Object { "$_" -eq "$RuleId" }).Count
        kept = [bool]($stored -or -not $total -or $Search)   # a count without a list = a run from before the list was kept, or an older one
        page = [math]::Max(1, $Page); pageSize = $(if ($All) { $stored } else { [math]::Min(500, [math]::Max(1, $PageSize)) })
        rows = @($rows); why = @($why); misses = @($misses); missRun = $missRun; runs = @($runs)
    }
}

function Format-EpsScopeText {
    # a scope in words, for the test run pages: "3 named: a, b, c", "userPrincipalName like *@pilot.*", "members of G",
    # "users in OU=..."; the tag types a test run was limited to after it
    param($Scope)
    if (-not $Scope) { return 'everyone' }
    $g = { param($k) if ($Scope -is [System.Collections.IDictionary]) { $Scope[$k] } else { $Scope.$k } }
    $v = @(& $g 'Values' | Where-Object { $_ })
    $txt = switch ("$(& $g 'Kind')") {
        'Objects' { "$($v.Count) named: $(($v | Select-Object -First 5) -join ', ')$(if ($v.Count -gt 5) { ', ...' })" }
        'Filter' { "$(& $g 'Property') like $(& $g 'Pattern')" }
        'Group' { "members of $($v -join ', ')" }
        'OU' { "users in $($v -join '; ')" }
        default { 'everyone' }
    }
    $tt = @(& $g 'TagTypes' | Where-Object { $_ })
    if ($tt.Count) { $txt += " - only $($tt -join ', ')" }
    $txt
}

function Save-EpsScope {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)]$Scope, [Parameter(Mandatory)][string]$Actor)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ n = $Name } -Query 'SELECT Name, ObjectType, Kind, Definition FROM eps.Scope WHERE Name = @n')[0]
    $def = $Scope | ConvertTo-Json -Compress -Depth 4
    $p = @{ n = $Name; o = $ObjectType; k = $Scope.Kind; d = $def } + (New-EpsJournalParameters -Actor $Actor -Entity 'Scope' -Key $Name -Action $(if ($cur) { 'Update' } else { 'Create' }) -Before $(if ($cur) { $cur.Definition }) -After $def)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON;
BEGIN TRAN;
MERGE eps.Scope AS x USING (SELECT @n AS Name) AS s ON x.Name = s.Name WHEN MATCHED THEN UPDATE SET ObjectType = @o, Kind = @k, Definition = @d, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ObjectType, Kind, Definition) VALUES (@n, @o, @k, @d);
$(Get-EpsJournalSql)
COMMIT;
"@)
    @{ Result = 'ok'; Created = -not $cur; Before = $(if ($cur) { $cur.Definition }); After = $def }
}

function Remove-EpsScope {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Actor)
    $cur = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ n = $Name } -Query 'SELECT Name, Definition FROM eps.Scope WHERE Name = @n')[0]
    if (-not $cur) { return @{ Result = 'missing' } }
    $p = @{ n = $Name } + (New-EpsJournalParameters -Actor $Actor -Entity 'Scope' -Key $Name -Action 'Delete' -Before $cur.Definition -After $null)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query "SET XACT_ABORT ON; BEGIN TRAN; DELETE FROM eps.Scope WHERE Name = @n; $(Get-EpsJournalSql) COMMIT;")
    @{ Result = 'ok'; Before = $cur.Definition }
}

function ConvertTo-EpsWebTime { param($d) if ($d -is [datetime]) { [datetime]::SpecifyKind($d, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") } }

function ConvertTo-EpsExpectedText {
    # the version a page sends back ("expected": the UpdatedAtUtc it was given). ConvertFrom-Json turns an ISO time
    # into a DateTime - often in LOCAL time - so "$x" of it would never equal the stored version: back to UTC text.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ConvertTo-EpsWebTime $(if ($Value.Kind -eq 'Local') { $Value.ToUniversalTime() } else { $Value }) }
    "$Value"
}
