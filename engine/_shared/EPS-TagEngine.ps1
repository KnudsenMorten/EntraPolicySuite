# EntraPolicySuite -- the tag engine: evaluate (rules: conditions) -> decide (plan) for user and device tagging
# (DESIGN §2a pipeline, §5.2, §5.3). It builds the PLAN only - every change it would make, with old and new value and
# the rule behind it. Preview = this plan; apply, troubleshooting (one object, -Trace) and undo all start from it.
# Writes nothing. Dot-source EPS-Conditions.ps1 first.
#
# v1 rule semantics, kept 1:1 (C:\SCRIPTS\Entra-Policy-Suite\Entra-ID-User-Tagging.ps1 / -Device-Tagging.ps1):
#   * a rule is a CARD = v1's rows with the same Persona|TagType|TagValueAD|TagValueCloud|ConditionGroup (blank group =
#     a card of its own); its conditions are ANDed; cards are evaluated in Order (v1: CSV order, on every PS version).
#   * ValueMode per tag type: First (default) = the first matching card wins; Last = the last; Multiple = every match,
#     in order, blanks skipped, duplicates removed case-insensitively, joined with ','.
#   * a Modified value (Exchange conditions) is taken from the card's LAST condition and gets 'Cloud_' / 'AD_Synced_'
#     inserted after its first '_'.
#   * a user value is skipped when its AD or cloud value is empty, or longer than 1024 characters (extensionAttribute
#     limit); a device value may be empty (= clear the attribute), as in v1.
#   * a tag type that got no value gets its fallback (v1: Classification NonManaged_User_*, Authentication
#     NonManaged_User_*_MFA, DeviceCategory Unknown_DeviceCategory); a CopyProperty fallback (v1 Company <- companyName)
#     applies only when the tag type has no enabled rules at all, and never clears.
#   * an existing value equal to the new one (case-insensitive, as v1's -eq) is not changed.
# Fixed against v1 (DESIGN D3 / owner to confirm, REQUIREMENTS §2): a user is AD-synced when onPremisesSyncEnabled is
# TRUE. v1 tested the value as a [string], so 'False' (sync switched off, the object now cloud-managed) was sent to AD.

Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'EPS-FastEval.ps1')   # the compiled property-condition path (always loaded with the engine)

function Get-EpsTagBaseSelect {
    param([ValidateSet('User', 'Device')][string]$ObjectType)
    if ($ObjectType -eq 'User') { @('id', 'userPrincipalName', 'displayName', 'onPremisesSyncEnabled', 'onPremisesExtensionAttributes', 'onPremisesUserPrincipalName', 'onPremisesSecurityIdentifier', 'companyName') }
    else { @('id', 'deviceId', 'displayName', 'extensionAttributes') }
}

function ConvertTo-EpsModifiedValue {
    # v1: 'Exchange_SharedMailbox' -> 'Exchange_Cloud_SharedMailbox' / 'Exchange_AD_Synced_SharedMailbox'.
    param([string]$Value, [string]$Insert)
    $i = $Value.IndexOf('_')
    if ($i -ge 0) { $Value.Substring(0, $i + 1) + $Insert + $Value.Substring($i + 1) } else { $Value }
}

function Resolve-EpsMatchValue {
    param([System.Collections.IList]$List, [string]$Mode, [string]$Field)
    switch ($Mode) {
        'Last'     { [string]$List[$List.Count - 1].$Field }
        'Multiple' {
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $vals = foreach ($m in $List) { $v = [string]$m.$Field; if (-not [string]::IsNullOrWhiteSpace($v) -and $seen.Add($v.Trim())) { $v.Trim() } }
            @($vals) -join ','
        }
        default    { [string]$List[0].$Field }
    }
}

function Invoke-EpsTagPlan {
    <#
    .SYNOPSIS
        Builds the tagging plan for a set of users or devices. Writes nothing.
    .PARAMETER Rules
        Rule cards: @{ RuleId; Order; Persona; TagType; TagValueAD; TagValueCloud; Enabled; Conditions = @(@{ ConditionType; Target }) }.
        Device cards carry their one value in both TagValueAD and TagValueCloud.
    .PARAMETER TagTypes
        Name -> @{ Name; ObjectType; Attribute; ValueMode; FallbackAD; FallbackCloud; FallbackFromProperty; Enabled }.
    .PARAMETER Context
        Run data the condition modules read: EntraGroupMembers, AdGroupMembers, Mailboxes, SkuPartNumbers. A key left
        out = that source was not read; rules that need it are reported unavailable.
    .PARAMETER Trace
        Object ids (or '*') to record the whole decision for - the troubleshooting view (DESIGN §5.8). Tracing evaluates
        every card and every condition, so it is for one object or a few, not a whole tenant.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType,
        [object[]]$Objects = @(),
        [object[]]$Rules = @(),
        [Parameter(Mandatory)][hashtable]$TagTypes,
        [Parameter(Mandatory)][hashtable]$Catalog,
        [hashtable]$Context = @{},
        [string[]]$Trace = @()
    )
    $isUser = $ObjectType -eq 'User'
    $types = @{}
    foreach ($t in $TagTypes.Values) { if ($t.ObjectType -eq $ObjectType) { $types[$t.Name] = $t } }
    $cards = @($Rules | Where-Object { $_ } | Sort-Object { [int]$_.Order })
    # each card's conditions with their definition looked up ONCE per run (not once per object)
    $compiled = [System.Collections.Generic.Dictionary[object, object]]::new()   # keyed by the card itself (reference)
    foreach ($c in $cards) {
        $compiled[$c] = @(foreach ($k in $c.Conditions) {
            @{ Def = $Catalog["${ObjectType}:$($k.ConditionType)"]; ConditionType = [string]$k.ConditionType; Target = [string]$k.Target } })
    }
    # the fast path: every card's PROPERTY conditions compiled once; per object only the candidate cards (whose property
    # conditions all pass) are walked below. A traced object takes the full path, which explains every condition.
    $fast = New-EpsFastCards -Cards $cards -Catalog $Catalog -ObjectType $ObjectType
    $all = if ($cards.Count) { [int[]](0..($cards.Count - 1)) } else { [int[]]@() }
    $ruleCountByType = @{}
    foreach ($c in $cards) { if ($c.Enabled -ne $false) { $ruleCountByType[$c.TagType] = 1 + [int]$ruleCountByType[$c.TagType] } }
    $traceAll = $Trace -contains '*'
    $traceSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Trace), [StringComparer]::OrdinalIgnoreCase)

    $plan = @{
        ObjectType = $ObjectType; Objects = 0; Unchanged = 0
        Changes = [System.Collections.Generic.List[object]]::new()
        Skipped = [System.Collections.Generic.List[object]]::new()
        Unavailable = @{}; Traces = @{}
        Matched = @{}   # rule id -> objects the rule DECIDED (changed or already right): the Rules page's "Matched"
        # RULES-MATCHED (owner 2026-11-03: "maybe give more context here which users are in scope like a list" / "a button
        # with more context"): rule id -> WHO it decided - at most $script:EpsRuleHitMax per rule and run (the count above
        # stays exact; a 200,000-user tenant keeps a bounded list); written to eps.TagRuleHit by the tagging job
        Hits = @{}
    }
    $hitMax = if ($script:EpsRuleHitMax) { [int]$script:EpsRuleHitMax } else { 10000 }

    # one change proposal - defined ONCE; it reads $obj / $id / $tr / $ext of the object being planned at call time
    $propose = {
        param($tt, [string]$value, [string]$reason, [string]$persona, $ruleIds)
        $attr = $tt.Attribute
        $old = Get-EpsValue $ext $attr
        $oldS = [string]$old
        $same = [string]::Equals($oldS, $value, [StringComparison]::OrdinalIgnoreCase)
        foreach ($rid in @($ruleIds)) {
            if ($null -eq $rid -or "$rid" -eq '') { continue }
            $plan.Matched["$rid"] = 1 + [int]$plan.Matched["$rid"]
            $hl = $plan.Hits["$rid"]
            if ($null -eq $hl) { $hl = [System.Collections.Generic.List[object]]::new(); $plan.Hits["$rid"] = $hl }
            if ($hl.Count -lt $hitMax) { $hl.Add(@($id, $name, $tt.Name, $value, $oldS, (-not $same))) }
        }
        if ($tr) { $tr.Decisions.Add(@{ TagType = $tt.Name; Attribute = $attr; Current = $oldS; Wanted = $value; Reason = $reason; Persona = $persona; Action = $(if ($same) { 'NoChange' } else { 'Change' }) }) }
        if ($same) { $plan.Unchanged++; return }
        $plan.Changes.Add([pscustomobject]@{
            ObjectType = $ObjectType; ObjectId = $id; ObjectName = $name
            Directory  = $(if ($synced) { 'AD' } else { 'Cloud' })
            OnPremisesUserPrincipalName = $(if ($synced) { [string](Get-EpsValue $obj 'onPremisesUserPrincipalName') })
            OnPremisesSecurityIdentifier = $(if ($synced) { [string](Get-EpsValue $obj 'onPremisesSecurityIdentifier') })
            TagType = $tt.Name; Attribute = $attr; OldValue = $oldS; NewValue = $value
            Overwrite = -not [string]::IsNullOrEmpty($oldS); Reason = $reason; Persona = $persona; RuleIds = @($ruleIds)
        })
    }

    foreach ($obj in $Objects) {
        $plan.Objects++
        $id = [string](Get-EpsValue $obj 'id')
        $name = if ($isUser) { [string](Get-EpsValue $obj 'userPrincipalName') } else { [string](Get-EpsValue $obj 'displayName') }
        $synced = $isUser -and [bool](Get-EpsValue $obj 'onPremisesSyncEnabled')
        $ext = if ($isUser) { Get-EpsValue $obj 'onPremisesExtensionAttributes' } else { Get-EpsValue $obj 'extensionAttributes' }
        $tr = $null
        if ($traceAll -or $traceSet.Contains($id) -or ($name -and $traceSet.Contains($name))) {
            $tr = @{ ObjectId = $id; Name = $name; Synced = $synced; Rules = [System.Collections.Generic.List[object]]::new(); Decisions = [System.Collections.Generic.List[object]]::new() }
            $plan.Traces[$id] = $tr
        }
        $matchesByType = [ordered]@{}

        $useFast = $null -eq $tr
        $indexes = if ($useFast) { [Eps.FastEval]::Candidates($obj, $fast.Cards) } else { $all }
        foreach ($ci in $indexes) {
            $card = $cards[$ci]
            $tt = $types[$card.TagType]
            $why = if ($card.Enabled -eq $false) { 'rule disabled' } elseif (-not $tt) { "unknown tag type '$($card.TagType)'" } elseif ($tt.Enabled -eq $false) { "tag type '$($card.TagType)' disabled" }
            if ($why) { if ($tr) { $tr.Rules.Add(@{ RuleId = $card.RuleId; Persona = $card.Persona; TagType = $card.TagType; Result = 'Skipped'; Reason = $why }) }; continue }
            $mode = if ($tt.ValueMode) { $tt.ValueMode } else { 'First' }
            if ($mode -eq 'First' -and $matchesByType.Contains($card.TagType)) {
                if ($tr) { $tr.Rules.Add(@{ RuleId = $card.RuleId; Persona = $card.Persona; TagType = $card.TagType; Result = 'NotNeeded'; Reason = 'an earlier rule already decided this tag type (First)' }) }
                continue
            }
            $met = @($card.Conditions).Count -gt 0     # a card without conditions never matches (it would match everyone)
            $modified = $null
            # never "$x = if (...) { [List]::new() }": an empty list is enumerated away and $x ends up $null
            $condTrace = $null
            if ($tr) { $condTrace = [System.Collections.Generic.List[object]]::new() }
            $explain = $null -ne $tr
            # fast path: the property conditions already passed - only the rest (modules, unknown types) is evaluated
            # here, and the Modified value counts only when the card's LAST condition is one of them (v1)
            $toEval = if ($useFast) { $fast.Rest[$ci] } else { $compiled[$card] }
            foreach ($cond in $toEval) {
                $r = if ($cond.Def) { Test-EpsCondition $cond.Def $cond.Target $obj $Context $explain }
                     else { @{ Met = $false; Unavailable = "unknown condition type '$($cond.ConditionType)'" } }
                $modified = $r.Modified
                if ($r.Unavailable) { $plan.Unavailable[$r.Unavailable] = 1 + [int]$plan.Unavailable[$r.Unavailable] }
                if ($null -ne $condTrace) { $condTrace.Add(@{ ConditionType = $cond.ConditionType; Target = $cond.Target; Met = [bool]$r.Met; Actual = $r.Actual; Unavailable = $r.Unavailable }) }
                if (-not $r.Met) { $met = $false; if (-not $tr) { break } }
            }
            if ($tr) { $tr.Rules.Add(@{ RuleId = $card.RuleId; Persona = $card.Persona; TagType = $card.TagType; Result = $(if ($met) { 'Matched' } else { 'NotMatched' }); Conditions = $condTrace }) }
            if (-not $met) { continue }
            if ($useFast -and -not $fast.LastIsRest[$ci]) { $modified = $null }
            $vAD = [string]$card.TagValueAD; $vCloud = [string]$card.TagValueCloud
            if ($modified) { $vAD = ConvertTo-EpsModifiedValue $modified 'AD_Synced_'; $vCloud = ConvertTo-EpsModifiedValue $modified 'Cloud_' }
            if (-not $matchesByType.Contains($card.TagType)) { $matchesByType[$card.TagType] = [System.Collections.Generic.List[object]]::new() }
            $matchesByType[$card.TagType].Add([pscustomobject]@{ AD = $vAD; Cloud = $vCloud; Persona = $card.Persona; RuleId = $card.RuleId })
        }

        $resolved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($typeName in $matchesByType.Keys) {
            $tt = $types[$typeName]; $list = $matchesByType[$typeName]
            $mode = if ($tt.ValueMode) { $tt.ValueMode } else { 'First' }
            $vAD = Resolve-EpsMatchValue $list $mode 'AD'
            $vCloud = Resolve-EpsMatchValue $list $mode 'Cloud'
            $value = if ($synced) { $vAD } else { $vCloud }
            $used = if ($mode -eq 'First') { @($list[0]) } elseif ($mode -eq 'Last') { @($list[$list.Count - 1]) } else { @($list) }
            $persona = (@($used.Persona | Select-Object -Unique) -join ',')
            $skip = if ($isUser -and ([string]::IsNullOrEmpty($vAD) -or [string]::IsNullOrEmpty($vCloud))) { 'the value is empty' }
                    elseif ($value.Length -gt 1024) { 'the value is longer than 1024 characters' }
            if ($skip) {
                $plan.Skipped.Add([pscustomobject]@{ ObjectId = $id; ObjectName = $name; TagType = $typeName; Reason = $skip; Persona = $persona })
                if ($tr) { $tr.Decisions.Add(@{ TagType = $typeName; Wanted = $value; Reason = 'Rule'; Persona = $persona; Action = 'Skipped'; Why = $skip }) }
                continue
            }
            [void]$resolved.Add($typeName)
            & $propose $tt $(if ($isUser) { $value } elseif ($value -eq '') { $null } else { $value }) 'Rule' $persona @($used.RuleId)
        }

        foreach ($tt in $types.Values) {
            if ($tt.Enabled -eq $false -or $resolved.Contains($tt.Name)) { continue }
            if ($tt.FallbackFromProperty) {
                if ($ruleCountByType[$tt.Name]) { continue }
                $v = ([string](Get-EpsValue $obj $tt.FallbackFromProperty)).Trim()
                if ($v) { & $propose $tt $v 'CopyProperty' $null @() }
                continue
            }
            $fb = if ($synced) { $tt.FallbackAD } else { $tt.FallbackCloud }
            if ($fb) { & $propose $tt ([string]$fb) 'Fallback' $null @() }
        }
    }
    $plan
}

function Get-EpsPlanSummary {
    # The plan's counts - what the preview shows and what the mass-change guard looks at (DESIGN §5.8, §5.9).
    param([Parameter(Mandatory)][hashtable]$Plan)
    # one loop, a HashSet for the distinct objects: Select-Object -Unique is quadratic and took minutes at 60,000 users
    $byValue = @{}; $byRule = @{}; $overwrites = 0
    $objects = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Plan.Changes) {
        $k = "$($c.TagType)=$($c.NewValue)"; $byValue[$k] = 1 + [int]$byValue[$k]
        foreach ($r in $c.RuleIds) { $byRule["$r"] = 1 + [int]$byRule["$r"] }
        if ($c.Overwrite) { $overwrites++ }
        [void]$objects.Add([string]$c.ObjectId)
    }
    [pscustomobject]@{
        ObjectType = $Plan.ObjectType; Objects = $Plan.Objects; Changes = $Plan.Changes.Count; Unchanged = $Plan.Unchanged
        Overwrites = $overwrites
        ObjectsChanged = $objects.Count
        Skipped = $Plan.Skipped.Count; ByValue = $byValue; ByRule = $byRule; Unavailable = $Plan.Unavailable
        Matched = $(if ($Plan.Matched) { $Plan.Matched } else { @{} })
    }
}
