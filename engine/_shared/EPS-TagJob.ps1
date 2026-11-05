# EntraPolicySuite -- the tagging job: the whole pipeline for user or device tagging (DESIGN §2a, §4, §5.2, §5.3, §5.8):
#   scope -> collect (Graph) -> evaluate + decide (EPS-TagEngine) -> guard (EPS-Guard) -> apply -> record -> report
# Preview = the same run without apply. Every change of a run is recorded in eps.TagChange with its old value, which is
# what the troubleshooting view, the tamper monitor ("the engine's own change") and undo read.
# Dot-source EPS-Conditions, EPS-TagEngine, EPS-Guard, EPS-SqlStore, EPS-Graph and EPS-Exchange first.

Set-StrictMode -Off

function Read-EpsTagTypes {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = @{}
    foreach ($r in Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT * FROM eps.TagType') {
        $out["$($r.ObjectType):$($r.Name)"] = @{ Name = $r.Name; ObjectType = $r.ObjectType; Attribute = $r.Attribute; ValueMode = $r.ValueMode
            AllowMultiple = [bool]$r.AllowMultiple; FallbackAD = $r.FallbackAD; FallbackCloud = $r.FallbackCloud
            FallbackFromProperty = $r.FallbackFromProperty; Enabled = [bool]$r.Enabled }
    }
    $out
}

function Read-EpsTagRules {
    # The rule cards of one object type, in Order, with their conditions in Seq.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [string]$RuleSet = 'default')
    $t = if ($ObjectType -eq 'User') { 'UserTagRule' } else { 'DeviceTagRule' }
    $val = if ($ObjectType -eq 'User') { 'r.TagValueAD, r.TagValueCloud, r.Persona' } else { 'r.TagValue AS TagValueAD, r.TagValue AS TagValueCloud, r.TagType AS Persona' }
    $rows = Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ s = $RuleSet } -Query @"
SELECT r.RuleId, r.[Order], r.TagType, r.Enabled, $val, c.Seq, c.ConditionType, c.Target
FROM eps.$t r LEFT JOIN eps.${t}Condition c ON c.RuleId = r.RuleId
WHERE r.RuleSet = @s ORDER BY r.[Order], r.RuleId, c.Seq
"@
    $cards = [ordered]@{}
    foreach ($r in $rows) {
        if (-not $cards.Contains([string]$r.RuleId)) {
            $cards[[string]$r.RuleId] = @{ RuleId = [string]$r.RuleId; Order = [int]$r.Order; Persona = $r.Persona; TagType = $r.TagType
                TagValueAD = $r.TagValueAD; TagValueCloud = $r.TagValueCloud; Enabled = [bool]$r.Enabled; Conditions = [System.Collections.Generic.List[object]]::new() }
        }
        if ($r.ConditionType) { $cards[[string]$r.RuleId].Conditions.Add(@{ ConditionType = $r.ConditionType; Target = $r.Target }) }
    }
    @($cards.Values)
}

function Get-EpsScopedObjects {
    # The scope (DESIGN §5.8): everyone, or a list of ids / UPNs / names, or a filter on the collected objects.
    # A scoped run says so in its record.
    param([object[]]$Objects, $Scope)
    if (-not $Scope -or $Scope.Kind -eq 'Everyone') { return $Objects }
    switch ($Scope.Kind) {
        'Objects' {
            $set = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Scope.Values), [StringComparer]::OrdinalIgnoreCase)
            # SEC-AUDIT-1 S13: a display name is not unique - it counts only when it names exactly one object (ids / UPNs always)
            $names = @{}; foreach ($x in $Objects) { $k = ([string]$x.displayName).ToLowerInvariant(); $names[$k] = 1 + [int]$names[$k] }
            @($Objects | Where-Object { $set.Contains([string]$_.id) -or $set.Contains([string]$_.userPrincipalName) -or ($set.Contains([string]$_.displayName) -and $names[([string]$_.displayName).ToLowerInvariant()] -eq 1) })
        }
        'Filter' {
            $w = Get-EpsWildcard ([string]$Scope.Pattern)
            @($Objects | Where-Object { $w.IsMatch([string](Get-EpsValue $_ $Scope.Property)) })
        }
        default { throw "scope kind '$($Scope.Kind)' is not supported here (Group / OU scopes are resolved to Objects first)" }
    }
}

function Get-EpsNotExcludedObjects {
    # leaves out every object whose UPN, display name or id matches one of the patterns (wildcards as -like)
    param([object[]]$Objects, [string[]]$Patterns = @())
    $w = @($Patterns | Where-Object { $_ } | ForEach-Object { Get-EpsWildcard ([string]$_) })
    if (-not $w.Count) { return $Objects }
    @($Objects | Where-Object { $o = $_; -not @($w | Where-Object { $_.IsMatch([string]$o.userPrincipalName) -or $_.IsMatch([string]$o.displayName) -or $_.IsMatch([string]$o.id) }).Count })
}

function Write-EpsTagChanges {
    # The plan's changes -> eps.TagChange in one bulk copy (a 60,000-user run is one round-trip, not 60,000).
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [object[]]$Changes = @())
    if (-not $Changes.Count) { return 0 }
    $dt = [System.Data.DataTable]::new()
    foreach ($c in 'RunId', 'ObjectType', 'ObjectId', 'ObjectName', 'Directory', 'TagType', 'Attribute', 'OldValue', 'NewValue', 'Reason', 'Persona', 'RuleIds', 'Status', 'Error', 'Via') {
        $col = $dt.Columns.Add($c); if ($c -in 'RunId', 'ObjectId') { $col.DataType = [guid] }
    }
    foreach ($c in $Changes) {
        $row = $dt.NewRow()
        $row.RunId = $RunId; $row.ObjectType = $c.ObjectType; $row.ObjectId = [guid]$c.ObjectId; $row.ObjectName = $c.ObjectName
        $row.Directory = $c.Directory; $row.TagType = $c.TagType; $row.Attribute = $c.Attribute
        $row.OldValue = if ([string]::IsNullOrEmpty($c.OldValue)) { [DBNull]::Value } else { $c.OldValue }
        $row.NewValue = if ([string]::IsNullOrEmpty($c.NewValue)) { [DBNull]::Value } else { $c.NewValue }
        $row.Reason = $c.Reason; $row.Persona = if ($c.Persona) { $c.Persona } else { [DBNull]::Value }
        $row.RuleIds = (@($c.RuleIds) -join ','); $row.Status = if ($c.Status) { $c.Status } else { 'Planned' }
        $row.Error = if ($c.Error) { $c.Error } else { [DBNull]::Value }
        $row.Via = if ($c.Via) { $c.Via } else { [DBNull]::Value }
        $dt.Rows.Add($row)
    }
    $conn = New-EpsSqlConnection -ConnectionString $ConnectionString
    try {
        Open-EpsSqlConnection $conn
        $bcType = ($conn.GetType().FullName -replace 'SqlConnection$', 'SqlBulkCopy') -as [type]
        $bc = $bcType::new($conn); $bc.DestinationTableName = 'eps.TagChange'; $bc.BatchSize = 5000; $bc.BulkCopyTimeout = 600
        foreach ($col in $dt.Columns) { [void]$bc.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
        $bc.WriteToServer($dt)
    } finally { $conn.Dispose() }
    $Changes.Count
}

function Invoke-EpsApplyChanges {
    # The apply step: writes each planned change and marks it Applied (with the path, Via) or Failed (with the error).
    # A cloud user goes through Graph; when Graph refuses a mail-enabled user's attribute, v1's fallback writes it in
    # Exchange (Set-Mailbox / Set-MailUser). A device goes through Graph. An AD-synced user is the hybrid worker's.
    # Used by the tagging job and, unchanged, by the live write proof.
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [object[]]$Changes = @(), [hashtable]$Context = @{}, [string]$TenantId)
    $applied = 0; $failed = 0; $queued = 0
    foreach ($c in $Changes) {
        # an AD-synced user: AD is the source of truth, so the hybrid worker writes it (a work package, DESIGN §6)
        if ($c.Directory -eq 'AD') { $c | Add-Member -NotePropertyName Status -NotePropertyValue 'Queued' -Force; $c | Add-Member -NotePropertyName Via -NotePropertyValue 'Worker' -Force; $queued++; continue }
        try {
            $via = 'Graph'
            if ($ObjectType -eq 'User') {
                try { Set-EpsUserAttribute -UserId $c.ObjectId -Attribute $c.Attribute -Value $c.NewValue }
                catch {
                    $rtd = if ($Context.Mailboxes) { $Context.Mailboxes[[string]$c.ObjectId] }
                    if (-not $rtd -or -not $TenantId) { throw }
                    $via = "Exchange $(Set-EpsExchangeCustomAttribute -TenantId $TenantId -ObjectId $c.ObjectId -RecipientTypeDetails $rtd -Attribute $c.Attribute -Value $c.NewValue)"
                }
            }
            else { Set-EpsDeviceAttribute -DeviceObjectId $c.ObjectId -Attribute $c.Attribute -Value $c.NewValue }
            $c | Add-Member -NotePropertyName Status -NotePropertyValue 'Applied' -Force; $applied++
            $c | Add-Member -NotePropertyName Via -NotePropertyValue $via -Force
        } catch {
            $c | Add-Member -NotePropertyName Status -NotePropertyValue 'Failed' -Force
            $c | Add-Member -NotePropertyName Error -NotePropertyValue "$($_.Exception.Message)" -Force; $failed++
        }
    }
    [pscustomobject]@{ Applied = $applied; Failed = $failed; Queued = $queued }
}

function Invoke-EpsTagJob {
    <#
    .SYNOPSIS
        One tagging run. -Mode Preview builds and records the plan and writes nothing to the tenant; -Mode Apply also
        applies it unless the mass-change guard holds the run. Returns the run record.
    .PARAMETER Objects
        Pre-collected objects (a test, a re-evaluation of one object). Default: collected from Graph with exactly the
        fields the rules need.
    .PARAMETER ApprovedBy
        An admin approved a held run (re-run with the approval).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType,
        [Parameter(Mandatory)][ValidateSet('Preview', 'Apply')][string]$Mode,
        [Parameter(Mandatory)][string]$ConnectionString,
        $Scope,
        [object[]]$Objects,
        [hashtable]$Context,
        [string]$ApprovedBy,
        [hashtable]$GuardSettings = @{},
        [string]$TenantId = $env:EPS_TENANT_ID,
        [guid]$RunId = [guid]::NewGuid()
    )
    $job = "${ObjectType}Tagging"
    $runId = $RunId
    $scopeJson = if ($Scope) { $Scope | ConvertTo-Json -Compress -Depth 5 }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; j = $job; m = $Mode; s = $scopeJson; a = $ApprovedBy } -Query 'INSERT INTO eps.Run (RunId, Job, Mode, Scope, ApprovedBy) VALUES (@id, @j, @m, @s, @a)' | Out-Null
    $log = { param($level, $msg) $script:__seq++; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; s = $script:__seq; l = $level; m = $msg } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
    $script:__seq = 0
    try {
        $catalog = Import-EpsConditionCatalog -CustomConditions @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Id AS id, ObjectType AS objectType, Property AS property, Operator AS operator, Guard AS guard, Description AS description, CAST(1 AS bit) AS custom FROM eps.ConditionType WHERE Enabled = 1")
        $types = Read-EpsTagTypes -ConnectionString $ConnectionString
        $rules = Read-EpsTagRules -ConnectionString $ConnectionString -ObjectType $ObjectType
        & $log 'Info' "$job ${Mode}: $($rules.Count) rule(s), $(@($types.Values | Where-Object { $_.ObjectType -eq $ObjectType -and $_.Enabled }).Count) enabled tag type(s)$(if ($Scope) { ", SCOPED: $scopeJson" })"

        if (-not $Objects) {
            $select = Get-EpsConditionSelect -Catalog $catalog -ObjectType $ObjectType -Rules $rules -Base (Get-EpsTagBaseSelect -ObjectType $ObjectType)
            if ($Scope -and $Scope.ById) {
                # the directory trigger names the changed objects by id: read only those (15 ids per filter, Graph's limit)
                $ids = @($Scope.Values); $byId = [System.Collections.Generic.List[object]]::new()
                for ($i = 0; $i -lt $ids.Count; $i += 15) {
                    $f = "id in ($((@($ids[$i..([math]::Min($i + 14, $ids.Count - 1))]) | ForEach-Object { "'$([guid]$_)'" }) -join ','))"
                    $page = if ($ObjectType -eq 'User') { Get-EpsUsers -Select $select -Filter $f } else { Get-EpsDevices -Select $select -Filter $f }
                    foreach ($o in @($page)) { if ($o) { $byId.Add($o) } }
                }
                $Objects = @($byId)
            } else { $Objects = if ($ObjectType -eq 'User') { Get-EpsUsers -Select $select } else { Get-EpsDevices -Select $select } }
            & $log 'Info' "collected $($Objects.Count) $($ObjectType.ToLower())(s) with $($select.Count) field(s)"
        }
        if (-not $Context) {
            $Context = @{}
            $needs = @($rules | ForEach-Object { $_.Conditions } | ForEach-Object { $catalog["${ObjectType}:$($_.ConditionType)"] } | Where-Object { $_ } | ForEach-Object { $_.Needs }) | Select-Object -Unique
            if ($needs -contains 'SkuPartNumbers') { $Context.SkuPartNumbers = Get-EpsSkuPartNumbers }
            if ($needs -contains 'EntraGroupMembers') {
                $names = @($rules | ForEach-Object { $_.Conditions } | Where-Object { $_.ConditionType -eq 'MemberOfGroup' } | ForEach-Object { $_.Target })
                $gNotes = [System.Collections.Generic.List[string]]::new()
                $Context.EntraGroupMembers = Get-EpsEntraGroupMembers -GroupNames $names -ConnectionString $ConnectionString -Notes $gNotes
                foreach ($n in $gNotes) { & $log 'Warning' $n }
            }
            if ($needs -contains 'Mailboxes') {
                if ($TenantId) { $Context.Mailboxes = Get-EpsExchangeRecipients -TenantId $TenantId; & $log 'Info' "read $($Context.Mailboxes.Count) Exchange recipient(s)" }
                else { & $log 'Warning' 'Exchange recipients not read: no tenant id (EPS_TENANT_ID)' }
            }
            # AD group members for AD-synced users come from the hybrid worker's snapshots. No live worker = left out,
            # and the rules that need them are reported Unavailable in the plan, never silently "no match".
            if ($needs -contains 'AdGroupMembers') {
                $ws = Get-EpsWorkerStatus -ConnectionString $ConnectionString
                if ($ws.Alive) {
                    $names = @($rules | ForEach-Object { $_.Conditions } | Where-Object { $_.ConditionType -eq 'MemberOfGroup' } | ForEach-Object { $_.Target })
                    $ag = Get-EpsAdGroupContext -ConnectionString $ConnectionString -Names $names
                    $Context.AdGroupMembers = $ag.Members
                    if ($ag.Missing.Count) { & $log 'Warning' "AD group(s) without a fresh snapshot yet (the hybrid worker reads them next): $($ag.Missing -join ', ')" }
                } else { & $log 'Warning' 'no hybrid worker heartbeat in 30 min: AD group membership not available' }
            }
        }
        $scoped = @(Get-EpsScopedObjects -Objects $Objects -Scope $Scope)
        # objects the customer never wants tagged (owner 2026-10-30: "skip the sync account") - left out before the plan
        $exRaw = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = "$job.ExcludeObjects" } -Query 'SELECT Value FROM eps.Setting WHERE Name = @n'
        $ex = @(if ($exRaw) { try { @($exRaw | ConvertFrom-Json) } catch { & $log 'Warning' "$job.ExcludeObjects is not a JSON list - ignored" } })
        if ($ex.Count) {
            $before = $scoped.Count; $scoped = @(Get-EpsNotExcludedObjects -Objects $scoped -Patterns $ex)
            & $log 'Info' "excluded $($before - $scoped.Count) object(s) by $job.ExcludeObjects ($($ex -join ', '))"
        }
        # "Try on a user" (RULES-UX): a scoped preview that records the whole decision of each object (a few at most)
        $traceIds = if ($Scope -and $Scope.Trace -and $scoped.Count -le 5) { @($scoped | ForEach-Object { [string]$_.id }) } else { @() }
        $plan = Invoke-EpsTagPlan -ObjectType $ObjectType -Objects $scoped -Rules $rules -TagTypes $types -Catalog $catalog -Context $Context -Trace $traceIds
        $sum = Get-EpsPlanSummary $plan
        foreach ($k in $plan.Unavailable.Keys) { & $log 'Warning' "unavailable: $k ($($plan.Unavailable[$k]) condition check(s) skipped)" }
        & $log 'Info' "plan: $($sum.Changes) change(s) on $($sum.ObjectsChanged) object(s), $($sum.Overwrites) overwrite(s), $($sum.Unchanged) already right, $($sum.Skipped) skipped"

        $status = 'Succeeded'; $held = $null; $applied = 0; $failed = 0; $queuedAd = 0
        if ($Mode -eq 'Apply') {
            $prev = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ j = $job; id = $runId } -Query "SELECT TOP 1 Planned, Overwrites FROM eps.Run WHERE Job = @j AND Mode = 'Apply' AND Status IN ('Succeeded', 'PartlyFailed') AND Scope IS NULL AND RunId <> @id ORDER BY StartedAtUtc DESC")[0]
            # a scoped run (one user, a test group) is measured as it is; the guard protects the run on everyone
            $g = Test-EpsMassChangeGuard -Summary $sum -Previous $(if ($Scope) { @{ Planned = $sum.Changes; Overwrites = $sum.Overwrites } } else { $prev }) -Settings $GuardSettings -Job $job -ApprovedBy $ApprovedBy
            if ($g.Held) {
                $status = 'Held'; $held = $g.Reason
                & $log 'Warning' "HELD by the mass-change guard: $($g.Reason)"
                foreach ($c in $plan.Changes) { $c | Add-Member -NotePropertyName Status -NotePropertyValue 'Skipped' -Force; $c | Add-Member -NotePropertyName Error -NotePropertyValue 'run held by the mass-change guard' -Force }
            } else {
                $res = Invoke-EpsApplyChanges -ObjectType $ObjectType -Changes @($plan.Changes) -Context $Context -TenantId $TenantId
                $applied = $res.Applied; $failed = $res.Failed; $queuedAd = $res.Queued
                if ($failed) { $status = 'PartlyFailed'; & $log 'Warning' "$failed change(s) failed - see the run's changes" }
            }
            if ($g.Record) { $script:EpsLastGuardRecord = $g.Record }   # the job's caller sends it (mail, uplink: GUARD-1.2)
        }
        [void](Write-EpsTagChanges -ConnectionString $ConnectionString -RunId $runId -Changes @($plan.Changes))
        if ($queuedAd) {
            # V1-PARITY P14: each AD change goes to the worker of its user's AD environment (HybridWorker.EnvironmentByUpnSuffix)
            # (EPS-WorkerPage.ps1 + EPS-Scheduler.ps1, both loaded by the engine; a test that loads neither queues without one)
            $envMap = if ((Get-Command ConvertFrom-EpsEnvironmentMap -ErrorAction SilentlyContinue) -and (Get-Command Get-EpsSetting -ErrorAction SilentlyContinue)) { ConvertFrom-EpsEnvironmentMap (Get-EpsSetting -ConnectionString $ConnectionString -Name 'HybridWorker.EnvironmentByUpnSuffix' -Default '[]') } else { @{ Entries = @(); Bad = @() } }
            if ($envMap.Bad.Count) { & $log 'Warning' "the AD environments setting has line(s) that are not '<upn suffix>=<environment>', left out: $($envMap.Bad -join '; ')" }
            [void](Add-EpsWorkPackages -ConnectionString $ConnectionString -RunId $runId -Changes @($plan.Changes) -EnvironmentMap @($envMap.Entries))
            $ws = Get-EpsWorkerStatus -ConnectionString $ConnectionString
            & $log $(if ($ws.Alive) { 'Info' } else { 'Warning' }) "$queuedAd AD-synced change(s) queued for the hybrid worker$(if (-not $ws.Alive) { ' - NO worker heartbeat in 30 min: they wait until a worker runs' })"
        }
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{
            id = $runId; st = $status; h = $held; o = $sum.Objects; p = $sum.Changes; ow = $sum.Overwrites; a = $applied; f = $failed; sk = $sum.Skipped
            js = ([ordered]@{ ByValue = $sum.ByValue; ByRule = $sum.ByRule; Matched = $sum.Matched; Unavailable = $sum.Unavailable; Unchanged = $sum.Unchanged; ObjectsChanged = $sum.ObjectsChanged
                    Traces = $(if ($traceIds.Count) { @($plan.Traces.Values) }) } | ConvertTo-Json -Compress -Depth 8)
        } -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @st, HeldReason = @h, Objects = @o, Planned = @p, Overwrites = @ow, Applied = @a, Failed = @f, Skipped = @sk, SummaryJson = @js WHERE RunId = @id' | Out-Null
        [pscustomobject]@{ RunId = $runId; Job = $job; Mode = $Mode; Status = $status; HeldReason = $held; Summary = $sum; Applied = $applied; Failed = $failed; Queued = $queuedAd; Plan = $plan }
    } catch {
        $err = "$($_.Exception.Message)"
        try { & $log 'Error' $err } catch { }
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; e = $err } -Query "UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = 'Failed', HeldReason = @e WHERE RunId = @id" | Out-Null
        throw
    }
}

function Invoke-EpsTagDirectoryCheck {
    <#
    .SYNOPSIS
        The opt-in directory trigger (<Job>.RunOnDirectoryChange; owner 2026-10-31: off by default, "there are millions of
        chg"): a Graph delta of EXACTLY the properties the rules read; the objects that changed are tagged, nothing else.
        The first check only notes "from now on" ($deltatoken=latest); a check that finds nothing records no run; the
        delta link moves on only after the run succeeded, so a failed run is tried again with the same changes.
        Returns @{ Action = Baseline | NoChange | Ran; Changed; Run }.
    #>
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][ValidateSet('Preview', 'Apply')][string]$Mode,
          [Parameter(Mandatory)][string]$ConnectionString, [hashtable]$GuardSettings = @{}, [int]$MaxObjects = 1000)
    $catalog = Import-EpsConditionCatalog -CustomConditions @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT Id AS id, ObjectType AS objectType, Property AS property, Operator AS operator, Guard AS guard, Description AS description, CAST(1 AS bit) AS custom FROM eps.ConditionType WHERE Enabled = 1")
    $rules = Read-EpsTagRules -ConnectionString $ConnectionString -ObjectType $ObjectType
    # the properties the rules read - a delta of them (the tag attributes only when a rule reads one: the engine's own
    # writes are then one extra no-change run, never a loop)
    $select = @(Get-EpsConditionSelect -Catalog $catalog -ObjectType $ObjectType -Rules $rules -Base (Get-EpsTagBaseSelect -ObjectType $ObjectType) | Sort-Object -Unique)
    $name = "tagDelta:$ObjectType"; $sel = $select -join ','
    $state = try { Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $name } -Query 'SELECT Value FROM eps.MonitorState WHERE Name = @n' | ConvertFrom-Json } catch { $null }
    $save = { param($link) Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $name; v = (@{ link = $link; select = $sel } | ConvertTo-Json -Compress) } -Query 'MERGE eps.MonitorState AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (@n, @v);' | Out-Null }
    if (-not $state -or -not $state.link -or $state.select -ne $sel) {
        # a new baseline: on first use, and when the rules read other properties (the old link would miss them)
        $d = try { Invoke-EpsGraphDelta -ObjectType $ObjectType -Select $select -Latest } catch { Invoke-EpsGraphDelta -ObjectType $ObjectType -Select $select }
        & $save $d.DeltaLink
        return @{ Action = 'Baseline'; Changed = 0 }
    }
    $d = Invoke-EpsGraphDelta -ObjectType $ObjectType -Select $select -DeltaLink $state.link
    $ids = @($d.Items | ForEach-Object { [string]$_.id } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $ids.Count) { & $save $d.DeltaLink; return @{ Action = 'NoChange'; Changed = 0 } }
    # many changes at once: one run on everyone is cheaper than reading them one filter at a time
    $scope = if ($ids.Count -gt $MaxObjects) { $null } else { @{ Kind = 'Objects'; Values = $ids; ById = $true; Trigger = 'directory' } }
    $r = Invoke-EpsTagJob -ObjectType $ObjectType -Mode $Mode -ConnectionString $ConnectionString -Scope $scope -GuardSettings $GuardSettings
    & $save $d.DeltaLink
    @{ Action = 'Ran'; Changed = $ids.Count; Run = $r }
}
