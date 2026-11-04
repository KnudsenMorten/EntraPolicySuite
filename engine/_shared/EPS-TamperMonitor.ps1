# EntraPolicySuite -- the tag tamper monitor (DESIGN §5.7a; owner 2026-10-29: "detects if anyone chg these specific
# extensionattributes (like a hacker). so it must detect chg not made by eps engine").
# The tags drive the dynamic groups and so the Conditional Access policies: setting a user's Classification to
# Break_Glass_Account, or clearing an Authentication tag, takes that user out of MFA policies.
#
#   watched  = exactly the attributes the ENABLED tag types use, on users and devices
#   delta    = every 15 min a Graph delta query (only the watched attributes selected) - cheap at 200,000 users
#   baseline = eps.WatchedValue: the last value seen per object + attribute; a change is a difference to it
#   own?     = a change is the ENGINE's only when its change record (eps.TagChange, Applied, this value) has it AND
#              the audit log does not name someone else; anything else is foreign
#   who      = the Entra audit log (needs Entra ID P1 + AuditLog.Read.All); without it the change is still found,
#              only "who" is unknown - and the event says so
#   allow    = known writers (an HR provisioning app): recorded as Allowed, not alerted
#   full     = a daily full compare against what the engine last wrote catches what a delta or a log gap missed
# A foreign change is never silently overwritten: the next tagging run would write the engine's value back, so the
# event is recorded FIRST; restore is one call (Restore-EpsTamperEvent), automatic restore a setting, OFF by default.
# Dot-source EPS-Conditions, EPS-SqlStore, EPS-Graph, EPS-TagJob (Read-EpsTagTypes, Invoke-EpsApplyChanges) first.

Set-StrictMode -Off

function Get-EpsWatchedAttributes {
    param([Parameter(Mandatory)][hashtable]$TagTypes)
    @(foreach ($t in $TagTypes.Values) { if ($t.Enabled -ne $false -and $t.Attribute) { [pscustomobject]@{ ObjectType = $t.ObjectType; Attribute = $t.Attribute; TagType = $t.Name } } })
}

function Invoke-EpsGraphDelta {
    # One delta round: every page until the deltaLink. No -DeltaLink = the first round (all objects, a new baseline).
    # Objects Graph reports as deleted ('@removed') are left out.
    # -Latest: no objects, only a deltaLink for "from now on" ($deltatoken=latest) - a baseline that reads nothing.
    param([Parameter(Mandatory)][ValidateSet('User', 'Device')][string]$ObjectType, [Parameter(Mandatory)][string[]]$Select, [string]$DeltaLink, [switch]$Latest)
    $uri = if ($DeltaLink) { $DeltaLink } else { "v1.0/$(if ($ObjectType -eq 'User') { 'users' } else { 'devices' })/delta?`$select=$($Select -join ',')$(if ($Latest) { '&$deltatoken=latest' })" }
    $items = [System.Collections.Generic.List[object]]::new(); $next = $null
    while ($uri) {
        $page = Invoke-EpsGraph -Path $uri
        foreach ($v in @($page.value)) { if ($v -and -not $v.PSObject.Properties['@removed']) { $items.Add($v) } }
        $uri = $page.'@odata.nextLink'
        if (-not $uri) { $next = $page.'@odata.deltaLink' }
    }
    @{ Items = $items; DeltaLink = $next }
}

function Find-EpsAuditInitiator {
    # Who changed the attribute: the newest directory audit entry for the object since -Since that modified it.
    # Returns @{ Who; Kind = user | app | engine | sync | unknown; Unavailable }.
    param([Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][string]$Attribute, [Parameter(Mandatory)][datetime]$Since, [string]$EngineAppId)
    $f = "activityDateTime ge $($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and targetResources/any(t:t/id eq '$ObjectId')"
    $rows = try { @(Invoke-EpsGraph -Path "v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($f))&`$top=50" -All) }
            catch { return @{ Who = $null; Kind = 'unknown'; Unavailable = "the audit log could not be read ($(("$_" -split '->')[-1].Trim())) - Entra ID P1 and AuditLog.Read.All are needed to say who" } }
    $hit = $rows | Where-Object { @($_.targetResources | Where-Object { $_.id -eq $ObjectId } | ForEach-Object { $_.modifiedProperties } | Where-Object { "$($_.displayName)" -match [regex]::Escape($Attribute) -or "$($_.displayName)" -match '(?i)extensionAttribute' }).Count } |
           Sort-Object { [datetime]$_.activityDateTime } -Descending | Select-Object -First 1
    if (-not $hit) { return @{ Who = $null; Kind = 'unknown'; Unavailable = $null } }
    $app = $hit.initiatedBy.app; $usr = $hit.initiatedBy.user
    if ($app -and ($app.appId -or $app.displayName)) {
        $kind = if ($EngineAppId -and $app.appId -eq $EngineAppId) { 'engine' } elseif ("$($app.displayName)" -match '(?i)Entra Connect|Azure AD Connect|AAD Connect|Sync') { 'sync' } else { 'app' }
        return @{ Who = "$($app.displayName) ($($app.appId))"; Kind = $kind; AppId = [string]$app.appId; Unavailable = $null }
    }
    if ($usr) {
        $kind = if ("$($usr.userPrincipalName)" -match '(?i)^Sync_') { 'sync' } else { 'user' }
        return @{ Who = "$($usr.userPrincipalName)$(if ($usr.ipAddress) { " from $($usr.ipAddress)" })"; Kind = $kind; Upn = [string]$usr.userPrincipalName; Unavailable = $null }
    }
    @{ Who = $null; Kind = 'unknown'; Unavailable = $null }
}

function Get-EpsTamperSeverity {
    # High when the change moves a user out of protection: a high value set or removed (default *Break_Glass*), or an
    # Authentication tag cleared (setting TamperMonitor.HighValues adds patterns).
    param([string]$TagType, [string]$Old, [string]$New, [string[]]$HighValues = @('*Break_Glass*'))
    foreach ($p in $HighValues) { $w = Get-EpsWildcard $p; if (($Old -and $w.IsMatch($Old)) -or ($New -and $w.IsMatch($New))) { return 'High' } }
    if ($TagType -eq 'Authentication' -and $Old -and -not $New) { return 'High' }
    'Normal'
}

function Invoke-EpsTamperMonitor {
    <#
    .SYNOPSIS
        One monitor run. -Mode Delta (every 15 min) or Full (the daily compare). Returns the run with its events.
        The first run of each object type takes a baseline and alerts nothing.
    .PARAMETER EngineAppId
        The engine's managed identity client id (EPS_ManagedIdentityClientId) - its writes in the audit log are its own.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [ValidateSet('Delta', 'Full')][string]$Mode = 'Delta',
          [string]$EngineAppId = $env:EPS_ManagedIdentityClientId, [datetime]$NowUtc = [datetime]::UtcNow)
    $runId = [guid]::NewGuid()
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; t = $NowUtc; m = $(if ($Mode -eq 'Full') { 'Apply' } else { 'Preview' }) } -Query "INSERT INTO eps.Run (RunId, Job, Mode, StartedAtUtc, Scope) VALUES (@id, 'TamperMonitor', @m, @t, NULL)" | Out-Null
    $events = [System.Collections.Generic.List[object]]::new(); $notes = [System.Collections.Generic.List[string]]::new()
    $q = { param($sql, $p = @{}) Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query $sql }
    try {
        $types = Read-EpsTagTypes -ConnectionString $ConnectionString
        $watched = Get-EpsWatchedAttributes -TagTypes $types
        $allow = @(); $hv = @('*Break_Glass*')
        $a = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = 'TamperMonitor.AllowList'"; if ($a) { $allow = @($a | ConvertFrom-Json) }
        $h = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = 'TamperMonitor.HighValues'"; if ($h) { $hv = @($h | ConvertFrom-Json) }
        $objectsSeen = 0
        foreach ($ot in 'User', 'Device') {
            $w = @($watched | Where-Object ObjectType -eq $ot)
            if (-not $w.Count) { continue }
            $extProp = if ($ot -eq 'User') { 'onPremisesExtensionAttributes' } else { 'extensionAttributes' }
            $select = @('id', $(if ($ot -eq 'User') { 'userPrincipalName' } else { 'displayName' }), $extProp) + $(if ($ot -eq 'User') { @('onPremisesSyncEnabled') } else { @() })
            $stateName = "delta:$ot"
            $link = if ($Mode -eq 'Delta') { Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $stateName } -Query 'SELECT Value FROM eps.MonitorState WHERE Name = @n' }
            $baselineRun = -not $link -and -not [bool](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $ot } -Query 'SELECT TOP 1 1 FROM eps.WatchedValue WHERE ObjectType = @o')
            $d = if ($Mode -eq 'Delta') { Invoke-EpsGraphDelta -ObjectType $ot -Select $select -DeltaLink $link } else { @{ Items = @(if ($ot -eq 'User') { Get-EpsUsers -Select $select } else { Get-EpsDevices -Select $select }); DeltaLink = $null } }
            $objectsSeen += $d.Items.Count
            # the baseline and the engine's last write, for exactly these objects
            $base = @{}
            foreach ($r in & $q "SELECT ObjectId, Attribute, Value, SeenAtUtc FROM eps.WatchedValue WHERE ObjectType = @o" @{ o = $ot }) { $base["$($r.ObjectId)|$($r.Attribute)".ToLowerInvariant()] = $r }
            $own = @{}
            foreach ($r in & $q "SELECT c.ObjectId, c.Attribute, c.NewValue, c.AtUtc FROM eps.TagChange c WHERE c.ObjectType = @o AND c.Status = 'Applied' AND c.ChangeId = (SELECT MAX(c2.ChangeId) FROM eps.TagChange c2 WHERE c2.ObjectId = c.ObjectId AND c2.Attribute = c.Attribute AND c2.Status = 'Applied')" @{ o = $ot }) { $own["$($r.ObjectId)|$($r.Attribute)".ToLowerInvariant()] = $r }
            $upserts = [System.Collections.Generic.List[object]]::new()
            foreach ($o in $d.Items) {
                $id = [string]$o.id; $name = if ($ot -eq 'User') { [string]$o.userPrincipalName } else { [string]$o.displayName }
                $ext = $o.$extProp
                foreach ($wa in $w) {
                    $key = "$id|$($wa.Attribute)".ToLowerInvariant()
                    $cur = [string](Get-EpsValue $ext $wa.Attribute)
                    $prev = $base[$key]
                    $upserts.Add(@{ ObjectId = $id; Attribute = $wa.Attribute; Value = $cur; Name = $name })
                    if (-not $prev) { continue }          # new object / first run: a baseline, nothing to compare with
                    $was = [string]$prev.Value
                    $engineLast = $own[$key]
                    $differs = -not [string]::Equals($was, $cur, [StringComparison]::OrdinalIgnoreCase)
                    $driftFromEngine = $Mode -eq 'Full' -and $engineLast -and -not [string]::Equals([string]$engineLast.NewValue, $cur, [StringComparison]::OrdinalIgnoreCase)
                    if (-not $differs -and -not $driftFromEngine) { continue }
                    $recordSaysEngine = $engineLast -and [string]::Equals([string]$engineLast.NewValue, $cur, [StringComparison]::OrdinalIgnoreCase) -and ([datetime]$engineLast.AtUtc) -ge ([datetime]$prev.SeenAtUtc).AddHours(-1)
                    $who = Find-EpsAuditInitiator -ObjectId $id -Attribute $wa.Attribute -Since ([datetime]$prev.SeenAtUtc).AddHours(-1) -EngineAppId $EngineAppId
                    if ($who.Unavailable -and -not $notes.Contains($who.Unavailable)) { $notes.Add($who.Unavailable) }
                    if ($recordSaysEngine -and $who.Kind -in 'engine', 'unknown', 'sync') { continue }   # the engine's own write (AD-synced: via the worker)
                    # the engine's record does NOT have this value, so an audit entry by the engine is its own EARLIER write,
                    # not this change: who made this one is unknown
                    if (-not $recordSaysEngine -and $who.Kind -eq 'engine') { $who = @{ Who = $null; Kind = 'unknown'; Unavailable = $null } }
                    $allowed = ($who.AppId -and $allow -contains $who.AppId) -or ($who.Upn -and $allow -contains $who.Upn)
                    $old = if ($differs) { $was } else { [string]$engineLast.NewValue }
                    $sev = Get-EpsTamperSeverity -TagType $wa.TagType -Old $old -New $cur -HighValues $hv
                    $detail = "$($wa.TagType) ($($wa.Attribute)) on $name changed '$old' -> '$cur' by $(if ($who.Who) { $who.Who } else { 'an unknown writer' }), not by the Entra Policy Suite engine. The dynamic groups and Conditional Access policies that read $($wa.Attribute) now see the new value." +
                              $(if ($who.Kind -eq 'sync') { ' It came through directory sync: the change was made in on-premises AD.' } elseif ($who.Unavailable) { " Who is unknown: $($who.Unavailable)." } else { '' })
                    # a plain hashtable: Invoke-EpsSql -Parameters takes [hashtable] (an ordered dictionary is not one)
                    $ev = @{ RunId = $runId; ObjectType = $ot; ObjectId = $id; ObjectName = $name; TagType = $wa.TagType; Attribute = $wa.Attribute; OldValue = $old; NewValue = $cur
                             Severity = $sev; Initiator = $who.Who; InitiatorKind = $who.Kind; FoundBy = $(if ($Mode -eq 'Full') { 'fullCompare' } else { 'delta' }); Detail = $detail; Status = $(if ($allowed) { 'Allowed' } else { 'Open' }) }
                    # never twice: an open event for the same object, attribute and value is not raised again
                    $dupe = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $id; a = $wa.Attribute; v = $cur } -Query "SELECT COUNT(*) FROM eps.TamperEvent WHERE ObjectId = @o AND Attribute = @a AND ISNULL(NewValue, '') = ISNULL(@v, '') AND Status = 'Open'"
                    if ($dupe) { continue }
                    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $ev -Query @'
INSERT INTO eps.TamperEvent (RunId, ObjectType, ObjectId, ObjectName, TagType, Attribute, OldValue, NewValue, Severity, Initiator, InitiatorKind, FoundBy, Detail, Status)
VALUES (@RunId, @ObjectType, @ObjectId, @ObjectName, @TagType, @Attribute, @OldValue, @NewValue, @Severity, @Initiator, @InitiatorKind, @FoundBy, @Detail, @Status)
'@ | Out-Null
                    $events.Add([pscustomobject]$ev)
                }
            }
            foreach ($u in $upserts) {
                Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = $ot; o = $u.ObjectId; a = $u.Attribute; v = $(if ($u.Value) { $u.Value }); n = $u.Name; s = $NowUtc } -Query @'
MERGE eps.WatchedValue AS d USING (SELECT @t AS ObjectType, @o AS ObjectId, @a AS Attribute) AS s ON d.ObjectType = s.ObjectType AND d.ObjectId = s.ObjectId AND d.Attribute = s.Attribute
WHEN MATCHED THEN UPDATE SET Value = @v, ObjectName = @n, SeenAtUtc = @s
WHEN NOT MATCHED THEN INSERT (ObjectType, ObjectId, Attribute, Value, ObjectName, SeenAtUtc) VALUES (@t, @o, @a, @v, @n, @s);
'@ | Out-Null
            }
            if ($d.DeltaLink) {
                Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $stateName; v = $d.DeltaLink } -Query 'MERGE eps.MonitorState AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (@n, @v);' | Out-Null
            }
            if ($baselineRun) { $notes.Add("$ot`: first run - a baseline of $($d.Items.Count) object(s) taken, nothing compared") }
        }
        $open = @($events | Where-Object Status -eq 'Open')
        $status = 'Succeeded'
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $status; o = $objectsSeen; p = $open.Count; j = (@{ Events = $events.Count; Open = $open.Count; High = @($open | Where-Object Severity -eq 'High').Count; Notes = @($notes) } | ConvertTo-Json -Compress -Depth 4) } `
            -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @s, Objects = @o, Planned = @p, SummaryJson = @j WHERE RunId = @id' | Out-Null
        [pscustomobject]@{ RunId = $runId; Status = $status; Objects = $objectsSeen; Events = @($events); Notes = @($notes) }
    } catch {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; e = "$($_.Exception.Message)" } -Query "UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = 'Failed', HeldReason = @e WHERE RunId = @id" | Out-Null
        throw
    }
}

function Restore-EpsTamperEvent {
    # One-click restore: the engine writes back the value it last wrote (or the value before the change), recorded as a
    # change (Reason Restore) of its own run, and the event is closed as Restored by whom.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$EventId, [Parameter(Mandatory)][string]$By)
    $e = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $EventId } -Query 'SELECT * FROM eps.TamperEvent WHERE EventId = @id')[0]
    if (-not $e) { throw "tamper event $EventId does not exist" }
    if ($e.Status -ne 'Open') { throw "tamper event $EventId is $($e.Status), not Open" }
    $last = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $e.ObjectId; a = $e.Attribute } -Query "SELECT TOP 1 NewValue FROM eps.TagChange WHERE ObjectId = @o AND Attribute = @a AND Status = 'Applied' ORDER BY ChangeId DESC"
    $value = if ($null -ne $last) { [string]$last } else { [string]$e.OldValue }
    $runId = [guid]::NewGuid()
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; a = $By } -Query "INSERT INTO eps.Run (RunId, Job, Mode, ApprovedBy) VALUES (@id, 'TamperRestore', 'Apply', @a)" | Out-Null
    $c = [pscustomobject]@{ ObjectType = $e.ObjectType; ObjectId = [string]$e.ObjectId; ObjectName = $e.ObjectName; Directory = 'Cloud'; TagType = $e.TagType; Attribute = $e.Attribute
                            OldValue = $e.NewValue; NewValue = $value; Reason = 'Restore'; Persona = $null; RuleIds = @() }
    $res = Invoke-EpsApplyChanges -ObjectType $e.ObjectType -Changes @($c)
    [void](Write-EpsTagChanges -ConnectionString $ConnectionString -RunId $runId -Changes @($c))
    $ok = $res.Applied -eq 1
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok) { 'Succeeded' } else { 'Failed' }); e = $c.Error } -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @s, Applied = CASE WHEN @s = ''Succeeded'' THEN 1 ELSE 0 END, HeldReason = @e WHERE RunId = @id' | Out-Null
    if ($ok) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $EventId; b = $By } -Query "UPDATE eps.TamperEvent SET Status = 'Restored', ResolvedBy = @b, ResolvedAtUtc = SYSUTCDATETIME() WHERE EventId = @id" | Out-Null }
    [pscustomobject]@{ EventId = $EventId; Restored = $ok; Value = $value; Error = $c.Error }
}
