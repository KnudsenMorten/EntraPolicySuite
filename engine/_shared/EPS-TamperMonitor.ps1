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
    param([Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][string]$Attribute, [Parameter(Mandatory)][datetime]$Since, [string]$EngineAppId, [string]$EngineObjectId)
    $f = "activityDateTime ge $($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and targetResources/any(t:t/id eq '$ObjectId')"
    $rows = try { @(Invoke-EpsGraph -Path "v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($f))&`$top=50" -All) }
            catch { return @{ Who = $null; Kind = 'unknown'; Unavailable = "the audit log could not be read ($(("$_" -split '->')[-1].Trim())) - Entra ID P1 and AuditLog.Read.All are needed to say who" } }
    $hit = $rows | Where-Object { @($_.targetResources | Where-Object { $_.id -eq $ObjectId } | ForEach-Object { $_.modifiedProperties } | Where-Object { "$($_.displayName)" -match [regex]::Escape($Attribute) -or "$($_.displayName)" -match '(?i)extensionAttribute' }).Count } |
           Sort-Object { [datetime]$_.activityDateTime } -Descending | Select-Object -First 1
    if (-not $hit) { return @{ Who = $null; Kind = 'unknown'; Unavailable = $null } }
    $app = $hit.initiatedBy.app; $usr = $hit.initiatedBy.user
    if ($app -and ($app.appId -or $app.displayName)) {
        # found live 2026-11-09: an entry by the engine's managed identity can come without an appId ("id-eps-engine ()"), so its
        # own write read as a foreign app. The service principal's object id says it too; a display name never does (any app can carry one)
        $kind = if (($EngineAppId -and $app.appId -eq $EngineAppId) -or ($EngineObjectId -and "$($app.servicePrincipalId)" -eq $EngineObjectId)) { 'engine' } elseif ("$($app.displayName)" -match '(?i)Entra Connect|Azure AD Connect|AAD Connect|Sync') { 'sync' } else { 'app' }
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
          [string]$EngineAppId = $env:EPS_ManagedIdentityClientId, [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$EngineObjectId = $(if (Get-Command Get-EpsEngineObjectId -ErrorAction SilentlyContinue) { try { Get-EpsEngineObjectId } catch { '' } }))
    $runId = [guid]::NewGuid()
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; t = $NowUtc; m = $(if ($Mode -eq 'Full') { 'Apply' } else { 'Preview' }) } -Query "INSERT INTO eps.Run (RunId, Job, Mode, StartedAtUtc, Scope) VALUES (@id, 'TamperMonitor', @m, @t, NULL)" | Out-Null
    $events = [System.Collections.Generic.List[object]]::new(); $notes = [System.Collections.Generic.List[string]]::new()
    $q = { param($sql, $p = @{}) Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query $sql }
    try {
        # Invardia 2026-11-13 (e): a restore queued for the hybrid worker is closed only on proof - read back (Update-EpsPendingRestores)
        foreach ($pendNote in @(Update-EpsPendingRestores -ConnectionString $ConnectionString -NowUtc $NowUtc)) { $notes.Add($pendNote) }
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
            # TRUST-1 Q4 (review 2026-11-12): a Planned row of an apply run that FAILED or is still RUNNING may have been written to the
            # tenant without its outcome row - it only SUPPRESSES an alarm for exactly that value (never the drift check or the old
            # value: a value the run never wrote must not look like EPS's last write)
            $ownMaybe = @{}
            foreach ($r in & $q "SELECT c.ObjectId, c.Attribute, c.NewValue, c.AtUtc FROM eps.TagChange c JOIN eps.Run r ON r.RunId = c.RunId WHERE c.ObjectType = @o AND c.Status = 'Planned' AND r.Mode IN ('Apply', 'Undo') AND r.Status IN ('Failed', 'Running') AND c.ChangeId = (SELECT MAX(c2.ChangeId) FROM eps.TagChange c2 JOIN eps.Run r2 ON r2.RunId = c2.RunId WHERE c2.ObjectId = c.ObjectId AND c2.Attribute = c.Attribute AND c2.Status = 'Planned' AND r2.Mode IN ('Apply', 'Undo') AND r2.Status IN ('Failed', 'Running')) AND c.ChangeId > ISNULL((SELECT MAX(c3.ChangeId) FROM eps.TagChange c3 WHERE c3.ObjectId = c.ObjectId AND c3.Attribute = c.Attribute AND c3.Status = 'Applied'), 0)" @{ o = $ot }) { $ownMaybe["$($r.ObjectId)|$($r.Attribute)".ToLowerInvariant()] = $r }
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
                    $maybeLast = $ownMaybe[$key]
                    if (-not $recordSaysEngine -and $maybeLast -and [string]::Equals([string]$maybeLast.NewValue, $cur, [StringComparison]::OrdinalIgnoreCase)) { $recordSaysEngine = $true }
                    if (-not $recordSaysEngine -and $script:EpsRestoreReadBack -and $script:EpsRestoreReadBack.ContainsKey($key) -and [string]::Equals([string]$script:EpsRestoreReadBack[$key], $cur, [StringComparison]::OrdinalIgnoreCase)) { $recordSaysEngine = $true }   # a restore read back this run
                    $who = Find-EpsAuditInitiator -ObjectId $id -Attribute $wa.Attribute -Since ([datetime]$prev.SeenAtUtc).AddHours(-1) -EngineAppId $EngineAppId -EngineObjectId $EngineObjectId
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
    # Invardia 2026-11-13 (e): through the RIGHT directory, as the tagging job and the undo do - an AD-synced user's value is
    # written by the hybrid worker (a work package: AD is the source of truth, a Graph write is refused or overwritten by
    # the next sync), a cloud user's through Graph with the Exchange fallback for a mail-enabled user, a device's through
    # Graph. The user's sync state is read at restore time; when it cannot be read nothing is guessed - the restore stops.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$EventId, [Parameter(Mandatory)][string]$By,
          [string]$TenantId = $env:EPS_TENANT_ID)
    $e = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $EventId } -Query 'SELECT * FROM eps.TamperEvent WHERE EventId = @id')[0]
    if (-not $e) { throw "tamper event $EventId does not exist" }
    if ($e.Status -ne 'Open') { throw "tamper event $EventId is $($e.Status), not Open" }
    # one restore at a time: an event whose restore waits for the hybrid worker is not queued twice
    $pend = Get-EpsRestoreMarker -Detail $e.Detail
    if ($pend.Kind -in 'queued', 'syncWait') { return [pscustomobject]@{ EventId = $EventId; Restored = $false; Queued = $false; Pending = $true; Value = $null; Error = "a restore of this event is already queued for the hybrid worker ($($pend.Text)) - it closes when the value is read back" } }
    # a newer tag value waits for the hybrid worker: the restore (the last WRITTEN value) would be older than it - not now
    $waiting = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $e.ObjectId; a = $e.Attribute } -Query "SELECT TOP 1 c.ChangeId FROM eps.TagChange c WHERE c.ObjectId = @o AND c.Attribute = @a AND c.Status = 'Queued' AND EXISTS (SELECT 1 FROM eps.WorkPackage w WHERE w.ChangeId = c.ChangeId AND w.Status IN ('Queued', 'Claimed'))"
    if ($waiting) { return [pscustomobject]@{ EventId = $EventId; Restored = $false; Queued = $false; Pending = $true; Value = $null; Error = "a newer tag value (change $waiting) is waiting for the hybrid worker - restore after it is written" } }
    $last = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ o = $e.ObjectId; a = $e.Attribute } -Query "SELECT TOP 1 NewValue FROM eps.TagChange WHERE ObjectId = @o AND Attribute = @a AND Status = 'Applied' ORDER BY ChangeId DESC"
    $value = if ($null -ne $last) { [string]$last } else { [string]$e.OldValue }
    $runId = [guid]::NewGuid()
    # the run names its event (Scope), so a restore the hybrid worker could not write re-opens exactly that event (Invoke-EpsTamperMonitor)
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; a = $By; s = "{""tamperEvent"":$EventId}" } -Query "INSERT INTO eps.Run (RunId, Job, Mode, ApprovedBy, Scope) VALUES (@id, 'TamperRestore', 'Apply', @a, @s)" | Out-Null
    $dir = 'Cloud'; $sid = $null; $upn = $null; $ctx = @{}
    if ($e.ObjectType -eq 'User') {
        $u = try { Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString([string]$e.ObjectId))?`$select=id,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesUserPrincipalName" } catch { $_ }
        if ($u -is [System.Management.Automation.ErrorRecord] -or -not $u) {
            $why = "the user could not be read to find its directory (AD-synced or cloud) - nothing was written: $(if ($u -is [System.Management.Automation.ErrorRecord]) { (("$($u.Exception.Message)") -split "`n")[0] } else { 'no answer' })"
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; e = (Get-EpsFailedRunReason -Message $why) } -Query "UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = 'Failed', Applied = 0, HeldReason = @e WHERE RunId = @id" | Out-Null
            return [pscustomobject]@{ EventId = $EventId; Restored = $false; Queued = $false; Value = $value; Error = $why }
        }
        if ([bool]$u.onPremisesSyncEnabled) { $dir = 'AD'; $sid = [string]$u.onPremisesSecurityIdentifier; $upn = [string]$u.onPremisesUserPrincipalName }
        elseif ($TenantId) {
            # the Exchange fallback (Invoke-EpsApplyChanges) needs the recipient type - read once per job run, as the undo does
            if ($null -eq $script:EpsRestoreMailboxes) { $script:EpsRestoreMailboxes = try { Get-EpsExchangeRecipients -TenantId $TenantId } catch { Write-Warning "Exchange recipients not read ($((("$($_.Exception.Message)") -split "`n")[0])) - a mail-enabled user Graph refuses fails"; $null } }
            if ($script:EpsRestoreMailboxes) { $ctx.Mailboxes = $script:EpsRestoreMailboxes }
        }
    }
    $c = [pscustomobject]@{ ObjectType = $e.ObjectType; ObjectId = [string]$e.ObjectId; ObjectName = $e.ObjectName; Directory = $dir; TagType = $e.TagType; Attribute = $e.Attribute
                            OldValue = $e.NewValue; NewValue = $value; Reason = 'Restore'; Persona = $null; RuleIds = @()
                            OnPremisesSecurityIdentifier = $sid; OnPremisesUserPrincipalName = $upn }
    # Invardia 2026-11-12 (b), as TRUST-1 Q4: the restore's row is written FIRST (Planned), then the tenant is changed, then its
    # outcome is written - a failed last write leaves a Planned row of a run that is not Succeeded, read as EPS's own (no false alarm)
    [void](Write-EpsTagChanges -ConnectionString $ConnectionString -RunId $runId -Changes @($c))
    $res = Invoke-EpsApplyChanges -ObjectType $e.ObjectType -Changes @($c) -Context $ctx -TenantId $TenantId
    [void](Update-EpsTagChangeStatus -ConnectionString $ConnectionString -RunId $runId -Changes @(@($c) | Where-Object { $_.Status -and "$($_.Status)" -ne 'Planned' }))
    $queued = $res.Queued -eq 1
    if ($queued) {
        # the worker writes it to AD; the work package carries the user's environment as the tagging job's do (P14)
        $envMap = if ((Get-Command ConvertFrom-EpsEnvironmentMap -ErrorAction SilentlyContinue) -and (Get-Command Get-EpsSetting -ErrorAction SilentlyContinue)) { ConvertFrom-EpsEnvironmentMap (Get-EpsSetting -ConnectionString $ConnectionString -Name 'HybridWorker.EnvironmentByUpnSuffix' -Default '[]') } else { @{ Entries = @() } }
        # (f): queued only when its package IS written (never "waiting for the worker" with nothing for the worker to take)
        $pkgFail = $null
        $queued = $(try { Add-EpsWorkPackages -ConnectionString $ConnectionString -RunId $runId -Changes @($c) -EnvironmentMap @($envMap.Entries) } catch { $pkgFail = (("$($_.Exception.Message)") -split "`n")[0]; 0 }) -eq 1
        if (-not $queued) {
            $c | Add-Member -NotePropertyName Error -NotePropertyValue "the work package for the hybrid worker could not be queued$(if ($pkgFail) { ": $pkgFail" })" -Force
            # its change row is not left Queued with nothing to take it (review of (f))
            Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $runId; e = $c.Error } -Query "UPDATE eps.TagChange SET Status = 'Failed', Error = @e, AtUtc = SYSUTCDATETIME() WHERE RunId = @r AND Status = 'Queued'" | Out-Null
        }
    }
    $ok = $res.Applied -eq 1
    # Invardia 2026-11-13 (e), "never resolved without proof" (TRUST-1): a restore QUEUED for the hybrid worker leaves the event
    # OPEN (its alert and every open count stay) with a marker in its Detail; the engine's next monitor runs read the value
    # back and close it then (Update-EpsPendingRestores)
    $alive = if ($queued -and (Get-Command Get-EpsWorkerStatus -ErrorAction SilentlyContinue)) { try { [bool](Get-EpsWorkerStatus -ConnectionString $ConnectionString).Alive } catch { $true } } else { $true }
    $note = if ($queued) { "queued for the hybrid worker - it writes '$value' to AD (AD-synced user); the event closes when the value is read back$(if (-not $alive) { ' - NO worker heartbeat in 30 min: it waits until a worker runs' })" } else { $c.Error }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $runId; s = $(if ($ok -or $queued) { 'Succeeded' } else { 'Failed' }); e = $(if ($ok -or $queued) { $note } else { Get-EpsFailedRunReason -Message $c.Error }); n = [int]$ok } -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @s, Applied = @n, HeldReason = @e WHERE RunId = @id' | Out-Null
    if ($ok) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $EventId; b = $By } -Query "UPDATE eps.TamperEvent SET Status = 'Restored', ResolvedBy = @b, ResolvedAtUtc = SYSUTCDATETIME() WHERE EventId = @id" | Out-Null }
    elseif ($queued) { Set-EpsRestoreMarker -ConnectionString $ConnectionString -EventId $EventId -Detail $e.Detail -Marker "restore queued for the hybrid worker since $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))Z by $By" }
    [pscustomobject]@{ EventId = $EventId; Restored = $ok; Queued = $queued; Pending = $queued; Value = $value; Error = $c.Error }
}

function Approve-EpsTamperEvent {
    <#
      SECURE-WEB-1 / review G point 5 (2.1.33): "Accept" of a tamper event, done by the ENGINE after the signed-request gate
      (the web identity no longer writes eps.TamperEvent). Checked again here, at the moment it is closed: the event exists,
      is Open, and has no restore waiting for the hybrid worker (it would still write the old value after the accept).
      Nothing in the directory changes. Never throws: @{ EventId; Accepted; Error }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$EventId, [Parameter(Mandatory)][string]$By)
    try {
        $e = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $EventId } -Query 'SELECT EventId, Status, Detail FROM eps.TamperEvent WHERE EventId = @id')[0]
        if (-not $e) { return @{ EventId = $EventId; Accepted = $false; Error = 'no such event' } }
        # review of 2.1.33: a second click before the engine ran - the event IS accepted, so that request is not a failure
        if ("$($e.Status)" -eq 'Accepted') { return @{ EventId = $EventId; Accepted = $true; Already = $true; Error = $null } }
        if ("$($e.Status)" -ne 'Open') { return @{ EventId = $EventId; Accepted = $false; Error = "the event is $($e.Status), not Open" } }
        if ((Get-EpsRestoreMarker -Detail $e.Detail).Kind -in 'queued', 'syncWait') { return @{ EventId = $EventId; Accepted = $false; Error = 'a restore of this event is waiting for the hybrid worker - accept it after the restore is read back or marked not applied' } }
        # the marker is checked again IN the update (review of 2.1.33): a restore queued between the read and the write wins
        $n = [int](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $EventId; b = $By } -Query @"
UPDATE eps.TamperEvent SET Status = 'Accepted', ResolvedBy = @b, ResolvedAtUtc = SYSUTCDATETIME()
WHERE EventId = @id AND Status = 'Open'
  AND ISNULL(Detail, N'') NOT LIKE N'%[[]restore queued for the hybrid worker%' AND ISNULL(Detail, N'') NOT LIKE N'%[[]restore applied in AD%'
"@)
        if ($n -ne 1) { return @{ EventId = $EventId; Accepted = $false; Error = 'the event changed while it was accepted (no longer Open, or a restore was queued) - nothing accepted' } }
        @{ EventId = $EventId; Accepted = $true; Error = $null }
    } catch { @{ EventId = $EventId; Accepted = $false; Error = (("$($_.Exception.Message)") -split "`n")[0] } }
}

function Get-EpsRestoreMarker {
    <# PURE. The restore marker at the end of a tamper event's Detail: "[restore queued for the hybrid worker since ...]",
       "[restore read back ...]" or "[restore not applied: ...]" -> @{ Kind = queued | readBack | notApplied | ''; Text; Base } #>
    param([AllowNull()][AllowEmptyString()][string]$Detail)
    # "[restore applied in AD at <time>, waiting for the directory sync]" = syncWait (still pending, like queued)
    $m = [regex]::Match("$Detail", '\s*\[(restore (queued for the hybrid worker|applied in AD|read back|not applied)[^\]]*)\]\s*$')
    if (-not $m.Success) { return @{ Kind = ''; Text = ''; Base = "$Detail" } }
    @{ Kind = $(switch ($m.Groups[2].Value) { 'read back' { 'readBack' } 'not applied' { 'notApplied' } 'applied in AD' { 'syncWait' } default { 'queued' } }); Text = $m.Groups[1].Value; Base = "$Detail".Substring(0, $m.Index) }
}

function Set-EpsRestoreMarker {
    # the event's Detail with its restore marker replaced (the column is 2000 characters: the marker is kept, the text is cut)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$EventId, [AllowNull()][AllowEmptyString()][string]$Detail, [Parameter(Mandatory)][string]$Marker,
          [string]$Status, [string]$ResolvedBy)
    $tail = " [$(($Marker -replace '[\[\]]', '').Substring(0, [Math]::Min(600, ($Marker -replace '[\[\]]', '').Length)))]"
    $base = (Get-EpsRestoreMarker -Detail $Detail).Base
    if ($base.Length + $tail.Length -gt 2000) { $base = $base.Substring(0, 2000 - $tail.Length) }
    $p = @{ id = $EventId; d = "$base$tail" }
    $set = 'Detail = @d'
    if ($Status) { $p.s = $Status; $p.b = $ResolvedBy; $set += ', Status = @s, ResolvedBy = @b, ResolvedAtUtc = SYSUTCDATETIME()' }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query "UPDATE eps.TamperEvent SET $set WHERE EventId = @id" | Out-Null
}

function Update-EpsPendingRestores {
    <#
      Invardia 2026-11-13 (e): every OPEN event whose restore waits for the hybrid worker, at the start of each monitor run.
      - the worker could not write it (the restore's change ended Failed): the event stays OPEN, marked "restore not applied"
      - the worker wrote it (the change is Applied - the worker reads AD back before it says so): the engine reads the user's
        value in Entra (it arrives with directory sync); when it is the restored value the event is Restored ("read back")
      - written in AD but not in Entra yet (Invardia 2026-11-13: Entra Connect syncs every ~30 min): "[restore applied in AD
        at <time>, waiting for the directory sync]", checked again each run; only after -SyncWaitMinutes (2 sync cycles + margin)
        with Entra still different is it "restore not applied"
      - otherwise (still queued): it waits. Returns the notes for the run.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow, [int]$SyncWaitMinutes = 90)
    $out = [System.Collections.Generic.List[string]]::new()
    # the values read back this run (object|attribute -> value): the compare that follows in the same run takes them as the
    # engine's own even when directory sync took longer than its one-hour window (review 2026-11-13)
    $script:EpsRestoreReadBack = @{}
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query @'
SELECT e.EventId, e.ObjectId, e.ObjectName, e.Attribute, e.Detail, lr.ApprovedBy, c.Status AS ChangeStatus, c.NewValue, c.Error AS ChangeError, c.AtUtc AS ChangeAtUtc
FROM eps.TamperEvent e
CROSS APPLY (SELECT TOP (1) r.RunId, r.ApprovedBy FROM eps.Run r WHERE r.Job = 'TamperRestore' AND r.Scope = CONCAT('{"tamperEvent":', e.EventId, '}') ORDER BY r.StartedAtUtc DESC) lr
JOIN eps.TagChange c ON c.RunId = lr.RunId AND c.Reason = 'Restore'
WHERE e.Status = 'Open' AND (e.Detail LIKE '%[[]restore queued for the hybrid worker%' OR e.Detail LIKE '%[[]restore applied in AD%')
'@)
    foreach ($r in $rows) {
        $kind = (Get-EpsRestoreMarker -Detail $r.Detail).Kind
        if ($kind -notin 'queued', 'syncWait') { continue }
        $at = $NowUtc.ToString('yyyy-MM-dd HH:mm')
        if ("$($r.ChangeStatus)" -in 'Failed', 'Skipped') {   # Skipped = superseded by a newer value for the same user (the worker)
            Set-EpsRestoreMarker -ConnectionString $ConnectionString -EventId $r.EventId -Detail $r.Detail -Marker "restore not applied: $((("$($r.ChangeError)") -split "`n")[0]) ($at`Z)"
            $out.Add("event $($r.EventId) ($($r.ObjectName) $($r.Attribute)): $(if ("$($r.ChangeStatus)" -eq 'Skipped') { 'the restore was superseded by a newer tag value' } else { 'the hybrid worker could not write the restore' }) - the event stays open (restore not applied)")
            continue
        }
        if ("$($r.ChangeStatus)" -ne 'Applied') { continue }
        $u = try { Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString([string]$r.ObjectId))?`$select=id,onPremisesExtensionAttributes" } catch { $null }
        if (-not $u) { $out.Add("event $($r.EventId): the restore was written in AD; its value could not be read back from Entra this run - tried again next run"); continue }
        $cur = [string]$u.onPremisesExtensionAttributes.([string]$r.Attribute)
        if ([string]::Equals($cur, [string]$r.NewValue, [StringComparison]::OrdinalIgnoreCase)) {
            Set-EpsRestoreMarker -ConnectionString $ConnectionString -EventId $r.EventId -Detail $r.Detail -Marker "restore read back $at`Z" -Status 'Restored' -ResolvedBy "$($r.ApprovedBy)"
            $script:EpsRestoreReadBack["$($r.ObjectId)|$($r.Attribute)".ToLowerInvariant()] = $cur
            $out.Add("event $($r.EventId) ($($r.ObjectName) $($r.Attribute)): the restore was read back ('$cur') - Restored")
            continue
        }
        $adAt = if ($r.ChangeAtUtc) { [datetime]$r.ChangeAtUtc } else { $NowUtc }
        $adText = $adAt.ToString('yyyy-MM-dd HH:mm')
        if (($NowUtc - $adAt).TotalMinutes -ge $SyncWaitMinutes) {
            Set-EpsRestoreMarker -ConnectionString $ConnectionString -EventId $r.EventId -Detail $r.Detail -Marker "restore not applied: written in AD at $adText`Z, but Entra still shows '$cur' after $SyncWaitMinutes min ($at`Z)"
            $out.Add("event $($r.EventId) ($($r.ObjectName) $($r.Attribute)): the restore was written in AD but Entra still shows '$cur' after $SyncWaitMinutes min - the event stays open (restore not applied)")
        } elseif ($kind -eq 'queued') {
            Set-EpsRestoreMarker -ConnectionString $ConnectionString -EventId $r.EventId -Detail $r.Detail -Marker "restore applied in AD at $adText`Z, waiting for the directory sync"
            $out.Add("event $($r.EventId) ($($r.ObjectName) $($r.Attribute)): the restore was written in AD - waiting for the directory sync to read it back")
        }
    }
    @($out)
}
