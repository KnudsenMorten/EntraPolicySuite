# EntraPolicySuite -- UNDO-BACKUP: backups, restore plans and undo (owner 2026-11-05: "feature req: i need to have both a
# new feature Undo + another new feature backup/restore. look at how PIM does it"; "it must work for both ca policies +
# tagging so i can recover"; "ok go with daily keep 30"; V1-PARITY P10 = v1's JSON export of every CA policy).
#
# PIM's model (PIM DESIGN "Undo, backup and restore", "Undo / rollback"), carried over:
#   * a backup is an immutable set: the engine inserts it and prunes old ones, nothing ever rewrites one
#   * a snapshot is taken BEFORE every change the engine makes to a Conditional Access policy, and before every commit of
#     the tagging configuration; a snapshot that cannot be written REFUSES the change (no change without its way back)
#   * a restore is never a silent rewind: it is a NEW change, shown first as a plan, approved with a reason, applied through
#     the same gates as any change (CA: SuperAdmin, the engine reads the tenant again, the break-glass check on the result;
#     tagging: the same routes, the commit queue, the mass-change guard), journaled and audited
#   * records are never restored: adoption records, version pairs, approvals, the audit trail and the journal are not in a
#     configuration backup; secrets are never stored
# The CA restore WRITES live in EPS-CaWrite.ps1 (the restore function there), pinned by tests/Test-EpsNoCaWrite.ps1. This file
# only reads Conditional Access (Graph GET) and writes SQL.
#
# Loaded by the engine (job-entry.ps1: the Backup job, the snapshots before a write, the restore routes) and by the web app
# (Start-EpsWeb.ps1: the lists, the exports and the plans - reads only).

Set-StrictMode -Off

$script:EpsBackupKeepDaily = 30        # owner 2026-11-05: "ok go with daily keep 30"
$script:EpsBackupKeepDays = 30         # a snapshot before a change, and "Back up now", are kept 30 days
$script:EpsBackupSecretName = '(?i)secret|password|passwd|token|apikey|api\.key|connectionstring|thumbprint|privatekey|credential'

# ---- pure helpers ---------------------------------------------------------------------------------------------------

function ConvertTo-EpsBackupFileName {
    # v1 (Entra-ConditionalAccess-Management.ps1, "Export Entra ID Conditional Access Policies as JSON"): one file per
    # policy, named after the policy, \ and / turned into - . Anything else a file name cannot hold is turned into - too.
    param([string]$Name)
    $n = "$Name".Replace('\', '-').Replace('/', '-')
    # Windows' set, fixed - not [IO.Path]::GetInvalidFileNameChars(): on Linux (the engine's container) that is only NUL
    # and '/', so 'x:y?' kept a name an admin cannot save on Windows (found on the Linux test runner 2026-11-08)
    $n = [regex]::Replace($n, '[<>:"/\\|?*\x00-\x1F]', '-')
    $n = $n.Trim().TrimEnd('.')
    if (-not $n) { $n = 'policy' }
    if ($n.Length -gt 180) { $n = $n.Substring(0, 180) }
    "$n.json"
}

function Test-EpsBackupSecret {
    # a setting that must never be stored in a backup: a name that says it holds a secret, or a value that looks like one
    param([string]$Name, [string]$Value)
    if ("$Name" -match $script:EpsBackupSecretName) { return $true }
    if ("$Value" -match '^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.') { return $true }                 # a JWT
    if ("$Value" -match '(?i)(AccountKey|SharedAccessSignature|Password|ClientSecret)\s*=') { return $true } # a connection string with a key
    if ("$Value" -match '^[A-Za-z0-9+/]{60,}={0,2}$') { return $true }                                   # a long base64 key
    $false
}

function ConvertTo-EpsBackupPolicyBody {
    # a policy as stored in a backup -> the parts an operator sets (name, state, conditions, grant, session); the read-only
    # parts (id, times, templateId, @odata) are left out - they are the tenant's, never written back
    param([Parameter(Mandatory)]$Body)
    $h = if ($Body -is [string]) { $Body | ConvertFrom-Json -AsHashtable -Depth 30 } else { ConvertTo-Json -InputObject $Body -Depth 30 -Compress | ConvertFrom-Json -AsHashtable -Depth 30 }
    $src = [ordered]@{}; foreach ($k in $script:EpsCaEditTop) { if ($h.Contains($k)) { $src[$k] = $h[$k] } }
    ConvertTo-EpsCaEditBody $src
}

function Get-EpsCaRestorePlan {
    <#
      The plan of a restore, pure, ONE policy at a time:
        -Backup  the policy as it was in the backup (its stored JSON)
        -Current the policy as it is now ($null = no longer in the tenant)
        -Mode    Restore (put the backup's body back) | Off (turn the policy off; the undo of a copy or a deploy)
      Restore of a policy that is there: a PATCH of exactly the parts that differ (nothing to change = nothing to do).
      Restore of a policy that is gone: it is created again, ALWAYS OFF (disabled) whatever its state was, with a name no
      policy in the tenant has; it is adopted on creation and then moves through the stages like any other.
      The break-glass check runs on the RESULT: a restore that leaves a policy ON without the break-glass exclusion is
      refused (it never "fixes" it); turning a policy off always passes.
      Returns @{ ok; reason; action (patch | create | none); policyId; displayName; patch; create; changes; breakGlass;
      stateBefore; stateAfter }.
    #>
    param($Backup, $Current, [ValidateSet('Restore', 'Off')][string]$Mode = 'Restore', $BreakGlass = @{}, [bool]$IsBreakGlassPolicy,
          [hashtable]$Names = @{}, [string[]]$ExistingNames = @(), [string]$PolicyId)
    $plan = [ordered]@{ ok = $true; reason = $null; action = 'none'; policyId = $PolicyId; displayName = $null; patch = $null; create = $null; changes = @(); breakGlass = $null; stateBefore = $null; stateAfter = $null }
    $refuse = { param($why) $plan.ok = $false; $plan.reason = $why; $plan }
    if ($Mode -eq 'Off') {
        if ($null -eq $Current) { return & $refuse 'the policy is no longer in the tenant - nothing to turn off' }
        $plan.displayName = "$($Current.displayName)"; $plan.stateBefore = "$($Current.state)"; $plan.stateAfter = 'disabled'
        if ("$($Current.state)" -eq 'disabled') { $plan.action = 'none'; $plan.reason = 'it is off already'; return $plan }
        $plan.action = 'patch'; $plan.patch = [ordered]@{ state = 'disabled' }
        $plan.changes = @([ordered]@{ path = 'state'; before = "$($Current.state)"; after = 'disabled' })
        $plan.breakGlass = [ordered]@{ ok = $true; exempt = $true; text = 'off - it cannot lock anyone out'; missing = @() }
        return $plan
    }
    if ($null -eq $Backup) { return & $refuse 'the backup does not hold this policy' }
    $b = ConvertTo-EpsBackupPolicyBody -Body $Backup
    if (-not $b.Ok) { return & $refuse "the backup's copy cannot be used: $($b.Reason)" }
    $want = $b.Body
    $plan.displayName = "$($want.displayName)"
    if ($null -ne $Current) {
        $e = Get-EpsCaEditPlan -Live $Current -Edit $want -Mode Edit -BreakGlass $BreakGlass -IsBreakGlassPolicy $IsBreakGlassPolicy -Names $Names
        $plan.stateBefore = $e.stateBefore; $plan.stateAfter = $e.stateAfter; $plan.changes = @($e.changes); $plan.breakGlass = $e.breakGlass
        if (-not $e.ok) {
            if ("$($e.reason)" -match 'nothing to change') { $plan.action = 'none'; $plan.reason = 'it is as in the backup already'; return $plan }
            return & $refuse $e.reason
        }
        $plan.action = 'patch'; $plan.patch = $e.patch
        return $plan
    }
    # gone from the tenant: created again, OFF
    if (@($ExistingNames | Where-Object { "$_" -ieq "$($want.displayName)" }).Count) { return & $refuse "a policy named '$($want.displayName)' is in the tenant already (another one) - rename that one first" }
    $create = [ordered]@{}; foreach ($k in $script:EpsCaEditTop) { if ($want.Contains($k) -and $null -ne $want[$k]) { $create[$k] = $want[$k] } }
    $plan.stateBefore = '(not in the tenant)'; $create.state = 'disabled'; $plan.stateAfter = 'disabled'
    $bg = Test-EpsCaBreakGlassExclusion -Policy $create -BreakGlass $BreakGlass -IsBreakGlassPolicy $IsBreakGlassPolicy
    $plan.breakGlass = [ordered]@{ ok = $bg.Ok; exempt = [bool]$bg.Exempt; text = $bg.Text; missing = @($bg.Missing) }
    if ($bg.Ok -eq $false) { return & $refuse "the break-glass check refuses it: the policy as it was $($bg.Text) - it could never be turned on" }
    $plan.action = 'create'; $plan.create = $create
    $plan.changes = @([ordered]@{ path = '(the whole policy)'; before = '(not in the tenant)'; after = "created again, OFF: $($want.displayName)" })
    $plan
}

function Get-EpsCaUndoTarget {
    <#
      What "Undo this change" does for ONE row of a policy's history (eps.CaStageMove), pure:
        a copy or a deploy (From 'Copy' / 'Template')   -> turn that policy OFF (never a delete)
        a removed old version (To 'Removed')            -> the policy created again from the body it had, OFF
        anything else (a stage move, an edit, a promote / roll back side, a restore) -> its body BEFORE the change put back
      Returns @{ Ok; Reason; Mode (Restore | Off); Body; Label }.
    #>
    param([Parameter(Mandatory)]$Move)
    $from = "$($Move.FromStage)"; $to = "$($Move.ToStage)"
    if ("$($Move.Result)" -notlike 'applied*') { return @{ Ok = $false; Reason = "this change was not applied ($($Move.Result)) - nothing to undo" } }
    if ($from -in 'Copy', 'Template') { return @{ Ok = $true; Mode = 'Off'; Label = "undo of the $(if ($from -eq 'Copy') { 'copy' } else { 'deploy' }) at $($Move.MovedAtUtc): turned off (not deleted)" } }
    $bj = "$($Move.BeforeJson)"
    if (-not $bj -or $bj -eq '{}') { return @{ Ok = $false; Reason = 'the history has no body from before this change' } }
    $before = $bj | ConvertFrom-Json -AsHashtable -Depth 30
    if (-not $before.Contains('displayName')) { return @{ Ok = $false; Reason = 'the history has no body from before this change' } }
    @{ Ok = $true; Mode = 'Restore'; Body = $before; Label = "undo of $from -> $to at $($Move.MovedAtUtc)" }
}

# ---- the web app's reads (and the engine's) ------------------------------------------------------------------------

function Get-EpsBackupList {
    # every backup set (CA and configuration), newest first, with what it holds
    param([Parameter(Mandatory)][string]$ConnectionString)
    $ca = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP 200 BackupId, Kind, TakenAtUtc, TakenBy, Cause, Policies, NamedLocations, AuthStrengths FROM eps.CaBackup ORDER BY BackupId DESC')
    $cf = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT TOP 200 BackupId, Kind, TakenAtUtc, TakenBy, Cause, RefId, CountsJson FROM eps.ConfigBackup ORDER BY BackupId DESC')
    @{ Ca = $ca; Config = $cf }
}

function Get-EpsCaBackupDetail {
    # one CA set: its header and its items (without their bodies), each policy compared with the last read of the tenant
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId)
    $h = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT BackupId, Kind, TakenAtUtc, TakenBy, Cause, Policies, NamedLocations, AuthStrengths FROM eps.CaBackup WHERE BackupId = @b')[0]
    if (-not $h) { return $null }
    $items = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query @'
SELECT i.ItemType, i.ObjectId, i.DisplayName, JSON_VALUE(i.BodyJson, '$.state') AS State,
       CASE WHEN i.ItemType <> 'policy' THEN NULL WHEN p.PolicyId IS NULL THEN 'not in the tenant' WHEN p.DisplayName = i.DisplayName AND p.State = JSON_VALUE(i.BodyJson, '$.state') THEN 'there' ELSE 'there (changed)' END AS Now
FROM eps.CaBackupItem i LEFT JOIN eps.CaPolicy p ON i.ItemType = 'policy' AND TRY_CONVERT(UNIQUEIDENTIFIER, i.ObjectId) = p.PolicyId
WHERE i.BackupId = @b ORDER BY i.ItemType, i.DisplayName
'@)
    @{ Header = $h; Items = $items }
}

function Get-EpsCaBackupZip {
    # the CA set as v1 exported it: one JSON file per policy, named after the policy (+ the named locations and the
    # authentication strengths in their own folders). Returns @{ Bytes; Name; Files } or $null.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId)
    $h = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT BackupId, TakenAtUtc FROM eps.CaBackup WHERE BackupId = @b')[0]
    if (-not $h) { return $null }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT ItemType, ObjectId, DisplayName, BodyJson FROM eps.CaBackupItem WHERE BackupId = @b ORDER BY ItemType, DisplayName')
    $ms = [IO.MemoryStream]::new(); $used = @{}
    $zip = [IO.Compression.ZipArchive]::new($ms, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($r in $rows) {
            $dir = switch ("$($r.ItemType)") { 'policy' { 'CAPolicies' } 'namedLocation' { 'NamedLocations' } default { 'AuthenticationStrengths' } }
            $fn = ConvertTo-EpsBackupFileName -Name "$($r.DisplayName)"
            $path = "$dir/$fn"; $i = 1
            while ($used.ContainsKey($path.ToLowerInvariant())) { $i++; $path = "$dir/$([IO.Path]::GetFileNameWithoutExtension($fn)) ($i).json" }
            $used[$path.ToLowerInvariant()] = $true
            $e = $zip.CreateEntry($path)
            $w = [IO.StreamWriter]::new($e.Open(), [Text.UTF8Encoding]::new($true))
            try { $w.Write(($r.BodyJson | ConvertFrom-Json -Depth 30 | ConvertTo-Json -Depth 30)) } finally { $w.Dispose() }
        }
    } finally { $zip.Dispose() }
    @{ Bytes = $ms.ToArray(); Name = "eps-ca-backup-$BackupId-$(([datetime]$h.TakenAtUtc).ToString('yyyyMMdd-HHmm')).zip"; Files = $rows.Count }
}

function Get-EpsCaRestoreContext {
    # what a restore plan needs from SQL: the break-glass context (no Graph), the names the engine stored, the policies as
    # last read (id -> body) and their names, the adoption of each
    param([Parameter(Mandatory)][string]$ConnectionString)
    $names = Get-EpsCaNameMap -ConnectionString $ConnectionString
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -NoGraph
    $cur = @{}; $hashes = @{}; $existing = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT PolicyId, DisplayName, BodyJson, ReviewJson FROM eps.CaPolicy')) {
        $k = "$($r.PolicyId)".ToLowerInvariant()
        if ($r.BodyJson) { $cur[$k] = $r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 30 }
        if ($r.ReviewJson) { $hashes[$k] = ($r.ReviewJson | ConvertFrom-Json).hash }
        $existing.Add("$($r.DisplayName)")
    }
    @{ Names = $names; Ctx = $ctx; Current = $cur; Hashes = $hashes; Existing = @($existing); Catalog = (Get-EpsCaTemplateCatalog) }
}

function Get-EpsCaRestorePlanFromStore {
    # the web app's preview of a restore of the picked policies of ONE backup set, from the last read of the tenant (no
    # Graph): per policy what changes, created again (off) when it is gone; the engine plans again from the LIVE tenant
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId, [string[]]$PolicyIds = @())
    $h = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT BackupId, Kind, TakenAtUtc FROM eps.CaBackup WHERE BackupId = @b')[0]
    if (-not $h) { return $null }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query "SELECT ObjectId, DisplayName, BodyJson FROM eps.CaBackupItem WHERE BackupId = @b AND ItemType = 'policy'")
    if ($PolicyIds.Count) { $want = @($PolicyIds | ForEach-Object { "$_".ToLowerInvariant() }); $rows = @($rows | Where-Object { "$($_.ObjectId)".ToLowerInvariant() -in $want }) }
    $x = Get-EpsCaRestoreContext -ConnectionString $ConnectionString
    $items = @(foreach ($r in $rows) {
        $k = "$($r.ObjectId)".ToLowerInvariant()
        $body = $r.BodyJson | ConvertFrom-Json -AsHashtable -Depth 30
        $rv = (Get-EpsCaReview -Policy $body -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog)
        $t = if ($rv.templateId) { $x.Catalog.ById["$($rv.templateId)"] }
        $p = Get-EpsCaRestorePlan -Backup $body -Current $x.Current[$k] -BreakGlass $x.Ctx.BreakGlass -IsBreakGlassPolicy ([bool]($t -and $t.breakGlassPolicy)) -Names $x.Names -ExistingNames $x.Existing -PolicyId "$($r.ObjectId)"
        $p.expected = $x.Hashes[$k]
        $p })
    [ordered]@{ backupId = $BackupId; takenAtUtc = $h.TakenAtUtc; kind = $h.Kind; items = $items
        summary = [ordered]@{ patch = @($items | Where-Object { $_.ok -and $_.action -eq 'patch' }).Count; create = @($items | Where-Object { $_.ok -and $_.action -eq 'create' }).Count
                              same = @($items | Where-Object { $_.action -eq 'none' -and $_.ok }).Count; refused = @($items | Where-Object { -not $_.ok }).Count } }
}

function Get-EpsCaUndoPlanFromStore {
    # the web app's preview of "Undo this change" (one row of a policy's history), from the last read of the tenant
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)][long]$MoveId)
    $mv = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId; m = $MoveId } -Query 'SELECT MoveId, PolicyId, DisplayName, FromStage, ToStage, BeforeJson, Result, MovedAtUtc FROM eps.CaStageMove WHERE PolicyId = @p AND MoveId = @m')[0]
    if (-not $mv) { return $null }
    $u = Get-EpsCaUndoTarget -Move $mv
    if (-not $u.Ok) { return [ordered]@{ ok = $false; reason = $u.Reason; moveId = $MoveId } }
    $x = Get-EpsCaRestoreContext -ConnectionString $ConnectionString
    $k = "$PolicyId".ToLowerInvariant()
    $cur = $x.Current[$k]
    $rv = if ($u.Body) { Get-EpsCaReview -Policy $u.Body -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog } elseif ($cur) { Get-EpsCaReview -Policy $cur -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog }
    $t = if ($rv -and $rv.templateId) { $x.Catalog.ById["$($rv.templateId)"] }
    $p = Get-EpsCaRestorePlan -Backup $u.Body -Current $cur -Mode $u.Mode -BreakGlass $x.Ctx.BreakGlass -IsBreakGlassPolicy ([bool]($t -and $t.breakGlassPolicy)) -Names $x.Names -ExistingNames $x.Existing -PolicyId "$PolicyId"
    $p.expected = $x.Hashes[$k]; $p.moveId = $MoveId; $p.label = $u.Label; $p.mode = $u.Mode
    $p
}

# ---- UNDO-BACKUP left-over: named locations and authentication strengths put back from a backup (create when missing,
# the backup's definition back when changed - NEVER deleted). The writes are EPS-OnboardWrite.ps1's Restore-EpsCaObjects
# (engine only, pinned); this part only plans.

function ConvertTo-EpsNamedLocationShape {
    # a named location -> the parts a restore compares and writes: @{ type = ip | country | other; body (what Graph takes);
    # key (compared) }
    param([Parameter(Mandatory)]$Location)
    $l = if ($Location -is [string]) { $Location | ConvertFrom-Json -AsHashtable -Depth 30 } else { ConvertTo-Json -InputObject $Location -Depth 30 -Compress | ConvertFrom-Json -AsHashtable -Depth 30 }
    $ot = "$($l['@odata.type'])"
    if ($ot -match 'ipNamedLocation') {
        $r = @(@($l.ipRanges) | Where-Object { $_ } | ForEach-Object { $c = "$($_.cidrAddress)"; [ordered]@{ '@odata.type' = $(if ($c -match ':') { '#microsoft.graph.iPv6CidrRange' } else { '#microsoft.graph.iPv4CidrRange' }); cidrAddress = $c } } | Sort-Object { $_.cidrAddress })
        $body = [ordered]@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; displayName = "$($l.displayName)"; isTrusted = [bool]$l.isTrusted; ipRanges = @($r) }
        return @{ type = 'ip'; body = $body; key = "ip|$([bool]$l.isTrusted)|$(@($r | ForEach-Object { $_.cidrAddress }) -join ',')" }
    }
    if ($ot -match 'countryNamedLocation') {
        $cc = @(@($l.countriesAndRegions) | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() } | Sort-Object -Unique)
        $m = if ("$($l.countryLookupMethod)") { "$($l.countryLookupMethod)" } else { 'clientIpAddress' }
        $body = [ordered]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; displayName = "$($l.displayName)"; countriesAndRegions = @($cc); includeUnknownCountriesAndRegions = [bool]$l.includeUnknownCountriesAndRegions; countryLookupMethod = $m }
        return @{ type = 'country'; body = $body; key = "country|$($cc -join ',')|$([bool]$l.includeUnknownCountriesAndRegions)|$m" }
    }
    @{ type = 'other'; body = $null; key = $null }
}

function Get-EpsCaObjectRestorePlan {
    <#
      PURE: what putting the picked named locations / authentication strengths of a backup back would do.
        -Backup   the backup's items (ItemType namedLocation | authStrength, ObjectId, DisplayName, BodyJson)
        -Current  @{ NamedLocations = @(...); AuthStrengths = @(...) } - the tenant now (live in the engine; the newest
                  backup in the web app's preview)
      Each item: matched by its id, else by its exact name; then
        create  - gone: made again from the backup's definition
        patch   - there but different: the backup's definition put back (a location: its whole definition; a strength:
                  its name / description, and its allowed combinations)
        none    - as in the backup already
        refused - a built-in strength (Microsoft's own), a location of a kind EPS does not write
      NOTHING is ever deleted: a location or strength made after the backup stays. Returns @{ ok; items; summary }.
    #>
    param([object[]]$Backup = @(), [hashtable]$Current = @{})
    $nl = @($Current.NamedLocations | Where-Object { $_ }); $st = @($Current.AuthStrengths | Where-Object { $_ })
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($b in @($Backup | Where-Object { $_ })) {
        $body = if ($b.BodyJson -is [string]) { $b.BodyJson | ConvertFrom-Json -AsHashtable -Depth 30 } else { ConvertTo-Json -InputObject $b.BodyJson -Depth 30 -Compress | ConvertFrom-Json -AsHashtable -Depth 30 }
        $kind = "$($b.ItemType)"; $name = "$($body.displayName)"; $bid = "$($body.id)"
        $it = [ordered]@{ kind = $kind; objectId = $bid; displayName = $name; action = 'none'; ok = $true; reason = $null; currentId = $null; changes = @(); body = $null; combinations = $null }
        if ($kind -eq 'namedLocation') {
            $want = ConvertTo-EpsNamedLocationShape -Location $body
            if ($want.type -eq 'other') { $it.ok = $false; $it.action = 'refused'; $it.reason = 'a named location of a kind Entra Policy Suite does not write - put it back by hand'; $items.Add($it); continue }
            $cur = @($nl | Where-Object { "$($_.id)" -eq $bid })[0]; if (-not $cur) { $cur = @($nl | Where-Object { "$($_.displayName)" -ceq $name })[0] }
            if (-not $cur) { $it.action = 'create'; $it.body = $want.body; $it.reason = 'not in the tenant - made again'; $items.Add($it); continue }
            $it.currentId = "$($cur.id)"
            $now = ConvertTo-EpsNamedLocationShape -Location $cur
            if ($now.type -ne $want.type) { $it.ok = $false; $it.action = 'refused'; $it.reason = "a location of this name is now a $($now.type) location - put it back by hand"; $items.Add($it); continue }
            $ch = [System.Collections.Generic.List[string]]::new()
            if ("$($cur.displayName)" -cne $name) { $ch.Add("name: $($cur.displayName) -> $name") }
            if ($now.key -ne $want.key) { $ch.Add($(if ($want.type -eq 'ip') { "ranges / trusted: $($now.key.Substring(3)) -> $($want.key.Substring(3))" } else { "countries: $($now.key.Substring(8)) -> $($want.key.Substring(8))" })) }
            if ($ch.Count) { $it.action = 'patch'; $it.body = $want.body; $it.changes = @($ch) } else { $it.reason = 'as in the backup already' }
            $items.Add($it); continue
        }
        if ($kind -eq 'authStrength') {
            if ("$($body.policyType)" -eq 'builtIn') { $it.ok = $false; $it.action = 'refused'; $it.reason = 'a built-in strength (Microsoft''s own) - it cannot be changed'; $items.Add($it); continue }
            $comb = @(@($body.allowedCombinations) | Where-Object { $_ } | ForEach-Object { "$_" } | Sort-Object -Unique)
            $cur = @($st | Where-Object { "$($_.id)" -eq $bid })[0]; if (-not $cur) { $cur = @($st | Where-Object { "$($_.displayName)" -ceq $name })[0] }
            if (-not $cur) { $it.action = 'create'; $it.body = [ordered]@{ displayName = $name; description = "$($body.description)"; allowedCombinations = @($comb) }; $it.reason = 'not in the tenant - made again'; $items.Add($it); continue }
            if ("$($cur.policyType)" -eq 'builtIn') { $it.ok = $false; $it.action = 'refused'; $it.reason = 'its name is now a built-in strength''s - put it back by hand'; $items.Add($it); continue }
            $it.currentId = "$($cur.id)"
            $ch = [System.Collections.Generic.List[string]]::new(); $patch = [ordered]@{}
            if ("$($cur.displayName)" -cne $name) { $ch.Add("name: $($cur.displayName) -> $name"); $patch.displayName = $name }
            if ("$($cur.description)" -cne "$($body.description)") { $ch.Add('description'); $patch.description = "$($body.description)" }
            $have = @(@($cur.allowedCombinations) | Where-Object { $_ } | ForEach-Object { "$_" } | Sort-Object -Unique)
            if (($have -join ',') -ne ($comb -join ',')) { $ch.Add("allowed combinations: $($have -join ' + ') -> $($comb -join ' + ')"); $it.combinations = @($comb) }
            if ($ch.Count) { $it.action = 'patch'; $it.body = $(if ($patch.Count) { $patch }); $it.changes = @($ch) } else { $it.reason = 'as in the backup already' }
            $items.Add($it); continue
        }
        $it.ok = $false; $it.action = 'refused'; $it.reason = "not a named location or an authentication strength ($kind)"; $items.Add($it)
    }
    [ordered]@{ ok = [bool]@($items | Where-Object { $_.ok -and $_.action -in 'create', 'patch' }).Count; items = @($items)
        summary = [ordered]@{ create = @($items | Where-Object { $_.ok -and $_.action -eq 'create' }).Count; patch = @($items | Where-Object { $_.ok -and $_.action -eq 'patch' }).Count
                              same = @($items | Where-Object { $_.ok -and $_.action -eq 'none' }).Count; refused = @($items | Where-Object { -not $_.ok }).Count } }
}

function Get-EpsCaObjectBackupItems {
    # the picked named locations / strengths of ONE backup (none picked = all of them); $null = no such backup
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId, [string[]]$ObjectIds = @())
    $h = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT BackupId, Kind, TakenAtUtc FROM eps.CaBackup WHERE BackupId = @b')[0]
    if (-not $h) { return $null }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query "SELECT ItemType, ObjectId, DisplayName, BodyJson FROM eps.CaBackupItem WHERE BackupId = @b AND ItemType IN ('namedLocation', 'authStrength')")
    if ($ObjectIds.Count) { $want = @($ObjectIds | ForEach-Object { "$_".ToLowerInvariant() }); $rows = @($rows | Where-Object { "$($_.ObjectId)".ToLowerInvariant() -in $want }) }
    @{ Header = $h; Rows = $rows }
}

function Get-EpsCaObjectRestorePlanFromStore {
    # the web app's preview (no Graph): compared with the NEWEST backup's copy of the tenant; the engine reads the tenant
    # again before it writes
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId, [string[]]$ObjectIds = @())
    $b = Get-EpsCaObjectBackupItems -ConnectionString $ConnectionString -BackupId $BackupId -ObjectIds $ObjectIds
    if (-not $b) { return $null }
    $last = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT TOP (1) BackupId, TakenAtUtc FROM eps.CaBackup WHERE Kind IN ('Daily', 'Manual') ORDER BY BackupId DESC")[0]
    $cur = @{ NamedLocations = @(); AuthStrengths = @() }
    if ($last) {
        foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = [long]$last.BackupId } -Query "SELECT ItemType, BodyJson FROM eps.CaBackupItem WHERE BackupId = @b AND ItemType IN ('namedLocation', 'authStrength')")) {
            $o = $r.BodyJson | ConvertFrom-Json -Depth 30
            if ("$($r.ItemType)" -eq 'namedLocation') { $cur.NamedLocations += $o } else { $cur.AuthStrengths += $o }
        }
    }
    $p = Get-EpsCaObjectRestorePlan -Backup $b.Rows -Current $cur
    $p.backupId = $BackupId; $p.takenAtUtc = $b.Header.TakenAtUtc
    $p.comparedWith = $(if ($last) { "the newest backup ($($last.BackupId), $(([datetime]$last.TakenAtUtc).ToString('yyyy-MM-dd HH:mm')) UTC) - the engine reads the tenant again before it writes" } else { 'no newer backup - the engine reads the tenant before it writes' })
    $p
}

function Get-EpsConfigBackupDetail {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId)
    $h = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT BackupId, Kind, TakenAtUtc, TakenBy, Cause, RefId, CountsJson FROM eps.ConfigBackup WHERE BackupId = @b')[0]
    if (-not $h) { return $null }
    $items = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ b = $BackupId } -Query 'SELECT Entity, ItemKey, BodyJson FROM eps.ConfigBackupItem WHERE BackupId = @b ORDER BY Entity, ItemKey')
    @{ Header = $h; Items = $items }
}

function Get-EpsConfigRestorePlan {
    <#
      The restore of a configuration backup (tagging + settings), PIM's way: the backup is compared with what is stored
      now and turned into the SAME requests a person makes on the pages - each goes through its own route (its checks, its
      journal, its audit; the commit queue stages the rules and tag types when it is on). Nothing is written here.
      Order: condition types, tag types, tag values, then each object type's rules as ONE batch (the import's own plan:
      the backup's rules CSV against the rules now, rules not in the backup deleted), then the settings, the personas and
      the monitors of the CA Policy Analyzer.
      -BackupId reads a stored backup; -Items takes the items of an IMPORT file instead (CONFIG-IO-1: @{ Entity; ItemKey;
      BodyJson }, already checked by Read-EpsConfigImportFile) and words the changes as an import (-Import).
      -Entities limits it (the undo of one commit: only what that commit touched). Returns @{ ok; requests; summary;
      counts (new / changed / same / refused); notes } - a request: @{ id; entity; key; method; path; body; summary; new }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [long]$BackupId = 0, [object[]]$Items, [string[]]$Entities = @(), [switch]$Import)
    if ($null -ne $Items) { $d = @{ Header = @{ TakenAtUtc = $null; Kind = 'Import' }; Items = @($Items) } }
    else { $d = Get-EpsConfigBackupDetail -ConnectionString $ConnectionString -BackupId $BackupId; if (-not $d) { return $null } }
    $want = { param($e) -not $Entities.Count -or $Entities -contains $e }
    $by = @{}; foreach ($i in $d.Items) { if (-not $by[$i.Entity]) { $by[$i.Entity] = [System.Collections.Generic.List[object]]::new() }; $by[$i.Entity].Add(@{ Key = "$($i.ItemKey)"; Body = ($i.BodyJson | ConvertFrom-Json) }) }
    $reqs = [System.Collections.Generic.List[object]]::new(); $notes = [System.Collections.Generic.List[string]]::new()
    $counts = [ordered]@{ new = 0; changed = 0; same = 0; refused = 0 }
    $vb = if ($Import) { @{ back = 'Change'; again = 'Create'; addAgain = 'Add'; to = 'as in the file' } } else { @{ back = 'Put back'; again = 'Create again'; addAgain = 'Add again'; to = 'back to the backup' } }
    $script:__n = 0
    $add = { param($entity, $key, $method, $path, $body, $summary, [bool]$isNew) $script:__n++; if ($isNew) { $counts.new++ } else { $counts.changed++ }
        $reqs.Add([ordered]@{ id = $script:__n; entity = $entity; key = $key; method = $method; path = $path; body = $body; summary = $summary; new = $isNew }) }
    $same = { param($a, $b, [string[]]$cols) foreach ($c in $cols) { if ("$($a.$c)" -cne "$($b.$c)") { return $false } }; $true }
    if (& $want 'ConditionType') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, Id, Property, Operator, Guard, Description, Enabled FROM eps.ConditionType')) { $now["$($r.ObjectType):$($r.Id)".ToLowerInvariant()] = $r }
        foreach ($it in @($by['ConditionType'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.ObjectType):$($b.Id)".ToLowerInvariant()]
            if ($c -and (& $same $b $c 'Property', 'Operator', 'Guard', 'Description', 'Enabled')) { $counts.same++; continue }
            & $add 'ConditionType' $it.Key 'PUT' "/api/conditions/$($b.ObjectType)/$($b.Id)" ([ordered]@{ property = $b.Property; operator = $b.Operator; guard = $b.Guard; description = $b.Description; enabled = [bool]$b.Enabled }) "$(if ($c) { $vb.back } else { $vb.again }) condition type $($b.ObjectType) $($b.Id)" (-not $c) }
    }
    if (& $want 'TagType') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, Name, Description, Attribute, ValueMode, AllowMultiple, FallbackAD, FallbackCloud, Enabled, UpdatedAtUtc FROM eps.TagType')) { $now["$($r.ObjectType):$($r.Name)".ToLowerInvariant()] = $r }
        foreach ($it in @($by['TagType'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.ObjectType):$($b.Name)".ToLowerInvariant()]
            if ($c -and (& $same $b $c 'Description', 'Attribute', 'ValueMode', 'AllowMultiple', 'FallbackAD', 'FallbackCloud', 'Enabled')) { $counts.same++; continue }
            $body = [ordered]@{ attribute = $b.Attribute; valueMode = $b.ValueMode; enabled = [bool]$b.Enabled; description = $b.Description; allowMultiple = [bool]$b.AllowMultiple; fallbackAD = $b.FallbackAD; fallbackCloud = $b.FallbackCloud }
            if ($c) { $body.expected = $(if ($c.UpdatedAtUtc -is [datetime]) { [datetime]::SpecifyKind($c.UpdatedAtUtc, 'Utc').ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'") } else { "$($c.UpdatedAtUtc)" }) }
            & $add 'TagType' $it.Key 'PUT' "/api/tagtypes/$($b.ObjectType)/$($b.Name)" $body "$(if ($c) { $vb.back } else { $vb.again }) $("$($b.ObjectType)".ToLowerInvariant()) tag type $($b.Name) ($($b.Attribute))" (-not $c) }
        $gone = @($now.Keys | Where-Object { $k = $_; -not @($by['TagType'] | Where-Object { $_ -and "$($_.Body.ObjectType):$($_.Body.Name)".ToLowerInvariant() -eq $k }).Count })
        if ($gone.Count -and @($by['TagType']).Count) { $notes.Add("tag type(s) not in the $(if ($Import) { 'file' } else { 'backup' }) stay: $(@($gone | ForEach-Object { $now[$_].Name }) -join ', ') - delete them on the Tag types page if you want them gone") }
    }
    if (& $want 'TagValue') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, TagType, Value, IsPattern, Description FROM eps.TagValue')) { $now["$($r.ObjectType):$($r.TagType):$($r.Value)".ToLowerInvariant()] = $r }
        foreach ($it in @($by['TagValue'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.ObjectType):$($b.TagType):$($b.Value)".ToLowerInvariant()]
            if ($c -and (& $same $b $c 'IsPattern', 'Description')) { $counts.same++; continue }
            & $add 'TagValue' $it.Key 'PUT' "/api/tagtypes/$($b.ObjectType)/$($b.TagType)/values" ([ordered]@{ value = $b.Value; description = $b.Description; isPattern = [bool]$b.IsPattern }) "$(if ($c) { $vb.back } else { $vb.addAgain }) value '$($b.Value)' of $($b.TagType)" (-not $c) }
    }
    foreach ($ot in 'User', 'Device') {
        if (-not (& $want "${ot}TagRule")) { continue }
        $it = @($by['Rules'] | Where-Object { $_ -and $_.Key -eq $ot })[0]
        if (-not $it) { continue }
        $cur = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ot)
        $p = ConvertFrom-EpsRuleCsv -Text "$($it.Body.csv)" -ObjectType $ot -Current $cur -DeleteMissing
        $ops = @($p.Ops)
        foreach ($e in @($p.Errors)) { $notes.Add("$ot rules: $e"); $counts.refused++ }
        if ($ops.Count) {
            $chk = Test-EpsRuleBatch -ConnectionString $ConnectionString -ObjectType $ot -Ops $ops -Current $cur
            if ($chk -and @($chk.Items | Where-Object unchanged).Count) { $ops = @(for ($i = 0; $i -lt $ops.Count; $i++) { if (-not $chk.Items[$i].unchanged) { $ops[$i] } }) }
        }
        if ($ops.Count) { & $add "${ot}TagRule" $ot 'POST' "/api/rules/$ot/batch" ([ordered]@{ ops = @($ops) }) "$ot rules $($vb.to): $($ops.Count) change(s) (rules not in the $(if ($Import) { 'file' } else { 'backup' }) are deleted)" $false }
        else { $counts.same++ }
    }
    if (& $want 'Setting') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Value FROM eps.Setting')) { $now["$($r.Name)".ToLowerInvariant()] = $r }
        foreach ($it in @($by['Setting'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.Name)".ToLowerInvariant()]
            if (Test-EpsBackupSecret -Name "$($b.Name)" -Value "$($b.Value)") { $counts.refused++; $notes.Add("setting $($b.Name) looks like a secret - never imported or restored"); continue }
            if ($c -and "$($c.Value)" -ceq "$($b.Value)") { $counts.same++; continue }
            $e = Get-EpsSettingEntry "$($b.Name)"
            if (-not $e) { $counts.refused++; $notes.Add("setting $($b.Name) is not in this version's catalog - left as it is"); continue }
            if ($e.editable -eq $false) { $counts.refused++; $notes.Add("setting $($b.Name) is set by $($e.setBy), not here - left as it is"); continue }
            & $add 'Setting' $it.Key 'PUT' "/api/settings/$($b.Name)" ([ordered]@{ value = $b.Value; expected = $(if ($c) { $c.Value } else { $null }) }) "Setting $($e.label): '$(if ($c) { $c.Value } else { '(default)' })' -> '$($b.Value)'" (-not $c) }
    }
    if (& $want 'Persona') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, PolicyIdsJson, RulesJson, ExcludeIdsJson FROM eps.CaPersona')) { $now["$($r.Name)".ToLowerInvariant()] = $r }
        $norm = { param($j) (@(if ($j -is [string]) { $j | ConvertFrom-Json } else { $j }) | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique) -join ',' }
        foreach ($it in @($by['Persona'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.Name)".ToLowerInvariant()]
            if ("$($b.Name)" -notmatch '^[A-Za-z0-9_.-]{1,100}$') { $counts.refused++; $notes.Add("persona '$($b.Name)': not a name a persona can have - left out"); continue }
            if ($c -and (& $norm $c.PolicyIdsJson) -eq (& $norm $b.PolicyIds) -and (& $norm $c.RulesJson) -eq (& $norm $b.Rules) -and (& $norm $c.ExcludeIdsJson) -eq (& $norm $b.ExcludeIds)) { $counts.same++; continue }
            & $add 'Persona' $it.Key 'PUT' "/api/ca/personas/$($b.Name)" ([ordered]@{ policyIds = @($b.PolicyIds); rules = @($b.Rules); excludeIds = @($b.ExcludeIds) }) "$(if ($c) { $vb.back } else { $vb.again }) persona $($b.Name)" (-not $c) }
    }
    if (& $want 'Monitor') {
        $now = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Definition, Schedule, Enabled FROM eps.CaMonitor')) { $now["$($r.Name)".ToLowerInvariant()] = $r }
        foreach ($it in @($by['Monitor'])) { if (-not $it) { continue }; $b = $it.Body; $c = $now["$($b.Name)".ToLowerInvariant()]
            if ("$($b.Name)" -notmatch $script:EpsCaMonitorNamePattern) { $counts.refused++; $notes.Add("monitor '$($b.Name)': not a name a monitor can have - left out"); continue }
            $defJ = ConvertTo-Json -InputObject $b.Definition -Depth 20 -Compress
            if ($c -and ((("$($c.Definition)" | ConvertFrom-Json) | ConvertTo-Json -Depth 20 -Compress) -ceq $defJ) -and "$($c.Schedule)" -ceq "$($b.Schedule)" -and [bool]$c.Enabled -eq [bool]$b.Enabled) { $counts.same++; continue }
            & $add 'Monitor' $it.Key 'PUT' "/api/ca/monitors/$([uri]::EscapeDataString("$($b.Name)"))" ([ordered]@{ definition = $b.Definition; schedule = "$($b.Schedule)"; enabled = [bool]$b.Enabled }) "$(if ($c) { $vb.back } else { $vb.again }) monitor $($b.Name) ($($b.Schedule)$(if (-not $b.Enabled) { ', off' }))" (-not $c) }
    }
    if (@($by['Scope']).Count) { $notes.Add("saved scopes are in the $(if ($Import) { 'file' } else { 'backup' }) ($(@($by['Scope']).Count)) but are put back by hand (Jobs: saved scopes)") }
    [ordered]@{ ok = $true; backupId = $(if ($BackupId) { $BackupId }); takenAtUtc = $d.Header.TakenAtUtc; kind = $d.Header.Kind; requests = @($reqs); notes = @($notes); counts = $counts
        summary = "$($reqs.Count) change(s) to make: $(@($reqs | Group-Object entity | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ') - $($counts.new) new, $($counts.changed) changed, $($counts.same) the same, $($counts.refused) refused" }
}

function Get-EpsCommitUndoPlan {
    # "Undo this commit" of the tagging configuration: the backup taken just BEFORE that commit, limited to what the
    # commit touched (its rules' object type, its tag types / values / condition types). Later commits on the same rules
    # are undone with it - the plan shows every change before anything is sent.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$CommitId)
    $b = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = "$CommitId" } -Query 'SELECT TOP 1 BackupId FROM eps.ConfigBackup WHERE RefId = @r ORDER BY BackupId DESC')[0]
    if (-not $b) { return [ordered]@{ ok = $false; reason = 'no backup was taken before this commit (it is older than the backups) - restore a daily backup instead'; requests = @() } }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ c = $CommitId } -Query "SELECT Entity, ObjectType FROM eps.PendingChange WHERE CommitId = @c AND Status = 'Applied'")
    if (-not $rows.Count) { return [ordered]@{ ok = $false; reason = 'this commit applied nothing'; requests = @() } }
    $ents = @($rows | ForEach-Object { "$($_.Entity)" } | Select-Object -Unique)
    $p = Get-EpsConfigRestorePlan -ConnectionString $ConnectionString -BackupId ([long]$b.BackupId) -Entities $ents
    $p.commitId = "$CommitId"
    if (-not @($p.requests).Count) { $p.ok = $false; $p.reason = 'nothing to undo: what this commit changed is as it was before it already' }
    $p
}

function Get-EpsTagRunUndoPreview {
    # what "Undo this run" would put back (from SQL; the engine reads every object again before it writes)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId)
    $run = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $RunId } -Query 'SELECT RunId, Job, Mode, Status, StartedAtUtc FROM eps.Run WHERE RunId = @r')[0]
    if (-not $run) { return $null }
    $why = Test-EpsTagRunUndoable -ConnectionString $ConnectionString -Run $run
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $RunId } -Query "SELECT TOP 500 ObjectName, Directory, TagType, Attribute, OldValue, NewValue FROM eps.TagChange WHERE RunId = @r AND Status = 'Applied' ORDER BY ObjectName")
    $n = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ r = $RunId } -Query "SELECT COUNT(*) FROM eps.TagChange WHERE RunId = @r AND Status = 'Applied'")
    [ordered]@{ ok = -not $why; reason = $why; runId = "$RunId"; job = $run.Job; startedAtUtc = $run.StartedAtUtc; applied = $n
        changes = @($rows | ForEach-Object { [ordered]@{ object = $_.ObjectName; directory = $_.Directory; tagType = $_.TagType; attribute = $_.Attribute; now = $_.NewValue; back = $_.OldValue } })
        notes = @('Each object is read again first: a tag someone changed after this run is left as it is (never overwritten).', 'AD-synced users are written by the hybrid worker, as tagging does.', 'The mass-change guard measures the undo like a run; a held undo is approved by sending it again with Approve.') }
}

function Test-EpsTagRunUndoable {
    # $null = it can be undone; else why not
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Run)
    if ("$($Run.Job)" -notin 'UserTagging', 'DeviceTagging') { return 'only a tagging run is undone here' }
    if ("$($Run.Mode)" -ne 'Apply') { return "a $($Run.Mode) run wrote nothing - nothing to undo" }
    if ("$($Run.Status)" -notin 'Succeeded', 'PartlyFailed') { return "the run is $($Run.Status) - it applied nothing to undo" }
    $done = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $Run.RunId } -Query "SELECT TOP 1 RunId, Status FROM eps.Run WHERE UndoOfRunId = @r AND Mode = 'Undo' AND Status IN ('Succeeded', 'PartlyFailed') ORDER BY StartedAtUtc DESC")[0]
    if ($done) { return "it was undone already (run $($done.RunId))" }
    $null
}

# ---- the engine: backups ------------------------------------------------------------------------------------------

function Read-EpsCaBackupContent {
    # every Conditional Access policy (adopted or not), named location and authentication strength, as Graph returns them
    # (v1's export read beta/conditionalAccess/policies; v1.0 holds the same policy parts the product writes)
    $pol = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/policies' -All)
    $loc = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All)
    $str = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/authenticationStrength/policies' -All)
    @{ Policies = $pol; NamedLocations = $loc; AuthStrengths = $str }
}

function Save-EpsCaBackupSet {
    # ONE immutable set (header + items) in one transaction; returns its id
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('Daily', 'BeforeChange', 'Manual')][string]$Kind, [object[]]$Policies = @(), [object[]]$NamedLocations = @(),
          [object[]]$AuthStrengths = @(), [Parameter(Mandatory)][string]$TakenBy, [string]$Cause)
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @(@{ T = 'policy'; L = $Policies }, @{ T = 'namedLocation'; L = $NamedLocations }, @{ T = 'authStrength'; L = $AuthStrengths })) {
        foreach ($o in @($x.L)) { if ($null -eq $o) { continue }; $items.Add([ordered]@{ t = $x.T; i = "$($o.id)"; n = "$($o.displayName)"; b = (ConvertTo-Json -InputObject $o -Depth 30 -Compress) }) }
    }
    $j = ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
    [long](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Timeout 300 -Parameters @{ k = $Kind; by = $TakenBy; c = $(if ($Cause) { $Cause.Substring(0, [math]::Min(400, $Cause.Length)) } else { $null })
        p = @($Policies | Where-Object { $_ }).Count; nl = @($NamedLocations | Where-Object { $_ }).Count; a = @($AuthStrengths | Where-Object { $_ }).Count; j = $j } -Query @'
SET XACT_ABORT ON; SET NOCOUNT ON; BEGIN TRAN;
DECLARE @b BIGINT;
INSERT INTO eps.CaBackup (Kind, TakenBy, Cause, Policies, NamedLocations, AuthStrengths) VALUES (@k, @by, @c, @p, @nl, @a);
SET @b = SCOPE_IDENTITY();
INSERT INTO eps.CaBackupItem (BackupId, ItemType, ObjectId, DisplayName, BodyJson)
SELECT @b, x.t, x.i, LEFT(x.n, 400), x.b FROM OPENJSON(@j) WITH (t NVARCHAR(20) '$.t', i NVARCHAR(64) '$.i', n NVARCHAR(MAX) '$.n', b NVARCHAR(MAX) '$.b') AS x;
COMMIT;
SELECT @b;
'@)
}

function Backup-EpsCaBeforeWrite {
    <#
      PIM's "a snapshot before every commit": the engine stores the policies a change is about to touch, as read LIVE,
      BEFORE its write. Returns @{ Ok; BackupId; Reason } - not Ok = the caller REFUSES the change (no change without its
      way back). Never throws.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Policies = @(), [Parameter(Mandatory)][string]$Cause, [Parameter(Mandatory)][string]$Actor)
    try {
        $id = Save-EpsCaBackupSet -ConnectionString $ConnectionString -Kind BeforeChange -Policies @($Policies | Where-Object { $_ }) -TakenBy $Actor -Cause $Cause
        @{ Ok = $true; BackupId = $id }
    } catch { @{ Ok = $false; Reason = "the backup before the change could not be written ($($_.Exception.Message))" } }
}

function ConvertTo-EpsBackupRow {
    param($Row, [string[]]$Columns)
    $o = [ordered]@{}; foreach ($c in $Columns) { $v = $Row.$c; $o[$c] = if ($v -is [datetime]) { [datetime]::SpecifyKind($v, 'Utc').ToString('o') } else { $v } }; $o
}

function Get-EpsConfigSnapshot {
    # the tagging configuration and the non-secret settings, as items (Entity, Key, Body)
    param([Parameter(Mandatory)][string]$ConnectionString)
    $items = [System.Collections.Generic.List[object]]::new(); $counts = [ordered]@{}
    $put = { param($e, $k, $b) $items.Add([ordered]@{ e = $e; k = "$k"; b = (ConvertTo-Json -InputObject $b -Depth 12 -Compress) }); $counts[$e] = 1 + [int]$counts[$e] }
    foreach ($ot in 'User', 'Device') {
        $cards = @(Read-EpsRuleCardsForEdit -ConnectionString $ConnectionString -ObjectType $ot)
        $tb = ConvertTo-EpsRuleCsvTable -Cards $cards -ObjectType $ot
        & $put 'Rules' $ot ([ordered]@{ objectType = $ot; rules = $cards.Count; csv = (ConvertTo-EpsCsv -Rows $tb.Rows -Columns $tb.Columns) })
    }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, Name, Description, Attribute, ValueMode, AllowMultiple, FallbackAD, FallbackCloud, FallbackFromProperty, Enabled FROM eps.TagType')) { & $put 'TagType' "$($r.ObjectType):$($r.Name)" (ConvertTo-EpsBackupRow $r 'ObjectType', 'Name', 'Description', 'Attribute', 'ValueMode', 'AllowMultiple', 'FallbackAD', 'FallbackCloud', 'FallbackFromProperty', 'Enabled') }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, TagType, Value, IsPattern, Description FROM eps.TagValue')) { & $put 'TagValue' "$($r.ObjectType):$($r.TagType):$($r.Value)" (ConvertTo-EpsBackupRow $r 'ObjectType', 'TagType', 'Value', 'IsPattern', 'Description') }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT ObjectType, Id, Property, Operator, Guard, Description, Enabled FROM eps.ConditionType')) { & $put 'ConditionType' "$($r.ObjectType):$($r.Id)" (ConvertTo-EpsBackupRow $r 'ObjectType', 'Id', 'Property', 'Operator', 'Guard', 'Description', 'Enabled') }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, ObjectType, Kind, Definition FROM eps.Scope')) { & $put 'Scope' "$($r.Name)" (ConvertTo-EpsBackupRow $r 'Name', 'ObjectType', 'Kind', 'Definition') }
    $skipped = 0
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Value FROM eps.Setting')) {
        if (Test-EpsBackupSecret -Name "$($r.Name)" -Value "$($r.Value)") { $skipped++; continue }   # a secret is never stored
        & $put 'Setting' "$($r.Name)" (ConvertTo-EpsBackupRow $r 'Name', 'Value')
    }
    if ($skipped) { $counts.SecretsLeftOut = $skipped }
    @{ Items = @($items); Counts = $counts }
}

# ---- CONFIG-IO-1 (DESIGN §3 "Export / import / undo of every rule set and setting"; framework CONFIG-IO-1): the whole
# configuration as ONE file - the same items a configuration backup holds (rules, tag types and values, condition types,
# saved scopes, the non-secret settings) plus the CA Policy Analyzer's personas and monitors. An import is the SAME path as
# a restore: Get-EpsConfigRestorePlan -Items turns the file into the requests the pages make, each sent through its own
# route (its checks, journal, audit; the commit queue stages what it stages). Never in the file: secrets, approvals,
# decisions, the audit trail, the journal, adoption records, backups.
$script:EpsConfigFormat = 'eps-configuration'
$script:EpsConfigEntities = @('Rules', 'TagType', 'TagValue', 'ConditionType', 'Scope', 'Setting', 'Persona', 'Monitor')
$script:EpsConfigMaxItems = 20000
$script:EpsConfigMaxBytes = 900KB   # the web app takes a request of at most 1 MB

function Get-EpsConfigExport {
    # the export file (an ordered object; the route sends it as JSON)
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$ExportedBy, [string]$Version)
    $s = Get-EpsConfigSnapshot -ConnectionString $ConnectionString
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($i in $s.Items) { $items.Add([ordered]@{ entity = $i.e; key = $i.k; body = ($i.b | ConvertFrom-Json -Depth 20) }) }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, PolicyIdsJson, RulesJson, ExcludeIdsJson FROM eps.CaPersona ORDER BY Name')) {
        $items.Add([ordered]@{ entity = 'Persona'; key = "$($r.Name)"; body = [ordered]@{ Name = "$($r.Name)"; PolicyIds = @("$($r.PolicyIdsJson)" | ConvertFrom-Json); Rules = @("$($r.RulesJson)" | ConvertFrom-Json); ExcludeIds = @("$(if ($r.ExcludeIdsJson -isnot [DBNull]) { $r.ExcludeIdsJson } else { '[]' })" | ConvertFrom-Json) } })
    }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Name, Definition, Schedule, Enabled FROM eps.CaMonitor ORDER BY Name')) {
        $items.Add([ordered]@{ entity = 'Monitor'; key = "$($r.Name)"; body = [ordered]@{ Name = "$($r.Name)"; Definition = ("$($r.Definition)" | ConvertFrom-Json -Depth 20); Schedule = "$($r.Schedule)"; Enabled = [bool]$r.Enabled } })
    }
    $counts = [ordered]@{}; foreach ($g in @($items | Group-Object { $_.entity })) { $counts[$g.Name] = $g.Count }
    if ($s.Counts.SecretsLeftOut) { $counts.SecretsLeftOut = $s.Counts.SecretsLeftOut }
    [ordered]@{ format = $script:EpsConfigFormat; formatVersion = 1; productVersion = $Version; exportedAtUtc = [datetime]::UtcNow.ToString('o'); exportedBy = $ExportedBy
        note = 'Entra Policy Suite configuration (CONFIG-IO-1). Secrets, approvals, records and the audit trail are never in it. Import it on Administration > Settings: every change is shown first.'
        counts = $counts; items = @($items) }
}

function Read-EpsConfigImportFile {
    <#
      Checks an import file (the parsed JSON, or its text) and returns @{ Ok; Error; Items (Entity, ItemKey, BodyJson - the
      shape Get-EpsConfigRestorePlan takes); Refused (count); Notes }. Refused, never imported: an entity this file format
      does not carry (records, approvals, the journal, ...), a setting that looks like a secret.
    #>
    param($File)
    $f = $File
    if ($f -is [string]) {
        if ([Text.Encoding]::UTF8.GetByteCount($f) -gt $script:EpsConfigMaxBytes) { return @{ Ok = $false; Error = "the file is larger than $($script:EpsConfigMaxBytes / 1KB) KB - export a part (the rules CSV on the Tagging page) or ask support" } }
        try { $f = $f | ConvertFrom-Json -Depth 30 } catch { return @{ Ok = $false; Error = 'the file is not JSON - export one from Administration > Settings' } }
    }
    if (-not $f -or "$($f.format)" -ne $script:EpsConfigFormat) { return @{ Ok = $false; Error = "not an Entra Policy Suite configuration file - export one from Administration > Settings" } }
    if ([int]"$($f.formatVersion)" -ne 1) { return @{ Ok = $false; Error = "format version $($f.formatVersion) is not known to this version - export it again" } }
    $all = @($f.items)
    if ($all.Count -gt $script:EpsConfigMaxItems) { return @{ Ok = $false; Error = "$($all.Count) items - at most $($script:EpsConfigMaxItems)" } }
    $items = [System.Collections.Generic.List[object]]::new(); $notes = [System.Collections.Generic.List[string]]::new(); $refused = 0
    foreach ($i in $all) {
        $e = "$($i.entity)"
        if ($e -notin $script:EpsConfigEntities) { $refused++; $notes.Add("'$e' is never imported (only rules, tag types and values, condition types, saved scopes, settings, personas and monitors)"); continue }
        if ($null -eq $i.body) { $refused++; $notes.Add("$e '$($i.key)': no body - left out"); continue }
        if ($e -eq 'Setting' -and (Test-EpsBackupSecret -Name "$($i.body.Name)" -Value "$($i.body.Value)")) { $refused++; $notes.Add("setting $($i.body.Name) looks like a secret - never imported"); continue }
        $items.Add(@{ Entity = $e; ItemKey = "$($i.key)"; BodyJson = (ConvertTo-Json -InputObject $i.body -Depth 20 -Compress) })
    }
    @{ Ok = $true; Items = @($items); Refused = $refused; Notes = @($notes | Select-Object -Unique)
       From = [ordered]@{ productVersion = "$($f.productVersion)"; exportedAtUtc = "$($f.exportedAtUtc)"; exportedBy = "$($f.exportedBy)" } }
}

function Save-EpsConfigBackupSet {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('Daily', 'BeforeChange', 'Manual')][string]$Kind, [Parameter(Mandatory)][string]$TakenBy, [string]$Cause, [string]$RefId)
    $s = Get-EpsConfigSnapshot -ConnectionString $ConnectionString
    [long](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Timeout 300 -Parameters @{ k = $Kind; by = $TakenBy; c = $(if ($Cause) { $Cause.Substring(0, [math]::Min(400, $Cause.Length)) } else { $null }); r = $(if ($RefId) { $RefId } else { $null })
        cj = ($s.Counts | ConvertTo-Json -Compress); j = (ConvertTo-Json -InputObject @($s.Items) -Depth 4 -Compress) } -Query @'
SET XACT_ABORT ON; SET NOCOUNT ON; BEGIN TRAN;
DECLARE @b BIGINT;
INSERT INTO eps.ConfigBackup (Kind, TakenBy, Cause, RefId, CountsJson) VALUES (@k, @by, @c, @r, @cj);
SET @b = SCOPE_IDENTITY();
INSERT INTO eps.ConfigBackupItem (BackupId, Entity, ItemKey, BodyJson)
SELECT @b, x.e, LEFT(x.k, 400), x.b FROM OPENJSON(@j) WITH (e NVARCHAR(40) '$.e', k NVARCHAR(MAX) '$.k', b NVARCHAR(MAX) '$.b') AS x;
COMMIT;
SELECT @b;
'@)
}

function Backup-EpsConfigBeforeCommit {
    # the snapshot before a commit of the tagging configuration (Invoke-EpsCommitQueue); @{ Ok; BackupId; Reason }, never throws
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$CommitId, [Parameter(Mandatory)][string]$Actor)
    try { @{ Ok = $true; BackupId = (Save-EpsConfigBackupSet -ConnectionString $ConnectionString -Kind BeforeChange -TakenBy $Actor -Cause "before commit $CommitId" -RefId "$CommitId") } }
    catch { @{ Ok = $false; Reason = "the backup before the commit could not be written ($($_.Exception.Message))" } }
}

function Remove-EpsExpiredBackups {
    # retention (owner 2026-11-05 "daily keep 30"): the newest 30 daily sets of each kind of backup; a snapshot before a
    # change and a manual one 30 days. Returns how many sets were removed.
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$KeepDaily = $script:EpsBackupKeepDaily, [int]$KeepDays = $script:EpsBackupKeepDays)
    $p = @{ k = $KeepDaily; d = $KeepDays }
    $ca = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters $p -Query @'
SET XACT_ABORT ON; SET NOCOUNT ON; BEGIN TRAN;
DECLARE @x TABLE (Id BIGINT PRIMARY KEY);
INSERT INTO @x (Id) SELECT BackupId FROM eps.CaBackup
 WHERE (Kind = 'Daily' AND BackupId NOT IN (SELECT TOP (@k) BackupId FROM eps.CaBackup WHERE Kind = 'Daily' ORDER BY BackupId DESC))
    OR (Kind <> 'Daily' AND TakenAtUtc < DATEADD(day, -@d, SYSUTCDATETIME()));
DELETE FROM eps.CaBackupItem WHERE BackupId IN (SELECT Id FROM @x);
DELETE FROM eps.CaBackup WHERE BackupId IN (SELECT Id FROM @x);
COMMIT;
SELECT COUNT(*) FROM @x;
'@)
    $cf = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters $p -Query @'
SET XACT_ABORT ON; SET NOCOUNT ON; BEGIN TRAN;
DECLARE @x TABLE (Id BIGINT PRIMARY KEY);
INSERT INTO @x (Id) SELECT BackupId FROM eps.ConfigBackup
 WHERE (Kind = 'Daily' AND BackupId NOT IN (SELECT TOP (@k) BackupId FROM eps.ConfigBackup WHERE Kind = 'Daily' ORDER BY BackupId DESC))
    OR (Kind <> 'Daily' AND TakenAtUtc < DATEADD(day, -@d, SYSUTCDATETIME()));
DELETE FROM eps.ConfigBackupItem WHERE BackupId IN (SELECT Id FROM @x);
DELETE FROM eps.ConfigBackup WHERE BackupId IN (SELECT Id FROM @x);
COMMIT;
SELECT COUNT(*) FROM @x;
'@)
    $ca + $cf
}

function Invoke-EpsBackupJob {
    <#
      The Backup job (daily, and "Back up now"): ONE CA set (every policy, named location and authentication strength, as
      read) and ONE configuration set, each read back; then the retention. Reads the tenant only.
      Returns @{ CaBackupId; ConfigBackupId; Policies; NamedLocations; AuthStrengths; ConfigItems; Removed; Lines }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [ValidateSet('Daily', 'Manual')][string]$Kind = 'Daily', [string]$Actor = 'Backup job', [string]$Cause = 'the daily backup', [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $c = Read-EpsCaBackupContent
    $caId = Save-EpsCaBackupSet -ConnectionString $ConnectionString -Kind $Kind -Policies $c.Policies -NamedLocations $c.NamedLocations -AuthStrengths $c.AuthStrengths -TakenBy $Actor -Cause $Cause
    $back = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ b = $caId } -Query "SELECT COUNT(*) FROM eps.CaBackupItem WHERE BackupId = @b AND ItemType = 'policy'")
    if ($back -ne $c.Policies.Count) { throw "the CA backup $caId was read back with $back of $($c.Policies.Count) policies" }
    & $Log 'Info' "Conditional Access backup $caId`: $($c.Policies.Count) policies, $($c.NamedLocations.Count) named locations, $($c.AuthStrengths.Count) authentication strengths (read back)"
    $cfId = Save-EpsConfigBackupSet -ConnectionString $ConnectionString -Kind $Kind -TakenBy $Actor -Cause $Cause
    $items = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ b = $cfId } -Query 'SELECT COUNT(*) FROM eps.ConfigBackupItem WHERE BackupId = @b')
    $counts = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ b = $cfId } -Query 'SELECT CountsJson FROM eps.ConfigBackup WHERE BackupId = @b'
    & $Log 'Info' "configuration backup $cfId`: $items item(s) $counts (read back; secrets are never stored)"
    $rm = Remove-EpsExpiredBackups -ConnectionString $ConnectionString
    & $Log 'Info' "retention: $rm old set(s) removed (the newest $script:EpsBackupKeepDaily daily sets kept; others $script:EpsBackupKeepDays days)"
    @{ CaBackupId = $caId; ConfigBackupId = $cfId; Policies = $c.Policies.Count; NamedLocations = $c.NamedLocations.Count; AuthStrengths = $c.AuthStrengths.Count; ConfigItems = $items; Removed = $rm }
}

# ---- the engine: undo of a tagging run -----------------------------------------------------------------------------

function Get-EpsTagObjectValue {
    # an object's current value of one extension attribute, as Graph returns it
    param($Object, [string]$ObjectType, [string]$Attribute)
    $bag = if ($ObjectType -eq 'User') { $Object.onPremisesExtensionAttributes } else { $Object.extensionAttributes }
    if ($null -eq $bag) { return $null }
    $v = if ($bag -is [System.Collections.IDictionary]) { $bag[$Attribute] } else { $bag.$Attribute }
    if ([string]::IsNullOrEmpty("$v")) { $null } else { "$v" }
}

function Invoke-EpsTagRunUndo {
    <#
      "Undo this run" (DESIGN §5 "undo this run puts every user's old tag back"): a NEW run (Mode Undo, UndoOfRunId) that
      writes back the old value of every tag the run applied - only where the object still has the value that run wrote
      (a later change, by a run or a person, is never overwritten: it is skipped and listed). The same path as tagging: the
      mass-change guard measures it (held unless approved), cloud objects through Graph (Exchange for a mail-enabled
      user), AD-synced users as work packages for the hybrid worker; every change in eps.TagChange (Reason Undo).
      Returns @{ Result = ok | held | refused | missing; Reason; RunId; Planned; Applied; Failed; Queued; Skipped }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [Parameter(Mandatory)][string]$Actor, [string]$Reason, [switch]$Approve,
          [string]$TenantId = $env:EPS_TENANT_ID, [hashtable]$GuardSettings = @{}, [object[]]$Objects)
    $run = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $RunId } -Query 'SELECT RunId, Job, Mode, Status FROM eps.Run WHERE RunId = @r')[0]
    if (-not $run) { return @{ Result = 'missing'; Reason = 'no such run' } }
    $why = Test-EpsTagRunUndoable -ConnectionString $ConnectionString -Run $run
    if ($why) { return @{ Result = 'refused'; Reason = $why } }
    $ot = if ($run.Job -eq 'UserTagging') { 'User' } else { 'Device' }
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ r = $RunId } -Query "SELECT ChangeId, ObjectType, ObjectId, ObjectName, Directory, TagType, Attribute, OldValue, NewValue, Persona, RuleIds FROM eps.TagChange WHERE RunId = @r AND Status = 'Applied' ORDER BY ChangeId")
    if (-not $rows.Count) { return @{ Result = 'refused'; Reason = 'the run applied no change - nothing to undo' } }
    # every object read again (15 ids per filter, Graph's limit)
    if (-not $Objects) {
        $ids = @($rows | ForEach-Object { "$($_.ObjectId)" } | Select-Object -Unique); $sel = @(Get-EpsTagBaseSelect -ObjectType $ot); $got = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $ids.Count; $i += 15) {
            $f = "id in ($((@($ids[$i..([math]::Min($i + 14, $ids.Count - 1))]) | ForEach-Object { "'$([guid]$_)'" }) -join ','))"
            foreach ($o in @($(if ($ot -eq 'User') { Get-EpsUsers -Select $sel -Filter $f } else { Get-EpsDevices -Select $sel -Filter $f }))) { if ($o) { $got.Add($o) } }
        }
        $Objects = @($got)
    }
    $byId = @{}; foreach ($o in $Objects) { $byId["$($o.id)".ToLowerInvariant()] = $o }
    $changes = [System.Collections.Generic.List[object]]::new(); $skips = [System.Collections.Generic.List[string]]::new(); $overwrites = 0; $byRule = @{}
    $last = @{}   # the LAST value the run wrote per object + attribute (a run writes one value per attribute; be sure)
    foreach ($r in $rows) { $last["$($r.ObjectId)|$($r.Attribute)".ToLowerInvariant()] = $r }
    foreach ($k in $last.Keys) {
        $r = $last[$k]; $o = $byId["$($r.ObjectId)".ToLowerInvariant()]
        if (-not $o) { $skips.Add("$($r.ObjectName): no longer in the directory"); continue }
        $now = Get-EpsTagObjectValue -Object $o -ObjectType $ot -Attribute $r.Attribute
        $wrote = if ([string]::IsNullOrEmpty("$($r.NewValue)")) { $null } else { "$($r.NewValue)" }
        if ("$now" -cne "$wrote") { $skips.Add("$($r.ObjectName) $($r.Attribute): changed since the run ('$now', the run wrote '$wrote') - left as it is"); continue }
        $back = if ([string]::IsNullOrEmpty("$($r.OldValue)")) { $null } else { "$($r.OldValue)" }
        if ($now -and $back) { $overwrites++ }
        $rule = "undo of $RunId"; $byRule[$rule] = 1 + [int]$byRule[$rule]
        $changes.Add([pscustomobject]@{ ObjectType = $ot; ObjectId = "$($r.ObjectId)"; ObjectName = $r.ObjectName; Directory = $r.Directory; TagType = $r.TagType; Attribute = $r.Attribute
            OldValue = $now; NewValue = $back; Reason = 'Undo'; Persona = $r.Persona; RuleIds = @("$($r.RuleIds)" -split ',' | Where-Object { $_ }); Status = 'Planned'
            OnPremisesSecurityIdentifier = $o.onPremisesSecurityIdentifier; OnPremisesUserPrincipalName = $o.onPremisesUserPrincipalName })
    }
    $newRun = [guid]::NewGuid(); $job = $run.Job
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $newRun; j = $job; a = $(if ($Approve) { $Actor } else { $null }); u = $RunId; s = (@{ undoOf = "$RunId"; by = $Actor; reason = $Reason } | ConvertTo-Json -Compress) } `
        -Query "INSERT INTO eps.Run (RunId, Job, Mode, Scope, ApprovedBy, UndoOfRunId) VALUES (@id, @j, 'Undo', @s, @a, @u)" | Out-Null
    $seq = 0; $log = { param($l, $m) $script:__useq++; Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $newRun; s = $script:__useq; l = $l; m = $m } -Query 'INSERT INTO eps.RunLog (RunId, Seq, Level, Message) VALUES (@r, @s, @l, @m)' | Out-Null }
    $script:__useq = 0
    & $log 'Info' "undo of run $RunId ($job) by $Actor$(if ($Reason) { ": $Reason" }) - $($changes.Count) tag(s) to put back, $($skips.Count) left as they are"
    foreach ($s in $skips | Select-Object -First 200) { & $log 'Info' "  skipped: $s" }
    $objs = @($changes | ForEach-Object { $_.ObjectId } | Select-Object -Unique).Count
    $sum = @{ Objects = $objs; Changes = $changes.Count; Overwrites = $overwrites; ByRule = $byRule }
    $prev = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ j = $job; id = $newRun } -Query "SELECT TOP 1 Planned, Overwrites FROM eps.Run WHERE Job = @j AND Mode = 'Apply' AND Status IN ('Succeeded', 'PartlyFailed') AND Scope IS NULL AND RunId <> @id ORDER BY StartedAtUtc DESC")[0]
    $g = Test-EpsMassChangeGuard -Summary $sum -Previous $prev -Settings $GuardSettings -Job $job -ApprovedBy $(if ($Approve) { $Actor } else { $null })
    $status = 'Succeeded'; $applied = 0; $failed = 0; $queued = 0; $held = $null
    if ($g.Held) {
        $status = 'Held'; $held = $g.Reason
        & $log 'Warning' "HELD by the mass-change guard: $($g.Reason) - send the undo again with Approve to apply it"
        foreach ($c in $changes) { $c.Status = 'Skipped'; $c | Add-Member -NotePropertyName Error -NotePropertyValue 'undo held by the mass-change guard' -Force }
    } elseif ($changes.Count) {
        $ctx = @{}
        if ($ot -eq 'User' -and $TenantId -and @($changes | Where-Object { $_.Directory -ne 'AD' }).Count) { try { $ctx.Mailboxes = Get-EpsExchangeRecipients -TenantId $TenantId } catch { & $log 'Warning' "Exchange recipients not read ($($_.Exception.Message)) - a mail-enabled user Graph refuses fails" } }
        $res = Invoke-EpsApplyChanges -ObjectType $ot -Changes @($changes) -Context $ctx -TenantId $TenantId
        $applied = $res.Applied; $failed = $res.Failed; $queued = $res.Queued
        if ($failed) { $status = 'PartlyFailed'; & $log 'Warning' "$failed change(s) failed - see the run's changes" }
    }
    [void](Write-EpsTagChanges -ConnectionString $ConnectionString -RunId $newRun -Changes @($changes))
    if ($queued) { [void](Add-EpsWorkPackages -ConnectionString $ConnectionString -RunId $newRun -Changes @($changes)); & $log 'Info' "$queued AD-synced change(s) queued for the hybrid worker" }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $newRun; st = $status; h = $held; o = $objs; p = $changes.Count; ow = $overwrites; a = $applied; f = $failed; sk = $skips.Count } `
        -Query 'UPDATE eps.Run SET EndedAtUtc = SYSUTCDATETIME(), Status = @st, HeldReason = @h, Objects = @o, Planned = @p, Overwrites = @ow, Applied = @a, Failed = @f, Skipped = @sk WHERE RunId = @id' | Out-Null
    @{ Result = $(if ($g.Held) { 'held' } else { 'ok' }); Reason = $held; RunId = "$newRun"; Planned = $changes.Count; Applied = $applied; Failed = $failed; Queued = $queued; Skipped = $skips.Count; SkippedText = @($skips | Select-Object -First 20) }
}
