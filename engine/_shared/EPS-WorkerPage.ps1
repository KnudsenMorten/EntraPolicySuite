# EntraPolicySuite -- the Hybrid worker page (WORKER-GUI, 2.0.82 - owner 2026-11-05: "i didnt see the ad hybrid worker
# anywhere in the gui or where to configure it or see the services" / "is that not built") and the AD environments
# (V1-PARITY P14). Loaded by the web app (reads SQL only: Get-EpsWorkerPage, Get-EpsWorkerSetup) and the engine (the
# two Admin actions it applies from a signed request: New-EpsWorkerTestPackage, Invoke-EpsWorkPackageRetry) - never by
# the worker (EPS-HybridWorker.ps1), which has no right to queue work.
# Dot-source EPS-SqlStore and EPS-Scheduler (Get-EpsSetting) first.

Set-StrictMode -Off
function ConvertFrom-EpsEnvironmentMap {
    <#
      V1-PARITY P14 (several AD environments - v1 ran its scripts once per environment: Internal_Prod, DMZ_Prod,
      Internal_Dev, Internal_Test, each with its own domain): the setting HybridWorker.EnvironmentByUpnSuffix, one line
      per environment "<upn suffix>=<environment>" (e.g. "dmz.contoso.com=DMZ_Prod"). Returns the entries, longest suffix
      first (so a sub-domain wins over its parent) - @{ Suffix; Environment } - and the lines it could not read.
    #>
    param($Value)
    $lines = @(if ($Value -is [string]) { $t = "$Value".Trim(); if ($t.StartsWith('[')) { try { @($t | ConvertFrom-Json) } catch { @($t -split "`n") } } else { @($t -split "`n") } } else { @($Value) })
    $ok = [System.Collections.Generic.List[object]]::new(); $bad = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $lines) {
        $s = "$l".Trim(); if (-not $s) { continue }
        if ($s -match '^@?(?<suffix>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*=\s*(?<env>[A-Za-z0-9_-]{1,50})$') { $ok.Add([pscustomobject]@{ Suffix = $Matches.suffix.ToLowerInvariant(); Environment = $Matches.env }) } else { $bad.Add($s) }
    }
    @{ Entries = @($ok | Sort-Object { $_.Suffix.Length } -Descending); Bad = @($bad) }
}

function Get-EpsWorkEnvironment {
    # The AD environment of an AD-synced user: the entry whose suffix ends the user's on-premises UPN (longest first);
    # none = $null (the package goes to any worker - one environment, as before P14).
    param([string]$Upn, [object[]]$Entries = @())
    $u = "$Upn".ToLowerInvariant(); if (-not $u.Contains('@')) { return $null }
    $dom = $u.Substring($u.IndexOf('@') + 1)
    foreach ($e in $Entries) { if ($dom -eq $e.Suffix -or $dom.EndsWith(".$($e.Suffix)")) { return $e.Environment } }
    $null
}

# ---------------- the cloud side: the Hybrid worker page (WORKER-GUI, 2.0.82) ----------------
function Get-EpsWorkerPage {
    <#
      Everything the Administration > Hybrid worker page shows, from SQL only (the web app reads, never writes): each
      worker with its scheduled task, AD domain, environment, version against the release (Behind) and last seen against
      HybridWorker.StaleMinutes (Stale); the queue by state and environment; packages per day (14 days); the failed and
      waiting packages with what they were for; the last connection tests; the AD environments set up (P14) and the
      environments that wait for a worker of their own.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$ReleaseVersion = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $sql = { param($q, $p = @{}) @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters $p -Query $q) }
    $stale = [int](Get-EpsSetting -ConnectionString $ConnectionString -Name 'HybridWorker.StaleMinutes' -Default '15'); if ($stale -lt 5) { $stale = 15 }
    $map = ConvertFrom-EpsEnvironmentMap (Get-EpsSetting -ConnectionString $ConnectionString -Name 'HybridWorker.EnvironmentByUpnSuffix' -Default '[]')
    $rel = $null; try { $rel = [version]("$ReleaseVersion" -replace '[^0-9.].*$', '') } catch { $rel = $null }
    $workers = @(foreach ($w in & $sql 'SELECT * FROM eps.WorkerHeartbeat ORDER BY WorkerName') {
        $seen = [datetime]$w.LastSeenUtc
        $v = $null; try { $v = [version]("$($w.Version)" -replace '[^0-9.].*$', '') } catch { $v = $null }
        [ordered]@{ name = "$($w.WorkerName)"; machine = "$($w.Machine)"; runAs = "$($w.RunAs)"; version = "$($w.Version)"; lastSeenUtc = $seen.ToString('o'); lastResult = "$($w.LastResult)"
            adDomain = "$($w.AdDomain)"; adServer = "$($w.AdServer)"; environment = "$($w.Environment)"; hostType = "$($w.HostType)"
            taskState = "$($w.TaskState)"; taskEnabled = $(if ($w.TaskEnabled -is [DBNull] -or $null -eq $w.TaskEnabled) { $null } else { [bool]$w.TaskEnabled })
            taskLastRunUtc = $(if ($w.TaskLastRunUtc -is [DBNull] -or $null -eq $w.TaskLastRunUtc) { $null } else { ([datetime]$w.TaskLastRunUtc).ToString('o') }); taskLastResult = "$($w.TaskLastResult)"
            taskNextRunUtc = $(if ($w.TaskNextRunUtc -is [DBNull] -or $null -eq $w.TaskNextRunUtc) { $null } else { ([datetime]$w.TaskNextRunUtc).ToString('o') })
            # WORKER-UPD (2.0.102): the worker's last daily update (Update-EpsHybridWorker.ps1, as SYSTEM)
            updateResult = "$($w.UpdateResult)"; updateAtUtc = $(if ($w.UpdateAtUtc -is [DBNull] -or $null -eq $w.UpdateAtUtc) { $null } else { ([datetime]$w.UpdateAtUtc).ToString('o') })
            stale = ($seen -lt $NowUtc.AddMinutes(-$stale)); minutesSinceSeen = [int][math]::Floor(($NowUtc - $seen).TotalMinutes)
            behind = [bool]($rel -and $v -and $v -lt $rel); ahead = [bool]($rel -and $v -and $v -gt $rel)
            taskProblem = ("$($w.TaskState)" -in 'Disabled', 'Missing' -or ($w.TaskEnabled -isnot [DBNull] -and $null -ne $w.TaskEnabled -and -not [bool]$w.TaskEnabled)) } })
    $counts = @(foreach ($r in & $sql "SELECT Status, ISNULL(Environment, '') AS Environment, COUNT(*) AS N FROM eps.WorkPackage WHERE Kind = 'AdSetAttribute' GROUP BY Status, ISNULL(Environment, '')") { [ordered]@{ status = "$($r.Status)"; environment = "$($r.Environment)"; count = [int]$r.N } })
    $perDay = @(foreach ($r in & $sql "SELECT CAST(QueuedAtUtc AS DATE) AS Day, SUM(1) AS Queued, SUM(CASE WHEN Status = 'Done' THEN 1 ELSE 0 END) AS Done, SUM(CASE WHEN Status = 'Failed' THEN 1 ELSE 0 END) AS Failed FROM eps.WorkPackage WHERE Kind = 'AdSetAttribute' AND QueuedAtUtc >= @f GROUP BY CAST(QueuedAtUtc AS DATE) ORDER BY Day DESC" @{ f = $NowUtc.Date.AddDays(-13) }) { [ordered]@{ day = ([datetime]$r.Day).ToString('yyyy-MM-dd'); queued = [int]$r.Queued; done = [int]$r.Done; failed = [int]$r.Failed } })
    $pkgCols = "PackageId, Kind, Status, Attempts, ClaimedBy, Error, ISNULL(Environment, '') AS Environment, QueuedAtUtc, ClaimedAtUtc, DoneAtUtc, ChangeId, RequestedBy, JSON_VALUE(Payload, '$.upn') AS Upn, JSON_VALUE(Payload, '$.attribute') AS Attribute, JSON_VALUE(Payload, '$.value') AS Value, JSON_VALUE(Payload, '$.retryOf') AS RetryOf"
    $retried = @{}; foreach ($r in & $sql "SELECT JSON_VALUE(Payload, '$.retryOf') AS R FROM eps.WorkPackage WHERE Kind = 'AdSetAttribute' AND JSON_VALUE(Payload, '$.retryOf') IS NOT NULL") { $retried["$($r.R)"] = $true }
    $shape = { param($r) [ordered]@{ packageId = [long]$r.PackageId; status = "$($r.Status)"; attempts = [int]$r.Attempts; claimedBy = "$($r.ClaimedBy)"; error = "$($r.Error)"; environment = "$($r.Environment)"
        queuedAtUtc = ([datetime]$r.QueuedAtUtc).ToString('o'); doneAtUtc = $(if ($r.DoneAtUtc -is [DBNull] -or $null -eq $r.DoneAtUtc) { $null } else { ([datetime]$r.DoneAtUtc).ToString('o') })
        upn = "$($r.Upn)"; attribute = "$($r.Attribute)"; value = "$($r.Value)"; retryOf = "$($r.RetryOf)"; requestedBy = "$($r.RequestedBy)"
        retried = [bool]$retried["$($r.PackageId)"]; canRetry = ("$($r.Status)" -eq 'Failed' -and -not $retried["$($r.PackageId)"] -and (Test-EpsWorkPackageRetryable -ErrorText "$($r.Error)")) } }
    $failed = @(foreach ($r in & $sql "SELECT TOP (200) $pkgCols FROM eps.WorkPackage WHERE Kind = 'AdSetAttribute' AND Status = 'Failed' ORDER BY DoneAtUtc DESC, PackageId DESC") { & $shape $r })
    $waiting = @(foreach ($r in & $sql "SELECT TOP (200) $pkgCols FROM eps.WorkPackage WHERE Kind = 'AdSetAttribute' AND Status IN ('Queued', 'Claimed') ORDER BY QueuedAtUtc") { & $shape $r })
    $tests = @(foreach ($r in & $sql "SELECT TOP (10) PackageId, Status, Error, Result, ISNULL(Environment, '') AS Environment, ClaimedBy, RequestedBy, QueuedAtUtc, DoneAtUtc FROM eps.WorkPackage WHERE Kind = 'AdPing' ORDER BY PackageId DESC") {
        [ordered]@{ packageId = [long]$r.PackageId; status = "$($r.Status)"; answer = $(if ("$($r.Result)") { "$($r.Result)" } else { "$($r.Error)" }); environment = "$($r.Environment)"; worker = "$($r.ClaimedBy)"; requestedBy = "$($r.RequestedBy)"
            queuedAtUtc = ([datetime]$r.QueuedAtUtc).ToString('o'); doneAtUtc = $(if ($r.DoneAtUtc -is [DBNull] -or $null -eq $r.DoneAtUtc) { $null } else { ([datetime]$r.DoneAtUtc).ToString('o') }) } })
    $envs = @($map.Entries | ForEach-Object Environment | Select-Object -Unique)
    $served = @($workers | Where-Object { -not $_.stale } | ForEach-Object { $_.environment })
    $noWorker = @(@($envs) + @($counts | Where-Object { $_.status -in 'Queued', 'Claimed' -and $_.environment } | ForEach-Object environment) | Select-Object -Unique | Where-Object { $_ -and $served -notcontains $_ })
    [ordered]@{ workers = $workers; staleMinutes = $stale; release = "$ReleaseVersion"; counts = $counts; perDay = $perDay; failed = $failed; waiting = $waiting; tests = $tests
        environments = @($map.Entries | ForEach-Object { [ordered]@{ suffix = $_.Suffix; environment = $_.Environment } }); environmentErrors = @($map.Bad); environmentsWithoutWorker = $noWorker
        anyWorkerForUnrouted = [bool](@($workers | Where-Object { -not $_.stale -and -not $_.environment }).Count) }
}

function Test-EpsWorkPackageRetryable {
    # A failed package may be tried again unless the worker refused it because it did not match the engine's own record
    # (SEC-AUDIT-1 S3: a package rewritten in the queue is never written - a retry must not give it a second chance)
    param([string]$ErrorText)
    $ErrorText -notmatch '^refused: (the package|change \d+|the package has no change record)'
}

function New-EpsWorkerTestPackage {
    # "Test connection" (Admin, applied by the engine): ONE read-only package; the next cycle of a worker of -Environment
    # (none = any) answers what it is connected to. Returns the package id.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Actor, [string]$Environment = '')
    if ($Environment -and $Environment -notmatch '^[A-Za-z0-9_-]{1,50}$') { throw "'$Environment' is not an AD environment name" }
    [long](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ e = $(if ($Environment) { $Environment } else { [DBNull]::Value }); a = $Actor; p = (@{ test = $true; environment = $Environment } | ConvertTo-Json -Compress) } -Query "INSERT INTO eps.WorkPackage (Kind, Payload, Status, Environment, RequestedBy) OUTPUT INSERTED.PackageId VALUES ('AdPing', @p, 'Queued', @e, @a)")
}

function Invoke-EpsWorkPackageRetry {
    <#
      "Try again" on a failed AD tag change (Admin, a reason, applied by the engine). Never edits the failed rows: a NEW
      change record (Reason 'Retry', the same user / attribute / value, Queued) and a NEW package pointing at it
      (payload retryOf = the failed package), so the worker's match check passes on the engine's own record and the
      history keeps both. Refused: not a failed tag package, already tried again, or refused by the worker as not
      matching the engine's record. Returns @{ Ok; Status; Reason; PackageId; ChangeId }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$PackageId, [Parameter(Mandatory)][string]$Actor)
    $p = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ id = $PackageId } -Query 'SELECT PackageId, Kind, Status, Error, ChangeId, RunId, Payload, Environment FROM eps.WorkPackage WHERE PackageId = @id')[0]
    if (-not $p) { return @{ Ok = $false; Status = 404; Reason = "no work package $PackageId" } }
    if ("$($p.Kind)" -ne 'AdSetAttribute' -or "$($p.Status)" -ne 'Failed') { return @{ Ok = $false; Status = 409; Reason = "package $PackageId is $($p.Kind) / $($p.Status) - only a FAILED tag change can be tried again" } }
    if (-not (Test-EpsWorkPackageRetryable -ErrorText "$($p.Error)")) { return @{ Ok = $false; Status = 409; Reason = "package $PackageId was refused because it did not match the engine's own record - it is never tried again (the next tagging run queues the change anew)" } }
    if ([int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ r = "$PackageId" } -Query "SELECT COUNT(*) FROM eps.WorkPackage WHERE JSON_VALUE(Payload, '$.retryOf') = @r") -gt 0) { return @{ Ok = $false; Status = 409; Reason = "package $PackageId was tried again already" } }
    if ($p.ChangeId -is [DBNull] -or -not $p.ChangeId) { return @{ Ok = $false; Status = 409; Reason = "package $PackageId has no change record - it cannot be tried again" } }
    $ch = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ c = [long]$p.ChangeId } -Query 'SELECT RunId, ObjectType, ObjectId, ObjectName, Directory, TagType, Attribute, OldValue, NewValue, Persona, RuleIds FROM eps.TagChange WHERE ChangeId = @c')[0]
    if (-not $ch) { return @{ Ok = $false; Status = 409; Reason = "change $($p.ChangeId) does not exist" } }
    $pl = $p.Payload | ConvertFrom-Json -AsHashtable; $pl.retryOf = "$PackageId"
    $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ run = $ch.RunId; ot = $ch.ObjectType; oid = $ch.ObjectId; on = $ch.ObjectName; d = $ch.Directory; tt = $ch.TagType; at = $ch.Attribute; ov = $ch.OldValue; nv = $ch.NewValue; pe = $ch.Persona; ri = $ch.RuleIds
            pl = ($pl | ConvertTo-Json -Compress); env = $p.Environment; a = $Actor } -Query @'
SET XACT_ABORT ON; BEGIN TRAN;
DECLARE @c TABLE (ChangeId BIGINT);
INSERT INTO eps.TagChange (RunId, ObjectType, ObjectId, ObjectName, Directory, TagType, Attribute, OldValue, NewValue, Reason, Persona, RuleIds, Status)
OUTPUT INSERTED.ChangeId INTO @c VALUES (@run, @ot, @oid, @on, @d, @tt, @at, @ov, @nv, 'Retry', @pe, @ri, 'Queued');
DECLARE @k TABLE (PackageId BIGINT);
INSERT INTO eps.WorkPackage (Kind, ChangeId, RunId, Payload, Status, Environment, RequestedBy) OUTPUT INSERTED.PackageId INTO @k
SELECT 'AdSetAttribute', ChangeId, @run, @pl, 'Queued', @env, @a FROM @c;
COMMIT;
SELECT (SELECT TOP 1 ChangeId FROM @c) AS ChangeId, (SELECT TOP 1 PackageId FROM @k) AS PackageId;
'@)[0]
    @{ Ok = $true; Status = 200; PackageId = [long]$r.PackageId; ChangeId = [long]$r.ChangeId; Reason = "queued again as package $($r.PackageId) (change $($r.ChangeId)); a worker takes it on its next cycle (every 5 minutes)" }
}

function Get-EpsOnboardFixCommands {
    <#
      ADMIN-WALK-2 N6: Get started's "Fix it" commands for THIS install - runnable, with this install's values filled in
      (as the Hybrid worker page's), never "-?". What the web app cannot know (the sender mailbox, the recipients when
      not set) stays a <placeholder>. @{ <step key> = @{ script; command; who } }
    #>
    param([string]$TenantId = '', [string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID, [string]$ResourceGroup = $env:EPS_RESOURCE_GROUP, [string]$Recipients = '')
    $base = 'https://invardia.com/support/eps'
    $line = { param($script, $args0) "Invoke-WebRequest $base/$script.ps1 -OutFile .\$script.ps1; .\$script.ps1 $args0" }
    $t = if ($TenantId) { $TenantId } else { '<tenant id>' }; $s = if ($SubscriptionId) { $SubscriptionId } else { '<subscription id>' }
    $rg = if ($ResourceGroup) { " -ResourceGroup $ResourceGroup" } else { '' }
    if ($Recipients -match '^\s*\[') { $Recipients = try { @($Recipients | ConvertFrom-Json) -join ',' } catch { '' } }
    $rc = if ($Recipients) { "'$($Recipients.Replace("'", "''"))'" } else { "'<alerts@contoso.com>'" }
    [ordered]@{
        rights = [ordered]@{ script = 'Grant-EpsEnginePermissions'; who = 'a Global Administrator (or Privileged Role Administrator)'
            command = & $line 'Grant-EpsEnginePermissions' "-TenantId $t -SubscriptionId $s$rg" }
        mail = [ordered]@{ script = 'Initialize-EpsMailSender'; who = 'an Exchange administrator'
            command = & $line 'Initialize-EpsMailSender' "-TenantId $t -SubscriptionId $s -Sender '<eps-alerts@contoso.com>' -Recipients $rc$rg" }
    }
}

function Get-EpsWorkerSetup {
    <#
      "Add a worker": the three commands for THIS install, in order, with this install's values filled in (the database,
      the tenant, the subscription and resource group where the web app knows them) - each a self-contained script at
      invardia.com/support/eps/. What is not known here stays a <placeholder> the person fills in.
    #>
    param([string]$ConnectionString = '', [string]$TenantId = '', [string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID, [string]$ResourceGroup = $env:EPS_RESOURCE_GROUP, [string]$Environment = '')
    $sqlServer = if ($ConnectionString -match '(?i)Server\s*=\s*(tcp:)?(?<s>[a-z0-9-]+\.database\.windows\.net)') { $Matches.s } else { '<name>.database.windows.net' }
    $base = 'https://invardia.com/support/eps'
    # download the one self-contained file, then run it (a file keeps its #Requires lines - Install needs an elevated shell)
    $line = { param($script, $args0) "Invoke-WebRequest $base/$script.ps1 -OutFile .\$script.ps1; .\$script.ps1 $args0" }
    $t = if ($TenantId) { $TenantId } else { '<tenant id>' }; $s = if ($SubscriptionId) { $SubscriptionId } else { '<subscription id>' }
    @(
        [ordered]@{ step = 1; script = 'Initialize-EpsHybridWorkerAd'; where = 'An AD admin, on any domain-joined machine'
            what = 'Gives the worker the right to write EXACTLY the tag attributes you choose on user (and, for device tags, computer) objects, at the domain root - through the group <gMSA>-PermissionGroup (the gMSA its only member), nothing else. Without -Apply it only shows the plan.'
            needs = 'A gMSA your AD admin created for the worker computer (the domain needs a KDS root key); the tag attributes you use.'
            command = & $line 'Initialize-EpsHybridWorkerAd' "-Gmsa 'gmsa-eps' -Attributes <extensionAttribute6, extensionAttribute7> -Apply" }
        [ordered]@{ step = 2; script = 'Install-EpsHybridWorker'; where = 'On the worker: a domain-joined Windows server (an Azure VM or an Azure Arc-enabled server), elevated'
            what = 'Copies the worker, locks its folder down, writes worker.json (the database and the worker''s name - no secret) and registers the scheduled task ''EntraPolicySuite Hybrid Worker'' (every 5 minutes, as the gMSA). -WhatIf shows every step.'
            needs = 'PowerShell 7; the machine''s managed identity (a VM: Identity on; Arc: built in); the gMSA from step 1.'
            command = & $line 'Install-EpsHybridWorker' "-GmsaName '<DOMAIN>\gmsa-eps`$' -SqlServer $sqlServer$(if ($Environment) { " -Environment $Environment" })" }
        [ordered]@{ step = 3; script = 'Grant-EpsHybridWorkerAccess'; where = 'Anyone allowed to start a job in the install''s resource group (a browser sign-in)'
            what = 'Gives the worker machine''s managed identity access to the database, in the worker role only (the work packages, its heartbeat, the AD group snapshots).'
            needs = 'The client id of the worker machine''s managed identity (a VM: Identity in the portal; Arc: the server''s enterprise application).'
            command = & $line 'Grant-EpsHybridWorkerAccess' "-TenantId $t -SubscriptionId $s -WorkerClientId <client id>$(if ($ResourceGroup) { " -ResourceGroup $ResourceGroup" })" }
    )
}

