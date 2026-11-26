# EntraPolicySuite -- the hybrid worker's UPDATE (WORKER-UPD, 2.0.102; every hour since 2.1.1, WORKER-UPD-2; framework §5.5, Invardia 2026-11-08: "copy
# PIM's design" - PIM's Install-PimHybridWorker.ps1 -Phase Update - "PLUS what PIM lacks: a worker self-test after the
# switch and an automatic flip-back on failure, recorded and on the heartbeat").
#
# A scheduled task as SYSTEM (never the gMSA) runs tools\eps-hybrid-worker\Update-EpsHybridWorker.ps1 every hour (once a day before 2.1.1):
#   1. the version THIS install runs and its ring: eps.Setting 'update-head-check' (the cloud's update job writes it; since 2.1.1 the engine's tick keeps its version = the version that runs)
#   2. Invardia's SIGNED Community manifest of that ring (GET /api/updates/entrapolicysuite/community/<ring>, no install key),
#      verified by InvardiaUpdate.verify.ps1 (embedded CN=Invardia-Updates keys; product, kind, ring, sequence, size, https)
#      - the worker moves ONLY when the signed version IS the install's version (it follows the install, never runs ahead)
#   3. a lower sequence than the one applied here is refused (<Root>\update-state.json, per ring); never backwards
#   4. the archive: the signed SHA-256 + size; the VERSION inside = the manifest's; only the worker's parts are taken, and a
#      path under pro\ refuses the release (a Pro install's worker runs the Community files of the same version)
#   5. unpacked next to the running version (<Root>\versions\<v>); <Root>\app is a JUNCTION switched to it - the worker's
#      task path never changes; the previous version is kept
#   6. the ACLs again; the NEW version's self-test; on a failure the junction goes BACK to the previous version
#   7. the outcome on the heartbeat (eps.WorkerHeartbeat UpdateResult / UpdateAtUtc) and in <Root>\logs\update-<date>.log
# Dot-source EPS-SqlStore.ps1, InvardiaUpdate.verify.ps1 and EPS-Updater.ps1 (Get-EpsUpdateTarget) first.

Set-StrictMode -Off
$script:EpsWorkerParts = @('engine\_shared', 'tools\eps-hybrid-worker', 'VERSION')
$script:EpsWorkerRequiredFiles = @('VERSION', 'engine\_shared\EPS-SqlStore.ps1', 'engine\_shared\EPS-AdDirectory.ps1', 'engine\_shared\EPS-AdDelegation.ps1', 'engine\_shared\EPS-HybridWorker.ps1',
    'engine\_shared\EPS-WorkerUpdate.ps1', 'engine\_shared\EPS-Updater.ps1', 'engine\_shared\InvardiaUpdate.verify.ps1',
    'tools\eps-hybrid-worker\Start-EpsHybridWorker.ps1', 'tools\eps-hybrid-worker\Update-EpsHybridWorker.ps1')
$script:EpsWorkerUpdateTask = 'EntraPolicySuite Hybrid Worker Update'

function Get-EpsWorkerFileList {
    <# The worker's files in a release tree (relative paths): only engine\_shared, tools\eps-hybrid-worker and VERSION. #>
    param([Parameter(Mandatory)][string]$Tree)
    $full = (Resolve-Path -LiteralPath $Tree).Path.TrimEnd('\')
    foreach ($p in $script:EpsWorkerParts) {
        $x = Join-Path $full $p
        if (Test-Path -LiteralPath $x -PathType Leaf) { $p; continue }
        if (Test-Path -LiteralPath $x) { Get-ChildItem -LiteralPath $x -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($full.Length + 1) } }
    }
}

function Test-EpsWorkerFileList {
    <# PURE. The worker's file list: every required file there, NOTHING under a pro folder (Invardia 2026-11-08: the
       Community files only). @{ Ok; Reason }. #>
    param([string[]]$Names = @())
    $n = @($Names | Where-Object { $_ } | ForEach-Object { "$_".Replace('/', '\').TrimStart('\') })
    $pro = @($n | Where-Object { $_ -match '(?i)(^|\\)pro(\\|$)' })
    if ($pro.Count) { return @{ Ok = $false; Reason = "the worker's files hold Pro code ($($pro[0])) - refused: the worker runs the Community files only" } }
    $miss = @($script:EpsWorkerRequiredFiles | Where-Object { $n -notcontains $_ })
    if ($miss.Count) { return @{ Ok = $false; Reason = "the release has no $($miss -join ', ') - not a worker this update can install" } }
    @{ Ok = $true; Reason = '' }
}

function Read-EpsWorkerInstallState {
    <# The version this install runs and its ring, as its update job wrote them (eps.Setting 'update-head-check'). #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $v = $null
    try { $v = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = N'update-head-check'" }
    catch { return @{ Ok = $false; Ring = -1; Version = ''; Reason = "the install's version could not be read: $((("$($_.Exception.Message)") -split "`n")[0])" } }
    ConvertFrom-EpsWorkerInstallState -Value $v
}

function ConvertFrom-EpsWorkerInstallState {
    <# PURE. The setting's JSON -> @{ Ok; Ring; Version; Reason }. #>
    param([AllowNull()][object]$Value)
    $no = { param($why) @{ Ok = $false; Ring = -1; Version = ''; Reason = $why } }
    if ($null -eq $Value -or $Value -is [DBNull] -or -not "$Value".Trim()) { return (& $no "the install has not said which version it runs yet (its update job writes it every night)") }
    $j = $null; try { $j = "$Value" | ConvertFrom-Json } catch { return (& $no "the install's update state is not readable") }
    $r = -1; if (-not [int]::TryParse("$($j.ring)", [ref]$r) -or $r -lt 0 -or $r -gt 3) { return (& $no "the install names no update ring") }
    $ver = "$($j.version)".Trim()
    if ($ver -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') { return (& $no "the install has not said which version it runs yet (it does from 2.0.102, after its next update check)") }
    @{ Ok = $true; Ring = $r; Version = $ver; Reason = '' }
}

$script:EpsWorkerRecheckSoonMinutes = 10
function Get-EpsWorkerRecheckMinutes {
    <# PURE. WORKER-RECHECK-1 (Invardia 2026-11-13: "fix the system rather than just waiting it out"): when the update check
       WAITED because the install runs an older version than the ring's signed release (the install is updating), the next
       check is in 10 minutes; anything else = the hourly check. The worker still never runs ahead of the install. #>
    param([string]$Outcome, [bool]$Soon)
    if ($Outcome -eq 'waiting' -and $Soon) { return $script:EpsWorkerRecheckSoonMinutes }
    60
}

function Get-EpsWorkerUpdateTriggerPlan {
    <# PURE. The update task's triggers for the next check: always the hourly repetition; plus ONE extra run at
       -NowLocal + -Minutes when that is sooner than the hour (a one-time trigger, replaced at the next check). #>
    param([int]$Minutes = 60, [datetime]$NowLocal = (Get-Date))
    @{ Hourly = $true; Once = $(if ($Minutes -gt 0 -and $Minutes -lt 60) { $NowLocal.AddMinutes($Minutes) } else { $null }) }
}

function Get-EpsWorkerUpdateDecision {
    <#
      PURE. -Install (Read-EpsWorkerInstallState), -Running (the worker's VERSION), -Target (Get-EpsUpdateTarget for the
      install's ring). @{ Action = install | none | wait | refused; Reason }:
        none     the worker runs the install's version
        wait     nothing to do yet (the install has not said its version, the ring's signed release is not the install's
                 version yet, Invardia unreachable, a held release) - asked again at the next check (hourly; 10 minutes
                 once per hour while the ring is newer than the install, WORKER-RECHECK-1)
        refused  the answer did not verify, or it would move the worker backwards
        install  the signed release IS the install's version and newer than the worker's
    #>
    param([Parameter(Mandatory)][hashtable]$Install, [AllowEmptyString()][string]$Running, [Parameter(Mandatory)][hashtable]$Target)
    if (-not $Install.Ok) { return @{ Action = 'wait'; Reason = $Install.Reason } }
    if ("$Running".Trim() -eq $Install.Version) { return @{ Action = 'none'; Reason = "the worker runs $Running, the version this install runs" } }
    switch ("$($Target.State)") {
        'refused'     { return @{ Action = 'refused'; Reason = "the signed release did not verify: $($Target.Reason)" } }
        'unreachable' { return @{ Action = 'wait'; Reason = "Invardia could not be asked: $($Target.Reason)" } }
        'held'        { return @{ Action = 'wait'; Reason = "the signed release is held: $($Target.Reason)" } }
    }
    $tv = "$($Target.Version)".Trim()
    if (-not $tv) { return @{ Action = 'wait'; Reason = "no signed release for ring $($Install.Ring) yet: $($Target.Reason)" } }
    # WORKER-RECHECK-1: the ring's signed release is NEWER than the install's version = the install is about to update - Soon =
    # check again in 10 minutes, not in an hour (an install AHEAD of its ring, a test install, is not "updating": hourly)
    if ($tv -ne $Install.Version) { return @{ Action = 'wait'; Soon = ((Compare-InvardiaReleaseVersion $tv $Install.Version) -gt 0); Reason = "the signed release of ring $($Install.Ring) is $tv, the install runs $($Install.Version) - the worker follows the install" } }
    if ("$Running".Trim() -and (Compare-InvardiaReleaseVersion $tv "$Running") -lt 0) { return @{ Action = 'refused'; Reason = "the install runs $tv, older than the worker's $Running - the worker never moves backwards" } }
    @{ Action = 'install'; Reason = "$($Target.Reason) - the version this install runs" }
}

function Get-EpsWorkerAppTarget {
    <# Where <Root>\app points: @{ Kind = junction | folder | none; Path; Version }. #>
    param([Parameter(Mandatory)][string]$Root)
    $app = Join-Path $Root 'app'
    if (-not (Test-Path -LiteralPath $app)) { return @{ Kind = 'none'; Path = ''; Version = '' } }
    $i = Get-Item -LiteralPath $app -Force
    $vf = Join-Path $app 'VERSION'
    $ver = if (Test-Path -LiteralPath $vf) { "$(Get-Content -LiteralPath $vf -Raw)".Trim() } else { '' }
    if ($i.LinkType -eq 'Junction' -or $i.LinkType -eq 'SymbolicLink') { $t = $i.Target; if ($t -is [array]) { $t = $t[0] }; return @{ Kind = 'junction'; Path = "$t"; Version = $ver } }
    @{ Kind = 'folder'; Path = $i.FullName; Version = $ver }
}

function Set-EpsWorkerAppLink {
    <# Points <Root>\app at -Target: a NEW junction app.next first, then the old link goes and app.next is renamed - the
       worker's task path (<Root>\app\tools\...) never changes. An install from before 2.0.102 (app is a folder) is moved to
       <Root>\versions\<its version> first. Returns the previous target (the folder to switch back to). #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Target)
    $app = Join-Path $Root 'app'; $next = Join-Path $Root 'app.next'
    if (-not (Test-Path -LiteralPath (Join-Path $Target 'VERSION'))) { throw "$Target holds no worker (no VERSION) - not switched" }
    $cur = Get-EpsWorkerAppTarget -Root $Root
    $prev = $cur.Path
    if ($cur.Kind -eq 'folder') {
        $vd = Join-Path $Root 'versions'; New-Item -ItemType Directory -Force -Path $vd | Out-Null
        $name = if ($cur.Version -match '^\d+\.\d+\.\d+(\.\d+)?$') { $cur.Version } else { 'previous' }
        $prev = Join-Path $vd $name
        if (Test-Path -LiteralPath $prev) { $prev = Join-Path $vd "$name-$([datetime]::UtcNow.ToString('yyyyMMddHHmmss'))" }
        Move-Item -LiteralPath $app -Destination $prev
    }
    if (Test-Path -LiteralPath $next) { (Get-Item -LiteralPath $next -Force).Delete() }
    New-Item -ItemType Junction -Path $next -Target $Target | Out-Null
    if (Test-Path -LiteralPath $app) { (Get-Item -LiteralPath $app -Force).Delete() }   # a junction: only the link goes
    Move-Item -LiteralPath $next -Destination $app
    $now = Get-EpsWorkerAppTarget -Root $Root
    if ($now.Kind -ne 'junction' -or -not (Test-Path -LiteralPath (Join-Path $app 'VERSION'))) { throw "the junction $app -> $Target did not resolve" }
    $prev
}

function Copy-EpsWorkerParts {
    <# Only the worker's parts of a release tree into -Destination (a pro folder is never copied - and refused before). #>
    param([Parameter(Mandatory)][string]$Tree, [Parameter(Mandatory)][string]$Destination)
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    foreach ($p in $script:EpsWorkerParts) {
        $s = Join-Path $Tree $p; if (-not (Test-Path -LiteralPath $s)) { continue }
        $d = Join-Path $Destination $p
        if (Test-Path -LiteralPath $s -PathType Leaf) { Copy-Item -LiteralPath $s -Destination $d -Force; continue }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $d) | Out-Null
        Copy-Item -LiteralPath $s -Destination (Split-Path -Parent $d) -Recurse -Force
    }
}

function Test-EpsWorkerSelfTest {
    <# The worker's self-test in a tree (the NEW version's own code): every script parses, the libraries load and name what the
       worker task calls, VERSION is -Version. @{ Ok; Reason }. Run in a child pwsh by the update (Update-EpsHybridWorker.ps1
       -SelfTest), so nothing of the new version loads into the updating process. #>
    param([Parameter(Mandatory)][string]$AppPath, [AllowEmptyString()][string]$Version = '')
    try {
        $names = @(Get-EpsWorkerFileList -Tree $AppPath)
        $fl = Test-EpsWorkerFileList -Names $names
        if (-not $fl.Ok) { return @{ Ok = $false; Reason = $fl.Reason } }
        $v = "$(Get-Content -LiteralPath (Join-Path $AppPath 'VERSION') -Raw)".Trim()
        if ($Version -and $v -ne $Version) { return @{ Ok = $false; Reason = "VERSION is '$v', expected $Version" } }
        foreach ($f in @($names | Where-Object { $_ -like '*.ps1' })) {
            $tk = $null; $er = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $AppPath $f), [ref]$tk, [ref]$er)
            if (@($er).Count) { return @{ Ok = $false; Reason = "$f does not parse: $(@($er)[0].Message)" } }
        }
        $sb = [scriptblock]::Create(@'
param($a)
foreach ($f in 'EPS-SqlStore', 'EPS-AdDirectory', 'EPS-HybridWorker', 'InvardiaUpdate.verify', 'EPS-Updater', 'EPS-WorkerUpdate') { . (Join-Path $a "engine\_shared\$f.ps1") }
@('Invoke-EpsHybridWorkerCycle', 'New-EpsAdDirectory', 'Assert-EpsAdWriter', 'Invoke-EpsSql', 'Get-EpsUpdateTarget', 'Test-InvardiaManifest', 'Invoke-EpsWorkerUpdate') | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
'@)
        $missing = @(& $sb $AppPath)
        if ($missing.Count) { return @{ Ok = $false; Reason = "the worker's libraries do not define $($missing -join ', ')" } }
        @{ Ok = $true; Reason = "$v parses and loads" }
    } catch { @{ Ok = $false; Reason = "the self-test failed: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}

function Read-EpsWorkerUpdateState {
    param([Parameter(Mandatory)][string]$Path)
    try { if (Test-Path -LiteralPath $Path) { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } } catch { }
    $null
}

function Write-EpsWorkerUpdateBeat {
    <# The outcome on the worker's heartbeat row (the worker task writes the row itself; none yet = nothing to mark). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$WorkerName, [Parameter(Mandatory)][string]$Result, [datetime]$NowUtc = [datetime]::UtcNow)
    $x = if ($Result.Length -gt 1000) { $Result.Substring(0, 997) + '...' } else { $Result }
    Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ w = $WorkerName; x = $x; t = $NowUtc } -Query 'UPDATE eps.WorkerHeartbeat SET UpdateResult = @x, UpdateAtUtc = @t WHERE WorkerName = @w' | Out-Null
}

function Invoke-EpsWorkerUpdate {
    <#
      The daily update (see the top of this file). Returns @{ Outcome = updated | current | waiting | refused | switched back
      | failed; Reason; From; To }. Seams (tests): -Http (Get-EpsUpdateTarget's), -Download { param($Url, $OutFile, $Sha256,
      $Size) } -> @{ ok; reason }, -SelfTest { param($AppPath, $Version) } -> @{ Ok; Reason }, -ApplyAcl { param($Root) },
      -InstallState (instead of SQL), -Beat { param($Result) } (instead of SQL), -TrustedKeys, -Say { param($m) }.
    #>
    param([Parameter(Mandatory)][string]$Root, [string]$ConnectionString = '', [string]$WorkerName = '',
          [scriptblock]$Http, [scriptblock]$Download = { param($u, $o, $s, $z) Save-InvardiaArchive -Url $u -OutFile $o -ExpectedSha256 $s -ExpectedSize $z },
          [scriptblock]$SelfTest, [scriptblock]$ApplyAcl = { param($r) }, [AllowNull()][hashtable]$InstallState = $null, [scriptblock]$Beat,
          [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys, [scriptblock]$Say = { param($m) }, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $SelfTest) { $SelfTest = { param($a, $v) Test-EpsWorkerSelfTest -AppPath $a -Version $v } }
    if (-not $Beat) { $Beat = { param($x) if ($ConnectionString -and $WorkerName) { Write-EpsWorkerUpdateBeat -ConnectionString $ConnectionString -WorkerName $WorkerName -Result $x -NowUtc $NowUtc } } }
    $statePath = Join-Path $Root 'update-state.json'
    $cur = Get-EpsWorkerAppTarget -Root $Root
    $running = $cur.Version
    $done = {
        param($o, $why, $to = '')
        $line = "$o`: $why"
        & $Say $line
        try { & $Beat $line } catch { & $Say "the heartbeat could not be marked: $((("$($_.Exception.Message)") -split "`n")[0])" }
        @{ Outcome = $o; Reason = $why; From = $running; To = $to }
    }
    $inst = if ($InstallState) { $InstallState } else { Read-EpsWorkerInstallState -ConnectionString $ConnectionString }
    & $Say "worker runs $(if ($running) { $running } else { 'nothing' }); the install $(if ($inst.Ok) { "runs $($inst.Version), ring $($inst.Ring)" } else { "- $($inst.Reason)" })"
    if (-not $inst.Ok) { return (& $done 'waiting' $inst.Reason) }
    if ($running -eq $inst.Version) { return (& $done 'current' "the worker runs $running, the version this install runs") }
    $st = Read-EpsWorkerUpdateState -Path $statePath
    $applied = 0; if ($st -and "$($st.ring)" -eq "$($inst.Ring)") { [void][int]::TryParse("$($st.sequence)", [ref]$applied) }
    $tp = @{ RunningVersion = $(if ($running) { $running } else { '0.0.0' }); Ring = $inst.Ring; AppliedSequence = $applied; TrustedKeys = $TrustedKeys }
    if ($Http) { $tp.Http = $Http }
    $t = Get-EpsUpdateTarget @tp
    $d = Get-EpsWorkerUpdateDecision -Install $inst -Running $running -Target $t
    if ($d.Action -eq 'none') { return (& $done 'current' $d.Reason) }
    if ($d.Action -eq 'wait') { $r0 = & $done 'waiting' $d.Reason; $r0.RecheckMinutes = (Get-EpsWorkerRecheckMinutes -Outcome 'waiting' -Soon ([bool]$d.Soon)); return $r0 }
    if ($d.Action -eq 'refused') { return (& $done 'refused' $d.Reason) }

    # ---- install: download, verify, unpack next to the running version
    $vd = Join-Path $Root 'versions'; New-Item -ItemType Directory -Force -Path $vd | Out-Null
    $work = Join-Path $vd ".stage-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $dest = Join-Path $vd $t.Version
    try {
        $zip = Join-Path $work "worker-release-$($t.Version).zip"
        $dl = & $Download $t.DownloadUrl $zip $t.Sha256 $t.Size
        if ($dl -and -not $dl.ok) { return (& $done 'refused' "the release archive was refused: $($dl.reason)") }
        $chk = Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $t.Sha256 -ExpectedSize $t.Size
        if (-not $chk.ok) { return (& $done 'refused' "the release archive was refused: $($chk.reason)") }
        $x = Join-Path $work 'x'
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $x) } catch { return (& $done 'refused' "the release could not be unpacked: $($_.Exception.Message)") }
        $vf = Join-Path $x 'VERSION'
        $inside = if (Test-Path -LiteralPath $vf) { "$(Get-Content -LiteralPath $vf -Raw)".Trim() } else { '' }
        if ($inside -ne $t.Version) { return (& $done 'refused' "the release holds version '$inside', the signed manifest says $($t.Version)") }
        $fl = Test-EpsWorkerFileList -Names @(Get-EpsWorkerFileList -Tree $x)
        if (-not $fl.Ok) { return (& $done 'refused' $fl.Reason) }
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        Copy-EpsWorkerParts -Tree $x -Destination $dest
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }

    # ---- switch, ACLs, self-test; back on a failure
    $prev = $null
    try { $prev = Set-EpsWorkerAppLink -Root $Root -Target $dest; & $ApplyAcl $Root }
    catch {
        $why = "the switch to $($t.Version) failed: $((("$($_.Exception.Message)") -split "`n")[0])"
        if ($prev -or $cur.Kind -ne 'none') { try { $back = if ($prev) { $prev } else { $cur.Path }; [void](Set-EpsWorkerAppLink -Root $Root -Target $back) } catch { $why += " - and the switch back failed too: $($_.Exception.Message)" } }
        return (& $done 'failed' $why)
    }
    $testResult = $null
    try { $testResult = & $SelfTest (Join-Path $Root 'app') $t.Version } catch { $testResult = @{ Ok = $false; Reason = "$($_.Exception.Message)" } }
    if (-not $testResult -or -not $testResult.Ok) {
        $why = "$($t.Version) failed its self-test ($(if ($testResult) { $testResult.Reason } else { 'no answer' }))"
        if ($prev) {
            try { [void](Set-EpsWorkerAppLink -Root $Root -Target $prev); & $ApplyAcl $Root; Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue; return (& $done 'switched back' "$why - the worker runs $running again" $t.Version) }
            catch { return (& $done 'failed' "$why - and the switch back to $running failed: $($_.Exception.Message)" $t.Version) }
        }
        return (& $done 'failed' "$why - there is no previous version to switch back to" $t.Version)
    }
    # the replay watermark, then keep only the new version and the one before it
    try { ([ordered]@{ ring = $inst.Ring; sequence = [int]$t.Sequence; version = $t.Version; previous = $running; atUtc = $NowUtc.ToString('o') } | ConvertTo-Json) | Set-Content -LiteralPath $statePath -Encoding utf8 } catch { & $Say "update-state.json could not be written: $($_.Exception.Message)" }
    $keep = @($dest, $prev) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
    Get-ChildItem -LiteralPath $vd -Directory -Force | Where-Object { $keep -notcontains $_.FullName.TrimEnd('\') -and $_.Name -notlike '.stage-*' } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    & $done 'updated' "$running -> $($t.Version) ($($d.Reason)); self-test: $($testResult.Reason); $(if ($prev) { "kept $running to switch back to" } else { 'no previous version' })" $t.Version
}

# ---- WORKER-ACL-1 (2.1.74, review tools-pro-1 #4 / tools-pro-2 #4): the worker's folder holds code that runs as SYSTEM (the
# update task) and as the gMSA (the worker task). Only SYSTEM and BUILTIN\Administrators may write it; the gMSA reads and
# runs it and writes only <Root>\logs. NTFS ACLs set with icacls by WELL-KNOWN SIDs (works on every Windows language),
# inheritance off on <Root>, read back with .NET; the worker refuses to run from a folder anyone else can write.
$script:EpsWorkerAclSystemSid = 'S-1-5-18'       # NT AUTHORITY\SYSTEM
$script:EpsWorkerAclAdminsSid = 'S-1-5-32-544'   # BUILTIN\Administrators
$script:EpsWorkerAclWriters = @($script:EpsWorkerAclSystemSid, $script:EpsWorkerAclAdminsSid)
# every right that changes a file / folder or its permissions: WriteData/CreateFiles 0x2, AppendData/CreateDirectories 0x4,
# WriteExtendedAttributes 0x10, DeleteSubdirectoriesAndFiles 0x40, WriteAttributes 0x100, Delete 0x10000, ChangePermissions
# 0x40000, TakeOwnership 0x80000, GENERIC_ALL 0x10000000, GENERIC_WRITE 0x40000000 (an inherit-only ACE keeps generic bits)
$script:EpsWorkerAclWriteMask = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)

function Get-EpsWorkerAclPlan {
    <# PURE. The icacls calls that lock <Root> down, each one argument list (string[]): inheritance off + SYSTEM and
       Administrators full control (+ the worker's account read and execute), Administrators the owner, the worker's account
       modify on <Root>\logs only. -WorkerSid '' = no worker account (SYSTEM and Administrators only). #>
    param([Parameter(Mandatory)][string]$Root, [AllowEmptyString()][string]$WorkerSid = '')
    if ($WorkerSid -and $WorkerSid -notmatch '^S-1-5-[0-9-]+$') { throw "'$WorkerSid' is not a SID" }
    $grant = @("*$($script:EpsWorkerAclSystemSid):(OI)(CI)F", "*$($script:EpsWorkerAclAdminsSid):(OI)(CI)F")
    if ($WorkerSid) { $grant += "*${WorkerSid}:(OI)(CI)RX" }
    $plan = [System.Collections.Generic.List[object]]::new()
    $plan.Add([string[]](@($Root, '/inheritance:r', '/grant:r') + $grant))
    $plan.Add([string[]]@($Root, '/setowner', "*$($script:EpsWorkerAclAdminsSid)"))
    if ($WorkerSid) { $plan.Add([string[]]@(("$($Root.TrimEnd('\', '/'))\logs"), '/grant', "*${WorkerSid}:(OI)(CI)M")) }
    $plan.ToArray()
}

function Test-EpsWorkerAclFacts {
    <# PURE. -Items: @{ Path; IsRoot; Protected; Owner (SID); Rules = @(@{ Sid; Name; Rights (int64); Allow }) }. Ok only
       when no ALLOW rule gives a write right to anyone but SYSTEM and Administrators, <Root> does not inherit its parent's
       permissions and <Root>'s owner is SYSTEM or Administrators. @{ Ok; Reason; Writers = @(@{ Path; Sid; Name }) }. #>
    param([object[]]$Items = @())
    $why = [System.Collections.Generic.List[string]]::new()
    $writers = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($Items | Where-Object { $_ })) {
        if ($it.IsRoot -and -not $it.Protected) { $why.Add("$($it.Path) inherits the permissions of its parent folder") }
        if ($it.IsRoot -and $script:EpsWorkerAclWriters -notcontains "$($it.Owner)") { $why.Add("$($it.Path) is owned by $($it.Owner), not SYSTEM or Administrators") }
        foreach ($r in @($it.Rules | Where-Object { $_ })) {
            if (-not $r.Allow -or $script:EpsWorkerAclWriters -contains "$($r.Sid)") { continue }
            if (([int64]$r.Rights -band $script:EpsWorkerAclWriteMask) -eq 0) { continue }
            $writers.Add(@{ Path = "$($it.Path)"; Sid = "$($r.Sid)"; Name = "$($r.Name)"; Inherited = [bool]$r.Inherited })
            $why.Add("$(if ($r.Name) { "$($r.Name) ($($r.Sid))" } else { "$($r.Sid)" }) can write $($it.Path)")
        }
    }
    if (-not $why.Count) { return @{ Ok = $true; Reason = 'only SYSTEM and Administrators can write the worker''s folder'; Writers = @() } }
    $more = if ($why.Count -gt 3) { " (and $($why.Count - 3) more)" } else { '' }
    @{ Ok = $false; Reason = "$(@($why | Select-Object -First 3) -join '; ')$more"; Writers = $writers.ToArray() }
}

function Get-EpsWorkerAclFacts {
    <# One file or folder's permissions as Test-EpsWorkerAclFacts reads them (.NET, Windows). #>
    param([Parameter(Mandatory)][string]$Path, [switch]$IsRoot)
    $i = Get-Item -LiteralPath $Path -Force
    $sec = if ($i -is [IO.DirectoryInfo]) { [System.IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]$i) } else { [System.IO.FileSystemAclExtensions]::GetAccessControl([IO.FileInfo]$i) }
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $rules = foreach ($r in $sec.GetAccessRules($true, $true, $sidType)) {
        $sid = $r.IdentityReference.Value; $rights = [int64][int]$r.FileSystemRights
        # the name only for a rule the check will name (a writer that is not SYSTEM / Administrators)
        $name = if ($script:EpsWorkerAclWriters -notcontains $sid -and ($rights -band $script:EpsWorkerAclWriteMask)) { try { ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value } catch { '' } } else { '' }
        @{ Sid = $sid; Name = $name; Rights = $rights; Inherited = [bool]$r.IsInherited; Allow =($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) }
    }
    @{ Path = $i.FullName; IsRoot = [bool]$IsRoot; Protected = [bool]$sec.AreAccessRulesProtected; Owner = "$($sec.GetOwner($sidType).Value)"; Rules = @($rules) }
}

function Test-EpsWorkerFolderLocked {
    <# Reads back the permissions of what the worker runs: <Root>, its files (worker.json, update-state.json), <Root>\versions,
       <Root>\app and the folder it points at with everything in it. <Root>\logs is the worker's own (left out).
       -Reader { param($Path, $IsRoot) } (tests) instead of the file system. @{ Ok; Reason; Writers }. #>
    param([Parameter(Mandatory)][string]$Root, [scriptblock]$Reader = { param($p, $isRoot) Get-EpsWorkerAclFacts -Path $p -IsRoot:$isRoot })
    try {
        if (-not (Test-Path -LiteralPath $Root)) { return @{ Ok = $false; Reason = "$Root does not exist"; Writers = @() } }
        $items = [System.Collections.Generic.List[object]]::new()
        $items.Add((& $Reader $Root $true))
        foreach ($c in @(Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.Name -ne 'logs' })) { $items.Add((& $Reader $c.FullName $false)) }
        $t = Get-EpsWorkerAppTarget -Root $Root
        if ($t.Path -and (Test-Path -LiteralPath $t.Path)) {
            if ($t.Kind -eq 'junction') { $items.Add((& $Reader $t.Path $false)) }
            foreach ($c in @(Get-ChildItem -LiteralPath $t.Path -Recurse -Force)) { $items.Add((& $Reader $c.FullName $false)) }
        }
        Test-EpsWorkerAclFacts -Items $items.ToArray()
    } catch { @{ Ok = $false; Reason = "the permissions of $Root could not be read: $((("$($_.Exception.Message)") -split "`n")[0])"; Writers = @() } }
}

function Get-EpsWorkerRootOfTree {
    <# PURE. The worker's <Root> of a code tree the update runs: <Root>\app (the junction, how every updater since 2.0.102
       calls the self-test) or <Root>\versions\<v>; '' for any other tree (a release folder, a test tree - not an install). #>
    param([Parameter(Mandatory)][string]$Tree)
    # string work, not Split-Path: the same answer for a Windows path on any platform (the tests run on Linux too)
    $cut = { param($p) $i = $p.LastIndexOfAny([char[]]@('\', '/')); if ($i -lt 1) { @('', $p) } else { @($p.Substring(0, $i), $p.Substring($i + 1)) } }
    $t = $Tree.TrimEnd('\', '/')
    $parent, $leaf = & $cut $t
    if ($leaf -eq 'app' -and $parent) { return $parent }
    if ($parent) { $gp, $pl = & $cut $parent; if ($pl -eq 'versions' -and $gp) { return $gp } }
    ''
}

function Invoke-EpsWorkerSelfTestLock {
    <# WORKER-ACL-2 (2.1.74, Invardia: "An update may never leave a running worker stopped"): the FIRST step of the NEW
       version's self-test. Every updater since 2.0.102 (the old code already on the worker) switches <Root>\app to the new
       version and then runs the new version's Update-EpsHybridWorker.ps1 -SelfTest in a child pwsh AS SYSTEM (the update
       task's identity) - so the new version locks its own folder there, before the worker's next 5-minute start can check
       it. Nothing locked = the self-test FAILS, and the old updater switches back to the version that ran (never stopped).
       Not an installed worker's tree (no <Root>\worker.json) = skipped. Seams (tests): -ResolveSid, -SetAcl, -TaskPrincipal.
       @{ Ok; Skipped; Reason }. #>
    param([Parameter(Mandatory)][string]$Tree,
          [scriptblock]$ResolveSid = { param($n) ([Security.Principal.NTAccount]$n).Translate([Security.Principal.SecurityIdentifier]).Value },
          [scriptblock]$SetAcl = { param($r, $sid) Set-EpsWorkerFolderAcl -Root $r -WorkerSid $sid },
          [scriptblock]$TaskPrincipal = { $t = @(Get-ScheduledTask -TaskName 'EntraPolicySuite Hybrid Worker' -ErrorAction SilentlyContinue)[0]; if ($t) { "$($t.Principal.UserId)".Trim() } })
    $root = Get-EpsWorkerRootOfTree -Tree $Tree
    $cfgFile = if ($root) { Join-Path $root 'worker.json' } else { '' }
    if (-not $cfgFile -or -not (Test-Path -LiteralPath $cfgFile)) { return @{ Ok = $true; Skipped = $true; Reason = 'not an installed worker''s tree - nothing to lock' } }
    try {
        $gmsa = "$((Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json).Gmsa)".Trim()
        if (-not $gmsa) { $gmsa = "$(& $TaskPrincipal)".Trim() }
        if (-not $gmsa) { return @{ Ok = $false; Skipped = $false; Reason = "the gMSA is not known (no Gmsa in $cfgFile, no worker task) - the folder could not be locked" } }
        $a = & $SetAcl $root (& $ResolveSid $gmsa)
        if (-not $a.Ok) { return @{ Ok = $false; Skipped = $false; Reason = "the folder could not be locked: $($a.Reason)" } }
        @{ Ok = $true; Skipped = $false; Reason = "$root locked: $($a.Reason)" }
    } catch { @{ Ok = $false; Skipped = $false; Reason = "the folder could not be locked: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}

function Wait-EpsWorkerFolderLocked {
    <# WORKER-ACL-2: the worker's start check. Locked = run. Not locked = checked again every -IntervalSeconds for up to
       -Seconds (the one moment an older updater has switched to this version and its SYSTEM self-test is locking the folder,
       a few seconds), then refused with the reason. The worker (the gMSA, read + execute only) never changes permissions
       itself. Seams (tests): -Check { } -> Test-EpsWorkerFolderLocked's answer, -Sleep { param($s) }.
       @{ Ok; Reason; Waited (seconds) }. #>
    param([Parameter(Mandatory)][string]$Root, [int]$Seconds = 120, [int]$IntervalSeconds = 10,
          [scriptblock]$Check = { Test-EpsWorkerFolderLocked -Root $Root }, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $waited = 0
    $r = & $Check
    while (-not $r.Ok -and $waited -lt $Seconds) {
        & $Sleep $IntervalSeconds; $waited += $IntervalSeconds
        $r = & $Check
    }
    @{ Ok = [bool]$r.Ok; Reason = "$($r.Reason)"; Waited = $waited }
}

function Set-EpsWorkerFolderAcl {
    <# Locks <Root> down (Get-EpsWorkerAclPlan), every icacls exit code checked; reads it back and removes any other account's
       own (explicit) write rule that was already there by its SID, then reads back once more. @{ Ok; Reason }: Ok only when
       the read-back says only SYSTEM and Administrators can write. Seams (tests): -Icacls { param([string[]]$Arguments) } ->
       @{ Exit; Output }, -ReadBack { param($Root) } -> Test-EpsWorkerFolderLocked's answer. #>
    param([Parameter(Mandatory)][string]$Root, [AllowEmptyString()][string]$WorkerSid = '',
          [scriptblock]$Icacls = { param([string[]]$a) $o = @(& icacls @a 2>&1 | ForEach-Object { "$_" }); @{ Exit = $LASTEXITCODE; Output = (@($o | Where-Object { $_.Trim() }) -join ' ') } },
          [scriptblock]$ReadBack = { param($r) Test-EpsWorkerFolderLocked -Root $r })
    $run = {
        param([string[]]$a)
        $x = & $Icacls $a
        if ($null -eq $x -or $x.Exit -ne 0) { return "icacls $($a -join ' ') failed (exit $(if ($null -ne $x) { $x.Exit } else { 'none' })): $(if ($x) { $x.Output })" }
        ''
    }
    try {
        foreach ($step in @(Get-EpsWorkerAclPlan -Root $Root -WorkerSid $WorkerSid)) { $e = & $run $step; if ($e) { return @{ Ok = $false; Reason = $e } } }
        $chk = & $ReadBack $Root
        if (-not $chk.Ok -and @($chk.Writers).Count) {
            # an inherited rule goes with its parent's: only an item's OWN rules are removed
            foreach ($w in @($chk.Writers | Where-Object { -not $_.Inherited })) { $e =& $run ([string[]]@($w.Path, '/remove:g', "*$($w.Sid)")); if ($e) { return @{ Ok = $false; Reason = $e } } }
            $chk = & $ReadBack $Root
        }
        if (-not $chk.Ok) { return @{ Ok = $false; Reason = "the permissions read back are not locked down: $($chk.Reason)" } }
        @{ Ok = $true; Reason = $chk.Reason }
    } catch { @{ Ok = $false; Reason = "the permissions could not be set: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}
