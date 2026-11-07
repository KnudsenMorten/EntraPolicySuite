# Entra Policy Suite -- the updater, phase 2: APPLY (UPDATER-1, OPEN-10 / UPD-07; owner 2026-11-03 "Build it now",
# 2026-11-04 "Yes, build it now" as alignment work; Invardia's approved plan). PIM's order (update-job-entry.ps1):
#   download + SHA-256 + size + VERSION -> the image built in the install's OWN registry (ACR Tasks; a private registry on
#   its build pool) -> the database through the setup job caj-eps-dbinit on the NEW image (SEC-08: schema, roles, users,
#   every principal read back; a failed job stops the update before any container moves) -> every job and the web app
#   rolled to the new image (only the image of the container 'eps' changes) -> the update job itself LAST -> read back.
# Azure is reached as the update job's OWN identity id-eps-updater (Contributor on the resource group + AcrPull - owner
# 2026-11-03 "Contributor, like SI/PIM"); the job's SQL run record stays with the engine identity (role eps_engine), so
# this file touches no SQL at all. The updater never grants Graph rights (owner: "Support app, else customer"); it holds
# three PIM-for-Groups roles + GroupMember.Read.All the INSTALL grants (framework §4.5 G5) to converge and renew the database setup identity's
# membership of the SQL admin group (G2-G4, Invoke-EpsSqlAdminGroupConverge in EPS-DbInit.ps1).
# A release that changes more than images (a new job, a new right, new settings on a resource) carries 'hold' in its
# signed manifest - it waits for an install run; the updater only moves images.
# Dot-source EPS-SqlStore, EPS-Graph, EPS-Arm, EPS-Scheduler, EPS-Install (+ EPS-DbInit) first.

Set-StrictMode -Off
$script:EpsUpdateApplySteps = [ordered]@{
    check = 'Check for an update'; download = 'Download the release'; verify = 'Verify the release'; build = 'Build the images'
    migrate = 'Update the database'; apply = 'Roll out the new version'; health = 'Check the new version'; done = 'Done'; failed = 'Failed'
}

function Stop-EpsStuckJobExecution {
    <#
      UPD-STUCK-RUN (found live 2026-11-06 at internal; framework UPD-06): stops ONE Container Apps job execution the update
      hold found stuck (Running for hours with no run row). As the updater identity (Contributor on the resource group).
      Throws on a refusal - the caller says so and does not wait for it either way.
    #>
    param([Parameter(Mandatory)][string]$JobsPath, [Parameter(Mandatory)][ValidatePattern('^caj-eps-[a-z0-9-]{1,40}$')][string]$Job,
          [Parameter(Mandatory)][ValidatePattern('^caj-eps-[a-z0-9-]{1,60}$')][string]$Execution, [Parameter(Mandatory)][string]$ApiVersion)
    [void](Invoke-EpsArm -Method POST -Path "$JobsPath/$Job/executions/$Execution/stop" -ApiVersion $ApiVersion)
}

function Save-EpsReleaseArchive {
    <#
      The release zip from the signed manifest's link: https only, the size and SHA-256 the signature names, then the zip's
      own VERSION must be the version the manifest names. Extracted with .NET (no module). Returns @{ Ok; Root; Reason }.
      -Fetch { param($url, $outFile) } is the test seam.
    #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Sha256, [int64]$Size = 0, [Parameter(Mandatory)][string]$Version, [scriptblock]$Fetch,
          [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) "eps-update-$([guid]::NewGuid().ToString('N').Substring(0, 8))"))
    if ($Url -notmatch '^https://') { return @{ Ok = $false; Reason = 'the download link is not https' } }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $zip = Join-Path $WorkDir 'release.zip'
    try { if ($Fetch) { & $Fetch $Url $zip } else { Invoke-WebRequest -Uri $Url -OutFile $zip -TimeoutSec 600 -UseBasicParsing } }
    catch { return @{ Ok = $false; Reason = "the download failed: $((("$($_.Exception.Message)") -split "`n")[0])" } }
    $len = (Get-Item -LiteralPath $zip).Length
    if ($Size -gt 0 -and $len -ne $Size) { Remove-Item -LiteralPath $zip -Force; return @{ Ok = $false; Reason = "the download is $len bytes, the signed release says $Size" } }
    $h = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    if ($h -ne "$Sha256".ToUpperInvariant()) { Remove-Item -LiteralPath $zip -Force; return @{ Ok = $false; Reason = 'the download does not match the signed SHA-256 - deleted, nothing installed' } }
    $root = Join-Path $WorkDir 'release'
    try { [IO.Compression.ZipFile]::ExtractToDirectory($zip, $root) } catch { return @{ Ok = $false; Reason = "the release could not be unpacked: $($_.Exception.Message)" } }
    $vf = Join-Path $root 'VERSION'
    $v = if (Test-Path -LiteralPath $vf) { (Get-Content -LiteralPath $vf -Raw).Trim() } else { '' }
    if ($v -ne $Version) { return @{ Ok = $false; Reason = "the release's VERSION is '$v', the signed manifest says $Version - refused" } }
    foreach ($need in 'tools\eps-engine\Dockerfile', 'sql\eps-schema.sql', 'sql\eps-grants.json') { if (-not (Test-Path -LiteralPath (Join-Path $root $need))) { return @{ Ok = $false; Reason = "the release has no $need - refused" } } }
    @{ Ok = $true; Root = $root; WorkDir = $WorkDir; Reason = "$Version downloaded, $len bytes, SHA-256 as signed" }
}

function Set-EpsEpsContainerImage {
    <#
      PURE. A copy of a job's / app's template with ONLY the container 'eps' on -Image (the web app's sign-in front and
      everything else untouched). Returns @{ Template; From; Changed }.
    #>
    param([Parameter(Mandatory)]$Template, [Parameter(Mandatory)][string]$Image)
    $t = $Template | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30 -AsHashtable
    $from = ''; $changed = $false
    foreach ($c in @($t.containers)) { if ("$($c.name)" -eq 'eps') { $from = "$($c.image)"; if ($from -ne $Image) { $c.image = $Image; $changed = $true } } }
    @{ Template = $t; From = $from; Changed = $changed }
}

function Get-EpsJobTimeoutPatch {
    <#
      PURE. UPD-STUCK-RUN (found live 2026-11-07 at internal: caj-eps-tamper still 604800 s after the update to 2.0.91 - only
      an install run set it): the job's configuration with replicaTimeout set to the schedule's own TimeoutSeconds, or
      $null when the job has none of its own or already has it. Without 'secrets' (an ARM read carries no values; PATCH
      keeps what is there). Returns @{ Configuration; From; To } or $null.
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][string]$Key)
    $d = @(Get-EpsDefaultJobSchedule | Where-Object { "$($_.AcaJobName)" -eq $Key -and $_.PSObject.Properties['TimeoutSeconds'] -and [int]$_.TimeoutSeconds -gt 0 })[0]
    if (-not $d -or -not $Job.properties.configuration) { return $null }
    $from = [int]"0$($Job.properties.configuration.replicaTimeout)"
    if ($from -eq [int]$d.TimeoutSeconds) { return $null }
    $c = $Job.properties.configuration | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30 -AsHashtable
    $c.Remove('secrets'); $c.replicaTimeout = [int]$d.TimeoutSeconds
    @{ Configuration = $c; From = $from; To = [int]$d.TimeoutSeconds }
}

function Get-EpsUpdateFacts {
    <#
      What the apply needs, read from Azure as the updater: the names (an older install keeps its names), the update job
      itself (its location and environment - a private install's environment is cae-eps-vnet), the identities' client ids
      (for the setup job's principals), whether the registry is private (then the build runs on its pool), every job and
      the web app of the product. Reads only.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SelfKey)
    $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $selfName = Get-EpsAcaJobResourceName -Names $n -Key $SelfKey
    $self = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$selfName" -ApiVersion $script:EpsApi.acajob
    $n.Environment = ("$($self.properties.environmentId)" -split '/')[-1]
    $ids = @{}
    foreach ($k in 'EngineIdentity', 'WebIdentity', 'DbInitIdentity') {
        $m = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n[$k])" -ApiVersion $script:EpsApi.mi -AllowNotFound
        if ($m) { $ids[$k] = @{ Id = $m.id; ClientId = "$($m.properties.clientId)"; PrincipalId = "$($m.properties.principalId)" } }
    }
    $ids.TickIdentity = $ids.EngineIdentity
    $acr = Invoke-EpsArm -Path "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ApiVersion $script:EpsApi.acr
    $jobs = @(@((Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs" -ApiVersion $script:EpsApi.acajob).value) | Where-Object {
        "$($_.tags.product)" -eq 'EntraPolicySuite' -and @($_.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' }).Count })
    $web = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -ApiVersion $script:EpsApi.aca -AllowNotFound
    @{ Names = $n; Self = $self; SelfName = $selfName; Location = "$($self.location)"; Identities = $ids
       PrivateRegistry = ("$($acr.properties.publicNetworkAccess)" -eq 'Disabled'); RegistryId = "$($acr.id)"; Jobs = $jobs; Web = $web }
}

function Invoke-EpsUpdateApply {
    <#
      The apply. -Target = the verified manifest (Version, Sha256, Size, DownloadUrl). -Emit { param($step, $state, $message) }
      reports a stage (framework §8.8); -Log { param($level, $msg) }. Never throws: @{ Ok; Step; Reason; Rolled }.
      Stops BEFORE any container moves when the download, the build or the database fails; once rolling starts, a
      component that does not take the new image fails the run (the next run tries again - images are idempotent).
    #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$RunningVersion, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [string]$SelfKey = 'caj-eps-update', [scriptblock]$Emit = { param($s, $st, $m) }, [scriptblock]$Log = { param($l, $m) },
          [scriptblock]$Fetch, [int]$PollSeconds = 15)
    $step = 'download'
    $fail = { param($s, $why) & $Emit $s 'failed' $why; & $Log 'Warning' "update to $($Target.Version) stopped at '$s': $why"; @{ Ok = $false; Step = $s; Reason = $why; Rolled = @() } }
    $work = $null
    try {
        & $Emit 'download' 'running' "downloading $($Target.Version)"
        $a = Save-EpsReleaseArchive -Url $Target.DownloadUrl -Sha256 $Target.Sha256 -Size $Target.Size -Version $Target.Version -Fetch $Fetch
        $work = $a.WorkDir
        if (-not $a.Ok) { return (& $fail 'verify' $a.Reason) }
        & $Emit 'download' 'ok' $a.Reason; & $Emit 'verify' 'ok' 'the size, SHA-256 and VERSION are as signed'
        $step = 'build'
        $f = Get-EpsUpdateFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SelfKey $SelfKey
        $n = $f.Names
        if (-not $f.Identities.DbInitIdentity) { return (& $fail 'migrate' "the database setup identity $($n.DbInitIdentity) is not there yet - this install needs one install run with 2.0.59 or later first (a setup step); nothing was changed") }
        $image = "$($n.Registry).azurecr.io/$($n.Image):$($Target.Version)"
        & $Emit 'build' 'running' "building $($n.Image):$($Target.Version) in $($n.Registry)$(if ($f.PrivateRegistry) { " on its build pool $($n.AgentPool)" })"
        $ctxFile = New-EpsBuildContext -SolutionRoot $a.Root
        try { $b = Invoke-EpsAcrBuild -RegistryId $f.RegistryId -ContextPath $ctxFile -DockerFile 'SOLUTIONS/EntraPolicySuite/tools/eps-engine/Dockerfile' -ImageName "$($n.Image):$($Target.Version)" -BuildArgs @{ EPS_CONTENT_HASH = $Target.Version } -PollSeconds $PollSeconds -AgentPoolName $(if ($f.PrivateRegistry) { $n.AgentPool } else { '' }) }
        finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        & $Emit 'build' 'ok' "built ($($b.Digest))"
        $step = 'migrate'
        # framework §4.5 SQL-ADMIN-GROUP G2-G4 (the owner: "both setup and upd"): the database setup identity's membership of
        # the SQL admin group converged and renewed BEFORE its job starts; refused both ways = the job is NOT started
        try { $cv = Invoke-EpsSqlAdminGroupConverge -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup; foreach ($l in $cv.Lines) { & $Log $(if ($l -match '^(WARNING|FINDING)|WARNING:') { 'Warning' } else { 'Info' }) "SQL admin group: $l" } }
        catch { return (& $fail 'migrate' "$((("$($_.Exception.Message)") -split "`n")[0]) - nothing was moved") }
        & $Emit 'migrate' 'running' "the database setup job $($n.DbInitJob) on $($Target.Version)"
        $ctx = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId; Location = $f.Location; Names = $n; Version = $Target.Version; SolutionRoot = $a.Root; Identities = $f.Identities; PollSeconds = $PollSeconds }
        $j = Invoke-EpsDbInitJob -Ctx $ctx
        & $Emit 'migrate' 'ok' "$($n.DbInitJob) ($($j.Execution)) read every principal back"
        $step = 'apply'
        & $Emit 'apply' 'running' "rolling the jobs and the web app to $($Target.Version)"
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $rolled = [System.Collections.Generic.List[string]]::new(); $left = [System.Collections.Generic.List[string]]::new()
        $roll = {
            param($path, $api, $template, $label, $cfg)
            $s = Set-EpsEpsContainerImage -Template $template -Image $image
            $props = @{}; if ($s.Changed) { $props.template = $s.Template }
            # a job's own timeout converges here too (the tamper job: 1 h, never 7 days) - in the same PATCH as its image
            if ($cfg) { $props.configuration = $cfg.Configuration; & $Log 'Info' "$label`: replicaTimeout $($cfg.From) -> $($cfg.To) s" }
            if ($props.Count) { [void](Invoke-EpsArm -Method PATCH -Path $path -ApiVersion $api -Body @{ properties = $props } -PollSeconds $PollSeconds) }
            $back = Invoke-EpsArm -Path $path -ApiVersion $api
            $now = "$(@($back.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
            if ($now -eq $image) { $rolled.Add($label) } else { $left.Add("$label ($now)") }
        }
        $others = @($f.Jobs | Where-Object { "$($_.name)" -notin $f.SelfName, $n.DbInitJob, $n.InsideCheckJob })
        foreach ($x in $others) { & $roll "$rg/providers/Microsoft.App/jobs/$($x.name)" $script:EpsApi.acajob $x.properties.template $x.name (Get-EpsJobTimeoutPatch -Job $x -Key "$($x.name)") }
        if ($f.Web) { & $roll "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" $script:EpsApi.aca $f.Web.properties.template $n.WebApp }
        # the update job itself LAST: this execution goes on in the old image; the next run is the new one
        & $roll "$rg/providers/Microsoft.App/jobs/$($f.SelfName)" $script:EpsApi.acajob $f.Self.properties.template $f.SelfName
        $step = 'health'
        if ($left.Count) { return (& $fail 'health' "not on $($Target.Version): $($left -join ', ') - the next run tries again") }
        & $Emit 'apply' 'ok' "$($rolled.Count) rolled: $($rolled -join ', ')"
        & $Emit 'health' 'ok' "every job and the web app read back on $image"
        & $Emit 'done' 'ok' "$RunningVersion -> $($Target.Version)"
        & $Log 'Info' "updated $RunningVersion -> $($Target.Version): $($rolled.Count) components on the new image"
        return @{ Ok = $true; Step = 'done'; Reason = "updated to $($Target.Version)"; Rolled = @($rolled) }
    } catch {
        return (& $fail $step "$((("$($_.Exception.Message)") -split "`n")[0])")
    } finally { if ($work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-EpsVaultPrivateShape {
    # PURE. framework installer rule 11: a PRIVATE install's vault = public access off, Deny, bypass AzureServices, no IP /
    # network rule. Returns @{ Ok; Drift (plain words) }.
    param([Parameter(Mandatory)]$Vault)
    $p = $Vault.properties; $a = $p.networkAcls; $d = [System.Collections.Generic.List[string]]::new()
    if ("$($p.publicNetworkAccess)" -ne 'Disabled') { $d.Add("public access $($p.publicNetworkAccess)") }
    if ("$($a.defaultAction)" -ne 'Deny') { $d.Add("default action $(if ($a.defaultAction) { $a.defaultAction } else { 'none' })") }
    if ("$($a.bypass)" -ne 'AzureServices') { $d.Add("bypass $(if ($a.bypass) { $a.bypass } else { 'none' })") }
    if (@($a.ipRules).Where({ $_ }).Count -or @($a.virtualNetworkRules).Where({ $_ }).Count) { $d.Add('IP / network rules present') }
    @{ Ok = -not $d.Count; Drift = @($d) }
}

function Invoke-EpsVaultShapeCheck {
    <#
      framework installer rule 11 (Invardia 2026-11-04, 2f1d6534): on EVERY update run the updater enforces and READS BACK the
      private Key Vault shape - a recovered vault loses its networkAcls. Only a private install (its environment is
      cae-eps-vnet); a public install: n/a. Never throws: @{ State (n/a | ok | fixed | failed); Reason }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$SelfKey = 'caj-eps-update')
    try {
        $f = Get-EpsUpdateFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SelfKey $SelfKey
        if ($f.Names.Environment -ne 'cae-eps-vnet') { return @{ State = 'n/a'; Reason = 'a public install (rule 11 applies to private installs)' } }
        $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$($f.Names.KeyVault)"
        $v = Invoke-EpsArm -Path $path -ApiVersion $script:EpsWeb.KvApi
        $t = Test-EpsVaultPrivateShape -Vault $v
        if ($t.Ok) { return @{ State = 'ok'; Reason = "$($f.Names.KeyVault): private shape read back" } }
        [void](Invoke-EpsArm -Method PATCH -Path $path -ApiVersion $script:EpsWeb.KvApi -Body @{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = @{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } } })
        $t2 = Test-EpsVaultPrivateShape -Vault (Invoke-EpsArm -Path $path -ApiVersion $script:EpsWeb.KvApi)
        if ($t2.Ok) { return @{ State = 'fixed'; Reason = "$($f.Names.KeyVault) had drifted ($($t.Drift -join ', ')): the private shape set again and read back" } }
        @{ State = 'failed'; Reason = "$($f.Names.KeyVault) still not private after the fix: $($t2.Drift -join ', ')" }
    } catch { @{ State = 'failed'; Reason = "not checked: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}

function Get-EpsBuildPoolFact {
    <#
      framework rule 11g (5): the registry build pool AS READ NOW, for the heartbeat's BuildPool { tier, count, building,
      checkedUtc } - the engine identity holds no Azure right, so the update job (as id-eps-updater) reads it on each run and
      the uplink sends what it stored. No pool (a public install) = @{ None = $true } (the field is then LEFT OUT - absent
      means "no pool, shared builders"; count 0 would claim a pool). Never throws: @{ None; Fact; Reason }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$SelfKey = 'caj-eps-update', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $f = Get-EpsUpdateFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SelfKey $SelfKey
        $p = Invoke-EpsArm -Path "$($f.RegistryId)/agentPools/$($f.Names.AgentPool)" -ApiVersion $script:EpsBuildPool.ApiVersion -AllowNotFound
        if (-not $p) { return @{ None = $true; Fact = $null; Reason = 'no build pool (a public install builds on shared builders)' } }
        $n = [int]$p.properties.count
        $fact = [ordered]@{ tier = "$($p.properties.tier)"; count = $n; building = ($n -gt 0); checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        @{ None = $false; Fact = $fact; Reason = "$($f.Names.AgentPool): $($fact.tier), $n instance(s)" }
    } catch { @{ None = $null; Fact = $null; Reason = "not read: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}
