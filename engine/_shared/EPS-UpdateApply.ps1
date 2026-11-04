# Entra Policy Suite -- the updater, phase 2: APPLY (UPDATER-1, OPEN-10 / UPD-07; owner 2026-11-03 "Build it now",
# 2026-11-04 "Yes, build it now" as alignment work; Invardia's approved plan). PIM's order (update-job-entry.ps1):
#   download + SHA-256 + size + VERSION -> the image built in the install's OWN registry (ACR Tasks; a private registry on
#   its build pool) -> the database through the setup job caj-eps-dbinit on the NEW image (SEC-08: schema, roles, users,
#   every principal read back; a failed job stops the update before any container moves) -> every job and the web app
#   rolled to the new image (only the image of the container 'eps' changes) -> the update job itself LAST -> read back.
# Azure is reached as the update job's OWN identity id-eps-updater (Contributor on the resource group + AcrPull - owner
# 2026-11-03 "Contributor, like SI/PIM"); the job's SQL run record stays with the engine identity (role eps_engine), so
# this file touches no SQL at all. The updater never grants Graph rights (owner: "Support app, else customer").
# A release that changes more than images (a new job, a new right, new settings on a resource) carries 'hold' in its
# signed manifest - it waits for an install run; the updater only moves images.
# Dot-source EPS-SqlStore, EPS-Graph, EPS-Arm, EPS-Scheduler, EPS-Install (+ EPS-DbInit) first.

Set-StrictMode -Off
$script:EpsUpdateApplySteps = [ordered]@{
    check = 'Check for an update'; download = 'Download the release'; verify = 'Verify the release'; build = 'Build the images'
    migrate = 'Update the database'; apply = 'Roll out the new version'; health = 'Check the new version'; done = 'Done'; failed = 'Failed'
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
        & $Emit 'migrate' 'running' "the database setup job $($n.DbInitJob) on $($Target.Version)"
        $ctx = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId; Location = $f.Location; Names = $n; Version = $Target.Version; SolutionRoot = $a.Root; Identities = $f.Identities; PollSeconds = $PollSeconds }
        $j = Invoke-EpsDbInitJob -Ctx $ctx
        & $Emit 'migrate' 'ok' "$($n.DbInitJob) ($($j.Execution)) read every principal back"
        $step = 'apply'
        & $Emit 'apply' 'running' "rolling the jobs and the web app to $($Target.Version)"
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $rolled = [System.Collections.Generic.List[string]]::new(); $left = [System.Collections.Generic.List[string]]::new()
        $roll = {
            param($path, $api, $template, $label)
            $s = Set-EpsEpsContainerImage -Template $template -Image $image
            if ($s.Changed) { [void](Invoke-EpsArm -Method PATCH -Path $path -ApiVersion $api -Body @{ properties = @{ template = $s.Template } } -PollSeconds $PollSeconds) }
            $back = Invoke-EpsArm -Path $path -ApiVersion $api
            $now = "$(@($back.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
            if ($now -eq $image) { $rolled.Add($label) } else { $left.Add("$label ($now)") }
        }
        $others = @($f.Jobs | Where-Object { "$($_.name)" -notin $f.SelfName, $n.DbInitJob, $n.InsideCheckJob })
        foreach ($x in $others) { & $roll "$rg/providers/Microsoft.App/jobs/$($x.name)" $script:EpsApi.acajob $x.properties.template $x.name }
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
