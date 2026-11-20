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
      PURE. A copy of a job's / app's template with ONLY the container 'eps' on -Image (everything else untouched).
      2.1.56 (FRONT-CODE-REMOVE, SECURE-WEB-1): no sign-in front is ever moved - the web app runs Microsoft's built-in
      sign-in. Returns @{ Template; From; Changed }.
    #>
    param([Parameter(Mandatory)]$Template, [Parameter(Mandatory)][string]$Image)
    $t = $Template | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30 -AsHashtable
    $from = ''; $changed = $false
    foreach ($c in @($t.containers)) {
        if ("$($c.name)" -eq 'eps') { $from = "$($c.image)"; if ($from -ne $Image) { $c.image = $Image; $changed = $true } }
    }
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

function Sync-EpsWebRegistrationAsOwner {
    <#
      2.1.35 (review G point 2, Invardia 2026-11-14): READ ONLY. The updater no longer writes the web app registration
      (Application.ReadWrite.OwnedBy is dropped with Microsoft's built-in sign-in): each update run READS the registration
      and says what differs from what the built-in sign-in needs - its address api://<appId>, the sign-in address
      https://<fqdn>/.auth/login/aad/callback, ID-token issuance ON (Microsoft's sign-in starts with code + id_token -
      never turned off again), access-token issuance OFF, the web identity's federated credential. The install run makes
      them. Never throws: @{ State (ok | drift | none | error); Lines }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    try {
        $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $a = Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)"
        if (-not $a) { return @{ State = 'none'; Lines = @('web registration: none (this install has no web app registration)') } }
        $web = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" -ApiVersion $script:EpsApi.aca -AllowNotFound
        $fqdn = "$($web.properties.configuration.ingress.fqdn)".Trim().ToLowerInvariant()
        $wi = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n.WebIdentity)" -ApiVersion $script:EpsApi.mi -AllowNotFound
        $fic = if ($wi) { Get-EpsFicSpec -TenantId $TenantId -PrincipalId "$($wi.properties.principalId)" }
        $todo = [System.Collections.Generic.List[string]]::new()
        if (@($a.identifierUris) -notcontains "api://$($a.appId)") { $todo.Add("address api://$($a.appId)") }
        if ($fqdn) { $ru = Get-EpsWebRedirectUris -Fqdn $fqdn -Existing @($a.web.redirectUris); if ($ru.Missing.Count) { $todo.Add("sign-in address $($ru.Missing -join ' + ')") } }
        if ($a.web.implicitGrantSettings.enableIdTokenIssuance -ne $true) { $todo.Add('ID-token issuance ON') }
        if ($a.web.implicitGrantSettings.enableAccessTokenIssuance -eq $true) { $todo.Add('access-token issuance OFF') }
        # §12.30 / §12.31 layer 1: the API for applications (the app role, the idtyp claim, v2 tokens)
        # (CLOSED, §12.35: not a to-do while the API for applications is off)
        if ($script:EpsAppApiOpen -eq $true) { foreach ($x in @((Get-EpsWebApiAuthPatch -App $a).Missing)) { $todo.Add($x) } }
        if ($fic) {
            $fics = @(Invoke-EpsGraph -Path "v1.0/applications/$($a.id)/federatedIdentityCredentials" -All)
            if (-not @($fics | Where-Object { $_.issuer -eq $fic.issuer -and $_.subject -eq $fic.subject }).Count) { $todo.Add("the web identity's federated credential") }
        }
        if (-not $todo.Count) { return @{ State = 'ok'; Lines = @('web registration: read; as the built-in sign-in needs it - nothing to change (the updater no longer writes it)') } }
        @{ State = 'drift'; Lines = @("WARNING web registration: read; not yet as the built-in sign-in needs it: $($todo -join ', ') - one install run sets it (the updater no longer writes the registration)") }
    } catch {
        @{ State = 'error'; Lines = @("WARNING web registration: $((("$($_.Exception.Message)") -split "`n")[0]) - nothing else in the update depends on it; the next run reads it again") }
    }
}

# ---- §12.30 SUPPORT-FIX-API-1: the Support app's enrolment, every update -------------------------------------------------
# Layer 2 only: the update FINDS the Invardia Support app of this tenant by its InvardiaSupport tag and writes its app id to
# Security.SupportApp (the API for applications then gives it the Support role) - exactly one, else none (more than one is
# refused and said). Layer 1, the Entra app role, is the customer admin's step, ON REQUEST ONLY (owner 2026-11-16):
# Set-EpsApiAuth.ps1 -SupportApp. The update only READS it back (Application.Read.All, held already) and says it as
# information - never a to-do, never self-granted (no product identity holds AppRoleAssignment.ReadWrite.All).

function Get-EpsSupportEnrolPlan {
    <# PURE. -Tagged: the service principals carrying the tag (@{ appId; id; displayName }); -Current: Security.SupportApp
       now; -Assigned: is the tagged one assigned EPS.Api.Call ($null = not read). -> @{ Value; Changed; Level; Line } #>
    param([object[]]$Tagged = @(), [string]$Current = '', $Assigned)
    $cur = "$Current".Trim().ToLowerInvariant()
    $t = @($Tagged | Where-Object { "$($_.appId)" -match '^[0-9a-fA-F-]{36}$' } | Sort-Object { "$($_.appId)".ToLowerInvariant() } -Unique)
    if ($t.Count -gt 1) {
        return @{ Value = ''; Changed = [bool]$cur; Level = 'Warning'; Line = "WARNING support fixes: $($t.Count) applications carry the InvardiaSupport tag ($(@($t | ForEach-Object { $_.appId }) -join ', ')) - none is enrolled until exactly one does (a support step: remove the tag from the one that is not Invardia's)" }
    }
    if (-not $t.Count) { return @{ Value = ''; Changed = [bool]$cur; Level = 'Info'; Line = 'support fixes: not enabled (on request) - no application of this tenant carries the InvardiaSupport tag' } }
    $id = "$($t[0].appId)".ToLowerInvariant()
    $line = if ($Assigned -eq $true) { "support fixes: enabled - the Invardia Support app $id is enrolled and assigned $script:EpsApiAppRoleValue" }
            elseif ($Assigned -eq $false) { "support fixes: not enabled (on request) - the Invardia Support app $id is enrolled here; your administrator switches it on when you ask for it (Set-EpsApiAuth.ps1 -SupportApp)" }
            else { "support fixes: the Invardia Support app $id is enrolled; its Entra assignment could not be read this run" }
    @{ Value = $id; Changed = ($cur -ne $id); Level = 'Info'; Line = $line }
}

function Sync-EpsSupportAppEnrolment {
    <# Every update run, as the updater identity (Graph READ) + the engine's database connection. Never throws: @{ State; Lines }. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    # CLOSED (owner 2026-11-16, §12.35): no enrolment while the API for applications is off - nothing read, nothing written
    if ($script:EpsAppApiOpen -ne $true) { return @{ State = 'closed'; Lines = @('API for applications: closed in this release (support fixes and settings by code are off)') } }
    try {
        $sel = '$select=id,appId,displayName,tags'
        $tagged = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=tags/any(t:t eq 'InvardiaSupport')&$sel" -All)
        if (-not $tagged.Count) {
            foreach ($a in @(Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:t eq 'InvardiaSupport')&`$select=appId" -All)) {
                $tagged += @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($a.appId)'&$sel" -All)
            }
        }
        $assigned = $null
        if (@($tagged).Count -eq 1) {
            $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
            $web = Find-EpsWebAppRegistration -Tag "eps-install-$($n.Suffix)"
            $roleId = "$(@(@($web.appRoles) | Where-Object { "$($_.value)" -eq $script:EpsApiAppRoleValue })[0].id)"
            if ($web -and $roleId) {
                $sp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($web.appId)'&`$select=id" -All)[0]
                $assigned = [bool]@(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -All | Where-Object { "$($_.principalId)" -eq "$($tagged[0].id)" -and "$($_.appRoleId)" -eq $roleId }).Count
            } elseif ($web) { $assigned = $false }
        }
        $cur = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'Security.SupportApp' -Default '')"
        $p = Get-EpsSupportEnrolPlan -Tagged $tagged -Current $cur -Assigned $assigned
        $lines = [System.Collections.Generic.List[string]]::new(); $lines.Add($p.Line)
        if ($p.Changed) {
            [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = $p.Value } -Query "MERGE eps.Setting AS d USING (SELECT N'Security.SupportApp' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = N'update' WHEN NOT MATCHED THEN INSERT (Name, Feature, Value, UpdatedBy) VALUES (N'Security.SupportApp', N'Security', @v, N'update');")
            $rb = "$(Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = N'Security.SupportApp'")"
            $ok = $rb -eq $p.Value
            [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.enrol' -Actor 'update' -ActorSource 'job' -Target 'Setting|Security.SupportApp' -Outcome $(if ($ok) { 'ok' } else { 'error' }) -Before @{ value = $cur } -After @{ value = $p.Value; assigned = $assigned })
            $lines.Add($(if ($ok) { "support enrolment: Security.SupportApp '$cur' -> '$($p.Value)', read back" } else { "WARNING support enrolment: written, but reads back '$rb'" }))
        }
        @{ State = $(if ($p.Level -eq 'Warning') { 'refused' } elseif ($p.Value) { 'enrolled' } else { 'none' }); Lines = @($lines) }
    } catch {
        @{ State = 'error'; Lines = @("WARNING support enrolment: $((("$($_.Exception.Message)") -split "`n")[0]) - the enrolment stays as it was; the next run reads it again") }
    }
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

function Get-EpsMigratedImage {
    <# 2.1.18 (Invardia 2026-11-13 (1)): is THIS version's migration already applied? = the database setup job runs -Image
       AND its newest execution RAN -Image and Succeeded (review H: the job is PUT to the new image BEFORE it is started -
       a run that stopped between the two leaves the job on the new image with only an OLD execution). Any doubt = not
       done (the update then builds and migrates, as before): a read that fails, an execution without a start time or
       without its image, more than one page of executions. @{ Done; Execution; Reason }. #>
    param([object[]]$Jobs = @(), [string]$DbInitJob, [string]$Image, [string]$SubscriptionId, [string]$ResourceGroup)
    try {
        # read the setup job itself (it may not be in the update's job list - that one keeps only jobs tagged with the product)
        $j = @($Jobs | Where-Object { "$($_.name)" -eq $DbInitJob })[0]
        if (-not $j -and $SubscriptionId) { $j = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$DbInitJob" -ApiVersion $script:EpsApi.acajob -AllowNotFound }
        $no = { param($why) @{ Done = $false; Execution = ''; Reason = $why } }
        if (-not $j) { return (& $no 'no setup job') }
        $epsDbJobImage = "$(@($j.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
        if ($epsDbJobImage -ne $Image) { return (& $no 'the setup job runs another image') }
        $page = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$DbInitJob/executions" -ApiVersion $script:EpsApi.acajob
        if ("$($page.nextLink)") { return (& $no 'more than one page of executions') }
        $ex = @(@($page.value) | Where-Object { $_ })
        if (-not $ex.Count) { return (& $no 'no execution') }
        $epsDbStart = { param($x) $d = [datetime]::MinValue; if ([datetime]::TryParse("$($x.properties.startTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { $d } else { $null } }
        if (@($ex | Where-Object { $null -eq (& $epsDbStart $_) }).Count) { return (& $no 'an execution without a start time (just scheduled)') }
        $newest = @($ex | Sort-Object { & $epsDbStart $_ } -Descending)[0]
        $ranImage = "$(@($newest.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
        if ($ranImage -ne $Image) { return (& $no "the newest execution $($newest.name) ran $(if ($ranImage) { $ranImage } else { 'an unknown image' })") }
        if ("$($newest.properties.status)" -ne 'Succeeded') { return (& $no "the newest execution $($newest.name) is $($newest.properties.status)") }
        @{ Done = $true; Execution = "$($newest.name)"; Reason = 'ran this image and Succeeded' }
    } catch { @{ Done = $false; Execution = ''; Reason = "a read failed: $((("$($_.Exception.Message)") -split "`n")[0])" } }
}

function Get-EpsMixedRollText {
    <# PURE. 2.1.17 (Invardia 2026-11-13): while a stopped roll leaves the install mixed, the run record says which
       components are on which version, and that the tick finishes the roll within minutes (ROLL-RETRY-1). #>
    # -Unknown: the component whose call did not answer - its change may or may not have been taken (live 2026-11-13: the
    # PATCH was Accepted, the read-back never came), so it is neither "on the new" nor "on the old" version
    param([string[]]$Rolled = @(), [string[]]$All = @(), [string]$Version, [string]$From, [string]$Unknown = '')
    $on = @($Rolled | Where-Object { $_ })
    $rest = @($All | Where-Object { $_ -and $_ -notin $on -and $_ -ne $Unknown })
    $unk = if ($Unknown) { ", $Unknown not known (its call did not answer)" } else { '' }
    if (-not $on.Count -and -not $Unknown) { return "nothing was moved (all on $From); the tick tries again within minutes (ROLL-RETRY-1)" }
    "mixed: $($on.Count) on $Version$(if ($on.Count) { " ($($on -join ', '))" })$unk, $($rest.Count) on $From ($($rest -join ', ')); the tick finishes the roll within minutes (ROLL-RETRY-1)"
}

function Get-EpsUpdateRetry {
    <#
      PURE. TRANSIENT-RETRY-1 (Invardia 2026-11-15): an update that stopped BEFORE the roll (download / verify / build -
      nothing in the install moved) on a cause a retry fixes -> @{ transient; priorVersion; priorHealthy; willRetry; cause }
      for the run record; anything else -> $null. A CLOSED list of causes, matched on the stop's own text. A failed image
      build as such is NEVER one (2.1.24 / 2.1.25: "exit status 1" was a real defect - a retry never fixed it); an 'apply'
      / 'health' / 'migrate' stop never is either (the install may be mixed, or the database moved). priorHealthy stays
      false: the stop does not read the components back (Invardia treats it as not proven). willRetry: the tick starts
      the update again.
    #>
    param([string]$Step, [string]$Reason, [string]$RunningVersion)
    if ("$Step" -notin 'download', 'verify', 'build') { return $null }
    if ("$RunningVersion" -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') { return $null }
    $t = "$Reason"
    $cause = if ($t -match '(?i)mcr\.microsoft\.com' -and $t -match '(?i)time(d)? ?out|deadline exceeded|TLS handshake') { 'image-pull-timeout' }
             elseif ($t -match '(?i)HttpClient\.Timeout|request timed out|operation timed out|\btimeout of \d+ seconds') { 'request-timeout' }
             elseif ($t -match '-> 409\b|\b409: ') { 'arm-409' }
             elseif ($t -match '-> 429\b|\b429: |TooManyRequests') { 'throttled' }
             elseif ($t -match '-> 5\d\d\b|\b5\d\d: ') { 'server-error' }
             else { $null }
    if (-not $cause) { return $null }
    [ordered]@{ transient = $true; priorVersion = "$RunningVersion"; priorHealthy = $false; willRetry = $true; cause = $cause }
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
          [scriptblock]$Fetch, [int]$PollSeconds = 15, [hashtable]$Prune = $null,
          # SEC-LANE-1 short path: the caller proved the release IMAGE-ONLY against what this install runs (Test-EpsImageOnlyMarker
          # on the signed package) - no database step; the setup job's image is swapped too (never started); the previous images
          # stay (the rollback point) until a job SUCCEEDED on the new image (the follow-up). The release is still downloaded, verified and built here.
          [switch]$ImageOnly)
    # -Prune (IMAGE-PRUNE CONTRACT, 2.1.12): @{ Switch = <EPS_Updater_ImagePrune>; SaveRecord = { param($record) } } - the
    # clean-up after 'health' and before 'done' (its totals go to Invardia with the run); $null = no clean-up
    $step = 'download'
    $startedUtc = [datetime]::UtcNow
    $fail = { param($s, $why) & $Emit $s 'failed' $why; & $Log 'Warning' "update to $($Target.Version) stopped at '$s': $why"; @{ Ok = $false; Step = $s; Reason = $why; Rolled = @(); Resent = @($resent) } }
    $work = $null
    # 2.1.18 (Invardia 2026-11-13 (3)): a call sent once more (Invoke-EpsArm -TimeoutRetry) is said in the run log and the run
    # record, not only on stdout
    $resent = [System.Collections.Generic.List[string]]::new()
    $savedNotice = $script:EpsArmNotice
    $script:EpsArmNotice = { param($line) if ("$line" -match 'sent once more') { $resent.Add($line) }; & $Log 'Warning' $line }.GetNewClosure()
    try {
        & $Emit 'download' 'running' "downloading $($Target.Version)"
        $a = Save-EpsReleaseArchive -Url $Target.DownloadUrl -Sha256 $Target.Sha256 -Size $Target.Size -Version $Target.Version -Fetch $Fetch
        $work = $a.WorkDir
        if (-not $a.Ok) { return (& $fail 'verify' $a.Reason) }
        & $Emit 'download' 'ok' $a.Reason; & $Emit 'verify' 'ok' 'the size, SHA-256 and VERSION are as signed'
        # SEC-LANE-1: the short path proves its marker on the package THIS apply downloaded, before anything is built or moved
        if ($ImageOnly) { $mk = Test-EpsImageOnlyMarker -Root $a.Root -Version $Target.Version -RunningVersion $RunningVersion; if (-not $mk.ImageOnly) { return (& $fail 'verify' "the image-only marker does not hold on the downloaded package ($($mk.Reason)) - nothing was built or moved") } }
        $step = 'build'
        $f = Get-EpsUpdateFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SelfKey $SelfKey
        $n = $f.Names
        if (-not $f.Identities.DbInitIdentity) { return (& $fail 'migrate' "the database setup identity $($n.DbInitIdentity) is not there yet - this install needs one install run with 2.0.59 or later first (a setup step); nothing was changed") }
        # IMAGE-PRUNE CONTRACT point 2: what ran BEFORE the roll, read now (before anything is built or moved)
        $ranBefore = if ($Prune) { Get-EpsInstallRunningImages -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup } else { $null }
        $image = "$($n.Registry).azurecr.io/$($n.Image):$($Target.Version)"
        # 2.1.18 (Invardia 2026-11-13 (1)): the RE-RUN of a stopped roll never builds or migrates again - the database setup
        # job already runs this version's image (so the image is in the registry) and its newest execution Succeeded (so the
        # migration of this version is applied). Only apply + health run. The signed release is still downloaded and
        # verified: what is rolled comes from it, never from what the install happens to run.
        $resume = Get-EpsMigratedImage -Jobs @($f.Jobs) -DbInitJob $n.DbInitJob -Image $image -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        if ($resume.Done) {
            & $Log 'Info' "update: $($Target.Version) is already built and its database setup ran ($($resume.Execution)) - the roll is finished, nothing is built or migrated again"
            & $Emit 'build' 'ok' "already built ($($n.Image):$($Target.Version) runs in $($n.DbInitJob)) - the roll of a stopped update is finished"
        } else {
        & $Emit 'build' 'running' "building $($n.Image):$($Target.Version) in $($n.Registry)$(if ($f.PrivateRegistry) { " on its build pool $($n.AgentPool)" })"
        $ctxFile = New-EpsBuildContext -SolutionRoot $a.Root
        try { $b = Invoke-EpsAcrBuild -RegistryId $f.RegistryId -ContextPath $ctxFile -DockerFile 'SOLUTIONS/EntraPolicySuite/tools/eps-engine/Dockerfile' -ImageName "$($n.Image):$($Target.Version)" -BuildArgs @{ EPS_CONTENT_HASH = $Target.Version } -PollSeconds $PollSeconds -AgentPoolName $(if ($f.PrivateRegistry) { $n.AgentPool } else { '' }) }
        finally { Remove-Item -LiteralPath $ctxFile -ErrorAction SilentlyContinue }
        & $Emit 'build' 'ok' "built ($($b.Digest))"
        }
        # 2.1.56 (FRONT-CODE-REMOVE, SECURE-WEB-1): no sign-in front is built or moved (IMAGE-PATCH-1 step 2 is retired)
        $step = 'migrate'
        if ($ImageOnly) { & $Emit 'migrate' 'ok' "image-only ($RunningVersion -> $($Target.Version), the same code): no database step" } elseif ($resume.Done) { & $Emit 'migrate' 'ok' "already applied ($($n.DbInitJob) $($resume.Execution) Succeeded on $($Target.Version))" } else {
        # framework §4.5 SQL-ADMIN-GROUP G2-G4 (the owner: "both setup and upd"): the database setup identity's membership of
        # the SQL admin group converged and renewed BEFORE its job starts; refused both ways = the job is NOT started
        try { $cv = Invoke-EpsSqlAdminGroupConverge -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup; foreach ($l in $cv.Lines) { & $Log $(if ($l -match '^(WARNING|FINDING)|WARNING:') { 'Warning' } else { 'Info' }) "SQL admin group: $l" } }
        catch { return (& $fail 'migrate' "$((("$($_.Exception.Message)") -split "`n")[0]) - nothing was moved") }
        # 2.1.38 G5a: the updater no longer adds the member - a membership drift stops the update BEFORE anything moves
        if ($cv -and $cv.Drift) { return (& $fail 'migrate' "the database setup identity is not in the SQL admin group (membership drift, framework G5a) - Invardia support puts it back; nothing was moved") }
        & $Emit 'migrate' 'running' "the database setup job $($n.DbInitJob) on $($Target.Version)"
        $ctx = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId; Location = $f.Location; Names = $n; Version = $Target.Version; SolutionRoot = $a.Root; Identities = $f.Identities; PollSeconds = $PollSeconds }
        # 2.1.40: the web app runs no sign-in front (Microsoft's built-in sign-in) = its old schema signin is dropped
        $noFront = $f.Web -and -not @($f.Web.properties.template.containers | Where-Object { "$($_.name)" -eq 'signin-front' }).Count
        $j = Invoke-EpsDbInitJob -Ctx $ctx -DropSignin:([bool]$noFront)
        & $Emit 'migrate' 'ok' "$($n.DbInitJob) ($($j.Execution)) read every principal back"
        }
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
            if ($props.Count) { [void](Invoke-EpsArm -Method PATCH -Path $path -ApiVersion $api -Body @{ properties = $props } -PollSeconds $PollSeconds -TimeoutRetry 1) }
            $back = Invoke-EpsArm -Path $path -ApiVersion $api -TimeoutRetry 1
            $now = "$(@($back.properties.template.containers | Where-Object { "$($_.name)" -eq 'eps' })[0].image)"
            if ($now -eq $image) { $rolled.Add($label) } else { $left.Add("$label ($now)") }
        }
        # 2.1.17: a component whose call fails is NAMED in the stop (found live 2026-11-13: "stopped at 'apply': The request
        # was canceled ..." named no job; only the activity log showed which)
        $rollAt = ''
        $others = @($f.Jobs | Where-Object { "$($_.name)" -notin $f.SelfName, $n.DbInitJob, $n.InsideCheckJob })
        # SEC-LANE-1: on the short path the setup job is not run, so its IMAGE is swapped here like any job (a later full update
        # still migrates: its newest execution ran the old image, Get-EpsMigratedImage)
        if ($ImageOnly) { $others = @($others) + @($f.Jobs | Where-Object { "$($_.name)" -eq $n.DbInitJob }) }
        $allLabels = @(@($others | ForEach-Object { "$($_.name)" }) + @(if ($f.Web) { $n.WebApp }) + @($f.SelfName))
        foreach ($x in $others) { $rollAt = "$($x.name)"; & $roll "$rg/providers/Microsoft.App/jobs/$($x.name)" $script:EpsApi.acajob $x.properties.template $x.name (Get-EpsJobTimeoutPatch -Job $x -Key "$($x.name)") }
        if ($f.Web) { $rollAt = "$($n.WebApp)"; & $roll "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)" $script:EpsApi.aca $f.Web.properties.template $n.WebApp $null }
        # the update job itself LAST: this execution goes on in the old image; the next run is the new one. 2.1.17
        # (ROLL-RETRY-1): only when EVERY other component read back on the new image - an updater on the new version with
        # others left behind would say "up to date" and never finish the roll
        if (-not $left.Count) { $rollAt = "$($f.SelfName)"; & $roll "$rg/providers/Microsoft.App/jobs/$($f.SelfName)" $script:EpsApi.acajob $f.Self.properties.template $f.SelfName }
        $rollAt = ''
        $step = 'health'
        if ($left.Count) {
            $r = & $fail 'health' "not on $($Target.Version): $($left -join ', ') - $(Get-EpsMixedRollText -Rolled @($rolled) -All $allLabels -Version $Target.Version -From $RunningVersion)"
            $r.Rolled = @($rolled); $r.Mixed = $true; return $r
        }
        & $Emit 'apply' 'ok' "$($rolled.Count) rolled: $($rolled -join ', ')"
        & $Emit 'health' 'ok' "every job and the web app read back on $image"
        & $Log 'Info' "updated $RunningVersion -> $($Target.Version): $($rolled.Count) components on the new image"
        # IMAGE-PRUNE (contract point 1): only here - the update read back healthy; never fails the update (point 6)
        $pr = $null
        if ($Prune) {
            $pr = try {
                Invoke-EpsImagePruneAfterUpdate -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Version $Target.Version -FromVersion $RunningVersion `
                    -RanBefore @(if ($ranBefore.Ok) { $ranBefore.Images }) -RanBeforeReason "$($ranBefore.Reason)" -NotBefore $startedUtc -Switch "$($Prune.Switch)" -SaveRecord $Prune.SaveRecord -ReadRecord $Prune.ReadRecord -Log $Log
            } catch { @{ Ok = $false; Off = $false; Deleted = 0; Left = 0; Lines = @("image prune: $((("$($_.Exception.Message)") -split "`n")[0])"); Table = @(); Summary = 'nothing deleted' } }
        }
        # the clean-up's totals ride on 'done' (one event per stage: a repeated stage Invardia might refuse would stop the
        # run's tracking before 'done'); an incomplete clean-up says so in the text - the update itself IS healthy
        & $Emit 'done' 'ok' "$RunningVersion -> $($Target.Version)$(if ($pr) { "; image clean-up: $($pr.Summary)" })"
        # UPLINK-SLOT-1 (framework §8.4, 2.1.48): the support link is started NOW on the new image (as this identity - the
        # tick may not), so its heartbeat reports the new version within minutes, not at the next 4-hourly slot. Never fails
        # the update: a start that does not go = the next normal run reports it.
        $ulName = @(@($f.Jobs) | ForEach-Object { "$($_.name)" } | Where-Object { $_ -eq 'caj-eps-uplink' })[0]
        if ($ulName) {
            try { [void](Invoke-EpsArm -Method POST -Path "$rg/providers/Microsoft.App/jobs/$ulName/start" -ApiVersion $script:EpsApi.acajob -Body @{} -WaitSeconds 60); & $Log 'Info' "support link: started now on $($Target.Version) - the new version goes to Invardia within minutes (UPLINK-SLOT-1)" }
            catch { & $Log 'Warning' "support link: not started now ($((("$($_.Exception.Message)") -split "`n")[0])) - its next run reports $($Target.Version)" }
        }
        return @{ Ok = $true; Step = 'done'; Reason = "updated to $($Target.Version)"; Rolled = @($rolled); Prune = $pr; Resent = @($resent); Resumed = [bool]$resume.Done; ImageOnly = [bool]$ImageOnly }
    } catch {
        $msg = "$((("$($_.Exception.Message)") -split "`n")[0])"
        if ($step -eq 'apply' -and $rollAt) {
            # 2.1.17: which component, and which are on which version while the install is mixed (the run record says it)
            $r = & $fail 'apply' "$rollAt`: $msg$(if ($resent.Count) { " (after $($resent.Count) call(s) sent once more)" }) - $(Get-EpsMixedRollText -Rolled @($rolled) -All $allLabels -Version $Target.Version -From $RunningVersion -Unknown $rollAt)"
            $r.Rolled = @($rolled); $r.Mixed = $true; return $r
        }
        return (& $fail $step $msg)
    } finally { $script:EpsArmNotice = $savedNotice; if ($work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } }
}

# ---------------------------------------------------------------------------------------------------- IMAGE-PRUNE
# OWNER DECISION 2026-11-12 (framework IMAGE-PATCH-1 "IMAGE-PRUNE"; "why woud we need to keep old images" -> "agreed"):
# each install's OWN registry keeps only the current release + 1 previous image. Defender scans every STORED image, so old
# ones keep listing old CVEs; the rollback moves down one version (an older one rebuilds from its release).
# 2.1.12 = the framework IMAGE-PRUNE CONTRACT (Invardia 3bc5e5bf; owner 2026-11-12: "prune images must be part of the
# framework" / "we cannot loose a single row of data. stability + data quality is prio 1"):
#   1 only after an update read back healthy, inside the update hold; the switch EPS_Updater_ImagePrune on the update job
#     (default on; 'off' = nothing deleted, said) - set by Invardia through the Support app, kept by an install run
#   2 kept = what the install RECORDS: every image a job / the web app / an active revision ran BEFORE the roll and runs
#     AFTER it, written as the release record (eps.Setting update.release-record) BEFORE the first delete; every child
#     manifest of a kept index; every referrer of a kept image (subject = it: Defender's scan attestations and their
#     signatures, found live 2026-11-12 - 2.1.13); every image whose layers prefix a kept image (a base). Not recorded = delete NOTHING; any
#     image that cannot be read = kept with its (unknowable) bases, i.e. nothing deleted in that repository
#   3 only the install's own registry, only eps-engine + signin-front, REST only
#   4 every registry call is watchdog progress (STALL-1 Step), so the run's progress moves at least once a minute
#   5 per repository a BEFORE line ("N images, K kept, D to delete") and an AFTER line ("d deleted, L left"), each logged
#     at once; the totals go to the run summary, the audit trail and the update run to Invardia
#   6 never fails the update; at most $script:EpsPruneMaxPerRepo deletes per repository per update (the rest: the next one)
$script:EpsPruneRepos = @('eps-engine', 'signin-front')   # the ONLY repositories ever pruned (the install's own images)
$script:EpsPruneMaxPerRepo = 100                           # a large backlog spans updates (contract point 6)
$script:EpsPruneSwitch = 'EPS_Updater_ImagePrune'          # the switch's name: an env var on the update job
$script:EpsReleaseRecordSetting = 'update.release-record'  # eps.Setting: the durable release record (contract point 2)
$script:EpsManifestAccept = 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

function Step-EpsPruneProgress {
    # contract point 4: a registry call is progress for this run's watchdog (EPS-Watchdog.ps1); never throws
    if ($script:EpsWatchOn) { try { [EpsRunWatchdog]::Step() } catch { } }
}

function Get-EpsShortDigest {
    # PURE. 'sha256:<hex>' -> 'sha256:<first 12>' (-Bare: '<first 12>') for a log line; never throws on a short or odd value
    param([AllowEmptyString()][string]$Digest, [switch]$Bare)
    $d = "$Digest"; $h = if ($d.StartsWith('sha256:')) { $d.Substring(7) } else { $d }
    $h = $h.Substring(0, [Math]::Min(12, $h.Length))
    if ($Bare) { $h } else { "sha256:$h" }
}

function ConvertTo-EpsImageVersion {
    # PURE. A version tag (2.1.10, 2.1.5.1) -> [version]; anything else $null.
    param([string]$Tag)
    if ("$Tag" -match '^\d+(\.\d+){2,3}$') { try { return [version]$Tag } catch { } }   # 3 or 4 parts only - a release
    $null
}

function Get-EpsPruneSwitch {
    # PURE. The switch's value -> 'on' | 'off'. Only an explicit off / false / 0 / no turns it off (framework default on).
    param([AllowEmptyString()][string]$Value)
    if ("$Value".Trim() -match '^(?i:off|false|0|no|disabled)$') { 'off' } else { 'on' }
}

function ConvertFrom-EpsImageRef {
    # PURE. '<login>/<repo>:<tag>' or '<login>/<repo>@sha256:<hex>' on THIS registry -> @{ Repo; Tag; Digest }; else $null.
    param([AllowEmptyString()][string]$Ref, [Parameter(Mandatory)][string]$LoginServer)
    $r = "$Ref".Trim()
    $p = "$LoginServer".ToLowerInvariant() + '/'
    if (-not $r.ToLowerInvariant().StartsWith($p)) { return $null }
    $rest = $r.Substring($p.Length)
    if ($rest -match '^([a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})$') { return @{ Repo = $Matches[1]; Tag = ''; Digest = $Matches[2] } }
    if ($rest -match '^([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})$') { return @{ Repo = $Matches[1]; Tag = $Matches[2]; Digest = '' } }
    $null
}

function Get-EpsTemplateImages {
    # PURE. Every container image of the given ARM objects (jobs, apps, revisions: properties.template.containers).
    param([object[]]$Items = @())
    @(foreach ($i in @($Items)) { foreach ($c in @($i.properties.template.containers) + @($i.properties.template.initContainers)) { if ($c -and "$($c.image)") { "$($c.image)" } } }) | Select-Object -Unique
}

function Get-EpsInstallRunningImages {
    <#
      What the install RUNS now (contract point 2), read from Azure as the updater: every container image of every job of
      the product in its resource group, of the web app, and of each ACTIVE revision of the web app. Reads only. Never
      throws: @{ Ok; Images; Reason } - not Ok = the caller deletes nothing.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    try {
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        # EVERY job and container app in the group (any product tag: an image of this registry counts wherever it runs),
        # every page; each app's ACTIVE revisions (every page)
        $jobs = @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/jobs" -ApiVersion $script:EpsApi.acajob)
        $apps = @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/containerApps" -ApiVersion $script:EpsApi.aca)
        $items = [System.Collections.Generic.List[object]]::new(); foreach ($j in $jobs + $apps) { if ($j) { $items.Add($j) } }
        $revs = 0
        foreach ($a in $apps) {
            if (-not "$($a.name)") { continue }
            foreach ($r in @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/containerApps/$($a.name)/revisions" -ApiVersion $script:EpsApi.aca)) { if ($r -and $r.properties.active) { $items.Add($r); $revs++ } }
        }
        $img = @(Get-EpsTemplateImages -Items @($items))
        if (-not $img.Count) { return @{ Ok = $false; Images = @(); Reason = 'no job or app image could be read' } }
        @{ Ok = $true; Images = $img; Reason = "$($jobs.Count) job(s), $($apps.Count) app(s), $revs active revision(s)" }
    } catch { @{ Ok = $false; Images = @(); Reason = (("$($_.Exception.Message)") -split "`n")[0] } }
}

function Get-EpsArmAll {
    # Every item of an ARM list, following nextLink (its own api-version is dropped - Invoke-EpsArm adds it). Throws when a
    # page fails or the list does not end (an incomplete list never drives a delete).
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion)
    $out = [System.Collections.Generic.List[object]]::new(); $p = $Path; $pages = 0
    while ($p) {
        if (++$pages -gt 50) { throw "the list $Path did not end after 50 pages" }
        $b = Invoke-EpsArm -Path $p -ApiVersion $ApiVersion
        foreach ($x in @($b.value)) { if ($x) { $out.Add($x) } }
        $p = if ("$($b.nextLink)" -match '^https://') { [regex]::Replace("$($b.nextLink)", '([?&])api-version=[^&]*&?', '$1').TrimEnd('?', '&') } else { $null }
    }
    @($out)
}

function ConvertFrom-EpsHttpBody {
    # PURE. A response body as text: Invoke-WebRequest hands back a non-text media type (application/vnd.oci...+json) as
    # bytes, which [string] turns into '123 34 ...'; that is decoded as UTF-8
    param($Body)
    if ($Body -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($Body) }
    $s = "$Body"
    if ($s -match '^\d{1,3}( \d{1,3})+$') { try { return [Text.Encoding]::UTF8.GetString([byte[]]@($s -split ' ' | ForEach-Object { [byte]$_ })) } catch { } }
    $s
}

function Select-EpsImagePrune {
    <#
      PURE (contract point 2). One repository's manifests (@{ digest; tags; createdTime; mediaType; layers; children;
      readOk }) + what the install RECORDS for it (-Recorded: @(@{ Tag; Digest })) -> what is kept (each with WHY) and
      what is deleted. Kept: the recorded images, any tag that is not a release version, any version newer than
      -CurrentVersion, anything created at or after -NotBefore (built during this update) or without a creation time - and
      then, until stable, every child manifest of a kept index, every index holding a kept child, every image whose layer
      list is a prefix of a kept image's (a base). Nothing recorded, a recorded image missing from the registry or ANY image
      that cannot be read (its bases unknown) = Ok $false and NOTHING deleted. At most -Max deletes (oldest first); the
      rest = Deferred.
      Returns @{ Ok; Reason; Keep (@{ digest; tags; why }); Delete (@{ digest; tags; createdTime }); Deferred; Counts }.
    #>
    param([object[]]$Manifests = @(), [object[]]$Recorded = @(), [object[]]$KeepIfPresent = @(), [string]$CurrentVersion = '', $NotBefore = $null, [int]$Max = 100)
    $none = { param($why) @{ Ok = $false; Reason = $why; Keep = @($Manifests | ForEach-Object { @{ digest = "$($_.digest)"; tags = @($_.tags); why = 'nothing pruned' } }); Delete = @(); Deferred = 0
                             Counts = @{ Images = @($Manifests).Count; Kept = @($Manifests).Count; Recorded = 0; Children = 0; Referrers = 0; Bases = 0; Extra = 0; ToDelete = 0 } } }
    $ms = @($Manifests | Where-Object { $_ -and "$($_.digest)" })
    $rec = @($Recorded | Where-Object { $_ -and ("$($_.Tag)" -or "$($_.Digest)") })
    if (-not $rec.Count) { return (& $none 'the install records no image in this repository - nothing deleted') }
    $byD = @{}; foreach ($m in $ms) { $byD["$($m.digest)"] = $m }
    $why = [ordered]@{}
    foreach ($r in $rec) {
        $m = if ("$($r.Digest)") { $byD["$($r.Digest)"] } else { @($ms | Where-Object { @($_.tags) -ccontains "$($r.Tag)" })[0] }   # registry tags are case-sensitive
        if (-not $m) { return (& $none "the recorded image $(if ("$($r.Tag)") { ":$($r.Tag)" } else { (Get-EpsShortDigest $r.Digest) }) is not in the registry - nothing deleted (never a guess)") }
        if (-not $why.Contains("$($m.digest)")) { $why["$($m.digest)"] = 'recorded (runs now or ran before this update)' }
    }
    # -KeepIfPresent: the last release record's images - kept when they are there, never a reason to stop when gone
    foreach ($r in @($KeepIfPresent | Where-Object { $_ -and ("$($_.Tag)" -or "$($_.Digest)") })) {
        $m = if ("$($r.Digest)") { $byD["$($r.Digest)"] } else { @($ms | Where-Object { @($_.tags) -ccontains "$($r.Tag)" })[0] }
        if ($m -and -not $why.Contains("$($m.digest)")) { $why["$($m.digest)"] = 'recorded (in the last release record)' }
    }
    $nRec = $why.Count
    # an image that cannot be read: it is kept, and so are its bases - which cannot be known, so nothing in this
    # repository is deleted (contract point 2; the next update reads it again)
    $unread = @($ms | Where-Object { -not $_.readOk })
    if ($unread.Count) { return (& $none "$($unread.Count) image(s) could not be read ($(@($unread | Select-Object -First 3 | ForEach-Object { (Get-EpsShortDigest $_.digest) }) -join ', ')) - their bases are unknown, nothing deleted") }
    $cv = ConvertTo-EpsImageVersion $CurrentVersion
    $nb = if ($NotBefore) { try { [datetimeoffset]$NotBefore } catch { $null } } else { $null }
    # kept on their own: a tag that is not a release version, a newer version, built during this update, no creation time
    $nExtra = 0
    foreach ($m in $ms) {
        $d = "$($m.digest)"; if ($why.Contains($d)) { continue }
        $tags = @($m.tags | Where-Object { "$_" })
        $ct = try { [datetimeoffset]"$($m.createdTime)" } catch { $null }
        $w = if (@($tags | Where-Object { -not (ConvertTo-EpsImageVersion $_) }).Count) { "tag $(@($tags | Where-Object { -not (ConvertTo-EpsImageVersion $_) })[0]) is not a release version" }
             elseif ($cv -and @($tags | Where-Object { (ConvertTo-EpsImageVersion $_) -gt $cv }).Count) { "newer than the current $CurrentVersion" }
             elseif (-not $ct) { 'its creation time is not known' }
             elseif ($nb -and $ct -ge $nb) { 'built during this update' }
             else { '' }
        if ($w) { $why[$d] = $w; $nExtra++ }
    }
    $nChild = 0; $nBase = 0; $nRef = 0
    # the kept set grows until it is stable: children of kept indexes, indexes of kept children, bases of kept images
    do {
        $grew = $false
        foreach ($d in @($why.Keys)) {
            $k = $byD[$d]
            foreach ($c in @($k.children)) { if ("$c" -and -not $why.Contains("$c") -and $byD.ContainsKey("$c")) { $why["$c"] = "child manifest of the kept $(Get-EpsShortDigest $d)"; $nChild++; $grew = $true } }
        }
        $keptLayers = @(foreach ($d in @($why.Keys)) { $k = $byD[$d]; if ($k -and @($k.layers).Count) { , @{ D = $d; L = @($k.layers) } } })
        foreach ($m in $ms) {
            $d = "$($m.digest)"; if ($why.Contains($d)) { continue }
            # a referrer (an OCI manifest whose subject is a kept image: Defender's scan attestation, a signature) stays with it
            if ("$($m.subject)" -and $why.Contains("$($m.subject)")) { $why[$d] = "a referrer (signature / scan) of the kept $(Get-EpsShortDigest $m.subject)"; $nRef++; $grew = $true; continue }
            $kc = @(@($m.children) | Where-Object { $why.Contains("$_") })
            if ($kc.Count) { $why[$d] = "an index of the kept $(Get-EpsShortDigest $kc[0])"; $nChild++; $grew = $true; continue }
            $L = @($m.layers)
            if ($L.Count) {
                foreach ($k in $keptLayers) {
                    if ($k.L.Count -ge $L.Count) { $same = $true; for ($i = 0; $i -lt $L.Count; $i++) { if ("$($L[$i])" -ne "$($k.L[$i])") { $same = $false; break } }
                        if ($same) { $why[$d] = "a base of the kept $(Get-EpsShortDigest $k.D)"; $nBase++; $grew = $true; break } }
                }
            }
        }
    } while ($grew)
    $cand = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $ms) {
        $d = "$($m.digest)"; if ($why.Contains($d)) { continue }
        $ct = try { [datetimeoffset]"$($m.createdTime)" } catch { $null }
        $cand.Add(@{ digest = $d; tags = @($m.tags | Where-Object { "$_" }); createdTime = "$($m.createdTime)"; At = $ct })
    }
    $sorted = @($cand | Sort-Object { if ($_.At) { $_.At.UtcDateTime } else { [datetime]::MaxValue } })
    $del = @($sorted | Select-Object -First ([Math]::Max(0, $Max)) | ForEach-Object { @{ digest = $_.digest; tags = $_.tags; createdTime = $_.createdTime } })
    $keep = @(foreach ($d in $why.Keys) { @{ digest = $d; tags = @($byD[$d].tags); why = $why[$d] } })
    @{ Ok = $true; Reason = "keeps $nRec recorded image(s) + $nChild child/index + $nRef referrer(s) + $nBase base(s) + $nExtra other"; Keep = $keep; Delete = $del; Deferred = [Math]::Max(0, $sorted.Count - $del.Count)
       Counts = @{ Images = $ms.Count; Kept = $keep.Count; Recorded = $nRec; Children = $nChild; Referrers = $nRef; Bases = $nBase; Extra = $nExtra; ToDelete = $sorted.Count } }
}

function Test-EpsSecurityReleaseMarker {
    <#
      PURE (reads one file). 2.1.38, framework SECURE-WEB-1 point 6c (owner 2026-11-14: "stop and update the moment each
      release passes ring 0"; Invardia 2026-11-15): the signed package's tools/eps-engine/security-release.json
      { security: true, version } marks a SECURITY release - the update then STOPS the running work executions and rolls
      at once (24x7, no owner click) instead of waiting for them. Bound to THIS release; anything else = the normal wait.
      @{ Security; Reason }.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Version)
    $p = Join-Path $Root 'tools\eps-engine\security-release.json'
    if (-not (Test-Path -LiteralPath $p)) { return @{ Security = $false; Reason = 'not marked as a security release' } }
    $j = try { Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch { $null }
    if (-not $j -or $j.security -isnot [bool] -or -not $j.security) { return @{ Security = $false; Reason = 'the security marker cannot be read' } }
    if ("$($j.version)" -ne $Version) { return @{ Security = $false; Reason = "the security marker names $($j.version), not this release ($Version)" } }
    @{ Security = $true; Reason = "a SECURITY release ($Version): running work is stopped, no wait (SECURE-WEB-1 point 6c)" }
}

function Stop-EpsRunningWorkForSecurity {
    <#
      2.1.38: every RUNNING execution of the install's own work jobs (caj-eps-*, never the updater itself and never the
      database setup job) is stopped - as the updater identity (Contributor on the resource group). A stopped run is
      started again by its schedule / queue after the update. Never throws: @{ Stopped; Failed; Lines }.
    #>
    # UPLINK-SLOT-1 (2.1.48): the Invardia support link is kept too (it must report the new version at once)
    param([Parameter(Mandatory)][string]$JobsPath, [Parameter(Mandatory)][string]$ApiVersion, [string[]]$Keep = @('caj-eps-updater', 'caj-eps-update', 'caj-eps-dbinit', 'caj-eps-uplink'))
    $lines = [System.Collections.Generic.List[string]]::new(); $stopped = 0; $failed = 0
    try {
        $jobs = @(@((Invoke-EpsArm -Path $JobsPath -ApiVersion $ApiVersion).value) | ForEach-Object { "$($_.name)" } | Where-Object { $_ -like 'caj-eps-*' -and $Keep -notcontains $_ })
        foreach ($j in $jobs) {
            $ex = @(@((Invoke-EpsArm -Path "$JobsPath/$j/executions" -ApiVersion $ApiVersion).value) | Where-Object { "$($_.properties.status)" -eq 'Running' })
            foreach ($e in $ex) {
                try { Stop-EpsStuckJobExecution -JobsPath $JobsPath -Job $j -Execution "$($e.name)" -ApiVersion $ApiVersion; $stopped++; $lines.Add("stopped $j execution $($e.name) (a security release does not wait)") }
                catch { $failed++; $lines.Add("WARNING could not stop $j execution $($e.name): $((("$($_.Exception.Message)") -split "`n")[0])") }
            }
        }
    } catch { $failed++; $lines.Add("WARNING the running work could not be listed: $((("$($_.Exception.Message)") -split "`n")[0]) - the update waits as usual") }
    @{ Stopped = $stopped; Failed = $failed; Lines = @($lines) }
}

function Test-EpsImageOnlyMarker {
    <#
      PURE (reads one file). SEC-LANE-1 point 7 (Invardia 2026-11-14 + EPS's binding): the signed package's tools/eps-engine/image-only.json
      { imageOnly: true, version, fromVersion, imageDiff } allows the SHORT path only when imageOnly is true, its version is
      THIS release and its fromVersion is EXACTLY the version this install runs (the same code). Anything else = the full
      update. @{ ImageOnly; Reason }.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$RunningVersion)
    $p = Join-Path $Root 'tools\eps-engine\image-only.json'   # under tools/ - in both packages (Community stage, Pro allow-list)
    if (-not (Test-Path -LiteralPath $p)) { return @{ ImageOnly = $false; Reason = 'no image-only marker in the release' } }
    $j = try { Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch { $null }
    if (-not $j -or $j.imageOnly -isnot [bool] -or -not $j.imageOnly) { return @{ ImageOnly = $false; Reason = 'the image-only marker cannot be read' } }
    if ("$($j.version)" -ne $Version) { return @{ ImageOnly = $false; Reason = "the image-only marker names $($j.version), not this release ($Version)" } }
    if ("$($j.fromVersion)" -ne $RunningVersion) { return @{ ImageOnly = $false; Reason = "image-only from $($j.fromVersion), this install runs $RunningVersion (other code) - the full update" } }
    @{ ImageOnly = $true; Reason = "image-only from $RunningVersion (the same code)" }
}

function ConvertTo-EpsRunningImageItems {
    <#
      PURE. SEC-LANE-1 (owner 2026-11-14: "patched" = what RUNS, read back per install; Invardia heartbeat Update.runningImages):
      -Containers @(@{ Component; Image }) + -Resolved @{ '<repo>:<tag>' = @{ Digest; Dotnet } } -> the heartbeat items
      [ordered]@{ component; repo; digest; dotnet; readUtc }, in Invardia's closed shape (component / repo slug, digest
      sha256:<64 hex>, dotnet a version); a part that does not fit is LEFT OUT of that item (never guessed); at most 40, one
      per component.
    #>
    param([object[]]$Containers = @(), [hashtable]$Resolved = @{}, [Parameter(Mandatory)][string]$LoginServer, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [System.Collections.Generic.List[object]]::new(); $seen = @{}
    foreach ($c in @($Containers)) {
        if (-not $c -or $out.Count -ge 40) { continue }
        $comp = "$($c.Component)".ToLowerInvariant()
        if ($comp -notmatch '^[a-z0-9][a-z0-9._-]{0,79}$' -or $seen.ContainsKey($comp)) { continue }
        $seen[$comp] = $true
        $it = [ordered]@{ component = $comp }
        $ref = ConvertFrom-EpsImageRef -Ref "$($c.Image)" -LoginServer $LoginServer
        if ($ref -and $ref.Repo -match '^[a-z0-9][a-z0-9._/-]{0,79}$') { $it.repo = $ref.Repo }
        $dg = if ($ref -and $ref.Digest) { $ref.Digest } elseif ($ref) { "$($Resolved["$($ref.Repo):$($ref.Tag)"].Digest)" } else { '' }
        if ($dg -match '^sha256:[0-9a-f]{64}$') { $it.digest = $dg }
        $dn = if ($ref) { "$($Resolved["$($ref.Repo):$($ref.Tag)"].Dotnet)" } else { '' }
        if ($ref -and $ref.Digest) { $dn = "$($Resolved["$($ref.Repo)@$($ref.Digest)"].Dotnet)" }
        if ($dn -match '^\d+\.\d+\.\d+$') { $it.dotnet = $dn }
        $it.readUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $out.Add($it)
    }
    @($out)
}

function Get-EpsRunningImagesFact {
    <#
      SEC-LANE-1: what EVERY EPS job and the web app RUN now, each container's image resolved in the install's OWN registry
      to its digest (GET /v2/<repo>/manifests/<tag>, Docker-Content-Digest) and its .NET runtime (the config's DOTNET_VERSION).
      As the updater identity; reads only. Component = the job / app name, '<app>.signin-front' for the web app's front.
      Never throws: @{ Ok; Items; Reason }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $regs = @((Invoke-EpsArm -Path "$rg/providers/Microsoft.ContainerRegistry/registries" -ApiVersion '2023-07-01').value)
        $login = "$(@($regs | Where-Object { "$($_.name)" -like 'acreps*' })[0].properties.loginServer)"
        if (-not $login) { $login = "$(@($regs)[0].properties.loginServer)" }
        if (-not $login) { return @{ Ok = $false; Items = @(); Reason = 'no registry in the resource group' } }
        $cont = [System.Collections.Generic.List[object]]::new()
        # the web app FIRST (review): the most exposed component is never the one the 4000-character store cuts
        foreach ($a in @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/containerApps" -ApiVersion $script:EpsApi.aca) | Where-Object { "$($_.name)" -like 'ca-eps-*' }) {
            foreach ($c in @($a.properties.template.containers)) { if ($c -and "$($c.image)") { $cont.Add(@{ Component = $(if ("$($c.name)" -in 'eps', '') { "$($a.name)" } else { "$($a.name).$($c.name)" }); Image = "$($c.image)" }) } }
        }
        foreach ($j in @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/jobs" -ApiVersion $script:EpsApi.acajob) | Where-Object { "$($_.name)" -like 'caj-eps-*' }) {
            foreach ($c in @($j.properties.template.containers)) { if ($c -and "$($c.image)") { $cont.Add(@{ Component = $(if ("$($c.name)" -in 'eps', '') { "$($j.name)" } else { "$($j.name).$($c.name)" }); Image = "$($c.image)" }) } }
        }
        $res = @{}; $tok = @{}; $failed = 0
        foreach ($c in $cont) {
            $ref = ConvertFrom-EpsImageRef -Ref $c.Image -LoginServer $login
            if (-not $ref) { continue }
            $key = if ($ref.Digest) { "$($ref.Repo)@$($ref.Digest)" } else { "$($ref.Repo):$($ref.Tag)" }
            if ($res.ContainsKey($key)) { continue }
            try {
                if (-not $tok.ContainsKey($ref.Repo)) { $tok[$ref.Repo] = Get-EpsAcrDataToken -LoginServer $login -TenantId $TenantId -Repo $ref.Repo -Actions 'pull' }
                $h = @{ Authorization = "Bearer $($tok[$ref.Repo])"; Accept = $script:EpsManifestAccept }
                $m = Invoke-EpsAcrCall 'GET' "https://$login/v2/$($ref.Repo)/manifests/$(if ($ref.Digest) { $ref.Digest } else { $ref.Tag })" $h $null
                if ([int]$m.Status -ne 200) { $failed++; $res[$key] = @{ Digest = ''; Dotnet = '' }; continue }
                $dg = if ($ref.Digest) { $ref.Digest } else { "$(@($m.Headers['Docker-Content-Digest'])[0])" }
                $b = (ConvertFrom-EpsHttpBody $m.Body) | ConvertFrom-Json
                if ($b.manifests) {   # an index: the linux/amd64 image's config
                    $sub = "$(@(@($b.manifests) | Where-Object { $_.platform.os -eq 'linux' -and $_.platform.architecture -eq 'amd64' })[0].digest)"
                    if ($sub) { $m2 = Invoke-EpsAcrCall 'GET' "https://$login/v2/$($ref.Repo)/manifests/$sub" $h $null; if ([int]$m2.Status -eq 200) { $b = (ConvertFrom-EpsHttpBody $m2.Body) | ConvertFrom-Json } }
                }
                $dn = ''
                if ("$($b.config.digest)") {
                    $cf = Invoke-EpsAcrCall 'GET' "https://$login/v2/$($ref.Repo)/blobs/$($b.config.digest)" @{ Authorization = "Bearer $($tok[$ref.Repo])" } $null
                    if ([int]$cf.Status -eq 200) { $dn = "$(@(@(((ConvertFrom-EpsHttpBody $cf.Body) | ConvertFrom-Json).config.Env) | Where-Object { "$_" -like 'DOTNET_VERSION=*' })[0])" -replace '^DOTNET_VERSION=', '' }
                }
                $res[$key] = @{ Digest = $dg; Dotnet = $dn }
            } catch { $failed++; $res[$key] = @{ Digest = ''; Dotnet = '' } }
        }
        $items = @(ConvertTo-EpsRunningImageItems -Containers @($cont) -Resolved $res -LoginServer $login -NowUtc $NowUtc)
        if (-not $items.Count) { return @{ Ok = $false; Items = @(); Reason = 'no job or app image could be read' } }
        @{ Ok = $true; Items = $items; Reason = "$($items.Count) component(s), $(@($items | Where-Object { $_.digest }).Count) with a digest$(if ($failed) { "; $failed image(s) could not be read in the registry" })" }
    } catch { @{ Ok = $false; Items = @(); Reason = (("$($_.Exception.Message)") -split "`n")[0] } }
}

function Invoke-EpsAcrCall {
    # one registry data-plane call: watchdog progress before and after (contract point 4)
    param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body)
    Step-EpsPruneProgress
    try { & $script:EpsHttp $Method $Uri $Headers $Body } finally { Step-EpsPruneProgress }
}

function Get-EpsAcrDataToken {
    # The registry's data-plane token for one repository, from the caller's Entra token (ARM audience) through the
    # registry's own exchange: POST /oauth2/exchange -> refresh token, POST /oauth2/token -> access token. Throws on refusal.
    # pull: a manifest's own read (GET /v2/<repo>/manifests/<digest>) needs it - metadata_read covers only the /acr/v1 listing
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Repo, [string]$Actions = 'pull,metadata_read,delete')
    $aad = Get-EpsToken -Resource 'https://management.azure.com'
    $form = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
    $e = Invoke-EpsAcrCall 'POST' "https://$LoginServer/oauth2/exchange" $form ("grant_type=access_token&service=$LoginServer&tenant=$TenantId&access_token=$([uri]::EscapeDataString($aad))")
    if ([int]$e.Status -ne 200) { throw "the registry refused the token exchange (HTTP $($e.Status))" }
    $rt = ("$($e.Body)" | ConvertFrom-Json).refresh_token
    $k = Invoke-EpsAcrCall 'POST' "https://$LoginServer/oauth2/token" $form ("grant_type=refresh_token&service=$LoginServer&scope=$([uri]::EscapeDataString("repository:$($Repo):$Actions"))&refresh_token=$([uri]::EscapeDataString($rt))")
    if ([int]$k.Status -ne 200) { throw "the registry refused a token for $Repo (HTTP $($k.Status))" }
    ("$($k.Body)" | ConvertFrom-Json).access_token
}

function Get-EpsAcrManifests {
    # Every manifest of one repository (digest, tags, createdTime), paged by the Link header. Throws on an error.
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Token)
    $out = [System.Collections.Generic.List[object]]::new(); $uri = "https://$LoginServer/acr/v1/$Repo/_manifests?n=500"; $pages = 0
    while ($uri -and $pages -lt 40) {
        $pages++
        $r = Invoke-EpsAcrCall 'GET' $uri @{ Authorization = "Bearer $Token" } $null
        if ([int]$r.Status -eq 404) { $uri = $null; break }   # 2.1.42: no repository (ACR removes an emptied one) = EMPTY, never "did not end"
        if ([int]$r.Status -ne 200) { throw "listing $Repo answered HTTP $($r.Status)" }
        foreach ($m in @(("$($r.Body)" | ConvertFrom-Json).manifests)) { if ($m) { $out.Add([pscustomobject]@{ digest = "$($m.digest)"; tags = @($m.tags | Where-Object { "$_" }); createdTime = "$($m.createdTime)" }) } }
        $link = "$(@($r.Headers['Link'])[0])"
        $uri = if ($link -match '<([^>]+)>;\s*rel="next"') { "https://$LoginServer$($Matches[1])" } else { $null }
    }
    if ($uri) { throw "listing $Repo did not end after $pages pages" }   # an incomplete list never drives a delete
    @($out)
}

function Get-EpsAcrManifestDetail {
    # One manifest's kind, layers and children (GET /v2/<repo>/manifests/<digest>). Never throws: @{ readOk; mediaType; layers; children }.
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Digest)
    try {
        $r = Invoke-EpsAcrCall 'GET' "https://$LoginServer/v2/$Repo/manifests/$Digest" @{ Authorization = "Bearer $Token"; Accept = $script:EpsManifestAccept } $null
        if ([int]$r.Status -ne 200) { return @{ readOk = $false; mediaType = ''; layers = @(); children = @(); subject = '' } }
        $b = (ConvertFrom-EpsHttpBody $r.Body) | ConvertFrom-Json
        @{ readOk = $true; mediaType = "$($b.mediaType)"; layers = @(@($b.layers) | ForEach-Object { "$($_.digest)" } | Where-Object { $_ }); children = @(@($b.manifests) | ForEach-Object { "$($_.digest)" } | Where-Object { $_ }); subject = "$($b.subject.digest)" }
    } catch { @{ readOk = $false; mediaType = ''; layers = @(); children = @(); subject = '' } }
}

function Invoke-EpsImagePrune {
    <#
      IMAGE-PRUNE (contract points 2-6) for the install's own repositories (eps-engine, signin-front) in ITS registry: per
      repository list + read every manifest, select (Select-EpsImagePrune with what the install records), say the BEFORE
      line, delete (DELETE /v2/<repo>/manifests/<digest>, oldest first, at most -Max), read back, say the AFTER line. Each
      line goes to -Log AT ONCE (a failing log write never stops it). -Recorded: the image references the install records.
      Touches no other registry, repository or resource. Never throws: @{ Ok; Deleted; Left; Lines; Table }.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$TenantId, [string[]]$Recorded = @(), [string[]]$KeepIfPresent = @(), [string]$CurrentVersion = '',
          $NotBefore = $null, [int]$Max = $script:EpsPruneMaxPerRepo, [scriptblock]$Log = { param($l, $m) })
    $lines = [System.Collections.Generic.List[string]]::new(); $table = [System.Collections.Generic.List[object]]::new(); $deleted = 0; $left = 0; $ok = $true
    $say = { param($lvl, $msg) $lines.Add($msg); try { & $Log $lvl $msg } catch { } }
    $refs = @(foreach ($r in $Recorded) { ConvertFrom-EpsImageRef -Ref $r -LoginServer $LoginServer })
    # a reference ON THIS registry that cannot be read (e.g. repo:tag@sha256:... pinned by hand) names an image nothing here
    # can match - so nothing is deleted anywhere (it could be the one a job runs)
    $keepRefs = @(foreach ($r in $KeepIfPresent) { ConvertFrom-EpsImageRef -Ref $r -LoginServer $LoginServer })
    $odd = @(@($Recorded) + @($KeepIfPresent) | Where-Object { "$_".Trim().ToLowerInvariant().StartsWith("$LoginServer".ToLowerInvariant() + '/') -and -not (ConvertFrom-EpsImageRef -Ref $_ -LoginServer $LoginServer) })
    if ($odd.Count) {
        & $say 'Warning' "image prune: $($odd.Count) image reference(s) on this registry could not be read ($(@($odd | Select-Object -First 3) -join ', ')) - nothing deleted"
        return @{ Ok = $false; Deleted = 0; Left = 0; Lines = @($lines); Table = @() }
    }
    foreach ($repo in $script:EpsPruneRepos) {
        $mine = @($refs | Where-Object { $_.Repo -eq $repo })
        if (-not $mine.Count) { & $say 'Notice' "image prune $repo`: the install records no image in it - left as it is"; continue }
        $row = [ordered]@{ repo = $repo; before = 0; kept = 0; recorded = 0; children = 0; referrers = 0; bases = 0; extra = 0; toDelete = 0; deleted = 0; left = 0; deferred = 0; failed = 0; why = @() }
        try {
            $tok = Get-EpsAcrDataToken -LoginServer $LoginServer -TenantId $TenantId -Repo $repo
            $ms = @(Get-EpsAcrManifests -LoginServer $LoginServer -Repo $repo -Token $tok)
            $row.before = $ms.Count
            if (-not $ms.Count) { & $say 'Warning' "image prune $repo`: no images listed - nothing deleted"; $ok = $false; $table.Add($row); continue }
            $full = @(foreach ($m in $ms) { $x = Get-EpsAcrManifestDetail -LoginServer $LoginServer -Repo $repo -Token $tok -Digest $m.digest
                [pscustomobject]@{ digest = $m.digest; tags = @($m.tags); createdTime = $m.createdTime; mediaType = $x.mediaType; layers = @($x.layers); children = @($x.children); subject = "$($x.subject)"; readOk = $x.readOk } })
            $sel = Select-EpsImagePrune -Manifests $full -Recorded @($mine | ForEach-Object { @{ Tag = $_.Tag; Digest = $_.Digest } }) -KeepIfPresent @($keepRefs | Where-Object { $_.Repo -eq $repo } | ForEach-Object { @{ Tag = $_.Tag; Digest = $_.Digest } }) -CurrentVersion $CurrentVersion -NotBefore $NotBefore -Max $Max
            $c = $sel.Counts
            $row.kept = $c.Kept; $row.recorded = $c.Recorded; $row.children = $c.Children; $row.referrers = $c.Referrers; $row.bases = $c.Bases; $row.extra = $c.Extra; $row.toDelete = $c.ToDelete; $row.deferred = $sel.Deferred
            $row.why = @($sel.Keep | Where-Object { $_.why -notlike 'recorded*' } | Select-Object -First 30 | ForEach-Object { "$(Get-EpsShortDigest $_.digest -Bare)$(if (@($_.tags).Count) { " ($(@($_.tags) -join ','))" }): $($_.why)" })
            if (-not $sel.Ok) { & $say 'Warning' "image prune $repo`: $($ms.Count) images - $($sel.Reason)"; $ok = $false; $row.kept = $ms.Count; $row.left = $ms.Count; $left += $ms.Count; $table.Add($row); continue }
            & $say 'Notice' "image prune $repo`: $($ms.Count) images, $($c.Kept) kept ($($c.Recorded) recorded, $($c.Children) child/index manifests, $($c.Referrers) referrers, $($c.Bases) bases, $($c.Extra) other), $($c.ToDelete) to delete$(if ($sel.Deferred) { " - $(@($sel.Delete).Count) in this update, $($sel.Deferred) at the next (a large backlog spans updates)" })"
            foreach ($w in $row.why) { & $say 'Notice' "image prune $repo kept: $w" }
            $gone = 0; $failed = [System.Collections.Generic.List[string]]::new()
            foreach ($d in $sel.Delete) {
                $r = Invoke-EpsAcrCall 'DELETE' "https://$LoginServer/v2/$repo/manifests/$($d.digest)" @{ Authorization = "Bearer $tok" } $null
                if ([int]$r.Status -in 200, 202, 404) { $gone++ } else { $failed.Add("$(if (@($d.tags).Count) { @($d.tags) -join ',' } else { (Get-EpsShortDigest $d.digest) }) (HTTP $($r.Status)$(if ([int]$r.Status -eq 405) { ', locked' }))") }
            }
            $after = @(Get-EpsAcrManifests -LoginServer $LoginServer -Repo $repo -Token $tok)
            $afterD = @($after | ForEach-Object { "$($_.digest)" })
            $missing = @($sel.Keep | Where-Object { $afterD -notcontains "$($_.digest)" })
            $row.deleted = $gone; $row.left = $after.Count; $row.failed = $failed.Count
            $deleted += $gone; $left += $after.Count
            if ($failed.Count -or $missing.Count) { $ok = $false }
            & $say $(if ($failed.Count -or $missing.Count) { 'Warning' } else { 'Notice' }) "image prune $repo`: $gone deleted, $($after.Count) left (read back)$(if ($failed.Count) { "; NOT deleted: $($failed -join ', ')" })$(if ($missing.Count) { "; WARNING $($missing.Count) kept image(s) missing in the read-back: $(@($missing | ForEach-Object { (Get-EpsShortDigest $_.digest) }) -join ', ')" })"
        } catch {
            $ok = $false
            & $say 'Warning' "image prune $repo`: $((("$($_.Exception.Message)") -split "`n")[0]) - nothing more deleted (the next update tries again)"
        }
        $table.Add($row)
    }
    @{ Ok = $ok; Deleted = $deleted; Left = $left; Lines = @($lines); Table = @($table) }
}

function Invoke-EpsImagePruneAfterUpdate {
    <#
      IMAGE-PRUNE after an update that READ BACK healthy (called by Invoke-EpsUpdateApply after 'health', inside the update
      hold): the switch (-Switch, the update job's EPS_Updater_ImagePrune); what ran BEFORE the roll (-RanBefore, read by
      the apply) and what runs NOW (read here); the release record written through -SaveRecord BEFORE the first delete;
      then Invoke-EpsImagePrune. Nothing recorded / the record not written = nothing deleted. Never throws:
      @{ Ok; Off; Deleted; Left; Lines; Table; Summary }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Version,
          [string]$FromVersion = '', [string[]]$RanBefore = @(), [string]$RanBeforeReason = '', $NotBefore = $null, [AllowEmptyString()][string]$Switch = '',
          [scriptblock]$SaveRecord, [scriptblock]$ReadRecord, [scriptblock]$Log = { param($l, $m) }, [int]$Max = $script:EpsPruneMaxPerRepo,
          # SEC-LANE-1 (owner 2026-11-14: "i prefer we dont leave any old version out there as it makes noise in defender" /
          # "when swap works we remove old"): ONLY what runs now is kept - NOT used by the short path yet (review 2026-11-14: a
          # read-back of the configuration never RAN the new image; the removal waits for a proven run - the follow-up);
          # the previous images (and the last record's) go. The record and every other guard stay as they are.
          [switch]$OnlyCurrent)
    # -ReadRecord { -> the stored record or $null }: the record the LAST update wrote - its images are kept too (contract
    # point 2, "a durable release record of the previous release"); a read that fails = nothing deleted
    $stop = { param($why, [bool]$off = $false)
        try { & $Log $(if ($off) { 'Notice' } else { 'Warning' }) "image prune: $why" } catch { }
        @{ Ok = $off; Off = $off; Deleted = 0; Left = 0; Lines = @("image prune: $why"); Table = @(); Summary = $(if ($off) { 'off' } else { 'nothing deleted' }) } }
    try {
        if ((Get-EpsPruneSwitch $Switch) -eq 'off') { return (& $stop "off ($script:EpsPruneSwitch = $Switch on the update job) - nothing deleted" $true) }
        $before = @($RanBefore | Where-Object { "$_" })
        if (-not $before.Count) { return (& $stop "the previous release is not recorded (what ran before the update could not be read$(if ($RanBeforeReason) { ": $RanBeforeReason" })) - nothing deleted") }
        $now = Get-EpsInstallRunningImages -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        if (-not $now.Ok) { return (& $stop "what runs now could not be read ($($now.Reason)) - nothing deleted") }
        $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $acr = Invoke-EpsArm -Path "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" -ApiVersion $script:EpsApi.acr
        $login = "$($acr.properties.loginServer)"
        if ($login -notmatch '^[a-z0-9]{5,50}\.azurecr\.io$' -or "$($acr.id)" -notlike "$rg/*") { return (& $stop "the install's registry $($n.Registry) is not readable in its own resource group - nothing deleted") }
        $record = [ordered]@{ atUtc = [datetime]::UtcNow.ToString('o'); registry = $login
            current = [ordered]@{ version = $Version; images = @($now.Images) }; previous = [ordered]@{ version = $FromVersion; images = @($before) } }
        if (-not $SaveRecord) { return (& $stop 'no release record writer - nothing deleted') }
        $stored = @()
        if ($ReadRecord) {
            $old = try { & $ReadRecord } catch { return (& $stop "the stored release record could not be read ($((("$($_.Exception.Message)") -split "`n")[0])) - nothing deleted") }
            if ($old) {
                $o = if ($old -is [string]) { try { $old | ConvertFrom-Json } catch { $null } } else { $old }
                if (-not $o) { return (& $stop 'the stored release record is not readable - nothing deleted') }
                $stored = @(@($o.current.images) + @($o.previous.images) | Where-Object { "$_" })
            }
        }
        try { & $SaveRecord $record } catch { return (& $stop "the release record could not be written ($((("$($_.Exception.Message)") -split "`n")[0])) - nothing deleted") }
        try { & $Log 'Notice' "image prune: release record written ($Version runs: $(@($now.Images).Count) image(s); $FromVersion ran: $($before.Count); the last record kept: $($stored.Count)) - $($now.Reason)" } catch { }
        $keepRec = if ($OnlyCurrent) { @($now.Images) } else { @(@($now.Images) + $before | Select-Object -Unique) }; $keepOld = if ($OnlyCurrent) { @() } else { $stored }
        if ($OnlyCurrent) { try { & $Log 'Notice' "image prune: image-only swap read back healthy - only what runs now is kept, the previous images go (owner: when swap works we remove old)" } catch { } }
        $p = Invoke-EpsImagePrune -LoginServer $login -TenantId $TenantId -Recorded $keepRec -KeepIfPresent $keepOld -CurrentVersion $Version -NotBefore $NotBefore -Max $Max -Log $Log
        $deferred = 0; foreach ($row in @($p.Table)) { $deferred += [int]$row.deferred }
        $p.Off = $false
        $p.Summary = "$($p.Deleted) old deleted, $($p.Left) left$(if ($deferred) { ", $deferred at the next update" })$(if (-not $p.Ok) { ' (prune incomplete)' })"
        $p
    } catch { & $stop "$((("$($_.Exception.Message)") -split "`n")[0]) - nothing more deleted (the next update tries again)" }
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

function Measure-EpsPlainSecrets {
    <#
      PURE. SEC-10 keyvault-secrets-only (framework ALIGN-AUTO-ALL, 2026-11-10): how many secrets sit OUTSIDE Key Vault in
      the Container Apps / jobs' definitions - a container secret without a keyVaultUrl, or an env var with a plain value
      that is a secret by its name (secret / password / token / api key) or by its content (a password or account key in a
      connection string, a SAS signature, a bearer token). Never returns a name or a value: the count only.
    #>
    param([object[]]$Resources = @())
    # 2.1.49 (internal 2026-11-15: keyvault-secrets-only 'missing', plain 1): Microsoft's built-in Container Apps sign-in
    # needs the web identity's CLIENT ID in a container secret of exactly this name (the secretless federated credential,
    # 2.1.35) - a public id, not a secret. A Key Vault reference would need a Key Vault right on the web identity, which
    # the product removed on purpose. Only this one name, only on a container app; any other plain secret still counts.
    $notSecret = @('override-use-mi-fic-assertion-client-id')
    $n = 0
    foreach ($r in @($Resources | Where-Object { $_ })) {
        $isApp = "$($r.type)" -eq 'Microsoft.App/containerApps' -or "$($r.id)" -match '/providers/Microsoft\.App/containerApps/'
        foreach ($s in @($r.properties.configuration.secrets | Where-Object { $_ })) { if (-not "$($s.keyVaultUrl)" -and -not ($isApp -and $notSecret -contains "$($s.name)")) { $n++ } }
        foreach ($c in @($r.properties.template.containers | Where-Object { $_ })) {
            foreach ($e in @($c.env | Where-Object { $_ })) {
                if ($e.secretRef -or -not "$($e.value)") { continue }
                if ("$($e.name)" -match '(?i)secret|passw(or)?d|\bpwd\b|token|api_?key' -or "$($e.value)" -match '(?i)(^|;)\s*(password|pwd|accountkey|sharedaccesskey)\s*=|[?&]sig=|^eyJ[A-Za-z0-9_-]{10,}\.|client_secret') { $n++ }
            }
        }
    }
    $n
}

function Get-EpsKeyVaultSetupFact {
    <#
      SEC-10 (framework ALIGN-AUTO-ALL, Invardia 2026-11-10): the two setup steps the updater reads on each run, as
      id-eps-updater (Contributor on the resource group): keyvault-purge-protection (the install's vault has purge
      protection on) and keyvault-secrets-only (Measure-EpsPlainSecrets over every job and the web app = 0). Never throws:
      @{ Fact = [ordered]@{ purge; secrets; plain; checkedUtc } | $null; Reason }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$SelfKey = 'caj-eps-update', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $f = Get-EpsUpdateFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SelfKey $SelfKey
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $v = Invoke-EpsArm -Path "$rg/providers/Microsoft.KeyVault/vaults/$($f.Names.KeyVault)" -ApiVersion $script:EpsWeb.KvApi
        $purge = if ($v.properties.enablePurgeProtection -eq $true) { 'ok' } else { 'missing' }
        $res = @(@((Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs" -ApiVersion $script:EpsApi.acajob).value)) + @(Invoke-EpsArm -Path "$rg/providers/Microsoft.App/containerApps/$($f.Names.WebApp)" -ApiVersion $script:EpsApi.aca -AllowNotFound)
        $plain = Measure-EpsPlainSecrets -Resources $res
        $fact = [ordered]@{ purge = $purge; secrets = $(if ($plain -eq 0) { 'ok' } else { 'missing' }); plain = $plain; resources = @($res | Where-Object { $_ }).Count; checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        @{ Fact = $fact; Reason = "$($f.Names.KeyVault): purge protection $purge; $plain secret(s) outside Key Vault in $($fact.resources) job(s) / app(s)" }
    } catch { @{ Fact = $null; Reason = "not read: $((("$($_.Exception.Message)") -split "`n")[0])" } }
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

# ======================================================================================================================
# 2.1.36 - framework SECURE-WEB-1 "ONE STANDARD + NO LEFTOVERS" (owner via PIM 2026-11-14: "make sure all installs are
# config the same" / "security, including leftovers"; Invardia runs the same check daily - SEC-SECOND-CHECK-1). The
# UPDATER reads, on every run, whether the web app is exactly the standard (DIFF) and what the sign-in front era left
# behind (LEFTOVERS) - and only REPORTS (removal on the owner's / Invardia's word, or an install run). PIM's reference
# check (ops/builtin-auth-consistency.ps1) copied in EPS's own terms, not shared.
# ======================================================================================================================
function Get-EpsBuiltInAuthConsistency {
    <#
      PURE. -Facts @{ App; AuthConfig; SecretNames; Registration (incl. passwordCredentials / keyCredentials); Fics;
      WebPrincipalId; WebClientId; WebRoles (every role assignment of the web identity in the resource group: id,
      properties.scope, properties.roleDefinitionId); FrontKey (the vault's signin-front key or $null); FrontKeyRoles;
      FrontManifests (count, or -1 = not read); TenantId; Storage } -> @{ Diff = @(...); Leftovers = @(...) }.
    #>
    param([Parameter(Mandatory)]$Facts)
    $f = $Facts; $d = [System.Collections.Generic.List[string]]::new(); $l = [System.Collections.Generic.List[string]]::new()
    $app = $f.App; $a = $f.AuthConfig.properties; $aad = $a.identityProviders.azureActiveDirectory
    $ctr = @($app.properties.template.containers); $eps = @($ctr | Where-Object { "$($_.name)" -eq 'eps' })[0]
    $ev = @{}; foreach ($x in @($eps.env)) { $ev["$($x.name)"] = "$($x.value)" }
    $fqdn = "$($app.properties.configuration.ingress.fqdn)".ToLowerInvariant()
    $appId = "$($f.Registration.appId)"
    # ---- the standard
    if ($ctr.Count -ne 1 -or -not $eps) { $d.Add("containers $(@($ctr | ForEach-Object name) -join '+') (want only eps)") }
    if ("$($app.properties.configuration.ingress.targetPort)" -ne "$($script:EpsWeb.AppPort)" -or $ev.EPS_WEB_PORT -ne "$($script:EpsWeb.AppPort)") { $d.Add("port: ingress $($app.properties.configuration.ingress.targetPort), EPS_WEB_PORT $($ev.EPS_WEB_PORT) (want $($script:EpsWeb.AppPort))") }
    if ($ev.EPS_WEB_LISTEN -ne 'all') { $d.Add("EPS_WEB_LISTEN=$($ev.EPS_WEB_LISTEN)") }
    if ($ev.EPS_TENANT_ID -ne $f.TenantId -or $ev.EPS_WEB_CLIENT_ID -ne $appId) { $d.Add('the app''s pins (EPS_TENANT_ID / EPS_WEB_CLIENT_ID) are not this tenant / registration') }
    if (@($f.SecretNames) -cnotcontains $script:EpsWeb.FicSecretName) { $d.Add("setting $($script:EpsWeb.FicSecretName) missing") }
    if ($a.platform.enabled -ne $true) { $d.Add('platform sign-in OFF') }
    if ("$($a.globalValidation.unauthenticatedClientAction)" -ne 'RedirectToLoginPage') { $d.Add("unauthenticatedClientAction=$($a.globalValidation.unauthenticatedClientAction)") }
    if (@($a.globalValidation.excludedPaths | Where-Object { $_ }).Count) { $d.Add("excluded paths $(@($a.globalValidation.excludedPaths) -join ',') (none allowed)") }
    if ("$($aad.registration.clientId)" -ne $appId) { $d.Add("sign-in clientId $($aad.registration.clientId) is not the registration") }
    if ("$($aad.registration.clientSecretSettingName)" -cne $script:EpsWeb.FicSecretName) { $d.Add("clientSecretSettingName=$($aad.registration.clientSecretSettingName)") }
    if ("$($aad.registration.openIdIssuer)" -ne "https://login.microsoftonline.com/$($f.TenantId)/v2.0") { $d.Add("openIdIssuer=$($aad.registration.openIdIssuer)") }
    if ((@($aad.validation.allowedAudiences) -join ',') -ne "api://$appId,$appId") { $d.Add("allowedAudiences=$(@($aad.validation.allowedAudiences) -join ',')") }
    if (@($aad.login.loginParameters) -notcontains 'prompt=select_account') { $d.Add('account picker (prompt=select_account) missing') }
    if ("$(@($aad.login.loginParameters))" -notmatch [regex]::Escape("api://$appId/$($script:EpsWeb.Scope)")) { $d.Add('the app''s own scope is not asked at sign-in') }
    if ($a.login.tokenStore.enabled -ne $true) { $d.Add('session store OFF') }
    if ("$($a.login.tokenStore.azureBlobStorage.blobContainerUri)" -notmatch "^https://$([regex]::Escape("$($f.Storage)"))\.blob\.[^/]+/$([regex]::Escape($script:EpsWeb.TokenContainer))$") { $d.Add("session store container=$($a.login.tokenStore.azureBlobStorage.blobContainerUri)") }
    if ("$($a.login.tokenStore.azureBlobStorage.managedIdentityResourceId)" -notmatch '(?i)/id-eps-web$') { $d.Add('the session store is not reached through id-eps-web') }
    if ("$($a.login.tokenStore.azureBlobStorage.sasUrlSettingName)") { $d.Add('the session store uses a SAS setting') }
    if ("$($a.login.cookieExpiration.convention)" -ne 'FixedTime' -or "$($a.login.cookieExpiration.timeToExpiration)" -ne ('{0:00}:00:00' -f [int]$script:EpsWeb.SessionHours)) { $d.Add("session $($a.login.cookieExpiration.convention) $($a.login.cookieExpiration.timeToExpiration) (want FixedTime 08:00:00)") }
    $kvR = @(@($f.WebRoles) | Where-Object { "$($_.properties.scope)" -match '(?i)/Microsoft\.KeyVault/' })
    if ($kvR.Count) { $d.Add("id-eps-web holds $($kvR.Count) Key Vault role(s)") }
    $blob = @(@($f.WebRoles) | Where-Object { "$($_.properties.roleDefinitionId)" -like "*/$($script:EpsWeb.BlobDataRole)" })
    if (-not @($blob | Where-Object { "$($_.properties.scope)" -match "/containers/$([regex]::Escape($script:EpsWeb.TokenContainer))$" }).Count) { $d.Add("no Storage Blob Data Contributor on $($script:EpsWeb.TokenContainer)") }
    if (@($blob | Where-Object { "$($_.properties.scope)" -notmatch "/containers/$([regex]::Escape($script:EpsWeb.TokenContainer))$" }).Count) { $d.Add('Storage Blob Data Contributor ALSO on another scope') }
    $w = $f.Registration.web
    if ($w.implicitGrantSettings.enableIdTokenIssuance -ne $true) { $d.Add('ID-token issuance OFF') }
    if ($w.implicitGrantSettings.enableAccessTokenIssuance -eq $true) { $d.Add('access-token issuance ON') }
    if (@($w.redirectUris) -notcontains "https://$fqdn/.auth/login/aad/callback") { $d.Add('the sign-in address /.auth/login/aad/callback missing') }
    if (-not @(@($f.Fics) | Where-Object { "$($_.subject)" -eq "$($f.WebPrincipalId)" -and @($_.audiences) -contains 'api://AzureADTokenExchange' }).Count) { $d.Add('no federated credential for id-eps-web') }
    # 2.1.37 (owner 2026-11-15 "anything having public exposure like api mcp must be protected with similar"): EVERY
    # external ingress of the install's resource group stands behind Microsoft's sign-in - none open, none anonymous
    foreach ($ig in @($f.Ingresses)) {
        if (-not $ig) { continue }
        if (-not $ig.AuthOn) { $d.Add("external ingress $($ig.Name) has NO Microsoft sign-in") }
        elseif ("$($ig.Action)" -eq 'AllowAnonymous') { $d.Add("external ingress $($ig.Name) lets requests through without a sign-in (AllowAnonymous)") }
        elseif (@($ig.Excluded | Where-Object { $_ }).Count) { $d.Add("external ingress $($ig.Name) has paths without a sign-in: $(@($ig.Excluded | Where-Object { $_ }) -join ',')") }
    }
    # ---- the leftovers
    foreach ($pc in @($f.Registration.passwordCredentials)) { if ($pc) { $l.Add("app registration client secret '$($pc.displayName)'") } }
    foreach ($kc in @($f.Registration.keyCredentials)) { if ($kc) { $l.Add("app registration certificate '$($kc.displayName)'") } }
    foreach ($ru in @($w.redirectUris | Where-Object { $_ -and $_ -notmatch '/\.auth/login/aad/callback$' })) { $l.Add("sign-in address $ru (not the built-in sign-in)") }
    foreach ($sn in @($f.SecretNames | Where-Object { $_ -cne $script:EpsWeb.FicSecretName })) { $l.Add("container app setting '$sn'") }
    foreach ($c in @($ctr | Where-Object { "$($_.name)" -ne 'eps' })) { $l.Add("container '$($c.name)'") }
    foreach ($k in @($ev.Keys | Where-Object { $_ -match '^SIGNIN_' })) { $l.Add("app setting $k") }
    if ($f.FrontKey) { $l.Add("Key Vault key $($script:EpsWeb.KeyName) still exists") }
    if (@($f.FrontKeyRoles).Count) { $l.Add("$(@($f.FrontKeyRoles).Count) role assignment(s) on that key") }
    if ([int]$f.FrontManifests -gt 0) { $l.Add("$($f.FrontManifests) signin-front image(s) still stored in the registry") }
    elseif ([int]$f.FrontManifests -lt 0) { $l.Add('the stored signin-front images could not be read') }
    @{ Diff = @($d); Leftovers = @($l) }
}

function Invoke-EpsBuiltInAuthCheck {
    <#
      2.1.36, the UPDATER, every run: READS the facts (Contributor on the resource group, Application.Read.All, AcrPull)
      and returns the lines - "sign-in standard: OK" or "WARNING sign-in standard: DIFF ...", and "WARNING sign-in
      leftovers: ..." when there are any. Changes NOTHING. Skipped while the install still runs the sign-in front (the
      switch says what it waits for). Never throws: @{ State (ok | diff | front | none | error); Diff; Leftovers; Lines }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    try {
        $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"; $appPath = "$rg/providers/Microsoft.App/containerApps/$($n.WebApp)"
        $app = Invoke-EpsArm -Path $appPath -ApiVersion $script:EpsApi.aca -AllowNotFound
        if (-not $app) { return @{ State = 'none'; Diff = @(); Leftovers = @(); Lines = @('sign-in standard: this install has no web app') } }
        $ac = Invoke-EpsArm -Path "$appPath/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -AllowNotFound
        if ((Get-EpsWebSigninMode -App $app -AuthConfig $ac) -eq 'front') { return @{ State = 'front'; Diff = @(); Leftovers = @(); Lines = @('sign-in standard: still the sign-in front - checked after the switch') } }
        $sec = @(@((Invoke-EpsArm -Method POST -Path "$appPath/listSecrets" -ApiVersion $script:EpsApi.aca -Body @{}).value) | ForEach-Object { "$($_.name)" })
        $reg = @(Invoke-EpsGraph -Path "v1.0/applications?`$filter=tags/any(t:t eq 'eps-install-$($n.Suffix)')&`$select=id,appId,web,passwordCredentials,keyCredentials" -All)[0]
        $fics = if ($reg) { @(Invoke-EpsGraph -Path "v1.0/applications/$($reg.id)/federatedIdentityCredentials" -All) } else { @() }
        $wi = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n.WebIdentity)" -ApiVersion $script:EpsApi.mi -AllowNotFound
        $wp = "$($wi.properties.principalId)"
        $roles = @(@((Invoke-EpsArm -Path "$rg/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$wp'" -ApiVersion $script:EpsApi.rbac).value) | Where-Object { "$($_.properties.principalId)" -eq $wp })
        $keyPath = "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)/keys/$($script:EpsWeb.KeyName)"
        $key = try { Invoke-EpsArm -Path $keyPath -ApiVersion $script:EpsWeb.KvApi -AllowNotFound } catch { $null }
        $keyRoles = if ($key) { @(@((Invoke-EpsArm -Path "$keyPath/providers/Microsoft.Authorization/roleAssignments" -ApiVersion $script:EpsApi.rbac).value) | Where-Object { "$($_.properties.scope)" -like "*/keys/$($script:EpsWeb.KeyName)" }) } else { @() }
        $ms = try { $login = "$($n.Registry).azurecr.io"; @(Get-EpsAcrManifests -LoginServer $login -Repo 'signin-front' -Token (Get-EpsAcrDataToken -LoginServer $login -TenantId $TenantId -Repo 'signin-front' -Actions 'metadata_read')).Count } catch { -1 }
        # every container app of the resource group with an EXTERNAL ingress, and its sign-in
        $ings = foreach ($ca in @(Get-EpsArmAll -Path "$rg/providers/Microsoft.App/containerApps" -ApiVersion $script:EpsApi.aca)) {
            if ($ca.properties.configuration.ingress.external -ne $true) { continue }
            $cac = Invoke-EpsArm -Path "$($ca.id)/authConfigs/current" -ApiVersion $script:EpsWeb.AuthApi -AllowNotFound
            [pscustomobject]@{ Name = "$($ca.name)"; AuthOn = ($cac.properties.platform.enabled -eq $true); Action = "$($cac.properties.globalValidation.unauthenticatedClientAction)"; Excluded = @($cac.properties.globalValidation.excludedPaths) }
        }
        $r = Get-EpsBuiltInAuthConsistency -Facts @{ Ingresses = @($ings); App = $app; AuthConfig = $ac; SecretNames = $sec; Registration = $reg; Fics = $fics; WebPrincipalId = $wp; WebClientId = "$($wi.properties.clientId)"
                                                     WebRoles = $roles; FrontKey = $key; FrontKeyRoles = $keyRoles; FrontManifests = $ms; TenantId = $TenantId; Storage = $n.Storage }
        $lines = @(if ($r.Diff.Count) { "WARNING sign-in standard: DIFF - $($r.Diff -join ' | ')" } else { "sign-in standard: OK (Microsoft's built-in sign-in exactly as the standard)" })
        if ($r.Leftovers.Count) { $lines += "WARNING sign-in leftovers (reported, nothing removed): $($r.Leftovers -join ' | ')" }
        @{ State = $(if ($r.Diff.Count) { 'diff' } else { 'ok' }); Diff = $r.Diff; Leftovers = $r.Leftovers; Lines = $lines }
    } catch { @{ State = 'error'; Diff = @(); Leftovers = @(); Lines = @("WARNING sign-in standard: not read - $((("$($_.Exception.Message)") -split "`n")[0])") } }
}

function Remove-EpsRetiredFrontImages {
    <#
      2.1.41 (framework SECURE-WEB-1 "LEFTOVER CLEANUP - WHO DELETES WHAT", Invardia 2026-11-15: the PRODUCT clears its own
      data plane): once the web app runs NO sign-in front and the release pins none, every image still stored in the
      install's OWN repository 'signin-front' is deleted by the updater (the same data-plane right as IMAGE-PRUNE) and read
      back. Touches no other repository and no other registry. Never throws: @{ State (removed | none | kept | error); Lines }.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][bool]$FrontRuns, [string]$Pin = '', [int]$Passes = 3)
    if ($FrontRuns -or $Pin) { return @{ State = 'kept'; Lines = @("retired sign-in front images: kept - $(if ($FrontRuns) { 'the web app still runs the sign-in front' } else { "this release pins signin-front $Pin" })") } }
    try {
        $repo = 'signin-front'
        $tok = Get-EpsAcrDataToken -LoginServer $LoginServer -TenantId $TenantId -Repo $repo
        $before = @(Get-EpsAcrManifests -LoginServer $LoginServer -Repo $repo -Token $tok)
        if (-not $before.Count) { return @{ State = 'none'; Lines = @('retired sign-in front images: none stored') } }
        $failed = [System.Collections.Generic.List[string]]::new()
        for ($k = 0; $k -lt $Passes; $k++) {
            $now = @(Get-EpsAcrManifests -LoginServer $LoginServer -Repo $repo -Token $tok)
            if (-not $now.Count) { break }
            $failed.Clear()
            # an index first, then what is left (a child that an index still names answers 4xx until its index is gone)
            foreach ($m in @($now | Sort-Object { -(@($_.tags).Count) })) {
                $r = Invoke-EpsAcrCall 'DELETE' "https://$LoginServer/v2/$repo/manifests/$($m.digest)" @{ Authorization = "Bearer $tok" } $null
                if ([int]$r.Status -notin 200, 202, 404) { $failed.Add("$(Get-EpsShortDigest $m.digest) (HTTP $($r.Status))") }
            }
        }
        $after = @(Get-EpsAcrManifests -LoginServer $LoginServer -Repo $repo -Token $tok)
        if ($after.Count) { return @{ State = 'error'; Lines = @("WARNING retired sign-in front images: $($before.Count) stored, $($after.Count) still there after the clean-up (read back)$(if ($failed.Count) { "; not deleted: $($failed -join ', ')" }) - the next update run tries again") } }
        @{ State = 'removed'; Lines = @("retired sign-in front images: $($before.Count) removed from $LoginServer/$repo (read back: none left)") }
    } catch { @{ State = 'error'; Lines = @("WARNING retired sign-in front images: $((("$($_.Exception.Message)") -split "`n")[0]) - the next update run tries again") } }
}