# EntraPolicySuite -- Azure Resource Manager over REST (framework NO-AZ: no Az module, no az CLI), and the image build in
# the customer's own registry (ACR tasks: upload the source, schedule a docker build, wait for it - PIM-AcrBuild.ps1's
# four calls). Uses Get-EpsToken / $script:EpsHttp from EPS-Graph.ps1, so a test stubs one hook for everything.

Set-StrictMode -Off
$script:EpsArmRoot = 'https://management.azure.com'

function Get-EpsHeader($r, [string]$name) {
    if (-not $r.Headers) { return $null }
    foreach ($k in @($r.Headers.Keys)) { if ([string]::Equals([string]$k, $name, [StringComparison]::OrdinalIgnoreCase)) { return [string](@($r.Headers[$k])[0]) } }
    $null
}

function Invoke-EpsArm {
    <#
    .SYNOPSIS
        One ARM call. 429 / 5xx are retried after Retry-After; a long-running PUT / POST / DELETE (201 / 202 with an
        Azure-AsyncOperation or Location header) is waited for. -AllowNotFound returns $null on 404. Any other error
        throws with ARM's own code and message.
    #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, $Body,
          [switch]$AllowNotFound, [int]$MaxRetry = 6, [int]$WaitSeconds = 900, [int]$PollSeconds = 5)
    $uri = if ($Path -match '^https://') { $Path } else { "$script:EpsArmRoot/$($Path.TrimStart('/'))" }
    $uri += $(if ($uri -match '\?') { '&' } else { '?' }) + "api-version=$ApiVersion"
    $json = if ($null -ne $Body -and $Body -isnot [string]) { $Body | ConvertTo-Json -Depth 30 -Compress } else { $Body }
    $try = 0
    while ($true) {
        $r = & $script:EpsHttp $Method $uri @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" } $json
        if (($r.Status -eq 429 -or $r.Status -ge 500) -and $try -lt $MaxRetry) {
            $try++; $wait = 0
            if (-not [int]::TryParse([string](Get-EpsHeader $r 'Retry-After'), [ref]$wait)) { $wait = [math]::Min(60, [math]::Pow(2, $try)) }
            Start-Sleep -Seconds ([math]::Max(1, $wait)); continue
        }
        break
    }
    if ($r.Status -eq 404 -and $AllowNotFound) { return $null }
    if ($r.Status -ge 400) {
        $e = try { ($r.Body | ConvertFrom-Json).error } catch { $null }
        throw "ARM $Method $($uri -replace '\?.*$', '') -> $($r.Status): $(if ($e) { "$($e.code): $($e.message)" } else { $r.Body })"
    }
    $async = Get-EpsHeader $r 'Azure-AsyncOperation'; $loc = Get-EpsHeader $r 'Location'
    foreach ($v in 'async', 'loc') { $x = Get-Variable -Name $v -ValueOnly; if ($x -and $x -notmatch '^https://') { Set-Variable -Name $v -Value "$script:EpsArmRoot/$($x.TrimStart('/'))" } }
    # ARM's convention (found live 2026-10-30): a 201 Created's Location is the new RESOURCE, not an operation to poll -
    # poll a 201 only with Azure-AsyncOperation, a 202 with either
    if (($r.Status -eq 201 -and $async) -or ($r.Status -eq 202 -and ($async -or $loc))) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $WaitSeconds) {
            Start-Sleep -Seconds $PollSeconds
            $p = & $script:EpsHttp 'GET' $(if ($async) { $async } else { $loc }) @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" } $null
            if ($loc -and -not $async) { if ($p.Status -eq 202) { continue }; if ($p.Status -ge 400) { throw "ARM $Method $($uri -replace '\?.*$', '') failed: $($p.Body)" }; break }
            $st = try { ($p.Body | ConvertFrom-Json).status } catch { '' }
            if ($st -in 'Succeeded') { break }
            if ($st -in 'Failed', 'Canceled') { throw "ARM $Method $($uri -replace '\?.*$', '') ended $st`: $(try { ($p.Body | ConvertFrom-Json).error.message } catch { $p.Body })" }
        }
        if ($sw.Elapsed.TotalSeconds -ge $WaitSeconds) { throw "ARM $Method $($uri -replace '\?.*$', '') still running after $WaitSeconds s" }
        if ($Method -in 'PUT', 'PATCH') { return (Invoke-EpsArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound) }
        return $null
    }
    if ($r.Body) { $r.Body | ConvertFrom-Json -Depth 30 }
}

# ---- the image, built in the customer's registry (no docker, no az) ----------------------------------------------
$script:EpsAcrTasksApi = '2019-06-01-preview'

function Invoke-EpsAcrBuild {
    <#
    .SYNOPSIS
        Builds -ImageName from a .tar.gz build context in the registry: upload URL, PUT the context (a blob SAS: no
        bearer token), schedule a docker build, wait for a terminal status. Returns @{ RunId; Status; Digest; Log }.
        A failed build throws with the registry's error and the end of the build log.
    #>
    param([Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$ContextPath, [Parameter(Mandatory)][string]$DockerFile,
          [Parameter(Mandatory)][string]$ImageName, [hashtable]$BuildArgs = @{}, [int]$TimeoutSeconds = 3600, [int]$PollSeconds = 10,
          # NET-1: the registry's build pool inside the network (a private registry cannot be reached by ACR Tasks from outside)
          [string]$AgentPoolName = '')
    $up = Invoke-EpsArm -Method POST -Path "$RegistryId/listBuildSourceUploadUrl" -ApiVersion $script:EpsAcrTasksApi -Body @{}
    $put = & $script:EpsHttp 'PUT' $up.uploadUrl @{ 'x-ms-blob-type' = 'BlockBlob' } ([IO.File]::ReadAllBytes($ContextPath))
    if ($put.Status -ge 300) { throw "uploading the build context failed: $($put.Status) $($put.Body)" }
    $body = @{ type = 'DockerBuildRequest'; isPushEnabled = $true; noCache = $false; dockerFilePath = $DockerFile; imageNames = @($ImageName)
               sourceLocation = $up.relativePath; platform = @{ os = 'Linux'; architecture = 'amd64' }; timeout = $TimeoutSeconds
               arguments = @(foreach ($k in $BuildArgs.Keys) { @{ name = $k; value = [string]$BuildArgs[$k]; isSecret = $false } }) }
    if ($AgentPoolName) { $body.agentPoolName = $AgentPoolName }
    $run = Invoke-EpsArm -Method POST -Path "$RegistryId/scheduleRun" -ApiVersion $script:EpsAcrTasksApi -Body $body
    $runId = if ($run.properties.runId) { $run.properties.runId } elseif ($run.runId) { $run.runId } else { $run.name }
    if (-not $runId) { throw 'the registry returned no build run id' }
    $sw = [Diagnostics.Stopwatch]::StartNew(); $st = ''
    do {
        Start-Sleep -Seconds $PollSeconds
        $r = Invoke-EpsArm -Path "$RegistryId/runs/$runId" -ApiVersion $script:EpsAcrTasksApi
        $st = [string]$r.properties.status
    } while ($st -notin 'Succeeded', 'Failed', 'Canceled', 'Error', 'Timeout' -and $sw.Elapsed.TotalSeconds -lt ($TimeoutSeconds + 300))
    $log = try { $l = Invoke-EpsArm -Method POST -Path "$RegistryId/runs/$runId/listLogSasUrl" -ApiVersion $script:EpsAcrTasksApi -Body @{}; (& $script:EpsHttp 'GET' $l.logLink @{} $null).Body } catch { '' }
    if ($st -ne 'Succeeded') { throw "the image build $runId ended '$st': $($r.properties.runErrorMessage)`n$(([string]$log).Split("`n") | Select-Object -Last 25 | Out-String)" }
    $digest = @($r.properties.outputImages | Where-Object { $_ }).digest | Select-Object -First 1
    [pscustomobject]@{ RunId = $runId; Status = $st; Digest = $digest; Log = $log }
}

function New-EpsBuildContext {
    # The build context: the repo root's SOLUTIONS/EntraPolicySuite (the Dockerfile copies it from there), as .tar.gz.
    # Uses the in-box tar (Windows 10+, Linux, Cloud Shell) - no module.
    param([Parameter(Mandatory)][string]$SolutionRoot, [string]$OutFile = (Join-Path ([IO.Path]::GetTempPath()) "eps-context-$([guid]::NewGuid().ToString('N')).tar.gz"))
    $stage = Join-Path ([IO.Path]::GetTempPath()) "eps-ctx-$([guid]::NewGuid().ToString('N'))"
    $dst = Join-Path $stage 'SOLUTIONS\EntraPolicySuite'
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    foreach ($d in Get-ChildItem -LiteralPath $SolutionRoot -Force | Where-Object { $_.Name -notin 'output', '.git' }) { Copy-Item -LiteralPath $d.FullName -Destination $dst -Recurse -Force }
    # Windows: the in-box bsdtar by its full path - a GNU tar earlier on PATH (Git's) reads 'C:\...' as a remote host
    # ("Cannot connect to C: resolve failed", found live 2026-10-30)
    $tar = if ($IsWindows -and (Test-Path (Join-Path $env:SystemRoot 'System32\tar.exe'))) { Join-Path $env:SystemRoot 'System32\tar.exe' } else { 'tar' }
    & $tar -czf $OutFile -C $stage SOLUTIONS
    if ($LASTEXITCODE) { throw "tar failed ($LASTEXITCODE)" }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    $OutFile
}
