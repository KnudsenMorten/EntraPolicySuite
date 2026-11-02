#Requires -Version 7.2
<#
.SYNOPSIS
    Downloads EntraPolicySuite 2.0 from its GitHub release and starts the install (the launcher is an asset of every
    release: https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1).
.DESCRIPTION
    Takes the latest v2 release of KnudsenMorten/EntraPolicySuite (or -Version), downloads its zip into a new temporary
    folder, checks it against the SHA-256 digest GitHub publishes for the asset (a mismatch deletes it and stops), unpacks
    it and runs its tools/setup/Install-EntraPolicySuite.ps1 with your parameters. v1 (the scripts) is on the v1 branch
    and is never downloaded or changed by this.
    Run it in PowerShell 7 or Azure Cloud Shell:
        Invoke-WebRequest https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1 -OutFile Start-EpsInstall.ps1
        ./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -WhatIf
    Exit code: the installer's (0 done, 1 a step failed, 2 a check failed), 3 = the download failed or did not match.
.LINK
    https://invardia.com/docs/eps/scripts/Start-EpsInstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$Location,
    [string]$ResourceGroup,
    [ValidatePattern('^$|^2\.\d+\.\d+$')][string]$Version,
    # test seams (as PIM's launcher): the release lookup, the download, the hand-over
    [scriptblock]$GetRelease, [scriptblock]$Download, [scriptblock]$RunInstaller
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://invardia.com/docs/eps/scripts/Start-EpsInstall'
# -WhatIf is for the INSTALLER (its plan, nothing changed in Azure); the download, the check and the unpack into a temp
# folder are real, or there is nothing to run (2026-10-30: the preference reached New-Item / Copy-Item and nothing was
# downloaded)
$what = [bool]$WhatIfPreference
$WhatIfPreference = $false
$repo = 'KnudsenMorten/EntraPolicySuite'
if (-not $GetRelease) { $GetRelease = { param($v) Invoke-RestMethod -Uri $(if ($v) { "https://api.github.com/repos/$repo/releases/tags/v$v" } else { "https://api.github.com/repos/$repo/releases?per_page=30" }) -Headers @{ 'User-Agent' = 'EntraPolicySuite-install' } } }
if (-not $Download) { $Download = { param($url, $file) Invoke-WebRequest -Uri $url -OutFile $file -Headers @{ 'User-Agent' = 'EntraPolicySuite-install' } } }
if (-not $RunInstaller) { $RunInstaller = { param($script, $params) & $script @params; $LASTEXITCODE } }

$rel = & $GetRelease $Version
# the latest v2 release (the repo's v1.0.x releases stay where they are and are never picked)
$rel = @($rel | Where-Object { $_.tag_name -match '^v2\.' -and -not $_.draft -and -not $_.prerelease } | Sort-Object { [version]($_.tag_name.TrimStart('v') -replace '[^0-9.].*$', '') } -Descending)[0]
if (-not $rel) { Write-Host "No EntraPolicySuite v2 release found in $repo$(if ($Version) { " for $Version" })." -ForegroundColor Red; exit 3 }
$asset = @($rel.assets | Where-Object { $_.name -match '^EntraPolicySuite-v2[0-9A-Za-z.+-]*\.zip$' })[0]
if (-not $asset) { Write-Host "Release $($rel.tag_name) has no EntraPolicySuite-v2*.zip asset." -ForegroundColor Red; exit 3 }

$dir = Join-Path ([IO.Path]::GetTempPath()) "eps-release-$($rel.tag_name)-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
New-Item -ItemType Directory -Path $dir | Out-Null
$zip = Join-Path $dir $asset.name
& $Download $asset.browser_download_url $zip
$got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$published = if ("$($asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' }
if ($published -and $got -ne $published) {
    [IO.Directory]::Delete($dir, $true)
    Write-Host "The download does not match the release's published SHA-256 ($published vs $got) - deleted, nothing run." -ForegroundColor Red
    exit 3
}
Write-Host "Release $($rel.tag_name): $($asset.name), SHA-256 $got $(if ($published) { '(matches the release)' } else { '(the release publishes no digest)' })"
Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
$installer = Get-ChildItem -LiteralPath $dir -Recurse -Filter 'Install-EntraPolicySuite.ps1' -File | Select-Object -First 1
if (-not $installer) { Write-Host 'The release has no tools/setup/Install-EntraPolicySuite.ps1.' -ForegroundColor Red; exit 3 }

$pass = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId }
foreach ($k in 'Location', 'ResourceGroup') { if ($PSBoundParameters.ContainsKey($k)) { $pass[$k] = $PSBoundParameters[$k] } }
if ($what) { $pass.WhatIf = $true }
exit (& $RunInstaller $installer.FullName $pass)
