#Requires -Version 5.1
#Requires -Modules @{ ModuleName='AutomateITPS'; ModuleVersion='0.1.0' }
<#
.SYNOPSIS
    Community cloud-native launcher for Entra-Policy-Suite\IdentityReporterTest.
.DESCRIPTION
    External user in Azure Function / Logic App / Hybrid Worker. MI + user's
    own KV holds Modern-ApplicationId-Azure + Modern-Secret-Azure. See
    CriticalAssetTagging\launcher.community-azure.template.ps1 for the
    full setup walkthrough.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : launcher.community-azure.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $communityMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (-not $communityMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'scripts') -and ($dirs -ccontains 'launchers')) { $communityMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($communityMatch) { return $communityMatch }
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a lowercase scripts/+launchers/ pair (community repo)." -f $Start)
}
if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }

$overrideFile = Join-Path $PSScriptRoot 'launcher.override.ps1'
if (Test-Path -LiteralPath $overrideFile) { . $overrideFile }

Import-Module (Join-Path $InstallPath 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Force

$ctx = New-PlatformContext `
    -TenantId           $env:PLATFORM_TENANT_ID `
    -SubscriptionId     $env:PLATFORM_SUBSCRIPTION_ID `
    -KeyVaultName       $env:PLATFORM_KEYVAULT `
    -StorageAccountName $env:PLATFORM_STORAGE_ACCOUNT

Initialize-PlatformIdentity -Context $ctx -IgnoreMissing | Out-Null

if (-not $ctx.Identity.Modern.Azure.AppId -or -not $ctx.Identity.Modern.Azure.Secret) {
    throw "Community cloud launcher: Modern-ApplicationId-Azure / Modern-Secret-Azure not present in KV '$($ctx.Tenant.KeyVaultName)'."
}

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ctx.Identity.Modern.Azure.Secret)
try   { $appSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$global:AutomationFramework = $false
$engineOwner  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$settingsOwner = $engineOwner
$settingsResolved = $null
foreach ($case in 'DATA','data') {
    $candidate = Join-Path $settingsOwner $case
    if (Test-Path -LiteralPath $candidate) { $settingsResolved = $candidate; break }
}
$global:SettingsPath = if ($settingsResolved) { $settingsResolved } else { $PSScriptRoot }
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings
$global:SpnTenantId         = $ctx.Tenant.Id
$global:SpnClientId         = $ctx.Identity.Modern.Azure.AppId
$global:SpnClientSecret     = $appSecretPlain

Write-PlatformLog -Context $ctx -Event 'engine.start' -Message 'IdentityReporterTest (community cloud) starting'

try {
    # Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'IdentityReporterTest.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'IdentityReporterTest.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts. Expected the launcher to live at <solroot>\LAUNCHERS\<engine>\ with a sibling SCRIPTS\ or scripts\ folder." }
    if (-not (Test-Path -LiteralPath $engine)) { throw "Cloud launcher: engine script not found at $engine." }
    & $engine
    Write-PlatformLog -Context $ctx -Event 'engine.end' -Message 'IdentityReporterTest (community cloud) completed'
}
catch {
    Write-PlatformLog -Context $ctx -Severity Error -Event 'engine.fail' -Message "IdentityReporterTest FAILED: $_" -Data @{ exception = $_.ToString(); stack = $_.ScriptStackTrace }
    throw
}
finally {
    $global:SpnClientSecret = $null
    $appSecretPlain = $null
    [System.GC]::Collect()
}
