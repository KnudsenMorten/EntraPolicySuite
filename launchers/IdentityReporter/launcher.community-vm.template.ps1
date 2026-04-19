#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for IdentityReporter.

.DESCRIPTION
    For public / external users of IdentityReporter (published via the
    EntraPolicySuite community GitHub repo). This launcher loads NO
    internal-only modules. Instead it dot-sources a user-edited
    LauncherConfig.ps1 (sitting beside this launcher on disk) that sets
    every $global:* customer value the engine expects.

    First-run steps for the community user:
      1. Copy LauncherConfig.sample.ps1 -> LauncherConfig.ps1
      2. Edit LauncherConfig.ps1 -- fill in your tenant, mail, OU patterns
      3. Install prerequisite modules: AutomateITPS, AutomateITPS.Compat,
         AutomateITPS.AD, AzLogDcrIngestPS, Microsoft.Graph.Beta,
         ExchangeOnlineManagement, ImportExcel, ActiveDirectory (RSAT).
      4. Authenticate to Azure / Graph / EXO as appropriate, then run
         this launcher.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : launcher.community-vm.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    [string]$InstallPath,

    [ValidateSet('Internal_Prod','DMZ_Prod','Internal_Dev','Internal_Test')]
    [string]$Environment = 'Internal_Prod',

    [string]$LauncherConfigPath,

    [string]$OutputDir,
    [string[]]$AlertTo,
    [int]$DeviceLastSyncDaysFilter = 30,
    [switch]$SkipOnPremAD
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

if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
    throw @"
Community launcher: $LauncherConfigPath not found.
Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1, fill in your values,
then re-run. LauncherConfig.ps1 is .gitignore'd so it stays on your machine.
"@
}
. $LauncherConfigPath

# Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'IdentityReporter.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'IdentityReporter.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts. Expected the launcher to live at <solroot>\LAUNCHERS\<engine>\ with a sibling SCRIPTS\ or scripts\ folder." }
if (-not (Test-Path -LiteralPath $engine)) {
    throw "Launcher: engine script not found at $engine."
}

& $engine `
    -Environment              $Environment `
    -SettingsPath             $PSScriptRoot `
    -OutputDir                $OutputDir `
    -AlertTo                  $AlertTo `
    -DeviceLastSyncDaysFilter $DeviceLastSyncDaysFilter `
    -SkipOnPremAD:$SkipOnPremAD
