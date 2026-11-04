#Requires -Version 7.2
<#
.SYNOPSIS
    Shows what a v1 Entra Policy Suite install's rules and settings become in Entra Policy Suite 2.0. Writes nothing.
.DESCRIPTION
    Reads a v1 folder - DATA\Identity_Tagging*.csv, Device_Tagging*.csv, EntraNamedLocations_AzureNetworkServiceTags.csv,
    Entra_Policy_Suite_custom.config, Entra_Policy_Suite_locked.config, and the attribute per tag type from
    Entra-Policy-Suite\Entra-ID-User-Tagging.ps1 - and shows the plan: the rule cards it makes (v1 rows with the same
    ConditionGroup become one card), the tag types and their values, the settings, break-glass accounts, admin units,
    target groups and service tags, and the HINTS on the rules (cloned rows that kept their ConditionGroup, a condition
    twice, a contradiction, an unknown condition type ...).
    This script never writes to the database (since 2.0.69 nobody needs a database right to import v1): the import is
    done in the web app - Overview > Import v1 (SuperAdmin): upload the same files, look at the plan, approve, and
    Entra Policy Suite writes it. -Apply prints those steps and the files to upload. The v1 folder is only read, never
    changed. Demo material (Identity_Tagging_Demo_Reset.csv, the demo scripts) is not read.
.PARAMETER Path
    The v1 folder: its DATA folder, or the folder that holds DATA (e.g. C:\SCRIPTS).
.PARAMETER UserTaggingScript
    v1's Entra-ID-User-Tagging.ps1, for the attribute per tag type. Default: <folder>\Entra-Policy-Suite\.
.PARAMETER OutFile
    Also save the plan as JSON (for review, or to hand to support).
.PARAMETER Apply
    Print how to import: the files to upload on the web app's Import v1 page. Nothing is written.
.PARAMETER ConnectionString
    No longer used (2.0.69): the script never connects to the database. Accepted so older command lines still run.
.EXAMPLE
    .\Import-EpsV1Data.ps1 -Path C:\SCRIPTS
    Shows the plan, writes nothing.
.EXAMPLE
    .\Import-EpsV1Data.ps1 -Path C:\SCRIPTS -Apply
    Shows the plan and the files to upload on Overview > Import v1.
.LINK
    https://invardia.com/docs/eps/scripts/Import-EpsV1Data
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$UserTaggingScript,
    [string]$OutFile,
    [switch]$Apply,
    [string]$ConnectionString,
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
$docUrl = 'https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Import-EpsV1Data when EPS is public there (DOC-LINKS)
if (-not $Quiet) { Write-Host "Documentation: $docUrl" }

$engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared'
. (Join-Path $engine 'EPS-Conditions.ps1')
. (Join-Path $engine 'EPS-V1Import.ps1')

$model = Read-EpsV1Data -Path $Path -UserTaggingScript $UserTaggingScript

function Show-EpsImportPlan($m) {
    Write-Host ''
    Write-Host "v1 source: $($m.Source)" -ForegroundColor Cyan
    foreach ($f in $m.Files.Keys) { Write-Host ("  {0,-50} {1}" -f $f, $(if ($m.Files[$f]) { 'found' } else { '-' })) }
    Write-Host ''
    Write-Host 'Tag types' -ForegroundColor Cyan
    foreach ($t in $m.TagTypes | Sort-Object ObjectType, Name) {
        $vals = @($m.TagValues | Where-Object { $_.ObjectType -eq $t.ObjectType -and $_.TagType -eq $t.Name }).Count
        Write-Host ("  {0,-7} {1,-15} {2,-20} {3,-8} {4} value(s)" -f $t.ObjectType, $t.Name, $t.Attribute, $t.ValueMode, $vals)
    }
    Write-Host ''
    Write-Host ("Rules: {0} user rule(s) from {1} v1 row(s), {2} device rule(s) from {3} v1 row(s)" -f @($m.UserRules).Count, $m.UserRowCount, @($m.DeviceRules).Count, $m.DeviceRowCount) -ForegroundColor Cyan
    foreach ($g in @($m.UserRules) | Group-Object TagType) { Write-Host ("  user   {0,-15} {1} rule(s)" -f $g.Name, $g.Count) }
    foreach ($g in @($m.DeviceRules) | Group-Object TagType) { Write-Host ("  device {0,-15} {1} rule(s)" -f $g.Name, $g.Count) }
    Write-Host ''
    Write-Host ("Settings {0}, break-glass accounts {1}, admin units {2}, target groups {3} ({4} dynamic), service tags {5}" -f `
        @($m.Settings.Keys).Count, @($m.BreakGlassAccounts).Count, @($m.AdminUnits).Count, @($m.TargetGroups).Count,
        @($m.TargetGroups | Where-Object Assignment -eq 'Dynamic').Count, @($m.ServiceTags).Count) -ForegroundColor Cyan
    foreach ($x in $m.NotMigrated) { Write-Host "  not moved: $x" -ForegroundColor DarkGray }
    Write-Host ''
    if (@($m.Hints).Count) {
        Write-Host "Hints on the rules ($(@($m.Hints).Count)) - shown, nothing is blocked:" -ForegroundColor Yellow
        foreach ($h in $m.Hints) { Write-Host "  [$($h.Code)] $($h.Message)" -ForegroundColor Yellow }
    } else { Write-Host 'Hints on the rules: none' -ForegroundColor Green }
}

if (-not $Quiet) { Show-EpsImportPlan $model }
if ($OutFile) { $model | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutFile -Encoding utf8; if (-not $Quiet) { Write-Host "`nPlan saved: $OutFile" } }

# SEC-08 row 8 (2.0.69): no person needs database rights to import v1 - this script only reads and shows. The import is
# written by Entra Policy Suite itself: the Import v1 page takes the same files, shows the plan, a SuperAdmin approves.
if (-not $Apply) {
    if (-not $Quiet) { Write-Host "`nNothing written. To import: Overview > Import v1 in the web app (run with -Apply to see the files to upload)." -ForegroundColor Cyan }
    return $model
}
$up = @(foreach ($f in $model.Files.Keys) { if ($model.Files[$f]) { Join-Path $model.Source $f } })
$scr = if ($UserTaggingScript) { $UserTaggingScript } else { Join-Path (Split-Path -Parent $model.Source) 'Entra-Policy-Suite\Entra-ID-User-Tagging.ps1' }
if (Test-Path -LiteralPath $scr) { $up += $scr }
if (-not $Quiet) {
    Write-Host "`nThis script does not write to the database. Import in the web app (a SuperAdmin):" -ForegroundColor Cyan
    Write-Host '  1. Open Entra Policy Suite > Overview > Import v1.'
    Write-Host '  2. Choose these files:'
    foreach ($u in $up) { Write-Host "       $u" }
    Write-Host '  3. Read the files, look at the plan (what is added and what changes), and approve. Entra Policy Suite writes it within 5 minutes.'
    if ($ConnectionString) { Write-Host '  (-ConnectionString is no longer used: nothing connects to the database.)' -ForegroundColor DarkGray }
}
[pscustomobject]@{ Written = $false; Upload = @($up); Page = 'Overview > Import v1' }
