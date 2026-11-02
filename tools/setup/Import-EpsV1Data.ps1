#Requires -Version 7.2
<#
.SYNOPSIS
    Moves a v1 EntraPolicySuite install's rules and settings into EntraPolicySuite 2.0 (SQL).
.DESCRIPTION
    Reads a v1 folder - DATA\Identity_Tagging*.csv, Device_Tagging*.csv, EntraNamedLocations_AzureNetworkServiceTags.csv,
    Entra_Policy_Suite_custom.config, Entra_Policy_Suite_locked.config, and the attribute per tag type from
    Entra-Policy-Suite\Entra-ID-User-Tagging.ps1 - and shows the plan: the rule cards it makes (v1 rows with the same
    ConditionGroup become one card), the tag types and their values, the settings, break-glass accounts, admin units,
    target groups and service tags, and the HINTS on the rules (cloned rows that kept their ConditionGroup, a condition
    twice, a contradiction, an unknown condition type ...).
    Nothing is written without -Apply. With -Apply the plan is written to SQL in one transaction; a re-import replaces
    the previous import's rules and never touches rules made in the GUI. The v1 folder is only read, never changed.
    Demo material (Identity_Tagging_Demo_Reset.csv, the demo scripts) is not read.
.PARAMETER Path
    The v1 folder: its DATA folder, or the folder that holds DATA (e.g. C:\SCRIPTS).
.PARAMETER UserTaggingScript
    v1's Entra-ID-User-Tagging.ps1, for the attribute per tag type. Default: <folder>\Entra-Policy-Suite\.
.PARAMETER OutFile
    Also save the plan as JSON (for review, or to hand to support).
.PARAMETER Apply
    Write the plan to SQL. Without it the script only reads and shows.
.PARAMETER ConnectionString
    The EntraPolicySuite database. With its own auth (Integrated Security) it is used as is; otherwise the managed
    identity of the machine / container signs in.
.EXAMPLE
    .\Import-EpsV1Data.ps1 -Path C:\SCRIPTS
    Shows the plan, writes nothing.
.EXAMPLE
    .\Import-EpsV1Data.ps1 -Path C:\SCRIPTS -Apply -ConnectionString 'Server=tcp:<server>.database.windows.net;Database=eps;Encrypt=True'
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
. (Join-Path $engine 'EPS-SqlStore.ps1')

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

if (-not $Apply) {
    if (-not $Quiet) { Write-Host "`nNothing written. Run again with -Apply -ConnectionString <the EntraPolicySuite database> to import." -ForegroundColor Cyan }
    return $model
}
if (-not $ConnectionString) { throw '-Apply needs -ConnectionString (the EntraPolicySuite database).' }
$what = "{0} user rule(s), {1} device rule(s), {2} tag type(s), {3} setting(s)" -f @($model.UserRules).Count, @($model.DeviceRules).Count, @($model.TagTypes).Count, @($model.Settings.Keys).Count
if ($PSCmdlet.ShouldProcess('EntraPolicySuite database', "import $what (replaces the previous v1 import's rules)")) {
    $result = Write-EpsV1Import -ConnectionString $ConnectionString -Model $model -Actor "v1-import:$([Environment]::UserName)"
    if (-not $Quiet) { Write-Host "`nImported: $($result | ConvertTo-Json -Compress)" -ForegroundColor Green }
    return $result
}
