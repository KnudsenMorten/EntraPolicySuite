# EntraPolicySuite -- the guard step of the pipeline (DESIGN §2a: ... -> decide (plan) -> GUARD -> apply ...).
# Only THREE guards block (DESIGN §5.9); this file holds the one that looks at a run's plan: the MASS-CHANGE guard.
# (Broken reference = the schema's constraints + the save check; break-glass excluded = the CA deploy step.)
#
# A run whose plan changes far more objects than the last run is HELD for an admin's approval - nothing is applied,
# nothing is lost. OVERWRITING an existing tag counts with a lower limit than filling an empty one: an overwrite moves a
# user between Conditional Access policies (owner's example 2026-10-29: 60,000 Classification overwrites vs ~40 last run).
# A trip produces the framework GUARD-1 record (mail, telemetry, ticket - sent by the job, failure-safe).

Set-StrictMode -Off

function Get-EpsGuardDefaults {
    # Every limit is a setting (DESIGN §5.8); these are the defaults. A limit = the larger of the count and the percent
    # of the objects in scope, so a small tenant is not held for normal churn and a large one is not let through 5,000.
    [ordered]@{ MaxChanges = 500; MaxChangesPercent = 5; MaxOverwrites = 100; MaxOverwritesPercent = 1 }
}

function Test-EpsMassChangeGuard {
    <#
    .SYNOPSIS
        Decides whether a run's plan may be applied. Returns @{ Held; Reason; Measured; Thresholds; Record }.
    .PARAMETER Summary
        Get-EpsPlanSummary of the plan.
    .PARAMETER Previous
        The last applied run of the same job: @{ Planned; Overwrites }. None = a first run, measured against 0.
    .PARAMETER ApprovedBy
        An admin approved this held run: it passes, and the approval is in the record.
    #>
    param(
        [Parameter(Mandatory)]$Summary,
        $Previous,
        [hashtable]$Settings = @{},
        [Parameter(Mandatory)][string]$Job,
        [string]$ApprovedBy,
        [string]$Version = '2.0.0'
    )
    $s = Get-EpsGuardDefaults
    foreach ($k in @($s.Keys)) { if ($null -ne $Settings[$k]) { $s[$k] = [double]$Settings[$k] } }
    $objects = [int]$Summary.Objects
    $limitChanges = [math]::Max([double]$s.MaxChanges, [math]::Ceiling($objects * $s.MaxChangesPercent / 100))
    $limitOverwrites = [math]::Max([double]$s.MaxOverwrites, [math]::Ceiling($objects * $s.MaxOverwritesPercent / 100))
    $prevChanges = if ($Previous) { [int]$Previous.Planned } else { 0 }
    $prevOverwrites = if ($Previous) { [int]$Previous.Overwrites } else { 0 }
    $changes = [int]$Summary.Changes; $overwrites = [int]$Summary.Overwrites
    $growChanges = $changes - $prevChanges; $growOverwrites = $overwrites - $prevOverwrites

    $why = @()
    if ($growOverwrites -gt $limitOverwrites) { $why += "$overwrites tag overwrites (last run $prevOverwrites) - more than $limitOverwrites over the last run" }
    if ($growChanges -gt $limitChanges) { $why += "$changes tag changes (last run $prevChanges) - more than $limitChanges over the last run" }
    $tripped = $why.Count -gt 0
    $held = $tripped -and -not $ApprovedBy
    # the rules behind the most changes, so the admin sees WHICH rule moves the users
    $top = @($Summary.ByRule.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Key): $($_.Value)" })
    $reason = if ($tripped) { ($why -join '; ') + $(if ($top) { ". Rules behind them: $($top -join ', ')" }) + $(if ($ApprovedBy) { ". Approved by $ApprovedBy." }) }

    $measured = [ordered]@{ objects = $objects; changes = $changes; overwrites = $overwrites; previousChanges = $prevChanges; previousOverwrites = $prevOverwrites }
    $thresholds = [ordered]@{ maxChanges = $limitChanges; maxOverwrites = $limitOverwrites }
    $record = if ($tripped) {
        # framework GUARD-1.3, Kind guard: held = warning severity (nothing lost, an admin decides)
        [ordered]@{ Schema = 2; Kind = 'guard'; GuardId = "eps.$($Job.ToLowerInvariant()).mass-change"; GuardOutcome = $(if ($held) { 'held' } else { 'warning' })
                    Severity = 'warning'; Area = 'EntraPolicySuite'; Job = "eps-$($Job.ToLowerInvariant())"; Version = $Version
                    Measured = $measured; Thresholds = $thresholds; HeldCount = $(if ($held) { $changes } else { 0 }); TripCount = 1
                    FirstSeenUtc = [datetime]::UtcNow.ToString('o')
                    ActionText = $(if ($held) { 'Review the plan on the run page, then approve or change the rules.' } else { "Approved by $ApprovedBy." }) }
    }
    [pscustomobject]@{ Held = $held; Tripped = $tripped; Reason = $reason; Measured = $measured; Thresholds = $thresholds; Record = $record }
}
