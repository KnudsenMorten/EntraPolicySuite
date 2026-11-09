# EntraPolicySuite -- THE JOB RENAME (framework NAMING-PROGRAMME-1, owner 2026-11-09: "rip of the bandage and chg the job +
# MI so it aligns to framework" - "Go - jobs + identities"; web apps are never renamed). An install made before 2.0.55 has
# the scheduler job caj-eps-tick and the update job caj-eps-update; the standard names are caj-eps-engine and
# caj-eps-updater. Azure cannot rename a job, so each is MOVED: the new job is made from the old one's LIVE spec (same
# identities, image, env, registries, timeouts) with a MANUAL trigger, proven with one real run, the old job is deleted
# (read back 404), and only then the new job gets the old one's trigger - so the two never fire side by side (a missed tick
# at most). Identities do not change (id-eps-engine / id-eps-updater) and no right moves: the rights are on the identities;
# a role assignment scoped to the old JOB itself is copied to the new one first. Runs only on the install's -RenameJobs
# (Invardia approves each install's plan first); otherwise the step is a read-only plan. Run by the install (a person or
# the Support app), never by the updater: the update job cannot replace itself.

Set-StrictMode -Off

function Get-EpsJobRenamePairs {
    # PURE. The jobs an older install renames: role, old name, new name, the queue key (unchanged)
    @(
        [pscustomobject]@{ Role = 'engine';  Old = 'caj-eps-tick';   New = 'caj-eps-engine';  Identity = 'id-eps-engine' }
        [pscustomobject]@{ Role = 'updater'; Old = 'caj-eps-update'; New = 'caj-eps-updater'; Identity = 'id-eps-updater' }
    )
}

function New-EpsJobRenameBody {
    <#
      PURE. The new job's PUT body from the old job's GET: same location, identities, tags, environment, workload profile,
      registries, timeouts, template (image, env, resources) - with a MANUAL trigger. Returns @{ Body; Trigger } where
      Trigger is the old job's trigger as a PATCH body (applied after the old job is gone). A secret with a VALUE cannot be
      copied (ARM never returns it) - refused, nothing is made.
    #>
    param([Parameter(Mandatory)]$OldJob)
    $c = $OldJob.properties.configuration
    foreach ($s in @($c.secrets)) { if ($s -and -not $s.keyVaultUrl) { throw "the job $($OldJob.name) has a secret '$($s.name)' with a value - it cannot be copied; nothing was made" } }
    $ua = [ordered]@{}; foreach ($k in @($OldJob.identity.userAssignedIdentities.PSObject.Properties.Name)) { if ($k) { $ua[$k] = @{} } }
    $cfg = [ordered]@{ triggerType = 'Manual'; replicaTimeout = $c.replicaTimeout; replicaRetryLimit = $c.replicaRetryLimit
                       manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
    if ($c.registries) { $cfg.registries = @($c.registries) }
    if (@($c.secrets).Count) { $cfg.secrets = @($c.secrets) }
    $props = [ordered]@{ environmentId = $OldJob.properties.environmentId; configuration = $cfg; template = $OldJob.properties.template }
    if ($OldJob.properties.workloadProfileName) { $props.workloadProfileName = $OldJob.properties.workloadProfileName }
    $body = [ordered]@{ location = $OldJob.location; properties = $props }
    if ($ua.Count) { $body.identity = [ordered]@{ type = $(if ("$($OldJob.identity.type)" -match 'SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }); userAssignedIdentities = $ua } }
    if ($OldJob.tags) { $body.tags = $OldJob.tags }
    $trig = [ordered]@{ triggerType = "$($c.triggerType)" }
    switch ("$($c.triggerType)") {
        'Schedule' { $trig.scheduleTriggerConfig = $c.scheduleTriggerConfig }
        'Event'    { $trig.eventTriggerConfig = $c.eventTriggerConfig }
        default    { $trig.manualTriggerConfig = $c.manualTriggerConfig }
    }
    @{ Body = $body; Trigger = @{ properties = @{ configuration = $trig } } }
}

function Get-EpsJobRenamePlan {
    <#
      READ ONLY. Per pair, from the live install: what exists and what the step would do -
        rename  : the old job exists, the new one not
        finish  : both exist (a move half done) - prove the new one, delete the old, set the trigger
        done    : only the new one exists
        n/a     : neither (not this kind of install)
      plus what moves with it: role assignments on the old job's own scope, log alert rules that name the old job, a
      running execution of the old job (the move waits for it). Returns the rows.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)"
    $alerts = @(try { @((Invoke-EpsArm -Path "$rg/providers/Microsoft.Insights/scheduledQueryRules" -ApiVersion '2023-03-15-preview' -AllowNotFound).value) } catch { @() })
    foreach ($p in Get-EpsJobRenamePairs) {
        $old = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$($p.Old)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
        $new = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$($p.New)" -ApiVersion $script:EpsApi.acajob -AllowNotFound
        $action = if ($old -and -not $new) { 'rename' } elseif ($old -and $new) { 'finish' } elseif ($new) { 'done' } else { 'n/a' }
        $ras = @(); $running = @(); $ids = @(); $trig = ''
        if ($old) {
            $ras = @(@((Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$($p.Old)/providers/Microsoft.Authorization/roleAssignments" -ApiVersion $script:EpsApi.rbac).value) | Where-Object { "$($_.properties.scope)" -like "*/jobs/$($p.Old)" })
            $running = @(@((Invoke-EpsArm -Path "$rg/providers/Microsoft.App/jobs/$($p.Old)/executions" -ApiVersion $script:EpsApi.acajob -AllowNotFound).value) | Where-Object { "$($_.properties.status)" -eq 'Running' })
            $ids = @($old.identity.userAssignedIdentities.PSObject.Properties.Name | ForEach-Object { ($_ -split '/')[-1] })
            $trig = "$($old.properties.configuration.triggerType)"
        }
        $al = @($alerts | Where-Object { ($_ | ConvertTo-Json -Depth 20 -Compress) -match [regex]::Escape($p.Old) } | ForEach-Object { "$($_.name)" })
        [pscustomobject]@{ Role = $p.Role; Old = $p.Old; New = $p.New; Action = $action; Trigger = $trig; Identities = $ids
            JobScopedRoleAssignments = @($ras | ForEach-Object { "$($_.properties.roleDefinitionId -replace '^.*/', '') -> $($_.properties.principalId)" })
            RunningExecutions = @($running | ForEach-Object { "$($_.name)" }); AlertRulesNamingOld = $al }
    }
}

function Invoke-EpsRenameJobsStep {
    # The install step 'renamejobs'. Without -RenameJobs (Ctx.RenameJobs): the plan only, nothing changes. With it: each
    # pair to move, in order (the scheduler first, then the update job), a rollback record per job under the install's
    # state folder; then the install's names are the standard ones. Returns the done rows.
    param([Parameter(Mandatory)]$Ctx)
    $rows = @(Get-EpsJobRenamePlan -Ctx $Ctx | Where-Object { $_.Action -in 'rename', 'finish' })
    if (-not $rows.Count) { return @() }
    if (-not $Ctx.RenameJobs) {
        foreach ($r in $rows) { Write-Host "  plan     $($r.Old) -> $($r.New) ($($r.Action)) - not run: -RenameJobs (after Invardia approved this install's plan)" -ForegroundColor Yellow }
        return @()
    }
    if (-not $Ctx.Renamed) { $Ctx.Renamed = [System.Collections.Generic.List[string]]::new() }
    $dir = if ($Ctx.StatePath) { Join-Path $Ctx.StatePath 'job-rename' } else { Join-Path ([IO.Path]::GetTempPath()) 'eps-job-rename' }
    $done = foreach ($r in $rows) {
        $rec = Join-Path $dir "$($r.Old)-$([datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
        $x = Invoke-EpsJobRename -Ctx $Ctx -Row $r -Record $rec
        $Ctx.Renamed.Add("job moved: $($x.Old) -> $($x.New) - proof run $($x.Proof); $($x.Note); rollback record $rec")
        $x
    }
    $Ctx.Names.TickJob = 'caj-eps-engine'; $Ctx.Names.UpdateJob = 'caj-eps-updater'
    @($done)
}

function Invoke-EpsJobRename {
    <#
      DOES one pair (a row of Get-EpsJobRenamePlan with Action rename / finish). Order, each step read back:
        1. the new job from the old one's live spec, MANUAL trigger (rename only) + the old job's job-scoped role assignments
        2. ONE REAL RUN of the new job, Succeeded (else: stop - the old job is untouched and keeps running; delete the new
           one to roll back)
        3. wait for a running execution of the old job, then DELETE the old job (read back 404)
        4. the new job gets the old one's trigger (Schedule / Event) - read back
      -Record: a path for the rollback record (the old job's full GET, written BEFORE anything changes).
      Returns @{ Role; Old; New; Proof; Note }.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$Row, [string]$Record, [int]$ProofTimeoutSeconds = 1800, [int]$PollSeconds = 15, [int]$OldRunWaitSeconds = 3600)
    $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)"
    $oldPath = "$rg/providers/Microsoft.App/jobs/$($Row.Old)"; $newPath = "$rg/providers/Microsoft.App/jobs/$($Row.New)"
    $old = Invoke-EpsArm -Path $oldPath -ApiVersion $script:EpsApi.acajob -AllowNotFound
    if (-not $old) { throw "the old job $($Row.Old) is gone - nothing to move (the plan says $($Row.Action))" }
    if ($Record) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Record) | Out-Null; ($old | ConvertTo-Json -Depth 30) | Set-Content -LiteralPath $Record -Encoding utf8NoBOM }
    $made = New-EpsJobRenameBody -OldJob $old
    # 1. the new job (MANUAL) + the job-scoped role assignments
    if (-not (Invoke-EpsArm -Path $newPath -ApiVersion $script:EpsApi.acajob -AllowNotFound)) {
        [void](Invoke-EpsArm -Method PUT -Path $newPath -ApiVersion $script:EpsApi.acajob -Body $made.Body)
    }
    $nj = Invoke-EpsArm -Path $newPath -ApiVersion $script:EpsApi.acajob
    if ("$($nj.properties.provisioningState)" -ne 'Succeeded') { throw "the new job $($Row.New) is $($nj.properties.provisioningState), not Succeeded" }
    $want = @($old.identity.userAssignedIdentities.PSObject.Properties.Name | Sort-Object) -join ','
    $have = @($nj.identity.userAssignedIdentities.PSObject.Properties.Name | Sort-Object) -join ','
    if ($want -ne $have) { throw "the new job $($Row.New) signs in as [$have], not [$want] - stopped before its run" }
    foreach ($ra in @(@((Invoke-EpsArm -Path "$oldPath/providers/Microsoft.Authorization/roleAssignments" -ApiVersion $script:EpsApi.rbac).value) | Where-Object { "$($_.properties.scope)" -like "*/jobs/$($Row.Old)" })) {
        Add-EpsRoleAssignment -Scope $newPath -RoleDefinitionId $ra.properties.roleDefinitionId -PrincipalId $ra.properties.principalId -PrincipalType "$($ra.properties.principalType)"
    }
    # 2. one real run of the new job
    $s = Start-EpsAcaJob -SubscriptionId $Ctx.SubscriptionId -ResourceGroup $Ctx.Names.ResourceGroup -Name $Row.New
    if (-not $s.Ok) { throw "the new job $($Row.New) could not be started: $($s.Reason) - the old job $($Row.Old) is untouched" }
    $w = Wait-EpsAcaJobExecution -Ctx $Ctx -Job $Row.New -Execution $s.Execution -TimeoutSeconds $ProofTimeoutSeconds -PollSeconds $PollSeconds
    if ($w.Status -ne 'Succeeded') { throw "the proof run of $($Row.New) ($($s.Execution)) ended $($w.Status) - the old job $($Row.Old) is untouched; delete $($Row.New) to roll back" }
    # 3. the old job: wait for its running execution, then delete, read back 404
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (@(@((Invoke-EpsArm -Path "$oldPath/executions" -ApiVersion $script:EpsApi.acajob -AllowNotFound).value) | Where-Object { "$($_.properties.status)" -eq 'Running' }).Count) {
        if ($sw.Elapsed.TotalSeconds -ge $OldRunWaitSeconds) { throw "the old job $($Row.Old) is still running after $OldRunWaitSeconds s - not deleted; the new job $($Row.New) is proven (Manual) - run again" }
        Start-Sleep -Seconds $PollSeconds
    }
    [void](Invoke-EpsArm -Method DELETE -Path $oldPath -ApiVersion $script:EpsApi.acajob -AllowNotFound)
    if (Invoke-EpsArm -Path $oldPath -ApiVersion $script:EpsApi.acajob -AllowNotFound) { throw "the old job $($Row.Old) still exists after the delete" }
    # 4. the old trigger on the new job, read back
    [void](Invoke-EpsArm -Method PATCH -Path $newPath -ApiVersion $script:EpsApi.acajob -Body $made.Trigger)
    $nj = Invoke-EpsArm -Path $newPath -ApiVersion $script:EpsApi.acajob
    $tt = "$($made.Trigger.properties.configuration.triggerType)"
    if ("$($nj.properties.configuration.triggerType)" -ne $tt) { throw "the new job $($Row.New) has trigger $($nj.properties.configuration.triggerType), not $tt - set it (the old job is deleted; the record has its trigger)" }
    @{ Role = $Row.Role; Old = $Row.Old; New = $Row.New; Proof = "$($s.Execution) Succeeded ($($w.Seconds) s)"; Note = "$($Row.Old) deleted (read back 404); $($Row.New) on the $tt trigger" }
}
