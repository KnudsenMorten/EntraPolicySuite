# EntraPolicySuite -- the audit trail (framework AUDIT-1, PIM's as the reference): ONE writer for every surface (the web
# app, the jobs, setup), a CLOSED action list, the store append-only in the database (schema v7: DENY UPDATE / DELETE).
# A failed audit write never fails the action it records (the change already happened) - it is reported, never swallowed.
# No secret or token is ever written: -Before / -After pass through Remove-EpsAuditSecrets.

Set-StrictMode -Off

# the closed list (AUDIT-1.1): a new action is added HERE, or the writer refuses it (and the suite fails)
$script:EpsAuditActions = @(
    'auth.request.refused'          # a request whose token did not verify (web)
    'access.grant', 'access.revoke' # eps.WebAccess (SuperAdmin)
    'job.run.request'               # Run now / Preview / Apply from the GUI (a signed JobRequest)
    'config.request'                # a configuration change queued as a signed Config request (2.0.8; was missing from
                                    # this list until 2.0.10, so the queueing itself was not audited - the engine's apply was)
    'job.schedule.change'           # the schedule and on / off of a job, on the Jobs page (journaled)
    'queue.stage', 'queue.commit', 'queue.discard', 'queue.discard-all'   # the commit queue (owner 2026-10-31, PIM's setup)
    'mail.test.request'             # "Send a test mail" (the engine sends it as its own identity)
    'setting.change'                # a setting saved (or refused) on the Settings page; the journal row is eps.ConfigChange
    'rule.create', 'rule.update', 'rule.delete', 'rule.move'   # rule cards (journal: eps.ConfigChange)
    'rule.batch', 'rule.batch.check', 'rule.import.plan', 'rules.export'   # the grid (RULES-GRID): a batch of card changes, its check, an import plan, the CSV export
    'tagtype.change', 'tagtype.delete', 'tagvalue.change', 'tagvalue.remove'   # tag types and their allowed values
    'condition.change', 'condition.delete'   # the customer's own property condition types
    'scope.change', 'scope.delete'  # saved scopes ("pilot users")
    'ca.analyze.request', 'ca.export', 'ca.monitor.change', 'ca.monitor.delete'   # the CA Policy Analyzer (read only towards the tenant)
    'ca.template.take'              # Template updates (TEMPLATE-UPDATES, 2.0.26): a newer library's persona changes taken / template changes marked seen - no policy is written
    'ca.persona.change', 'ca.persona.delete'   # the analyzer's personas (CA-PERSONA, 2.0.24): create / edit / rename, delete (journal: eps.ConfigChange)
    'ca.policy.adopt', 'ca.policy.release'   # Conditional Access: the operator RECORDS that he adopts / releases a policy - nothing in the tenant changes
    'identity.action.set'           # ID-ACTIONS (2.0.30): the follow-up fields set on users (EPS data only)
    'onboarding.check', 'breakglass.change'   # GET-STARTED (2.0.28): the engine checks the onboarding steps (reads only); the break-glass list edited (EPS data)
    'ca.policy.stage'               # CA-LIFECYCLE (2.0.27): a SuperAdmin moves ONE adopted policy ONE stage - the engine's one Conditional Access write
    'ca.documentation.export'       # the Conditional Access documentation (CSV / xlsx), ids resolved to names
    'identity.run.request', 'identity.export', 'view.save', 'view.delete'   # the identity report (read only) and saved views (LIST-1)
    'tamper.event.accept'           # the change was legitimate (no outside change)
    'tamper.event.restore.request'  # the GUI asks the engine to write the tag back (a signed JobRequest)
    'tamper.event.restore'          # the engine wrote it back (job)
    'audit.export', 'changes.export', 'runs.export'   # exports of audited data (AUDIT-1.2 item 4)
    'web.request.refused'           # a signed-in caller refused: role, anti-forgery, validation (web)
    'guard.trip'                    # a guard held a change (GUARD-1), e.g. removing the last SuperAdmin
    'support.state.change'          # Invardia's heartbeat answer changed the support state (SECAUDIT-1a) - recorded only, nothing granted (UPLINK-1)
    'support.session.refused'       # a support session above the customer's consent (framework SUPPORT ACCESS) - recorded as closed
    'v1import.plan', 'v1import.apply'   # Import v1 (SEC-08 row 8, 2.0.69): the uploaded files checked (the plan; nothing saved) / written by the engine from a SuperAdmin's signed request
    'support.access.change'         # caj-eps-support changed the Support app's database user (OPEN-01: none / read / admin during a session)
)

function Get-EpsAuditActions { $script:EpsAuditActions }

function Remove-EpsAuditSecrets {
    # a copy without any property that names a token, secret or password (any depth)
    param($Value)
    if ($null -eq $Value) { return $null }
    $o = $Value | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json -AsHashtable
    $walk = $null
    $walk = { param($x)
        if ($x -is [System.Collections.IDictionary]) { foreach ($k in @($x.Keys)) { if ("$k" -match '(?i)token|secret|password|authorization|cookie') { $x[$k] = '(removed)' } else { & $walk $x[$k] } } }
        elseif ($x -is [System.Collections.IList]) { foreach ($i in $x) { & $walk $i } } }
    & $walk $o
    $o
}

function Write-EpsAuditEvent {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)][string]$Actor,
          [ValidateSet('web', 'job', 'setup')][string]$ActorSource = 'web', [string]$Target, [string]$Reason,
          [ValidateSet('ok', 'error', 'refused', 'held')][string]$Outcome = 'ok', [string]$OutcomeText, $Before, $After,
          $CorrelationId, $RunId, [switch]$WhatIf)
    if ($script:EpsAuditActions -notcontains $Action) { Write-Warning "[audit] '$Action' is not in the closed action list - NOT written"; return $false }
    $json = { param($v) if ($null -eq $v) { $null } else { (Remove-EpsAuditSecrets $v) | ConvertTo-Json -Depth 8 -Compress } }
    $cut = { param($s, $n) if ($null -eq $s) { $null } elseif ("$s".Length -gt $n) { "$s".Substring(0, $n) } else { "$s" } }
    try {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{
            a = $Action; u = (& $cut $Actor 320); s = $ActorSource; t = (& $cut $Target 1000); r = (& $cut $Reason 1000); o = $Outcome; ot = (& $cut $OutcomeText 2000)
            b = (& $json $Before); af = (& $json $After); c = $(if ($CorrelationId) { [guid]"$CorrelationId" }); run = $(if ($RunId) { [guid]"$RunId" }); w = [bool]$WhatIf
        } -Query 'INSERT INTO eps.AuditEvent (Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, RunId, WhatIf) VALUES (@a, @u, @s, @t, @r, @o, @ot, @b, @af, @c, @run, @w)' | Out-Null
        $true
    } catch {
        $script:EpsAuditWriteFailures++
        Write-Warning "[audit] the audit event '$Action' by $Actor could NOT be written: $($_.Exception.Message)"
        $false
    }
}
$script:EpsAuditWriteFailures = 0
