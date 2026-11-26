# EntraPolicySuite -- the mail sender (framework MAIL-1): a shared mailbox (no licence) and the right of the engine's
# managed identity to send AS IT ONLY - Exchange RBAC for applications, 'Application Mail.Send' on a management scope
# that matches exactly that mailbox. A tenant-wide Graph Mail.Send grant on the identity is REMOVED: it is not
# restricted by the scope, it wins beside it (measured by PIM on a test tenant). Exchange over REST, no module
# (EPS-Exchange's InvokeCommand). PIM's sequence and traps (Initialize-PimMailSender.ps1):
#   * a fresh Exchange organization is "dehydrated" and refuses custom RBAC until Enable-OrganizationCustomization -
#     and its IsDehydrated flag is NOT a readiness signal: retry the real create
#   * New-ManagementRoleAssignment right after New-ServicePrincipal can answer 404 until Exchange has it - retry
#   * "already exists" on a create = done (an idempotent re-run)
# The plan is pure (the read Exchange state in, steps out) and tested offline.

Set-StrictMode -Off

function Get-EpsMailSenderPlan {
    <#
    .SYNOPSIS
        The steps to make -Sender a scoped sender for the identity. -State is what Exchange and Graph said:
        @{ Mailbox (or $null); Dehydrated; ServicePrincipals = @(@{ AppId }); Scopes = @(@{ Name; RecipientRestrictionFilter });
           Assignments = @(@{ Name; Role; CustomResourceScope; App/RoleAssignee }); GraphMailSendAssignmentIds = @() }
    #>
    param([Parameter(Mandatory)][string]$Sender, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$ObjectId, [string]$DisplayName = 'id-eps-engine',
          [Parameter(Mandatory)]$State)
    if ($Sender -notmatch "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$") { throw "-Sender '$Sender' is not a mail address" }
    $steps = [System.Collections.Generic.List[object]]::new()
    if (-not $State.Mailbox) {
        $alias = ($Sender -split '@')[0]
        $steps.Add([pscustomobject]@{ Cmdlet = 'New-Mailbox'; What = "create the shared mailbox $Sender (no licence)"; Parameters = @{ Shared = $true; Name = $alias; DisplayName = 'Entra Policy Suite'; Alias = $alias; PrimarySmtpAddress = $Sender } })
    }
    if ($State.Dehydrated) { $steps.Add([pscustomobject]@{ Cmdlet = 'Enable-OrganizationCustomization'; What = 'enable organization customization (a fresh Exchange organization refuses custom RBAC until then)'; Parameters = @{} }) }
    if (-not @($State.ServicePrincipals | Where-Object { "$($_.AppId)" -eq $AppId }).Count) {
        $steps.Add([pscustomobject]@{ Cmdlet = 'New-ServicePrincipal'; What = "register the engine identity $AppId in Exchange"; Parameters = @{ AppId = $AppId; ObjectId = $ObjectId; DisplayName = $DisplayName } })
    }
    # ONE-SENDER-1 B (framework, 2026-11-25; PIM's names): the scope and the assignment are named PER MAILBOX - the scope
    # '<mailbox name>-SendScope', the assignment '<mailbox name>-<identity objectId 8>-MailSend' - so a NEW sender's right
    # is created BESIDE the old one (assignment names are tenant-unique: one fixed name could never move to a new mailbox).
    # A scope for exactly this mailbox is ADOPTED (Exchange refuses a second scope with the same filter), under any name -
    # also an older install's '<address>-SendScope'. Exchange's REST answer can leave RecipientRestrictionFilter EMPTY
    # (seen live 2026-10-31, on every scope), so a scope is also known by the names this plan gives it.
    $part = ConvertTo-EpsExoNamePart (($Sender -split '@')[0])
    $defaultScope = "$part-SendScope"
    $names = @($defaultScope, "$Sender-SendScope")
    $scope = @($State.Scopes | Where-Object { "$($_.RecipientRestrictionFilter)".IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -ge 0 })[0]
    if (-not $scope) { $scope = @($State.Scopes | Where-Object { $n = "$($_.Name)"; @($names | Where-Object { [string]::Equals($n, $_, [StringComparison]::OrdinalIgnoreCase) }).Count })[0] }
    # a scope with our name that names ANOTHER mailbox is never reused and never rewritten (PIM §94: attaching to it
    # would let this sender send only as the other mailbox; rewriting it would cut the other one off)
    if ($scope) {
        $f = "$($scope.RecipientRestrictionFilter)"
        if ($f.Trim() -and $f.IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw "the Exchange scope '$($scope.Name)' already exists for ANOTHER mailbox ($f), not $Sender - refused: it is neither reused nor rewritten. Use a sender mailbox with another name." }
    }
    $scopeName = if ($scope) { [string]$scope.Name } else { $defaultScope }
    if (-not $scope) { $steps.Add([pscustomobject]@{ Cmdlet = 'New-ManagementScope'; What = "scope $scopeName -> $Sender only"; Parameters = @{ Name = $scopeName; RecipientRestrictionFilter = "PrimarySmtpAddress -eq '$Sender'" } }) }
    $short = $ObjectId.Substring(0, [math]::Min(8, $ObjectId.Length))
    $assignName = "$part-$short-MailSend"
    $legacy = "EPS-MailSend-$($AppId.Substring(0, [math]::Min(8, $AppId.Length)))"   # before 2.1.72: one fixed name for every mailbox
    $mine = { param($a) "$($a.Role)" -eq 'Application Mail.Send' -and ("$($a.App)" -eq $AppId -or "$($a.RoleAssignee)" -eq $AppId -or "$($a.RoleAssignee)" -eq $ObjectId -or ("$($a.Name)" -in @($assignName, $legacy)) -or "$($a.Name)" -like "*-$short-MailSend") }
    $ours = @($State.Assignments | Where-Object { "$($_.Role)" -eq 'Application Mail.Send' } | Where-Object { & $mine $_ })
    $has = @($ours | Where-Object { "$($_.CustomResourceScope)" -eq $scopeName }).Count
    if (-not $has) { $steps.Add([pscustomobject]@{ Cmdlet = 'New-ManagementRoleAssignment'; What = "'Application Mail.Send' for $AppId on $scopeName only"; Parameters = @{ App = $AppId; Role = 'Application Mail.Send'; CustomResourceScope = $scopeName; Name = $assignName } }) }
    foreach ($a in @($State.GraphMailSendAssignmentIds)) { $steps.Add([pscustomobject]@{ Cmdlet = 'Graph:RemoveMailSend'; What = "remove the TENANT-WIDE Graph Mail.Send of $AppId (it would win beside the scope)"; Parameters = @{ AssignmentId = $a } }) }
    # ONE-SENDER-1 C: the identity's send right on ANOTHER scope = the previous sender. It is removed only AFTER the new one
    # reads back (Cleanup - Initialize-EpsMailSender runs it then), and only when that scope's filter was READ and names
    # another mailbox (an unread filter may be this sender's own scope under an older name: never removed on a guess).
    # The old scope goes too when no other assignment is on it.
    $cleanup = [System.Collections.Generic.List[object]]::new(); $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($a in @($ours | Where-Object { "$($_.CustomResourceScope)" -ne $scopeName })) {
        $sn = "$($a.CustomResourceScope)"
        $sc = @($State.Scopes | Where-Object { "$($_.Name)" -eq $sn })[0]
        $f = "$(if ($sc) { $sc.RecipientRestrictionFilter })"
        if ($f.Trim() -and $f.IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -ge 0) { $kept.Add("$($a.Name) on $sn (its filter names $Sender)"); continue }
        if (-not $f.Trim()) {
            # Exchange's REST answer left the filter EMPTY (internal 2026-11-26: on every scope). A scope under one of OUR
            # OWN names is still known: '<address>-SendScope' (before 2.1.72) or '<mailbox name>-SendScope' - when that
            # name points at ANOTHER mailbox than the sender, it is the previous sender's; any other name is kept
            $addr = if ($sn -match '^(.+@.+)-SendScope$') { $Matches[1] } else { '' }
            $other = if ($addr) { -not [string]::Equals($addr, $Sender, [StringComparison]::OrdinalIgnoreCase) } elseif ($sn -match '^(.+)-SendScope$') { -not [string]::Equals($Matches[1], $part, [StringComparison]::OrdinalIgnoreCase) } else { $false }
            if (-not $other) { $kept.Add("$($a.Name) on $sn (its filter could not be read)"); continue }
            $f = "(not returned by Exchange; by our own name: $(if ($addr) { $addr } else { 'another mailbox' }))"
        }
        $idn = if ("$($a.Identity)".Trim()) { "$($a.Identity)".Trim() } else { "$($a.Name)".Trim() }
        $cleanup.Add([pscustomobject]@{ Cmdlet = 'Remove-ManagementRoleAssignment'; What = "remove the previous sender's right $idn (scope $($a.CustomResourceScope): $f)"; Parameters = @{ Identity = $idn; Confirm = $false } })
        $others = @($State.Assignments | Where-Object { "$($_.CustomResourceScope)" -eq "$($a.CustomResourceScope)" -and "$($_.Name)" -ne "$($a.Name)" })
        if (-not $others.Count -and "$($a.CustomResourceScope)" -like '*-SendScope' -and -not @($cleanup | Where-Object { $_.Cmdlet -eq 'Remove-ManagementScope' -and $_.Parameters.Identity -eq "$($a.CustomResourceScope)" }).Count) {
            $cleanup.Add([pscustomobject]@{ Cmdlet = 'Remove-ManagementScope'; What = "remove the previous sender's scope $($a.CustomResourceScope) (nothing else is on it)"; Parameters = @{ Identity = "$($a.CustomResourceScope)"; Confirm = $false } })
        }
    }
    # EPS full review 2026-11-26 (tools-pro reviewers 1 #2 / 2 #1, HIGH): a tenant-wide Graph Mail.Send is removed in the
    # first steps (the engine's probe can only prove the restriction once it is gone), but a put-back never restored it, so
    # an install that sent through it lost mail. The put-back now adds it again (PutBack: Graph:AddMailSend).
    $putBack = @(if (@($State.GraphMailSendAssignmentIds).Count -and $State.GraphSpId -and $State.MailSendRoleId) { [pscustomobject]@{ Cmdlet = 'Graph:AddMailSend'; What = "give back the tenant-wide Graph Mail.Send of $AppId it had (the change did not work)"; Parameters = @{ ResourceId = "$($State.GraphSpId)"; AppRoleId = "$($State.MailSendRoleId)" } } })
    @{ Steps = @($steps); ScopeName = $scopeName; AssignmentName = $assignName; Cleanup = @($cleanup); Kept = @($kept); NewScope = (-not $scope); PutBack = @($putBack) }
}

function ConvertTo-EpsExoNamePart {
    # PURE. A mailbox's local part as an Exchange object name: letters, digits, '.', '_' and '-' only (PIM's rule)
    param([string]$Value)
    $v = ("$Value" -replace '[^A-Za-z0-9._-]', '-').Trim('-', '.')
    if (-not $v) { $v = 'EPS-Sender' }
    if ($v.Length -gt 40) { $v = $v.Substring(0, 40) }
    $v
}

function Get-EpsMailSenderAuthVerdict {
    <#
      PURE. ONE-SENDER-1 C, the read-back of a sender change (Exchange's own test: Test-ServicePrincipalAuthorization rows
      @{ RoleName; InScope }): 'verified' = in scope for the sender AND (when a probe mailbox is given) out of scope for it;
      'pending' = not in scope yet (Exchange takes up to 2 hours); 'unrestricted' = in scope for the probe mailbox too.
    #>
    param([object[]]$SenderRows = @(), [object[]]$ProbeRows = @(), [bool]$HasProbe)
    $in = { param($rows) [bool]@($rows | Where-Object { "$($_.RoleName)" -eq 'Application Mail.Send' -and "$($_.InScope)" -eq 'True' }).Count }
    if (-not (& $in $SenderRows)) { return 'pending' }
    if ($HasProbe -and (& $in $ProbeRows)) { return 'unrestricted' }
    'verified'
}

function Invoke-EpsEngineMailProbe {
    <#
      ONE-SENDER-1 C (framework, 2026-11-26, after internal's E proof at 05:41Z: Exchange's test said "in scope" while the
      engine's real send was still refused 403): the switch is DONE only when the ENGINE ITSELF may send as the new sender.
      Starts ONE execution of the engine's job (its own managed identity) with EPS_JOB = MailProbe and the candidate sender:
      sendMail with no recipient (nothing is delivered) - allowed as the sender, denied as the probe mailbox. Reads only.
      Returns @{ Verdict = verified | pending; Status; Execution; Reason }.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Sender, [string]$Probe, [int]$TimeoutSeconds = 600)
    $n = $Ctx.Names
    $s = Start-EpsAcaJob -SubscriptionId $Ctx.SubscriptionId -ResourceGroup $n.ResourceGroup -Name $n.TickJob -Env @{ EPS_JOB = 'MailProbe'; EPS_MAIL_PROBE_SENDER = $Sender; EPS_MAIL_PROBE_MAILBOX = "$Probe" }
    if (-not $s.Ok) { return @{ Verdict = 'pending'; Status = 'NotStarted'; Execution = ''; Reason = "the engine's probe could not be started: $($s.Reason)" } }
    $w = Wait-EpsAcaJobExecution -Ctx $Ctx -Job $n.TickJob -Execution $s.Execution -TimeoutSeconds $TimeoutSeconds -PollSeconds 15
    @{ Verdict = $(if ($w.Status -eq 'Succeeded') { 'verified' } else { 'pending' }); Status = $w.Status; Execution = $s.Execution
       Reason = $(if ($w.Status -eq 'Succeeded') { '' } else { "the engine may not send as $Sender yet ($($s.Execution): $($w.Status))" }) }
}

function Test-EpsMailSenderAuthorization {
    # READ-ONLY: Exchange's own answer whether the identity may send as -Sender (and may NOT as -Probe). Returns the verdict
    # and the rows. A cmdlet error = 'pending' with its text (Exchange may not know the service principal yet).
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$Sender, [string]$Probe)
    $t = { param($res) @(Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet 'Test-ServicePrincipalAuthorization' -Parameters @{ Identity = $AppId; Resource = $res } -All) }
    try {
        $s = & $t $Sender
        $p = if ($Probe -and $Probe -ne $Sender) { & $t $Probe } else { @() }
        @{ Verdict = (Get-EpsMailSenderAuthVerdict -SenderRows $s -ProbeRows $p -HasProbe ([bool]($Probe -and $Probe -ne $Sender))); Text = '' }
    } catch { @{ Verdict = 'pending'; Text = "$($_.Exception.Message)" } }
}

function Get-EpsMailSenderState {
    # READ-ONLY: what Exchange and Graph say for the sender and the identity
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Sender, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$ObjectId)
    $exo = { param($c, $p = @{}) try { @(Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $c -Parameters $p -All) } catch { if ("$_" -match '404|couldn''t be found') { @() } else { throw } } }
    $graphSp = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -All)[0]
    $mailSend = @($graphSp.appRoles | Where-Object { $_.value -eq 'Mail.Send' })[0].id
    $mine = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$ObjectId/appRoleAssignments" -All | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $mailSend })
    $oc = @(& $exo 'Get-OrganizationConfig')[0]
    @{
        Mailbox = @(& $exo 'Get-Mailbox' @{ Identity = $Sender })[0]
        Dehydrated = "$($oc.IsDehydrated)" -eq 'True'
        ServicePrincipals = @(& $exo 'Get-ServicePrincipal')
        Scopes = @(& $exo 'Get-ManagementScope')
        Assignments = @(& $exo 'Get-ManagementRoleAssignment' @{ Role = 'Application Mail.Send' })
        GraphMailSendAssignmentIds = @($mine | ForEach-Object { [string]$_.id })
        GraphSpId = "$($graphSp.id)"; MailSendRoleId = "$mailSend"   # to give a removed tenant-wide Mail.Send back on a put-back
    }
}

function Invoke-EpsMailSenderPlan {
    # Applies the steps; "already exists" = done; dehydrated / not-yet-materialised = bounded retries.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)]$Plan, [int]$RetrySeconds = 60, [int]$MaxWaitSeconds = 1800)
    foreach ($s in $Plan.Steps) {
        if ($s.Cmdlet -eq 'Graph:RemoveMailSend') { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/servicePrincipals/$ObjectId/appRoleAssignments/$($s.Parameters.AssignmentId)"); continue }
        if ($s.Cmdlet -eq 'Graph:AddMailSend') { [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$ObjectId/appRoleAssignments" -Body @{ principalId = $ObjectId; resourceId = $s.Parameters.ResourceId; appRoleId = $s.Parameters.AppRoleId }); continue }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            try { [void](Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $s.Cmdlet -Parameters $s.Parameters); break }
            catch {
                $m = "$_"
                if ($m -match '(?i)already exists|is already|ManagementObjectAlreadyExists') { break }
                if ($s.Cmdlet -like 'Remove-*' -and $m -match '(?i)couldn''t be found|not found|404|ManagementObjectNotFound') { break }   # gone already = done
                # internal 2026-11-26 05:33Z (the E proof): the old scope's removal right after its assignment's removal
                # was refused "currently in use by one or more management role assignments" - Exchange's lag; asked again
                $wait = $m -match 'InvalidOperationInDehydratedContextException' -or ($s.Cmdlet -eq 'New-ManagementRoleAssignment' -and $m -match '404|couldn''t be found|not found') -or
                        ($s.Cmdlet -eq 'Remove-ManagementScope' -and $m -match '(?i)currently in use by one or more management role assignments')
                if ($s.Cmdlet -eq 'Enable-OrganizationCustomization' -and $m -match '(?i)already') { break }
                if (-not $wait -or $sw.Elapsed.TotalSeconds -ge $MaxWaitSeconds) { throw "$($s.Cmdlet): $m" }
                Start-Sleep -Seconds $RetrySeconds
            }
        }
    }
}
