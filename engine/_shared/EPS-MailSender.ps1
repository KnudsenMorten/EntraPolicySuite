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
    # a scope for exactly this mailbox: adopt one that exists (Exchange refuses a second scope with the same filter).
    # Exchange's REST answer can leave RecipientRestrictionFilter EMPTY (seen live 2026-10-31, on every scope), so our
    # own scope is also known by the name this plan gives it
    $scope = @($State.Scopes | Where-Object { "$($_.RecipientRestrictionFilter)".IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -ge 0 })[0]
    if (-not $scope) { $scope = @($State.Scopes | Where-Object { [string]::Equals("$($_.Name)", "$Sender-SendScope", [StringComparison]::OrdinalIgnoreCase) })[0] }
    $scopeName = if ($scope) { [string]$scope.Name } else { "$Sender-SendScope" }
    if (-not $scope) { $steps.Add([pscustomobject]@{ Cmdlet = 'New-ManagementScope'; What = "scope $scopeName -> $Sender only"; Parameters = @{ Name = $scopeName; RecipientRestrictionFilter = "PrimarySmtpAddress -eq '$Sender'" } }) }
    $assignName = "EPS-MailSend-$($AppId.Substring(0, 8))"
    $has = @($State.Assignments | Where-Object { "$($_.Role)" -eq 'Application Mail.Send' -and "$($_.CustomResourceScope)" -eq $scopeName -and ("$($_.App)" -eq $AppId -or "$($_.RoleAssignee)" -eq $AppId -or "$($_.Name)" -eq $assignName) }).Count
    if (-not $has) { $steps.Add([pscustomobject]@{ Cmdlet = 'New-ManagementRoleAssignment'; What = "'Application Mail.Send' for $AppId on $scopeName only"; Parameters = @{ App = $AppId; Role = 'Application Mail.Send'; CustomResourceScope = $scopeName; Name = $assignName } }) }
    foreach ($a in @($State.GraphMailSendAssignmentIds)) { $steps.Add([pscustomobject]@{ Cmdlet = 'Graph:RemoveMailSend'; What = "remove the TENANT-WIDE Graph Mail.Send of $AppId (it would win beside the scope)"; Parameters = @{ AssignmentId = $a } }) }
    @{ Steps = @($steps); ScopeName = $scopeName; AssignmentName = $assignName }
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
    }
}

function Invoke-EpsMailSenderPlan {
    # Applies the steps; "already exists" = done; dehydrated / not-yet-materialised = bounded retries.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)]$Plan, [int]$RetrySeconds = 60, [int]$MaxWaitSeconds = 1800)
    foreach ($s in $Plan.Steps) {
        if ($s.Cmdlet -eq 'Graph:RemoveMailSend') { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/servicePrincipals/$ObjectId/appRoleAssignments/$($s.Parameters.AssignmentId)"); continue }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            try { [void](Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $s.Cmdlet -Parameters $s.Parameters); break }
            catch {
                $m = "$_"
                if ($m -match '(?i)already exists|is already|ManagementObjectAlreadyExists') { break }
                $wait = $m -match 'InvalidOperationInDehydratedContextException' -or ($s.Cmdlet -eq 'New-ManagementRoleAssignment' -and $m -match '404|couldn''t be found|not found')
                if ($s.Cmdlet -eq 'Enable-OrganizationCustomization' -and $m -match '(?i)already') { break }
                if (-not $wait -or $sw.Elapsed.TotalSeconds -ge $MaxWaitSeconds) { throw "$($s.Cmdlet): $m" }
                Start-Sleep -Seconds $RetrySeconds
            }
        }
    }
}
