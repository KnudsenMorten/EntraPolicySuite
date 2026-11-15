# EntraPolicySuite -- the engine's Exchange right, least privilege (2.1.39; review G point 4, Invardia 2026-11-15: "scope
# the Exchange role down ... least privilege wins"). The engine runs exactly three Exchange cmdlets app-only over the
# admin API (EPS-Exchange's InvokeCommand): Get-Recipient (read the recipients) and Set-Mailbox / Set-MailUser with
# -CustomAttribute1..15 (write a tag). Instead of the Entra role Exchange Recipient Administrator at "/" (every recipient
# setting org-wide, forwarding included), the engine's service principal is a member of ONE Exchange role group holding
# ONE custom management role 'EPS Tag Writer': the parent 'Mail Recipients' pared to Get-Recipient + Set-Mailbox +
# Set-MailUser, and the two Set cmdlets pared to -Identity + -CustomAttribute1..15. The Microsoft way for app-only admin
# cmdlets (custom role groups for a service principal). Made by an Exchange administrator (Organization Management),
# over REST, no module (Initialize-EpsExchangeTagRole.ps1). The Entra role is removed only in a SECOND, explicit step,
# after the engine's tag write was proven through the role group. The plan is pure and tested offline.

Set-StrictMode -Off
$script:EpsTagRole = @{
    Name      = 'EPS Tag Writer'
    Group     = 'EPS Tag Writers'
    Parent    = 'Mail Recipients'
    Keep      = @('Get-Recipient', 'Set-Mailbox', 'Set-MailUser')
    SetParams = @(@('Identity') + @(1..15 | ForEach-Object { "CustomAttribute$_" }))
    # the PowerShell common parameters a role entry carries; kept so the cmdlet can run at all
    Common    = @('Confirm', 'Debug', 'DomainController', 'ErrorAction', 'ErrorVariable', 'OutBuffer', 'OutVariable', 'Verbose', 'WarningAction', 'WarningVariable', 'WhatIf', 'InformationAction', 'InformationVariable', 'PipelineVariable')
}

function Get-EpsTagRolePlan {
    <#
      PURE. -State @{ Dehydrated; ServicePrincipals = @(@{ AppId }); Role (or $null); Entries = @(@{ Name; Parameters }); Groups = @(@{ Name; Roles; Members }) }
      -> @{ Steps = @([pscustomobject]@{ Cmdlet; What; Parameters }) }. Idempotent: a complete state gives no step.
    #>
    param([Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$ObjectId, [string]$DisplayName = 'id-eps-engine', [Parameter(Mandatory)]$State)
    $r = $script:EpsTagRole; $steps = [System.Collections.Generic.List[object]]::new()
    $add = { param($c, $w, $p) $steps.Add([pscustomobject]@{ Cmdlet = $c; What = $w; Parameters = $p }) }
    if ($State.Dehydrated) { & $add 'Enable-OrganizationCustomization' 'enable organization customization (a fresh Exchange organization refuses custom roles until then)' @{} }
    if (-not @($State.ServicePrincipals | Where-Object { "$($_.AppId)" -eq $AppId }).Count) { & $add 'New-ServicePrincipal' "register the engine identity $AppId in Exchange" @{ AppId = $AppId; ObjectId = $ObjectId; DisplayName = $DisplayName } }
    if (-not $State.Role) {
        & $add 'New-ManagementRole' "create the role '$($r.Name)' from '$($r.Parent)'" @{ Name = $r.Name; Parent = $r.Parent }
        # a new role copies every entry of its parent - all but the three are removed, the two Set cmdlets pared; the
        # entries are known only once the role exists, so the plan is made again after this step (Invoke-EpsTagRolePlan)
        return @{ Steps = @($steps); Again = $true }
    }
    foreach ($e in @($State.Entries)) {
        $nm = "$($e.Name)"
        if ($r.Keep -notcontains $nm) { & $add 'Remove-ManagementRoleEntry' "remove '$nm' from the role" @{ Identity = "$($r.Name)\$nm"; Confirm = $false }; continue }
        if ($nm -like 'Set-*') {
            $extra = @(@($e.Parameters) | Where-Object { $_ -and $r.SetParams -notcontains $_ -and $r.Common -notcontains $_ })
            if ($extra.Count) { & $add 'Set-ManagementRoleEntry' "limit '$nm' to -Identity and -CustomAttribute1..15 ($($extra.Count) parameter(s) removed)" @{ Identity = "$($r.Name)\$nm"; Parameters = @($extra); RemoveParameter = $true; Confirm = $false } }
        }
    }
    foreach ($k in $r.Keep) { if (-not @($State.Entries | Where-Object { "$($_.Name)" -eq $k }).Count) { throw "the role '$($r.Name)' has no '$k' entry - its parent '$($r.Parent)' does not carry it here; nothing more is changed" } }
    $g = @($State.Groups | Where-Object { "$($_.Name)" -eq $r.Group })[0]
    if (-not $g) { & $add 'New-RoleGroup' "create the role group '$($r.Group)' with the role '$($r.Name)'" @{ Name = $r.Group; Roles = @($r.Name); Description = 'Entra Policy Suite: the engine writes the tag attributes (CustomAttribute1-15) and reads recipients - nothing else.' } }
    elseif (@($g.Roles) -notcontains $r.Name) { throw "a role group '$($r.Group)' exists without the role '$($r.Name)' - not made by Entra Policy Suite; nothing is changed" }
    if (-not $g -or -not @(@($g.Members) | Where-Object { "$_" -in $ObjectId, $AppId, $DisplayName }).Count) { & $add 'Add-RoleGroupMember' "make the engine identity a member of '$($r.Group)'" @{ Identity = $r.Group; Member = $ObjectId } }
    @{ Steps = @($steps); Again = $false }
}

function Get-EpsTagRoleState {
    # READ-ONLY: what Exchange says (an Exchange administrator's token)
    param([Parameter(Mandatory)][string]$TenantId)
    $r = $script:EpsTagRole
    $exo = { param($c, $p = @{}) try { @(Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $c -Parameters $p -All) } catch { if ("$_" -match '404|couldn''t be found|was not found') { @() } else { throw } } }
    $oc = @(& $exo 'Get-OrganizationConfig')[0]
    $role = @(& $exo 'Get-ManagementRole' @{ Identity = $r.Name })[0]
    @{
        Dehydrated = "$($oc.IsDehydrated)" -eq 'True'
        ServicePrincipals = @(& $exo 'Get-ServicePrincipal')
        Role = $role
        Entries = $(if ($role) { @(& $exo 'Get-ManagementRoleEntry' @{ Identity = "$($r.Name)\*" } | ForEach-Object { @{ Name = "$($_.Name)"; Parameters = @($_.Parameters) } }) } else { @() })
        Groups = @(& $exo 'Get-RoleGroup' @{ Identity = $r.Group } | ForEach-Object { @{ Name = "$($_.Name)"; Roles = @($_.Roles | ForEach-Object { "$_" -replace '^.*\\', '' }); Members = @($_.Members) } })
    }
}

function Invoke-EpsTagRolePlan {
    # applies the plan until nothing is left (a new role is planned again once its entries exist); "already exists" =
    # done; the dehydrated / not-yet-materialised answers = bounded retries (as the mail sender)
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$ObjectId, [string]$DisplayName = 'id-eps-engine', [int]$RetrySeconds = 60, [int]$MaxWaitSeconds = 1800, [int]$Rounds = 4)
    $done = [System.Collections.Generic.List[string]]::new()
    for ($k = 0; $k -lt $Rounds; $k++) {
        $plan = Get-EpsTagRolePlan -AppId $AppId -ObjectId $ObjectId -DisplayName $DisplayName -State (Get-EpsTagRoleState -TenantId $TenantId)
        if (-not $plan.Steps.Count) { return @($done) }
        foreach ($s in $plan.Steps) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                try { [void](Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $s.Cmdlet -Parameters $s.Parameters); $done.Add($s.What); break }
                catch {
                    $m = "$_"
                    if ($m -match '(?i)already exists|is already|ManagementObjectAlreadyExists|already a member') { break }
                    $wait = $m -match 'InvalidOperationInDehydratedContextException' -or ($s.Cmdlet -in 'Add-RoleGroupMember', 'New-RoleGroup' -and $m -match '404|couldn''t be found|not found')
                    if (-not $wait -or $sw.Elapsed.TotalSeconds -ge $MaxWaitSeconds) { throw "$($s.Cmdlet): $m" }
                    Start-Sleep -Seconds $RetrySeconds
                }
            }
        }
    }
    $left = Get-EpsTagRolePlan -AppId $AppId -ObjectId $ObjectId -DisplayName $DisplayName -State (Get-EpsTagRoleState -TenantId $TenantId)
    if ($left.Steps.Count) { throw "not in place after $Rounds rounds: $(@($left.Steps | ForEach-Object What) -join '; ')" }
    @($done)
}
