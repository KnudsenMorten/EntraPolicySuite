# EntraPolicySuite -- the engine identity's rights granted or taken away AFTER the install (PRM-02, framework §0.2 area
# 5/7: "a Support-app grant script exists for every right the updater may not grant itself"). Used by
# tools/setup/Grant-EpsEnginePermissions.ps1 (a person, or Invardia support through the Support app).
#   Only rights EntraPolicySuite DECLARES for its engine ($script:EpsEngineGraphRoles + the Exchange pair, EPS-Install.ps1)
#   can be asked for; every change is read back (Graph is eventually consistent); one result row per right.
# Dot-source EPS-Graph and EPS-Install first.

Set-StrictMode -Off

function Get-EpsEnginePermissionRequest {
    # PURE. What was asked, checked against the declared list. @{ Ok; Reason; Remove; Items = @(@{ Kind; What; Resource; Value }) }
    #   Kind: appRole (Resource = the API's application id, Value = the permission) | directoryRole (Value = the role template id)
    param([string[]]$GraphPermission = @(), [switch]$Exchange, [switch]$Remove)
    $asked = @($GraphPermission | ForEach-Object { "$_".Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    # SEC-02-GRAPH (2.0.99): the write rights are declared too, asked for BY NAME only (a feature that writes is on)
    $declared = @($script:EpsEngineGraphRoles) + @($script:EpsEngineGraphWriteRoles)
    $unknown = @($asked | Where-Object { $declared -cnotcontains $_ })
    if ($unknown.Count) { return @{ Ok = $false; Reason = "not a Graph permission Entra Policy Suite declares for its engine: $($unknown -join ', ') (declared: $($declared -join ', '))" } }
    if ($Remove -and -not $asked.Count -and -not $Exchange) { return @{ Ok = $false; Reason = '-Remove needs the rights to take away: -GraphPermission <name> and/or -Exchange (it never removes everything at once)' } }
    # none asked and no -Exchange: every Graph permission the engine needs (a catch-up after an install that could not grant)
    if (-not $asked.Count -and -not $Exchange) { $asked = @($script:EpsEngineGraphRoles) }
    $items = @(foreach ($p in $asked) { @{ Kind = 'appRole'; What = "Graph $p"; Resource = '00000003-0000-0000-c000-000000000000'; Value = $p } })
    if ($Exchange) {
        $items += @{ Kind = 'appRole'; What = 'Exchange Exchange.ManageAsApp'; Resource = $script:EpsExchangeAppId; Value = 'Exchange.ManageAsApp' }
        $items += @{ Kind = 'directoryRole'; What = 'Entra role Exchange Recipient Administrator'; Value = $script:EpsExchangeRecipientAdminRole }
    }
    @{ Ok = $true; Reason = ''; Remove = [bool]$Remove; Items = $items }
}

function Get-EpsUpdaterPermissionRequest {
    # PURE (PRM-02, Invardia review 2026-11-07; 2.0.99): the UPDATER identity's Graph roles - exactly the declared ones
    # ($script:EpsUpdaterGraphRoles, framework §4.5 G5, + Application.ReadWrite.OwnedBy, SECAUDIT-1a). Never
    # RoleManagement.ReadWrite.Directory (G5) or anything else. Same shape as Get-EpsEnginePermissionRequest.
    param([string[]]$GraphPermission = @(), [switch]$Remove)
    $declared = @($script:EpsUpdaterGraphRoles) + @($script:EpsUpdaterOwnerGraphRole)
    $asked = @($GraphPermission | ForEach-Object { "$_".Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $unknown = @($asked | Where-Object { $declared -cnotcontains $_ })
    if ($unknown.Count) { return @{ Ok = $false; Reason = "not a Graph permission Entra Policy Suite declares for its updater: $($unknown -join ', ') (declared: $($declared -join ', '))" } }
    if ($Remove -and -not $asked.Count) { return @{ Ok = $false; Reason = '-Remove needs the rights to take away: -GraphPermission <name> (it never removes everything at once)' } }
    if (-not $asked.Count) { $asked = $declared }
    @{ Ok = $true; Reason = ''; Remove = [bool]$Remove; Items = @(foreach ($p in $asked) { @{ Kind = 'appRole'; What = "Graph $p"; Resource = '00000003-0000-0000-c000-000000000000'; Value = $p } }) }
}

function Invoke-EpsEnginePermissionPlan {
    # One row per right: @{ What; Status; Reason }. Status: already there | granted | not there | removed | would grant |
    # would remove | refused. -PlanOnly reads only. Never throws for one right: the next is still tried.
    param([Parameter(Mandatory)][string]$EngineObjectId, [Parameter(Mandatory)]$Request, [switch]$PlanOnly, [int]$ReadBackSeconds = 15)
    $rows = [System.Collections.Generic.List[object]]::new()
    $sps = @{}
    foreach ($it in $Request.Items) {
        try {
            if ($it.Kind -eq 'appRole') {
                if (-not $sps.ContainsKey($it.Resource)) { $sps[$it.Resource] = @(Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=appId eq '$($it.Resource)'&`$select=id,appRoles" -All)[0] }
                $sp = $sps[$it.Resource]
                if (-not $sp) { $rows.Add(@{ What = $it.What; Status = 'refused'; Reason = "the tenant has no service principal for $($it.Resource)" }); continue }
                $role = @($sp.appRoles | Where-Object { "$($_.value)" -ceq $it.Value })[0]
                if (-not $role) { $rows.Add(@{ What = $it.What; Status = 'refused'; Reason = 'the permission does not exist on that API' }); continue }
                $find = { @(Invoke-EpsGraph -Path "v1.0/servicePrincipals/$EngineObjectId/appRoleAssignments" -All | Where-Object { "$($_.resourceId)" -eq "$($sp.id)" -and "$($_.appRoleId)" -eq "$($role.id)" }) }
                $have = & $find
                if ($Request.Remove) {
                    if (-not $have.Count) { $rows.Add(@{ What = $it.What; Status = 'not there' }); continue }
                    if ($PlanOnly) { $rows.Add(@{ What = $it.What; Status = 'would remove' }); continue }
                    foreach ($a in $have) { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/servicePrincipals/$EngineObjectId/appRoleAssignments/$($a.id)") }
                } else {
                    if ($have.Count) { $rows.Add(@{ What = $it.What; Status = 'already there' }); continue }
                    if ($PlanOnly) { $rows.Add(@{ What = $it.What; Status = 'would grant' }); continue }
                    try { [void](Invoke-EpsGraph -Method POST -Path "v1.0/servicePrincipals/$EngineObjectId/appRoleAssignments" -Body @{ principalId = $EngineObjectId; resourceId = $sp.id; appRoleId = $role.id }) }
                    catch { if ("$_" -notmatch '(?i)already exists') { throw } }
                }
            } else {
                $find = { @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$EngineObjectId' and roleDefinitionId eq '$($it.Value)'" -All) }
                $have = & $find
                if ($Request.Remove) {
                    if (-not $have.Count) { $rows.Add(@{ What = $it.What; Status = 'not there' }); continue }
                    if ($PlanOnly) { $rows.Add(@{ What = $it.What; Status = 'would remove' }); continue }
                    foreach ($a in $have) { [void](Invoke-EpsGraph -Method DELETE -Path "v1.0/roleManagement/directory/roleAssignments/$($a.id)") }
                } else {
                    if ($have.Count) { $rows.Add(@{ What = $it.What; Status = 'already there' }); continue }
                    if ($PlanOnly) { $rows.Add(@{ What = $it.What; Status = 'would grant' }); continue }
                    [void](Invoke-EpsGraph -Method POST -Path 'v1.0/roleManagement/directory/roleAssignments' -Body @{ principalId = $EngineObjectId; roleDefinitionId = $it.Value; directoryScopeId = '/' })
                }
            }
            # read back (a control that was not read back is not a control); Graph lags - poll
            $ok = $false
            for ($i = 0; $i -lt 9; $i++) {
                $now = & $find
                if (($Request.Remove -and -not $now.Count) -or (-not $Request.Remove -and $now.Count)) { $ok = $true; break }
                Start-Sleep -Seconds $ReadBackSeconds
            }
            $rows.Add($(if ($ok) { @{ What = $it.What; Status = $(if ($Request.Remove) { 'removed' } else { 'granted' }) } } else { @{ What = $it.What; Status = 'refused'; Reason = 'not read back after the change' } }))
        } catch {
            $m = "$($_.Exception.Message)"
            $why = if ($m -match '-> 403') { 'your account may not do this (Privileged Role Administrator or Global Administrator needed)' } else { $m }
            $rows.Add(@{ What = $it.What; Status = 'refused'; Reason = $why })
        }
    }
    $rows.ToArray()
}
