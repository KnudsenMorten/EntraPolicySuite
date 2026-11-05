#Requires -Version 7.2
<#
.SYNOPSIS
    Sets up Entra Policy Suite's Log Analytics integration (v1: EPSIntegration): the identity report's users go to the
    custom table EntraUsersMetadata_CL, and the exposure lists are read back from it with the Entra sign-in logs.
.DESCRIPTION
    In the workspace you name, it makes (or completes) what v1 used:
      - the table EntraUsersMetadata_CL with v1's columns. A table v1 already made is kept: its columns keep their
        types, only missing columns are added, nothing is removed;
      - a data collection endpoint (or the one you name) and the data collection rule dcr-entra-EntraUsersMetadata_CL;
      - for the engine's managed identity, exactly two rights: 'Monitoring Metrics Publisher' on that one rule (to send
        the rows) and 'Log Analytics Reader' on that one workspace (to read the exposure lists). No tenant-wide right.
    Every step is read back. Then it stores the target in the Entra Policy Suite database (through the database setup
    job). It does NOT switch the upload on: a SuperAdmin does that in Settings > Identity report.
    Run it again after adding a user tag type, so the table gets that column. You sign in in a browser (no module). You
    need rights to create resources and role assignments on the workspace's resource group. -WhatIf: the plan only.
.EXAMPLE
    ./Initialize-EpsLogAnalytics.ps1 -TenantId <tenant> -SubscriptionId <sub> -WorkspaceResourceId /subscriptions/<sub>/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/log-security -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Initialize-EpsLogAnalytics
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$')][string]$WorkspaceResourceId,
    [string]$DataCollectionResourceGroup = '',
    [string]$DceName = 'dce-entrapolicysuite',
    [string[]]$TagColumn = @(),
    [string]$ResourceGroup = ''
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Graph', 'EPS-Arm', 'EPS-SignIn', 'EPS-Scheduler', 'EPS-Install', 'EPS-InstallWeb', 'EPS-IdentityReport', 'EPS-LogAnalytics') { . (Join-Path $sol "engine\_shared\$f.ps1") }
$what = [bool]$WhatIfPreference; $WhatIfPreference = $false
if (-not ($global:EPS_TokenProvider -and $global:EPS_InstallPerson -and "$($global:EPS_SignInTenant)" -eq "$TenantId")) { [void](Connect-EpsSignedIn -TenantId "$TenantId") }

# the install (its engine identity) and the workspace
if (-not $ResourceGroup) { $rgPick = Resolve-EpsResourceGroup -SubscriptionId "$SubscriptionId"; if (-not $rgPick.Ok) { throw $rgPick.Reason }; $ResourceGroup = $rgPick.Name }
$names = Resolve-EpsInstallNames -TenantId "$TenantId" -SubscriptionId "$SubscriptionId" -ResourceGroup $ResourceGroup
$mi = Invoke-EpsArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($names.EngineIdentity)" -ApiVersion '2023-01-31' -AllowNotFound
if (-not $mi) { throw "no engine identity $($names.EngineIdentity) in $ResourceGroup - is Entra Policy Suite installed there?" }
$oid = [string]$mi.properties.principalId
$ws = Invoke-EpsArm -Path $WorkspaceResourceId -ApiVersion $script:EpsLaArmApi.workspace -AllowNotFound
if (-not $ws) { throw "the workspace $WorkspaceResourceId is not there (or you cannot read it)" }
$wsSub = ($WorkspaceResourceId -split '/')[2]
$dcRg = if ($DataCollectionResourceGroup) { $DataCollectionResourceGroup } else { ($WorkspaceResourceId -split '/')[4] }
$dcBase = "/subscriptions/$wsSub/resourceGroups/$dcRg/providers/Microsoft.Insights"
$dcePath = "$dcBase/dataCollectionEndpoints/$DceName"; $dcrPath = "$dcBase/dataCollectionRules/$($script:EpsLaDcrName)"
$tablePath = "$WorkspaceResourceId/tables/$($script:EpsLaTable)"

$read = {
    $tbl = Invoke-EpsArm -Path $tablePath -ApiVersion $script:EpsLaArmApi.table -AllowNotFound
    $dce = Invoke-EpsArm -Path $dcePath -ApiVersion $script:EpsLaArmApi.insights -AllowNotFound
    $dcr = Invoke-EpsArm -Path $dcrPath -ApiVersion $script:EpsLaArmApi.insights -AllowNotFound
    $as = @()
    foreach ($scope in @($dcrPath, $WorkspaceResourceId)) {
        $x = Invoke-EpsArm -Path "$scope/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$oid'" -ApiVersion $script:EpsApi.rbac -AllowNotFound
        $as += @($x.value | Where-Object { "$($_.properties.scope)" -ieq $scope } | ForEach-Object { ("$($_.properties.roleDefinitionId)" -split '/')[-1].ToLowerInvariant() })
    }
    @{ Table = $tbl; Dce = $dce; Dcr = $dcr; Assigned = @($as) }
}
# v1's columns; the user tag types beyond v1's four as -TagColumn (the column names the Identity page shows, e.g. Company or Tag_Department)
$cols = Get-EpsLaColumns -Tags @($TagColumn | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Column = $_ } })
$now = & $read
$plan = Get-EpsLaSetupPlan -Workspace $ws -Table $now.Table -Dce $now.Dce -Dcr $now.Dcr -Columns $cols -Assigned $now.Assigned -DceName $DceName
Write-Host "Log Analytics for $($names.EngineIdentity): workspace $($ws.name), rule $($script:EpsLaDcrName) in $dcRg" -ForegroundColor Cyan
if (-not $plan.Steps.Count) { Write-Host '  everything is in place' -ForegroundColor DarkGray }
foreach ($s in $plan.Steps) { Write-Host "  $($s.What)" }
if ($what) { Write-Host "`nWhatIf: nothing was changed." -ForegroundColor Cyan; return }

foreach ($s in $plan.Steps) {
    switch ($s.Kind) {
        'table' {
            $tc = @(@{ name = 'TimeGenerated'; type = 'datetime' }) + @(foreach ($k in $plan.TableColumns.Keys) { @{ name = $k; type = $plan.TableColumns[$k] } })
            [void](Invoke-EpsArm -Method PUT -Path $tablePath -ApiVersion $script:EpsLaArmApi.table -Body @{ properties = @{ schema = @{ name = $script:EpsLaTable; columns = $tc } } })
        }
        'dce' { [void](Invoke-EpsArm -Method PUT -Path $dcePath -ApiVersion $script:EpsLaArmApi.insights -Body @{ location = $ws.location; tags = @{ product = 'EntraPolicySuite' }; properties = @{ networkAcls = @{ publicNetworkAccess = 'Enabled' } } }) }
        'dcr' {
            $dceNow = Invoke-EpsArm -Path $dcePath -ApiVersion $script:EpsLaArmApi.insights
            [void](Invoke-EpsArm -Method PUT -Path $dcrPath -ApiVersion $script:EpsLaArmApi.insights -Body (New-EpsLaDcrBody -Location $ws.location -DceId "$($dceNow.id)" -WorkspaceResourceId $WorkspaceResourceId -Columns $plan.TableColumns))
        }
        'role-dcr' { Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope $dcrPath -RoleDefinitionId "/subscriptions/$wsSub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsLaRole.MetricsPublisher)" -PrincipalId $oid } }
        'role-ws' { Invoke-EpsWithRetry { Add-EpsRoleAssignment -Scope $WorkspaceResourceId -RoleDefinitionId "/subscriptions/$wsSub/providers/Microsoft.Authorization/roleDefinitions/$($script:EpsLaRole.LogAnalyticsReader)" -PrincipalId $oid } }
    }
    Write-Host "  done: $($s.What)" -ForegroundColor DarkGray
}

# read back: a step that was not read back did not happen
$after = & $read
$left = Get-EpsLaSetupPlan -Workspace $ws -Table $after.Table -Dce $after.Dce -Dcr $after.Dcr -Columns $cols -Assigned $after.Assigned -DceName $DceName
if ($left.Steps.Count) { throw "not in place after the apply: $(@($left.Steps | ForEach-Object What) -join '; ')" }
$endpoint = "$($after.Dce.properties.logsIngestion.endpoint)"; $immutable = "$($after.Dcr.properties.immutableId)"
$target = [ordered]@{ workspaceResourceId = $WorkspaceResourceId; workspaceId = "$($ws.properties.customerId)"; ingestionEndpoint = $endpoint; dcrImmutableId = $immutable; stream = $script:EpsLaStream; columns = $left.TableColumns }
$chk = Test-EpsLaTarget -Json ($target | ConvertTo-Json -Compress -Depth 6)
if (-not $chk.Ok) { throw "the target read back is not usable: $($chk.Reason)" }

# the target into the database: through the database setup job (no SQL right for you - SEC-08 row 9)
$ctx = @{ TenantId = "$TenantId"; SubscriptionId = "$SubscriptionId"; Names = $names; SolutionRoot = $sol }
$me = try { "$((Invoke-EpsGraph -Path 'v1.0/me?$select=userPrincipalName').userPrincipalName)" } catch { 'Initialize-EpsLogAnalytics' }
$r = Invoke-EpsDbInitJob -Ctx $ctx -Settings ([ordered]@{ 'IdentityReport.LogAnalytics.Target' = ($target | ConvertTo-Json -Compress -Depth 6) }) -By $me -UseExisting
Write-Host "  the target stored by the database setup job ($($r.Execution))" -ForegroundColor DarkGray
Write-Host "`nLog Analytics is set up: rows go to $($script:EpsLaTable) in $($ws.name) through $($script:EpsLaDcrName). Switch it on in Settings > Identity report > 'Send the report to Log Analytics'." -ForegroundColor Green
