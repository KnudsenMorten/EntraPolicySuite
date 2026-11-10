#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the Entra Policy Suite engine the one right that writing to users needs: User.ReadWrite.All. Nothing else.
.DESCRIPTION
    For user tagging, the tamper monitor's restore and the stale account clean-up's disable action. You sign in in a
    browser (no module). -WhatIf shows the plan and changes nothing. The grant is read back.
.EXAMPLE
    ./Enable-EpsUserTagging.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Enable-EpsUserTagging
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = ''
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Grant-EpsEnginePermissions.ps1') -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -GraphPermission 'User.ReadWrite.All' -WhatIf:$WhatIfPreference
exit $LASTEXITCODE
