#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the Entra Policy Suite engine the one right that device tagging needs: Device.ReadWrite.All. Nothing else.
.DESCRIPTION
    You sign in in a browser (no module). -WhatIf shows the plan and changes nothing. The grant is read back.
.EXAMPLE
    ./Enable-EpsDeviceTagging.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Enable-EpsDeviceTagging
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = ''
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Grant-EpsEnginePermissions.ps1') -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -GraphPermission 'Device.ReadWrite.All' -WhatIf:$WhatIfPreference
exit $LASTEXITCODE
