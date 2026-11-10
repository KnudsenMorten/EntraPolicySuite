#Requires -Version 7.2
<#
.SYNOPSIS
    Gives the Entra Policy Suite engine the Exchange rights: Exchange.ManageAsApp and the Exchange Recipient Administrator role. Nothing else.
.DESCRIPTION
    For mailbox tags and mailbox types. You sign in in a browser (no module). -WhatIf shows the plan and changes nothing.
    The grant is read back.
.EXAMPLE
    ./Enable-EpsExchangeAccess.ps1 -TenantId <tenant> -SubscriptionId <sub> -WhatIf
.LINK
    https://invardia.com/docs/eps/scripts/Enable-EpsExchangeAccess
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [string]$ResourceGroup = ''
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Grant-EpsEnginePermissions.ps1') -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Exchange -WhatIf:$WhatIfPreference
exit $LASTEXITCODE
