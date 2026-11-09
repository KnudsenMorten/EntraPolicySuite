#Requires -Version 7.2
<#
.SYNOPSIS
    Delegates the Entra Policy Suite hybrid worker in Active Directory: the right to write EXACTLY the tag attributes
    you choose on user (and, for device tags, computer) objects - nothing else (DESIGN §6). Run once by a domain admin on
    a domain machine.
.DESCRIPTION
    The same way for every hybrid worker (framework HYBRID-AD-1):
    - every right goes to the group "<gMSA>-PermissionGroup" (the gMSA its ONLY member) - never to the gMSA itself; the
      group is made in the gMSA's own container when it is missing;
    - at the DOMAIN ROOT, inherited by descendant objects of the classes you name (users are spread over many OUs): one
      Allow ACE per attribute and class, WriteProperty on that attribute;
    - only the attributes you list (extensionAttribute1-15 - your tag attributes; anything else is refused);
    - protected accounts (Domain Admins and the like) only with -IncludeProtectedAccounts: the same right on AdminSDHolder.
    Plan first: without -Apply it shows every step and changes nothing. With -Apply it makes the changes and reads them back.
    -Remove takes exactly these rights away again (the group stays). No module: .NET System.DirectoryServices.
    The gMSA itself (and its <gMSA>-PrincipalsAllowedAccess group, the worker computers that may use it) is made
    beforehand by your AD admin; this script finds it by name.
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -Gmsa 'gMSA-EPS-L1-T0' -Attributes extensionAttribute6, extensionAttribute7
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -Gmsa 'gMSA-EPS-L1-T0' -Attributes extensionAttribute6, extensionAttribute7 -ObjectClasses user, computer -Apply
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -Gmsa 'gMSA-EPS-L1-T0' -Attributes extensionAttribute6 -IncludeProtectedAccounts -Apply
    Also protected admins: the same right on AdminSDHolder - a Tier 0 decision.
.LINK
    https://invardia.com/docs/eps/scripts/Initialize-EpsHybridWorkerAd
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # the worker's gMSA (name, or DOMAIN\name$)
    [Parameter(Mandatory)][ValidatePattern('^([A-Za-z0-9._-]{1,15}\\)?[A-Za-z0-9._-]{1,15}\$?$')][string]$Gmsa,
    # YOUR tag attributes - customer-specific, no default (owner 2026-11-09: "extensions are individual per customer")
    [Parameter(Mandatory)][ValidatePattern('^extensionAttribute([1-9]|1[0-5])$')][string[]]$Attributes,
    # user objects (user tags); add computer for device tags
    [ValidateSet('user', 'computer')][string[]]$ObjectClasses = @('user'),
    # the shared parameter of HYBRID-AD-1 for objects a product OWNS - Entra Policy Suite owns no AD objects, so it is not used
    [string]$ProductOu,
    [string]$Server,
    # owner 2026-10-30 "New gMSA + protected admins": the same narrow right on AdminSDHolder, so protected admins (Domain
    # Admins and the like, who do not inherit domain rights) are tagged too - this makes the worker Tier 0 sensitive
    [switch]$IncludeProtectedAccounts,
    [switch]$Apply,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://github.com/KnudsenMorten/EntraPolicySuite#readme'   # invardia.com/docs/eps/scripts/Initialize-EpsHybridWorkerAd when EPS is public there (DOC-LINKS)
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\EPS-AdDelegation.ps1')
$write = $Apply -and -not $WhatIfPreference
$WhatIfPreference = $false
if ("$ProductOu".Trim()) { Write-Host '-ProductOu is not used: Entra Policy Suite owns no AD objects (it writes tag attributes on your users and computers only).' -ForegroundColor DarkGray }
$dir = New-EpsAdDelegationDirectory -Server $Server
$holder = if ($IncludeProtectedAccounts) { $dir.GetAdminSdHolderDn() }
if ($holder) { Write-Host "Protected accounts: the right also goes on $holder - AD copies it onto every protected account (Domain Admins and the like) within about 60 minutes. The worker can then change an ADMIN's tags, and with them his Conditional Access policies: treat it as a Tier 0 account." -ForegroundColor Yellow }
$args1 = @{ Directory = $dir; Gmsa = $Gmsa; Attributes = $Attributes; ObjectClasses = $ObjectClasses; Remove = $Remove; ProtectedHolderDn = $holder }
$plan = @(Get-EpsAdDelegationPlan @args1)
Write-Host "Rights to: $(Get-EpsAdPermissionGroupName -Gmsa $Gmsa) (the gMSA its only member), at $($dir.NamingContext())" -ForegroundColor Cyan
foreach ($p in $plan) { Write-Host ("  {0,-11} {1,-20} {2,-9} on {3}" -f $p.Action, $p.Attribute, $p.ObjectClass, $p.OU) -ForegroundColor $(if ($p.Action -in 'add', 'remove', 'creategroup', 'addmember') { 'Yellow' } else { 'DarkGray' }) }
$todo = @($plan | Where-Object { $_.Action -in 'add', 'remove', 'creategroup', 'addmember' })
if (-not $write) { Write-Host "`n$($todo.Count) change(s) planned. Nothing changed - run again with -Apply." -ForegroundColor Cyan; return }
Invoke-EpsAdDelegationPlan -Directory $dir -Gmsa $Gmsa -Plan $todo
# read back: a new plan has nothing left to do
$left = @(Get-EpsAdDelegationPlan @args1 | Where-Object { $_.Action -in 'add', 'remove', 'creategroup', 'addmember' })
if ($left.Count) { throw "read back: $($left.Count) change(s) still not in AD ($(@($left | ForEach-Object { "$($_.Action) $($_.Attribute) $($_.ObjectClass)" }) -join '; '))" }
Write-Host "`nDone and read back: $($todo.Count) change(s) $(if ($Remove) { 'removed' } else { 'made' })." -ForegroundColor Green
