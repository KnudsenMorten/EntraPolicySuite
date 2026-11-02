#Requires -Version 7.2
<#
.SYNOPSIS
    Delegates the EntraPolicySuite hybrid worker's gMSA in Active Directory: the right to write EXACTLY the tag
    attributes on user objects below the OUs you name - nothing else (DESIGN §6). Run by an AD admin on a domain machine.
.DESCRIPTION
    For each OU and each attribute (default: extensionAttribute5-9, the v1 tag types; give -Attributes to match yours)
    it adds one inheritable Allow ACE: WriteProperty on that attribute, for descendant user objects, for the gMSA. Plan
    first: without -Apply it shows every ACE it would add (and the ones already there) and changes nothing.
    -Remove takes exactly these ACEs away again. No module: .NET System.DirectoryServices.
    The gMSA itself is created beforehand by your AD admin (a group managed service account the worker computer may
    use; it needs the domain's KDS root key) - this script only finds it by name.
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -GmsaName 'gmsa-eps' -OrganizationalUnit 'OU=Users,OU=Corp,DC=corp,DC=example'
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -GmsaName 'gmsa-eps' -OrganizationalUnit 'OU=Users,OU=Corp,DC=corp,DC=example' -Apply
.EXAMPLE
    .\Initialize-EpsHybridWorkerAd.ps1 -GmsaName 'gmsa-eps' -OrganizationalUnit 'OU=Users,OU=Corp,DC=corp,DC=example' -IncludeProtectedAccounts -Apply
    Also protected admins (Domain Admins and the like): the same right on AdminSDHolder - a Tier 0 decision.
.LINK
    https://invardia.com/docs/eps/scripts/Initialize-EpsHybridWorkerAd
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{1,15}\$?$')][string]$GmsaName,
    [Parameter(Mandatory)][string[]]$OrganizationalUnit,
    [ValidatePattern('^extensionAttribute([1-9]|1[0-5])$')][string[]]$Attributes = @('extensionAttribute5', 'extensionAttribute6', 'extensionAttribute7', 'extensionAttribute8', 'extensionAttribute9'),
    [string]$Server,
    # owner 2026-10-30 "New gMSA + protected admins": the same narrow right on AdminSDHolder, so protected admins (Domain
    # Admins and the like, who do not inherit OU rights) are tagged too - this makes the gMSA Tier 0 sensitive
    [switch]$IncludeProtectedAccounts,
    # give the rights to this EPS group (the gMSA its member) instead of the gMSA itself - recommended next to PIM, so
    # each product removes its own principal cleanly
    [ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')][string]$GroupName,
    [switch]$Apply,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Write-Host 'Documentation: https://invardia.com/docs/eps/scripts/Initialize-EpsHybridWorkerAd'
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\EPS-AdDelegation.ps1')
$write = $Apply -and -not $WhatIfPreference
$WhatIfPreference = $false
$dir = New-EpsAdDelegationDirectory -Server $Server
$holder = if ($IncludeProtectedAccounts) { $dir.GetAdminSdHolderDn() }
if ($holder) { Write-Host "Protected accounts: the right also goes on $holder - AD copies it onto every protected account (Domain Admins and the like) within about 60 minutes. The gMSA can then change an ADMIN's tags, and with them his Conditional Access policies: treat it as a Tier 0 account." -ForegroundColor Yellow }
$plan = Get-EpsAdDelegationPlan -Directory $dir -GmsaName $GmsaName -OrganizationalUnit $OrganizationalUnit -Attributes $Attributes -Remove:$Remove -ProtectedHolderDn $holder -GroupName $GroupName
foreach ($p in $plan) { Write-Host ("  {0,-8} {1} on {2}" -f $p.Action, $p.Attribute, $p.OU) -ForegroundColor $(if ($p.Action -in 'add', 'remove') { 'Yellow' } else { 'DarkGray' }) }
$todo = @($plan | Where-Object { $_.Action -in 'add', 'remove' })
if (-not $write) { Write-Host "`n$($todo.Count) ACE(s) to $(if ($Remove) { 'remove' } else { 'add' }). Nothing changed - run again with -Apply." -ForegroundColor Cyan; return }
Invoke-EpsAdDelegationPlan -Directory $dir -Plan $todo
Write-Host "`nDone: $($todo.Count) ACE(s) $(if ($Remove) { 'removed' } else { 'added' })." -ForegroundColor Green
