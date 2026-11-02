# EntraPolicySuite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

## 2.0.22 - a readable rule editor
- Tagging Rules: new, edit, duplicate and restore open the rule in a wide dialog. Each field (persona, tag type, the
  value, notes) has its own full-width line, so long tag types, values and notes are readable, and each condition is a
  row of type, target and Remove, with its explanation under it. The dialog closes after a save; the bar at the top
  follows the change.

## 2.0.21 - private network install
- Private network install: add `-PrivateNetwork` to install EntraPolicySuite inside your own virtual network. The web app
  then has no public address (reachable from your network, still behind the Entra sign-in), and the database, Key Vault,
  job queues and container registry are created with public access off and reached through private endpoints and
  private DNS zones. Bring your own network (`-VnetId`) or let the install make one (`-VnetAddressPrefix`, default
  10.230.0.0/24); use your central DNS zones (`-PrivateDnsZonesResourceGroupId`); optionally peer with your hub
  (`-HubVnetId -PeerToHub`) and link the zones to it (`-LinkZonesToHub`). The parameter names are the same as in
  SecurityInsight.
- The install checks DNS from the machine it runs on before it touches any data, prints the exact DNS records your
  network needs when a name does not resolve, and continues where it stopped when you run it again. At the end a check
  from inside the network proves the web app and every job before the install reports success.
- The network hand-off: the peering, DNS zones and records, outbound addresses and the check to run are printed and
  saved next to the install journal, with a ready-to-run script for the owner of your hub network.
- An existing public install moves to the private network with the same command and `-PrivateNetwork`; `-WhatIf`
  shows the plan first.
- The two-line install passes every install parameter on (the private network ones included);
  `tools/setup/install-parameters.json` lists them all with their defaults.
- The scripts print the README on GitHub as their documentation link.

## 2.0.20 - the first public release of 2.0
EntraPolicySuite moves from scripts to your own Azure: Container Apps jobs, Azure SQL and a web app your admins sign in
to with Microsoft Entra ID.
- **Install in two lines** (PowerShell 7 or Azure Cloud Shell, browser sign-in, no modules): `Start-EpsInstall.ps1`
  downloads the release, checks it against GitHub's SHA-256 digest and runs the installer. `-WhatIf` shows the plan;
  a stopped install resumes.
- **User and device tagging** with rules as cards (persona, tag type, value, conditions), a preview of every run before
  it applies, rule guards, scopes, and an import of your v1 rule files.
- **Tagging Rules page** with grouping, Expand all / Collapse all, multi-select filters and bulk actions.
- **Tag tamper monitor**: a change to a watched tag that EntraPolicySuite did not make is alerted; accept or restore it.
- **Conditional Access**: the template library, a review of your policies against it with a Persona column, adopt /
  release (also several at once), and a documentation export. EntraPolicySuite never writes a Conditional Access policy.
- **CA Policy Analyzer**: policies grouped by persona (Global first); pick a persona, a series (CA2 = the whole CA2xx
  series, shown as you type) or single policies; monitors per persona, each with its own alert recipients.
- **Identity report** with gap views and a workbook download.
- **Hybrid worker** for AD-synced users.
- **Access and audit**: SuperAdmin / Admin / Reader roles and an append-only audit trail; a note on a change is optional.
- Every feature is off after the install.
