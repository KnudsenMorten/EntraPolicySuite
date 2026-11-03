# EntraPolicySuite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

## 2.0.27 - stage buttons for Conditional Access policies
- On the Conditional Access page, a SuperAdmin moves an adopted policy one stage at a time: Initial (off), Pilot1
  (report-only for the pilot group), Pilot2 / Pilot3 (on for the pilot group), Prod (on for its targets), one stage
  back, or off (Disable). The policy page shows the stages, a button for each move, and the moves made.
- Each move first shows what changes: the name, the state and who the policy includes, now and after the move. A move
  that enforces the policy (Pilot2, Pilot3, Prod) needs a tick that you checked who it enforces for.
- What a move changes is what the v1 scripts' stage modes did, for the group-targeting method you set. EntraPolicySuite
  never changes a group: with dynamic pilot groups, the move says which pilot values the group's rule must take, and
  you change the rule yourself.
- The engine applies the move within 5 minutes. It reads the policy again first, and refuses (changing nothing) when:
  - the policy changed since you looked at it
  - a group the stage needs is not in the tenant
  - the break-glass accounts would not stay excluded
  Turning a policy off is always allowed.
- It then makes the one change and reads the policy back. The move is journaled, audited and kept in the policy's
  history, and the monitor does not report your own move as a drift.
- **Run the install again after the update:** the engine needs the Microsoft Graph permission
  Policy.ReadWrite.ConditionalAccess for the stage buttons. To leave it out, use
  `-ExcludeGraphRole Policy.ReadWrite.ConditionalAccess`; the buttons then say the tenant refused the move.
- Nothing changes a Conditional Access policy by itself: no schedule, job, monitor or template update writes one.
## 2.0.26 - template updates you control
- Conditional Access has a new tab, **Template updates**. When a release brings a newer template library, nothing
  changes by itself. The tab lists what is new, changed or removed since the library your install took. For each
  changed template it shows the settings side by side (before and after), and how each of your policies with that
  CA number differs from the new template. Each template can be exported as JSON, as it is now and as you took it.
- Persona changes in the library (a CA number added to a persona, or taken out) are listed per persona. **Apply** adds
  or removes the numbers as name rules in your persona, and creates the persona if you do not have it. **Skip** leaves
  your persona as it is. Either way the change is not offered again.
- A template change is only **marked as seen**. The next update then compares from that version. Your policies are never
  changed: if you want what a new template does, make the change yourself in the tenant.
- Every take needs Admin, has a reason, and is applied by the engine, journaled and audited.
- This release has the same library as before (2.0-v1), so the tab says "Nothing new". The engine records the library
  your install took at its next read of the policy list.
## 2.0.25 - personas and monitors: leave out any policy
- A persona can leave out a policy its name rules take: in Manage personas, untick it and it stays out; tick it again
  to take it back.
- "Remove from monitor..." on the Conditional Access page now removes any policy. A policy you picked one by one is
  unpicked; a policy that comes in through a persona or an older series rule is left out of that monitor. The
  confirmation says per policy what happens. "Add to monitor..." takes a left-out policy back.
- The CA Policy Analyzer form shows a monitor's left-out policies as "left out of this monitor", each with "take back".
  Unticking a policy that a ticked persona takes leaves it out of that monitor.
- The Persona column on the Conditional Access page shows the personas you manage: every persona that takes the policy
  ("no persona" when none). Filtering on a persona finds a policy that is in several.
- Personas and monitors work on your real policies. The built-in personas are a starting list, made once from your
  policies when the analyzer first runs; after that it is yours. You can delete the last persona: an empty list stays
  empty. Policies in no persona are listed under "No persona".
- The analyzer still only reads: nothing changes a Conditional Access policy.
## 2.0.24 - one CA Policy Analyzer form, personas you manage
- The CA Policy Analyzer has ONE form: pick a new monitor or an existing one at the top, then 1. which policies,
  2. which sign-ins (the last 24 hours, 3, 7, 14 or 30 days) and 3. Analyse now or Save as monitor. Analyse first and
  save the same choice as a monitor, or save it straight away. Edit on a monitor loads it into the same form.
- The less common options (non-interactive sign-ins, guests, disabled accounts, reading a large log in parts) are under
  a closed "More options". "Read the policy list" is now a small "Refresh the list" link beside the policy count.
- Personas are a list you manage (Manage personas): create one, rename it, add or remove policies and name rules
  (CA2 = every CA2xx, CA006 = the CA006 policies, CA6* = a wildcard), delete it. The template personas are the starting
  list. A policy can be in several personas, or none. A monitor that names a persona follows a rename, and takes a
  change at its next run. A persona a monitor uses is deleted only after the page names those monitors and you confirm.
- The Series box is gone. A monitor saved with series keeps running them; the form shows them and lets you remove them.
- Each policy in the list shows the monitors it is in. On the Conditional Access page, select policies and choose
  "Add to monitor..." or "Remove from monitor...".
- The persona groups sort as intended: Global first, the personas A-Z, policies without a persona last.
- The analyzer still only reads: nothing changes a Conditional Access policy.

## 2.0.23 - bulk changes in one engine check, full-width pages
- A bulk change (for example adopting many Conditional Access policies at once) is applied in ONE engine check:
  the engine takes every waiting configuration change together instead of one per check.
- The bar at the top says what really happens: the engine picks changes up at its next check (every 5 minutes), and it
  counts how many are applied and how many are waiting. A second click while a selection is still being sent sends
  nothing twice.
- Pages use the full width of the window on a laptop and a desktop alike: the explanations, info boxes, settings
  fields, table cells and the search box are no longer capped.

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
