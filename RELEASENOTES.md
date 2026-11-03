# EntraPolicySuite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

## 2.0.35 - a private install checks everything first, a shorter install line
- A private network install now checks everything it needs before it creates anything: your network and its two
  subnets, the hub network, and every private DNS zone EntraPolicySuite uses in your central DNS zones resource group.
  Anything missing is listed at once, in plain words, and nothing is created. Fix the list and run the same command
  again, or leave out -PrivateDnsZonesResourceGroupId and the install makes its own zones.
- The install line names only what you must give: `-TenantId <tenant id> -SubscriptionId <subscription id>`. The region
  is West Europe unless you add `-Location <region>`.
- The support scripts at invardia.com/support/eps/ come with a full README: the install lines and every script with
  its documentation page and SHA-256.
## 2.0.34 - what an install tells Invardia, sign-in on a second run
- For installs that report to Invardia: the heartbeat now gives the install's addresses (the web app and its API) and,
  while a job runs, how long it has been running against its usual length.
- The setup scripts for mail, web access and alerts now always sign in again on a second run in the same PowerShell
  window, instead of reusing an earlier sign-in that has expired or belongs to another tenant.
- The install line names the region: `-TenantId <tenant id> -SubscriptionId <subscription id> -Location <region>`.
- Every script a person runs is now handed over to Invardia for invardia.com/support/eps/, each as one self-contained
  file. It downloads the release, checks it against the release's SHA-256, and runs the script from it.
## 2.0.33 - every policy has its persona, template library 2.0-v1.1
- A Conditional Access policy shows its persona even when none of your managed personas takes it: its template's
  persona, or, for a policy without a template, the persona its name says. CA000-CA0xx are Global, CA095-CA099
  BreakGlassAccounts. Your managed personas still come first.
- **Template library 2.0-v1.1:** each template's persona now comes from the template's name, which fixes v1's spelling
  slips (Users-Internals, Users-Internal-Developerss, Users-Externals) and CA262. The 29 corrected templates are version
  v1.1. Conditional Access > Template updates shows each change, old against new, for you to adopt.
- Personas you don't manage yet are marked as coming from the template in Manage personas. Editing one makes it yours.
- CA Policy Analyzer: the "read a large log in parts" field is gone. EPS decides: a window longer than a day is read a
  day at a time.
- Get started opens with how to bring v1 over: the tagging rules in the browser (Tagging Rules > Import CSV), or
  everything with the import script, step by step.
- Tagging Rules grid: one number column, # (the run order). The rule's id shows when you point at the number.
## 2.0.32 - the menus open
- The six menus opened in 2.0.31 but stayed hidden under the menu bar. They now fold out, on a click and when you point
  at them.
## 2.0.31 - six menus instead of sixteen tabs
- The menu has six groups: **Overview**, **Tagging**, **Conditional Access**, **Identity report**, **Jobs & runs** and
  **Administration**. Each group opens a list of its pages, every page with one line on what it is for. The group
  you are in is highlighted.
- The full name "Entra Policy Suite" next to EPS in the header is now light and easy to read.
## 2.0.30 - an action per user in the identity report
- Every user in the identity report has four follow-up fields: **Action** (Disable, Delete, Investigate, Remove from
  cloud sync), **Status** (Not started, In progress, Closed), **Who** (who is responsible) and **Notes**.
- Tick users, or take every user a view and its filters show (up to 5,000), and set the fields on all of them at once.
  For example: filter to the service accounts that are synced to the cloud, then set "Remove from cloud sync", the team,
  and a note.
- A field you leave as it is stays unchanged; "clear" empties it.
- The fields are kept per user across report runs. They show in every user view and can be filtered, sorted, pivoted and
  exported like any other column.
- Setting them needs Admin and is journaled and audited. It is a record for follow-up: nothing in the tenant or AD
  changes.
## 2.0.29 - alerts to Invardia accepted, EPS in the header, rules collapsed
- Alerts sent to Invardia (for installs that report) carry only the fields Invardia's alert contract takes. Before
  this, Invardia refused every alert (HTTP 422), and the Uplink job reported PartlyFailed at each run.
- The header says **EPS**, with "Entra Policy Suite" in smaller letters.
- Tagging Rules: the groups start collapsed (Expand all opens them; a search shows what it finds). The value column says
  **Tag Value**, and Matched explains itself when you point at it: how many accounts the rule matched in the last run.
- Get started: the mail-sender step's text no longer reads like a command.
## 2.0.28 - Get started
- A new page, **Get started**, lists what EntraPolicySuite needs before the templates, tagging and reports work: what
  v1's scripts set up first. **Check now** reads the tenant and changes nothing. Each item shows as ready, missing or
  to check, with what was found. There are 13 steps:
  1. The engine's Graph permissions and Exchange role, and the licences the templates need.
  2. The break-glass accounts: cloud-only, password never expires, Global Administrator, their group, excluded from
     every policy.
  3. The FIDO2 and Windows Hello authentication strengths (compared with v1's: the allowed methods and the 11 key
     models), and the authentication methods switched on.
  4. The group targeting method, now a choice of v1's three, and the group names that follow from it.
  5. The target groups: in the tenant, with members, the dynamic rule as stored.
  6. The pilot and exclude groups of your adopted policies.
  7. The administrative units.
  8. Named locations: denied countries and a trusted location for your offices.
  9. The tag attributes, the rules, and the AD Connect sync account left out.
  10. The alert mail.
  11. The hybrid worker.
  12. The report's AD OU patterns.
  13. The templates that need an input.
- The break-glass accounts can now be added and changed on the page (SuperAdmin), where until now only the v1 import
  filled the list. This changes EntraPolicySuite's list only, never the tenant. Never write a password there.
- The heartbeat to Invardia (for installs that report) now says, from a real check each time, whether every one-time
  setup step is in place, such as each of the engine's Graph permissions.
- Creating what is missing, as v1 did, comes in the next releases, one step at a time, each after you see the plan.
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
