# Entra Policy Suite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

## 2.0.62 - support consent from the Invardia portal
- The install keeps the support access level your organisation sets for it in the Invardia customer portal (none, read,
  or troubleshoot / setup), as Invardia sends it with the answer to the install's own heartbeat. The web app can only
  read it.
- A support session that goes beyond that level, or that arrives before any level was received, is not taken: it is
  recorded as closed and the refusal is written to the audit trail.
- Fixed: the install read its environment name from Invardia with the wrong header and was refused; it now sends the
  header that call expects.

## 2.0.61 - setup steps for the database job and the updater
- The heartbeat to Invardia reports two more setup steps: whether the database setup job has set up the database, and
  whether the update job has its own identity to install releases. Each comes from a real record (the job's own record
  in the database, and the last update run), never from a remembered value.
- When the database setup job is in use, the version of the sign-in front the web app runs is recorded through that job,
  so the person who installs needs no database right for it either.

## 2.0.60 - the updater installs approved releases
- The nightly update job now installs a release Invardia approved for your update ring: it downloads the release and
  checks it against the signed size and SHA-256, builds the new image in your own container registry (on the build pool
  of a private install), updates the database with the database setup job, then moves every job and the web app to the
  new image and reads each one back. A stage that fails stops the update before anything moves; the next night tries
  again. When a job is running, the update waits for the next night.
- The update job does this as its own identity, id-eps-updater, with Contributor on the install's resource group only.
  The engine identity still holds no Azure right. An install run with this release adds the identity; until then the
  update job only checks, as before.
- Each stage of an update is reported to Invardia as it happens.
- Fixed: 2.0.59 read the SQL admin group's members back from the group, which leaves the setup job's identity out for
  an installer without directory read rights - the install then ran the database steps the old way. The membership is
  now read from the identity's side.

## 2.0.59 - nobody needs database admin rights to install
- The database is now set up by a one-time job inside your install, with its own identity (id-eps-dbinit): the
  schema, one least-privilege role per identity, their database users, the sign-in front's state and you as the first
  SuperAdmin. Every user is read back before the install goes on.
- The Azure SQL server's admin is a security group, grp-eps-sql-admins (found, else created; or your own group with
  -SqlAdminGroupId), and the job's identity is its member. The person who installs needs no SQL right, and the install
  no longer opens a temporary firewall rule for that machine. A private install needs no machine inside the network for
  its database steps.
- An existing install keeps its SQL admin. A group admin gets the job's identity added; a server whose admin is a person
  goes on as before, and the installer says so.
- The install's final check now reads the scheduler run's result from Azure instead of from the database.

## 2.0.58 - long runs reported to Invardia in the agreed shape
- While a job runs, the heartbeat reports it the way Invardia reads it: running, which job, since when, and how its
  length compares with its usual one.
- When Invardia refuses a field of the heartbeat and names it, the heartbeat is sent again without only that field;
  the rest of the report still arrives.
- Fixed: 2.0.57 did not raise an existing S0 database to S1 (Azure reports an S0 database's size in another form than
  the install compared). An install run now raises it.

## 2.0.57 - the database starts larger, and the sign-in version in the heartbeat
- A new install's database starts at Standard S1 with 250 GB (was S0). An install run raises an existing S0 or Basic
  database to S1; a database you sized yourself is left as it is.
- The heartbeat to Invardia now reports the version of the sign-in front the web app runs. The install records it at
  every deploy, so no extra Azure right is needed.

## 2.0.56 - the scheduler runs as the engine identity in every install
- An install made before 2.0.55 moves its scheduler job to the engine's identity (id-eps-engine), as new installs do.
  Its job names and other Azure names stay as they are.
- After the install has run the scheduler that way, it removes the old scheduler identity (id-eps-tick): its role
  assignments, its database user and the identity itself, each read back. Nothing is removed before that.

## 2.0.55 - standard names for new installs, and the return route for a private install
- A new install uses the standard names: resource group rg-eps; the scheduler job caj-eps-engine (was caj-eps-tick)
  and the update job caj-eps-updater (was caj-eps-update); registry, SQL server, Key Vault and storage end in six
  characters derived from the install. The scheduler now runs as the engine's identity, so a new install has two managed
  identities (id-eps-engine and id-eps-web).
- An existing install keeps every Azure name it has. Run without -ResourceGroup, the installer and the setup scripts
  find an install in rg-entrapolicysuite and stay there.
- Private install behind a hub firewall: new optional -InternalRanges and -FirewallIp. On a network the install makes,
  it creates the route table rt-eps on the apps subnet (your ranges back through the firewall, BGP route propagation
  off) and reads it back. Without it, replies to your network time out. On your own network the route is on the
  network hand-off list.

## 2.0.54 - the install waits instead of failing, and reads back what it links
- When the install needs something from you first, it now says it is WAITING instead of failing: missing DNS records,
  or no proof yet from inside your network. The step shows "waiting" with the reason, and the installer ends with exit
  code 4. Run the same command again when it is done; it resumes at that step.
- Private install: every private DNS zone link the install makes is read back before the install goes on.
- Private install: when your sign-in may not read your hub network or your central DNS zones, or write records in
  them, the install warns you and puts it on the network hand-off list as a task for your network team. It no longer
  stops.
- A build pool or Key Vault left in a failed state by an earlier run is created again when the install resumes.
- Two stop messages no longer suggest removing something that may be in use elsewhere.

## 2.0.53 - private install: the build pool's way out
- Azure now creates new subnets without internet access. In a private install, the registry's build pool runs in the
  endpoints subnet and needs a way out: the subnet the install makes now has default outbound access on, and one it made
  in an earlier run is set the same way.
- Before the build pool is created, the install checks the subnet's way out (a NAT gateway, a 0.0.0.0/0 route, or
  default outbound access). When you bring your own subnet and it has none, the install says so before it creates
  anything, and tells you what to add. Your subnet is never changed.

## 2.0.52 - Exchange rights only where they are used
- The engine holds the Exchange Online permission and the Exchange Recipient Administrator role only while user tagging,
  the identity report or a rule with a mailbox condition is on. A new install grants neither. An install run removes them
  when none of these is on any more, and grants them again when one is switched on. Alert mail does not need them.
- The setup step for the Exchange role now says whether it is needed, and the command that grants or removes it.

## 2.0.51 - security findings to Invardia by default
- Send security findings to Invardia (Uplink.Alerts.Enabled) is on by default: Invardia now takes all six kinds (tag
  changes made outside Entra Policy Suite, high-severity tag changes, Conditional Access drift, a deleted policy, a
  missing break-glass exclusion, a silent hybrid worker). A SuperAdmin can switch it off. An install that switched it off
  keeps it off.

## 2.0.50 - standard identity names, the read-back
- Fixed: right after a rename, Microsoft Graph can return the old name for a while; the install stopped instead of
  waiting. It now waits up to two minutes for the new name.

## 2.0.49 - standard identity names
- The web app's app registration and enterprise application are named Entra Policy Suite (with the resource group in
  brackets only when several installs share one tenant). An install made before is renamed in place by its next install
  run: same object, same app id, nobody loses access.
- A SQL admin group still named after the old product name is renamed to grp-eps-sql-admins in place, and the SQL
  server's admin entry follows it. A group you named yourself keeps its name.
- The install lists what it renamed at the end.

## 2.0.48 - the update check reads the install key
- Fixed: the update check did not read the per-install key from the Key Vault, so it never asked Invardia whether an
  update is wanted now and never reported a new version.

## 2.0.47 - the update check says more
- The update check's run log always says what happened with the "update now" question to Invardia, including why
  it was not asked.

## 2.0.46 - the update check
- New job: every night at 03:00 the update job asks Invardia which Entra Policy Suite version is approved for this
  install's update ring, checks that the answer is genuine and complete, and records what it would install in its run.
  In this release it only checks: it downloads and installs nothing. With the per-install key it also reports a new
  version to Invardia once. New setting Update.Enabled (on by default) switches it off.

## 2.0.45 - the product name, the rest
- The installer's closing line, two messages and the generated security review pack and API reference also say
  Entra Policy Suite.

## 2.0.44 - the product name
- The product is called Entra Policy Suite everywhere you read it: the web app's title, the mails (the header and the
  subject, e.g. `[Entra Policy Suite]`), the Azure Monitor alert names, the script help and the documentation. The
  GitHub repository, the installer, the support path and the Azure resource names stay EntraPolicySuite, so an existing
  install updates in place and nothing is renamed.

## 2.0.43 - wording
- The product page text of the CA Policy Analyzer uses US spelling, like the rest of the documentation.

## 2.0.42 - mails with a button, the update ring, a script for the engine's permissions
- Every mail EntraPolicySuite sends has the product's header, one blue button that opens the page the mail is about
  (the Tamper page, Conditional Access, the CA Policy Analyzer, the identity report, the mail settings) and a link to
  the web app. The test mail and the identity report mail now use the same subject format as every other mail.
- New script Grant-EpsEnginePermissions.ps1: gives the engine a permission it is missing after the install, or takes
  one away (-Remove). Only the permissions EntraPolicySuite declares for its engine can be asked for; -WhatIf shows the
  plan; every change is read back.
- The install's resource group gets the standard tags (product, ring, edition, hosting, tenant, owner, purpose); a
  re-run keeps the tags you set yourself.
- New install parameter -Ring: the update ring this install belongs to, reported to Invardia.
## 2.0.41 - private network install: re-installs and resumes
- Fixed: re-installing a private install into the same resource group stopped at the Key Vault key when the vault was
  recovered from an earlier install. The install now sets the vault's network rules every time before it makes the key.
- Fixed: an install resumed from before the jobs step could stop at the web app ("applications/ -> 405").
## 2.0.40 - private network install: the Key Vault key, a stricter region check
- Fixed: a private network install stopped at the Key Vault key. The private Key Vault still has public access off and
  no IP or network rules, and now lets trusted Azure services through, so the install can create its key.
- The region check now also catches a refused region on a fresh install (no resource group yet), and its test storage
  account uses the same settings as the real one, so a policy your install passes does not stop the check.
- The web sign-in step waits for Microsoft Entra to show the new app before it gives consent, instead of failing once.
## 2.0.39 - the region check explains an Azure Policy
- When an Azure Policy in your subscription refuses the region check's test resources, the install now says so in plain
  words and names the policy, then goes on. Before, it showed only Azure's generic message.
## 2.0.38 - private network install fixed, the region is checked first
- Fixed: a private network install stopped at its first private endpoint ("the private endpoint ... gives no address").
  The install now reads each endpoint's addresses from its network interface.
- Before anything is created, the install checks that Azure accepts new resources in the chosen region for your
  subscription. If it does not, it stops, creates nothing, and names regions that do.
## 2.0.37 - the security pack, Conditional Access docs corrected
- The security pack for reviewers is now delivered with each release: architecture, identities, every permission and
  why, data, vendor access, supply chain, change control, hardening, compliance, uninstall and scripts. It is generated
  from the code, so it always matches the version you run.
- Fixed: the documentation still said EntraPolicySuite cannot change a Conditional Access policy. It can make one
  change, on approval: a SuperAdmin moves an adopted policy to another stage after seeing what changes. The install
  documentation now lists the permission for it.
- The install's script description no longer mentions a custom role that installs since 2.0.10 no longer create.
## 2.0.36 - move a policy to any stage, the stage preview shows names
- Conditional Access: a SuperAdmin can move an adopted policy to any stage - Pilot1, Pilot2, Pilot3 or Prod, up or
  down - or disable it. A move that skips stages says which. The Move stage column has one "Move to ..." list per policy.
- Fixed: the move dialog showed "System.Object[]" instead of the users and groups the policy has now, and listed them
  as a change even when they stayed the same.
- The environment name in the page header, in alert mails and in the report to Invardia is now the name Invardia keeps
  for the install, when it reports to Invardia. The Environment name setting is the fallback.
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
