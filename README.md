# Entra Policy Suite

**Regain control of your digital identity.** A PowerShell-driven framework that makes Microsoft Entra ID posture management a **code discipline** — persona classification, tag-driven dynamic groups, numbered Conditional Access policies, break-glass-safe exclusions, and a staged Initial → Pilot → Prod lifecycle. 100+ engines covering every identity class most tenants encounter, all idempotent, all dry-run-capable.

> **"Same security with no exceptions — including in the office. No convenient considerations."**

Developed by **Morten Knudsen** — Microsoft MVP (Security · Azure · Security Copilot).

Author blog: [mortenknudsen.net](https://mortenknudsen.net) · [aka.ms/morten](https://aka.ms/morten)

Sample generated CA policy documentation (what you get after deployment):
📎 [Conditional Access Policy Documentation (PDF)](https://mortenknudsen.net/wp-content/uploads/2025/05/Conditional-Access-Policy-Documentation.pdf)

---

## 📑 What's in this doc

1. **[Executive Summary](#-executive-summary)** — the problem, the model, why it matters.
2. **[The persona model](#-the-persona-model)** — every identity gets two tags; every tag drives a dynamic group; every group is a CA target.
3. **[The CA numbering scheme](#-the-ca-numbering-scheme)** — why `CA000`–`CA800`, and what each range does.
4. **[Break-glass accounts](#-break-glass-accounts--the-first-thing-you-build)** — non-negotiable safety net.
5. **[Admin tiering](#-admin-tiering)** — separate accounts for separate control planes.
6. **[Named locations](#-named-locations--why-they-come-first)** — trusted IP boundaries before anything else.
7. **[CA lifecycle](#-ca-lifecycle-initial--pilot--prod)** — how a policy moves from idea to production.
8. **[Quick Start](#-quick-start)** — get running in three steps.
9. **[Implementation roadmap](#-implementation-roadmap-10-phases)** — the full rollout sequence.
10. **[Engines in this suite](#-engines-in-this-suite)** — what each script and CA range does.
11. **[Preview vs Stable](#-preview-vs-stable)**
12. **[Contributing, bugs, discussions](#-contributing-bugs-discussions)**
13. **[Requirements & licensing](#-requirements--licensing)**
14. **[Anti-patterns to avoid](#-anti-patterns-to-avoid)**
15. **[License](#-license)**

---

# 🧩 Executive Summary

## Identity is the perimeter

Microsoft reports blocking **~7,000 password attempts every second** across its identity platform, and a **146% increase in adversary-in-the-middle (AiTM) phishing** year over year. The Microsoft **Secure Future Initiative** names identity its top focus area. If your tenant is over-permissioned, drifting, or policy-inconsistent, **you are the attacker's easiest target.**

## Most tenants have lost control

Real engagement from this suite's author:

> **"We started with 2,200 accounts. After the clean-up we were down to 1,351."**

Tenants accumulate:

- **Account sprawl.** Shadow admins, stale admins from departed staff, test accounts that never got deleted, guests dormant for 365+ days, externals still holding active sessions.
- **Unknown ownership.** Nobody can answer *"who owns this account, and what does it do?"*
- **Cloud-synced accounts that shouldn't be.** AD accounts that only touch legacy resources should never have been exposed to Entra in the first place.
- **Service-account sprawl.** 3rd-party apps running as AD service accounts instead of managed identities or app registrations.
- **Weak auth on critical identities.** Shared-device users with `Password1234` and no MFA. Admins who never registered MFA.
- **CA policy sprawl.** 50–150 CA policies with no numbering, no naming convention, no documented exclusion strategy, and no break-glass guarantee.

## How attackers exploit it

Classic attack patterns the deck calls out:

- **Password spray** and **credential stuffing** against cloud auth endpoints
- **AiTM phishing** (Evilginx, EvilProxy) harvesting session cookies in real time
- **Man-in-the-middle** on untrusted Wi-Fi
- **Keylogger malware** on un-managed personal devices
- **Social engineering** impersonating IT asking for MFA approval
- **Insecure 3rd-party app integrations** over-permissioned against Graph

## The fix: make posture a code discipline

Entra Policy Suite implements an **opinionated, persona-driven model** where:

1. **Every identity is classified** into a persona (see [persona model](#-the-persona-model)) — internal admin, external developer, service account, break-glass, shared-device user, Teams room, etc.
2. **Every persona has a prescribed authentication method** — FIDO2 / WHfB / TAP / password — written back to the account as a compound tag on `extensionAttribute7`.
3. **Dynamic groups** are generated from those tags.
4. **Conditional Access policies are numbered** (`CA000`–`CA800`) so every policy's purpose and target persona is readable at a glance.
5. **Deploy idempotently** via one `.ps1` per policy. Diff before you push. Dry-run before you apply. Roll back by re-running a prior version.
6. **Lifecycle-staged**: every policy moves through *Initial (disabled) → Pilot1 → Pilot2 → Pilot3 → Prod* before it's enforced on the general population.

> **"100% automated. Think of targeting with personas."**

---

# 🧑‍🎯 The persona model

The heart of the suite is a **two-dimensional classification** that every identity receives:

- **Persona** — what *kind* of identity is this? (internal user, external admin, service account, break-glass, etc.)
- **Authentication method** — what auth does this persona use? (FIDO2, WHfB, AD-synced password, TAP, cert)

The two are joined into a single compound tag written to `extensionAttribute7` on the user object (and `extensionAttribute6` on the device object for device classification). Dynamic groups read the tag; CA policies target the groups.

<details>
<summary><b>📋 Full persona catalogue (click to expand)</b></summary>

| Persona tag | Description |
|---|---|
| `Internal_User` | Regular internal employee. |
| `Internal_Admin` | Internal administrative account (separate from their user account). |
| `Internal_User_Developer` | Internal developer — higher session frequency, broader app access. |
| `External_User` | Contractor / consultant with a local account in the tenant. |
| `External_Admin` | External admin (MSP / partner) with delegated rights. |
| `External_Guest` | B2B guest invited from another tenant. |
| `AppSystem_Test_User` | Test account owned by an application or test harness. |
| `Service_Account` | Traditional service account (pre-MI era). Block from untrusted locations. |
| `Shared_Mail_User` | Mailbox-only identity, no interactive login. |
| `Teams_Room` | Teams Room device account. |
| `Shared_Device_User` | Kiosk / shared-device user (factory floor, front desk). |
| `Break_Glass_Account` | Emergency-access Global Admin. **Excluded from all CA policies except its own.** |
| `NonManaged_User_Cloud` | Cloud-only account not yet tagged / classified. |
| `NonManaged_User_AD_Synced` | AD-synced account not yet tagged / classified. |
| `Contact` | Contact object, no login. |
| `FacilityAccessOnly` | Physical badge / identity-only. No digital access. |
| `Exchange_LinkedMailBox` | Cross-forest linked mailbox. |

</details>

<details>
<summary><b>🔑 Persona × authentication-method matrix (click to expand)</b></summary>

The compound tag values look like `<Persona>_<SyncState>_<AuthMethod>`. ~25 predefined combinations, e.g.:

| Compound tag (sample) | Who |
|---|---|
| `Internal_Admin_AD_Synced_FIDO` | Internal admin, AD-synced, FIDO2 security key |
| `Internal_Admin_Cloud_FIDO` | Internal admin, cloud-only, FIDO2 |
| `Internal_User_AD_Synced_Pwd` | Internal regular user, AD password |
| `Internal_User_AD_Synced_WHfB` | Internal user, Windows Hello for Business |
| `Service_Account_Cloud_Pwd` | Service account, cloud-only, password auth |
| `Shared_Device_User_Cloud_WHfB` | Shared-device user, WHfB + PIN |
| `Break_Glass_Account_Cloud_FIDO` | Break-glass, cloud-only, FIDO2 |
| `External_Admin_Cloud_FIDO` | External (MSP) admin, FIDO2 |
| `AppSystem_Test_User_Cloud_Pwd` | Test account, password (lab only) |

The tagging engine (`Entra-ID-User-Tagging.ps1`) takes a CSV of accounts-to-tags and writes these values to `extensionAttribute7`. See [Identity tagging + reporting](#identity-tagging--reporting).

</details>

## Why two attributes, not one

`extensionAttribute6` = device classification (e.g. `AutoPilot_PAW_Windows_EntraJoined_Tier0_English`).
`extensionAttribute7` = user persona + auth-method tag.

CA policies can target **both** simultaneously (e.g. "Tier-0 admins may only sign in from Tier-0 PAWs"):

```
User.extensionAttribute7 -contains "Internal_Admin_AD_Synced_FIDO"
  AND
Device.extensionAttribute6 -contains "PAW_Tier0"
```

> **The 6 / 7 split is the default — change it to suit your tenant.** Each
> tenant has 15 `extensionAttribute1`–`extensionAttribute15` slots on
> `User` and another 15 on `Device`. If your environment already uses
> `extensionAttribute6` / `extensionAttribute7` for something else (HR sync,
> asset tag, email signature data), pick any free pair instead. Update the
> attribute names in `LauncherConfig.ps1` (community mode) or in your
> `launcher.override.ps1` (internal mode) — every engine reads the values
> through the launcher's globals, so all CA policies, dynamic-group rules,
> tagging engines and reports follow automatically. The only constraint:
> use **two different** attributes (one for user persona, one for device
> classification) so CA rules can target them independently.

---

# 🔢 The CA numbering scheme

Every CA policy in the suite slots into a numbered range. The first three digits tell you, at a glance, who the policy targets and what it does.

| Range | Target | Purpose |
|---|---|---|
| `CA000`–`CA090` | **All users (global)** | Catch-alls: "new user MFA", block Device Code Flow, high-risk user block, trusted-location-first baseline. |
| `CA096`–`CA099` | **Break-glass accounts** | The only CA policies that *target* break-glass accounts. Permissive (trusted location + MFA) so emergency access actually works. |
| `CA100`–`CA149` | **Internal admins** | Tier-0/1 admin access rules. PAW device required. FIDO2 / phishing-resistant. |
| `CA150`–`CA199` | **External admins (MSP / partner)** | B2B admins with delegated rights. Stricter than internal admins. |
| `CA200`–`CA249` | **Internal users** | MFA, trusted location, device compliance. |
| `CA250`–`CA299` | **Internal developers** | Broader app access, different session frequency (7 days vs 30 for regular users). |
| `CA300`–`CA349` | **External users** | Contractors / consultants. |
| `CA350`–`CA399` | **External developers** | Cross-org dev access. |
| `CA400`–`CA409` | **Guests** | B2B guest restrictions. |
| `CA500`–`CA539` | **Shared-device users** | Kiosk / front-desk. Phishing-resistant only. No personal MFA carryover. |
| `CA540`–`CA549` | **Teams Rooms** | Meeting-room endpoints. |
| `CA550`–`CA559` | **Shared mailbox users** | Mail-only identities. |
| `CA600`–`CA699` | **Service accounts** | Block from untrusted locations. Named-location allowlist per integration (backup, automation, LogicApp, etc.). |
| `CA700`–`CA799` | **Workload identities** | App registrations / SPNs. Requires Entra Workload ID license. |
| `CA800`–`CA809` | **Non-managed / untagged users** | Fallback for accounts not yet classified. |
| `410`–`499`, `560`–`599`, `810`–`999` | *Reserved* | For your own customizations. |

## Naming convention

Policy name = `CA<###>-<Stage>-<Persona>-<Apps>-<Platform>-<Conditions>-<SessionControls>-<GrantControls>`

Example: `CA006-Prod-Global-AllApps-AnyPlatform-HighUserRisk-Block`.

The full name tells ops staff exactly what the policy does without opening the portal.

---

# 🚨 Break-glass accounts — the first thing you build

**Before any restrictive CA policy goes live.** No exceptions.

Recommended: **3 break-glass accounts**, all Global Admin, all cloud-only (never synced from AD), all with password-never-expires, all excluded from every CA policy **except** the ones in the `CA096`–`CA099` range that target them explicitly.

| Name | Auth | Location rule | Physical key custody |
|---|---|---|---|
| `BGA-0` | MFA + password | Trusted location only | In the office safe |
| `BGA-1` | FIDO2 | Any location | IT Director's home safe |
| `BGA-2` | FIDO2 | Any location | CISO's home safe / off-site |

> **"Entra Policy Suite will exclude break-glass accounts using both groups AND accounts — yes, I know it is double. That's the point."**

The `CA000`-series catch-all will also exclude break-glass accounts as a belt-and-braces guarantee.

---

# 🏛️ Admin tiering

Every administrator gets **multiple accounts**, one per control plane:

| Account | Where it lives | Syncs to cloud? | Used for |
|---|---|---|---|
| `MOK` (their user) | AD / Entra (synced) | Yes | Regular email, Teams, Office work |
| `ADMIN-MOK-AD` | AD only | **No** | Active Directory admin tasks |
| `ADMIN-MOK-ID` | Entra only (cloud) | — | Entra ID admin tasks, Azure RBAC |
| `ADMIN-MOK-L0-T0-AD` | AD only | **No** | **Tier-0** AD admin (domain controllers, schema) |
| `ADMIN-MOK-L0-T0-ID` | Entra only | — | **Tier-0** cloud admin (Global Admin) |

Rule: **admin accounts are never synced from AD to cloud.** The cloud-admin account is a separate cloud-only object. This stops an on-prem compromise from automatically giving the attacker cloud admin.

PAW (Privileged Access Workstation) filter for Tier-0 admins (slide 44):

```
device.extensionAttribute6 -eq "W365_PAW_W365_Windows_EntraJoined_Tier0_English"
```

Non-PAW devices are blocked from the admin portals entirely.

---

# 🌐 Named locations — why they come first

Named locations are the **trust boundary** every other CA policy keys off. Build them **before** you roll out FIDO2 onboarding, before you lock down admins, before anything else. Reason: the FIDO2 user-action CA policy that lets people *register* their security key depends on being in a trusted location — deploy CA before the location exists and you lock everyone out of FIDO2 enrollment.

Design principles:

- **One named location per purpose.** Don't lump everything into a single giant "trusted." Separate:
  - `Trusted HQ / office IPs` (physical perimeter)
  - `KeepIT Backup Datacenter EU` (per-SaaS allowlist)
  - `Automation MS WE`, `Azure LogicApp MS WE` (per-Microsoft-service allowlists — refreshed via `EntraNamedLocations_AzureNetworkServiceTags.ps1`)
  - `Denied Countries` (explicit deny)
- **No "office exception" for convenience.** Security is the same inside and outside HQ. The office IP range is trusted so FIDO2 enrollment works — not so password auth is tolerated.
- **Daily refresh of Azure service tags.** Microsoft's public IP ranges change. The `EntraNamedLocations_AzureNetworkServiceTags.ps1` engine pulls the official `ServiceTags_Public_YYYYMMDD.json` feed and upserts matching Entra Named Locations automatically.

---

# 🔄 CA lifecycle: Initial → Pilot → Prod

Every CA policy moves through five states before enforcement hits your general population:

```
┌───────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌──────┐
│ Initial   │ -> │ Pilot1 │ -> │ Pilot2 │ -> │ Pilot3 │ -> │ Prod │
│ (disabled)│    │ (10%)  │    │ (50%)  │    │ (90%)  │    │(100%)│
└───────────┘    └────────┘    └────────┘    └────────┘    └──────┘
   Baseline        IAM team      Power users   Full pilot    GA
   drafted         only
```

Each stage has its own dynamic group and its own exclusion set. A policy in Pilot1 is enforced on an IAM-team dynamic group only; in Pilot2 it extends to power users; in Pilot3 to the full pilot population; in Prod to all tagged personas.

You promote a policy by running its launcher with a stage flag. Roll back by re-running the prior stage's launcher.

---

# 📦 Quick Start

```powershell
# 1. Get the latest stable release
#    -> https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest
#    Download the zip, extract to e.g. C:\EntraPolicySuite
#    (or:  git clone https://github.com/KnudsenMorten/EntraPolicySuite.git)

# 2. Establish prerequisites BEFORE any restrictive policy goes live:
#    (a) 3 break-glass accounts (see "Break-glass accounts" section)
#    (b) Named locations (trusted HQ + per-service + denied-countries)
#    (c) One service principal or managed identity with:
#        - Conditional Access Administrator
#        - Directory Readers
#        - User Administrator (for tagging)

# 3. Pick ONE policy to start with. A good first target: CA000 - "new user catch-all MFA".
cd C:\EntraPolicySuite\launchers\CA000
Copy-Item LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1        # fill in TenantId + auth method
.\launcher.community-vm.template.ps1 -WhatIfMode    # dry-run
.\launcher.community-vm.template.ps1                # apply
```

The LauncherConfig values (TenantId, SPN credentials, KV references) are the same across every CA policy — copy the populated `LauncherConfig.ps1` into each `launchers/CA###/` folder as you roll out.

Four auth methods supported in every launcher:

1. **Managed Identity** (Azure VM / Function / Arc-enabled server) — most secure
2. **SPN + Key Vault secret** (VM has MI with Secrets User role on the vault)
3. **SPN + certificate** (thumbprint in local cert store)
4. **SPN + plaintext secret** (**testing / lab only**)

---

# 🗺️ Implementation roadmap (10 phases)

Do these in order. Don't skip phase 1.

### Phase 1 — Inventory & clean-up
Run `IdentityReporter.ps1`. For every account answer:
- Who owns it?
- What's its purpose?
- Does it need to exist at all?
- Does it need to be cloud-synced?

Expected outcome: an account list roughly half the size of what you started with. Deal with:
- Old admins from departed staff → delete
- Test accounts → delete
- Dormant guests (>365 days, no sign-in) → remove
- AD accounts that only touch legacy AD resources → stop syncing to cloud
- 3rd-party service accounts → migrate to Managed Identity or app registration

### Phase 2 — Break-glass accounts
Create `BGA-0`, `BGA-1`, `BGA-2` as described above. Store keys physically. Document custody.

### Phase 3 — Admin tiering
Split every admin's identity into user / AD admin / cloud admin / L0-T0 variants. Admin accounts cloud-only (never synced). Document. Push back on developers who want to "just use my user for Azure portal too."

### Phase 4 — Named locations
Build trusted-HQ, per-service allowlists, and denied-countries. Deploy the daily Azure service-tag sync. **Verify a trusted location exists before phase 7.**

### Phase 5 — Persona tagging
Define your persona + auth-method combinations. Populate the tag CSV. Run `Entra-ID-User-Tagging.ps1`. Every account should now have `extensionAttribute7` set.

### Phase 6 — Dynamic groups
Create one dynamic group per persona + auth-method tag. Verify membership counts roughly match your tag CSV. No orphans, no surprise memberships.

### Phase 7 — FIDO2 / WHfB onboarding
Deploy the user-action CA policies (`CA0xx` range) that gate authentication-method registration. **This is why phase 4 had to happen first** — enrollment policy is keyed on trusted location.

### Phase 8 — CA policy rollout
Deploy CA policies through the lifecycle: Initial (disabled) → Pilot1 → Pilot2 → Pilot3 → Prod. Start with `CA000` catch-all, then `CA005` (block Device Code Flow), then work outward by persona.

### Phase 9 — Legacy-auth deadline
Microsoft retired legacy authentication on **September 30, 2025**. If you still have basic auth on Exchange Online or anywhere else, migrate immediately.

### Phase 10 — Ongoing SecOps automation
- Re-tag users every N hours (scheduled task / Function App)
- Disable → quarantine → delete stale accounts on a schedule
- Report via `IdentityReporter.ps1` + Entra Identity Secure Score
- Validate posture with [Maester](https://maester.dev/)

---

# 🧰 Engines in this suite

## Conditional Access engines (138 scripts)

One `.ps1` per policy, in `scripts/CA-Scripts-Active/<CA###>.ps1`, with a 1:1 launcher at `launchers/<CA###>/`. See [CA numbering scheme](#-the-ca-numbering-scheme) for what each range targets.

## Core engines

| Engine | What it does |
|---|---|
| `Entra-ConditionalAccess-Management.ps1` | Reads `DATA/Entra_Policy_Suite_*.config` and deploys the full policy set end-to-end. Idempotent. Dry-run-capable. Used when you want bulk deployment vs. per-policy launchers. |
| `Entra-ConditionalAccess-Management-DEMO-EXPORT.ps1` | Exports the current tenant's CA graph to JSON. Snapshot before big changes. |
| `Entra-ConditionalAccess-Management-DEMO-CONFIG.ps1` | Demo config for evaluation environments. |
| `Entra-ID-User-Tagging.ps1` | Reads a CSV of `userPrincipalName,tag` rows and writes `extensionAttribute7`. |
| `Entra-ID-User-Tagging-Test.ps1` | Smoke-test variant that reports what *would* be written. |
| `Entra-ID-User-Tagging-Reset-Demo.ps1` | Clears tags in a demo tenant. |
| `Entra-ID-User-Tagging-Troubleshooting.ps1` | Diagnostic helper — why is this user not in the expected dynamic group? |
| `Entra-ID-User-Tagging-Troubleshooting-PS7.ps1` | PS 7 variant of the above. |
| `Entra-ID-Device-Tagging.ps1` | Same pattern, writes `extensionAttribute6` on devices. |
| `Entra-Public-Suite-Onboarding.ps1` | First-run helper: creates the SPN, grants Graph permissions, upserts KV secret. Run once per tenant. |
| `EntraNamedLocations_AzureNetworkServiceTags.ps1` | Downloads the daily `ServiceTags_Public_YYYYMMDD.json` feed and upserts matching Entra Named Locations. Schedule this daily. |
| `IdentityReporter.ps1` | Graph-driven reports: accounts missing MFA, accounts missing CA-required licenses, accounts with no login in X days, cloud-exposed accounts that never signed in. |
| `IdentityReporterTest.ps1` | Non-destructive smoke test of the reporter. |
| `ExposureSigninReports.ps1` | Correlates sign-in logs against applied CA policies to surface exposure gaps (who signed in *without* MFA? Which app bypassed CA?). |
| `Kusto-Queries.ps1` | Canned KQL queries for Log Analytics / Sentinel dashboards. |
| `Demo-Connect-Workload-SP-from-Trusted-IP.ps1` | Verifies that a workload-identity CA policy restricting SPN sign-in to a named location is actually enforced. |
| `_shared/EntraPolicySuite.psm1` | Shared module: Graph connection, pagination helpers, CA-object builders, structured logging. Imported by every engine. |

## Identity tagging + reporting

Two attributes, a schedule, a tagging engine, and a reporter:

- **Tag storage:** `extensionAttribute7` on user, `extensionAttribute6` on device. Both Graph-readable.
- **Tagging engine:** `Entra-ID-User-Tagging.ps1` runs on a schedule (hourly typical), reading a CSV source of truth and writing tags.
- **Dynamic groups:** one per tag value. Entra evaluates membership continuously.
- **CA targeting:** every CA policy targets (or excludes) one or more of those dynamic groups.
- **Reporter:** `IdentityReporter.ps1` pulls Graph snapshots into CSV and highlights:
  - Accounts missing required authentication methods
  - Accounts missing CA-required licenses (no Entra P1 → no CA coverage)
  - Accounts with no login for N days
  - Cloud-exposed accounts that never logged in
- **Documentation:** deployed CA policies are auto-documented into a PDF like [this sample](https://mortenknudsen.net/wp-content/uploads/2025/05/Conditional-Access-Policy-Documentation.pdf) for audit / handover.

---

# 🧪 Preview vs Stable

| Branch | When to use |
|---|---|
| `main` | **Default.** Stable release channel. Every release is tagged `v{X.Y.Z}` and has a matching GitHub Release with a downloadable zip. |
| `preview` | Pre-release work. Force-pushed when upstream cuts a `-preview` tag. Useful if you want to try a new CA engine before the next stable cut — but expect breaking changes. |

```powershell
# Preview channel
git clone -b preview https://github.com/KnudsenMorten/EntraPolicySuite.git

# Switch an existing clone
git fetch origin preview
git checkout preview
```

---

# 📣 Contributing, bugs, discussions

- **Bug / incident** → [open a GitHub Issue](https://github.com/KnudsenMorten/EntraPolicySuite/issues/new/choose). Include tenant context (prod / lab), PowerShell version, full error + stack trace.
- **Feature request / question** → GitHub Issue with `enhancement` or `question` label.
- **Pull request** → welcome. This repo is auto-mirrored from an upstream monorepo; PRs here are reviewed and bridged upstream, with your attribution preserved. See `CONTRIBUTING.md`.

---

# 📋 Requirements & licensing

## PowerShell + modules

- **PowerShell 5.1+ or PowerShell 7.2+.** Most engines target 5.1 for compatibility; a few explicit `-PS7` variants exist where PS 7 features are needed.
- **Microsoft Graph PowerShell SDK 2.x** (`Microsoft.Graph.Authentication` at minimum; most engines auto-install additional sub-modules on first run).
- **Az PowerShell** if you use Managed Identity / Key Vault auth: `Az.Accounts`, `Az.KeyVault`.

## Entra / Azure roles

For the service principal or managed identity that runs the engines:

| Role | Why |
|---|---|
| **Conditional Access Administrator** | CA policy CRUD |
| **Directory Readers** | User / device / group lookup |
| **User Administrator** | Writing `extensionAttribute7` / tagging |
| **Privileged Role Administrator** | Only if onboarding-helpers grant roles to other SPNs |
| **Reports Reader** (optional) | Sign-in logs for `ExposureSigninReports.ps1` |
| **Application Administrator** (optional) | Managing workload identities in the `CA7xx` range |

## Licensing

| Feature | Needs |
|---|---|
| Conditional Access (the whole point) | **Entra ID P1** per targeted user |
| Risk-based sign-in (`CA006`, etc.) | **Entra ID P2** |
| Privileged Identity Management | **Entra ID P2** |
| Workload ID CA (`CA7xx` range) | **Microsoft Entra Workload ID** license |
| FIDO2 / passkey deployment | P1 + hardware keys |

> **No P1 = no CA. No P2 = no risk-based policies. No Workload ID license = no app-registration protection.**
> Run `IdentityReporter.ps1` first to find accounts that would be unreachable under your current licensing.

---

# ⚠️ Anti-patterns to avoid

Hard-won lessons from the author's engagements:

- ❌ **Don't sync admin accounts to cloud.** AD admin accounts stay in AD. Cloud admin is a separate cloud-only object.
- ❌ **Don't sync AD accounts that only touch legacy on-prem resources.** Exposing them to Entra is free attack surface.
- ❌ **Don't create service accounts in AD and sync them** if they're cloud-only in purpose. Use Managed Identity or app registration.
- ❌ **Don't forget to exclude break-glass** from every new CA policy. Entra Policy Suite excludes by group *and* account — deliberately redundant.
- ❌ **Don't roll out CA without named locations first.** The FIDO2 user-action registration policy breaks without a trusted location — you'll lock everyone out of enrollment.
- ❌ **Don't leave personal MFA on shared devices.** An IT-staffer's phone becomes a backdoor. Strip personal methods before handover.
- ❌ **Don't use TAP to re-authenticate cloud apps** that need ongoing token refresh. TAP is for interactive one-time login, not long-running sessions.
- ❌ **Don't treat the office as special.** Same security in HQ as out of HQ. The trusted location is for FIDO enrollment, not for tolerating password auth.
- ❌ **Don't leave SSPR open to phishing-resistant-only personas.** FIDO2 / WHfB / cert accounts should be explicitly excluded from SSPR via a dynamic group on `extensionAttribute7`.
- ❌ **Don't use Device Code Flow.** Block it globally (CA005).
- ❌ **Don't forget the catch-all.** CA000 must enforce MFA for any untagged newly-created user, or new hires have a classic gap between account creation and persona tagging.
- ❌ **Don't skip admin tiering even if developers push back.** They will. "I just want to use my user account for Azure portal too." Say no.
- ❌ **Don't forget device ergonomics** for shared / kiosk users. Not every kiosk has USB ports for FIDO — WHfB + PIN is often the right answer.
- ❌ **Don't assume licensing works out.** P1 coverage gaps silently exclude users from CA. Audit it.

---

# 📜 License

**MIT.** See `LICENSE`.

© Morten Knudsen. Every engine ships with a `.NOTES` header containing author + contact + support info.

- Blog: https://mortenknudsen.net  (aka.ms/morten)
- GitHub: https://github.com/KnudsenMorten
- Support: GitHub Issues on this repo.
