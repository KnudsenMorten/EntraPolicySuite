# Entra Policy Suite 2.0

Conditional Access management, user and device tagging, and identity reporting for Microsoft Entra ID - running in
your own Azure subscription as Container Apps with Azure SQL, with a web app your admins sign in to with Microsoft
Entra ID.

> **v1 (the scripts) is unchanged** and stays on the [`v1` branch](https://github.com/KnudsenMorten/EntraPolicySuite/tree/v1)
> with its releases v1.0.1 and v1.0.2. Entra Policy Suite 2.0 is a new major: it reads your v1 rule files and moves them
> into its database (the web app's Import v1 page), and it never changes your v1 install.

## What it does

| Feature | What you get |
|---|---|
| **User and device tagging** | Rules (persona, tag type, value, conditions) write tags to extension attributes on users and devices. Every run is planned first: you preview what would change, then switch a rule set to Apply. |
| **Tag tamper monitor** | A change to a watched tag that Entra Policy Suite did not make is found and alerted; you accept it or restore the tag. |
| **Conditional Access** | The template library as data, a review of your policies against it (template, stage, difference, break-glass), adopt / release, a documentation export, and stage buttons: a SuperAdmin moves an adopted policy one stage (Pilot1, Pilot2, Pilot3, Prod, back, or off) after seeing exactly what changes. Nothing changes a policy by itself. |
| **CA Policy Analyzer** | Analyse policies by persona or series (for example CA2 for the whole CA2xx series), and monitor them with alerts to the team that owns them. |
| **Identity report** | Every user with licences, sign-in activity, MFA methods, roles and devices, plus ready-made gap views; downloadable as a workbook. |
| **Hybrid worker** | For AD-synced users, a domain-joined Windows Server writes the tags in Active Directory. |

Every feature is **off** after the install, and a scheduled run only previews until you switch it to Apply.

## Install

Two lines in PowerShell 7 (Windows, macOS, Linux) or Azure Cloud Shell. You sign in in your browser; no PowerShell
modules, no Azure CLI, no secret.

```powershell
Invoke-WebRequest https://github.com/KnudsenMorten/EntraPolicySuite/releases/latest/download/Start-EpsInstall.ps1 -OutFile Start-EpsInstall.ps1
./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
```

This is the Community install. Pro customers install from invardia.com: <https://invardia.com/support/eps/>.
The 60-day trial uses the same Pro lines; the license then arrives by itself. Pro and the trial open when Invardia
announces them. Everything in Community stays in Community.

Line 2 downloads the latest 2.x release, checks it against the SHA-256 digest GitHub publishes for it, and installs.
To see the plan first, add `-WhatIf` at the end of line 2: it shows every step the installer would take - nothing is
created. A stopped install continues where it stopped when you run the same command again.

| Parameter | Default | What it is |
|---|---|---|
| `-TenantId` | (required) | Your Entra tenant id |
| `-SubscriptionId` | (required) | The subscription to install in |
| `-Location` | westeurope | The Azure region |
| `-ResourceGroup` | rg-eps | The resource group to install into (an install made before 2.0.55 in rg-entrapolicysuite is found and kept) |
| `-Version` | the latest 2.x release | A specific release, for example 2.0.20 |

### Private network

Add `-PrivateNetwork` to the same line to install inside your own virtual network: the web app gets no public address
(you reach it from your network, still behind the Entra sign-in), and the database, Key Vault, job queues and container
registry are created with public access off and reached through private endpoints and private DNS zones.

```powershell
./Start-EpsInstall.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PrivateNetwork
```

| Parameter | What it is |
|---|---|
| `-VnetId` | Your existing virtual network (same region); without it the install creates one from `-VnetAddressPrefix` (default 10.230.0.0/24) |
| `-AppsSubnetName` / `-EndpointsSubnetName` | The subnets for the apps and for the private endpoints (created when missing) |
| `-PrivateDnsZonesResourceGroupId` | Use your central private DNS zones instead of zones in Entra Policy Suite's resource group |
| `-HubVnetId`, `-PeerToHub`, `-LinkZonesToHub` | Peer with your hub network and link the zones to it (both off by default) |

Run a private install from a machine inside your network: it checks DNS before it touches any data, prints the DNS
records your network needs when a name does not resolve, and continues where it stopped when you run it again. It also
writes a hand-off list (and a ready-to-run script for your hub network's owner). An existing public install moves to
the private network with the same command and `-PrivateNetwork`.

**Rights for the person who installs:** Owner on the subscription, and Global Administrator or Privileged Role
Administrator in Microsoft Entra ID (for the engine's Microsoft Graph and Exchange Online permissions and the web app's
sign-in registration).

**What it creates, in one resource group:** three managed identities (engine, scheduler, web app - no client secrets,
no certificates), an Azure SQL database (Microsoft Entra authentication only), a container registry with the image
built inside it, a Container Apps environment with the jobs and the web app, a storage account for the job queues, a
Log Analytics workspace and a Key Vault. The installer's help (`Get-Help ./tools/setup/Install-EntraPolicySuite.ps1
-Full`) lists every permission it grants and why.

## After the install

1. Open the web app address the installer prints and sign in - you are its first SuperAdmin.
2. Optional: `tools/setup/Initialize-EpsMailSender.ps1` sets up the shared mailbox the alerts are sent from.
3. Optional: Overview > Import v1 in the web app brings your v1 rules and settings over (upload the files, see the plan, approve).
4. Switch a feature on in Settings, preview, then go live.

## Folders

| Folder | What is in it |
|---|---|
| `engine` | the engine: shared libraries, condition types, Conditional Access templates, settings |
| `sql` | the database schema (idempotent, additive) and each part's database grants |
| `tools/setup` | the scripts a person runs, each with its `.doc.json` |
| `tools/eps-engine`, `tools/eps-web`, `tools/eps-hybrid-worker` | the engine image, the web app and the hybrid worker |

## Licence

MIT - see [LICENSE](LICENSE). Release notes: [RELEASENOTES.md](RELEASENOTES.md).
