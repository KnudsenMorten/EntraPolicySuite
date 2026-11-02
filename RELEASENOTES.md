# EntraPolicySuite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

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
