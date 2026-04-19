#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for Kusto-Queries.
.DESCRIPTION
    Copy to LauncherConfig.ps1 (same folder) and fill in your SPN values.
    LauncherConfig.ps1 is .gitignore'd so the populated copy stays local.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'
