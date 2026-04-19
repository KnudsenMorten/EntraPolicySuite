#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for IdentityReporter.

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the same folder, fill in your
    values, and the community launcher will dot-source it automatically.

    LauncherConfig.ps1 is .gitignore'd by the global *_LauncherConfig.ps1
    pattern -- your edited copy stays on your machine and never gets
    committed. This sample file is the only version checked into the
    public repo.

    Every variable here corresponds to something the engine reads. Leaving
    one unset is usually fine if the feature that uses it is disabled
    (e.g. if $global:Mail_Identity_Maintenance_SendMail = $false, the
    mail block is skipped).

.NOTES
    Solution       : Entra-Policy-Suite
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>

# --- Tenant / Exchange Online --------------------------------------------------
$global:TenantNameOrganization                                         = '<your-tenant>.onmicrosoft.com'

# --- EntraPolicySuite extension attribute mapping (engine has defaults) -------
$global:EntraPolicySuite_Tagging_User_AccountInfo                      = 'extensionAttribute5'
$global:EntraPolicySuite_Tagging_User_Classification                   = 'extensionAttribute6'
$global:EntraPolicySuite_Tagging_User_Authentication                   = 'extensionAttribute7'
$global:EntraPolicySuite_Tagging_User_Pilot                            = 'extensionAttribute8'

# --- AD OU regex patterns used for cross-validation of synced users -----------
$global:IdentityReporter_UserADSynced_AD_OU_Match                      = 'OU=Users,.*'
$global:IdentityReporter_ServiceAccountADSynced_AD_OU_Match            = 'OU=ServiceAccounts,.*'
$global:IdentityReporter_SharedUserADSynced_AD_OU_Match                = 'OU=SharedUsers,.*'
$global:IdentityReporter_SharedMailboxADSynced_AD_OU_Match             = 'OU=SharedMailboxes,.*'

# --- Per-environment AD search bases + domains (set what you use; rest can stay) ---
$global:AD_LDAP_SearchBase_Internal_Prod_CN                            = '<dn-cn>'
$global:AD_LDAP_SearchBase_Internal_Prod_OU                            = '<dn-ou>'
$global:AD_Domain_Internal_Prod                                        = '<ad.prod.internal.domain>'

$global:AD_LDAP_SearchBase_DMZ_Prod_CN                                 = ''
$global:AD_LDAP_SearchBase_DMZ_Prod_OU                                 = ''
$global:AD_Domain_DMZ_Prod                                             = ''

$global:AD_LDAP_SearchBase_Internal_Dev_CN                             = ''
$global:AD_LDAP_SearchBase_Internal_Dev_OU                             = ''
$global:AD_Domain_Internal_Dev                                         = ''

$global:AD_LDAP_SearchBase_Internal_Test_CN                            = ''
$global:AD_LDAP_SearchBase_Internal_Test_OU                            = ''
$global:AD_Domain_Internal_Test                                        = ''

# --- Mail delivery ------------------------------------------------------------
# Set -SendMail $true and -TO to enable; the engine's mail block is otherwise skipped.
$global:Mail_SendAnonymous                                             = $false
$global:Mail_Identity_Maintenance_SendMail                             = $false
$global:Mail_Identity_Maintenance_TO                                   = @('<ops-team@example.com>')

# --- Log Analytics DCR ingestion ----------------------------------------------
# Set $global:EPSIntegration = $true to enable the DCR upload block.
$global:EPSIntegration                                                 = $false
$global:EPSAzDceNameSrv                                                = 'dce-<your-dce-name>'
$global:EPSAzDcrResourceGroupSrv                                       = 'rg-<your-dcr-rg>'
$global:AzureTenantID                                                  = '<your-tenant-id-guid>'
$global:MainLogAnalyticsWorkspaceResourceId                            = '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>'
$global:AzDcrLogIngestServicePrincipalObjectId                         = '<spn-object-id-guid>'
$global:LogHubUploadPath                                               = ''
