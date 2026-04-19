<#
.SYNOPSIS
    Kusto-Queries - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : Kusto-Queries.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
// Detect Service Accounts that are exposed into cloud - with Sign-ins from Trusted Locations during last 90 days !
let Service_Accounts = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Service_Account"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Service_Accounts)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 1
| where Result == "Success"
| distinct UserDisplayName, UserPrincipalName

#------------------------------------------------------------------------------------------------------------------------

// Detect Service Accounts that are exposed into cloud - with Sign-ins from Non-Trusted Locations during last 90 days !
let Service_Accounts = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Service_Account"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Service_Accounts)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 0
| where Result == "Success"
| distinct UserDisplayName, UserPrincipalName


#------------------------------------------------------------------------------------------------------------------------

// Detect Service Accounts that are exposed into cloud - with Sign-ins from Non-Trusted Locations during last 90 days - Show Sign-ins !
let Service_Accounts = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Service_Account"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Service_Accounts)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 0
| where Result == "Success"

#------------------------------------------------------------------------------------------------------------------------


// Detect Service Accounts that are exposed into cloud with No sign-ins in last 90 days
let Service_Accounts =
    EntraUsersMetadata_CL
    | summarize arg_max(CollectionTime, *) by UserPrincipalName
    | where tostring(UserClassification) =~ "Service_Account"
    | project UPN = tolower(UserPrincipalName);
// All sign-ins (simple presence)
let Signins =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated >= ago(90d)
    | project UPN = tolower(UserPrincipalName);
// Service accounts with NO sign-ins
Service_Accounts
| join kind=leftanti (Signins) on UPN
| order by UPN

#------------------------------------------------------------------------------------------------------------------------

// Detect Shared Device Users that are exposed into cloud - with Sign-ins from Trusted Locations during last 90 days !
let Shared_Device_Users = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Shared_Device_Users"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Shared_Device_Users)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 1
| where Result == "Success"
| distinct UserDisplayName, UserPrincipalName


#------------------------------------------------------------------------------------------------------------------------

// Detect Shared Device Users that are exposed into cloud - with Sign-ins from Non-Trusted Locations during last 90 days !
let Shared_Device_Users = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Shared_Device_Users"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Shared_Device_Users)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 0
| where Result == "Success"
| distinct UserDisplayName, UserPrincipalName


#------------------------------------------------------------------------------------------------------------------------

// Detect Shared Device Users that are exposed into cloud - with Sign-ins from Non-Trusted Locations during last 90 days - Show Sign-ins !
let Shared_Device_Users = EntraUsersMetadata_CL
| summarize CollectionTime = arg_max(CollectionTime,*) by UserPrincipalName
| where UserClassification =~ "Shared_Device_Users"
| project UserPrincipalName;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| extend UPN = tolower(UserPrincipalName)
| where UPN in (Shared_Device_Users)
| extend Result = iff(tolong(ResultType) == 0, "Success", "Failure")
| extend IP = IPAddress
// Parse JSON string into dynamic
| extend NetworkLocationDetails = todynamic(NetworkLocationDetails)
// Expand each location entry
| mv-expand NetworkLocationDetails
| extend TrustedLocation = tostring(NetworkLocationDetails.networkType)
// Always wrap networkNames into array
| extend NamesArray = todynamic(pack_array(NetworkLocationDetails.networkNames))
// Expand names
| mv-expand NamesArray
| extend TrustedName = tostring(NamesArray)
| extend IsTrusted = iif(TrustedLocation == "trustedNamedLocation", 1, 0)
// Summarize back per login
| where IsTrusted == 0
| where Result == "Success"


#------------------------------------------------------------------------------------------------------------------------


// Detect Shared Device Users that are exposed into cloud with No sign-ins in last 90 days
let Shared_Device_Users =
    EntraUsersMetadata_CL
    | summarize arg_max(CollectionTime, *) by UserPrincipalName
    | where UserClassification =~ "Shared_Device_Users"
    | project UPN = tolower(UserPrincipalName);
// All sign-ins (simple presence)
let Signins =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated >= ago(90d)
    | project UPN = tolower(UserPrincipalName);
// Shared Device Users with NO sign-ins
Shared_Device_Users
| join kind=leftanti (Signins) on UPN
| order by UPN  change to shared device users
