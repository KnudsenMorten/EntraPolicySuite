<#
.SYNOPSIS
    ExposureSigninReports - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : ExposureSigninReports.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Identity Reporter - Kusto Queries against Sign-up Log"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@2linkit.net | 40 178 179"
Write-Output "***********************************************************************************************"

#------------------------------------------------------------------------------------------------------------
# Loading Functions, Connectivity & Default variables
#------------------------------------------------------------------------------------------------------------
$ScriptDirectory = $PSScriptRoot
$global:PathScripts = Split-Path -parent $ScriptDirectory
Write-Output ""
Write-Output "Script Directory -> $($global:PathScripts)"

# v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
# One call to Initialize-PlatformAutomationFramework does cert-based
# Connect-AzAccount, fetches Modern secrets from KV, populates
# $global:HighPriv_* / $global:AzureTenantId (public contract), and
# dot-sources Layer-1 platform-defaults.ps1. Zero v1 module imports.
$repoRoot = $PSScriptRoot
while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
    $repoRoot = Split-Path -Parent $repoRoot
}
if (-not $repoRoot) {
    throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
}
$global:PathScripts = $repoRoot
Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
$null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets

#==============================
# USER VARIABLES (EDIT HERE)
#==============================
$WorkspaceId    = $global:MainLogAnalyticsWorkspaceId
$OutputXlsx     = "$global:PathScripts\OUTPUT\Entra_Exposure_User_Reports.xlsx"
$ForceLogin     = $false     # Interactive login if true
$OverwriteXlsx  = $true      # Overwrite existing Excel file if true
#==============================

# --- Helper functions --------------------------------------------------------

function Write-Section($text) {
  Write-Host ""
  Write-Host "==== $text ====" -ForegroundColor Cyan
}

function Ensure-Module {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Host "Installing module: $Name ..." -ForegroundColor Yellow
    try {
      Install-Module -Name $Name -Scope CurrentUser -Force -ErrorAction Stop
    } catch {
      Write-Error "Failed to install $Name. $_"
      throw
    }
  }
  Import-Module $Name -ErrorAction Stop
}

function Ensure-AzContext {
  if ($ForceLogin -or -not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
  }
}

function Invoke-WorkspaceQuery {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Query
  )

  Write-Section "Running query: $Name"

  try {
    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -ErrorAction Stop
  } catch {
    return [pscustomobject]@{
      Name  = $Name
      Error = "Invoke failed: $($_.Exception.Message)"
      Table = $null
      Rows  = @()
    }
  }

  # Some module versions expose Error or ErrorMessage — check both safely
  $hasErrProp = $result.PSObject.Properties.Name -contains 'Error'
  if ($hasErrProp -and $null -ne $result.Error) {
    return [pscustomobject]@{
      Name  = $Name
      Error = "KQL error: $($result.Error.Message)"
      Table = $null
      Rows  = @()
    }
  }
  $hasErrMsgProp = $result.PSObject.Properties.Name -contains 'ErrorMessage'
  if ($hasErrMsgProp -and -not [string]::IsNullOrWhiteSpace($result.ErrorMessage)) {
    return [pscustomobject]@{
      Name  = $Name
      Error = "KQL error: $($result.ErrorMessage)"
      Table = $null
      Rows  = @()
    }
  }

  $rows = @()
  $table0 = $null

  # Normalize across Az versions:
  $hasTables  = $result.PSObject.Properties.Name -contains 'Tables'
  $hasResults = $result.PSObject.Properties.Name -contains 'Results'

  if ($hasTables -and $result.Tables -and $result.Tables.Count -gt 0) {
    # Newer shape: $result.Tables[0] with Columns/Rows arrays
    $table0 = $result.Tables[0]
    $t = $table0
    foreach ($r in $t.Rows) {
      $o = [ordered]@{}
      for ($i = 0; $i -lt $t.Columns.Count; $i++) {
        $o[$t.Columns[$i].Name] = $r[$i]
      }
      $rows += [pscustomobject]$o
    }
  }
  elseif ($hasResults -and $result.Results) {
    # Older shape: $result.Results is an array of hashtables/PSObjects
    foreach ($r in $result.Results) {
      # Ensure a PSCustomObject per row
      $rows += [pscustomobject]$r
    }
    # no formal table metadata in this shape
    $table0 = $null
  }
  else {
    # Nothing recognized returned — emit a friendly diagnostic
    return [pscustomobject]@{
      Name  = $Name
      Error = "Unknown result shape from Invoke-AzOperationalInsightsQuery. Properties: " +
              ($result.PSObject.Properties.Name -join ', ')
      Table = $null
      Rows  = @()
    }
  }

  [pscustomobject]@{
    Name  = $Name
    Error = $null
    Table = $table0
    Rows  = $rows
  }
}

function Export-Worksheet {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)]$Rows
  )
  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  if ($Rows -and $Rows.Count -gt 0) {
    $Rows | Export-Excel -Path $Path -WorksheetName $safeSheet `
      -TableName ($safeSheet -replace '\W','_') -AutoSize -AutoFilter -Append `
      -FreezeTopRow -BoldTopRow
  } else {
    # Ensure a visible sheet exists even with no data
    [pscustomobject]@{ Info = "No rows returned" } | Export-Excel -Path $Path -WorksheetName $safeSheet `
      -TableName ($safeSheet -replace '\W','_') -AutoSize -Append -FreezeTopRow -BoldTopRow
  }
}

# --- Prep environment --------------------------------------------------------

Write-Section "Preparing environment"
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Ensure-Module -Name Az.Accounts
Ensure-Module -Name Az.OperationalInsights
Ensure-Module -Name ImportExcel
Ensure-AzContext

# Ensure output directory; handle overwrite
$xlsxDir = Split-Path -Path $OutputXlsx -Parent
if ($xlsxDir -and -not (Test-Path $xlsxDir)) { New-Item -ItemType Directory -Path $xlsxDir -Force | Out-Null }
if (Test-Path $OutputXlsx) {
  if ($OverwriteXlsx) {
    Remove-Item $OutputXlsx -Force
  }
}

# --- Summary sheet first -----------------------------------------------------

$runInfo = [pscustomobject]@{
  RunAtUTC     = [DateTime]::UtcNow
  RunBy        = $env:USERNAME
  Computer     = $env:COMPUTERNAME
  WorkspaceId  = $WorkspaceId
  ForceLogin   = $ForceLogin
  ScriptPath   = $PSCommandPath
}
Export-Worksheet -Path $OutputXlsx -SheetName 'Summary' -Rows @($runInfo)

# --- KQL Queries (unaltered from your source) --------------------------------

# SERVICE ACCOUNTS
$Kql_Service_Trusted = @'
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
'@

$Kql_Service_NonTrusted = @'
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
'@

$Kql_Service_NonTrusted_Show = @'
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
'@

$Kql_Service_NoSignins = @'
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
'@

# SHARED DEVICE USERS
$Kql_Shared_Trusted = @'
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
'@

$Kql_Shared_NonTrusted = @'
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
'@

$Kql_Shared_NonTrusted_Show = @'
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
'@

$Kql_Shared_NoSignins = @'
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
| order by UPN
'@

# --- Run & Export ------------------------------------------------------------

$queries = @(
  @{ Name = 'Svc_Trusted'            ; Text = $Kql_Service_Trusted },
  @{ Name = 'Svc_NonTrusted'         ; Text = $Kql_Service_NonTrusted },
  @{ Name = 'Svc_NonTrusted_Show'    ; Text = $Kql_Service_NonTrusted_Show },
  @{ Name = 'Svc_NoSignins'          ; Text = $Kql_Service_NoSignins },
  @{ Name = 'Shared_Trusted'         ; Text = $Kql_Shared_Trusted },
  @{ Name = 'Shared_NonTrusted'      ; Text = $Kql_Shared_NonTrusted },
  @{ Name = 'Shared_NonTrusted_Show' ; Text = $Kql_Shared_NonTrusted_Show },
  @{ Name = 'Shared_NoSignins'       ; Text = $Kql_Shared_NoSignins }
)

$errors = @()

foreach ($q in $queries) {
  $res = Invoke-WorkspaceQuery -Name $q.Name -Query $q.Text
  if ($res.Error) {
    $errors += [pscustomobject]@{ Query = $res.Name; Error = $res.Error }
    $errObj = [pscustomobject]@{ Error = $res.Error }
    Export-Worksheet -Path $OutputXlsx -SheetName $res.Name -Rows @($errObj)
  } else {
    Export-Worksheet -Path $OutputXlsx -SheetName $res.Name -Rows $res.Rows
  }
}

if ($errors.Count -gt 0) {
  Write-Section "Errors"
  $errors | Format-Table -AutoSize
  Export-Worksheet -Path $OutputXlsx -SheetName 'Errors' -Rows $errors
}

Write-Section "Done"
Write-Host "Excel file: $OutputXlsx" -ForegroundColor Green

############################################################
# Send Mail with Report
############################################################

    $TitleAlert       = "Identity Correlation (Sign-ins + Exposure in Cloud)" 
    $BodyAlert        = "<font color=red>Identity Correlation (Sign-ins + Exposure in Cloud)</font><br><br>"
    $BodyAlert       += "Attached you will find correlated identity data between Sign-ins + Exposure in Cloud<br><br>"


    $TitleMoreInfo    = "Identity Overview" 
    $SubtitleMoreInfo = "Recommendations" 
    $BodyMoreInfo     = "<font color=blue>(1) Please go through the identities and validate if any should be disabled</font><br>"
    #----------------------------------------------------------------------------------------------------------------------------------------------------------

    $Attachments            = @($OutputXlsx)
    $Channel                = 'Identity'          # See file \CONFIG\DefaultSettings.psm1 for more values
    $MessageClassification  = 'Investigations'            # Alert | Investigations | ProductChanges | ProductInfo | AutomationInfo | Info
    $AlertImpactUrgency     = 'P1'                        # Alert-only: P1 = Critical Business (urgent for business, work impact) | P2 = High (department/location impact, work impact) | P3 = Moderate (Impact:Number of Users) | P4 = Low (Impact:Single user, Urgentcy:Low)

    If ($global:Mail_SendAnonymous -eq $true)
        {
            If ($global:Mail_Identity_Maintenance_SendMail -eq $true)  # Send mail
                {
                    $To = $global:Mail_Identity_Maintenance_TO

                    SendAlertAsMailAnonymous
                }
        }
    ElseIf ($global:Mail_SendAnonymous -eq $false)
        {
            If ($global:Mail_Identity_Maintenance_SendMail -eq $true)  # Send mail
                {
                    $To = $global:Mail_Identity_Maintenance_TO

                    SendAlertAsMailUsingSecureCredentials
                }
        }