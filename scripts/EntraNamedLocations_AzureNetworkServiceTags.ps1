<#
.SYNOPSIS
    EntraNamedLocations_AzureNetworkServiceTags - engine script in the Entra-Policy-Suite solution.

.NOTES
    Solution       : Entra-Policy-Suite
    File           : EntraNamedLocations_AzureNetworkServiceTags.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Management of Named Locations in Entra ID, baed on service tags"
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


######################################################################################################
# Main Program
######################################################################################################

# === CONFIGURATION ===
$csvPath = "$($global:PathScripts)\DATA\EntraNamedLocations_AzureNetworkServiceTags.csv"
$cacheDir = "$($global:PathScripts)\TEMP\ServiceTagCache"
$outputJsonFile = "$($global:PathScripts)\TEMP\ServiceTags_Public.json"
$region = "westeurope"
$apiVersion = "2022-05-01"
$namedLocationPrefix = "Azure.Network.ServiceTag."

# === PREP ===
$subscriptionId = (Get-AzContext).Subscription.Id
$serviceTagsUrl = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Network/locations/$region/serviceTags?api-version=$apiVersion"

# Get ARM token
$tokenSecure = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenSecure)
)

# Call the Service Tags API
$response = Invoke-RestMethod -Uri $serviceTagsUrl -Headers @{ Authorization = "Bearer $token" } -Method Get
$apiValues = $response.values

# Load service tags from CSV
$tags = Import-Csv -Path $csvPath | Select-Object -ExpandProperty Tag
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

# === Fallback JSON Loader ===
function Get-StaticServiceTagsJson {
    if (-Not (Test-Path $outputJsonFile)) {
        Write-Host "Downloading latest Service Tags JSON metadata page..."
        $confirmationPageHtml = Invoke-WebRequest -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519" -UseBasicParsing | Select-Object -ExpandProperty Content

        # Match the .json link using regex
        $jsonLink = [regex]::Match($confirmationPageHtml, "https://download\.microsoft\.com/download/[^""]+?ServiceTags_Public_\d+\.json").Value

        if (-not $jsonLink) {
            throw "❌ Failed to locate the JSON download link from confirmation page."
        }

        Write-Host "Found JSON link: $jsonLink"
        Write-Host "Downloading JSON file..."

        Invoke-WebRequest -Uri $jsonLink -OutFile $outputJsonFile
        Write-Host "✅ Downloaded latest Service Tags JSON to: $outputJsonFile"
    }

    return Get-Content -Raw -Path $outputJsonFile | ConvertFrom-Json
}

$staticTags = Get-StaticServiceTagsJson

# === MAIN LOOP ===
foreach ($tag in $tags) {
    $locationDisplayName = "$namedLocationPrefix$tag"

    # 1. Try API first
    $matched = $apiValues | Where-Object { $_.name -eq $tag }
    $ipPrefixes = @()

    if ($matched) {
        $ipPrefixes = $matched.properties.addressPrefixes
    } else {
        Write-Warning "Tag '$tag' not found in API. Trying fallback JSON..."
        $staticMatch = $staticTags.values | Where-Object { $_.name -eq $tag }
        if ($staticMatch) {
            $ipPrefixes = $staticMatch.properties.addressPrefixes
            Write-Host "Found '$tag' in fallback static JSON."
        } else {
            Write-Warning "Tag '$tag' not found in static JSON either. Skipping."
            continue
        }
    }

    $ipPrefixes = $ipPrefixes | Sort-Object -Unique
    $cacheFile = Join-Path $cacheDir "$tag.json"
    $previous = if (Test-Path $cacheFile) { Get-Content $cacheFile | ConvertFrom-Json } else { @() }

    if (-not ($ipPrefixes -eq $previous)) {
        Write-Host "Change detected for $tag. Updating Named Location..."

        $existing = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationDisplayName }

        $ipObjects = $ipPrefixes | ForEach-Object {
            @{ "@odata.type" = "#microsoft.graph.ipRange"; cidrAddress = $_ }
        }

        if ($existing) {
            Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existing.Id -BodyParameter @{
                "@odata.type" = "#microsoft.graph.ipNamedLocation"
                displayName = $locationDisplayName
                ipRanges = $ipObjects
                isTrusted = $false
            }
            Write-Host "✅ Updated existing Named Location: $locationDisplayName"
        } else {
            New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{
                "@odata.type" = "#microsoft.graph.ipNamedLocation"
                displayName = $locationDisplayName
                ipRanges = $ipObjects
                isTrusted = $false
            }
            Write-Host "✅ Created new Named Location: $locationDisplayName"
        }

        # Save cache
        $ipPrefixes | ConvertTo-Json -Depth 2 | Set-Content $cacheFile
    } else {
        Write-Host "No changes for $tag."
    }
}

# === DISPLAY COMBINED LIST OF AVAILABLE SERVICE TAGS (API + JSON) ===
$apiNames = $apiValues.name
$staticNames = $staticTags.values.name
$combinedTagList = ($apiNames + $staticNames) | Sort-Object -Unique