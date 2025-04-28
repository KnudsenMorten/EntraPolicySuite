function EntraAuthenticationStrength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        
        [Parameter()]
        [string]$Description = "",  # Default to an empty string if not provided
        
        [Parameter()]
        [ValidateSet("MFA", "windowsHelloForBusiness", "fido2", "temporaryAccessPassOneTime")]
        [array]$AllowedCombinations,
        
        [Parameter()]
        [string[]]$CombinationConfigurations,
        
        [Parameter()]
        [ValidateSet("custom")]
        [string]$PolicyType,

        [Parameter()]
        [ValidateSet("mfa")]
        [string]$RequirementsSatisfied,

        [Parameter()]
        [switch]$ViewOnly,
        
        [Parameter()]
        [switch]$CreateOnly,
        
        [Parameter()]
        [switch]$ForceUpdate
    )

# Get all existing authentication strength policies
$ExistingPolicies = Get-MgPolicyAuthenticationStrengthPolicy

# Check if the policy already exists
$ExistingPolicy = $ExistingPolicies | Where-Object { $_.displayName -eq $PolicyName }

if ($ViewOnly) {
    return $ExistingPolicy
}

# Building the policy parameters hashtable
    $PolicyParams = @{
        displayName = $PolicyName
    }

    if ($PSBoundParameters.ContainsKey('Description')) {
        $PolicyParams.description = $Description
    }

    if ($PSBoundParameters.ContainsKey('RequirementsSatisfied')) {
        $PolicyParams.requirementsSatisfied = $RequirementsSatisfied
    }

    if ($PSBoundParameters.ContainsKey('AllowedCombinations')) {
        $PolicyParams.allowedCombinations = $AllowedCombinations
    }

    if ($PSBoundParameters.ContainsKey('CombinationConfigurations')) {
        $PolicyParams.combinationConfigurations = $CombinationConfigurations
    }

    if ($ExistingPolicy) {
        if ($ForceUpdate) {
            Write-Host "Updating existing authentication strength policy: $PolicyName"
            Update-MgPolicyAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $ExistingPolicy.id -BodyParameter $PolicyParams
        } else {
            Write-Host "Policy already exists. Use -ForceUpdate to modify it."
        }
    } elseif ($CreateOnly) {
        Write-Host "Creating new authentication strength policy: $PolicyName"
        New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $PolicyParams
    }
}

