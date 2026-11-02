# Condition module Teams_Room_Like. v1 1:1: TRUE = the user has a licence whose SKU part number is like
# *Microsoft_Teams_Rooms_Pro*, FALSE = it has none. v1 asked Graph per user (Get-MgUserLicenseDetail); v2 reads the
# user's assignedLicenses in the one user pass and maps skuId -> part number from subscribedSkus (one call per run).
@{
    Id          = 'Teams_Room_Like'
    ObjectType  = 'User'
    Description = 'the user has (TRUE) or has not (FALSE) a Teams Rooms Pro licence'
    Select      = @('assignedLicenses')
    Needs       = @('SkuPartNumbers')
    Validate    = { param($Target) if ("$Target" -notmatch '(?i)TRUE|FALSE') { 'the target must be TRUE or FALSE' } }
    Evaluate    = {
        param($Object, $Target, $Context)
        if ($null -eq $Context.SkuPartNumbers) { return @{ Met = $false; Unavailable = 'the tenant licence list was not read' } }
        $licences = Get-EpsValue $Object 'assignedLicenses'      # assigned, not wrapped in @(): that nests the array
        $parts = @(foreach ($l in $licences) {
            $sku = [string](Get-EpsValue $l 'skuId'); if ($sku) { $Context.SkuPartNumbers[$sku] } })
        $room = @($parts | Where-Object { $_ -like '*Microsoft_Teams_Rooms_Pro*' }).Count -gt 0
        $met = ("$Target" -match 'TRUE' -and $room) -or ("$Target" -match 'FALSE' -and -not $room)
        @{ Met = [bool]$met; Actual = "Teams Rooms Pro licence: $(if ($room) { 'yes' } else { 'no' })" }
    }
}
