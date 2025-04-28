Function EntraGroupsAsHashtable {
    $Entra_ID_Groups_ALL = Get-MgGroup -All

    # order Groups into hash
    $EntraGroupsHashTable = [ordered]@{}
    $Entra_ID_Groups_ALL | ForEach-Object { $EntraGroupsHashTable.add($_.DisplayName,$_) }
    Return $EntraGroupsHashTable
}

