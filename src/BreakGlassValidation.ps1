Function BreakGlassValidation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$BreakGlassAccountsGroup,
        [Parameter()]
        [object]$BreakGlassAccounts

    )

    If (!($BreakGlassAccountsGroup))
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts Group variable is OK !"
            Write-host ""
        }


    If (!($BreakGlassAccounts))
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is empty ..... terminating !!"
            Write-host ""
            Break
        }
    Else
        {
            Write-host ""
            Write-host "Break Glass Accounts variable is OK !"
            Write-host ""
        }
}

