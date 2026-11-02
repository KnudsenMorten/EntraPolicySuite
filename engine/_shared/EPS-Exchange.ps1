# EntraPolicySuite -- Exchange Online through its admin REST API, no ExchangeOnlineManagement module (DESIGN §7, D6).
#   POST https://outlook.office365.com/adminapi/beta/<tenantId>/InvokeCommand
#   { "CmdletInput": { "CmdletName": "Get-Recipient", "Parameters": { "ResultSize": "Unlimited" } } }
# The reply is OData: value[] + @odata.nextLink. $select on the URL trims each recipient from ~146 fields to the ones
# asked for (proven 2026-10-29 in a test tenant: 17 recipients, 3 fields, 3.7 KB, one page). Dot-source EPS-Graph.ps1
# first (Get-EpsToken, $script:EpsHttp).

Set-StrictMode -Off
$script:EpsExchangeRoot = 'https://outlook.office365.com/adminapi/beta'

function Invoke-EpsExchangeCommand {
    # One Exchange cmdlet over REST. -All follows every page (each page is the same POST to the nextLink, with the
    # $select put back if the nextLink dropped it). Returns the items (-All) or the parsed reply.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{}, [string[]]$Select, [switch]$All, [int]$MaxRetry = 6)
    $sel = if ($Select) { "`$select=$($Select -join ',')" }
    $uri = "$script:EpsExchangeRoot/$TenantId/InvokeCommand$(if ($sel) { "?$sel" })"
    $body = @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Parameters } } | ConvertTo-Json -Depth 6 -Compress
    $items = [System.Collections.Generic.List[object]]::new()
    $exHost = ([uri]$uri).Host
    while ($uri) {
        $try = 0
        while ($true) {
            $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://outlook.office365.com')" }
            $r = & $script:EpsHttp 'POST' $uri $h $body
            if ($r.Status -in 429, 503, 504 -and $try -lt $MaxRetry) {
                $try++; $wait = 0; $ra = if ($r.Headers) { $r.Headers['Retry-After'] }
                if (-not [int]::TryParse([string](@($ra)[0]), [ref]$wait)) { $wait = [math]::Min(60, [math]::Pow(2, $try)) }
                Start-Sleep -Seconds ([math]::Max(1, $wait)); continue
            }
            break
        }
        if ($r.Status -ge 400) {
            $msg = try { $e = $r.Body | ConvertFrom-Json; if ($e.error.details) { ($e.error.details | ForEach-Object { $_.message }) -join '; ' } else { $e.error.message } } catch { $r.Body }
            throw "Exchange $Cmdlet -> $($r.Status): $msg"
        }
        $obj = if ($r.Body) { $r.Body | ConvertFrom-Json -Depth 20 }
        if (-not $All) { return $obj }
        foreach ($v in @($obj.value)) { if ($null -ne $v) { $items.Add($v) } }
        $uri = $obj.'@odata.nextLink'
        if ($uri -and ([uri]$uri).Host -ne $exHost) { throw "Exchange returned a next page on another host ($(([uri]$uri).Host)) - refused" }   # SEC-AUDIT-1 S10
        if ($uri -and $sel -and $uri -notmatch '[?&]\$select=') { $uri += $(if ($uri -match '\?') { '&' } else { '?' }) + $sel }
    }
    # the items, one by one (", $items" made "-All | Where-Object" see ONE object: the list; "@(...)[0]" the whole list)
    $items.ToArray()
}

function Set-EpsExchangeCustomAttribute {
    # v1's fallback, over REST: a mail-enabled user's extensionAttributeN IS Exchange's CustomAttributeN, and Entra
    # refuses the write through Graph for it - so it is set in Exchange (Set-Mailbox for a mailbox, Set-MailUser for a
    # mail user), which syncs it back to Entra. A cleared value is sent as null.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][string]$RecipientTypeDetails,
          [Parameter(Mandatory)][ValidatePattern('^extensionAttribute([1-9]|1[0-5])$')][string]$Attribute, [AllowEmptyString()][AllowNull()][string]$Value)
    $cmdlet = if ($RecipientTypeDetails -like '*MailUser') { 'Set-MailUser' } elseif ($RecipientTypeDetails -like '*Mailbox') { 'Set-Mailbox' }
              else { throw "Exchange recipient type '$RecipientTypeDetails' has no custom attributes the engine writes" }
    $n = $Attribute -replace '^extensionAttribute', 'CustomAttribute'
    $v = if ([string]::IsNullOrEmpty($Value)) { $null } else { $Value }
    [void](Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet $cmdlet -Parameters @{ Identity = $ObjectId; $n = $v })
    $cmdlet
}

function Get-EpsExchangeRecipients {
    # Entra object id -> RecipientTypeDetails for every recipient, in one pass per run (the Mailbox_* condition
    # modules read it). Recipients without an Entra object (e.g. the DiscoveryMailbox) are left out.
    param([Parameter(Mandatory)][string]$TenantId)
    $map = @{}
    foreach ($r in (Invoke-EpsExchangeCommand -TenantId $TenantId -Cmdlet 'Get-Recipient' -Parameters @{ ResultSize = 'Unlimited' } -Select 'ExternalDirectoryObjectId', 'RecipientTypeDetails' -All)) {
        $id = [string]$r.ExternalDirectoryObjectId
        if ($id) { $map[$id] = [string]$r.RecipientTypeDetails }
    }
    $map
}
