# EntraPolicySuite -- Graph REST and the sources (DESIGN §2a "collect", §7: no Microsoft.Graph module).
# One pass per object type with exactly the fields the enabled rules need (Get-EpsConditionSelect), paged, with
# Retry-After on 429 / 503 / 504.
#
# Two hooks, so the same code runs in the product, in a test and in a live check:
#   $global:EPS_TokenProvider = { param($Resource) <token> }   default: the managed identity (EPS-SqlStore.ps1)
#   $script:EpsHttp           = { param($Method, $Uri, $Headers, $Body) -> @{ Status; Headers; Body } }   tests stub it
# A live check through the Invardia Support app sets the token provider to Get-InvardiaSupportToken.

Set-StrictMode -Off
$script:EpsGraphRoot = 'https://graph.microsoft.com'

function Get-EpsToken {
    param([Parameter(Mandatory)][string]$Resource)
    if ($global:EPS_TokenProvider) { return (& $global:EPS_TokenProvider $Resource) }
    $key = "tok|$Resource"
    if (-not $script:EpsTokens) { $script:EpsTokens = @{} }
    $c = $script:EpsTokens[$key]
    if ($c -and $c.Expires -gt [datetime]::UtcNow) { return $c.Token }
    $t = Get-EpsManagedIdentityToken -Resource $Resource
    $script:EpsTokens[$key] = @{ Token = $t; Expires = [datetime]::UtcNow.AddMinutes(45) }
    $t
}

function Get-EpsHttpRequestBody {
    <# PURE. The body as it goes on the wire. A JSON body (no content type of the caller's own) goes as UTF-8 BYTES with
       'application/json; charset=utf-8' (found 2026-11-12 by PIM: since ~17:55Z Graph sendMail refuses a JSON body with
       non-ASCII text that is not sent as UTF-8 - HTTP 400 RequestBodyRead "missing parameters: Message"; a mail naming a
       user with æ / ø / å is exactly that). A caller's own content type (the storage queue's XML, a form post) is kept. #>
    param($Body, [string]$CallerContentType = '')
    if ($CallerContentType) { return @{ Body = $Body; ContentType = $CallerContentType } }
    if ($Body -is [string]) { return @{ Body = [Text.Encoding]::UTF8.GetBytes($Body); ContentType = 'application/json; charset=utf-8' } }
    @{ Body = $Body; ContentType = 'application/json; charset=utf-8' }
}

$script:EpsHttp = if ($global:EPS_HttpOverride) { $global:EPS_HttpOverride } else {
    {
        param($Method, $Uri, $Headers, $Body)
        $p = @{ Method = $Method; Uri = $Uri; Headers = $Headers; SkipHttpErrorCheck = $true; TimeoutSec = 120 }
        if ($null -ne $Body) {
            # a caller that names its own content type (the storage queue's XML, 2.0.9) - as a parameter, not a header
            $own = ''
            if ($Headers -and $Headers.ContainsKey('Content-Type')) { $own = "$($Headers['Content-Type'])"; $h2 = @{} + $Headers; $h2.Remove('Content-Type'); $p.Headers = $h2 }
            $rb = Get-EpsHttpRequestBody -Body $Body -CallerContentType $own
            $p.Body = $rb.Body; $p.ContentType = $rb.ContentType
        }
        $r = Invoke-WebRequest @p
        @{ Status = [int]$r.StatusCode; Headers = $r.Headers; Body = [string]$r.Content }
    }
}   # $global:EPS_HttpOverride: a test (or a live check) that runs a whole entry script in another scope

function Test-EpsTransportError {
    <# PURE. Did this request get NO HTTP answer at all - a TLS handshake that failed, a connection that was reset or
       refused, a name that did not resolve, a timeout? An HTTP status is never one: it comes back as a status. #>
    param($ErrorRecord)
    $e = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    for ($x = $e; $x; $x = $x.InnerException) {
        if ($x -is [System.Net.Http.HttpRequestException] -or $x -is [System.IO.IOException] -or $x -is [System.Net.Sockets.SocketException] -or
            $x -is [System.Security.Authentication.AuthenticationException] -or $x -is [System.TimeoutException] -or $x -is [System.Threading.Tasks.TaskCanceledException]) { return $true }
        if ("$($x.Message)" -match '(?i)SSL connection could not be established|error occurred while sending the request|connection was (forcibly )?closed|connection (was )?reset|response ended prematurely|No such host is known|HttpClient\.Timeout|request was canceled|timed out') { return $true }
        if ($x -isnot [Exception]) { break }
    }
    $false
}

$script:EpsReadRetryWaitSeconds = 5
function Invoke-EpsHttpRead {
    <# One request that only READS. When it got no HTTP answer at all (Test-EpsTransportError), it is sent ONCE more
       after a short wait - internal 2026-11-13 01:01Z: one failed TLS handshake at the Exchange recipients read failed
       the whole identity report. A second failure throws as before. Never used for a call that changes something. The
       parameter names are the HTTP hook's own (a test's hook sees the caller's variables). #>
    param($Method, $Uri, $Headers, $Body)
    try { return (& $script:EpsHttp $Method $Uri $Headers $Body) }
    catch {
        if (-not (Test-EpsTransportError $_)) { throw }
        $epsReadFirst = (("$($_.Exception.Message)") -split "`n")[0]
        Write-Warning "a read of $(try { ([uri]$Uri).Host } catch { 'the service' }) got no answer ($epsReadFirst) - sent once more"
        Start-Sleep -Seconds $script:EpsReadRetryWaitSeconds
        & $script:EpsHttp $Method $Uri $Headers $Body
    }
}

function Invoke-EpsGraph {
    <#
    .SYNOPSIS
        One Graph call (or every page of a collection with -All). Returns the parsed body, or with -All the items.
        Retries 429 / 503 / 504 after Retry-After (at most -MaxRetry times); any other error throws with Graph's message.
    #>
    # -MaxItems (with -All): stop reading pages once that many items are in (0 = every page) - the analyzer's sign-in cap
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Body, [switch]$All, [switch]$Eventual, [int]$MaxRetry = 6, [int]$MaxItems = 0)
    $uri = if ($Path -match '^https://') { $Path } else { "$script:EpsGraphRoot/$($Path.TrimStart('/'))" }
    $items = [System.Collections.Generic.List[object]]::new()
    $json = if ($null -ne $Body -and $Body -isnot [string]) { $Body | ConvertTo-Json -Depth 10 -Compress } else { $Body }
    while ($uri) {
        $try = 0
        while ($true) {
            $h = @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://graph.microsoft.com')" }
            if ($Eventual) { $h.ConsistencyLevel = 'eventual' }
            # a GET only reads: one with no answer at all is sent once more (Invoke-EpsHttpRead); a write never is
            $r = if ($Method -eq 'GET') { Invoke-EpsHttpRead $Method $uri $h $json } else { & $script:EpsHttp $Method $uri $h $json }
            if ($r.Status -in 429, 503, 504 -and $try -lt $MaxRetry) {
                $try++
                $wait = 0; $ra = if ($r.Headers) { $r.Headers['Retry-After'] }
                if (-not [int]::TryParse([string](@($ra)[0]), [ref]$wait)) { $wait = [math]::Min(60, [math]::Pow(2, $try)) }
                Start-Sleep -Seconds ([math]::Max(1, $wait))
                continue
            }
            break
        }
        if ($r.Status -ge 400) {
            $msg = try { ($r.Body | ConvertFrom-Json).error.message } catch { $r.Body }
            throw "Graph $Method $($uri -replace '\?.*$', '') -> $($r.Status): $msg"
        }
        if ($script:EpsWatchOn) { [EpsRunWatchdog]::Step() }   # STALL-1: a page read is progress (a 429 retry is not)
        $obj = if ($r.Body) { $r.Body | ConvertFrom-Json -Depth 20 }
        if (-not $All) { return $obj }
        foreach ($v in @($obj.value)) { if ($null -ne $v) { $items.Add($v) } }
        $uri = $obj.'@odata.nextLink'
        if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) { $uri = $null }
        # SEC-AUDIT-1 S10: the bearer token goes to Graph only - a next page elsewhere is refused
        if ($uri -and ([uri]$uri).Host -ne ([uri]$script:EpsGraphRoot).Host) { throw "Graph returned a next page on another host ($(([uri]$uri).Host)) - refused" }
    }
    # the items, one by one (", $items" made "-All | Where-Object" see ONE object: the list; "@(...)[0]" the whole list)
    $items.ToArray()
}

function Get-EpsGraphPageSize {
    # gap (4): 999 (Graph's maximum) - smaller after repeated failed runs of the job (Get-EpsShrunkSize, EPS-SqlStore)
    if (Get-Command Get-EpsShrunkSize -ErrorAction SilentlyContinue) { Get-EpsShrunkSize -Base 999 -Min 100 } else { 999 }
}

function Get-EpsUsers {
    # Every user with the given fields, 999 per page (Graph's maximum for users; smaller after repeated failed runs).
    param([Parameter(Mandatory)][string[]]$Select, [string]$Filter)
    $q = "v1.0/users?`$select=$($Select -join ',')&`$top=$(Get-EpsGraphPageSize)"
    if ($Filter) { $q += "&`$filter=$([uri]::EscapeDataString($Filter))&`$count=true" }
    Invoke-EpsGraph -Path $q -All -Eventual:([bool]$Filter)
}

function Get-EpsDevices {
    param([Parameter(Mandatory)][string[]]$Select, [string]$Filter)
    $q = "v1.0/devices?`$select=$($Select -join ',')&`$top=$(Get-EpsGraphPageSize)"
    if ($Filter) { $q += "&`$filter=$([uri]::EscapeDataString($Filter))&`$count=true" }
    Invoke-EpsGraph -Path $q -All -Eventual:([bool]$Filter)
}

function Get-EpsSkuPartNumbers {
    # skuId -> skuPartNumber for the tenant (one call per run; Teams_Room_Like reads it).
    $map = @{}
    foreach ($s in (Invoke-EpsGraph -Path 'v1.0/subscribedSkus?$select=skuId,skuPartNumber' -All)) { $map[[string]$s.skuId] = [string]$s.skuPartNumber }
    $map
}

function Get-EpsEntraGroupMembers {
    # display name -> the set of member object ids, for exactly the groups the MemberOfGroup rules name (v1: by display
    # name, transitive members not included - v1 used Get-MgGroupMember). A name that matches no group is left out, so
    # the rule simply does not match.
    # SEC-AUDIT-1 S2: a display name is not unique - anyone allowed to create a group could create a namesake and pull its
    # members into the rule. So, with -ConnectionString, the name is PINNED to the group's object id the first time it
    # resolves to exactly one group (eps.GroupPin), and later runs read that group by id; a name that matches more than one
    # group (and has no pin) is REFUSED, and so is a pinned group that is gone. Each refusal is a note (-Notes).
    # -Refused (TRUST-1 point 3, Invardia 2026-11-12 Q2): each REFUSED name is added - its membership is UNKNOWN (the
    # MemberOfGroup condition then leaves the tag as it is), never "nobody is a member"
    param([string[]]$GroupNames, [string]$ConnectionString, [System.Collections.Generic.List[string]]$Notes, [System.Collections.Generic.HashSet[string]]$Refused)
    $out = @{}
    $note = { param($m) if ($null -ne $Notes) { $Notes.Add($m) } else { Write-Warning $m } }
    foreach ($name in @($GroupNames | Where-Object { $_ } | Select-Object -Unique)) {
        $gid = $null
        $pin = if ($ConnectionString) { Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $name } -Query "SELECT ObjectId FROM eps.GroupPin WHERE Source = 'Entra' AND Name = @n" }
        if ($pin) {
            $g = try { Invoke-EpsGraph -Path "v1.0/groups/$([guid]$pin)?`$select=id,displayName" } catch { if ("$_" -match '-> 404') { $null } else { throw } }
            if (-not $g) { & $note "group '$name': the pinned group $pin no longer exists - the rule leaves its tags as they are until its pin is cleared"; if ($null -ne $Refused) { [void]$Refused.Add($name) }; continue }
            $gid = [string]$g.id
        } else {
            $esc = $name.Replace("'", "''")
            $groups = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=$([uri]::EscapeDataString("displayName eq '$esc'"))&`$select=id,displayName" -All)
            if (-not $groups.Count) { continue }
            if ($groups.Count -gt 1) { & $note "group '$name': $($groups.Count) groups have this name - refused (the rule leaves its tags as they are until one is pinned)"; if ($null -ne $Refused) { [void]$Refused.Add($name) }; continue }
            $gid = [string]$groups[0].id
            if ($ConnectionString) { Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $name; o = [guid]$gid } -Query "IF NOT EXISTS (SELECT 1 FROM eps.GroupPin WHERE Source = 'Entra' AND Name = @n) INSERT INTO eps.GroupPin (Source, Name, ObjectId) VALUES ('Entra', @n, @o)" | Out-Null }
        }
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in (Invoke-EpsGraph -Path "v1.0/groups/$gid/members?`$select=id&`$top=999" -All)) { [void]$set.Add([string]$m.id) }
        $out[$name] = $set
    }
    $out
}
function Set-EpsUserAttribute {
    # A cloud-only user's extensionAttribute (Graph: onPremisesExtensionAttributes). A synced user is written in AD by
    # the hybrid worker, never here (Entra refuses it for a synced user).
    param([Parameter(Mandatory)][string]$UserId, [Parameter(Mandatory)][string]$Attribute, [AllowEmptyString()][AllowNull()][string]$Value)
    $v = if ([string]::IsNullOrEmpty($Value)) { $null } else { $Value }
    [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/users/$UserId" -Body @{ onPremisesExtensionAttributes = @{ $Attribute = $v } })
}

function Set-EpsDeviceAttribute {
    param([Parameter(Mandatory)][string]$DeviceObjectId, [Parameter(Mandatory)][string]$Attribute, [AllowEmptyString()][AllowNull()][string]$Value)
    $v = if ([string]::IsNullOrEmpty($Value)) { $null } else { $Value }
    [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/devices/$DeviceObjectId" -Body @{ extensionAttributes = @{ $Attribute = $v } })
}
