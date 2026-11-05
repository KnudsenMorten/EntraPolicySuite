# EntraPolicySuite -- GET-STARTED phase 2, the rest (V1-PARITY P7 / P8 / P9; DESIGN §5.10): what Get started CREATES
# besides the groups - the two authentication strengths, the denied-countries location, a trusted (IP) location, and the
# break-glass accounts - exactly as v1's Entra-ConditionalAccess-Management.ps1 does (L197-209, L252-296, L375-387).
#
#   Owner 2026-11-03 "Check + create on approval"; 2026-11-05 "solution must be min 1:1 on pair with the old eps script
#   solution" and "it is always 100% opeator controlled": every change is planned first, shown, and applied by the engine
#   from a SuperAdmin's signed request with a reason.
#
# THIS file is the plan only (pure; the web app's preview and the engine both load it) and the preview state the web app
# builds from the last check (SQL). It writes nothing anywhere. The writes are in EPS-OnboardWrite.ps1 (engine only).

Set-StrictMode -Off

$script:EpsServiceTagPrefix = 'Azure.Network.ServiceTag.'   # v1's $namedLocationPrefix - the service-tag job owns these names
$script:EpsOnboardActions = @('strengths', 'deniedcountries', 'trusted', 'breakglass')

function Test-EpsCidr {
    # an IPv4 or IPv6 range in CIDR form (1.2.3.4/32, 2001:db8::/48) - what Graph accepts for an IP named location
    param([string]$Text)
    $t = "$Text".Trim()
    if ($t -notmatch '^([0-9A-Fa-f:.]+)/(\d{1,3})$') { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$ip)) { return $false }
    $bits = [int]$Matches[2]
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { return ($Matches[1] -match '^\d{1,3}(\.\d{1,3}){3}$' -and $bits -le 32) }
    $bits -le 128
}

function ConvertTo-EpsIpRange {
    # one CIDR -> Graph's ipRange object (v4 or v6, by the address)
    param([Parameter(Mandatory)][string]$Cidr)
    $c = $Cidr.Trim()
    if ($c -match ':') { [ordered]@{ '@odata.type' = '#microsoft.graph.iPv6CidrRange'; cidrAddress = $c } } else { [ordered]@{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = $c } }
}

function Get-EpsStrengthName {
    # the strength's name: the setting (v1's custom config, imported), else the name the template library ships
    param([Parameter(Mandatory)][string]$Key, [hashtable]$Settings = @{}, $Defaults, $Catalog)
    $def = $Defaults.authStrengths[$Key]
    $n = "$($Settings[$def.setting])".Trim()
    if (-not $n) { $n = "$($Catalog.authStrengthDefaults[$Key])" }
    $n
}

function Get-EpsOnboardPlan {
    <#
      ONE operator request, planned (pure). -Action:
        strengths       the missing ones of FIDO + TAP (v1's 11 key models) and WHfB + TAP - v1 creates, it never changes
                        an existing strength (E-CM L252-296: -CreateOnly)
        deniedcountries the denied-countries location as v1 (E-CM L375-387: AF BY CN CU IR KP RU SY UA VE, unknown countries
                        in, client IP lookup); there already: v1's countries it lacks are ADDED, the others kept (v1's
                        -AppendExisting) - never one taken out
        trusted         ONE IP location the operator names (-Location @{ name; ranges; trusted }): made, or its ranges /
                        trust set; never a service-tag location (the job owns those) and never the denied-countries one
        breakglass      the break-glass accounts of EPS's list that are not in the tenant, made as v1 (E-CM L197-209:
                        enabled, the UPN's name as nickname and given name, a generated password that must be changed at
                        the first sign-in - never shown, stored or logged); an account there is never changed
      -State (what the tenant has; the engine reads it live, the preview takes the last check):
        Strengths @{ FIDO / WHfB = @{ Found ($true / $false / $null = not read); Id } }
        Denied    @{ Found; Id; Countries (or $null when not read); IncludeUnknown; Differs }
        Locations $null (not read) or @{ <name lower> = @{ Id; Name; Type ('ip' | 'country'); IsTrusted; Ranges } }
        Accounts  @( @{ Upn; DisplayName; Found } )
      Returns @{ ok; reason; action; summary; items = @( @{ name; do (create | update | skip | refused); detail; body;
      extra } ) }. ok = at least one create / update and nothing refused that blocks it.
    #>
    param([Parameter(Mandatory)][string]$Action, $State = @{}, [string[]]$Names = @(), [hashtable]$Location, [hashtable]$Settings = @{}, $Defaults, $Catalog)
    if (-not $Defaults) { $Defaults = Get-EpsOnboardingDefaults }
    if (-not $Catalog) { $Catalog = Get-EpsCaTemplateCatalog }
    $items = [System.Collections.Generic.List[object]]::new()
    $no = { param($r) @{ ok = $false; reason = $r; action = $Action; summary = ''; items = @($items) } }
    if ($Action -notin $script:EpsOnboardActions) { return (& $no "'$Action' is not something Get started creates ($($script:EpsOnboardActions -join ', '))") }
    switch ($Action) {
        'strengths' {
            $keys = if (@($Names | Where-Object { $_ }).Count) { @($Names) } else { @('FIDO', 'WHfB') }
            foreach ($k in $keys) {
                $def = $Defaults.authStrengths[$k]
                if (-not $def) { $items.Add(@{ name = "$k"; do = 'refused'; detail = 'not one of v1''s two strengths (FIDO, WHfB)' }); continue }
                $nm = Get-EpsStrengthName -Key $k -Settings $Settings -Defaults $Defaults -Catalog $Catalog
                $st = $State.Strengths[$k]
                if ($null -eq $st -or $null -eq $st.Found) { $items.Add(@{ name = $nm; do = 'refused'; detail = 'not read yet - Check now first' }); continue }
                if ($st.Found) { $items.Add(@{ name = $nm; do = 'skip'; detail = 'in the tenant - v1 only creates a strength, it never changes one (change it in Entra if it differs)' }); continue }
                $body = [ordered]@{ displayName = $nm; description = "$($def.description)"; allowedCombinations = @($def.allowedCombinations) }
                $extra = $null
                if ($def.fido2AllowedAAGUIDs) { $extra = [ordered]@{ '@odata.type' = '#microsoft.graph.fido2CombinationConfiguration'; appliesToCombinations = @('fido2'); allowedAAGUIDs = @($def.fido2AllowedAAGUIDs) } }
                $items.Add(@{ name = $nm; do = 'create'; detail = "$(@($def.allowedCombinations) -join ' + ')$(if ($extra) { "; FIDO2 limited to v1's $(@($def.fido2AllowedAAGUIDs).Count) key models" })"; body = $body; extra = $extra; key = $k })
            }
        }
        'deniedcountries' {
            $dc = $Defaults.deniedCountries
            $nm = "$($Settings[$dc.setting])".Trim(); if (-not $nm) { $nm = "$($Catalog.namedLocationDefaults.DeniedCountries)" }
            $st = $State.Denied
            if ($null -eq $st -or $null -eq $st.Found) { $items.Add(@{ name = $nm; do = 'refused'; detail = 'not read yet - Check now first' }); break }
            if (-not $st.Found) {
                $body = [ordered]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; displayName = $nm; countriesAndRegions = @($dc.countries); includeUnknownCountriesAndRegions = [bool]$dc.includeUnknownCountriesAndRegions; countryLookupMethod = "$($dc.countryLookupMethod)" }
                $items.Add(@{ name = $nm; do = 'create'; detail = "$(@($dc.countries) -join ', ')$(if ($dc.includeUnknownCountriesAndRegions) { ' and unknown countries' }); looked up by the client's IP address (v1)"; body = $body }); break
            }
            if ($null -eq $st.Countries) {
                # the preview has only the check's verdict: the engine reads the list before it adds anything
                if ($st.Differs) { $items.Add(@{ name = $nm; do = 'update'; detail = 'adds v1''s countries it lacks (the engine reads the list first; none is taken out)' }) }
                else { $items.Add(@{ name = $nm; do = 'skip'; detail = 'has v1''s countries' }) }
                break
            }
            $have = @($st.Countries | ForEach-Object { "$_".ToUpperInvariant() })
            $add = @($dc.countries | Where-Object { $have -notcontains $_ })
            if (-not $add.Count) { $items.Add(@{ name = $nm; do = 'skip'; detail = "has v1's countries ($($have.Count) in it)" }); break }
            $all = @(@($have) + @($add) | Sort-Object -Unique)
            $body = [ordered]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; displayName = $nm; countriesAndRegions = $all; includeUnknownCountriesAndRegions = [bool]$st.IncludeUnknown }
            $items.Add(@{ name = $nm; do = 'update'; detail = "adds $($add -join ', ') (v1's list); the $($have.Count) there are kept"; body = $body; id = $st.Id })
        }
        'trusted' {
            $L = if ($Location) { $Location } else { @{} }
            $nm = "$($L.name)".Trim()
            $ranges = @(@($L.ranges) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
            $dn = "$($Settings[$Defaults.deniedCountries.setting])".Trim(); if (-not $dn) { $dn = "$($Catalog.namedLocationDefaults.DeniedCountries)" }
            if (-not $nm -or $nm.Length -gt 256) { return (& $no 'a name of 1 to 256 characters') }
            if ($nm.StartsWith($script:EpsServiceTagPrefix, [StringComparison]::OrdinalIgnoreCase)) { return (& $no "names starting '$($script:EpsServiceTagPrefix)' belong to the service-tag job") }
            if ($nm -ieq $dn) { return (& $no "$dn is the denied-countries location - use its own button") }
            $bad = @($ranges | Where-Object { -not (Test-EpsCidr $_) })
            if ($bad.Count) { return (& $no "not an IP range in CIDR form: $($bad -join ', ') (for example 203.0.113.10/32)") }
            if (-not $ranges.Count) { return (& $no 'at least one IP range (CIDR), for example 203.0.113.10/32') }
            if ($ranges.Count -gt 2000) { return (& $no "$($ranges.Count) ranges - a named location takes at most 2000") }
            $trusted = if ($null -eq $L.trusted) { $true } else { [bool]$L.trusted }
            $body = [ordered]@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; displayName = $nm; isTrusted = $trusted; ipRanges = @($ranges | ForEach-Object { ConvertTo-EpsIpRange $_ }) }
            $desc = "$($ranges.Count) range(s): $(@($ranges | Select-Object -First 5) -join ', ')$(if ($ranges.Count -gt 5) { ', ...' }); $(if ($trusted) { 'trusted' } else { 'not trusted' })"
            if ($null -eq $State.Locations) { $items.Add(@{ name = $nm; do = 'create'; detail = "$desc (when the tenant has one by this name, its ranges and trust are set instead)"; body = $body }); break }
            $cur = $State.Locations[$nm.ToLowerInvariant()]
            if (-not $cur) { $items.Add(@{ name = $nm; do = 'create'; detail = $desc; body = $body }); break }
            if ($cur.Type -ne 'ip') { return (& $no "$nm is a $($cur.Type) location, not an IP location - pick another name") }
            $same = ((@($cur.Ranges | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join ',') -eq (@($ranges | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ',')) -and ([bool]$cur.IsTrusted -eq $trusted)
            if ($same) { $items.Add(@{ name = $nm; do = 'skip'; detail = "already $desc" }); break }
            $items.Add(@{ name = $nm; do = 'update'; detail = "$desc (now: $(@($cur.Ranges).Count) range(s), $(if ($cur.IsTrusted) { 'trusted' } else { 'not trusted' }))"; body = $body; id = $cur.Id })
        }
        'breakglass' {
            $acc = @($State.Accounts)
            if (-not $acc.Count) { return (& $no 'no break-glass account in Entra Policy Suite''s list - add them on Get started, step 2, first') }
            $want = @($Names | Where-Object { $_ } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
            foreach ($a in $acc) {
                $upn = "$($a.Upn)".Trim().ToLowerInvariant()
                if ($want.Count -and $want -notcontains $upn) { continue }
                if ($upn -notmatch '^([^@\s]{1,64})@[A-Za-z0-9.-]{3,100}$') { $items.Add(@{ name = $upn; do = 'refused'; detail = 'not a user principal name' }); continue }
                $nick = $Matches[1]
                if ($null -eq $a.Found) { $items.Add(@{ name = $upn; do = 'refused'; detail = 'not read yet - Check now first' }); continue }
                if ($a.Found) { $items.Add(@{ name = $upn; do = 'skip'; detail = 'in the tenant - an existing account is never changed' }); continue }
                $dn = "$($a.DisplayName)".Trim(); if (-not $dn) { $dn = $nick }
                $body = [ordered]@{ accountEnabled = $true; displayName = $dn; userPrincipalName = $upn; mailNickname = $nick; givenName = $nick }
                $items.Add(@{ name = $upn; do = 'create'; detail = "a cloud account '$dn', enabled; a generated password that must be changed at the first sign-in - Entra Policy Suite never shows, stores or logs it: set its password or Temporary Access Pass in Entra, register its FIDO2 key, make it Global Administrator (as v1, the role is yours to give)"; body = $body })
            }
            if ($want.Count -and -not $items.Count) { return (& $no "not in Entra Policy Suite's break-glass list: $($want -join ', ')") }
        }
    }
    $n = { param($d) @($items | Where-Object { $_.do -eq $d }).Count }
    $summary = (@(foreach ($d in 'create', 'update', 'skip', 'refused') { if ((& $n $d)) { "$(& $n $d) $d" } }) -join ', ')
    $todo = (& $n 'create') + (& $n 'update')
    @{ ok = ($todo -gt 0); reason = $(if (-not $todo) { $(if (& $n 'refused') { "nothing can be done yet: $(@($items | Where-Object do -eq 'refused' | ForEach-Object { "$($_.name) ($($_.detail))" }) -join '; ')" } else { 'nothing to change - it is all there' }) }); action = $Action; summary = $summary; items = @($items) }
}

function Get-EpsOnboardPreviewState {
    <#
      The web app's preview (SQL only, no Graph): what the LAST Get started check found, in the plan's state shape. The
      engine reads the tenant again before it changes anything (Read-EpsOnboardWriteState, EPS-OnboardWrite.ps1).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Step, Item, State FROM eps.OnboardingCheck')
    $st = @{}; foreach ($r in $rows) { $st["$($r.Step)|$($r.Item)"] = "$($r.State)" }
    $found = { param($k) switch ($st[$k]) { 'missing' { $false } { $_ -in 'ok', 'check' } { $true } default { $null } } }
    $acc = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT UserPrincipalName, DisplayName FROM eps.BreakGlassAccount WHERE Directory = 'Entra' AND Enabled = 1 ORDER BY UserPrincipalName" | ForEach-Object {
        @{ Upn = "$($_.UserPrincipalName)"; DisplayName = $(if ($_.DisplayName -isnot [DBNull]) { "$($_.DisplayName)" }); Found = (& $found "breakglass|account:$("$($_.UserPrincipalName)")") } })
    @{ Strengths = @{ FIDO = @{ Found = (& $found 'auth|strength:FIDO') }; WHfB = @{ Found = (& $found 'auth|strength:WHfB') } }
       Denied = @{ Found = (& $found 'locations|denied'); Countries = $null; Differs = ($st['locations|denied'] -eq 'check') }
       Locations = $null; Accounts = $acc }
}

function Get-EpsServiceTagChange {
    <#
      The service-tag job's decision for ONE tag (pure; v1's EntraNamedLocations_AzureNetworkServiceTags.ps1): the prefixes
      found (sorted, unique) against the cache. Write when they changed, or when the named location is missing (v1 kept a
      file cache and did not notice a location deleted in Entra). Returns @{ Write; Reason; Prefixes }.
    #>
    param([string[]]$Found = @(), [string[]]$Cached = @(), [bool]$LocationExists = $true)
    $f = @($Found | Where-Object { $_ } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique)
    $c = @($Cached | Where-Object { $_ } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique)
    if (-not $f.Count) { return @{ Write = $false; Reason = 'no prefixes found - nothing written (the location is kept as it is)'; Prefixes = @() } }
    if (($f -join ',') -ne ($c -join ',')) { $plus = @($f | Where-Object { $c -notcontains $_ }).Count; $minus = @($c | Where-Object { $f -notcontains $_ }).Count; return @{ Write = $true; Reason = "changed: $plus added, $minus gone ($($f.Count) prefixes)"; Prefixes = $f } }
    if (-not $LocationExists) { return @{ Write = $true; Reason = "the named location is missing in the tenant - made again ($($f.Count) prefixes)"; Prefixes = $f } }
    @{ Write = $false; Reason = "no change ($($f.Count) prefixes)"; Prefixes = $f }
}
