# EntraPolicySuite -- the PRIVATE network install (NET-1, DESIGN §2b, owner 2026-11-02: "do you support both public +
# privte network install like pim and si does"): the spoke network and its two subnets, the privatelink DNS zones,
# one private endpoint per data resource (Azure SQL, Key Vault, the job queues, the registry), the Container Apps
# environment inside the network (internal, its own DNS zone), the optional hub peering / zone links, the network
# hand-off for the network team, the DNS check from the install machine, the registry's build pool, the inside check
# and the final read-back that public access is off. Parameter names are SecurityInsight's, so the products read the same.
# PIM's model (New-PimHostingPrerequisites, Convert-PimToPrivate, New-PimHubPrepareScript), copied, not shared.
# Dot-sourced by EPS-Install.ps1. Everything here runs only when $Ctx.Network.Private is set - the public install never
# calls it.

Set-StrictMode -Off
$script:EpsNetApi = @{ net = '2023-09-01'; dns = '2020-06-01'; graph = '2021-03-01'; perm = '2022-04-01'; acrPool = '2019-06-01-preview'; acaexec = '2024-03-01' }
# the privatelink zones a private install needs, by the public DNS suffix of the name it answers for. The job queues
# are the only storage service EPS uses (EPS-Scheduler: <account>.queue.core.windows.net) - no blob, table or file
# endpoint is made.
$script:EpsPrivateZones = [ordered]@{
    'database.windows.net'   = 'privatelink.database.windows.net'
    'vault.azure.net'        = 'privatelink.vaultcore.azure.net'
    'queue.core.windows.net' = 'privatelink.queue.core.windows.net'
    'azurecr.io'             = 'privatelink.azurecr.io'
}
$script:EpsVnetIdRx = '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$'
$script:EpsRgIdRx = '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/([^/]+?)/?$'
$script:EpsSubnetNameRx = '^[A-Za-z0-9][A-Za-z0-9_.-]{0,78}[A-Za-z0-9_]$'
# the hosts a private install reaches OUTBOUND (the customer's firewall decides; the installer's help lists them)
$script:EpsOutboundHosts = @('graph.microsoft.com', 'login.microsoftonline.com', 'outlook.office365.com', 'management.azure.com', 'invardia.com', 'mcr.microsoft.com (the base images of the build)')

# ---------------------------------------------------------------- addresses (PURE) ----------------------------------
function ConvertFrom-EpsCidr {
    # 'a.b.c.d/n' -> @{ Start; End; Length; Text } (IPv4, the network address itself - host bits set is refused); $null when not
    param([string]$Cidr)
    if ("$Cidr" -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $null }
    $m = $Matches; $o = @([int]$m[1], [int]$m[2], [int]$m[3], [int]$m[4]); $len = [int]$m[5]
    if (@($o | Where-Object { $_ -gt 255 }).Count -or $len -lt 8 -or $len -gt 29) { return $null }
    [uint64]$ip = ([uint64]$o[0] -shl 24) + ([uint64]$o[1] -shl 16) + ([uint64]$o[2] -shl 8) + [uint64]$o[3]
    [uint64]$size = [uint64][math]::Pow(2, 32 - $len)
    if ($ip % $size) { return $null }
    @{ Start = $ip; End = $ip + $size - 1; Length = $len; Text = "$Cidr" }
}
function ConvertTo-EpsCidrText([uint64]$Start, [int]$Length) {
    '{0}.{1}.{2}.{3}/{4}' -f (($Start -shr 24) -band 255), (($Start -shr 16) -band 255), (($Start -shr 8) -band 255), ($Start -band 255), $Length
}
function Test-EpsCidrOverlap($A, $B) { $A -and $B -and $A.Start -le $B.End -and $B.Start -le $A.End }
function Test-EpsCidrInside($Inner, $Outer) { $Inner -and $Outer -and $Inner.Start -ge $Outer.Start -and $Inner.End -le $Outer.End }

# ---------------------------------------------------------------- the plan (PURE) -----------------------------------
function Get-EpsNetworkPlan {
    <#
      PURE. Checks every network parameter of the installer and returns the plan, or @{ Ok = $false; Reason }. -Bound:
      the names the caller GAVE (its $PSBoundParameters.Keys) - a network parameter without -PrivateNetwork is refused,
      never silently ignored. Public (no -PrivateNetwork): @{ Ok; Private = $false } and nothing else.
    #>
    param([Parameter(Mandatory)][hashtable]$P, [string[]]$Bound = @())
    $no = { param($why) @{ Ok = $false; Reason = $why } }
    $netParams = 'VnetId', 'VnetAddressPrefix', 'VnetName', 'AppsSubnetName', 'AppsSubnetPrefix', 'EndpointsSubnetName', 'EndpointsSubnetPrefix', 'PrivateDnsZonesResourceGroupId', 'HubVnetId', 'PeerToHub', 'LinkZonesToHub', 'ConfirmedFromInside'
    if (-not $P.PrivateNetwork) {
        $given = @($netParams | Where-Object { $Bound -contains $_ })
        if ($given) { return (& $no "-$($given -join ', -') belong to a private install: add -PrivateNetwork (or leave them out for the public install)") }
        if ("$($P.WebAppAccess)" -eq 'internal') { return (& $no '-WebAppAccess internal needs -PrivateNetwork (the web app is then reachable from your network only)') }
        return @{ Ok = $true; Private = $false }
    }
    if ($Bound -contains 'WebAppAccess' -and "$($P.WebAppAccess)" -ne 'internal') { return (& $no '-PrivateNetwork means -WebAppAccess internal (no public address); leave -WebAppAccess out or say internal') }
    $plan = [ordered]@{ Ok = $true; Private = $true; WebAppAccess = 'internal'; ConfirmedFromInside = [bool]$P.ConfirmedFromInside
        AppsSubnetName = "$($P.AppsSubnetName)"; EndpointsSubnetName = "$($P.EndpointsSubnetName)"; PeerToHub = [bool]$P.PeerToHub; LinkZonesToHub = [bool]$P.LinkZonesToHub }
    foreach ($k in 'AppsSubnetName', 'EndpointsSubnetName') { if ($plan[$k] -notmatch $script:EpsSubnetNameRx) { return (& $no "-$k '$($plan[$k])' is not a subnet name") } }
    if ($plan.AppsSubnetName -eq $plan.EndpointsSubnetName) { return (& $no '-AppsSubnetName and -EndpointsSubnetName must be two different subnets') }
    if ("$($P.VnetId)") {
        if ("$($P.VnetId)" -notmatch $script:EpsVnetIdRx) { return (& $no "-VnetId '$($P.VnetId)' is not a virtual network resource id (/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<name>)") }
        $plan.VnetId = "$($P.VnetId)"; $plan.VnetSubscription = $Matches[1].ToLowerInvariant(); $plan.VnetResourceGroup = $Matches[2]; $plan.VnetName = $Matches[3]; $plan.CreateVnet = $false
        if ($Bound -contains 'VnetAddressPrefix') { return (& $no '-VnetAddressPrefix is only for a network EPS makes - not with -VnetId (your network keeps its own range)') }
        if ($Bound -contains 'VnetName') { return (& $no '-VnetName is only for a network EPS makes - with -VnetId the name is in the id') }
    } else {
        $v = ConvertFrom-EpsCidr "$($P.VnetAddressPrefix)"
        if (-not $v) { return (& $no "-VnetAddressPrefix '$($P.VnetAddressPrefix)' is not an IPv4 network range (a.b.c.d/n, the network address itself)") }
        if ($v.Length -gt 25) { return (& $no "-VnetAddressPrefix $($v.Text) is too small: at least a /25 (two /26 subnets); a /24 is the usual size") }
        if ("$($P.VnetName)" -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}[A-Za-z0-9_]$') { return (& $no "-VnetName '$($P.VnetName)' is not a virtual network name") }
        $plan.CreateVnet = $true; $plan.VnetName = "$($P.VnetName)"; $plan.VnetAddressPrefix = $v.Text
        # default subnets: the first /26 (the environment), the second /26 (the endpoints)
        if (-not "$($P.AppsSubnetPrefix)") { $plan.AppsSubnetPrefix = ConvertTo-EpsCidrText $v.Start 26 }
        if (-not "$($P.EndpointsSubnetPrefix)") { $plan.EndpointsSubnetPrefix = ConvertTo-EpsCidrText ($v.Start + 64) 26 }
    }
    if ("$($P.AppsSubnetPrefix)") { $plan.AppsSubnetPrefix = "$($P.AppsSubnetPrefix)" }
    if ("$($P.EndpointsSubnetPrefix)") { $plan.EndpointsSubnetPrefix = "$($P.EndpointsSubnetPrefix)" }
    $a = if ($plan.AppsSubnetPrefix) { ConvertFrom-EpsCidr $plan.AppsSubnetPrefix }; $e = if ($plan.EndpointsSubnetPrefix) { ConvertFrom-EpsCidr $plan.EndpointsSubnetPrefix }
    if ($plan.AppsSubnetPrefix -and -not $a) { return (& $no "-AppsSubnetPrefix '$($plan.AppsSubnetPrefix)' is not an IPv4 network range") }
    if ($plan.EndpointsSubnetPrefix -and -not $e) { return (& $no "-EndpointsSubnetPrefix '$($plan.EndpointsSubnetPrefix)' is not an IPv4 network range") }
    if ($a -and $a.Length -gt 27) { return (& $no "-AppsSubnetPrefix $($a.Text) is too small for a Container Apps environment: at least a /27") }
    if ($e -and $e.Length -gt 28) { return (& $no "-EndpointsSubnetPrefix $($e.Text) is too small: at least a /28") }
    if ($a -and $e -and (Test-EpsCidrOverlap $a $e)) { return (& $no "-AppsSubnetPrefix $($a.Text) and -EndpointsSubnetPrefix $($e.Text) overlap") }
    if ($plan.CreateVnet) {
        $v = ConvertFrom-EpsCidr $plan.VnetAddressPrefix
        foreach ($s in @($a, $e)) { if ($s -and -not (Test-EpsCidrInside $s $v)) { return (& $no "the subnet range $($s.Text) is not inside -VnetAddressPrefix $($v.Text)") } }
    }
    if ("$($P.PrivateDnsZonesResourceGroupId)") {
        if ("$($P.PrivateDnsZonesResourceGroupId)" -notmatch $script:EpsRgIdRx) { return (& $no "-PrivateDnsZonesResourceGroupId '$($P.PrivateDnsZonesResourceGroupId)' is not a resource group id (/subscriptions/<id>/resourceGroups/<name>)") }
        $plan.ZonesRgId = "$($P.PrivateDnsZonesResourceGroupId)".TrimEnd('/')
    }
    if ("$($P.HubVnetId)") {
        if ("$($P.HubVnetId)" -notmatch $script:EpsVnetIdRx) { return (& $no "-HubVnetId '$($P.HubVnetId)' is not a virtual network resource id") }
        $plan.HubVnetId = "$($P.HubVnetId)"; $plan.HubName = $Matches[3]
        if ($plan.VnetId -and $plan.VnetId -eq $plan.HubVnetId) { return (& $no '-HubVnetId is the same network as -VnetId - the hub is the network your clients resolve through, EPS runs in a spoke') }
    } elseif ($plan.PeerToHub -or $plan.LinkZonesToHub) { return (& $no '-PeerToHub and -LinkZonesToHub need -HubVnetId') }
    $plan
}

function Test-EpsNetworkPrerequisites {
    <#
      Installer rule 8 (framework §0, from a real install 2026-11-03: the central DNS group lacked two zones, found only
      AFTER resources were made): EVERY prerequisite of the chosen network options, checked BEFORE anything is created -
      the spoke network (-VnetId) and its two subnets (each there, or a range given to make it), the hub (-HubVnetId),
      the central zones' resource group and EVERY privatelink zone EPS needs in it (-PrivateDnsZonesResourceGroupId).
      Reads only (ARM GETs). Returns the missing ones as plain sentences, ALL at once (empty = ready).
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $miss = [System.Collections.Generic.List[string]]::new()
    if (-not $net -or -not $net.Private) { return @() }
    $read = { param($id, $api) try { @{ Ok = $true; Value = (Invoke-EpsArm -Path $id -ApiVersion $api -AllowNotFound) } } catch { @{ Ok = $false; Error = (("$($_.Exception.Message)" -split '->')[-1]).Trim() } } }
    if ($net.VnetId) {
        $v = & $read $net.VnetId $script:EpsNetApi.net
        if (-not $v.Ok) { $miss.Add("the network $($net.VnetName) (-VnetId) cannot be read with your sign-in: $($v.Error)") }
        elseif (-not $v.Value) { $miss.Add("the network -VnetId $($net.VnetId) does not exist") }
        else {
            foreach ($s in @(@{ Name = $net.AppsSubnetName; Prefix = $net.AppsSubnetPrefix; Param = 'AppsSubnetPrefix'; For = 'the Container Apps environment' }, @{ Name = $net.EndpointsSubnetName; Prefix = $net.EndpointsSubnetPrefix; Param = 'EndpointsSubnetPrefix'; For = 'the private endpoints' })) {
                if ($s.Prefix) { continue }   # a range given: the install makes the subnet
                $sr = & $read "$($net.VnetId)/subnets/$($s.Name)" $script:EpsNetApi.net
                if ($sr.Ok -and -not $sr.Value) { $miss.Add("the subnet $($s.Name) (for $($s.For)) is not in $($net.VnetName) - create it, or give -$($s.Param) so the install makes it") }
                elseif (-not $sr.Ok) { $miss.Add("the subnet $($s.Name) in $($net.VnetName) cannot be read with your sign-in: $($sr.Error)") }
            }
        }
    }
    if ($net.HubVnetId) {
        $h = & $read $net.HubVnetId $script:EpsNetApi.net
        if (-not $h.Ok) { $miss.Add("the hub network $($net.HubName) (-HubVnetId) cannot be read with your sign-in: $($h.Error)") }
        elseif (-not $h.Value) { $miss.Add("the hub network -HubVnetId $($net.HubVnetId) does not exist") }
    }
    if ($net.ZonesRgId) {
        # every zone EPS needs, each read (a missing resource group shows as every zone missing)
        foreach ($z in $script:EpsPrivateZones.Values) {
            $zr = & $read "$($net.ZonesRgId)/providers/Microsoft.Network/privateDnsZones/$z" $script:EpsNetApi.dns
            if (-not $zr.Ok) { $miss.Add("the private DNS zone $z cannot be read in $(($net.ZonesRgId -split '/')[-1]): $($zr.Error)") }
            elseif (-not $zr.Value) { $miss.Add("the private DNS zone $z is not in $(($net.ZonesRgId -split '/')[-1]) - create it there (EPS needs it for $(@($script:EpsPrivateZones.Keys | Where-Object { $script:EpsPrivateZones[$_] -eq $z })[0]))") }
        }
    }
    @($miss)
}

function Get-EpsPrivateEndpointAddresses {
    <#
      NET1-PE-ADDRESS (the NET-1 live proof 2026-11-03; framework installer rule 10): a private endpoint's fqdn -> address
      map. Azure leaves properties.customDnsConfigs EMPTY when the endpoint has a private DNS zone group (EPS always
      attaches one), so the addresses are read, in order, from: (1) the endpoint's network interface - each
      ipConfiguration's privateLinkConnectionProperties.fqdns + privateIPAddress; (2) the zone group's recordSets
      (fqdn + ipAddresses); (3) customDnsConfigs. Reads only. -Pe: the endpoint as ARM returned it.
    #>
    param([Parameter(Mandatory)]$Pe, [string]$PePath)
    $map = @{}
    $add = { param($fqdn, $ip) $k = "$fqdn".Trim().TrimEnd('.').ToLowerInvariant(); if ($k -and "$ip" -and -not $map.ContainsKey($k)) { $map[$k] = "$ip" } }
    foreach ($nic in @($Pe.properties.networkInterfaces)) {
        if (-not "$($nic.id)") { continue }
        $n = Invoke-EpsArm -Path "$($nic.id)" -ApiVersion $script:EpsNetApi.net -AllowNotFound
        foreach ($ic in @($n.properties.ipConfigurations)) {
            foreach ($q in @($ic.properties.privateLinkConnectionProperties.fqdns)) { & $add $q $ic.properties.privateIPAddress }
        }
    }
    if ($PePath) {
        $zg = Invoke-EpsArm -Path "$PePath/privateDnsZoneGroups" -ApiVersion $script:EpsNetApi.net -AllowNotFound
        foreach ($g in @($zg.value)) { foreach ($zc in @($g.properties.privateDnsZoneConfigs)) { foreach ($rs in @($zc.properties.recordSets)) { if (@($rs.ipAddresses).Count) { & $add $rs.fqdn @($rs.ipAddresses)[0] } } } }
    }
    foreach ($c in @($Pe.properties.customDnsConfigs)) { if ($c.fqdn -and @($c.ipAddresses).Count) { & $add $c.fqdn @($c.ipAddresses)[0] } }
    $map
}

function Get-EpsZoneLinkName {
    # the name of a zone's link to a network: the network's name + a hash of its full id (two networks of the same name
    # in two resource groups get two links); at most 80 characters
    param([Parameter(Mandatory)][string]$VnetId)
    $h = -join ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($VnetId.ToLowerInvariant()))[0..3] | ForEach-Object { $_.ToString('x2') })
    $n = ($VnetId -split '/')[-1]
    "link-$($n.Substring(0, [math]::Min(60, $n.Length)))-$h"
}

function Get-EpsPeeringNames {
    param([Parameter(Mandatory)][string]$SpokeVnetId, [Parameter(Mandatory)][string]$HubVnetId)
    $s = ($SpokeVnetId -split '/')[-1]; $h = ($HubVnetId -split '/')[-1]
    @{ Spoke = "peer-$s-to-$h"; Hub = "peer-$h-to-$s" }
}

function Get-EpsPrivateEndpointSpecs {
    # PURE. One private endpoint per data resource: what it points at, its group, its zone, the names it answers for.
    # The registry answers for TWO names (the login server and the data endpoint where the layers move) - both need an A
    # record or a pull logs in and then hangs (PIM's trap).
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    @(
        [ordered]@{ Key = 'registry'; Step = 'registryendpoint'; Target = "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)"; GroupId = 'registry'; Zone = 'privatelink.azurecr.io'
                    Fqdns = @("$($n.Registry).azurecr.io", "$($n.Registry).$($Ctx.Location).data.azurecr.io"); Name = "pe-$($n.Registry)-registry" }
        [ordered]@{ Key = 'sql'; Step = 'sqlendpoint'; Target = "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)"; GroupId = 'sqlServer'; Zone = 'privatelink.database.windows.net'
                    Fqdns = @("$($n.SqlServer).database.windows.net"); Name = "pe-$($n.SqlServer)-sql" }
        [ordered]@{ Key = 'queue'; Step = 'queueendpoint'; Target = "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)"; GroupId = 'queue'; Zone = 'privatelink.queue.core.windows.net'
                    Fqdns = @("$($n.Storage).queue.core.windows.net"); Name = "pe-$($n.Storage)-queue" }
        [ordered]@{ Key = 'vault'; Step = 'keyvaultendpoint'; Target = "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)"; GroupId = 'vault'; Zone = 'privatelink.vaultcore.azure.net'
                    Fqdns = @("$($n.KeyVault).vault.azure.net"); Name = "pe-$($n.KeyVault)-vault" }
    )
}

function Get-EpsARecordFor {
    # PURE. 'sql-eps-1.database.windows.net' -> @{ Zone = 'privatelink.database.windows.net'; Record = 'sql-eps-1' }
    param([Parameter(Mandatory)][string]$Fqdn)
    foreach ($suffix in $script:EpsPrivateZones.Keys) {
        if ($Fqdn.ToLowerInvariant().EndsWith(".$suffix")) { return @{ Zone = $script:EpsPrivateZones[$suffix]; Record = $Fqdn.Substring(0, $Fqdn.Length - $suffix.Length - 1).ToLowerInvariant() } }
    }
    $null
}

function Test-EpsPrivateIp([string]$Ip) { $Ip -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' }

# ---------------------------------------------------------------- rights (ARM, read only) --------------------------
function Test-EpsArmActions {
    # may the signed-in person do -Actions at -Scope? Azure's own answer (Microsoft.Authorization/permissions), read
    # BEFORE any change (a hub change is never tried and then half undone). @{ Ok; Missing; Reason }
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string[]]$Actions)
    $perms = try { @((Invoke-EpsArm -Path "$Scope/providers/Microsoft.Authorization/permissions" -ApiVersion $script:EpsNetApi.perm).value) } catch { return @{ Ok = $false; Missing = $Actions; Reason = "your rights on $Scope cannot be read: $($_.Exception.Message)" } }
    $missing = @(foreach ($a in $Actions) {
        $allowed = @($perms | Where-Object { $p = $_; @($p.actions | Where-Object { $a -like $_ }).Count -and -not @($p.notActions | Where-Object { $a -like $_ }).Count }).Count
        if (-not $allowed) { $a }
    })
    @{ Ok = -not $missing.Count; Missing = $missing; Reason = $(if ($missing.Count) { "you may not $($missing -join ', ') on $Scope" } else { 'ok' }) }
}

# ---------------------------------------------------------------- the steps -----------------------------------------
function Get-EpsSpokeVnetId([Parameter(Mandatory)]$Ctx) {
    $net = $Ctx.Network
    if ($net.VnetId) { return $net.VnetId }
    "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/virtualNetworks/$($net.VnetName)"
}

function Read-EpsNetworkFacts {
    # what a resumed install no longer has in memory: the subnet ids, the endpoint addresses, the environment's domain
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $vid = Get-EpsSpokeVnetId $Ctx
    if (-not $net.AppsSubnetId) { $net.AppsSubnetId = "$vid/subnets/$($net.AppsSubnetName)"; $net.EndpointsSubnetId = "$vid/subnets/$($net.EndpointsSubnetName)" }
    if (-not $net.EndpointIps) { $net.EndpointIps = @{} }
    if (-not $net.ZoneIds) {
        # which zones are EPS's own and which the customer's (the hub links and the hand-off need it)
        $net.ZoneIds = @{}; $net.ZoneSource = @{}
        foreach ($z in $script:EpsPrivateZones.Values) {
            $own = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateDnsZones/$z"
            if ($net.ZonesRgId) { $net.ZoneIds[$z] = "$($net.ZonesRgId)/providers/Microsoft.Network/privateDnsZones/$z"; $net.ZoneSource[$z] = 'customer' }
            elseif (Invoke-EpsArm -Path $own -ApiVersion $script:EpsNetApi.dns -AllowNotFound) { $net.ZoneIds[$z] = $own; $net.ZoneSource[$z] = 'eps' }
        }
    }
    if (-not $net.ZoneSource) { $net.ZoneSource = @{} }
    foreach ($s in Get-EpsPrivateEndpointSpecs -Ctx $Ctx) {
        if (@($s.Fqdns | Where-Object { $net.EndpointIps[$_] }).Count -eq $s.Fqdns.Count) { continue }
        $pePath = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateEndpoints/$($s.Name)"
        $pe = Invoke-EpsArm -Path $pePath -ApiVersion $script:EpsNetApi.net -AllowNotFound
        if ($pe) { $a = Get-EpsPrivateEndpointAddresses -Pe $pe -PePath $pePath; foreach ($k in $a.Keys) { $net.EndpointIps[$k] = $a[$k] } }
    }
    if (-not $net.EnvDomain) {
        $ce = Invoke-EpsArm -Path "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($Ctx.Names.Environment)" -ApiVersion $script:EpsApi.aca -AllowNotFound
        if ($ce) { $net.EnvDomain = "$($ce.properties.defaultDomain)".ToLowerInvariant(); $net.EnvStaticIp = "$($ce.properties.staticIp)" }
    }
    if ($net.EnvDomain -and -not $net.EnvZoneId) {
        $ez = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateDnsZones/$($net.EnvDomain)"
        if (Invoke-EpsArm -Path $ez -ApiVersion $script:EpsNetApi.dns -AllowNotFound) { $net.EnvZoneId = $ez }
    }
}

function Invoke-EpsNetworkStep {
    <#
      The spoke and its two subnets. A network EPS makes (-VnetAddressPrefix): vnet-eps with snet-eps-apps (delegated to
      Container Apps) and snet-eps-endpoints (no delegation; private endpoint network policies Enabled, so NSG and
      route tables apply). Your network (-VnetId): only a MISSING subnet is created, and an existing EMPTY apps subnet is
      delegated - nothing else on it changes (never its private endpoint policies). A range that overlaps is refused.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $vid = Get-EpsSpokeVnetId $Ctx; $api = $script:EpsNetApi.net
    $vnet = Invoke-EpsArm -Path $vid -ApiVersion $api -AllowNotFound
    if (-not $vnet) {
        if (-not $net.CreateVnet) { throw "the network $vid does not exist (or you cannot read it)" }
        $vnet = Invoke-EpsArm -Method PUT -Path $vid -ApiVersion $api -Body @{ location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite' }; properties = @{ addressSpace = @{ addressPrefixes = @($net.VnetAddressPrefix) } } }
    }
    if ("$($vnet.location)" -and "$($vnet.location)".Replace(' ', '').ToLowerInvariant() -ne $Ctx.Location) { throw "the network $($vnet.name) is in '$($vnet.location)', the install in '$($Ctx.Location)' - a private install needs its network in the same region" }
    $space = @(@($vnet.properties.addressSpace.addressPrefixes) | ForEach-Object { ConvertFrom-EpsCidr $_ } | Where-Object { $_ })
    # overlap with the hub is refused (a peering of overlapping ranges cannot be made) - when the hub can be read
    if ($net.HubVnetId) {
        $hub = try { Invoke-EpsArm -Path $net.HubVnetId -ApiVersion $api -AllowNotFound } catch { $null }
        foreach ($h in @($hub.properties.addressSpace.addressPrefixes)) { foreach ($s in $space) { if (Test-EpsCidrOverlap (ConvertFrom-EpsCidr $h) $s) { throw "the spoke range $($s.Text) overlaps the hub's $h - refused (they cannot be peered)" } } }
    }
    foreach ($role in 'Apps', 'Endpoints') {
        $name = $net["$($role)SubnetName"]; $sid = "$vid/subnets/$name"
        $sub = Invoke-EpsArm -Path $sid -ApiVersion $api -AllowNotFound
        if (-not $sub) {
            $pfx = $net["$($role)SubnetPrefix"]
            if (-not $pfx) { throw "the subnet $name does not exist in $($vnet.name): give -$($role)SubnetPrefix (a free range inside the network) to create it" }
            $c = ConvertFrom-EpsCidr $pfx
            if (-not @($space | Where-Object { Test-EpsCidrInside $c $_ }).Count) { throw "-$($role)SubnetPrefix $pfx is not inside the network's range ($(@($vnet.properties.addressSpace.addressPrefixes) -join ', '))" }
            foreach ($o in @(Invoke-EpsArm -Path "$vid/subnets" -ApiVersion $api -AllowNotFound).value) {
                foreach ($op in @($o.properties.addressPrefix) + @($o.properties.addressPrefixes) | Where-Object { $_ }) { if (Test-EpsCidrOverlap $c (ConvertFrom-EpsCidr $op)) { throw "-$($role)SubnetPrefix $pfx overlaps the subnet $($o.name) ($op) - refused" } }
            }
            $props = @{ addressPrefix = $pfx; privateEndpointNetworkPolicies = 'Enabled' }
            if ($role -eq 'Apps') { $props.delegations = @(@{ name = 'aca'; properties = @{ serviceName = 'Microsoft.App/environments' } }) }
            $sub = Invoke-EpsArm -Method PUT -Path $sid -ApiVersion $api -Body @{ properties = $props }
        } else {
            $dl = @(@($sub.properties.delegations) | ForEach-Object { "$($_.properties.serviceName)" } | Where-Object { $_ })
            $len = (ConvertFrom-EpsCidr "$(@($sub.properties.addressPrefix) + @($sub.properties.addressPrefixes) | Where-Object { $_ } | Select-Object -First 1)").Length
            if ($role -eq 'Apps') {
                if ($len -gt 27) { throw "the subnet $name is a /$len - a Container Apps environment needs at least a /27" }
                if ($dl -and $dl -notcontains 'Microsoft.App/environments') { throw "the subnet $name is delegated to $($dl -join ', ') - the environment needs a subnet delegated to Microsoft.App/environments (or an empty one)" }
                if (-not $dl) {
                    if (@($sub.properties.ipConfigurations | Where-Object { $_ }).Count -or @($sub.properties.privateEndpoints | Where-Object { $_ }).Count -or @($sub.properties.serviceAssociationLinks | Where-Object { $_ }).Count) { throw "the subnet $name is in use - the environment needs an empty subnet" }
                    # the subnet as it is, plus the delegation - nothing else changes
                    $p2 = @{}; foreach ($k in $sub.properties.PSObject.Properties.Name) { if ($k -notin 'provisioningState', 'etag', 'purpose') { $p2[$k] = $sub.properties.$k } }
                    $p2.delegations = @(@{ name = 'aca'; properties = @{ serviceName = 'Microsoft.App/environments' } })
                    $sub = Invoke-EpsArm -Method PUT -Path $sid -ApiVersion $api -Body @{ properties = $p2 }
                }
            } elseif ($dl) { throw "the subnet $name is delegated to $($dl -join ', ') - private endpoints need a subnet without a delegation" }
        }
        $net["$($role)SubnetId"] = $sid
    }
    $net.ResolvedVnetId = $vid
}

function Get-EpsLinkedZones {
    # the privatelink zones that ALREADY answer in the spoke (a zone of the same name linked to it from anywhere): zone
    # name -> zone id. Azure Resource Graph, read only. Only for a network the customer brought (-VnetId).
    param([Parameter(Mandatory)][string]$VnetId)
    $q = "resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' | where tolower(tostring(properties.virtualNetwork.id)) == '$($VnetId.ToLowerInvariant())' | project id"
    $r = Invoke-EpsArm -Method POST -Path '/providers/Microsoft.ResourceGraph/resources' -ApiVersion $script:EpsNetApi.graph -Body @{ query = $q }
    $out = @{}
    foreach ($row in @($r.data)) { $zid = "$($row.id)" -replace '(?i)/virtualNetworkLinks/[^/]+$', ''; $out[($zid -split '/')[-1].ToLowerInvariant()] = $zid }
    $out
}

function Invoke-EpsDnsZonesStep {
    <#
      The privatelink zones. With -PrivateDnsZonesResourceGroupId: the customer's central zones are USED and nothing is
      written there (a missing zone or a missing link to the spoke goes on the hand-off list); no spoke-local zone of the
      same name is made. Without it: a zone the spoke already links is reused, any other is made in EPS's resource group
      and linked to the spoke. Ambiguous (the spoke links a same-name zone from elsewhere AND central zones are given):
      refused - the names would resolve from two places.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)"; $vid = Get-EpsSpokeVnetId $Ctx; $api = $script:EpsNetApi.dns
    $linked = if ($net.VnetId) { try { Get-EpsLinkedZones -VnetId $vid } catch { $net.Notes += "the zones already linked to $($net.VnetName) could not be read ($($_.Exception.Message)) - check that no same-name zone answers there"; @{} } } else { @{} }
    $net.ZoneIds = @{}; $net.ZoneSource = @{}; $net.MissingZones = @(); $net.MissingLinks = @()
    foreach ($z in $script:EpsPrivateZones.Values) {
        $other = $linked[$z]
        if ($net.ZonesRgId) {
            if ($other -and -not $other.StartsWith("$($net.ZonesRgId)/", [StringComparison]::OrdinalIgnoreCase)) { throw "ambiguous DNS: the network already links '$z' from $other, and -PrivateDnsZonesResourceGroupId names other zones - remove one of them (refused)" }
            $zid = "$($net.ZonesRgId)/providers/Microsoft.Network/privateDnsZones/$z"
            if (Invoke-EpsArm -Path $zid -ApiVersion $api -AllowNotFound) {
                $net.ZoneIds[$z] = $zid; $net.ZoneSource[$z] = 'customer'
                if (-not $other) { $net.MissingLinks += $z }
            } else { throw "the private DNS zone $z is not in $(($net.ZonesRgId -split '/')[-1]) - the preflight checks every zone before anything is made; create it and run the install again" }
            continue
        }
        if ($other) { $net.ZoneIds[$z] = $other; $net.ZoneSource[$z] = 'reused'; continue }
        $zid = "$rg/providers/Microsoft.Network/privateDnsZones/$z"
        [void](Invoke-EpsArm -Method PUT -Path $zid -ApiVersion $api -Body @{ location = 'global'; tags = @{ product = 'EntraPolicySuite' } })
        [void](Invoke-EpsArm -Method PUT -Path "$zid/virtualNetworkLinks/$(Get-EpsZoneLinkName -VnetId $vid)" -ApiVersion $api -Body @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $vid }; registrationEnabled = $false } })
        $net.ZoneIds[$z] = $zid; $net.ZoneSource[$z] = 'eps'
    }
}

function Invoke-EpsPrivateEndpointStep {
    # one data resource's private endpoint in the endpoints subnet + its record in the zone (the endpoint's zone group
    # writes the A record(s) - for the registry both names). Reads back the addresses it got.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Key)
    $net = $Ctx.Network; Read-EpsNetworkFacts -Ctx $Ctx
    $s = @(Get-EpsPrivateEndpointSpecs -Ctx $Ctx | Where-Object { $_.Key -eq $Key })[0]
    $pe = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateEndpoints/$($s.Name)"
    [void](Invoke-EpsArm -Method PUT -Path $pe -ApiVersion $script:EpsNetApi.net -Body @{ location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite' }
        properties = @{ subnet = @{ id = $net.EndpointsSubnetId }; privateLinkServiceConnections = @(@{ name = $s.Name; properties = @{ privateLinkServiceId = $s.Target; groupIds = @($s.GroupId) } }) } })
    if (-not $net.ZoneIds) { $net.ZoneIds = @{} }
    if (-not $net.ZoneIds[$s.Zone]) {
        # resumed: the zone's id is read again (EPS's own, or the customer's)
        $cand = if ($net.ZonesRgId) { "$($net.ZonesRgId)/providers/Microsoft.Network/privateDnsZones/$($s.Zone)" } else { "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateDnsZones/$($s.Zone)" }
        if (Invoke-EpsArm -Path $cand -ApiVersion $script:EpsNetApi.dns -AllowNotFound) { $net.ZoneIds[$s.Zone] = $cand }
    }
    if ($net.ZoneIds[$s.Zone]) {
        [void](Invoke-EpsArm -Method PUT -Path "$pe/privateDnsZoneGroups/default" -ApiVersion $script:EpsNetApi.net -Body @{ properties = @{ privateDnsZoneConfigs = @(@{ name = $s.Zone.Replace('.', '-'); properties = @{ privateDnsZoneId = $net.ZoneIds[$s.Zone] } }) } })
    }
    $r = Invoke-EpsArm -Path $pe -ApiVersion $script:EpsNetApi.net
    $st = "$(@($r.properties.privateLinkServiceConnections)[0].properties.privateLinkServiceConnectionState.status)"
    if ($st -and $st -ne 'Approved') { throw "the private endpoint $($s.Name) is '$st', not Approved" }
    $a = Get-EpsPrivateEndpointAddresses -Pe $r -PePath $pe; foreach ($k in $a.Keys) { $net.EndpointIps[$k] = $a[$k] }   # NET1-PE-ADDRESS: the NIC first, never customDnsConfigs alone
    $miss = @($s.Fqdns | Where-Object { -not $net.EndpointIps[$_.ToLowerInvariant()] })
    if ($miss) { throw "the private endpoint $($s.Name) gives no address for $($miss -join ', ')" }
}

function New-EpsPrivateEnvironmentBody {
    # PURE. The environment inside the spoke: the apps subnet, internal (no public address), workload profiles
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$LawCustomerId, [Parameter(Mandatory)][string]$LawKey)
    @{ location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; version = $Ctx.Version }
       properties = @{ workloadProfiles = @(@{ name = 'Consumption'; workloadProfileType = 'Consumption' })
           vnetConfiguration = @{ infrastructureSubnetId = $Ctx.Network.AppsSubnetId; internal = $true }
           appLogsConfiguration = @{ destination = 'log-analytics'; logAnalyticsConfiguration = @{ customerId = $LawCustomerId; sharedKey = $LawKey } } } }
}

function Invoke-EpsEnvironmentDnsStep {
    # the environment's own zone (its default domain) in EPS's resource group, always: '@', '*' and '*.internal' to its
    # static address; linked to the spoke
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $net.EnvDomain = $null; Read-EpsNetworkFacts -Ctx $Ctx
    if (-not $net.EnvDomain -or -not $net.EnvStaticIp) { throw "the environment $($Ctx.Names.Environment) reports no default domain / static address yet" }
    $api = $script:EpsNetApi.dns
    $zid = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.Network/privateDnsZones/$($net.EnvDomain)"
    [void](Invoke-EpsArm -Method PUT -Path $zid -ApiVersion $api -Body @{ location = 'global'; tags = @{ product = 'EntraPolicySuite' } })
    foreach ($r in '@', '*', '*.internal') { [void](Invoke-EpsArm -Method PUT -Path "$zid/A/$r" -ApiVersion $api -Body @{ properties = @{ ttl = 300; aRecords = @(@{ ipv4Address = $net.EnvStaticIp }) } }) }
    $vid = Get-EpsSpokeVnetId $Ctx
    [void](Invoke-EpsArm -Method PUT -Path "$zid/virtualNetworkLinks/$(Get-EpsZoneLinkName -VnetId $vid)" -ApiVersion $api -Body @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $vid }; registrationEnabled = $false } })
    $net.EnvZoneId = $zid
}

function Invoke-EpsHubStep {
    <#
      Optional, both off by default (the hub owner does them, or runs the generated prepare-hub script). -PeerToHub: both
      sides of the peering, only when Azure says you may write both (read BEFORE any change); never half a peering - when
      the second side fails, the first is deleted again. -LinkZonesToHub: EPS's own zones linked to the hub (the
      customer's central zones are never touched). Whatever is not done goes on the hand-off list. @{ Peering; Links }
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $out = @{ Peering = 'not asked'; Links = 'not asked' }
    if (-not $net.HubVnetId) { $net.Hub = $out; return $out }
    Read-EpsNetworkFacts -Ctx $Ctx
    $api = $script:EpsNetApi.net; $spoke = Get-EpsSpokeVnetId $Ctx; $hub = $net.HubVnetId
    $pn = Get-EpsPeeringNames -SpokeVnetId $spoke -HubVnetId $hub
    $body = { param($remote) @{ properties = @{ remoteVirtualNetwork = @{ id = $remote }; allowVirtualNetworkAccess = $true; allowForwardedTraffic = $true; allowGatewayTransit = $false; useRemoteGateways = $false } } }
    if ($net.PeerToHub) {
        $need = @('Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write', 'Microsoft.Network/virtualNetworks/peer/action')
        $rs = Test-EpsArmActions -Scope $spoke -Actions $need; $rh = Test-EpsArmActions -Scope $hub -Actions $need
        if (-not $rs.Ok -or -not $rh.Ok) { $out.Peering = "not made - $(@($rs, $rh | Where-Object { -not $_.Ok } | ForEach-Object Reason) -join '; ') (on the hand-off list)" }
        else {
            $sp = "$spoke/virtualNetworkPeerings/$($pn.Spoke)"; $hp = "$hub/virtualNetworkPeerings/$($pn.Hub)"
            $hadSpoke = [bool](Invoke-EpsArm -Path $sp -ApiVersion $api -AllowNotFound)
            [void](Invoke-EpsArm -Method PUT -Path $sp -ApiVersion $api -Body (& $body $hub))
            try { [void](Invoke-EpsArm -Method PUT -Path $hp -ApiVersion $api -Body (& $body $spoke)) }
            catch {
                if (-not $hadSpoke) { try { [void](Invoke-EpsArm -Method DELETE -Path $sp -ApiVersion $api -AllowNotFound) } catch { } }
                throw "the hub side of the peering could not be made ($($_.Exception.Message)) - the spoke side was removed again (never half a peering)"
            }
            $state = ''
            for ($i = 0; $i -lt 12; $i++) {
                $a = Invoke-EpsArm -Path $sp -ApiVersion $api; $b = Invoke-EpsArm -Path $hp -ApiVersion $api
                $state = "$($a.properties.peeringState)/$($b.properties.peeringState)"
                if ($state -eq 'Connected/Connected') { break }
                Start-Sleep -Seconds ($Ctx.PollSeconds ?? 10)
            }
            if ($state -ne 'Connected/Connected') { throw "the peering is $state, not Connected on both sides" }
            $out.Peering = "Connected ($($pn.Spoke) / $($pn.Hub))"
        }
    }
    if ($net.LinkZonesToHub) {
        $r = Test-EpsArmActions -Scope $hub -Actions @('Microsoft.Network/virtualNetworks/join/action')
        if (-not $r.Ok) { $out.Links = "not made - $($r.Reason) (on the hand-off list)" }
        else {
            $own = @(@($net.ZoneIds.Keys | Where-Object { $net.ZoneSource[$_] -eq 'eps' } | ForEach-Object { $net.ZoneIds[$_] }) + @($net.EnvZoneId) | Where-Object { $_ })
            foreach ($zid in $own) { [void](Invoke-EpsArm -Method PUT -Path "$zid/virtualNetworkLinks/$(Get-EpsZoneLinkName -VnetId $hub)" -ApiVersion $script:EpsNetApi.dns -Body @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $hub }; registrationEnabled = $false } }) }
            $out.Links = "$($own.Count) zone(s) linked to the hub"
        }
    }
    $net.Hub = $out; $out
}

function Get-EpsNetworkHandoff {
    <#
      PURE (from what the steps found). The network team's list: the peering, the zones and their exact A records, the
      outbound hosts, and the check to run. Lines of text.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $spoke = Get-EpsSpokeVnetId $Ctx
    $L = [System.Collections.Generic.List[string]]::new()
    $L.Add("EntraPolicySuite $($Ctx.Version) - network hand-off for $($Ctx.Names.ResourceGroup) ($($Ctx.Location))")
    $L.Add("Spoke network: $spoke$(if ($net.VnetAddressPrefix) { " ($($net.VnetAddressPrefix))" })")
    $L.Add("  apps subnet $($net.AppsSubnetName) (delegated to Microsoft.App/environments), endpoints subnet $($net.EndpointsSubnetName)")
    $L.Add('')
    $L.Add('1. Peering with your hub')
    if (-not $net.HubVnetId) { $L.Add('   No -HubVnetId was given: peer the spoke above with the network your clients and your DNS resolver use (both directions, allow virtual network access and forwarded traffic, no gateway transit).') }
    elseif ("$($net.Hub.Peering)" -like 'Connected*') { $L.Add("   Done: $($net.Hub.Peering)") }
    else {
        $pn = Get-EpsPeeringNames -SpokeVnetId $spoke -HubVnetId $net.HubVnetId
        $L.Add("   To do ($($net.Hub.Peering)): '$($pn.Hub)' on $($net.HubVnetId) -> the spoke, and '$($pn.Spoke)' on the spoke -> the hub;")
        $L.Add('   allow virtual network access and forwarded traffic, no gateway transit, no remote gateways. prepare-hub-entrapolicysuite.ps1 does it.')
    }
    $L.Add('')
    $L.Add('2. DNS: these names must resolve to these addresses wherever the install, the hybrid worker or your browser resolves them')
    $L.Add('   (link the zones to your hub, or add the records to your DNS):')
    foreach ($s in Get-EpsPrivateEndpointSpecs -Ctx $Ctx) {
        foreach ($f in $s.Fqdns) {
            $rec = Get-EpsARecordFor -Fqdn $f
            $L.Add(("   {0,-58} A {1,-15}  zone {2}, record '{3}'" -f $f, $(if ($net.EndpointIps -and $net.EndpointIps[$f.ToLowerInvariant()]) { $net.EndpointIps[$f.ToLowerInvariant()] } else { '(the endpoint''s address)' }), $rec.Zone, $rec.Record))
        }
    }
    if ($net.EnvDomain) { foreach ($r in '@', '*', '*.internal') { $L.Add(("   {0,-58} A {1,-15}  zone {2}, record '{3}' (the web app)" -f $(if ($r -eq '@') { $net.EnvDomain } else { "$r.$($net.EnvDomain)" }), $net.EnvStaticIp, $net.EnvDomain, $r)) } }
    foreach ($z in @($net.MissingZones | Where-Object { $_ })) { $L.Add("   MISSING in your zones resource group $($net.ZonesRgId): the zone $z - create it there and link it to the spoke (EPS writes nothing there)") }
    foreach ($z in @($net.MissingLinks | Where-Object { $_ })) { $L.Add("   Your zone $z is not linked to the spoke: link it ($($net.ZonesRgId))") }
    if ($net.HubVnetId) { $L.Add("   Zone links to the hub: $($net.Hub.Links)") }
    $L.Add('')
    $L.Add('3. Outbound HTTPS from the apps subnet (default outbound, or allow them on your firewall):')
    foreach ($h in $script:EpsOutboundHosts) { $L.Add("   $h") }
    $L.Add('')
    $L.Add('4. The check, from a machine in your network: each name above answers with its private address, e.g.')
    $L.Add("   Resolve-DnsName $($Ctx.Names.SqlServer).database.windows.net   (expect $(if ($net.EndpointIps) { $net.EndpointIps["$($Ctx.Names.SqlServer).database.windows.net"] } else { 'the private address' }))")
    $L.Add('   Then run the install again from that machine - it resumes.')
    foreach ($x in @($net.Notes)) { if ($x) { $L.Add("Note: $x") } }
    @($L)
}

function New-EpsHubPrepareScript {
    <#
      The script the hub owner runs (PIM's New-PimHubPrepareScript, copied): ONE self-contained file, PowerShell 7, a
      browser sign-in as the hub owner, no module, no other file. Without -Apply it prints its plan. With -Apply: the hub
      side of the peering (and the spoke side when that account may write it), EPS's zones linked to the hub, and - when
      the installing person's object id is baked in - Network Contributor for them on the hub (so a re-run of the
      install with -PeerToHub / -LinkZonesToHub can finish). It never deletes anything; running it twice is safe.
      Returns @{ FileName; Text }.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; $spoke = Get-EpsSpokeVnetId $Ctx; $hub = $net.HubVnetId
    if (-not $hub) { throw 'no -HubVnetId: there is no hub to prepare' }
    $pn = Get-EpsPeeringNames -SpokeVnetId $spoke -HubVnetId $hub
    $zones = @(@($net.ZoneIds.Keys | Where-Object { $net.ZoneSource[$_] -eq 'eps' } | ForEach-Object { $net.ZoneIds[$_] }) + @($net.EnvZoneId) | Where-Object { $_ })
    foreach ($v in @($spoke, $hub) + $zones) { if ("$v" -match "['`"``\r\n]") { throw "a value contains a quote or a line break: '$v'" } }
    $oid = if ("$($Ctx.Person.PrincipalType)" -in '', 'User' -and "$($Ctx.Person.ObjectId)" -match '^[0-9a-fA-F-]{36}$') { "$($Ctx.Person.ObjectId)" } else { '' }
    # the browser sign-in, exactly as the loaded EPS-SignIn.ps1 defines it (one source; the file carries a copy)
    $fns = foreach ($f in 'Test-EpsCloudShell', 'ConvertFrom-EpsJwt', 'Save-EpsToken', 'Get-EpsInteractiveToken') {
        $c = Get-Command -Name $f -CommandType Function -ErrorAction SilentlyContinue
        if (-not $c) { throw "the sign-in helper $f is not loaded - the hub script would not be complete" }
        $fd = $c.ScriptBlock.Ast; if ($fd -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fd = $fd.Parent }
        ($fd.Extent.Text -replace "`r`n", "`n")
    }
    $L = [System.Collections.Generic.List[string]]::new()
    $L.Add('<#'); $L.Add('.SYNOPSIS')
    $L.Add("    EntraPolicySuite - PREPARE THE HUB NETWORK for the spoke $(($spoke -split '/')[-1]). Generated $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC by the EntraPolicySuite install.")
    $L.Add('.DESCRIPTION')
    $L.Add('    Run it as the owner of the hub network: PowerShell 7 on any machine, a browser sign-in, no Azure CLI, no module, no')
    $L.Add('    other file. Without -Apply it only shows what it would do. It never deletes anything; running it twice is safe.')
    $L.Add("      1. the peering '$($pn.Hub)' on the hub -> the spoke (and '$($pn.Spoke)' on the spoke -> the hub when you may write the spoke)")
    foreach ($z in $zones) { $L.Add("      -  links the private DNS zone $(($z -split '/')[-1]) to the hub") }
    if ($oid) { $L.Add("      2. Network Contributor on the hub for the person who installs EntraPolicySuite ($oid), so the install can finish its side") }
    $L.Add('      3. shows the state of both sides of the peering.')
    $L.Add('.PARAMETER Apply'); $L.Add('    Make the changes. Without it the script prints its plan and changes nothing.')
    $L.Add('.NOTES')
    $L.Add('    Needs: Network Contributor (or Owner) on the hub network; Private DNS Zone Contributor on the zones above to link them;')
    $L.Add('    Owner or User Access Administrator on the hub network for step 2. Reaches login.microsoftonline.com and management.azure.com.')
    $L.Add('#>')
    $L.Add('#Requires -Version 7.0')
    $L.Add('[CmdletBinding()] param([switch]$Apply)')
    $L.Add('$ErrorActionPreference = ''Stop''')
    $L.Add("`$HubId = '$hub'"); $L.Add("`$SpokeId = '$spoke'"); $L.Add("`$HubPeering = '$($pn.Hub)'"); $L.Add("`$SpokePeering = '$($pn.Spoke)'")
    $L.Add("`$Zones = @($(($zones | ForEach-Object { "'$_'" }) -join ', '))"); $L.Add("`$Who = '$oid'"); $L.Add("`$TenantId = '$($Ctx.TenantId)'")
    $L.Add("`$LinkName = '$(Get-EpsZoneLinkName -VnetId $hub)'")
    $L.Add('$script:EpsCliClientId = ''04b07795-8ddb-461a-bbee-02f9e1bf7b46''   # Microsoft Azure CLI public client, over REST (the CLI itself is not used)')
    foreach ($f in $fns) { $L.Add($f) }
    $L.Add(@'
function Arm([string]$Method, [string]$Path, [string]$Api, $Body) {
    $h = @{ Authorization = "Bearer $(Get-EpsInteractiveToken -Resource 'https://management.azure.com' -TenantId $TenantId)" }
    $a = @{ Method = $Method; Uri = "https://management.azure.com$($Path)?api-version=$Api"; Headers = $h; SkipHttpErrorCheck = $true; StatusCodeVariable = 'sc' }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 20); $a.ContentType = 'application/json' }
    $r = Invoke-RestMethod @a
    if ($sc -eq 404 -and $Method -eq 'GET') { return $null }
    if ($sc -ge 400) { throw "$Method $Path -> $sc $($r | ConvertTo-Json -Depth 5 -Compress)" }
    $r
}
$peer = { param($remote) @{ properties = @{ remoteVirtualNetwork = @{ id = $remote }; allowVirtualNetworkAccess = $true; allowForwardedTraffic = $true; allowGatewayTransit = $false; useRemoteGateways = $false } } }
Write-Host "Hub:   $HubId"; Write-Host "Spoke: $SpokeId"
Write-Host "Plan:  peering $HubPeering on the hub; $SpokePeering on the spoke if you may; $($Zones.Count) zone link(s) to the hub$(if ($Who) { "; Network Contributor on the hub for $Who" })"
if (-not $Apply) { Write-Host 'Nothing changed. Run again with -Apply.' -ForegroundColor Yellow; return }
[void](Arm PUT "$HubId/virtualNetworkPeerings/$HubPeering" '2023-09-01' (& $peer $SpokeId))
try { [void](Arm PUT "$SpokeId/virtualNetworkPeerings/$SpokePeering" '2023-09-01' (& $peer $HubId)) } catch { Write-Host "The spoke side is left to the EntraPolicySuite install (-PeerToHub): $($_.Exception.Message)" -ForegroundColor Yellow }
foreach ($z in $Zones) { [void](Arm PUT "$z/virtualNetworkLinks/$LinkName" '2020-06-01' @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $HubId }; registrationEnabled = $false } }) }
if ($Who) {
    $role = "/subscriptions/$(($HubId -split '/')[2])/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
    $name = [guid]::new([Security.Cryptography.MD5]::HashData([Text.Encoding]::UTF8.GetBytes("$HubId|$Who".ToLowerInvariant())))
    try { [void](Arm PUT "$HubId/providers/Microsoft.Authorization/roleAssignments/$name" '2022-04-01' @{ properties = @{ roleDefinitionId = $role; principalId = $Who; principalType = 'User' } }) } catch { if ("$_" -notmatch 'RoleAssignmentExists|409') { throw } }
}
$a = Arm GET "$HubId/virtualNetworkPeerings/$HubPeering" '2023-09-01'; $b = Arm GET "$SpokeId/virtualNetworkPeerings/$SpokePeering" '2023-09-01'
Write-Host "Hub side: $($a.properties.peeringState); spoke side: $(if ($b) { $b.properties.peeringState } else { 'not made yet (the install makes it)' })" -ForegroundColor Cyan
'@)
    @{ FileName = 'prepare-hub-entrapolicysuite.ps1'; Text = (($L -join "`n").TrimEnd("`n") + "`n") }
}

function Invoke-EpsHandoffStep {
    # the hand-off list on screen and in <state folder>/network-hand-off.txt; with a hub, the hub owner's script next to it
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; Read-EpsNetworkFacts -Ctx $Ctx
    $lines = Get-EpsNetworkHandoff -Ctx $Ctx
    $net.HandoffText = $lines -join "`n"
    if ($Ctx.StatePath) {
        New-Item -ItemType Directory -Force -Path $Ctx.StatePath | Out-Null
        $net.HandoffPath = Join-Path $Ctx.StatePath 'network-hand-off.txt'
        Set-Content -LiteralPath $net.HandoffPath -Value $net.HandoffText -Encoding utf8
        if ($net.HubVnetId) {
            $h = New-EpsHubPrepareScript -Ctx $Ctx
            $net.HubScriptPath = Join-Path $Ctx.StatePath $h.FileName
            [IO.File]::WriteAllText($net.HubScriptPath, $h.Text, [Text.UTF8Encoding]::new($false))
        }
    }
}

function Invoke-EpsDnsCheckStep {
    <#
      From THIS machine, before any read or write of a data plane (the image upload, SQL): every private name resolves
      to its endpoint's address - the registry's TWO names included. When one does not, the install STOPS (exit 1, it
      resumes) and prints the exact A records the hub (or your DNS) needs. The database steps run from this machine, so a
      private install runs from a machine inside your network.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $net = $Ctx.Network; Read-EpsNetworkFacts -Ctx $Ctx
    $resolve = if ($global:EPS_DnsResolveOverride) { $global:EPS_DnsResolveOverride } else { { param($h) try { @([System.Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { @() } } }
    $bad = [System.Collections.Generic.List[string]]::new()
    foreach ($s in Get-EpsPrivateEndpointSpecs -Ctx $Ctx) {
        foreach ($f in $s.Fqdns) {
            $want = $net.EndpointIps[$f.ToLowerInvariant()]
            $got = @(& $resolve $f)
            if (-not $want -or $got -notcontains $want) {
                $rec = Get-EpsARecordFor -Fqdn $f
                $bad.Add(("  {0,-58} A {1,-15}  (zone {2}, record '{3}') - this machine got: {4}" -f $f, $(if ($want) { $want } else { '?' }), $rec.Zone, $rec.Record, $(if ($got) { $got -join ' ' } else { 'no answer' })))
            }
        }
    }
    if ($bad.Count) {
        throw ("DNS check from this machine: $($bad.Count) private name(s) do not resolve to their private endpoint. Add these A records (or link the zones to your hub), then run the same command again from a machine in your network - it resumes:`n" +
               ($bad -join "`n") + $(if ($net.HandoffPath) { "`nThe full network hand-off: $($net.HandoffPath)" }))
    }
    @{ Resolved = @(Get-EpsPrivateEndpointSpecs -Ctx $Ctx | ForEach-Object { $_.Fqdns }).Count }
}

function Invoke-EpsAgentPoolStep {
    # the registry's build pool INSIDE the spoke (endpoints subnet): with public access off, ACR Tasks can reach the
    # registry only from there (PIM: New-PimHostingPrerequisites -AcrAgentPoolName). Premium only.
    param([Parameter(Mandatory)]$Ctx)
    Read-EpsNetworkFacts -Ctx $Ctx
    $p = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.ContainerRegistry/registries/$($Ctx.Names.Registry)/agentPools/$($Ctx.Names.AgentPool)"
    $have = Invoke-EpsArm -Path $p -ApiVersion $script:EpsNetApi.acrPool -AllowNotFound
    if (-not $have -or "$($have.properties.virtualNetworkSubnetResourceId)" -ne $Ctx.Network.EndpointsSubnetId) {
        $have = Invoke-EpsArm -Method PUT -Path $p -ApiVersion $script:EpsNetApi.acrPool -Body @{ location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite' }; properties = @{ count = 1; tier = 'S1'; os = 'Linux'; virtualNetworkSubnetResourceId = $Ctx.Network.EndpointsSubnetId } }
    }
    for ($i = 0; "$($have.properties.provisioningState)" -notin 'Succeeded', 'Failed', 'Canceled' -and $i -lt 60; $i++) { Start-Sleep -Seconds ($Ctx.PollSeconds ?? 10); $have = Invoke-EpsArm -Path $p -ApiVersion $script:EpsNetApi.acrPool }
    if ("$($have.properties.provisioningState)" -ne 'Succeeded') { throw "the registry's build pool $($Ctx.Names.AgentPool) is '$($have.properties.provisioningState)' - without it the image cannot be built in a private registry" }
}

function Get-EpsInsideCheckScript {
    # PURE. What the one-time job runs INSIDE the environment, as the engine identity: every private name resolves to a
    # private address, the web app answers (/healthz 200, a page without a session -> the Entra sign-in), and each work
    # job's queue is readable through the queue's private endpoint (the path the queue trigger - KEDA, managed identity -
    # takes for every job type). Exit 0 = proven, 1 = what failed is printed.
    @'
$bad = @()
foreach ($h in ($env:EPS_CHECK_HOSTS -split ',' | Where-Object { $_ })) {
    $a = try { @([Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }) } catch { @() }
    if (-not @($a | Where-Object { $_ -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' }).Count) { $bad += "dns $h -> $($a -join ' ')" }
}
$hc = [Net.Http.HttpClient]::new([Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $false }); $hc.Timeout = [TimeSpan]::FromSeconds(20)
try { $r = $hc.GetAsync("https://$env:EPS_CHECK_WEB/healthz").GetAwaiter().GetResult(); if ([int]$r.StatusCode -ne 200) { $bad += "web /healthz $([int]$r.StatusCode)" } } catch { $bad += "web /healthz $($_.Exception.GetBaseException().Message)" }
try { $r = $hc.GetAsync("https://$env:EPS_CHECK_WEB/").GetAwaiter().GetResult(); if ([int]$r.StatusCode -ne 302 -or "$($r.Headers.Location)" -notmatch '^https://login\.microsoftonline\.com/') { $bad += "web / $([int]$r.StatusCode) $($r.Headers.Location)" } } catch { $bad += "web / $($_.Exception.GetBaseException().Message)" }
$tok = try { (Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?api-version=2019-08-01&resource=https://storage.azure.com/&client_id=$($env:EPS_ManagedIdentityClientId)" -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }).access_token } catch { $bad += "token $($_.Exception.Message)"; '' }
foreach ($q in ($env:EPS_CHECK_QUEUES -split ',' | Where-Object { $_ })) {
    try { [void](Invoke-WebRequest -Uri "https://$env:EPS_STORAGE_ACCOUNT.queue.core.windows.net/$q/messages?peekonly=true&numofmessages=1" -Headers @{ Authorization = "Bearer $tok"; 'x-ms-version' = '2021-08-06' } -UseBasicParsing) } catch { $bad += "queue $q $($_.Exception.Message)" }
}
if ($bad) { $bad | ForEach-Object { Write-Host "INSIDE-CHECK FAIL $_" }; exit 1 }
Write-Host 'INSIDE-CHECK OK'; exit 0
'@
}

function New-EpsInsideCheckJobBody {
    # PURE. The one-time job: manual trigger, the engine image and identity, the check script as its command
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$WebFqdn)
    $n = $Ctx.Names; $mi = $Ctx.Identities.EngineIdentity
    $hosts = @(Get-EpsPrivateEndpointSpecs -Ctx $Ctx | ForEach-Object { $_.Fqdns }) + @($WebFqdn)
    $queues = @(Get-EpsDefaultJobSchedule | Where-Object Implemented | ForEach-Object { Get-EpsJobQueueName $_.AcaJobName })
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-EpsInsideCheckScript)))
    [ordered]@{ location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; job = 'InsideCheck' }
        identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $mi.Id = @{} } }
        properties = [ordered]@{ environmentId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"; workloadProfileName = 'Consumption'
            configuration = [ordered]@{ triggerType = 'Manual'; replicaTimeout = 600; replicaRetryLimit = 0; manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 }
                registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = $mi.Id }) }
            template = @{ containers = @(@{ name = 'insidecheck'; image = "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)"; resources = @{ cpu = 0.25; memory = '0.5Gi' }
                command = @('pwsh'); args = @('-NoProfile', '-NonInteractive', '-EncodedCommand', $enc)
                env = @(@{ name = 'EPS_CHECK_HOSTS'; value = ($hosts -join ',') }, @{ name = 'EPS_CHECK_WEB'; value = $WebFqdn }, @{ name = 'EPS_STORAGE_ACCOUNT'; value = $n.Storage }
                        @{ name = 'EPS_CHECK_QUEUES'; value = ($queues -join ',') }, @{ name = 'EPS_ManagedIdentityClientId'; value = $mi.ClientId }) }) } } }
}

function Invoke-EpsInsideCheckStep {
    <#
      Success of a private install is proven from INSIDE the network: the one-time job caj-eps-insidecheck (always tried;
      ARM starts it from anywhere) - a job that ran and FAILED stops the install; else this machine reaching the web app;
      else -ConfirmedFromInside (you checked it yourself). The job is deleted again. @{ Ok; How }
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"; $jp = "$rg/providers/Microsoft.App/jobs/$($n.InsideCheckJob)"
    $fqdn = $Ctx.Web.Fqdn
    $job = @{ Ran = $false; Status = ''; Reason = '' }
    try {
        [void](Invoke-EpsArm -Method PUT -Path $jp -ApiVersion $script:EpsApi.acajob -Body (New-EpsInsideCheckJobBody -Ctx $Ctx -WebFqdn $fqdn))
        $s = Invoke-EpsArm -Method POST -Path "$jp/start" -ApiVersion $script:EpsApi.acajob -Body @{}
        $ex = "$($s.name)"; if (-not $ex) { $ex = "$($s.id)" -replace '^.*/', '' }
        if (-not $ex) { throw 'no execution name' }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt ($Ctx.InsideCheckWaitSeconds ?? 900)) {
            $e = Invoke-EpsArm -Path "$jp/executions/$ex" -ApiVersion $script:EpsNetApi.acaexec -AllowNotFound
            $st = "$($e.properties.status)"
            if ($st -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { $job = @{ Ran = $true; Status = $st; Reason = "execution $ex" }; break }
            Start-Sleep -Seconds ($Ctx.PollSeconds ?? 15)
        }
        if (-not $job.Ran) { $job.Reason = "execution $ex did not finish in time" }
    } catch { $job.Reason = "$($_.Exception.Message)" }
    finally { try { [void](Invoke-EpsArm -Method DELETE -Path $jp -ApiVersion $script:EpsApi.acajob -AllowNotFound) } catch { } }
    if ($job.Ran -and $job.Status -ne 'Succeeded') { throw "the inside check ($($n.InsideCheckJob), $($job.Reason)) ran INSIDE the network and ended '$($job.Status)': a private name, the web app or a job queue cannot be reached from there - see its log in $($n.Logs) (lines 'INSIDE-CHECK FAIL')" }
    $r = if ($job.Ran) { @{ Ok = $true; How = "inside the environment ($($n.InsideCheckJob)): private DNS, the web app and every job queue through its endpoint" } }
         elseif ((Test-EpsWebAppAnswers -Fqdn $fqdn -WaitSeconds ($Ctx.InsideMachineWaitSeconds ?? 60) -PollSeconds ($Ctx.PollSeconds ?? 10)).Ok) { @{ Ok = $true; How = "from this machine: the web app answers at https://$fqdn/ (the inside job did not run: $($job.Reason))" } }
         elseif ($Ctx.Network.ConfirmedFromInside) { @{ Ok = $true; How = "-ConfirmedFromInside (the inside job did not run: $($job.Reason); this machine cannot reach the web app)" } }
         else { throw "the private install is not proven from inside the network: the inside job did not run ($($job.Reason)) and this machine cannot reach https://$fqdn/. Run the install again from a machine in your network, or check the web app from one and run again with -ConfirmedFromInside" }
    $Ctx.Network.InsideCheck = $r; $r
}

function Invoke-EpsRetireOldEnvStep {
    <#
      Public -> private: the old public environment goes ONLY after the inside check passed. First everything that named
      its address is moved: the web sign-in registration's redirect URIs / logout URL of the old domain are removed (the
      new address was added by the web app step); no job or app may still live in it. Then it is deleted.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    if ($n.PublicEnvironment -eq $n.Environment) { return @{ Retired = $false } }
    if (-not (@($Ctx.Completed) -contains 'insidecheck') -and -not $Ctx.Network.InsideCheck.Ok) { throw 'the old environment is removed only after the inside check passed' }
    $old = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/managedEnvironments/$($n.PublicEnvironment)" -ApiVersion $script:EpsApi.aca -AllowNotFound
    if (-not $old) { return @{ Retired = $false } }
    $oldId = "$($old.id)"; if (-not $oldId) { $oldId = "$rg/providers/Microsoft.App/managedEnvironments/$($n.PublicEnvironment)" }
    $still = @(foreach ($j in @(Get-EpsJobBodies -Ctx $Ctx -Image 'x' | ForEach-Object { "jobs/$($_.Name)" }) + @("containerApps/$($n.WebApp)")) {
        $r = Invoke-EpsArm -Path "$rg/providers/Microsoft.App/$j" -ApiVersion $script:EpsApi.aca -AllowNotFound
        if ($r -and "$($r.properties.environmentId)" -eq $oldId) { $j }
    })
    if ($still) { throw "still in the old environment $($n.PublicEnvironment): $($still -join ', ') - not removed" }
    $dom = "$($old.properties.defaultDomain)".ToLowerInvariant()
    if ($dom -and $Ctx.Web.AppObjectId) {
        $reg = Invoke-EpsGraph -Path "v1.0/applications/$($Ctx.Web.AppObjectId)?`$select=web"
        $keep = @(@($reg.web.redirectUris) | Where-Object { $_ -and "$_".ToLowerInvariant() -notlike "*.$dom/*" })
        $logout = if ("$($reg.web.logoutUrl)".ToLowerInvariant() -like "*.$dom/*") { "https://$($Ctx.Web.Fqdn)/signout-callback-oidc" } else { "$($reg.web.logoutUrl)" }
        if ($keep.Count -ne @($reg.web.redirectUris | Where-Object { $_ }).Count -or $logout -ne "$($reg.web.logoutUrl)") {
            [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/applications/$($Ctx.Web.AppObjectId)" -Body @{ web = @{ redirectUris = $keep; logoutUrl = $logout; implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } } })
        }
    }
    [void](Invoke-EpsArm -Method DELETE -Path $oldId -ApiVersion $script:EpsApi.aca -AllowNotFound)
    @{ Retired = $true; Domain = $dom }
}

function Remove-EpsAppInOtherEnvironment {
    # public -> private: a job or an app cannot move to another environment - one that lives in another environment is
    # deleted, so the step re-creates it (same name) in the new one. Nothing happens when it is already where it belongs.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$EnvironmentId)
    $api = if ($Path -like '*/jobs/*') { $script:EpsApi.acajob } else { $script:EpsApi.aca }
    $r = Invoke-EpsArm -Path $Path -ApiVersion $api -AllowNotFound
    if ($r -and "$($r.properties.environmentId)" -and "$($r.properties.environmentId)" -ne $EnvironmentId) { [void](Invoke-EpsArm -Method DELETE -Path $Path -ApiVersion $api -AllowNotFound); return $true }
    $false
}

function Test-EpsPrivateInstallStep {
    # READ-ONLY: the plan of a private install's step (as Test-EpsInstallStep); $null = the public step's plan applies
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $net = $Ctx.Network; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    $has = { param($path, $api) [bool](Invoke-EpsArm -Path $path -ApiVersion $api -AllowNotFound) }
    $vid = Get-EpsSpokeVnetId $Ctx
    switch ($Id) {
        'network' {
            if ($net.CreateVnet -and -not (& $has $vid $script:EpsNetApi.net)) { return @{ Action = 'create'; Detail = "$($net.VnetName) $($net.VnetAddressPrefix): $($net.AppsSubnetName) $($net.AppsSubnetPrefix) (delegated to Microsoft.App/environments), $($net.EndpointsSubnetName) $($net.EndpointsSubnetPrefix)" } }
            return @{ Action = 'update'; Detail = "$vid - a missing subnet is created, an empty apps subnet delegated; nothing else changes" }
        }
        'dnszones' { return @{ Action = 'run'; Detail = $(if ($net.ZonesRgId) { "use the zones in $($net.ZonesRgId) (nothing is written there): $($script:EpsPrivateZones.Values -join ', ')" } else { "$($script:EpsPrivateZones.Values -join ', ') in $($n.ResourceGroup), linked to the spoke (a zone the spoke already links is reused)" }) } }
        'registry' { if (& $has "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)" $script:EpsApi.acr) { return @{ Action = 'update'; Detail = "$($n.Registry) -> Premium (AcrPull checked; public access closed by the lockdown step)" } }; return @{ Action = 'create'; Detail = "$($n.Registry) (Premium, public access off, no exception)" } }
        'sql' { if (& $has "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)/databases/$($n.Database)" $script:EpsApi.sql) { return @{ Action = 'exists'; Detail = "$($n.SqlServer)/$($n.Database) (public access closed by the lockdown step)" } }; return @{ Action = 'create'; Detail = "$($n.SqlServer) (Entra-only, public access off, no firewall rule) + $($n.Database) (S0)" } }
        'queues' { if (& $has "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)" $script:EpsApi.st) { return @{ Action = 'update'; Detail = "$($n.Storage) (queues + who may send / read checked; public access closed by the lockdown step)" } }; return @{ Action = 'create'; Detail = "$($n.Storage) (no shared key, public access off) + one queue per work job" } }
        'keyvault' { if (& $has "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)" $script:EpsWeb.KvApi) { return @{ Action = 'exists'; Detail = "$($n.KeyVault) (key checked; public access closed by the lockdown step)" } }; return @{ Action = 'create'; Detail = "$($n.KeyVault) (Standard, RBAC, purge protection, public access off) + RSA key $($script:EpsWeb.KeyName)" } }
        { $_ -in 'registryendpoint', 'sqlendpoint', 'queueendpoint', 'keyvaultendpoint' } {
            $s = @(Get-EpsPrivateEndpointSpecs -Ctx $Ctx | Where-Object { $_.Step -eq $Id })[0]
            return @{ Action = $(if (& $has "$rg/providers/Microsoft.Network/privateEndpoints/$($s.Name)" $script:EpsNetApi.net) { 'update' } else { 'create' }); Detail = "$($s.Name) in $($net.EndpointsSubnetName) -> $($s.GroupId); records in $($s.Zone): $($s.Fqdns -join ', ')" }
        }
        'environment' {
            if (& $has "$rg/providers/Microsoft.App/managedEnvironments/$($n.Environment)" $script:EpsApi.aca) { return @{ Action = 'exists'; Detail = $n.Environment } }
            $conv = & $has "$rg/providers/Microsoft.App/managedEnvironments/$($n.PublicEnvironment)" $script:EpsApi.aca
            return @{ Action = 'create'; Detail = "$($n.Environment) in $($net.AppsSubnetName), internal (no public address), workload profile Consumption$(if ($conv) { " - REPLACES the public $($n.PublicEnvironment): the jobs and the web app are re-created in it (same identities, database and queues), and $($n.PublicEnvironment) is removed after the inside check" })" }
        }
        'environmentdns' { return @{ Action = 'run'; Detail = "the environment's default domain as a zone in $($n.ResourceGroup): @, *, *.internal -> its static address; linked to the spoke" } }
        'hub' { return @{ Action = 'run'; Detail = $(if (-not $net.HubVnetId) { 'no -HubVnetId: nothing (the peering is on the hand-off list)' } else { "peering: $(if ($net.PeerToHub) { 'both sides, after a check of your rights (never half a peering)' } else { 'not asked (hand-off list)' }); zone links to the hub: $(if ($net.LinkZonesToHub) { 'EPS''s zones, after a check of your rights' } else { 'not asked (hand-off list)' })" }) } }
        'handoff' { return @{ Action = 'run'; Detail = "network-hand-off.txt in the state folder$(if ($net.HubVnetId) { ' + prepare-hub-entrapolicysuite.ps1 for the hub owner' })" } }
        'dnscheck' { return @{ Action = 'run'; Detail = "from this machine: $(@(Get-EpsPrivateEndpointSpecs -Ctx $Ctx | ForEach-Object { $_.Fqdns }) -join ', ') must resolve to their endpoints - stops with the A records when not" } }
        'agentpool' { return @{ Action = 'run'; Detail = "$($n.AgentPool) (S1 x 1) in $($net.EndpointsSubnetName): the image builds run inside the network" } }
        'insidecheck' { return @{ Action = 'run'; Detail = "one-time job $($n.InsideCheckJob) inside the environment (private DNS, the web app, every job queue through its endpoint), else this machine, else -ConfirmedFromInside" } }
        'retireoldenv' { if (& $has "$rg/providers/Microsoft.App/managedEnvironments/$($n.PublicEnvironment)" $script:EpsApi.aca) { return @{ Action = 'run'; Detail = "remove the old public $($n.PublicEnvironment) (its redirect URIs first) - after the inside check" } }; return @{ Action = 'exists'; Detail = 'no public environment to remove' } }
        'lockdown' { return @{ Action = 'run'; Detail = "public network access Disabled, read back: $($n.SqlServer) (public firewall rules removed), $($n.KeyVault), $($n.Storage), $($n.Registry) - only after the inside check" } }
    }
    $null
}

function Invoke-EpsLockdownStep {
    <#
      The LAST step, only after the inside check passed: public network access Disabled on Azure SQL (its public firewall
      rules removed), Key Vault, the storage account and the registry, then read back - each must say Disabled. A new
      private install created them Disabled (this only proves it); a converted public install is closed here, after its
      endpoints and DNS were proven from inside.
    #>
    param([Parameter(Mandatory)]$Ctx)
    if (-not (@($Ctx.Completed) -contains 'insidecheck') -and -not $Ctx.Network.InsideCheck.Ok) { throw 'public access goes off only after the inside check passed' }
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    $targets = @(
        @{ Path = "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)"; Api = $script:EpsApi.sql; Patch = @{ properties = @{ publicNetworkAccess = 'Disabled' } } }
        @{ Path = "$rg/providers/Microsoft.KeyVault/vaults/$($n.KeyVault)"; Api = $script:EpsWeb.KvApi; Patch = @{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = @{ defaultAction = 'Deny'; bypass = 'None' } } } }
        @{ Path = "$rg/providers/Microsoft.Storage/storageAccounts/$($n.Storage)"; Api = $script:EpsApi.st; Patch = @{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = @{ defaultAction = 'Deny'; bypass = 'None' } } } }
        @{ Path = "$rg/providers/Microsoft.ContainerRegistry/registries/$($n.Registry)"; Api = $script:EpsApi.acr; Patch = @{ properties = @{ publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'None' } } }
    )
    foreach ($fw in 'AllowAllWindowsAzureIps', 'AllowSetupHost') { [void](Invoke-EpsArm -Method DELETE -Path "$($targets[0].Path)/firewallRules/$fw" -ApiVersion $script:EpsApi.sql -AllowNotFound) }
    $open = @()
    foreach ($t in $targets) {
        $r = Invoke-EpsArm -Path $t.Path -ApiVersion $t.Api
        if ("$($r.properties.publicNetworkAccess)" -ne 'Disabled') { [void](Invoke-EpsArm -Method PATCH -Path $t.Path -ApiVersion $t.Api -Body $t.Patch); $r = Invoke-EpsArm -Path $t.Path -ApiVersion $t.Api }
        if ("$($r.properties.publicNetworkAccess)" -ne 'Disabled') { $open += ($t.Path -split '/')[-1] }
    }
    if ($open) { throw "public network access is still on for $($open -join ', ') after the change" }
    @{ Closed = 4 }
}
