# EntraPolicySuite -- the ONE place that creates what Get started's last steps need (V1-PARITY P7 / P8 / P9, DESIGN §5.10):
# the authentication strengths, the denied-countries and trusted named locations, the break-glass accounts - and the daily
# job that keeps the Azure service tags as named locations (v1's EntraNamedLocations_AzureNetworkServiceTags.ps1).
#
#   Owner 2026-11-03 "Check + create on approval"; 2026-11-05 "solution must be min 1:1 on pair with the old eps script
#   solution" and "it is always 100% opeator controlled": Invoke-EpsOnboardChange runs only from a SuperAdmin's signed
#   request (the four POST /api/onboarding/<action> routes, Apply = Engine, a reason) - plans again from the tenant,
#   writes, reads each change back and journals it. The ONE thing here that runs on a schedule is the service-tag job -
#   as v1's VisualCron job did, daily, only when the operator switched it on (NamedLocations.Enabled), and it writes ONLY
#   named locations whose name starts 'Azure.Network.ServiceTag.' (v1's prefix).
#
# Loaded by the ENGINE only (tools/eps-engine/job-entry.ps1): the web app never loads this file. tests/Test-EpsOnboardWrite.ps1
# and tests/Test-EpsNoCaWrite.ps1 pin every write in it.

Set-StrictMode -Off

function New-EpsBreakGlassPassword {
    # v1's Generate-SecurePassword (16 characters from its set), from a cryptographic source, with every character class
    # (Entra's complexity rule). Never logged, stored, journaled or returned to anyone but the one POST.
    $set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?'
    while ($true) {
        $p = -join (1..16 | ForEach-Object { $set[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($set.Length)] })
        if ($p -cmatch '[a-z]' -and $p -cmatch '[A-Z]' -and $p -match '\d' -and $p -match '[^A-Za-z0-9]') { return $p }
    }
}

function Read-EpsOnboardWriteState {
    # the tenant as it is NOW, in Get-EpsOnboardPlan's state shape (Graph GETs only)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Action, [hashtable]$Settings = @{})
    $d = Get-EpsOnboardingDefaults; $cat = Get-EpsCaTemplateCatalog
    $s = @{}
    if ($Action -eq 'strengths') {
        $sp = Invoke-EpsOnboardingGraph -Path 'v1.0/policies/authenticationStrengthPolicies?$filter=policyType eq ''custom''' -All
        $s.Strengths = @{}
        foreach ($k in 'FIDO', 'WHfB') {
            $nm = Get-EpsStrengthName -Key $k -Settings $Settings -Defaults $d -Catalog $cat
            $hit = if ($sp.Ok) { @($sp.Value | Where-Object { "$($_.displayName)" -eq $nm })[0] }
            $s.Strengths[$k] = @{ Found = $(if (-not $sp.Ok) { $null } else { [bool]$hit }); Id = $(if ($hit) { "$($hit.id)" }); Error = $sp.Error }
        }
    }
    if ($Action -in 'deniedcountries', 'trusted') {
        # inline GET (Test-EpsNoCaWrite: a Conditional Access URL stands only as the -Path of an Invoke-EpsGraph read)
        $nl = try { @{ Ok = $true; Value = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All) } } catch { @{ Ok = $false; Error = (("$($_.Exception.Message)" -split '->')[-1]).Trim() } }
        if ($nl.Ok) {
            $s.Locations = @{}
            foreach ($l in $nl.Value) {
                $type = if ("$($l.'@odata.type')" -match 'ipNamedLocation') { 'ip' } elseif ("$($l.'@odata.type')" -match 'countryNamedLocation') { 'country' } else { 'other' }
                $s.Locations["$($l.displayName)".ToLowerInvariant()] = @{ Id = "$($l.id)"; Name = "$($l.displayName)"; Type = $type; IsTrusted = [bool]$l.isTrusted; Ranges = @($l.ipRanges | ForEach-Object { "$($_.cidrAddress)" }) }
            }
            $dn = "$($Settings[$d.deniedCountries.setting])".Trim(); if (-not $dn) { $dn = "$($cat.namedLocationDefaults.DeniedCountries)" }
            $den = @($nl.Value | Where-Object { "$($_.displayName)" -eq $dn })[0]
            $s.Denied = if ($den) { @{ Found = $true; Id = "$($den.id)"; Countries = @($den.countriesAndRegions | ForEach-Object { "$_" }); IncludeUnknown = [bool]$den.includeUnknownCountriesAndRegions } } else { @{ Found = $false } }
        } else { $s.Denied = @{ Found = $null; Error = $nl.Error }; $s.Locations = $null; $s.LocationsError = $nl.Error }
    }
    if ($Action -eq 'breakglass') {
        $s.Accounts = @(foreach ($a in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT UserPrincipalName, DisplayName FROM eps.BreakGlassAccount WHERE Directory = 'Entra' AND Enabled = 1 ORDER BY UserPrincipalName")) {
            $upn = "$($a.UserPrincipalName)"
            $u = Invoke-EpsOnboardingGraph -Path "v1.0/users/$([uri]::EscapeDataString($upn))?`$select=id,userPrincipalName"
            @{ Upn = $upn; DisplayName = $(if ($a.DisplayName -isnot [DBNull]) { "$($a.DisplayName)" }); Found = $(if ($u.Ok) { $true } elseif ($u.Error -match '(?i)404|not ?found|Request_ResourceNotFound|does not exist') { $false } else { $null }) }
        })
    }
    $s
}

function Invoke-EpsOnboardChangeItems {
    # the writes of ONE plan, each read back; returns the items with result / readback. The four kinds of write here and
    # nowhere else (Test-EpsOnboardWrite pins them): a strength (+ its FIDO2 key models), a named location made or set, a
    # break-glass user made.
    param([Parameter(Mandatory)]$Plan, [scriptblock]$Log = { param($l, $m) })
    $done = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($Plan.items)) {
        $r = @{ name = $it.name; do = $it.do; detail = $it.detail; result = 'skipped' }
        if ($it.do -in 'skip', 'refused') { $done.Add($r); continue }
        try {
            switch ($Plan.action) {
                'strengths' {
                    [void](Invoke-EpsGraph -Method POST -Path 'v1.0/policies/authenticationStrengthPolicies' -Body $it.body)
                    $back = @(Invoke-EpsGraph -Path "v1.0/policies/authenticationStrengthPolicies?`$filter=policyType eq 'custom'" -All | Where-Object { "$($_.displayName)" -eq "$($it.body.displayName)" })
                    if ($back.Count -ne 1) { throw "read back: $($back.Count) strengths with this name" }
                    $sid = "$($back[0].id)"
                    $have = @($back[0].allowedCombinations | ForEach-Object { "$_" } | Sort-Object); $want = @($it.body.allowedCombinations | Sort-Object)
                    if (($have -join ',') -ne ($want -join ',')) { throw "read back: it allows $($have -join ' + ')" }
                    $r.after = @{ id = $sid; allowedCombinations = $have }
                    if ($it.extra) {
                        # v1's 11 FIDO2 key models (E-CM L276-293)
                        [void](Invoke-EpsGraph -Method POST -Path "v1.0/policies/authenticationStrengthPolicies/$sid/combinationConfigurations" -Body $it.extra)
                        $cc = @(Invoke-EpsGraph -Path "v1.0/policies/authenticationStrengthPolicies/$sid/combinationConfigurations" -All)
                        $ag = @($cc | ForEach-Object { @($_.allowedAAGUIDs) } | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
                        $miss = @($it.extra.allowedAAGUIDs | Where-Object { $ag -notcontains "$_".ToLowerInvariant() })
                        if ($miss.Count) { throw "read back: $($miss.Count) of v1's key models are not allowed" }
                        $r.after.fido2KeyModels = $ag.Count
                    }
                    $r.result = 'done'
                }
                { $_ -in 'deniedcountries', 'trusted' } {
                    if ($it.do -eq 'create') {
                        [void](Invoke-EpsGraph -Method POST -Path 'v1.0/identity/conditionalAccess/namedLocations' -Body $it.body)
                        $back = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All | Where-Object { "$($_.displayName)" -eq "$($it.body.displayName)" })
                        if ($back.Count -ne 1) { throw "read back: $($back.Count) named locations with this name" }
                        $l = $back[0]
                    } else {
                        [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/identity/conditionalAccess/namedLocations/$($it.id)" -Body $it.body)
                        $l = Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/namedLocations/$($it.id)"
                    }
                    if ($it.body.countriesAndRegions) {
                        $miss = @($it.body.countriesAndRegions | Where-Object { @($l.countriesAndRegions) -notcontains $_ })
                        if ($miss.Count) { throw "read back: $($miss -join ', ') not in it" }
                        $r.after = @{ id = "$($l.id)"; countries = @($l.countriesAndRegions).Count; includeUnknown = [bool]$l.includeUnknownCountriesAndRegions }
                    } else {
                        $n = @($l.ipRanges).Count
                        if ($n -ne @($it.body.ipRanges).Count -or [bool]$l.isTrusted -ne [bool]$it.body.isTrusted) { throw "read back: $n range(s), $(if ($l.isTrusted) { 'trusted' } else { 'not trusted' })" }
                        $r.after = @{ id = "$($l.id)"; ranges = $n; isTrusted = [bool]$l.isTrusted }
                    }
                    $r.result = 'done'
                }
                'breakglass' {
                    # E-CM L197-209 (EntraUser -Create): forceChangePasswordNextSignIn, the password only in this request
                    $body = [ordered]@{}; foreach ($k in $it.body.Keys) { $body[$k] = $it.body[$k] }
                    $body.passwordProfile = [ordered]@{ forceChangePasswordNextSignIn = $true; password = (New-EpsBreakGlassPassword) }
                    [void](Invoke-EpsGraph -Method POST -Path 'v1.0/users' -Body $body)
                    $body.passwordProfile = $null; $body = $null
                    $u = Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString("$($it.body.userPrincipalName)"))?`$select=id,userPrincipalName,accountEnabled"
                    if (-not $u.id -or -not $u.accountEnabled) { throw 'read back: not there, or not enabled' }
                    $r.after = @{ id = "$($u.id)"; accountEnabled = [bool]$u.accountEnabled }
                    $r.result = 'done'
                }
            }
        } catch {
            $r.result = 'failed'; $r.error = (("$($_.Exception.Message)" -split '->')[-1]).Trim()
            if ($r.error -match '(?i)403|Authorization_RequestDenied|privilege') { $r.error += " (the engine needs $(switch ($Plan.action) { 'strengths' { 'Policy.ReadWrite.AuthenticationMethod' } 'breakglass' { 'User.ReadWrite.All' } default { 'Policy.ReadWrite.ConditionalAccess' } }) - run the install again to grant it)" }
        }
        & $Log $(if ($r.result -eq 'failed') { 'Warning' } else { 'Info' }) "  $($Plan.action) $($it.do) $($it.name): $($r.result)$(if ($r.error) { " - $($r.error)" })"
        $done.Add($r)
    }
    , @($done)
}

function Get-EpsOnboardSettings {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $o = @{}; foreach ($n in 'CA.AuthStrengthFidoName', 'CA.AuthStrengthWhfbName', 'CA.DeniedCountriesLocationName') { $o[$n] = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name $n -Default '')" }
    $o
}

function Invoke-EpsOnboardChange {
    <#
      ONE operator request (the engine runs it from a SuperAdmin's signed request):
        1. the tenant AS IT IS NOW (Graph GETs) - the plan is made again from it
        2. refused when the plan is (nothing to do, not read, a name that is not allowed)
        3. the writes, each read back; one journal row per item done (eps.ConfigChange: AuthenticationStrength,
           NamedLocation or User - a password is never in it)
      Returns @{ Result = ok | partial | refused | failed; Reason; Items; Text }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Action, [string[]]$Names = @(), [hashtable]$Location,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    if ($Action -notin $script:EpsOnboardActions) { return @{ Result = 'refused'; Reason = "'$Action' is not something Get started creates"; Items = @() } }
    $set = Get-EpsOnboardSettings -ConnectionString $ConnectionString
    $state = Read-EpsOnboardWriteState -ConnectionString $ConnectionString -Action $Action -Settings $set
    $plan = Get-EpsOnboardPlan -Action $Action -State $state -Names $Names -Location $Location -Settings $set
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Items = @($plan.items) } }
    & $Log 'Info' "Get started: $Action ($($plan.summary)), requested by $Actor"
    $items = Invoke-EpsOnboardChangeItems -Plan $plan -Log $Log
    $ent = switch ($Action) { 'strengths' { 'AuthenticationStrength' } 'breakglass' { 'User' } default { 'NamedLocation' } }
    foreach ($it in @($items | Where-Object { $_.result -eq 'done' })) {
        $p = New-EpsJournalParameters -Actor $Actor -Entity $ent -Key "$($it.name)" -Action $(if ($it.do -eq 'create') { 'Create' } else { 'Update' }) -Before $null -After ([ordered]@{ do = $it.do; detail = $it.detail; after = $it.after; reason = $Reason } | ConvertTo-Json -Compress -Depth 5)
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query (Get-EpsJournalSql))
    }
    $failed = @($items | Where-Object { $_.result -eq 'failed' }); $ok = @($items | Where-Object { $_.result -eq 'done' })
    $res = if (-not $failed.Count) { 'ok' } elseif ($ok.Count) { 'partial' } else { 'failed' }
    @{ Result = $res; Reason = (@($failed | ForEach-Object { "$($_.name): $($_.error)" }) -join '; '); Items = @($items)
       Text = "$($ok.Count) done$(if ($failed.Count) { ", $($failed.Count) failed: $(@($failed | ForEach-Object { "$($_.name) ($($_.error))" }) -join '; ')" })$(if (@($items | Where-Object { $_.do -eq 'skip' }).Count) { ", $(@($items | Where-Object { $_.do -eq 'skip' }).Count) already there" })$(if ($Action -eq 'breakglass' -and $ok.Count) { '. Set each new account''s password or Temporary Access Pass in Entra, register its FIDO2 key and make it Global Administrator - Entra Policy Suite never shows its password' })." }
}

# ---- UNDO-BACKUP left-over: named locations and authentication strengths put back from a backup ---------------------
# The operator's request (POST /api/backups/ca/{id}/restore-other: SuperAdmin, a reason, applied by the engine): the tenant
# read LIVE, the plan made again (EPS-Backup.ps1 Get-EpsCaObjectRestorePlan: create when missing, the backup's definition
# back when changed, NEVER a delete), a backup of what is touched BEFORE any write (none = nothing written), each write
# read back and journaled. Five more writes, pinned in tests/Test-EpsNoCaWrite.ps1 and tests/Test-EpsOnboardWrite.ps1.

function Restore-EpsCaObjectItems {
    # the writes of ONE object restore plan, each read back - its only caller is Invoke-EpsCaObjectRestore
    param([Parameter(Mandatory)][object[]]$Items, [scriptblock]$Log = { param($l, $m) })
    $done = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($Items | Where-Object { $_.ok -and $_.action -in 'create', 'patch' })) {
        $r = [ordered]@{ kind = $it.kind; displayName = $it.displayName; action = $it.action; result = 'failed'; text = $null }
        try {
            if ($it.kind -eq 'namedLocation') {
                if ($it.action -eq 'create') { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/identity/conditionalAccess/namedLocations' -Body $it.body) }
                else { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/identity/conditionalAccess/namedLocations/$($it.currentId)" -Body $it.body) }
                $back = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All | Where-Object { "$($_.displayName)" -ceq "$($it.body.displayName)" })
                if ($back.Count -ne 1) { throw "read back: $($back.Count) named locations with this name" }
                if ((ConvertTo-EpsNamedLocationShape -Location $back[0]).key -ne (ConvertTo-EpsNamedLocationShape -Location $it.body).key) { throw 'read back: it is not as in the backup' }
            } else {
                if ($it.action -eq 'create') { [void](Invoke-EpsGraph -Method POST -Path 'v1.0/policies/authenticationStrengthPolicies' -Body $it.body) }
                else {
                    if ($it.body) { [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/policies/authenticationStrengthPolicies/$($it.currentId)" -Body $it.body) }
                    if ($it.combinations) { [void](Invoke-EpsGraph -Method POST -Path "v1.0/policies/authenticationStrengthPolicies/$($it.currentId)/updateAllowedCombinations" -Body @{ allowedCombinations = @($it.combinations) }) }
                }
                $back = @(Invoke-EpsGraph -Path "v1.0/policies/authenticationStrengthPolicies?`$filter=policyType eq 'custom'" -All | Where-Object { "$($_.displayName)" -ceq "$($it.displayName)" })
                if ($back.Count -ne 1) { throw "read back: $($back.Count) strengths with this name" }
                $want = @(if ($it.action -eq 'create') { $it.body.allowedCombinations } elseif ($it.combinations) { $it.combinations } else { $back[0].allowedCombinations })
                if ((@($back[0].allowedCombinations | ForEach-Object { "$_" } | Sort-Object -Unique) -join ',') -ne (@($want | ForEach-Object { "$_" } | Sort-Object -Unique) -join ',')) { throw 'read back: its allowed combinations are not as in the backup' }
            }
            $r.result = 'done'; $r.text = $(if ($it.action -eq 'create') { 'made again' } else { 'put back: ' + (@($it.changes) -join '; ') })
        } catch {
            $r.text = (("$($_.Exception.Message)" -split '->')[-1]).Trim()
            if ($r.text -match '(?i)403|Authorization_RequestDenied|privilege') { $r.text += " (the engine needs $(if ($it.kind -eq 'namedLocation') { 'Policy.ReadWrite.ConditionalAccess' } else { 'Policy.ReadWrite.AuthenticationMethod' }) - run the install again to grant it)" }
        }
        & $Log $(if ($r.result -eq 'failed') { 'Warning' } else { 'Info' }) "  restore $($it.kind) $($it.action) $($it.displayName): $($r.result)$(if ($r.result -eq 'failed') { " - $($r.text)" })"
        $done.Add($r)
    }
    , @($done)
}

function Invoke-EpsCaObjectRestore {
    <#
      Puts the picked named locations / authentication strengths of ONE backup back (the operator's request): the tenant
      read LIVE, the plan made again, a backup of what is about to change BEFORE any write, the writes (read back), one
      journal row per item. Returns @{ Result = ok | partial | refused | failed; Reason; Items; Text }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$BackupId, [string[]]$ObjectIds = @(),
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $b = Get-EpsCaObjectBackupItems -ConnectionString $ConnectionString -BackupId $BackupId -ObjectIds $ObjectIds
    if (-not $b) { return @{ Result = 'refused'; Reason = 'no such backup (it may have been removed by the retention)'; Items = @() } }
    if (-not $b.Rows.Count) { return @{ Result = 'refused'; Reason = 'the backup holds none of these named locations or strengths'; Items = @() } }
    $nl = try { @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All) } catch { return @{ Result = 'failed'; Reason = "the named locations could not be read: $((("$($_.Exception.Message)") -split '->')[-1].Trim())"; Items = @() } }
    $st = try { @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/authenticationStrength/policies' -All) } catch { return @{ Result = 'failed'; Reason = "the authentication strengths could not be read: $((("$($_.Exception.Message)") -split '->')[-1].Trim())"; Items = @() } }
    $plan = Get-EpsCaObjectRestorePlan -Backup $b.Rows -Current @{ NamedLocations = $nl; AuthStrengths = $st }
    $todo = @($plan.items | Where-Object { $_.ok -and $_.action -in 'create', 'patch' })
    if (-not $todo.Count) { return @{ Result = 'refused'; Reason = 'nothing to put back: ' + (@($plan.items | ForEach-Object { "$($_.displayName) ($($_.reason))" }) -join '; '); Items = @($plan.items) } }
    # what is about to change, as it is now, stored first (no backup, no change)
    $tl = @($todo | Where-Object { $_.kind -eq 'namedLocation' -and $_.currentId } | ForEach-Object { $id = $_.currentId; @($nl | Where-Object { "$($_.id)" -eq $id })[0] })
    $ts = @($todo | Where-Object { $_.kind -eq 'authStrength' -and $_.currentId } | ForEach-Object { $id = $_.currentId; @($st | Where-Object { "$($_.id)" -eq $id })[0] })
    try { [void](Save-EpsCaBackupSet -ConnectionString $ConnectionString -Kind BeforeChange -NamedLocations $tl -AuthStrengths $ts -TakenBy $Actor -Cause "before the restore of $($todo.Count) named location(s) / strength(s) from backup $BackupId") }
    catch { return @{ Result = 'refused'; Reason = "the backup before the change could not be written ($($_.Exception.Message)) - nothing was changed"; Items = @($plan.items) } }
    & $Log 'Info' "restore from backup $BackupId`: $($todo.Count) named location(s) / strength(s), requested by $Actor"
    $done = Restore-EpsCaObjectItems -Items $todo -Log $Log
    foreach ($d in @($done | Where-Object { $_.result -eq 'done' })) {
        $p = New-EpsJournalParameters -Actor $Actor -Entity $(if ($d.kind -eq 'namedLocation') { 'NamedLocation' } else { 'AuthenticationStrength' }) -Key "$($d.displayName)" -Action $(if ($d.action -eq 'create') { 'Create' } else { 'Update' }) -Before $null -After ([ordered]@{ restoredFrom = $BackupId; do = $d.action; text = $d.text; reason = $Reason } | ConvertTo-Json -Compress)
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query (Get-EpsJournalSql))
    }
    $ok = @($done | Where-Object { $_.result -eq 'done' }); $bad = @($done | Where-Object { $_.result -ne 'done' })
    @{ Result = $(if (-not $bad.Count) { 'ok' } elseif ($ok.Count) { 'partial' } else { 'failed' }); Reason = (@($bad | ForEach-Object { "$($_.displayName): $($_.text)" }) -join '; '); Items = @($done)
       Text = "$($ok.Count) put back$(if (@($plan.items | Where-Object { $_.action -eq 'none' }).Count) { ", $(@($plan.items | Where-Object { $_.action -eq 'none' }).Count) as in the backup already" })$(if ($bad.Count) { ", $($bad.Count) failed: " + (@($bad | ForEach-Object { "$($_.displayName) ($($_.text))" }) -join '; ') })" }
}

# ---- the daily service-tag job (v1's EntraNamedLocations_AzureNetworkServiceTags.ps1, its VisualCron job) --------------
$script:EpsServiceTagApi = '2022-05-01'   # v1's $apiVersion
$script:EpsServiceTagPages = @('https://www.microsoft.com/en-us/download/details.aspx?id=56519', 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519')

function Get-EpsServiceTagSource {
    <#
      The service tags with their prefixes, as v1 reads them: first the ARM service-tag API for the region (the engine's
      subscription), then v1's fallback - Microsoft's published JSON (the download page's ServiceTags_Public_<n>.json).
      Returns @{ Api = @{ tag -> prefixes } or $null; Static = @{ ... } or $null; Notes }.
    #>
    param([Parameter(Mandatory)][string]$Region, [string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID, [scriptblock]$Log = { param($l, $m) })
    $toMap = { param($vals) $m = @{}; foreach ($v in @($vals)) { if ($v.name) { $m["$($v.name)".ToLowerInvariant()] = @($v.properties.addressPrefixes | ForEach-Object { "$_" }) } }; $m }
    $notes = [System.Collections.Generic.List[string]]::new(); $api = $null; $static = $null
    if ($SubscriptionId) {
        try {
            $r = & $script:EpsHttp 'GET' "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Network/locations/$Region/serviceTags?api-version=$script:EpsServiceTagApi" @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://management.azure.com/')" } $null
            if ($r.Status -lt 300) { $api = & $toMap (($r.Body | ConvertFrom-Json -Depth 20).values) } else { $notes.Add("the service-tag API answered $($r.Status) - v1's fallback (the published file) is used") }
        } catch { $notes.Add("the service-tag API could not be read ($((("$($_.Exception.Message)") -split "`n")[0])) - v1's fallback is used") }
    } else { $notes.Add('no subscription for the service-tag API - v1''s fallback (the published file) is used') }
    $static = $null
    foreach ($page in $script:EpsServiceTagPages) {
        try {
            $h = & $script:EpsHttp 'GET' $page @{} $null
            $link = [regex]::Match("$($h.Body)", 'https://download\.microsoft\.com/download/[^"''\s<>]+?ServiceTags_Public_\d+\.json').Value
            if (-not $link) { continue }
            $j = & $script:EpsHttp 'GET' $link @{} $null
            if ($j.Status -lt 300) { $static = & $toMap (($j.Body | ConvertFrom-Json -Depth 20).values); break }
        } catch { $notes.Add("the published service-tag file could not be read from $page`: $((("$($_.Exception.Message)") -split "`n")[0])") }
    }
    if (-not $api -and -not $static) { $notes.Add('neither the API nor the published file could be read - nothing is changed this run') }
    @{ Api = $api; Static = $static; Notes = @($notes) }
}

function Invoke-EpsServiceTagJob {
    <#
      The named-locations job (daily, when NamedLocations.Enabled; v1 1:1): for each service tag in eps.ServiceTagLocation
      (v1's CSV, imported): its prefixes from the API, else from the published file; when they differ from the cache
      (eps.ServiceTagPrefix) - or the location is missing in the tenant - the IP named location 'Azure.Network.ServiceTag.
      <tag>' is made or its ranges set (not trusted, as v1), read back, the cache replaced and the change journaled. It
      writes NO other named location. Returns @{ Tags; Written; Unchanged; Failed; Lines }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" }, [string]$SubscriptionId = $env:EPS_SUBSCRIPTION_ID)
    $out = @{ Tags = 0; Written = 0; Unchanged = 0; Failed = 0 }
    $tags = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Tag FROM eps.ServiceTagLocation WHERE Enabled = 1 ORDER BY Tag' | ForEach-Object { "$($_.Tag)" })
    $out.Tags = $tags.Count
    if (-not $tags.Count) { & $Log 'Info' 'no service tag to keep (import v1''s EntraNamedLocations_AzureNetworkServiceTags.csv on the Import v1 page)'; return $out }
    $region = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'NamedLocations.Region' -Default 'westeurope')".Trim()
    & $Log 'Info' "service tags: $($tags.Count) ($($tags -join ', ')), region $region"
    $src = Get-EpsServiceTagSource -Region $region -SubscriptionId $SubscriptionId -Log $Log
    foreach ($n in $src.Notes) { & $Log 'Warning' "  $n" }
    if (-not $src.Api -and -not $src.Static) { $out.Failed = $tags.Count; return $out }
    # inline GET (Test-EpsNoCaWrite: a Conditional Access URL stands only as the -Path of an Invoke-EpsGraph read)
    $locs = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All)
    foreach ($tag in $tags) {
        $name = "$script:EpsServiceTagPrefix$tag"
        $k = $tag.ToLowerInvariant()
        $found = if ($src.Api -and $src.Api.ContainsKey($k)) { $src.Api[$k] } elseif ($src.Static -and $src.Static.ContainsKey($k)) { & $Log 'Warning' "  $tag is not in the API - taken from the published file"; $src.Static[$k] } else { $null }
        if ($null -eq $found) { & $Log 'Warning' "  $tag`: not in the API nor in the published file - skipped"; $out.Failed++; continue }
        $cached = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ t = $tag } -Query 'SELECT Prefix FROM eps.ServiceTagPrefix WHERE Tag = @t' | ForEach-Object { "$($_.Prefix)" })
        $cur = @($locs | Where-Object { "$($_.displayName)" -eq $name })
        $ch = Get-EpsServiceTagChange -Found $found -Cached $cached -LocationExists ([bool]$cur.Count)
        if (-not $ch.Write) { & $Log 'Info' "  $name`: $($ch.Reason)"; $out.Unchanged++; continue }
        if ($cur.Count -gt 1) { & $Log 'Warning' "  $name`: $($cur.Count) named locations have this name - none is changed"; $out.Failed++; continue }
        if ($cur.Count -and "$($cur[0].'@odata.type')" -notmatch 'ipNamedLocation') { & $Log 'Warning' "  $name`: a named location of another kind has this name - not changed"; $out.Failed++; continue }
        $body = [ordered]@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; displayName = $name; isTrusted = $false; ipRanges = @($ch.Prefixes | ForEach-Object { ConvertTo-EpsIpRange $_ }) }
        try {
            if ($cur.Count) {
                [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/identity/conditionalAccess/namedLocations/$($cur[0].id)" -Body $body)
                $l = Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/namedLocations/$($cur[0].id)"
            } else {
                [void](Invoke-EpsGraph -Method POST -Path 'v1.0/identity/conditionalAccess/namedLocations' -Body $body)
                $l = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All | Where-Object { "$($_.displayName)" -eq $name })[0]
            }
            if (-not $l -or @($l.ipRanges).Count -ne $ch.Prefixes.Count) { throw "read back: $(if ($l) { "$(@($l.ipRanges).Count) range(s), $($ch.Prefixes.Count) sent" } else { 'not there' })" }
        } catch { & $Log 'Warning' "  $name`: NOT written - $((("$($_.Exception.Message)") -split '->')[-1].Trim())"; $out.Failed++; continue }
        $p = @{ t = $tag; j = (ConvertTo-Json -InputObject @($ch.Prefixes) -Compress) } + (New-EpsJournalParameters -Actor 'NamedLocations job' -Entity 'NamedLocation' -Key $name -Action $(if ($cur.Count) { 'Update' } else { 'Create' }) -Before $(if ($cached.Count) { ConvertTo-Json -InputObject @{ prefixes = $cached.Count } -Compress }) -After (ConvertTo-Json -InputObject ([ordered]@{ id = "$($l.id)"; prefixes = $ch.Prefixes.Count; why = $ch.Reason }) -Compress))
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.ServiceTagPrefix WHERE Tag = @t;
INSERT INTO eps.ServiceTagPrefix (Tag, Prefix) SELECT @t, LEFT(x.value, 64) FROM OPENJSON(@j) AS x;
$(Get-EpsJournalSql)
COMMIT;
"@)
        & $Log 'Info' "  $name`: $(if ($cur.Count) { 'updated' } else { 'created' }) - $($ch.Reason)"
        $out.Written++
        if (-not $cur.Count) { $locs = @($locs) + @($l) }
    }
    $out
}
