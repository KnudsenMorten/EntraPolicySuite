# EntraPolicySuite -- the options of the Conditional Access Edit form (CA-EDIT-PICKERS).
#
#   Owner 2026-11-05: "where are the add buttn" / "make dropdown for fx block" / "too shaky for a text field" / "talk with
#   graph to understand the optins per field" / "consider a discovery process monthly to get available options per field
#   via graph".
#
#   * engine/ca/graph-enums.json - the value set of every field with a known set, as Graph v1.0 documents it (shipped,
#     pinned by tests/Test-EpsCaEdit.ps1); the form's fall-back.
#   * the CaOptions job (monthly, automatic; Run now) - reads Graph v1.0's $metadata (the EnumType members of those fields,
#     and the condition set's properties) and the tenant's lists (authentication strengths, named locations, terms of use,
#     role definitions) into eps.CaGraphOption. READS only. A value Graph has and the catalog has not = "new from Graph".
#   * the web app (SQL only): the form's options (Get-EpsCaEditOptions) and the picker's instant search of the names EPS
#     already stores (Find-EpsCaDirectoryNames); "Search the tenant" is an engine request (Search-EpsCaTenantDirectory,
#     reads only) whose results are stored as names, so the picker finds them.
# Dot-source EPS-SqlStore.ps1 (and, in the engine, EPS-Graph.ps1 + EPS-CaManage.ps1) first.

Set-StrictMode -Off
$script:EpsCaEnumCatalogFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'ca\graph-enums.json'
$script:EpsCaMetadataUri = 'https://graph.microsoft.com/v1.0/$metadata'
$script:EpsCaTenantFields = [ordered]@{ authStrength = 'tenant.authStrength'; location = 'tenant.location'; termsOfUse = 'tenant.termsOfUse'; role = 'tenant.role' }
$script:EpsCaPickKinds = @('user', 'group', 'role', 'location', 'application', 'authStrength')

function Get-EpsCaEnumCatalog {
    if (-not $script:EpsCaEnumCatalogCache) { $script:EpsCaEnumCatalogCache = Get-Content -LiteralPath $script:EpsCaEnumCatalogFile -Raw | ConvertFrom-Json -AsHashtable -Depth 10 }
    $script:EpsCaEnumCatalogCache
}

function ConvertFrom-EpsGraphMetadata {
    <#
      PURE: Graph's $metadata (CSDL XML) -> @{ Enums = @{ <EnumType name> = @(members) }; ConditionSet = @(property names) }.
      Only the microsoft.graph namespace (the one the policy uses).
    #>
    param([Parameter(Mandatory)][string]$Xml)
    $doc = [xml]::new(); $doc.XmlResolver = $null; $doc.LoadXml($Xml)
    $enums = @{}; $cs = @()
    foreach ($s in @($doc.SelectNodes("//*[local-name()='Schema' and @Namespace='microsoft.graph']"))) {
        foreach ($e in @($s.SelectNodes("*[local-name()='EnumType']"))) { $enums["$($e.Name)"] = @($e.SelectNodes("*[local-name()='Member']") | ForEach-Object { "$($_.Name)" }) }
        $c = $s.SelectSingleNode("*[local-name()='ComplexType' and @Name='conditionalAccessConditionSet']")
        if ($c) { $cs = @($c.SelectNodes("*[local-name()='Property']") | ForEach-Object { "$($_.Name)" }) }
    }
    @{ Enums = $enums; ConditionSet = $cs }
}

function Get-EpsCaOptionRows {
    <#
      PURE: the catalog + the parsed $metadata -> the rows the job stores (Source = metadata) and what it reports:
      NewFromGraph (field = value pairs Graph has and the catalog has not), NotInGraph (catalog values Graph no longer
      lists - kept, and said), MissingTypes (an EnumType Graph does not have), UnknownConditions (condition-set properties
      EPS does not know). unknownFutureValue and a field's 'omit' members are never offered.
    #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)]$Metadata)
    $rows = [System.Collections.Generic.List[object]]::new(); $new = [System.Collections.Generic.List[string]]::new()
    $gone = [System.Collections.Generic.List[string]]::new(); $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @($Catalog.fields)) {
        if (-not $f.enumType) { continue }
        $members = $Metadata.Enums[$f.enumType]
        if ($null -eq $members) { $missing.Add("$($f.field) ($($f.enumType))"); continue }
        $skip = @('unknownFutureValue') + @($f.omit)
        foreach ($v in @($members | Where-Object { $_ -notin $skip })) {
            $in = $v -cin @($f.values)
            $rows.Add(@{ Field = $f.field; Value = $v; Label = $null; Detail = $f.enumType; Source = 'metadata'; InCatalog = $in })
            if (-not $in) { $new.Add("$($f.field) = $v") }
        }
        foreach ($v in @($f.values)) { if ($v -cnotin @($members)) { $gone.Add("$($f.field) = $v") } }
    }
    $known = @($Catalog.conditionSet.known)
    $unknown = @($Metadata.ConditionSet | Where-Object { $_ -notin $known -and $_ -notlike '*@odata*' })
    @{ Rows = @($rows); NewFromGraph = @($new); NotInGraph = @($gone); MissingTypes = @($missing); UnknownConditions = @($unknown) }
}

function Read-EpsCaTenantOptions {
    # the engine: the tenant's lists the form offers, by GET with the engine's own read rights (Policy.Read.All,
    # RoleManagement.Read.Directory). A list it cannot read is said in Notes and left out (never guessed).
    param([System.Collections.Generic.List[string]]$Notes)
    $note = { param($m) if ($null -ne $Notes) { $Notes.Add($m) } }
    $rows = [System.Collections.Generic.List[object]]::new(); $read = [System.Collections.Generic.List[string]]::new()
    $add = { param($kind, $id, $name, $detail) if ($id) { $rows.Add(@{ Field = $script:EpsCaTenantFields[$kind]; Value = [string]$id; Label = [string]$name; Detail = $(if ($detail) { [string]$detail }); Source = 'tenant'; InCatalog = $true }) } }
    try { foreach ($s in @(Invoke-EpsGraph -Path 'v1.0/policies/authenticationStrengthPolicies?$select=id,displayName,policyType' -All)) { & $add 'authStrength' $s.id $s.displayName $s.policyType }; $read.Add('authStrength') }
    catch { & $note "authentication strengths could not be read: $($_.Exception.Message)" }
    try { foreach ($l in @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All)) { & $add 'location' $l.id $l.displayName $(if ($l.'@odata.type') { "$($l.'@odata.type')" -replace '^#microsoft\.graph\.', '' }) }; $read.Add('location') }
    catch { & $note "named locations could not be read: $($_.Exception.Message)" }
    # a policy names a directory role by its TEMPLATE id (built-in roles: the same as the id)
    try { foreach ($r in @(Invoke-EpsGraph -Path 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn' -All)) { & $add 'role' $(if ($r.templateId) { $r.templateId } else { $r.id }) $r.displayName $(if ($r.isBuiltIn) { 'built-in' } else { 'custom' }) }; $read.Add('role') }
    catch { & $note "directory roles could not be read: $($_.Exception.Message)" }
    # terms of use need Agreement.Read.All, which the engine does not hold: tried, and said when refused
    try { foreach ($a in @(Invoke-EpsGraph -Path 'v1.0/identityGovernance/termsOfUse/agreements?$select=id,displayName' -All)) { & $add 'termsOfUse' $a.id $a.displayName $null }; $read.Add('termsOfUse') }
    catch { & $note "terms of use could not be read (the engine holds no Agreement.Read.All; a policy's terms of use are kept as they are and editable in Advanced (JSON)): $($_.Exception.Message)" }
    @{ Rows = @($rows); Read = @($read) }
}

function Save-EpsCaGraphOptions {
    # the engine: upsert the rows (FirstSeen kept, LastSeen now); a TENANT list that was read this run loses the objects
    # that are gone. Returns the keys that are NEW in the table (first seen this run).
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Rows = @(), [string[]]$TenantFieldsRead = @())
    $have = @{}; foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Field, Value FROM eps.CaGraphOption')) { $have["$($r.Field)|$($r.Value)"] = 1 }
    $first = @($Rows | Where-Object { -not $have.ContainsKey("$($_.Field)|$($_.Value)") } | ForEach-Object { "$($_.Field) = $($_.Value)" })
    $j = if (@($Rows).Count) { ConvertTo-Json -InputObject @($Rows | ForEach-Object { @{ f = $_.Field; v = $_.Value; l = $_.Label; d = $_.Detail; s = $_.Source; c = [int][bool]$_.InCatalog } }) -Compress -Depth 4 } else { '[]' }
    $tf = ConvertTo-Json -InputObject @($TenantFieldsRead | ForEach-Object { $script:EpsCaTenantFields[$_] } | Where-Object { $_ }) -Compress
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ j = $j; tf = $(if ($tf) { $tf } else { '[]' }) } -Query @'
SET XACT_ABORT ON; BEGIN TRAN;
DECLARE @now DATETIME2 = SYSUTCDATETIME();
MERGE eps.CaGraphOption AS t
USING (SELECT f, v, l, d, s, c FROM OPENJSON(@j) WITH (f NVARCHAR(200) '$.f', v NVARCHAR(200) '$.v', l NVARCHAR(400) '$.l', d NVARCHAR(400) '$.d', s NVARCHAR(20) '$.s', c BIT '$.c')) AS x
ON t.Field = x.f AND t.Value = x.v
WHEN MATCHED THEN UPDATE SET Label = x.l, Detail = x.d, Source = x.s, InCatalog = x.c, LastSeenUtc = @now
WHEN NOT MATCHED THEN INSERT (Field, Value, Label, Detail, Source, InCatalog, FirstSeenUtc, LastSeenUtc) VALUES (x.f, x.v, x.l, x.d, x.s, x.c, @now, @now);
DELETE FROM eps.CaGraphOption WHERE Source = 'tenant' AND LastSeenUtc < @now AND Field IN (SELECT value FROM OPENJSON(@tf));
COMMIT;
'@)
    @($first)
}

function Invoke-EpsCaOptionsDiscovery {
    <#
      The CaOptions job (monthly, automatic; Run now): Graph v1.0's $metadata -> the value set of every field the Edit
      form offers, and the tenant's lists -> eps.CaGraphOption. READS the tenant only. Returns @{ Ok; MetadataRead;
      NewFromGraph; NotInGraph; MissingTypes; UnknownConditions; Tenant (field -> count); Notes }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $notes = [System.Collections.Generic.List[string]]::new()
    $cat = Get-EpsCaEnumCatalog
    $opt = $null
    try {
        $r = & $script:EpsHttp 'GET' $script:EpsCaMetadataUri @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://graph.microsoft.com')"; Accept = 'application/xml' } $null
        if ($r.Status -ge 400) { throw "Graph `$metadata -> $($r.Status)" }
        $opt = Get-EpsCaOptionRows -Catalog $cat -Metadata (ConvertFrom-EpsGraphMetadata -Xml ([string]$r.Body))
        & $Log 'Info' "Graph v1.0 `$metadata read: $(@($opt.Rows).Count) values for $(@($cat.fields | Where-Object { $_.enumType }).Count) fields"
    } catch { $notes.Add("Graph's `$metadata could not be read - the form keeps the shipped catalog: $($_.Exception.Message)") }
    $ten = Read-EpsCaTenantOptions -Notes $notes
    $rows = @(); if ($opt) { $rows += @($opt.Rows) }; $rows += @($ten.Rows)
    $first = Save-EpsCaGraphOptions -ConnectionString $ConnectionString -Rows $rows -TenantFieldsRead @($ten.Read)
    $tenant = [ordered]@{}; foreach ($k in $script:EpsCaTenantFields.Keys) { if ($k -in $ten.Read) { $tenant[$k] = @($ten.Rows | Where-Object Field -eq $script:EpsCaTenantFields[$k]).Count } }
    $newG = if ($opt) { @($opt.NewFromGraph) } else { @() }
    foreach ($n in $newG) { & $Log 'Warning' "new from Graph (not in the shipped catalog; the form offers it, marked): $n" }
    if ($opt) {
        foreach ($n in @($opt.NotInGraph)) { & $Log 'Warning' "in the catalog but not in Graph's `$metadata any more: $n" }
        foreach ($n in @($opt.MissingTypes)) { & $Log 'Warning' "Graph's `$metadata has no EnumType for: $n" }
        if (@($opt.UnknownConditions).Count) { & $Log 'Warning' "conditions Graph has that the form does not show (kept as they are; Advanced (JSON)): $(@($opt.UnknownConditions) -join ', ')" }
    }
    & $Log 'Info' "tenant lists: $((@($tenant.Keys | ForEach-Object { "$_ $($tenant[$_])" })) -join ', '); first seen this run: $(@($first).Count)"
    foreach ($n in $notes) { & $Log 'Warning' $n }
    @{ Ok = ($null -ne $opt -or @($ten.Read).Count -gt 0); MetadataRead = ($null -ne $opt); NewFromGraph = $newG; NotInGraph = $(if ($opt) { @($opt.NotInGraph) } else { @() })
       MissingTypes = $(if ($opt) { @($opt.MissingTypes) } else { @() }); UnknownConditions = $(if ($opt) { @($opt.UnknownConditions) } else { @() }); Tenant = $tenant; FirstSeen = @($first); Notes = @($notes) }
}

function Get-EpsCaEditOptions {
    <#
      The web app (SQL only): what the Edit form offers. Per field: the catalog's values in its order, then a value the
      discovery found that the catalog has not (isNew = "new from Graph"). The tenant's lists from the discovery, else
      from the names the policy read stored. The break-glass accounts and group(s), so the form can mark them.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $cat = Get-EpsCaEnumCatalog
    $tab = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Field, Value, Label, Detail, Source, InCatalog, FirstSeenUtc, LastSeenUtc FROM eps.CaGraphOption')
    $fields = [ordered]@{}
    foreach ($f in @($cat.fields)) {
        $vals = [System.Collections.Generic.List[object]]::new()
        foreach ($v in @($f.values)) { $vals.Add([ordered]@{ value = $v; isNew = $false }) }
        foreach ($r in @($tab | Where-Object { $_.Source -eq 'metadata' -and $_.Field -eq $f.field -and -not $_.InCatalog })) { if ("$($r.Value)" -cnotin @($f.values)) { $vals.Add([ordered]@{ value = [string]$r.Value; isNew = $true }) } }
        $fields[$f.field] = [ordered]@{ label = $f.label; doc = $f.doc; values = @($vals) }
    }
    $names = Get-EpsCaNameMap -ConnectionString $ConnectionString
    $tenant = [ordered]@{}
    $fromNames = @{ authStrength = 'authStrength'; location = 'location'; role = 'role' }
    foreach ($k in $script:EpsCaTenantFields.Keys) {
        $rows = @($tab | Where-Object { $_.Source -eq 'tenant' -and $_.Field -eq $script:EpsCaTenantFields[$k] } | ForEach-Object { [ordered]@{ id = [string]$_.Value; name = [string]$_.Label; detail = $(if ($_.Detail -isnot [DBNull]) { [string]$_.Detail }) } })
        if (-not $rows.Count -and $fromNames[$k]) { $rows = @(foreach ($key in @($names.Keys)) { $n = $names[$key]; if ($n.Kind -eq $fromNames[$k]) { [ordered]@{ id = ($key -split '\|', 2)[1]; name = $n.Name; detail = $n.Detail } } }) }
        $tenant[$k] = @($rows | Sort-Object { "$($_.name)" })
    }
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -NoGraph
    $bgGroups = @(foreach ($g in @($ctx.BreakGlass.RelatedGroupIds)) { [ordered]@{ id = "$g"; name = $(if ($names["group|$("$g".ToLowerInvariant())"]) { $names["group|$("$g".ToLowerInvariant())"].Name }) } })
    $bgUsers = @(foreach ($a in @($ctx.BreakGlass.Accounts)) { [ordered]@{ id = "$($a.Id)"; upn = "$($a.Upn)" } })
    $disc = @($tab | Where-Object Source -eq 'metadata' | ForEach-Object LastSeenUtc | Sort-Object -Descending)[0]
    @{ fields = $fields; keywords = $cat.keywords; tenant = $tenant; breakGlass = @{ users = $bgUsers; groups = $bgGroups }
       discoveredAtUtc = $disc; graphVersion = $cat.graphVersion }
}

function Find-EpsCaDirectoryNames {
    <#
      The web app (SQL only): the picker's instant search of the names EPS already stores - the names the policy read
      found, the managed and target groups, the break-glass accounts, the tenant lists of the discovery. A contains-match
      on the name (and a user's UPN); at most -Top. Returns @{ value (the id, or the name when EPS knows no id); name;
      detail; kind }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('user', 'group', 'role', 'location', 'application', 'authStrength')][string]$Kind, [string]$Text = '', [int]$Top = 20)
    $t = "%$(("$Text".Trim()) -replace '([\[\]%_])', '[$1]')%"
    $out = [System.Collections.Generic.List[object]]::new(); $seen = @{}
    $put = { param($v, $n, $d) if (-not $v) { return }; $k = "$v".ToLowerInvariant(); if ($seen.ContainsKey($k) -or $out.Count -ge $Top) { return }; $seen[$k] = 1; $out.Add([ordered]@{ value = [string]$v; name = [string]$n; detail = $(if ($null -ne $d -and $d -isnot [DBNull] -and "$d" -ne '') { [string]$d }); kind = $Kind }) }
    # the discovery's tenant lists first (a role by its template id, as a policy names it), then the names the read stored
    $tf = @{ authStrength = 'tenant.authStrength'; location = 'tenant.location'; role = 'tenant.role' }[$Kind]
    if ($tf) { foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ f = $tf; t = $t; n = $Top } -Query 'SELECT TOP (@n) Value, Label, Detail FROM eps.CaGraphOption WHERE Field = @f AND Label LIKE @t ORDER BY Label')) { & $put $r.Value $r.Label $r.Detail } }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ k = $Kind; t = $t; n = $Top } -Query "SELECT TOP (@n) ObjectId, Name, CASE WHEN Kind = 'group' THEN NULL ELSE Detail END AS Detail FROM eps.CaDirectoryName WHERE Kind = @k AND (Name LIKE @t OR (Kind = 'user' AND Detail LIKE @t)) ORDER BY Name")) {
        # a role is stored under its id AND its template id: offer one entry per name
        if ($Kind -eq 'role' -and @($out | Where-Object { $_.name -eq [string]$r.Name }).Count) { continue }
        & $put $r.ObjectId $r.Name $r.Detail }
    if ($Kind -eq 'group') {
        foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ t = $t; n = $Top } -Query 'SELECT TOP (@n) Name, ObjectId FROM eps.ManagedGroup WHERE Name LIKE @t ORDER BY Name')) { & $put $(if ($r.ObjectId -and $r.ObjectId -isnot [DBNull]) { $r.ObjectId } else { $r.Name }) $r.Name 'managed group' }
        foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ t = $t; n = $Top } -Query 'SELECT DISTINCT TOP (@n) DisplayName FROM eps.TargetGroup WHERE DisplayName LIKE @t ORDER BY DisplayName')) { & $put $r.DisplayName $r.DisplayName 'target group (looked up by name)' }
    }
    if ($Kind -eq 'user') {
        foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ t = $t; n = $Top } -Query "SELECT TOP (@n) UserPrincipalName, DisplayName, ObjectId FROM eps.BreakGlassAccount WHERE Directory = 'Entra' AND (UserPrincipalName LIKE @t OR DisplayName LIKE @t) ORDER BY UserPrincipalName")) { & $put $(if ($r.ObjectId -and $r.ObjectId -isnot [DBNull]) { "$($r.ObjectId)" } else { $r.UserPrincipalName }) $(if ($r.DisplayName -and $r.DisplayName -isnot [DBNull]) { $r.DisplayName } else { $r.UserPrincipalName }) "$($r.UserPrincipalName) (break-glass)" }
    }
    @($out)
}

function Search-EpsCaTenantDirectory {
    <#
      The engine (an Admin's request, READS only): objects in the tenant whose name starts with -Text, at most -Top, with
      the engine's read rights. Returns "kind|id" -> @{ Kind; Name; Detail } - stored as names, so the picker finds them.
    #>
    param([Parameter(Mandatory)][ValidateSet('user', 'group', 'role', 'location', 'application', 'authStrength')][string]$Kind, [Parameter(Mandatory)][string]$Text, [int]$Top = 20)
    $q = ("$Text".Trim()).Replace("'", "''"); if (-not $q) { throw 'type the start of a name to search for' }
    $e = [uri]::EscapeDataString($q)
    $names = @{}
    $put = { param($k, $id, $n, $d) if ($id) { $names["$k|$("$id".ToLowerInvariant())"] = @{ Kind = $k; Name = [string]$n; Detail = $(if ($d) { [string]$d }) } } }
    switch ($Kind) {
        'user' { foreach ($u in @((Invoke-EpsGraph -Path "v1.0/users?`$filter=startswith(displayName,'$e') or startswith(userPrincipalName,'$e')&`$select=id,displayName,userPrincipalName&`$top=$Top").value)) { & $put 'user' $u.id $u.displayName $u.userPrincipalName } }
        'group' { foreach ($g in @((Invoke-EpsGraph -Path "v1.0/groups?`$filter=startswith(displayName,'$e')&`$select=id,displayName,membershipRule&`$top=$Top").value)) { & $put 'group' $g.id $g.displayName $g.membershipRule } }
        'application' { foreach ($s in @((Invoke-EpsGraph -Path "v1.0/servicePrincipals?`$filter=startswith(displayName,'$e')&`$select=appId,displayName&`$top=$Top").value)) { & $put 'application' $s.appId $s.displayName $null } }
        'role' { foreach ($r in @(Invoke-EpsGraph -Path 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId' -All | Where-Object { "$($_.displayName)" -like "$Text*" } | Select-Object -First $Top)) { & $put 'role' $(if ($r.templateId) { $r.templateId } else { $r.id }) $r.displayName $null } }
        'location' { foreach ($l in @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All | Where-Object { "$($_.displayName)" -like "*$Text*" } | Select-Object -First $Top)) { & $put 'location' $l.id $l.displayName $null } }
        'authStrength' { foreach ($s in @(Invoke-EpsGraph -Path 'v1.0/policies/authenticationStrengthPolicies?$select=id,displayName,policyType' -All | Where-Object { "$($_.displayName)" -like "*$Text*" } | Select-Object -First $Top)) { & $put 'authStrength' $s.id $s.displayName $s.policyType } }
    }
    $names
}

function Save-EpsCaPickNames {
    # the engine: the found objects as names (the stored names of those keys replaced; nothing else touched)
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$Names = @{})
    $rows = @(foreach ($k in $Names.Keys) { $n = $Names[$k]; @{ k = $n.Kind; i = ($k -split '\|', 2)[1]; n = $n.Name; d = $n.Detail } })
    if (-not $rows.Count) { return 0 }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ nj = (ConvertTo-Json -InputObject @($rows) -Compress -Depth 4) } -Query @'
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaDirectoryName WHERE EXISTS (SELECT 1 FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '$.k', i NVARCHAR(100) '$.i') AS x WHERE x.k = eps.CaDirectoryName.Kind AND x.i = eps.CaDirectoryName.ObjectId);
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail) SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '$.k', i NVARCHAR(100) '$.i', n NVARCHAR(MAX) '$.n', d NVARCHAR(MAX) '$.d') AS x;
COMMIT;
'@)
    $rows.Count
}
