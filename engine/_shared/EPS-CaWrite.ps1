# EntraPolicySuite -- the ONE place that changes a Conditional Access policy (CA-LIFECYCLE, DESIGN §5.1 "Lifecycle").
#
#   The hard rule (owner 2026-10-30): "it must not automatically do things i have not approved. otherwise i can be locked
#   out of my tenant !!" - and the owner's answers 2026-11-03: "Write on approval" (Policy.ReadWrite.ConditionalAccess for
#   the engine; each button moves ONE adopted policy ONE stage, only after the operator saw the before / after and gave a
#   reason; refused when the break-glass accounts would not be excluded; journaled and audited; no schedule, job or monitor
#   ever writes) and "SuperAdmin only".
#
# Loaded by the ENGINE only (tools/eps-engine/job-entry.ps1): the web app never loads this file, so it cannot write a
# policy even by mistake. Called ONLY from the routes POST /api/capolicies/policies/{policy}/stage, /edit and /clone, which
# the engine runs from the SuperAdmin's signed request (Invoke-EpsEngineConfigRequest). tests/Test-EpsNoCaWrite.ps1 fails
# the build when a Conditional Access write appears anywhere else, or when anything but its route calls one of them.

Set-StrictMode -Off

function Resolve-EpsCaStageIds {
    # the plan's names -> the tenant's ids, by GET: a group by its exact name (exactly one), a user by UPN (a break-glass
    # account's stored id first), keywords (All, None, GuestsOrExternalUsers) as they are. Returns @{ Ok; Reason; Set
    # (path -> ids); Names (new "kind|id" -> name entries) }.
    param([Parameter(Mandatory)]$Plan, $Ctx = @{})
    $set = [ordered]@{}; $names = @{}
    foreach ($path in @($Plan.set.Keys)) {
        $x = $Plan.set[$path]; $ids = [System.Collections.Generic.List[string]]::new()
        foreach ($v in @($x.values)) {
            if ($v -in $script:EpsCaUserKeywords) { $ids.Add($v); continue }
            if ($x.kind -eq 'group') {
                $g = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$("$v".Replace("'", "''"))'&`$select=id,displayName,membershipRule" -All)
                if ($g.Count -ne 1) { return @{ Ok = $false; Reason = $(if (-not $g.Count) { "the group $v is not in the tenant (v1's Initial_Setup creates it) - create it first" } else { "$($g.Count) groups are named $v - the move needs exactly one" }) } }
                $ids.Add([string]$g[0].id); $names["group|$("$($g[0].id)".ToLowerInvariant())"] = @{ Kind = 'group'; Name = [string]$g[0].displayName; Detail = $(if ($g[0].membershipRule) { [string]$g[0].membershipRule }) }
            } elseif ($x.kind -eq 'user') {
                $id = @($Ctx.BreakGlass.Accounts | Where-Object { "$($_.Upn)" -ieq "$v" -and $_.Id } | ForEach-Object { "$($_.Id)" })[0]
                if (-not $id) { try { $id = [string](Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString("$v"))?`$select=id").id } catch { return @{ Ok = $false; Reason = "the user $v could not be read: $($_.Exception.Message)" } } }
                $ids.Add($id); $names["user|$($id.ToLowerInvariant())"] = @{ Kind = 'user'; Name = "$v"; Detail = "$v".ToLowerInvariant() }
            } else { return @{ Ok = $false; Reason = "$path ($($x.kind)) is not a setting a stage move changes" } }
        }
        $set[$path] = @($ids)
    }
    @{ Ok = $true; Set = $set; Names = $names }
}

function Invoke-EpsCaStageMove {
    <#
      Moves ONE adopted policy to another stage (any stage, owner 2026-11-03) (the operator's request, applied by the engine):
        1. the policy must be adopted; it is read LIVE (GET) and must be exactly the policy the operator looked at
           (-Expected = the review hash he saw) - else refused, nothing written
        2. the plan is made again from the live policy (Get-EpsCaStagePlan) and the names resolved to ids (GET)
        3. the break-glass check on the RESULT: refused unless the break-glass accounts stay excluded (it never "fixes")
        4. ONE PATCH of that policy: its name, its state and the users it targets - nothing else
        5. read back (GET) and compared with the plan; recorded: eps.CaPolicy (the new body + review), the adoption
           baseline = the body as deployed (the monitor does not call our own change a drift), eps.CaStageMove (before /
           after, for the history and a step back), the journal
      Returns @{ Result = ok | notadopted | missing | changed | refused | failed; Reason; Plan; Before; After; Verified }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)][string]$To, [string]$Expected,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $ad = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT Status FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    if (-not $ad -or "$($ad.Status)" -ne 'Adopted') { return @{ Result = 'notadopted'; Reason = 'only an adopted policy moves through the stages - adopt it first' } }
    $raw = try { Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" } catch { if ("$_" -match '(?i)404|not ?found|ResourceNotFound') { return @{ Result = 'missing'; Reason = 'the policy is no longer in the tenant' } }; throw }
    $live = $raw | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 20
    $hash = Get-EpsCaBodyHash $live
    if (-not $Expected -or $Expected -ne $hash) { return @{ Result = 'changed'; Reason = 'the policy in the tenant is not the one you looked at (it changed since the last read) - read the list again and look again' } }
    $notes = [System.Collections.Generic.List[string]]::new()
    $names = Resolve-EpsCaDirectoryNames -Policies @($live) -Notes $notes
    $cat = Get-EpsCaTemplateCatalog
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -Notes $notes -Catalog $cat
    $review = Get-EpsCaReview -Policy $live -Names $names -Ctx $ctx -Catalog $cat
    $plan = Get-EpsCaStagePlan -Policy $live -Review $review -To $To -Ctx $ctx -Names $names -Catalog $cat
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    $rs = Resolve-EpsCaStageIds -Plan $plan -Ctx $ctx
    if (-not $rs.Ok) { return @{ Result = 'refused'; Reason = $rs.Reason; Plan = $plan } }
    foreach ($k in $rs.Names.Keys) { $names[$k] = $rs.Names[$k] }
    # the change: the name, the state, and the users block as read with the planned lists in it (Graph keeps the other
    # conditions as they are; the users block is sent whole, so nothing in it is left to a partial merge)
    $patch = [ordered]@{ state = $plan.stateAfter }
    if ($plan.displayNameAfter -cne $plan.displayNameBefore) { $patch.displayName = $plan.displayNameAfter }
    if ($rs.Set.Count) {
        $users = [ordered]@{}
        $cur = Get-EpsCaV $live 'conditions.users'
        foreach ($k in @($cur.Keys)) { if ("$k" -notlike '@odata*' -and $null -ne $cur[$k]) { $users[$k] = $cur[$k] } }
        foreach ($path in $rs.Set.Keys) { $users[($path -split '\.')[-1]] = @($rs.Set[$path]) }
        $patch.conditions = [ordered]@{ users = $users }
    }
    # the break-glass check on the RESULT (a disabled policy cannot lock anyone out - Disable always passes)
    $after = $live | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 20
    $after.state = $patch.state; if ($patch.displayName) { $after.displayName = $patch.displayName }
    if ($patch.conditions) { $after.conditions.users = $patch.conditions.users }
    $t = $cat.ById["$($review.templateId)"]
    $bg = Test-EpsCaBreakGlassExclusion -Policy $after -BreakGlass $ctx.BreakGlass -IsBreakGlassPolicy ([bool]($t -and $t.breakGlassPolicy))
    if ($To -ne 'Disabled' -and $bg.Ok -ne $true) { return @{ Result = 'refused'; Reason = "the break-glass check refuses it: $($bg.Text)"; Plan = $plan } }
    # CA-GROUPS P3 (V1-PARITY, CAnnn.ps1 with Dynamic_Using_Tags): the dynamic pilot group takes the stage's rule FIRST, as
    # v1 does - refused (the policy untouched) when it cannot (EPS-GroupWrite.ps1)
    if (Get-Command Set-EpsPilotGroupForStage -ErrorAction SilentlyContinue) {
        $pg = Set-EpsPilotGroupForStage -ConnectionString $ConnectionString -TemplateId "$($review.templateId)" -To $To -Actor $Actor -Reason $Reason -Log $Log
        if ($pg.Result -in 'refused', 'failed') { return @{ Result = 'refused'; Reason = "the pilot group: $($pg.Reason)"; Plan = $plan } }
    }
    & $Log 'Info' "CA stage move: $($plan.displayNameBefore) $($plan.from) -> $To, requested by $Actor"
    # THE write (the only Conditional Access write in EntraPolicySuite)
    try { [void](Invoke-EpsGraph -Method 'PATCH' -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" -Body $patch) }
    catch { return @{ Result = 'failed'; Reason = "the tenant refused the change: $($_.Exception.Message)$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })"; Plan = $plan } }
    # read back and compare with the plan
    $now = (Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId") | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 20
    $off = [System.Collections.Generic.List[string]]::new()
    if ("$($now.state)" -ne $plan.stateAfter) { $off.Add("state is $($now.state)") }
    if ("$($now.displayName)" -cne $plan.displayNameAfter) { $off.Add("name is $($now.displayName)") }
    foreach ($path in $rs.Set.Keys) {
        $a = (@(Get-EpsCaList $now $path | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join ','); $b = (@($rs.Set[$path] | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join ',')
        if ($a -ne $b) { $off.Add("$path is [$a]") }
    }
    $nowReview = Get-EpsCaReview -Policy $now -Names $names -Ctx $ctx -Catalog $cat
    $nowHash = Get-EpsCaBodyHash $now
    $before = [ordered]@{ displayName = $plan.displayNameBefore; state = $plan.stateBefore; stage = $plan.from; hash = $hash }
    $afterRec = [ordered]@{ displayName = "$($now.displayName)"; state = "$($now.state)"; stage = $nowReview.stage; hash = $nowHash; changes = @($plan.changes) }
    $nameRows = @(foreach ($k in $rs.Names.Keys) { $n = $rs.Names[$k]; @{ k = $n.Kind; i = ($k -split '\|', 2)[1]; n = $n.Name; d = $n.Detail } })
    $p = @{ p = $PolicyId; n = "$($now.displayName)"; s = "$($now.state)"; m = $(if ($now.modifiedDateTime) { [datetimeoffset]"$($now.modifiedDateTime)" } else { [DBNull]::Value })
            b = ($now | ConvertTo-Json -Compress -Depth 20); r = ($nowReview | ConvertTo-Json -Compress -Depth 20)
            cb = ((ConvertTo-EpsCaCanonical $now) | ConvertTo-Json -Compress -Depth 20); ch = $nowHash; st = "$($nowReview.stage)"
            f = $plan.from; t = $To; bj = ($live | ConvertTo-Json -Compress -Depth 20); res = $(if ($off.Count) { 'applied, differs' } else { 'applied' }); rt = ($off -join '; '); by = $Actor; rs = $Reason
            nj = $(if ($nameRows.Count) { ConvertTo-Json -InputObject @($nameRows) -Compress -Depth 4 } else { '[]' }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaPolicy' -Key "$PolicyId" -Action 'Update' -Before ($before | ConvertTo-Json -Compress) -After ($afterRec | ConvertTo-Json -Compress -Depth 6))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaPolicy WHERE PolicyId = @p;
INSERT INTO eps.CaPolicy (PolicyId, DisplayName, State, ModifiedAtUtc, BodyJson, ReviewJson) VALUES (@p, @n, @s, @m, @b, @r);
DELETE FROM eps.CaDirectoryName WHERE EXISTS (SELECT 1 FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i') AS x WHERE x.k = eps.CaDirectoryName.Kind AND x.i = eps.CaDirectoryName.ObjectId);
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail) SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i', n NVARCHAR(MAX) '`$.n', d NVARCHAR(MAX) '`$.d') AS x;
UPDATE eps.CaAdoption SET DisplayName = @n, AdoptedBodyJson = @cb, AdoptedBodyHash = @ch WHERE PolicyId = @p AND Status = 'Adopted';
INSERT INTO eps.CaStageMove (PolicyId, DisplayName, FromStage, ToStage, BeforeJson, AfterJson, Result, ResultText, RequestedBy, Reason) VALUES (@p, @n, @f, @t, @bj, @b, @res, @rt, @by, @rs);
$(Get-EpsJournalSql)
COMMIT;
"@)
    if ($off.Count) { & $Log 'Warning' "  applied, but the policy as read back differs from the plan: $($off -join '; ')" }
    @{ Result = 'ok'; Plan = $plan; Before = $before; After = $afterRec; Verified = (-not $off.Count); Differs = @($off) }
}

# ---- CA-EDIT (owner 2026-11-05: "where is the option to modify or/and clone a policy" -> "Edit + clone, any field";
# "again once a policy is imported into from the templates, then it should be fuly manageable in the gui"; "but it is
# always 100% opeator controlled"). Two more writes, under the same rules as the stage move: ONE adopted policy, read live
# and refused when it is not the one the operator looked at, the break-glass check on the RESULT (refused, never fixed),
# ONE write, read back, recorded and journaled. Each has ONE caller, its route (SuperAdmin, a reason, applied by the
# engine from the signed request) - no job, schedule, monitor or retry calls them (tests/Test-EpsNoCaWrite.ps1).

function Get-EpsCaEditLookup {
    # the engine's lookup of a NAME the operator typed in a list -> its id, by GET (exactly one match, else a reason)
    {
        param($kind, $v)
        $esc = "$v".Replace("'", "''")
        switch ($kind) {
            'group' {
                $g = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$esc'&`$select=id,displayName,membershipRule" -All)
                if ($g.Count -ne 1) { return @{ Reason = $(if (-not $g.Count) { "the group '$v' is not in the tenant" } else { "$($g.Count) groups are named '$v' - give its id instead" }) } }
                return @{ Id = [string]$g[0].id; Name = [string]$g[0].displayName; Detail = $(if ($g[0].membershipRule) { [string]$g[0].membershipRule }) }
            }
            'user' {
                $u = try { Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString("$v"))?`$select=id,userPrincipalName" } catch { $null }
                if (-not $u -or -not $u.id) { return @{ Reason = "the user '$v' is not in the tenant" } }
                return @{ Id = [string]$u.id; Name = "$($u.userPrincipalName)"; Detail = "$($u.userPrincipalName)".ToLowerInvariant() }
            }
            'role' {
                $r = @(Invoke-EpsGraph -Path "v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$esc'&`$select=id,displayName,templateId" -All | Where-Object { "$($_.displayName)" -ieq "$v" })
                if ($r.Count -ne 1) { return @{ Reason = "the directory role '$v' is not known - give its id instead" } }
                return @{ Id = $(if ($r[0].templateId) { [string]$r[0].templateId } else { [string]$r[0].id }); Name = [string]$r[0].displayName }
            }
            'location' {
                $l = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/namedLocations' -All | Where-Object { "$($_.displayName)" -ieq "$v" })
                if ($l.Count -ne 1) { return @{ Reason = $(if (-not $l.Count) { "the named location '$v' is not in the tenant" } else { "$($l.Count) named locations are called '$v' - give its id instead" }) } }
                return @{ Id = [string]$l[0].id; Name = [string]$l[0].displayName }
            }
        }
        $null
    }
}

function Get-EpsCaEditContext {
    # what an edit / a clone needs about the live policy: the names, the context (break-glass), the review, its template
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Live)
    $notes = [System.Collections.Generic.List[string]]::new()
    $names = Resolve-EpsCaDirectoryNames -Policies @($Live) -Notes $notes
    $cat = Get-EpsCaTemplateCatalog
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -Notes $notes -Catalog $cat
    $review = Get-EpsCaReview -Policy $Live -Names $names -Ctx $ctx -Catalog $cat
    $t = $cat.ById["$($review.templateId)"]
    @{ Names = $names; Ctx = $ctx; Review = $review; Catalog = $cat; IsBreakGlassPolicy = [bool]($t -and $t.breakGlassPolicy) }
}

function Get-EpsCaEditReadBack {
    # the parts of a policy as read back that the plan set, compared the way the plan made them (read-only parts out)
    param($Now, $Plan, [string[]]$Parts)
    $src = [ordered]@{}; foreach ($k in $script:EpsCaEditTop) { if ($Now.Contains($k)) { $src[$k] = $Now[$k] } }
    $cn = ConvertTo-EpsCaCanonical ((ConvertTo-EpsCaEditBody $src).Body); $cp = ConvertTo-EpsCaCanonical $Plan.after
    @(foreach ($k in $Parts) { if ((ConvertTo-Json -InputObject $cn[$k] -Depth 30 -Compress) -cne (ConvertTo-Json -InputObject $cp[$k] -Depth 30 -Compress)) { "$k differs" } })
}

function Invoke-EpsCaPolicyEdit {
    <#
      Edits ONE adopted policy (the operator's request, applied by the engine) - any part an operator sets: name, state,
      conditions, grant, session (owner 2026-11-05: "Edit + clone, any field"):
        1. adopted, read LIVE, and exactly the policy the operator looked at (-Expected = the review hash) - else refused
        2. his body checked (only the parts he may set), the names he typed turned into ids (GET; one not found refuses)
        3. the plan (Get-EpsCaEditPlan): only the parts that really change; the break-glass check on the RESULT
        4. ONE PATCH of that policy with those parts; read back and compared; recorded (eps.CaPolicy, the adoption baseline
           so the monitor sees no drift, the history in eps.CaStageMove as '<stage> -> Edited', the journal)
      Returns @{ Result = ok | notadopted | invalid | missing | changed | refused | failed; Reason; Plan; Before; After; Verified; Differs }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)]$Policy, [string]$Expected,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $ad = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT Status FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    if (-not $ad -or "$($ad.Status)" -ne 'Adopted') { return @{ Result = 'notadopted'; Reason = 'only an adopted policy is edited from here - adopt it first' } }
    $e = ConvertTo-EpsCaEditBody $Policy
    if (-not $e.Ok) { return @{ Result = 'invalid'; Reason = $e.Reason } }
    $raw = try { Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" } catch { if ("$_" -match '(?i)404|not ?found|ResourceNotFound') { return @{ Result = 'missing'; Reason = 'the policy is no longer in the tenant' } }; throw }
    $live = $raw | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
    $hash = Get-EpsCaBodyHash $live
    if (-not $Expected -or $Expected -ne $hash) { return @{ Result = 'changed'; Reason = 'the policy in the tenant is not the one you looked at (it changed since the last read) - read the list again and look again' } }
    $x = Get-EpsCaEditContext -ConnectionString $ConnectionString -Live $live
    $rs = Resolve-EpsCaEditNames -Body $e.Body -Lookup (Get-EpsCaEditLookup) -Strict
    if (-not $rs.Ok) { return @{ Result = 'refused'; Reason = $rs.Reason } }
    foreach ($k in $rs.Names.Keys) { $x.Names[$k] = $rs.Names[$k] }
    $plan = Get-EpsCaEditPlan -Live $live -Edit $rs.Body -Mode Edit -BreakGlass $x.Ctx.BreakGlass -IsBreakGlassPolicy $x.IsBreakGlassPolicy -Names $x.Names
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    & $Log 'Info' "CA edit: $($plan.displayNameBefore) ($(@($plan.patch.Keys) -join ', ')), requested by $Actor"
    # THE write: ONE PATCH of this policy with the parts that change
    try { [void](Invoke-EpsGraph -Method 'PATCH' -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" -Body ($plan.patch | ConvertTo-Json -Depth 30 -Compress)) }
    catch { return @{ Result = 'failed'; Reason = "the tenant refused the change: $($_.Exception.Message)$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })"; Plan = $plan } }
    $now = (Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId") | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
    $off = @(Get-EpsCaEditReadBack -Now $now -Plan $plan -Parts @($plan.patch.Keys))
    $nowReview = Get-EpsCaReview -Policy $now -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog
    $nowHash = Get-EpsCaBodyHash $now
    $before = [ordered]@{ displayName = $plan.displayNameBefore; state = $plan.stateBefore; stage = $x.Review.stage; hash = $hash }
    $afterRec = [ordered]@{ displayName = "$($now.displayName)"; state = "$($now.state)"; stage = $nowReview.stage; hash = $nowHash; parts = @($plan.patch.Keys); changes = @($plan.changes | ForEach-Object { $_.path }) }
    $nameRows = @(foreach ($k in $rs.Names.Keys) { $n = $rs.Names[$k]; @{ k = $n.Kind; i = ($k -split '\|', 2)[1]; n = $n.Name; d = $n.Detail } })
    $p = @{ p = $PolicyId; n = "$($now.displayName)"; s = "$($now.state)"; m = $(if ($now.modifiedDateTime) { [datetimeoffset]"$($now.modifiedDateTime)" } else { [DBNull]::Value })
            b = ($now | ConvertTo-Json -Compress -Depth 30); r = ($nowReview | ConvertTo-Json -Compress -Depth 20)
            cb = ((ConvertTo-EpsCaCanonical $now) | ConvertTo-Json -Compress -Depth 30); ch = $nowHash
            f = "$($x.Review.stage)"; t = 'Edited'; bj = ($live | ConvertTo-Json -Compress -Depth 30); res = $(if ($off.Count) { 'applied, differs' } else { 'applied' })
            rt = $(if ($off.Count) { $off -join '; ' } else { "changed: $(@($plan.patch.Keys) -join ', ')" }); by = $Actor; rs = $Reason
            nj = $(if ($nameRows.Count) { ConvertTo-Json -InputObject @($nameRows) -Compress -Depth 4 } else { '[]' }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaPolicy' -Key "$PolicyId" -Action 'Update' -Before ($before | ConvertTo-Json -Compress) -After ($afterRec | ConvertTo-Json -Compress -Depth 6))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaPolicy WHERE PolicyId = @p;
INSERT INTO eps.CaPolicy (PolicyId, DisplayName, State, ModifiedAtUtc, BodyJson, ReviewJson) VALUES (@p, @n, @s, @m, @b, @r);
DELETE FROM eps.CaDirectoryName WHERE EXISTS (SELECT 1 FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i') AS x WHERE x.k = eps.CaDirectoryName.Kind AND x.i = eps.CaDirectoryName.ObjectId);
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail) SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i', n NVARCHAR(MAX) '`$.n', d NVARCHAR(MAX) '`$.d') AS x;
UPDATE eps.CaAdoption SET DisplayName = @n, AdoptedBodyJson = @cb, AdoptedBodyHash = @ch WHERE PolicyId = @p AND Status = 'Adopted';
INSERT INTO eps.CaStageMove (PolicyId, DisplayName, FromStage, ToStage, BeforeJson, AfterJson, Result, ResultText, RequestedBy, Reason) VALUES (@p, @n, @f, @t, @bj, @b, @res, LEFT(@rt, 2000), @by, @rs);
$(Get-EpsJournalSql)
COMMIT;
"@)
    if ($off.Count) { & $Log 'Warning' "  applied, but the policy as read back differs from the plan: $($off -join '; ')" }
    @{ Result = 'ok'; Plan = $plan; Before = $before; After = $afterRec; Verified = (-not $off.Count); Differs = @($off) }
}

function Invoke-EpsCaPolicyClone {
    <#
      Copies ONE adopted policy into a NEW one (the operator's request, applied by the engine), with his changes:
        1. the source adopted, read LIVE, exactly the one he looked at (-Expected) - else refused
        2. his body checked, names turned into ids (GET); a new name that no policy in the tenant has
        3. the plan (Get-EpsCaEditPlan -Mode Clone): ALWAYS created OFF (disabled), whatever the source's state; refused
           when the copy would not exclude the break-glass accounts
        4. ONE POST that creates it; read back; recorded and ADOPTED on creation (eps.CaPolicy, eps.CaAdoption with its
           baseline, the history 'Copy -> <stage>', the journal) - it then moves through the stages like any other
      Returns @{ Result = ok | notadopted | invalid | missing | changed | refused | failed; Reason; Plan; NewId; Before; After; Verified; Differs }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)]$Policy, [string]$Expected,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $ad = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = $PolicyId } -Query 'SELECT Status FROM eps.CaAdoption WHERE PolicyId = @p')[0]
    if (-not $ad -or "$($ad.Status)" -ne 'Adopted') { return @{ Result = 'notadopted'; Reason = 'only an adopted policy is copied from here - adopt it first' } }
    $e = ConvertTo-EpsCaEditBody $Policy
    if (-not $e.Ok) { return @{ Result = 'invalid'; Reason = $e.Reason } }
    $raw = try { Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" } catch { if ("$_" -match '(?i)404|not ?found|ResourceNotFound') { return @{ Result = 'missing'; Reason = 'the policy is no longer in the tenant' } }; throw }
    $live = $raw | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
    $hash = Get-EpsCaBodyHash $live
    if (-not $Expected -or $Expected -ne $hash) { return @{ Result = 'changed'; Reason = 'the policy in the tenant is not the one you looked at (it changed since the last read) - read the list again and look again' } }
    $x = Get-EpsCaEditContext -ConnectionString $ConnectionString -Live $live
    $rs = Resolve-EpsCaEditNames -Body $e.Body -Lookup (Get-EpsCaEditLookup) -Strict
    if (-not $rs.Ok) { return @{ Result = 'refused'; Reason = $rs.Reason } }
    foreach ($k in $rs.Names.Keys) { $x.Names[$k] = $rs.Names[$k] }
    $existing = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/policies?$select=id,displayName' -All | ForEach-Object { "$($_.displayName)" })
    $plan = Get-EpsCaEditPlan -Live $live -Edit $rs.Body -Mode Clone -BreakGlass $x.Ctx.BreakGlass -IsBreakGlassPolicy $x.IsBreakGlassPolicy -Names $x.Names -ExistingNames $existing
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    $create = [ordered]@{}; foreach ($k in $script:EpsCaEditTop) { if ($plan.after.Contains($k) -and $null -ne $plan.after[$k]) { $create[$k] = $plan.after[$k] } }
    & $Log 'Info' "CA clone: $($plan.displayNameBefore) -> $($plan.displayNameAfter) (off), requested by $Actor"
    # THE write: ONE POST that creates the copy, off
    $new = try { Invoke-EpsGraph -Method 'POST' -Path 'v1.0/identity/conditionalAccess/policies' -Body ($create | ConvertTo-Json -Depth 30 -Compress) }
           catch { return @{ Result = 'failed'; Reason = "the tenant refused the copy: $($_.Exception.Message)$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })"; Plan = $plan } }
    $newId = "$($new.id)"
    if ($newId -notmatch $script:EpsCaGuidRx) { return @{ Result = 'failed'; Reason = 'the tenant created the copy but did not return its id - read the policy list again'; Plan = $plan } }
    $now = (Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$newId") | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
    $off = @(Get-EpsCaEditReadBack -Now $now -Plan $plan -Parts @($create.Keys))
    $nowReview = Get-EpsCaReview -Policy $now -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog
    $nowHash = Get-EpsCaBodyHash $now
    $before = [ordered]@{ source = "$PolicyId"; displayName = $plan.displayNameBefore; state = $plan.stateBefore; stage = $x.Review.stage; hash = $hash }
    $afterRec = [ordered]@{ policyId = $newId; displayName = "$($now.displayName)"; state = "$($now.state)"; stage = $nowReview.stage; hash = $nowHash; status = 'Adopted' }
    $nameRows = @(foreach ($k in $rs.Names.Keys) { $n = $rs.Names[$k]; @{ k = $n.Kind; i = ($k -split '\|', 2)[1]; n = $n.Name; d = $n.Detail } })
    $p = @{ p = [guid]$newId; n = "$($now.displayName)"; s = "$($now.state)"; m = $(if ($now.modifiedDateTime) { [datetimeoffset]"$($now.modifiedDateTime)" } elseif ($now.createdDateTime) { [datetimeoffset]"$($now.createdDateTime)" } else { [DBNull]::Value })
            b = ($now | ConvertTo-Json -Compress -Depth 30); r = ($nowReview | ConvertTo-Json -Compress -Depth 20)
            cb = ((ConvertTo-EpsCaCanonical $now) | ConvertTo-Json -Compress -Depth 30); ch = $nowHash
            tid = $nowReview.templateId; tv = $nowReview.templateVersion; st = "$($nowReview.stage)"
            f = 'Copy'; t = $(if ($nowReview.stage) { "$($nowReview.stage)" } else { 'Initial' }); bj = ($live | ConvertTo-Json -Compress -Depth 30); res = $(if ($off.Count) { 'applied, differs' } else { 'applied' })
            rt = "a copy of $($plan.displayNameBefore) ($PolicyId)$(if ($off.Count) { ' - ' + ($off -join '; ') })"; by = $Actor; rs = $Reason
            nj = $(if ($nameRows.Count) { ConvertTo-Json -InputObject @($nameRows) -Compress -Depth 4 } else { '[]' }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaPolicy' -Key $newId -Action 'Create' -Before ($before | ConvertTo-Json -Compress) -After ($afterRec | ConvertTo-Json -Compress -Depth 6))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaPolicy WHERE PolicyId = @p;
INSERT INTO eps.CaPolicy (PolicyId, DisplayName, State, ModifiedAtUtc, BodyJson, ReviewJson) VALUES (@p, @n, @s, @m, @b, @r);
DELETE FROM eps.CaDirectoryName WHERE EXISTS (SELECT 1 FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i') AS x WHERE x.k = eps.CaDirectoryName.Kind AND x.i = eps.CaDirectoryName.ObjectId);
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail) SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i', n NVARCHAR(MAX) '`$.n', d NVARCHAR(MAX) '`$.d') AS x;
MERGE eps.CaAdoption AS x USING (SELECT @p AS PolicyId) AS s ON x.PolicyId = s.PolicyId
WHEN MATCHED THEN UPDATE SET DisplayName = @n, TemplateId = @tid, TemplateVersion = @tv, StageAtAdopt = @st, Status = 'Adopted', AdoptedBodyJson = @cb, AdoptedBodyHash = @ch, AdoptedBy = @by, AdoptedAtUtc = SYSUTCDATETIME(), AdoptReason = @rs, ReleasedBy = NULL, ReleasedAtUtc = NULL, ReleaseReason = NULL
WHEN NOT MATCHED THEN INSERT (PolicyId, DisplayName, TemplateId, TemplateVersion, StageAtAdopt, Status, AdoptedBodyJson, AdoptedBodyHash, AdoptedBy, AdoptReason) VALUES (@p, @n, @tid, @tv, @st, 'Adopted', @cb, @ch, @by, @rs);
INSERT INTO eps.CaStageMove (PolicyId, DisplayName, FromStage, ToStage, BeforeJson, AfterJson, Result, ResultText, RequestedBy, Reason) VALUES (@p, @n, @f, @t, @bj, @b, @res, LEFT(@rt, 2000), @by, @rs);
$(Get-EpsJournalSql)
COMMIT;
"@)
    if ($off.Count) { & $Log 'Warning' "  created, but the copy as read back differs from the plan: $($off -join '; ')" }
    @{ Result = 'ok'; Plan = $plan; NewId = $newId; Before = $before; After = $afterRec; Verified = (-not $off.Count); Differs = @($off) }
}
