# EntraPolicySuite -- the ONE place that changes a Conditional Access policy (CA-LIFECYCLE, DESIGN §5.1 "Lifecycle").
#
#   The hard rule (owner 2026-10-30): "it must not automatically do things i have not approved. otherwise i can be locked
#   out of my tenant !!" - and the owner's answers 2026-11-03: "Write on approval" (Policy.ReadWrite.ConditionalAccess for
#   the engine; each button moves ONE adopted policy ONE stage, only after the operator saw the before / after and gave a
#   reason; refused when the break-glass accounts would not be excluded; journaled and audited; no schedule, job or monitor
#   ever writes) and "SuperAdmin only".
#
# Loaded by the ENGINE only (tools/eps-engine/job-entry.ps1): the web app never loads this file, so it cannot write a
# policy even by mistake. Called ONLY from the routes POST /api/capolicies/policies/{policy}/stage, /edit, /clone,
# /newversion, /promote, /rollback, /removeold and POST /api/catemplates/{template}/deploy, which the engine runs from the
# SuperAdmin's signed request (Invoke-EpsEngineConfigRequest). tests/Test-EpsNoCaWrite.ps1 fails the build when a
# Conditional Access write appears anywhere else, or when anything but its route calls one of them.

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
    # UNDO-BACKUP: the policy as it is, stored BEFORE anything is written - no backup, no change (EPS-Backup.ps1)
    $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($live) -Cause "before the stage move of $($plan.displayNameBefore) to $To" -Actor $Actor
    if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = $bk.Reason; Plan = $plan } }
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
    $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($live) -Cause "before the edit of $($plan.displayNameBefore)" -Actor $Actor
    if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = $bk.Reason; Plan = $plan } }
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
    $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($live) -Cause "before the copy of $($plan.displayNameBefore) to $($plan.displayNameAfter)" -Actor $Actor
    if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = $bk.Reason; Plan = $plan } }
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

# ---- CA-TEMPLATES (owner 2026-11-05: Templates "Side-by-side only" - "can i adopt a template version and add a v1.1
# version of the same policy which i can test, and then i ave a v1.0 vesion of the policy"; "again once a policy is
# imported into from the templates, then it should be fuly manageable in the gui"; "but it is always 100% opeator
# controlled"; V1-PARITY P5 / P6). Four more actions under the same rules as every write here: the operator's request
# only (SuperAdmin, a reason, applied by the engine), the tenant read LIVE first, the break-glass check on the RESULT
# (refused, never fixed), read back, recorded and journaled. The writes: ONE POST that creates a policy from a template
# (a deploy, or a newer version tested next to the policy it replaces), the PATCH of one policy of a version pair (a
# promote and a roll back each make two: the one turned on first, then the one turned off), and the DELETE of an old
# version that was promoted away and is off. No job, schedule, tick, monitor or retry calls any of them.

function Save-EpsCaPolicyRecord {
    # one policy as read back after a write: eps.CaPolicy, the names, the adoption (the baseline = as written, so the
    # monitor does not call our own change a drift; -Create adopts it), the history row (eps.CaStageMove) and the journal
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)]$Now, $Before, $Review, [hashtable]$NameRows = @{},
          [string]$From, [string]$To, [string]$ResultText, [bool]$Differs, [Parameter(Mandatory)][string]$Actor, [string]$Reason,
          [switch]$Create, [string]$TemplateId, [string]$TemplateVersion, [string]$JournalAction = 'Update', $JournalBefore, $JournalAfter)
    $rows = @(foreach ($k in $NameRows.Keys) { $n = $NameRows[$k]; @{ k = $n.Kind; i = ($k -split '\|', 2)[1]; n = $n.Name; d = $n.Detail } })
    $hash = Get-EpsCaBodyHash $Now
    $p = @{ p = $PolicyId; n = "$($Now.displayName)"; s = "$($Now.state)"; m = $(if ($Now.modifiedDateTime) { [datetimeoffset]"$($Now.modifiedDateTime)" } elseif ($Now.createdDateTime) { [datetimeoffset]"$($Now.createdDateTime)" } else { [DBNull]::Value })
            b = ($Now | ConvertTo-Json -Compress -Depth 30); r = ($Review | ConvertTo-Json -Compress -Depth 20)
            cb = ((ConvertTo-EpsCaCanonical $Now) | ConvertTo-Json -Compress -Depth 30); ch = $hash
            tid = $(if ($TemplateId) { $TemplateId } else { [DBNull]::Value }); tv = $(if ($TemplateVersion) { $TemplateVersion } else { [DBNull]::Value }); st = "$($Review.stage)"
            f = $From; t = $To; bj = $(if ($Before) { $Before | ConvertTo-Json -Compress -Depth 30 } else { '{}' }); res = $(if ($Differs) { 'applied, differs' } else { 'applied' })
            rt = "$ResultText"; by = $Actor; rs = $Reason
            nj = $(if ($rows.Count) { ConvertTo-Json -InputObject @($rows) -Compress -Depth 4 } else { '[]' }) } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaPolicy' -Key "$PolicyId" -Action $JournalAction -Before $(if ($JournalBefore) { $JournalBefore | ConvertTo-Json -Compress -Depth 6 }) -After $(if ($JournalAfter) { $JournalAfter | ConvertTo-Json -Compress -Depth 6 }))
    $adopt = if ($Create) { @"
MERGE eps.CaAdoption AS x USING (SELECT @p AS PolicyId) AS s ON x.PolicyId = s.PolicyId
WHEN MATCHED THEN UPDATE SET DisplayName = @n, TemplateId = @tid, TemplateVersion = @tv, StageAtAdopt = @st, Status = 'Adopted', AdoptedBodyJson = @cb, AdoptedBodyHash = @ch, AdoptedBy = @by, AdoptedAtUtc = SYSUTCDATETIME(), AdoptReason = @rs, ReleasedBy = NULL, ReleasedAtUtc = NULL, ReleaseReason = NULL
WHEN NOT MATCHED THEN INSERT (PolicyId, DisplayName, TemplateId, TemplateVersion, StageAtAdopt, Status, AdoptedBodyJson, AdoptedBodyHash, AdoptedBy, AdoptReason) VALUES (@p, @n, @tid, @tv, @st, 'Adopted', @cb, @ch, @by, @rs);
"@ } else { "UPDATE eps.CaAdoption SET DisplayName = @n, AdoptedBodyJson = @cb, AdoptedBodyHash = @ch WHERE PolicyId = @p AND Status = 'Adopted';" }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaPolicy WHERE PolicyId = @p;
INSERT INTO eps.CaPolicy (PolicyId, DisplayName, State, ModifiedAtUtc, BodyJson, ReviewJson) VALUES (@p, @n, @s, @m, @b, @r);
DELETE FROM eps.CaDirectoryName WHERE EXISTS (SELECT 1 FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i') AS x WHERE x.k = eps.CaDirectoryName.Kind AND x.i = eps.CaDirectoryName.ObjectId);
INSERT INTO eps.CaDirectoryName (Kind, ObjectId, Name, Detail) SELECT x.k, x.i, LEFT(x.n, 400), x.d FROM OPENJSON(@nj) WITH (k NVARCHAR(20) '`$.k', i NVARCHAR(100) '`$.i', n NVARCHAR(MAX) '`$.n', d NVARCHAR(MAX) '`$.d') AS x;
$adopt
INSERT INTO eps.CaStageMove (PolicyId, DisplayName, FromStage, ToStage, BeforeJson, AfterJson, Result, ResultText, RequestedBy, Reason) VALUES (@p, @n, @f, @t, @bj, @b, @res, LEFT(@rt, 2000), @by, @rs);
$(Get-EpsJournalSql)
COMMIT;
"@)
    $hash
}

function Get-EpsCaLivePolicy {
    # ONE policy read LIVE (GET), as a hashtable; $null when it is no longer in the tenant
    param([Parameter(Mandatory)][string]$PolicyId)
    $raw = try { Invoke-EpsGraph -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" } catch { if ("$_" -match '(?i)404|not ?found|ResourceNotFound') { return $null }; throw }
    $raw | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
}

function Invoke-EpsCaTemplateDeploy {
    <#
      Creates ONE policy from a template (the operator's request, applied by the engine) - v1's CAnnn.ps1 -Mode
      Initial_Setup (a deploy) or -Mode Install_Latest_Policy_Disabled (-VersionOf: a NEWER version tested next to the
      adopted policy it replaces, named CAnnn-vX.Y-<rest>; that policy is not touched):
        1. the template, the targeting method; -VersionOf: that policy adopted, read LIVE and exactly the one the operator
           looked at (-Expected), its template has a newer version, no version is under test next to it already
        2. the tenant's policies read: a template already in the tenant is not deployed again; a name taken is refused
        3. the plan (Get-EpsCaDeployPlan); the groups it names read in the tenant - a missing one is CREATED first as v1
           does (EPS-GroupWrite.ps1); one that cannot be created refuses the deploy before any policy is made
        4. every name -> its id (GET; one not found refuses); the authentication strength by its name
        5. the break-glass check on the RESULT by id (refused, never fixed)
        6. ONE POST that creates it (off, or report-only at Pilot1); read back; recorded and ADOPTED with the template and
           its version; -VersionOf: the version pair recorded (eps.CaVersionPair, Testing)
      Returns @{ Result = ok | invalid | notadopted | missing | changed | refused | failed; Reason; Plan; NewId; Before; After; Groups; Verified; Differs }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$TemplateId, [string]$Stage, [string]$VersionOf, [string]$Expected,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $cat = Get-EpsCaTemplateCatalog
    if (-not $Stage) { $Stage = $(if ($VersionOf) { 'Pilot1' } else { 'Initial' }) }
    $ad = $null; $oldLive = $null
    if ($VersionOf) {
        $ad = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ p = [guid]$VersionOf } -Query 'SELECT Status, TemplateId, TemplateVersion FROM eps.CaAdoption WHERE PolicyId = @p')[0]
        if (-not $ad -or "$($ad.Status)" -ne 'Adopted') { return @{ Result = 'notadopted'; Reason = 'a newer version is tested next to an ADOPTED policy - adopt it first' } }
        $oldLive = Get-EpsCaLivePolicy -PolicyId $VersionOf
        if (-not $oldLive) { return @{ Result = 'missing'; Reason = 'the policy is no longer in the tenant' } }
        if (-not $Expected -or $Expected -ne (Get-EpsCaBodyHash $oldLive)) { return @{ Result = 'changed'; Reason = 'the policy in the tenant is not the one you looked at (it changed since the last read) - read the list again and look again' } }
        $vi = Get-EpsCaVersionInfo -Adoption $ad -Review (Get-EpsCaReview -Policy $oldLive -Catalog $cat) -Catalog $cat
        if (-not $vi.available) { return @{ Result = 'refused'; Reason = "no newer version to test: $($vi.reason)" } }
        $open = Get-EpsCaVersionPair -ConnectionString $ConnectionString -PolicyId ([guid]$VersionOf)
        if ($open -and "$($open.Status)" -in 'Testing', 'RolledBack') { return @{ Result = 'refused'; Reason = "a version is already being tested next to this policy ($($open.NewVersion)) - promote it, or roll it back" } }
        $TemplateId = $(if ($ad.TemplateId -isnot [DBNull] -and "$($ad.TemplateId)") { "$($ad.TemplateId)" } else { (Get-EpsCaNameMatch -DisplayName "$($oldLive.displayName)" -Catalog $cat).TemplateId })
    }
    $t = $cat.ById["$TemplateId".ToUpperInvariant()]
    if (-not $t) { return @{ Result = 'invalid'; Reason = "$TemplateId is not in the template library" } }
    # the tenant's policies, as they are now
    $existing = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/policies?$select=id,displayName' -All | ForEach-Object { $nm = Get-EpsCaNameMatch -DisplayName "$($_.displayName)" -Catalog $cat; @{ id = "$($_.id)"; displayName = "$($_.displayName)"; templateId = $nm.TemplateId; versionCopy = $nm.VersionCopy } })
    $ctx0 = Get-EpsCaContext -ConnectionString $ConnectionString -Names @{} -NoGraph -Catalog $cat
    $plan = Get-EpsCaDeployPlan -Template $t -Stage $Stage -Ctx $ctx0 -Catalog $cat -Existing $existing -VersionCopy:([bool]$VersionOf)
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    # the groups it names: in the tenant, or created first as v1 does
    $need = @($plan.groups | ForEach-Object { $_.name } | Select-Object -Unique)
    $live = @{}; foreach ($x in @(Read-EpsManagedGroupState -Names $need)) { $live["$($x.Name)"] = $x }
    $unread = @($need | Where-Object { $null -eq $live[$_].Found })
    if ($unread.Count) { return @{ Result = 'failed'; Reason = "the groups could not be read: $(@($unread | ForEach-Object { "$_ ($($live[$_].Error))" }) -join '; ')"; Plan = $plan } }
    $missing = @($need | Where-Object { $live[$_].Found -eq $false })
    $created = @()
    if ($missing.Count) {
        $m = Get-EpsManagedGroups -ConnectionString $ConnectionString -Templates @($t.id)
        $foreign = @($missing | Where-Object { -not $m.Groups.Contains($_) })
        if ($foreign.Count) { return @{ Result = 'refused'; Reason = "not in the tenant, and not a group Entra Policy Suite makes: $($foreign -join ', ') - create it first"; Plan = $plan } }
        & $Log 'Info' "  the groups $($plan.displayName) needs first: $($missing -join ', ')"
        $gc = Invoke-EpsGroupChange -ConnectionString $ConnectionString -Action 'create' -Names $missing -Templates @($t.id) -Actor $Actor -Reason "for $($plan.displayName): $Reason" -Log $Log
        if ($gc.Result -ne 'ok') { return @{ Result = 'refused'; Reason = "the groups it needs could not all be created ($($gc.Text)) - no policy was created"; Plan = $plan; Groups = @($gc.Items) } }
        $created = @($missing)
    }
    # names -> ids; the authentication strength by its name
    $body = ConvertTo-Json -InputObject $plan.body -Depth 30 -Compress | ConvertFrom-Json -AsHashtable -Depth 30
    $rs = Resolve-EpsCaEditNames -Body $body -Lookup (Get-EpsCaEditLookup) -Strict
    if (-not $rs.Ok) { return @{ Result = 'refused'; Reason = $rs.Reason; Plan = $plan; Groups = $created } }
    $body = $rs.Body
    $asName = Get-EpsCaV $body 'grantControls.authenticationStrength.displayName'
    if ($asName) {
        $hit = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/authenticationStrength/policies' -All | Where-Object { "$($_.displayName)" -ieq "$asName" })
        if ($hit.Count -ne 1) { return @{ Result = 'refused'; Reason = "the authentication strength '$asName' is $(if ($hit.Count) { 'there more than once' } else { 'not in the tenant (Get started: authentication strengths)' })"; Plan = $plan; Groups = $created } }
        $body.grantControls.authenticationStrength = [ordered]@{ id = "$($hit[0].id)" }
    }
    # the break-glass check on the RESULT, by id (the context read after any group was created)
    $names = @{}; foreach ($k in $rs.Names.Keys) { $names[$k] = $rs.Names[$k] }
    $ctx = Get-EpsCaContext -ConnectionString $ConnectionString -Names $names -Catalog $cat
    $bg = Test-EpsCaBreakGlassExclusion -Policy $body -BreakGlass $ctx.BreakGlass -IsBreakGlassPolicy ([bool]$t.breakGlassPolicy)
    if ($bg.Ok -ne $true) { return @{ Result = 'refused'; Reason = "the break-glass check refuses it: the new policy $($bg.Text)"; Plan = $plan; Groups = $created } }
    $create = [ordered]@{}; foreach ($k in $script:EpsCaEditTop) { if ($body.Contains($k) -and $null -ne $body[$k]) { $create[$k] = $body[$k] } }
    # UNDO-BACKUP: a deploy changes no policy that is there (its undo turns the new one off); a test next to a policy
    # stores that policy first
    if ($oldLive) {
        $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($oldLive) -Cause "before the test of $($t.id) $($t.version) next to $($oldLive.displayName)" -Actor $Actor
        if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = "$($bk.Reason) - no policy was created"; Plan = $plan; Groups = $created } }
    }
    & $Log 'Info' "CA $(if ($VersionOf) { "test of $($t.id) $($t.version) next to $($oldLive.displayName)" } else { "deploy of $($t.id) $($t.version)" }): $($plan.displayName) ($Stage), requested by $Actor"
    # THE write: ONE POST that creates the policy
    $new = try { Invoke-EpsGraph -Method 'POST' -Path 'v1.0/identity/conditionalAccess/policies' -Body ($create | ConvertTo-Json -Depth 30 -Compress) }
           catch { return @{ Result = 'failed'; Reason = "the tenant refused the new policy: $($_.Exception.Message)$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })"; Plan = $plan; Groups = $created } }
    $newId = "$($new.id)"
    if ($newId -notmatch $script:EpsCaGuidRx) { return @{ Result = 'failed'; Reason = 'the tenant created the policy but did not return its id - read the policy list again'; Plan = $plan; Groups = $created } }
    $now = Get-EpsCaLivePolicy -PolicyId $newId
    $off = @(Get-EpsCaEditReadBack -Now $now -Plan @{ after = $create } -Parts @($create.Keys))
    foreach ($k in (Resolve-EpsCaDirectoryNames -Policies @($now)).GetEnumerator()) { $names[$k.Key] = $k.Value }
    $review = Get-EpsCaReview -Policy $now -Names $names -Ctx $ctx -Catalog $cat
    $after = [ordered]@{ policyId = $newId; displayName = "$($now.displayName)"; state = "$($now.state)"; stage = $review.stage; template = "$($t.id) $($t.version)"; status = 'Adopted'; groupsCreated = @($created) }
    $before = if ($VersionOf) { [ordered]@{ versionOf = $VersionOf; displayName = "$($oldLive.displayName)"; version = "$($ad.TemplateVersion)" } } else { [ordered]@{ template = "$($t.id) $($t.version)" } }
    [void](Save-EpsCaPolicyRecord -ConnectionString $ConnectionString -PolicyId ([guid]$newId) -Now $now -Before $null -Review $review -NameRows $names -From 'Template' -To $Stage `
        -ResultText "$($t.id) $($t.version)$(if ($VersionOf) { " - a test next to $($oldLive.displayName)" })$(if ($created.Count) { "; groups created first: $($created -join ', ')" })$(if ($off.Count) { ' - ' + ($off -join '; ') })" -Differs ([bool]$off.Count) `
        -Actor $Actor -Reason $Reason -Create -TemplateId "$($t.id)" -TemplateVersion "$($t.version)" -JournalAction 'Create' -JournalBefore $before -JournalAfter $after)
    if ($VersionOf) {
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ t = "$($t.id)"; o = [guid]$VersionOf; n = [guid]$newId; ov = $(if ($ad.TemplateVersion -is [DBNull]) { [DBNull]::Value } else { "$($ad.TemplateVersion)" }); nv = "$($t.version)"; by = $Actor; rs = $Reason } `
            -Query "INSERT INTO eps.CaVersionPair (TemplateId, OldPolicyId, NewPolicyId, OldVersion, NewVersion, Status, CreatedBy, Reason) VALUES (@t, @o, @n, @ov, @nv, 'Testing', @by, @rs)")
    }
    if ($off.Count) { & $Log 'Warning' "  created, but the policy as read back differs from the plan: $($off -join '; ')" }
    @{ Result = 'ok'; Plan = $plan; NewId = $newId; Before = $before; After = $after; Groups = @($created); Verified = (-not $off.Count); Differs = @($off) }
}

function Invoke-EpsCaPairPatch {
    # the PATCH of ONE policy of a version pair (a promote, a roll back) - its only caller is Invoke-EpsCaVersionPair
    param([Parameter(Mandatory)][string]$PolicyId, [Parameter(Mandatory)]$Patch)
    [void](Invoke-EpsGraph -Method 'PATCH' -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" -Body ($Patch | ConvertTo-Json -Depth 30 -Compress))
}

function Remove-EpsCaPolicyById {
    # the DELETE of ONE policy - an old version that was promoted away and is off; its only caller is Invoke-EpsCaRemoveOldVersion
    param([Parameter(Mandatory)][string]$PolicyId)
    [void](Invoke-EpsGraph -Method 'DELETE' -Path "v1.0/identity/conditionalAccess/policies/$PolicyId")
}

function Get-EpsCaPairLive {
    # the pair a policy is in, and both policies read LIVE, checked against what the operator looked at
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [string]$ExpectedOld, [string]$ExpectedNew, [switch]$OldOnly)
    $pair = Get-EpsCaVersionPair -ConnectionString $ConnectionString -PolicyId $PolicyId
    if (-not $pair) { return @{ Result = 'refused'; Reason = 'this policy has no version under test' } }
    $old = Get-EpsCaLivePolicy -PolicyId "$($pair.OldPolicyId)"
    $new = if ($OldOnly) { $null } else { Get-EpsCaLivePolicy -PolicyId "$($pair.NewPolicyId)" }
    if (-not $old -or (-not $OldOnly -and -not $new)) { return @{ Result = 'missing'; Reason = "the $(if (-not $old) { 'old' } else { 'new' }) version is no longer in the tenant" } }
    if (-not $ExpectedOld -or $ExpectedOld -ne (Get-EpsCaBodyHash $old) -or (-not $OldOnly -and (-not $ExpectedNew -or $ExpectedNew -ne (Get-EpsCaBodyHash $new)))) { return @{ Result = 'changed'; Reason = 'a policy of the pair is not the one you looked at (it changed since the last read) - read the list again and look again' } }
    @{ Result = 'ok'; Pair = $pair; Old = $old; New = $new }
}

function Invoke-EpsCaVersionPair {
    <#
      Promote or Roll back the version pair ONE policy is in (the operator's request, applied by the engine):
        Promote   the new version to Prod (the template's Prod targets, on, CAnnn-Prod-<rest>) FIRST, then the old one OFF
                  (CAnnn-<its version>-<rest>) and kept - how it was is recorded for a roll back
        Rollback  the old one back as it was before the promote FIRST, then the new one OFF
      Both policies read LIVE and refused when one is not what the operator looked at; the break-glass check on the result
      of the one turned on; each PATCH read back; both recorded; the pair's status changes. When the second PATCH fails, the
      first stays (two policies on is safe; none on is not) and the answer says so.
      Returns @{ Result = ok | partial | missing | changed | refused | failed; Reason; Plan; Before; After; Verified; Differs }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [Parameter(Mandatory)][ValidateSet('Promote', 'Rollback')][string]$Action,
          [string]$ExpectedOld, [string]$ExpectedNew, [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $lv = Get-EpsCaPairLive -ConnectionString $ConnectionString -PolicyId $PolicyId -ExpectedOld $ExpectedOld -ExpectedNew $ExpectedNew
    if ($lv.Result -ne 'ok') { return $lv }
    $pair = $lv.Pair; $old = $lv.Old; $new = $lv.New
    $xo = Get-EpsCaEditContext -ConnectionString $ConnectionString -Live $old
    $xn = Get-EpsCaEditContext -ConnectionString $ConnectionString -Live $new
    $sp = $null; $rs = $null
    if ($Action -eq 'Promote') {
        $sp = Get-EpsCaPromoteStagePlan -New $new -NewReview $xn.Review -TemplateId "$($pair.TemplateId)" -Ctx $xn.Ctx -Names $xn.Names -Catalog $xn.Catalog
        if ($sp.ok) { $rs = Resolve-EpsCaStageIds -Plan $sp -Ctx $xn.Ctx; if (-not $rs.Ok) { return @{ Result = 'refused'; Reason = $rs.Reason } }; foreach ($k in $rs.Names.Keys) { $xn.Names[$k] = $rs.Names[$k] } }
    }
    $plan = Get-EpsCaPairPlan -Action $Action -Pair $pair -Old $old -New $new -NewStagePlan $sp -Catalog $xn.Catalog
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    $users = { param($live, $set) $u = [ordered]@{}; $cur = Get-EpsCaV $live 'conditions.users'; foreach ($k in @($cur.Keys)) { if ("$k" -notlike '@odata*' -and $null -ne $cur[$k]) { $u[$k] = $cur[$k] } }; foreach ($p in @($set.Keys)) { $u[($p -split '\.')[-1]] = @($set[$p]) }; $u }
    # the one turned ON first, then the one turned OFF
    if ($Action -eq 'Promote') {
        $onId = "$($pair.NewPolicyId)"; $onLive = $new; $onX = $xn; $offId = "$($pair.OldPolicyId)"; $offLive = $old; $offX = $xo
        $onPatch = [ordered]@{ displayName = $plan.new.displayNameAfter; state = $plan.new.stateAfter }
        if ($rs -and $rs.Set.Count) { $onPatch.conditions = [ordered]@{ users = (& $users $new $rs.Set) } }
        $offPatch = $plan.old.patch
        $oldBefore = [ordered]@{ displayName = "$($old.displayName)"; state = "$($old.state)"; users = (& $users $old @{}) }
    } else {
        $onId = "$($pair.OldPolicyId)"; $onLive = $old; $onX = $xo; $offId = "$($pair.NewPolicyId)"; $offLive = $new; $offX = $xn
        $onPatch = $plan.old.patch; $offPatch = $plan.new.patch; $oldBefore = $null
    }
    $onAfter = ConvertTo-Json -InputObject $onLive -Depth 30 -Compress | ConvertFrom-Json -AsHashtable -Depth 30
    foreach ($k in @($onPatch.Keys)) { if ($k -eq 'conditions') { $onAfter.conditions.users = $onPatch.conditions.users } else { $onAfter[$k] = $onPatch[$k] } }
    $bg = Test-EpsCaBreakGlassExclusion -Policy $onAfter -BreakGlass $onX.Ctx.BreakGlass -IsBreakGlassPolicy $onX.IsBreakGlassPolicy
    if ("$($onAfter.state)" -ne 'disabled' -and $bg.Ok -ne $true) { return @{ Result = 'refused'; Reason = "the break-glass check refuses it: $($onAfter.displayName) $($bg.Text)"; Plan = $plan } }
    $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($old, $new) -Cause "before the $($Action.ToLower()) of $($pair.TemplateId) ($($pair.OldVersion) / $($pair.NewVersion))" -Actor $Actor
    if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = "$($bk.Reason) - nothing was changed"; Plan = $plan } }
    & $Log 'Info' "CA version $($Action.ToLower()) $($pair.TemplateId) ($($pair.OldVersion) / $($pair.NewVersion)): on $($onPatch.displayName), off $($offPatch.displayName), requested by $Actor"
    $fail = { param($e) "the tenant refused it: $($e.Exception.Message)$(if ("$e" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })" }
    try { Invoke-EpsCaPairPatch -PolicyId $onId -Patch $onPatch } catch { return @{ Result = 'failed'; Reason = "$(& $fail $_) - nothing was changed"; Plan = $plan } }
    $offErr = $null
    try { Invoke-EpsCaPairPatch -PolicyId $offId -Patch $offPatch } catch { $offErr = & $fail $_ }
    # read back and record both
    $out = @{}
    foreach ($side in @(@{ Id = $onId; Live = $onLive; X = $onX; Patch = $onPatch; On = $true }, @{ Id = $offId; Live = $offLive; X = $offX; Patch = $offPatch; On = $false })) {
        if (-not $side.On -and $offErr) { continue }
        $now = Get-EpsCaLivePolicy -PolicyId $side.Id
        $d = [System.Collections.Generic.List[string]]::new()
        if ("$($now.state)" -ne "$($side.Patch.state)") { $d.Add("state is $($now.state)") }
        if ("$($now.displayName)" -cne "$($side.Patch.displayName)") { $d.Add("name is $($now.displayName)") }
        $rv = Get-EpsCaReview -Policy $now -Names $side.X.Names -Ctx $side.X.Ctx -Catalog $side.X.Catalog
        $isNew = $side.Id -eq "$($pair.NewPolicyId)"
        $txt = switch ("$Action|$isNew") { 'Promote|True' { "promoted: $($pair.NewVersion) replaces $($pair.OldVersion) ($($old.displayName))" } 'Promote|False' { "replaced by $($pair.NewVersion) ($($plan.new.displayNameAfter)) - off, kept for a roll back" } 'Rollback|False' { "rolled back: $($pair.OldVersion) on again as before the promote" } default { "rolled back: off, $($pair.OldVersion) is on again" } }
        [void](Save-EpsCaPolicyRecord -ConnectionString $ConnectionString -PolicyId ([guid]$side.Id) -Now $now -Before $side.Live -Review $rv -NameRows $side.X.Names -From "$($side.X.Review.stage)" -To $(if ($side.On) { "$($rv.stage)" } else { 'Disabled' }) `
            -ResultText "$txt$(if ($d.Count) { ' - ' + ($d -join '; ') })" -Differs ([bool]$d.Count) -Actor $Actor -Reason $Reason `
            -JournalBefore ([ordered]@{ displayName = "$($side.Live.displayName)"; state = "$($side.Live.state)"; stage = "$($side.X.Review.stage)" }) -JournalAfter ([ordered]@{ displayName = "$($now.displayName)"; state = "$($now.state)"; stage = "$($rv.stage)"; action = $Action }))
        $out[$(if ($side.On) { 'on' } else { 'off' })] = @{ displayName = "$($now.displayName)"; state = "$($now.state)"; stage = "$($rv.stage)"; differs = @($d) }
    }
    $status = if ($Action -eq 'Promote') { 'Promoted' } else { 'RolledBack' }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [long]$pair.PairId; s = $status; ob = $(if ($oldBefore) { $oldBefore | ConvertTo-Json -Compress -Depth 30 } else { [DBNull]::Value }); by = $Actor; rs = $Reason } `
        -Query 'UPDATE eps.CaVersionPair SET Status = @s, OldBeforeJson = COALESCE(@ob, OldBeforeJson), ChangedBy = @by, ChangedAtUtc = SYSUTCDATETIME(), Reason = @rs WHERE PairId = @id')
    $differs = @(@($out.on.differs) + @($out.off.differs) | Where-Object { $_ })
    $before = [ordered]@{ pair = "$($pair.PairId)"; status = "$($pair.Status)"; on = "$($onLive.displayName) ($($onLive.state))"; off = "$($offLive.displayName) ($($offLive.state))" }
    $after = [ordered]@{ pair = "$($pair.PairId)"; status = $status; on = $out.on; off = $out.off }
    if ($offErr) { & $Log 'Warning' "  $($onPatch.displayName) is on; $($offLive.displayName) could NOT be turned off: $offErr"; return @{ Result = 'partial'; Reason = "$($onPatch.displayName) is on, but $($offLive.displayName) could not be turned off ($offErr) - both are on; turn it off with Edit or Disable"; Plan = $plan; Before = $before; After = $after } }
    @{ Result = 'ok'; Plan = $plan; Before = $before; After = $after; Verified = (-not $differs.Count); Differs = $differs }
}

function Invoke-EpsCaRemoveOldVersion {
    <#
      DELETES the old version of a promoted pair (the operator's request, applied by the engine; never part of a promote):
      the pair promoted, the old policy read LIVE, exactly the one he looked at (-ExpectedOld), OFF, and its name typed to
      confirm (-Confirm). ONE DELETE; read back (gone); its record released, its history and the journal written, the pair
      Removed. Returns @{ Result = ok | missing | changed | refused | failed; Reason; Before; After }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$PolicyId, [string]$ExpectedOld, [string]$Confirm,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $lv = Get-EpsCaPairLive -ConnectionString $ConnectionString -PolicyId $PolicyId -ExpectedOld $ExpectedOld -OldOnly
    if ($lv.Result -ne 'ok') { return $lv }
    $pair = $lv.Pair; $old = $lv.Old
    $plan = Get-EpsCaPairPlan -Action 'Remove' -Pair $pair -Old $old
    if (-not $plan.ok) { return @{ Result = 'refused'; Reason = $plan.reason; Plan = $plan } }
    if ("$Confirm".Trim() -cne "$($old.displayName)") { return @{ Result = 'refused'; Reason = "type the old version's name exactly to confirm ($($old.displayName))"; Plan = $plan } }
    $oldId = "$($pair.OldPolicyId)"
    $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($old) -Cause "before the removal of the old version $($old.displayName)" -Actor $Actor
    if (-not $bk.Ok) { return @{ Result = 'refused'; Reason = "$($bk.Reason) - nothing was deleted"; Plan = $plan } }
    & $Log 'Info' "CA remove of the old version $($old.displayName) ($($pair.TemplateId) $($pair.OldVersion), replaced by $($pair.NewVersion)), requested by $Actor"
    try { Remove-EpsCaPolicyById -PolicyId $oldId } catch { return @{ Result = 'failed'; Reason = "the tenant refused the delete: $($_.Exception.Message)$(if ("$_" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })"; Plan = $plan } }
    $gone = $null -eq (Get-EpsCaLivePolicy -PolicyId $oldId)
    $before = [ordered]@{ policyId = $oldId; displayName = "$($old.displayName)"; state = "$($old.state)"; version = "$($pair.OldVersion)" }
    $after = [ordered]@{ deleted = $gone; replacedBy = "$($pair.NewPolicyId)"; version = "$($pair.NewVersion)" }
    $p = @{ p = [guid]$oldId; n = "$($old.displayName)"; bj = ($old | ConvertTo-Json -Compress -Depth 30); res = $(if ($gone) { 'applied' } else { 'applied, differs' }); rt = $(if ($gone) { "deleted: replaced by $($pair.NewVersion)" } else { 'deleted, but it is still read in the tenant' }); by = $Actor; rs = $Reason; id = [long]$pair.PairId
            rr = "deleted from the tenant: replaced by $($pair.NewVersion)$(if ($Reason) { " - $Reason" })" } +
         (New-EpsJournalParameters -Actor $Actor -Entity 'CaPolicy' -Key $oldId -Action 'Delete' -Before ($before | ConvertTo-Json -Compress) -After ($after | ConvertTo-Json -Compress))
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query @"
SET XACT_ABORT ON; BEGIN TRAN;
DELETE FROM eps.CaPolicy WHERE PolicyId = @p;
UPDATE eps.CaAdoption SET Status = 'Released', ReleasedBy = @by, ReleasedAtUtc = SYSUTCDATETIME(), ReleaseReason = LEFT(@rr, 1000) WHERE PolicyId = @p AND Status = 'Adopted';
INSERT INTO eps.CaStageMove (PolicyId, DisplayName, FromStage, ToStage, BeforeJson, AfterJson, Result, ResultText, RequestedBy, Reason) VALUES (@p, @n, 'Disabled', 'Removed', @bj, '{}', @res, LEFT(@rt, 2000), @by, @rs);
UPDATE eps.CaVersionPair SET Status = 'Removed', ChangedBy = @by, ChangedAtUtc = SYSUTCDATETIME(), Reason = @rs WHERE PairId = @id;
$(Get-EpsJournalSql)
COMMIT;
"@)
    if (-not $gone) { & $Log 'Warning' "  deleted, but $($old.displayName) is still read in the tenant" }
    @{ Result = 'ok'; Plan = $plan; Before = $before; After = $after; Verified = $gone }
}

# ---- UNDO-BACKUP (owner 2026-11-05: "i need to have both a new feature Undo + another new feature backup/restore. look at
# how PIM does it"; "it must work for both ca policies + tagging so i can recover"; "always 100% opeator controlled"):
# a restore from a backup, and the undo of one change in a policy's history, are the SAME action - put a body that is
# stored back - under the rules of every write here: a SuperAdmin's request (a reason, applied by the engine), each
# policy read LIVE and refused when it is not the one the operator looked at, the break-glass check on the RESULT
# (refused, never fixed), a backup of the policy as it is BEFORE the write, ONE write per policy, read back, recorded
# and journaled. Two more writes, pinned in tests/Test-EpsNoCaWrite.ps1: the PATCH of a policy that is there (only the
# parts that differ) and the POST that creates a policy that is gone - ALWAYS OFF. Each has one caller,
# Invoke-EpsCaRestore, which only the restore and the undo routes call. No job, schedule, tick, monitor or retry.

function Set-EpsCaPolicyFromBackup {
    # the PATCH of ONE policy back to a stored body (the parts that differ) - its only caller is Invoke-EpsCaRestore
    param([Parameter(Mandatory)][string]$PolicyId, [Parameter(Mandatory)]$Patch)
    [void](Invoke-EpsGraph -Method 'PATCH' -Path "v1.0/identity/conditionalAccess/policies/$PolicyId" -Body ($Patch | ConvertTo-Json -Depth 30 -Compress))
}

function New-EpsCaPolicyFromBackup {
    # the POST that creates ONE policy again from a stored body, OFF - its only caller is Invoke-EpsCaRestore
    param([Parameter(Mandatory)]$Create)
    Invoke-EpsGraph -Method 'POST' -Path 'v1.0/identity/conditionalAccess/policies' -Body ($Create | ConvertTo-Json -Depth 30 -Compress)
}

function Invoke-EpsCaRestore {
    <#
      Puts stored bodies back, ONE policy at a time (the operator's request, applied by the engine):
        -Items  @{ PolicyId; Expected (the review hash he saw; needed when the policy is there); Body (the stored policy:
                a backup's copy, or its body before a change); Mode = Restore | Off (the undo of a copy / a deploy) }
        1. the policy read LIVE; there and not the one he looked at = refused (that one only)
        2. the plan (Get-EpsCaRestorePlan): a PATCH of only the parts that differ; gone = created again OFF with a name no
           policy has; the break-glass check on the result; nothing to change = left as it is
        3. a backup of the policy as it is, BEFORE the write (none = refused)
        4. ONE write; read back; recorded (the policy, the history '<stage> -> Restored', the journal; a policy created
           again is ADOPTED, as a copy is)
      Returns @{ Result = ok | partial | refused; Items (per policy: policyId; displayName; result; text); Done; Text }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Items = @(), [Parameter(Mandatory)][string]$Source,
          [Parameter(Mandatory)][string]$Actor, [string]$Reason, [scriptblock]$Log = { param($l, $m) Write-Host "[$l] $m" })
    $out = [System.Collections.Generic.List[object]]::new()
    $existing = $null
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $pid0 = "$($it.PolicyId)"; $mode = if ("$($it.Mode)" -eq 'Off') { 'Off' } else { 'Restore' }
        $res = [ordered]@{ policyId = $pid0; displayName = $(if ($it.Body) { "$($it.Body.displayName)" }); result = 'refused'; text = $null }
        $out.Add($res)
        $live = if ($pid0 -match $script:EpsCaGuidRx) { Get-EpsCaLivePolicy -PolicyId $pid0 } else { $null }
        if ($live) {
            $res.displayName = "$($live.displayName)"
            if (-not "$($it.Expected)" -or "$($it.Expected)" -ne (Get-EpsCaBodyHash $live)) { $res.result = 'changed'; $res.text = 'the policy in the tenant is not the one you looked at (it changed since the last read) - read the list again and look again'; continue }
        }
        if ($mode -eq 'Restore' -and -not $live -and $null -eq $existing) { $existing = @(Invoke-EpsGraph -Path 'v1.0/identity/conditionalAccess/policies?$select=id,displayName' -All | ForEach-Object { "$($_.displayName)" }) }
        $x = Get-EpsCaEditContext -ConnectionString $ConnectionString -Live $(if ($live) { $live } else { $it.Body })
        $plan = Get-EpsCaRestorePlan -Backup $it.Body -Current $live -Mode $mode -BreakGlass $x.Ctx.BreakGlass -IsBreakGlassPolicy $x.IsBreakGlassPolicy -Names $x.Names -ExistingNames @($existing) -PolicyId $pid0
        if (-not $plan.ok) { $res.text = $plan.reason; continue }
        if ($plan.action -eq 'none') { $res.result = 'same'; $res.text = $plan.reason; continue }
        if ($live) {
            $bk = Backup-EpsCaBeforeWrite -ConnectionString $ConnectionString -Policies @($live) -Cause "before $Source of $($live.displayName)" -Actor $Actor
            if (-not $bk.Ok) { $res.text = "$($bk.Reason) - not changed"; continue }
        }
        $fail = { param($e) "the tenant refused it: $($e.Exception.Message)$(if ("$e" -match '(?i)403|Authorization|privilege') { ' (the engine needs Policy.ReadWrite.ConditionalAccess - run the install again to grant it)' })" }
        if ($plan.action -eq 'patch') {
            & $Log 'Info' "CA $Source`: $($live.displayName) ($(@($plan.patch.Keys) -join ', ')), requested by $Actor"
            try { Set-EpsCaPolicyFromBackup -PolicyId $pid0 -Patch $plan.patch } catch { $res.result = 'failed'; $res.text = & $fail $_; continue }
            $now = Get-EpsCaLivePolicy -PolicyId $pid0
            $off = @(Get-EpsCaEditReadBack -Now $now -Plan @{ after = $plan.patch } -Parts @($plan.patch.Keys))
            $rv = Get-EpsCaReview -Policy $now -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog
            [void](Save-EpsCaPolicyRecord -ConnectionString $ConnectionString -PolicyId ([guid]$pid0) -Now $now -Before $live -Review $rv -NameRows $x.Names -From "$($x.Review.stage)" -To 'Restored' `
                -ResultText "$Source`: $(@($plan.patch.Keys) -join ', ')$(if ($off.Count) { ' - ' + ($off -join '; ') })" -Differs ([bool]$off.Count) -Actor $Actor -Reason $Reason `
                -JournalBefore ([ordered]@{ displayName = "$($live.displayName)"; state = "$($live.state)"; stage = "$($x.Review.stage)" }) -JournalAfter ([ordered]@{ displayName = "$($now.displayName)"; state = "$($now.state)"; stage = "$($rv.stage)"; restored = $Source; parts = @($plan.patch.Keys) }))
            $res.result = $(if ($off.Count) { 'applied, differs' } else { 'applied' }); $res.displayName = "$($now.displayName)"; $res.text = "$($plan.stateBefore) -> $($now.state); changed: $(@($plan.patch.Keys) -join ', ')"
            continue
        }
        # created again, OFF
        & $Log 'Info' "CA $Source`: $($plan.displayName) created again (off), requested by $Actor"
        $new = try { New-EpsCaPolicyFromBackup -Create $plan.create } catch { $res.result = 'failed'; $res.text = & $fail $_; continue }
        $newId = "$($new.id)"
        if ($newId -notmatch $script:EpsCaGuidRx) { $res.result = 'failed'; $res.text = 'the tenant created the policy but did not return its id - read the policy list again'; continue }
        $now = Get-EpsCaLivePolicy -PolicyId $newId
        $off = @(Get-EpsCaEditReadBack -Now $now -Plan @{ after = $plan.create } -Parts @($plan.create.Keys))
        $rv = Get-EpsCaReview -Policy $now -Names $x.Names -Ctx $x.Ctx -Catalog $x.Catalog
        [void](Save-EpsCaPolicyRecord -ConnectionString $ConnectionString -PolicyId ([guid]$newId) -Now $now -Before $null -Review $rv -NameRows $x.Names -From 'Backup' -To 'Initial' `
            -ResultText "$Source`: created again, off (it was $pid0)$(if ($off.Count) { ' - ' + ($off -join '; ') })" -Differs ([bool]$off.Count) -Actor $Actor -Reason $Reason `
            -Create -TemplateId "$($rv.templateId)" -TemplateVersion "$($rv.templateVersion)" -JournalAction 'Create' -JournalBefore ([ordered]@{ policyId = $pid0; gone = $true }) -JournalAfter ([ordered]@{ policyId = $newId; displayName = "$($now.displayName)"; state = "$($now.state)"; restored = $Source; status = 'Adopted' }))
        $res.result = $(if ($off.Count) { 'applied, differs' } else { 'applied' }); $res.policyId = $newId; $res.displayName = "$($now.displayName)"; $res.text = "created again, OFF (it was $pid0) - adopted; move it through the stages when it is ready"
    }
    $done = @($out | Where-Object { "$($_.result)" -like 'applied*' }).Count
    $bad = @($out | Where-Object { "$($_.result)" -notlike 'applied*' -and $_.result -ne 'same' }).Count
    @{ Result = $(if ($bad -and $done) { 'partial' } elseif ($bad) { 'refused' } else { 'ok' }); Items = @($out); Done = $done
       Text = "$done put back, $(@($out | Where-Object result -eq 'same').Count) already as stored, $bad not changed$(if ($bad) { ': ' + (@($out | Where-Object { "$($_.result)" -notlike 'applied*' -and $_.result -ne 'same' } | ForEach-Object { "$($_.displayName) ($($_.text))" }) -join '; ') })" }
}
