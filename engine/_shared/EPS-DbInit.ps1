# EntraPolicySuite -- the database setup job caj-eps-dbinit (SEC-08 plan A, framework §0 "no person needs database admin
# rights at an install", Invardia DESIGN ch 12; the same shape as PIM's ca-pim-dbinit). The job runs the engine image as
# its OWN identity id-eps-dbinit, a member of the SQL server's Entra admin group grp-eps-sql-admins (Invardia decided (b)
# 2026-11-03: group-as-admin, the job identity a member). It makes the schema, the component roles and grants, the
# managed identities' database users, the sign-in front's state and - for ONE execution, when the installer asks - the
# first SuperAdmin; it removes a retired identity's user when asked. Every decision is made HERE, from the image's own
# files (sql/eps-schema.sql, sql/eps-grants.json) and a few checked inputs; the job only connects, executes and reads
# back. Exit 0 only when every principal is read back as asked.
#
# Inputs (environment of the job; the per-execution ones are set only on that one start):
#   EPS_SQL_CONNECTION          the database (the job's identity signs in - EPS_ManagedIdentityClientId names it, else
#                               the platform would hand out another identity's token)
#   EPS_DBINIT_PRINCIPALS       JSON [{ "name": "id-eps-engine", "clientId": "<guid>", "role": "eps_engine" }, ...]
#   EPS_DBINIT_WEB_USER         the web identity's user (owner of schema signin)
#   EPS_DBINIT_SUPERADMIN       per execution: "<upn>|<object id>" - the first SuperAdmin (only when there is none)
#   EPS_DBINIT_DROP             per execution: database user names to remove (comma separated; never one in the list)
# Dot-source EPS-SqlStore and EPS-Install (Get-EpsGrantList / Get-EpsGrantScript / Get-EpsSqlUserScript /
# ConvertTo-EpsSqlSid) and EPS-InstallWeb (Get-EpsSigninStateSql / Get-EpsFirstSuperAdminSql) first.

Set-StrictMode -Off

$script:EpsDbInitNamePattern = '^[A-Za-z0-9-]{1,128}$'
$script:EpsDbInitBanned = @('db_owner', 'db_datareader', 'db_datawriter', 'db_ddladmin')

function Read-EpsDbInitInput {
    <#
      PURE. The job's inputs, checked. Returns @{ Ok; Reason; Principals; WebUser; SuperAdmin; Drop }. Refused: a name or
      role outside the patterns, a role the grant list does not have, a client id that is not a GUID, a web user that is
      not one of the principals, a drop that names a principal the list keeps, a SuperAdmin that is not "<upn>|<guid>".
    #>
    param([string]$PrincipalsJson, [string]$WebUser, [string]$SuperAdmin, [string]$Drop, [Parameter(Mandatory)][string[]]$Roles)
    $no = { param($r) @{ Ok = $false; Reason = $r } }
    if (-not "$PrincipalsJson".Trim()) { return (& $no 'EPS_DBINIT_PRINCIPALS is not set') }
    $list = try { @($PrincipalsJson | ConvertFrom-Json -Depth 5) } catch { return (& $no "EPS_DBINIT_PRINCIPALS is not JSON: $($_.Exception.Message)") }
    if (-not $list.Count) { return (& $no 'EPS_DBINIT_PRINCIPALS lists nobody') }
    $p = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $list) {
        $name = "$($x.name)"; $cid = "$($x.clientId)"; $role = "$($x.role)"
        if ($name -notmatch $script:EpsDbInitNamePattern) { return (& $no "unsafe database user name '$name'") }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($cid, [ref]$g) -or $g -eq [guid]::Empty) { return (& $no "the client id of $name is not a GUID") }
        if ($role -notin $Roles) { return (& $no "role '$role' of $name is not in the grant list ($($Roles -join ', '))") }
        $same = @($p | Where-Object { $_.Name -eq $name })
        if (@($same | Where-Object { $_.ClientId -ne $g.ToString() }).Count) { return (& $no "$name is listed with two different client ids") }
        if (-not @($same | Where-Object { $_.Role -eq $role }).Count) { $p.Add([pscustomobject]@{ Name = $name; ClientId = $g.ToString(); Role = $role }) }
    }
    if ("$WebUser" -notmatch $script:EpsDbInitNamePattern) { return (& $no "unsafe web user name '$WebUser'") }
    if (-not @($p | Where-Object Name -eq $WebUser).Count) { return (& $no "the web user $WebUser is not one of the principals") }
    $sa = $null
    if ("$SuperAdmin".Trim()) {
        $parts = "$SuperAdmin".Split('|')
        $o = [guid]::Empty
        if ($parts.Count -ne 2 -or -not [guid]::TryParse($parts[1], [ref]$o) -or $parts[0] -notmatch '^[^@\s''"\]\[|]+@[^@\s''"\]\[|]+\.[^@\s''"\]\[|]+$') { return (& $no 'EPS_DBINIT_SUPERADMIN is not "<upn>|<object id>"') }
        $sa = @{ Upn = $parts[0]; ObjectId = $o.ToString() }
    }
    $d = @(foreach ($x in "$Drop".Split(',')) { $t = $x.Trim(); if ($t) { $t } })
    foreach ($x in $d) {
        if ($x -notmatch $script:EpsDbInitNamePattern) { return (& $no "unsafe database user name to remove '$x'") }
        if (@($p | Where-Object Name -eq $x).Count) { return (& $no "$x is to be removed AND kept - refused") }
    }
    @{ Ok = $true; Reason = ''; Principals = @($p); WebUser = $WebUser; SuperAdmin = $sa; Drop = @($d) }
}

function Get-EpsDbInitPlan {
    # PURE. The batches the job runs, in order (after the schema): the component roles + grants (they need the tables),
    # each principal as a user in its role, the sign-in front's schema (its owner must exist), the first SuperAdmin, the
    # removals. Each batch @{ Name; Sql }.
    param([Parameter(Mandatory)]$DbInput, [Parameter(Mandatory)]$GrantList)
    $b = [System.Collections.Generic.List[object]]::new()
    $b.Add(@{ Name = 'roles and grants (sql/eps-grants.json)'; Sql = (Get-EpsGrantScript -GrantList $GrantList) })
    $b.Add(@{ Name = "database users ($(@($DbInput.Principals | ForEach-Object { "$($_.Name) in $($_.Role)" }) -join ', '))"
              Sql = (@(foreach ($x in $DbInput.Principals) { Get-EpsSqlUserScript -Name $x.Name -ClientId $x.ClientId -Role $x.Role }) -join "`n") })
    $b.Add(@{ Name = "the sign-in front's state (schema signin owned by $($DbInput.WebUser))"; Sql = (Get-EpsSigninStateSql -WebUser $DbInput.WebUser) })
    if ($DbInput.SuperAdmin) { $b.Add(@{ Name = "the first SuperAdmin $($DbInput.SuperAdmin.Upn) (only when there is none)"; Sql = (Get-EpsFirstSuperAdminSql -Upn $DbInput.SuperAdmin.Upn -ObjectId $DbInput.SuperAdmin.ObjectId) }) }
    foreach ($x in $DbInput.Drop) { $b.Add(@{ Name = "remove the database user $x"; Sql = "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$x') DROP USER [$x];" }) }
    @($b)
}

$script:EpsDbInitReadBackSql = @'
SELECT dp.name AS Name, CONVERT(VARCHAR(200), dp.sid, 1) AS Sid, r.name AS RoleName
FROM sys.database_principals dp
LEFT JOIN sys.database_role_members m ON m.member_principal_id = dp.principal_id
LEFT JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
WHERE dp.type IN ('E', 'X', 'S', 'U')
UNION ALL SELECT N'#signin-owner', NULL, USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'
UNION ALL SELECT N'#superadmins', NULL, CONVERT(NVARCHAR(20), COUNT(*)) FROM eps.WebAccess WHERE Role = 'SuperAdmin'
UNION ALL SELECT N'#schema', NULL, CONVERT(NVARCHAR(20), MAX(Version)) FROM eps.SchemaVersion
'@

function Test-EpsDbInitReadBack {
    <#
      PURE. The verdict from the read-back rows: every principal is a user with ITS sid (from the client id) and a member
      of its role, and of no broad db_* role; every removed user is gone; schema signin is owned by the web user; a
      SuperAdmin exists when one was asked for; the schema has a version. Returns @{ Ok; Problems; Lines }.
    #>
    param([Parameter(Mandatory)]$DbInput, [object[]]$Rows = @())
    $problems = [System.Collections.Generic.List[string]]::new(); $lines = [System.Collections.Generic.List[string]]::new()
    $byName = @{}
    foreach ($r in $Rows) { $k = "$($r.Name)"; if (-not $byName.ContainsKey($k)) { $byName[$k] = [System.Collections.Generic.List[object]]::new() }; $byName[$k].Add($r) }
    foreach ($name in @($DbInput.Principals | ForEach-Object Name | Select-Object -Unique)) {
        $want = @($DbInput.Principals | Where-Object Name -eq $name)
        $sid = (ConvertTo-EpsSqlSid $want[0].ClientId).ToUpperInvariant()
        $have = if ($byName.ContainsKey($name)) { @($byName[$name]) } else { @() }
        if (-not $have.Count) { $problems.Add("$name is not a database user"); continue }
        if ("$($have[0].Sid)".ToUpperInvariant() -ne $sid) { $problems.Add("$name has another sid ($($have[0].Sid)) than its client id gives"); continue }
        $roles = @($have | ForEach-Object { "$($_.RoleName)" } | Where-Object { $_ })
        foreach ($w in $want) { if ($roles -notcontains $w.Role) { $problems.Add("$name is not a member of $($w.Role)") } }
        $broad = @($roles | Where-Object { $_ -in $script:EpsDbInitBanned })
        if ($broad.Count) { $problems.Add("$name is still in $($broad -join ', ')") }
        $lines.Add("read back: $name (sid ok) in $(@($want | ForEach-Object Role) -join ', ')")
    }
    foreach ($x in $DbInput.Drop) { if ($byName.ContainsKey($x)) { $problems.Add("$x is still a database user") } else { $lines.Add("read back: $x is gone") } }
    $owner = if ($byName.ContainsKey('#signin-owner')) { "$(@($byName['#signin-owner'])[0].RoleName)" } else { '' }
    if ($owner -ne $DbInput.WebUser) { $problems.Add("schema signin is owned by '$owner', not $($DbInput.WebUser)") } else { $lines.Add("read back: schema signin owned by $owner") }
    $sa = if ($byName.ContainsKey('#superadmins')) { [int]"0$(@($byName['#superadmins'])[0].RoleName)" } else { 0 }
    if ($DbInput.SuperAdmin -and $sa -lt 1) { $problems.Add('no SuperAdmin after the first SuperAdmin was asked for') }
    $ver = if ($byName.ContainsKey('#schema')) { "$(@($byName['#schema'])[0].RoleName)" } else { '' }
    if (-not $ver) { $problems.Add('the schema has no version') } else { $lines.Add("read back: schema version $ver; SuperAdmins $sa") }
    @{ Ok = -not $problems.Count; Problems = @($problems); Lines = @($lines) }
}

function Invoke-EpsDbInit {
    <#
      The job's run. -Log { param($m) } prints a line. Returns the exit code: 0 = everything read back, 1 = a step or the
      read-back failed, 2 = misconfigured (refused inputs). A refused login (the group membership is new, or still
      replicating) is retried for up to ~5 minutes with a fresh token each time.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][scriptblock]$Log, [hashtable]$Env = @{},
          [string]$SolutionRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), [int]$LoginTries = 16, [int]$LoginWaitSeconds = 20)
    $e = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])" } else { [Environment]::GetEnvironmentVariable($k) } }
    $gl = Get-EpsGrantList -SolutionRoot $SolutionRoot
    $in = Read-EpsDbInitInput -PrincipalsJson (& $e 'EPS_DBINIT_PRINCIPALS') -WebUser (& $e 'EPS_DBINIT_WEB_USER') -SuperAdmin (& $e 'EPS_DBINIT_SUPERADMIN') -Drop (& $e 'EPS_DBINIT_DROP') -Roles @($gl.roles.Keys)
    if (-not $in.Ok) { & $Log "refused: $($in.Reason)"; return 2 }
    & $Log "principals: $(@($in.Principals | ForEach-Object { "$($_.Name)=$($_.Role)" }) -join ', '); web user $($in.WebUser)$(if ($in.SuperAdmin) { "; first SuperAdmin $($in.SuperAdmin.Upn)" })$(if ($in.Drop.Count) { "; remove $($in.Drop -join ', ')" })"
    # the login first: the job's identity is the admin only through the group
    $ok = $false
    for ($i = 1; $i -le $LoginTries; $i++) {
        try { [void](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query 'SELECT 1'); $ok = $true; break }
        catch {
            $m = "$($_.Exception.Message)"
            if ($m -notmatch '(?i)Login failed|18456|40615|not allowed to access|token-identified principal') { & $Log "SQL could not be reached: $m"; return 1 }
            & $Log "login refused (try $i of $LoginTries) - the identity's membership of the SQL admin group may still be replicating: $m"
            $script:EpsSqlToken = $null
            if ($i -lt $LoginTries) { Start-Sleep -Seconds $LoginWaitSeconds }
        }
    }
    if (-not $ok) { & $Log "the job's identity could not sign in to SQL as the admin group's member after $LoginTries tries"; return 1 }
    try {
        $v = Install-EpsSchema -ConnectionString $ConnectionString -SchemaPath (Join-Path $SolutionRoot 'sql\eps-schema.sql')
        & $Log "schema: version $v"
        foreach ($b in Get-EpsDbInitPlan -DbInput $in -GrantList $gl) {
            [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query $b.Sql)
            & $Log "done: $($b.Name)"
        }
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $script:EpsDbInitReadBackSql)
    } catch { & $Log "failed: $($_.Exception.Message)"; return 1 }
    $t = Test-EpsDbInitReadBack -DbInput $in -Rows $rows
    foreach ($l in $t.Lines) { & $Log $l }
    foreach ($p in $t.Problems) { & $Log "NOT OK: $p" }
    if (-not $t.Ok) { return 1 }
    & $Log 'verdict: every principal read back'
    0
}

# ======================================================================================================================
# The INSTALLER's side (EPS-Install.ps1 dot-sources this file): the SQL admin group with the job's identity in it, the
# job, one execution and its verdict. The person who installs needs NO SQL right and opens NO firewall window.
# ======================================================================================================================

function Get-EpsDbInitPrincipals {
    # PURE. The users the job makes: each install identity in the role the grant list gives it (the scheduler runs as
    # the engine identity, so id-eps-engine gets eps_engine AND eps_tick).
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$GrantList)
    $n = $Ctx.Names
    $roleOf = @{}; foreach ($r in $GrantList.roles.Keys) { $roleOf["$($GrantList.roles[$r].identity)"] = $r }
    @(foreach ($k in 'EngineIdentity', 'TickIdentity', 'WebIdentity') {
        if (-not $Ctx.Identities[$k].ClientId) { throw "the client id of $($n[$k]) is not known - run the identities step" }
        [ordered]@{ name = $n[$k]; clientId = "$($Ctx.Identities[$k].ClientId)"; role = $roleOf[$k] }
    })
}

function Get-EpsDbInitJobBody {
    # PURE. caj-eps-dbinit: MANUAL trigger (the installer / the updater start it; never the tick, never a queue), the
    # engine image, its OWN identity id-eps-dbinit (the only identity in the SQL admin group), no secret.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)]$GrantList)
    $n = $Ctx.Names
    $mi = $Ctx.Identities.DbInitIdentity
    $miId = if ($mi.Id) { $mi.Id } else { "(the $($n.DbInitIdentity) identity, created by the install)" }
    $cs = "Server=tcp:$($n.SqlServer).database.windows.net,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $pr = if ($Ctx.Identities.EngineIdentity.ClientId) { ConvertTo-Json -InputObject @(Get-EpsDbInitPrincipals -Ctx $Ctx -GrantList $GrantList) -Compress -Depth 5 } else { '(the identities, created by the install)' }
    [ordered]@{
        Name = $n.DbInitJob
        Body = [ordered]@{
            location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; job = 'DbInit' }
            identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $miId = @{} } }
            properties = [ordered]@{
                environmentId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
                workloadProfileName = 'Consumption'
                configuration = [ordered]@{ triggerType = 'Manual'; replicaTimeout = 1800; replicaRetryLimit = 0
                    manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 }
                    registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = $miId }) }
                template = @{ containers = @(@{ name = 'eps'; image = $Image; resources = @{ cpu = [double]0.5; memory = '1Gi' }
                    env = @(
                        @{ name = 'EPS_JOB'; value = 'DbInit' }
                        @{ name = 'EPS_SQL_CONNECTION'; value = $cs }
                        @{ name = 'EPS_TENANT_ID'; value = $Ctx.TenantId }
                        @{ name = 'EPS_ManagedIdentityClientId'; value = "$($mi.ClientId)" }
                        @{ name = 'EPS_DBINIT_PRINCIPALS'; value = $pr }
                        @{ name = 'EPS_DBINIT_WEB_USER'; value = $n.WebIdentity }) }) }
            }
        }
    }
}

function Find-EpsSqlAdminGroup {
    # The group by its standard name (grp-eps-sql-admins); several with that name = refused (never a guess).
    param([Parameter(Mandatory)]$Ctx)
    $name = $Ctx.Names.SqlAdminGroup
    $g = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$name'&`$select=id,displayName" -All)
    if ($g.Count -gt 1) { throw "$($g.Count) groups are named $name - say which with -SqlAdminGroupId" }
    if ($g.Count) { return @{ ObjectId = "$($g[0].id)"; Name = "$($g[0].displayName)" } }
    $null
}

function Add-EpsDbInitToGroup {
    # The job's identity in the group, READ BACK (spec point 7: membership first, then the first start - a managed
    # identity's token is cached). Idempotent. Throws on a refusal.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$GroupId)
    $sp = "$($Ctx.Identities.DbInitIdentity.PrincipalId)"
    if (-not $sp) { throw "the principal of $($Ctx.Names.DbInitIdentity) is not known - run the identities step" }
    $isIn = { @(Invoke-EpsGraph -Path "v1.0/groups/$GroupId/members?`$select=id" -All | Where-Object { "$($_.id)" -eq $sp }).Count -gt 0 }
    if (& $isIn) { return 'already a member' }
    try { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path "v1.0/groups/$GroupId/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$sp" }) } }
    catch { if ("$_" -notmatch '(?i)already exist') { throw } }
    for ($i = 0; $i -lt 9; $i++) {
        if (& $isIn) { return 'added, read back' }
        Start-Sleep -Seconds $(if ($null -ne $script:EpsGraphReadBackSeconds) { $script:EpsGraphReadBackSeconds } else { 15 })
    }
    throw "$($Ctx.Names.DbInitIdentity) is still not a member of the group $GroupId after it was added"
}

function Initialize-EpsSqlAdminGroup {
    <#
      SEC-03 / SEC-08 row 5: the SQL server's Entra admin is a GROUP and the job's identity is in it. Which group:
        - an EXISTING server keeps its admin (a re-run never takes the customer's admin away): a group admin gets the
          job's identity added; a person / application admin cannot hold a member, so the database steps run as the
          signed-in person, said plainly (to stop that: make grp-eps-sql-admins the admin);
        - a new server: the customer's group (-SqlAdminGroupId), else grp-eps-sql-admins (found, else created).
      Never throws on a refused Graph write: returns @{ Use = $false; Why } and the install goes on the old way.
      Sets $Ctx.SqlAdminGroup (the 'sql' step names it as a new server's admin) and $Ctx.DbJob.
    #>
    param([Parameter(Mandatory)]$Ctx, [switch]$NoCreate)
    $n = $Ctx.Names
    $srv = Invoke-EpsArm -Path "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Sql/servers/$($n.SqlServer)" -ApiVersion $script:EpsApi.sql -AllowNotFound
    $a = if ($srv) { $srv.properties.administrators }
    $res = $null
    try {
        if ($a -and "$($a.sid)") {
            if ("$($a.principalType)" -notin 'Group', '') { $res = @{ Use = $false; Why = "the SQL server's Entra admin is $($a.login) ($($a.principalType)), not a group - the database steps run as you; make $($n.SqlAdminGroup) the admin to stop that" } }
            else {
                $g = try { Invoke-EpsGraph -Path "v1.0/groups/$($a.sid)?`$select=id,displayName" } catch { $null }
                if (-not $g) { $res = @{ Use = $false; Why = "the SQL server's Entra admin $($a.login) is not a group - the database steps run as you" } }
                else {
                    $how = Add-EpsDbInitToGroup -Ctx $Ctx -GroupId "$($g.id)"
                    $Ctx.SqlAdminGroup = @{ ObjectId = "$($g.id)"; Name = "$($g.displayName)" }
                    $res = @{ Use = $true; Why = "$($n.DbInitIdentity) in the server's admin group $($g.displayName) ($how)" }
                }
            }
        } else {
            $grp = if ($Ctx.SqlAdminGroup -and $Ctx.SqlAdminGroup.ObjectId) { $Ctx.SqlAdminGroup } else { Find-EpsSqlAdminGroup -Ctx $Ctx }
            if (-not $grp -and -not $NoCreate) {
                $c = Invoke-EpsGraph -Method POST -Path 'v1.0/groups' -Body @{ displayName = $n.SqlAdminGroup; mailEnabled = $false; mailNickname = $n.SqlAdminGroup; securityEnabled = $true
                    description = 'Entra Policy Suite: the Azure SQL server admin. Members: the database setup job identity (and support, just in time).' }
                $grp = @{ ObjectId = "$($c.id)"; Name = "$($c.displayName)" }
                [void](Invoke-EpsWithRetry { Invoke-EpsGraph -Path "v1.0/groups/$($grp.ObjectId)?`$select=id" })
            }
            if (-not $grp) { $res = @{ Use = $false; Why = "no $($n.SqlAdminGroup) group" } }
            else {
                $how = Add-EpsDbInitToGroup -Ctx $Ctx -GroupId $grp.ObjectId
                $Ctx.SqlAdminGroup = $grp
                $res = @{ Use = $true; Why = "$($n.DbInitIdentity) in $($grp.Name) ($how) - the new server's admin" }
            }
        }
    } catch { $res = @{ Use = $false; Why = "the SQL admin group could not be set up ($($_.Exception.Message)) - the database steps run as you; the next run tries again" } }
    $Ctx.DbJob = $res
    $res
}

function Wait-EpsAcaJobExecution {
    # ARM: the execution's own status until it ends (Succeeded / Failed / Stopped / Degraded). Returns @{ Status; Seconds }.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][string]$Execution, [int]$TimeoutSeconds = 1200, [int]$PollSeconds = 15)
    $p = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($Ctx.Names.ResourceGroup)/providers/Microsoft.App/jobs/$Job/executions/$Execution"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $e = Invoke-EpsArm -Path $p -ApiVersion $script:EpsApi.acajob -AllowNotFound
        $st = "$($e.properties.status)"
        if ($st -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { return @{ Status = $st; Seconds = [int]$sw.Elapsed.TotalSeconds } }
        Start-Sleep -Seconds $PollSeconds
    }
    @{ Status = 'TimedOut'; Seconds = [int]$sw.Elapsed.TotalSeconds }
}

function Invoke-EpsDbInitJob {
    <#
      The job made (PUT - the same body every run), started ONCE with this run's inputs (the first SuperAdmin, users to
      remove), waited for; the verdict = the execution's own status (the entry exits 0 only when every principal was
      read back). A failure names the execution and where its lines are.
    #>
    param([Parameter(Mandatory)]$Ctx, $SuperAdmin, [string[]]$Drop = @())
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    $gl = Get-EpsGrantList -SolutionRoot $Ctx.SolutionRoot
    $j = Get-EpsDbInitJobBody -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)" -GrantList $gl
    [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -ApiVersion $script:EpsApi.acajob -Body $j.Body)
    $env = @{}
    if ($SuperAdmin) { $env.EPS_DBINIT_SUPERADMIN = "$($SuperAdmin.Upn)|$($SuperAdmin.ObjectId)" }
    if (@($Drop).Count) { $env.EPS_DBINIT_DROP = (@($Drop) -join ',') }
    $s = Start-EpsAcaJob -SubscriptionId $Ctx.SubscriptionId -ResourceGroup $n.ResourceGroup -Name $j.Name -Env $env -Waits @(0, 15, 30, 60)
    if (-not $s.Ok) { throw "the database setup job $($j.Name) could not be started: $($s.Reason)" }
    $w = Wait-EpsAcaJobExecution -Ctx $Ctx -Job $j.Name -Execution $s.Execution -PollSeconds ($Ctx.PollSeconds ?? 15)
    if ($w.Status -ne 'Succeeded') { throw "the database setup job ($($s.Execution)) ended '$($w.Status)' after $($w.Seconds) s - its lines are in $($n.Logs) (ContainerAppConsoleLogs_CL, ContainerJobName_s = '$($j.Name)'); fix the cause and run the install again" }
    @{ Execution = $s.Execution; Seconds = $w.Seconds }
}
