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
    # -FrontVersion: per execution, the sign-in front the web app RUNS (OPEN-15) - recorded for the heartbeat
    param([string]$PrincipalsJson, [string]$WebUser, [string]$SuperAdmin, [string]$Drop, [Parameter(Mandatory)][string[]]$Roles, [string]$FrontVersion,
          # a role renamed in the grant list (renamedFrom): a job set up before the rename still names the old one
          [hashtable]$RoleAliases = @{})
    $no = { param($r) @{ Ok = $false; Reason = $r } }
    if (-not "$PrincipalsJson".Trim()) { return (& $no 'EPS_DBINIT_PRINCIPALS is not set') }
    $list = try { @($PrincipalsJson | ConvertFrom-Json -Depth 5) } catch { return (& $no "EPS_DBINIT_PRINCIPALS is not JSON: $($_.Exception.Message)") }
    if (-not $list.Count) { return (& $no 'EPS_DBINIT_PRINCIPALS lists nobody') }
    $p = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $list) {
        $name = "$($x.name)"; $cid = "$($x.clientId)"; $role = "$($x.role)"; if ($RoleAliases.ContainsKey($role)) { $role = $RoleAliases[$role] }
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
    $fv = "$FrontVersion".Trim()
    if ($fv -and $fv -notmatch '^[0-9A-Za-z.+]{1,50}$') { return (& $no "EPS_DBINIT_FRONT '$fv' is not a version") }
    @{ Ok = $true; Reason = ''; Principals = @($p); WebUser = $WebUser; SuperAdmin = $sa; Drop = @($d); FrontVersion = $fv }
}

function Read-EpsDbInitSettings {
    <#
      PURE. SEC-08 row 9: per execution, settings a setup script asks the job to write (EPS_DBINIT_SETTINGS, a JSON object).
      ONLY these keys, each checked: Mail.Mode (sharedMailbox | none), Mail.Sender (one mail address), Mail.Recipients (a
      JSON list of 1-20 mail addresses), Platform.EnvironmentName (plain text, at most 120), IdentityReport.LogAnalytics.Target
      (Test-EpsLaTarget). Anything else refuses the whole input. Returns @{ Ok; Reason; Settings (ordered) }.
    #>
    param([AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { return @{ Ok = $true; Reason = ''; Settings = [ordered]@{} } }
    $o = try { $Json | ConvertFrom-Json -AsHashtable -Depth 5 } catch { return @{ Ok = $false; Reason = 'EPS_DBINIT_SETTINGS is not JSON' } }
    if ($o -isnot [System.Collections.IDictionary]) { return @{ Ok = $false; Reason = 'EPS_DBINIT_SETTINGS is not an object' } }
    $mail = '^[^@\s''"<>;,]{1,64}@[^@\s''"<>;,]{1,190}\.[A-Za-z]{2,24}$'
    $s = [ordered]@{}
    foreach ($k in @($o.Keys)) {
        $v = $o[$k]
        switch ($k) {
            'Mail.Mode' { if ("$v" -notin 'sharedMailbox', 'none') { return @{ Ok = $false; Reason = "Mail.Mode '$v' is not sharedMailbox or none" } }; $s[$k] = "$v" }
            'Mail.Sender' { if ("$v" -notmatch $mail) { return @{ Ok = $false; Reason = 'Mail.Sender is not a mail address' } }; $s[$k] = "$v" }
            'Mail.Recipients' {
                $l = @($v | ForEach-Object { "$_" }); if (-not $l.Count -or $l.Count -gt 20 -or @($l | Where-Object { $_ -notmatch $mail }).Count) { return @{ Ok = $false; Reason = 'Mail.Recipients is not a list of 1-20 mail addresses' } }
                $s[$k] = (ConvertTo-Json -InputObject @($l) -Compress)
            }
            'Platform.EnvironmentName' { if ("$v" -notmatch '^[^\x00-\x1f<>''"]{1,120}$') { return @{ Ok = $false; Reason = 'Platform.EnvironmentName is not plain text of at most 120 characters' } }; $s[$k] = "$v" }
            # V1-PARITY P11: Initialize-EpsLogAnalytics.ps1's target (the workspace, the endpoint, the rule, the stream's
            # columns) - checked whole by Test-EpsLaTarget (EPS-LogAnalytics.ps1, loaded by the job's entry)
            'IdentityReport.LogAnalytics.Target' {
                $j = if ($v -is [string]) { "$v" } else { ConvertTo-Json -InputObject $v -Compress -Depth 6 }
                if ($j.Length -gt 8000) { return @{ Ok = $false; Reason = 'IdentityReport.LogAnalytics.Target is longer than 8000 characters' } }
                if (-not (Get-Command Test-EpsLaTarget -ErrorAction SilentlyContinue)) { return @{ Ok = $false; Reason = 'IdentityReport.LogAnalytics.Target cannot be checked here (EPS-LogAnalytics.ps1 is not loaded)' } }
                $t = Test-EpsLaTarget -Json $j
                if (-not $t.Ok) { return @{ Ok = $false; Reason = "IdentityReport.LogAnalytics.Target: $($t.Reason)" } }
                $s[$k] = $j
            }
            default { return @{ Ok = $false; Reason = "setting '$k' may not be written by the setup job" } }
        }
    }
    @{ Ok = $true; Reason = ''; Settings = $s }
}

function Get-EpsDbInitSettingsSql {
    # PURE. The checked settings as MERGEs + ONE audit row (setting.change, by the setup job for the named person)
    param([Parameter(Mandatory)]$Settings, [string]$By = 'setup script')
    $q = { param($x) "N'$("$x".Replace("'", "''"))'" }
    $lines = @(foreach ($k in $Settings.Keys) { "MERGE eps.Setting AS d USING (SELECT $(& $q $k) AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = $(& $q $Settings[$k]), UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = $(& $q $By) WHEN NOT MATCHED THEN INSERT (Name, Feature, Value, UpdatedBy) VALUES ($(& $q $k), $(& $q $k.Split('.')[0]), $(& $q $Settings[$k]), $(& $q $By));" })
    $after = (@{} + $Settings | ConvertTo-Json -Compress).Replace("'", "''")
    $lines += "INSERT INTO eps.AuditEvent (Action, Actor, ActorSource, Target, Reason, Outcome, AfterJson) VALUES ('setting.change', $(& $q $By), 'setup', N'Setting|$(($Settings.Keys) -join ',')', N'written by the database setup job for a setup script (SEC-08)', 'ok', N'$after');"
    $lines -join "`n"
}

function Get-EpsUplinkStateMergeSql {
    # PURE. One eps.UplinkState row (name and value already checked by the caller's patterns)
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9.-]{1,60}$')][string]$Name, [Parameter(Mandatory)][ValidatePattern('^[0-9A-Za-z.+:| -]{1,100}$')][string]$Value)
    "MERGE eps.UplinkState AS t USING (SELECT N'$Name' AS Name) AS s ON t.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = N'$Value', UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (N'$Name', N'$Value');"
}

function Get-EpsDbInitPlan {
    # PURE. The batches the job runs, in order (after the schema): the component roles + grants (they need the tables),
    # each principal as a user in its role, the sign-in front's schema (its owner must exist), the first SuperAdmin, the
    # removals. Each batch @{ Name; Sql }.
    # -Version: the job's own VERSION - recorded as setup.dbjob (TEL-03: the heartbeat's setup step 'db-job')
    param([Parameter(Mandatory)]$DbInput, [Parameter(Mandatory)]$GrantList, [string]$Version)
    $b = [System.Collections.Generic.List[object]]::new()
    $b.Add(@{ Name = 'roles and grants (sql/eps-grants.json)'; Sql = (Get-EpsGrantScript -GrantList $GrantList) })
    $b.Add(@{ Name = "database users ($(@($DbInput.Principals | ForEach-Object { "$($_.Name) in $($_.Role)" }) -join ', '))"
              Sql = (@(foreach ($x in $DbInput.Principals) { Get-EpsSqlUserScript -Name $x.Name -ClientId $x.ClientId -Role $x.Role }) -join "`n") })
    $b.Add(@{ Name = "the sign-in front's state (schema signin owned by $($DbInput.WebUser))"; Sql = (Get-EpsSigninStateSql -WebUser $DbInput.WebUser) })
    if ($DbInput.SuperAdmin) { $b.Add(@{ Name = "the first SuperAdmin $($DbInput.SuperAdmin.Upn) (only when there is none)"; Sql = (Get-EpsFirstSuperAdminSql -Upn $DbInput.SuperAdmin.Upn -ObjectId $DbInput.SuperAdmin.ObjectId) }) }
    foreach ($x in $DbInput.Drop) { $b.Add(@{ Name = "remove the database user $x"; Sql = "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$x') DROP USER [$x];" }) }
    if ($DbInput.FrontVersion) { $b.Add(@{ Name = "the sign-in front the web app runs: $($DbInput.FrontVersion)"; Sql = (Get-EpsUplinkStateMergeSql -Name 'signin.front' -Value $DbInput.FrontVersion) }) }
    if ("$Version" -match '^[0-9A-Za-z.+]{1,50}$') { $b.Add(@{ Name = "the setup job's record (setup.dbjob = $Version)"; Sql = (Get-EpsUplinkStateMergeSql -Name 'setup.dbjob' -Value "$Version") }) }
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

function Get-EpsSchemaFileVersion {
    # PURE. The schema version a release's sql/eps-schema.sql brings: its highest INSERT INTO eps.SchemaVersion
    param([Parameter(Mandatory)][string]$Text)
    $v = @([regex]::Matches($Text, '(?i)INSERT INTO eps\.SchemaVersion \(Version[^)]*\) VALUES \((\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    if ($v.Count) { ($v | Measure-Object -Maximum).Maximum } else { 0 }
}

function Test-EpsDbInitGrantsOnly {
    <#
      PURE. DBINIT-GRANTS-ONLY (framework §8.18, Invardia 39254c83, 2026-11-06): EPS_DBINIT_STEPS = grants may run BESIDE a
      pipeline run because it changes no table or column a run uses - only the roles and grants, the identities' users and
      their role membership, and create-if-missing objects that are already there. So it refuses: a database whose schema
      is older than this release's (the grants may name what is not there yet - that needs the full run between runs), and
      every input that writes data or removes something (a first SuperAdmin, users to remove, a worker removed, settings,
      the Support app's starting level). EPS signs no procedure, so the re-sign rule (no open Support session) never applies.
      @{ Ok; Reason }.
    #>
    param([Parameter(Mandatory)]$DbInput, [int]$DatabaseVersion, [int]$FileVersion, [string]$Worker, [string]$Seed, [int]$SettingCount)
    $no = @()
    if ($DatabaseVersion -lt $FileVersion) { $no += "the database is at schema $DatabaseVersion and this release brings $FileVersion - the full setup runs between runs" }
    if ($DbInput.SuperAdmin) { $no += 'a first SuperAdmin (a data row)' }
    if (@($DbInput.Drop).Count) { $no += "removing users ($(@($DbInput.Drop) -join ', '))" }
    if ("$Worker" -eq 'remove') { $no += 'removing the hybrid worker''s user' }
    if ("$Seed") { $no += 'the Support app''s starting level (a data row)' }
    if ($SettingCount -gt 0) { $no += 'settings (data rows)' }
    if ($no.Count) { return @{ Ok = $false; Reason = "grants only, but this is not only grants: $($no -join '; ')" } }
    @{ Ok = $true; Reason = "grants only: schema $DatabaseVersion is this release's; roles, grants and users only" }
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
    $ver = try { (Get-Content -LiteralPath (Join-Path $SolutionRoot 'VERSION') -Raw).Trim() } catch { '' }
    $in = Read-EpsDbInitInput -PrincipalsJson (& $e 'EPS_DBINIT_PRINCIPALS') -WebUser (& $e 'EPS_DBINIT_WEB_USER') -SuperAdmin (& $e 'EPS_DBINIT_SUPERADMIN') -Drop (& $e 'EPS_DBINIT_DROP') -Roles @($gl.roles.Keys) -RoleAliases $($al = @{}; foreach ($k in $gl.roles.Keys) { if ($gl.roles[$k].renamedFrom) { $al["$($gl.roles[$k].renamedFrom)"] = $k } }; $al) -FrontVersion (& $e 'EPS_DBINIT_FRONT')
    if (-not $in.Ok) { & $Log "refused: $($in.Reason)"; return 2 }
    # SEC-08 row 7: per execution, the hybrid worker's identity as the database user eps-hybrid-worker in eps_worker
    # (EPS_DBINIT_WORKER = its client id), or 'remove' - the person who adds a worker needs no SQL right
    $wk = "$(& $e 'EPS_DBINIT_WORKER')".Trim().ToLowerInvariant()
    if ($wk) {
        if ($wk -eq 'remove') { $in.Drop = @(@($in.Drop) + 'eps-hybrid-worker') }
        elseif ($wk -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and $gl.roles.Contains('eps_worker')) { $in.Principals = @(@($in.Principals) + [pscustomobject]@{ Name = 'eps-hybrid-worker'; ClientId = $wk; Role = 'eps_worker' }) }
        else { & $Log "refused: EPS_DBINIT_WORKER is not a client id or 'remove'"; return 2 }
    }
    # the install's -SupportAppId (as SI / PIM): the Support app's STARTING level, written only when no level is there yet;
    # the support job then applies it until the customer's level from the Invardia portal arrives
    $seed = "$(& $e 'EPS_DBINIT_SUPPORT')".Trim().ToLowerInvariant()
    $seedSql = ''
    if ($seed) {
        if ($seed -notmatch '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\|(troubleshoot|read|none)$') { & $Log "refused: EPS_DBINIT_SUPPORT is not '<client id>|troubleshoot|read|none'"; return 2 }
        $seedSql = "IF NOT EXISTS (SELECT 1 FROM eps.SupportAccess) INSERT INTO eps.SupportAccess (Id, Level, AppId, Applied) VALUES (1, N'$($Matches[2])', N'$($Matches[1])', N'the starting level from the install (-SupportAppId)');"
    }
    $set = Read-EpsDbInitSettings -Json (& $e 'EPS_DBINIT_SETTINGS')
    if (-not $set.Ok) { & $Log "refused: $($set.Reason)"; return 2 }
    $by = "$(& $e 'EPS_DBINIT_BY')".Trim(); if ($by -notmatch '^[^\x00-\x1f<>''"]{1,200}$') { $by = 'setup script' }
    $steps = "$(& $e 'EPS_DBINIT_STEPS')".Trim().ToLowerInvariant()
    if ($steps -notin '', 'all', 'grants') { & $Log "refused: EPS_DBINIT_STEPS is '$steps' (all or grants)"; return 2 }
    $grantsOnly = $steps -eq 'grants'
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
        if ($grantsOnly) {
            # DBINIT-GRANTS-ONLY: no schema change - the database must already be at this release's schema
            $dbv = [int]"0$(Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query 'SELECT MAX(Version) FROM eps.SchemaVersion')"
            $fv = Get-EpsSchemaFileVersion -Text (Get-Content -LiteralPath (Join-Path $SolutionRoot 'sql\eps-schema.sql') -Raw)
            $go = Test-EpsDbInitGrantsOnly -DbInput $in -DatabaseVersion $dbv -FileVersion $fv -Worker $wk -Seed $seed -SettingCount @($set.Settings.Keys).Count
            if (-not $go.Ok) { & $Log "refused: $($go.Reason)"; return 2 }
            & $Log $go.Reason
            # only the roles and grants, the users and the sign-in front's schema (create-if-missing); no record rows
            $plan = @(Get-EpsDbInitPlan -DbInput $in -GrantList $gl | Where-Object { $_.Name -like 'roles and grants*' -or $_.Name -like 'database users*' -or $_.Name -like "the sign-in front's state*" })
        } else {
        $v = Install-EpsSchema -ConnectionString $ConnectionString -SchemaPath (Join-Path $SolutionRoot 'sql\eps-schema.sql')
        & $Log "schema: version $v"
        $plan = @(Get-EpsDbInitPlan -DbInput $in -GrantList $gl -Version $ver)
        }
        if ($seedSql) { $plan += @{ Name = "the Support app's starting level (only when none is set)"; Sql = $seedSql } }
        if ($set.Settings.Count) { $plan += @{ Name = "settings for a setup script: $(@($set.Settings.Keys) -join ', ') (by $by)"; Sql = (Get-EpsDbInitSettingsSql -Settings $set.Settings -By $by) } }
        foreach ($b in $plan) {
            [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query $b.Sql)
            & $Log "done: $($b.Name)"
        }
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $script:EpsDbInitReadBackSql)
    } catch {
        & $Log "failed: $($_.Exception.Message)"
        [void](Write-EpsDbInitAudit -ConnectionString $ConnectionString -DbInput $in -By $by -Version $ver -Worker $wk -SupportSeed $seed -SettingKeys @($set.Settings.Keys) -Outcome 'error' -OutcomeText "$($_.Exception.Message)")
        return 1
    }
    $t = Test-EpsDbInitReadBack -DbInput $in -Rows $rows
    foreach ($l in $t.Lines) { & $Log $l }
    foreach ($p in $t.Problems) { & $Log "NOT OK: $p" }
    # AUD-01: the job's change is in the trail, with its read-back verdict (the job's log alone is not the durable store)
    $au = Write-EpsDbInitAudit -ConnectionString $ConnectionString -DbInput $in -By $by -Version $ver -Worker $wk -SupportSeed $seed -SettingKeys @($set.Settings.Keys) `
        -Outcome $(if ($t.Ok) { 'ok' } else { 'error' }) -OutcomeText $(if ($t.Ok) { 'every principal read back' } else { $t.Problems -join '; ' })
    & $Log "audit: setup.database.apply $(if ($au) { 'recorded' } else { 'NOT recorded (see the warning)' })"
    if (-not $t.Ok) { return 1 }
    & $Log 'verdict: every principal read back'
    0
}

function Write-EpsDbInitAudit {
    # AUD-01 (framework AUDIT-1.2 items 1 + 3): ONE audit row for the setup job's run - who asked (the setup script's
    # person, else the install), what it set up (users and roles, the hybrid worker added / removed, the first SuperAdmin,
    # removals, the Support app's starting level, the setting keys) and the read-back verdict. Never throws.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$DbInput, [string]$By, [string]$Version, [string]$Worker, [string]$SupportSeed,
          [string[]]$SettingKeys = @(), [ValidateSet('ok', 'error')][string]$Outcome = 'ok', [string]$OutcomeText)
    $after = [ordered]@{
        appliedBy = 'caj-eps-dbinit'; version = $Version
        users = @($DbInput.Principals | ForEach-Object { "$($_.Name)=$($_.Role)" })
        removed = @($DbInput.Drop)
        firstSuperAdmin = $(if ($DbInput.SuperAdmin) { "$($DbInput.SuperAdmin.Upn) (only when there was none)" })
        hybridWorker = $(if ($Worker -eq 'remove') { 'removed' } elseif ($Worker) { "added ($Worker)" })
        supportStartingLevel = $(if ($SupportSeed) { ($SupportSeed -split '\|')[-1] })
        settings = @($SettingKeys)
    }
    try {
        Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'setup.database.apply' -Actor $(if ("$By".Trim()) { $By } else { 'setup script' }) -ActorSource 'setup' `
            -Target 'Database' -Outcome $Outcome -OutcomeText $OutcomeText -After $after
    } catch { Write-Warning "[audit] setup.database.apply could not be written: $($_.Exception.Message)"; $false }
}

# ======================================================================================================================
# The INSTALLER's side (EPS-Install.ps1 dot-sources this file): the SQL admin group with the job's identity in it, the
# job, one execution and its verdict. The person who installs needs NO SQL right and opens NO firewall window.
# ======================================================================================================================

function Get-EpsDbInitPrincipals {
    # PURE. The users the job makes: each install identity in the role the grant list gives it (the scheduler runs as
    # the engine identity, so id-eps-engine gets eps_engine AND eps_schedule).
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$GrantList)
    $n = $Ctx.Names
    $roleOf = @{}; foreach ($r in $GrantList.roles.Keys) { $roleOf["$($GrantList.roles[$r].identity)"] = $r }
    # SUP-02 (2.0.101): + the support read identity (eps_supportread) - only when the install has made it
    @(foreach ($k in @('EngineIdentity', 'TickIdentity', 'WebIdentity') + @(if ($Ctx.Identities.SupportReadIdentity.ClientId) { 'SupportReadIdentity' })) {
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

function Get-EpsSupportJobBody {
    # PURE. caj-eps-support (OPEN-01): every 5 minutes, as id-eps-dbinit (the SQL admin group's member), the engine image,
    # EPS_JOB SupportAccess; the vault NAME for the install key (Key Vault Secrets User on uplink-key only). No secret.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Image)
    $n = $Ctx.Names; $mi = $Ctx.Identities.DbInitIdentity
    $cs = "Server=tcp:$($n.SqlServer).database.windows.net,1433;Database=$($n.Database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    [ordered]@{
        Name = $n.SupportJob
        Body = [ordered]@{
            location = $Ctx.Location; tags = @{ product = 'EntraPolicySuite'; job = 'SupportAccess' }
            identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ "$($mi.Id)" = @{} } }
            properties = [ordered]@{
                environmentId = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.App/managedEnvironments/$($n.Environment)"
                workloadProfileName = 'Consumption'
                configuration = [ordered]@{ triggerType = 'Schedule'; replicaTimeout = 300; replicaRetryLimit = 0
                    scheduleTriggerConfig = @{ cronExpression = '*/5 * * * *'; parallelism = 1; replicaCompletionCount = 1 }
                    registries = @(@{ server = "$($n.Registry).azurecr.io"; identity = "$($mi.Id)" }) }
                template = @{ containers = @(@{ name = 'eps'; image = $Image; resources = @{ cpu = [double]0.25; memory = '0.5Gi' }
                    env = @(
                        @{ name = 'EPS_JOB'; value = 'SupportAccess' }
                        @{ name = 'EPS_SQL_CONNECTION'; value = $cs }
                        @{ name = 'EPS_TENANT_ID'; value = $Ctx.TenantId }
                        @{ name = 'EPS_KEY_VAULT'; value = $n.KeyVault }
                        @{ name = 'EPS_ManagedIdentityClientId'; value = "$($mi.ClientId)" }) }) }
            }
        }
    }
}

function Find-EpsSqlAdminGroup {
    # The group by its standard name (grp-eps-sql-admins); several with that name = refused (never a guess).
    param([Parameter(Mandatory)]$Ctx)
    $name = $Ctx.Names.SqlAdminGroup
    $g = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$name'&`$select=id,displayName,isAssignableToRole" -All)
    if ($g.Count -gt 1) { throw "$($g.Count) groups are named $name - say which with -SqlAdminGroupId" }
    if ($g.Count) { return @{ ObjectId = "$($g[0].id)"; Name = "$($g[0].displayName)"; RoleAssignable = ($g[0].isAssignableToRole -eq $true) } }
    $null
}

function Get-EpsPimGroupMaxAssignment {
    # The longest ACTIVE member assignment the group's PIM-for-Groups policy allows (its rule Expiration_Admin_Assignment,
    # an ISO 8601 duration such as P180D) - read when the caller may read it, else the default P180D.
    param([Parameter(Mandatory)][string]$GroupId)
    try {
        $a = @(Invoke-EpsGraph -Path "v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq 'member'&`$expand=policy(`$expand=rules)" -All)
        $d = "$(@(@($a | ForEach-Object { $_.policy.rules }) | Where-Object { "$($_.id)" -eq 'Expiration_Admin_Assignment' })[0].maximumDuration)"
        if ($d -match '^P') { return $d }
    } catch { }
    'P180D'
}

function Add-EpsDbInitToGroup {
    # the install's caller of the shared G3 order (framework §4.5 SQL-ADMIN-GROUP G2/G3): the database setup identity
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$GroupId)
    $sp = "$($Ctx.Identities.DbInitIdentity.PrincipalId)"
    if (-not $sp) { throw "the principal of $($Ctx.Names.DbInitIdentity) is not known - run the identities step" }
    Add-EpsSqlAdminMember -PrincipalId $sp -Who $Ctx.Names.DbInitIdentity -GroupId $GroupId -By 'setup'
}

function Add-EpsSqlAdminMember {
    <#
      A principal in the SQL admin group, READ BACK before anything depends on it (spec point 7: membership first, then the
      first start - a managed identity's token is cached). Framework §4.5 SQL-ADMIN-GROUP G2 / G3 (owner 2026-11-05 via SI:
      "it must be in setup"; "both setup and upd"): the product's code makes the membership - the install (-By setup) AND
      the update job (-By update) - never a hand: members/$ref first; refused -> an ACTIVE PIM-for-Groups member
      assignment, permanent first, time-limited only when the group's PIM policy refuses permanent (and then said, with the
      end date); both refused -> one error naming both, so the dependent job never starts. Idempotent. Returns how it was
      made; throws 'EPS-GROUP-ADD: ...' on a refusal or a read-back that never shows it.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$Who, [Parameter(Mandatory)][string]$GroupId, [ValidateSet('setup', 'update')][string]$By = 'setup',
          # where the member's own memberOf is read: a managed identity is a service principal; the replace step (G3a) also
          # copies people and groups
          [ValidateSet('servicePrincipals', 'users', 'groups')][string]$Collection = 'servicePrincipals')
    $sp = $PrincipalId
    $redo = if ($By -eq 'update') { 'the update job renews it on its next run, or run the install again' } else { 'run the install again before that date to renew it' }
    # read from the IDENTITY's side (memberOf): a group's /members silently leaves service principals out for a caller
    # without directory read rights (found live at internal 2026-11-04: the member was there, the list showed only a user);
    # an ACTIVE PIM-for-Groups member shows there too
    $isIn = { @(Invoke-EpsGraph -Path "v1.0/$Collection/$sp/memberOf?`$select=id" -All | Where-Object { "$($_.id)" -eq $GroupId }).Count -gt 0 }
    if (& $isIn) { return 'already a member' }
    $how = $null; $refRefused = $null
    try { Invoke-EpsWithRetry { [void](Invoke-EpsGraph -Method POST -Path "v1.0/groups/$GroupId/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$sp" }) }; $how = 'added (members/$ref)' }
    catch { if ("$_" -match '(?i)already exist') { $how = 'added (members/$ref)' } else { $refRefused = (("$($_.Exception.Message)") -split "`n")[0] } }
    if (-not $how) {
        # an ACTIVE PIM-for-Groups member assignment (the caller needs PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup)
        $pim = { param($exp) Invoke-EpsGraph -Method POST -Path 'v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' -Body @{
            accessId = 'member'; principalId = $sp; groupId = $GroupId; action = 'adminAssign'
            justification = "Entra Policy Suite $(if ($By -eq 'update') { 'update job' } else { 'setup' }): $Who in the SQL admin group (framework 4.5)"
            scheduleInfo = @{ startDateTime = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); expiration = $exp } } }
        try { [void](& $pim @{ type = 'noExpiration' }); $how = 'added by a permanent PIM-for-Groups member assignment (members/$ref was refused)' }
        catch {
            $pimErr = (("$($_.Exception.Message)") -split "`n")[0]
            if ($pimErr -match '(?i)ExpirationRule|expiration|PolicyValidation|maximum') {
                # the group's PIM policy refuses permanent: the longest it allows - a renewal date someone must own
                $dur = Get-EpsPimGroupMaxAssignment -GroupId $GroupId
                $end = [datetime]::UtcNow.Add([System.Xml.XmlConvert]::ToTimeSpan($dur))
                try { [void](& $pim @{ type = 'afterDuration'; duration = $dur }); $how = "added by a TIME-LIMITED PIM-for-Groups member assignment until $($end.ToString('yyyy-MM-dd HH:mm'))Z (the group's PIM policy refuses permanent; members/`$ref was refused) - $redo" }
                catch { $pimErr = "$pimErr; then time-limited ($dur): $((("$($_.Exception.Message)") -split "`n")[0])" }
            }
            if (-not $how) {
                $fix = if ($By -eq 'update') { "The update job ($Who's membership) needs PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup on its own identity (framework §4.5 G5 - the install grants it): run the install again" } else { "Run the install as someone who may add members to that group (an owner of it, or Group.ReadWrite.All / GroupMember.ReadWrite.All), or who may assign PIM-for-Groups members (PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup), then run it again" }
                throw "EPS-GROUP-ADD: $Who could not be put into the group $GroupId - members/`$ref: $refRefused; PIM-for-Groups member assignment: $pimErr. The database setup job is NOT started. $fix"
            }
        }
    }
    for ($i = 0; $i -lt 9; $i++) {
        if (& $isIn) { return "$how, read back" }
        Start-Sleep -Seconds $(if ($null -ne $script:EpsGraphReadBackSeconds) { $script:EpsGraphReadBackSeconds } else { 15 })
    }
    throw "EPS-GROUP-ADD: $Who is still not a member of the group $GroupId after it was $($how -replace '^added ', 'added ') - the database setup job is NOT started; run the install again"
}

function Get-EpsPimMemberSchedule {
    # The principal's ACTIVE PIM-for-Groups member assignment in the group (framework §4.5 G3 read-back / G4): $null when
    # there is none (a direct member, or not a member); else @{ Permanent; End }.
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$PrincipalId)
    $i = @(Invoke-EpsGraph -Path "v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$GroupId' and principalId eq '$PrincipalId'" -All | Where-Object { "$($_.accessId)" -eq 'member' })
    if (-not $i.Count) { return $null }
    $ends = @($i | ForEach-Object {
        $e = $_.endDateTime
        if ($e -is [datetime]) { $e.ToUniversalTime() }
        elseif ("$e") { [datetime]::Parse("$e", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
        else { [datetime]::MaxValue } })
    $end = ($ends | Measure-Object -Maximum).Maximum
    @{ Permanent = ($end -eq [datetime]::MaxValue); End = $(if ($end -eq [datetime]::MaxValue) { $null } else { $end }) }
}

function Update-EpsSqlAdminMemberRenewal {
    <#
      framework §4.5 G4: a TIME-LIMITED PIM-for-Groups member assignment that ends within -Days (30) is renewed by the
      update job - permanent first (adminUpdate, noExpiration), else extended for the group policy's maximum (adminExtend) -
      and read back. NEVER throws: a failed renewal is a WARNING with the end date, never a failed update.
      Returns @{ State = none|permanent|ok|renewed|failed; Text; End }.
    #>
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$Who, [int]$Days = 30, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $s = Get-EpsPimMemberSchedule -GroupId $GroupId -PrincipalId $PrincipalId
        if (-not $s) { return @{ State = 'none'; Text = "$Who is a direct member (no PIM-for-Groups assignment to renew)" } }
        if ($s.Permanent) { return @{ State = 'permanent'; Text = "$Who holds a permanent PIM-for-Groups member assignment" } }
        if ($s.End -gt $NowUtc.AddDays($Days)) { return @{ State = 'ok'; End = $s.End; Text = "$Who's time-limited PIM-for-Groups member assignment ends $($s.End.ToString('yyyy-MM-dd HH:mm'))Z - renewed when it is within $Days days" } }
        $req = { param($action, $exp) Invoke-EpsGraph -Method POST -Path 'v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' -Body @{
            accessId = 'member'; principalId = $PrincipalId; groupId = $GroupId; action = $action
            justification = "Entra Policy Suite update job: renew $Who in the SQL admin group (framework 4.5 G4)"
            scheduleInfo = @{ startDateTime = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); expiration = $exp } } }
        $how = $null; $errs = @()
        try { [void](& $req 'adminUpdate' @{ type = 'noExpiration' }); $how = 'made permanent' } catch { $errs += "permanent: $((("$($_.Exception.Message)") -split "`n")[0])" }
        if (-not $how) {
            $dur = Get-EpsPimGroupMaxAssignment -GroupId $GroupId
            try { [void](& $req 'adminExtend' @{ type = 'afterDuration'; duration = $dur }); $how = "extended by $dur (the group's PIM policy refuses permanent)" } catch { $errs += "extend ($dur): $((("$($_.Exception.Message)") -split "`n")[0])" }
        }
        if (-not $how) { return @{ State = 'failed'; End = $s.End; Text = "WARNING: $Who's PIM-for-Groups member assignment ends $($s.End.ToString('yyyy-MM-dd HH:mm'))Z and could NOT be renewed ($($errs -join '; ')) - the update goes on; renew it before that date (run the install again)" } }
        $n = Get-EpsPimMemberSchedule -GroupId $GroupId -PrincipalId $PrincipalId
        if ($n -and ($n.Permanent -or $n.End -gt $s.End)) { return @{ State = 'renewed'; End = $n.End; Text = "$Who's PIM-for-Groups member assignment $how, read back: $(if ($n.Permanent) { 'permanent' } else { 'ends ' + $n.End.ToString('yyyy-MM-dd HH:mm') + 'Z' })" } }
        @{ State = 'failed'; End = $s.End; Text = "WARNING: $Who's PIM-for-Groups member assignment was $how but does not read back renewed (it still ends $($s.End.ToString('yyyy-MM-dd HH:mm'))Z) - the update goes on; the next run tries again" }
    } catch { @{ State = 'failed'; Text = "WARNING: $Who's PIM-for-Groups member assignment could not be read for its renewal: $((("$($_.Exception.Message)") -split "`n")[0]) - the update goes on" } }
}

function Get-EpsTokenRoles {
    # The application roles in the caller's OWN access token for -Resource (the 'roles' claim) - how the update job sees
    # which Graph rights its identity holds without any directory read right. $null when the token is not a readable JWT.
    param([string]$Resource = 'https://graph.microsoft.com')
    try {
        $t = "$(Get-EpsToken -Resource $Resource)"; $p = @($t -split '\.')
        if ($p.Count -lt 2) { return $null }
        $b = $p[1].Replace('-', '+').Replace('_', '/'); $b += '=' * ((4 - $b.Length % 4) % 4)
        @(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) | ConvertFrom-Json).roles)
    } catch { $null }
}

function Invoke-EpsSqlAdminGroupConverge {
    <#
      framework §4.5 SQL-ADMIN-GROUP G2 / G4 / G5, the UPDATE JOB's side (the owner: "both setup and upd"), run as
      id-eps-updater on every update run and again right before the database setup job of an update:
        - G5: the updater's own Graph roles (its token's 'roles' claim) - a missing one is REPORTED (the install grants
          it; the update job never grants itself a right);
        - G1: the group the SQL server names as its Entra admin; not role-assignable = a FINDING, never moved;
          a server admin that is not a group, or no group = said, nothing to converge (creating the group is setup's);
        - G3: id-eps-dbinit in that group (memberOf) - else the shared order (members/$ref, else PIM for Groups,
          permanent first), read back; both refused THROWS 'EPS-GROUP-ADD: ...' (the caller does not start the job);
        - G4: a time-limited assignment ending within 30 days renewed - a failed renewal is a warning only.
      Returns @{ Ok; Lines; Finding; Renewal; MissingRoles } (Ok = the membership is there or there is nothing to converge).
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [datetime]$NowUtc = [datetime]::UtcNow)
    $lines = [System.Collections.Generic.List[string]]::new()
    $n = Resolve-EpsInstallNames -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $roles = Get-EpsTokenRoles
    $missing = @()
    if ($null -eq $roles) { $lines.Add("G5: the update job's Graph roles could not be read from its token - this run could not check them") }
    else {
        $missing = @($script:EpsUpdaterGraphRoles | Where-Object { $roles -notcontains $_ })
        if ($missing.Count) { $lines.Add("WARNING G5: $($n.UpdaterIdentity) lacks $($missing -join ', ') - run the install again (it grants them; the update job never grants itself a right)") }
        else { $lines.Add("G5: $($n.UpdaterIdentity) holds $($script:EpsUpdaterGraphRoles -join ', ')") }
        if ($roles -contains 'RoleManagement.ReadWrite.Directory') { $lines.Add("WARNING G5: $($n.UpdaterIdentity) holds RoleManagement.ReadWrite.Directory, which framework §4.5 G5 does not give an updater - remove it") }
    }
    $srv = Invoke-EpsArm -Path "$rg/providers/Microsoft.Sql/servers/$($n.SqlServer)" -ApiVersion $script:EpsApi.sql -AllowNotFound
    $a = if ($srv) { $srv.properties.administrators }
    if (-not $a -or -not "$($a.sid)") { $lines.Add("no SQL server admin to converge ($(if ($srv) { 'the server names no Entra admin' } else { "no server $($n.SqlServer)" }))"); return @{ Ok = $true; Lines = @($lines); MissingRoles = $missing } }
    if ("$($a.principalType)" -notin 'Group', '') { $lines.Add("the SQL server's Entra admin is $($a.login) ($($a.principalType)), not a group - nothing to converge (making grp-eps-sql-admins the admin is a setup step)"); return @{ Ok = $true; Lines = @($lines); MissingRoles = $missing } }
    $g = Invoke-EpsGraph -Path "v1.0/groups/$($a.sid)?`$select=id,displayName,isAssignableToRole"
    $finding = $null
    if ($g.isAssignableToRole -ne $true) { $finding = "FINDING (framework §4.5 G1): $($g.displayName) is not role-assignable - replacing it with a role-assignable group is an owner decision, not done by this run"; $lines.Add($finding) }
    $mi = Invoke-EpsArm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n.DbInitIdentity)" -ApiVersion $script:EpsApi.mi -AllowNotFound
    if (-not $mi) { $lines.Add("no $($n.DbInitIdentity) yet - nothing to converge (an install run makes it)"); return @{ Ok = $true; Lines = @($lines); Finding = $finding; MissingRoles = $missing } }
    $sp = "$($mi.properties.principalId)"
    $how = Add-EpsSqlAdminMember -PrincipalId $sp -Who $n.DbInitIdentity -GroupId "$($g.id)" -By 'update'   # throws EPS-GROUP-ADD
    $lines.Add("G2/G3: $($n.DbInitIdentity) in $($g.displayName): $how")
    $rn = Update-EpsSqlAdminMemberRenewal -GroupId "$($g.id)" -PrincipalId $sp -Who $n.DbInitIdentity -NowUtc $NowUtc
    $lines.Add("G4: $($rn.Text)")
    @{ Ok = $true; Lines = @($lines); Finding = $finding; Renewal = $rn; MissingRoles = $missing }
}

# ---- framework §4.5 SQL-ADMIN-GROUP G3a: moving the SQL server's admin to a (new) group ---------------------------------
# EPS internal 2026-11-05: the admin was moved to a new role-assignable group with id-eps-dbinit in it (read back), and the
# setup job still failed 16 sign-ins in 5 minutes - its managed identity's cached token kept the OLD group claims. So: the
# members first; the admin moves only once they have been in the new group for 24 h (the time is kept in the group's
# own description, where every later run reads it); right after the move the setup job runs; if it cannot sign in, the
# admin moves BACK and is read back. Never a store without a working admin path.
$script:EpsSqlAdminMoveWaitHours = 24
$script:EpsMembersAddedTag = 'Members added'

function Get-EpsGroupMembersAddedUtc {
    # the time the replace step last added a member, from the group's description ('... Members added 2026-11-05T21:00:00Z.')
    param([string]$Description)
    if ("$Description" -match "$([regex]::Escape($script:EpsMembersAddedTag)) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)") {
        return [datetime]::ParseExact($Matches[1], "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    }
    $null
}

function Get-EpsSqlServerAdminSid {
    # the SQL server's Entra admin as its own sub-resource (where a move is written and read back)
    param([Parameter(Mandatory)][string]$ServerPath)
    $x = Invoke-EpsArm -Path "$ServerPath/administrators/ActiveDirectory" -ApiVersion $script:EpsApi.sql -AllowNotFound
    "$($x.properties.sid)"
}

function Move-EpsSqlServerAdmin {
    <#
      framework §4.5 G3a, the move itself - called only when the members have been in -To for 24 h. The admin PUT to -To,
      read back; then the database setup job starts AT ONCE: it signs in through the new group, or the admin is moved BACK
      to -Back and read back, and this THROWS 'EPS-SQLADMIN-MOVE: ...' naming both outcomes. Returns @{ State = 'moved'; Text }.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$To, [Parameter(Mandatory)]$Back)
    $n = $Ctx.Names
    $srv = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Sql/servers/$($n.SqlServer)"
    $put = { param($login, $sid, $tenant) [void](Invoke-EpsArm -Method PUT -Path "$srv/administrators/ActiveDirectory" -ApiVersion $script:EpsApi.sql -PollSeconds ($Ctx.PollSeconds ?? 10) -Body @{ properties = @{ administratorType = 'ActiveDirectory'; login = $login; sid = $sid; tenantId = $tenant } }) }
    $tenant = if ("$($Back.tenantId)") { "$($Back.tenantId)" } else { "$($Ctx.TenantId)" }
    & $put $To.Name $To.Id $tenant
    $now = Get-EpsSqlServerAdminSid -ServerPath $srv
    if ($now -ne $To.Id) { throw "EPS-SQLADMIN-MOVE: the SQL server's admin did not read back as $($To.Name) (it reads $now) - nothing else was done; the admin is still $($Back.login)" }
    try {
        $j = Invoke-EpsDbInitJob -Ctx $Ctx
        @{ State = 'moved'; Text = "the SQL server's admin is now $($To.Name) (role-assignable), read back; $($n.DbInitJob) ($($j.Execution)) signed in through it at once (framework §4.5 G3a)" }
    } catch {
        $why = (("$($_.Exception.Message)") -split "`n")[0]
        $backOk = $false; $backErr = ''
        try { & $put "$($Back.login)" "$($Back.sid)" $tenant; $backOk = ((Get-EpsSqlServerAdminSid -ServerPath $srv) -eq "$($Back.sid)") } catch { $backErr = (("$($_.Exception.Message)") -split "`n")[0] }
        throw "EPS-SQLADMIN-MOVE: the database setup job could NOT sign in through $($To.Name) right after the move ($why) - the admin was moved BACK to $($Back.login): $(if ($backOk) { 'read back, the store has its old admin path again' } else { "NOT read back$(if ($backErr) { " ($backErr)" }) - set the server's Entra admin to $($Back.login) yourself now" }). The members stay in $($To.Name); run the install with -ReplaceSqlAdminGroup again later"
    }
}

function Invoke-EpsSqlAdminGroupReplace {
    <#
      framework §4.5 G1 / G3a: the operator's STEP (install -ReplaceSqlAdminGroup) that replaces a NON-role-assignable SQL
      admin group - a run never starts it by itself (G1: a plain group is a finding, never moved by a run). Two runs:
        1. the old group renamed '<name>-old' (kept, never deleted); a new ROLE-ASSIGNABLE group with the standard name made
           (or the one an earlier run made); every member of the old group (and id-eps-dbinit) copied into it in the G3
           order, the FIRST add retried (Graph can refuse an add right after the group is made); the time the members were
           added written into the new group's description; the admin is NOT moved yet ('waiting', with the time);
        2. once that time is 24 h old: Move-EpsSqlServerAdmin (move, the setup job at once, moved back on a failed sign-in).
      -NowUtc is the test seam. Returns @{ State = none|done|refused|waiting|moved; Text }. A refusal THROWS.
    #>
    param([Parameter(Mandatory)]$Ctx, [datetime]$NowUtc = [datetime]::UtcNow)
    $n = $Ctx.Names
    $srv = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Sql/servers/$($n.SqlServer)"
    $s = Invoke-EpsArm -Path $srv -ApiVersion $script:EpsApi.sql -AllowNotFound
    $a = if ($s) { $s.properties.administrators }
    if (-not $a -or -not "$($a.sid)") { return @{ State = 'none'; Text = 'no SQL server admin to replace (a new server gets a role-assignable group when it is made)' } }
    if ("$($a.principalType)" -notin 'Group', '') { return @{ State = 'refused'; Text = "the SQL server's admin is $($a.login) ($($a.principalType)), not a group - this step replaces a group only (moving a person / application admin is your own step)" } }
    $old = Invoke-EpsGraph -Path "v1.0/groups/$($a.sid)?`$select=id,displayName,isAssignableToRole,description"
    if ($old.isAssignableToRole -eq $true) { return @{ State = 'done'; Text = "$($old.displayName) is role-assignable - nothing to replace" } }
    $name = $n.SqlAdminGroup
    # the replacement an earlier run made: role-assignable, the standard name, not the old group
    $new = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$name'&`$select=id,displayName,isAssignableToRole,description" -All | Where-Object { "$($_.id)" -ne "$($old.id)" -and $_.isAssignableToRole -eq $true })[0]
    $oldName = "$($old.displayName)"
    if ($oldName -eq $name) {
        $oldName = "$name-old"
        [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/groups/$($old.id)" -Body @{ displayName = $oldName; description = "Entra Policy Suite: the previous SQL server admin group (not role-assignable), replaced by a role-assignable $name - kept, never deleted" })
    }
    if (-not $new) {
        $new = Invoke-EpsGraph -Method POST -Path 'v1.0/groups' -Body @{ displayName = $name; mailEnabled = $false; mailNickname = "$name-ra"; securityEnabled = $true; isAssignableToRole = $true
            description = 'Entra Policy Suite: the Azure SQL server admin (role-assignable). Members: the database setup job identity (and support, just in time).' }
        [void](Invoke-EpsWithRetry { Invoke-EpsGraph -Path "v1.0/groups/$($new.id)?`$select=id" })
    }
    # the members: everyone in the old group, and id-eps-dbinit whatever the old group holds
    $mem = @(Invoke-EpsGraph -Path "v1.0/groups/$($old.id)/members?`$select=id,displayName" -All | ForEach-Object {
        $t = "$($_.'@odata.type')"; @{ Id = "$($_.id)"; Who = $(if ("$($_.displayName)") { "$($_.displayName)" } else { "$($_.id)" }); Collection = $(if ($t -like '*user') { 'users' } elseif ($t -like '*group') { 'groups' } else { 'servicePrincipals' }) } })
    $dbi = "$($Ctx.Identities.DbInitIdentity.PrincipalId)"
    if ($dbi -and -not @($mem | Where-Object { $_.Id -eq $dbi }).Count) { $mem += @{ Id = $dbi; Who = $n.DbInitIdentity; Collection = 'servicePrincipals' } }
    $added = 0; $first = $true
    foreach ($m in $mem) {
        $try = 0
        while ($true) {
            try { $how = Add-EpsSqlAdminMember -PrincipalId $m.Id -Who $m.Who -GroupId "$($new.id)" -By 'setup' -Collection $m.Collection; break }
            catch {
                $e = "$($_.Exception.Message)"
                # the first add right after the group is made can be refused while Graph has not seen the group everywhere
                if ($first -and $try -lt 4 -and $e -match '(?i)not ?found|does not exist|Request_ResourceNotFound|404') { $try++; Start-Sleep -Seconds $(if ($null -ne $script:EpsGraphReadBackSeconds) { $script:EpsGraphReadBackSeconds } else { 15 }); continue }
                throw "EPS-SQLADMIN-REPLACE: $($m.Who) could not be put into the new group $name ($(($e -split "`n")[0])) - the server's admin was NOT moved; it is still $($a.login)"
            }
        }
        $first = $false
        if ($how -notmatch '^already a member') { $added++ }
    }
    $since = Get-EpsGroupMembersAddedUtc -Description "$($new.description)"
    if ($added -or -not $since) {
        $since = $NowUtc
        [void](Invoke-EpsGraph -Method PATCH -Path "v1.0/groups/$($new.id)" -Body @{ description = "Entra Policy Suite: the Azure SQL server admin (role-assignable). $($script:EpsMembersAddedTag) $($since.ToString('yyyy-MM-ddTHH:mm:ssZ'))." })
    }
    $ready = $since.AddHours($script:EpsSqlAdminMoveWaitHours)
    if ($NowUtc -lt $ready) {
        return @{ State = 'waiting'; Text = "the members are in the new role-assignable group $name ($(@($mem).Count), $added added now; the old group is '$oldName', kept); the server's admin moves after $($ready.ToString('yyyy-MM-dd HH:mm'))Z - a managed identity's token keeps its old groups up to $($script:EpsSqlAdminMoveWaitHours) h (framework §4.5 G3a): run the install with -ReplaceSqlAdminGroup again after that time" }
    }
    $mv = Move-EpsSqlServerAdmin -Ctx $Ctx -To @{ Id = "$($new.id)"; Name = $name } -Back $a
    $Ctx.SqlAdminGroup = @{ ObjectId = "$($new.id)"; Name = $name; RoleAssignable = $true }
    $mv.Text = "$($mv.Text); the old group '$oldName' is kept"
    $mv
}

function Get-EpsSqlAdminReplacePlan {
    # -WhatIf for the replace step: READS only, says what the run would do (framework §4.5 G1 / G3a)
    param([Parameter(Mandatory)]$Ctx, [datetime]$NowUtc = [datetime]::UtcNow)
    $n = $Ctx.Names
    $srv = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Sql/servers/$($n.SqlServer)"
    $s = Invoke-EpsArm -Path $srv -ApiVersion $script:EpsApi.sql -AllowNotFound
    $a = if ($s) { $s.properties.administrators }
    if (-not $a -or -not "$($a.sid)") { return 'replace the SQL admin group: no server admin yet - nothing to replace' }
    if ("$($a.principalType)" -notin 'Group', '') { return "replace the SQL admin group: the admin is $($a.login) ($($a.principalType)), not a group - not this step" }
    $old = Invoke-EpsGraph -Path "v1.0/groups/$($a.sid)?`$select=id,displayName,isAssignableToRole"
    if ($old.isAssignableToRole -eq $true) { return "replace the SQL admin group: $($old.displayName) is role-assignable - nothing to replace" }
    $new = @(Invoke-EpsGraph -Path "v1.0/groups?`$filter=displayName eq '$($n.SqlAdminGroup)'&`$select=id,isAssignableToRole,description" -All | Where-Object { "$($_.id)" -ne "$($old.id)" -and $_.isAssignableToRole -eq $true })[0]
    $since = if ($new) { Get-EpsGroupMembersAddedUtc -Description "$($new.description)" }
    if ($since -and $NowUtc -ge $since.AddHours($script:EpsSqlAdminMoveWaitHours)) { return "replace the SQL admin group: MOVE the server's admin from $($old.displayName) to $($n.SqlAdminGroup) (members in it since $($since.ToString('yyyy-MM-dd HH:mm'))Z), start $($n.DbInitJob) at once, move back if it cannot sign in (framework §4.5 G3a)" }
    "replace the SQL admin group: rename $($old.displayName) to '$($old.displayName)-old' (kept), $(if ($new) { "use the role-assignable $($n.SqlAdminGroup) an earlier run made" } else { "make a role-assignable $($n.SqlAdminGroup)" }), copy the members; the admin moves on a run 24 h after the members are in (framework §4.5 G3a)"
}

function Initialize-EpsSqlAdminGroup {
    <#
      SEC-03 / SEC-08 row 5: the SQL server's Entra admin is a GROUP and the job's identity is in it. Which group:
        - an EXISTING server keeps its admin (a re-run never takes the customer's admin away): a group admin gets the
          job's identity added; a person / application admin cannot hold a member, so the database steps run as the
          signed-in person, said plainly (to stop that: make grp-eps-sql-admins the admin);
        - a new server: the customer's group (-SqlAdminGroupId), else grp-eps-sql-admins (found, else created).
      A group it cannot find or make returns @{ Use = $false; Why } (the install goes on the old way); the job's identity
      refused by BOTH members/$ref and PIM-for-Groups (framework §4.5 point 5) THROWS 'EPS-GROUP-ADD: ...' - the step
      fails, both errors named, and nothing that needs the membership (the database setup job) starts.
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
                $g = try { Invoke-EpsGraph -Path "v1.0/groups/$($a.sid)?`$select=id,displayName,isAssignableToRole" } catch { $null }
                if (-not $g) { $res = @{ Use = $false; Why = "the SQL server's Entra admin $($a.login) is not a group - the database steps run as you" } }
                else {
                    $how = Add-EpsDbInitToGroup -Ctx $Ctx -GroupId "$($g.id)"
                    $Ctx.SqlAdminGroup = @{ ObjectId = "$($g.id)"; Name = "$($g.displayName)" }
                    # framework §4.5 point 1 (owner 2026-11-05 "i propose that it is role assign grp" / "i agree. safer"): an
                    # existing group that is NOT role-assignable is REPORTED, never moved here - moving it is an owner decision
                    $fnd = if ($g.isAssignableToRole -ne $true) { "; FINDING (framework §4.5 point 1): $($g.displayName) is not role-assignable - any Groups / User Administrator or its owner could change who administers the database; replacing it with a role-assignable group is an owner decision, not done by this run" } else { '' }
                    $res = @{ Use = $true; Why = "$($n.DbInitIdentity) in the server's admin group $($g.displayName) ($how)$fnd" }
                }
            }
        } else {
            $grp = if ($Ctx.SqlAdminGroup -and $Ctx.SqlAdminGroup.ObjectId) { $Ctx.SqlAdminGroup } else { Find-EpsSqlAdminGroup -Ctx $Ctx }
            if (-not $grp -and -not $NoCreate) {
                # framework §4.5 point 1 (owner 2026-11-05 "i propose that it is role assign grp" / "i agree. safer"): a
                # product's SQL admin group IS role-assignable - only a Privileged Role / Global Administrator (or
                # RoleManagement.ReadWrite.Directory) can change its members, so a Groups / User Administrator cannot take
                # over the database. Said explicitly, never left to a default. Adding a member then needs that right; the
                # §4.5 point 5 order names it when refused.
                $c = Invoke-EpsGraph -Method POST -Path 'v1.0/groups' -Body @{ displayName = $n.SqlAdminGroup; mailEnabled = $false; mailNickname = $n.SqlAdminGroup; securityEnabled = $true; isAssignableToRole = $true
                    description = 'Entra Policy Suite: the Azure SQL server admin. Members: the database setup job identity (and support, just in time).' }
                $grp = @{ ObjectId = "$($c.id)"; Name = "$($c.displayName)"; RoleAssignable = $true }
                [void](Invoke-EpsWithRetry { Invoke-EpsGraph -Path "v1.0/groups/$($grp.ObjectId)?`$select=id" })
            }
            if (-not $grp) { $res = @{ Use = $false; Why = "no $($n.SqlAdminGroup) group" } }
            else {
                $how = Add-EpsDbInitToGroup -Ctx $Ctx -GroupId $grp.ObjectId
                $Ctx.SqlAdminGroup = $grp
                $fnd = if ($grp.ContainsKey('RoleAssignable') -and $grp.RoleAssignable -ne $true) { "; FINDING (framework §4.5 point 1): $($grp.Name) is not role-assignable - replacing it with a role-assignable group is an owner decision, not done by this run" } else { '' }
                $res = @{ Use = $true; Why = "$($n.DbInitIdentity) in $($grp.Name) ($how) - the new server's admin$fnd" }
            }
        }
    } catch {
        # framework §4.5 point 5: the job's identity could not be put into the group by setup - stop here; the database
        # steps never fall back to running as the signed-in person for this (SEC-08)
        if ("$($_.Exception.Message)" -like 'EPS-GROUP-ADD:*') { throw }
        $res = @{ Use = $false; Why = "the SQL admin group could not be set up ($($_.Exception.Message)) - the database steps run as you; the next run tries again" }
    }
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
    param([Parameter(Mandatory)]$Ctx, $SuperAdmin, [string[]]$Drop = @(), [string]$FrontVersion, [switch]$UseExisting, [System.Collections.IDictionary]$Settings, [string]$By, [string]$Worker, $SupportSeed,
          # DBINIT-GRANTS-ONLY (framework §8.18): 'grants' = only roles, grants and users - may run beside a pipeline run
          [ValidateSet('', 'all', 'grants')][string]$Steps = '')
    $n = $Ctx.Names; $rg = "/subscriptions/$($Ctx.SubscriptionId)/resourceGroups/$($n.ResourceGroup)"
    # -UseExisting: start the job the install made, as it is (a setup script: the person may start it, nothing else)
    if ($UseExisting) { $j = @{ Name = $n.DbInitJob } } else {
    $gl = Get-EpsGrantList -SolutionRoot $Ctx.SolutionRoot
    $j = Get-EpsDbInitJobBody -Ctx $Ctx -Image "$($n.Registry).azurecr.io/$($n.Image):$($Ctx.Version)" -GrantList $gl
    [void](Invoke-EpsArm -Method PUT -Path "$rg/providers/Microsoft.App/jobs/$($j.Name)" -ApiVersion $script:EpsApi.acajob -Body $j.Body) }
    $env = @{}
    if ($SuperAdmin) { $env.EPS_DBINIT_SUPERADMIN = "$($SuperAdmin.Upn)|$($SuperAdmin.ObjectId)" }
    if (@($Drop).Count) { $env.EPS_DBINIT_DROP = (@($Drop) -join ',') }
    if ($FrontVersion) { $env.EPS_DBINIT_FRONT = $FrontVersion }
    if ($Worker) { $env.EPS_DBINIT_WORKER = $Worker }
    if ($Steps) { $env.EPS_DBINIT_STEPS = $Steps }
    if ($SupportSeed -and $SupportSeed.AppId) { $env.EPS_DBINIT_SUPPORT = "$($SupportSeed.AppId)|$($SupportSeed.Level)" }
    if ($Settings -and $Settings.Count) { $env.EPS_DBINIT_SETTINGS = ($Settings | ConvertTo-Json -Compress -Depth 5); if ($By) { $env.EPS_DBINIT_BY = $By } }
    $s = Start-EpsAcaJob -SubscriptionId $Ctx.SubscriptionId -ResourceGroup $n.ResourceGroup -Name $j.Name -Env $env -Waits @(0, 15, 30, 60)
    if (-not $s.Ok) { throw "the database setup job $($j.Name) could not be started: $($s.Reason)" }
    $w = Wait-EpsAcaJobExecution -Ctx $Ctx -Job $j.Name -Execution $s.Execution -PollSeconds ($Ctx.PollSeconds ?? 15)
    if ($w.Status -ne 'Succeeded') { throw "the database setup job ($($s.Execution)) ended '$($w.Status)' after $($w.Seconds) s - its lines are in $($n.Logs) (ContainerAppConsoleLogs_CL, ContainerJobName_s = '$($j.Name)'); fix the cause and run the install again" }
    @{ Execution = $s.Execution; Seconds = $w.Seconds }
}
