# Entra Policy Suite -- support access in the database (OPEN-01; framework SUPPORT ACCESS, owner 2026-11-04: "none,
# read, troubleshoot/setup", the customer sets it in the Invardia customer portal). The job caj-eps-support runs every
# 5 minutes as the database setup identity id-eps-dbinit (the only member of the SQL admin group the install makes) and:
#   1. asks Invardia ITSELF for this install's consent (GET /api/support/consent, x-invardia-install-key) - never from
#      anything the engine wrote (Invardia's guard: what runs as the engine must not be able to raise support access);
#      unreachable = the last level it stored keeps applying (and an admin window still ends at its time);
#   2. converges ONE contained database user for the Support app (WITH SID = its client id), named invardia-support:
#        none          -> no user (dropped)
#        read          -> the user in eps_support_read (SELECT on schema eps, nothing else)
#        troubleshoot  -> read, plus db_owner ONLY while Invardia reports an open support session for it, at most 8 h
#                         ahead; dropped from db_owner when the session closes or its time passes
#   3. reads the result back, writes eps.SupportAccess (no product role has any grant on it) and audits every change.
# Dot-source EPS-SqlStore, EPS-Install (ConvertTo-EpsSqlSid), EPS-Audit and EPS-Uplink (Get-EpsUplinkKey) first.

Set-StrictMode -Off
$script:EpsSupportUser = 'invardia-support'
$script:EpsSupportRole = 'eps_support_read'
$script:EpsSupportMaxHours = 8

function Get-EpsSupportConsentFromInvardia {
    <#
      GET <base>/api/support/consent with the install key -> { environmentId, product, supportConsent: { level, appId? },
      support?: { state, maxUntil, ticketNumber, openedBy } }. Returns @{ Ok; Level; AppId; Session; Reason } - Level:
      setup | troubleshoot -> troubleshoot, read -> read, anything else -> none; Session only for an OPEN session with a
      valid maxUntil. Never throws; the key is never in Reason.
    #>
    param([AllowEmptyString()][string]$Key, [scriptblock]$Http, [string]$BaseUrl = 'https://invardia.com', [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($r) @{ Ok = $false; Level = ''; AppId = ''; Session = $null; Reason = $r } }
    if ("$Key".Trim() -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return (& $no 'no install key') }
    $url = "$("$BaseUrl".TrimEnd('/'))/api/support/consent"
    $h = @{ 'X-Invardia-Install-Key' = "$Key".Trim(); Accept = 'application/json' }
    $r = try { if ($Http) { & $Http 'GET' $url $h } else { $w = Invoke-WebRequest -Uri $url -Headers $h -TimeoutSec 20 -UseBasicParsing -SkipHttpErrorCheck; @{ Status = [int]$w.StatusCode; Body = "$($w.Content)" } } } catch { return (& $no "not reachable: $((("$($_.Exception.Message)") -split "`n")[0] -replace [regex]::Escape("$Key".Trim()), '***')") }
    if ([int]$r.Status -ne 200) { return (& $no "HTTP $([int]$r.Status)") }
    $b = try { "$($r.Body)" | ConvertFrom-Json -Depth 10 } catch { $null }
    if (-not $b -or -not $b.supportConsent) { return (& $no 'the answer carries no supportConsent') }
    if ("$($b.product)" -and "$($b.product)".ToLowerInvariant() -ne 'entrapolicysuite') { return (& $no "the answer is for another product ($($b.product))") }
    $l = "$($b.supportConsent.level)".Trim().ToLowerInvariant()
    $level = if ($l -in 'troubleshoot', 'setup') { 'troubleshoot' } elseif ($l -eq 'read') { 'read' } else { 'none' }
    $app = "$($b.supportConsent.appId)".Trim().ToLowerInvariant(); if ($app -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $app = '' }
    $sess = $null
    if ($b.support -and "$($b.support.state)".ToLowerInvariant() -eq 'open') {
        $mu = $b.support.maxUntil
        $u = if ($mu -is [datetime]) { if ($mu.Kind -eq 'Local') { $mu.ToUniversalTime() } else { [datetime]::SpecifyKind($mu, 'Utc') } } else { try { [datetime]::Parse("$mu", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } }
        if ($u) { $sess = @{ Until = [datetime]::SpecifyKind($u, 'Utc'); Ticket = "$($b.support.ticketNumber)"; OpenedBy = "$($b.support.openedBy)" } }
    }
    @{ Ok = $true; Level = $level; AppId = $app; Session = $sess; Reason = "HTTP 200: $level" }
}

function Get-EpsSupportAccessPlan {
    <#
      PURE. What to do. -Level / -AppId: the consent to apply; -SessionUntil: an open session's end ($null = none);
      -Current: @{ Exists; Sid; InRead; InOwner } of the user today. Returns @{ Want (none | read | admin); Sql (statements,
      in order); Lines (plain words); AdminUntil }. Admin only with troubleshoot AND an open session that ends in the future
      and at most 8 h ahead (a longer one is refused, said); no Support app id = no user at all.
    #>
    param([string]$Level, [string]$AppId, [AllowNull()]$SessionUntil, [Parameter(Mandatory)]$Current, [datetime]$NowUtc = [datetime]::UtcNow)
    $u = $script:EpsSupportUser; $role = $script:EpsSupportRole
    $lines = [System.Collections.Generic.List[string]]::new(); $sql = [System.Collections.Generic.List[string]]::new()
    $want = if ($Level -in 'read', 'troubleshoot' -and $AppId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { 'read' } else { 'none' }
    if ($Level -in 'read', 'troubleshoot' -and $want -eq 'none') { $lines.Add("the consent is $Level but no Support app id is known: no user") }
    $adminUntil = $null
    if ($want -eq 'read' -and $Level -eq 'troubleshoot' -and $SessionUntil) {
        $su = [datetime]$SessionUntil
        if ($su -le $NowUtc) { $lines.Add("the support session ended at $($su.ToString('u')): no admin") }
        elseif ($su -gt $NowUtc.AddHours($script:EpsSupportMaxHours)) { $lines.Add("the support session asks for admin until $($su.ToString('u')), more than $($script:EpsSupportMaxHours) h ahead: refused") }
        else { $want = 'admin'; $adminUntil = $su }
    }
    if ($want -eq 'none') {
        if ($Current.InOwner) { $sql.Add("ALTER ROLE [db_owner] DROP MEMBER [$u];") }
        if ($Current.Exists) { $sql.Add("DROP USER [$u];"); $lines.Add("$u removed (level $(if ($Level) { $Level } else { 'none' }))") }
        return @{ Want = 'none'; Sql = @($sql); Lines = @($lines); AdminUntil = $null }
    }
    $sid = ConvertTo-EpsSqlSid $AppId
    $sql.Add("IF DATABASE_PRINCIPAL_ID(N'$role') IS NULL CREATE ROLE [$role];")
    $sql.Add("GRANT SELECT ON SCHEMA::eps TO [$role];")
    if ($Current.Exists -and "$($Current.Sid)".ToUpperInvariant() -ne $sid.ToUpperInvariant()) { if ($Current.InOwner) { $sql.Add("ALTER ROLE [db_owner] DROP MEMBER [$u];") }; $sql.Add("DROP USER [$u];"); $lines.Add("$u belonged to another Support app: replaced"); $Current = @{ Exists = $false } }
    if (-not $Current.Exists) { $sql.Add("CREATE USER [$u] WITH SID = $sid, TYPE = E;"); $lines.Add("$u created for the Support app $AppId") }
    if (-not $Current.InRead) { $sql.Add("ALTER ROLE [$role] ADD MEMBER [$u];"); $lines.Add("$u can read (role $role)") }
    if ($want -eq 'admin' -and -not $Current.InOwner) { $sql.Add("ALTER ROLE [db_owner] ADD MEMBER [$u];"); $lines.Add("$u is db_owner until $($adminUntil.ToString('u')) (an open support session)") }
    if ($want -ne 'admin' -and $Current.InOwner) { $sql.Add("ALTER ROLE [db_owner] DROP MEMBER [$u];"); $lines.Add("$u is no longer db_owner") }
    @{ Want = $want; Sql = @($sql); Lines = @($lines); AdminUntil = $adminUntil }
}

$script:EpsSupportCurrentSql = @"
SELECT CONVERT(VARCHAR(100), dp.sid, 1) AS Sid, IS_ROLEMEMBER(N'$script:EpsSupportRole', dp.name) AS InRead, IS_ROLEMEMBER(N'db_owner', dp.name) AS InOwner
FROM sys.database_principals dp WHERE dp.name = N'$script:EpsSupportUser'
"@

function Invoke-EpsSupportAccess {
    <#
      The job's run. Returns the exit code (0 = applied and read back, 1 = failed). -Http / -Key: test seams.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][scriptblock]$Log, [scriptblock]$Http, [AllowNull()][object]$Key = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $readCur = { $r = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query $script:EpsSupportCurrentSql)[0]; if ($r) { @{ Exists = $true; Sid = "$($r.Sid)"; InRead = ([int]"0$($r.InRead)" -eq 1); InOwner = ([int]"0$($r.InOwner)" -eq 1) } } else { @{ Exists = $false; Sid = ''; InRead = $false; InOwner = $false } } }
    try {
        $stored = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Level, AppId, SessionUntil FROM eps.SupportAccess WHERE Id = 1')[0]
        if ($null -eq $Key) { $k = Get-EpsUplinkKey; $Key = "$($k.Key)" }
        $c = Get-EpsSupportConsentFromInvardia -Key "$Key" -Http $Http -NowUtc $NowUtc
        if ($c.Ok) { $level = $c.Level; $app = $c.AppId; $until = if ($c.Session) { $c.Session.Until } else { $null }; & $Log "consent from Invardia: $level$(if ($app) { " (Support app $app)" })$(if ($until) { "; an open session until $($until.ToString('u'))" })" }
        elseif ($stored) { $level = "$($stored.Level)"; $app = "$($stored.AppId)"; $until = if ($stored.SessionUntil -is [datetime]) { [datetime]::SpecifyKind($stored.SessionUntil, 'Utc') } else { $null }; & $Log "Invardia not read ($($c.Reason)): the last level ($level) keeps applying" }
        else { $level = 'none'; $app = ''; $until = $null; & $Log "Invardia not read ($($c.Reason)) and no level was ever stored: none" }
        $cur = & $readCur
        $p = Get-EpsSupportAccessPlan -Level $level -AppId $app -SessionUntil $until -Current $cur -NowUtc $NowUtc
        foreach ($s in $p.Sql) { [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query $s) }
        $after = & $readCur
        $ok = switch ($p.Want) { 'none' { -not $after.Exists } 'read' { $after.Exists -and $after.InRead -and -not $after.InOwner } 'admin' { $after.Exists -and $after.InRead -and $after.InOwner } }
        $applied = "$($p.Want)$(if ($p.AdminUntil) { " until $($p.AdminUntil.ToString('u'))" }): $(if ($p.Lines.Count) { $p.Lines -join '; ' } else { 'no change' })"
        if ($applied.Length -gt 400) { $applied = $applied.Substring(0, 400) }
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ l = $level; a = $(if ($app) { $app } else { $null }); u = $(if ($until -and $p.Want -eq 'admin') { $until } else { $null }); p = $applied; r = [bool]($after.Exists -and $after.InRead); o = [bool]($after.Exists -and $after.InOwner) } -Query @'
MERGE eps.SupportAccess AS t USING (SELECT 1 AS Id) AS s ON t.Id = s.Id
WHEN MATCHED THEN UPDATE SET Level = @l, AppId = @a, SessionUntil = @u, Applied = @p, ReadUser = @r, AdminNow = @o, CheckedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Id, Level, AppId, SessionUntil, Applied, ReadUser, AdminNow) VALUES (1, @l, @a, @u, @p, @r, @o);
'@ | Out-Null
        if ($p.Sql.Count -and @($p.Sql | Where-Object { $_ -notlike 'IF DATABASE_PRINCIPAL_ID*' -and $_ -notlike 'GRANT SELECT ON SCHEMA*' }).Count) {
            [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'support.access.change' -Actor 'caj-eps-support (consent from Invardia)' -ActorSource 'job' -Target "DatabaseUser|$($script:EpsSupportUser)" `
                -Reason "framework SUPPORT ACCESS: level $level$(if ($c.Ok) { '' } else { ' (the last stored level)' })" -Outcome $(if ($ok) { 'ok' } else { 'error' }) -Before @{ exists = $cur.Exists; read = $cur.InRead; owner = $cur.InOwner } -After @{ exists = $after.Exists; read = $after.InRead; owner = $after.InOwner })
        }
        & $Log "applied: $applied; read back $(if ($ok) { 'ok' } else { 'NOT as wanted' })"
        return $(if ($ok) { 0 } else { 1 })
    } catch { & $Log "failed: $($_.Exception.Message)"; return 1 }
}
