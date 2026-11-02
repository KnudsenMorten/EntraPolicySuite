# EntraPolicySuite -- the SQL store (DESIGN §3). Raw ADO.NET, no PowerShell module (framework NO-AZ).
# Auth, in this order:
#   1. a connection string with its own auth (Integrated Security / User ID) - the test VM's SQL Server, a dev box;
#   2. $global:EPS_SqlAccessToken - a token the caller minted (the v1 import from the operator's browser sign-in);
#   3. the managed identity (Container Apps: IDENTITY_ENDPOINT + IDENTITY_HEADER) - the product itself.
# Lessons copied from PIM (PIM-SqlStore.ps1): the token is cached and the SAME string instance is assigned to every
# connection (ADO.NET pools per token object - a new string per connection = a new pool, and Azure SQL's session limit),
# and an explicitly given token is never silently replaced by a different identity.

Set-StrictMode -Off

function Resolve-EpsSqlClientType {
    if ($script:EpsSqlClientType) { return $script:EpsSqlClientType }
    $t = ('Microsoft.Data.SqlClient.SqlConnection' -as [type])
    if (-not $t) { $t = ('System.Data.SqlClient.SqlConnection' -as [type]) }
    if (-not $t -and $env:EPS_SQLCLIENT_DLL -and (Test-Path -LiteralPath $env:EPS_SQLCLIENT_DLL)) {
        # the driver's dependencies (Microsoft.Identity.Client, Azure.Core, ...) load on demand from its own folder (PIM's
        # resolver): without it the first connection fails with "Could not load file or assembly" inside the container
        $script:EpsSqlDllDir = Split-Path -Parent $env:EPS_SQLCLIENT_DLL
        [System.AppDomain]::CurrentDomain.add_AssemblyResolve([System.ResolveEventHandler]{
            param($s, $e)
            $cand = Join-Path $script:EpsSqlDllDir ((($e.Name -split ',')[0]) + '.dll')
            if (Test-Path -LiteralPath $cand) { return [System.Reflection.Assembly]::LoadFrom($cand) }
            $null
        })
        Add-Type -Path $env:EPS_SQLCLIENT_DLL
        $t = ('Microsoft.Data.SqlClient.SqlConnection' -as [type])
    }
    if (-not $t) { throw 'No SQL client: Windows has System.Data.SqlClient in-box; the container image sets EPS_SQLCLIENT_DLL to its bundled Microsoft.Data.SqlClient.dll.' }
    $script:EpsSqlClientType = $t
    $t
}

function Get-EpsManagedIdentityToken {
    # A token for a resource from the managed identity. Container Apps / App Service form first, then IMDS (an Azure VM,
    # the hybrid worker). $env:EPS_ManagedIdentityClientId picks a user-assigned identity.
    param([Parameter(Mandatory)][string]$Resource)
    $cid = $env:EPS_ManagedIdentityClientId
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
        $u = "$($env:IDENTITY_ENDPOINT)?api-version=2019-08-01&resource=$([uri]::EscapeDataString($Resource))"
        if ($cid) { $u += "&client_id=$cid" }
        return (Invoke-RestMethod -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -TimeoutSec 30).access_token
    }
    if ($env:IDENTITY_ENDPOINT) {
        # an Azure Arc-enabled server (the on-premises hybrid worker): the agent answers 401 with the path of a key file
        # only local Administrators / 'Hybrid agent extension applications' may read; the second call sends its content
        $u = "$($env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=$([uri]::EscapeDataString($Resource))"
        $r = Invoke-WebRequest -Uri $u -Headers @{ Metadata = 'true' } -SkipHttpErrorCheck -TimeoutSec 30
        if ([int]$r.StatusCode -eq 200) { return ($r.Content | ConvertFrom-Json).access_token }
        $challenge = [string](@($r.Headers['WWW-Authenticate'])[0])
        if ($challenge -notmatch 'Basic realm=(.+)$') { throw "the Arc identity endpoint answered $($r.StatusCode) without a key challenge" }
        $key = Get-Content -LiteralPath $Matches[1].Trim() -Raw
        return (Invoke-RestMethod -Uri $u -Headers @{ Metadata = 'true'; Authorization = "Basic $key" } -TimeoutSec 30).access_token
    }
    $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($Resource))"
    if ($cid) { $u += "&client_id=$cid" }
    (Invoke-RestMethod -Uri $u -Headers @{ Metadata = 'true' } -TimeoutSec 10).access_token
}

function New-EpsSqlConnection {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $type = Resolve-EpsSqlClientType
    $c = $type::new($ConnectionString)
    if ($ConnectionString -match '(?i)Integrated\s*Security|Trusted_Connection|User\s*ID|UID\s*=|Authentication\s*=') { return $c }
    if ($global:EPS_SqlAccessToken) { $c.AccessToken = $global:EPS_SqlAccessToken; return $c }
    if (-not ($script:EpsSqlToken -and $script:EpsSqlToken.Expires -gt [datetime]::UtcNow)) {
        $script:EpsSqlToken = @{ Token = (Get-EpsManagedIdentityToken -Resource 'https://database.windows.net/'); Expires = [datetime]::UtcNow.AddMinutes(45) }
    }
    $c.AccessToken = $script:EpsSqlToken.Token    # the cached instance itself - never "$token"
    $c
}

function Open-EpsSqlConnection {
    # Opens a connection. TESTS ONLY: $global:EPS_TestRunAs = a database user makes every connection the product opens run
    # as that user (EXECUTE AS USER), so the suite runs each component's real SQL - bulk copies too - under its own
    # least-privilege role (found live 2026-10-31: the VM's tests run as sysadmin and missed a missing right). Never set in
    # the product; it would need IMPERSONATE, which no product identity has.
    param([Parameter(Mandatory)]$Connection)
    $Connection.Open()
    if ($global:EPS_TestRunAs) {
        $c = $Connection.CreateCommand(); $c.CommandText = 'EXECUTE AS USER = @u'
        [void]$c.Parameters.AddWithValue('@u', [string]$global:EPS_TestRunAs); [void]$c.ExecuteNonQuery()
    }
}

function Invoke-EpsSql {
    # One statement with named parameters (@Name). -Scalar returns the first column of the first row; otherwise the
    # rows as objects. -Transaction runs it on an open transaction's connection.
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Query, [hashtable]$Parameters = @{}, [switch]$Scalar, [switch]$NonQuery, $Transaction, [int]$Timeout = 120)
    $own = -not $Transaction
    $conn = if ($own) { New-EpsSqlConnection -ConnectionString $ConnectionString } else { $Transaction.Connection }
    try {
        if ($own) { Open-EpsSqlConnection $conn }
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = $Timeout
        if ($Transaction) { $cmd.Transaction = $Transaction }
        foreach ($k in $Parameters.Keys) {
            $v = $Parameters[$k]
            $prm = $cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $v) { [DBNull]::Value } else { $v }))
            # a DateTime goes as datetime2: AddWithValue picks datetime (1/300 s), and an equality check on a datetime2
            # column (the scheduler's claim) would then never match the value it just read
            if ($v -is [datetime]) { $prm.SqlDbType = [System.Data.SqlDbType]::DateTime2 }
        }
        if ($NonQuery) { return $cmd.ExecuteNonQuery() }
        if ($Scalar) { $r = $cmd.ExecuteScalar(); if ($r -is [DBNull]) { return $null }; return $r }
        $rd = $cmd.ExecuteReader()
        try {
            while ($rd.Read()) {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $rd.FieldCount; $i++) { $row[$rd.GetName($i)] = if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) } }
                [pscustomobject]$row
            }
        } finally { $rd.Dispose() }
    } finally { if ($own) { $conn.Dispose() } }
}

function Install-EpsSchema {
    # Applies sql/eps-schema.sql (idempotent, additive). Batches are split on GO lines, should the file ever get them.
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$SchemaPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'sql\eps-schema.sql'))
    $sql = Get-Content -LiteralPath $SchemaPath -Raw
    foreach ($batch in ($sql -split '(?im)^\s*GO\s*$')) {
        if ($batch.Trim()) { [void](Invoke-EpsSql -ConnectionString $ConnectionString -Query $batch -NonQuery) }
    }
    Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT MAX(Version) FROM eps.SchemaVersion' -Scalar
}

function Write-EpsV1Import {
    <#
    .SYNOPSIS
        Writes a Read-EpsV1Data model to SQL in ONE transaction. A re-import replaces the previous import's rules
        (Source = 'v1-import') and leaves rules made in the GUI alone; tag types, settings and the CA inputs are upserted.
        Every entity written is journaled in eps.ConfigChange (Action = Import), so the import can be seen and undone.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Model, [string]$Actor = 'v1-import')
    $conn = New-EpsSqlConnection -ConnectionString $ConnectionString
    Open-EpsSqlConnection $conn
    $tx = $conn.BeginTransaction()
    $n = @{}
    $q = { param($sql, $p) Invoke-EpsSql -Transaction $tx -Query $sql -Parameters $p -NonQuery }
    try {
        foreach ($t in $Model.TagTypes) {
            & $q @'
MERGE eps.TagType AS d USING (SELECT @ObjectType AS ObjectType, @Name AS Name) AS s ON d.ObjectType = s.ObjectType AND d.Name = s.Name
WHEN MATCHED THEN UPDATE SET Attribute = @Attribute, ValueMode = @ValueMode, AllowMultiple = @AllowMultiple, FallbackAD = @FallbackAD,
     FallbackCloud = @FallbackCloud, FallbackFromProperty = @FallbackFromProperty, Description = @Description, UpdatedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, ObjectType, Description, Attribute, ValueMode, AllowMultiple, FallbackAD, FallbackCloud, FallbackFromProperty, Enabled, Shipped)
     VALUES (@Name, @ObjectType, @Description, @Attribute, @ValueMode, @AllowMultiple, @FallbackAD, @FallbackCloud, @FallbackFromProperty, 1, @Shipped);
'@ @{ Name = $t.Name; ObjectType = $t.ObjectType; Description = $t.Description; Attribute = $t.Attribute; ValueMode = $t.ValueMode
     AllowMultiple = [bool]$t.AllowMultiple; FallbackAD = $t.FallbackAD; FallbackCloud = $t.FallbackCloud; FallbackFromProperty = $t.FallbackFromProperty; Shipped = [bool]$t.Shipped } | Out-Null
        }
        $n.TagTypes = @($Model.TagTypes).Count
        foreach ($v in $Model.TagValues) {
            & $q "IF NOT EXISTS (SELECT 1 FROM eps.TagValue WHERE ObjectType = @o AND TagType = @t AND Value = @v) INSERT INTO eps.TagValue (ObjectType, TagType, Value, IsPattern) VALUES (@o, @t, @v, @p)" @{ o = $v.ObjectType; t = $v.TagType; v = $v.Value; p = [bool]$v.IsPattern } | Out-Null
        }
        $n.TagValues = @($Model.TagValues).Count

        & $q "DELETE FROM eps.UserTagRule WHERE Source = 'v1-import'" @{} | Out-Null
        & $q "DELETE FROM eps.DeviceTagRule WHERE Source = 'v1-import'" @{} | Out-Null
        foreach ($r in $Model.UserRules) {
            $id = Invoke-EpsSql -Transaction $tx -Scalar -Query "INSERT INTO eps.UserTagRule ([Order], Persona, TagType, TagValueAD, TagValueCloud, Source, V1ConditionGroup, Notes) OUTPUT INSERTED.RuleId VALUES (@o, @p, @t, @ad, @c, 'v1-import', @g, @n)" -Parameters @{ o = $r.Order; p = $r.Persona; t = $r.TagType; ad = $r.TagValueAD; c = $r.TagValueCloud; g = $r.V1ConditionGroup; n = "v1: $(@($r.V1Rows) -join ', ')" }
            $s = 0; foreach ($k in $r.Conditions) { $s++; & $q "INSERT INTO eps.UserTagRuleCondition (RuleId, Seq, ConditionType, Target) VALUES (@r, @s, @c, @t)" @{ r = $id; s = $s; c = $k.ConditionType; t = $k.Target } | Out-Null }
        }
        foreach ($r in $Model.DeviceRules) {
            $id = Invoke-EpsSql -Transaction $tx -Scalar -Query "INSERT INTO eps.DeviceTagRule ([Order], TagType, TagValue, Source, V1ConditionGroup, Notes) OUTPUT INSERTED.RuleId VALUES (@o, @t, @v, 'v1-import', @g, @n)" -Parameters @{ o = $r.Order; t = $r.TagType; v = $r.TagValueCloud; g = $r.V1ConditionGroup; n = "v1: $(@($r.V1Rows) -join ', ')" }
            $s = 0; foreach ($k in $r.Conditions) { $s++; & $q "INSERT INTO eps.DeviceTagRuleCondition (RuleId, Seq, ConditionType, Target) VALUES (@r, @s, @c, @t)" @{ r = $id; s = $s; c = $k.ConditionType; t = $k.Target } | Out-Null }
        }
        $n.UserRules = @($Model.UserRules).Count; $n.DeviceRules = @($Model.DeviceRules).Count

        foreach ($k in $Model.Settings.Keys) {
            & $q "MERGE eps.Setting AS d USING (SELECT @n AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = @a WHEN NOT MATCHED THEN INSERT (Name, Feature, Value, UpdatedBy) VALUES (@n, @f, @v, @a);" @{ n = $k; f = $k.Split('.')[0]; v = [string]$Model.Settings[$k]; a = $Actor } | Out-Null
        }
        foreach ($b in $Model.BreakGlassAccounts) {
            & $q "MERGE eps.BreakGlassAccount AS d USING (SELECT @u AS UserPrincipalName) AS s ON d.UserPrincipalName = s.UserPrincipalName WHEN MATCHED THEN UPDATE SET DisplayName = @d, AuthenticationMethod = @m, ClassificationTagValue = @c, AuthenticationTagValue = @t, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (UserPrincipalName, DisplayName, AuthenticationMethod, ClassificationTagValue, AuthenticationTagValue) VALUES (@u, @d, @m, @c, @t);" @{ u = $b.UserPrincipalName; d = $b.DisplayName; m = $b.AuthenticationMethod; c = $b.ClassificationTagValue; t = $b.AuthenticationTagValue } | Out-Null
        }
        foreach ($a in $Model.AdminUnits) {
            & $q "MERGE eps.AdminUnit AS d USING (SELECT @n AS DisplayName) AS s ON d.DisplayName = s.DisplayName WHEN MATCHED THEN UPDATE SET Purpose = @p, Description = @x WHEN NOT MATCHED THEN INSERT (DisplayName, Purpose, Description) VALUES (@n, @p, @x);" @{ n = $a.DisplayName; p = $a.Purpose; x = $a.Description } | Out-Null
        }
        foreach ($g in $Model.TargetGroups) {
            & $q "MERGE eps.TargetGroup AS d USING (SELECT @n AS DisplayName) AS s ON d.DisplayName = s.DisplayName WHEN MATCHED THEN UPDATE SET VariableName = @v, Assignment = @a, Description = @x, GroupQuery = @q WHEN NOT MATCHED THEN INSERT (DisplayName, VariableName, Assignment, Description, GroupQuery) VALUES (@n, @v, @a, @x, @q);" @{ n = $g.DisplayName; v = $g.VariableName; a = $g.Assignment; x = $g.Description; q = $g.GroupQuery } | Out-Null
        }
        foreach ($t in $Model.ServiceTags) {
            & $q "IF NOT EXISTS (SELECT 1 FROM eps.ServiceTagLocation WHERE Tag = @t) INSERT INTO eps.ServiceTagLocation (Tag) VALUES (@t)" @{ t = $t.Tag } | Out-Null
        }
        $n.Settings = @($Model.Settings.Keys).Count; $n.BreakGlassAccounts = @($Model.BreakGlassAccounts).Count
        $n.AdminUnits = @($Model.AdminUnits).Count; $n.TargetGroups = @($Model.TargetGroups).Count; $n.ServiceTags = @($Model.ServiceTags).Count

        & $q "INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, AfterJson, Source) VALUES (@a, 'V1Import', @k, 'Import', @j, 'v1-import')" @{ a = $Actor; k = [string]$Model.Source; j = ($n | ConvertTo-Json -Compress) } | Out-Null
        $tx.Commit()
    } catch {
        try { $tx.Rollback() } catch { }
        throw
    } finally { $conn.Dispose() }
    [pscustomobject]$n
}
