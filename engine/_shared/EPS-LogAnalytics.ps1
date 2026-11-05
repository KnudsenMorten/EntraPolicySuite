# EntraPolicySuite -- V1-PARITY P11: the identity report in Log Analytics, as v1 does it live (IdentityReporter.ps1
# L858-913: every user row to EntraUsersMetadata_CL through a data collection endpoint + rule), and v1's two exposure
# reports read back from it (CAPolicyEvaluator\ExposureSigninReports-ServiceAccounts.ps1 / -SharedDeviceUsers.ps1).
#
#   upload   : the Logs Ingestion API (REST, the engine's managed identity, token for https://monitor.azure.com), batched
#              below 1 MB per call, retried on 429 / 5xx - the identity needs ONLY 'Monitoring Metrics Publisher' on the
#              one data collection rule (no tenant-wide right, no Graph permission)
#   exposure : the Log Analytics query API (token for https://api.loganalytics.io) - ONLY 'Log Analytics Reader' on the
#              one workspace
#   setup    : tools/setup/Initialize-EpsLogAnalytics.ps1 (a person with rights on the workspace) makes the table, the
#              endpoint, the rule and the two role assignments, then stores the target (IdentityReport.LogAnalytics.Target)
# Loaded by the ENGINE (tools/eps-engine/job-entry.ps1) and the setup script. The pure parts (v1's columns, the records,
# the batches, the queries) are in EPS-IdentityReport.ps1. Off until a SuperAdmin switches IdentityReport.LogAnalytics.Enabled
# on; then it runs after every identity report run on its own (owner 2026-11-05: scheduled jobs stay automatic).

Set-StrictMode -Off
$script:EpsLaIngestApi = '2023-01-01'
$script:EpsLaArmApi = @{ table = '2022-10-01'; insights = '2022-06-01'; workspace = '2022-10-01' }
$script:EpsLaRole = @{ MetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'; LogAnalyticsReader = '73c42c96-874c-492b-b04d-ab87d138a893' }
$script:EpsLaSleep = { param($s) Start-Sleep -Seconds $s }   # a test makes the waits instant

function Get-EpsLaRetryAfter($r) {
    if (-not $r.Headers) { return $null }
    foreach ($k in @($r.Headers.Keys)) { if ("$k" -ieq 'Retry-After') { $n = 0; if ([int]::TryParse([string](@($r.Headers[$k])[0]), [ref]$n)) { return $n } } }
    $null
}

function Test-EpsLaTarget {
    <#
      PURE. The stored target (IdentityReport.LogAnalytics.Target, JSON, written by Initialize-EpsLogAnalytics.ps1): the
      workspace (resource id + its workspace id), the ingestion endpoint, the rule's immutable id, the stream and the columns
      the stream declares (name -> type). Returns @{ Ok; Reason; Target }.
    #>
    param([AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { return @{ Ok = $false; Reason = 'not set up yet - run Initialize-EpsLogAnalytics.ps1' } }
    $o = try { $Json | ConvertFrom-Json -AsHashtable -Depth 6 } catch { return @{ Ok = $false; Reason = 'the stored target is not JSON - run Initialize-EpsLogAnalytics.ps1 again' } }
    if ($o -isnot [System.Collections.IDictionary]) { return @{ Ok = $false; Reason = 'the stored target is not an object' } }
    if ("$($o.workspaceResourceId)" -notmatch '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$') { return @{ Ok = $false; Reason = 'workspaceResourceId is not a Log Analytics workspace' } }
    if ("$($o.workspaceId)" -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return @{ Ok = $false; Reason = 'workspaceId is not a GUID' } }
    if ("$($o.ingestionEndpoint)" -notmatch '^https://[a-z0-9.-]+\.ingest\.monitor\.azure\.com/?$') { return @{ Ok = $false; Reason = 'ingestionEndpoint is not a Logs Ingestion endpoint (https://<name>.<region>-1.ingest.monitor.azure.com)' } }
    if ("$($o.dcrImmutableId)" -notmatch '^dcr-[0-9a-f]{32}$') { return @{ Ok = $false; Reason = 'dcrImmutableId is not a data collection rule id (dcr-<32 hex>)' } }
    if ("$($o.stream)" -ne $script:EpsLaStream) { return @{ Ok = $false; Reason = "stream must be $($script:EpsLaStream)" } }
    $cols = $o.columns
    if ($cols -isnot [System.Collections.IDictionary] -or -not $cols.Count) { return @{ Ok = $false; Reason = 'columns: the stream''s columns (name -> type) are missing' } }
    foreach ($k in @($cols.Keys)) { if ("$k" -notmatch '^[A-Za-z][A-Za-z0-9_]{0,62}$' -or "$($cols[$k])" -notin 'string', 'boolean', 'int', 'long', 'real', 'datetime', 'dynamic') { return @{ Ok = $false; Reason = "columns: '$k' ($($cols[$k])) is not a column the stream can declare" } } }
    @{ Ok = $true; Reason = ''; Target = $o }
}

function Get-EpsLaTarget {
    # the switch + the stored target. @{ Enabled; Ok; Reason; Target }
    param([Parameter(Mandatory)][string]$ConnectionString)
    $on = "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'IdentityReport.LogAnalytics.Enabled' -Default 'false')" -eq 'true'
    if (-not $on) { return @{ Enabled = $false; Ok = $false; Reason = 'off (Settings > Identity report > Send the report to Log Analytics)' } }
    $t = Test-EpsLaTarget -Json "$(Get-EpsSetting -ConnectionString $ConnectionString -Name 'IdentityReport.LogAnalytics.Target' -Default '')"
    @{ Enabled = $true; Ok = $t.Ok; Reason = $t.Reason; Target = $t.Target }
}

function Send-EpsLaRecords {
    <#
      The records to the Logs Ingestion API: POST <endpoint>/dataCollectionRules/<immutable id>/streams/<stream>, one call
      per batch (Split-EpsLaBatches). 429 / 5xx / no answer: wait (Retry-After, else 2, 4, 8, 16, 32 s) and try again, at
      most 5 times; any other answer stops at that batch (v1 stopped on the first error too). Never throws.
      Returns @{ Ok; Sent; Total; Batches; Calls; TooLarge; Reason }.
    #>
    param([Parameter(Mandatory)]$Target, [object[]]$Records = @(), [int]$MaxTries = 5, [scriptblock]$Log = { param($l, $m) })
    $split = Split-EpsLaBatches -Records $Records
    $uri = "$("$($Target.ingestionEndpoint)".TrimEnd('/'))/dataCollectionRules/$($Target.dcrImmutableId)/streams/$($Target.stream)?api-version=$($script:EpsLaIngestApi)"
    $sent = 0; $calls = 0; $i = 0
    foreach ($b in $split.Batches) {
        $i++; $n = [int]$b.Count
        $ok = $false; $last = ''
        for ($try = 1; $try -le $MaxTries; $try++) {
            $calls++
            $r = try { & $script:EpsHttp 'POST' $uri @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://monitor.azure.com')"; 'Content-Type' = 'application/json' } $b.Json } catch { @{ Status = 0; Body = "$($_.Exception.Message)" } }
            if ($r.Status -ge 200 -and $r.Status -lt 300) { $ok = $true; break }
            $last = "HTTP $($r.Status): $((("$($r.Body)") -split "`n")[0])"
            if ($r.Status -ne 0 -and $r.Status -ne 429 -and $r.Status -lt 500) { break }   # a refusal: trying again changes nothing
            if ($try -lt $MaxTries) { $w = Get-EpsLaRetryAfter $r; if ($null -eq $w) { $w = [math]::Pow(2, $try) }; & $script:EpsLaSleep ([math]::Min(60, $w)) }
        }
        if (-not $ok) {
            & $Log 'Warn' "Log Analytics: batch $i of $($split.Batches.Count) not taken ($last) - $sent of $(@($Records).Count) row(s) sent"
            return @{ Ok = $false; Sent = $sent; Total = @($Records).Count; Batches = $split.Batches.Count; Calls = $calls; TooLarge = $split.TooLarge.Count; Reason = $last }
        }
        $sent += $n
    }
    @{ Ok = $true; Sent = $sent; Total = @($Records).Count; Batches = $split.Batches.Count; Calls = $calls; TooLarge = $split.TooLarge.Count; Reason = $(if ($split.TooLarge.Count) { "$($split.TooLarge.Count) row(s) over 1 MB each were not sent" } else { '' }) }
}

function Invoke-EpsLaQuery {
    # ONE query against the workspace (POST https://api.loganalytics.io/v1/workspaces/<id>/query). Never throws:
    # @{ Ok; Columns; Rows (objects); Error }
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Query, [string]$Timespan = 'P90D')
    $body = @{ query = $Query; timespan = $Timespan } | ConvertTo-Json -Compress
    $r = try { & $script:EpsHttp 'POST' "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query" @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://api.loganalytics.io')" } $body } catch { @{ Status = 0; Body = "$($_.Exception.Message)" } }
    if ($r.Status -lt 200 -or $r.Status -ge 300) {
        $e = try { $x = ($r.Body | ConvertFrom-Json).error; "$($x.message)$(if ($x.innererror.message) { ": $($x.innererror.message)" })" } catch { "$($r.Body)" }
        return @{ Ok = $false; Columns = @(); Rows = @(); Error = "HTTP $($r.Status): $e$(if ($r.Status -eq 403) { ' (the engine needs Log Analytics Reader on the workspace - run Initialize-EpsLogAnalytics.ps1)' })" }
    }
    if (-not "$($r.Body)".Trim()) { return @{ Ok = $true; Columns = @(); Rows = @(); Error = $null } }
    $j = $r.Body | ConvertFrom-Json -Depth 20
    $t = @($j.tables)[0]
    $cols = @($t.columns | ForEach-Object { "$($_.name)" })
    $rows = @(foreach ($row in @($t.rows)) { $o = [ordered]@{}; for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = @($row)[$i] }; [pscustomobject]$o })
    @{ Ok = $true; Columns = $cols; Rows = $rows; Error = $null }
}

function Invoke-EpsLaExposure {
    <#
      v1's exposure lists against the workspace: first which tables have data in 90 days (EntraUsersMetadata_CL,
      SigninLogs, AADNonInteractiveUserSignInLogs - union isfuzzy leaves a missing table out instead of failing), then the
      eight queries (Get-EpsExposureQueryCatalog). Without the sign-in logs in this workspace the lists cannot be built:
      the note says so. Never throws. Returns @{ Tables; Note; Results }.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceId, [scriptblock]$Log = { param($l, $m) })
    $probe = Invoke-EpsLaQuery -WorkspaceId $WorkspaceId -Query 'union isfuzzy=true (EntraUsersMetadata_CL | take 1 | project T = "EntraUsersMetadata_CL"), (SigninLogs | take 1 | project T = "SigninLogs"), (AADNonInteractiveUserSignInLogs | take 1 | project T = "AADNonInteractiveUserSignInLogs") | distinct T'
    if (-not $probe.Ok) { & $Log 'Warn' "Log Analytics: the workspace could not be read ($($probe.Error))"; return @{ Tables = @(); Note = "The workspace could not be read: $($probe.Error)"; Results = @() } }
    $have = @($probe.Rows | ForEach-Object { "$($_.T)" })
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($have -notcontains 'SigninLogs' -and $have -notcontains 'AADNonInteractiveUserSignInLogs') { $notes.Add('The Entra sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs) are not in this workspace, or hold nothing from the last 90 days: the exposure lists cannot be built. Send the sign-in logs to this workspace (Entra ID > Diagnostic settings).') }
    elseif ($have -notcontains 'AADNonInteractiveUserSignInLogs') { $notes.Add('Only the interactive sign-ins (SigninLogs) are in this workspace: non-interactive sign-ins are not counted.') }
    if ($have -notcontains 'EntraUsersMetadata_CL') { $notes.Add('EntraUsersMetadata_CL holds nothing yet (the first upload can take a few minutes to show): the lists are empty until it does.') }
    $res = @(foreach ($q in Get-EpsExposureQueryCatalog) {
        if ($notes.Count -and $have -notcontains 'SigninLogs' -and $have -notcontains 'AADNonInteractiveUserSignInLogs') { [ordered]@{ name = $q.Name; set = $q.Set; count = 0; truncated = $false; columns = @(); rows = @(); error = 'no sign-in logs in this workspace' }; continue }
        $x = Invoke-EpsLaQuery -WorkspaceId $WorkspaceId -Query $q.Kql
        if (-not $x.Ok) { & $Log 'Warn' "Log Analytics: $($q.Name) failed ($($x.Error))" }
        [ordered]@{ name = $q.Name; set = $q.Set; count = @($x.Rows).Count; truncated = (@($x.Rows).Count -ge 5000); columns = @($x.Columns); rows = @($x.Rows); error = $x.Error }
    })
    @{ Tables = $have; Note = ($notes -join ' '); Results = $res }
}

function Invoke-EpsIdentityLogAnalytics {
    <#
      After an identity report run (Invoke-EpsIdentityReportJob): when switched on, the users go to EntraUsersMetadata_CL
      and v1's exposure lists are read back; the result is stored for the run (eps.IdentityLaRun) and shown on the
      Identity page. Off = nothing (no row). Never fails the report run: an error is stored and logged.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [object[]]$Users = @(), $Config,
          [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Log = { param($l, $m) })
    $t = Get-EpsLaTarget -ConnectionString $ConnectionString
    if (-not $t.Enabled) { return $null }
    $row = @{ Rows = @($Users).Count; Sent = 0; Ok = $false; Text = ''; Tables = @(); Exposure = @(); Note = '' }
    try {
        if (-not $t.Ok) { $row.Text = "not sent: $($t.Reason)"; $row.Note = $t.Reason; & $Log 'Warn' "Log Analytics: $($row.Text)" }
        else {
            $want = Get-EpsLaColumns -Tags @($Config.Tags)
            $cols = [ordered]@{}; foreach ($k in $t.Target.columns.Keys) { $cols[$k] = "$($t.Target.columns[$k])" }   # what the stream declares
            $missing = @($want.Keys | Where-Object { -not $cols.Contains($_) })
            $recs = ConvertTo-EpsLaRecords -Rows @($Users) -Columns $cols -CollectionTime $NowUtc -HireDateAttribute "$($Config.HireDateAttribute)"
            $s = Send-EpsLaRecords -Target $t.Target -Records $recs -Log $Log
            $row.Sent = $s.Sent; $row.Ok = $s.Ok
            $row.Text = "$($s.Sent) of $($s.Total) user(s) sent in $($s.Batches) call(s)$(if ($s.Reason) { " - $($s.Reason)" })$(if ($missing.Count) { "; $($missing.Count) column(s) the table does not have yet ($($missing -join ', ')) - run Initialize-EpsLogAnalytics.ps1 again to add them" })"
            & $Log $(if ($s.Ok) { 'Info' } else { 'Warn' }) "Log Analytics: $($row.Text)"
            $e = Invoke-EpsLaExposure -WorkspaceId "$($t.Target.workspaceId)" -Log $Log
            $row.Tables = @($e.Tables); $row.Exposure = @($e.Results); $row.Note = $e.Note
            & $Log 'Info' "Log Analytics: exposure lists $(@($e.Results | ForEach-Object { "$($_.name) $($_.count)" }) -join ', ')"
        }
    } catch { $row.Text = "failed: $($_.Exception.Message)"; & $Log 'Warn' "Log Analytics: $($row.Text)" }
    Save-EpsIdentityLaRun -ConnectionString $ConnectionString -RunId $RunId -Result $row -NowUtc $NowUtc
    $row
}

function Save-EpsIdentityLaRun {
    # one row per report run (eps.IdentityLaRun; it goes with its snapshot - ON DELETE CASCADE)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RunId, [Parameter(Mandatory)][hashtable]$Result, [datetime]$NowUtc = [datetime]::UtcNow)
    $p = @{ r = $RunId; t = $NowUtc; n = [int]$Result.Rows; s = [int]$Result.Sent; o = [bool]$Result.Ok; x = "$($Result.Text)".Substring(0, [math]::Min(2000, "$($Result.Text)".Length))
            tb = (ConvertTo-Json -InputObject @($Result.Tables) -Compress); e = (ConvertTo-Json -InputObject @($Result.Exposure) -Compress -Depth 6); no = "$($Result.Note)".Substring(0, [math]::Min(2000, "$($Result.Note)".Length)) }
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters $p -Query 'INSERT INTO eps.IdentityLaRun (RunId, CheckedAtUtc, UploadRows, UploadSent, UploadOk, UploadText, TablesJson, ExposureJson, Note) VALUES (@r, @t, @n, @s, @o, @x, @tb, @e, @no)')
}

# ---- the setup (Initialize-EpsLogAnalytics.ps1): the table, the endpoint, the rule, the two role assignments -------
function Get-EpsLaSetupPlan {
    <#
      PURE. What the setup does, from what is there now:
        -Workspace : the workspace as read (GET) - its location and workspace id
        -Table     : EntraUsersMetadata_CL as read (GET, $null = none) - its columns are KEPT with their types (a table v1
                     made may hold a column as string); only missing columns are added, none is removed or retyped
        -Dce / -Dcr: the endpoint / rule as read ($null = none)
        -Columns   : the columns to have (Get-EpsLaColumns)
        -Assigned  : the role assignment ids already there (role definition guid, lower case) for the engine
      Returns @{ Steps (What, Kind); TableColumns (name -> type, what the stream declares); Missing }.
    #>
    param([Parameter(Mandatory)]$Workspace, $Table, $Dce, $Dcr, [Parameter(Mandatory)][System.Collections.IDictionary]$Columns, [string[]]$Assigned = @(),
          [Parameter(Mandatory)][string]$DceName, [string]$DcrName = $script:EpsLaDcrName)
    $have = [ordered]@{}
    foreach ($c in @($Table.properties.schema.columns)) { if ($c.name -and "$($c.name)" -ne 'TimeGenerated') { $have["$($c.name)"] = "$($c.type)".ToLowerInvariant() } }
    $final = [ordered]@{}; foreach ($k in $have.Keys) { $final[$k] = $have[$k] }
    $missing = @($Columns.Keys | Where-Object { -not $have.Contains($_) })
    foreach ($k in $missing) { $final[$k] = $Columns[$k] }
    $steps = [System.Collections.Generic.List[object]]::new()
    if (-not $Table) { $steps.Add(@{ Kind = 'table'; What = "create the table $($script:EpsLaTable) in $($Workspace.name) ($($final.Count) columns, v1's)" }) }
    elseif ($missing.Count) { $steps.Add(@{ Kind = 'table'; What = "add $($missing.Count) column(s) to $($script:EpsLaTable): $($missing -join ', ') (the others are kept as they are)" }) }
    if (-not $Dce) { $steps.Add(@{ Kind = 'dce'; What = "create the data collection endpoint $DceName ($($Workspace.location))" }) }
    $streamCols = @($Dcr.properties.streamDeclarations.$($script:EpsLaStream).columns | ForEach-Object { "$($_.name)" })
    if (-not $Dcr -or @($final.Keys | Where-Object { $streamCols -notcontains $_ }).Count) { $steps.Add(@{ Kind = 'dcr'; What = "$(if ($Dcr) { 'update' } else { 'create' }) the data collection rule $DcrName (stream $($script:EpsLaStream) -> $($script:EpsLaTable))" }) }
    if (@($Assigned) -notcontains $script:EpsLaRole.MetricsPublisher) { $steps.Add(@{ Kind = 'role-dcr'; What = "give the engine 'Monitoring Metrics Publisher' on $DcrName only (to send the rows)" }) }
    if (@($Assigned) -notcontains $script:EpsLaRole.LogAnalyticsReader) { $steps.Add(@{ Kind = 'role-ws'; What = "give the engine 'Log Analytics Reader' on $($Workspace.name) only (to read the exposure lists)" }) }
    @{ Steps = $steps.ToArray(); TableColumns = $final; Missing = $missing }
}

function New-EpsLaDcrBody {
    # PURE. The data collection rule: one stream (the columns, TimeGenerated set at ingestion as v1's rules did) to the table
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$DceId, [Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][System.Collections.IDictionary]$Columns)
    @{
        location = $Location; tags = @{ product = 'EntraPolicySuite' }
        properties = @{
            dataCollectionEndpointId = $DceId
            streamDeclarations = @{ $script:EpsLaStream = @{ columns = @(foreach ($k in $Columns.Keys) { @{ name = $k; type = $Columns[$k] } }) } }
            destinations = @{ logAnalytics = @(@{ workspaceResourceId = $WorkspaceResourceId; name = 'eps-workspace' }) }
            dataFlows = @(@{ streams = @($script:EpsLaStream); destinations = @('eps-workspace'); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $script:EpsLaStream })
        }
    }
}
