# EntraPolicySuite -- STALL-1: a run that keeps going without progress is caught, stopped and started once more
# (framework 8.18; owner via Invardia 2026-11-10: a hanging job at a customer was not detected - STALLED is not
# died, and is caught too).
#
#   the job      every finished SQL statement and Graph page is progress (Step in Invoke-EpsSql / Invoke-EpsGraph). A
#                background thread (C#, IsBackground: it never keeps a finished job alive) writes the count to its run row
#                once a minute (eps.Run.Progress / ProgressAtUtc) and ENDS the execution when the engine marked the run
#                stalled - the scheduler holds no right to stop an execution (SEC-AUDIT-1 S4), so the run stops itself.
#   the tick     Get-EpsStallVerdict per running run: no progress for 60 min, or more than twice its usual length (at
#                least 30 min, and no progress for 15 min) = stalled. The run is marked (Failed, "stalled (stopping): ..."),
#                and 2 minutes later - its execution has ended - started once more through its own queue. A run that
#                stalls again within 24 h stays stopped, and the update job is never stopped (only reported).
#   the uplink   Pipeline.longRun.state = 'stalled' (EPS-Uplink.ps1 Get-EpsUplinkLongRun).

Set-StrictMode -Off
$script:EpsStallQuietMinutes = 60       # no progress this long = stalled
$script:EpsStallMinMinutes = 30         # the twice-its-usual rule never stops a run younger than this
$script:EpsStallSlowQuietMinutes = 15   # ... nor one whose progress moved in the last 15 min (slow, not stalled)
$script:EpsStallRestartAfterMinutes = 2 # the marked execution ends within a minute (its watchdog reads the mark)
$script:EpsStallNeverStop = @('Update') # an update is never stopped half-way: reported only

if (-not ('EpsRunWatchdog' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Data.Common;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;

public static class EpsRunWatchdog {
    static long _progress;
    static long _written = -1;
    static Thread _thread;
    static volatile bool _stop;
    static Type _connType;
    static string _cs, _job, _token;
    static DateTime _startedUtc, _tokenExp;
    static bool _mayStop;
    static int _interval = 60;
    public static Guid RunId = Guid.Empty;
    public static string LastError = "";
    public static string LastResult = "";

    public static long Progress { get { return Interlocked.Read(ref _progress); } }
    public static void Step() { Interlocked.Increment(ref _progress); }
    public static void Pin(Guid runId) { RunId = runId; }
    public static bool Alive { get { return _thread != null && _thread.IsAlive; } }

    public static void Start(Type connType, string connectionString, string job, DateTime startedUtc, bool mayStop, int intervalSeconds) {
        if (_thread != null) return;
        _connType = connType; _cs = connectionString; _job = job; _startedUtc = startedUtc; _mayStop = mayStop;
        _interval = Math.Max(5, intervalSeconds);
        _thread = new Thread(Loop);
        _thread.IsBackground = true;
        _thread.Name = "eps-watchdog";
        _thread.Start();
    }
    public static void Stop() { _stop = true; }

    static string Token() {
        if (_token != null && DateTime.UtcNow < _tokenExp) return _token;
        string ep = Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT"), hdr = Environment.GetEnvironmentVariable("IDENTITY_HEADER");
        if (String.IsNullOrEmpty(ep) || String.IsNullOrEmpty(hdr)) throw new InvalidOperationException("no managed identity endpoint for SQL");
        string u = ep + "?api-version=2019-08-01&resource=" + Uri.EscapeDataString("https://database.windows.net/");
        string cid = Environment.GetEnvironmentVariable("EPS_ManagedIdentityClientId");
        if (!String.IsNullOrEmpty(cid)) u += "&client_id=" + cid;
        using (var h = new HttpClient()) {
            h.Timeout = TimeSpan.FromSeconds(30);
            var rq = new HttpRequestMessage(HttpMethod.Get, u);
            rq.Headers.Add("X-IDENTITY-HEADER", hdr);
            var rs = h.Send(rq);
            rs.EnsureSuccessStatusCode();
            string body = rs.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using (var d = JsonDocument.Parse(body)) { _token = d.RootElement.GetProperty("access_token").GetString(); }
        }
        _tokenExp = DateTime.UtcNow.AddMinutes(45);
        return _token;
    }

    static DbConnection Open() {
        var c = (DbConnection)Activator.CreateInstance(_connType, _cs);
        if (!Regex.IsMatch(_cs, @"(?i)Integrated\s*Security|Trusted_Connection|User\s*ID|UID\s*=|Authentication\s*="))
            _connType.GetProperty("AccessToken").SetValue(c, Token());
        c.Open();
        return c;
    }
    static void Add(DbCommand c, string n, object v) { var p = c.CreateParameter(); p.ParameterName = n; p.Value = v ?? DBNull.Value; c.Parameters.Add(p); }

    static void Loop() {
        while (!_stop) {
            for (int i = 0; i < _interval * 10 && !_stop; i++) Thread.Sleep(100);
            if (_stop) break;
            try { LastResult = Once(); LastError = ""; } catch (Exception e) { LastError = e.Message; }
        }
    }

    // one look: find (once) and update this execution's run row; end the execution when the engine marked it stalled
    public static string Once() {
        using (var c = Open()) {
            if (RunId == Guid.Empty) {
                var q = c.CreateCommand();
                q.CommandText = "SELECT TOP (1) RunId FROM eps.Run WHERE Job = @j AND Status = 'Running' AND StartedAtUtc >= @s ORDER BY StartedAtUtc";
                Add(q, "@j", _job); Add(q, "@s", _startedUtc.AddMinutes(-2));
                object r = q.ExecuteScalar();
                if (r == null || r is DBNull) return "no run row yet";
                RunId = (Guid)r;
            }
            long p = Progress;
            if (p != _written) {
                var u = c.CreateCommand();
                u.CommandText = "UPDATE eps.Run SET Progress = @p, ProgressAtUtc = SYSUTCDATETIME() WHERE RunId = @r AND Status = 'Running'";
                Add(u, "@p", p); Add(u, "@r", RunId);
                u.ExecuteNonQuery();
                _written = p;
            }
            var s = c.CreateCommand();
            s.CommandText = "SELECT Status, HeldReason FROM eps.Run WHERE RunId = @r";
            Add(s, "@r", RunId);
            string status = "", held = "";
            using (var rd = s.ExecuteReader()) { if (rd.Read()) { status = rd.IsDBNull(0) ? "" : rd.GetString(0); held = rd.IsDBNull(1) ? "" : rd.GetString(1); } }
            if (status == "Failed" && held.StartsWith("stalled") && _mayStop) {
                Console.Out.WriteLine("[" + DateTime.UtcNow.ToString("u") + "] [eps watchdog] the engine marked this run stalled - this execution ends so it can be started again: " + held);
                Console.Out.Flush();
                Environment.Exit(3);
            }
            return "progress " + p + ", run " + status;
        }
    }
}
'@
}

function Start-EpsRunWatchdog {
    # The job's side: the background thread for this execution. Never throws (a job runs without it - the tick then judges
    # it by its length only, as before STALL-1).
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][datetime]$StartedUtc,
          [switch]$MayStop, [int]$IntervalSeconds = 60)
    try {
        [EpsRunWatchdog]::Start((Resolve-EpsSqlClientType), $ConnectionString, $Job, $StartedUtc.ToUniversalTime(), [bool]$MayStop, $IntervalSeconds)
        $script:EpsWatchOn = $true
        "watchdog on (progress every $IntervalSeconds s$(if (-not $MayStop) { ', never stops this job' }))"
    } catch { "watchdog not started: $($_.Exception.Message)" }
}

function Set-EpsWatchRun {
    # a job that runs side by side with itself (the CA Policy Analyzer) names its own run row
    param([Parameter(Mandatory)][guid]$RunId)
    if ($script:EpsWatchOn) { [EpsRunWatchdog]::Pin($RunId) }
}

function Get-EpsStallVerdict {
    <# PURE. One running run -> @{ Stalled; Reason; AgeMin; UsualMin; Ratio; QuietMin }.
       -Durations: the job's last finished runs' lengths in minutes (the usual = their median, at least 1 min; fewer than 3 =
       no usual, only the progress rule). -ProgressAtUtc: $null = no watchdog (an older image) - only the length rule. #>
    param([Parameter(Mandatory)][datetime]$StartedUtc, $ProgressAtUtc, [double[]]$Durations = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = [datetime]::SpecifyKind($NowUtc, 'Utc')
    $age = [Math]::Round(($now - [datetime]::SpecifyKind($StartedUtc, 'Utc')).TotalMinutes, 1)
    $quiet = if ($ProgressAtUtc -and $ProgressAtUtc -isnot [DBNull]) { [Math]::Round(($now - [datetime]::SpecifyKind([datetime]$ProgressAtUtc, 'Utc')).TotalMinutes, 1) } else { $null }
    $d = @($Durations | Where-Object { $null -ne $_ } | Sort-Object)
    $usual = if ($d.Count -ge 3) { [Math]::Max(1.0, [double]$d[[int][Math]::Floor(($d.Count - 1) / 2)]) } else { $null }
    $ratio = if ($usual) { [Math]::Round($age / $usual, 2) } else { $null }
    $v = @{ Stalled = $false; Reason = ''; AgeMin = $age; UsualMin = $usual; Ratio = $ratio; QuietMin = $quiet }
    if ($null -ne $quiet -and $quiet -ge $script:EpsStallQuietMinutes) {
        $v.Stalled = $true; $v.Reason = "no progress for $([int]$quiet) min (running $([int]$age) min)"; return $v
    }
    if ($usual -and $age -gt 2 * $usual -and $age -ge $script:EpsStallMinMinutes -and ($null -eq $quiet -or $quiet -ge $script:EpsStallSlowQuietMinutes)) {
        $v.Stalled = $true
        $v.Reason = "running $([int]$age) min, more than twice its usual $([Math]::Round($usual, 1)) min$(if ($null -ne $quiet) { ", no progress for $([int]$quiet) min" })"
    }
    $v
}

function Get-EpsJobDurations {
    # the job's last 10 finished, completed runs' lengths in minutes (the usual, as the uplink's longRun)
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Job)
    @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ j = $Job } -Query "SELECT TOP 10 DATEDIFF(second, StartedAtUtc, EndedAtUtc) / 60.0 AS M FROM eps.Run WHERE Job = @j AND EndedAtUtc IS NOT NULL AND Status IN ('Succeeded', 'PartlyFailed') ORDER BY StartedAtUtc DESC" | ForEach-Object { [double]$_.M })
}

function Invoke-EpsStallWatch {
    <#
      The tick's side (every engine check). -Start { param($job, $why, $fromRequest, $envs) -> decision } is the tick's own
      start (claims, guards, its queue); -Blocked { param($job) -> $null or why } its guard. Returns the decisions.
      1. a running run judged stalled is MARKED: Failed, "stalled (stopping): <why>" - its watchdog ends the execution
      2. a run marked >= 2 min ago: started once more, unless it stalled before within 24 h, the job may not start now,
         or a person asked for that run (the request must be asked again - its signature is used up)
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow, [Parameter(Mandatory)][scriptblock]$Start, [Parameter(Mandatory)][scriptblock]$Blocked)
    $out = [System.Collections.Generic.List[object]]::new()
    $never = "'" + ($script:EpsStallNeverStop -join "','") + "'"
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT RunId, Job, StartedAtUtc, ProgressAtUtc FROM eps.Run WHERE Status = 'Running' AND Job <> 'Tick' AND Job NOT IN ($never)")) {
        $v = Get-EpsStallVerdict -StartedUtc $r.StartedAtUtc -ProgressAtUtc $r.ProgressAtUtc -Durations (Get-EpsJobDurations -ConnectionString $ConnectionString -Job $r.Job) -NowUtc $NowUtc
        if (-not $v.Stalled) { continue }
        $n = Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $r.RunId; h = "stalled (stopping): $($v.Reason)"; t = $NowUtc } `
            -Query "UPDATE eps.Run SET Status = 'Failed', EndedAtUtc = @t, HeldReason = @h WHERE RunId = @r AND Status = 'Running'"
        if ($n -eq 1) { $out.Add(@{ Job = [string]$r.Job; Action = 'Stalled'; Reason = "$($v.Reason) - marked, its execution ends; started once more in $script:EpsStallRestartAfterMinutes min" }) }
    }
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ c = $NowUtc.AddMinutes(-$script:EpsStallRestartAfterMinutes) } -Query "SELECT RunId, Job, Scope, HeldReason FROM eps.Run WHERE Status = 'Failed' AND HeldReason LIKE 'stalled (stopping):%' AND EndedAtUtc <= @c")) {
        $job = [string]$r.Job
        $why = ("$($r.HeldReason)" -replace '^stalled \(stopping\):\s*', '')
        # the same job AND the same scope (one CA analyzer monitor is not another's earlier stall)
        $before = [int](Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ j = $job; r = $r.RunId; t = $NowUtc.AddHours(-24); sc = "$($r.Scope)" } -Query "SELECT COUNT(*) FROM eps.Run WHERE Job = @j AND RunId <> @r AND HeldReason LIKE 'stalled%' AND EndedAtUtc > @t AND ISNULL(Scope, N'') = @sc")
        $sc = if ($r.Scope) { try { $r.Scope | ConvertFrom-Json } catch { $null } }
        $not = if ($before) { 'it stalled before within 24 h - look at its log' }
               elseif ($sc -and $sc.request) { "it was a person's request - ask for it again" }
               else { & $Blocked $job }
        $d = $null
        if (-not $not) {
            $d = & $Start $job "started once more after a stalled run ($why)" $false $(if ($sc -and $sc.monitor) { @{ EPS_CA_MONITOR = [string]$sc.monitor } })
            if ($d.Action -ne 'Started') { $not = "the start failed: $($d.Reason)" }
        }
        $text = if ($not) { "stalled: $why. Stopped; not started again: $not" } else { "stalled: $why. Stopped and started once more." }
        if ($text.Length -gt 1000) { $text = $text.Substring(0, 997) + '...' }
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ r = $r.RunId; h = $text } -Query "UPDATE eps.Run SET HeldReason = @h WHERE RunId = @r AND HeldReason LIKE 'stalled (stopping):%'")
        $out.Add(@{ Job = $job; Action = $(if ($not) { 'Stopped' } else { 'Restarted' }); Reason = $text; Execution = $(if ($d) { $d.Execution }) })
    }
    # the run report goes NOW (Invardia's run monitor opens its ticket from it), not at the next 4-hourly cycle: one uplink
    # run, through its own queue, when a stalled run got its outcome in this check
    if (@($out | Where-Object { $_.Action -in 'Restarted', 'Stopped' }).Count -and -not (& $Blocked 'Uplink')) {
        $u = & $Start 'Uplink' 'a stalled run is reported to Invardia now' $false $null
        $out.Add(@{ Job = 'Uplink'; Action = $u.Action; Reason = $(if ($u.Action -eq 'Started') { 'a stalled run is reported to Invardia now' } else { $u.Reason }); Execution = $u.Execution })
    }
    @($out)
}
