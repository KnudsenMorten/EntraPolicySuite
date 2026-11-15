#Requires -Version 7.2
<#
.SYNOPSIS
    The Entra Policy Suite web app (DESIGN §2): a loopback-only HttpListener behind the shared sign-in front.
.DESCRIPTION
    Runs in the web app's container (EPS_JOB = Web). The sign-in front is the other container of the same revision and
    the only thing the ingress reaches; this listens on http://127.0.0.1:<EPS_WEB_PORT> only, so nothing else can reach
    it. Every request goes through Invoke-EpsWebRequest (engine/_shared/EPS-WebApi.ps1), which verifies the front's
    access token itself. Settings: EPS_SQL_CONNECTION, EPS_TENANT_ID, EPS_WEB_CLIENT_ID, EPS_WEB_PORT (default 8081).
    It refuses to start without the tenant and the client id (no pins = no trust).
#>
[CmdletBinding()]
param([string]$ConnectionString = $env:EPS_SQL_CONNECTION, [int]$Port = $(if ($env:EPS_WEB_PORT) { [int]$env:EPS_WEB_PORT } else { 8081 }))
$ErrorActionPreference = 'Stop'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'EPS-SqlStore', 'EPS-Scheduler', 'EPS-Conditions', 'EPS-WebAuth', 'EPS-Audit', 'EPS-Settings', 'EPS-Rules', 'EPS-V1Import', 'EPS-Mail', 'EPS-CaAnalyzer', 'EPS-CaManage', 'EPS-CaOptions', 'EPS-Backup', 'EPS-Onboarding', 'EPS-GroupManage', 'EPS-OnboardManage', 'EPS-IdentityReport', 'EPS-WorkerPage', 'EPS-WebApi', 'EPS-Licence') { . (Join-Path $sol "engine\_shared\$f.ps1") }
# EPS PRO: the Pro package's modules (pro/engine) - never a *Write.ps1 (a write the engine alone makes, e.g. an account
# disabled); without the Pro package the folder is not there and nothing is loaded
$proEngine = Join-Path $sol 'pro\engine'
if (Test-Path -LiteralPath $proEngine) { foreach ($pf in @(Get-ChildItem -LiteralPath $proEngine -Filter '*.ps1' -File | Where-Object { $_.Name -notlike '*Write.ps1' } | Sort-Object Name)) { . $pf.FullName } }
$version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim()
$cfg = Get-EpsWebAuthConfig
if (-not $cfg.Issuers.Count -or -not $cfg.Audiences.Count) { Write-Host '[eps web] EPS_TENANT_ID and EPS_WEB_CLIENT_ID must be set - not starting (fail closed)'; exit 2 }
if (-not $ConnectionString) { Write-Host '[eps web] EPS_SQL_CONNECTION is not set - not starting'; exit 2 }
$ctx = @{ ConnectionString = $ConnectionString; AuthConfig = $cfg; Version = $version; StaticRoot = (Join-Path $PSScriptRoot 'www') }
# 2.1.43 (Invardia 2026-11-15): the sign-in check proves itself at START, with no person - Microsoft's library loaded and
# the request path run on made-up input; not ok = not starting (fail closed: an unhealthy revision at ring 0, never a
# web app that refuses every person later)
$self = Test-EpsIdentityModelSelfCheck
if (-not $self.ok) { Write-Host "[eps web] identity-model self-check FAILED: $($self.detail) - not starting (fail closed)"; exit 3 }
Write-Host "[eps web] identity-model self-check OK: $($self.detail)"

$listener = [System.Net.HttpListener]::new()
# 2.1.35 (owner 2026-11-14, Microsoft's built-in Container Apps sign-in): EPS_WEB_LISTEN = 'all' when the app itself is
# the ingress target - the platform's sign-in stands in front of it, and every request is still verified HERE (the
# token check above, fail closed); otherwise loopback ONLY (the older sign-in front is the only way in)
$bind = if ("$env:EPS_WEB_LISTEN" -eq 'all') { '+' } else { '127.0.0.1' }
$listener.Prefixes.Add("http://$($bind):$Port/")
$listener.Start()
Write-Host "[eps web] $version listening on $(if ($bind -eq '+') { 'all addresses (behind Microsoft''s built-in sign-in)' } else { '127.0.0.1' }):$Port (tenant $($cfg.TenantId), audience $($cfg.Audiences[0]), scope $($cfg.Scope))"
try {
    while ($listener.IsListening) {
        $hc = $listener.GetContext()
        $rq = $hc.Request; $rs = $hc.Response
        try {
            $headers = [System.Collections.Hashtable]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($k in $rq.Headers.AllKeys) { $headers[$k] = $rq.Headers[$k] }
            $query = @{}; foreach ($k in $rq.QueryString.AllKeys) { if ($k) { $query[$k] = $rq.QueryString[$k] } }
            $body = ''
            if ($rq.HasEntityBody) {
                if ($rq.ContentLength64 -gt 1MB) { throw [System.IO.InvalidDataException]::new('body too large') }
                # SEC-AUDIT-1 S9: the bytes READ are counted too, so a chunked body (no Content-Length) is held to the same 1 MB
                $buf = [IO.MemoryStream]::new(); $chunk = [byte[]]::new(65536)
                while (($got = $rq.InputStream.Read($chunk, 0, $chunk.Length)) -gt 0) { $buf.Write($chunk, 0, $got); if ($buf.Length -gt 1MB) { throw [System.IO.InvalidDataException]::new('body too large') } }
                $body = [Text.Encoding]::UTF8.GetString($buf.ToArray()); $buf.Dispose()
            }
            $r = Invoke-EpsWebRequest -Ctx $ctx -Request @{ Method = $rq.HttpMethod; Path = $rq.Url.AbsolutePath; Query = $query; Headers = $headers; Body = $body }
        } catch [System.IO.InvalidDataException] { $r = New-EpsWebError 413 'the request is too large'; $r.Headers = @{} }
        catch { Write-Host "[eps web] ERROR $($_.Exception.Message)"; $r = New-EpsWebError 500 'internal error'; $r.Headers = @{} }
        try {
            $rs.StatusCode = $r.Status
            $rs.ContentType = $r.ContentType
            foreach ($k in $r.Headers.Keys) { $rs.Headers[$k] = "$($r.Headers[$k])" }
            $bytes = if ($r.Body -is [byte[]]) { $r.Body } elseif ($r.Body -is [string]) { [Text.Encoding]::UTF8.GetBytes($r.Body) } else { [Text.Encoding]::UTF8.GetBytes(($r.Body | ConvertTo-Json -Depth 10 -Compress)) }
            $rs.ContentLength64 = $bytes.Length
            if ($rq.HttpMethod -ne 'HEAD') { $rs.OutputStream.Write($bytes, 0, $bytes.Length) }
        } catch { Write-Host "[eps web] could not answer: $($_.Exception.Message)" } finally { try { $rs.Close() } catch { } }
    }
} finally { $listener.Stop() }
