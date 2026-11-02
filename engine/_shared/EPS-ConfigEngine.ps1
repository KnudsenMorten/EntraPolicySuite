# EntraPolicySuite -- the ENGINE's side of configuration (SEC-AUDIT-1 S1): the web app never writes configuration; it queues
# the requester's signed request (Job = Config) and the engine applies it here, through the web route's own handler, as
# the requester. Loaded by the engine (job-entry) only - never by the web app (it calls Graph).
# Dot-source EPS-SqlStore, EPS-Graph, EPS-WebAuth, EPS-Audit, EPS-Settings, EPS-Rules and EPS-WebApi first.

Set-StrictMode -Off

# the person's object id for an access grant (the engine reads Entra; a test sets its own): $null = no such user
$script:EpsResolveUserObjectId = { param($upn) try { [string](Invoke-EpsGraph -Path "v1.0/users/$([uri]::EscapeDataString($upn))?`$select=id").id } catch { if ("$_" -match '-> 404') { $null } else { throw } } }

function Update-EpsWebAccessObjectIds {
    # the engine binds every grant that has no object id yet (grants from before 2.0.8, Set-EpsWebAccess without one) to
    # the person's object id - the web app no longer pins a name to the first token that carries it. Returns the count.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $n = 0
    foreach ($r in @(Invoke-EpsSql -ConnectionString $ConnectionString -Query 'SELECT Principal FROM eps.WebAccess WHERE ObjectId IS NULL')) {
        $oid = & $script:EpsResolveUserObjectId ([string]$r.Principal)
        if ($oid) { $n += [int](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ p = [string]$r.Principal; o = [guid]$oid } -Query 'UPDATE eps.WebAccess SET ObjectId = @o WHERE Principal = @p AND ObjectId IS NULL') }
    }
    $n
}

function Invoke-EpsEngineConfigRequest {
    <#
    .SYNOPSIS
        THE ENGINE applies one Config request (SEC-AUDIT-1 S1): the route the requester called, run with the requester's
        VERIFIED identity (the engine checked the signature) and the role they hold NOW - the same handler, validation,
        journal and audit as when the web app wrote it. Returns @{ Status; Text }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)]$Scope, [Parameter(Mandatory)][string]$Identity, [string]$ObjectId, [string]$Token, $CorrelationId)
    $method = "$($Scope.method)".ToUpperInvariant(); $path = "$($Scope.path)"
    $route = $null; $m = $null
    foreach ($r in Get-EpsWebRoutes) { if ($r.Method -eq $method -and $path -match $r.Pattern) { $route = $r; $m = $Matches; break } }
    if (-not $route -or $route.Apply -ne 'Engine') { return @{ Status = 400; Text = "not a configuration change: $method $path" } }
    $role = Get-EpsWebRole -ConnectionString $ConnectionString -Identity $Identity -ObjectId $ObjectId
    $body = if ($Scope.body) { $Scope.body } else { [pscustomobject]@{} }
    $cor = if ($CorrelationId) { [guid]"$CorrelationId" } else { [guid]::NewGuid() }
    $audit = { param($res, $outcome, $text) [void](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action $(if ($res.Audit.Guard) { 'guard.trip' } elseif ($res.Audit.Action) { $res.Audit.Action } else { $route.Action }) -Actor $Identity -ActorSource 'job' `
        -Target $(if ($res.Audit.Target) { $res.Audit.Target } else { "$method $path" }) -Reason "$($body.reason)" -Outcome $outcome -OutcomeText $text -Before $res.Audit.Before -After $res.Audit.After -CorrelationId $cor) }
    if (-not (Test-EpsWebRole -Have $role -Need $route.Role)) { & $audit @{} 'refused' "needs $($route.Role), is $role now"; return @{ Status = 403; Text = "refused: this needs the $($route.Role) role ($Identity is $role now)" } }
    # a reason is optional since 2.0.19 (owner 2026-11-02) - a request without one is applied
    $c = @{ Ctx = @{ ConnectionString = $ConnectionString; Engine = $true }; Caller = @{ identity = $Identity; objectId = $ObjectId; token = $Token; verifiedAtUtc = [datetime]::UtcNow }; Role = $role; Query = @{}; Body = $body; Correlation = $cor }
    $res = try { & $route.Handler $c $m } catch { $cid = [guid]::NewGuid(); Write-Host "  [config] ERROR $method $path ($cid): $($_.Exception.Message)"; @{ Status = 500; Body = @{ error = "internal error (reference $cid - see the engine log)" }; Audit = @{ Outcome = 'error'; OutcomeText = "$($_.Exception.Message) ($cid)" } } }
    $a = if ($res.Audit) { $res.Audit } else { @{} }
    $outcome = if ($a.Outcome) { $a.Outcome } elseif ($res.Status -ge 400) { 'error' } else { 'ok' }
    & $audit $res $outcome $a.OutcomeText
    @{ Status = [int]$res.Status; Body = $res.Body; Text = "$(if ($res.Body.text) { $res.Body.text } elseif ($res.Body.error) { $res.Body.error } else { "HTTP $($res.Status)" })" }
}
