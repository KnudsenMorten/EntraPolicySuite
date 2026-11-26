# EntraPolicySuite -- mail (framework MAIL-1 / MAIL-3, one place for every mail the product sends).
#   MAIL-1: a shared mailbox (no licence); the product's OWN managed identity sends with Graph app-only
#           POST /users/<mailbox>/sendMail; the right is Exchange RBAC 'Application Mail.Send' scoped to that ONE
#           mailbox (Initialize-EpsMailSender.ps1) - never a tenant-wide Mail.Send consent.
#   MAIL-3 + MAIL-ENV (12.11a): subject  [<KIND>] <environment> - <severity word if relevant> <what happened> [Entra Policy Suite], max 120 characters,
#           only <what happened> is shortened; every mail names its environment in the footer (name, tenant, product,
#           version).
# Settings: Mail.Mode (none | sharedMailbox; default none), Mail.Sender (the mailbox's UPN or id), Mail.Recipients
# (a JSON array), Platform.EnvironmentName. Dot-source EPS-SqlStore and EPS-Graph first.

Set-StrictMode -Off
$script:EpsProductName = 'Entra Policy Suite'
# BRAND-3: the mail header's logo (reversed, on brand-ink) - Invardia's brand page, https only, no tracking parameter
$script:EpsMailLogoUrl = 'https://invardia.com/brand/Invardia-EntraPolicySuite-logo/horizontal/invardia-entrapolicysuite-horizontal-reversed-512w.png'

function New-EpsMailSubject {
    # MAIL-3. -Severity: Failed | Warning | 'Action needed' | '' (none on a normal mail).
    param([Parameter(Mandatory)][string]$Environment, [Parameter(Mandatory)][string]$What, [ValidateSet('', 'Failed', 'Warning', 'Action needed')][string]$Severity = '', [string]$Ticket)
    # MAIL-ENV (framework 12.11a, owner 2026-11-12 "What eng is this"): the ENVIRONMENT first - its label ("[PROD] internal",
    # Get-EpsMailEnvironmentLabel), then " - ", the severity and what happened: "[PROD] internal - Warning: ... [Entra Policy Suite]"
    $head = "$("$Environment".Trim()) - " + $(if ($Severity) { "$Severity`: " } else { '' })
    $tail = $(if ($Ticket) { " [$Ticket]" } else { '' }) + " [$script:EpsProductName]"
    $room = 120 - $head.Length - $tail.Length
    $w = if ($What.Length -gt $room) { $What.Substring(0, [math]::Max(0, $room - 3)) + '...' } else { $What }
    "$head$w$tail"
}

function ConvertTo-EpsHtml([string]$s) { [Net.WebUtility]::HtmlEncode($s) }

function Get-EpsMailLink {
    # MAIL-2 item 1: a STABLE deep link to one page of the web app (its #page route), never a session URL. '' when the
    # install has no web address (the install sets EPS_WEB_URL on every job) or the page id is not a plain id.
    param([string]$WebUrl = $env:EPS_WEB_URL, [string]$Page = '')
    if ("$WebUrl" -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?/?$') { return '' }
    $u = "$WebUrl".TrimEnd('/') + '/'
    if ($Page -and $Page -match '^[a-z]+(/[A-Za-z0-9._-]+)?$') { $u += "#$Page" }
    $u
}

function New-EpsMailBody {
    # The calm format (framework 12.11): a summary, the facts, what to do, the details - and the footer that names the
    # environment (MAIL-1 "every mail names its environment"). MAIL-2 (framework 12.11 items 1, 4, 7): the product's
    # wordmark on the BRAND-2 header, ONE blue button that deep-links to the page the mail is about (-ButtonText +
    # -ButtonPage, a #page route of the web app) and a plain link to the product's home in the footer.
    param([Parameter(Mandatory)][string]$Summary, [object[]]$Rows = @(), [string[]]$Columns = @(), [string]$WhatToDo,
          [Parameter(Mandatory)][hashtable]$Footer, [string]$ButtonText, [string]$ButtonPage, [string]$WebUrl = $env:EPS_WEB_URL,
          [string]$SummaryHtml)
    $sb = [Text.StringBuilder]::new()
    [void]$sb.Append("<html><body style=""font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1b1b1b"">")
    # BRAND-2.1 + BRAND-3 (owner via Invardia 2026-11-08): the brand-ink header with the Invardia Entra Policy Suite logo
    # (reversed, served by invardia.com/brand) and the 1 px brand-blue line under it. Mail clients block images by default,
    # so the product name is the image's alt text, in brand-wordmark - a blocked image still reads "Entra Policy Suite".
    [void]$sb.Append("<div style=""background:#0B1633;border-bottom:1px solid #1B4FE4;padding:10px 16px""><img src=""$script:EpsMailLogoUrl"" alt=""$script:EpsProductName"" height=""32"" style=""display:block;height:32px;width:auto;border:0;color:#9FC3FF;font-size:18px;font-weight:600""></div>")
    # MAIL-ENV (framework 12.11a): the FIRST line names the environment and the tenant (display name + id) - every mail
    [void]$sb.Append("<p style=""font-size:12px;color:#444;margin:12px 0 4px""><b>$(ConvertTo-EpsHtml $Footer.Environment)</b>$(if ("$($Footer.TenantName)$($Footer.TenantId)".Trim()) { " &middot; tenant $(ConvertTo-EpsHtml $(if ("$($Footer.TenantName)".Trim()) { $Footer.TenantName } else { '(name not known)' })) ($(ConvertTo-EpsHtml $Footer.TenantId))" })</p>")
    [void]$sb.Append("<p>$(ConvertTo-EpsHtml $Summary)</p>")
    # -SummaryHtml: markup the CALLER built and encoded (e.g. a list); never a value from outside unencoded
    if ($SummaryHtml) { [void]$sb.Append($SummaryHtml) }
    if ($Rows.Count -and $Columns.Count) {
        [void]$sb.Append('<table style="border-collapse:collapse;font-size:13px"><tr>')
        foreach ($c in $Columns) { [void]$sb.Append("<th style=""text-align:left;border-bottom:1px solid #ccc;padding:4px 10px"">$(ConvertTo-EpsHtml $c)</th>") }
        [void]$sb.Append('</tr>')
        foreach ($r in $Rows) {
            [void]$sb.Append('<tr>')
            foreach ($c in $Columns) { [void]$sb.Append("<td style=""border-bottom:1px solid #eee;padding:4px 10px"">$(ConvertTo-EpsHtml ([string]$r.$c))</td>") }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</table>')
    }
    if ($WhatToDo) { [void]$sb.Append("<p><b>What to do:</b> $(ConvertTo-EpsHtml $WhatToDo)</p>") }
    $link = Get-EpsMailLink -WebUrl $WebUrl -Page $ButtonPage
    if ($link -and $ButtonText) {
        # a table-cell button: Outlook draws a padded <a> without its background
        [void]$sb.Append("<table role=""presentation"" style=""border-collapse:collapse;margin:16px 0""><tr><td style=""background:#1B4FE4;border-radius:6px""><a href=""$(ConvertTo-EpsHtml $link)"" style=""display:inline-block;padding:10px 18px;color:#ffffff;font-weight:600;text-decoration:none"">$(ConvertTo-EpsHtml $ButtonText)</a></td></tr></table>")
    }
    [void]$sb.Append("<hr style=""border:0;border-top:1px solid #ddd""><p style=""font-size:12px;color:#666"">")
    [void]$sb.Append("Environment: $(ConvertTo-EpsHtml $Footer.Environment) &middot; tenant $(ConvertTo-EpsHtml $Footer.TenantName) ($(ConvertTo-EpsHtml $Footer.TenantId)) &middot; $script:EpsProductName $(ConvertTo-EpsHtml $Footer.Version)")
    $homeLink = Get-EpsMailLink -WebUrl $WebUrl
    if ($homeLink) { [void]$sb.Append(" &middot; <a href=""$(ConvertTo-EpsHtml $homeLink)"" style=""color:#0969da"">$(ConvertTo-EpsHtml $homeLink)</a>") }
    [void]$sb.Append('</p></body></html>')
    $sb.ToString()
}

function Get-EpsEnvironmentName {
    <#
      In EPS-Mail (loaded by the engine and the web app - both may read eps.Setting + eps.UplinkState; the hybrid
      worker never loads it). NAM-02 (framework alignment, Invardia 2026-11-03: Invardia is master of the environment name): the name every page
      header, alert mail and heartbeat uses. Invardia's displayName (GET /api/enrollments/environment, kept by the uplink
      in eps.UplinkState 'environment' - the last good answer, so it holds offline) wins; an install Invardia does not know
      (no install key) falls back to the local setting Platform.EnvironmentName, then to -Default. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Default = '')
    try {
        $j = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.UplinkState WHERE Name = 'environment'"
        if ($null -ne $j -and $j -isnot [DBNull] -and "$j".Trim()) { $e = "$j" | ConvertFrom-Json; if ("$($e.displayName)".Trim()) { return "$($e.displayName)".Trim() } }
    } catch { }
    try {
        $v = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = 'Platform.EnvironmentName'"
        if ($null -ne $v -and $v -isnot [DBNull] -and "$v".Trim()) { return "$v".Trim() }
    } catch { }
    $Default
}

function Get-EpsMailEnvironmentLabel {
    <#
      MAIL-ENV (framework 12.11a, corrected 2026-11-12 00:42Z - owner: "In the mail I see only prod and not <handle>"):
      the environment as every mail names it - "[<KIND>] <handle>", the display name after it only when it says more
      ("[PROD] internal (Production)"). Handle, display name and kind are Invardia's (eps.UplinkState 'environment', the
      last good answer of GET /api/enrollments/environment); an install without a key (Community without the yes) has no
      record and uses its own name (Get-EpsEnvironmentName). Only THIS install's names. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Default = '')
    $rec = $null
    try {
        $j = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.UplinkState WHERE Name = 'environment'"
        if ($null -ne $j -and $j -isnot [DBNull] -and "$j".Trim()) { $rec = "$j" | ConvertFrom-Json }
    } catch { }
    $local = if ($rec) { '' } else { Get-EpsEnvironmentName -ConnectionString $ConnectionString -Default $Default }
    ConvertTo-EpsMailEnvironmentLabel -Handle "$($rec.handle)" -DisplayName "$($rec.displayName)" -Kind "$($rec.kind)" -LocalName $local -Default $Default
}

function ConvertTo-EpsMailEnvironmentLabel {
    # PURE. MAIL-ENV: "[<KIND>] <handle>" + " (<display name>)" only when the display name differs from the handle and is
    # not just the kind ("PROD" says nothing). No handle: the display name; no Invardia record: the local name.
    param([string]$Handle, [string]$DisplayName, [string]$Kind, [string]$LocalName, [string]$Default = '')
    $tag = ConvertTo-EpsMailKindTag -Kind $Kind
    $h = "$Handle".Trim(); $d = "$DisplayName".Trim()
    $name = if ($h) { $h } elseif ($d) { $d } elseif ("$LocalName".Trim()) { "$LocalName".Trim() } else { $Default }
    $extra = if ($h -and $d -and $d -ine $h -and $d -ine $tag -and $d -ine "[$tag]" -and $d -ine "$Kind".Trim()) { " ($d)" } else { '' }
    $lab = "$name$extra"
    if ($tag -and $lab -notlike "[$tag]*") { "[$tag] $lab" } else { $lab }
}
function ConvertTo-EpsMailKindTag {
    # PURE. Invardia's environment kind -> the subject tag: prod / production -> PROD, test -> TEST, dev / development -> DEV,
    # demo -> DEMO; another plain word (2-12 letters) in capitals; anything else none.
    param([string]$Kind)
    $k = "$Kind".Trim().ToLowerInvariant()
    switch -Regex ($k) {
        '^(prod|production)$' { return 'PROD' }
        '^(dev|development)$' { return 'DEV' }
        '^[a-z]{2,12}$'       { return $k.ToUpperInvariant() }
        default               { return '' }
    }
}

$script:EpsMailTenantName = $null
function Get-EpsMailTenantName {
    # MAIL-ENV: the tenant's display name for the body - the setting Platform.TenantName, else the directory's own name
    # (Graph /organization, read once per process); '' when neither can be read. Never throws.
    param([string]$Setting)
    if ("$Setting".Trim()) { return "$Setting".Trim() }
    if ($null -ne $script:EpsMailTenantName) { return $script:EpsMailTenantName }
    $script:EpsMailTenantName = ''
    try { $o = Invoke-EpsGraph -Path 'v1.0/organization?$select=displayName'; $v = @($o.value)[0].displayName; if ("$v".Trim()) { $script:EpsMailTenantName = "$v".Trim() } } catch { }
    $script:EpsMailTenantName
}

$script:EpsTenantVerifiedDomains = $null
function Get-EpsTenantVerifiedDomains {
    # MAIL-TENANT-1 (2.1.74, review tools-pro-2 #12): the tenant's own verified domains, lower case - Graph GET /organization
    # verifiedDomains (the same read and right as the tenant name above: Organization.Read.All, granted always). Read once
    # per process (only a good answer is kept); @() when it cannot be read. Never throws.
    if ($null -ne $script:EpsTenantVerifiedDomains) { return @($script:EpsTenantVerifiedDomains) }
    try {
        $o = Invoke-EpsGraph -Path 'v1.0/organization?$select=verifiedDomains'
        $d = @(@(@($o.value)[0].verifiedDomains) | ForEach-Object { "$($_.name)".Trim().TrimEnd('.').ToLowerInvariant() } | Where-Object { $_ })
        if ($d.Count) { $script:EpsTenantVerifiedDomains = $d }
        return $d
    } catch { return @() }
}

function Test-EpsMailAddressInDomains {
    # PURE. MAIL-TENANT-1: $true when -Address is one mailbox address (local@domain) whose domain IS one of -Domains (case
    # does not matter; exact - Entra lists each verified subdomain itself, so a look-alike or a subdomain of a verified
    # domain outside the verified list is outside).
    param([AllowEmptyString()][string]$Address, [string[]]$Domains = @())
    $a = "$Address".Trim()
    if ($a -notmatch '^[^@\s<>,;]+@([^@\s<>,;]+)$') { return $false }
    $dom = $Matches[1].TrimEnd('.').ToLowerInvariant()
    [bool](@($Domains | Where-Object { "$_".Trim().TrimEnd('.').ToLowerInvariant() -eq $dom }).Count)
}

function Resolve-EpsMailFrom {
    <#
      PURE. ONE-SENDER-1 A1 (framework, agreed 2026-11-26): an update never switches an install to an unproven From.
      SMTP mode: Mail.SmtpFrom is the From the relay has already accepted (the proven From). While it holds a value that
      differs from Mail.Sender, it STAYS the From and the two keys are DRIFT (@{ Sender; ProvenFrom }); Mail.Sender becomes
      the From when its test mail passes (Send-EpsTestMail, which then clears Mail.SmtpFrom). Mail.SmtpFrom empty or equal
      to Mail.Sender: From = Mail.Sender, no drift. Graph (sharedMailbox) mode: Mail.SmtpFrom is an SMTP-only key and has
      no meaning there - From = Mail.Sender, no drift. Returns @{ From; Drift } (Drift $null = none).
    #>
    param([string]$Mode, [string]$Sender, [string]$SmtpFrom)
    $s = "$Sender".Trim(); $p = "$SmtpFrom".Trim()
    if ($Mode -eq 'smtp' -and $p -and $p -ne $s) { return [pscustomobject]@{ From = $p; Drift = [ordered]@{ Sender = $s; ProvenFrom = $p } } }
    [pscustomobject]@{ From = $s; Drift = $null }
}

function Get-EpsMailConfig {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $g = { param($n, $d) $v = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $n } -Query 'SELECT Value FROM eps.Setting WHERE Name = @n'; if ($null -eq $v -or "$v" -eq '') { $d } else { [string]$v } }
    $rcpt = & $g 'Mail.Recipients' '[]'
    $mode = & $g 'Mail.Mode' 'none'; $snd = & $g 'Mail.Sender' ''
    # ONE-SENDER-1 A1: the From an SMTP send uses - the relay's proven From (Mail.SmtpFrom) while it differs from Mail.Sender
    $sel = Resolve-EpsMailFrom -Mode $mode -Sender $snd -SmtpFrom (& $g 'Mail.SmtpFrom' '')
    [pscustomobject]@{
        # ONE-SENDER-1 A (framework, 2026-11-25): Mail.Sender is the one sender key in both modes; A1 (2026-11-26): through
        # the SMTP relay the From is FromAddress (Resolve-EpsMailFrom) - Sender keeps its meaning for the Graph probe
        Mode = $mode; Sender = $snd; ProbeMailbox = & $g 'Mail.ProbeMailbox' ''
        FromAddress = $sel.From; Drift = $sel.Drift
        # V1-PARITY P12: v1's SMTP relay (its $global:SMTPserver / SMTPPort / SMTP_UseSSL / SMTPUser); the password, when
        # the relay needs one, is a Key Vault secret the engine reads at send time - never a value in SQL. The relay's
        # SIGN-IN user name (Mail.SmtpUser) is a credential, never a From (Invardia 2026-11-25)
        SmtpServer = & $g 'Mail.SmtpServer' ''; SmtpPort = [int](& $g 'Mail.SmtpPort' '25'); SmtpUseTls = ((& $g 'Mail.SmtpUseTls' 'true') -eq 'true')
        SmtpUser = & $g 'Mail.SmtpUser' ''; SmtpCredentialSecret = & $g 'Mail.SmtpCredentialSecret' ''
        Recipients = @(try { $rcpt | ConvertFrom-Json } catch { @() }) | Where-Object { $_ }
        Environment = (Get-EpsMailEnvironmentLabel -ConnectionString $ConnectionString -Default $(if ($env:EPS_TENANT_ID) { "tenant $($env:EPS_TENANT_ID)" } else { 'Entra Policy Suite' }))
        TenantId = $env:EPS_TENANT_ID; TenantName = (Get-EpsMailTenantName -Setting (& $g 'Platform.TenantName' ''))
        ConnectionString = $ConnectionString   # the send right's check before the first send records its result here
    }
}

function ConvertTo-EpsMailErrorCode {
    # PURE. A failed send's reason -> ONE closed code for the heartbeat (never the text): denied | not-found | throttled |
    # server | auth | network | other
    param([string]$Reason)
    $r = "$Reason"
    if ($r -match '(?i)-> (401|403)\b|Access is denied|AccessDenied|Authorization_RequestDenied') { return 'denied' }
    if ($r -match '(?i)-> 404\b|ResourceNotFound|MailboxNotEnabled|InvalidUser|not a mailbox') { return 'not-found' }
    if ($r -match '(?i)-> 429\b|throttl|ApplicationThrottled') { return 'throttled' }
    if ($r -match '(?i)-> 5\d\d\b') { return 'server' }
    # a relay that refuses the From (5.7.1 / "send as") is a refusal of the address, not of the sign-in
    if ($r -match '(?i)\b5\.7\.1\b|send as|SendAsDenied') { return 'denied' }
    if ($r -match '(?i)\b5\.7\.\d+\b|authentication|Key Vault secret') { return 'auth' }
    if ($r -match '(?i)timed? ?out|connection|resolve|unreachable|No such host') { return 'network' }
    'other'
}

function Save-EpsMailOutcome {
    # 2.1.74 (Invardia 2026-11-26: the heartbeat's Mail block must reflect EVERY send, not only the alert mails): the
    # outcome of one send in eps.UplinkState - 'mail.lastSent' (the time) or 'mail.lastFailed' ({ at, code }). A send
    # that was not attempted (mail off, no sender, no recipient) records nothing. Never throws.
    param([string]$ConnectionString, [bool]$Sent, [string]$Reason)
    if (-not $ConnectionString) { return }
    try {
        $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $name = if ($Sent) { 'mail.lastSent' } else { 'mail.lastFailed' }
        $val = if ($Sent) { $now } else { ([ordered]@{ at = $now; code = (ConvertTo-EpsMailErrorCode $Reason) } | ConvertTo-Json -Compress) }
        [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ n = $name; v = $val } -Query 'MERGE eps.UplinkState WITH (HOLDLOCK) AS t USING (SELECT @n AS Name) AS s ON t.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (@n, @v);')
    } catch { }
}

function Send-EpsMail {
    # One mail, its outcome recorded (Save-EpsMailOutcome). NEVER throws; returns @{ Sent; Reason } as Send-EpsMailCore.
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Importance = 'normal', [object[]]$Attachments = @(), [int]$MaxAttachmentBytes = 3000000)
    $r = Send-EpsMailCore -Config $Config -Subject $Subject -Html $Html -Importance $Importance -Attachments $Attachments -MaxAttachmentBytes $MaxAttachmentBytes
    $tried = $r.Sent -or ("$($r.Reason)" -notmatch '^(Mail\.Mode is |Mail\.Sender is not set|Mail\.Recipients is empty|Mail\.SmtpServer is not set)')
    if ($tried) { Save-EpsMailOutcome -ConnectionString "$($Config.ConnectionString)" -Sent ([bool]$r.Sent) -Reason "$($r.Reason)" }
    $r
}

function Send-EpsMailCore {
    # One mail. NEVER throws (an alert that cannot be mailed must not fail the job): returns @{ Sent; Reason }.
    # Mode none, no sender or no recipient = not sent, and said why.
    # -Attachments: @{ Name; Bytes; ContentType } - inline (Graph sendMail takes ~3 MB in all); a larger one is left out
    # and the mail says so (the GUI has the export).
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Importance = 'normal', [object[]]$Attachments = @(), [int]$MaxAttachmentBytes = 3000000)
    if ($Config.Mode -eq 'smtp') { return (Send-EpsSmtpMail -Config $Config -Subject $Subject -Html $Html -Importance $Importance -Attachments $Attachments -MaxAttachmentBytes $MaxAttachmentBytes) }
    if ($Config.Mode -ne 'sharedMailbox') { return @{ Sent = $false; Reason = "Mail.Mode is '$($Config.Mode)' - no mail is sent (set it up: Initialize-EpsMailSender.ps1)" } }
    if (-not $Config.Sender) { return @{ Sent = $false; Reason = 'Mail.Sender is not set' } }
    if (-not @($Config.Recipients).Count) { return @{ Sent = $false; Reason = 'Mail.Recipients is empty' } }
    # ONE-SENDER-1 D: before this process's first send, the send right is checked once and recorded (it never stops a mail)
    # (in an engine job only - EPS_JOB is set by the install on every job; a test or a script sends without it)
    if ($env:EPS_JOB -and $Config.ConnectionString -and -not $script:EpsMailCheckedThisProcess) { $script:EpsMailCheckedThisProcess = $true; try { [void](Invoke-EpsMailRestrictionCheck -ConnectionString $Config.ConnectionString -Config $Config) } catch { } }
    $att = @(); $left = @()
    foreach ($a in $Attachments) {
        if (@($a.Bytes).Count -gt $MaxAttachmentBytes) { $left += $a.Name; continue }
        $att += @{ '@odata.type' = '#microsoft.graph.fileAttachment'; name = [string]$a.Name; contentType = [string]$a.ContentType; contentBytes = [Convert]::ToBase64String([byte[]]$a.Bytes) }
    }
    if ($left) { $Html += "<p><i>$([System.Net.WebUtility]::HtmlEncode(($left -join ', '))) is too large to attach - export it from the web app.</i></p>" }
    $msg = @{ message = @{ subject = $Subject; importance = $Importance; body = @{ contentType = 'HTML'; content = $Html }
                           toRecipients = @(foreach ($r in $Config.Recipients) { @{ emailAddress = @{ address = [string]$r } } }) }; saveToSentItems = $true }
    if ($att) { $msg.message.attachments = $att }
    try {
        [void](Invoke-EpsGraph -Method POST -Path "v1.0/users/$([uri]::EscapeDataString($Config.Sender))/sendMail" -Body $msg)
        @{ Sent = $true; Reason = "sent to $(@($Config.Recipients).Count) recipient(s)" }
    } catch { @{ Sent = $false; Reason = "sendMail failed: $($_.Exception.Message)" } }
}

function Get-EpsSmtpSecret {
    # the SMTP relay's password from a Key Vault secret (Mail.SmtpCredentialSecret = its https://<vault>.vault.azure.net/
    # secrets/<name> address), read as the engine's identity at send time - it needs 'Key Vault Secrets User' on that
    # secret. Never stored, logged or returned in a reason. @{ Ok; Value; Reason }.
    param([Parameter(Mandatory)][string]$SecretUri)
    if ($SecretUri -notmatch $script:EpsSmtpSecretPattern) { return @{ Ok = $false; Reason = 'Mail.SmtpCredentialSecret is not a Key Vault secret address (https://<vault>.vault.azure.net/secrets/<name>)' } }
    try {
        $r = & $script:EpsHttp 'GET' ("$($SecretUri.TrimEnd('/'))?api-version=7.4") @{ Authorization = "Bearer $(Get-EpsToken -Resource 'https://vault.azure.net')" } $null
        if ($r.Status -ne 200) { return @{ Ok = $false; Reason = "the Key Vault secret could not be read ($($r.Status)) - the engine identity needs 'Key Vault Secrets User' on it" } }
        $v = "$((($r.Body | ConvertFrom-Json).value))"
        if (-not $v) { return @{ Ok = $false; Reason = 'the Key Vault secret is empty' } }
        @{ Ok = $true; Value = $v }
    } catch { @{ Ok = $false; Reason = 'the Key Vault secret could not be read (the engine identity needs ''Key Vault Secrets User'' on it)' } }
}
$script:EpsSmtpSecretPattern = '^https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/secrets/[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?/?$'

# a test replaces the sender: @{ Server; Port; Tls; From; User; Password; To; Subject; Html; Importance; Attachments }
$script:EpsSmtpSend = {
    param($m)
    $msg = [System.Net.Mail.MailMessage]::new()
    try {
        $msg.From = [System.Net.Mail.MailAddress]::new($m.From)
        foreach ($t in $m.To) { $msg.To.Add([System.Net.Mail.MailAddress]::new([string]$t)) }
        $msg.Subject = $m.Subject; $msg.Body = $m.Html; $msg.IsBodyHtml = $true; $msg.BodyEncoding = [Text.Encoding]::UTF8; $msg.SubjectEncoding = [Text.Encoding]::UTF8
        $msg.Priority = if ($m.Importance -eq 'high') { [System.Net.Mail.MailPriority]::High } else { [System.Net.Mail.MailPriority]::Normal }
        foreach ($a in $m.Attachments) { $msg.Attachments.Add([System.Net.Mail.Attachment]::new([IO.MemoryStream]::new([byte[]]$a.Bytes), [string]$a.Name, [string]$a.ContentType)) }
        $c = [System.Net.Mail.SmtpClient]::new($m.Server, [int]$m.Port)
        try {
            $c.EnableSsl = [bool]$m.Tls; $c.Timeout = 60000
            if ($m.Password) { $c.UseDefaultCredentials = $false; $c.Credentials = [System.Net.NetworkCredential]::new($m.User, $m.Password) }
            $c.Send($msg)
        } finally { $c.Dispose() }
    } finally { $msg.Dispose() }
}

function Send-EpsSmtpMail {
    # V1-PARITY P12 (v1's Send-MailMessage through its relay): Mail.Mode = smtp. From = the config's FromAddress
    # (ONE-SENDER-1 A1, Resolve-EpsMailFrom: the relay's proven From while it differs from Mail.Sender, else Mail.Sender).
    # Anonymous when no credential secret is set (v1's Mail_SendAnonymous), else Mail.SmtpUser + the Key Vault secret's
    # password. TLS (STARTTLS) by Mail.SmtpUseTls. NEVER throws; the password never appears in a reason. @{ Sent; Reason }.
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Importance = 'normal', [object[]]$Attachments = @(), [int]$MaxAttachmentBytes = 3000000)
    if (-not $Config.SmtpServer) { return @{ Sent = $false; Reason = 'Mail.SmtpServer is not set' } }
    $from = if ("$($Config.FromAddress)".Trim()) { "$($Config.FromAddress)".Trim() } else { "$($Config.Sender)" }
    if (-not $from) { return @{ Sent = $false; Reason = 'Mail.Sender is not set (Initialize-EpsMailSender.ps1 -SmtpRelay sets it)' } }
    if (-not @($Config.Recipients).Count) { return @{ Sent = $false; Reason = 'Mail.Recipients is empty' } }
    $pw = $null
    if ($Config.SmtpCredentialSecret) {
        if (-not $Config.SmtpUser) { return @{ Sent = $false; Reason = 'Mail.SmtpUser is not set - the relay credential needs its user name (Initialize-EpsMailSender.ps1 -SmtpRelay -SmtpUser)' } }
        $s = Get-EpsSmtpSecret -SecretUri $Config.SmtpCredentialSecret; if (-not $s.Ok) { return @{ Sent = $false; Reason = $s.Reason } }; $pw = $s.Value
    }
    $att = @(); $left = @()
    foreach ($a in $Attachments) { if (@($a.Bytes).Count -gt $MaxAttachmentBytes) { $left += $a.Name } else { $att += $a } }
    if ($left) { $Html += "<p><i>$([System.Net.WebUtility]::HtmlEncode(($left -join ', '))) is too large to attach - export it from the web app.</i></p>" }
    try {
        & $script:EpsSmtpSend @{ Server = $Config.SmtpServer; Port = $(if ($Config.SmtpPort) { $Config.SmtpPort } else { 25 }); Tls = [bool]$Config.SmtpUseTls; From = $from; User = $Config.SmtpUser; Password = $pw
                                 To = @($Config.Recipients); Subject = $Subject; Html = $Html; Importance = $Importance; Attachments = $att }
        @{ Sent = $true; Reason = "sent to $(@($Config.Recipients).Count) recipient(s) through $($Config.SmtpServer)" }
    } catch {
        $e = "$($_.Exception.InnerException.Message)"; if (-not $e) { $e = "$($_.Exception.Message)" }
        if ($pw) { $e = $e.Replace($pw, '***') }
        @{ Sent = $false; Reason = "SMTP send through $($Config.SmtpServer) failed: $e" }
    }
}

# ---- ONE-SENDER-1 D (framework, 2026-11-25 - SI's Graph probe, NO new right): is the engine's send right the scoped one
# for exactly Mail.Sender? Two sendMail calls WITHOUT a recipient (nothing can be delivered): as the sender it must be
# ALLOWED, as the probe mailbox DENIED, and the engine's token must not hold the tenant-wide Graph Mail.Send. Once a day
# (the Backup job) and before a process's first send. The result: eps.UplinkState 'mail.restriction' (JSON) - the
# heartbeat reads it. It only reads; it never stops a mail.
function Get-EpsMailProbeVerdict {
    # PURE (SI's Get-SIMailProbeVerdict). allowed = 202, or 400 on the missing recipient (past the authorization);
    # denied = 401 / 403; not-found = 404 / no such mailbox; error = anything else
    param([int]$StatusCode, [string]$Body)
    $code = ''; $msg = "$Body"; try { $e = ($Body | ConvertFrom-Json).error; $code = "$($e.code)"; $msg = "$($e.message)" } catch { }
    if ($StatusCode -eq 202) { return 'allowed' }
    if ($StatusCode -eq 400 -and ($code -match '(?i)InvalidRecipients' -or $msg -match '(?i)recipient')) { return 'allowed' }
    if ($StatusCode -in 401, 403 -or $code -match '(?i)AccessDenied|Authorization_RequestDenied') { return 'denied' }
    if ($StatusCode -eq 404 -or $code -match '(?i)InvalidUser|ResourceNotFound|MailboxNotEnabled') { return 'not-found' }
    'error'
}

function Get-EpsMailRestrictionVerdict {
    <#
      PURE. @{ State = verified | pending | failed; Detail }:
        verified  may send as the sender; may NOT as the probe mailbox (or no probe given); no tenant-wide Mail.Send
        pending   may not send as the sender YET - the scoped right is missing or not active yet (Exchange: up to 2 hours)
        failed    the sender is no mailbox, the right is not restricted (the probe mailbox is allowed, or the token holds
                  the tenant-wide Mail.Send), or the check said nothing
    #>
    param([bool]$TokenHasMailSend, [string]$Self, [string]$Other, [string]$Sender, [string]$ProbeMailbox)
    $r = { param($s, $d) [pscustomobject]@{ State = $s; Detail = $d } }
    if ($Self -eq 'not-found') { return (& $r 'failed' "the sender $Sender is not a mailbox") }
    if ($Self -eq 'denied') { return (& $r 'pending' "the engine may not send as $Sender yet - its 'Application Mail.Send' right for it is missing or not active yet (Exchange takes up to 2 hours); run Initialize-EpsMailSender.ps1") }
    if ($Self -ne 'allowed') { return (& $r 'failed' "the send right on $Sender could not be checked") }
    if ($Other -eq 'allowed') { return (& $r 'failed' "NOT restricted: the engine could also send as $ProbeMailbox$(if ($TokenHasMailSend) { ' - it holds the tenant-wide Graph Mail.Send; run Initialize-EpsMailSender.ps1 (it removes it)' })") }
    if ($TokenHasMailSend) { return (& $r 'failed' 'NOT restricted: the engine holds the tenant-wide Graph Mail.Send - run Initialize-EpsMailSender.ps1 (it removes it)') }
    $d = "restricted to $Sender (Exchange RBAC for Applications; no tenant-wide Mail.Send)"
    if ($Other -eq 'denied') { $d += "; sending as $ProbeMailbox is refused" } elseif ($ProbeMailbox -and $Other) { $d += "; the probe mailbox $ProbeMailbox could not be used ($Other)" }
    & $r 'verified' $d
}

function Test-EpsTokenHasMailSend {
    # PURE. Whether a Graph access token's roles claim holds the tenant-wide Mail.Send
    param([string]$Token)
    try { $p = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }; return [bool](@(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).roles) -contains 'Mail.Send') } catch { $false }
}

function Invoke-EpsMailRestrictionCheck {
    # The probe as the engine (sharedMailbox mode), stored in eps.UplinkState 'mail.restriction'. Never throws; returns
    # @{ State; Detail; Sender; ProbeMailbox; CheckedUtc } (State 'not-applicable' when mail is not sent through Graph).
    # -NoStore: the MailProbe job's check of a CANDIDATE sender during a change (it must not overwrite the current one's)
    param([Parameter(Mandatory)][string]$ConnectionString, $Config, [switch]$NoStore)
    $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if (-not $Config) { $Config = try { Get-EpsMailConfig -ConnectionString $ConnectionString } catch { $null } }
    $out = [ordered]@{ State = 'not-applicable'; Detail = ''; Sender = "$($Config.Sender)"; ProbeMailbox = "$($Config.ProbeMailbox)"; Mode = "$($Config.Mode)"; CheckedUtc = $now
                       # ONE-SENDER-1 A1: the From mail goes out with, and the drift of the two SMTP keys (@{ Sender; ProvenFrom } or null)
                       From = $(if ("$($Config.FromAddress)".Trim()) { "$($Config.FromAddress)".Trim() } else { "$($Config.Sender)" }); Drift = $(if ($Config.Drift) { $Config.Drift } else { $null }) }
    if ($out.Drift) { $out.Detail = "the relay's proven From $($out.Drift.ProvenFrom) stays the From; the saved sender $($out.Drift.Sender) becomes the From when its test mail passes (Settings > Alert mail > Send a test mail)" }
    if ($Config -and $Config.Mode -eq 'sharedMailbox' -and $Config.Sender) {
        try {
            $tok = Get-EpsToken -Resource 'https://graph.microsoft.com'
            $body = @{ message = @{ subject = 'Entra Policy Suite permission check (never delivered: no recipient)'; body = @{ contentType = 'Text'; content = '-' }; toRecipients = @() }; saveToSentItems = $false } | ConvertTo-Json -Depth 5 -Compress
            $ask = { param($box) $x = & $script:EpsHttp 'POST' "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($box))/sendMail" @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json' } $body; Get-EpsMailProbeVerdict -StatusCode ([int]$x.Status) -Body "$($x.Body)" }
            $self = & $ask $Config.Sender
            $other = if ($self -eq 'allowed' -and $Config.ProbeMailbox -and $Config.ProbeMailbox -ne $Config.Sender) { & $ask $Config.ProbeMailbox } else { '' }
            $v = Get-EpsMailRestrictionVerdict -TokenHasMailSend (Test-EpsTokenHasMailSend $tok) -Self $self -Other $other -Sender $Config.Sender -ProbeMailbox $Config.ProbeMailbox
            $out.State = $v.State; $out.Detail = $v.Detail
        } catch { $out.State = 'failed'; $out.Detail = "the send right could not be checked: $($_.Exception.Message)" }
    }
    if (-not $NoStore) { try {
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ v = (ConvertTo-Json $out -Compress) } -Query "MERGE eps.UplinkState AS d USING (SELECT N'mail.restriction' AS Name) AS s ON d.Name = s.Name WHEN MATCHED THEN UPDATE SET Value = @v, UpdatedAtUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (N'mail.restriction', @v);" | Out-Null
    } catch { } }
    # MAIL-RETRY (2.1.74): a passed probe of the CURRENT sender = mail works again - the unsent Support fix notices go at once
    # (never for a candidate's -NoStore probe; never inside a resend that is already sending)
    if (-not $NoStore -and $out.State -eq 'verified' -and -not $script:EpsNoticeResendActive) {
        $nr = Invoke-EpsSupportNoticeResend -ConnectionString $ConnectionString
        if ($nr.Lines.Count) { $out.NoticeResend = (@($nr.Lines) -join '; ') }
    }
    [pscustomobject]$out
}

function Get-EpsMailDrift {
    # PURE. ONE-SENDER-1 point 4: drift = the last check was not 'verified', or it checked another sender than the one key
    # holds now (the setting changed since, or a component used its own copy). @{ Drift; Reason }
    # ONE-SENDER-1 A1 (smtp mode): drift = the relay's proven From (-ProvenFrom, the Mail.SmtpFrom key) holds a value that
    # differs from the sender key - that proven From stays the From until the sender's test mail passes
    param($Check, [string]$Sender, [string]$Mode, [string]$ProvenFrom = '')
    if ($Mode -eq 'smtp') {
        $sel = Resolve-EpsMailFrom -Mode $Mode -Sender $Sender -SmtpFrom $ProvenFrom
        if ($sel.Drift) { return @{ Drift = $true; Reason = "the relay's proven From $($sel.Drift.ProvenFrom) stays the From; the sender key is $($sel.Drift.Sender)" } }
        return @{ Drift = $false; Reason = '' }
    }
    if ($Mode -ne 'sharedMailbox') { return @{ Drift = $false; Reason = '' } }
    if (-not $Check) { return @{ Drift = $true; Reason = 'the send right was never checked' } }
    if ("$($Check.Sender)" -ne $Sender) { return @{ Drift = $true; Reason = "the last check was for $($Check.Sender), the sender is $Sender" } }
    if ("$($Check.State)" -ne 'verified') { return @{ Drift = $true; Reason = "$($Check.State): $($Check.Detail)" } }
    @{ Drift = $false; Reason = '' }
}

function Send-EpsTestMail {
    # "Send a test mail" (Settings > Alert mail): proves the sender works AS THE ENGINE'S IDENTITY - the scoped
    # Application Mail.Send - not as the person who set it up. @{ Sent; Reason }; never throws.
    # ONE-SENDER-1 A1 (smtp mode with drift): the test mail is sent FROM the saved Mail.Sender. It passes = the relay accepts
    # it: Mail.Sender is then proven, Mail.SmtpFrom is cleared (journaled + audited) and Mail.Sender is the From of every
    # mail. It fails = nothing changes; the proven From stays the From. @{ Sent; Reason; Promoted }
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$RequestedBy, [string]$Version = '2.0.0')
    $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
    $drift = if ($cfg.Mode -eq 'smtp' -and $cfg.Drift -and "$($cfg.Drift.Sender)".Trim()) { $cfg.Drift }
    if ($drift) { $cfg.FromAddress = "$($drift.Sender)".Trim() }
    # MAIL-3 subject + the MAIL-2 body like every other mail (was a hand-made '[EntraPolicySuite] <env>: test mail')
    $how = if ($cfg.Mode -eq 'smtp') { "through the SMTP relay $($cfg.SmtpServer) as $(if ("$($cfg.FromAddress)".Trim()) { $cfg.FromAddress } else { $cfg.Sender })" } else { "as $($cfg.Sender)" }
    $dSay = if ($drift) { " It comes from the saved sender $($drift.Sender): when the relay accepts it, $($drift.Sender) is the From of every mail (until now $($drift.ProvenFrom))." } else { '' }
    $html = New-EpsMailBody -Summary "This is a test mail from Entra Policy Suite $Version ($($cfg.Environment)), sent by the engine $how. Requested by $RequestedBy at $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC. Tamper alerts and every other mail come the same way.$dSay" `
        -ButtonText 'Open the mail settings' -ButtonPage 'settings' -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
    $r = Send-EpsMail -Config $cfg -Subject (New-EpsMailSubject -Environment $cfg.Environment -What 'Test mail') -Html $html
    $out = @{ Sent = [bool]$r.Sent; Reason = "$($r.Reason)"; Promoted = $false }
    if (-not $drift) { return $out }
    if (-not $r.Sent) { $out.Reason += "; the proven From $($drift.ProvenFrom) stays the From"; return $out }
    # LOW A#3 (2.1.74 review): the test-mail request runs on its own path before the signed-request check. The promotion
    # it can make is narrow on purpose - it only clears Mail.SmtpFrom after the relay accepted the Mail.Sender an Admin
    # already saved, with the same mode and relay server, all held under one lock
    $p = Complete-EpsMailFromPromotion -ConnectionString $ConnectionString -Sender "$($drift.Sender)" -ProvenFrom "$($drift.ProvenFrom)" -RequestedBy $RequestedBy -SmtpServer "$($cfg.SmtpServer)"
    $out.Promoted = [bool]$p.Promoted; $out.Reason += "; $($p.Reason)"
    $out
}

function Complete-EpsMailFromPromotion {
    <#
      ONE-SENDER-1 A1: the saved Mail.Sender passed its test mail through the relay - it is now the proven From. Clears
      Mail.SmtpFrom in one transaction, only while BOTH keys still hold what the test used (a change in between = nothing
      cleared; the next test mail proves the new value), with the setting journal row (eps.ConfigChange, Source 'test-mail')
      and an audit event (setting.change). The engine's own rights (eps.Setting UPDATE, eps.ConfigChange INSERT, eps.AuditEvent
      INSERT) - no new right. Never throws: @{ Promoted; Reason }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sender, [Parameter(Mandatory)][string]$ProvenFrom, [string]$RequestedBy, [string]$SmtpServer = '')
    $by = 'engine (test mail)'
    try {
        $row = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ s = $Sender; p = $ProvenFrom; a = $by; v = $SmtpServer } -Query @'
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @n INT = 0;
IF EXISTS (SELECT 1 FROM eps.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'Mail.Sender' AND LTRIM(RTRIM(CONVERT(NVARCHAR(400), Value))) = @s)
   AND EXISTS (SELECT 1 FROM eps.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'Mail.Mode' AND CONVERT(NVARCHAR(40), Value) = N'smtp')
   AND (@v = N'' OR EXISTS (SELECT 1 FROM eps.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'Mail.SmtpServer' AND LTRIM(RTRIM(CONVERT(NVARCHAR(400), Value))) = @v))
BEGIN
    UPDATE eps.Setting SET Value = N'', UpdatedAtUtc = SYSUTCDATETIME(), UpdatedBy = @a WHERE Name = N'Mail.SmtpFrom' AND LTRIM(RTRIM(CONVERT(NVARCHAR(400), Value))) = @p;
    SET @n = @@ROWCOUNT;
    IF @n > 0
        INSERT INTO eps.ConfigChange (Actor, Entity, EntityKey, Action, BeforeJson, AfterJson, Source)
        VALUES (@a, 'Setting', N'Mail.SmtpFrom', 'Update', (SELECT @p AS value FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), (SELECT N'' AS value FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), N'test-mail');
END
COMMIT;
SELECT @n AS Cleared;
'@)[0]
        if ([int]"$($row.Cleared)" -lt 1) { return @{ Promoted = $false; Reason = "the mail keys changed during the test - the From is as before; send the test mail again" } }
        $aud = $false
        if (Get-Command Write-EpsAuditEvent -ErrorAction SilentlyContinue) {
            $aud = [bool](Write-EpsAuditEvent -ConnectionString $ConnectionString -Action 'setting.change' -Actor $by -ActorSource 'job' -Target 'Setting|Mail.SmtpFrom' `
                -Reason "ONE-SENDER-1 A1: the test mail $(if ($RequestedBy) { "requested by $RequestedBy " })passed from the saved sender $Sender" -Before @{ value = $ProvenFrom } -After @{ value = ''; from = $Sender })
        }
        # review B LOW 4: the change is journaled in the same transaction; an audit row that could not be written is said
        @{ Promoted = $true; Reason = "$Sender is now the From of every mail (it replaces $ProvenFrom)$(if (-not $aud) { ' - the audit trail entry could not be written; the configuration journal has it' })" }
    } catch { @{ Promoted = $false; Reason = "the From is as before ($ProvenFrom): the switch to $Sender could not be saved ($($_.Exception.Message)) - send the test mail again" } }
}

function Send-EpsSupportActionMail {
    <#
      §12.30 / §12.32 (owner 2026-11-16): every change the Invardia Support app makes here (a catalogued fix, on a ticket) is
      MAILED to the install's admins (Mail.Recipients): what, the ticket, the result. Sent by the engine when it takes the
      Support app's request. Only for the ENROLLED Support app (Security.SupportApp); any other requester = nothing sent.
      Never throws: @{ Sent; Reason }.
    #>
    # -At (MAIL-RETRY 2.1.74): when the fix was applied - a notice sent again names the time of the fix, not of the resend
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$RequestedBy, [string]$What, [string]$Reason, [string]$Result, [string]$Version = '2.0.0', [datetime]$At = [datetime]::UtcNow)
    try {
        $sup = "$(Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = N'Security.SupportApp'")".Trim().ToLowerInvariant()
        if (-not $sup -or "$RequestedBy".ToLowerInvariant() -ne "app:$sup") { return @{ Sent = $false; Reason = 'not the Support app' } }
        $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
        $ticket = if ("$Reason" -match '\bSUP-\d{4}-\d{5}\b') { $Matches[0] } else { 'no ticket id' }
        $html = New-EpsMailBody -Summary "Invardia Support applied a fix in Entra Policy Suite on ticket $ticket. It can only apply a fix Entra Policy Suite offers for a reported failure, through the same checks and audit trail as a person." `
            -Rows @([pscustomobject]@{ Ticket = $ticket; Fix = "$What"; Result = "$Result"; When = $(if ($At.Kind -eq 'Local') { $At.ToUniversalTime() } else { $At }).ToString('yyyy-MM-dd HH:mm') + ' UTC' }) -Columns 'Ticket', 'Fix', 'Result', 'When' `
            -WhatToDo 'Nothing, if you asked for it. If you did not, remove the Support app''s assignment (Set-EpsApiAuth.ps1 -SupportApp -Remove) and contact Invardia. The audit trail shows every call.' -ButtonText 'Open the audit trail' -ButtonPage 'audit' `
            -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
        Send-EpsMail -Config $cfg -Subject (New-EpsMailSubject -Environment $cfg.Environment -What "Invardia Support applied a fix ($ticket)") -Html $html
    } catch { @{ Sent = $false; Reason = "not mailed: $($_.Exception.Message)" } }
}

# ---- MAIL-RETRY (2.1.74, Invardia 2026-11-26): an unsent Support fix notice is sent again ------------------------------
# The record of a Support app action is its eps.JobRequest row (Job Config, RequestedBy app:<the Support app>) - the audit
# trail is append-only (DENY UPDATE) and cannot be marked. NoticeSentAtUtc is set only when the notice went out. The tick
# sends an unsent one again once an hour, and at once after a passed mail probe (Invoke-EpsMailRestrictionCheck verified:
# the Backup job's daily check, the check before a process's first send). After 7 days it is given up: counted in the
# heartbeat (Mail.noticesGivenUp + Mail.noticesGivenUpOldestUtc) and shown on the Overview's Invardia support section.
$script:EpsSupportNoticeDays = 7
$script:EpsNoticeResendActive = $false

function Split-EpsSupportNoticeBacklog {
    # PURE. Unsent notices (rows with UpdatedAtUtc = when the fix was applied) -> @{ Due = under -Days old; GivenUp = older }
    param([object[]]$Rows = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$Days = $script:EpsSupportNoticeDays)
    $r = @($Rows | Where-Object { $_ -and $_.UpdatedAtUtc -and $_.UpdatedAtUtc -isnot [DBNull] })
    $cut = $NowUtc.AddDays(-$Days)
    @{ Due = @($r | Where-Object { [datetime]$_.UpdatedAtUtc -gt $cut }); GivenUp = @($r | Where-Object { [datetime]$_.UpdatedAtUtc -le $cut }) }
}

function Set-EpsSupportNoticeSent {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RequestId)
    [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $RequestId } -Query 'UPDATE eps.JobRequest SET NoticeSentAtUtc = SYSUTCDATETIME(), NoticeClaimAtUtc = NULL WHERE RequestId = @id AND NoticeSentAtUtc IS NULL')
}

function Request-EpsSupportNoticeClaim {
    # 2.1.75 review L3: $true when THIS caller claimed the unsent notice (no claim yet, or one older than 10 min); $false = another
    # sender has it, or it was sent meanwhile. One UPDATE, so two senders can never both get it.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][guid]$RequestId)
    1 -eq [int](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = $RequestId } -Query 'UPDATE eps.JobRequest SET NoticeClaimAtUtc = SYSUTCDATETIME() WHERE RequestId = @id AND NoticeSentAtUtc IS NULL AND (NoticeClaimAtUtc IS NULL OR NoticeClaimAtUtc < DATEADD(MINUTE, -10, SYSUTCDATETIME()))')
}

function Get-EpsSupportNoticeState {
    # the given-up notices (unsent, older than 7 days) of the enrolled Support app: @{ GivenUp; OldestUtc } - for the
    # heartbeat. Never throws ($null when it cannot be read).
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$Days = $script:EpsSupportNoticeDays)
    try {
        $row = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ d = $Days } -Query @'
SELECT COUNT(*) AS GivenUp, MIN(q.UpdatedAtUtc) AS OldestUtc FROM eps.JobRequest q
WHERE q.Job = N'Config' AND q.NoticeSentAtUtc IS NULL AND q.Status IN (N'Done', N'Failed', N'Refused') AND q.UpdatedAtUtc <= DATEADD(DAY, -@d, SYSUTCDATETIME())
  AND q.RequestedBy = N'app:' + (SELECT TOP (1) LOWER(LTRIM(RTRIM(CONVERT(NVARCHAR(400), s.Value)))) FROM eps.Setting s WHERE s.Name = N'Security.SupportApp')
'@)[0]
        @{ GivenUp = [int]$row.GivenUp; OldestUtc = $(if ($row.OldestUtc -is [DBNull]) { $null } else { $row.OldestUtc }) }
    } catch { $null }
}

function Invoke-EpsSupportNoticeResend {
    <#
      Sends again the Support app's fix notices that were not sent and are under 7 days old (the mail rebuilt from the
      request row: the fix, the ticket in its reason, the result and when it was applied - the same mail). Never throws;
      never runs inside itself (a send's own first-send check would start it again). @{ Resent; Failed; Lines }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version = '', [datetime]$NowUtc = [datetime]::UtcNow)
    # the footer's version: the caller's, else the VERSION file this code shipped with (the probe's call knows none)
    if (-not $Version) { $Version = try { ([IO.File]::ReadAllText((Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'))).Trim() } catch { '2.0.0' } }
    $out = @{ Resent = 0; Failed = 0; Claimed = 0; Lines = [System.Collections.Generic.List[string]]::new() }
    if ($script:EpsNoticeResendActive) { return $out }
    $script:EpsNoticeResendActive = $true
    try {
        $sup = "$(Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.Setting WHERE Name = N'Security.SupportApp'")".Trim().ToLowerInvariant()
        if (-not $sup) { return $out }
        $rows = @(Invoke-EpsSql -ConnectionString $ConnectionString -Parameters @{ a = "app:$sup"; d = ($script:EpsSupportNoticeDays + 1) } -Query @'
SELECT TOP (50) RequestId, RequestedBy, Scope, Status, StatusText, UpdatedAtUtc FROM eps.JobRequest
WHERE Job = N'Config' AND RequestedBy = @a AND NoticeSentAtUtc IS NULL AND Status IN (N'Done', N'Failed', N'Refused') AND UpdatedAtUtc > DATEADD(DAY, -@d, SYSUTCDATETIME())
ORDER BY UpdatedAtUtc
'@)
        $b = Split-EpsSupportNoticeBacklog -Rows $rows -NowUtc $NowUtc
        foreach ($x in $b.Due) {
            # 2.1.75 review L3: claim the row first - the tick and a passed probe (the Backup job) may resend at the same time;
            # only the sender whose UPDATE took it sends (a claim older than 10 min is taken over: a sender that died)
            if (-not (Request-EpsSupportNoticeClaim -ConnectionString $ConnectionString -RequestId ([guid]$x.RequestId))) { $out.Claimed++; $out.Lines.Add("Support action notice of request $($x.RequestId): another sender has it - not sent here"); continue }
            $sc = try { "$($x.Scope)" | ConvertFrom-Json } catch { $null }
            $txt = if ($x.StatusText -is [DBNull]) { '' } else { "$($x.StatusText)" }
            $m = try { Send-EpsSupportActionMail -ConnectionString $ConnectionString -RequestedBy "$($x.RequestedBy)" -What "$(if ($sc) { "$($sc.method) $($sc.path)" })" -Reason "$(if ($sc.body) { $sc.body.reason })" -Result "$($x.Status) - $txt" -Version $Version -At ([datetime]$x.UpdatedAtUtc) } catch { @{ Sent = $false; Reason = "$($_.Exception.Message)" } }
            if ($m.Sent) { Set-EpsSupportNoticeSent -ConnectionString $ConnectionString -RequestId ([guid]$x.RequestId); $out.Resent++ }
            else { try { [void](Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Parameters @{ id = [guid]$x.RequestId } -Query 'UPDATE eps.JobRequest SET NoticeClaimAtUtc = NULL WHERE RequestId = @id AND NoticeSentAtUtc IS NULL') } catch { }; $out.Failed++ }
            $out.Lines.Add("Support action notice of request $($x.RequestId) sent again: $(if ($m.Sent) { 'sent' } else { "NOT sent ($($m.Reason))" })")
        }
    } catch { $out.Lines.Add("the unsent Support action notices could not be sent again: $($_.Exception.Message)") }
    finally { $script:EpsNoticeResendActive = $false }
    $out
}

function Send-EpsTamperAlert {
    <#
    .SYNOPSIS
        The tamper monitor's alert (DESIGN §5.7a): ONE mail for the OPEN events of a run that were not alerted yet, the
        HIGH ones first, each with what it means; the events are then marked AlertedAtUtc (an event is alerted once, a
        failed send is tried again by the next run). Allowed writers' changes are never alerted.
        Returns @{ Events; Sent; Reason }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Version = '2.0.0')
    $open = @(Invoke-EpsSql -ConnectionString $ConnectionString -Query "SELECT * FROM eps.TamperEvent WHERE Status = 'Open' AND AlertedAtUtc IS NULL ORDER BY CASE Severity WHEN 'High' THEN 0 ELSE 1 END, FoundAtUtc")
    if (-not $open.Count) { return @{ Events = 0; Sent = $false; Reason = 'nothing new to alert' } }
    $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
    $high = @($open | Where-Object Severity -eq 'High').Count
    $what = "$($open.Count) change(s) to watched tags not made by the engine$(if ($high) { ", $high HIGH" })"
    $subject = New-EpsMailSubject -Environment $cfg.Environment -What $what -Severity 'Action needed'
    $rows = @(foreach ($e in $open) { [pscustomobject]@{ Severity = $e.Severity; Object = $e.ObjectName; Tag = "$($e.TagType) ($($e.Attribute))"; Change = "'$($e.OldValue)' -> '$($e.NewValue)'"; Who = $(if ($e.Initiator) { $e.Initiator } else { 'unknown' }); Found = ([datetime]$e.FoundAtUtc).ToString('yyyy-MM-dd HH:mm') + ' UTC' } })
    $html = New-EpsMailBody -Summary "The Entra Policy Suite tamper monitor found $what. The tags drive the dynamic groups and the Conditional Access policies that read them, so a changed tag can move a user out of a policy (a break-glass value or a cleared Authentication tag takes the user out of MFA)." `
        -Rows $rows -Columns 'Severity', 'Object', 'Tag', 'Change', 'Who', 'Found' `
        -WhatToDo 'Check each change on the Tamper page. Restore puts the engine''s value back; a known writer (e.g. an HR provisioning app) can be added to the allow list (TamperMonitor.AllowList).' -ButtonText 'Open the Tamper page' -ButtonPage 'tamper' `
        -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
    $r = Send-EpsMail -Config $cfg -Subject $subject -Html $html -Importance $(if ($high) { 'high' } else { 'normal' })
    if ($r.Sent) {
        $ids = (@($open | ForEach-Object { [long]$_.EventId }) -join ',')
        Invoke-EpsSql -ConnectionString $ConnectionString -NonQuery -Query "UPDATE eps.TamperEvent SET AlertedAtUtc = SYSUTCDATETIME() WHERE EventId IN ($ids)" | Out-Null
    }
    @{ Events = $open.Count; High = $high; Sent = $r.Sent; Reason = $r.Reason; Subject = $subject }
}
