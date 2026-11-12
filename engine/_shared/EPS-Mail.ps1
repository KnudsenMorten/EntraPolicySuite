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
      MAIL-ENV (framework 12.11a): the environment as every mail names it - "[<KIND>] <display name>". The display name and
      the kind are Invardia's (eps.UplinkState 'environment', the last good answer of GET /api/enrollments/environment); an
      install without a key (Community without the yes) has no kind and uses its own name (Get-EpsEnvironmentName). Only
      THIS install's names - never another customer's. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Default = '')
    $name = Get-EpsEnvironmentName -ConnectionString $ConnectionString -Default $Default
    $kind = ''
    try {
        $j = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Query "SELECT Value FROM eps.UplinkState WHERE Name = 'environment'"
        if ($null -ne $j -and $j -isnot [DBNull] -and "$j".Trim()) { $kind = ConvertTo-EpsMailKindTag -Kind "$(("$j" | ConvertFrom-Json).kind)" }
    } catch { }
    if ($kind -and "$name" -notlike "[$kind]*") { "[$kind] $name" } else { "$name" }
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

function Get-EpsMailConfig {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $g = { param($n, $d) $v = Invoke-EpsSql -ConnectionString $ConnectionString -Scalar -Parameters @{ n = $n } -Query 'SELECT Value FROM eps.Setting WHERE Name = @n'; if ($null -eq $v -or "$v" -eq '') { $d } else { [string]$v } }
    $rcpt = & $g 'Mail.Recipients' '[]'
    [pscustomobject]@{
        Mode = & $g 'Mail.Mode' 'none'; Sender = & $g 'Mail.Sender' ''
        # V1-PARITY P12: v1's SMTP relay (its $global:SMTPserver / SMTPPort / SMTP_UseSSL / SMTPUser); the password, when
        # the relay needs one, is a Key Vault secret the engine reads at send time - never a value in SQL
        SmtpServer = & $g 'Mail.SmtpServer' ''; SmtpPort = [int](& $g 'Mail.SmtpPort' '25'); SmtpUseTls = ((& $g 'Mail.SmtpUseTls' 'true') -eq 'true')
        SmtpFrom = & $g 'Mail.SmtpFrom' ''; SmtpCredentialSecret = & $g 'Mail.SmtpCredentialSecret' ''
        Recipients = @(try { $rcpt | ConvertFrom-Json } catch { @() }) | Where-Object { $_ }
        Environment = (Get-EpsMailEnvironmentLabel -ConnectionString $ConnectionString -Default $(if ($env:EPS_TENANT_ID) { "tenant $($env:EPS_TENANT_ID)" } else { 'Entra Policy Suite' }))
        TenantId = $env:EPS_TENANT_ID; TenantName = (Get-EpsMailTenantName -Setting (& $g 'Platform.TenantName' ''))
    }
}

function Send-EpsMail {
    # One mail. NEVER throws (an alert that cannot be mailed must not fail the job): returns @{ Sent; Reason }.
    # Mode none, no sender or no recipient = not sent, and said why.
    # -Attachments: @{ Name; Bytes; ContentType } - inline (Graph sendMail takes ~3 MB in all); a larger one is left out
    # and the mail says so (the GUI has the export).
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Importance = 'normal', [object[]]$Attachments = @(), [int]$MaxAttachmentBytes = 3000000)
    if ($Config.Mode -eq 'smtp') { return (Send-EpsSmtpMail -Config $Config -Subject $Subject -Html $Html -Importance $Importance -Attachments $Attachments -MaxAttachmentBytes $MaxAttachmentBytes) }
    if ($Config.Mode -ne 'sharedMailbox') { return @{ Sent = $false; Reason = "Mail.Mode is '$($Config.Mode)' - no mail is sent (set it up: Initialize-EpsMailSender.ps1)" } }
    if (-not $Config.Sender) { return @{ Sent = $false; Reason = 'Mail.Sender is not set' } }
    if (-not @($Config.Recipients).Count) { return @{ Sent = $false; Reason = 'Mail.Recipients is empty' } }
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
    # V1-PARITY P12 (v1's Send-MailMessage through its relay): Mail.Mode = smtp. Anonymous when no credential secret is
    # set (v1's Mail_SendAnonymous), else Mail.SmtpFrom + the Key Vault secret's password. TLS (STARTTLS) by
    # Mail.SmtpUseTls. NEVER throws; the password never appears in a reason. @{ Sent; Reason }.
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Importance = 'normal', [object[]]$Attachments = @(), [int]$MaxAttachmentBytes = 3000000)
    if (-not $Config.SmtpServer) { return @{ Sent = $false; Reason = 'Mail.SmtpServer is not set' } }
    if (-not $Config.SmtpFrom) { return @{ Sent = $false; Reason = 'Mail.SmtpFrom is not set' } }
    if (-not @($Config.Recipients).Count) { return @{ Sent = $false; Reason = 'Mail.Recipients is empty' } }
    $pw = $null
    if ($Config.SmtpCredentialSecret) { $s = Get-EpsSmtpSecret -SecretUri $Config.SmtpCredentialSecret; if (-not $s.Ok) { return @{ Sent = $false; Reason = $s.Reason } }; $pw = $s.Value }
    $att = @(); $left = @()
    foreach ($a in $Attachments) { if (@($a.Bytes).Count -gt $MaxAttachmentBytes) { $left += $a.Name } else { $att += $a } }
    if ($left) { $Html += "<p><i>$([System.Net.WebUtility]::HtmlEncode(($left -join ', '))) is too large to attach - export it from the web app.</i></p>" }
    try {
        & $script:EpsSmtpSend @{ Server = $Config.SmtpServer; Port = $(if ($Config.SmtpPort) { $Config.SmtpPort } else { 25 }); Tls = [bool]$Config.SmtpUseTls; From = $Config.SmtpFrom; User = $Config.SmtpFrom; Password = $pw
                                 To = @($Config.Recipients); Subject = $Subject; Html = $Html; Importance = $Importance; Attachments = $att }
        @{ Sent = $true; Reason = "sent to $(@($Config.Recipients).Count) recipient(s) through $($Config.SmtpServer)" }
    } catch {
        $e = "$($_.Exception.InnerException.Message)"; if (-not $e) { $e = "$($_.Exception.Message)" }
        if ($pw) { $e = $e.Replace($pw, '***') }
        @{ Sent = $false; Reason = "SMTP send through $($Config.SmtpServer) failed: $e" }
    }
}

function Send-EpsTestMail {
    # "Send a test mail" (Settings > Alert mail): proves the sender works AS THE ENGINE'S IDENTITY - the scoped
    # Application Mail.Send - not as the person who set it up. @{ Sent; Reason }; never throws.
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$RequestedBy, [string]$Version = '2.0.0')
    $cfg = Get-EpsMailConfig -ConnectionString $ConnectionString
    # MAIL-3 subject + the MAIL-2 body like every other mail (was a hand-made '[EntraPolicySuite] <env>: test mail')
    $how = if ($cfg.Mode -eq 'smtp') { "through the SMTP relay $($cfg.SmtpServer) as $($cfg.SmtpFrom)" } else { "as $($cfg.Sender)" }
    $html = New-EpsMailBody -Summary "This is a test mail from Entra Policy Suite $Version ($($cfg.Environment)), sent by the engine $how. Requested by $RequestedBy at $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC. Tamper alerts and every other mail come the same way." `
        -ButtonText 'Open the mail settings' -ButtonPage 'settings' -Footer @{ Environment = $cfg.Environment; TenantName = $cfg.TenantName; TenantId = $cfg.TenantId; Version = $Version }
    Send-EpsMail -Config $cfg -Subject (New-EpsMailSubject -Environment $cfg.Environment -What 'Test mail') -Html $html
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
