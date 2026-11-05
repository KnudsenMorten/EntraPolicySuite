# EntraPolicySuite -- Active Directory for the hybrid worker, through .NET System.DirectoryServices (DESIGN §6: no
# ActiveDirectory module, framework NO-AZ). Windows only; runs on the worker as its gMSA (the scheduled task's
# run-as account), never as SYSTEM: a write as SYSTEM would be the computer account's, not the delegated gMSA's.
#
# New-EpsAdDirectory returns the interface the worker uses - the same shape a test's fake AD has:
#   FindUser(sid, upn)            -> a user handle, or $null      (by objectSid first: Entra's onPremisesSecurityIdentifier)
#   GetAttribute(user, attribute) -> the value ('' when not set)
#   SetAttribute(user, attribute, value)  ('' / $null clears it)
#   HasAttribute(attribute)       -> is it in this AD's schema (extensionAttribute5/9 exist only with the Exchange schema)
#   GetGroupUserMembers(name)     -> the UPNs of the group's user members, RECURSIVE (v1: Get-ADGroupMember -Recursive),
#                                    or $null when no group has that name / sAMAccountName

Set-StrictMode -Off

function ConvertTo-EpsLdapFilterValue {
    # RFC 4515 escaping of a value inside an LDAP filter: \ * ( ) NUL - a group name from a rule is not trusted
    param([AllowEmptyString()][string]$Value)
    $sb = [Text.StringBuilder]::new()
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) { '\' { [void]$sb.Append('\5c') } '*' { [void]$sb.Append('\2a') } '(' { [void]$sb.Append('\28') } ')' { [void]$sb.Append('\29') } ([char]0) { [void]$sb.Append('\00') } default { [void]$sb.Append($ch) } }
    }
    $sb.ToString()
}

function Assert-EpsAdWriter {
    # AD is written as the delegated gMSA only
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($me.IsSystem) { throw 'refused: the hybrid worker writes AD as its gMSA (the scheduled task''s run-as account), never as SYSTEM' }
    $me.Name
}

function New-EpsAdDirectory {
    param([string]$Server)   # a DC; empty = the domain's locator picks one
    if (-not $IsWindows) { throw 'the AD layer runs on the Windows hybrid worker only' }
    Add-Type -AssemblyName System.DirectoryServices
    $root = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
    $ad = [pscustomobject]@{ Server = $Server; Root = $root; Schema = @{} }
    # search the domain (its default naming context) - a bare "LDAP:" cannot be searched (found live 2026-10-31)
    # a RootDSE read can come back empty once (seen live 2026-10-31) - read it again before giving up
    $ad | Add-Member ScriptMethod SearchRoot {
        for ($i = 0; $i -lt 3; $i++) {
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)RootDSE")
            try { $rootDse.RefreshCache(@('defaultNamingContext')); $nc = [string]$rootDse.Properties['defaultNamingContext'].Value } catch { $nc = $null }
            if ($nc) { return [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)$nc") }
            Start-Sleep -Seconds 2
        }
        throw "could not read the domain's naming context from $($this.Root)RootDSE - is a domain controller reachable?"
    }
    # WORKER-GUI (2.0.82): what the worker is connected to - read only (RootDSE + one search for a single user object):
    # @{ Domain (DNS form); Server (the DC that answered); NamingContext; CanReadUsers }
    $ad | Add-Member ScriptMethod Describe {
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)RootDSE")
        $rootDse.RefreshCache(@('defaultNamingContext', 'dnsHostName'))
        $nc = [string]$rootDse.Properties['defaultNamingContext'].Value
        $dns = (@($nc -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.')
        $read = $false
        try { $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot()); $ds.Filter = '(&(objectCategory=person)(objectClass=user))'; $ds.SizeLimit = 1; [void]$ds.PropertiesToLoad.Add('objectSid'); $read = [bool]$ds.FindOne() } catch { $read = $false }
        [pscustomobject]@{ Domain = $dns; Server = [string]$rootDse.Properties['dnsHostName'].Value; NamingContext = $nc; CanReadUsers = $read }
    }
    $ad | Add-Member ScriptMethod HasAttribute {
        param([string]$Attribute)
        if (-not $this.Schema.ContainsKey($Attribute)) {
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)RootDSE")
            $ds = [System.DirectoryServices.DirectorySearcher]::new([System.DirectoryServices.DirectoryEntry]::new("$($this.Root)$([string]$rootDse.Properties['schemaNamingContext'][0])"))
            $ds.Filter = "(lDAPDisplayName=$(ConvertTo-EpsLdapFilterValue $Attribute))"
            $this.Schema[$Attribute] = [bool]$ds.FindOne()
        }
        $this.Schema[$Attribute]
    }
    $ad | Add-Member ScriptMethod FindUser {
        param([string]$Sid, [string]$Upn)
        if ($Sid) {
            try {
                $e = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)<SID=$Sid>")
                [void]$e.RefreshCache(@('distinguishedName', 'objectClass'))
                if ($e.Properties['objectClass'] -contains 'user') { return $e }
            } catch { }
        }
        if ($Upn) {
            $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot())
            $ds.Filter = "(&(objectCategory=person)(objectClass=user)(userPrincipalName=$(ConvertTo-EpsLdapFilterValue $Upn)))"
            $r = $ds.FindOne()
            if ($r) { return $r.GetDirectoryEntry() }
        }
        $null
    }
    $ad | Add-Member ScriptMethod GetAttribute {
        param($User, [string]$Attribute)
        [void]$User.RefreshCache(@($Attribute))
        $v = $User.Properties[$Attribute].Value
        if ($null -eq $v) { '' } else { [string]$v }
    }
    $ad | Add-Member ScriptMethod SetAttribute {
        param($User, [string]$Attribute, [string]$Value)
        [void](Assert-EpsAdWriter)
        if ([string]::IsNullOrEmpty($Value)) { $User.Properties[$Attribute].Clear() } else { $User.Properties[$Attribute].Value = $Value }
        $User.CommitChanges()
    }
    $ad | Add-Member ScriptMethod GetGroupUserMembers {
        param([string]$Name)
        $base = $this.SearchRoot()
        $ds = [System.DirectoryServices.DirectorySearcher]::new($base)
        $n = ConvertTo-EpsLdapFilterValue $Name
        $ds.Filter = "(&(objectCategory=group)(|(name=$n)(sAMAccountName=$n)))"
        [void]$ds.PropertiesToLoad.Add('distinguishedName')
        # SEC-AUDIT-1 S2: a name is unique only inside one OU - more than one match is refused, never "the first one"
        $all = $ds.FindAll()
        try { $hits = @(foreach ($x in $all) { [string]$x.Properties['distinguishedname'][0] }) } finally { $all.Dispose() }
        if (-not $hits.Count) { return $null }
        if ($hits.Count -gt 1) { throw "refused: $($hits.Count) AD groups are named '$Name' - the rule's group is ambiguous" }
        $dn = $hits[0]
        # LDAP_MATCHING_RULE_IN_CHAIN: every user member, through nested groups (v1's Get-ADGroupMember -Recursive)
        $ms = [System.DirectoryServices.DirectorySearcher]::new($base)
        $ms.Filter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$(ConvertTo-EpsLdapFilterValue $dn)))"
        $ms.PageSize = 1000
        [void]$ms.PropertiesToLoad.Add('userPrincipalName')
        $upns = [System.Collections.Generic.List[string]]::new()
        $res = $ms.FindAll()
        try { foreach ($r in $res) { $u = $r.Properties['userprincipalname']; if ($u.Count) { $upns.Add([string]$u[0]) } } } finally { $res.Dispose() }
        , $upns.ToArray()
    }
    $ad | Add-Member ScriptMethod GetAllUsers {
        # every user, read once (the identity report's AD columns; v1 queried the same DC once per DC - B5): paged, only
        # the attributes the report reads. READ ONLY.
        $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot())
        $ds.Filter = '(&(objectCategory=person)(objectClass=user))'; $ds.PageSize = 1000
        foreach ($a in 'objectSid', 'sAMAccountName', 'userPrincipalName', 'userAccountControl', 'lockoutTime', 'lastLogonTimestamp', 'accountExpires', 'whenCreated', 'description') { [void]$ds.PropertiesToLoad.Add($a) }
        $out = [System.Collections.Generic.List[object]]::new()
        $res = $ds.FindAll()
        try { foreach ($r in $res) { $p = @{}; foreach ($n in $r.Properties.PropertyNames) { $p[$n] = $r.Properties[$n][0] }; $out.Add((ConvertFrom-EpsAdUserProperties $p)) } } finally { $res.Dispose() }
        , $out.ToArray()
    }
    $ad
}

function ConvertFrom-EpsFileTime($v) {
    # an AD FILETIME (Int64; 0 or Int64.MaxValue = never) -> UTC [datetime] or $null
    if ($null -eq $v) { return $null }
    $n = [long]$v
    if ($n -le 0 -or $n -eq [long]::MaxValue) { return $null }
    try { [datetime]::FromFileTimeUtc($n) } catch { $null }
}

function ConvertFrom-EpsAdUserProperties {
    # one AD search result (lower-case property names, as DirectorySearcher returns them) -> the snapshot row. Pure.
    param([Parameter(Mandatory)][hashtable]$P)
    $uac = [int]$(if ($null -ne $P['useraccountcontrol']) { $P['useraccountcontrol'] } else { 0 })
    $sid = $P['objectsid']; if ($sid -is [byte[]]) { $sid = [Security.Principal.SecurityIdentifier]::new($sid, 0).Value }
    $desc = [string]$P['description']; if ($desc.Length -gt 1024) { $desc = $desc.Substring(0, 1024) }
    [pscustomobject]@{
        Sid = [string]$sid; SamAccountName = [string]$P['samaccountname']; UserPrincipalName = [string]$P['userprincipalname']
        Enabled = -not ($uac -band 0x2)
        LockedOut = ($null -ne $P['lockouttime'] -and [long]$P['lockouttime'] -gt 0)   # lockoutTime set = locked until it expires or is reset
        PasswordNeverExpires = [bool]($uac -band 0x10000)
        CannotChangePassword = [bool]($uac -band 0x40)                                  # the UAC flag (the ACE is not read)
        LastLogonUtc = ConvertFrom-EpsFileTime $P['lastlogontimestamp']
        AccountExpiresUtc = ConvertFrom-EpsFileTime $P['accountexpires']
        WhenCreatedUtc = $(if ($P['whencreated'] -is [datetime]) { $P['whencreated'].ToUniversalTime() })
        Description = $desc
    }
}
