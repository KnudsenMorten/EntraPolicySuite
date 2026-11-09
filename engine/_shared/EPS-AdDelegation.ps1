# EntraPolicySuite -- the hybrid worker's AD delegation (DESIGN §6): the gMSA may write EXACTLY the tag attributes on
# user objects below the named OUs. The plan is pure (a directory interface in, a list of ACEs out) so it is tested
# without an AD; the real directory is .NET System.DirectoryServices (no module).
#   Directory interface: GetSid(name) GetAttributeGuid(lDAPDisplayName) GetRules(ouDn) AddRule(ouDn, sid, attrGuid) RemoveRule(ouDn, sid, attrGuid)
#   a rule: @{ Sid; Rights (WriteProperty); ObjectType (attribute guid); InheritedObjectType (user class guid); Allow }
# Protected accounts (owner 2026-10-30: "New gMSA + protected admins"): members of protected groups (Domain Admins ...)
# do not inherit OU rights - AD's SDProp copies the ACL of CN=AdminSDHolder,CN=System onto them (about every 60 min).
# So the same narrow right goes on AdminSDHolder as an ACE for THE OBJECT ITSELF (no inheritance, no inherited type):
# the gMSA may then write the tag attributes on protected admins too - which makes it Tier 0 sensitive.

Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'EPS-AdDirectory.ps1')   # ConvertTo-EpsLdapFilterValue
$script:EpsUserClassGuid = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'   # schemaIDGUID of the 'user' class (well-known)

function Get-EpsAdDelegationPlan {
    param([Parameter(Mandatory)]$Directory, [Parameter(Mandatory)][string]$GmsaName, [Parameter(Mandatory)][string[]]$OrganizationalUnit,
          [Parameter(Mandatory)][string[]]$Attributes, [switch]$Remove, [string]$ProtectedHolderDn, [string]$GroupName)
    # -GroupName (PIM's pattern, 2026-10-30): the rights go to an EPS GROUP the gMSA is a member of, so each product
    # takes away its own principal cleanly (AdminSDHolder is shared with PIM)
    if ($GroupName) {
        $sid = $Directory.GetGroupSid($GroupName)
        if (-not $sid) { throw "no group '$GroupName' in AD - your AD admin creates it first (and makes the gMSA its member)" }
    } else {
        $sid = $Directory.GetSid($GmsaName)
        if (-not $sid) { throw "no gMSA '$GmsaName' in AD - your AD admin creates it first" }
    }
    foreach ($a in $Attributes) { if ($a -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw "refused: '$a' is not an extensionAttribute (the worker writes the tag attributes only)" } }
    foreach ($ou in $OrganizationalUnit) {
        $rules = @($Directory.GetRules($ou))
        foreach ($a in $Attributes) {
            $g = [guid]$Directory.GetAttributeGuid($a)
            $has = [bool]($rules | Where-Object { $_.Allow -and $_.Sid -eq $sid -and $_.Rights -match 'WriteProperty' -and [guid]$_.ObjectType -eq $g -and [guid]$_.InheritedObjectType -eq $script:EpsUserClassGuid })
            $action = if ($Remove) { if ($has) { 'remove' } else { 'absent' } } else { if ($has) { 'present' } else { 'add' } }
            [pscustomobject]@{ OU = $ou; Attribute = $a; AttributeGuid = $g; Sid = $sid; Action = $action; Kind = 'Ou' }
        }
    }
    if ($ProtectedHolderDn) {
        $rules = @($Directory.GetRules($ProtectedHolderDn))
        foreach ($a in $Attributes) {
            $g = [guid]$Directory.GetAttributeGuid($a)
            $has = [bool]($rules | Where-Object { $_.Allow -and $_.Sid -eq $sid -and $_.Rights -match 'WriteProperty' -and [guid]$_.ObjectType -eq $g -and [guid]$_.InheritedObjectType -eq [guid]::Empty })
            $action = if ($Remove) { if ($has) { 'remove' } else { 'absent' } } else { if ($has) { 'present' } else { 'add' } }
            [pscustomobject]@{ OU = $ProtectedHolderDn; Attribute = $a; AttributeGuid = $g; Sid = $sid; Action = $action; Kind = 'Protected' }
        }
    }
}

function Invoke-EpsAdDelegationPlan {
    param([Parameter(Mandatory)]$Directory, [object[]]$Plan = @())
    foreach ($p in $Plan) {
        if ($p.Action -eq 'add') { $Directory.AddRule($p.OU, $p.Sid, $p.AttributeGuid, $p.Kind) }
        elseif ($p.Action -eq 'remove') { $Directory.RemoveRule($p.OU, $p.Sid, $p.AttributeGuid, $p.Kind) }
    }
}

function New-EpsAdDelegationDirectory {
    param([string]$Server)
    if (-not $IsWindows) { throw 'AD delegation runs on a Windows domain machine' }
    Add-Type -AssemblyName System.DirectoryServices
    $root = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
    $d = [pscustomobject]@{ Root = $root }
    $d | Add-Member ScriptMethod Entry { param($dn) [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)$dn") }
    # the domain's default naming context; a RootDSE read can come back empty once (seen live 2026-10-31) - read it again
    $d | Add-Member ScriptMethod NamingContext {
        for ($i = 0; $i -lt 3; $i++) {
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)RootDSE")
            try { $rootDse.RefreshCache(@('defaultNamingContext')); $nc = [string]$rootDse.Properties['defaultNamingContext'].Value } catch { $nc = $null }
            if ($nc) { return $nc }
            Start-Sleep -Seconds 2
        }
        throw "could not read the domain's naming context from $($this.Root)RootDSE - is a domain controller reachable?"
    }
    # search the domain (its default naming context) - a bare "LDAP:" cannot be searched
    $d | Add-Member ScriptMethod SearchRoot { $this.Entry($this.NamingContext()) }
    $d | Add-Member ScriptMethod GetSid {
        param([string]$Name)
        $n = $Name.TrimEnd('$') + '$'
        $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot())
        $ds.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue $n)))"
        [void]$ds.PropertiesToLoad.Add('objectSid')
        $r = $ds.FindOne(); if (-not $r) { return $null }
        ([Security.Principal.SecurityIdentifier]::new([byte[]]$r.Properties['objectsid'][0], 0)).Value
    }
    $d | Add-Member ScriptMethod GetGroupSid {
        param([string]$Name)
        $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot())
        $ds.Filter = "(&(objectClass=group)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue $Name)))"
        [void]$ds.PropertiesToLoad.Add('objectSid')
        $r = $ds.FindOne(); if (-not $r) { return $null }
        ([Security.Principal.SecurityIdentifier]::new([byte[]]$r.Properties['objectsid'][0], 0)).Value
    }
    $d | Add-Member ScriptMethod GetAttributeGuid {
        param([string]$Ldap)
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new("$($this.Root)RootDSE")
        $schema = [string]$rootDse.Properties['schemaNamingContext'][0]
        $ds = [System.DirectoryServices.DirectorySearcher]::new($this.Entry($schema))
        $ds.Filter = "(lDAPDisplayName=$(ConvertTo-EpsLdapFilterValue $Ldap))"
        [void]$ds.PropertiesToLoad.Add('schemaIDGUID')
        $r = $ds.FindOne(); if (-not $r) { throw "no attribute '$Ldap' in the AD schema" }
        [guid]::new([byte[]]$r.Properties['schemaidguid'][0])
    }
    $d | Add-Member ScriptMethod GetRules {
        param([string]$Ou)
        foreach ($r in $this.Entry($Ou).ObjectSecurity.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
            [pscustomobject]@{ Sid = $r.IdentityReference.Value; Rights = [string]$r.ActiveDirectoryRights; ObjectType = $r.ObjectType; InheritedObjectType = $r.InheritedObjectType; Allow = $r.AccessControlType -eq 'Allow' }
        }
    }
    $mk = { param($sid, $g, $kind)
        if ($kind -eq 'Protected') {   # AdminSDHolder: for the object itself - SDProp copies it onto every protected account
            return [System.DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [Security.AccessControl.AccessControlType]::Allow, [guid]$g, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) }
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [Security.AccessControl.AccessControlType]::Allow, [guid]$g, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $script:EpsUserClassGuid) }
    $d | Add-Member NoteProperty MakeRule $mk
    $d | Add-Member ScriptMethod AddRule { param($Ou, $Sid, $Guid, $Kind) $e = $this.Entry($Ou); $e.ObjectSecurity.AddAccessRule((& $this.MakeRule $Sid $Guid $Kind)); $e.CommitChanges() }
    $d | Add-Member ScriptMethod RemoveRule { param($Ou, $Sid, $Guid, $Kind) $e = $this.Entry($Ou); [void]$e.ObjectSecurity.RemoveAccessRule((& $this.MakeRule $Sid $Guid $Kind)); $e.CommitChanges() }
    $d | Add-Member ScriptMethod GetAdminSdHolderDn { "CN=AdminSDHolder,CN=System,$($this.NamingContext())" }
    $d
}
