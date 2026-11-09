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
$script:EpsComputerClassGuid = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'   # schemaIDGUID of the 'computer' class (well-known; device tags)

function Get-EpsAdPermissionGroupName {
    # PURE. framework HYBRID-AD-1 (owner 2026-11-09): every AD right goes to "<gMSA>-PermissionGroup" (the gMSA its only member)
    param([Parameter(Mandatory)][string]$Gmsa)
    "$($Gmsa.Split('\')[-1].TrimEnd('$'))-PermissionGroup"
}

function Get-EpsAdDelegationPlan {
    <#
      framework HYBRID-AD-1 (owner 2026-11-09: "permissions to chg tags must be ad domain root, otherwise you will not
      catch all users or devices. and extensions are individual per customer"):
      - the principal is <gMSA>-PermissionGroup (the gMSA its ONLY member) - never the gMSA itself; a missing group is a
        step of the plan ('creategroup'), a group with another member is refused;
      - one inheritable Allow ACE per attribute and object class: WriteProperty on that attribute, for descendant objects
        of that class (user; computer for device tags), at the DOMAIN ROOT (-Scope; default the domain's naming context);
      - only the attributes the customer chose (extensionAttribute1-15; anything else refused);
      - AdminSDHolder (the object itself) only with -ProtectedHolderDn (the opt-in switch).
    #>
    param([Parameter(Mandatory)]$Directory, [Parameter(Mandatory)][string]$Gmsa, [Parameter(Mandatory)][string[]]$Attributes,
          [ValidateSet('user', 'computer')][string[]]$ObjectClasses = @('user'), [string]$Scope, [switch]$Remove, [string]$ProtectedHolderDn)
    foreach ($a in $Attributes) { if ($a -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw "refused: '$a' is not an extensionAttribute (the worker writes the tag attributes only)" } }
    $gmsaSid = $Directory.GetSid($Gmsa)
    if (-not $gmsaSid) { throw "no gMSA '$Gmsa' in AD - your AD admin creates it first (with its <gMSA>-PrincipalsAllowedAccess group)" }
    $groupName = Get-EpsAdPermissionGroupName -Gmsa $Gmsa
    $sid = $Directory.GetGroupSid($groupName)
    if ($sid) {
        $others = @($Directory.GetGroupMemberSids($groupName) | Where-Object { $_ -ne $gmsaSid })
        if ($others.Count) { throw "refused: $groupName has other members than the gMSA ($($others.Count)) - it must hold the gMSA only (HYBRID-AD-1)" }
        if (-not $Remove -and -not @($Directory.GetGroupMemberSids($groupName) | Where-Object { $_ -eq $gmsaSid }).Count) { [pscustomobject]@{ OU = $groupName; Attribute = '(member)'; AttributeGuid = [guid]::Empty; Sid = $gmsaSid; Action = 'addmember'; Kind = 'Group'; ObjectClass = '' } }
    } elseif ($Remove) { return } else {
        [pscustomobject]@{ OU = $groupName; Attribute = '(group)'; AttributeGuid = [guid]::Empty; Sid = $gmsaSid; Action = 'creategroup'; Kind = 'Group'; ObjectClass = '' }
        $sid = "(the new group $groupName)"
    }
    if (-not $Scope) { $Scope = $Directory.NamingContext() }
    $classGuid = @{ user = $script:EpsUserClassGuid; computer = $script:EpsComputerClassGuid }
    $rules = if ($sid -like '(*') { @() } else { @($Directory.GetRules($Scope)) }
    foreach ($cls in $ObjectClasses) {
        foreach ($a in $Attributes) {
            $g = [guid]$Directory.GetAttributeGuid($a)
            $has = [bool]($rules | Where-Object { $_.Allow -and $_.Sid -eq $sid -and $_.Rights -match 'WriteProperty' -and [guid]$_.ObjectType -eq $g -and [guid]$_.InheritedObjectType -eq $classGuid[$cls] })
            $action = if ($Remove) { if ($has) { 'remove' } else { 'absent' } } else { if ($has) { 'present' } else { 'add' } }
            [pscustomobject]@{ OU = $Scope; Attribute = $a; AttributeGuid = $g; Sid = $sid; Action = $action; Kind = 'Root'; ObjectClass = $cls }
        }
    }
    if ($ProtectedHolderDn) {
        $rules = if ($sid -like '(*') { @() } else { @($Directory.GetRules($ProtectedHolderDn)) }
        foreach ($a in $Attributes) {
            $g = [guid]$Directory.GetAttributeGuid($a)
            $has = [bool]($rules | Where-Object { $_.Allow -and $_.Sid -eq $sid -and $_.Rights -match 'WriteProperty' -and [guid]$_.ObjectType -eq $g -and [guid]$_.InheritedObjectType -eq [guid]::Empty })
            $action = if ($Remove) { if ($has) { 'remove' } else { 'absent' } } else { if ($has) { 'present' } else { 'add' } }
            [pscustomobject]@{ OU = $ProtectedHolderDn; Attribute = $a; AttributeGuid = $g; Sid = $sid; Action = $action; Kind = 'Protected'; ObjectClass = '' }
        }
    }
}

function Invoke-EpsAdDelegationPlan {
    # Applies the rows in order (the group first). The group is made in the gMSA's own container, the gMSA its only member.
    param([Parameter(Mandatory)]$Directory, [Parameter(Mandatory)][string]$Gmsa, [object[]]$Plan = @())
    $groupName = Get-EpsAdPermissionGroupName -Gmsa $Gmsa
    $sid = $null
    foreach ($p in $Plan) {
        switch ($p.Action) {
            'creategroup' { $Directory.NewGroup($groupName, $Gmsa); $sid = $Directory.GetGroupSid($groupName); if (-not $sid) { throw "the group $groupName could not be read back after it was made" } }
            'addmember'   { $Directory.AddGroupMember($groupName, $Gmsa) }
            'add'         { $Directory.AddRule($p.OU, $(if ("$($p.Sid)" -like '(*') { $sid } else { $p.Sid }), $p.AttributeGuid, $p.Kind, $p.ObjectClass) }
            'remove'      { $Directory.RemoveRule($p.OU, $p.Sid, $p.AttributeGuid, $p.Kind, $p.ObjectClass) }
        }
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
        $n = $Name.Split('\')[-1].TrimEnd('$') + '$'
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
    $mk = { param($sid, $g, $kind, $cls)
        if ($kind -eq 'Protected') {   # AdminSDHolder: for the object itself - SDProp copies it onto every protected account
            return [System.DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [Security.AccessControl.AccessControlType]::Allow, [guid]$g, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) }
        $classGuid = if ($cls -eq 'computer') { $script:EpsComputerClassGuid } else { $script:EpsUserClassGuid }
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [Security.AccessControl.AccessControlType]::Allow, [guid]$g, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $classGuid) }
    $d | Add-Member NoteProperty MakeRule $mk
    $d | Add-Member ScriptMethod AddRule { param($Ou, $Sid, $Guid, $Kind, $Cls) $e = $this.Entry($Ou); $e.ObjectSecurity.AddAccessRule((& $this.MakeRule $Sid $Guid $Kind $Cls)); $e.CommitChanges() }
    $d | Add-Member ScriptMethod RemoveRule { param($Ou, $Sid, $Guid, $Kind, $Cls) $e = $this.Entry($Ou); [void]$e.ObjectSecurity.RemoveAccessRule((& $this.MakeRule $Sid $Guid $Kind $Cls)); $e.CommitChanges() }
    # HYBRID-AD-1: the gMSA's <gMSA>-PermissionGroup - its members (SIDs), made in the gMSA's own container, the gMSA added
    $d | Add-Member ScriptMethod FindDn {
        param([string]$Filter)
        $ds = [System.DirectoryServices.DirectorySearcher]::new($this.SearchRoot()); $ds.Filter = $Filter; [void]$ds.PropertiesToLoad.Add('distinguishedName')
        $r = $ds.FindOne(); if ($r) { [string]$r.Properties['distinguishedname'][0] }
    }
    $d | Add-Member ScriptMethod GetGroupMemberSids {
        param([string]$Name)
        $dn = $this.FindDn("(&(objectClass=group)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue $Name)))"); if (-not $dn) { return @() }
        $e = $this.Entry($dn); $e.RefreshCache(@('member'))
        @(foreach ($m in @($e.Properties['member'])) { $me = $this.Entry($m); $me.RefreshCache(@('objectSid')); ([Security.Principal.SecurityIdentifier]::new([byte[]]$me.Properties['objectSid'][0], 0)).Value })
    }
    $d | Add-Member ScriptMethod NewGroup {
        param([string]$Name, [string]$Gmsa)
        $gdn = $this.FindDn("(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue ($Gmsa.Split('\')[-1].TrimEnd('$') + '$'))))")
        if (-not $gdn) { throw "no gMSA '$Gmsa' in AD" }
        $parent = $gdn.Substring($gdn.IndexOf(',') + 1)
        $g = $this.Entry($parent).Children.Add("CN=$Name", 'group')
        [void]$g.Properties['sAMAccountName'].Add($Name)
        [void]$g.Properties['groupType'].Add([int](0x80000000 -bor 0x2))   # a global security group
        [void]$g.Properties['description'].Add("Permission group for $($Gmsa.Split('\')[-1]) (Entra Policy Suite hybrid worker): every AD right of the worker is granted to this group; the gMSA is its only member")
        $g.CommitChanges()
        $this.AddGroupMember($Name, $Gmsa)
    }
    $d | Add-Member ScriptMethod AddGroupMember {
        param([string]$Name, [string]$Gmsa)
        $gdn = $this.FindDn("(&(objectClass=group)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue $Name)))")
        $mdn = $this.FindDn("(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$(ConvertTo-EpsLdapFilterValue ($Gmsa.Split('\')[-1].TrimEnd('$') + '$'))))")
        $e = $this.Entry($gdn); [void]$e.Properties['member'].Add($mdn); $e.CommitChanges()
    }
    $d | Add-Member ScriptMethod GetAdminSdHolderDn { "CN=AdminSDHolder,CN=System,$($this.NamingContext())" }
    $d
}
