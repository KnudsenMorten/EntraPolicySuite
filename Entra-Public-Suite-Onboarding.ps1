#Requires -Version 5.0

<#
    .NAME
    Initial Onboarding of Entra Policy Suite (EPS)

    .SYNOPSIS

    .NOTES
    
    .VERSION
    1.0
    
    .AUTHOR
    Morten Knudsen, Microsoft MVP - https://mortenknudsen.net

    .LICENSE
    Licensed under the MIT license.

    .PROJECTURI
    https://github.com/KnudsenMorten/EntraPolicySuite


    .WARRANTY
    Use at your own risk, no warranty given!
#>

########################################################################################################################################
# Entra Policy Suite Functions
########################################################################################################################################

    # Set the path to the custom config file
    $FunctionFile = ".\EntraPolicySuite.psm1"

    # Check if the config file exists
    if (-Not (Test-Path $configFilePath)) {
        Write-host ""
        Write-host "EntraPolicySuite.psm1 was not found in current directory. Terminating !" -ForegroundColor DarkYellow
        break
    }

    Import-Module $FunctionFile -Global -force -WarningAction SilentlyContinue


########################################################################################################################################
# Onboarding ImportExcel PS module
########################################################################################################################################

    # Install PS module from Powershell Gallery
    Install-module ImportExcel

########################################################################################################################################
# Onboarding Entra Policy Suite PS module
########################################################################################################################################

    # Install PS module from Powershell Gallery
    Install-module EntraPolicySuite


########################################################################################################################################
# Onboarding Microsoft Graph integration
########################################################################################################################################

    # Instal PS module from Powershell Gallery
    Install-module MicrosoftGraphPS
<#

    # Create Azure App SP with the following Microsoft Graph API app-permissions:
        User.ReadWrite.All
        Group.ReadWrite.All
        Policy.Read.All
        Policy.ReadWrite.ConditionalAccess
        Policy.ReadWrite.AuthenticationMethod

    Delete app-permission from Office 365 Exchange Online - found under "APIs my organization use':
        Exchange.ManageAsApp

    Delegate Entra ID Role permission 'Exchange Recipient Administrator' to App SP.
#>

########################################################################################################################################
# Onboarding Active Directory PS modules
########################################################################################################################################

    # Install Active Directory Powershell PS modules
    $WindowsFeatureModules   = @("RSAT-AD-PowerShell","RSAT-ADDS","RSAT-AD-TOOLS")

    $InstalledWindowsFeatures = Get-WindowsFeature
                
    ForEach ($WindowsFeature in $WindowsFeatureModules)
        {
            $DetectInstalled = $InstalledWindowsFeatures | Where-Object { ($_.name -eq $WindowsFeature) -and ($_.InstallState -eq "Installed") }
                If ($DetectInstalled)
                    {
                        # skip Windows Feature Installed
                    }
                Else
                    {

                        Install-WindowsFeature -Name $WindowsFeature -IncludeAllSubFeature -IncludeManagementTools
                    }
        }


########################################################################################################################################
# Onboarding Active Directory connectivity using GMSA account
# High-privileged Domain Admin Account | Delegation-level/Tiering: L1, T0
########################################################################################################################################

    # Customized values
    $AccountName                            = "gMSA-AUTM-L1-T0"
    $AccountDescription                     = "High-privileged Domain Admin (L1, T0) | Used by Automation from Morten Knudsen/2LINKIT"
    $AccountPasswordChangeFrequencyDays     = 30
    $AccountKerberosEncryptionType          = "AES256"

    $GroupPermissionMemberOf                = "Domain Admins"
    $PrincipalsAllowedMembers               = @("AZWE-S-AUTM-P01$") # Members that can access password
    $DNSHostName                            = $AccountName + "@" + "myaddomain.local"
    $OUPathParentLDAP                       = "OU=High Privilege Service Accounts,OU=Service Accounts,OU=OnPrem Only - No Sync to Cloud,OU=SPECIAL ACCOUNTS,DC=myaddomain,DC=local"  # NOTE: Must be under OU, that is NOT repliaced to cloud (on-prem only)
    $OUPathName                             = "Automation"
    $DomainController                       = "azwe-s-dc-p01.myaddomain.local"   # use specific DC to avoid replication delays

    # Calculated values
    $GroupPermissionMembers                 = $AccountName + "$"
    $OUPathLDAP                             = "OU=" + $OUPathName + "," + $OUPathParentLDAP
    $GroupPermissionGroupName               = $AccountName + "-PermissionGroup" # Group should contain the GMSA. Use this when granting it access to the files and anything else, such as the right to logon as service & as batch job on your server. It makes it easier to replace the GMSA if that ever becomes necessary.
    $GroupPermissionGroupDescription        = "Permission-group for $($AccountName)"
    $GroupPermissionGroupNotes              = "This group contains the GMSA. Group can be used to delegate for the gMSA account, like make group memberOf Domain Admins or more granular ACLS permissions in AD. Group is part of Automation-concept from 2LINKIT/Morten Knudsen"

    $GroupPrincipalsAllowedGroupName        = $AccountName + "-PrincipalsAllowedAccess" #  Group should contain the server's computer account, that are allowed to access credentials. It is used in the PowerShell command that allows the server to fetch the GMSA's password from your DCs. Same reason as above: if you need to rebuild the server, you just add the new computer account to the group & everything works again.
    $GroupPrincipalsAllowedGroupDescription = "Principals Allowed to retrieve password for $($AccountName)"
    $GroupPrincipalsAllowedGroupNotes       = "This group contains the Principals allowed to retrieve gMSA password. Group is part of Automation-concept from 2LINKIT/Morten Knudsen"

    # OU
        Create_GMSA_OU -OUPathName $OUPathName -OUPathParentLDAP $OUPathParentLDAP -DomainController $DomainController

    # Permission Group
        Create_GMSA_Group_AD -GroupName $GroupPermissionGroupName -GroupDescription $GroupPermissionGroupDescription -OUPath $OUPathLDAP -Notes $GroupPermissionGroupNotes  -DomainController $DomainController
        AddGroupMemberOf_GMSA_Group_AD -GroupName $GroupPermissionGroupName -GroupMemberOf $GroupPermissionMemberOf -DomainController $DomainController

    # PrincipalsAllowed Group
        Create_GMSA_Group_AD -GroupName $GroupPrincipalsAllowedGroupName -GroupDescription $GroupPrincipalsAllowedGroupDescription -OUPath $OUPathLDAP -Notes $GroupPrincipalsAllowedGroupNotes -DomainController $DomainController
        AddMembers_GMSA_Group_AD -GroupName $GroupPrincipalsAllowedGroupName -GroupMembers $PrincipalsAllowedMembers -DomainController $DomainController

    # Create GMSA account
        Create_GMSA_Account -AccountName $AccountName `
                            -DNSHostName $DNSHostName `
                            -AccountDescription $AccountDescription `
                            -AccountPasswordChangeFrequencyDays $AccountPasswordChangeFrequencyDays `
                            -OUPathLDAP $OUPathLDAP `
                            -GroupPrincipalsAllowedGroupName $GroupPrincipalsAllowedGroupName `
                            -KerberosEncryptionType $AccountKerberosEncryptionType `
                            -DomainController $DomainController

    # Add GMSA group member of Permission Group
        AddMembers_GMSA_Group_AD -GroupName $GroupPermissionGroupName -GroupMembers $GroupPermissionMembers -DomainController $DomainController

    # Get info about gMSA
        Get-ADServiceAccount -Identity $AccountName -Properties *

    # Purge Kerberos tickets
        klist purge -li 0x3e7

    # Install GMSA account on server
        Install-ADServiceAccount $AccountName

    # Test - should return TRUE
        Test-ADServiceAccount $AccountName

#####################################################################################################################
# Add group gMSA-AUTM-L1-T0-PermissionGroup to AdminSDHolder with Full Control + run below commands
#####################################################################################################################

Invoke-ADSDPropagation 


##########################################################
# Changes in AD
##########################################################

<#
    Give Full Control on top OU in AD to gMSA-AUTM-L1-T0-PermissionGroup


    ##################################################################
    # Validation Permissions to run script using Computer permissions
    ##################################################################

    VisualCron / Task Scheduler:
    <domain>\gMSA-AUTM-L1-T0$ - sample: myaddomain.local\gMSA-AUTM-L1-T0$

    Interactive login with Powershell ISE and PSExec:
    %~dp0\PsExec.exe -h -e -s -i "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

#>

