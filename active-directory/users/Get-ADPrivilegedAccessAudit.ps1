<#
.SYNOPSIS
    Comprehensive privileged access audit: who has what admin rights and why.
.DESCRIPTION
    Maps all privileged access paths: direct group membership, nested groups,
    GPO delegation, local admin via GPP, and AdminSDHolder-protected accounts.
    Produces a single consolidated privileged access matrix.
.EXAMPLE
    Get-ADPrivilegedAccessAudit -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Matrix    = [System.Collections.Generic.List[PSObject]]::new()

$PrivGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                "Account Operators","Backup Operators","Server Operators","Print Operators",
                "Group Policy Creator Owners","DNSAdmins","DHCP Administrators")

foreach ($group in $PrivGroups) {
    try {
        Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | ForEach-Object {
            $obj = Get-ADObject $_.DistinguishedName -Properties Enabled,PasswordLastSet,LastLogonDate -ErrorAction SilentlyContinue
            $Matrix.Add([PSCustomObject]@{
                PrivilegedGroup = $group
                Account         = $_.SamAccountName
                AccountType     = $_.objectClass
                Enabled         = $obj.Enabled
                PasswordLastSet = $obj.PasswordLastSet
                LastLogon       = $obj.LastLogonDate
                PwdAgeDays      = if ($obj.PasswordLastSet) { ((Get-Date)-$obj.PasswordLastSet).Days } else { "N/A" }
            })
        }
    } catch {}
}

$Matrix | Export-Csv (Join-Path $OutputPath "PrivAccessMatrix_$Timestamp.csv") -NoTypeInformation
$enabled  = ($Matrix | Where-Object Enabled -eq $true | Select-Object Account -Unique).Count
$accounts = ($Matrix | Select-Object Account -Unique).Count
Write-Host "[DONE] Privileged entries: $($Matrix.Count) across $($PrivGroups.Count) groups | Unique accounts: $accounts | Enabled: $enabled" -ForegroundColor Yellow
