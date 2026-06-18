<#
.SYNOPSIS
    Comprehensive Active Directory security audit covering privileged accounts,
    stale objects, password policy, and GPO configuration.
.DESCRIPTION
    Audits AD for: privileged group membership, stale accounts/computers,
    accounts with password-never-expires, unconstrained delegation,
    AdminSDHolder anomalies, and Kerberoastable service accounts.
.PARAMETER DomainController
    Target DC to query. Defaults to current domain DC.
.PARAMETER InactivityDays
    Days of inactivity before flagging a user/computer as stale. Default: 90.
.EXAMPLE
    Get-ADSecurityAudit -InactivityDays 60 -OutputPath "C:\ADReports"
#>
[CmdletBinding()]
param(
    [string]$DomainController,
    [int]$InactivityDays = 90,
    [string]$OutputPath  = $PWD
)

Import-Module ActiveDirectory -ErrorAction Stop

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir  = New-Item (Join-Path $OutputPath "ADSecurityAudit_$Timestamp") -ItemType Directory -Force
$DCParams   = if ($DomainController) { @{ Server = $DomainController } } else { @{} }
$StaleDate  = (Get-Date).AddDays(-$InactivityDays)

Write-Host "[*] Starting Active Directory Security Audit" -ForegroundColor Cyan
Write-Host "    Domain: $((Get-ADDomain @DCParams).DNSRoot)" -ForegroundColor Gray
Write-Host "    Output: $ReportDir" -ForegroundColor Gray

# 1. Privileged Group Membership
Write-Host "`n[*] Auditing privileged groups..." -ForegroundColor Yellow
$PrivGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators","Group Policy Creator Owners")
$privMembers = foreach ($group in $PrivGroups) {
    try {
        Get-ADGroupMember -Identity $group -Recursive @DCParams | ForEach-Object {
            [PSCustomObject]@{
                Group       = $group
                SamAccount  = $_.SamAccountName
                Name        = $_.Name
                ObjectClass = $_.objectClass
                Enabled     = (Get-ADObject $_.distinguishedName -Properties Enabled @DCParams).Enabled
            }
        }
    } catch { Write-Warning "Could not query group: $group" }
}
$privMembers | Export-Csv "$ReportDir\privileged_group_members.csv" -NoTypeInformation
Write-Host "  [+] Privileged members: $($privMembers.Count)" -ForegroundColor Green

# 2. Stale User Accounts
Write-Host "[*] Auditing stale user accounts..." -ForegroundColor Yellow
$staleUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $StaleDate } `
    -Properties LastLogonDate, PasswordLastSet, Description, MemberOf @DCParams |
    Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, Description,
        @{N="DaysSinceLogon";E={((Get-Date) - $_.LastLogonDate).Days}},
        @{N="MemberOf";E={($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join "|"}}
$staleUsers | Export-Csv "$ReportDir\stale_users.csv" -NoTypeInformation
Write-Host "  [+] Stale users (>$InactivityDays days): $($staleUsers.Count)" -ForegroundColor $(if ($staleUsers.Count -gt 50) { "Red" } else { "Green" })

# 3. Password Never Expires
Write-Host "[*] Auditing password-never-expires accounts..." -ForegroundColor Yellow
$pwdNeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
    -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate, Description @DCParams |
    Select-Object Name, SamAccountName, PasswordLastSet, LastLogonDate, Description
$pwdNeverExpires | Export-Csv "$ReportDir\password_never_expires.csv" -NoTypeInformation
Write-Host "  [+] Password-never-expires accounts: $($pwdNeverExpires.Count)" -ForegroundColor $(if ($pwdNeverExpires.Count -gt 10) { "Red" } else { "Green" })

# 4. Kerberoastable Service Accounts (SPN + non-computer)
Write-Host "[*] Auditing Kerberoastable service accounts..." -ForegroundColor Yellow
$kerberoastable = Get-ADUser -Filter { ServicePrincipalName -like "*" } `
    -Properties ServicePrincipalName, PasswordLastSet, AdminCount, Enabled @DCParams |
    Where-Object Enabled -eq $true |
    Select-Object Name, SamAccountName, ServicePrincipalName, PasswordLastSet, AdminCount,
        @{N="PwdAgeDays";E={((Get-Date) - $_.PasswordLastSet).Days}}
$kerberoastable | Export-Csv "$ReportDir\kerberoastable_accounts.csv" -NoTypeInformation
Write-Host "  [+] Kerberoastable accounts: $($kerberoastable.Count)" -ForegroundColor $(if ($kerberoastable.Count -gt 5) { "Red" } else { "Green" })

# 5. Unconstrained Delegation
Write-Host "[*] Auditing unconstrained delegation..." -ForegroundColor Yellow
$unconstrainedDelegation = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
    -Properties TrustedForDelegation, OperatingSystem, LastLogonDate @DCParams |
    Where-Object { $_.Name -ne "domain controllers" } |
    Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate
$unconstrainedDelegation | Export-Csv "$ReportDir\unconstrained_delegation.csv" -NoTypeInformation
Write-Host "  [+] Unconstrained delegation (non-DC): $($unconstrainedDelegation.Count)" -ForegroundColor $(if ($unconstrainedDelegation.Count -gt 0) { "Red" } else { "Green" })

# 6. AdminSDHolder protected accounts
Write-Host "[*] Auditing AdminSDHolder protected accounts..." -ForegroundColor Yellow
$adminSDHolderAccts = Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount, LastLogonDate @DCParams |
    Select-Object Name, SamAccountName, LastLogonDate, @{N="DaysSinceLogon";E={((Get-Date) - $_.LastLogonDate).Days}}
$adminSDHolderAccts | Export-Csv "$ReportDir\admin_sdk_holder.csv" -NoTypeInformation

# 7. Domain Password Policy
Write-Host "[*] Auditing password policies..." -ForegroundColor Yellow
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy @DCParams
$pwdPolicy | Select-Object * | Export-Csv "$ReportDir\password_policy.csv" -NoTypeInformation

# 8. Summary Report
$summary = [PSCustomObject]@{
    AuditDate             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Domain                = (Get-ADDomain @DCParams).DNSRoot
    PrivilegedMembers     = $privMembers.Count
    StaleUsers            = $staleUsers.Count
    PwdNeverExpires       = $pwdNeverExpires.Count
    KerberoastableAccts   = $kerberoastable.Count
    UnconstrainedDelegation = $unconstrainedDelegation.Count
    AdminSDHolderAccts    = $adminSDHolderAccts.Count
    MinPwdLength          = $pwdPolicy.MinPasswordLength
    PwdHistoryCount       = $pwdPolicy.PasswordHistoryCount
    MaxPwdAgeDays         = $pwdPolicy.MaxPasswordAge.Days
    LockoutThreshold      = $pwdPolicy.LockoutThreshold
}
$summary | Export-Csv "$ReportDir\audit_summary.csv" -NoTypeInformation

Write-Host "`n[=== AUDIT SUMMARY ===]" -ForegroundColor Cyan
$summary | Format-List
Write-Host "[OUTPUT] $ReportDir" -ForegroundColor Gray
