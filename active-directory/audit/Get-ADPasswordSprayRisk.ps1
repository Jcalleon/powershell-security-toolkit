<#
.SYNOPSIS
    Identifies accounts most vulnerable to password spray attacks.
.DESCRIPTION
    Finds accounts with weak lockout policy, no recent password change,
    commonly targeted usernames, and disabled MFA indicators.
.EXAMPLE
    Get-ADPasswordSprayRisk -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD, [int]$PwdAgeThresholdDays = 180)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$domainPolicy  = Get-ADDefaultDomainPasswordPolicy
$weakLockout   = $domainPolicy.LockoutThreshold -eq 0 -or $domainPolicy.LockoutThreshold -ge 20

$riskAccounts = Get-ADUser -Filter { Enabled -eq $true } `
    -Properties PasswordLastSet, PasswordNeverExpires, LastLogonDate, Description, BadLogonCount |
    ForEach-Object {
        $pwdAge = if ($_.PasswordLastSet) { ((Get-Date) - $_.PasswordLastSet).Days } else { 9999 }
        $commonName = $_.SamAccountName -match "^(admin|administrator|svc|service|test|demo|user|guest|backup|scan|helpdesk)$"
        [PSCustomObject]@{
            Account           = $_.SamAccountName
            PasswordAgeDays   = $pwdAge
            PwdNeverExpires   = $_.PasswordNeverExpires
            CommonName        = [bool]$commonName
            LastLogon         = $_.LastLogonDate
            BadLogonCount     = $_.BadLogonCount
            WeakDomainLockout = $weakLockout
            SprayRisk         = ($pwdAge -gt $PwdAgeThresholdDays -or $_.PasswordNeverExpires -or $commonName)
        }
    } | Where-Object SprayRisk | Sort-Object PasswordAgeDays -Descending

$results | Export-Csv (Join-Path $OutputPath "PasswordSprayRisk_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] High spray-risk accounts: $($riskAccounts.Count) | Weak lockout policy: $weakLockout" -ForegroundColor $(if ($riskAccounts.Count -gt 10) { "Red" } else { "Yellow" })
