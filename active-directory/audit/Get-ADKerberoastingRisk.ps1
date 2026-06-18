<#
.SYNOPSIS
    Identifies Kerberoastable accounts and assesses cracking risk based on password age.
.DESCRIPTION
    Finds all service accounts with SPNs, scores cracking risk by password age
    and account privilege level. Generates prioritized remediation list.
.EXAMPLE
    Get-ADKerberoastingRisk -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
Import-Module ActiveDirectory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$accounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } `
    -Properties ServicePrincipalName, PasswordLastSet, AdminCount, MemberOf, Enabled, LastLogonDate |
    Where-Object Enabled -eq $true

$results = $accounts | ForEach-Object {
    $pwdAge   = ((Get-Date) - $_.PasswordLastSet).Days
    $isAdmin  = $_.AdminCount -eq 1
    $isPriv   = ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -match "Domain Admins|Enterprise Admins|Schema Admins"

    $riskScore = 0
    if ($pwdAge -gt 365) { $riskScore += 40 }
    elseif ($pwdAge -gt 90) { $riskScore += 20 }
    if ($isAdmin) { $riskScore += 40 }
    if ($isPriv)  { $riskScore += 20 }

    [PSCustomObject]@{
        Account         = $_.SamAccountName
        SPNs            = ($_.ServicePrincipalName -join "|")
        PasswordAgeDays = $pwdAge
        IsAdmin         = $isAdmin
        IsPrivileged    = [bool]$isPriv
        RiskScore       = $riskScore
        RiskLevel       = if ($riskScore -ge 60) { "CRITICAL" } elseif ($riskScore -ge 30) { "HIGH" } else { "MEDIUM" }
        Recommendation  = if ($pwdAge -gt 365) { "Rotate password immediately" } else { "Review SPN necessity" }
    }
} | Sort-Object RiskScore -Descending

$results | Export-Csv (Join-Path $OutputPath "KerberoastingRisk_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Kerberoastable accounts: $($results.Count) | Critical: $(($results|Where-Object RiskLevel -eq 'CRITICAL').Count)" -ForegroundColor $(
    if (($results|Where-Object RiskLevel -eq 'CRITICAL').Count -gt 0) { "Red" } else { "Yellow" })
$results | Format-Table Account, PasswordAgeDays, RiskLevel, Recommendation -AutoSize
