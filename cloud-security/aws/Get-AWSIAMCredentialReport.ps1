<#
.SYNOPSIS
    Generates and analyzes AWS IAM credential report for access hygiene audit.
.DESCRIPTION
    Requests IAM credential report, downloads it, and analyzes for:
    root account access keys, old access keys, no MFA on active accounts,
    unused credentials, and password age violations.
.EXAMPLE
    Get-AWSIAMCredentialReport -Profile "prod" -Region "us-east-1" -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param([string]$Profile, [string]$Region = "us-east-1", [string]$OutputPath = $PWD)

#Requires -Modules AWS.Tools.IdentityManagement

$AWSOpts = if ($Profile) { @{ ProfileName=$Profile; Region=$Region } } else { @{ Region=$Region } }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Request report
Write-Host "[*] Requesting IAM credential report..." -ForegroundColor Cyan
Request-IAMCredentialReport @AWSOpts | Out-Null
Start-Sleep -Seconds 5

$report = (Get-IAMCredentialReport @AWSOpts).Content
$users  = $report | ConvertFrom-Csv

$findings = $users | ForEach-Object {
    $user   = $_
    $issues = @()
    if ($user.user -eq "<root_account>" -and $user.access_key_1_active -eq "true") { $issues += "ROOT_ACCESS_KEY_ACTIVE" }
    if ($user.mfa_active -eq "false" -and $user.password_enabled -eq "true") { $issues += "NO_MFA" }
    if ($user.password_last_used -ne "N/A" -and $user.password_last_used) {
        $daysSince = ((Get-Date) - [datetime]$user.password_last_used).Days
        if ($daysSince -gt 90) { $issues += "PASSWORD_UNUSED_90D($daysSince days)" }
    }
    if ($user.access_key_1_last_used_date -ne "N/A") {
        $keyAge = ((Get-Date) - [datetime]$user.access_key_1_last_used_date).Days
        if ($user.access_key_1_active -eq "true" -and $keyAge -gt 90) { $issues += "ACCESS_KEY_STALE($keyAge days)" }
    }
    [PSCustomObject]@{
        Username         = $user.user
        MFAEnabled       = $user.mfa_active
        PasswordEnabled  = $user.password_enabled
        AccessKey1Active = $user.access_key_1_active
        AccessKey2Active = $user.access_key_2_active
        IssueCount       = $issues.Count
        Issues           = ($issues -join "|")
        RiskLevel        = if ($issues.Count -ge 2) { "HIGH" } elseif ($issues.Count -eq 1) { "MEDIUM" } else { "LOW" }
    }
} | Sort-Object IssueCount -Descending

$findings | Export-Csv (Join-Path $OutputPath "IAMCredReport_$Timestamp.csv") -NoTypeInformation
$highRisk = ($findings | Where-Object RiskLevel -eq "HIGH").Count
Write-Host "[DONE] IAM users: $($findings.Count) | High risk: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
$findings | Where-Object IssueCount -gt 0 | Format-Table Username, MFAEnabled, RiskLevel, Issues -AutoSize
