<#
.SYNOPSIS
    Get-ADStaleAccounts - Active Directory security automation script.
.DESCRIPTION
    Part of the enterprise AD security toolkit. See full documentation in README.md.
.EXAMPLE
    ./Get-ADStaleAccounts.ps1
#>
[CmdletBinding()]
param([string] = $PWD, [int] = 90)
Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "[*] Running Get-ADStaleAccounts..." -ForegroundColor Cyan
$cutoff = (Get-Date).AddDays(-$Days)
$staleUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
    -Properties LastLogonDate, PasswordLastSet, Department, Manager |
    Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, Department,
        @{N="DaysSinceLogin"; E={((Get-Date)-$_.LastLogonDate).Days}}
$staleComputers = Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
    -Properties LastLogonDate, OperatingSystem |
    Select-Object Name, LastLogonDate, OperatingSystem, @{N="DaysSinceLogin";E={((Get-Date)-$_.LastLogonDate).Days}}
$staleUsers     | Export-Csv "$OutputPath\StaleUsers_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
$staleComputers | Export-Csv "$OutputPath\StaleComputers_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
Write-Host "[DONE] Stale users: $($staleUsers.Count) | Stale computers: $($staleComputers.Count)" -ForegroundColor Yellow
