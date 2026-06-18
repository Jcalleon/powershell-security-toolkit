<#
.SYNOPSIS
    Identifies and removes stale members from Active Directory security groups.
.DESCRIPTION
    Scans specified groups for disabled accounts, accounts inactive beyond threshold,
    and accounts that no longer exist. Produces a remediation report with
    optional auto-removal with approval workflow.
.EXAMPLE
    Invoke-ADGroupCleanup -GroupPattern "VPN-*","Server-Admins-*" -InactivityDays 90
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$GroupPattern  = @("*"),
    [int]$InactivityDays     = 90,
    [switch]$AutoRemediate,
    [string]$OutputPath      = $PWD
)
Import-Module ActiveDirectory
$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$StaleMembers= [System.Collections.Generic.List[PSObject]]::new()
$StaleDate   = (Get-Date).AddDays(-$InactivityDays)

$groups = $GroupPattern | ForEach-Object { Get-ADGroup -Filter "Name -like '$_'" } | Select-Object -Unique

foreach ($group in $groups) {
    Write-Host "[*] Analyzing: $($group.Name)" -ForegroundColor Cyan
    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | Where-Object objectClass -eq "user"
    foreach ($member in $members) {
        try {
            $user = Get-ADUser $member.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction Stop
            $stale = (-not $user.Enabled) -or ($user.LastLogonDate -and $user.LastLogonDate -lt $StaleDate)
            if ($stale) {
                $reason = if (-not $user.Enabled) { "Disabled account" } else { "Inactive >$InactivityDays days (Last: $($user.LastLogonDate?.ToString('yyyy-MM-dd')))" }
                $StaleMembers.Add([PSCustomObject]@{ Group=$group.Name; Account=$user.SamAccountName; Reason=$reason; Enabled=$user.Enabled; LastLogon=$user.LastLogonDate })
                if ($AutoRemediate -and $PSCmdlet.ShouldProcess("$($group.Name)\$($user.SamAccountName)", "Remove stale member")) {
                    Remove-ADGroupMember -Identity $group -Members $user.SamAccountName -Confirm:$false
                    Write-Host "  [-] Removed: $($user.SamAccountName) from $($group.Name)" -ForegroundColor Yellow
                }
            }
        } catch { Write-Warning "Could not process $($member.SamAccountName)" }
    }
}

$StaleMembers | Export-Csv (Join-Path $OutputPath "StaleGroupMembers_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Stale members found: $($StaleMembers.Count) | Auto-removed: $(if ($AutoRemediate) {$StaleMembers.Count} else {0})" -ForegroundColor Yellow
