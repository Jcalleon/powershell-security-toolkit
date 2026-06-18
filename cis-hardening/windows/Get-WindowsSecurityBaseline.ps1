<#
.SYNOPSIS
    Exports current Windows security baseline configuration for comparison or documentation.
.DESCRIPTION
    Collects security-relevant settings: audit policy, firewall rules, local users,
    installed patches, running services, startup items, and open network connections.
.PARAMETER OutputPath
    Directory to save the baseline export. Default: current directory.
.EXAMPLE
    Get-WindowsSecurityBaseline -OutputPath "C:\Baselines"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir   = New-Item -Path (Join-Path $OutputPath "Baseline_$Timestamp") -ItemType Directory -Force

Write-Host "[*] Collecting Windows Security Baseline..." -ForegroundColor Cyan

# Audit Policy
Write-Host "  [*] Audit policy..." -ForegroundColor Gray
auditpol /get /category:* > "$BaseDir\audit_policy.txt"

# Firewall Rules
Write-Host "  [*] Firewall rules..." -ForegroundColor Gray
Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object Name, Direction, Action, Profile, DisplayName |
    Export-Csv "$BaseDir\firewall_rules.csv" -NoTypeInformation

# Local Users & Groups
Write-Host "  [*] Local accounts..." -ForegroundColor Gray
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon, PasswordNeverExpires |
    Export-Csv "$BaseDir\local_users.csv" -NoTypeInformation
Get-LocalGroupMember -Group "Administrators" | Export-Csv "$BaseDir\local_admins.csv" -NoTypeInformation

# Installed Patches
Write-Host "  [*] Patch inventory..." -ForegroundColor Gray
Get-HotFix | Sort-Object InstalledOn -Descending | Export-Csv "$BaseDir\hotfixes.csv" -NoTypeInformation

# Running Services
Write-Host "  [*] Services..." -ForegroundColor Gray
Get-Service | Where-Object Status -eq "Running" | Select-Object Name, DisplayName, StartType |
    Export-Csv "$BaseDir\running_services.csv" -NoTypeInformation

# Open Network Connections
Write-Host "  [*] Network connections..." -ForegroundColor Gray
Get-NetTCPConnection | Where-Object State -eq "Listen" | Select-Object LocalAddress, LocalPort, OwningProcess |
    ForEach-Object { $_ | Add-Member -NotePropertyName "Process" -NotePropertyValue (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -PassThru } |
    Export-Csv "$BaseDir\listening_ports.csv" -NoTypeInformation

# Scheduled Tasks (potential persistence)
Write-Host "  [*] Scheduled tasks..." -ForegroundColor Gray
Get-ScheduledTask | Where-Object State -ne "Disabled" | Select-Object TaskName, TaskPath, State |
    Export-Csv "$BaseDir\scheduled_tasks.csv" -NoTypeInformation

# Startup Programs
Write-Host "  [*] Startup items..." -ForegroundColor Gray
$StartupKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$startupItems = foreach ($key in $StartupKeys) {
    if (Test-Path $key) {
        (Get-ItemProperty $key).PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } |
            Select-Object @{N="Hive";E={$key}}, Name, Value
    }
}
$startupItems | Export-Csv "$BaseDir\startup_items.csv" -NoTypeInformation

# Installed Software
Write-Host "  [*] Installed software..." -ForegroundColor Gray
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object DisplayName | Sort-Object DisplayName |
    Export-Csv "$BaseDir\installed_software.csv" -NoTypeInformation

Write-Host "`n[DONE] Baseline saved to: $BaseDir" -ForegroundColor Green
