<#
.SYNOPSIS
    Configures Windows Firewall to CIS benchmark standards with custom rule sets.
.DESCRIPTION
    Enables all firewall profiles, sets default deny-inbound policy, blocks
    known dangerous ports, and creates baseline allow rules for common services.
.EXAMPLE
    Set-WindowsFirewallPolicy
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$BlockRDP,
    [string[]]$AllowedRDPSources = @()
)

#Requires -RunAsAdministrator

Write-Host "[*] Configuring Windows Firewall..." -ForegroundColor Cyan

# Enable all profiles with default deny inbound
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True
Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes 32767

Write-Host "  [+] All profiles: enabled, default inbound block, logging on" -ForegroundColor Green

# Remove overly permissive default rules
$rulesToRemove = @(
    "File and Printer Sharing*",
    "Network Discovery*",
    "Remote Assistance*"
)
foreach ($pattern in $rulesToRemove) {
    Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.Profile -eq "Any" -or $_.Profile -eq "Public" } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

# Block dangerous inbound ports
$BlockPorts = @(
    @{ Port=23;   Protocol="TCP"; Description="Telnet" },
    @{ Port=135;  Protocol="TCP"; Description="RPC Endpoint Mapper" },
    @{ Port=137;  Protocol="UDP"; Description="NetBIOS Name Service" },
    @{ Port=138;  Protocol="UDP"; Description="NetBIOS Datagram" },
    @{ Port=139;  Protocol="TCP"; Description="NetBIOS Session" },
    @{ Port=445;  Protocol="TCP"; Description="SMB (from WAN)" },
    @{ Port=593;  Protocol="TCP"; Description="RPC over HTTP" },
    @{ Port=1433; Protocol="TCP"; Description="MSSQL (explicit block)" },
    @{ Port=4444; Protocol="TCP"; Description="Metasploit default listener" },
    @{ Port=5985; Protocol="TCP"; Description="WinRM HTTP" },
    @{ Port=5986; Protocol="TCP"; Description="WinRM HTTPS" }
)
foreach ($rule in $BlockPorts) {
    New-NetFirewallRule -DisplayName "BLOCK_$($rule.Description)" `
        -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port `
        -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  [+] Blocked inbound $($rule.Protocol)/$($rule.Port) ($($rule.Description))" -ForegroundColor Green
}

# RDP rule
if ($BlockRDP) {
    New-NetFirewallRule -DisplayName "BLOCK_RDP_All" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Any | Out-Null
    Write-Host "  [+] RDP blocked on all profiles" -ForegroundColor Yellow
} elseif ($AllowedRDPSources.Count -gt 0) {
    New-NetFirewallRule -DisplayName "ALLOW_RDP_Restricted" -Direction Inbound -Protocol TCP -LocalPort 3389 `
        -RemoteAddress $AllowedRDPSources -Action Allow -Profile Domain,Private | Out-Null
    Write-Host "  [+] RDP restricted to: $($AllowedRDPSources -join ', ')" -ForegroundColor Green
}

Write-Host "`n[DONE] Firewall policy applied." -ForegroundColor Green
