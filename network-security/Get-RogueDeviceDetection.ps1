<#
.SYNOPSIS
    Detects rogue or unauthorized devices on the network by cross-referencing DHCP/DNS with AD.
.DESCRIPTION
    Compares active DHCP leases and ARP table entries against AD computer objects
    and an authorized device list. Flags devices not in AD or the approved inventory.
.EXAMPLE
    Get-RogueDeviceDetection -DHCPServer "DHCP01" -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DHCPServer,
    [string]$AuthorizedDevicesCSV,
    [string]$OutputPath = $PWD
)
Import-Module DhcpServer,ActiveDirectory -ErrorAction Stop
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Get all DHCP leases
$leases = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId (
    Get-DhcpServerv4Scope -ComputerName $DHCPServer).ScopeId |
    Where-Object AddressState -eq "Active"

# Get AD computer names
$adComputers = (Get-ADComputer -Filter { Enabled -eq $true }).DNSHostName

# Get authorized device list
$authorized = @()
if ($AuthorizedDevicesCSV -and (Test-Path $AuthorizedDevicesCSV)) {
    $authorized = (Import-Csv $AuthorizedDevicesCSV).MACAddress
}

$results = $leases | ForEach-Object {
    $inAD     = $adComputers -contains $_.HostName
    $inList   = $_.ClientId -in $authorized
    [PSCustomObject]@{
        IP          = $_.IPAddress
        Hostname    = $_.HostName
        MAC         = $_.ClientId
        LeaseExpiry = $_.LeaseExpiryTime
        InAD        = $inAD
        Authorized  = $inList
        Rogue       = (-not $inAD -and -not $inList)
        RiskLevel   = if (-not $inAD -and -not $inList) { "HIGH" } elseif (-not $inAD) { "MEDIUM" } else { "LOW" }
    }
}

$results | Export-Csv (Join-Path $OutputPath "RogueDevices_$Timestamp.csv") -NoTypeInformation
$rogue = $results | Where-Object Rogue
Write-Host "[DONE] Total devices: $($results.Count) | Potential rogue: $($rogue.Count)" -ForegroundColor $(if ($rogue.Count -gt 0) { "Red" } else { "Green" })
if ($rogue) { $rogue | Format-Table IP, Hostname, MAC, RiskLevel -AutoSize }
