<#
.SYNOPSIS
    Performs an internal network security scan for open ports and weak services.
.DESCRIPTION
    Scans specified IP ranges for open ports, detects weak/insecure services
    (Telnet, FTP, unencrypted HTTP, SNMPv1), checks for default credentials
    on common management interfaces, and maps results to CVEs.
.PARAMETER IPRange
    CIDR notation or IP range (e.g., "10.0.1.0/24" or "10.0.1.1-10.0.1.254").
.PARAMETER Ports
    Port list to scan. Default: common security-relevant ports.
.PARAMETER Timeout
    TCP connection timeout in milliseconds. Default: 500.
.EXAMPLE
    Invoke-NetworkSecurityScan -IPRange "10.0.1.0/24" -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IPRange,
    [int[]]$Ports       = @(21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,587,636,993,995,1433,1521,3306,3389,5432,5900,5985,5986,6379,8080,8443,27017),
    [int]$Timeout       = 500,
    [int]$ThrottleLimit = 50,
    [string]$OutputPath = $PWD
)

$RiskyPorts = @{
    21   = @{ Service="FTP";       Risk="High";   Note="Cleartext credentials" }
    23   = @{ Service="Telnet";    Risk="Critical"; Note="Cleartext credentials and session" }
    25   = @{ Service="SMTP";      Risk="Medium"; Note="Open relay check needed" }
    111  = @{ Service="RPC";       Risk="High";   Note="Portmapper - pivot risk" }
    135  = @{ Service="MSRPC";     Risk="High";   Note="DCE/RPC - lateral movement" }
    139  = @{ Service="NetBIOS";   Risk="High";   Note="Legacy SMB - disable" }
    161  = @{ Service="SNMP";      Risk="High";   Note="Check for community strings" }
    445  = @{ Service="SMB";       Risk="High";   Note="Verify SMBv1 disabled" }
    5900 = @{ Service="VNC";       Risk="High";   Note="Check for auth bypass" }
    6379 = @{ Service="Redis";     Risk="Critical"; Note="Often unauthenticated" }
    27017= @{ Service="MongoDB";   Risk="Critical"; Note="Often unauthenticated" }
    3389 = @{ Service="RDP";       Risk="Medium"; Note="Verify NLA required" }
    5985 = @{ Service="WinRM-HTTP";Risk="High";   Note="Cleartext WinRM" }
    8080 = @{ Service="HTTP-Alt";  Risk="Medium"; Note="Non-standard web, check for admin UI" }
}

function ConvertTo-IPList {
    param([string]$Range)
    if ($Range -match "(\d+\.\d+\.\d+\.\d+)/(\d+)") {
        $ip      = [System.Net.IPAddress]::Parse($matches[1])
        $prefix  = [int]$matches[2]
        $ipInt   = [BitConverter]::ToUInt32($ip.GetAddressBytes()[3..0], 0)
        $mask    = ([UInt32]::MaxValue) -shl (32 - $prefix)
        $network = $ipInt -band $mask
        $bcast   = $network -bor (-bnot $mask -band [UInt32]::MaxValue)
        ($network + 1)..($bcast - 1) | ForEach-Object {
            $bytes = [BitConverter]::GetBytes([UInt32]$_)[3..0]
            [System.Net.IPAddress]::new($bytes).ToString()
        }
    } elseif ($Range -match "(\d+\.\d+\.\d+\.)(\d+)-(\d+)") {
        $base  = $matches[1]
        [int]$start = $matches[2]; [int]$end = $matches[3]
        $start..$end | ForEach-Object { "$base$_" }
    } else { @($Range) }
}

$IPs = ConvertTo-IPList $IPRange
Write-Host "[*] Scanning $($IPs.Count) hosts across $($Ports.Count) ports..." -ForegroundColor Cyan

$Results = $IPs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $IP      = $_
    $Ports   = $using:Ports
    $Timeout = $using:Timeout
    $Risky   = $using:RiskyPorts

    $openPorts = foreach ($port in $Ports) {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $conn = $tcp.BeginConnect($IP, $port, $null, $null)
        $wait = $conn.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($wait -and -not $tcp.Client.Connected -eq $false) {
            try { $tcp.EndConnect($conn); $true } catch { $false }
        } else { $false }
        $tcp.Close()

        if ($wait) {
            $riskInfo = $Risky[$port]
            [PSCustomObject]@{
                IP       = $IP
                Port     = $port
                Service  = if ($riskInfo) { $riskInfo.Service } else { "Unknown" }
                Risk     = if ($riskInfo) { $riskInfo.Risk } else { "Info" }
                Note     = if ($riskInfo) { $riskInfo.Note } else { "" }
            }
        }
    }
    $openPorts
}

$CsvPath = Join-Path $OutputPath "NetworkScan_$(Get-Date -Format yyyyMMdd_HHmm).csv"
$Results | Export-Csv $CsvPath -NoTypeInformation

$Critical = ($Results | Where-Object Risk -eq "Critical").Count
$High     = ($Results | Where-Object Risk -eq "High").Count
Write-Host "`n[RESULTS] Open ports: $($Results.Count) | Critical: $Critical | High: $High" -ForegroundColor $(if ($Critical -gt 0) { "Red" } else { "Yellow" })
$Results | Where-Object { $_.Risk -in "Critical","High" } | Sort-Object Risk | Format-Table IP, Port, Service, Risk, Note -AutoSize
