<#
.SYNOPSIS
    Sends GELF (Graylog Extended Log Format) messages to Graylog via UDP or HTTP.
.DESCRIPTION
    Formats PowerShell security events as GELF JSON and ships to Graylog
    via HTTP Input or UDP for SIEM ingestion and correlation.
.PARAMETER GraylogServer
    Graylog server hostname or IP.
.PARAMETER Port
    GELF HTTP Input port (default 12201) or UDP port.
.PARAMETER Protocol
    HTTP or UDP. Default: HTTP.
.EXAMPLE
    Send-GraylogGELF -GraylogServer "graylog.corp.local" -Port 12201 `
        -ShortMessage "CIS audit failure" -Host "SRV01" `
        -AdditionalFields @{ cis_control="2.3.1"; severity="high"; score=62 }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GraylogServer,
    [int]$Port                    = 12201,
    [ValidateSet("HTTP","UDP")][string]$Protocol = "HTTP",
    [Parameter(Mandatory)][string]$ShortMessage,
    [string]$FullMessage,
    [string]$Host_                = $env:COMPUTERNAME,
    [ValidateSet(0,1,2,3,4,5,6,7)][int]$Level = 6,
    [hashtable]$AdditionalFields  = @{}
)

$GELFMsg = @{
    version       = "1.1"
    host          = $Host_
    short_message = $ShortMessage
    full_message  = if ($FullMessage) { $FullMessage } else { $ShortMessage }
    timestamp     = [math]::Round(([DateTimeOffset]::UtcNow).ToUnixTimeMilliseconds() / 1000.0, 3)
    level         = $Level
}

foreach ($key in $AdditionalFields.Keys) {
    $GELFMsg["_$key"] = $AdditionalFields[$key]
}
$GELFMsg["_ps_host"]    = $env:COMPUTERNAME
$GELFMsg["_ps_user"]    = $env:USERNAME
$GELFMsg["_ps_version"] = $PSVersionTable.PSVersion.ToString()

$json = $GELFMsg | ConvertTo-Json -Compress

if ($Protocol -eq "HTTP") {
    Invoke-RestMethod -Uri "http://${GraylogServer}:${Port}/gelf" -Method POST `
        -Body $json -ContentType "application/json" -ErrorAction Stop | Out-Null
    Write-Verbose "[GELF] Sent via HTTP to ${GraylogServer}:${Port}"
} else {
    $ep  = [System.Net.IPEndPoint]::new([System.Net.Dns]::GetHostAddresses($GraylogServer)[0], $Port)
    $udp = [System.Net.Sockets.UdpClient]::new()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $udp.Send($bytes, $bytes.Length, $ep) | Out-Null
    $udp.Close()
    Write-Verbose "[GELF] Sent via UDP to ${GraylogServer}:${Port}"
}
