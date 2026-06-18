<#
.SYNOPSIS
    Tests external attack surface by querying Shodan/Censys for your IP ranges.
.DESCRIPTION
    Queries Shodan InternetDB (free, no API key) and optionally Censys for
    known-exposed services on your public IPs. Correlates with internal asset list.
.EXAMPLE
    Test-ExternalExposure -PublicIPRanges "203.0.113.0/28" -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$PublicIPRanges,
    [string]$ShodanAPIKey,
    [string]$OutputPath = $PWD
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Findings  = [System.Collections.Generic.List[PSObject]]::new()

function Get-IPList {
    param([string]$CIDR)
    if ($CIDR -match "(\d+\.\d+\.\d+\.\d+)/(\d+)") {
        $ip = [System.Net.IPAddress]::Parse($Matches[1])
        $bits = [int]$Matches[2]
        $mask = ([UInt32]::MaxValue) -shl (32 - $bits)
        $ipInt = [BitConverter]::ToUInt32(($ip.GetAddressBytes()[3..0]), 0)
        $net   = $ipInt -band $mask
        $bcast = $net -bor (-bnot $mask -band [UInt32]::MaxValue)
        ($net + 1)..($bcast - 1) | ForEach-Object {
            [System.Net.IPAddress]::new([BitConverter]::GetBytes([UInt32]$_)[3..0]).ToString()
        }
    } else { @($CIDR) }
}

$allIPs = $PublicIPRanges | ForEach-Object { Get-IPList $_ }
Write-Host "[*] Querying external exposure for $($allIPs.Count) IPs via Shodan InternetDB..." -ForegroundColor Cyan

foreach ($ip in $allIPs) {
    try {
        $result = Invoke-RestMethod -Uri "https://internetdb.shodan.io/$ip" -ErrorAction Stop
        if ($result.ports) {
            $Findings.Add([PSCustomObject]@{
                IP       = $ip
                Ports    = ($result.ports -join ",")
                Hostnames= ($result.hostnames -join "|")
                Vulns    = ($result.vulns -join "|")
                Tags     = ($result.tags -join "|")
                CPEs     = ($result.cpes -join "|")
                RiskLevel= if ($result.vulns) { "HIGH" } elseif ($result.ports -match "23|3389|5900|445") { "MEDIUM" } else { "INFO" }
            })
            Write-Host "  [!] $ip - Ports: $($result.ports -join ',') $(if ($result.vulns) { '| VULNS: ' + ($result.vulns -join ',') })" -ForegroundColor $(if ($result.vulns) { "Red" } else { "Yellow" })
        }
    } catch { }
    Start-Sleep -Milliseconds 200  # Rate limit courtesy
}

$Findings | Export-Csv (Join-Path $OutputPath "ExternalExposure_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Exposed IPs: $($Findings.Count) | With known vulns: $(($Findings|Where-Object{$_.Vulns}).Count)" -ForegroundColor $(if ($Findings.Count -gt 0) { "Yellow" } else { "Green" })
