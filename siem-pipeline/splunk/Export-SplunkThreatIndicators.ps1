<#
.SYNOPSIS
    Exports threat indicators (IOCs) from Splunk threat intelligence lookups for sharing.
.DESCRIPTION
    Queries Splunk threat intel lookup tables (IPs, domains, hashes) and exports
    in STIX-compatible CSV format for sharing with threat intel platforms or
    other SIEM tools. Useful for automating IOC lifecycle management.
.EXAMPLE
    Export-SplunkThreatIndicators -SplunkServer "splunk.corp.local" -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SplunkServer,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [string[]]$LookupTables = @("ip_intel","domain_intel","file_intel"),
    [string]$OutputPath = $PWD
)

$BaseUrl = "https://${SplunkServer}:8089"
$auth    = @{ Credential=$Credential; SkipCertificateCheck=$true }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$allIOCs = [System.Collections.Generic.List[PSObject]]::new()
foreach ($table in $LookupTables) {
    try {
        Write-Host "[*] Exporting lookup: $table" -ForegroundColor Cyan
        $raw = Invoke-RestMethod -Uri "$BaseUrl/services/data/lookup-table-files/$table.csv" `
            -Method GET @auth
        $iocs = $raw | ConvertFrom-Csv
        $iocs | ForEach-Object { $_ | Add-Member -NotePropertyName "SourceLookup" -NotePropertyValue $table -PassThru } |
            ForEach-Object { $allIOCs.Add($_) }
        Write-Host "  [+] $($iocs.Count) IOCs from $table" -ForegroundColor Green
    } catch { Write-Warning "Could not access lookup: $table" }
}

$allIOCs | Export-Csv (Join-Path $OutputPath "ThreatIndicators_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Total IOCs exported: $($allIOCs.Count)" -ForegroundColor Green
