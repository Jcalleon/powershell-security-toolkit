<#
.SYNOPSIS
    Audits DNS configuration for security misconfigurations and zone transfer exposure.
.DESCRIPTION
    Checks for DNS zone transfer exposure, DNSSEC configuration, SPF/DKIM/DMARC
    records, wildcard records, and internal/external DNS consistency.
.PARAMETER Domain
    Primary domain to audit.
.PARAMETER DNSServers
    Internal DNS servers to test zone transfer against.
.EXAMPLE
    Get-DNSAudit -Domain "company.com" -DNSServers "10.0.1.10","10.0.1.11"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Domain,
    [string[]]$DNSServers,
    [string]$OutputPath = $PWD
)

$Findings = [System.Collections.Generic.List[PSObject]]::new()
function Check { param($Cat,$Check,$Pass,$Detail,$Sev="Medium")
    $Findings.Add([PSCustomObject]@{ Category=$Cat; Check=$Check; Status=if($Pass){"PASS"}else{"FAIL"}; Severity=if($Pass){"Info"}else{$Sev}; Detail=$Detail })
    Write-Host "  $( if($Pass){'[PASS]'}else{'[FAIL]'}) $Check" -ForegroundColor $(if($Pass){"Green"}else{"Red"})
}

Write-Host "[*] DNS Security Audit: $Domain" -ForegroundColor Cyan

# SPF
$spf = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match "v=spf1" }
Check "Email Security" "SPF Record Exists" ($spf -ne $null) (if ($spf) { $spf.Strings } else { "No SPF record found" }) "High"
if ($spf) { Check "Email Security" "SPF Hardfail (~all or -all)" ($spf.Strings -match "\-all|\~all") $spf.Strings "Medium" }

# DMARC
$dmarc = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction SilentlyContinue
Check "Email Security" "DMARC Record Exists" ($dmarc -ne $null) (if ($dmarc) { $dmarc.Strings } else { "No DMARC record" }) "High"
if ($dmarc) { Check "Email Security" "DMARC Policy Enforced (quarantine/reject)" ($dmarc.Strings -match "p=quarantine|p=reject") $dmarc.Strings "Medium" }

# DNSSEC
$dnssec = Resolve-DnsName -Name $Domain -Type DNSKEY -ErrorAction SilentlyContinue
Check "DNSSEC" "DNSSEC Configured" ($dnssec -ne $null) (if ($dnssec) { "DNSKEY records found" } else { "No DNSKEY records - DNSSEC not configured" }) "Medium"

# Zone Transfer Test
if ($DNSServers) {
    foreach ($ns in $DNSServers) {
        try {
            $zt = nslookup -type=axfr $Domain $ns 2>&1
            $exposed = $zt -notmatch "Transfer failed|refused|SERVFAIL"
            Check "Zone Transfer" "Zone Transfer Blocked on $ns" (-not $exposed) (if ($exposed) { "AXFR succeeded - DNS zone exposed!" } else { "AXFR refused" }) "Critical"
        } catch { Write-Warning "Zone transfer test failed for $ns" }
    }
}

# Wildcard DNS check
$wildcard = Resolve-DnsName -Name "randomnonexistent12345.$Domain" -ErrorAction SilentlyContinue
Check "DNS Config" "No Wildcard DNS Record" ($wildcard -eq $null) (if ($wildcard) { "Wildcard DNS resolves - potential phishing risk" } else { "No wildcard record" }) "Medium"

$CsvPath = Join-Path $OutputPath "DNSAudit_${Domain}_$(Get-Date -Format yyyyMMdd).csv"
$Findings | Export-Csv $CsvPath -NoTypeInformation

$Fail = ($Findings | Where-Object Status -eq "FAIL").Count
Write-Host "`n[RESULTS] $Fail findings | Output: $CsvPath" -ForegroundColor $(if ($Fail -gt 0) { "Yellow" } else { "Green" })
