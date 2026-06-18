<#
.SYNOPSIS
    Maps security tool coverage to NIST CSF and CIS Control framework categories.
.DESCRIPTION
    Evaluates which security controls are covered by existing tools and scripts,
    identifies gaps, and produces a coverage heat map for risk assessment and
    audit evidence (SOC 2, ISO 27001, FedRAMP).
.EXAMPLE
    Get-SecurityControlCoverage -OutputPath "C:\Reports\Compliance"
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$ControlMatrix = @(
    @{ CISControl="1"; Title="Inventory of Enterprise Assets";           NISTFunction="Identify";  Tools=@("Get-EDRDeploymentStatus","Get-RogueDeviceDetection");       CoveredBy="EDR, DHCP audit" },
    @{ CISControl="2"; Title="Inventory of Software Assets";             NISTFunction="Identify";  Tools=@("Get-InstalledSoftwareAudit");                               CoveredBy="Software audit script" },
    @{ CISControl="3"; Title="Data Protection";                          NISTFunction="Protect";   Tools=@("Invoke-BitLockerAudit");                                    CoveredBy="BitLocker audit" },
    @{ CISControl="4"; Title="Secure Configuration";                     NISTFunction="Protect";   Tools=@("Invoke-CISBenchmarkAudit","Set-CISWindowsHardening");       CoveredBy="CIS hardening scripts" },
    @{ CISControl="5"; Title="Account Management";                       NISTFunction="Protect";   Tools=@("Get-ADSecurityAudit","Invoke-ADUserProvisioning");          CoveredBy="AD provisioning + audit" },
    @{ CISControl="6"; Title="Access Control Management";                NISTFunction="Protect";   Tools=@("Get-ADPrivilegedAccessAudit","Set-ADFineGrainedPasswordPolicy"); CoveredBy="AD PAM scripts" },
    @{ CISControl="7"; Title="Continuous Vulnerability Management";      NISTFunction="Identify";  Tools=@("Get-QualysScanResults","Get-TenableVulnerabilities");       CoveredBy="Qualys + Tenable integration" },
    @{ CISControl="8"; Title="Audit Log Management";                     NISTFunction="Detect";    Tools=@("Set-WindowsAuditPolicy","Send-SplunkHECEvent");             CoveredBy="Audit policy + SIEM pipeline" },
    @{ CISControl="9"; Title="Email and Web Browser Protections";        NISTFunction="Protect";   Tools=@("Get-DNSAudit");                                            CoveredBy="DNS/SPF/DMARC audit" },
    @{ CISControl="10"; Title="Malware Defenses";                        NISTFunction="Protect";   Tools=@("Get-WindowsDefenderStatus","Get-EDRDeploymentStatus");      CoveredBy="Defender + EDR coverage" },
    @{ CISControl="11"; Title="Data Recovery";                           NISTFunction="Recover";   Tools=@();                                                          CoveredBy="GAP - No current script" },
    @{ CISControl="12"; Title="Network Infrastructure Management";       NISTFunction="Protect";   Tools=@("Invoke-NetworkSecurityScan","Get-SMBShareAudit");           CoveredBy="Network scan + share audit" },
    @{ CISControl="13"; Title="Network Monitoring and Defense";          NISTFunction="Detect";    Tools=@("Get-RogueDeviceDetection","Invoke-SplunkSearchAPI");        CoveredBy="Rogue device + SIEM query" },
    @{ CISControl="16"; Title="Application Software Security";           NISTFunction="Protect";   Tools=@("Invoke-AppLockerPolicy");                                  CoveredBy="AppLocker policy" },
    @{ CISControl="17"; Title="Incident Response Management";            NISTFunction="Respond";   Tools=@("Invoke-LiveResponseCollection","Invoke-ThreatContainment"); CoveredBy="IR collection + containment" }
) | ForEach-Object { [PSCustomObject]$_ }

$covered = ($ControlMatrix | Where-Object { $_.Tools.Count -gt 0 }).Count
$gaps    = ($ControlMatrix | Where-Object { $_.Tools.Count -eq 0 }).Count

$ControlMatrix | Export-Csv (Join-Path $OutputPath "ControlCoverage_$Timestamp.csv") -NoTypeInformation

Write-Host "[COVERAGE] $covered / $($ControlMatrix.Count) CIS Controls covered | Gaps: $gaps" -ForegroundColor $(if ($gaps -gt 0) { "Yellow" } else { "Green" })
$ControlMatrix | Format-Table CISControl, Title, NISTFunction, CoveredBy -AutoSize
