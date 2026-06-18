# PowerShell Security Toolkit

> Enterprise-grade PowerShell automation for vulnerability management, CIS hardening, Active Directory security, SIEM integration, and incident response. 100+ production-ready scripts across 10 security domains.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Scripts](https://img.shields.io/badge/Scripts-100%2B-orange)](.)
[![Frameworks](https://img.shields.io/badge/Frameworks-CIS%20%7C%20NIST%20%7C%20MITRE%20ATT%26CK-purple)](.)

---

## Author

**Jacob Calleon** | CISSP, CompTIA Network+ | M.S. Cybersecurity (Purdue, 3.92 GPA)  
5+ years in vulnerability management, detection engineering, CIS hardening, SIEM, EDR, and IAM across enterprise environments (5,000+ systems).

---

## Repository Structure

```
powershell-security-toolkit/
├── cis-hardening/
│   ├── windows/          # 12 scripts — CIS Benchmark L1/L2 audit & hardening
│   └── linux/            #  2 scripts — Remote SSH-based Linux hardening
├── vulnerability-management/
│   ├── qualys/           #  6 scripts — Qualys API automation
│   └── tenable/          #  4 scripts — Tenable.io / Tenable.sc API
├── active-directory/
│   ├── audit/            #  6 scripts — AD security audit & threat detection
│   ├── users/            #  7 scripts — Provisioning, offboarding, lifecycle
│   ├── groups/           #  2 scripts — Group management & cleanup
│   └── policies/         #  2 scripts — GPO export, fine-grained pwd policy
├── siem-pipeline/
│   ├── splunk/           #  6 scripts — HEC forwarding, search API, detection deployment
│   ├── elk/              #  4 scripts — ECS event shipping, KQL/detection rules
│   └── graylog/          #  2 scripts — GELF forwarding, alert retrieval
├── patch-compliance/
│   ├── reporting/        #  3 scripts — Fleet compliance, missing KBs, WSUS dashboard
│   └── remediation/      #  2 scripts — Bulk patching, WSUS-forced remediation
├── endpoint-security/    #  8 scripts — EDR coverage, malware hunting, Defender, USB, BitLocker
├── network-security/     #  7 scripts — Port scan, DNS audit, cert audit, SMB audit, external exposure
├── incident-response/    #  7 scripts — Live response, timeline, LM indicators, containment
├── cloud-security/
│   ├── azure/            #  6 scripts — Posture, CA policies, Sentinel, PIM, Log Analytics
│   └── aws/              #  4 scripts — CIS audit, IAM credential report, GuardDuty, CloudTrail
└── automation-utilities/ # 10 scripts — Secret rotation, bulk exec, ticketing, digest, reporting
```

---

## Quick Start

```powershell
# Clone the repo
git clone https://github.com/jcalleon/powershell-security-toolkit.git
cd powershell-security-toolkit

# CIS Benchmark audit (local)
.\cis-hardening\windows\Invoke-CISBenchmarkAudit.ps1 -Level 1 -OutputPath "C:\Reports"

# CIS hardening apply (with backup)
.\cis-hardening\windows\Set-CISWindowsHardening.ps1 -BackupPath "C:\Backups" -WhatIf
.\cis-hardening\windows\Set-CISWindowsHardening.ps1 -BackupPath "C:\Backups"

# Active Directory security audit
.\active-directory\audit\Get-ADSecurityAudit.ps1 -InactivityDays 90 -OutputPath "C:\Reports"

# Qualys vulnerability pull
$cred = Get-Credential
.\vulnerability-management\qualys\Get-QualysScanResults.ps1 `
    -Platform "qualysapi.qualys.com" -QualysUsername $cred.UserName `
    -QualysPassword $cred.Password -MinCVSS 7.0

# Fleet patch compliance
.\patch-compliance\reporting\Get-PatchComplianceReport.ps1 -OutputPath "C:\Reports"

# Live incident response collection
.\incident-response\Invoke-LiveResponseCollection.ps1 -ComputerName "SUSPECT01" -OutputPath "C:\IR\INC001"
```

---

## Key Scripts

### CIS Hardening
| Script | Description |
|--------|-------------|
| `Invoke-CISBenchmarkAudit.ps1` | Full CIS L1/L2 registry audit with pass/fail scoring |
| `Set-CISWindowsHardening.ps1` | Apply CIS controls: WDigest, LSASS PPL, SMBv1, NTLMv2, PS logging |
| `Get-CISComplianceScore.ps1` | Numeric compliance score (0-100) for dashboarding / SLA tracking |
| `Set-WindowsAuditPolicy.ps1` | Granular audit subcategory configuration via auditpol.exe |
| `Invoke-CISLinuxHardeningRemote.ps1` | SSH-based Linux hardening: SSH config, sysctl, auditd, services |

### Vulnerability Management
| Script | Description |
|--------|-------------|
| `Get-QualysScanResults.ps1` | Pull Qualys findings by CVSS threshold with remediation priority tiers |
| `Invoke-QualysRemediationValidation.ps1` | Launch targeted scan, poll completion, validate specific QIDs fixed |
| `Get-TenableVulnerabilities.ps1` | Tenable.io/sc findings with VPR scoring and remediation priority |
| `Invoke-TenableScanLaunch.ps1` | Programmatic scan launch with completion polling for CI/CD pipelines |

### Active Directory / IAM
| Script | Description |
|--------|-------------|
| `Get-ADSecurityAudit.ps1` | Comprehensive AD audit: privileged groups, stale users, Kerberoastable, delegation |
| `Get-ADKerberoastingRisk.ps1` | SPN account risk scoring by password age and privilege level |
| `Invoke-ADUserProvisioning.ps1` | Bulk provisioning from HR CSV with dept→OU/group mapping |
| `Set-ADFineGrainedPasswordPolicy.ps1` | Tiered PSOs: service accounts, admins, standard users (NIST aligned) |
| `Get-ADPrivilegedAccessAudit.ps1` | Consolidated privileged access matrix across all admin groups |

### SIEM Pipeline
| Script | Description |
|--------|-------------|
| `Send-SplunkHECEvent.ps1` | Forward security events to Splunk HEC with proper metadata |
| `Invoke-SplunkSearchAPI.ps1` | Run SPL queries via REST, poll completion, return PS objects |
| `Invoke-SplunkDetectionDeployment.ps1` | Bulk deploy detection library as Splunk saved searches |
| `Send-ELKSecurityEvent.ps1` | Index events to Elasticsearch with ECS 8.0 field mapping |

### Incident Response
| Script | Description |
|--------|-------------|
| `Invoke-LiveResponseCollection.ps1` | Forensic artifact collection: processes, network, autoruns, event logs |
| `Get-AccountActivityTimeline.ps1` | Reconstruct user activity from Security event log across all DCs |
| `Get-LateralMovementIndicators.ps1` | Detect PtH, PsExec, WMI remote execution patterns (MITRE T1021.x) |
| `Invoke-ThreatContainment.ps1` | Staged containment: disable account → isolate network → collect artifacts → notify SOC |

---

## Prerequisites

```powershell
# PowerShell 7+ recommended for parallel execution (-Parallel)
# PS 5.1 compatible for most scripts

# Active Directory scripts
Import-Module ActiveDirectory

# Azure scripts
Install-Module Az -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser

# AWS scripts
Install-Module AWS.Tools.Installer
Install-AWSToolsModule AWS.Tools.IAM, AWS.Tools.SecurityHub, AWS.Tools.CloudTrail
```

---

## Frameworks & Compliance Mapping

| Framework | Coverage |
|-----------|----------|
| **CIS Controls v8** | Controls 1-13, 16-17 |
| **NIST CSF** | Identify, Protect, Detect, Respond, Recover |
| **MITRE ATT&CK** | T1021, T1047, T1053, T1055, T1059, T1078, T1110, T1547 |
| **CIS Benchmarks** | Windows Server 2019/2022, Ubuntu 22.04, RHEL 8/9 |
| **CIS AWS Foundations** | 1.x IAM, 2.x Storage, 3.x Logging |

---

## Contributing

Scripts follow these conventions:
- Full comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`)
- `[CmdletBinding(SupportsShouldProcess)]` for state-changing scripts
- `#Requires` statements for module dependencies
- CSV output with timestamps for all reports
- Verbose/Warning/Error streams used correctly

---

## License

MIT License — see [LICENSE](LICENSE)
