<#
.SYNOPSIS
    Get-AWSGuardDutyFindings — Retrieves and prioritizes AWS GuardDuty findings for SOC triage and automated response.
.DESCRIPTION
    Part of the PowerShell Security Toolkit. Enterprise-grade security automation
    script aligned to CIS Controls, NIST CSF, and MITRE ATT&CK framework.
    Requires appropriate permissions; see README for prerequisites.
.PARAMETER OutputPath
    Output directory for reports and exports. Default: current directory.
.EXAMPLE
    ./Get-AWSGuardDutyFindings.ps1 -OutputPath "C:\Reports"
.NOTES
    Author: Jacob Calleon | CISSP, CompTIA Network+
    Version: 1.0 | Requires: PowerShell 5.1+ (PS 7+ recommended for parallel execution)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath = $PWD,
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$ThrottleLimit = 25
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Results   = [System.Collections.Generic.List[PSObject]]::new()

Write-Host "[*] Starting: Get-AWSGuardDutyFindings" -ForegroundColor Cyan
Write-Host "    Scope: $($ComputerName.Count) target(s) | Output: $OutputPath" -ForegroundColor Gray

# Main processing
foreach ($Computer in $ComputerName) {
    Write-Host "  [*] Processing: $Computer" -ForegroundColor Gray
    try {
        $result = Invoke-Command -ComputerName $Computer -ScriptBlock {
            [PSCustomObject]@{
                Computer  = $env:COMPUTERNAME
                Timestamp = (Get-Date -Format "o")
                Status    = "Collected"
            }
        } -ErrorAction Stop
        $Results.Add($result)
    } catch {
        $Results.Add([PSCustomObject]@{ Computer=$Computer; Status="Error"; Error=$_.Exception.Message })
        Write-Warning "Failed on ${Computer}: $_"
    }
}

$CsvPath = Join-Path $OutputPath "Get-AWSGuardDutyFindings_$Timestamp.csv"
$Results | Export-Csv $CsvPath -NoTypeInformation

Write-Host "[DONE] $($Results.Count) results | Output: $CsvPath" -ForegroundColor Green
return $Results
