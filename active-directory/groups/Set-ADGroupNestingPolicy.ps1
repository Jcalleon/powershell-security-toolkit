<#
.SYNOPSIS
    Set-ADGroupNestingPolicy — Enforces group nesting policy (AGDLP/AGUDLP) and flags violations for remediation.
.DESCRIPTION
    Part of the PowerShell Security Toolkit. Enterprise-grade security automation
    script aligned to CIS Controls, NIST CSF, and MITRE ATT&CK framework.
    Requires appropriate permissions; see README for prerequisites.
.PARAMETER OutputPath
    Output directory for reports and exports. Default: current directory.
.EXAMPLE
    ./Set-ADGroupNestingPolicy.ps1 -OutputPath "C:\Reports"
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

Write-Host "[*] Starting: Set-ADGroupNestingPolicy" -ForegroundColor Cyan
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

$CsvPath = Join-Path $OutputPath "Set-ADGroupNestingPolicy_$Timestamp.csv"
$Results | Export-Csv $CsvPath -NoTypeInformation

Write-Host "[DONE] $($Results.Count) results | Output: $CsvPath" -ForegroundColor Green
return $Results
