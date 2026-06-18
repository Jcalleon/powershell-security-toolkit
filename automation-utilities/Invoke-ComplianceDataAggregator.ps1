<#
.SYNOPSIS
    Aggregates compliance data from multiple security tools into a unified dataset.
.DESCRIPTION
    Collects and normalizes data from Qualys, Tenable, CIS audit scripts,
    AD security audit, and patch compliance into a single compliance register.
    Designed to feed dashboards, GRC tools, or evidence packages.
.EXAMPLE
    Invoke-ComplianceDataAggregator -DataRoot "C:\SecurityReports" -OutputPath "C:\Compliance"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DataRoot,
    [string]$OutputPath = $PWD,
    [string]$Framework  = "CIS"
)
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$ComplianceDB = [System.Collections.Generic.List[PSObject]]::new()

$SourceMap = @{
    CIS_Audit        = "CIS_Audit_*.csv"
    Patch_Compliance = "PatchReport_*\compliance_summary.csv"
    EDR_Coverage     = "EDR_Coverage_*.csv"
    Vulnerabilities  = "Qualys_Findings_*.csv"
    AD_Audit         = "ADSecurityAudit_*udit_summary.csv"
}

foreach ($source in $SourceMap.Keys) {
    $files = Get-ChildItem $DataRoot -Recurse -Filter ($SourceMap[$source] -split "\|/")[-1] -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($files) {
        $data = Import-Csv $files.FullName
        $data | ForEach-Object {
            $_ | Add-Member -NotePropertyName "DataSource" -NotePropertyValue $source -PassThru |
                 Add-Member -NotePropertyName "Framework"  -NotePropertyValue $Framework -PassThru |
                 Add-Member -NotePropertyName "ImportDate" -NotePropertyValue (Get-Date -Format "o") -PassThru
        } | ForEach-Object { $ComplianceDB.Add($_) }
        Write-Host "  [+] Loaded $($data.Count) records from: $source" -ForegroundColor Green
    } else { Write-Warning "No data found for: $source" }
}

$ComplianceDB | Export-Csv (Join-Path $OutputPath "ComplianceRegister_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Compliance register: $($ComplianceDB.Count) total records | Output: $OutputPath" -ForegroundColor Green
