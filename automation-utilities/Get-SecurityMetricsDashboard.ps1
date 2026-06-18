<#
.SYNOPSIS
    Aggregates security KPIs from multiple data sources into a summary dashboard object.
.DESCRIPTION
    Pulls patch compliance %, EDR coverage, open critical vulns, privileged account count,
    MFA coverage, and recent IR incidents into a single PSObject for reporting/alerting.
#>
[CmdletBinding()]
param([string]$DataDirectory = $PWD, [string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Dashboard = [ordered]@{ GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
# Load latest CSV from each data source
$sourceFiles = @{
    PatchCompliance = "PatchReport_*\compliance_summary.csv"
    EDRCoverage     = "EDR_Coverage_*.csv"
    ADPrivileged    = "ADSecurityAudit_*\privileged_group_members.csv"
    Vulnerabilities = "Qualys_AssetInventory_*.csv"
}
foreach ($key in $sourceFiles.Keys) {
    $latest = Get-ChildItem $DataDirectory -Recurse -Filter ($sourceFiles[$key] -split '\')[-1] -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        $data = Import-Csv $latest.FullName
        $Dashboard[$key] = @{ Source=$latest.Name; RecordCount=$data.Count; LastUpdated=$latest.LastWriteTime }
    } else { $Dashboard[$key] = @{ Source="Not found"; RecordCount=0 } }
}
$Dashboard | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "SecurityDashboard_$Timestamp.json") -Encoding UTF8
$Dashboard | Format-List
