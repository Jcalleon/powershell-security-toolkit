<#
.SYNOPSIS
    Exports all GPO settings to XML for baseline documentation and change detection.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
Import-Module GroupPolicy
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$GPODir = New-Item (Join-Path $OutputPath "GPOBaseline_$Timestamp") -ItemType Directory -Force
$GPOs = Get-GPO -All
foreach ($gpo in $GPOs) {
    $safeName = $gpo.DisplayName -replace '[\/:*?"<>|]', '_'
    $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    $xml | Out-File "$GPODir\${safeName}.xml" -Encoding UTF8
}
$GPOs | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime |
    Export-Csv "$GPODir\gpo_inventory.csv" -NoTypeInformation
Write-Host "[DONE] Exported $($GPOs.Count) GPOs to $GPODir" -ForegroundColor Green
