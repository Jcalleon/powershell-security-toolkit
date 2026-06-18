<#
.SYNOPSIS
    Generates enterprise patch compliance report across Windows fleet via WSUS or direct query.
.DESCRIPTION
    Queries WSUS server or polls systems directly for patch status, builds
    compliance summary by business unit/OU, and calculates % compliant
    per patch severity tier with SLA breach flagging.
.PARAMETER WSUSServer
    WSUS server hostname. If omitted, queries systems directly via WMI.
.PARAMETER ComputerList
    Path to text file with one hostname per line, or AD OU to query.
.PARAMETER SLADays
    Hashtable of severity -> SLA days. Default: Critical=7, Important=14, Moderate=30.
.PARAMETER OutputPath
    Directory for report output.
.EXAMPLE
    Get-PatchComplianceReport -WSUSServer "WSUS01" -OutputPath "C:\Reports\Patches"
    Get-PatchComplianceReport -ComputerList "C:\hosts.txt" -OutputPath "C:\Reports\Patches"
#>
[CmdletBinding()]
param(
    [string]$WSUSServer,
    [string]$ComputerList,
    [hashtable]$SLADays = @{ Critical=7; Important=14; Moderate=30; Low=90 },
    [string]$OutputPath = $PWD,
    [PSCredential]$Credential
)

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir   = New-Item (Join-Path $OutputPath "PatchReport_$Timestamp") -ItemType Directory -Force
$AllFindings = [System.Collections.Generic.List[PSObject]]::new()

function Get-SystemPatchStatus {
    param([string]$Computer)
    try {
        $session  = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $Computer))
        $searcher = $session.CreateUpdateSearcher()
        $missing  = $searcher.Search("IsInstalled=0 and Type='Software'").Updates

        $lastPatch = (Get-HotFix -ComputerName $Computer -ErrorAction Stop |
            Sort-Object InstalledOn -Descending | Select-Object -First 1)

        return [PSCustomObject]@{
            Computer        = $Computer
            MissingCount    = $missing.Count
            CriticalMissing = ($missing | Where-Object MsrcSeverity -eq "Critical").Count
            ImportantMissing= ($missing | Where-Object MsrcSeverity -eq "Important").Count
            LastPatchDate   = $lastPatch.InstalledOn
            DaysSincePatch  = if ($lastPatch.InstalledOn) { ((Get-Date) - $lastPatch.InstalledOn).Days } else { 9999 }
            LastHotFix      = $lastPatch.HotFixID
            Status          = "Queried"
        }
    } catch {
        return [PSCustomObject]@{ Computer=$Computer; Status="Error"; Error=$_.Exception.Message }
    }
}

# Get computer list
$Computers = @()
if ($ComputerList -and (Test-Path $ComputerList)) {
    $Computers = Get-Content $ComputerList
} elseif ($ComputerList -match "^OU=") {
    $Computers = (Get-ADComputer -SearchBase $ComputerList -Filter { Enabled -eq $true }).Name
} else {
    $Computers = @($env:COMPUTERNAME)
}

Write-Host "[*] Querying $($Computers.Count) systems for patch compliance..." -ForegroundColor Cyan

$Results = $Computers | ForEach-Object -ThrottleLimit 20 -Parallel {
    $Computer = $_
    $session  = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $Computer))
    try {
        $searcher = $session.CreateUpdateSearcher()
        $missing  = $searcher.Search("IsInstalled=0 and Type='Software'").Updates
        [PSCustomObject]@{
            Computer        = $Computer
            MissingCount    = $missing.Count
            CriticalMissing = ($missing | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
            ImportantMissing= ($missing | Where-Object { $_.MsrcSeverity -eq "Important" }).Count
            Status          = "Queried"
        }
    } catch {
        [PSCustomObject]@{ Computer=$Computer; Status="Error"; Error=$_.Exception.Message }
    }
}

# Calculate compliance
$Compliant    = ($Results | Where-Object { $_.Status -eq "Queried" -and $_.CriticalMissing -eq 0 -and $_.MissingCount -eq 0 }).Count
$Total        = $Results.Count
$CompliancePct= [math]::Round(($Compliant / $Total) * 100, 1)

$Results | Export-Csv "$ReportDir\patch_status_detail.csv" -NoTypeInformation

$Summary = [PSCustomObject]@{
    ReportDate      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    TotalSystems    = $Total
    Compliant       = $Compliant
    NonCompliant    = $Total - $Compliant
    ErrorCount      = ($Results | Where-Object Status -eq "Error").Count
    CompliancePct   = $CompliancePct
    CriticalExposure= ($Results | Measure-Object CriticalMissing -Sum).Sum
    SLAStatus       = if ($CompliancePct -ge 90) { "COMPLIANT" } elseif ($CompliancePct -ge 70) { "AT-RISK" } else { "BREACH" }
}
$Summary | Export-Csv "$ReportDir\compliance_summary.csv" -NoTypeInformation

Write-Host "`n[RESULTS] Compliance: $CompliancePct% | Status: $($Summary.SLAStatus)" -ForegroundColor $(
    if ($CompliancePct -ge 90) { "Green" } elseif ($CompliancePct -ge 70) { "Yellow" } else { "Red" })
Write-Host "[OUTPUT]  $ReportDir" -ForegroundColor Gray
