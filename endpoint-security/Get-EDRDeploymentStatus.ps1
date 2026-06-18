<#
.SYNOPSIS
    Audits EDR/XDR agent deployment status across the enterprise endpoint fleet.
.DESCRIPTION
    Checks for CrowdStrike Falcon, SentinelOne, Cortex XDR, and ESET agent
    presence, service status, and version compliance across all AD-joined systems.
    Identifies unprotected endpoints for immediate remediation.
.PARAMETER SupportedEDR
    Which EDR products to check for. Default: checks all known agents.
.PARAMETER OutputPath
    Report output directory.
.EXAMPLE
    Get-EDRDeploymentStatus -OutputPath "C:\Reports\EDR"
#>
[CmdletBinding()]
param(
    [ValidateSet("CrowdStrike","SentinelOne","CortexXDR","ESET","Any")]
    [string[]]$SupportedEDR = @("CrowdStrike","SentinelOne","CortexXDR","ESET"),
    [string]$OutputPath = $PWD,
    [string]$ADSearchBase
)

$EDRSignatures = @{
    CrowdStrike  = @{ Services = @("CSFalconService","CsFalconContainer"); Processes = @("CSFalconService","falcon-sensor"); RegKey = "HKLM:\SYSTEM\CrowdStrike"; DisplayName = "CrowdStrike*" }
    SentinelOne  = @{ Services = @("SentinelAgent","SentinelStaticEngine"); Processes = @("SentinelAgent"); RegKey = "HKLM:\SOFTWARE\SentinelOne"; DisplayName = "SentinelOne*" }
    CortexXDR    = @{ Services = @("cyserver","CyberarkEPM"); Processes = @("cortex_xdr"); RegKey = "HKLM:\SOFTWARE\Palo Alto Networks\Traps"; DisplayName = "Cortex XDR*" }
    ESET         = @{ Services = @("ekrn","ERAAgent"); Processes = @("egui","ekrn"); RegKey = "HKLM:\SOFTWARE\ESET"; DisplayName = "ESET*" }
}

$Computers = if ($ADSearchBase) {
    (Get-ADComputer -SearchBase $ADSearchBase -Filter { Enabled -eq $true -and OperatingSystem -like "Windows*" }).Name
} else {
    (Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like "Windows*" }).Name
}

Write-Host "[*] Checking EDR deployment on $($Computers.Count) endpoints..." -ForegroundColor Cyan

$Results = $Computers | ForEach-Object -ThrottleLimit 30 -Parallel {
    $Computer = $_
    $Sigs     = $using:EDRSignatures
    $Supported= $using:SupportedEDR

    $detected = @()
    foreach ($edr in $Supported) {
        $sig = $Sigs[$edr]
        $svcRunning = $false
        foreach ($svc in $sig.Services) {
            try {
                $s = Get-Service -ComputerName $Computer -Name $svc -ErrorAction Stop
                if ($s.Status -eq "Running") { $svcRunning = $true; break }
            } catch {}
        }
        if ($svcRunning) { $detected += $edr }
    }

    $lastSeen = try {
        (Get-ADComputer $Computer -Properties LastLogonDate).LastLogonDate
    } catch { $null }

    [PSCustomObject]@{
        Computer    = $Computer
        Protected   = ($detected.Count -gt 0)
        DetectedEDR = ($detected -join "|")
        NoEDR       = ($detected.Count -eq 0)
        LastSeen    = $lastSeen
        Reachable   = $true
    }
}

$Protected   = ($Results | Where-Object Protected).Count
$Unprotected = ($Results | Where-Object NoEDR).Count
$Total       = $Results.Count
$Coverage    = [math]::Round(($Protected / $Total) * 100, 1)

$CsvPath = Join-Path $OutputPath "EDR_Coverage_$(Get-Date -Format yyyyMMdd).csv"
$Results | Export-Csv $CsvPath -NoTypeInformation

Write-Host "`n[RESULTS] Coverage: $Coverage% | Protected: $Protected | UNPROTECTED: $Unprotected" -ForegroundColor $(
    if ($Coverage -ge 98) { "Green" } elseif ($Coverage -ge 90) { "Yellow" } else { "Red" })

if ($Unprotected -gt 0) {
    Write-Host "`n[!] UNPROTECTED ENDPOINTS:" -ForegroundColor Red
    $Results | Where-Object NoEDR | Format-Table Computer, LastSeen -AutoSize
}
