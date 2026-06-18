<#
.SYNOPSIS
    Audits Windows Defender / Microsoft Defender for Endpoint status across fleet.
#>
[CmdletBinding()]
param([string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computers = (Get-ADComputer -Filter { Enabled -eq $true }).Name
$Results = $Computers | ForEach-Object -ThrottleLimit 25 -Parallel {
    $comp = $_
    try {
        Invoke-Command -ComputerName $comp -ScriptBlock {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            [PSCustomObject]@{
                Computer            = $env:COMPUTERNAME
                DefenderEnabled     = $mpStatus.AntivirusEnabled
                RealtimeProtection  = $mpStatus.RealTimeProtectionEnabled
                SignatureVersion    = $mpStatus.AntivirusSignatureVersion
                SignatureAge        = $mpStatus.AntivirusSignatureAge
                LastScanTime        = $mpStatus.LastFullScanEndTime
                TamperProtection    = $mpStatus.IsTamperProtected
                CloudProtection     = $mpStatus.MAPSReporting -ne "Disabled"
                Compliant           = ($mpStatus.AntivirusEnabled -and $mpStatus.RealTimeProtectionEnabled -and $mpStatus.AntivirusSignatureAge -le 7)
            }
        } -ErrorAction Stop
    } catch { [PSCustomObject]@{ Computer=$comp; Error=$_.Exception.Message } }
}
$Results | Export-Csv (Join-Path $OutputPath "DefenderStatus_$Timestamp.csv") -NoTypeInformation
$nonCompliant = $Results | Where-Object { $_.Compliant -eq $false }
Write-Host "[DONE] Fleet: $($Results.Count) | Non-compliant: $($nonCompliant.Count)" -ForegroundColor $(if ($nonCompliant.Count -gt 0) { "Yellow" } else { "Green" })
