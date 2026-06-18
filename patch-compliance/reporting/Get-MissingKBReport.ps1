<#
.SYNOPSIS
    Generates targeted missing KB report for specific CVEs or patch Tuesday releases.
#>
[CmdletBinding()]
param([string[]]$CVEs, [string[]]$KBIDs, [string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computers = (Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like 'Windows*' }).Name
$Results = $Computers | ForEach-Object -ThrottleLimit 20 -Parallel {
    $comp = $_;$KBs = $using:KBIDs
    try {
        $installed = (Get-HotFix -ComputerName $comp -ErrorAction Stop).HotFixID
        $missing = $KBs | Where-Object { $_ -notin $installed }
        [PSCustomObject]@{ Computer=$comp; MissingKBs=($missing -join "|"); MissingCount=$missing.Count; InstalledCount=$installed.Count }
    } catch { [PSCustomObject]@{ Computer=$comp; Error=$_.Exception.Message } }
}
$Results | Export-Csv (Join-Path $OutputPath "MissingKB_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Systems missing target KBs: $(($Results | Where-Object MissingCount -gt 0).Count)" -ForegroundColor Yellow
