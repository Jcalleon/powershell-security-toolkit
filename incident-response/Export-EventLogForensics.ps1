<#
.SYNOPSIS
    Exports Windows event logs in bulk for offline forensic analysis.
.DESCRIPTION
    Exports Security, System, Application, PowerShell Operational, Sysmon,
    and WMI Operational logs from target systems. Creates timestamped packages
    with manifest for chain of custody documentation.
.EXAMPLE
    Export-EventLogForensics -ComputerName "SUSPECT01" -CaseName "INC-2026-001" -OutputPath "C:\IR\Cases"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ComputerName,
    [string]$CaseName   = "Case_$(Get-Date -Format yyyyMMdd_HHmm)",
    [Parameter(Mandatory)][string]$OutputPath,
    [int]$MaxEvents     = 50000
)

$CaseDir  = New-Item (Join-Path $OutputPath "${CaseName}_${ComputerName}") -ItemType Directory -Force
$Manifest = [System.Collections.Generic.List[PSObject]]::new()

$Logs = @(
    @{ Name="Security";              MaxEvents=$MaxEvents },
    @{ Name="System";                MaxEvents=10000 },
    @{ Name="Application";           MaxEvents=10000 },
    @{ Name="Microsoft-Windows-PowerShell/Operational"; MaxEvents=10000 },
    @{ Name="Microsoft-Windows-WMI-Activity/Operational"; MaxEvents=5000 },
    @{ Name="Microsoft-Windows-TaskScheduler/Operational"; MaxEvents=5000 },
    @{ Name="Microsoft-Windows-DriverFrameworks-UserMode/Operational"; MaxEvents=5000 }
)

Write-Host "[*] Exporting event logs from $ComputerName (Case: $CaseName)" -ForegroundColor Cyan

foreach ($log in $Logs) {
    $safeName = $log.Name -replace "[/\]","_"
    $csvPath  = "$CaseDir\${safeName}.csv"
    try {
        $events = Get-WinEvent -ComputerName $ComputerName -LogName $log.Name `
            -MaxEvents $log.MaxEvents -ErrorAction Stop
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, UserId,
            @{N="Message";E={$_.Message -replace '?
',' '}} |
            Export-Csv $csvPath -NoTypeInformation
        $Manifest.Add([PSCustomObject]@{ Log=$log.Name; File=$safeName+".csv"; Count=$events.Count; Status="OK" })
        Write-Host "  [+] $($log.Name): $($events.Count) events" -ForegroundColor Green
    } catch {
        $Manifest.Add([PSCustomObject]@{ Log=$log.Name; Status="FAILED"; Error=$_.Exception.Message })
        Write-Warning "Failed: $($log.Name) - $_"
    }
}

$Manifest | Export-Csv "$CaseDir\manifest.csv" -NoTypeInformation
"CaseName: $CaseName`nComputer: $ComputerName`nCollectedBy: $env:USERNAME`nCollectedAt: $(Get-Date -Format 'o')`nCollectionHost: $env:COMPUTERNAME" |
    Out-File "$CaseDir\chain_of_custody.txt"

Write-Host "[DONE] Case package: $CaseDir | Logs: $($Manifest.Count)" -ForegroundColor Green
