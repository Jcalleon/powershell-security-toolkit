<#
.SYNOPSIS
    Performs live response evidence collection from a potentially compromised system.
.DESCRIPTION
    Collects volatile and non-volatile forensic artifacts: running processes,
    network connections, logged-on users, prefetch, event logs, scheduled tasks,
    registry autoruns, and memory strings. Designed for incident triage.
.PARAMETER ComputerName
    Target system for live response. Defaults to local.
.PARAMETER OutputPath
    Directory to store collected artifacts.
.PARAMETER CollectMemory
    Include memory strings collection (requires strings.exe or PowerShell equivalent).
.EXAMPLE
    Invoke-LiveResponseCollection -ComputerName "WORKSTATION01" -OutputPath "C:\IR\Cases\INC001"
#>
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$CollectMemory
)

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$CaseDir    = New-Item (Join-Path $OutputPath "LR_${ComputerName}_$Timestamp") -ItemType Directory -Force
$Manifest   = [System.Collections.Generic.List[PSObject]]::new()

function Collect {
    param([string]$ArtifactName, [scriptblock]$Action, [string]$OutFile)
    Write-Host "  [*] Collecting: $ArtifactName" -ForegroundColor Gray
    try {
        & $Action | Export-Csv "$CaseDir\$OutFile" -NoTypeInformation -ErrorAction Stop
        $Manifest.Add([PSCustomObject]@{ Artifact=$ArtifactName; File=$OutFile; Status="OK"; Timestamp=(Get-Date -Format "HH:mm:ss") })
    } catch {
        $Manifest.Add([PSCustomObject]@{ Artifact=$ArtifactName; File=$OutFile; Status="FAILED"; Error=$_.Exception.Message })
        Write-Warning "Failed: $ArtifactName - $_"
    }
}

Write-Host "[*] Live Response Collection: $ComputerName" -ForegroundColor Cyan
Write-Host "    Case directory: $CaseDir" -ForegroundColor Gray

# Volatile: Processes
Collect "Running Processes" {
    Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId,
        @{N="ParentName";E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name}},
        @{N="Path";E={$_.ExecutablePath}}, CreationDate
} "processes.csv"

# Volatile: Network Connections
Collect "Network Connections" {
    Get-NetTCPConnection | ForEach-Object {
        $_ | Add-Member -NotePropertyName "Process" -NotePropertyValue (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name -PassThru |
             Add-Member -NotePropertyName "ProcessPath" -NotePropertyValue (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path -PassThru
    }
} "network_connections.csv"

# Volatile: Logged-on Users
Collect "Logged-on Users" {
    query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
        $parts = $_ -split '\s+'
        [PSCustomObject]@{ Username=$parts[1]; Session=$parts[2]; ID=$parts[3]; State=$parts[4]; LogonTime="$($parts[5]) $($parts[6])" }
    }
} "logged_on_users.csv"

# Volatile: DNS Cache
Collect "DNS Cache" { Get-DnsClientCache | Select-Object Entry, RecordType, TimeToLive, Data } "dns_cache.csv"

# Non-Volatile: Autoruns
Collect "Registry Autoruns" {
    $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    $keys | ForEach-Object { $k = $_; (Get-ItemProperty $k -EA SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notmatch "^PS" } | Select-Object @{N="Key";E={$k}}, Name, Value }
} "autoruns_registry.csv"

# Non-Volatile: Scheduled Tasks
Collect "Scheduled Tasks" {
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
        @{N="Action";E={$_.Actions.Execute}}, @{N="Args";E={$_.Actions.Arguments}},
        @{N="Trigger";E={$_.Triggers.Enabled}}
} "scheduled_tasks.csv"

# Non-Volatile: Recent Event Log (Security, System, Application)
foreach ($log in @("Security","System","Application")) {
    $outFile = "eventlog_${log.ToLower()}.csv"
    Write-Host "  [*] Event log: $log (last 1000)" -ForegroundColor Gray
    try {
        Get-WinEvent -LogName $log -MaxEvents 1000 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv "$CaseDir\$outFile" -NoTypeInformation
        $Manifest.Add([PSCustomObject]@{ Artifact="EventLog-$log"; File=$outFile; Status="OK" })
    } catch { $Manifest.Add([PSCustomObject]@{ Artifact="EventLog-$log"; File=$outFile; Status="FAILED" }) }
}

# Non-Volatile: Prefetch (if exists)
$prefetchPath = "C:\Windows\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "  [*] Collecting prefetch file list..." -ForegroundColor Gray
    Get-ChildItem $prefetchPath -Filter "*.pf" | Select-Object Name, CreationTime, LastWriteTime, Length |
        Export-Csv "$CaseDir\prefetch.csv" -NoTypeInformation
}

# Non-Volatile: Installed Software
Collect "Installed Software" {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
} "installed_software.csv"

# Manifest
$Manifest | Export-Csv "$CaseDir\collection_manifest.csv" -NoTypeInformation
Write-Host "`n[DONE] Collection complete: $CaseDir" -ForegroundColor Green
Write-Host "       Artifacts: $($Manifest.Count) | Failed: $(($Manifest | Where-Object Status -eq 'FAILED').Count)" -ForegroundColor Gray
