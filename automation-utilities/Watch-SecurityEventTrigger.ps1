<#
.SYNOPSIS
    Monitors Windows event log in real-time and triggers automated responses.
.DESCRIPTION
    Subscribes to Windows Event Log for specific Event IDs and executes
    response actions (alert, disable account, isolate, ticket) when triggered.
    Lightweight alternative to full SOAR for on-prem environments.
.EXAMPLE
    Watch-SecurityEventTrigger -AlertEmail "soc@company.com" -SMTPServer "smtp.corp.local"
#>
[CmdletBinding()]
param(
    [string]$AlertEmail,
    [string]$SMTPServer,
    [string]$LogPath = "C:\SecurityAutomation\Logs"
)

if (-not (Test-Path $LogPath)) { New-Item $LogPath -ItemType Directory -Force | Out-Null }

$TriggerRules = @(
    @{ EventID=4625; Threshold=5; Window=300;  Action="Alert"; Description="Failed logon spike" },
    @{ EventID=4720; Threshold=1; Window=60;   Action="Alert"; Description="New user account created" },
    @{ EventID=4728; Threshold=1; Window=60;   Action="Alert"; Description="User added to security group" },
    @{ EventID=7045; Threshold=1; Window=60;   Action="Alert"; Description="New service installed" },
    @{ EventID=1102; Threshold=1; Window=60;   Action="Alert"; Description="Audit log cleared" }
)

Write-Host "[*] Security event monitor started. Ctrl+C to stop." -ForegroundColor Cyan
Write-Host "    Watching $(($TriggerRules).Count) trigger rules..." -ForegroundColor Gray

$tracker = @{}

Register-EngineEvent -SourceIdentifier "Console.CancelKeyPress" -Action { exit } | Out-Null

$query   = "*[System[EventID=$(($TriggerRules.EventID | Select-Object -Unique) -join ' or EventID=')]]"
$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher("Security", $query)
$watcher.EventRecordWritten += {
    param($src, $e)
    $id   = $e.EventRecord.Id
    $rule = $TriggerRules | Where-Object EventID -eq $id | Select-Object -First 1
    if (-not $rule) { return }

    $key  = "$id"
    if (-not $tracker[$key]) { $tracker[$key] = @() }
    $tracker[$key] = @($tracker[$key] | Where-Object { ((Get-Date)-$_).TotalSeconds -le $rule.Window }) + (Get-Date)

    if ($tracker[$key].Count -ge $rule.Threshold) {
        $msg = "[TRIGGER] $($rule.Description) | EventID: $id | Count: $($tracker[$key].Count) in $($rule.Window)s"
        Write-Host $msg -ForegroundColor Red
        Add-Content "$LogPath	riggers.log" "$(Get-Date -Format 'o') | $msg"
        if ($AlertEmail -and $SMTPServer) {
            Send-MailMessage -To $AlertEmail -From "security-watch@corp.local" `
                -Subject "[SECURITY ALERT] $($rule.Description)" -Body $msg -SmtpServer $SMTPServer
        }
        $tracker[$key] = @()  # Reset after trigger
    }
}

$watcher.Enabled = $true
Write-Host "[RUNNING] Event watcher active..." -ForegroundColor Green
while ($true) { Start-Sleep -Seconds 10 }
