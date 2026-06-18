<#
.SYNOPSIS
    Monitors and reports recent Active Directory group membership changes.
.DESCRIPTION
    Queries Security event log for Event ID 4728/4732/4756 (member added)
    and 4729/4733/4757 (member removed) from DCs. Focuses on privileged groups.
    Can be run on a schedule to alert on sensitive group changes.
.PARAMETER HoursBack
    How far back to search the event log. Default: 24 hours.
.PARAMETER WatchGroups
    Group names to specifically alert on. Defaults to all privileged groups.
.PARAMETER AlertEmail
    Email address to send alerts. Requires Send-MailMessage config.
.EXAMPLE
    Get-ADGroupChanges -HoursBack 48 -AlertEmail "security@company.com"
#>
[CmdletBinding()]
param(
    [int]$HoursBack     = 24,
    [string[]]$WatchGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators"),
    [string]$AlertEmail,
    [string]$SMTPServer,
    [string]$OutputPath = $PWD
)

$StartTime = (Get-Date).AddHours(-$HoursBack)
$Events    = [System.Collections.Generic.List[PSObject]]::new()

# Event IDs: 4728=added to security global, 4729=removed from security global
#            4732=added to security local, 4733=removed from security local
#            4756=added to universal, 4757=removed from universal
$EventIDs = @(4728, 4729, 4732, 4733, 4756, 4757)

$DCs = (Get-ADDomainController -Filter *).HostName
foreach ($DC in $DCs) {
    Write-Host "[*] Querying event log on: $DC" -ForegroundColor Cyan
    try {
        $rawEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName   = "Security"
            Id        = $EventIDs
            StartTime = $StartTime
        } -ErrorAction Stop

        foreach ($e in $rawEvents) {
            $xml   = [xml]$e.ToXml()
            $data  = $xml.Event.EventData.Data
            $group = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"
            $actor = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"
            $added = ($data | Where-Object { $_.Name -eq "MemberName" })."#text"

            if (-not $WatchGroups -or $WatchGroups -contains $group) {
                $Events.Add([PSCustomObject]@{
                    Timestamp  = $e.TimeCreated
                    DC         = $DC
                    EventID    = $e.Id
                    Action     = if ($e.Id -in 4728,4732,4756) { "ADDED" } else { "REMOVED" }
                    Group      = $group
                    Account    = $added
                    PerformedBy= $actor
                    Message    = $e.Message
                })
            }
        }
    } catch { Write-Warning "Could not query $DC`: $_" }
}

$CsvPath = Join-Path $OutputPath "ADGroupChanges_$(Get-Date -Format yyyyMMdd_HH).csv"
$Events | Export-Csv $CsvPath -NoTypeInformation

Write-Host "`n[RESULTS] $($Events.Count) group changes in last $HoursBack hours" -ForegroundColor $(if ($Events.Count -gt 0) { "Yellow" } else { "Green" })
if ($Events.Count -gt 0) { $Events | Format-Table Timestamp, Action, Group, Account, PerformedBy -AutoSize }

# Alert on privileged group changes
$privilegedChanges = $Events | Where-Object { $WatchGroups -contains $_.Group }
if ($privilegedChanges -and $AlertEmail -and $SMTPServer) {
    $body = $privilegedChanges | ConvertTo-Html -Property Timestamp,Action,Group,Account,PerformedBy | Out-String
    Send-MailMessage -To $AlertEmail -From "ad-monitoring@company.com" `
        -Subject "[ALERT] $($privilegedChanges.Count) Privileged AD Group Changes Detected" `
        -Body $body -BodyAsHtml -SmtpServer $SMTPServer
    Write-Host "[ALERT] Email sent to $AlertEmail" -ForegroundColor Red
}
