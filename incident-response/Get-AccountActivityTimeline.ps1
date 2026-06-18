<#
.SYNOPSIS
    Builds a timeline of account activity from Windows Security event logs.
.DESCRIPTION
    Reconstructs user activity timeline from Security event log:
    logon/logoff, privilege use, account changes, object access.
    Useful for investigating insider threats or compromised accounts.
.PARAMETER Username
    Account to investigate (SamAccountName).
.PARAMETER StartTime
    Start of investigation window.
.PARAMETER EndTime
    End of investigation window. Default: now.
.PARAMETER DomainControllers
    DCs to query. Default: all in current domain.
.EXAMPLE
    Get-AccountActivityTimeline -Username "jsmith" -StartTime "2026-01-15 00:00:00" -OutputPath "C:\IR"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][datetime]$StartTime,
    [datetime]$EndTime   = (Get-Date),
    [string[]]$DomainControllers,
    [string]$OutputPath  = $PWD
)

if (-not $DomainControllers) {
    $DomainControllers = (Get-ADDomainController -Filter *).HostName
}

$Timeline = [System.Collections.Generic.List[PSObject]]::new()

$EventMap = @{
    4624 = "Logon - Successful"
    4625 = "Logon - Failed"
    4634 = "Logoff"
    4648 = "Logon - Explicit Credentials Used"
    4672 = "Privilege - Special Privileges Assigned"
    4720 = "Account - User Created"
    4722 = "Account - User Enabled"
    4723 = "Account - Password Change Attempt"
    4724 = "Account - Password Reset"
    4725 = "Account - User Disabled"
    4726 = "Account - User Deleted"
    4728 = "Group - Member Added (Global)"
    4732 = "Group - Member Added (Local)"
    4738 = "Account - User Account Changed"
    4740 = "Account - User Locked Out"
    4768 = "Kerberos - TGT Request"
    4769 = "Kerberos - Service Ticket Request"
    4776 = "NTLM - Credential Validation"
}

foreach ($DC in $DomainControllers) {
    Write-Host "[*] Querying $DC for account: $Username" -ForegroundColor Cyan
    try {
        $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName   = "Security"
            Id        = $EventMap.Keys
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop

        foreach ($e in $events) {
            $xml  = [xml]$e.ToXml()
            $data = $xml.Event.EventData.Data
            $subj = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"
            $tgt  = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"

            if ($subj -eq $Username -or $tgt -eq $Username) {
                $Timeline.Add([PSCustomObject]@{
                    Timestamp  = $e.TimeCreated
                    EventID    = $e.Id
                    Action     = $EventMap[$e.Id]
                    Source     = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"
                    Workstation= ($data | Where-Object { $_.Name -eq "WorkstationName" })."#text"
                    LogonType  = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"
                    TargetUser = $tgt
                    Subject    = $subj
                    DC         = $DC
                })
            }
        }
    } catch { Write-Warning "Could not query $DC`: $_" }
}

$Sorted  = $Timeline | Sort-Object Timestamp
$CsvPath = Join-Path $OutputPath "AccountTimeline_${Username}_$(Get-Date -Format yyyyMMdd).csv"
$Sorted  | Export-Csv $CsvPath -NoTypeInformation

Write-Host "`n[TIMELINE] $($Sorted.Count) events for $Username between $StartTime and $EndTime" -ForegroundColor Green
$Sorted | Format-Table Timestamp, EventID, Action, Source, Workstation -AutoSize
