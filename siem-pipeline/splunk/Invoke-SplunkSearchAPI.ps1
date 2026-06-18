<#
.SYNOPSIS
    Runs Splunk searches via REST API and returns structured results for automation.
.DESCRIPTION
    Wraps Splunk REST search API to run SPL queries programmatically, poll for
    job completion, and return results as PowerShell objects. Useful for driving
    automated response workflows from Splunk alert data.
.PARAMETER SplunkServer
    Splunk server hostname or IP.
.PARAMETER Port
    Splunk REST API port. Default: 8089.
.PARAMETER Credential
    Splunk credentials (Get-Credential).
.PARAMETER SPLQuery
    SPL search query string.
.PARAMETER EarliestTime
    Search earliest time (Splunk time modifier, e.g., "-24h@h" or epoch).
.PARAMETER LatestTime
    Search latest time. Default: "now".
.EXAMPLE
    $cred = Get-Credential
    $results = Invoke-SplunkSearchAPI -SplunkServer "splunk.corp.local" -Credential $cred `
        -SPLQuery "index=security sourcetype=WinEventLog EventCode=4625 | stats count by src_ip" `
        -EarliestTime "-1h@h"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SplunkServer,
    [int]$Port = 8089,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [Parameter(Mandatory)][string]$SPLQuery,
    [string]$EarliestTime = "-24h@h",
    [string]$LatestTime   = "now",
    [int]$MaxResults      = 10000,
    [int]$PollSec         = 5
)

$BaseUrl = "https://${SplunkServer}:${Port}"
$headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
$auth    = @{ Credential = $Credential; SkipCertificateCheck = $true }

# Submit search job
Write-Host "[*] Submitting Splunk search..." -ForegroundColor Cyan
$jobResp = Invoke-RestMethod -Uri "$BaseUrl/services/search/jobs" -Method POST @auth `
    -Body "search=$([uri]::EscapeDataString("search $SPLQuery"))&earliest_time=$EarliestTime&latest_time=$LatestTime&output_mode=json"
$sid = $jobResp.sid
Write-Host "  [*] Job SID: $sid" -ForegroundColor Gray

# Poll until done
$done = $false
while (-not $done) {
    Start-Sleep -Seconds $PollSec
    $statusResp = Invoke-RestMethod -Uri "$BaseUrl/services/search/jobs/$sid" -Method GET @auth -Body "output_mode=json"
    $state = $statusResp.entry.content.dispatchState
    $pct   = $statusResp.entry.content.doneProgress
    Write-Host "  [~] Status: $state ($([math]::Round($pct * 100, 0))%)" -ForegroundColor Gray
    if ($state -in "DONE","FAILED","FINALIZED") { $done = $true }
}

if ($state -ne "DONE") { Write-Warning "Search ended with state: $state"; return }

# Retrieve results
$resultsResp = Invoke-RestMethod -Uri "$BaseUrl/services/search/jobs/$sid/results" -Method GET @auth `
    -Body "output_mode=json&count=$MaxResults"

$results = $resultsResp.results
Write-Host "[DONE] $($results.Count) results returned" -ForegroundColor Green
return $results
