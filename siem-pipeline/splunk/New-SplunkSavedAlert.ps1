<#
.SYNOPSIS
    Creates Splunk saved searches and alert actions via REST API.
.DESCRIPTION
    Programmatically deploys detection rules as Splunk saved searches with
    alerting. Useful for bulk-deploying detection content from a library.
.PARAMETER SplunkServer
    Splunk server hostname.
.PARAMETER Credential
    Splunk admin credentials.
.PARAMETER AlertName
    Name for the saved search/alert.
.PARAMETER SPLQuery
    SPL detection query.
.PARAMETER CronSchedule
    Cron expression for scheduling. Default: "*/5 * * * *" (every 5 min).
.PARAMETER WebhookUrl
    Webhook URL for alert action (SOAR, Teams, Slack, etc.).
.EXAMPLE
    New-SplunkSavedAlert -SplunkServer "splunk.corp.local" -Credential (Get-Credential) `
        -AlertName "Failed Logons - Brute Force" `
        -SPLQuery "index=security EventCode=4625 | stats count by src_ip | where count > 20" `
        -WebhookUrl "https://soar.corp.local/api/webhook/brute-force"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SplunkServer,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [Parameter(Mandatory)][string]$AlertName,
    [Parameter(Mandatory)][string]$SPLQuery,
    [string]$App          = "search",
    [string]$CronSchedule = "*/5 * * * *",
    [int]$AlertThreshold  = 1,
    [string]$WebhookUrl,
    [string]$Severity     = "high"
)

$BaseUrl = "https://${SplunkServer}:8089"
$auth    = @{ Credential = $Credential; SkipCertificateCheck = $true }

$body = @{
    name                             = $AlertName
    search                           = $SPLQuery
    cron_schedule                    = $CronSchedule
    is_scheduled                     = "1"
    alert_type                       = "number of events"
    alert_comparator                 = "greater than"
    alert_threshold                  = $AlertThreshold
    "alert.severity"                 = $Severity
    "alert.suppress"                 = "0"
    "alert.track"                    = "1"
    dispatch.earliest_time           = "-5m@m"
    dispatch.latest_time             = "now"
    realtime_schedule                = "0"
}

if ($WebhookUrl) {
    $body["action.webhook"]              = "1"
    $body["action.webhook.param.url"]    = $WebhookUrl
}

if ($PSCmdlet.ShouldProcess($AlertName, "Create Splunk saved alert")) {
    try {
        $resp = Invoke-RestMethod -Uri "$BaseUrl/servicesNS/admin/$App/saved/searches" `
            -Method POST @auth -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "[+] Alert created: $AlertName" -ForegroundColor Green
        Write-Host "    Schedule: $CronSchedule | Threshold: >$AlertThreshold events" -ForegroundColor Gray
        return $resp
    } catch {
        Write-Error "Failed to create alert '$AlertName': $($_.Exception.Message)"
    }
}
