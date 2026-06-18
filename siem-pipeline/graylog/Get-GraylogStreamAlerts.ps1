<#
.SYNOPSIS
    Retrieves active Graylog stream alerts and event notifications via REST API.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GraylogServer,
    [int]$Port = 9000,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [string]$OutputPath = $PWD
)
$BaseUrl = "http://${GraylogServer}:${Port}/api"
$Bytes   = [System.Text.Encoding]::ASCII.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)")
$Headers = @{ "Authorization"="Basic "+[Convert]::ToBase64String($Bytes); "X-Requested-By"="PowerShell" }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$alerts = (Invoke-RestMethod -Uri "$BaseUrl/events/definitions" -Headers $Headers).event_definitions
$results = $alerts | ForEach-Object {
    [PSCustomObject]@{
        ID          = $_.id
        Title       = $_.title
        Description = $_.description
        Priority    = $_.priority
        Enabled     = $_.enabled
        Type        = $_.config.type
        Schedule    = $_.config.search_within_ms
    }
}
$results | Export-Csv (Join-Path $OutputPath "GraylogAlerts_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Graylog event definitions: $($results.Count) | Enabled: $(($results | Where-Object Enabled).Count)" -ForegroundColor Green
