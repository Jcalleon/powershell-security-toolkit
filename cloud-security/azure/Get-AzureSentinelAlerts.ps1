<#
.SYNOPSIS
    Retrieves Microsoft Sentinel security alerts and incidents via REST API.
.DESCRIPTION
    Queries Sentinel incidents and alerts, filters by severity/status,
    and exports for SOC triage, SLA reporting, or SOAR integration.
.EXAMPLE
    Get-AzureSentinelAlerts -WorkspaceId "xxx" -ResourceGroup "rg-sentinel" `
        -SubscriptionId "yyy" -MinSeverity "High"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkspaceId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [ValidateSet("Informational","Low","Medium","High")][string]$MinSeverity = "Medium",
    [ValidateSet("New","Active","Closed")][string]$Status = "New",
    [string]$OutputPath = $PWD
)

$token   = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
$headers = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }
$baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceId/providers/Microsoft.SecurityInsights"

$SevOrder = @{ Informational=0; Low=1; Medium=2; High=3 }
$minVal   = $SevOrder[$MinSeverity]

Write-Host "[*] Retrieving Sentinel incidents (Status: $Status, Min Severity: $MinSeverity)..." -ForegroundColor Cyan

$incidents = (Invoke-RestMethod -Uri "$baseUri/incidents?api-version=2023-02-01&`$filter=properties/status eq '$Status'" -Headers $headers).value |
    Where-Object { $SevOrder[$_.properties.severity] -ge $minVal }

$results = $incidents | ForEach-Object {
    [PSCustomObject]@{
        IncidentNumber = $_.properties.incidentNumber
        Title          = $_.properties.title
        Severity       = $_.properties.severity
        Status         = $_.properties.status
        CreatedTime    = $_.properties.createdTimeUtc
        LastUpdated    = $_.properties.lastModifiedTimeUtc
        AlertsCount    = $_.properties.additionalData.alertsCount
        Owner          = $_.properties.owner.assignedTo
        URL            = $_.properties.incidentUrl
    }
} | Sort-Object CreatedTime -Descending

$results | Export-Csv (Join-Path $OutputPath "SentinelIncidents_$(Get-Date -Format yyyyMMdd).csv") -NoTypeInformation
Write-Host "[DONE] Incidents: $($results.Count) | High: $(($results|Where-Object Severity -eq 'High').Count)" -ForegroundColor $(
    if (($results|Where-Object Severity -eq 'High').Count -gt 0) { "Red" } else { "Yellow" })
return $results
