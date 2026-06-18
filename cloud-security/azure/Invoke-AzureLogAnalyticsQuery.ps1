<#
.SYNOPSIS
    Runs KQL queries against Azure Log Analytics / Microsoft Sentinel via REST API.
.DESCRIPTION
    Executes Kusto Query Language (KQL) searches against Log Analytics workspaces
    for threat hunting, compliance checks, and security investigation workflows.
    Returns structured results for PowerShell pipeline integration.
.EXAMPLE
    $results = Invoke-AzureLogAnalyticsQuery -WorkspaceId "xxxx" `
        -Query "SecurityEvent | where EventID == 4625 | summarize count() by Account, IpAddress" `
        -TimeSpan "PT24H"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkspaceId,
    [Parameter(Mandatory)][string]$Query,
    [string]$TimeSpan   = "PT24H",
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret
)

# Auth via service principal or current AZ context
if ($ClientId -and $ClientSecret -and $TenantId) {
    $tokenResp = Invoke-RestMethod "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body @{
        grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret
        scope="https://api.loganalytics.io/.default"
    }
    $token = $tokenResp.access_token
} else {
    $token = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io").Token
}

$headers  = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }
$body     = @{ query=$Query; timespan=$TimeSpan } | ConvertTo-Json

Write-Host "[*] Running KQL query against workspace $WorkspaceId..." -ForegroundColor Cyan

$resp = Invoke-RestMethod -Uri "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query" `
    -Method POST -Headers $headers -Body $body -ErrorAction Stop

$cols = $resp.tables[0].columns.name
$rows = $resp.tables[0].rows | ForEach-Object {
    $row = $_; $obj = [ordered]@{}
    for ($i = 0; $i -lt $cols.Count; $i++) { $obj[$cols[$i]] = $row[$i] }
    [PSCustomObject]$obj
}

Write-Host "[DONE] Rows returned: $($rows.Count)" -ForegroundColor Green
return $rows
