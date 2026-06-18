<#
.SYNOPSIS
    Deploys Elasticsearch/Kibana SIEM detection rules via the Security API.
.DESCRIPTION
    Creates or updates Kibana SIEM detection rules from a JSON library using
    the Kibana Detection Engine REST API. Supports bulk import, tagging,
    and deployment tracking.
.EXAMPLE
    Invoke-ELKDetectionRuleDeployment -KibanaUrl "https://kibana.corp.local:5601" `
        -ApiKey "abc==" -RulePath "C:\ELKRules"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$KibanaUrl,
    [string]$ApiKey,
    [PSCredential]$Credential,
    [Parameter(Mandatory)][string]$RulePath
)

$Headers = @{ "kbn-xsrf"="true"; "Content-Type"="application/json" }
if ($ApiKey)     { $Headers["Authorization"] = "ApiKey $ApiKey" }

$auth = @{}
if ($Credential) { $auth["Credential"] = $Credential }

$rules = Get-ChildItem $RulePath -Filter "*.json" -Recurse | ForEach-Object {
    Get-Content $_.FullName | ConvertFrom-Json
}

Write-Host "[*] Deploying $($rules.Count) ELK detection rules..." -ForegroundColor Cyan

# Bulk create
$bulkBody = @{ rules = $rules } | ConvertTo-Json -Depth 10
if ($PSCmdlet.ShouldProcess("Kibana", "Bulk deploy $($rules.Count) detection rules")) {
    $result = Invoke-RestMethod -Uri "$KibanaUrl/api/detection_engine/rules/_bulk_create" `
        -Method POST -Headers $Headers -Body $bulkBody @auth
    $created = ($result | Where-Object { -not $_.error }).Count
    $failed  = ($result | Where-Object { $_.error }).Count
    Write-Host "[DONE] Created: $created | Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
}
