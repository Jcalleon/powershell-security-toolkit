<#
.SYNOPSIS
    Queries Kibana/Elasticsearch for active security alerts and rule status.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ElasticsearchUrl, [string]$ApiKey, [string]$OutputPath = $PWD)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Headers   = @{ "Content-Type"="application/json"; "kbn-xsrf"="true" }
if ($ApiKey) { $Headers["Authorization"] = "ApiKey $ApiKey" }
$alertQuery = @{ query=@{ range=@{ "@timestamp"=@{ gte="now-24h"; lte="now" } } }; size=100 } | ConvertTo-Json -Depth 5
$resp    = Invoke-RestMethod -Uri "$ElasticsearchUrl/.alerts-security.alerts-default/_search" -Method POST -Headers $Headers -Body $alertQuery -SkipCertificateCheck
$alerts  = $resp.hits.hits | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_._source."@timestamp"; Rule=$_._source."kibana.alert.rule.name"
        Severity  = $_._source."kibana.alert.severity"; Host=$_._source."host.name"
        Status    = $_._source."kibana.alert.workflow_status"
    }
}
$alerts | Export-Csv (Join-Path $OutputPath "ELKAlerts_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] Active alerts (24h): $($alerts.Count)" -ForegroundColor $(if ($alerts.Count -gt 0) { "Yellow" } else { "Green" })
