<#
.SYNOPSIS
    Ships structured security events to Elasticsearch via REST API.
.DESCRIPTION
    Indexes PowerShell-generated security events (audit results, alert triggers,
    automation findings) into Elasticsearch with proper index naming, mappings,
    and ECS (Elastic Common Schema) field alignment.
.PARAMETER ElasticsearchUrl
    Elasticsearch endpoint (e.g., https://elk.corp.local:9200).
.PARAMETER IndexPrefix
    Index name prefix. Events go to ${prefix}-YYYY.MM.DD. Default: security-ps.
.PARAMETER ApiKey
    Elasticsearch API key (base64 encoded id:key). Use instead of basic auth.
.EXAMPLE
    $event = @{ event=@{action="cis_audit"; outcome="failure"}; host=@{name="SRV01"}; vulnerability=@{score=@{base=9.1}} }
    Send-ELKSecurityEvent -ElasticsearchUrl "https://elk:9200" -ApiKey "abc==" -EventData $event
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ElasticsearchUrl,
    [Parameter(Mandatory)][object]$EventData,
    [string]$IndexPrefix = "security-ps",
    [string]$ApiKey,
    [PSCredential]$Credential,
    [switch]$SkipCertCheck
)

$Index    = "$IndexPrefix-$(Get-Date -Format 'yyyy.MM.dd')"
$Uri      = "$($ElasticsearchUrl.TrimEnd('/'))/$Index/_doc"
$Headers  = @{ "Content-Type" = "application/json" }

if ($ApiKey) { $Headers["Authorization"] = "ApiKey $ApiKey" }

# ECS base fields
$ECSEvent = @{
    "@timestamp"     = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    "ecs.version"    = "8.0.0"
    "host"           = @{ "name" = $env:COMPUTERNAME; "os" = @{ "family" = "windows" } }
    "agent"          = @{ "name" = "powershell-security-automation"; "type" = "powershell" }
    "event"          = @{ "created" = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"); "module" = "powershell" }
}

# Merge user event data
foreach ($key in $EventData.Keys) { $ECSEvent[$key] = $EventData[$key] }

$Params = @{
    Uri     = $Uri
    Method  = "POST"
    Headers = $Headers
    Body    = ($ECSEvent | ConvertTo-Json -Depth 10 -Compress)
}
if ($Credential)    { $Params["Credential"] = $Credential }
if ($SkipCertCheck) { $Params["SkipCertificateCheck"] = $true }

try {
    $resp = Invoke-RestMethod @Params -ErrorAction Stop
    Write-Verbose "[ELK] Indexed to $Index ($($resp.result))"
    return $resp._id
} catch { Write-Error "ELK indexing failed: $($_.Exception.Message)" }
