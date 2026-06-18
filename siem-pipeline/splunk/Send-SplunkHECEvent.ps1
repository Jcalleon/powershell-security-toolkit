<#
.SYNOPSIS
    Sends structured security events to Splunk via HTTP Event Collector (HEC).
.DESCRIPTION
    Provides a reusable function to forward PowerShell-generated security events
    (audit findings, alert triggers, automation results) to Splunk HEC with
    proper sourcetype, index, and host metadata.
.PARAMETER SplunkHECUrl
    Splunk HEC endpoint URL (e.g., https://splunk.corp.local:8088/services/collector).
.PARAMETER HECToken
    Splunk HEC token (store in secrets vault, not plaintext).
.PARAMETER EventData
    Hashtable or PSObject to send as the event payload.
.PARAMETER SourceType
    Splunk sourcetype. Default: powershell:security.
.PARAMETER Index
    Target Splunk index. Default: security.
.EXAMPLE
    $event = @{ action="cis_audit"; host="SRV01"; score=82; findings=5 }
    Send-SplunkHECEvent -SplunkHECUrl "https://splunk:8088/services/collector" `
        -HECToken "your-hec-token" -EventData $event -SourceType "powershell:cis_audit"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SplunkHECUrl,
    [Parameter(Mandatory)][string]$HECToken,
    [Parameter(Mandatory)][object]$EventData,
    [string]$SourceType = "powershell:security",
    [string]$Index      = "security",
    [string]$Host_      = $env:COMPUTERNAME,
    [switch]$SkipCertCheck
)

$Headers = @{ "Authorization" = "Splunk $HECToken" }

$Payload = @{
    time       = [math]::Round(([DateTimeOffset]::UtcNow).ToUnixTimeSeconds(), 0)
    host       = $Host_
    sourcetype = $SourceType
    index      = $Index
    event      = $EventData
} | ConvertTo-Json -Depth 10

$IWRParams = @{
    Uri         = $SplunkHECUrl
    Method      = "POST"
    Headers     = $Headers
    Body        = $Payload
    ContentType = "application/json"
    ErrorAction = "Stop"
}
if ($SkipCertCheck) { $IWRParams["SkipCertificateCheck"] = $true }

try {
    $response = Invoke-RestMethod @IWRParams
    if ($response.text -eq "Success") {
        Write-Verbose "[HEC] Event sent successfully to $Index ($SourceType)"
        return $true
    }
} catch {
    Write-Error "[HEC] Failed to send event: $($_.Exception.Message)"
    return $false
}
