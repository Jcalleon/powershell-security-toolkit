<#
.SYNOPSIS
    Bulk-deploys detection rules from a YAML/JSON library to Splunk as saved searches.
.DESCRIPTION
    Reads a detection library (Sigma rules converted to SPL, or custom JSON),
    deploys each rule as a Splunk saved search with proper metadata.
    Supports dry-run, rollback tracking, and deployment audit log.
.EXAMPLE
    Invoke-SplunkDetectionDeployment -SplunkServer "splunk.corp.local" `
        -Credential (Get-Credential) -DetectionLibraryPath "C:\Detections"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SplunkServer,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [Parameter(Mandatory)][string]$DetectionLibraryPath,
    [string]$App        = "search",
    [switch]$EnableAll
)

$BaseUrl = "https://${SplunkServer}:8089"
$auth    = @{ Credential=$Credential; SkipCertificateCheck=$true }
$Deployed= [System.Collections.Generic.List[PSObject]]::new()

$files = Get-ChildItem $DetectionLibraryPath -Filter "*.json" -Recurse
Write-Host "[*] Deploying $($files.Count) detections to Splunk ($SplunkServer)..." -ForegroundColor Cyan

foreach ($file in $files) {
    $rule = Get-Content $file.FullName | ConvertFrom-Json
    $body = @{
        name                  = $rule.name
        search                = $rule.spl_query
        cron_schedule         = $rule.schedule ?? "*/15 * * * *"
        is_scheduled          = "1"
        "alert.severity"      = $rule.severity ?? "medium"
        "alert.suppress"      = "0"
        description           = $rule.description
        dispatch.earliest_time= $rule.lookback ?? "-15m@m"
        dispatch.latest_time  = "now"
    }
    if ($PSCmdlet.ShouldProcess($rule.name, "Deploy detection rule")) {
        try {
            Invoke-RestMethod -Uri "$BaseUrl/servicesNS/admin/$App/saved/searches" `
                -Method POST @auth -Body $body -ContentType "application/x-www-form-urlencoded" | Out-Null
            Write-Host "  [+] $($rule.name)" -ForegroundColor Green
            $Deployed.Add([PSCustomObject]@{ Rule=$rule.name; Status="SUCCESS"; File=$file.Name })
        } catch {
            Write-Host "  [!] $($rule.name) - $_" -ForegroundColor Red
            $Deployed.Add([PSCustomObject]@{ Rule=$rule.name; Status="FAILED"; Error=$_.Exception.Message })
        }
    }
}

$Deployed | Export-Csv "DetectionDeployment_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "[DONE] Deployed: $(($Deployed|Where-Object Status -eq 'SUCCESS').Count) | Failed: $(($Deployed|Where-Object Status -eq 'FAILED').Count)" -ForegroundColor Green
