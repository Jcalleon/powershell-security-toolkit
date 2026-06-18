<#
.SYNOPSIS
    Creates ServiceNow or Jira tickets from security findings automatically.
.DESCRIPTION
    Takes security findings (from CIS audit, vuln scan, AD audit) and creates
    properly categorized tickets in ServiceNow or Jira with all relevant metadata.
    Designed for automated remediation workflow initiation.
.PARAMETER Platform
    Ticketing platform: ServiceNow or Jira.
.EXAMPLE
    $findings = Import-Csv "CIS_Audit_20260101.csv" | Where-Object Status -eq "FAIL"
    New-SecurityTicket -Platform "ServiceNow" -BaseUrl "https://company.service-now.com" `
        -Credential (Get-Credential) -Findings $findings -AssignmentGroup "IT-Security"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("ServiceNow","Jira")][string]$Platform = "ServiceNow",
    [Parameter(Mandatory)][string]$BaseUrl,
    [Parameter(Mandatory)][PSCredential]$Credential,
    [Parameter(Mandatory)][object[]]$Findings,
    [string]$AssignmentGroup = "IT-Security",
    [string]$JiraProject      = "SEC"
)

$Bytes   = [System.Text.Encoding]::ASCII.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)")
$Headers = @{ "Authorization"="Basic "+[Convert]::ToBase64String($Bytes); "Content-Type"="application/json" }
$Created = [System.Collections.Generic.List[PSObject]]::new()

foreach ($finding in $Findings) {
    $title = if ($finding.Title) { $finding.Title } elseif ($finding.PluginName) { $finding.PluginName } else { $finding.Check }
    $body  = if ($Platform -eq "ServiceNow") {
        @{ short_description="[Security] $title"; description=($finding | ConvertTo-Json)
           category="security"; assignment_group=$AssignmentGroup
           urgency=if($finding.Status -match "Critical|FAIL"){"2"}else{"3"}
           impact=if($finding.Status -match "Critical"){"2"}else{"3"} } | ConvertTo-Json
    } else {
        @{ fields=@{ project=@{key=$JiraProject}; summary="[Security] $title"
                     description=($finding|ConvertTo-Json); issuetype=@{name="Bug"}
                     priority=@{name=if($finding.Severity -match "Critical|High"){"High"}else{"Medium"}} } } | ConvertTo-Json -Depth 5
    }
    if ($PSCmdlet.ShouldProcess($title, "Create $Platform ticket")) {
        try {
            $ep   = if ($Platform -eq "ServiceNow") { "/api/now/table/incident" } else { "/rest/api/2/issue" }
            $resp = Invoke-RestMethod -Uri "$BaseUrl$ep" -Method POST -Headers $Headers -Body $body -ErrorAction Stop
            $id   = if ($Platform -eq "ServiceNow") { $resp.result.number } else { $resp.key }
            $Created.Add([PSCustomObject]@{ TicketID=$id; Title=$title; Platform=$Platform })
            Write-Host "  [+] Created $id: $title" -ForegroundColor Green
        } catch { Write-Warning "Failed to create ticket for: $title - $_" }
    }
}
Write-Host "[DONE] Tickets created: $($Created.Count)" -ForegroundColor Green
$Created | Format-Table TicketID, Title -AutoSize
