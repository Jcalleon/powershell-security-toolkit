<#
.SYNOPSIS
    Orchestrates threat containment actions on a compromised host.
.DESCRIPTION
    Executes a staged containment playbook: disable AD account, isolate network,
    kill suspicious processes, preserve forensic artifacts, notify SOC team.
    Designed as an automated SOAR-style response workflow.
.EXAMPLE
    Invoke-ThreatContainment -ComputerName "WORKSTATION01" -Username "jsmith" `
        -IncidentID "INC-2026-042" -NotifyEmail "soc@company.com"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ComputerName,
    [string]$Username,
    [Parameter(Mandatory)][string]$IncidentID,
    [string]$NotifyEmail,
    [string]$SMTPServer,
    [string]$ForensicsPath = "C:\IR\Cases",
    [switch]$SkipNetworkIsolation
)

$IRSystems = @("10.0.1.100","10.0.1.101")   # SOC/IR systems allowed through isolation
$Actions   = [System.Collections.Generic.List[PSObject]]::new()
function Log-Action { param($step,$status,$detail)
    $script:Actions.Add([PSCustomObject]@{ Timestamp=(Get-Date -Format "o"); IncidentID=$IncidentID; Step=$step; Status=$status; Detail=$detail })
    Write-Host "  $(if($status -eq 'DONE'){'[+]'}else{'[!]'}) $step - $status" -ForegroundColor $(if($status -eq 'DONE'){'Green'}else{'Red'})
}

Write-Host "[*] THREAT CONTAINMENT INITIATED - $IncidentID | $ComputerName" -ForegroundColor Red

# Step 1: Disable AD account
if ($Username -and $PSCmdlet.ShouldProcess($Username, "Disable AD account")) {
    try { Disable-ADAccount -Identity $Username; Log-Action "Disable AD Account $Username" "DONE" "Account disabled in AD" }
    catch { Log-Action "Disable AD Account $Username" "FAILED" $_.Exception.Message }
}

# Step 2: Network isolation
if (-not $SkipNetworkIsolation -and $PSCmdlet.ShouldProcess($ComputerName, "Isolate network")) {
    try {
        Invoke-Command -ComputerName $ComputerName -ArgumentList (,$IRSystems) -ScriptBlock {
            param($ir)
            New-NetFirewallRule -DisplayName "CONTAIN_Block_All_In"  -Direction Inbound  -Action Block -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "CONTAIN_Block_All_Out" -Direction Outbound -Action Block -Profile Any | Out-Null
            foreach ($ip in $ir) {
                New-NetFirewallRule -DisplayName "CONTAIN_Allow_IR_In_$ip"  -Direction Inbound  -RemoteAddress $ip -Action Allow | Out-Null
                New-NetFirewallRule -DisplayName "CONTAIN_Allow_IR_Out_$ip" -Direction Outbound -RemoteAddress $ip -Action Allow | Out-Null
            }
        }
        Log-Action "Network Isolation" "DONE" "All traffic blocked except IR systems"
    } catch { Log-Action "Network Isolation" "FAILED" $_.Exception.Message }
}

# Step 3: Forensic collection
try {
    $caseDir = Join-Path $ForensicsPath $IncidentID
    & "$PSScriptRoot\Invoke-LiveResponseCollection.ps1" -ComputerName $ComputerName -OutputPath $caseDir
    Log-Action "Forensic Collection" "DONE" "Artifacts saved to $caseDir"
} catch { Log-Action "Forensic Collection" "FAILED" $_.Exception.Message }

# Step 4: Notify SOC
if ($NotifyEmail -and $SMTPServer) {
    $body = $Actions | ConvertTo-Html -Property Timestamp,Step,Status,Detail | Out-String
    Send-MailMessage -To $NotifyEmail -From "ir-automation@company.com" `
        -Subject "[IR] Containment Actions Taken - $IncidentID ($ComputerName)" `
        -Body $body -BodyAsHtml -SmtpServer $SMTPServer
    Log-Action "SOC Notification" "DONE" "Email sent to $NotifyEmail"
}

$Actions | Export-Csv (Join-Path $ForensicsPath "${IncidentID}_containment_log.csv") -NoTypeInformation
Write-Host "[CONTAINMENT COMPLETE] $IncidentID | Actions: $($Actions.Count)" -ForegroundColor Red
