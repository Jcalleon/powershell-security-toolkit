<#
.SYNOPSIS
    Calculates a CIS compliance score for a Windows system and trends over time.
.DESCRIPTION
    Runs a lightweight CIS check battery and produces a numeric score (0-100)
    suitable for dashboarding, SLA reporting, or triggering remediation workflows.
    Stores historical scores to track improvement over time.
.EXAMPLE
    Get-CISComplianceScore -ComputerName "SRV01" -ScoreHistoryPath "C:\Compliance\History"
#>
[CmdletBinding()]
param(
    [string]$ComputerName   = $env:COMPUTERNAME,
    [string]$ScoreHistoryPath = "$env:ProgramData\CISScores"
)

$Checks = [System.Collections.Generic.List[PSObject]]::new()

function Add-Check {
    param([string]$ID, [string]$Name, [bool]$Pass, [int]$Weight = 1)
    $Checks.Add([PSCustomObject]@{ ID=$ID; Name=$Name; Pass=$Pass; Weight=$Weight })
}

# Run checks
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
Add-Check "1.1" "WDigest disabled"          ($lsa.UseLogonCredential -eq 0)         -Weight 3
Add-Check "1.2" "LSASS PPL enabled"         ($lsa.RunAsPPL -eq 1)                   -Weight 3
Add-Check "1.3" "NTLMv2 required"           ($lsa.LmCompatibilityLevel -ge 5)       -Weight 3
Add-Check "2.1" "SMBv1 disabled"            ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false) -Weight 3
Add-Check "2.2" "SMB signing required"      ((Get-SmbServerConfiguration).RequireSecuritySignature -eq $true) -Weight 2
Add-Check "3.1" "Firewall Domain on"        ((Get-NetFirewallProfile -Profile Domain).Enabled -eq "True") -Weight 2
Add-Check "3.2" "Firewall Private on"       ((Get-NetFirewallProfile -Profile Private).Enabled -eq "True") -Weight 2
Add-Check "3.3" "Firewall Public on"        ((Get-NetFirewallProfile -Profile Public).Enabled -eq "True") -Weight 2
Add-Check "4.1" "PS Script Block Logging"   ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1) -Weight 2
Add-Check "4.2" "RDP NLA required"         ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue).UserAuthentication -eq 1) -Weight 2
Add-Check "5.1" "AutoRun disabled"          ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun -eq 255) -Weight 1
Add-Check "5.2" "Windows Defender running"  ((Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status -eq "Running") -Weight 2

$totalWeight  = ($Checks | Measure-Object Weight -Sum).Sum
$passedWeight = ($Checks | Where-Object Pass | Measure-Object Weight -Sum).Sum
$score        = [math]::Round(($passedWeight / $totalWeight) * 100, 1)

# Store history
if (-not (Test-Path $ScoreHistoryPath)) { New-Item $ScoreHistoryPath -ItemType Directory -Force | Out-Null }
$histFile = Join-Path $ScoreHistoryPath "${ComputerName}_scores.csv"
[PSCustomObject]@{ Date=(Get-Date -Format "yyyy-MM-dd"); Computer=$ComputerName; Score=$score; Passed=$(($Checks|Where-Object Pass).Count); Total=$Checks.Count } |
    Export-Csv $histFile -Append -NoTypeInformation

Write-Host "[SCORE] $ComputerName CIS Compliance: $score / 100" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
$Checks | Where-Object { -not $_.Pass } | Format-Table ID, Name -AutoSize
return [PSCustomObject]@{ Computer=$ComputerName; Score=$score; PassedChecks=$(($Checks|Where-Object Pass).Count); TotalChecks=$Checks.Count }
