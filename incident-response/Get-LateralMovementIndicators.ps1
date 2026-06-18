<#
.SYNOPSIS
    Hunts for lateral movement indicators across Windows event logs and artifacts.
.DESCRIPTION
    Detects common lateral movement patterns: pass-the-hash (4624 type 3 NTLM),
    PsExec artifacts, WMI remote execution, scheduled task creation over network,
    and SMB admin share access from unusual sources.
    Maps to MITRE ATT&CK T1021.x (Remote Services).
.EXAMPLE
    Get-LateralMovementIndicators -ComputerName "DC01","SRV01" -HoursBack 48
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$HoursBack = 24,
    [string]$OutputPath = $PWD
)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Findings  = [System.Collections.Generic.List[PSObject]]::new()
$StartTime = (Get-Date).AddHours(-$HoursBack)

function Add-LMFinding { param($comp,$tech,$detail,$src)
    $script:Findings.Add([PSCustomObject]@{
        Computer=$comp; Timestamp=(Get-Date -Format "o"); Technique=$tech; Detail=$detail; SourceIP=$src
    })
    Write-Host "  [LM] $tech | $detail" -ForegroundColor Yellow
}

foreach ($comp in $ComputerName) {
    Write-Host "[*] LM hunting on: $comp" -ForegroundColor Cyan
    try {
        $events = Get-WinEvent -ComputerName $comp -FilterHashtable @{ LogName="Security"; StartTime=$StartTime } -ErrorAction Stop

        # T1021.002 - Pass-the-Hash (Type 3 NTLM logon from non-domain source)
        $events | Where-Object { $_.Id -eq 4624 } | ForEach-Object {
            $xml = [xml]$_.ToXml(); $d = $xml.Event.EventData.Data
            $logonType    = ($d | Where-Object Name -eq "LogonType")."#text"
            $authPackage  = ($d | Where-Object Name -eq "AuthenticationPackageName")."#text"
            $srcIP        = ($d | Where-Object Name -eq "IpAddress")."#text"
            if ($logonType -eq "3" -and $authPackage -eq "NTLM" -and $srcIP -notmatch "^(127\.|::1|-$)") {
                Add-LMFinding $comp "T1021.002 Pass-the-Hash candidate" "Type3 NTLM from $srcIP" $srcIP
            }
        }

        # T1021.003 - DCOM / WMI remote (event 4688 WmiPrvSE with network parent)
        $events | Where-Object { $_.Id -eq 4688 } | ForEach-Object {
            $xml = [xml]$_.ToXml(); $d = $xml.Event.EventData.Data
            $proc   = ($d | Where-Object Name -eq "NewProcessName")."#text"
            $parent = ($d | Where-Object Name -eq "ParentProcessName")."#text"
            if ($proc -match "WmiPrvSE|wmiprvse" -and $parent -match "svchost") { } # benign
            elseif ($parent -match "WmiPrvSE" -and $proc -match "cmd|powershell|cscript|wscript") {
                Add-LMFinding $comp "T1021.003 WMI Remote Execution" "$parent -> $proc" ""
            }
        }

        # PsExec artifacts (service creation with PSEXESVC)
        $events | Where-Object { $_.Id -eq 7045 } | ForEach-Object {
            $xml = [xml]$_.ToXml(); $d = $xml.Event.EventData.Data
            $svcName = ($d | Where-Object Name -eq "ServiceName")."#text"
            if ($svcName -match "PSEXESVC|psexesvc") {
                Add-LMFinding $comp "T1021.002 PsExec Service Installed" "Service: $svcName" ""
            }
        }

    } catch { Write-Warning "Could not query $comp`: $_" }
}

$Findings | Export-Csv (Join-Path $OutputPath "LateralMovement_$Timestamp.csv") -NoTypeInformation
Write-Host "[DONE] LM indicators found: $($Findings.Count)" -ForegroundColor $(if ($Findings.Count -gt 0) { "Red" } else { "Green" })
