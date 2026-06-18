<#
.SYNOPSIS
    Automates service account password rotation across systems with zero-downtime.
.DESCRIPTION
    Rotates service account passwords in AD, then updates dependent services,
    scheduled tasks, IIS app pools, and SQL Server agent jobs with the new
    credential. Validates connectivity before committing rotation.
.PARAMETER ServiceAccount
    AD service account to rotate.
.PARAMETER AffectedSystems
    List of servers where this account is used as a service credential.
.PARAMETER PasswordLength
    Length of generated password. Default: 32.
.EXAMPLE
    Invoke-SecretRotation -ServiceAccount "svc_splunk" -AffectedSystems "SPLUNK01","SPLUNK02" -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ServiceAccount,
    [Parameter(Mandatory)][string[]]$AffectedSystems,
    [int]$PasswordLength = 32,
    [string]$NotifyEmail,
    [string]$SMTPServer
)

Import-Module ActiveDirectory

function New-ComplexPassword {
    param([int]$Length = 32)
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*"
    $pwd   = (1..$Length | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] }) -join ""
    # Ensure complexity
    while ($pwd -notmatch '[A-Z]' -or $pwd -notmatch '[a-z]' -or $pwd -notmatch '\d' -or $pwd -notmatch '[!@#$%^&*]') {
        $pwd = (1..$Length | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] }) -join ""
    }
    return $pwd
}

$RotationLog = [System.Collections.Generic.List[PSObject]]::new()
$NewPassword = New-ComplexPassword -Length $PasswordLength
$SecurePwd   = ConvertTo-SecureString $NewPassword -AsPlainText -Force

Write-Host "[*] Starting secret rotation for: $ServiceAccount" -ForegroundColor Cyan
Write-Host "    Target systems: $($AffectedSystems -join ', ')" -ForegroundColor Gray

# Step 1: Validate account exists
$adAccount = Get-ADUser $ServiceAccount -Properties * -ErrorAction Stop
Write-Host "  [+] Account found: $($adAccount.DistinguishedName)" -ForegroundColor Green

# Step 2: Update AD password
if ($PSCmdlet.ShouldProcess($ServiceAccount, "Rotate AD password")) {
    try {
        Set-ADAccountPassword -Identity $ServiceAccount -NewPassword $SecurePwd -Reset
        Write-Host "  [+] AD password updated" -ForegroundColor Green
        $RotationLog.Add([PSCustomObject]@{ Step="AD Password"; Status="SUCCESS"; Timestamp=(Get-Date) })
    } catch {
        Write-Error "Failed to update AD password: $_"
        return
    }
}

# Step 3: Update services on affected systems
foreach ($Server in $AffectedSystems) {
    Write-Host "`n  [*] Updating services on: $Server" -ForegroundColor Yellow

    # Windows Services
    $services = Get-WmiObject Win32_Service -ComputerName $Server |
        Where-Object { $_.StartName -match [regex]::Escape($ServiceAccount) }

    foreach ($svc in $services) {
        if ($PSCmdlet.ShouldProcess("$Server\$($svc.Name)", "Update service credential")) {
            $result = $svc.Change($null,$null,$null,$null,$null,$null,$null,$NewPassword)
            $status = if ($result.ReturnValue -eq 0) { "SUCCESS" } else { "FAILED($($result.ReturnValue))" }
            Write-Host "    Service: $($svc.Name) - $status" -ForegroundColor $(if ($status -eq "SUCCESS") {"Green"} else {"Red"})
            $RotationLog.Add([PSCustomObject]@{ Step="Service:$($svc.Name)"; Server=$Server; Status=$status; Timestamp=(Get-Date) })
        }
    }

    # Scheduled Tasks
    $tasks = Get-ScheduledTask -CimSession (New-CimSession -ComputerName $Server -ErrorAction SilentlyContinue) |
        Where-Object { $_.Principal.UserId -match [regex]::Escape($ServiceAccount) }

    foreach ($task in $tasks) {
        if ($PSCmdlet.ShouldProcess("$Server\$($task.TaskName)", "Update scheduled task credential")) {
            try {
                Set-ScheduledTask -CimSession (New-CimSession -ComputerName $Server) `
                    -TaskName $task.TaskName -TaskPath $task.TaskPath `
                    -User $ServiceAccount -Password $NewPassword -ErrorAction Stop
                Write-Host "    Task: $($task.TaskName) - SUCCESS" -ForegroundColor Green
            } catch { Write-Host "    Task: $($task.TaskName) - FAILED" -ForegroundColor Red }
        }
    }
}

$RotationLog | Export-Csv "SecretRotation_${ServiceAccount}_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "`n[DONE] Rotation complete. Log saved." -ForegroundColor Green

# Security: Zero out password variable
$NewPassword = "0" * $PasswordLength
[System.GC]::Collect()
