<#
.SYNOPSIS
    Disables Windows features and components not required in a hardened server role.
.DESCRIPTION
    Removes or disables: PowerShell v2, SMB 1.0, Telnet Client, TFTP Client,
    Windows Media Player, XPS Viewer, Internet Explorer, and other unneeded
    features per CIS and DISA STIG guidance.
.EXAMPLE
    Disable-UnneededWindowsFeatures -WhatIf
    Disable-UnneededWindowsFeatures
#>
[CmdletBinding(SupportsShouldProcess)]
param([string[]]$ComputerName = @($env:COMPUTERNAME))

$FeaturesToDisable = @(
    "MicrosoftWindowsPowerShellV2Root",
    "SMB1Protocol",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
    "TelnetClient",
    "TFTP",
    "WindowsMediaPlayer",
    "Xps-Foundation-Xps-Viewer",
    "WorkFolders-Client"
)

$WindowsCapabilitiesToRemove = @(
    "Browser.InternetExplorer~~~~0.0.11.0",
    "Microsoft.Windows.WordPad~~~~0.0.1.0"
)

foreach ($Computer in $ComputerName) {
    Write-Host "[*] Disabling unneeded features on: $Computer" -ForegroundColor Cyan
    $sb = {
        param($features, $caps)
        foreach ($f in $features) {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
            if ($feat -and $feat.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Output "Disabled feature: $f"
            }
        }
        foreach ($cap in $caps) {
            $c = Get-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue
            if ($c -and $c.State -eq "Installed") {
                Remove-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue | Out-Null
                Write-Output "Removed capability: $cap"
            }
        }
    }
    if ($PSCmdlet.ShouldProcess($Computer, "Disable unneeded features")) {
        if ($Computer -eq $env:COMPUTERNAME) { & $sb $FeaturesToDisable $WindowsCapabilitiesToRemove }
        else { Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList $FeaturesToDisable,$WindowsCapabilitiesToRemove }
    }
}
Write-Host "[DONE] Feature hardening complete." -ForegroundColor Green
