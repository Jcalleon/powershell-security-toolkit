<#
.SYNOPSIS
    Disables legacy and insecure network protocols across Windows systems.
.DESCRIPTION
    Disables SMBv1, LLMNR, NetBIOS over TCP/IP, WPAD, weak TLS/SSL,
    and RC4/DES cipher suites per CIS and STIG guidance.
.PARAMETER TargetComputer
    Remote computer(s) to harden. Omit for local execution.
.EXAMPLE
    Disable-LegacyProtocols
    Disable-LegacyProtocols -TargetComputer "SRV01","SRV02"
#>
[CmdletBinding(SupportsShouldProcess)]
param([string[]]$TargetComputer)

function Apply-Hardening {
    # SMBv1
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Type DWord
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue

    # LLMNR
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $llmnrPath)) { New-Item $llmnrPath -Force | Out-Null }
    Set-ItemProperty $llmnrPath -Name EnableMulticast -Value 0 -Type DWord

    # NetBIOS over TCP/IP (disable on all adapters)
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "TcpipNetbiosOptions IS NOT NULL"
    foreach ($a in $adapters) { $a.SetTcpipNetbios(2) | Out-Null }

    # WPAD
    $wpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
    if (-not (Test-Path $wpadPath)) { New-Item $wpadPath -Force | Out-Null }
    Set-ItemProperty $wpadPath -Name WpadOverride -Value 1 -Type DWord

    # Disable SSL 2.0
    $ssl2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
    New-Item $ssl2 -Force | Out-Null
    Set-ItemProperty $ssl2 -Name Enabled -Value 0 -Type DWord

    # Disable SSL 3.0
    $ssl3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    New-Item $ssl3 -Force | Out-Null
    Set-ItemProperty $ssl3 -Name Enabled -Value 0 -Type DWord

    # Disable TLS 1.0
    $tls10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
    New-Item $tls10 -Force | Out-Null
    Set-ItemProperty $tls10 -Name Enabled -Value 0 -Type DWord

    # Disable TLS 1.1
    $tls11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    New-Item $tls11 -Force | Out-Null
    Set-ItemProperty $tls11 -Name Enabled -Value 0 -Type DWord

    # Enable TLS 1.2 and 1.3
    foreach ($ver in @("TLS 1.2","TLS 1.3")) {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server"
        New-Item $p -Force | Out-Null
        Set-ItemProperty $p -Name Enabled -Value 1 -Type DWord
        Set-ItemProperty $p -Name DisabledByDefault -Value 0 -Type DWord
    }

    # Disable weak ciphers
    foreach ($cipher in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128","DES 56/56","NULL")) {
        $cp = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        New-Item $cp -Force | Out-Null
        Set-ItemProperty $cp -Name Enabled -Value 0 -Type DWord
    }

    Write-Host "[+] Legacy protocol hardening complete" -ForegroundColor Green
}

if ($TargetComputer) {
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock ${function:Apply-Hardening}
} else {
    Apply-Hardening
}
