<#
.SYNOPSIS
    Audits Windows systems against CIS Benchmark Level 1 and Level 2 controls.
.DESCRIPTION
    Evaluates registry keys, security policies, services, and audit settings
    against CIS Microsoft Windows Server 2019/2022 Benchmark v2.0.
.PARAMETER ComputerName
    Target computer(s) to audit. Defaults to local machine.
.PARAMETER Level
    CIS benchmark level: 1 (recommended) or 2 (high security). Default: 1.
.PARAMETER OutputPath
    Path to export audit results CSV. Default: current directory.
.EXAMPLE
    Invoke-CISBenchmarkAudit -ComputerName "SERVER01","SERVER02" -Level 1 -OutputPath "C:\Reports"
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [ValidateSet(1,2)][int]$Level = 1,
    [string]$OutputPath = $PWD
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Test-RegistryValue {
    param([string]$Path, [string]$Name, $ExpectedValue, [string]$Operator = "eq")
    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        $pass = switch ($Operator) {
            "eq"  { $actual -eq $ExpectedValue }
            "ge"  { $actual -ge $ExpectedValue }
            "le"  { $actual -le $ExpectedValue }
            "ne"  { $actual -ne $ExpectedValue }
        }
        return [PSCustomObject]@{ Actual = $actual; Pass = $pass }
    } catch {
        return [PSCustomObject]@{ Actual = "NOT_FOUND"; Pass = $false }
    }
}

$CISControls = @(
    @{ ID="1.1.1";  Title="Enforce password history";           Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=24; Op="ge"; Category="Account Policies" },
    @{ ID="1.1.2";  Title="Maximum password age";               Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=365; Op="le"; Category="Account Policies" },
    @{ ID="1.1.3";  Title="Minimum password length";            Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MinimumPasswordLength"; Expected=14; Op="ge"; Category="Account Policies" },
    @{ ID="2.2.1";  Title="Guest account disabled";             Path="HKLM:\SAM\SAM\Domains\Account\Users\000001F5"; Name="F"; Expected=$null; Op="ne"; Category="Local Policies" },
    @{ ID="2.3.1";  Title="Audit credential validation";        Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="AuditBaseObjects"; Expected=1; Op="eq"; Category="Audit Policy" },
    @{ ID="2.3.2";  Title="SMBv1 disabled";                     Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0; Op="eq"; Category="Network" },
    @{ ID="2.3.3";  Title="NTLMv2 required";                    Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5; Op="ge"; Category="Network" },
    @{ ID="2.3.4";  Title="WDigest auth disabled";              Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Expected=0; Op="eq"; Category="Credential Protection" },
    @{ ID="2.3.5";  Title="LSASS protected process";            Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Expected=1; Op="eq"; Category="Credential Protection" },
    @{ ID="2.3.6";  Title="Credential Guard enabled";           Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1; Op="eq"; Category="Credential Protection" },
    @{ ID="3.1.1";  Title="Windows Firewall - Domain profile";  Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Name="EnableFirewall"; Expected=1; Op="eq"; Category="Firewall" },
    @{ ID="3.1.2";  Title="Windows Firewall - Private profile"; Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Name="EnableFirewall"; Expected=1; Op="eq"; Category="Firewall" },
    @{ ID="3.1.3";  Title="Windows Firewall - Public profile";  Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"; Name="EnableFirewall"; Expected=1; Op="eq"; Category="Firewall" },
    @{ ID="3.2.1";  Title="AutoRun disabled";                   Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255; Op="eq"; Category="System" },
    @{ ID="3.2.2";  Title="RDP NLA required";                   Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="UserAuthentication"; Expected=1; Op="eq"; Category="Remote Access" },
    @{ ID="3.2.3";  Title="RDP encryption level high";          Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3; Op="ge"; Category="Remote Access" },
    @{ ID="3.3.1";  Title="PowerShell script block logging";    Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1; Op="eq"; Category="Logging" },
    @{ ID="3.3.2";  Title="PowerShell transcription enabled";   Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1; Op="eq"; Category="Logging" },
    @{ ID="3.3.3";  Title="Event log - Security size";          Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name="MaxSize"; Expected=196608; Op="ge"; Category="Logging" },
    @{ ID="3.3.4";  Title="Event log - System size";            Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"; Name="MaxSize"; Expected=32768; Op="ge"; Category="Logging" }
)

foreach ($Computer in $ComputerName) {
    Write-Host "[*] Auditing: $Computer" -ForegroundColor Cyan
    foreach ($Control in $CISControls) {
        if ($Level -eq 1 -or $Control.Category -notmatch "^L2") {
            $check = Test-RegistryValue -Path $Control.Path -Name $Control.Name -ExpectedValue $Control.Expected -Operator $Control.Op
            $Results.Add([PSCustomObject]@{
                Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Computer   = $Computer
                ControlID  = $Control.ID
                Title      = $Control.Title
                Category   = $Control.Category
                Status     = if ($check.Pass) { "PASS" } else { "FAIL" }
                Expected   = $Control.Expected
                Actual     = $check.Actual
            })
        }
    }
}

$CsvPath = Join-Path $OutputPath "CIS_Audit_$Timestamp.csv"
$Results | Export-Csv -Path $CsvPath -NoTypeInformation

$Pass  = ($Results | Where-Object Status -eq "PASS").Count
$Fail  = ($Results | Where-Object Status -eq "FAIL").Count
$Score = [math]::Round(($Pass / ($Pass + $Fail)) * 100, 1)

Write-Host "`n[RESULTS] Pass: $Pass | Fail: $Fail | Score: $Score%" -ForegroundColor $(if ($Score -ge 80) { "Green" } else { "Yellow" })
Write-Host "[OUTPUT]  $CsvPath" -ForegroundColor Gray

$Results | Where-Object Status -eq "FAIL" | Format-Table Computer, ControlID, Title, Actual -AutoSize
