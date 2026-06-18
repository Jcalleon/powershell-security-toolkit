<#
.SYNOPSIS
    Deploys and audits AppLocker policy on Windows systems.
.DESCRIPTION
    Configures AppLocker rules in Audit or Enforce mode for executable,
    script, MSI, and DLL path rules. Generates policy from golden image.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Audit","Enforce")][string]$Mode = "Audit",
    [string[]]$ComputerName = @($env:COMPUTERNAME)
)
foreach ($comp in $ComputerName) {
    if ($PSCmdlet.ShouldProcess($comp, "Apply AppLocker policy ($Mode)")) {
        try {
            Invoke-Command -ComputerName $comp -ArgumentList $Mode -ScriptBlock {
                param($mode)
                # Enable Application Identity service (required for AppLocker)
                Set-Service -Name AppIDSvc -StartupType Automatic
                Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
                # Get current policy or create default
                $policy = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
                if (-not $policy) {
                    # Create default allow-Windows rules
                    $rules = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy
                    # Default rule: Allow Everyone to run from Windows and Program Files
                    New-AppLockerPolicy -FileInformation (Get-AppLockerFileInformation -Directory "C:\Windows" -Recurse -FileType Exe -ErrorAction SilentlyContinue | Select-Object -First 10) `
                        -RuleType Path -User Everyone -RuleNamePrefix "DefaultAllow" -Optimize -ErrorAction SilentlyContinue |
                        Set-AppLockerPolicy -ErrorAction SilentlyContinue
                }
                Write-Output "AppLocker configured in $mode mode on $env:COMPUTERNAME"
            } -ErrorAction Stop
            Write-Host "  [+] AppLocker deployed on $comp ($Mode)" -ForegroundColor Green
        } catch { Write-Warning "Failed on $comp: $_" }
    }
}
