<#
.SYNOPSIS
    Creates and assigns Fine-Grained Password Policies (PSOs) for privileged accounts.
.DESCRIPTION
    Implements tiered password policies per CIS/NIST guidance:
    - Tier 1: Service accounts (long, complex, no expiry)
    - Tier 2: Admin accounts (max security, 90d rotation)
    - Tier 3: Standard users (NIST SP 800-63b compliant)
.EXAMPLE
    Set-ADFineGrainedPasswordPolicy
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Import-Module ActiveDirectory -ErrorAction Stop

$policies = @(
    @{
        Name            = "PSO-ServiceAccounts"
        Precedence      = 10
        MinLength       = 24
        Complexity      = $true
        ReversibleEncryption = $false
        MaxAge          = [TimeSpan]::Zero  # Never expires
        MinAge          = (New-TimeSpan -Days 0)
        History         = 24
        LockoutThreshold= 5
        LockoutWindow   = (New-TimeSpan -Minutes 30)
        LockoutDuration = (New-TimeSpan -Hours 0)  # Admin must unlock
        ApplyTo         = @("Service-Accounts")     # AD group
        Description     = "Tier 1: Service Accounts - Long password, no expiry, admin unlock"
    },
    @{
        Name            = "PSO-PrivilegedAdmins"
        Precedence      = 20
        MinLength       = 16
        Complexity      = $true
        ReversibleEncryption = $false
        MaxAge          = (New-TimeSpan -Days 90)
        MinAge          = (New-TimeSpan -Days 1)
        History         = 24
        LockoutThreshold= 5
        LockoutWindow   = (New-TimeSpan -Minutes 30)
        LockoutDuration = (New-TimeSpan -Hours 0)
        ApplyTo         = @("Domain Admins","Enterprise Admins","IT-Admins")
        Description     = "Tier 2: Privileged Admins - 90d rotation, admin unlock on lockout"
    },
    @{
        Name            = "PSO-StandardUsers"
        Precedence      = 50
        MinLength       = 12
        Complexity      = $true
        ReversibleEncryption = $false
        MaxAge          = (New-TimeSpan -Days 365)
        MinAge          = (New-TimeSpan -Days 1)
        History         = 10
        LockoutThreshold= 10
        LockoutWindow   = (New-TimeSpan -Minutes 15)
        LockoutDuration = (New-TimeSpan -Minutes 15)
        ApplyTo         = @("All-Staff")
        Description     = "Tier 3: Standard Users - NIST SP 800-63b aligned"
    }
)

foreach ($p in $policies) {
    if ($PSCmdlet.ShouldProcess($p.Name, "Create Fine-Grained Password Policy")) {
        try {
            $existing = Get-ADFineGrainedPasswordPolicy -Identity $p.Name -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "  [~] Updating existing PSO: $($p.Name)" -ForegroundColor Yellow
                Set-ADFineGrainedPasswordPolicy -Identity $p.Name `
                    -MinPasswordLength $p.MinLength -PasswordHistoryCount $p.History `
                    -ComplexityEnabled $p.Complexity -MaxPasswordAge $p.MaxAge `
                    -MinPasswordAge $p.MinAge -LockoutThreshold $p.LockoutThreshold `
                    -LockoutObservationWindow $p.LockoutWindow -LockoutDuration $p.LockoutDuration
            } else {
                New-ADFineGrainedPasswordPolicy -Name $p.Name `
                    -Precedence $p.Precedence -MinPasswordLength $p.MinLength `
                    -PasswordHistoryCount $p.History -ComplexityEnabled $p.Complexity `
                    -ReversibleEncryptionEnabled $p.ReversibleEncryption `
                    -MaxPasswordAge $p.MaxAge -MinPasswordAge $p.MinAge `
                    -LockoutThreshold $p.LockoutThreshold `
                    -LockoutObservationWindow $p.LockoutWindow -LockoutDuration $p.LockoutDuration `
                    -Description $p.Description
                Write-Host "  [+] Created PSO: $($p.Name) (Precedence: $($p.Precedence))" -ForegroundColor Green
            }

            foreach ($group in $p.ApplyTo) {
                Add-ADFineGrainedPasswordPolicySubject -Identity $p.Name -Subjects $group -ErrorAction SilentlyContinue
                Write-Host "      -> Applied to: $group" -ForegroundColor Gray
            }
        } catch { Write-Host "  [!] Failed: $($p.Name) - $_" -ForegroundColor Red }
    }
}

Write-Host "`n[DONE] Fine-grained password policies configured." -ForegroundColor Green
Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold -AutoSize
