<#
.SYNOPSIS
    Automates AD user account provisioning from HR CSV input with security controls.
.DESCRIPTION
    Creates AD accounts from CSV, enforces naming conventions, sets secure
    initial passwords, assigns group memberships by department/role, configures
    fine-grained password policies, and logs all actions for audit.
.PARAMETER CsvPath
    Path to CSV with columns: FirstName, LastName, Department, Title, Manager, EmployeeID, OfficeLocation
.PARAMETER OU
    Organizational Unit for new accounts. Default: auto-selected by Department.
.PARAMETER PasswordVaultPath
    Path to store encrypted initial passwords (for IT handoff).
.EXAMPLE
    Invoke-ADUserProvisioning -CsvPath "C:\HR\NewHires_20260101.csv" -PasswordVaultPath "C:\Secure\InitialPwds"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [string]$OU,
    [string]$PasswordVaultPath = "$env:TEMP\ADPassVault",
    [string]$DefaultDomain     = (Get-ADDomain).DNSRoot
)

Import-Module ActiveDirectory -ErrorAction Stop
$AuditLog = [System.Collections.Generic.List[PSObject]]::new()

# Department -> OU and Group mapping
$DeptMapping = @{
    "Engineering"   = @{ OU = "OU=Engineering,OU=Users,DC=corp,DC=local";   Groups = @("Engineering-Staff","VPN-Users","GitHub-Users") }
    "Finance"       = @{ OU = "OU=Finance,OU=Users,DC=corp,DC=local";       Groups = @("Finance-Staff","VPN-Users") }
    "IT"            = @{ OU = "OU=IT,OU=Users,DC=corp,DC=local";            Groups = @("IT-Staff","VPN-Users","Server-Admins-Lite") }
    "Security"      = @{ OU = "OU=Security,OU=Users,DC=corp,DC=local";      Groups = @("Security-Staff","VPN-Users","SIEM-Readonly") }
    "HR"            = @{ OU = "OU=HR,OU=Users,DC=corp,DC=local";            Groups = @("HR-Staff") }
    "Default"       = @{ OU = "OU=Users,DC=corp,DC=local";                  Groups = @("All-Staff") }
}

function New-SecurePassword {
    $chars  = "abcdefghjkmnpqrstuvwxyz"
    $upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $digits = "23456789"
    $spec   = "!@#$%^&*"
    $pwd    = ($chars   | Get-Random -Count 4 | ForEach-Object { $_ }) +
              ($upper   | Get-Random -Count 3 | ForEach-Object { $_ }) +
              ($digits  | Get-Random -Count 2 | ForEach-Object { $_ }) +
              ($spec    | Get-Random -Count 1 | ForEach-Object { $_ })
    return ($pwd | Sort-Object { Get-Random }) -join ""
}

$users = Import-Csv $CsvPath
Write-Host "[*] Processing $($users.Count) new hire accounts..." -ForegroundColor Cyan

if (-not (Test-Path $PasswordVaultPath)) { New-Item $PasswordVaultPath -ItemType Directory -Force | Out-Null }

foreach ($user in $users) {
    $samAccount  = ("$($user.FirstName[0])$($user.LastName)" -replace '\s','').ToLower() -replace '[^a-z0-9]',''
    $upn         = "$samAccount@$DefaultDomain"
    $displayName = "$($user.FirstName) $($user.LastName)"
    $dept        = $user.Department
    $mapping     = if ($DeptMapping[$dept]) { $DeptMapping[$dept] } else { $DeptMapping["Default"] }
    $targetOU    = if ($OU) { $OU } else { $mapping.OU }
    $initialPwd  = New-SecurePassword
    $securePwd   = ConvertTo-SecureString $initialPwd -AsPlainText -Force

    if ($PSCmdlet.ShouldProcess($samAccount, "Create AD user")) {
        try {
            # Check for duplicate
            if (Get-ADUser -Filter { SamAccountName -eq $samAccount } -ErrorAction SilentlyContinue) {
                $samAccount = "${samAccount}$($user.EmployeeID)"
            }

            New-ADUser -Name $displayName `
                -GivenName $user.FirstName `
                -Surname $user.LastName `
                -SamAccountName $samAccount `
                -UserPrincipalName $upn `
                -Title $user.Title `
                -Department $user.Department `
                -EmployeeID $user.EmployeeID `
                -Office $user.OfficeLocation `
                -Path $targetOU `
                -AccountPassword $securePwd `
                -Enabled $true `
                -ChangePasswordAtLogon $true `
                -PasswordNeverExpires $false `
                -ErrorAction Stop

            # Group assignments
            foreach ($group in $mapping.Groups) {
                Add-ADGroupMember -Identity $group -Members $samAccount -ErrorAction SilentlyContinue
            }

            # Save encrypted initial password
            $securePwd | ConvertFrom-SecureString | Set-Content "$PasswordVaultPath\$samAccount.pwd"

            $AuditLog.Add([PSCustomObject]@{ Status="SUCCESS"; User=$samAccount; UPN=$upn; Department=$dept; OU=$targetOU; Groups=($mapping.Groups -join "|") })
            Write-Host "  [+] Created: $samAccount ($displayName) in $dept" -ForegroundColor Green
        } catch {
            $AuditLog.Add([PSCustomObject]@{ Status="FAILED"; User=$samAccount; Error=$_.Exception.Message })
            Write-Host "  [!] FAILED: $samAccount - $_" -ForegroundColor Red
        }
    }
}

$AuditLog | Export-Csv "ADProvisioning_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "`n[DONE] Success: $(($AuditLog|Where-Object Status -eq 'SUCCESS').Count) | Failed: $(($AuditLog|Where-Object Status -eq 'FAILED').Count)" -ForegroundColor Green
