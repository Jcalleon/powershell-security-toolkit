<#
.SYNOPSIS
    Set-ADUserOffboarding - Active Directory security automation script.
.DESCRIPTION
    Part of the enterprise AD security toolkit. See full documentation in README.md.
.EXAMPLE
    ./Set-ADUserOffboarding.ps1
#>
[CmdletBinding()]
param([string] = $PWD, [int] = 90)
Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "[*] Running Set-ADUserOffboarding..." -ForegroundColor Cyan
param([Parameter(Mandatory)][string]$Username, [string]$DisabledOU = "OU=Disabled,DC=corp,DC=local")
$user = Get-ADUser $Username -Properties * -ErrorAction Stop
# 1. Disable account
Disable-ADAccount -Identity $Username
# 2. Reset password to random
$randomPwd = [System.Web.Security.Membership]::GeneratePassword(32,8)
Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString $randomPwd -AsPlainText -Force) -Reset
# 3. Remove all group memberships (except Domain Users)
$user.MemberOf | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $Username -Confirm:$false -ErrorAction SilentlyContinue }
# 4. Move to disabled OU
Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU
# 5. Set description with offboarding date
Set-ADUser -Identity $Username -Description "OFFBOARDED: $(Get-Date -Format 'yyyy-MM-dd') by $env:USERNAME"
Write-Host "[DONE] $Username offboarded, disabled, moved to $DisabledOU" -ForegroundColor Green
