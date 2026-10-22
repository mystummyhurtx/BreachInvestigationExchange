# Run-MailRuleAudit.ps1
# Helpdesk wrapper: requires PowerShell 7, updates the Exchange Online module, signs in, runs the audit,
# then compares the IPs of flagged rule events to Entra sign-in logs.
$ErrorActionPreference = 'Stop'

# Device code sign-in (-Device) only exists in PowerShell 7. Switch to it if installed, otherwise tell the user to install it.
if ($PSVersionTable.PSEdition -ne 'Core') {
    if (Get-Command pwsh -ErrorAction SilentlyContinue) {
        Write-Host 'Switching to PowerShell 7...'
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
    Write-Host 'PowerShell 7 is required but is not installed.' -ForegroundColor Red
    Write-Host 'Install it with:  winget install --id Microsoft.PowerShell' -ForegroundColor Yellow
    Write-Host '(or download it from https://aka.ms/powershell), then run RunAudit.bat again.' -ForegroundColor Yellow
    exit 1
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Get-ChildItem $PSScriptRoot -File | Unblock-File
. "$PSScriptRoot\Common.ps1"

# --- Update package tooling (old NuGet/PowerShellGet is the usual cause of module install failures) ---
Write-Host 'Checking PowerShell package tooling...'
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
}
$psg = Get-Module -ListAvailable PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
if (-not $psg -or $psg.Version -lt [version]'2.2.5') {
    Install-Module PowerShellGet -Scope CurrentUser -Force -AllowClobber
    Write-Host 'PowerShellGet was updated. Close this window and run RunAudit.bat again.' -ForegroundColor Yellow
    exit 0
}

# --- Install or update the Exchange Online module ---
Install-RequiredModule ExchangeOnlineManagement

# --- Start clean in case an Exchange session is already open ---
try { Disconnect-ExchangeOnline -Confirm:$false } catch {}

# --- Sign in (isolated InPrivate Edge + device code, so no cached, personal or browser accounts are involved) ---
$ok = Invoke-PrivateSignIn {
    Connect-ExchangeOnline -Device -ShowBanner:$false
    Write-Host "Signed in as $((Get-ConnectionInformation | Select-Object -First 1).UserPrincipalName)." -ForegroundColor Green
}
if (-not $ok) { exit 1 }

# --- Run the audit ---
& "$PSScriptRoot\MailRuleActionsAudit.ps1"
try { Disconnect-ExchangeOnline -Confirm:$false } catch {}

# --- Compare flagged IPs to Entra sign-in logs ---
# Runs in its own process: the Exchange and Graph modules ship overlapping auth libraries and can conflict if loaded together.
$csv = 'C:\Temp\MailRuleActionsAudit.csv'
if ((Test-Path $csv) -and @(Import-Csv $csv | Where-Object Flag).Count -gt 0) {
    Write-Host "`nFlagged rule events found. Checking their IPs against Entra sign-in logs (second sign-in required)..." -ForegroundColor Cyan
    & pwsh -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\SignInIpCheck.ps1"
} else {
    Write-Host 'No flagged rule events, skipping the sign-in check.'
}

if (Test-Path $csv) { explorer.exe "/select,$csv" }
