# Run-MailRuleAudit.ps1
# Helpdesk wrapper: checks prerequisites, updates the Exchange Online module, signs in, runs the audit.
$ErrorActionPreference = 'Stop'

# Device code sign-in (private window) only exists in PowerShell 7, so switch to it if it is installed
if ($PSVersionTable.PSEdition -eq 'Desktop' -and (Get-Command pwsh -ErrorAction SilentlyContinue)) {
    Write-Host 'PowerShell 7 found, switching to it...'
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Get-ChildItem $PSScriptRoot -File | Unblock-File

# --- Prerequisites ---
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    Write-Error 'PowerShell 5.1 or newer is required. Install Windows Management Framework 5.1 (or PowerShell 7) and rerun.'
}
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $net = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
    if ($net -lt 461808) { Write-Error '.NET Framework 4.7.2 or newer is required. Install it through Windows Update and rerun.' }
}

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
$installed = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
try {
    $latest = (Find-Module ExchangeOnlineManagement).Version
    if (-not $installed -or $installed.Version -lt $latest) {
        Write-Host "Installing ExchangeOnlineManagement $latest..."
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
} catch {
    if (-not $installed) { Write-Error "Could not install ExchangeOnlineManagement: $($_.Exception.Message)" }
    Write-Warning "Could not check for module updates; using installed version $($installed.Version)."
}
Import-Module ExchangeOnlineManagement

# --- Start clean in case an Exchange session is already open ---
try { Disconnect-ExchangeOnline -Confirm:$false } catch {}

# --- Sign in ---
# PowerShell 7: isolated InPrivate Edge + device code (no cached, personal or browser accounts involved).
# Windows PowerShell 5.1 has no device code option, so it falls back to a normal browser sign-in.
$cmd        = Get-Command Connect-ExchangeOnline
$deviceFlow = $cmd.Parameters.ContainsKey('Device')
if (-not $deviceFlow) {
    Write-Warning 'Private-window sign-in needs PowerShell 7 (not installed). Using normal browser sign-in instead. Be careful to pick the correct admin account.'
}
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1

while ($true) {
    $upn = (Read-Host 'Admin UPN (e.g. admin@client.com)').Trim()
    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { Write-Warning 'That is not a valid email format.'; continue }
    if ((Read-Host "Sign in as $upn ? (Y/N)") -notmatch '^[Yy]') { continue }

    $profileDir = Join-Path $env:TEMP "MailRuleAudit-Edge-$([guid]::NewGuid())"   # throwaway browser profile, never shares a session
    $proc = $null
    try {
        if ($deviceFlow) {
            if ($edge) {
                $proc = Start-Process $edge -PassThru -ArgumentList '--inprivate', '--no-first-run', "--user-data-dir=`"$profileDir`"", 'https://microsoft.com/devicelogin'
            } else {
                Write-Warning 'Edge not found. Open a private/incognito window yourself and go to https://microsoft.com/devicelogin'
            }
            Write-Host "Type the code shown below into the browser window, then sign in as $upn." -ForegroundColor Cyan
            Connect-ExchangeOnline -Device -ShowBanner:$false
        } else {
            $conn = @{ UserPrincipalName = $upn; ShowBanner = $false }
            if ($cmd.Parameters.ContainsKey('DisableWAM')) { $conn.DisableWAM = $true }   # browser sign-in instead of the Windows account popup
            Connect-ExchangeOnline @conn
        }

        $who = (Get-ConnectionInformation | Select-Object -First 1).UserPrincipalName
        if ($who -ne $upn) {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Warning "Signed in as $who but expected $upn. Please try again."
            continue
        }
        break
    } catch {
        Write-Warning "Sign-in failed: $($_.Exception.Message)"
        if ($deviceFlow) { Write-Warning 'If this mentions device code or Conditional Access, device code sign-in may be blocked in this tenant. Ask an engineer.' }
        if ((Read-Host 'Try again? (Y/N)') -notmatch '^[Yy]') { exit 1 }
    } finally {
        if ($proc) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
        Start-Sleep -Seconds 2
        Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Run the audit ---
& "$PSScriptRoot\MailRuleActionsAudit.ps1"
Disconnect-ExchangeOnline -Confirm:$false
if (Test-Path 'C:\Temp\MailRuleActionsAudit.csv') { explorer.exe '/select,C:\Temp\MailRuleActionsAudit.csv' }
