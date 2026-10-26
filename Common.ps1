# Common.ps1 - shared helpers, dot-sourced by Run-MailRuleAudit.ps1 and SignInIpCheck.ps1

function Install-RequiredModule([string]$Name) {
    $installed = Get-Module -ListAvailable $Name | Sort-Object Version -Descending | Select-Object -First 1
    try {
        $latest = (Find-Module $Name).Version
        if (-not $installed -or $installed.Version -lt $latest) {
            Write-Host "Installing $Name $latest..."
            Install-Module $Name -Scope CurrentUser -Force -AllowClobber
        }
    } catch {
        if (-not $installed) { Write-Error "Could not install ${Name}: $($_.Exception.Message)" }
        Write-Warning "Could not check for $Name updates; using installed version $($installed.Version)."
    }
    Import-Module $Name
}

# Runs a sign-in scriptblock (device code) while an isolated InPrivate Edge window is open for entering the code.
# Returns $true on success, $false if the user gives up.
function Invoke-PrivateSignIn([scriptblock]$Connect) {
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1

    while ($true) {
        $profileDir = Join-Path $env:TEMP "MailRuleAudit-Edge-$([guid]::NewGuid())"   # throwaway browser profile, never shares a session
        $proc = $null
        try {
            if ($edge) {
                $proc = Start-Process $edge -PassThru -ArgumentList '--inprivate', '--no-first-run', "--user-data-dir=`"$profileDir`"", 'https://microsoft.com/devicelogin'
            } else {
                Write-Warning 'Edge not found. Open a private/incognito window yourself and go to https://microsoft.com/devicelogin'
            }
            Write-Host 'Type the code shown below into the browser window, then sign in with the desired admin account.' -ForegroundColor Cyan
            & $Connect | Out-Host   # Out-Host so any message the connect command emits (e.g. the device code) shows on screen instead of being swallowed into the return value
            return $true
        } catch {
            Write-Warning "Sign-in failed: $($_.Exception.Message)"
            Write-Warning 'If this mentions device code or Conditional Access, device code sign-in may be blocked in this tenant. Ask an engineer.'
            if ((Read-Host 'Try again? (Y/N)') -notmatch '^[Yy]') { return $false }
        } finally {
            if ($proc) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
            Start-Sleep -Seconds 2
            Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Asks for expected public IPs (office, VPN, ...) that the sign-in check should skip. Returns an array (empty if none).
function Read-TrustedIps {
    $ips = @(); $label = "the office's public IP"
    while ($true) {
        $ip = (Read-Host "What is $label? (press Enter to skip)").Trim()
        if (-not $ip) { break }
        $valid = [ipaddress]::TryParse($ip, [ref]$null) -and ($ip -match '^\d{1,3}(\.\d{1,3}){3}$' -or $ip.Contains(':'))
        if (-not $valid) { Write-Warning 'That is not a valid IP address (enter it without a port).'; continue }
        if ((Read-Host "Confirm $ip is correct (Y/N)") -notmatch '^[Yy]') { continue }
        $ips += $ip
        if ((Read-Host 'Any other expected public IPs (Y/N)') -notmatch '^[Yy]') { break }
        $label = 'the next expected public IP'
    }
    $ips
}
