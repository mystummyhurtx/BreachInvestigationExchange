# SignInIpCheck.ps1
# Looks up the client IPs of FLAGGED rule events (from MailRuleActionsAudit.csv) in the Entra sign-in logs.
# Shows every account that signed in from those IPs, which finds the real source of a breach or confirms it was contained.
# Prereq: Entra ID P1/P2 (sign-in logs) and a role such as Global Reader, Security Reader or Reports Reader.
# Usage:  .\SignInIpCheck.ps1 [-In C:\Temp\MailRuleActionsAudit.csv] [-Out C:\Temp\FlaggedIpSignIns.csv] [-Days 30]
# Sign-in logs are only kept 30 days, so older activity cannot be checked.
param(
    [string]$In  = 'C:\Temp\MailRuleActionsAudit.csv',
    [string]$Out = 'C:\Temp\FlaggedIpSignIns.csv',
    [int]$Days   = 30
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Common.ps1"

# Audit IPs can arrive as "1.2.3.4:5678" or "[2603:...]:5678"
function Get-CleanIp($ip) {
    $ip = "$ip".Trim()
    if ($ip -match '^\[(.+)\](:\d+)?$') { return $Matches[1] }
    if ($ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }
    $ip
}

$flagged = @(Import-Csv $In | Where-Object { $_.Flag -and $_.ClientIP })
$byIp = @($flagged | Group-Object -Property { Get-CleanIp $_.ClientIP } |
          Where-Object { [ipaddress]::TryParse($_.Name, [ref]$null) })
if (-not $byIp) { Write-Host 'No flagged events with a usable client IP. Nothing to check.'; return }

Install-RequiredModule Microsoft.Graph.Authentication
try { Disconnect-MgGraph | Out-Null } catch {}
$ok = Invoke-PrivateSignIn {
    Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -UseDeviceCode -NoWelcome
    Write-Host "Signed in to Graph as $((Get-MgContext).Account)." -ForegroundColor Green
}
if (-not $ok) { exit 1 }

$since = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hits = foreach ($g in $byIp) {
    $ip = $g.Name
    $ruleUsers = @($g.Group.User | Sort-Object -Unique)
    # Two passes: default (interactive) sign-ins, then non-interactive (token/session reuse, EWS, etc.)
    foreach ($extra in '', " and signInEventTypes/any(t: t eq 'nonInteractiveUser')") {
        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ipAddress eq '$ip' and createdDateTime ge $since$extra&`$top=500"
        try {
            while ($uri) {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
                foreach ($s in $resp.value) {
                    [pscustomobject]@{
                        Id                 = $s.id
                        Time               = ([datetime]$s.createdDateTime).ToLocalTime()
                        IP                 = $ip
                        User               = $s.userPrincipalName
                        UserInFlaggedRules = if ($ruleUsers -contains $s.userPrincipalName) { 'Yes' } else { 'No' }
                        App                = $s.appDisplayName
                        ClientApp          = $s.clientAppUsed
                        Resource           = $s.resourceDisplayName
                        Result             = if ($s.status.errorCode -eq 0) { 'Success' } else { "Fail $($s.status.errorCode)" }
                        Interactive        = $s.isInteractive
                        Location           = "$($s.location.city), $($s.location.countryOrRegion)"
                        Device             = "$($s.deviceDetail.operatingSystem) $($s.deviceDetail.browser)".Trim()
                        ConditionalAccess  = $s.conditionalAccessStatus
                    }
                }
                $uri = $resp.'@odata.nextLink'
            }
        } catch { Write-Warning "Sign-in query failed for $ip : $($_.Exception.Message)" }
    }
}
Disconnect-MgGraph | Out-Null

$rows = @($hits | Sort-Object Id -Unique | Sort-Object Time -Descending)
$rows | Export-Csv $Out -NoTypeInformation

Write-Host "`nChecked $($byIp.Count) flagged IP(s) against the last $Days days of sign-ins: $($rows.Count) sign-ins found. Saved to $Out"
foreach ($g in $byIp) {
    $r = @($rows | Where-Object IP -eq $g.Name)
    if ($r) {
        $users = $r | Group-Object User | ForEach-Object { "$($_.Name) ($($_.Count))" }
        Write-Host "  $($g.Name): $($r.Count) sign-ins | $($users -join ', ')"
    } else {
        Write-Host "  $($g.Name): no sign-ins found (older than $Days days, or not a user sign-in)"
    }
}
$others = @($rows | Where-Object UserInFlaggedRules -eq 'No' | Select-Object -ExpandProperty User -Unique)
if ($others) {
    Write-Host "`nAccounts that signed in from a flagged IP but had no flagged rule event (check these first):" -ForegroundColor Yellow
    $others | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}
