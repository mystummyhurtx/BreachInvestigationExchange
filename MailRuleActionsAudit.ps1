# MailRuleActionsAudit.ps1
# Prereq: already connected via Connect-ExchangeOnline (needs Audit Logs / View-Only Audit Logs role).
# Usage:  .\MailRuleActionsAudit.ps1            (180 days)
#         .\MailRuleActionsAudit.ps1 -Days 365  (if your audit retention allows)
# Output: C:\Temp\MailRuleActionsAudit.csv. Check the Flag column; blank means nothing suspicious matched.
param([int]$Days = 180, [string]$Out = 'C:\Temp\MailRuleActionsAudit.csv')

New-Item -ItemType Directory -Path (Split-Path $Out) -Force | Out-Null
$ops      = 'New-InboxRule','Set-InboxRule','Remove-InboxRule','UpdateInboxRules','Set-Mailbox'
$internal = (Get-AcceptedDomain).DomainName
$end      = Get-Date
$rows     = @()

for ($off = 0; $off -lt $Days; $off += 30) {          # newest 30-day window first
    $wEnd   = $end.AddDays(-$off)
    $wStart = $end.AddDays(-[Math]::Min($off + 30, $Days))
    $sid = [guid]::NewGuid().ToString(); $got = @()
    do {
        $b = Search-UnifiedAuditLog -StartDate $wStart -EndDate $wEnd -Operations $ops `
             -ResultSize 5000 -SessionId $sid -SessionCommand ReturnLargeSet
        $got += $b
    } while ($b)
    if ($got.Count -ge 50000) { Write-Warning "50,000 cap hit for $wStart to $wEnd. Rerun with smaller windows." }

    foreach ($r in ($got | Sort-Object Identity -Unique)) {
        $d   = $r.AuditData | ConvertFrom-Json
        $p   = @($d.Parameters) + @($d.OperationProperties) | Where-Object { $_ }
        $txt = ($p | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        $isMbx = $r.Operations -eq 'Set-Mailbox'
        $name  = ($p | Where-Object { $_.Name -in 'Name','RuleName' } | Select-Object -First 1).Value
        if (-not $name) { $name = $d.ObjectId }

        $f = @(); $external = $false

        if (-not $isMbx -and $name -match '^[\W_]*$|^.$') { $f += "Name is '$name'" }

        foreach ($m in [regex]::Matches($txt, '(ForwardTo|ForwardAsAttachmentTo|RedirectTo|ForwardingSmtpAddress|ForwardingAddress)=([^;]+)')) {
            $dom = [regex]::Match($m.Groups[2].Value, '@([\w.-]+)').Groups[1].Value
            $ext = $dom -and ($internal -notcontains $dom)
            if ($ext) { $external = $true }
            $f += "Forwards to: $($m.Groups[2].Value.Trim())" + $(if ($ext) { ' (EXTERNAL)' })
        }

        if ($isMbx -and -not $external) { continue }   # Set-Mailbox only matters for external forwarding

        if ($txt -match 'MoveToFolder=[^;]*?(RSS Feeds|RSS Subscriptions|Conversation History|Archive|Notes|Sync Issues|Clutter)') { $f += "Moves to: $($Matches[1])" }
        if ($txt -match '(DeleteMessage|SoftDeleteMessage|PermanentDelete|MoveToDeletedItems)=True') { $f += 'Deletes message' }
        if ($f.Count -and $txt -match 'MarkAsRead=True') { $f += 'Marks as read' }   # only flagged alongside another flag (alone it is usually benign)

        $rows += [pscustomobject]@{
            CreationDate = $r.CreationDate.ToLocalTime()
            User         = $r.UserIds
            Operation    = $r.Operations
            ClientIP     = if ($d.ClientIPAddress) { $d.ClientIPAddress } else { $d.ClientIP }
            RuleName     = $name
            Flag         = $f -join ' | '
            Params       = $txt
        }
    }
}

$rows | Sort-Object CreationDate -Descending | Export-Csv $Out -NoTypeInformation
Write-Host "Done: $($rows.Count) events, $(@($rows | Where-Object Flag).Count) flagged. Saved to $Out"
