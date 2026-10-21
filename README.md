# Exchange Online Mail Rule Audit

PowerShell tooling for finding malicious inbox rules in a Microsoft 365 / Exchange Online tenant.

Attackers who compromise a mailbox commonly create hidden rules to conceal their activity: a rule named `.` that marks mail as read and moves it to *RSS Feeds* or *Conversation History*, or a rule that forwards mail to an external address. This toolkit searches the unified audit log for rule activity across the whole tenant, flags the suspicious patterns, and gives you client IPs to pivot on to find other affected accounts.

## What's included

| File | Purpose |
|------|---------|
| `MailRuleActionsAudit.ps1` | Tenant-wide audit log search. Outputs a CSV with a `Flag` column. |
| `Run-MailRuleAudit.ps1` | Helpdesk wrapper: installs the module, signs in with a prompted admin UPN, runs the audit, disconnects. |
| `RunAudit.bat` | Double-click launcher for the wrapper. |
| `Get-InboxRule` one-liner (below) | Inspect a single mailbox's rules, including hidden ones. |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) module (the wrapper installs it for the current user if missing)
- An account with the **Audit Logs** or **View-Only Audit Logs** role (Exchange admin or Global Reader is typically sufficient)
- Unified audit logging enabled (on by default in most tenants)
- Internet access to the PowerShell Gallery (wrapper only)

## Quick start (helpdesk)

1. Extract the folder anywhere. Keep all three files together.
2. Double-click `RunAudit.bat`.
3. Enter the admin UPN when prompted and sign in.
4. When it finishes, open `C:\Temp\MailRuleActionsAudit.csv`.

The wrapper disconnects any existing Exchange Online session before it starts, so it won't run against a tenant you were previously connected to.

## Manual use

Connect first, then run the audit:

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@domain.com
.\MailRuleActionsAudit.ps1              # last 180 days
.\MailRuleActionsAudit.ps1 -Days 365    # if your audit retention allows it
.\MailRuleActionsAudit.ps1 -Out D:\Reports\rules.csv
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Days` | `180` | How far back to search. Anything beyond your retention is simply not returned. |
| `-Out` | `C:\Temp\MailRuleActionsAudit.csv` | CSV output path. |

## What it searches

Audit operations: `New-InboxRule`, `Set-InboxRule`, `Remove-InboxRule`, `UpdateInboxRules`, `Set-Mailbox`.

The search runs in 30-day windows, newest first, and warns if a window reaches the 50,000-record session cap. All rule events are written to the CSV. Rules that don't match a flag still appear, with a blank `Flag`, so you can see rules that were created benign and later modified.

## What gets flagged

| Flag | Meaning |
|------|---------|
| `Name is '<x>'` | Rule name is blank, one character, or punctuation only (`.`, `..`, `/`, `//`, `-`, `_`) |
| `Forwards to: <addr> (EXTERNAL)` | Forward, redirect, or forward-as-attachment rule. Marked EXTERNAL when the target domain is not one of the tenant's accepted domains. |
| `Moves to: <folder>` | Move to RSS Feeds, RSS Subscriptions, Conversation History, Archive, Notes, Sync Issues, or Clutter |
| `Deletes message` | Delete, soft delete, permanent delete, or move to Deleted Items |
| `Marks as read` | Rule marks matching mail as read |

`Set-Mailbox` events are kept only when they set forwarding to an external address.

Internal domains come from `Get-AcceptedDomain`, so tenants with multiple domains need no configuration.

### Deliberately not flagged

Subject/sender keywords, "stop processing more rules", "copy to folder", and "move to Junk" are not flagged. Users create these constantly for legitimate organization and they produce mostly false positives. Actions and rule names are the strongest indicators of compromise.

## CSV columns

| Column | Description |
|--------|-------------|
| `CreationDate` | Event time, **in UTC** |
| `User` | Account that performed the action |
| `Operation` | Audit operation |
| `ClientIP` | Source IP of the change |
| `RuleName` | Rule name (falls back to the audit object ID if unavailable) |
| `Flag` | Plain-text summary of everything suspicious, separated by `\|`. Blank if nothing matched. |
| `Params` | Raw parameters recorded in the audit event |

## Reading the results

1. Filter `Flag` to non-blank. Prioritize rows with multiple flags, dot-style names, or a hidden-folder move.
2. Pivot on `ClientIP`. The same IP creating rules on several accounts is a strong sign of one attacker:

   ```powershell
   Import-Csv C:\Temp\MailRuleActionsAudit.csv |
     Where-Object Flag | Group-Object ClientIP | Sort-Object Count -Descending
   ```
3. Look for a `New-InboxRule` followed by a `Set-InboxRule` on the same user. A rule created innocuously and then modified to hide mail is a common pattern.
4. Search the audit log for the suspicious IP across all activity:

   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-180) -EndDate (Get-Date) `
     -IPAddresses "x.x.x.x" -ResultSize 5000 | Group-Object UserIds | Sort-Object Count -Descending
   ```
5. Confirm what a rule actually does with the mailbox check below.

## Checking a single mailbox

The audit log records only the parameters passed in each event, so it can miss a rule's actions. `Get-InboxRule` shows the rule's current stored definition, and `-IncludeHidden` reveals rules not visible in Outlook or OWA:

```powershell
Get-InboxRule -Mailbox user@domain.com -IncludeHidden |
  Format-List Name, Identity, Enabled, Priority, RuleIdentity, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder, Description
```

`Description` spells out every condition and action in plain English. Normal system rules you'll see on most mailboxes: `Junk E-mail Rule`, `Microsoft.Exchange.OOF.InternalSenders.Global`, `Microsoft.Exchange.OOF.AllExternalSenders.Global`.

## Limitations

- **Retention:** the audit log defaults to 180 days (longer with E5 or the audit add-on). Older events are not available.
- **Incomplete audit detail:** Outlook-created rules (`UpdateInboxRules`) sometimes log no rule contents, and not every parameter is always recorded. A blank `Flag` does not prove a rule is clean. Use the mailbox check as the authority on what a rule does.
- **Auditing gaps:** mailboxes without auditing enabled, or where `AuditOwner` excludes rule operations, may not generate events.
- **Rules only:** this does not cover OAuth app consents, delegate permissions, or compromises that don't involve rules.
- **Marks as read** is the noisiest flag. Many legitimate rules use it.
- Audit searches can occasionally return partial results on large tenants. If counts look low, rerun.

## If you find a compromised account

1. Remove the rule: `Remove-InboxRule -Mailbox user@domain.com -Identity <RuleIdentity>` (use `RuleIdentity` for odd or blank names).
2. Reset the password and **revoke all sessions** (a stolen token survives a password reset otherwise).
3. Review registered MFA methods and remove any you don't recognize.
4. Review OAuth app consents, mailbox forwarding (`Get-Mailbox user | fl ForwardingAddress, ForwardingSmtpAddress`), and delegates.
5. Review sent mail and message trace since the earliest suspicious event. Verify any payment or banking requests with the other party by phone.
6. Hunt the attacker IP across the tenant (see above) and remediate every account it touched.

## Security notes

- The CSV contains usernames, IP addresses, and rule contents. Treat it as sensitive and delete it when the investigation is done.
- Review the scripts before running them in a client tenant. They make read-only queries against the audit log and tenant configuration.
- The wrapper runs `Unblock-File` on its own folder and the batch file launches PowerShell with `-ExecutionPolicy Bypass`, which only applies to that process.

## License

Add your license of choice here.
