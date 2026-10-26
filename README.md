# Exchange Online Mail Rule Audit

PowerShell tooling for finding malicious inbox rules in a Microsoft 365 / Exchange Online tenant, then tracing the IPs behind them through the Entra sign-in logs.

Attackers who compromise a mailbox commonly create hidden rules to conceal their activity: a rule named `.` that moves mail to *RSS Feeds* or *Conversation History*, or a rule that forwards mail to an external address. This toolkit does two things:

1. **Rule audit:** searches the unified audit log for inbox rule activity across the whole tenant and flags suspicious rules.
2. **Sign-in check:** takes the client IPs of the *flagged* rule events and looks them up in the Entra sign-in logs, showing every account that signed in from those IPs. This finds the real source of a breach (for example, a delegate account that was never edited) or confirms it was contained to the accounts you already know about.

## What's included

| File | Purpose |
|------|---------|
| `RunAudit.bat` | Double-click launcher. |
| `Run-MailRuleAudit.ps1` | Wrapper: updates prerequisites, signs in, runs the audit, then runs the sign-in check. |
| `MailRuleActionsAudit.ps1` | Tenant-wide audit log search. Outputs `MailRuleActionsAudit.csv`. |
| `SignInIpCheck.ps1` | Looks up flagged IPs in Entra sign-in logs. Outputs `FlaggedIpSignIns.csv`. |
| `Common.ps1` | Shared helpers (module install/update, private-window sign-in). Required by the scripts above. |

Keep all files in the same folder.

## Requirements

- **PowerShell 7** (`winget install --id Microsoft.PowerShell`). Device code sign-in is not available in Windows PowerShell 5.1. If `RunAudit.bat` is launched from 5.1 it switches to PowerShell 7 when installed and otherwise stops with install instructions.
- **Microsoft Edge** (used for the private sign-in window; the script tells the user to open one manually if Edge isn't found).
- An admin account with the **Audit Logs** or **View-Only Audit Logs** role (Exchange Administrator or Global Reader is typically sufficient). Unified audit logging must be enabled (on by default in most tenants).
- For the sign-in check: **Entra ID P1/P2** (required for sign-in logs) and a role that can read them (Global Reader, Security Reader, or Reports Reader).
- Internet access to the PowerShell Gallery. The wrapper installs or updates `ExchangeOnlineManagement` and `Microsoft.Graph.Authentication` for the current user (no local admin needed), and updates NuGet and PowerShellGet if they are outdated.

## Quick start

1. Extract the zip anywhere (do not run from inside the zip). Keep all files together.
2. Double-click `RunAudit.bat`.
3. A private Edge window opens and a device code appears in the PowerShell window. Enter the code in the Edge window and sign in with the admin account.
4. When the audit finishes, if any rule events were flagged, it asks for the client's **expected public IPs** (the office, VPN, and so on; one or more, each confirmed). Those IPs are skipped in the sign-in check. Then a **second sign-in** (new device code) is requested for the Graph check. If nothing was flagged, both steps are skipped.
5. Results open in Explorer. Files are written to `C:\Temp`:
   - `MailRuleActionsAudit.csv`
   - `FlaggedIpSignIns.csv` (only when flagged events exist)

### How sign-in works

Both sign-ins use device code flow in an InPrivate Edge window with a throwaway profile folder. The window shares nothing with the technician's normal browser, so cached or personal accounts are never offered, and the Windows account popup (with its "allow my organization to manage this device" prompt) is avoided. The throwaway profile is deleted afterward. If a tenant's Conditional Access policies block device code flow, sign-in will fail; use a different method for that tenant.

## Manual use

Connect to Exchange Online, then run the audit on its own:

```powershell
Connect-ExchangeOnline -Device
.\MailRuleActionsAudit.ps1                  # last 180 days
.\MailRuleActionsAudit.ps1 -Days 365        # if your audit retention allows it
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Days` | `180` | How far back to search. Anything beyond your retention is simply not returned. |
| `-Out` | `C:\Temp\MailRuleActionsAudit.csv` | CSV output path. |

Run the sign-in check on its own (it signs in to Graph itself):

```powershell
.\SignInIpCheck.ps1
.\SignInIpCheck.ps1 -In C:\Temp\MailRuleActionsAudit.csv -Out C:\Temp\FlaggedIpSignIns.csv -Days 30
.\SignInIpCheck.ps1 -ExcludeIp 203.0.113.10,203.0.113.11      # skip trusted IPs such as the office
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-ExcludeIp` | none | Trusted public IPs to skip. |
| `-MaxPerIp` | `1000` | Stop paging an IP after this many sign-ins. |
| `-Days` | `30` | Sign-in window (logs are kept 30 days). |

## Rule audit details

**Searches:** `New-InboxRule`, `Set-InboxRule`, `Remove-InboxRule`, `UpdateInboxRules`, `Set-Mailbox`, in 30-day windows (newest first). A warning is shown if a window reaches the 50,000-record session cap. All rule events are written to the CSV; `Flag` is blank when nothing matched, so you can still see rules that were created benign and modified later.

### What gets flagged

| Flag | Meaning |
|------|---------|
| `Name is '<x>'` | Rule name is one character or punctuation only (`.`, `..`, `/`, `//`, `-`, `_`). Blank names are not flagged (they can't be created), and Outlook placeholder stubs whose only action is `DeferAction` (for example a rule named `\|` left by an interrupted sync) are skipped. |
| `Forwards to: <addr> (EXTERNAL)` | Forward, redirect, or forward-as-attachment to an address outside the tenant's accepted domains. Forwards to internal addresses are not flagged. |
| `Moves to: <folder>` | Move to RSS Feeds, RSS Subscriptions, Conversation History, Archive, Notes, Sync Issues, or Clutter |
| `Deletes message` | Delete, soft delete, permanent delete, or move to Deleted Items |
| `Marks as read` | Only added when another flag also matched. Mark-as-read alone is common in legitimate rules and produced mostly false positives. |

`Set-Mailbox` events are kept only when they set forwarding to an external address. Accepted domains come from `Get-AcceptedDomain`, so tenants with multiple domains need no configuration.

Not flagged on purpose: sender/subject/body keywords, "stop processing more rules", "copy to folder", and "move to Junk". Users create these constantly and they generate mostly false positives. Rule names and actions are the strongest indicators.

### `MailRuleActionsAudit.csv` columns

| Column | Description |
|--------|-------------|
| `CreationDate` | Event time, converted to the local time zone of the machine running the script |
| `User` | Account that performed the action |
| `Operation` | Audit operation |
| `ClientIP` | Source IP of the change (may include a port) |
| `RuleName` | Rule name (falls back to the audit object ID) |
| `Flag` | Plain-text summary of everything suspicious, separated by `\|` |
| `Params` | Raw parameters recorded in the audit event |

## Sign-in check details

`SignInIpCheck.ps1` reads only the rows that have a `Flag` and a `ClientIP`. It strips ports and brackets (`194.0.213.65:41970` becomes `194.0.213.65`), then asks Microsoft Graph for sign-ins from each unique IP in the last 30 days. It queries both the default (interactive) sign-ins and non-interactive sign-ins, since token and session reuse often appears as non-interactive.

### Trusted and high-volume IPs

An office or VPN address has sign-ins from every user, so looking it up is slow and gets throttled. The wrapper asks for expected public IPs and skips them. As a safety net, any other IP that returns `-MaxPerIp` (default 1000) sign-ins is cut off and listed in yellow as high-volume; its results are incomplete. Graph throttles the sign-in logs heavily, so requests are paced and retried with waits, and any IP that still fails is listed in red as not fully checked (rerun later).

### `FlaggedIpSignIns.csv` columns

`Time`, `IP`, `User`, `UserInFlaggedRules`, `App`, `ClientApp`, `Resource`, `Result`, `Interactive`, `Location`, `Device`, `ConditionalAccess`, `Id`.

`UserInFlaggedRules` is `Yes` when the signed-in account also appears in the flagged rule events, and `No` when it doesn't. The console summary lists the `No` accounts: those signed in from a flagged IP but had no flagged rule event. **Check those first.** They are often the real entry point (for example, a delegate account with access to the affected mailboxes).

### Permissions and consent

The script connects to Microsoft Graph with the delegated scopes `AuditLog.Read.All` and `Directory.Read.All`. Both are read-only and both require admin consent. The sign-in logs API needs both, so the scope list can't be narrowed.

- On first use in a tenant, an admin must approve the *Microsoft Graph Command Line Tools* app. Consent for just that admin account is enough if the same admin runs the tool each time. Check "Consent on behalf of your organization" only if a lower-privileged account (such as Global Reader) will run it later.
- Consent creates an enterprise application and consent record in the tenant. To review or remove it: Entra → Enterprise applications → Microsoft Graph Command Line Tools.
- The script disconnects from Graph when finished and clears any existing session first.

## Reading the results

1. Filter `Flag` to non-blank in `MailRuleActionsAudit.csv`. Prioritize dot-style names, hidden-folder moves, external forwards, and rows with several flags.
2. Look at `FlaggedIpSignIns.csv`: which accounts signed in from the same IPs, from where, with what app, and whether it succeeded.
3. The same IP on rules for several accounts is a strong sign of one attacker. Quick pivot:

   ```powershell
   Import-Csv C:\Temp\MailRuleActionsAudit.csv |
     Where-Object Flag | Group-Object ClientIP | Sort-Object Count -Descending
   ```
4. Look for a `New-InboxRule` followed by a `Set-InboxRule` on the same user. A rule created innocuously and later modified to hide mail is a common pattern.
5. Confirm what a rule actually does with the mailbox check below.

## Checking a single mailbox

The audit log records only the parameters passed in each event, so it can miss a rule's actions. `Get-InboxRule` shows the rule's current definition, and `-IncludeHidden` reveals rules not visible in Outlook or OWA:

```powershell
Get-InboxRule -Mailbox user@domain.com -IncludeHidden |
  Format-List Name, Identity, Enabled, Priority, RuleIdentity, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder, Description
```

`Description` spells out every condition and action in plain English. Normal system rules on most mailboxes: `Junk E-mail Rule`, `Microsoft.Exchange.OOF.InternalSenders.Global`, `Microsoft.Exchange.OOF.AllExternalSenders.Global`.

## Limitations

- **Audit retention:** 180 days by default (longer with E5 or the audit add-on). Older events aren't available.
- **Sign-in log retention:** 30 days. If a rule was created earlier, the sign-in check can't see the matching sign-ins even though the rule audit can.
- **Incomplete audit detail:** Outlook-created rules (`UpdateInboxRules`) sometimes log no rule contents, and not every parameter is always recorded. A blank `Flag` does not prove a rule is clean. Use the mailbox check as the authority on what a rule does.
- **Auditing gaps:** mailboxes without auditing enabled, or where `AuditOwner` excludes rule operations, may not generate events.
- **IP matching only:** attackers can change IPs, and an IP with no sign-ins can be a Microsoft-side address or older than 30 days. Treat the sign-in check as a strong lead, not proof of containment.
- **Rules only:** the tool doesn't cover OAuth app consents, delegate grants, or compromises that don't involve rules.
- The non-interactive sign-in query uses the Graph beta endpoint, which Microsoft may change.
- Audit searches can occasionally return partial results on large tenants. If counts look low, rerun.

## If you find a compromised account

1. Remove the rule: `Remove-InboxRule -Mailbox user@domain.com -Identity <RuleIdentity>` (use `RuleIdentity` for odd or blank names).
2. Reset the password and **revoke all sessions** (a stolen token survives a password reset otherwise).
3. Review registered MFA methods and remove any you don't recognize.
4. Review OAuth app consents, mailbox forwarding (`Get-Mailbox user | fl ForwardingAddress, ForwardingSmtpAddress`), and delegates (`Get-MailboxPermission`, `Get-RecipientPermission`).
5. Review sent mail and message trace since the earliest suspicious event. Verify any payment or banking requests with the other party by phone.
6. Remediate every account that signed in from the attacker IPs, not only the ones with rules.

## Security notes

- The CSVs contain usernames, IP addresses, locations, and rule contents. Treat them as sensitive and delete them when the investigation is done.
- The Graph scopes are read-only, and the tool makes only read requests against the audit log, tenant configuration, and sign-in logs. Review changes to the scripts before use, since anyone editing them could request broader permissions.
- The wrapper runs `Unblock-File` on its folder, and the batch file starts PowerShell with `-ExecutionPolicy Bypass`, which applies to that process only.

## License

Add your license of choice here.
