#SingleMailboxRuleCheck.ps1
# Use case: Checking a user's mailbox in a confirmed or suspected breach scenario.
# Prereq: fully updated PowerShell, with ExchangeOnline module installed / loaded. Must be connected via Connect-ExchangeOnline prior to running. Designed to be used in VSCode, works in a regular powershell window as long as you connect to exchange online first because the command is one line.
# Action: This script will list all rules & actions for one particular mailbox, including hidden rules.
# Output: Results are output to the terminal of VSCode.
# Usage: Adjust "user@domain.com" below to the mailbox you need to check.

Get-InboxRule -Mailbox user@domain.com -IncludeHidden | Format-List Name, Identity, Enabled, Priority, RuleIdentity, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder, Description

#Once you review the user's rules, if you determine any to be malicious, delete them with this command:
#Remove-InboxRule -Mailbox user@domain.com -Identity "Rule Name OR ID"
#This can be copy pasted into the terminal below.