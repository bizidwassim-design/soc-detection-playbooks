# Playbook — Phishing & Business Email Compromise (BEC)

| | |
|---|---|
| **Triggered by** | `rules/phishing/m365_inbox_rule_forwarding_external.yml`, `rules/phishing/office_app_spawns_shell.yml`, user report |
| **MITRE ATT&CK** | T1566.001 Spearphishing Attachment · T1566.002 Spearphishing Link · T1114.003 Email Forwarding Rule · T1098.002 Additional Email Delegate Permissions · T1078.004 Valid Accounts: Cloud |
| **Severity guide** | High if credentials were entered or a rule/delegate was created; Critical if finance, HR or an executive mailbox is involved |
| **Target times** | Triage 15 min · Containment 1 h · Full scope 24 h |

## 1. Triage (first 15 minutes)

**Questions to answer**
- Who received it, who clicked, who entered credentials? (Reports often undercount — check telemetry.)
- Is the sender spoofed, look-alike, or a compromised legitimate partner?
- Does the message ask for a payment, bank-detail change, gift cards or credentials? (→ treat as BEC.)

**Tools / data**
- Mail gateway logs and quarantine; message trace in Microsoft 365 / Google Workspace.
- URL and attachment analysis in a sandbox (never open on a production host).
- Sign-in logs for the targeted users (new country, new device, impossible travel, legacy auth).

**Decision:** if any user *entered credentials* or the mailbox shows new rules, delegates, OAuth consents or unfamiliar sign-ins → go to **Containment** now.

## 2. Containment

1. **Reset the password and revoke sessions** of every affected account (`Revoke sign-in sessions` in Entra ID; re-register MFA if it may be compromised).
2. **Remove malicious artefacts** in the mailbox: inbox rules, forwarding (`ForwardingSmtpAddress`), delegates, "Send As" permissions, OAuth app consents.
3. **Purge the message** from all mailboxes (soft-delete + block sender / URL at the gateway).
4. Block the sender domain, URL and any indicators at the gateway, proxy and EDR.
5. If a payment was requested: **alert Finance immediately** — stop pending transfers and call the bank's fraud desk if money moved.

## 3. Investigation

- **Scope**: who else received the same message or hash? Search the gateway for the sender, subject, URL and attachment hash.
- **Mailbox audit**: `MailItemsAccessed`, `Send`, `SendAs`, `New-InboxRule`, `Set-Mailbox` events for the last 30 days on affected accounts.
- **Lateral use**: did the account authenticate to other apps (SharePoint downloads, Teams, VPN)? Check the unified audit log and the identity provider.
- **Endpoint**: if an attachment ran (`office_app_spawns_shell` fired), pivot to the **Malware / endpoint** steps: process tree, persistence, outbound connections, isolate the host.
- **Financial fraud**: collect the full email headers, invoice/bank details requested, and timeline — needed by the bank and law enforcement.

## 4. Eradication & recovery

- Confirm no residual rule, delegate, device registration or OAuth grant remains.
- Re-enable the account with MFA enforced; monitor it for 14 days.
- Apply the lesson: enable DMARC `p=reject`, external-sender tagging, Safe Links/attachment sandboxing, block legacy authentication, and alert on rule creation (this repo's rule).

## 5. Communication & closure

- Inform the affected user(s) without blame; brief Finance/HR if their process was targeted.
- Notify partners whose identity was spoofed; evaluate privacy-breach notification duties if mail content was accessed.
- Record: root cause, dwell time, data accessed, controls improved. Feed a detection-engineering ticket if a rule missed.

## Evidence checklist

- [ ] Original message (.eml with headers)
- [ ] Gateway trace and recipient list
- [ ] Sign-in and audit-log exports for affected accounts
- [ ] Mailbox rule/delegate/OAuth findings (before removal)
- [ ] Sandbox report for links/attachments
- [ ] Timeline of actions taken (who, what, when)
