# Playbook — Cloud Account / Tenant Compromise (Entra ID, AWS)

| | |
|---|---|
| **Triggered by** | `rules/cloud/entra_mfa_disabled_or_removed.yml`, `rules/cloud/aws_cloudtrail_logging_disabled.yml`, provider abuse notification, unusual billing |
| **MITRE ATT&CK** | T1078.004 Valid Accounts: Cloud · T1556.006 MFA Modification · T1685.002 Disable or Modify Cloud Log · T1098 Account Manipulation · T1530 Data from Cloud Storage |
| **Severity** | High; Critical if a Global Admin / root / IAM admin is involved or logging was disabled |

## 1. Triage

- **Who** made the change, from **where** (IP, country, user agent), **how** (portal, CLI, API key, OAuth app)?
- Was MFA removed from a privileged account? Was a Conditional Access policy weakened? Was a trail/detector turned off?
- Is there a change ticket or pipeline run that explains it? If yes, verify with the requester, not just the ticket.

## 2. Containment

**Entra ID / Microsoft 365**
1. Revoke sessions and refresh tokens for the affected account; reset password; re-register MFA on a verified device.
2. Restore the Conditional Access policy from its last known-good definition; re-enable MFA methods.
3. Review and remove suspicious OAuth consents, app registrations, service principals and their credentials.
4. Check for new or modified Global Admins, partner (GDAP/DAP) relationships and federated domains.

**AWS**
1. Re-enable CloudTrail logging / GuardDuty; confirm the S3 log bucket is intact and locked.
2. Disable or rotate the access keys and session of the identity involved; apply a deny-all SCP/policy if it is an attacker-created principal.
3. Look for new IAM users, roles with trust to foreign accounts, access keys, and `AssumeRole` from unknown accounts.
4. If root was used: rotate root credentials and MFA, check billing contacts and alternate contacts.

## 3. Investigation

- Reconstruct the attacker's session: all operations by that identity in the window (audit log / CloudTrail), ordered.
- Data access: SharePoint/OneDrive downloads, mailbox access, S3 `GetObject` / `ListBucket` bursts, snapshot sharing, public bucket policies.
- Persistence: enterprise app grants, inbox rules, Lambda/EC2 instances, IAM roles, cross-account trusts, new API keys.
- Initial access vector: phishing / token theft (AiTM), leaked key in a repo, compromised CI/CD, over-privileged third-party app.

## 4. Eradication & hardening

- Remove all attacker persistence; rotate every secret the identity could read.
- Enforce phishing-resistant MFA for admins, block legacy auth, scope admin roles with PIM / just-in-time elevation.
- Enable alerts on: logging disabled, MFA removal, CA changes, new admins, root usage, key creation (this repo's rules).
- Secret scanning in repositories; short-lived credentials via OIDC for pipelines instead of static keys.

## Evidence checklist

- [ ] Audit log / CloudTrail export for the identity and window (immutable copy)
- [ ] Sign-in log with IP, device and user-agent details
- [ ] List of created/modified principals, apps, keys, policies
- [ ] Data-access evidence (what was read, downloaded, shared)
- [ ] Billing anomalies, if any
