# Playbook — Credential Access (dumping, spraying, theft)

| | |
|---|---|
| **Triggered by** | `rules/credential_access/lsass_memory_access.yml`, `rules/credential_access/password_spray_failed_logons.yml`, leaked-credential notification |
| **MITRE ATT&CK** | T1003.001 LSASS Memory · T1110.003 Password Spraying · T1110.004 Credential Stuffing · T1555 Credentials from Password Stores · T1558 Steal or Forge Kerberos Tickets |
| **Severity** | High; Critical if a privileged account is involved or a dump succeeded on a domain controller |

## 1. Triage

**For an LSASS-access alert**
- Which process read LSASS, from which path, signed by whom? Known security tool → tune and close. Unknown / unsigned / temp path → **treat as active intrusion**.
- Is the host a domain controller, jump host or server with many cached credentials? (Blast radius.)

**For a password-spray alert**
- Source IP: internal host or external? Known VPN egress? Tor/VPN provider?
- Did **any** attempt succeed (4624 / successful sign-in from the same source)? That changes everything.
- Which accounts were targeted — a generic list, or executives/admins?

## 2. Containment

- LSASS dump: **isolate the host**, disable the account that ran the process, and assume every credential ever used on that host is compromised.
- Spray from outside: block the source at the perimeter / identity provider, enable smart lockout, require MFA on affected accounts.
- Spray from inside: isolate the source host — it is likely already compromised.
- Any successful logon from the attacker source: reset that account immediately and revoke sessions and refresh tokens.

## 3. Investigation

- Which accounts had sessions on the dumped host (4624 history, cached credentials)? Prioritise privileged ones.
- Look for follow-on use: pass-the-hash / overpass-the-hash (4624 logon type 9, NTLM from unusual hosts), Kerberoasting (4769 with RC4), DCSync (4662 replication rights), new admin group members (4728/4732).
- Correlate the spray source with other telemetry: did the same IP touch VPN, OWA, cloud apps?
- Check whether a breached-credential list is in play (same password tried everywhere → stuffing, not spraying).

## 4. Eradication & hardening

- Reset affected credentials; if a DC or domain admin was involved, plan a full tiered reset including **KRBTGT (twice)**.
- Enable Credential Guard / LSA protection (`RunAsPPL`), remove local admin from users, deploy LAPS.
- Enforce MFA and conditional access for all remote access; block legacy authentication protocols.
- Deploy breached-password screening and a lockout/smart-lockout policy with alerting (this repo's rules).

## Evidence checklist

- [ ] Process tree and binary hash of the dumping process
- [ ] Memory image of the host if a dump is suspected
- [ ] Authentication logs (success and failure) for the window and source
- [ ] List of accounts exposed on the host
- [ ] Changes made to privileged groups, GPOs, service accounts
