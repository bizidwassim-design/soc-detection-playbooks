# Playbook — Ransomware

| | |
|---|---|
| **Triggered by** | `rules/ransomware/shadow_copy_deletion.yml`, `rules/ransomware/mass_file_rename_extension.yml`, ransom note found, EDR detection |
| **MITRE ATT&CK** | T1486 Data Encrypted for Impact · T1490 Inhibit System Recovery · T1021 Remote Services · T1003 OS Credential Dumping · T1567 Exfiltration to Cloud Storage |
| **Severity** | **Critical by default** — speed matters more than certainty |
| **Target times** | Isolate first host ≤ 15 min · Declare incident ≤ 30 min · Scope ≤ 4 h |

> Modern ransomware is usually "double extortion": assume data was **stolen** before it was encrypted until proven otherwise.

## 1. Immediate actions (minutes)

1. **Isolate** the affected host(s) at the EDR or switch port — do **not** power off (memory holds keys and evidence).
2. **Disable the account(s)** performing the encryption / rename activity; reset domain admin and service-account credentials if any were in use on the host.
3. **Protect backups**: disconnect or lock backup repositories, verify an offline/immutable copy exists and is untouched.
4. **Declare a major incident**: open the bridge, name an incident lead, start the timeline log.
5. If encryption is spreading across shares: consider **isolating the file server / segment** rather than hunting host by host.

## 2. Triage questions

- Which strain? (note name, extension, tor URL — identify with a reputable ID service; never pay or contact from corporate mail.)
- First encrypted timestamp and first affected host → gives you the **patient zero** window.
- Which accounts were used? Domain admin? Service accounts?
- Which systems hold critical data and are they encrypted, exfiltrated, both, or safe?

## 3. Investigation

- **Initial access**: VPN/RDP exposed without MFA, phishing (see BEC playbook), unpatched edge device, supplier access.
- **Credential access & lateral movement**: look for `lsass` access, Mimikatz artefacts, PsExec/WMI/RDP fan-out (rules in `credential_access/` and `lateral_movement/`).
- **Precursors**: shadow-copy deletion, security tooling disabled, GPO changes, new scheduled tasks or services.
- **Exfiltration**: large outbound transfers to cloud storage (Mega, rclone, FTP), DNS tunnelling, hours before encryption.
- **Scope**: query EDR for the ransomware binary hash, the ransom note filename and the extension across the whole fleet.

## 4. Eradication & recovery

- Rebuild (do not "clean") compromised hosts from known-good images; patch the initial-access vector first.
- Reset **all** credentials, including KRBTGT twice, service accounts and local admin passwords (LAPS).
- Restore from backups verified to pre-date the intrusion; scan restored data before reconnecting.
- Bring systems back in business-priority order with monitoring heightened for 30 days.

## 5. Legal, communication, extortion

- Involve legal counsel and insurer early (cyber-insurance policies often mandate specific responders).
- Assess notification duties (personal data, regulators, customers, partners). Preserve evidence for law enforcement.
- Payment decisions are executive + legal decisions, informed by backups, sanctions screening and law-enforcement advice — never by the SOC alone.

## Evidence checklist

- [ ] Ransom note(s) and sample encrypted files (keep originals)
- [ ] Memory image and disk image of patient zero (if feasible)
- [ ] EDR timeline exports for affected hosts
- [ ] Authentication logs for the accounts used
- [ ] Network flow / proxy logs for exfiltration windows
- [ ] Backup integrity verification record
- [ ] Incident timeline with decisions and approvers
