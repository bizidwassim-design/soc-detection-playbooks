# Playbook — Discovery, Command & Control and Data Exfiltration

| | |
|---|---|
| **Triggered by** | `rules/discovery/ad_enumeration_from_workstation.yml`, `rules/command_and_control/powershell_download_cradle.yml`, `rules/exfiltration/cloud_sync_tool_execution.yml`, proxy/DLP alerts on large uploads |
| **MITRE ATT&CK** | T1087.002 Domain Account · T1482 Domain Trust Discovery · T1018 Remote System Discovery · T1105 Ingress Tool Transfer · T1059.001 PowerShell · T1567.002 Exfiltration to Cloud Storage · T1041 Exfiltration Over C2 Channel |
| **Severity** | Discovery: Medium (early warning) · Download cradle: High · Cloud sync tool: **High — treat as pre-ransomware** |
| **Target times** | Download cradle / exfil tool: isolate ≤ 15 min · Discovery: triage ≤ 1 h |

> These three rules describe the middle of an intrusion: the attacker is in, is learning the environment, pulling
> tooling and moving data out. Catching any one of them usually means encryption or extortion is hours away.

## 1. Triage

- **Discovery**: is the account an admin working from an admin host? If yes and the host is in the admin naming convention, close as expected. If a standard user or a non-admin workstation: escalate.
- **Download cradle**: what was the parent process (Office app, browser, script host, management agent)? What URL/host was contacted? Decode the `-EncodedCommand` payload (base64 → UTF-16LE) and read it.
- **Cloud sync tool**: who ran it, from which host, with which remote (`--config` file or remote name), and how much data left (proxy bytes out, EDR network events)? Is this account a sanctioned backup identity?
- Chain the events: discovery → credential access → lateral movement → tooling download → exfiltration. One host with two of these is an incident, not an alert.

## 2. Containment

1. Isolate the host at the EDR / switch port; do not power off.
2. Block the destination (cloud storage domain, attacker IP) at the proxy/firewall; revoke any API tokens found in the tool's config file.
3. Disable the account used; reset credentials of any admin account that authenticated to the host.
4. If a cloud transfer tool ran: **activate the ransomware playbook now** — protect backups, prepare to isolate file servers.

## 3. Investigation

- **What was taken**: reconstruct the file list from the tool's log or config (`rclone.conf`, MEGA cache), file-server access logs (4663), and proxy bytes-out per destination. Classify the data (personal data? regulated?) — this drives legal notifications.
- **Where it went**: destination service and account identifiers; preserve for law-enforcement requests.
- **How the tooling arrived**: the download cradle's URL, the dropped file hash, the initial-access vector (phishing document, exposed service).
- **Who else**: hunt fleet-wide for the same hashes, the same remote names, the same `-EncodedCommand` payload, and the discovery commands from other hosts.

## 4. Eradication & hardening

- Rebuild the host; rotate every credential it touched.
- **Egress control**: block unsanctioned cloud-storage categories at the proxy; alert on uploads above a daily baseline per host.
- **PowerShell hardening**: Constrained Language Mode for standard users, script-block logging (Event 4104), AMSI enabled, block `-EncodedCommand` for non-admin accounts via AppLocker/WDAC where feasible.
- **Discovery noise reduction**: admins work from dedicated admin workstations; standard users have no need for `net group /domain`.
- **DLP**: label and protect Confidential/Restricted data so bulk copies trigger alerts.

## 5. Legal and communication

- If personal or regulated data left the organisation, start the notification clock (e.g. 72 hours under GDPR) — legal decides, but the SOC provides the facts: what, how much, when, where to.
- Preserve evidence with chain of custody; extortion contact must be handled by executives and counsel, not the SOC.

## Evidence checklist

- [ ] EDR process tree for the discovery / cradle / transfer tool executions
- [ ] Decoded PowerShell payloads and downloaded binaries (hashes, samples)
- [ ] Transfer tool configuration and logs (remote names, tokens — redact in reports)
- [ ] Proxy / firewall logs with bytes out per destination for the window
- [ ] File-server access logs showing what was read
- [ ] Data classification of the exfiltrated set
- [ ] Timeline linking discovery → tooling → exfiltration
