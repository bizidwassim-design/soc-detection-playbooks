# Playbook — Lateral Movement

| | |
|---|---|
| **Triggered by** | `rules/lateral_movement/psexec_remote_service_creation.yml`, `rules/lateral_movement/rdp_from_workstation_to_many_hosts.yml`, `rules/persistence/scheduled_task_from_temp_path.yml` |
| **MITRE ATT&CK** | T1021.001 RDP · T1021.002 SMB/Admin Shares · T1569.002 Service Execution · T1047 WMI · T1053.005 Scheduled Task · T1550 Use Alternate Authentication Material |
| **Severity** | High — lateral movement means the attacker already has a foothold and credentials |

## 1. Triage

- Is the source a **workstation** or a jump/admin host? Workstation-to-server admin activity is a red flag.
- Is the account a named admin, a user account with unexpected admin rights, or a service account used interactively?
- Does the pattern match a tool (PsExec, WMI, WinRM, RDP) and a time (outside business hours)?
- Was there a credential-access alert on the source host earlier? (Chain the events.)

## 2. Containment

1. Isolate the **source** host first — it holds the attacker's tooling and credentials.
2. Disable the account used; reset its credentials and any admin accounts that logged on to the source host.
3. Isolate destination hosts where a service, task or new binary was created.
4. Block SMB/RDP/WinRM from workstations to servers at the firewall/EDR policy if the spread is active.

## 3. Investigation

- Build the hop graph: for each 4624 (types 3/10) and 7045 / 4698 event, record source → destination → account → time.
- On each destination: new services, scheduled tasks, dropped binaries in `ADMIN$`/`Temp`, WMI subscriptions, registry run keys.
- Identify the objective: domain controller access, file servers (staging for exfiltration), backup servers (precursor to ransomware).
- Find the origin: the first host in the chain and how it was compromised (phishing, exposed service, supplier).

## 4. Eradication & hardening

- Remove artefacts from every destination; rebuild hosts where unsigned tooling ran.
- Tiered administration: admins log on to servers only from hardened admin workstations; no workstation-to-server admin SMB/RDP.
- Enable Windows Firewall rules blocking inbound SMB/RDP between workstations; require RDP through a gateway with MFA.
- LAPS for local admin passwords; Credential Guard; disable NTLM where possible.

## Evidence checklist

- [ ] Hop graph (source/destination/account/time)
- [ ] Service / task creation events and binaries (hashes)
- [ ] Authentication logs across involved hosts
- [ ] EDR process trees on source and destinations
- [ ] Origin-host analysis
