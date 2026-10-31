# MITRE ATT&CK coverage

Mapping of every rule to ATT&CK (Enterprise matrix, **v20 identifiers** — the version bundled with pySigma, which is what `sigma check` validates tags against) and to the playbook that handles it.

> ATT&CK v20 split the former *Defense Evasion* tactic into **Defense Impairment** (TA0112) and **Stealth** (TA0005), and replaced *T1562 Impair Defenses* with **T1685 Disable or Modify Tools** (T1685.002 = cloud logs). If your SIEM content still uses v15 identifiers, map T1685 → T1562.001 and T1685.002 → T1562.008.

| Rule | Tactic | Technique | Playbook |
|------|--------|-----------|----------|
| `phishing/office_app_spawns_shell.yml` | Initial Access, Execution | T1566.001, T1204.002, T1059 | phishing-business-email-compromise |
| `phishing/m365_inbox_rule_forwarding_external.yml` | Collection, Persistence | T1114.003, T1098.002 | phishing-business-email-compromise |
| `ransomware/shadow_copy_deletion.yml` | Impact | T1490 | ransomware |
| `ransomware/mass_file_rename_extension.yml` | Impact | T1486 | ransomware |
| `credential_access/lsass_memory_access.yml` | Credential Access | T1003.001 | credential-access |
| `credential_access/password_spray_failed_logons.yml` | Credential Access | T1110.003 | credential-access |
| `cloud/entra_mfa_disabled_or_removed.yml` | Defense Impairment, Persistence | T1685, T1556.006 | cloud-account-compromise |
| `cloud/aws_cloudtrail_logging_disabled.yml` | Defense Impairment | T1685.002 | cloud-account-compromise |
| `lateral_movement/psexec_remote_service_creation.yml` | Lateral Movement, Execution | T1021.002, T1569.002 | lateral-movement |
| `lateral_movement/rdp_from_workstation_to_many_hosts.yml` | Lateral Movement | T1021.001 | lateral-movement |
| `persistence/scheduled_task_from_temp_path.yml` | Persistence | T1053.005 | lateral-movement |
| `discovery/ad_enumeration_from_workstation.yml` | Discovery | T1087.002, T1482, T1018 | data-exfiltration |
| `command_and_control/powershell_download_cradle.yml` | Command and Control, Execution | T1105, T1059.001 | data-exfiltration |
| `exfiltration/cloud_sync_tool_execution.yml` | Exfiltration | T1567.002 | data-exfiltration |

## Coverage by tactic

| Tactic | Techniques covered |
|--------|--------------------|
| Initial Access | T1566.001 |
| Execution | T1204.002, T1059, T1059.001, T1569.002 |
| Persistence | T1098.002, T1556.006, T1053.005 |
| Defense Impairment | T1685, T1685.002 |
| Credential Access | T1003.001, T1110.003 |
| Discovery | T1087.002, T1482, T1018 |
| Lateral Movement | T1021.001, T1021.002 |
| Collection | T1114.003 |
| Command and Control | T1105 |
| Exfiltration | T1567.002 |
| Impact | T1486, T1490 |

Every ATT&CK tactic in a typical ransomware kill chain now has at least one rule. Not yet covered (good first
contributions): Privilege Escalation (T1068, T1548), Command and Control over web protocols / tunnelling (T1071.001, T1572),
exfiltration over alternative protocols (T1048), Linux and macOS log sources.

## Threshold rules are Sigma correlation rules

`password_spray_failed_logons.yml`, `rdp_from_workstation_to_many_hosts.yml` and `mass_file_rename_extension.yml` each contain
two YAML documents: a noisy **base rule** (`level: informational`, with a `name`) and a **correlation rule** of type `value_count`
that references it with `group-by`, `timespan` and a `condition` threshold. Only the correlation rule should raise an alert.
Backends that support correlations (Splunk, Elasticsearch ES|QL, Loki, …) convert them with `sigma convert` as usual.

## Importing into ATT&CK Navigator

Generate a layer with the tag list above, or use `scripts/attack_layer.py` to build `docs/attack-layer.json` from the rule tags automatically.
