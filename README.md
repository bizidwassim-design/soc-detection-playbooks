# SOC Detection Rules & Playbooks

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/bizidwassim-design/soc-detection-playbooks/actions/workflows/ci.yml/badge.svg)](https://github.com/bizidwassim-design/soc-detection-playbooks/actions/workflows/ci.yml) [![No macros](https://img.shields.io/badge/office%20files-no%20macros-success)](SECURITY.md) [![Fictional data](https://img.shields.io/badge/sample%20data-fictional-informational)](SECURITY.md)

A free, open-source starter pack for a security operations team: **Sigma detection rules** for the
attacks that actually hit small and mid-sized organisations, paired with **investigation playbooks**
that tell an analyst what to check, in which tool, and what decision to make — all mapped to **MITRE ATT&CK**.

> 🇫🇷 Résumé en français en bas de page.

## Layout

```
rules/          Sigma rules, one folder per use case
  phishing/
  ransomware/
  credential_access/
  cloud/
  lateral_movement/
  persistence/
  discovery/
  command_and_control/
  exfiltration/
playbooks/      Markdown playbooks: triage → containment → investigation → recovery → evidence
docs/           MITRE ATT&CK mapping table and a ready-made Navigator layer
scripts/        attack_layer.py — rebuilds docs/attack-layer.json from the rule tags
```

## What's inside

| Use case | Rules | Playbook |
|----------|-------|----------|
| Phishing / BEC | Office app spawning a shell · Inbox rule forwarding mail externally (M365) | [phishing-business-email-compromise.md](playbooks/phishing-business-email-compromise.md) |
| Ransomware | Shadow-copy deletion · Mass file rename on a share | [ransomware.md](playbooks/ransomware.md) |
| Credential access | LSASS memory access · Password spraying | [credential-access.md](playbooks/credential-access.md) |
| Cloud | Entra ID MFA removed / Conditional Access weakened · AWS CloudTrail logging stopped | [cloud-account-compromise.md](playbooks/cloud-account-compromise.md) |
| Lateral movement & persistence | PsExec-style remote service · RDP fan-out · Scheduled task from temp path | [lateral-movement.md](playbooks/lateral-movement.md) |
| Discovery, C2 & exfiltration | AD enumeration from a workstation · PowerShell download cradle / encoded command · rclone / MEGA transfer tool | [data-exfiltration.md](playbooks/data-exfiltration.md) |

Full technique list: [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md).
Navigator layer: [docs/attack-layer.json](docs/attack-layer.json) (import at https://mitre-attack.github.io/attack-navigator/).

## Using the rules

Sigma is vendor-neutral. Convert a rule to your SIEM/EDR query language with
[`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) and the backend for your platform, for example:

```bash
pip install sigma-cli
sigma plugin install splunk            # or: microsoft365defender, elasticsearch, loki, ...
sigma convert -t splunk -p sysmon rules/ransomware/shadow_copy_deletion.yml
```

Validate rules before committing (the same check runs in CI on every push and pull request, together with a
conversion to the Splunk backend and a freshness check of the Navigator layer):

```bash
sigma check rules/
```

**Before deploying**, replace the placeholders marked in comments (`@yourcompany.example`, service-account names),
tune the thresholds of the three correlation rules (`condition: gte: N` in the password-spray, RDP fan-out and
mass-rename files) to your environment, and run each rule in audit mode for a week.

## Using the playbooks

Each playbook follows the same shape so an analyst under pressure knows where to look:

1. **Trigger & ATT&CK mapping** — which rule fired, which techniques are in play.
2. **Triage** — the questions to answer in the first 15 minutes, and where to find the data.
3. **Containment** — concrete, ordered actions.
4. **Investigation** — scoping, pivots and what "done" looks like.
5. **Eradication & hardening** — close the gap for good.
6. **Evidence checklist** — what to preserve.

Copy them into your knowledge base and adapt the tool names to your stack. Target times are suggestions, not SLAs.

## Good practices this pack follows

* One rule, one behaviour — no mega-rules.
* Every rule documents its `falsepositives` and a `level`; threshold detections are proper Sigma **correlation rules**
  (`value_count` over a base rule), not deprecated pipe aggregations.
* Tags follow the ATT&CK version bundled with pySigma (v20) so `sigma check` passes clean — see the mapping doc for the v15 equivalents.
* Logsource definitions use the standard Sigma taxonomy so backends map fields automatically.
* Detection content never contains real indicators from an incident, customer names or internal hostnames.

## Contributing

New rules, playbooks for uncovered techniques (see the "not yet covered" list in the mapping doc), false-positive
notes and translations are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please run `sigma check` and
`python scripts/attack_layer.py` before opening a pull request.

## Disclaimer

Detection content must be tested in your own environment. These rules will produce false positives until tuned,
and no rule set is complete. The playbooks are guidance, not legal or regulatory advice.

## License

[MIT](LICENSE).

---

## 🇫🇷 Résumé

Pack de démarrage open source pour un SOC : **14 règles de détection Sigma** (hameçonnage/BEC, rançongiciel, vol d'identifiants,
nuage Entra ID/AWS, déplacement latéral, persistance, reconnaissance, C2, exfiltration) validées en intégration continue et **playbooks d'investigation** en Markdown (triage, confinement,
investigation, rétablissement, preuves), le tout cartographié sur **MITRE ATT&CK** avec une couche Navigator prête à importer.
Convertissez les règles vers votre SIEM avec `sigma-cli`. Remplacez les valeurs d'exemple et ajustez les seuils avant déploiement. Licence MIT.
