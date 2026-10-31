# Contributing

Detection content gets better with more eyes. Welcome contributions:

* new Sigma rules (especially for techniques listed as "not yet covered" in `docs/mitre-attack-mapping.md`);
* false-positive notes and tuning advice from real deployments;
* playbook improvements and translations;
* corrections to ATT&CK mappings.

## Rules

1. One behaviour per rule. Put it in the matching `rules/<use-case>/` folder (create a new folder if needed).
2. Follow the Sigma specification: unique UUID in `id`, `status`, `description`, `references`, `tags` with
   `attack.<tactic>` (hyphenated, e.g. `attack.credential-access`) and `attack.t####(.###)` using the ATT&CK version
   pySigma bundles, a standard `logsource`, `falsepositives`, `level`.
   Threshold logic ("more than N in M minutes") goes in a Sigma correlation rule, not a `| count()` pipe.
3. Use placeholders (`@yourcompany.example`, `svc-example`) — never real domains, hostnames, accounts or IOCs from an incident.
4. Validate: `pip install sigma-cli && sigma check rules/`.
5. Regenerate the Navigator layer: `python scripts/attack_layer.py`, and add the rule to `docs/mitre-attack-mapping.md`.

## Playbooks

Keep the common structure (trigger/mapping → triage → containment → investigation → eradication → evidence).
Prefer concrete questions and actions over theory. Name tools generically where possible ("identity provider", "EDR").

## Ground rules

* No real indicators, customer data or internal details. Fictional examples only.
* Respect the [Code of Conduct](CODE_OF_CONDUCT.md).
* By contributing you agree your work is released under the [MIT License](LICENSE).
