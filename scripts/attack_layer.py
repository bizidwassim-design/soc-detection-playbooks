#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer (docs/attack-layer.json) from the technique tags of every Sigma rule.

Usage:  pip install pyyaml && python scripts/attack_layer.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
OUT = ROOT / "docs" / "attack-layer.json"

techniques: dict[str, list[str]] = {}
for path in sorted(RULES.rglob("*.yml")):
    seen: set[str] = set()
    # A file may hold several documents (base rule + correlation rule); count each technique once per file.
    for rule in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        for tag in (rule or {}).get("tags", []):
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                techniques.setdefault(m.group(1).upper(), []).append(path.relative_to(ROOT).as_posix())

layer = {
    "name": "soc-detection-playbooks coverage",
    "versions": {"attack": "20", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques covered by the Sigma rules in this repository.",
    "techniques": [
        {"techniqueID": tid, "score": len(rules), "comment": "\n".join(rules), "enabled": True}
        for tid, rules in sorted(techniques.items())
    ],
    "gradient": {"colors": ["#ffffff", "#2F80ED"], "minValue": 0, "maxValue": max((len(r) for r in techniques.values()), default=1)},
    "legendItems": [{"label": "Rules covering the technique", "color": "#2F80ED"}],
}
OUT.write_text(json.dumps(layer, indent=2), encoding="utf-8")
print(f"Wrote {OUT.relative_to(ROOT)} with {len(techniques)} techniques from {sum(len(r) for r in techniques.values())} rule-tag pairs.")
