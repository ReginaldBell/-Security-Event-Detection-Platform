from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_FIELDS = [
    "id",
    "technique_id",
    "name",
    "detections",
    "triage",
    "false_positives",
    "escalation",
]

_PLAYBOOKS_PATH = Path(__file__).resolve().parents[2] / "config" / "playbooks.json"


def validate_playbook(p: Dict[str, Any]) -> None:
    for f in REQUIRED_FIELDS:
        if f not in p:
            raise ValueError(f"Missing {f} in {p.get('id')}")


with _PLAYBOOKS_PATH.open(encoding="utf-8") as f:
    raw = json.load(f)

if not isinstance(raw, list):
    raise ValueError("config/playbooks.json must contain a list of playbooks")

PLAYBOOKS_BY_TECHNIQUE: Dict[str, Dict[str, Any]] = {}
PLAYBOOKS_BY_ID: Dict[str, Dict[str, Any]] = {}
PLAYBOOKS: List[Dict[str, Any]] = []

for p in raw:
    if not isinstance(p, dict):
        raise ValueError("Every playbook must be a JSON object")
    validate_playbook(p)
    PLAYBOOKS.append(p)
    PLAYBOOKS_BY_TECHNIQUE[p["technique_id"]] = p
    PLAYBOOKS_BY_ID[p["id"]] = p

if "generic_investigation" not in PLAYBOOKS_BY_ID:
    raise ValueError("config/playbooks.json must define generic_investigation")


def get_playbook_by_technique(technique_id: str | None) -> Dict[str, Any]:
    return PLAYBOOKS_BY_TECHNIQUE.get(
        technique_id or "GENERIC",
        PLAYBOOKS_BY_ID["generic_investigation"],
    )


def get_playbook_by_id(playbook_id: str | None) -> Dict[str, Any]:
    return PLAYBOOKS_BY_ID.get(
        playbook_id or "generic_investigation",
        PLAYBOOKS_BY_ID["generic_investigation"],
    )


def list_playbooks() -> List[Dict[str, Any]]:
    return list(PLAYBOOKS)


def has_playbook_id(playbook_id: str | None) -> bool:
    return bool(playbook_id and playbook_id in PLAYBOOKS_BY_ID)
