from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from app.schemas.incident_new import IncidentNew

logger = logging.getLogger(__name__)

_CHAINS_PATH = Path("runs") / "correlation_chains.json"
_lock = threading.Lock()

ATTACK_CHAIN = [
    {"stage": 1, "technique": "T1110", "label": "Brute Force / Password Spray", "incident_type": "brute_force"},
    {"stage": 2, "technique": "T1110.003", "label": "Credential Spray", "incident_type": "credential_abuse"},
    {"stage": 3, "technique": "T1078", "label": "Valid Account Compromise", "incident_type": "credential_abuse"},
    {"stage": 4, "technique": "T1021.002", "label": "Lateral Movement via SMB", "incident_type": "lateral_movement"},
]

_CHAIN_SEQUENCE = ["T1110", "T1110.003", "T1078", "T1021.002"]

_TECHNIQUE_TO_STAGE = {entry["technique"]: entry["stage"] for entry in ATTACK_CHAIN}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_chains_locked() -> Dict[str, dict]:
    _CHAINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _CHAINS_PATH.exists():
        return {}
    try:
        raw = json.loads(_CHAINS_PATH.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _save_chains_locked(chains: Dict[str, dict]) -> None:
    _CHAINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CHAINS_PATH.write_text(json.dumps(chains, indent=2, default=str), encoding="utf-8")


def _technique_from_incident(incident: IncidentNew) -> Optional[str]:
    mitre = getattr(incident, "mitre", None)
    if mitre and isinstance(mitre, dict):
        return mitre.get("technique")
    if hasattr(incident, "type"):
        type_map = {
            "brute_force": "T1110",
            "credential_abuse": "T1110.003",
            "lateral_movement": "T1021.002",
        }
        return type_map.get(incident.type)
    return None


def _chain_stage(technique: Optional[str]) -> int:
    if technique is None:
        return 0
    return _TECHNIQUE_TO_STAGE.get(technique, 0)


def correlate_incident(incident: IncidentNew) -> dict:
    technique = _technique_from_incident(incident)
    stage = _chain_stage(technique)

    with _lock:
        chains = _load_chains_locked()

        entity_key = "_".join(sorted(incident.affected_entities)) if incident.affected_entities else incident.incident_id

        chain = chains.get(entity_key)
        if chain is None:
            chain = {
                "chain_id": entity_key,
                "entity_key": entity_key,
                "stages_observed": [],
                "incidents": [],
                "first_seen": incident.first_seen,
                "last_seen": incident.last_seen,
                "chain_complete": False,
                "updated_at": _utcnow(),
            }

        if stage > 0 and stage not in chain["stages_observed"]:
            chain["stages_observed"].append(stage)
            chain["stages_observed"].sort()

        if incident.incident_id not in chain["incidents"]:
            chain["incidents"].append(incident.incident_id)

        chain["last_seen"] = max(chain.get("last_seen", ""), incident.last_seen)
        chain["chain_complete"] = set(range(1, len(ATTACK_CHAIN) + 1)).issubset(set(chain["stages_observed"]))
        chain["updated_at"] = _utcnow()

        chains[entity_key] = chain

        _save_chains_locked(chains)

        sidecar_path = Path("runs") / f"correlation_{incident.incident_id}.json"
        sidecar = {
            "incident_id": incident.incident_id,
            "technique": technique,
            "chain_stage": stage,
            "chain_id": entity_key,
            "stages_observed": chain["stages_observed"],
            "chain_complete": chain["chain_complete"],
            "peer_incidents": [i for i in chain["incidents"] if i != incident.incident_id],
            "updated_at": chain["updated_at"],
        }
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        return sidecar


def get_chain(chain_id: str) -> Optional[dict]:
    with _lock:
        chains = _load_chains_locked()
        return chains.get(chain_id)


def list_chains() -> List[dict]:
    with _lock:
        chains = _load_chains_locked()
        return sorted(chains.values(), key=lambda c: c.get("last_seen", ""), reverse=True)


def get_incident_correlation(incident_id: str) -> Optional[dict]:
    sidecar_path = Path("runs") / f"correlation_{incident_id}.json"
    if not sidecar_path.exists():
        return None
    try:
        return json.loads(sidecar_path.read_text(encoding="utf-8"))
    except Exception:
        return None
