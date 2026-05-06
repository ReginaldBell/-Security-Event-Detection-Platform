from __future__ import annotations

import json
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.schemas.incident_new import IncidentNew
from app.services.incident_store import incident_to_response
from app.services.security_contracts import (
    SECURE_CONTEXT_ALLOWED_FIELDS,
    SECURE_CONTEXT_GUARANTEES,
    SECURE_CONTEXT_REMOVED_FIELDS,
)

_AI_CONTEXT_AUDIT_PATH = Path("runs") / "secure_context_audit.json"

FIELD_POLICY = {
    "allowed": SECURE_CONTEXT_ALLOWED_FIELDS,
    "removed": SECURE_CONTEXT_REMOVED_FIELDS,
    "guarantees": SECURE_CONTEXT_GUARANTEES,
}

ATTACK_CHAIN = [
    {"technique": "T1110", "label": "Credential attack"},
    {"technique": "T1078", "label": "Valid account use"},
    {"technique": "T1021", "label": "Remote services"},
]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_ref(value: str, prefix: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _chain_correlation(incident: IncidentNew) -> dict[str, Any]:
    technique = incident.mitre.technique if incident.mitre else incident.mitre_technique
    normalized = "T1110" if technique == "T1110.003" else technique
    index = next(
        (idx for idx, step in enumerate(ATTACK_CHAIN) if step["technique"] == normalized),
        0,
    )
    next_step = ATTACK_CHAIN[index + 1] if index + 1 < len(ATTACK_CHAIN) else None
    return {
        "stage": index + 1,
        "stage_count": len(ATTACK_CHAIN),
        "current_technique": technique,
        "next_likely_step": next_step,
        "chain": ATTACK_CHAIN,
    }


def record_ai_context_audit(
    incident_id: str,
    user: str = "analyst_1",
    purpose: str = "triage_context",
) -> None:
    _AI_CONTEXT_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        raw = json.loads(_AI_CONTEXT_AUDIT_PATH.read_text(encoding="utf-8")) if _AI_CONTEXT_AUDIT_PATH.exists() else []
    except Exception:
        raw = []
    if not isinstance(raw, list):
        raw = []
    raw.append(
        {
            "incident_id": incident_id,
            "action": "secure_context_generated",
            "user": user,
            "purpose": purpose,
            "timestamp": _utcnow(),
            "field_policy": FIELD_POLICY,
        }
    )
    _AI_CONTEXT_AUDIT_PATH.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def list_ai_context_audit(incident_id: str | None = None) -> list[dict[str, Any]]:
    try:
        raw = json.loads(_AI_CONTEXT_AUDIT_PATH.read_text(encoding="utf-8")) if _AI_CONTEXT_AUDIT_PATH.exists() else []
    except Exception:
        raw = []
    if not isinstance(raw, list):
        return []
    if incident_id is None:
        return raw
    return [entry for entry in raw if entry.get("incident_id") == incident_id]


def build_incident_context(incident: IncidentNew) -> dict[str, Any]:
    """Build sanitized incident context for AI-assisted triage.

    The context intentionally excludes raw event payloads. It keeps only stable
    detection metadata, entity pivots, MITRE mapping, and aggregate evidence.
    """
    started = time.perf_counter()
    response_view = incident_to_response(incident)
    context = {
        "context_type": "secure_incident_triage",
        "incident_id": incident.incident_id,
        "type": incident.type,
        "status": incident.status,
        "assignee": incident.assignee,
        "severity": incident.severity,
        "effective_priority": response_view["effective_priority"],
        "sla": {
            "breached": response_view["sla_breached"],
            "action_required": response_view["sla_action_required"],
            "deadline_minutes": response_view["sla_deadline_minutes"],
        },
        "confidence": incident.confidence,
        "mitre": incident.mitre.model_dump(mode="json") if incident.mitre else None,
        "subject_refs": {
            "source_ip_ref": _stable_ref(incident.subject.source_ip, "ip"),
            "username_ref": _stable_ref(incident.subject.username, "user"),
        },
        "entity_refs": [
            _stable_ref(entity, "entity")
            for entity in sorted(set(incident.affected_entities))
        ],
        "entity_counts": {
            "affected_entities": len(set(incident.affected_entities)),
            "source_count": incident.source_count,
        },
        "summary": incident.summary,
        "recommended_actions": list(incident.recommended_actions),
        "signal_summary": {
            "threshold": incident.explanation.threshold,
            "observed": incident.explanation.observed,
            "window": incident.explanation.window,
            "trigger_field": incident.explanation.trigger_field,
        },
        "timeline_summary": {
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "evidence_count": incident.evidence_count,
            "source_count": incident.source_count,
            "counts": dict(incident.evidence.counts),
        },
        "chain_correlation": _chain_correlation(incident),
        "field_policy": FIELD_POLICY,
        "redaction_policy": {
            "raw_identifiers": "hashed",
            "raw_events": "excluded",
            "raw_source": "excluded",
            "secret_values": "excluded",
        },
    }
    context["generation_time_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return context
