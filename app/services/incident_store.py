from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from app.schemas.incident_new import IncidentNew
from app.services.security_contracts import (
    INCIDENT_TRANSITIONS,
    SLA_MINUTES_BY_SEVERITY,
    SEVERITY_PRIORITY_ORDER,
)
from app.services.playbook_registry import get_playbook_by_technique
from app.services import entity_risk as entity_risk_service
from app.services import metrics as metrics_service
from app.db.database import get_session, init_db
from app.db.models import AuditEventRow, IncidentRow

logger = logging.getLogger(__name__)

# Legacy JSON paths — used only for one-time migration on first startup.
_LEGACY_STORE_PATH = Path("runs") / "incidents.json"
_LEGACY_AUDIT_PATH = Path("runs") / "incident_audit.json"
_STORE_PATH = _LEGACY_STORE_PATH
_AUDIT_PATH = _LEGACY_AUDIT_PATH

_STALE_AFTER = timedelta(minutes=5)
_lock = threading.Lock()
_incidents_by_id: Dict[str, IncidentNew] = {}
_loaded = False


def _compat_store_path() -> Optional[Path]:
    path = globals().get("_STORE_PATH")
    if path is None:
        return None
    path = Path(path)
    return path if path != _LEGACY_STORE_PATH else None


def _compat_audit_path() -> Optional[Path]:
    path = globals().get("_AUDIT_PATH")
    if path is None:
        return None
    path = Path(path)
    return path if path != _LEGACY_AUDIT_PATH else None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _max_timestamp(a: str, b: str) -> str:
    da = _parse_iso8601(a)
    db = _parse_iso8601(b)
    if da and db:
        return a if da >= db else b
    if db and not da:
        return b
    if da and not db:
        return a
    return a if a >= b else b


def _min_timestamp(a: str, b: str) -> str:
    da = _parse_iso8601(a)
    db = _parse_iso8601(b)
    if da and db:
        return a if da <= db else b
    if db and not da:
        return b
    if da and not db:
        return a
    return a if a <= b else b


def _copy_incident(incident: IncidentNew) -> IncidentNew:
    return IncidentNew.model_validate(incident.model_dump(mode="json"))


def _is_stale(last_seen: str, now: Optional[datetime] = None) -> bool:
    seen = _parse_iso8601(last_seen)
    if seen is None:
        return False
    reference = now or _utcnow()
    return (reference - seen) > _STALE_AFTER


def _age_seconds(value: Optional[datetime | str], now: Optional[datetime] = None) -> int:
    if value is None:
        return 0
    parsed = value if isinstance(value, datetime) else _parse_iso8601(value)
    if parsed is None:
        return 0
    reference = now or _utcnow()
    return max(int((reference - parsed).total_seconds()), 0)


def _sla_deadline_minutes(incident: IncidentNew) -> int:
    return SLA_MINUTES_BY_SEVERITY.get(incident.severity, 480)


def _sla_breached(incident: IncidentNew, now: Optional[datetime] = None) -> bool:
    if incident.status == "closed":
        return False
    started_at = incident.created_at or _parse_iso8601(incident.first_seen)
    return _age_seconds(started_at, now) > _sla_deadline_minutes(incident) * 60


def _priority_after_sla(incident: IncidentNew, breached: bool) -> str:
    if not breached:
        return incident.severity
    try:
        index = SEVERITY_PRIORITY_ORDER.index(incident.severity)
    except ValueError:
        return "high"
    return SEVERITY_PRIORITY_ORDER[min(index + 1, len(SEVERITY_PRIORITY_ORDER) - 1)]


def valid_next_statuses(incident: IncidentNew) -> List[str]:
    return list(INCIDENT_TRANSITIONS.get(incident.status, ()))


def incident_to_response(incident: IncidentNew) -> dict:
    out = incident.model_dump(mode="json")
    if not out.get("playbook_id"):
        out["playbook_id"] = get_playbook_by_technique(incident.mitre_technique)["id"]
    out["is_stale"] = _is_stale(incident.last_seen)
    now = _utcnow()
    out["time_since_alert_seconds"] = _age_seconds(
        incident.created_at or incident.first_seen,
        now,
    )
    out["time_in_state_seconds"] = _age_seconds(
        incident.updated_at or incident.created_at or incident.first_seen,
        now,
    )
    out["sla_deadline_minutes"] = _sla_deadline_minutes(incident)
    breached = _sla_breached(incident, now)
    out["sla_breached"] = breached
    out["sla_action_required"] = bool(breached and incident.status in {"open", "acknowledged"})
    out["effective_priority"] = _priority_after_sla(incident, breached)
    out["valid_next_statuses"] = valid_next_statuses(incident)
    return out


def _row_from_incident(incident: IncidentNew) -> IncidentRow:
    return IncidentRow(
        incident_id=incident.incident_id,
        type=incident.type,
        status=incident.status,
        severity=incident.severity,
        confidence=incident.confidence,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        data=json.dumps(incident.model_dump(mode="json")),
    )


def _write_incident_locked(incident: IncidentNew) -> None:
    if _compat_store_path() is not None:
        _save_compat_store_locked()
        return
    with get_session() as session:
        session.merge(_row_from_incident(incident))


def _save_compat_store_locked() -> None:
    path = _compat_store_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    items = [
        _incidents_by_id[key].model_dump(mode="json")
        for key in sorted(_incidents_by_id.keys())
    ]
    path.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _append_audit_locked(
    incident_id: str,
    action: str,
    user: str,
    before_status: Optional[str] = None,
    after_status: Optional[str] = None,
    assignee: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    audit_path = _compat_audit_path()
    if audit_path is not None:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            raw = json.loads(audit_path.read_text(encoding="utf-8")) if audit_path.exists() else []
        except Exception:
            raw = []
        if not isinstance(raw, list):
            raw = []
        raw.append(
            {
                "incident_id": incident_id,
                "action": action,
                "user": user,
                "timestamp": _utcnow().isoformat().replace("+00:00", "Z"),
                "before_status": before_status,
                "after_status": after_status,
                "assignee": assignee,
                "detail": detail or {},
            }
        )
        audit_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        return

    try:
        with get_session() as session:
            session.add(AuditEventRow(
                incident_id=incident_id,
                action=action,
                user=user,
                timestamp=_utcnow().isoformat().replace("+00:00", "Z"),
                before_status=before_status,
                after_status=after_status,
                assignee=assignee,
                detail=json.dumps(detail or {}),
            ))
    except Exception as exc:
        logger.warning(f"Audit write failed for {incident_id}: {exc}")


def _migrate_incidents_locked(session) -> Dict[str, IncidentNew]:
    """One-time import from legacy JSON file. Returns migrated incidents."""
    index: Dict[str, IncidentNew] = {}
    if not _LEGACY_STORE_PATH.exists():
        return index
    try:
        raw = json.loads(_LEGACY_STORE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return index
    if not isinstance(raw, list):
        return index
    for item in raw:
        try:
            incident = IncidentNew.model_validate(item)
            index[incident.incident_id] = incident
            session.add(_row_from_incident(incident))
        except Exception:
            continue
    if index:
        logger.info(f"Migrated {len(index)} incidents from JSON to database")
    return index


def _migrate_audit_locked(session) -> None:
    """One-time import of audit trail from legacy JSON file."""
    if not _LEGACY_AUDIT_PATH.exists():
        return
    try:
        raw = json.loads(_LEGACY_AUDIT_PATH.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(raw, list):
        return
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            session.add(AuditEventRow(
                incident_id=entry.get("incident_id", ""),
                action=entry.get("action", ""),
                user=entry.get("user", ""),
                timestamp=entry.get("timestamp", ""),
                before_status=entry.get("before_status"),
                after_status=entry.get("after_status"),
                assignee=entry.get("assignee"),
                detail=json.dumps(entry.get("detail") or {}),
            ))
        except Exception:
            continue


def _load_store_locked() -> None:
    global _incidents_by_id, _loaded
    index: Dict[str, IncidentNew] = {}

    compat_path = _compat_store_path()
    if compat_path is not None:
        compat_path.parent.mkdir(parents=True, exist_ok=True)
        if not compat_path.exists():
            compat_path.write_text("[]", encoding="utf-8")
        try:
            raw = json.loads(compat_path.read_text(encoding="utf-8"))
        except Exception:
            raw = []
        if isinstance(raw, list):
            for item in raw:
                try:
                    incident = IncidentNew.model_validate(item)
                    index[incident.incident_id] = incident
                except Exception:
                    continue
        _incidents_by_id = index
        _loaded = True
        return

    init_db()

    with get_session() as session:
        rows = session.query(IncidentRow).all()

        if not rows:
            # First startup after migration: import legacy JSON data if present.
            index = _migrate_incidents_locked(session)
            audit_count = session.query(AuditEventRow).count()
            if audit_count == 0:
                _migrate_audit_locked(session)
        else:
            for row in rows:
                try:
                    incident = IncidentNew.model_validate(json.loads(row.data))
                    index[incident.incident_id] = incident
                except Exception:
                    continue

    _incidents_by_id = index
    _loaded = True


def _ensure_loaded_locked() -> None:
    if not _loaded:
        _load_store_locked()


def _merge_sources(existing: IncidentNew, incoming: IncidentNew) -> int:
    merged_sources: Set[str] = set()
    merged_events = list(existing.evidence.events) + list(incoming.evidence.events)
    for event in merged_events:
        if not isinstance(event, dict):
            continue
        source = event.get("source")
        if isinstance(source, str) and source:
            merged_sources.add(source)
    if merged_sources:
        return len(merged_sources)
    return max(existing.source_count, incoming.source_count)


def _merge_incident(existing: IncidentNew, incoming: IncidentNew, now: datetime) -> IncidentNew:
    merged = existing.model_copy(deep=True)

    merged.first_seen = _min_timestamp(existing.first_seen, incoming.first_seen)
    merged.last_seen = _max_timestamp(existing.last_seen, incoming.last_seen)
    merged.evidence_count = existing.evidence_count + incoming.evidence_count
    merged.affected_entities = sorted(
        set(existing.affected_entities).union(set(incoming.affected_entities))
    )
    merged.source_count = _merge_sources(existing, incoming)
    merged.updated_at = now

    merged.evidence.window_start = _min_timestamp(
        existing.evidence.window_start,
        incoming.evidence.window_start,
    )
    merged.evidence.window_end = _max_timestamp(
        existing.evidence.window_end,
        incoming.evidence.window_end,
    )
    merged.evidence.timeline = list(existing.evidence.timeline) + list(incoming.evidence.timeline)
    merged.evidence.events = list(existing.evidence.events) + list(incoming.evidence.events)

    counts = dict(existing.evidence.counts)
    incoming_counts = dict(incoming.evidence.counts)
    if "failures" in counts or "failures" in incoming_counts:
        counts["failures"] = merged.evidence_count
    if "distinct_users" in counts or "distinct_users" in incoming_counts:
        distinct_users = set()
        for event in merged.evidence.events:
            if not isinstance(event, dict):
                continue
            username = event.get("username")
            if isinstance(username, str) and username:
                distinct_users.add(username)
        if distinct_users:
            counts["distinct_users"] = len(distinct_users)
    merged.evidence.counts = counts

    merged.severity = incoming.severity
    merged.confidence = incoming.confidence
    merged.summary = incoming.summary
    merged.recommended_actions = incoming.recommended_actions
    merged.explanation = incoming.explanation
    merged.subject = incoming.subject

    return merged


def _safe_metric_increment(counter_name: str) -> None:
    try:
        metrics_service.increment_counter(counter_name)
    except Exception as exc:
        logger.warning(f"Incident metric increment failed for {counter_name}: {exc}")


def _safe_entity_risk_record(incident: IncidentNew) -> None:
    try:
        entity_risk_service.record_incident(incident)
    except Exception as exc:
        logger.warning(f"Entity risk update failed for {incident.incident_id}: {exc}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_store() -> None:
    with _lock:
        _load_store_locked()


def save_store() -> None:
    pass  # DB writes happen immediately on every upsert/transition


def list_audit_events(incident_id: Optional[str] = None) -> List[dict]:
    with _lock:
        audit_path = _compat_audit_path()
        if audit_path is not None:
            try:
                raw = json.loads(audit_path.read_text(encoding="utf-8")) if audit_path.exists() else []
            except Exception:
                raw = []
            if not isinstance(raw, list):
                return []
            if incident_id is None:
                return raw
            return [event for event in raw if event.get("incident_id") == incident_id]

        try:
            with get_session() as session:
                query = session.query(AuditEventRow)
                if incident_id is not None:
                    query = query.filter(AuditEventRow.incident_id == incident_id)
                rows = query.order_by(AuditEventRow.id).all()
                result = []
                for row in rows:
                    try:
                        detail = json.loads(row.detail) if row.detail else {}
                    except Exception:
                        detail = {}
                    result.append({
                        "incident_id": row.incident_id,
                        "action": row.action,
                        "user": row.user,
                        "timestamp": row.timestamp,
                        "before_status": row.before_status,
                        "after_status": row.after_status,
                        "assignee": row.assignee,
                        "detail": detail,
                    })
                return result
        except Exception as exc:
            logger.warning(f"Audit read failed: {exc}")
            return []


def get_incident(incident_id: str) -> Optional[IncidentNew]:
    with _lock:
        _ensure_loaded_locked()
        incident = _incidents_by_id.get(incident_id)
        return _copy_incident(incident) if incident else None


def list_incidents() -> List[IncidentNew]:
    with _lock:
        _ensure_loaded_locked()
        return [_copy_incident(_incidents_by_id[key]) for key in sorted(_incidents_by_id.keys())]


def upsert_incident(incident: IncidentNew) -> IncidentNew:
    with _lock:
        _ensure_loaded_locked()

        now = _utcnow()
        incoming = _copy_incident(incident)
        if not incoming.playbook_id:
            incoming.playbook_id = get_playbook_by_technique(incoming.mitre_technique)["id"]
        existing = _incidents_by_id.get(incoming.incident_id)

        if existing is None:
            incoming.status = "open"
            incoming.resolution_reason = None
            incoming.created_at = now
            incoming.updated_at = now
            _incidents_by_id[incoming.incident_id] = incoming
            _write_incident_locked(incoming)
            _append_audit_locked(incoming.incident_id, "created", "system", after_status="open")
            _safe_metric_increment("incidents_created_total")
            _safe_entity_risk_record(incoming)
            return _copy_incident(incoming)

        merged = _merge_incident(existing, incoming, now)

        if existing.status == "closed":
            merged.status = "open"
            merged.resolution_reason = None
            merged.created_at = existing.created_at
            _incidents_by_id[merged.incident_id] = merged
            _write_incident_locked(merged)
            _append_audit_locked(
                merged.incident_id,
                "reopened",
                "system",
                before_status="closed",
                after_status="open",
            )
            _safe_metric_increment("incidents_reopened_total")
            _safe_entity_risk_record(merged)
            return _copy_incident(merged)

        merged.status = existing.status
        merged.resolution_reason = existing.resolution_reason
        merged.created_at = existing.created_at
        _incidents_by_id[merged.incident_id] = merged
        _write_incident_locked(merged)
        _safe_metric_increment("incidents_updated_total")
        return _copy_incident(merged)


def transition_incident(
    incident_id: str,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    resolution_reason: Optional[str] = None,
    user: str = "analyst_1",
    reopen: bool = False,
) -> IncidentNew:
    with _lock:
        _ensure_loaded_locked()

        existing = _incidents_by_id.get(incident_id)
        if existing is None:
            raise KeyError(incident_id)

        updated = existing.model_copy(deep=True)
        changed = False

        if status is not None:
            if status == "open" and reopen:
                if existing.status != "closed":
                    raise ValueError(f"Invalid reopen: {existing.status} -> open")
                updated.status = "open"
                updated.resolution_reason = None
                changed = True
            elif status == "open":
                raise ValueError("Reopen requires reopen=true")
            else:
                allowed = set(INCIDENT_TRANSITIONS.get(existing.status, ()))
                if status not in allowed:
                    raise ValueError(f"Invalid transition: {existing.status} -> {status}")
                updated.status = status
                changed = True

        if assignee is not None:
            cleaned_assignee = assignee.strip()
            updated.assignee = cleaned_assignee or None
            changed = True

        if not changed:
            raise ValueError("No incident update requested")

        updated.updated_at = _utcnow()
        if status == "closed":
            updated.resolution_reason = resolution_reason
            _safe_metric_increment("incidents_closed_total")

        _incidents_by_id[incident_id] = updated
        _write_incident_locked(updated)

        if status is not None:
            _append_audit_locked(
                incident_id,
                "reopened" if reopen else status,
                user,
                before_status=existing.status,
                after_status=updated.status,
                assignee=updated.assignee,
                detail={
                    **({"resolution_reason": resolution_reason} if resolution_reason else {}),
                    **({"reopen": True} if reopen else {}),
                } or None,
            )
        if assignee is not None:
            _append_audit_locked(
                incident_id,
                "assigned",
                user,
                before_status=existing.status,
                after_status=updated.status,
                assignee=updated.assignee,
            )
        return _copy_incident(updated)
