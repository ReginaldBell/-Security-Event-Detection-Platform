from __future__ import annotations

import ipaddress
import logging
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.schemas.incident_new import IncidentNew
from app.db.database import get_session
from app.db.models import EntityRiskRow

logger = logging.getLogger(__name__)

RISK_INCREMENT_BY_TYPE: Dict[str, float] = {
    "brute_force": 10.0,
    "credential_abuse": 25.0,
    "ai_prompt_injection": 30.0,
    "ai_privilege_escalation": 35.0,
    "ai_jailbreak": 30.0,
    "ai_data_exfiltration": 35.0,
    "ai_combined_attack": 45.0,
    "ai_dlp_high": 20.0,
    "ai_dlp_critical": 40.0,
}
DECAY_HALF_LIFE_HOURS = 24.0
_SECONDS_PER_HOUR = 3600.0
_DECAY_LAMBDA = math.log(2) / DECAY_HALF_LIFE_HOURS

_lock = threading.Lock()


@dataclass
class _RiskState:
    score: float
    last_updated: datetime


_risk_by_entity: Dict[Tuple[str, str], _RiskState] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
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


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _collect_entities(incident: IncidentNew) -> Dict[str, Set[str]]:
    source_ips: Set[str] = set()
    usernames: Set[str] = set()

    if isinstance(incident.subject.source_ip, str) and incident.subject.source_ip:
        source_ips.add(incident.subject.source_ip)
    if (
        isinstance(incident.subject.username, str)
        and incident.subject.username
        and incident.subject.username != "multiple_accounts"
    ):
        usernames.add(incident.subject.username)

    for entity in incident.affected_entities:
        if not isinstance(entity, str) or not entity:
            continue
        if _is_ip_address(entity):
            source_ips.add(entity)
        else:
            usernames.add(entity)

    return {"source_ip": source_ips, "username": usernames}


def _decay_score(score: float, elapsed_seconds: float) -> float:
    if elapsed_seconds <= 0:
        return score
    elapsed_hours = elapsed_seconds / _SECONDS_PER_HOUR
    return score * math.exp(-_DECAY_LAMBDA * elapsed_hours)


def _decay_state_to_locked(state: _RiskState, at: datetime) -> None:
    if at <= state.last_updated:
        return
    elapsed_seconds = (at - state.last_updated).total_seconds()
    state.score = _decay_score(state.score, elapsed_seconds)
    state.last_updated = at


def _apply_weight_locked(entity_type: str, entity_id: str, weight: float, at: datetime) -> None:
    key = (entity_type, entity_id)
    state = _risk_by_entity.get(key)
    if state is None:
        state = _RiskState(score=0.0, last_updated=at)
        _risk_by_entity[key] = state
    _decay_state_to_locked(state, at)
    state.score += weight


def _record_incident_locked(incident: IncidentNew, at: datetime) -> None:
    weight = RISK_INCREMENT_BY_TYPE.get(incident.type, 0.0)
    ai_data = incident.ai_pipeline_data
    if ai_data is not None:
        if ai_data.dlp_max_severity == "critical":
            weight += RISK_INCREMENT_BY_TYPE["ai_dlp_critical"]
        elif ai_data.dlp_max_severity == "high":
            weight += RISK_INCREMENT_BY_TYPE["ai_dlp_high"]
    if weight <= 0:
        return
    entities = _collect_entities(incident)
    for source_ip in entities["source_ip"]:
        _apply_weight_locked("source_ip", source_ip, weight, at)
    for username in entities["username"]:
        _apply_weight_locked("username", username, weight, at)


def _persist_risk_locked() -> None:
    """Write current in-memory risk state to DB. Caller must hold _lock."""
    try:
        with get_session() as session:
            for (entity_type, entity_id), state in _risk_by_entity.items():
                session.merge(EntityRiskRow(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    score=state.score,
                    last_updated=state.last_updated.isoformat().replace("+00:00", "Z"),
                ))
    except Exception as exc:
        logger.warning(f"Entity risk persist failed: {exc}")


def record_incident(incident: IncidentNew) -> None:
    at = _parse_iso8601(incident.last_seen) or _utcnow()
    with _lock:
        _record_incident_locked(incident, at)
        _persist_risk_locked()


def rehydrate(incidents: Iterable[IncidentNew]) -> None:
    incident_list = list(incidents)
    if incident_list:
        with _lock:
            _risk_by_entity.clear()
            ordered = sorted(
                incident_list,
                key=lambda inc: _parse_iso8601(inc.last_seen) or _utcnow(),
            )
            for incident in ordered:
                at = _parse_iso8601(incident.last_seen) or _utcnow()
                _record_incident_locked(incident, at)
            _persist_risk_locked()
        return

    # Try loading persisted risk state from DB first.
    try:
        with get_session() as session:
            rows = session.query(EntityRiskRow).all()
            if rows:
                with _lock:
                    _risk_by_entity.clear()
                    for row in rows:
                        dt = _parse_iso8601(row.last_updated)
                        if dt is None:
                            continue
                        _risk_by_entity[(row.entity_type, row.entity_id)] = _RiskState(
                            score=row.score,
                            last_updated=dt,
                        )
                logger.info(f"Entity risk rehydrated from database ({len(rows)} entities)")
                return
    except Exception as exc:
        logger.warning(f"Failed to load entity risk from DB, rebuilding: {exc}")

    # Fall back: rebuild from incident history (same as before).
    with _lock:
        _risk_by_entity.clear()
        ordered = sorted(
            incident_list,
            key=lambda inc: _parse_iso8601(inc.last_seen) or _utcnow(),
        )
        for incident in ordered:
            at = _parse_iso8601(incident.last_seen) or _utcnow()
            _record_incident_locked(incident, at)
        _persist_risk_locked()


def build_entity_risk_rows(incidents: List[IncidentNew]) -> List[Dict[str, object]]:
    now = _utcnow()
    with _lock:
        risk_snapshot: Dict[Tuple[str, str], float] = {}
        for key, state in _risk_by_entity.items():
            _decay_state_to_locked(state, now)
            risk_snapshot[key] = round(state.score, 2)

    aggregates: Dict[Tuple[str, str], Dict[str, object]] = {}

    for incident in incidents:
        entities = _collect_entities(incident)
        for source_ip in entities["source_ip"]:
            key = ("source_ip", source_ip)
            row = aggregates.setdefault(
                key,
                {
                    "entity_type": "source_ip",
                    "entity_id": source_ip,
                    "total_incidents": 0,
                    "open_incidents": 0,
                    "highest_confidence": 0.0,
                    "last_seen": None,
                },
            )
            row["total_incidents"] += 1
            if incident.status == "open":
                row["open_incidents"] += 1
            row["highest_confidence"] = max(float(row["highest_confidence"]), float(incident.confidence))
            existing_seen = _parse_iso8601(row["last_seen"])
            candidate_seen = _parse_iso8601(incident.last_seen)
            if candidate_seen and (existing_seen is None or candidate_seen >= existing_seen):
                row["last_seen"] = incident.last_seen

        for username in entities["username"]:
            key = ("username", username)
            row = aggregates.setdefault(
                key,
                {
                    "entity_type": "username",
                    "entity_id": username,
                    "total_incidents": 0,
                    "open_incidents": 0,
                    "highest_confidence": 0.0,
                    "last_seen": None,
                },
            )
            row["total_incidents"] += 1
            if incident.status == "open":
                row["open_incidents"] += 1
            row["highest_confidence"] = max(float(row["highest_confidence"]), float(incident.confidence))
            existing_seen = _parse_iso8601(row["last_seen"])
            candidate_seen = _parse_iso8601(incident.last_seen)
            if candidate_seen and (existing_seen is None or candidate_seen >= existing_seen):
                row["last_seen"] = incident.last_seen

    for key, score in risk_snapshot.items():
        row = aggregates.setdefault(
            key,
            {
                "entity_type": key[0],
                "entity_id": key[1],
                "total_incidents": 0,
                "open_incidents": 0,
                "highest_confidence": 0.0,
                "last_seen": None,
            },
        )
        row["risk_score"] = score

    rows: List[Dict[str, object]] = []
    for key, row in aggregates.items():
        risk_score = risk_snapshot.get(key, 0.0)
        rows.append(
            {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "risk_score": round(float(risk_score), 2),
                "total_incidents": int(row["total_incidents"]),
                "open_incidents": int(row["open_incidents"]),
                "highest_confidence": round(float(row["highest_confidence"]), 4),
                "last_seen": row["last_seen"],
            }
        )

    rows.sort(
        key=lambda item: (
            -float(item["risk_score"]),
            -int(item["open_incidents"]),
            -float(item["highest_confidence"]),
            item["entity_type"],
            item["entity_id"],
        )
    )
    return rows
