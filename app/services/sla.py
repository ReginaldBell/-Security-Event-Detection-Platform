from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.schemas.incident_new import IncidentNew

DCE_SLA_MINUTES_BY_SEVERITY = {
    "critical": 60,
    "high": 240,
    "medium": 1440,
    "low": 4320,
}

_WARNING_RATIO = 0.75


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


def _age_seconds(value: Optional[str | datetime], now: Optional[datetime] = None) -> int:
    if value is None:
        return 0
    parsed = value if isinstance(value, datetime) else _parse_iso8601(value)
    if parsed is None:
        return 0
    reference = now or _utcnow()
    return max(int((reference - parsed).total_seconds()), 0)


def sla_deadline_minutes(incident: IncidentNew) -> int:
    return DCE_SLA_MINUTES_BY_SEVERITY.get(incident.severity, 1440)


def sla_deadline_utc(incident: IncidentNew) -> Optional[str]:
    started_at = incident.created_at or _parse_iso8601(incident.first_seen)
    if started_at is None:
        return None
    from datetime import timedelta
    deadline = started_at + timedelta(minutes=sla_deadline_minutes(incident))
    return deadline.isoformat().replace("+00:00", "Z")


def sla_state(incident: IncidentNew, now: Optional[datetime] = None) -> str:
    """Returns 'ok', 'warning', or 'breach'."""
    if incident.status == "closed":
        return "ok"
    started_at = incident.created_at or _parse_iso8601(incident.first_seen)
    age = _age_seconds(started_at, now)
    deadline_secs = sla_deadline_minutes(incident) * 60
    if age >= deadline_secs:
        return "breach"
    if age >= deadline_secs * _WARNING_RATIO:
        return "warning"
    return "ok"


def sla_remaining_seconds(incident: IncidentNew, now: Optional[datetime] = None) -> int:
    started_at = incident.created_at or _parse_iso8601(incident.first_seen)
    age = _age_seconds(started_at, now)
    return max(sla_deadline_minutes(incident) * 60 - age, 0)


def build_sla_block(incident: IncidentNew, now: Optional[datetime] = None) -> dict:
    reference = now or _utcnow()
    state = sla_state(incident, reference)
    return {
        "sla_state": state,
        "sla_deadline_minutes": sla_deadline_minutes(incident),
        "sla_deadline_utc": sla_deadline_utc(incident),
        "sla_remaining_seconds": sla_remaining_seconds(incident, reference),
        "sla_breached": state == "breach",
        "sla_action_required": state in ("warning", "breach") and incident.status in {"open", "acknowledged"},
    }
