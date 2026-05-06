from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.schemas.incident_new import IncidentNew
from app.ai_pipeline.secure_context import build_incident_context
from app.services import incident_store


def _ts(base: datetime, seconds: int = 0) -> str:
    return (base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _incident(
    incident_id: str,
    base: datetime,
    *,
    last_seen_offset: int = 0,
    evidence_count: int = 5,
    source: str = "auth_service",
    affected_entities: list[str] | None = None,
) -> IncidentNew:
    entities = affected_entities or ["203.0.113.10", "alice"]
    first_seen = _ts(base, 0)
    last_seen = _ts(base, last_seen_offset)
    return IncidentNew(
        incident_id=incident_id,
        type="brute_force",
        mitre_technique="T1110",
        severity="medium",
        confidence=0.85,
        first_seen=first_seen,
        last_seen=last_seen,
        affected_entities=entities,
        evidence_count=evidence_count,
        source_count=1,
        summary="test incident",
        recommended_actions=["investigate"],
        explanation={
            "threshold": 5,
            "observed": evidence_count,
            "window": "60s",
            "trigger_field": "username",
        },
        subject={"source_ip": "203.0.113.10", "username": "alice"},
        evidence={
            "window_start": first_seen,
            "window_end": last_seen,
            "counts": {"failures": evidence_count},
            "timeline": [
                {
                    "timestamp": first_seen,
                    "event_type": "login_attempt",
                    "result": "failure",
                    "reason": "bad_password",
                    "username": "alice",
                }
            ],
            "events": [
                {
                    "timestamp": first_seen,
                    "event_type": "login_attempt",
                    "result": "failure",
                    "reason": "bad_password",
                    "username": "alice",
                    "source": source,
                }
            ],
        },
    )


def _reset_store(tmp_path: Path) -> None:
    incident_store._STORE_PATH = tmp_path / "runs" / "incidents.json"
    incident_store._AUDIT_PATH = tmp_path / "runs" / "incident_audit.json"
    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()


def test_new_incident_creates_with_open_status(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    created = incident_store.upsert_incident(
        _incident("inc_test_001", datetime(2026, 1, 1, tzinfo=timezone.utc))
    )

    assert created.status == "open"
    assert created.created_at is not None
    assert created.updated_at is not None
    assert created.resolution_reason is None


def test_same_incident_id_dedups_and_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    incident_store.upsert_incident(_incident("inc_test_002", base, evidence_count=5, source="auth_a"))
    merged = incident_store.upsert_incident(
        _incident(
            "inc_test_002",
            base,
            last_seen_offset=30,
            evidence_count=3,
            source="auth_b",
            affected_entities=["203.0.113.10", "alice", "svc_account"],
        )
    )

    assert len(incident_store.list_incidents()) == 1
    assert merged.evidence_count == 8
    assert merged.last_seen == _ts(base, 30)
    assert merged.source_count == 2
    assert set(merged.affected_entities) == {"203.0.113.10", "alice", "svc_account"}


def test_closed_incident_reopens_correctly(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    incident_store.upsert_incident(_incident("inc_test_003", base))
    incident_store.transition_incident("inc_test_003", "acknowledged")
    incident_store.transition_incident("inc_test_003", "escalated")
    incident_store.transition_incident("inc_test_003", "closed", resolution_reason="contained")

    reopened = incident_store.upsert_incident(
        _incident("inc_test_003", base, last_seen_offset=45, evidence_count=2, source="auth_b")
    )

    assert len(incident_store.list_incidents()) == 1
    assert reopened.status == "open"
    assert reopened.resolution_reason is None
    assert reopened.evidence_count == 7


def test_invalid_transition_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    incident_store.upsert_incident(
        _incident("inc_test_004", datetime(2026, 1, 1, tzinfo=timezone.utc))
    )

    with pytest.raises(ValueError, match="Invalid transition"):
        incident_store.transition_incident("inc_test_004", "closed")

    with pytest.raises(ValueError, match="Invalid transition"):
        incident_store.transition_incident("inc_test_004", "escalated")


def test_lifecycle_fields_updated_properly(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    created = incident_store.upsert_incident(_incident("inc_test_005", base))
    acknowledged = incident_store.transition_incident("inc_test_005", "acknowledged")

    assert created.created_at is not None
    assert acknowledged.created_at == created.created_at
    assert acknowledged.updated_at is not None
    assert created.updated_at is not None
    assert acknowledged.updated_at >= created.updated_at
    assert acknowledged.status == "acknowledged"


def test_escalate_and_assign_incident(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    incident_store.upsert_incident(_incident("inc_test_007", base))
    incident_store.transition_incident("inc_test_007", "acknowledged")

    escalated = incident_store.transition_incident(
        "inc_test_007",
        "escalated",
        assignee="tier2",
        user="analyst_1",
    )
    assert escalated.status == "escalated"
    assert escalated.assignee == "tier2"

    closed = incident_store.transition_incident(
        "inc_test_007",
        "closed",
        resolution_reason="escalated_contained",
    )
    assert closed.status == "closed"
    assert closed.assignee == "tier2"
    assert closed.resolution_reason == "escalated_contained"
    audit = incident_store.list_audit_events("inc_test_007")
    assert any(event["action"] == "escalated" for event in audit)
    assert any(event["action"] == "assigned" and event["assignee"] == "tier2" for event in audit)


def test_secure_context_excludes_raw_events():
    incident = _incident("inc_test_secure_context", datetime(2026, 1, 1, tzinfo=timezone.utc))

    context = build_incident_context(incident)

    assert context["incident_id"] == "inc_test_secure_context"
    assert context["redaction_policy"]["raw_events"] == "excluded"
    assert context["redaction_policy"]["raw_identifiers"] == "hashed"
    assert "field_policy" in context
    assert "evidence.events" in context["field_policy"]["removed"]
    assert "subject.username" in context["field_policy"]["removed"]
    assert context["chain_correlation"]["stage"] == 1
    assert context["chain_correlation"]["next_likely_step"]["technique"] == "T1078"
    assert "events" not in context
    assert "subject" not in context
    assert "alice" not in str(context)
    assert "203.0.113.10" not in str(context)
    assert context["timeline_summary"]["evidence_count"] == incident.evidence_count


def test_incident_response_includes_sla_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    created = incident_store.upsert_incident(
        _incident("inc_test_sla", datetime(2026, 1, 1, tzinfo=timezone.utc))
    )

    response = incident_store.incident_to_response(created)

    assert response["time_since_alert_seconds"] >= 0
    assert response["time_in_state_seconds"] >= 0
    assert response["sla_deadline_minutes"] == 120
    assert response["sla_breached"] in {True, False}
    assert response["effective_priority"] in {"medium", "high"}
    assert response["valid_next_statuses"] == ["acknowledged"]


def test_sla_breach_auto_flags_and_increases_priority():
    incident = _incident("inc_test_sla_breach", datetime(2020, 1, 1, tzinfo=timezone.utc))
    incident.created_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    incident.updated_at = datetime(2020, 1, 1, tzinfo=timezone.utc)

    response = incident_store.incident_to_response(incident)

    assert response["sla_breached"] is True
    assert response["sla_action_required"] is True
    assert response["effective_priority"] == "high"


def test_closed_to_open_requires_explicit_reopen(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    incident_store.upsert_incident(_incident("inc_test_reopen", base))
    incident_store.transition_incident("inc_test_reopen", "acknowledged")
    incident_store.transition_incident("inc_test_reopen", "escalated")
    incident_store.transition_incident("inc_test_reopen", "closed", resolution_reason="contained")

    with pytest.raises(ValueError, match="Reopen requires"):
        incident_store.transition_incident("inc_test_reopen", "open")

    reopened = incident_store.transition_incident("inc_test_reopen", "open", reopen=True)
    assert reopened.status == "open"
    assert reopened.resolution_reason is None


def test_persistence_survives_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)

    created = incident_store.upsert_incident(
        _incident("inc_test_006", datetime(2026, 1, 1, tzinfo=timezone.utc))
    )
    created_at = created.created_at

    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()
    reloaded = incident_store.get_incident("inc_test_006")

    assert reloaded is not None
    assert reloaded.created_at == created_at
    assert reloaded.status == "open"
