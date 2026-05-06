from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import incident_store
from app.services import metrics as metrics_service


_BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ts(offset_seconds: int = 0) -> str:
    return (_BASE + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def _failure(offset_seconds: int) -> dict:
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "login_attempt",
        "result": "failure",
        "reason": "bad_password",
        "source_ip": "203.0.113.10",
        "username": "alice",
        "source": "auth_service",
    }


def _success(offset_seconds: int) -> dict:
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "login_attempt",
        "result": "success",
        "source_ip": "203.0.113.10",
        "username": "alice",
        "source": "auth_service",
    }


def _reset_store(tmp_path: Path) -> None:
    incident_store._STORE_PATH = tmp_path / "runs" / "incidents.json"
    incident_store._AUDIT_PATH = tmp_path / "runs" / "incident_audit.json"
    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()


def _sanitize_disabled(*_a, **_k):
    raise RuntimeError("sanitization disabled for test isolation")


def test_brute_force_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Stub metrics increments to avoid DB writes in the store layer
    monkeypatch.setattr(
        incident_store.metrics_service,
        "increment_counter",
        lambda *_a, **_k: None,
    )

    # Bypass PII sanitization: it strips username/source_ip, which breaks
    # brute-force detection.  The ingest route falls back to normalized.json.
    monkeypatch.setattr("app.routes.ingest.sanitize_run", _sanitize_disabled)

    _reset_store(tmp_path)

    # 10 failures within the 60-second brute-force window (every 6 s, T+0…T+54)
    # 1 success at T+64 s — 10 s after the last failure, within the 300 s
    # cross-source correlation window that emits bruteforce_then_success.
    events = [_failure(i * 6) for i in range(10)]
    events.append(_success(64))

    client = TestClient(app)

    # ------------------------------------------------------------------ ingest
    resp = client.post("/ingest/", json=events)
    assert resp.status_code == 200

    body = resp.json()
    assert body["event_count"] == 11
    assert body["normalization_status"] == "success"
    assert body["detection_status"] == "success"
    assert len(body["incidents"]) >= 1

    # ------------------------------------------------- T1110 incident fields
    brute = next(
        (inc for inc in body["incidents"] if inc.get("type") == "brute_force"),
        None,
    )
    assert brute is not None, "Expected a brute_force incident in the ingest response"

    assert brute["mitre"]["technique"] == "T1110"
    assert brute["playbook_id"] == "bruteforce_investigation"
    assert brute["subject"]["username"] == "alice"
    assert brute["subject"]["source_ip"] == "203.0.113.10"
    assert brute["evidence_count"] == 10
    assert brute["evidence"]["counts"]["failures"] == 10
    assert brute["evidence"]["counts"]["success_after_failure"] == 1
    assert "bruteforce_then_success" in brute["correlation_flags"]

    # ------------------------------------------ persistence through registry
    incident_id = brute["incident_id"]

    list_resp = client.get("/incidents/")
    assert list_resp.status_code == 200

    list_body = list_resp.json()
    stored_ids = [inc["incident_id"] for inc in list_body["incidents"]]
    assert incident_id in stored_ids, (
        f"Expected incident_id {incident_id!r} to appear in GET /incidents/ response"
    )

    stored = next(inc for inc in list_body["incidents"] if inc["incident_id"] == incident_id)
    assert stored["status"] == "open"
    assert "time_since_alert_seconds" in stored
    assert stored["time_since_alert_seconds"] >= 0
    assert "sla_deadline_minutes" in stored
    assert "sla_breached" in stored
