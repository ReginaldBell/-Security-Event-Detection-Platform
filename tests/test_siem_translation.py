from __future__ import annotations

from datetime import datetime, timezone

from app.routes import incidents as incidents_route
from app.schemas.incident_new import IncidentNew
from app.services.siem_translation import generate_spl, incident_spl_bundle


def _incident() -> IncidentNew:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return IncidentNew(
        incident_id="inc_siem_001",
        type="brute_force",
        mitre_technique="T1110",
        severity="low",
        confidence=0.70,
        first_seen=ts,
        last_seen=ts,
        affected_entities=["203.0.113.10", "alice"],
        evidence_count=5,
        source_count=1,
        summary="siem test",
        recommended_actions=["review logs"],
        explanation={
            "threshold": 5,
            "observed": 5,
            "window": "60s",
            "trigger_field": "username",
        },
        subject={"source_ip": "203.0.113.10", "username": "alice"},
        evidence={
            "window_start": ts,
            "window_end": ts,
            "counts": {"failures": 5},
            "timeline": [],
            "events": [],
        },
    )


def test_generate_spl_bruteforce_query():
    query = generate_spl("brute_force", {"threshold": 5})

    assert "index=auth_logs" in query
    assert "earliest=-15m" in query
    assert "| bin _time span=60s" in query
    assert "| stats count by src_ip, user, _time" in query
    assert "| where count >= 5" in query
    assert "cidrmatch" in query


def test_generate_spl_password_spraying_query():
    query = generate_spl("credential_abuse", {"threshold": 8, "distinct_users": 5})

    assert "dc(user) as distinct_users" in query
    assert "count >= 8 AND distinct_users >= 5" in query
    assert "T1110.003" in query


def test_incident_spl_bundle_includes_pivots(tmp_path, monkeypatch):
    from app.services import siem_translation

    monkeypatch.setattr(siem_translation, "_QUERY_CACHE_PATH", tmp_path / "runs" / "siem_query_cache.json")

    bundle = incident_spl_bundle(_incident())

    assert bundle["siem"] == "splunk"
    assert bundle["mapping_version"] == "1.0"
    assert bundle["detection_type"] == "brute_force"
    assert bundle["query"] == bundle["detection_query"]
    assert bundle["confidence"] > 0
    assert bundle["notes"]
    assert bundle["cache_key"]
    assert bundle["used_count"] >= 1
    assert len(bundle["pivot_queries"]) >= 3
    assert any("src_ip=\"203.0.113.10\"" in pivot["query"] for pivot in bundle["pivot_queries"])


def test_incident_spl_bundle_uses_cache(tmp_path, monkeypatch):
    from app.services import siem_translation

    monkeypatch.setattr(siem_translation, "_QUERY_CACHE_PATH", tmp_path / "runs" / "siem_query_cache.json")

    first = siem_translation.incident_spl_bundle(_incident())
    second = siem_translation.incident_spl_bundle(_incident())

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["used_count"] == 2
    assert second["query"] == first["query"]


def test_investigation_endpoint_returns_playbook(tmp_path, monkeypatch):
    from app.services import incident_store

    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    incident_store._STORE_PATH = tmp_path / "runs" / "incidents.json"
    incident_store._AUDIT_PATH = tmp_path / "runs" / "incident_audit.json"
    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()
    incident_store.upsert_incident(_incident())

    response = incidents_route.get_incident_investigation("inc_siem_001")

    assert response["questions"]
    assert response["pivot_queries"]
    assert response["escalation_conditions"]
