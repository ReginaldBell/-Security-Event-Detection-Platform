from __future__ import annotations

import pytest

from app.detection import registry
from app.models.normalized_event import NormalizedEvent
from app.services.correlation_engine import correlate
from app.services.incident_builder import build_incident
from app.services.playbook_registry import get_playbook_by_technique
from app.services.risk_engine import compute_risk, risk_level


def test_playbook_registry_returns_specific_and_fallback_playbooks():
    assert get_playbook_by_technique("T1110") is not None
    assert get_playbook_by_technique("NO_SUCH_TECHNIQUE")["id"] == "generic_investigation"


def test_locked_mapping_normalizes_user_src_dest():
    raw = {
        "TargetUserName": "alice",
        "IpAddress": "203.0.113.10",
        "Computer": "host01",
    }
    normalized = NormalizedEvent(raw)

    assert normalized.user == "alice"
    assert normalized.src == "203.0.113.10"
    assert normalized.dest == "host01"


def test_detection_registry_contract_and_determinism():
    original = list(registry.DETECTIONS)
    registry.DETECTIONS.clear()

    @registry.register
    def sample_detection(_event):
        return {
            "technique_id": "T1110",
            "detection_id": "bruteforce_sequence",
            "evidence": {"failures": 6, "success": True},
            "confidence": 0.9,
        }

    try:
        event = NormalizedEvent({"user": "alice", "src": "10.0.0.1", "host": "host01"})
        assert registry.run_detections(event) == registry.run_detections(event)
    finally:
        registry.DETECTIONS[:] = original


def test_detection_registry_rejects_bad_contract():
    original = list(registry.DETECTIONS)
    registry.DETECTIONS.clear()

    @registry.register
    def bad_detection(_event):
        return {"technique_id": "T1110"}

    try:
        with pytest.raises(ValueError, match="missing required fields"):
            registry.run_detections(NormalizedEvent({}))
    finally:
        registry.DETECTIONS[:] = original


def test_risk_engine_same_input_same_score():
    detection = {
        "technique_id": "T1110",
        "detection_id": "bruteforce_sequence",
        "evidence": {"success": True, "unique_ips": 3},
        "confidence": 0.9,
    }
    event = NormalizedEvent({"user": "alice", "src": "203.0.113.10"})

    assert compute_risk(detection, event) == compute_risk(detection, event)
    assert risk_level(compute_risk(detection, event)) == "HIGH"


def test_t1110_fail_plus_success_creates_incident():
    detection = {
        "technique_id": "T1110",
        "detection_id": "bruteforce_sequence",
        "evidence": {"failures": 6, "success": True},
        "confidence": 0.9,
    }
    event = NormalizedEvent({"username": "alice", "source_ip": "203.0.113.10", "host": "host01"})

    correlated = correlate([detection])
    incident = build_incident(correlated[0], event)

    assert len(correlated) == 1
    assert incident["playbook_id"] == "bruteforce_investigation"
    assert incident["subject"]["username"] == "alice"


def test_t1059_encoded_is_high_risk():
    detection = {
        "technique_id": "T1059",
        "detection_id": "encoded_command",
        "evidence": {"encoded": True},
        "confidence": 0.9,
    }
    event = NormalizedEvent({"username": "alice", "source_ip": "10.0.0.5", "host": "host01"})

    incident = build_incident(correlate([detection])[0], event)

    assert incident["risk_score"] == 75
    assert incident["risk_level"] == "HIGH"


def test_t1021_multi_host_triggers():
    detection = {
        "technique_id": "T1021",
        "detection_id": "remote_services_fanout",
        "evidence": {"unique_dests": 3},
        "confidence": 0.8,
    }

    assert correlate([detection]) == [detection]


def test_t1003_always_escalates_to_incident():
    detection = {
        "technique_id": "T1003",
        "detection_id": "credential_dumping_signal",
        "evidence": {},
        "confidence": 0.95,
    }

    assert correlate([detection]) == [detection]
