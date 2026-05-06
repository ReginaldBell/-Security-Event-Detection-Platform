from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.api_contract import PlaybookListResponse, PlaybookResponse
from app.schemas.incident_new import IncidentNew


client = TestClient(app)


def _incident(technique_id: str = "T1110") -> IncidentNew:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return IncidentNew(
        incident_id="inc_playbook_contract",
        type="brute_force",
        mitre_technique=technique_id,
        severity="medium",
        confidence=0.8,
        first_seen=ts,
        last_seen=ts,
        affected_entities=["203.0.113.10", "alice"],
        evidence_count=5,
        source_count=1,
        summary="playbook test",
        recommended_actions=["review"],
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


def test_list_playbooks_contract():
    response = client.get("/playbooks/")

    assert response.status_code == 200
    payload = PlaybookListResponse.model_validate(response.json())
    assert payload.playbook_count == len(payload.playbooks)
    assert payload.playbook_count >= 1
    assert any(p.id == "generic_investigation" for p in payload.playbooks)


def test_get_playbook_by_id():
    response = client.get("/playbooks/bruteforce_investigation")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert payload.technique_id == "T1110"
    assert payload.detections.primary == "bruteforce_sequence"
    assert payload.triage


def test_get_playbook_by_unknown_id_returns_404():
    response = client.get("/playbooks/not_a_real_playbook")

    assert response.status_code == 404


def test_get_playbook_by_technique_uses_specific_and_fallback():
    specific = client.get("/playbooks/technique/T1059")
    fallback = client.get("/playbooks/technique/NO_SUCH_TECHNIQUE")

    assert specific.status_code == 200
    assert fallback.status_code == 200
    assert specific.json()["id"] == "command_execution_investigation"
    assert fallback.json()["id"] == "generic_investigation"


def test_t1110_playbook_serves_rich_detection_logic():
    response = client.get("/playbooks/technique/T1110")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert payload.deployment_context["cim"] == "required"
    assert "single_source" in payload.detection_logic
    assert "distributed_spray" in payload.detection_logic
    assert "cross_source_correlation" in payload.detection_logic
    assert "Was there success after failures" in payload.triage
    assert (
        payload.chain_context
        == "Successful brute force yields valid credentials, enabling execution under legitimate account context, progressing to lateral movement."
    )


def test_t1059_playbook_serves_execution_network_logic():
    response = client.get("/playbooks/technique/T1059")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert "execution_network_correlation" in payload.detection_logic
    assert "known_admin_activity" in payload.false_positive_logic
    assert "Was command obfuscated" in payload.triage


def test_t1021_playbook_serves_lateral_movement_logic():
    response = client.get("/playbooks/technique/T1021")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert "sequence_volume_hybrid" in payload.detection_logic
    assert "multi-host access volume" in payload.escalation_criteria
    assert payload.chain_steps == ["Valid Account", "Lateral Movement", "Execution"]


def test_get_playbook_for_incident(monkeypatch):
    from app.routes import playbooks as playbooks_route

    monkeypatch.setattr(playbooks_route.incident_store, "get_incident", lambda _id: _incident("T1110.003"))

    response = client.get("/playbooks/incident/inc_playbook_contract")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert payload.id == "password_spray_investigation"


def test_get_playbook_from_incident_workflow_endpoint(monkeypatch):
    from app.routes import incidents as incidents_route

    monkeypatch.setattr(incidents_route.incident_store, "get_incident", lambda _id: _incident("T1110"))

    response = client.get("/incidents/inc_playbook_contract/playbook")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert payload.id == "bruteforce_investigation"
    assert payload.technique_id == "T1110"


def test_get_playbook_from_incident_workflow_endpoint_uses_fallback(monkeypatch):
    from app.routes import incidents as incidents_route

    monkeypatch.setattr(incidents_route.incident_store, "get_incident", lambda _id: _incident("NO_SUCH_TECHNIQUE"))

    response = client.get("/incidents/inc_playbook_contract/playbook")

    assert response.status_code == 200
    payload = PlaybookResponse.model_validate(response.json())
    assert payload.id == "generic_investigation"


def test_get_playbook_from_missing_incident_workflow_endpoint_returns_404(monkeypatch):
    from app.routes import incidents as incidents_route

    monkeypatch.setattr(incidents_route.incident_store, "get_incident", lambda _id: None)

    response = client.get("/incidents/missing/playbook")

    assert response.status_code == 404


def test_get_playbook_for_missing_incident_returns_404(monkeypatch):
    from app.routes import playbooks as playbooks_route

    monkeypatch.setattr(playbooks_route.incident_store, "get_incident", lambda _id: None)

    response = client.get("/playbooks/incident/missing")

    assert response.status_code == 404
