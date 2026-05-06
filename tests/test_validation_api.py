from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.routes import validation as validation_route


client = TestClient(app, base_url="http://testserver")


def test_validate_scenario_posts_to_current_app_origin(monkeypatch, tmp_path):
    monkeypatch.setattr(validation_route, "RESULTS_FILE", tmp_path / "validation_results.json")
    captured = {}

    def fake_run_scenario(path: str, ingest_url: str | None = None) -> dict:
        captured["ingest_url"] = ingest_url
        return {"incidents": []}

    monkeypatch.setattr(validation_route, "run_scenario", fake_run_scenario)
    monkeypatch.setattr(validation_route, "validate_detection", lambda scenario, incidents: {
        "scenario_id": scenario["scenario_id"],
        "expected": scenario.get("expected_detection"),
        "detected": False,
        "false_positive": False,
    })
    monkeypatch.setattr(validation_route, "compute_score", lambda validation, elapsed: {
        "score": 0,
        "status": "fail",
        "latency_seconds": elapsed,
    })
    monkeypatch.setattr(validation_route, "_write_wazuh_log", lambda result: None)

    response = client.post("/validate/password_spray")

    assert response.status_code == 200
    assert captured["ingest_url"] == "http://testserver/ingest/"


def test_mitre_coverage_uses_latest_result_per_scenario(monkeypatch):
    monkeypatch.setattr(validation_route, "_get_mitre_technique", lambda scenario: "T1110.003")
    monkeypatch.setattr(validation_route, "_load_results", lambda: [
        {
            "scenario": "password_spray",
            "validation": {
                "scenario_id": "password_spray_01",
                "expected": "credential_abuse",
                "detected": False,
            },
        },
        {
            "scenario": "password_spray",
            "validation": {
                "scenario_id": "password_spray",
                "expected": "credential_abuse",
                "detected": True,
            },
        },
    ])

    assert validation_route.mitre_coverage() == {
        "T1110.003": {"tested": 1, "detected": 1, "success_rate": 100.0}
    }
