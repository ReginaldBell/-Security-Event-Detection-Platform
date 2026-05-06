from __future__ import annotations

import asyncio
from pathlib import Path

from app.routes import ai_pipeline as ai_pipeline_route
from app.schemas.ai_pipeline import AIPipelineResultsResponse, AIPipelineRunRequest, AIPipelineRunResponse
from app.services import incident_store


def _reset_incident_store(tmp_path: Path) -> None:
    incident_store._STORE_PATH = tmp_path / "runs" / "incidents.json"
    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()


def test_ai_pipeline_run_persists_results_and_bridges_incidents(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(ai_pipeline_route, "RUNS_DIR", runs_root)
    monkeypatch.setattr(ai_pipeline_route, "WAZUH_LOG", runs_root / "securewatch_wazuh.log")
    monkeypatch.setattr(ai_pipeline_route, "AI_ATTACK_LOG", runs_root / "ai-pipeline-attacks.log")
    monkeypatch.setattr(ai_pipeline_route, "LATEST_POINTER", runs_root / "ai-pipeline-latest.txt")
    _reset_incident_store(tmp_path)

    request = AIPipelineRunRequest(
        mode="mock",
        security="OFF",
        source_ip="203.0.113.250",
        username="ai-tester",
    )
    response = asyncio.run(ai_pipeline_route.run_attacks(request))
    validated = AIPipelineRunResponse.model_validate(response)

    assert validated.status == "complete"
    assert validated.count == 17
    assert validated.incident_count >= 1
    assert (runs_root / validated.run_id / "results.json").exists()
    assert (runs_root / "securewatch_wazuh.log").exists()

    incidents = incident_store.list_incidents()
    ai_incidents = [incident for incident in incidents if incident.source == "ai_pipeline"]
    assert ai_incidents
    assert all(incident.ai_pipeline_data is not None for incident in ai_incidents)


def test_ai_pipeline_results_returns_empty_without_prior_run(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(ai_pipeline_route, "RUNS_DIR", runs_root)
    monkeypatch.setattr(ai_pipeline_route, "LATEST_POINTER", runs_root / "ai-pipeline-latest.txt")

    response = ai_pipeline_route.get_results()
    validated = AIPipelineResultsResponse.model_validate(response)

    assert validated.run_id is None
    assert validated.result_count == 0
    assert validated.results == []
