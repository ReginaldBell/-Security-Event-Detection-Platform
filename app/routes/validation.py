import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from app.simulation.runner import load_scenario, run_scenario
from app.validation.validator import validate_detection
from app.validation.scorer import compute_score

router = APIRouter(prefix="/validate", tags=["validation"])
logger = logging.getLogger(__name__)

RESULTS_FILE = Path("runs/validation_results.json")
SCENARIOS_DIR = Path("app/simulation/scenarios")
WAZUH_LOG = Path(os.environ.get("WAZUH_LOG_PATH", "runs/securewatch_wazuh.log"))


def _resolve_scenario_path(scenario_name: str) -> Path | None:
    direct = SCENARIOS_DIR / f"{scenario_name}.json"
    if direct.exists():
        return direct
    for path in sorted(SCENARIOS_DIR.glob("*.json"), key=lambda p: p.stem):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("scenario_id") == scenario_name:
            return path
    return None


def _load_results() -> list:
    if RESULTS_FILE.exists():
        try:
            return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _save_result(result: dict) -> None:
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    results = _load_results()
    results.append(result)
    RESULTS_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")


def _write_wazuh_log(result: dict) -> None:
    try:
        WAZUH_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "rule_id": "securewatch_validation",
            "timestamp": result["run_at"],
            "scenario": result["validation"]["scenario_id"],
            "detected": result["validation"]["detected"],
            "false_positive": result["validation"].get("false_positive", False),
            "score": result["score"]["score"],
            "latency_seconds": result["latency_seconds"],
        }
        with WAZUH_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.warning(f"Wazuh log write failed: {exc}")


def _get_mitre_technique(scenario_name: str) -> str | None:
    path = _resolve_scenario_path(scenario_name)
    if path is None:
        return None
    try:
        scenario = json.loads(path.read_text(encoding="utf-8"))
        mitre = scenario.get("mitre")
        if isinstance(mitre, dict):
            return mitre.get("technique")
        return mitre  # legacy string format
    except Exception:
        return None


@router.post("/{scenario_name}")
def validate_scenario(scenario_name: str, request: Request):
    path = _resolve_scenario_path(scenario_name)

    if path is None:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_name}' not found")

    scenario = load_scenario(str(path))
    start_time = datetime.now(timezone.utc)

    try:
        t0 = time.monotonic()
        ingest_url = str(request.url_for("ingest_events"))
        ingest_result = run_scenario(str(path), ingest_url=ingest_url)
        elapsed_seconds = time.monotonic() - t0
    except Exception as exc:
        logger.error(f"Scenario runner failed for '{scenario_name}': {exc}")
        raise HTTPException(status_code=502, detail=f"Scenario runner failed: {exc}")

    incidents = ingest_result.get("incidents", [])
    validation = validate_detection(scenario, incidents)
    score_data = compute_score(validation, elapsed_seconds)

    response = {
        "scenario": scenario_name,
        "scenario_name": scenario.get("name"),
        "mitre": scenario.get("mitre"),
        "validation": validation,
        "score": score_data,
        "latency_seconds": round(elapsed_seconds, 3),
        "run_at": start_time.isoformat().replace("+00:00", "Z"),
    }

    _save_result(response)
    _write_wazuh_log(response)
    return response


@router.get("/results/report")
def download_report(org: str = "Your Organization"):
    from app.reporting.report_generator import generate_report, load_results as _lr
    from fastapi.responses import PlainTextResponse
    report = generate_report(_lr(), org_name=org)
    return PlainTextResponse(content=report, media_type="text/plain")


@router.get("/results")
def list_results():
    return _load_results()


@router.get("/results/mitre-coverage")
def mitre_coverage():
    results = _load_results()
    coverage: dict = {}
    latest_by_scenario: dict[str, dict] = {}

    for r in results:
        scenario_id = r.get("scenario") or r.get("validation", {}).get("scenario_id")
        if scenario_id:
            latest_by_scenario[str(scenario_id)] = r

    for r in latest_by_scenario.values():
        expected = r.get("validation", {}).get("expected")
        if not expected:
            continue  # skip benign scenarios

        technique = _get_mitre_technique(r.get("scenario", "")) or expected
        detected = r.get("validation", {}).get("detected", False)

        if technique not in coverage:
            coverage[technique] = {"tested": 0, "detected": 0, "success_rate": 0.0}

        coverage[technique]["tested"] += 1
        if detected:
            coverage[technique]["detected"] += 1

    for tech_data in coverage.values():
        if tech_data["tested"] > 0:
            tech_data["success_rate"] = round(
                tech_data["detected"] / tech_data["tested"] * 100, 1
            )

    return coverage
