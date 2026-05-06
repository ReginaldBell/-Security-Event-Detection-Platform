from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any
from uuid import uuid4
from datetime import datetime, timezone
import json
import os
import logging
import time
from pathlib import Path
from app.services.normalization import normalize_run
from app.services.sanitization import sanitize_run
from app.services.detection import detect_run
from app.services import incident_store
from app.services import metrics as metrics_service
from app.services import correlation as correlation_service
from app.schemas.api_contract import IngestResponse
from app.schemas.incident_new import IncidentNew

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

RUNS_DIR = "runs"


@router.post("/", response_model=IngestResponse)
async def ingest_events(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    envelope_meta: Dict[str, Any] = {}
    validation_mode = False

    if isinstance(body, list):
        events = body
    elif isinstance(body, dict):
        if "events" not in body or not isinstance(body["events"], list):
            raise HTTPException(status_code=400, detail="Envelope must contain an 'events' list")
        events = body["events"]
        validation_mode = bool(body.get("validation_mode", False))
        if "source" in body and isinstance(body["source"], str):
            envelope_meta["envelope_source"] = body["source"]
        if "schema_version" in body and isinstance(body["schema_version"], str):
            envelope_meta["schema_version"] = body["schema_version"]
        if "scenario_id" in body and isinstance(body["scenario_id"], str):
            envelope_meta["scenario_id"] = body["scenario_id"]
        if "validation_run_id" in body and isinstance(body["validation_run_id"], str):
            envelope_meta["validation_run_id"] = body["validation_run_id"]
    else:
        raise HTTPException(status_code=400, detail="Body must be a JSON array or envelope object")

    if not events:
        raise HTTPException(status_code=400, detail="No events provided")

    run_id = envelope_meta.get("validation_run_id") if validation_mode else None
    if not isinstance(run_id, str) or not run_id:
        run_id = f"run-{uuid4().hex}"
    run_path = os.path.join(RUNS_DIR, run_id)
    os.makedirs(run_path, exist_ok=True)

    raw_path = os.path.join(run_path, "raw.json")
    meta_path = os.path.join(run_path, "meta.json")

    with open(raw_path, "w") as f:
        json.dump(events, f, indent=2)

    meta = {
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_count": len(events),
        "validation_mode": validation_mode,
        **envelope_meta,
    }

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Created run {run_id} with {len(events)} raw events")

    # Normalization (best effort, does not affect response)
    normalization_status = "pending"
    norm_stats = None
    try:
        norm_started = time.perf_counter()
        norm_stats = normalize_run(run_id=run_id, runs_root=Path("runs"))
        norm_ms = round((time.perf_counter() - norm_started) * 1000, 3)
        logger.info(f"[NORM] run {run_id} normalized in {norm_ms}ms")
        normalization_status = "success"
    except Exception as e:
        logger.error(f"Normalization failed for {run_id}: {str(e)}")
        normalization_status = "failed"
        if validation_mode:
            raise HTTPException(status_code=500, detail=f"Normalization failed: {e}")

    # Sanitization — PII tokenization + IP abstraction (best effort)
    sanitization_source = "normalized.json"
    if normalization_status == "success" and not validation_mode:
        try:
            san_started = time.perf_counter()
            sanitize_run(run_id=run_id, runs_root=Path("runs"))
            san_ms = round((time.perf_counter() - san_started) * 1000, 3)
            logger.info(f"[SAN] run {run_id} sanitized in {san_ms}ms")
            sanitization_source = "sanitized.json"
        except Exception as e:
            logger.warning(f"Sanitization failed for {run_id}, falling back to normalized: {str(e)}")

    # Detection (best effort, does not affect response)
    detection_status = "pending"
    lifecycle_incidents = []
    try:
        detection_started = time.perf_counter()
        detect_run(run_id=run_id, runs_root=Path("runs"), source_file=sanitization_source)
        detection_ms = round((time.perf_counter() - detection_started) * 1000, 3)
        logger.info(f"[DET] run {run_id} processed in {detection_ms}ms")
        detection_status = "success"
    except Exception as e:
        logger.error(f"Detection failed for {run_id}: {str(e)}")
        detection_status = "failed"
        if validation_mode:
            raise HTTPException(status_code=500, detail=f"Detection failed: {e}")

    if detection_status == "success":
        try:
            # Lifecycle + deduplication layer (stateful, persisted separately)
            run_incidents_path = Path("runs") / run_id / "incidents.json"
            detected_incidents = json.loads(run_incidents_path.read_text(encoding="utf-8"))
            if isinstance(detected_incidents, list):
                for raw_incident in detected_incidents:
                    try:
                        incident = IncidentNew.model_validate(raw_incident)
                        if validation_mode:
                            lifecycle_incidents.append(incident_store.incident_to_response(incident))
                        else:
                            managed = incident_store.upsert_incident(incident)
                            lifecycle_incidents.append(incident_store.incident_to_response(managed))
                            # Chain correlation sidecar — best effort
                            try:
                                correlation_service.correlate_incident(managed)
                            except Exception as corr_exc:
                                logger.warning(f"Correlation failed for {managed.incident_id}: {corr_exc}")
                    except Exception as upsert_exc:
                        logger.warning(f"Incident lifecycle upsert failed for {run_id}: {upsert_exc}")
                        if validation_mode:
                            raise HTTPException(status_code=500, detail=f"Incident lifecycle failed: {upsert_exc}")
        except Exception as e:
            if isinstance(e, HTTPException):
                raise
            logger.warning(f"Incident lifecycle processing failed for {run_id}: {e}")
            if validation_mode:
                raise HTTPException(status_code=500, detail=f"Incident lifecycle failed: {e}")

    # Update structured metrics (best effort — never breaks ingest)
    if norm_stats is not None:
        try:
            run_dir = Path("runs") / run_id
            normalized_events = json.loads((run_dir / "normalized.json").read_text(encoding="utf-8"))
            incidents_data = json.loads((run_dir / "incidents.json").read_text(encoding="utf-8"))
            metrics_service.record_ingest(norm_stats, normalized_events, incidents_data)
        except Exception as e:
            logger.warning(f"Metrics update failed for {run_id}: {e}")

    return {
        "run_id": run_id,
        "event_count": len(events),
        "normalization_status": normalization_status,
        "detection_status": detection_status,
        "incident_count": len(lifecycle_incidents),
        "incidents": lifecycle_incidents,
    }
