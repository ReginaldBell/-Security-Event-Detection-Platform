import json
import os
import hashlib
from datetime import datetime, timedelta, timezone
import requests

INGEST_URL = os.environ.get("SECUREWATCH_INGEST_URL")
DEFAULT_BASE_TIME = "2026-01-01T00:00:00Z"


def load_scenario(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _parse_base_time(value: str | None) -> datetime:
    raw = value or DEFAULT_BASE_TIME
    if raw.endswith("Z"):
        return datetime.fromisoformat(raw[:-1]).replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def deterministic_run_id(scenario_id: str, base_time: str | None = None) -> str:
    seed_time = _parse_base_time(base_time).isoformat().replace("+00:00", "Z")
    digest = hashlib.sha256(f"{scenario_id}|{seed_time}".encode("utf-8")).hexdigest()[:24]
    return f"vrun-{digest}"


def run_scenario(path: str, ingest_url: str | None = None) -> dict:
    scenario = load_scenario(path)
    scenario_id = scenario["scenario_id"]
    base_time_raw = scenario.get("base_time") or DEFAULT_BASE_TIME
    base_time = _parse_base_time(base_time_raw)
    validation_run_id = scenario.get("validation_run_id") or deterministic_run_id(
        scenario_id,
        base_time_raw,
    )

    events = []
    for index, e in enumerate(scenario["events"], start=1):
        event = dict(e)
        event_time = base_time + timedelta(seconds=event.pop("timestamp_offset", 0))
        event["timestamp"] = event_time.isoformat().replace("+00:00", "Z")
        event.setdefault("event_id", f"{scenario_id}-e{index:03d}")
        event.setdefault("scenario_id", scenario_id)
        event.setdefault("validation_run_id", validation_run_id)
        events.append(event)

    payload = {
        "events": events,
        "source": "scenario",
        "schema_version": "validation.v1",
        "scenario_id": scenario_id,
        "validation_run_id": validation_run_id,
        "validation_mode": True,
    }
    target_url = ingest_url or INGEST_URL
    if not target_url:
        raise RuntimeError("SECUREWATCH_INGEST_URL is not set and no ingest_url was supplied")
    response = requests.post(target_url, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()
