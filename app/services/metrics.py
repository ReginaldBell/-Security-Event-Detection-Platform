from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from app.db.database import get_session
from app.db.models import MetricRow

logger = logging.getLogger(__name__)

# Legacy path — read once on first startup for migration, then ignored.
_LEGACY_METRICS_FILE = Path("runs/metrics.json")

_lock = threading.Lock()

_DEFAULT_COUNTERS: Dict[str, Any] = {
    "events_ingested_total": 0,
    "normalized_success_total": 0,
    "telemetry_rejected_total": 0,
    "missing_required_total": 0,
    "events_by_source": {},
    "incidents_total": {},
    "runs_total": 0,
    "incidents_created_total": 0,
    "incidents_updated_total": 0,
    "incidents_reopened_total": 0,
    "incidents_closed_total": 0,
}

_counters: Dict[str, Any] = json.loads(json.dumps(_DEFAULT_COUNTERS))

_METRICS_KEY = "counters"


def _ensure_counter_shape() -> None:
    for key, value in _DEFAULT_COUNTERS.items():
        if key not in _counters:
            _counters[key] = json.loads(json.dumps(value))


def _persist() -> None:
    try:
        with get_session() as session:
            session.merge(MetricRow(
                key=_METRICS_KEY,
                value=json.dumps(_counters),
            ))
    except Exception as exc:
        logger.warning(f"Failed to persist metrics: {exc}")


def record_ingest(
    norm_stats: Dict[str, int],
    normalized_events: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> None:
    with _lock:
        _ensure_counter_shape()
        _counters["events_ingested_total"] += norm_stats.get("raw", 0)
        _counters["normalized_success_total"] += norm_stats.get("normalized", 0)
        _counters["telemetry_rejected_total"] += norm_stats.get("telemetry_rejected", 0)
        _counters["missing_required_total"] += norm_stats.get("dropped", 0)
        _counters["runs_total"] += 1

        by_source = _counters["events_by_source"]
        for event in normalized_events:
            src = event.get("source") or "unknown"
            by_source[src] = by_source.get(src, 0) + 1

        by_type = _counters["incidents_total"]
        for inc in incidents:
            t = inc.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        _persist()


def increment_counter(name: str, amount: int = 1) -> None:
    with _lock:
        _ensure_counter_shape()
        if name not in _counters:
            _counters[name] = 0
        if not isinstance(_counters.get(name), int):
            raise ValueError(f"Metric '{name}' is not an integer counter")
        _counters[name] += amount
        _persist()


def get_metrics() -> Dict[str, Any]:
    with _lock:
        _ensure_counter_shape()
        return json.loads(json.dumps(_counters))


def rehydrate(runs_root: Path) -> None:
    global _counters

    # 1. Try loading from DB.
    try:
        with get_session() as session:
            row = session.query(MetricRow).filter(MetricRow.key == _METRICS_KEY).first()
            if row is not None:
                data = json.loads(row.value)
                if isinstance(data, dict) and "events_ingested_total" in data:
                    with _lock:
                        _counters.update(data)
                        _ensure_counter_shape()
                    logger.info("Metrics rehydrated from database")
                    return
    except Exception as exc:
        logger.warning(f"Failed to load metrics from DB: {exc}")

    # 2. One-time migration: load from legacy metrics.json if present.
    if _LEGACY_METRICS_FILE.exists():
        try:
            data = json.loads(_LEGACY_METRICS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "events_ingested_total" in data:
                with _lock:
                    _counters.update(data)
                    _ensure_counter_shape()
                    _persist()
                logger.info("Metrics migrated from JSON to database")
                return
        except Exception as exc:
            logger.warning(f"Failed to read legacy metrics.json: {exc}")

    # 3. Fall back: rebuild from run artifacts on disk.
    if not runs_root.exists():
        return

    run_dirs = sorted(runs_root.iterdir())
    total_raw = 0
    total_norm = 0
    total_runs = 0
    by_source: Dict[str, int] = defaultdict(int)
    by_type: Dict[str, int] = defaultdict(int)

    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue

        meta_path = run_dir / "meta.json"
        norm_path = run_dir / "normalized.json"
        inc_path = run_dir / "incidents.json"

        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                total_raw += meta.get("event_count", 0)
                total_runs += 1
            except Exception:
                continue

        if norm_path.exists():
            try:
                events = json.loads(norm_path.read_text(encoding="utf-8"))
                if isinstance(events, list):
                    total_norm += len(events)
                    for ev in events:
                        src = ev.get("source") or "unknown"
                        by_source[src] += 1
            except Exception:
                pass

        if inc_path.exists():
            try:
                incidents = json.loads(inc_path.read_text(encoding="utf-8"))
                if isinstance(incidents, list):
                    for inc in incidents:
                        t = inc.get("type", "unknown")
                        by_type[t] += 1
            except Exception:
                pass

    with _lock:
        _counters.clear()
        _counters.update(json.loads(json.dumps(_DEFAULT_COUNTERS)))
        _counters["events_ingested_total"] = total_raw
        _counters["normalized_success_total"] = total_norm
        _counters["missing_required_total"] = max(total_raw - total_norm, 0)
        _counters["telemetry_rejected_total"] = 0
        _counters["events_by_source"] = dict(by_source)
        _counters["incidents_total"] = dict(by_type)
        _counters["runs_total"] = total_runs
        _ensure_counter_shape()
        _persist()

    logger.info(f"Metrics rehydrated from {total_runs} run artifacts")
