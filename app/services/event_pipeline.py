from __future__ import annotations

from collections.abc import Callable
from typing import Any, Dict, List

from app.detection.registry import run_detections
from app.models.normalized_event import NormalizedEvent
from app.services.correlation_engine import correlate
from app.services.incident_builder import build_incident


def process_event(
    raw: Dict[str, Any],
    save_incident: Callable[[Dict[str, Any]], Any] | None = None,
) -> List[Dict[str, Any]]:
    event = NormalizedEvent(raw)
    detections = run_detections(event)
    correlated = correlate(detections)

    incidents = [build_incident(detection, event) for detection in correlated]
    if save_incident is not None:
        for incident in incidents:
            save_incident(incident)
    return incidents
