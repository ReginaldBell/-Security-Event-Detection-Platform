from __future__ import annotations

from typing import Any, Dict, Iterable, List


def correlate(detections: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    incidents: List[Dict[str, Any]] = []

    for detection in detections:
        technique_id = detection.get("technique_id")
        evidence = detection.get("evidence") or {}

        if technique_id == "T1110":
            if evidence.get("failures", 0) > 5 and evidence.get("success"):
                incidents.append(detection)

        elif technique_id == "T1021":
            if evidence.get("unique_dests", 0) > 2:
                incidents.append(detection)

        elif technique_id == "T1003":
            incidents.append(detection)

        elif technique_id == "T1059":
            if evidence.get("encoded"):
                incidents.append(detection)

    return incidents
