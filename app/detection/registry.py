from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

DetectionResult = Dict[str, Any]
Detection = Callable[[Any], Optional[DetectionResult]]

DETECTIONS: List[Detection] = []
_REQUIRED_RESULT_FIELDS = {"technique_id", "detection_id", "evidence", "confidence"}


def _validate_detection_result(result: DetectionResult) -> None:
    missing = _REQUIRED_RESULT_FIELDS.difference(result)
    if missing:
        raise ValueError(f"Detection result missing required fields: {sorted(missing)}")
    if not isinstance(result["evidence"], dict):
        raise ValueError("Detection result evidence must be a dict")


def register(det: Detection) -> Detection:
    DETECTIONS.append(det)
    return det


def run_detections(event: Any) -> List[DetectionResult]:
    results: List[DetectionResult] = []
    for detection in DETECTIONS:
        result = detection(event)
        if result:
            _validate_detection_result(result)
            results.append(result)
    return results
