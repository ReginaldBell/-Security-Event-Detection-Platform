from typing import Optional


def _expected_event_ids(scenario: dict) -> set[str]:
    scenario_id = scenario["scenario_id"]
    ids = set()
    for index, event in enumerate(scenario.get("events", []), start=1):
        ids.add(str(event.get("event_id") or f"{scenario_id}-e{index:03d}"))
    return ids


def _incident_event_ids(incident: dict) -> set[str]:
    events = (((incident.get("evidence") or {}).get("events")) or [])
    return {
        str(event.get("event_id"))
        for event in events
        if isinstance(event, dict) and event.get("event_id")
    }


def _matches_expected(incident: dict, scenario: dict, expected: str) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if incident.get("type") != expected:
        failures.append("type")

    expected_subject = scenario.get("expected_subject") or {}
    subject = incident.get("subject") or {}
    for field in ("source_ip", "username"):
        expected_value = expected_subject.get(field)
        if expected_value is not None and subject.get(field) != expected_value:
            failures.append(f"subject.{field}")

    expected_mitre = scenario.get("expected_mitre")
    if expected_mitre is None:
        mitre = scenario.get("mitre")
        if isinstance(mitre, dict):
            expected_mitre = mitre.get("technique")
    if expected_mitre is not None:
        mitre = incident.get("mitre") or {}
        actual_mitre = mitre.get("technique") or incident.get("mitre_technique")
        if actual_mitre != expected_mitre:
            failures.append("mitre.technique")

    expected_severity = scenario.get("expected_severity")
    if expected_severity is not None and incident.get("severity") != expected_severity:
        failures.append("severity")

    expected_confidence = scenario.get("expected_confidence")
    if expected_confidence is not None:
        try:
            confidence_ok = abs(float(incident.get("confidence")) - float(expected_confidence)) <= 0.001
        except Exception:
            confidence_ok = False
        if not confidence_ok:
            failures.append("confidence")

    expected_ids = set(str(x) for x in scenario.get("expected_event_ids", []))
    if not expected_ids:
        expected_ids = _expected_event_ids(scenario)
    actual_ids = _incident_event_ids(incident)
    if expected_ids and not expected_ids.issubset(actual_ids):
        failures.append("evidence.event_ids")

    return not failures, failures


def validate_detection(scenario: dict, detected_incidents: list) -> dict:
    expected = scenario.get("expected_detection")
    scenario_id = scenario["scenario_id"]

    # Benign scenario: no detection expected — check for false positives
    if expected is None:
        false_positive = len(detected_incidents) > 0
        return {
            "scenario_id": scenario_id,
            "expected": None,
            "detected": false_positive,
            "detection_time": None,
            "false_positive": false_positive,
            "matched_incident_id": None,
            "unexpected_incident_ids": [i.get("incident_id") for i in detected_incidents],
            "assertion_failures": [] if not false_positive else ["unexpected_incident"],
        }

    match = False
    detection_time: Optional[str] = None
    matched_incident_id: Optional[str] = None
    assertion_failures: list[str] = []
    unexpected_incident_ids: list[str] = []

    for inc in detected_incidents:
        matched, failures = _matches_expected(inc, scenario, expected)
        if matched:
            match = True
            detection_time = inc.get("first_seen")
            matched_incident_id = inc.get("incident_id")
            break
        unexpected_incident_ids.append(inc.get("incident_id"))
        if inc.get("type") == expected:
            assertion_failures.extend(failures)

    return {
        "scenario_id": scenario_id,
        "expected": expected,
        "detected": match,
        "detection_time": detection_time,
        "false_positive": bool(unexpected_incident_ids),
        "matched_incident_id": matched_incident_id,
        "unexpected_incident_ids": unexpected_incident_ids if not match else [
            inc.get("incident_id")
            for inc in detected_incidents
            if inc.get("incident_id") != matched_incident_id
        ],
        "assertion_failures": sorted(set(assertion_failures)),
    }
