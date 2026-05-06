"""Explain why a detection may have failed — for CLI output and reporting."""

DETECTION_RULES: dict = {
    "credential_abuse": {
        "requires": "5+ distinct usernames AND 8+ total failures from the same source IP within 60s",
        "causes": [
            "Threshold not met — needs 5+ distinct users AND 8+ total failures from one IP within 60s",
            "Failures are not all from the same source_ip — the rule groups by IP address",
            "Events span beyond the 60-second sliding detection window",
            "Events are missing required fields: source_ip, username, or result='failure'",
            "Normalization dropped events — check for schema validation errors in logs",
        ],
    },
    "brute_force": {
        "requires": "5+ failures against the same username from the same source IP within 60s",
        "causes": [
            "Threshold not met — needs 5+ failures targeting the same user from the same IP within 60s",
            "Failures target different usernames — brute force tracks single-account attacks only",
            "Failures come from different source IPs — rule groups by (source_ip, username) pair",
            "Events span beyond the 60-second sliding detection window",
            "Events are missing required fields: source_ip, username, or result='failure'",
        ],
    },
}


def diagnose_failure(scenario: dict, detected_incidents: list) -> list[str]:
    """Return a list of human-readable causes for why the expected detection did not fire."""
    expected = scenario.get("expected_detection")
    if not expected:
        return []

    rule = DETECTION_RULES.get(expected)
    if not rule:
        return [f"No diagnostic information available for detection type '{expected}'"]

    causes = list(rule["causes"])

    # Surface any other detection types that DID fire — useful context
    detected_types = {inc.get("type") for inc in detected_incidents if inc.get("type")} - {expected}
    if detected_types:
        others = ", ".join(sorted(detected_types))
        causes.insert(0, f"Note: other detections fired ({others}) — confirm the scenario targets '{expected}'")

    return causes
