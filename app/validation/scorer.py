def compute_score(validation_result: dict, elapsed_seconds: float) -> dict:
    expected = validation_result.get("expected")

    # Benign scenario: no detection expected
    if expected is None:
        if validation_result.get("false_positive"):
            return {"score": 0, "status": "false_positive", "latency_seconds": elapsed_seconds}
        return {"score": 100, "status": "pass", "latency_seconds": elapsed_seconds}

    if not validation_result["detected"]:
        return {"score": 0, "status": "fail", "latency_seconds": elapsed_seconds}

    if validation_result.get("false_positive") or validation_result.get("unexpected_incident_ids"):
        return {"score": 0, "status": "false_positive", "latency_seconds": elapsed_seconds}

    score = 70
    if elapsed_seconds < 5:
        score += 30
    elif elapsed_seconds < 15:
        score += 15

    return {"score": score, "status": "pass", "latency_seconds": elapsed_seconds}
