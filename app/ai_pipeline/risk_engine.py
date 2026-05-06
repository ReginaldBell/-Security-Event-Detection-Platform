"""
Unified risk engine — aggregates DLP, pattern, and semantic findings into a
single score and decision action.

Score → Action:
  >= 100  block       DLP critical or multi-layer combined hit
  80–99   block       DLP high / semantic high-confidence
  60–79   redact      DLP medium or lower-confidence high
  40–59   redact      pattern match only
  20–39   warn        semantic low-confidence
  0–19    allow       no findings

Decision actions: allow | warn | redact | block | alert_only
"""

from typing import Optional

ALLOW      = "allow"
WARN       = "warn"
REDACT     = "redact"
BLOCK      = "block"
ALERT_ONLY = "alert_only"

_SEVERITY_BASE = {"critical": 100, "high": 80, "medium": 50, "low": 20}


def score(
    dlp_findings: list[dict],
    detection_layer: Optional[str],
    detection_reason: Optional[str],
    semantic_confidence: float = 0.0,
) -> tuple[int, str]:
    """
    Returns (risk_score, action).

    Layers are scored independently then combined. Multi-layer hits always
    escalate to block because correlated signals indicate higher attacker intent.
    """
    total = 0
    layers_active = 0

    # ── DLP component ─────────────────────────────────────────────────────────
    if dlp_findings:
        layers_active += 1
        peak = max(_SEVERITY_BASE.get(f["severity"], 0) for f in dlp_findings)
        total += peak
        # Each additional finding beyond the first adds 10 points.
        total += 10 * (len(dlp_findings) - 1)

    # ── Pattern component ──────────────────────────────────────────────────────
    if detection_layer == "pattern" or (
        detection_reason
        and any(
            detection_reason.startswith(p)
            for p in ("input_blocked", "input_filtered", "output_redacted")
        )
    ):
        layers_active += 1
        total += 50

    # ── Semantic component ─────────────────────────────────────────────────────
    if detection_layer == "semantic" or semantic_confidence > 0:
        layers_active += 1
        if semantic_confidence >= 0.80:
            total += 85
        elif semantic_confidence >= 0.50:
            total += 50
        else:
            total += 25

    # Multi-layer escalation: two or more layers always warrant a block.
    if layers_active >= 2:
        total = max(total, 100)

    # ── Map score to action ────────────────────────────────────────────────────
    if total >= 80:
        action = BLOCK
    elif total >= 40:
        action = REDACT
    elif total >= 20:
        action = WARN
    else:
        action = ALLOW

    return total, action
