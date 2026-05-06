from typing import Optional

from app.ai_pipeline.dlp_secrets import max_severity as dlp_max_sev, requires_block, scan as dlp_scan
from app.ai_pipeline.llm_client import LIVE, MOCK, classify, complete
from app.ai_pipeline.controls import BLOCKED_RESPONSE, REDACTED_TOKEN, apply_input_controls, apply_output_controls
from app.ai_pipeline.risk_engine import score as compute_risk


def run_pipeline(prompt: str, security_mode: str, llm_mode: str = MOCK) -> dict:
    """
    4-layer detection pipeline: DLP → pattern controls → LLM → output controls → semantic.

    Returns a result dict consumed by scripts and the API. All callers receive
    the same structure so reporting and validation stay consistent.
    """
    layers_hit: list[str] = []
    detection_reason: Optional[str] = None
    semantic_confidence = 0.0

    # ── Layer 1: DLP scan (always-on, pre-LLM, mode-independent) ─────────────
    dlp_findings, prompt_after_dlp = dlp_scan(prompt)

    if dlp_findings:
        layers_hit.append("dlp")
        detection_reason = (
            "dlp_" + dlp_max_sev(dlp_findings) + ": "
            + ", ".join(f["finding_type"] for f in dlp_findings)
        )
        # High-certainty DLP findings stop the pipeline before the LLM is called.
        if requires_block(dlp_findings):
            rs, action = compute_risk(dlp_findings, "dlp", detection_reason, 0.0)
            return _build(
                BLOCKED_RESPONSE, detection_reason, layers_hit,
                dlp_findings, rs, action,
            )

    # ── Layer 2: Pattern controls (mode-dependent, operates on DLP-cleaned prompt) ──
    controlled_prompt, input_reason = apply_input_controls(prompt_after_dlp, security_mode)

    if controlled_prompt == BLOCKED_RESPONSE:
        if "pattern" not in layers_hit:
            layers_hit.append("pattern")
        if not detection_reason:
            detection_reason = input_reason
        rs, action = compute_risk(dlp_findings, "pattern", detection_reason, 0.0)
        return _build(BLOCKED_RESPONSE, detection_reason, layers_hit, dlp_findings, rs, action)

    # ── LLM call ──────────────────────────────────────────────────────────────
    raw_response = complete(controlled_prompt, llm_mode)

    # ── Output controls (mode-dependent) ──────────────────────────────────────
    final_response, output_reason = apply_output_controls(raw_response, security_mode)

    pattern_reason = input_reason or output_reason
    if pattern_reason:
        if "pattern" not in layers_hit:
            layers_hit.append("pattern")
        if not detection_reason:
            detection_reason = pattern_reason

    # ── Layer 3: Semantic classifier (live mode, fires after pattern layer) ───
    if llm_mode == LIVE and not pattern_reason:
        result = classify(controlled_prompt, raw_response)
        if result["detected"]:
            layers_hit.append("semantic")
            semantic_confidence = result["confidence"]
            sem_reason = (
                f"semantic: category={result['category']}"
                f" confidence={result['confidence']:.2f}"
            )
            if not detection_reason:
                detection_reason = sem_reason

    # ── Risk engine: aggregate all layer findings ──────────────────────────────
    primary = (
        "dlp"      if "dlp"      in layers_hit else
        "pattern"  if "pattern"  in layers_hit else
        "semantic" if "semantic" in layers_hit else None
    )
    rs, action = compute_risk(dlp_findings, primary, detection_reason, semantic_confidence)

    return _build(final_response, detection_reason, layers_hit, dlp_findings, rs, action)


def _build(
    response: str,
    detection_reason: Optional[str],
    layers_hit: list[str],
    dlp_findings: list[dict],
    risk_score: int,
    risk_action: str,
) -> dict:
    primary = (
        "dlp"      if "dlp"      in layers_hit else
        "pattern"  if "pattern"  in layers_hit else
        "semantic" if "semantic" in layers_hit else None
    )
    detected = (
        response == BLOCKED_RESPONSE
        or REDACTED_TOKEN in response
        or detection_reason is not None
        or bool(dlp_findings)
    )
    max_sev = dlp_max_sev(dlp_findings)
    return {
        "response":          response,
        "detected":          detected,
        "detection_reason":  detection_reason,
        "detection_layer":   primary,
        "detection_layers":  layers_hit,
        "combined_detection": len(layers_hit) >= 2,
        "dlp_findings":      dlp_findings,
        "dlp_finding_count": len(dlp_findings),
        "dlp_max_severity":  max_sev,
        "risk_score":        risk_score,
        "risk_action":       risk_action,
    }
