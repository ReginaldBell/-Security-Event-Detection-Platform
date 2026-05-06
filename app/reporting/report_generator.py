"""Generate client-ready detection validation reports from stored results."""

import json
from datetime import datetime, timezone
from pathlib import Path

RESULTS_FILE = Path("runs/validation_results.json")
SCENARIOS_DIR = Path("app/simulation/scenarios")

DETECTION_DISPLAY = {
    "credential_abuse": "Password Spraying / Credential Abuse",
    "brute_force": "Brute Force Authentication",
}

MITRE_DISPLAY = {
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1078": "Valid Accounts",
    "T1566": "Phishing",
}

RECOMMENDATIONS = {
    "credential_abuse": [
        "Enable per-IP multi-account authentication failure alerting",
        "Tune credential abuse thresholds — lower distinct_user limit for sensitive environments",
        "Ensure all authentication sources forward source_ip in log events",
        "Deploy MFA to reduce impact of password spray success",
    ],
    "brute_force": [
        "Enable authentication failure logging on all endpoints and VPNs",
        "Lower brute force failure threshold for privileged and service accounts",
        "Implement account lockout or request throttling policies",
        "Alert on repeated failures against service accounts specifically",
    ],
}


def _load_scenarios_meta() -> dict:
    meta = {}
    for p in SCENARIOS_DIR.glob("*.json"):
        try:
            meta[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return meta


def load_results() -> list:
    if not RESULTS_FILE.exists():
        return []
    try:
        return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def generate_report(results: list, org_name: str = "Your Organization") -> str:
    if not results:
        return "No validation results found. Run scenarios first with: python run_validation.py <scenario>\n"

    scenarios_meta = _load_scenarios_meta()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sep = "=" * 62
    lines = []

    def section(title: str) -> None:
        lines.append("")
        lines.append(title)
        lines.append("─" * len(title))

    # ── Header ───────────────────────────────────────────────────
    lines.append(sep)
    lines.append(f"  Detection Validation Report — {org_name}")
    lines.append(f"  Generated: {now}")
    lines.append(sep)

    # ── Partition results ─────────────────────────────────────────
    attack_runs = [r for r in results if r.get("validation", {}).get("expected")]
    benign_runs = [r for r in results if not r.get("validation", {}).get("expected")]

    detected_count = sum(1 for r in attack_runs if r["validation"]["detected"])
    false_positives = sum(1 for r in benign_runs if r["validation"].get("false_positive"))
    latencies = [r["latency_seconds"] for r in results if r.get("latency_seconds") is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    scores = [r["score"]["score"] for r in results if r.get("score")]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    # ── Executive Summary ─────────────────────────────────────────
    section("EXECUTIVE SUMMARY")
    lines.append(f"  Techniques Tested:    {len(attack_runs)}")
    lines.append(f"  Techniques Detected:  {detected_count}/{len(attack_runs)}")
    if benign_runs:
        lines.append(f"  False Positives:      {false_positives}/{len(benign_runs)} benign scenarios")
    lines.append(f"  Average Latency:      {avg_latency:.1f}s")
    lines.append(f"  Average Score:        {avg_score:.0f}/100")

    # ── MITRE Coverage ────────────────────────────────────────────
    section("MITRE ATT&CK COVERAGE")
    coverage: dict = {}
    for r in attack_runs:
        scenario = scenarios_meta.get(r.get("scenario", ""), {})
        mitre = scenario.get("mitre")
        technique = (mitre.get("technique") if isinstance(mitre, dict) else mitre) \
                    or r["validation"].get("expected", "unknown")
        tactic = mitre.get("tactic", "") if isinstance(mitre, dict) else ""
        if technique not in coverage:
            coverage[technique] = {"tactic": tactic, "tested": 0, "detected": 0}
        coverage[technique]["tested"] += 1
        if r["validation"]["detected"]:
            coverage[technique]["detected"] += 1

    if coverage:
        for tech, data in sorted(coverage.items()):
            rate = data["detected"] / data["tested"] * 100 if data["tested"] else 0
            icon = "✓" if data["detected"] == data["tested"] else ("~" if data["detected"] > 0 else "✗")
            label = MITRE_DISPLAY.get(tech, tech)
            tactic_str = f"  ({data['tactic']})" if data["tactic"] else ""
            lines.append(f"  {icon}  {tech:<14} {label}{tactic_str}")
            lines.append(f"            Detected {data['detected']}/{data['tested']} runs  ({rate:.0f}%)")
    else:
        lines.append("  No attack scenarios have been run yet.")

    # ── High Risk Gaps ────────────────────────────────────────────
    gaps = {t: d for t, d in coverage.items() if d["detected"] == 0}
    section("HIGH RISK GAPS")
    if gaps:
        for tech, data in gaps.items():
            label = MITRE_DISPLAY.get(tech, tech)
            tactic_str = f"  [{data['tactic']}]" if data["tactic"] else ""
            lines.append(f"  ✗  {tech}  {label}{tactic_str}")
            lines.append(f"       Not detected across all {data['tested']} run(s)")
    else:
        lines.append("  None — all tested techniques were detected.")

    # ── False Positive Analysis ───────────────────────────────────
    if benign_runs:
        section("FALSE POSITIVE ANALYSIS")
        fp_runs = [r for r in benign_runs if r["validation"].get("false_positive")]
        if fp_runs:
            for r in fp_runs:
                name = r.get("scenario_name") or r.get("scenario", "unknown")
                lines.append(f"  ✗  '{name}' triggered unexpected alerts")
            lines.append("")
            lines.append("  Action: Review detection thresholds for over-sensitivity.")
        else:
            lines.append("  ✓  No false positives — all benign scenarios passed cleanly.")

    # ── Recommendations ───────────────────────────────────────────
    section("RECOMMENDATIONS")
    undetected_types: set = set()
    for r in attack_runs:
        if not r["validation"]["detected"]:
            undetected_types.add(r["validation"].get("expected", ""))

    if undetected_types:
        for det_type in sorted(undetected_types):
            recs = RECOMMENDATIONS.get(det_type, [])
            label = DETECTION_DISPLAY.get(det_type, det_type)
            lines.append(f"  For {label}:")
            for rec in recs:
                lines.append(f"    • {rec}")
            lines.append("")
    else:
        lines.append("  All tested techniques are currently being detected.")
        lines.append("  Consider expanding coverage to additional MITRE techniques.")

    lines.append("")
    lines.append(sep)
    lines.append("")
    return "\n".join(lines)
