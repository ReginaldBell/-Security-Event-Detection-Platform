from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.schemas.event_models_new import NormalizedEventNew as NormalizedEvent
from app.schemas.incident_new import IncidentNew as Incident
from app.services.investigation_playbooks import get_investigation_playbook
from app.services.playbook_registry import get_playbook_by_technique
from app.services.risk_engine import compute_risk, risk_level


MITRE_T1110 = "T1110"
MITRE_T1110_003 = "T1110.003"
MITRE_TACTIC_CREDENTIAL_ACCESS = "Credential Access"
MITRE_TECHNIQUE_BRUTE_FORCE = "Brute Force"
MITRE_TECHNIQUE_PASSWORD_SPRAYING = "Password Spraying"

WINDOW_SECONDS = 60
BRUTE_FORCE_FAILURE_THRESHOLD = 5
CRED_ABUSE_DISTINCT_USER_THRESHOLD = 5
CRED_ABUSE_FAILURE_THRESHOLD = 8
COMPROMISE_CORRELATION_SECONDS = 300


class _RiskSubject:
    def __init__(self, user: Optional[str], src: Optional[str], dest: Optional[str]):
        self.user = user
        self.src = src
        self.dest = dest


def _locked_detection_from_incident(incident: dict) -> dict:
    technique_id = incident.get("mitre_technique", "GENERIC")
    evidence = incident.get("evidence") or {}
    counts = evidence.get("counts") or {}
    timeline = evidence.get("timeline") or []
    command_lines = [
        str(item.get("command_line") or "").lower()
        for item in timeline
        if isinstance(item, dict)
    ]
    return {
        "technique_id": technique_id,
        "detection_id": incident.get("type", "incident_detection"),
        "evidence": {
            "failures": counts.get("failures", 0),
            "success": counts.get("success_after_failure", 0) > 0,
            "unique_ips": incident.get("source_count", 0),
            "unique_dests": counts.get("unique_dests", 0),
            "encoded": any("-enc" in cmd or "-encodedcommand" in cmd for cmd in command_lines),
        },
        "confidence": incident.get("confidence", 0.0),
    }


def _finalize_incident(incident: dict) -> dict:
    detection = _locked_detection_from_incident(incident)
    subject = incident.get("subject") or {}
    risk_subject = _RiskSubject(
        user=subject.get("username"),
        src=subject.get("source_ip"),
        dest=subject.get("host") or incident.get("dest"),
    )
    score = compute_risk(detection, risk_subject)
    playbook = get_playbook_by_technique(detection["technique_id"])
    incident.setdefault("playbook_id", playbook["id"])
    incident.setdefault("risk_score", score)
    incident.setdefault("risk_level", risk_level(score))
    incident.setdefault("detection_id", detection["detection_id"])
    obj = Incident(**incident)
    data = obj.model_dump(exclude_unset=True)
    if not data.get("investigation"):
        data["investigation"] = get_investigation_playbook(obj)
    return Incident(**data).model_dump(exclude_unset=True)

def _phase4_summary(incident: dict) -> str:
    technique = incident.get("mitre_technique", "T1110")
    subject = incident.get("subject") or {}
    evidence = incident.get("evidence") or {}
    counts = evidence.get("counts") or {}

    username = subject.get("username", "unknown")
    source_ip = subject.get("source_ip", "unknown")
    failures = counts.get("failures", 0)
    ws = evidence.get("window_start", "unknown")
    we = evidence.get("window_end", "unknown")

    return (
        f"Brute-force authentication activity detected (MITRE {technique}): "
        f"{failures} failed login attempts against user '{username}' from source IP {source_ip} "
        f"during {ws}–{we}, exceeding brute-force threshold."
    )


def _phase4_summary_cred_abuse(incident: dict) -> str:
    """Generate summary for credential abuse (password spraying) incidents."""
    subject = incident.get("subject") or {}
    evidence = incident.get("evidence") or {}
    counts = evidence.get("counts") or {}

    source_ip = subject.get("source_ip", "unknown")
    failures = counts.get("failures", 0)
    distinct_users = counts.get("distinct_users", 0)
    ws = evidence.get("window_start", "unknown")
    we = evidence.get("window_end", "unknown")

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(source_ip)))
    source_label = f"source IP {source_ip}" if is_ip else f"workstation {source_ip} (NTLM path — IP not logged)"

    return (
        f"Potential Credential Abuse detected (MITRE T1110.003 - Password Spraying): "
        f"{failures} failed login attempts across {distinct_users} distinct accounts "
        f"from {source_label} during {ws}–{we}. "
        "This pattern is indicative of compromised credentials or unauthorized access attempts."
    )


def _phase4_recommended_actions() -> list[str]:
    return [
        "Validate whether the source IP and login pattern are expected for this user (VPNs, known locations, automation).",
        "Review authentication activity before and after the detection window to identify escalation or successful access.",
        "Assess account controls (lockout behavior, MFA enforcement) and confirm whether the user experienced authentication issues.",
        "If activity is unauthorized, follow response policy: reset credentials, revoke active sessions, and apply network controls as appropriate."
    ]


def _phase4_apply_explainability(incident: dict) -> dict:
    incident["summary"] = _phase4_summary(incident)
    incident["recommended_actions"] = _phase4_recommended_actions()
    return incident


def _phase4_apply_explainability_cred_abuse(incident: dict) -> dict:
    incident["summary"] = _phase4_summary_cred_abuse(incident)
    incident["recommended_actions"] = _phase4_recommended_actions()
    return incident


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _stable_incident_id(seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"inc_{h[:24]}"


def _is_failure(ev: Dict[str, Any]) -> bool:
    r = ev.get("result")
    return isinstance(r, str) and r.lower() == "failure"


def _is_auth_event(ev: Dict[str, Any]) -> bool:
    event_type = ev.get("event_type")
    if not isinstance(event_type, str):
        return False
    normalized = event_type.strip().lower()
    return (
        "login" in normalized
        or "auth" in normalized
        or normalized in {"signin", "sign_in", "sign-in"}
    )


def _is_success(ev: Dict[str, Any]) -> bool:
    r = ev.get("result")
    return isinstance(r, str) and r.lower() == "success"


def _is_process_event(ev: Dict[str, Any]) -> bool:
    event_type = ev.get("event_type")
    if not isinstance(event_type, str):
        return False
    return event_type.strip().lower() in {"process_start", "process_create", "process_creation"}


def _is_suspicious_process(ev: Dict[str, Any]) -> bool:
    process_name = str(ev.get("process_name") or "").lower()
    command_line = str(ev.get("command_line") or "").lower()
    suspicious_names = ("powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe", "mshta.exe")
    suspicious_args = (" -enc", "-encodedcommand", "downloadstring", "invoke-webrequest", "iex ")
    return any(name in process_name for name in suspicious_names) or any(arg in command_line for arg in suspicious_args)


def _raise_severity(severity: str) -> str:
    order = ["low", "medium", "high", "critical"]
    if severity not in order:
        return "high"
    return order[min(order.index(severity) + 1, len(order) - 1)]


def _severity_and_confidence(count: int) -> Tuple[str, float]:
    if count >= 20:
        return ("high", 0.95)
    if count >= 10:
        return ("medium", 0.85)
    return ("low", 0.70)


def _window_bounds(window: Deque[Tuple[datetime, Dict[str, Any]]]) -> Tuple[str, str]:
    start = window[0][0].isoformat().replace("+00:00", "Z")
    end = window[-1][0].isoformat().replace("+00:00", "Z")
    return start, end


def _event_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ev in events:
        out.append(
            {
                "timestamp": ev.get("timestamp"),
                "event_type": ev.get("event_type"),
                "result": ev.get("result"),
                "reason": ev.get("reason"),
                "username": ev.get("username"),
                "process_name": ev.get("process_name"),
                "command_line": ev.get("command_line"),
                "location": ev.get("location"),
            }
        )
    return out


def _apply_cross_source_correlation(
    incidents: List[Dict[str, Any]],
    validated: List[Tuple[datetime, Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    if not incidents:
        return incidents

    out = list(incidents)
    emitted_ids = {inc.get("incident_id") for inc in out}
    correlation_delta = timedelta(seconds=COMPROMISE_CORRELATION_SECONDS)

    for incident in out:
        if incident.get("type") not in {"brute_force", "credential_abuse"}:
            continue
        subject = incident.get("subject") or {}
        user = subject.get("username")
        ip = subject.get("source_ip")
        last_seen = _parse_ts(str(incident.get("last_seen") or ""))
        if last_seen is None:
            continue

        success_events = []
        for dt, ev in validated:
            if dt < last_seen or dt > last_seen + correlation_delta:
                continue
            if not (_is_auth_event(ev) and _is_success(ev)):
                continue
            same_user = user == "multiple_accounts" or ev.get("username") == user
            same_source = ev.get("source_ip") == ip
            if same_user and same_source:
                success_events.append((dt, ev))

        if success_events:
            incident["severity"] = _raise_severity(str(incident.get("severity", "low")))
            incident["confidence"] = min(float(incident.get("confidence", 0.7)) + 0.05, 0.99)
            flags = set(incident.get("correlation_flags") or [])
            flags.add("bruteforce_then_success")
            incident["correlation_flags"] = sorted(flags)
            incident["chain_confidence"] = max(float(incident.get("chain_confidence") or 0), 0.78)
            incident.setdefault("evidence", {}).setdefault("counts", {})["success_after_failure"] = len(success_events)
            actions = incident.setdefault("recommended_actions", [])
            action = "Escalate if the success event is not expected; review session activity and revoke active sessions if unauthorized."
            if action not in actions:
                actions.append(action)

        for success_dt, success_ev in success_events:
            success_user = success_ev.get("username")
            if not isinstance(success_user, str) or not success_user:
                continue
            suspicious_events = [
                ev
                for dt, ev in validated
                if success_dt <= dt <= success_dt + correlation_delta
                and ev.get("username") == success_user
                and _is_process_event(ev)
                and _is_suspicious_process(ev)
            ]
            if not suspicious_events:
                continue

            first_process = suspicious_events[0]
            start_ts = success_dt.isoformat().replace("+00:00", "Z")
            end_ts = str(first_process.get("timestamp") or start_ts)
            host = first_process.get("source_ip") or success_ev.get("source_ip") or "unknown"
            seed = f"possible_compromise|{success_user}|{host}|{start_ts}"
            incident_id = _stable_incident_id(seed)
            if incident_id in emitted_ids:
                continue
            emitted_ids.add(incident_id)

            evidence_events = [success_ev] + suspicious_events
            compromise = {
                "incident_id": incident_id,
                "type": "possible_compromise",
                "mitre_technique": "T1059",
                "mitre": {
                    "tactic": "Execution",
                    "technique": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                },
                "severity": "high",
                "confidence": 0.88,
                "first_seen": start_ts,
                "last_seen": end_ts,
                "affected_entities": sorted({str(host), success_user}),
                "evidence_count": len(evidence_events),
                "source_count": len({e.get("source") for e in evidence_events if e.get("source")}),
                "summary": (
                    f"Possible account compromise chain: successful login for '{success_user}' "
                    "followed by suspicious process execution within 5 minutes."
                ),
                "recommended_actions": [
                    "Validate whether the login and process execution were expected.",
                    "Collect endpoint process tree and network connections for the host.",
                    "Reset credentials and revoke sessions if activity is unauthorized.",
                    "Escalate to Tier 2 if encoded commands, lateral movement, or privileged access are present.",
                ],
                "correlation_flags": ["bruteforce_then_success", "process_after_auth"],
                "chain_confidence": 0.85,
                "explanation": {
                    "threshold": 1,
                    "observed": len(suspicious_events),
                    "window": f"{COMPROMISE_CORRELATION_SECONDS}s",
                    "trigger_field": "username",
                },
                "subject": {"source_ip": str(host), "username": success_user},
                "evidence": {
                    "window_start": start_ts,
                    "window_end": end_ts,
                    "counts": {
                        "login_successes": 1,
                        "suspicious_processes": len(suspicious_events),
                    },
                    "timeline": _event_timeline(evidence_events),
                    "events": evidence_events,
                },
            }
            try:
                out.append(_finalize_incident(compromise))
            except Exception:
                continue

    return out


def detect_incidents(normalized_events: Any) -> List[Dict[str, Any]]:
    if not isinstance(normalized_events, list):
        return []

    # Validate + ensure deterministic ordering
    validated: List[Tuple[datetime, Dict[str, Any]]] = []
    for item in normalized_events:
        if not isinstance(item, dict):
            continue
        try:
            ev_obj = NormalizedEvent(**item)
            ev = ev_obj.model_dump()
        except Exception:
            continue

        ts = ev.get("timestamp")
        if not isinstance(ts, str):
            continue
        dt = _parse_ts(ts)
        if dt is None:
            continue
        validated.append((dt, ev))

    validated.sort(key=lambda x: x[0])

    # Sliding window over failures only (used by credential abuse detector)
    win: Deque[Tuple[datetime, Dict[str, Any]]] = deque()
    out_incidents: List[Dict[str, Any]] = []

    emitted: set[str] = set()
    incident_index_by_id: Dict[str, int] = {}

    window_delta = timedelta(seconds=WINDOW_SECONDS)
    brute_force_windows: Dict[Tuple[str, str], Deque[Tuple[datetime, Dict[str, Any]]]] = {}
    active_bruteforce: Dict[Tuple[str, str], Dict[str, Any]] = {}
    credential_abuse_windows: Dict[str, Deque[Tuple[datetime, Dict[str, Any]]]] = {}

    for dt, ev in validated:
        if not _is_failure(ev) or not _is_auth_event(ev):
            continue

        # Brute-force state machine: one active incident per (ip, username)
        # per 60-second detection window anchored to the incident start.
        ip = ev.get("source_ip")
        user = ev.get("username")
        if isinstance(ip, str) and ip and isinstance(user, str) and user:
            pair = (ip, user)
            pair_window = brute_force_windows.setdefault(pair, deque())
            active_state = active_bruteforce.get(pair)

            if active_state is not None:
                start_dt = active_state["start_dt"]
                if (dt - start_dt) > window_delta:
                    active_bruteforce.pop(pair, None)
                    pair_window.clear()
                    active_state = None

            pair_window.append((dt, ev))
            while pair_window and (dt - pair_window[0][0]) > window_delta:
                pair_window.popleft()

            if active_state is None and len(pair_window) >= BRUTE_FORCE_FAILURE_THRESHOLD:
                start_dt = pair_window[0][0]
                start_ts = start_dt.isoformat().replace("+00:00", "Z")
                end_ts = dt.isoformat().replace("+00:00", "Z")
                entities = sorted([ip, user])
                seed = f"brute_force|{'|'.join(entities)}|{start_ts}"
                incident_id = _stable_incident_id(seed)
                if incident_id in emitted:
                    active_bruteforce[pair] = {"incident_id": incident_id, "start_dt": start_dt}
                    continue

                evidence_events = [item[1] for item in pair_window]
                evidence_count = len(evidence_events)
                sev, conf = _severity_and_confidence(evidence_count)

                incident = {
                    "incident_id": incident_id,
                    "type": "brute_force",
                    "mitre_technique": MITRE_T1110,
                    "mitre": {
                        "tactic": MITRE_TACTIC_CREDENTIAL_ACCESS,
                        "technique": MITRE_T1110,
                        "technique_name": MITRE_TECHNIQUE_BRUTE_FORCE,
                    },
                    "severity": sev,
                    "confidence": conf,
                    "first_seen": start_ts,
                    "last_seen": end_ts,
                    "affected_entities": entities,
                    "evidence_count": evidence_count,
                    "source_count": len({e.get("source") for e in evidence_events if e.get("source")}),
                    "summary": "",
                    "recommended_actions": [],
                    "explanation": {
                        "threshold": BRUTE_FORCE_FAILURE_THRESHOLD,
                        "observed": BRUTE_FORCE_FAILURE_THRESHOLD,
                        "window": f"{WINDOW_SECONDS}s",
                        "trigger_field": "username",
                    },
                    "subject": {"source_ip": ip, "username": user},
                    "evidence": {
                        "window_start": start_ts,
                        "window_end": end_ts,
                        "counts": {"failures": evidence_count},
                        "timeline": _event_timeline(evidence_events),
                        "events": evidence_events,
                    },
                }

                incident = _phase4_apply_explainability(incident)
                try:
                    dumped = _finalize_incident(incident)
                    out_incidents.append(dumped)
                    emitted.add(incident_id)
                    incident_index_by_id[incident_id] = len(out_incidents) - 1
                    active_bruteforce[pair] = {"incident_id": incident_id, "start_dt": start_dt}
                except Exception:
                    pass

            elif active_state is not None:
                incident_id = active_state["incident_id"]
                incident_idx = incident_index_by_id.get(incident_id)
                if incident_idx is not None:
                    incident = out_incidents[incident_idx]
                    evidence_events = incident.get("evidence", {}).get("events", [])
                    evidence_events.append(ev)
                    evidence_count = len(evidence_events)

                    sev, conf = _severity_and_confidence(evidence_count)
                    end_ts = dt.isoformat().replace("+00:00", "Z")

                    incident["last_seen"] = end_ts
                    incident["severity"] = sev
                    incident["confidence"] = conf
                    incident["evidence_count"] = evidence_count
                    incident["source_count"] = len({e.get("source") for e in evidence_events if e.get("source")})
                    incident["evidence"]["window_end"] = end_ts
                    incident["evidence"]["counts"]["failures"] = evidence_count
                    incident["evidence"]["timeline"] = _event_timeline(evidence_events)
                    incident["explanation"]["observed"] = BRUTE_FORCE_FAILURE_THRESHOLD
                    incident = _phase4_apply_explainability(incident)
                    out_incidents[incident_idx] = incident

        cred_ip = ev.get("source_ip")
        cred_user = ev.get("username")
        if not isinstance(cred_ip, str) or not cred_ip:
            continue
        if not isinstance(cred_user, str) or not cred_user:
            continue

        cred_window = credential_abuse_windows.setdefault(cred_ip, deque())
        cred_window.append((dt, ev))
        while cred_window and (dt - cred_window[0][0]) > window_delta:
            cred_window.popleft()

        # Credential Abuse: same IP, multiple distinct usernames
        for ip, ip_window in credential_abuse_windows.items():
            events = [item[1] for item in ip_window]
            distinct_users = {e.get("username") for e in events if e.get("username")}
            count = len(events)

            if len(distinct_users) >= CRED_ABUSE_DISTINCT_USER_THRESHOLD and count >= CRED_ABUSE_FAILURE_THRESHOLD:
                start_ts, end_ts = _window_bounds(ip_window)
                entities = sorted([ip] + sorted(distinct_users))
                seed = f"credential_abuse|{'|'.join(entities)}|{start_ts}"
                incident_id = _stable_incident_id(seed)

                if incident_id in emitted:
                    continue
                emitted.add(incident_id)

                # Severity based on distinct user count
                sev = "critical" if len(distinct_users) > 15 else "high"

                incident = {
                    "incident_id": incident_id,
                    "type": "credential_abuse",
                    "mitre_technique": MITRE_T1110_003,
                    "mitre": {
                        "tactic": MITRE_TACTIC_CREDENTIAL_ACCESS,
                        "technique": MITRE_T1110_003,
                        "technique_name": MITRE_TECHNIQUE_PASSWORD_SPRAYING,
                    },
                    "severity": sev,
                    "confidence": 0.90,
                    "first_seen": start_ts,
                    "last_seen": end_ts,
                    "affected_entities": entities,
                    "evidence_count": count,
                    "source_count": len({e.get("source") for e in events if e.get("source")}),
                    "summary": "",
                    "recommended_actions": [],
                    "explanation": {
                        "threshold": CRED_ABUSE_FAILURE_THRESHOLD,
                        "observed": count,
                        "window": f"{WINDOW_SECONDS}s",
                        "trigger_field": "source_ip",
                    },
                    "subject": {"source_ip": ip, "username": "multiple_accounts"},
                    "evidence": {
                        "window_start": start_ts,
                        "window_end": end_ts,
                        "counts": {
                            "failures": count,
                            "distinct_users": len(distinct_users)
                        },
                        "timeline": _event_timeline(events),
                        "events": events,
                    },
                }

                incident = _phase4_apply_explainability_cred_abuse(incident)
                try:
                    out_incidents.append(_finalize_incident(incident))
                except Exception:
                    continue

    out_incidents = _apply_cross_source_correlation(out_incidents, validated)

    # Final deterministic ordering
    out_incidents.sort(key=lambda x: x.get("incident_id", ""))
    return out_incidents


def detect_run(run_id: str, runs_root: Path, source_file: str = "normalized.json") -> Dict[str, int]:
    run_dir = runs_root / run_id
    in_path = run_dir / source_file
    if not in_path.exists():
        in_path = run_dir / "normalized.json"
    out_path = run_dir / "incidents.json"

    if not in_path.exists():
        out_path.write_text("[]", encoding="utf-8")
        return {"normalized": 0, "incidents": 0}

    normalized = json.loads(in_path.read_text(encoding="utf-8"))
    incidents = detect_incidents(normalized)

    out_path.write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    n_count = len(normalized) if isinstance(normalized, list) else 0
    i_count = len(incidents)
    return {"normalized": n_count, "incidents": i_count}
