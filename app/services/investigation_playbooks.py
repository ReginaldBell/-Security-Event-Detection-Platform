from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.schemas.incident_new import IncidentNew
from app.services.playbook_registry import get_playbook_by_technique
from app.services.siem_translation import generate_pivot_queries


PLAYBOOKS: dict[str, dict[str, Any]] = {
    "brute_force": {
        "questions": [
            "Is this IP known, internal, or expected for this user?",
            "Has this user logged in successfully after the failures?",
            "Are other users targeted from this IP?",
        ],
        "false_positives": [
            "User forgot password and retried multiple times",
            "Automated system misconfigured authentication",
            "Internal vulnerability scanner",
        ],
        "escalation_conditions": [
            "Successful login after failures",
            "Multiple users targeted from same IP",
            "IP geolocation is unusual",
            "MFA bypass, disabled MFA, or repeated MFA failures",
        ],
    },
    "credential_abuse": {
        "questions": [
            "Are targeted users privileged or service accounts?",
            "Did any login succeed after the spray window?",
            "Is the source IP external, anonymized, or unusual for the tenant?",
        ],
        "false_positives": [
            "Shared application retrying old credentials",
            "Corporate VPN or proxy collapsing many users behind one source",
            "Identity provider outage causing repeated failures",
        ],
        "escalation_conditions": [
            "Any successful login from the spraying source",
            "High-value or privileged accounts targeted",
            "Source appears on threat intelligence or unusual geo lists",
        ],
    },
    "possible_compromise": {
        "questions": [
            "Was the successful login expected for this user and location?",
            "Did suspicious process execution occur on a host tied to the login?",
            "Are there follow-on network, persistence, or privilege escalation signals?",
        ],
        "false_positives": [
            "Administrator troubleshooting with scripted tools",
            "Endpoint management or software deployment activity",
            "Security team testing detection coverage",
        ],
        "escalation_conditions": [
            "Encoded PowerShell or suspicious command line after login",
            "Remote services, lateral movement, or privilege escalation follows",
            "The account is privileged or accesses sensitive systems",
        ],
    },
}


def get_investigation_playbook(incident: IncidentNew) -> dict[str, Any]:
    playbook = deepcopy(get_playbook_by_technique(incident.mitre_technique))
    base = {
        "questions": playbook.get("triage", []),
        "triage": playbook.get("triage", []),
        "pivot_queries": generate_pivot_queries(incident, "splunk"),
        "false_positives": playbook.get("false_positives", []),
        "escalation_conditions": [
            (
                f"{playbook.get('escalation', {}).get('condition', 'manual')} / "
                f"SLA {playbook.get('escalation', {}).get('sla', '30m')}"
            )
        ],
        "playbook_id": playbook.get("id"),
        "playbook_name": playbook.get("name"),
    }
    if not base["questions"]:
        legacy = deepcopy(PLAYBOOKS.get(incident.type) or PLAYBOOKS["brute_force"])
        base["questions"] = legacy.get("questions", [])
        base["triage"] = base["questions"]
        base["false_positives"] = legacy.get("false_positives", [])
        base["escalation_conditions"] = legacy.get("escalation_conditions", [])
    return base
