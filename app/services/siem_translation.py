from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml

from app.schemas.incident_new import IncidentNew

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "siem_mappings.yaml"
_QUERY_CACHE_PATH = Path("runs") / "siem_query_cache.json"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_siem_mappings() -> Dict[str, Any]:
    with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def mapping_version() -> str:
    mappings = load_siem_mappings()
    return str(mappings.get("version") or "legacy")


def _mapping(siem: str) -> dict[str, Any]:
    mappings = load_siem_mappings()
    sources = mappings.get("sources")
    source_map = sources if isinstance(sources, dict) else mappings
    profile = source_map.get(siem)
    if not isinstance(profile, dict):
        raise ValueError(f"Unsupported SIEM: {siem}")
    return profile


def _query_notes(detection_type: str) -> list[str]:
    common = [
        "Requires canonical auth result values mapped to success/failure.",
        "Internal 10.0.0.0/8 sources are suppressed as baseline noise; tune for your environment.",
    ]
    if detection_type == "credential_abuse":
        return common + [
            "Coverage assumes the user field uniquely identifies accounts.",
            "Password spraying confidence depends on source IP fidelity and proxy/VPN behavior.",
        ]
    if detection_type == "possible_compromise":
        return common + [
            "Requires EDR process telemetry such as Sysmon EventCode=1 or equivalent.",
            "Process coverage depends on process_name and command_line ingestion.",
        ]
    return common + [
        "Brute-force coverage depends on source IP and username being present in auth logs.",
    ]


def _query_confidence(detection_type: str) -> float:
    if detection_type == "possible_compromise":
        return 0.72
    if detection_type == "credential_abuse":
        return 0.82
    return 0.86


def _cache_key(incident: IncidentNew, siem: str) -> str:
    updated_at = incident.updated_at.isoformat() if incident.updated_at else ""
    return "|".join(
        [
            incident.incident_id,
            siem,
            incident.type,
            incident.mitre_technique,
            str(incident.explanation.threshold),
            updated_at,
            mapping_version(),
        ]
    )


def _load_query_cache() -> dict[str, Any]:
    try:
        raw = json.loads(_QUERY_CACHE_PATH.read_text(encoding="utf-8")) if _QUERY_CACHE_PATH.exists() else {}
    except Exception:
        raw = {}
    return raw if isinstance(raw, dict) else {}


def _save_query_cache(cache: dict[str, Any]) -> None:
    _QUERY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _QUERY_CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _field(profile: dict[str, Any], canonical: str) -> str:
    fields = profile.get("fields") or {}
    return str(fields.get(canonical) or canonical)


def generate_spl(detection_type: str, params: dict[str, Any] | None = None) -> str:
    return generate_detection_query("splunk", detection_type, params)


def generate_detection_query(
    siem: str,
    detection_type: str,
    params: dict[str, Any] | None = None,
) -> str:
    if siem != "splunk":
        raise ValueError("Only Splunk SPL generation is implemented for executable queries")

    params = params or {}
    profile = _mapping(siem)
    index = profile["index"]
    source_ip = _field(profile, "source_ip")
    username = _field(profile, "username")
    result = _field(profile, "result")
    timestamp = _field(profile, "timestamp")
    process_name = _field(profile, "process_name")
    command_line = _field(profile, "command_line")

    if detection_type == "credential_abuse":
        threshold = int(params.get("threshold", 8))
        distinct_users = int(params.get("distinct_users", 5))
        return "\n".join(
            [
                f"index={index} {result}=failure earliest=-15m",
                f"| where NOT cidrmatch(\"10.0.0.0/8\", {source_ip})",
                f"| bin {timestamp} span=60s",
                f"| stats count dc({username}) as distinct_users by {source_ip}, {timestamp}",
                f"| where count >= {threshold} AND distinct_users >= {distinct_users}",
                "| eval detection_type=\"credential_abuse\"",
                "| eval mitre=\"T1110.003\"",
                "| eval severity=case(count>=20,\"high\", count>=10,\"medium\", count>=8,\"low\")",
            ]
        )

    if detection_type == "possible_compromise":
        suspicious = params.get("suspicious_process", "powershell.exe")
        return "\n".join(
            [
                f"index={index} earliest=-15m ({result}=success OR {process_name}=\"{suspicious}\")",
                f"| eval is_success=if({result}=\"success\",1,0)",
                f"| eval is_suspicious_process=if(match(lower({process_name}), \"powershell|cmd.exe|rundll32|wmic|mshta\") OR match(lower({command_line}), \"-enc|-encodedcommand|downloadstring|invoke-webrequest\"),1,0)",
                f"| stats max(is_success) as login_success max(is_suspicious_process) as suspicious_process values({process_name}) as process_names values({command_line}) as command_lines by {username}, {source_ip}",
                "| where login_success=1 AND suspicious_process=1",
                "| eval detection_type=\"possible_compromise\"",
                "| eval severity=\"high\"",
            ]
        )

    threshold = int(params.get("threshold", 5))
    return "\n".join(
        [
            f"index={index} {result}=failure earliest=-15m",
            f"| where NOT cidrmatch(\"10.0.0.0/8\", {source_ip})",
            f"| bin {timestamp} span=60s",
            f"| stats count by {source_ip}, {username}, {timestamp}",
            f"| where count >= {threshold}",
            "| eval detection_type=\"brute_force\"",
            "| eval mitre=\"T1110\"",
            "| eval severity=case(count>=20,\"high\", count>=10,\"medium\", count>=5,\"low\")",
        ]
    )


def generate_pivot_queries(
    incident: IncidentNew,
    siem: str = "splunk",
) -> list[dict[str, str]]:
    if siem != "splunk":
        raise ValueError("Only Splunk SPL pivot generation is implemented")

    profile = _mapping(siem)
    index = profile["index"]
    source_ip = _field(profile, "source_ip")
    username = _field(profile, "username")
    result = _field(profile, "result")
    timestamp = _field(profile, "timestamp")
    process_name = _field(profile, "process_name")
    command_line = _field(profile, "command_line")

    ip_value = incident.subject.source_ip
    user_value = incident.subject.username
    return [
        {
            "name": "Full Activity for IP",
            "description": "All events associated with the source IP or host pivot.",
            "query": f"index={index} {source_ip}=\"{ip_value}\"\n| sort - {timestamp}",
        },
        {
            "name": "IP Authentication Breakdown",
            "description": "Which users and outcomes are tied to this source.",
            "query": f"index={index} {source_ip}=\"{ip_value}\"\n| stats count by {username}, {result}",
        },
        {
            "name": "User Activity Timeline",
            "description": "Authentication result trend for the affected user.",
            "query": f"index={index} {username}=\"{user_value}\"\n| timechart count by {result}",
        },
        {
            "name": "Suspicious Process Follow-up",
            "description": "EDR pivot for command execution after authentication activity.",
            "query": f"index={index} {username}=\"{user_value}\" ({process_name}=powershell.exe OR {command_line}=\"*-enc*\" OR {command_line}=\"*downloadstring*\")\n| sort - {timestamp}",
        },
    ]


def incident_spl_bundle(incident: IncidentNew) -> dict[str, Any]:
    key = _cache_key(incident, "splunk")
    cache = _load_query_cache()
    cached = cache.get(key)
    required_cached_fields = {"query", "detection_query", "confidence", "notes", "mapping_version"}
    if isinstance(cached, dict) and required_cached_fields.issubset(cached.keys()):
        cached["cache_hit"] = True
        cached["last_used_at"] = _utcnow()
        cached["used_count"] = int(cached.get("used_count") or 0) + 1
        cache[key] = cached
        _save_query_cache(cache)
        return cached

    params = {
        "threshold": incident.explanation.threshold,
        "distinct_users": incident.evidence.counts.get("distinct_users", 5),
    }
    query = generate_spl(incident.type, params)
    bundle = {
        "siem": "splunk",
        "mapping_version": mapping_version(),
        "detection_type": incident.type,
        "query": query,
        "detection_query": query,
        "confidence": _query_confidence(incident.type),
        "notes": _query_notes(incident.type),
        "pivot_queries": generate_pivot_queries(incident, "splunk"),
        "cache_hit": False,
        "cache_key": key,
        "generated_at": _utcnow(),
        "last_used_at": _utcnow(),
        "used_count": 1,
    }
    cache[key] = bundle
    _save_query_cache(cache)
    return bundle
