from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

PRIVILEGED_ROLES = frozenset({"admin", "administrator", "root", "sysadmin", "domain_admin", "service_account"})

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


def _token_username(username: str) -> str:
    digest = hashlib.sha256(username.encode()).hexdigest()[:16]
    return f"usr_{digest}"


def _abstract_ip(ip_str: str) -> str:
    if not ip_str:
        return ip_str
    return "internal_host" if _is_internal(ip_str) else "external_host"


def sanitize(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sanitized = []
    for event in events:
        e = dict(event)

        raw_username = e.get("username") or e.get("user") or ""
        if raw_username:
            token = _token_username(raw_username)
            role = (e.get("role") or "").lower()
            e["username_token"] = token
            e["is_privileged"] = role in PRIVILEGED_ROLES or raw_username.lower() in PRIVILEGED_ROLES
            e.pop("username", None)
            e.pop("user", None)

        for ip_field in ("source_ip", "src_ip", "ip", "dest_ip", "destination_ip"):
            if ip_field in e and e[ip_field]:
                e[ip_field] = _abstract_ip(str(e[ip_field]))

        e.pop("raw_source", None)
        e.pop("request_payload", None)
        e.pop("response_payload", None)
        e.pop("secret_values", None)

        sanitized.append(e)
    return sanitized


def sanitize_run(run_id: str, runs_root: Path) -> Dict[str, int]:
    run_dir = runs_root / run_id
    norm_path = run_dir / "normalized.json"
    if not norm_path.exists():
        raise FileNotFoundError(f"normalized.json not found for run {run_id}")

    events: List[Dict] = json.loads(norm_path.read_text(encoding="utf-8"))
    if not isinstance(events, list):
        events = []

    sanitized_events = sanitize(events)

    out_path = run_dir / "sanitized.json"
    out_path.write_text(json.dumps(sanitized_events, indent=2), encoding="utf-8")

    stats = {
        "total": len(events),
        "sanitized": len(sanitized_events),
        "privileged_flagged": sum(1 for e in sanitized_events if e.get("is_privileged")),
    }
    logger.info(f"[SANITIZE] run {run_id}: {stats}")
    return stats
