"""Programmatic event generator for building custom attack scenarios."""
from datetime import datetime, timedelta, timezone
from typing import List


def password_spray(source_ip: str, usernames: List[str], offset_seconds: int = 1) -> List[dict]:
    """Generate a password-spray event sequence from a single source IP."""
    base = datetime.now(timezone.utc)
    return [
        {
            "timestamp": (base + timedelta(seconds=i * offset_seconds)).isoformat().replace("+00:00", "Z"),
            "source_ip": source_ip,
            "username": username,
            "event_type": "login_attempt",
            "result": "failure",
        }
        for i, username in enumerate(usernames)
    ]


def brute_force(source_ip: str, username: str, count: int = 10, offset_seconds: int = 1) -> List[dict]:
    """Generate a brute-force event sequence targeting a single account."""
    base = datetime.now(timezone.utc)
    return [
        {
            "timestamp": (base + timedelta(seconds=i * offset_seconds)).isoformat().replace("+00:00", "Z"),
            "source_ip": source_ip,
            "username": username,
            "event_type": "login_attempt",
            "result": "failure",
        }
        for i in range(count)
    ]
