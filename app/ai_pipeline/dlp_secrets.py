"""
DLP secrets detector — Layer 1 of the SecureWatch detection pipeline.

Runs pre-LLM, deterministic. Scans text for 7 secret/PII types using
regex pattern matching. Returns findings + redacted text.

CRITICAL: Raw secret values are NEVER stored or logged.
Only SHA-256 prefix hashes + detection metadata are returned.
"""

import hashlib
import re
from typing import Optional

# Detection rules ordered critical → high → medium so the most severe finding
# is always processed first when iterating matches.
_FINDERS = [
    {
        "finding_type": "aws_access_key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
        "confidence": 0.98,
        "mitre": ["T1552", "TA0010"],
    },
    {
        "finding_type": "github_token",
        "pattern": re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59,82}"),
        "severity": "critical",
        "confidence": 0.97,
        "mitre": ["T1552.001"],
    },
    {
        "finding_type": "private_key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "severity": "critical",
        "confidence": 0.99,
        "mitre": ["T1552.004"],
    },
    {
        "finding_type": "jwt_token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "severity": "high",
        "confidence": 0.95,
        "mitre": ["T1528"],
    },
    {
        "finding_type": "database_url",
        "pattern": re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)://\S+",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.93,
        "mitre": ["T1213"],
    },
    {
        "finding_type": "password_string",
        "pattern": re.compile(
            r"(?:password|passwd|pwd|secret)\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
        "severity": "high",
        "confidence": 0.82,
        "mitre": ["T1552"],
    },
    {
        "finding_type": "email_address",
        "pattern": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        "severity": "medium",
        "confidence": 0.90,
        "mitre": ["T1589.002"],
    },
]

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _sha_prefix(value: str, length: int = 8) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _should_block(finding: dict) -> bool:
    # Critical findings always block. High-confidence high-severity findings block.
    # Lower-confidence high-severity (e.g. password_string at 0.82) only redact,
    # allowing downstream layers to still fire on combined attack scenarios.
    if finding["severity"] == "critical":
        return True
    if finding["severity"] == "high" and finding["confidence"] >= 0.90:
        return True
    return False


def scan(text: str) -> tuple[list[dict], str]:
    """
    Scan text for secrets. Returns (findings, redacted_text).

    Each finding contains only detection metadata — raw values are replaced
    with [REDACTED:<sha256_prefix>] in the returned text.
    """
    findings: list[dict] = []
    redacted = text

    for finder in _FINDERS:
        for match in finder["pattern"].finditer(text):
            raw = match.group()
            prefix = _sha_prefix(raw)
            findings.append(
                {
                    "detector": "dlp_secrets",
                    "finding_type": finder["finding_type"],
                    "severity": finder["severity"],
                    "confidence": finder["confidence"],
                    "mitre": finder["mitre"],
                    "sha256_prefix": prefix,
                }
            )
            # Replace in the working copy, not in `text`, so later patterns still
            # match the original positions.
            redacted = redacted.replace(raw, f"[REDACTED:{prefix}]", 1)

    return findings, redacted


def requires_block(findings: list[dict]) -> bool:
    """True if any finding mandates an immediate pre-LLM block."""
    return any(_should_block(f) for f in findings)


def max_severity(findings: list[dict]) -> Optional[str]:
    if not findings:
        return None
    return max(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 0))["severity"]
