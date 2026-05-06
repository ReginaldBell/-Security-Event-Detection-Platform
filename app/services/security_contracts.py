from __future__ import annotations

INCIDENT_STATUSES = ("open", "acknowledged", "escalated", "closed")

INCIDENT_TRANSITIONS = {
    "open": ("acknowledged",),
    "acknowledged": ("escalated",),
    "escalated": ("closed",),
    "closed": (),
}

REOPEN_FROM_STATUSES = ("closed",)

SLA_MINUTES_BY_SEVERITY = {
    "critical": 15,
    "high": 30,
    "medium": 120,
    "low": 480,
}

SEVERITY_PRIORITY_ORDER = ("low", "medium", "high", "critical")

SECURE_CONTEXT_GUARANTEES = [
    "No raw identifiers are sent to AI context.",
    "No direct infrastructure identifiers are sent to AI context.",
    "Only derived detection features and stable hashed pivots are included.",
    "All secure context generation events are written to audit logs.",
]

SECURE_CONTEXT_ALLOWED_FIELDS = [
    "incident_id",
    "type",
    "status",
    "assignee",
    "severity",
    "effective_priority",
    "confidence",
    "mitre",
    "subject_refs",
    "entity_refs",
    "entity_counts",
    "summary",
    "recommended_actions",
    "signal_summary",
    "timeline_summary",
    "chain_correlation",
]

SECURE_CONTEXT_REMOVED_FIELDS = [
    "subject.username",
    "subject.source_ip",
    "affected_entities.raw_values",
    "evidence.events",
    "raw_source",
    "secret_values",
    "request_payload",
    "response_payload",
]
