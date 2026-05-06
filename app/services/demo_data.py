from __future__ import annotations

from app.schemas.incident_new import IncidentNew

DEMO_BASE_TS = "2026-05-05T14:00:00Z"


def demo_incidents() -> list[IncidentNew]:
    return [
        IncidentNew(
            incident_id="demo_chain_stage_1",
            type="brute_force",
            mitre_technique="T1110",
            severity="high",
            confidence=0.91,
            first_seen=DEMO_BASE_TS,
            last_seen="2026-05-05T14:01:00Z",
            affected_entities=["demo-user-a", "198.51.100.42"],
            evidence_count=8,
            source_count=2,
            summary="Password attack against a privileged demo user crossed threshold.",
            recommended_actions=["Acknowledge triage", "Check for valid account use", "Escalate if SLA is breached"],
            explanation={
                "threshold": 5,
                "observed": 8,
                "window": "60s",
                "trigger_field": "username",
            },
            subject={"source_ip": "198.51.100.42", "username": "demo-user-a"},
            evidence={
                "window_start": DEMO_BASE_TS,
                "window_end": "2026-05-05T14:01:00Z",
                "counts": {"failures": 8, "distinct_users": 1},
                "timeline": [
                    {"timestamp": DEMO_BASE_TS, "event_type": "login_attempt", "result": "failure"},
                    {"timestamp": "2026-05-05T14:01:00Z", "event_type": "login_attempt", "result": "failure"},
                ],
                "events": [],
            },
        ),
        IncidentNew(
            incident_id="demo_chain_stage_2",
            type="credential_abuse",
            mitre_technique="T1110.003",
            severity="critical",
            confidence=0.96,
            first_seen="2026-05-05T14:03:00Z",
            last_seen="2026-05-05T14:04:30Z",
            affected_entities=["demo-user-b", "203.0.113.77", "vpn"],
            evidence_count=12,
            source_count=3,
            summary="Credential abuse pattern indicates possible valid account follow-on risk.",
            recommended_actions=["Escalate to Tier 2", "Review VPN and endpoint activity", "Prepare containment"],
            explanation={
                "threshold": 5,
                "observed": 12,
                "window": "120s",
                "trigger_field": "source_ip",
            },
            subject={"source_ip": "203.0.113.77", "username": "demo-user-b"},
            evidence={
                "window_start": "2026-05-05T14:03:00Z",
                "window_end": "2026-05-05T14:04:30Z",
                "counts": {"failures": 12, "distinct_users": 4},
                "timeline": [
                    {"timestamp": "2026-05-05T14:03:00Z", "event_type": "login_attempt", "result": "failure"},
                    {"timestamp": "2026-05-05T14:04:30Z", "event_type": "login_attempt", "result": "success"},
                ],
                "events": [],
            },
        ),
    ]
