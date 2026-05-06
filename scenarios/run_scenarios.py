#!/usr/bin/env python3
"""
Scenario validation runner — 12 scenarios across 4 detection axes.
Usage:
    python scenarios/run_scenarios.py
    python scenarios/run_scenarios.py http://localhost:9000
"""
import sys
import time
import statistics
from datetime import datetime, timedelta, timezone

import requests

BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"
INGEST_URL = f"{BASE_URL}/ingest/"


# ── Event factories ────────────────────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def failure(ip: str, user: str, offset: int = 0) -> dict:
    return {
        "timestamp": _ts(offset),
        "source_ip": ip,
        "username": user,
        "event_type": "login_attempt",
        "result": "failure",
        "reason": "bad_password",
        "source": "scenario",
    }


def success(ip: str, user: str, offset: int = 0) -> dict:
    return {
        "timestamp": _ts(offset),
        "source_ip": ip,
        "username": user,
        "event_type": "login_attempt",
        "result": "success",
        "source": "scenario",
    }


def telemetry(ip: str, offset: int = 0) -> dict:
    return {
        "timestamp": _ts(offset),
        "source_ip": ip,
        "username": "system",
        "event_type": "heartbeat",
        "result": "success",
        "source": "scenario",
    }


# ── Result tracking ────────────────────────────────────────────────────────────

_results: list[tuple[str, str, float, str]] = []
_latencies_ms: list[float] = []  # positive-scenario wall-clock only


def _post(events: list[dict]) -> tuple[dict, float]:
    t0 = time.monotonic()
    resp = requests.post(INGEST_URL, json=events, timeout=15)
    elapsed_ms = (time.monotonic() - t0) * 1000
    resp.raise_for_status()
    return resp.json(), elapsed_ms


def scenario(
    label: str,
    events: list[dict],
    *,
    expect_type: str | None = None,
    expect_severity: str | None = None,
    expect_confidence: float | None = None,
) -> None:
    data, elapsed_ms = _post(events)
    incidents = data.get("incidents", [])

    if expect_type is None:
        passed = len(incidents) == 0
        note = "no incidents" if passed else f"unexpected: {incidents[0]['type']}"
    else:
        matches = [i for i in incidents if i["type"] == expect_type]
        if not matches:
            passed = False
            got = [i["type"] for i in incidents] or ["nothing"]
            note = f"expected {expect_type}, got {got}"
        else:
            inc = matches[0]
            errors = []
            if expect_severity and inc["severity"] != expect_severity:
                errors.append(f"severity={inc['severity']} want={expect_severity}")
            if expect_confidence is not None:
                got_conf = float(inc["confidence"])
                if abs(got_conf - expect_confidence) > 0.001:
                    errors.append(f"confidence={got_conf} want={expect_confidence}")
            passed = not errors
            note = ", ".join(errors) if errors else "ok"
            if passed:
                _latencies_ms.append(elapsed_ms)

    status = "PASS" if passed else "FAIL"
    _results.append((label, status, elapsed_ms, note))
    print(f"  [{status}] {label:<58} {elapsed_ms:>7.1f}ms  {note}")


# ── Scenarios ─────────────────────────────────────────────────────────────────

print(f"\nSecureWatch Scenario Runner — {BASE_URL}\n")
print(f"  {'Scenario':<60} {'Latency':>9}  Notes")
print(f"  {'-'*60} {'-'*9}  -----")

# s01 — brute_force fires, low severity (5 failures, same ip+user)
scenario(
    "s01: brute_force low — 5 failures",
    [failure("10.0.1.1", "u_s01", i) for i in range(5)],
    expect_type="brute_force",
    expect_severity="low",
    expect_confidence=0.70,
)

# s02 — one short of brute_force threshold
scenario(
    "s02: brute_force no-fire — 4 failures",
    [failure("10.0.1.2", "u_s02", i) for i in range(4)],
)

# s03 — brute_force fires, medium severity (10 failures)
scenario(
    "s03: brute_force medium — 10 failures",
    [failure("10.0.1.3", "u_s03", i) for i in range(10)],
    expect_type="brute_force",
    expect_severity="medium",
    expect_confidence=0.85,
)

# s04 — brute_force fires, high severity (20 failures)
scenario(
    "s04: brute_force high — 20 failures",
    [failure("10.0.1.4", "u_s04", i) for i in range(20)],
    expect_type="brute_force",
    expect_severity="high",
    expect_confidence=0.95,
)

# s05 — window boundary: 61s span, first event evicted, max 4 in any window
# Eviction condition is strictly > 60s (detection.py:205), so at t=61 the
# event at t=0 satisfies (61-0) > 60 and is dropped, leaving 4 events.
scenario(
    "s05: window boundary no-fire — 61s span",
    [failure("10.0.1.5", "u_s05", 0)]
    + [failure("10.0.1.5", "u_s05", 61 + i) for i in range(4)],
)

# s06 — window boundary: 60s span, first event still in window
# At t=60: (60-0) > 60 is False, so t=0 is not evicted. 5 events → fires.
scenario(
    "s06: window boundary fires — 60s span",
    [failure("10.0.1.6", "u_s06", i) for i in range(4)]
    + [failure("10.0.1.6", "u_s06", 60)],
    expect_type="brute_force",
    expect_severity="low",
    expect_confidence=0.70,
)

# s07 — credential_abuse fires: 8 failures across 8 distinct users, fixed 0.90
scenario(
    "s07: credential_abuse high — 8 failures / 8 users",
    [failure("10.0.1.7", f"u_s07_{i}", i) for i in range(8)],
    expect_type="credential_abuse",
    expect_severity="high",
    expect_confidence=0.90,
)

# s08 — credential_abuse: failure count met (12), user count not (4, need 5)
#        brute_force also misses: 3 failures per (ip, user), need 5
scenario(
    "s08: cred_abuse no-fire — 12 failures / 4 users",
    [failure("10.0.1.8", f"u_s08_{i % 4}", i) for i in range(12)],
)

# s09 — successes only, nothing to detect
scenario(
    "s09: successes ignored — 10 successes",
    [success("10.0.1.9", "u_s09", i) for i in range(10)],
)

# s10 — telemetry events dropped before detection sees them
scenario(
    "s10: telemetry dropped — 10 heartbeats",
    [telemetry("10.0.1.10", i) for i in range(10)],
)

# s11 — mixed: 3 failures + 10 successes, only failures count toward threshold
scenario(
    "s11: mixed events no-fire — 3 failures + 10 successes",
    [failure("10.0.1.11", "u_s11", i) for i in range(3)]
    + [success("10.0.1.11", "u_s11", 3 + i) for i in range(10)],
)

# s12 — brute_force grouping: same IP, one distinct user per failure
#        each (ip, user) pair has 1 failure — never reaches 5
#        5 distinct users but only 5 total failures — credential_abuse needs 8
scenario(
    "s12: brute_force grouping no-fire — 5 failures / 5 users",
    [failure("10.0.1.12", f"u_s12_{i}", i) for i in range(5)],
)


# ── Summary ───────────────────────────────────────────────────────────────────

passed = sum(1 for _, s, _, _ in _results if s == "PASS")
failed = sum(1 for _, s, _, _ in _results if s == "FAIL")

print(f"\n  {'─'*75}")
print(f"  Results: {passed}/{len(_results)} passed" + (f"  ({failed} FAILED)" if failed else ""))

if _latencies_ms:
    avg = statistics.mean(_latencies_ms)
    p95 = sorted(_latencies_ms)[int(len(_latencies_ms) * 0.95)] if len(_latencies_ms) > 1 else _latencies_ms[0]
    print(f"  Positive-scenario latency — avg: {avg:.1f}ms  p95: {p95:.1f}ms")

if failed:
    print(f"\n  Failed:")
    for label, status, _, note in _results:
        if status == "FAIL":
            print(f"    {label}: {note}")

print()
