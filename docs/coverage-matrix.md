# SecureWatch Detection Coverage Matrix

SecureWatch should be positioned as a coverage and effectiveness platform, not as a raw count of attack simulations. The stronger message is:

> Core detection coverage with validation-backed effectiveness metrics.

This document inventories the scenarios already built, groups them into coverage packs, and identifies strategic gaps worth filling next.

## Current Coverage Summary

| Tactic | Techniques Covered | Coverage Pack | Status |
|---|---|---|---|
| Credential Access | T1110, T1110.003 | Credential Abuse Detection | Implemented and validated |
| Lateral Movement | None yet | Lateral Movement Detection | Strategic gap |
| Persistence | None yet | Persistence Detection | Strategic gap |
| Defense Evasion | None yet | Defense Evasion Detection | Strategic gap |
| Execution | None yet | Execution Detection | Strategic gap |
| Discovery | None yet | Discovery Detection | Strategic gap |
| Exfiltration | None yet | Exfiltration Detection | Strategic gap |

## Scenario Inventory

| Scenario | MITRE | Category | Detection Type |
|---|---|---|---|
| s01 - Brute force fires at threshold | T1110 | Positive validation | brute_force |
| s02 - Brute force below threshold | T1110 | Negative validation | no detection expected |
| s03 - Brute force medium severity | T1110 | Positive validation | brute_force |
| s04 - Brute force high severity | T1110 | Positive validation | brute_force |
| s05 - Brute force 61 second boundary | T1110 | Negative validation | no detection expected |
| s06 - Brute force 60 second boundary | T1110 | Positive validation | brute_force |
| s07 - Credential abuse/password spray | T1110.003 | Positive validation | credential_abuse |
| s08 - Credential abuse below user threshold | T1110.003 | Negative validation | no detection expected |
| s09 - Successful logins only | Authentication noise | Negative validation | no detection expected |
| s10 - Heartbeat telemetry | Telemetry rejection | Negative validation | no detection expected |
| s11 - Mixed success and failure payload | T1110 boundary | Negative validation | no detection expected |
| s12 - Cross-user failures, no brute force | T1110 boundary | Negative validation | no detection expected |
| password_spray_01 | T1110.003 | API validation scenario | credential_abuse |
| normal_login_activity | Benign authentication | API validation scenario | no detection expected |

## Coverage Packs

### Credential Abuse Detection Pack

Purpose: detect high-risk authentication abuse and prove the rule boundaries are correctly tuned.

| Technique | Scenario Coverage | Effectiveness Signal |
|---|---|---|
| T1110 - Brute Force | Threshold fire, below-threshold no-fire, medium escalation, high escalation, 60s/61s window boundary | Validates detection, severity scaling, confidence scaling, and sliding-window behavior |
| T1110.003 - Password Spraying | Multi-user same-IP spray, below distinct-user threshold | Validates credential abuse detection and false-positive resistance |
| Authentication noise handling | Success-only, mixed success/failure, heartbeat telemetry | Validates that normal activity and telemetry do not become incidents |

Sellable framing:

> Credential Abuse Detection Pack: brute force, password spraying, threshold boundaries, severity escalation, and benign-noise resistance.

## Coverage and Effectiveness

Use this format in demos, reports, and portfolio descriptions:

| Coverage Area | Techniques | Detection Coverage | Effectiveness |
|---|---|---|---|
| Credential Access | T1110, T1110.003 | 2/2 implemented techniques detected in positive scenarios | 12/12 standalone scenarios passing; avg 38.0ms, p95 57.1ms in the documented containerized run |
| False Positive Resistance | Benign auth, telemetry, below-threshold activity | Negative scenarios validate no alert when thresholds are not met | 0 false positives across the documented negative scenario set |

Important: the latency numbers above come from the documented standalone scenario suite. For live API validation, use `GET /validate/results` and `GET /validate/results/mitre-coverage` after running scenarios so the report reflects the current environment.

## Strategic Gap Analysis

Current strength:

- Strong Credential Access coverage.
- Strong validation depth around boundaries, not just happy-path detection.
- Good demo story: each rule has a corresponding positive scenario and no-fire scenarios.

Current gaps:

- No implemented Lateral Movement detection pack yet.
- No implemented Persistence detection pack yet.
- No implemented Defense Evasion detection pack yet.
- No implemented Discovery or Exfiltration coverage yet.

Recommended expansion order:

| Priority | Pack | Suggested MITRE Techniques | Why This Gap Matters |
|---|---|---|---|
| 1 | Lateral Movement Detection | T1021.001, T1021.002 | Natural next step after credential abuse; shows what happens after valid credentials are used |
| 2 | Defense Evasion Detection | T1070, T1562 | Adds maturity because it detects attacker attempts to hide or disable controls |
| 3 | Discovery Detection | T1087, T1018 | Often precedes lateral movement; useful for early-stage intrusion visibility |
| 4 | Persistence Detection | T1053.005, T1547 | Shows endpoint and AD persistence awareness |
| 5 | Exfiltration Detection | T1041 or cloud/storage-specific patterns | Useful later, but should be added after movement and evasion coverage |

## Recommended Messaging

Avoid:

> I have 25 attacks.

Use:

> SecureWatch provides validation-backed detection coverage across credential abuse patterns, with scenario-level measurements for detection success, false positives, latency, and MITRE coverage.

Portfolio phrasing:

> Core Detection Coverage:
> - Credential Abuse Detection Pack
> - Lateral Movement Detection Pack planned
> - Defense Evasion Detection Pack planned
> - Persistence Detection Pack planned
> - Discovery Detection Pack planned

## Next Build Targets

Only add strategic detections that expand the matrix. Do not add random scenarios just to increase the count.

Recommended next scenarios:

| New Scenario | MITRE | Pack | Detection Type |
|---|---|---|---|
| SMB admin share access from unusual host | T1021.002 | Lateral Movement Detection | lateral_movement_smb |
| Remote services / RDP login burst | T1021.001 | Lateral Movement Detection | lateral_movement_rdp |
| Audit log clearing | T1070 | Defense Evasion Detection | log_clearing |
| Security tooling disabled | T1562 | Defense Evasion Detection | control_impairment |
| Account enumeration | T1087 | Discovery Detection | account_discovery |
| Remote system discovery | T1018 | Discovery Detection | remote_system_discovery |
| Scheduled task persistence | T1053.005 | Persistence Detection | scheduled_task_persistence |

## Maturity Measurement Model

For each pack, track:

| Metric | Meaning |
|---|---|
| Techniques covered | Number of MITRE techniques implemented and validated |
| Positive detection rate | Positive scenarios detected / positive scenarios run |
| False positives | Benign or boundary scenarios that unexpectedly triggered |
| Average latency | Mean time from ingest request to validation response |
| P95 latency | Tail latency for validation response |
| Severity correctness | Whether incidents produce expected severity |
| Confidence correctness | Whether incidents produce expected confidence |

Example target format:

| Pack | Techniques | Detection Rate | Avg Latency | False Positives |
|---|---|---:|---:|---:|
| Credential Abuse Detection | T1110, T1110.003 | 2/2 techniques | 38.0ms | 0 |
| Lateral Movement Detection | T1021.001, T1021.002 | Planned | TBD | TBD |
| Defense Evasion Detection | T1070, T1562 | Planned | TBD | TBD |
