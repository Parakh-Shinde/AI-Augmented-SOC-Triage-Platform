# TEST-001 — Network Reconnaissance Detection Validation

**Project:** AI-Augmented SOC Triage Platform  
**Date:** 25 August 2026 (IST)  
**Status:** PARTIALLY PASSED — telemetry observed; alert detection not proven  
**Framework alignment:** ISO/IEC 27001:2022, NIST CSF 2.0, NIST SP 800-61, MITRE ATT&CK

## Executive conclusion

Splunk returned four Suricata SSH/flow events from `10.0.10.40` to `10.0.10.10:22`. This proves collection, indexing and field extraction. The `signature` field was blank, so the evidence does **not** prove that a reconnaissance analytic fired. The documented Kali-to-web-server test must be repeated after confirming source and target addresses.

## Evidence summary

| Time (IST) | Host | Event | Network path |
|---|---|---|---|
| 01:12:39.758 | web-server | ssh | 10.0.10.40 → 10.0.10.10:22 |
| 01:12:44.237 | windows-endpoint | flow | 10.0.10.40 → 10.0.10.10:22 |
| 01:12:54.238 | windows-endpoint | flow | 10.0.10.40 → 10.0.10.10:22 |
| 01:13:57.431 | web-server | flow | 10.0.10.40 → 10.0.10.10:22 |

## Analyst assessment

- Severity: Informational.
- True-positive status: Undetermined.
- Containment: Not recommended from this evidence alone.
- MITRE ATT&CK: `T1046 Network Service Discovery` is a candidate only after scan behavior is confirmed.
- Data-quality finding: observed source/target differ from the planned Kali-to-web-server scenario.

## Retest acceptance criteria

- Confirm current Kali and target IP addresses.
- Capture the bounded Nmap command and timestamps.
- Obtain `event_type=alert` with a populated `alert.signature`, or an approved Splunk correlation alert.
- Run the AI pipeline with `failed=0`.
- Capture dashboard severity, verdict, evidence, MITRE mapping and response recommendation.
- Measure ingestion, detection and triage latency.

## Control mapping

| Framework | Area | Evidence |
|---|---|---|
| ISO/IEC 27001:2022 | A.8.15 Logging; A.8.16 Monitoring | Suricata events searchable in Splunk |
| ISO/IEC 27001:2022 | A.5.24–A.5.28 incident management/evidence | Structured assessment and corrective actions |
| NIST CSF 2.0 | Detect, Respond, Recover/Improve | Monitoring, analysis and retest workflow |
| NIST SP 800-61 | Detection and Analysis | Evidence-based incident classification |
| MITRE ATT&CK | T1046 candidate | Not confirmed by current evidence |

## Final disposition

**OPEN FOR RETEST.** Telemetry visibility passed. Reconnaissance detection, AI triage and ATT&CK mapping remain to be proven.
