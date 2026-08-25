# Security Validation and Incident Reports

This directory contains evidence-based reports produced during authorized testing of the AI-Augmented SOC Triage Platform.

| Report | Scope | Status |
|---|---|---|
| [AI-SOC Consolidated Security Validation Report](INC-2026-08-25-AI-SOC-Security-Validation-Report.md) | SSH password guessing, Suricata alerts, Ollama triage, MITRE mapping, YARA and pipeline health | Partially Passed |
| [TEST-001 Network Reconnaissance Validation](TEST-001_Network_Reconnaissance_Validation_Report.md) | Network telemetry and reconnaissance-detection validation | Open for retest |

## Reporting Principles

- Claims must be supported by visible or machine-readable evidence.
- Telemetry visibility is not treated as a confirmed detection.
- MITRE ATT&CK describes behavior and does not automatically prove malicious intent.
- Authorized simulations are clearly separated from real incidents.
- Missing evidence is recorded as an open action rather than assumed successful.
- Sensitive credentials, tokens and personal information are excluded from public reports.

