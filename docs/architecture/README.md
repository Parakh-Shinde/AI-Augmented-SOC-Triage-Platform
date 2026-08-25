# Enterprise Cloud Security Monitoring & Threat Detection Platform

> An AWS-based security operations lab that centralizes cloud, network, web application, and Linux authentication telemetry in Splunk Enterprise for threat detection, investigation, and analyst-controlled response.

![AWS](https://img.shields.io/badge/AWS-Cloud%20Security-FF9900?logo=amazonaws&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise%20SIEM-65A637?logo=splunk&logoColor=white)
![CloudTrail](https://img.shields.io/badge/AWS-CloudTrail-8C4FFF)
![WAF](https://img.shields.io/badge/AWS-WAF-FF4F8B)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E34F26)
![Detections](https://img.shields.io/badge/Custom%20Detections-10-blue)

## Executive Summary

This project implements a small-scale enterprise cloud Security Operations Center (SOC) environment on AWS. Two Ubuntu EC2 instances host the Damn Vulnerable Web Application (DVWA) behind an Application Load Balancer (ALB). AWS WAF inspects inbound web traffic, while AWS CloudTrail, VPC Flow Logs, Apache logs, Linux authentication logs, and system logs provide security telemetry.

Splunk Enterprise acts as the centralized SIEM. It receives host telemetry through Splunk Universal Forwarders and AWS telemetry through the Splunk Add-on for AWS. The platform provides dashboards, scheduled alerts, threat hunting searches, and ten custom SPL detections mapped to MITRE ATT&CK.

The environment was validated through authorized attack simulations, including SSH brute force, SQL injection, cross-site scripting, directory traversal, and web reconnaissance. Cloud control-plane detections were validated using available CloudTrail events and non-persistent synthetic detection tests where performing the real action would create unnecessary security risk.

This project intentionally uses analyst-controlled response. It does not automatically block IP addresses, disable accounts, revoke credentials, or modify production infrastructure.

## Business Problem

AWS environments generate security-relevant events across multiple services and systems. Without centralized collection and correlation, security teams may struggle to answer basic incident-response questions:

- What happened?
- Which user, IP address, host, or AWS identity was involved?
- Was the activity successful or denied?
- Which systems were affected?
- Is the activity isolated or repeated?
- Which MITRE ATT&CK technique best describes the behavior?
- What should an analyst investigate next?

This platform addresses that visibility gap by consolidating cloud, network, web, and authentication telemetry into a single investigation interface.

## Project Objectives

- Build a multi-server AWS web environment behind an Application Load Balancer.
- Protect and monitor the application with AWS WAF.
- Centralize AWS and host logs in Splunk Enterprise.
- Detect web attacks, authentication abuse, IAM changes, cloud logging tampering, and risky network-control modifications.
- Map detection logic to MITRE ATT&CK.
- Create scheduled alerts and a live SOC dashboard.
- Validate detections through controlled and authorized simulations.
- Document operational risks, limitations, and production recommendations.

## Architecture

![Enterprise Cloud Security SOC Architecture](architecture/aws-soc-architecture-3d.png)

```mermaid
flowchart LR
    U[Internet Users] --> W[AWS WAF]
    K[Authorized Kali Test Host] -. Lab simulations .-> W
    W --> A[Application Load Balancer]
    A --> E1[DVWA Web Server 01]
    A --> E2[DVWA Web Server 02]
    E1 -->|Universal Forwarder| S[Splunk Enterprise SIEM]
    E2 -->|Universal Forwarder| S
    C[AWS CloudTrail] --> B[Amazon S3]
    B --> Q[Amazon SQS]
    Q --> S
    W --> CW[CloudWatch Logs]
    V[VPC Flow Logs] --> CW
    CW --> S
    S --> D[SOC Dashboard and Alerts]
    D --> H[Analyst Investigation]
```

### High-Level Data Flow

1. Internet users and the authorized Kali test system send requests toward the application.
2. AWS WAF inspects requests before they reach the ALB.
3. The ALB distributes requests between two DVWA web servers.
4. Splunk Universal Forwarders send Apache, Linux authentication, and system logs to Splunk Enterprise.
5. CloudTrail delivers AWS control-plane events to Amazon S3.
6. Amazon S3 notifications are delivered through Amazon SQS for Splunk ingestion.
7. WAF and VPC Flow telemetry is delivered through CloudWatch Logs.
8. Splunk dashboards and scheduled SPL searches provide detection and investigation visibility.
9. A human analyst reviews evidence and decides whether response action is appropriate.

## Implemented Components

| Layer | Component | Purpose |
|---|---|---|
| Perimeter | AWS WAF | Inspects web requests and records managed-rule matches. Currently operated in monitoring/count mode. |
| Traffic distribution | Application Load Balancer | Distributes HTTP requests across two DVWA web servers. |
| Application | Two Ubuntu EC2 web servers | Host Apache and DVWA for controlled security testing. |
| Host telemetry | Splunk Universal Forwarder | Sends Apache, Linux authentication, and syslog data to Splunk. |
| Central SIEM | Splunk Enterprise on EC2 | Provides indexing, search, dashboards, scheduled alerts, and investigations. |
| AWS audit | AWS CloudTrail | Records AWS API and account activity. |
| CloudTrail transport | Amazon S3 and Amazon SQS | Stores CloudTrail files and queues notifications for Splunk ingestion. |
| Web security telemetry | CloudWatch Logs | Stores AWS WAF request logs for ingestion into Splunk. |
| Network telemetry | VPC Flow Logs | Provides network-flow metadata. Splunk ingestion is enabled on demand to control volume. |
| Analyst interface | Splunk Dashboard Studio | Displays operational health, cloud activity, web threats, and investigation data. |

## Log Sources and Indexes

| Splunk index | Primary sourcetype | Data collected | Operational status |
|---|---|---|---|
| `web` | `access_combined`, `apache:error` | Apache requests and application errors | Active |
| `linux` | `linux_secure`, `syslog` | SSH authentication and Linux operating-system activity | Active |
| `cloudtrail` | `aws:cloudtrail` | AWS API, identity, and control-plane activity | Active |
| `waf` | `aws:cloudwatchlogs` | AWS WAF requests and managed-rule matches | Active |
| `vpcflow` | `aws:cloudwatchlogs:vpcflow` | VPC network-flow metadata | Splunk input paused; enabled during network investigations |

### Data-Volume Control

Continuous VPC Flow ingestion generated a disproportionate number of events for the single-node lab SIEM. The Splunk VPC Flow input was therefore paused after validation. AWS-side flow logging can remain available, while Splunk ingestion is enabled during focused network investigations.

This is a lab cost-and-capacity decision, not a recommendation to remove network telemetry from a production SOC.

## Detection Engineering

The project contains ten custom SPL detections. Thresholds and lookback windows are designed for this lab and must be baselined before production use.

| ID | Detection | Primary source | Severity | MITRE ATT&CK | Validation |
|---|---|---|---|---|---|
| DET-001 | SSH Brute Force | Linux authentication logs | High | T1110 – Brute Force | Controlled invalid-user SSH attempts |
| DET-002 | SQL Injection Attempt | Apache access logs | High | T1190 – Exploit Public-Facing Application | Encoded SQLi request sent to DVWA through the ALB |
| DET-003 | Cross-Site Scripting Attempt | Apache access logs | High | T1190 – Exploit Public-Facing Application | Encoded reflected-XSS request sent to DVWA |
| DET-004 | Potential IAM Privilege Escalation | CloudTrail | High/Critical | T1098 – Account Manipulation | Detection logic and available IAM audit events reviewed |
| DET-005 | CloudTrail Logging Modified or Disabled | CloudTrail | High/Critical | T1562.008 – Disable or Modify Cloud Logs | Non-persistent synthetic logic test; no trail disruption performed |
| DET-006 | Security Group Opened to the Internet | CloudTrail | Medium–Critical | T1562.007 – Disable or Modify System Firewall | Non-persistent synthetic logic test; no unsafe exposure created |
| DET-007 | Repeated AWS WAF Rule Matches | AWS WAF logs | Low–High | T1190 – Exploit Public-Facing Application | Repeated authorized web-attack simulations |
| DET-008 | Directory Traversal Attempt | Apache access logs | High | T1190 – Exploit Public-Facing Application | Encoded traversal request sent to DVWA |
| DET-009 | Web Reconnaissance and Enumeration | Apache access logs | Medium | T1595 – Active Scanning | Requests to multiple commonly enumerated paths |
| DET-010 | Successful SSH Login Following Multiple Failures | Linux authentication logs | High | T1110 – Brute Force | Failed logins followed by an authorized key-based login from the same IP |

### Detection Design Principles

- Prefer decoded and normalized request values when matching encoded web payloads.
- Extract source IP addresses explicitly when automatic field extraction is unreliable.
- Preserve raw evidence for analyst review.
- Group repeated events by source, host, identity, or resource.
- Use severity based on behavior and outcome rather than event name alone.
- Distinguish successful cloud changes from failed attempts.
- Account for AWS log-delivery delay with appropriate lookback windows.
- Use throttling to prevent duplicate alert storms.
- Never perform a dangerous cloud change solely to produce a detection screenshot.

## SOC Dashboard

The Splunk Dashboard Studio dashboard provides the following views:

- Failed SSH attempts
- Total ingested events
- AWS WAF inspected requests
- AWS API activity
- Security events over time
- Top external web source IPs
- AWS WAF rule-match distribution
- Active log-source health
- Historical VPC traffic disposition
- Historical top destination ports
- Live security investigation queue
- High-volume web sources

![SOC Dashboard Overview](screenshots/dashboard/soc-dashboard-overview.png)

![Cloud and Web Security Monitoring](screenshots/dashboard/soc-dashboard-cloud-activity.png)

![WAF and Log Source Health](screenshots/dashboard/soc-dashboard-waf-health.png)

![Network and Investigation View](screenshots/dashboard/soc-dashboard-network-investigation.png)

The dashboard source is available at:

[`dashboard/cloud_security_soc_dashboard.json`](dashboard/cloud_security_soc_dashboard.json)

## Authorized Attack Simulations

Testing was limited to the project owner’s DVWA lab and AWS resources.

| Simulation | Security objective | Expected evidence |
|---|---|---|
| Invalid-user SSH attempts | Validate authentication-abuse monitoring | `linux_secure` events and DET-001 |
| Failed SSH attempts followed by valid login | Validate correlation across failure and success | DET-010 |
| SQL injection request | Validate payload decoding and web-attack detection | Apache event, possible WAF match, DET-002 |
| Cross-site scripting request | Validate encoded payload inspection | Apache event, WAF managed-rule match, DET-003 |
| Directory traversal request | Validate file-path abuse detection | Apache event and DET-008 |
| Common-path enumeration | Validate reconnaissance thresholding | Multiple unique URLs and DET-009 |
| Repeated managed-rule matches | Validate WAF aggregation | DET-007 |

No testing should be directed at systems that the tester does not own or have explicit permission to assess.

## Incident Investigation Workflow

```mermaid
flowchart LR
    A[Collect telemetry] --> B[Normalize fields]
    B --> C[Run SPL detections]
    C --> D[Generate alert]
    D --> E[Validate evidence]
    E --> F[Scope affected assets]
    F --> G[Assign severity]
    G --> H[Analyst decision]
    H --> I[Document and close or escalate]
```

### Recommended Analyst Questions

1. Is the source internal, external, expected, or previously observed?
2. Did the event succeed, fail, or operate in monitoring/count mode?
3. Which hosts, AWS resources, users, or roles were affected?
4. Are related events visible in another data source?
5. Does the behavior match a known administrative activity?
6. Is the evidence sufficient to contain, escalate, or close the incident?
7. What telemetry or context is missing?

## Security Risk Assessment

| Risk | Evidence or condition | Potential impact | Current control | Residual risk | Recommendation |
|---|---|---|---|---|---|
| DVWA is intentionally vulnerable | Application supports controlled exploitation | Unauthorized access or compromise if exposed broadly | Lab-only purpose, WAF visibility, centralized logging | High if left internet-accessible | Restrict source ranges, stop instances when not testing, never use production data, and destroy the lab when complete |
| WAF is in monitoring/count mode | Requests are logged but not necessarily blocked | Known malicious requests may reach DVWA | Managed-rule visibility and Splunk alerting | High for an internet-facing vulnerable app | Review false positives, then move selected validated rules to Block mode using a staged change process |
| HTTP is used at the ALB | Browser displays an insecure connection | Traffic can be intercepted or modified | Lab scope only | Medium | Use an ACM certificate and HTTPS listener; redirect HTTP to HTTPS |
| VPC Flow ingestion is paused in Splunk | High event volume affected SIEM stability | Reduced real-time network visibility | AWS-side logging and on-demand ingestion | Medium | Apply targeted flow-log filters, shorter retention, summary indexing, or a scalable ingestion tier |
| Single Splunk EC2 instance | One system performs search, indexing, and dashboards | SIEM outage creates a monitoring gap | Boot-start, resource checks, and lab maintenance | Medium–High | Use EBS snapshots, configuration backups, health alarms, and separate Splunk roles for production |
| WAF and CloudWatch delivery delay | WAF events may arrive later than host logs | Short searches can miss recent activity | One-hour WAF detection lookback and alert throttling | Medium | Monitor ingestion latency and tune lookbacks based on measured delay |
| Root or highly privileged AWS activity | CloudTrail may record privileged actors | Account-wide compromise if credentials are abused | CloudTrail monitoring and IAM detections | High | Enable root MFA, remove root access keys, use least-privilege roles, and alert on root activity |
| Public administration interfaces | SSH or Splunk Web may be reachable from the internet | Brute force, exploitation, or unauthorized access | Security groups and authentication logs | High if broadly exposed | Restrict to a trusted IP or VPN, use key-only SSH, disable password login, and avoid exposing Splunk Web publicly |
| Sensitive information in evidence | Screenshots may contain account IDs, ARNs, IPs, or resource names | Information disclosure and attacker reconnaissance | Manual redaction before publishing | Medium | Use sanitized evidence and automated secret scanning before every GitHub commit |
| Alert thresholds are lab-specific | Small test volumes differ from enterprise baselines | False positives or missed attacks | Controlled validation | Medium | Establish production baselines, tune thresholds, document exceptions, and measure detection quality |

## Security Impact

The platform provides the following measurable engineering outcomes without relying on unsupported claims:

- Centralized four active security-data domains: AWS control plane, AWS WAF, Linux authentication/system activity, and Apache web activity.
- Validated ten custom SPL detections across identity, web, and cloud-security use cases.
- Correlated failed and successful SSH activity by source and host.
- Preserved decoded web-request evidence for investigation.
- Identified AWS-managed WAF rules triggered during controlled simulations.
- Implemented health monitoring for active log sources.
- Added scheduled alerts with throttling to reduce duplicate notifications.
- Documented data-ingestion constraints and deliberately paused a high-volume source rather than allowing it to destabilize the SIEM.

## Production Recommendations

### Immediate

1. Restrict SSH and Splunk Web access to a trusted IP, VPN, or bastion.
2. Enforce key-based SSH and disable password authentication.
3. Add HTTPS to the ALB using AWS Certificate Manager.
4. Review WAF Count-mode matches and move validated protections to Block mode.
5. Enable MFA for privileged identities and avoid routine root-user activity.
6. Configure EBS snapshots and Splunk configuration backups.
7. Add CloudWatch alarms for EC2 health, disk usage, memory pressure, and service availability.

### Near Term

1. Tune detections against an established baseline.
2. Filter VPC Flow Logs to security-relevant traffic before continuous ingestion.
3. Add asset criticality, environment, owner, and business-service context.
4. Create documented triage playbooks for every detection.
5. Add approved email, ticketing, or chat notifications.
6. Test restore procedures for Splunk configuration and indexed data.
7. Add secret scanning and repository protection to the GitHub workflow.

### Long Term

1. Deploy infrastructure through reviewed Terraform modules.
2. Evaluate Amazon GuardDuty after cost and operational approval.
3. Separate Splunk search, indexing, and collection roles for scale and resilience.
4. Add a controlled SOAR workflow with explicit analyst approval.
5. Introduce detection-as-code testing and version-controlled deployment.
6. Add continuous validation using safe, repeatable security test cases.

These are roadmap items and are not represented as completed features.

## Limitations

- The environment is a lab, not a production deployment.
- DVWA is intentionally insecure.
- AWS WAF is currently used for monitoring/count visibility.
- VPC Flow ingestion into Splunk is paused except during investigations.
- The Splunk deployment is a single-node architecture.
- Some cloud detections remain quiet unless the corresponding administrative action occurs.
- Synthetic tests validate SPL output logic but do not prove end-to-end ingestion of an event that was never generated.
- GuardDuty, Terraform, Kubernetes, AI analysis, and automated containment are not implemented.
- Detection thresholds require tuning before enterprise use.

## Repository Structure

```text
Enterprise-Cloud-Security-Monitoring-Platform/
├── README.md
├── architecture/
│   ├── aws-soc-architecture-3d.png
│   └── aws-soc-architecture.cloudcraft
├── dashboard/
│   └── cloud_security_soc_dashboard.json
├── detections/
│   ├── DET-001-ssh-brute-force.spl
│   ├── DET-002-sql-injection.spl
│   ├── DET-003-xss-attempt.spl
│   ├── DET-004-iam-privilege-escalation.spl
│   ├── DET-005-cloudtrail-tampering.spl
│   ├── DET-006-public-security-group.spl
│   ├── DET-007-repeated-waf-matches.spl
│   ├── DET-008-directory-traversal.spl
│   ├── DET-009-web-reconnaissance.spl
│   └── DET-010-successful-ssh-after-failures.spl
├── screenshots/
│   ├── architecture/
│   ├── aws/
│   ├── dashboard/
│   └── detections/
└── docs/
    └── detection-validation.md
```

## Reproducing the Project

### Prerequisites

- An authorized AWS account and isolated lab environment
- Two Ubuntu EC2 web servers
- One EC2 instance for Splunk Enterprise
- Application Load Balancer
- AWS WAF
- CloudTrail, Amazon S3, Amazon SQS, and CloudWatch Logs
- Splunk Enterprise
- Splunk Universal Forwarder
- Splunk Add-on for AWS
- Kali Linux or another explicitly authorized test host

### Deployment Sequence

1. Create the VPC, subnets, route tables, internet connectivity, and security groups.
2. Deploy two Ubuntu web servers and install Apache and DVWA.
3. Create an ALB, register both instances, and validate target health.
4. Associate AWS WAF with the ALB and begin in Count/monitoring mode.
5. Deploy Splunk Enterprise and restrict management access.
6. Install Universal Forwarders and configure Apache, authentication, and syslog monitoring.
7. Enable CloudTrail and deliver logs through S3 and SQS to Splunk.
8. Enable WAF logging through CloudWatch Logs and configure the Splunk AWS input.
9. Enable VPC Flow Logs and validate on-demand ingestion.
10. Create indexes, field extractions, dashboard panels, saved searches, and scheduled alerts.
11. Run only authorized simulations and record validation evidence.
12. Stop or remove lab resources when testing is complete.

Detailed deployment values such as account IDs, IP addresses, credentials, ARNs, tokens, and private keys must never be committed to this repository.

## Importing the Dashboard

1. Open Splunk Dashboard Studio.
2. Create a new dashboard.
3. Open the dashboard source editor.
4. Copy the sanitized JSON from `dashboard/cloud_security_soc_dashboard.json`.
5. Validate data-source names, index names, and time tokens.
6. Save the dashboard.

The dashboard assumes the index and sourcetype names documented in this README. Adjust them when deploying into another environment.

## Using the Detection Files

Each `.spl` file contains the production search for one detection.

Recommended alert settings:

- Schedule: every five minutes
- Trigger condition: result count greater than zero
- Trigger mode: once per search
- Throttling: normally 30 minutes using the relevant source, identity, host, or resource
- Action: add to Splunk Triggered Alerts
- Response: analyst review before containment

Do not use the synthetic `makeresults` searches as production detections.

## Evidence Handling

Public screenshots must be reviewed and redacted before upload. Remove:

- AWS account IDs
- Access-key identifiers and secrets
- Public and private IP addresses when disclosure is unnecessary
- Full IAM user and role ARNs
- EC2 instance IDs
- S3 bucket names
- SQS queue URLs
- ALB DNS names
- Splunk session information
- Webhook URLs
- Private-key names or contents

## Cost and Resource Management

This lab is not intended to run continuously.

- Stop EC2 instances when the lab is not in use.
- Review EBS, snapshot, CloudWatch, WAF, S3, SQS, and data-transfer charges.
- Use AWS Budgets and billing alerts.
- Control high-volume telemetry before enabling continuous SIEM ingestion.
- Delete unused resources after preserving sanitized evidence and configuration backups.

## Disclaimer

This repository is for defensive-security education and authorized testing. DVWA and all attack simulations must be used only in an isolated environment owned by the tester or covered by explicit written authorization.

## Author

**Parakh Shinde**  
Cloud Security and SOC Engineering Portfolio Project

## License

This project is released under the MIT License. Third-party products, icons, and trademarks remain the property of their respective owners.
