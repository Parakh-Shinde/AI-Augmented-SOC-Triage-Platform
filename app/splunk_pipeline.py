"""Collect live security detections from Splunk and run AI triage."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.ai_triage import triage_alert
from app.database import save_alert, save_triage_result
from app.normalizer import normalize_alert
from app.splunk_hec import send_hec_event
from app.splunk_search import run_splunk_search

PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"
SEARCH_WINDOW = "-30m"
MAX_NEW_ALERTS_PER_RUN = 6

# Convert telemetry into actionable alerts. This covers every lab source while
# preventing harmless raw events from exhausting the small local LLM.
DETECTION_SEARCHES = {
    "encoded_powershell": r'''
index=windows source="WinEventLog:Windows PowerShell" ("-EncodedCommand" OR "-enc ")
| rex field=_raw "<EventID[^>]*>(?<windows_event_id>\d+)</EventID>"
| search windows_event_id IN (400,403)
| eval detection_name="Encoded PowerShell Execution", detection_source="windows_powershell"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "windows_failed_logon": r'''
index=windows source="WinEventLog:Security"
| rex field=_raw "<EventID[^>]*>(?<windows_event_id>\d+)</EventID>"
| search windows_event_id=4625
| rex field=_raw "<Data[^>]+Name=.IpAddress.[^>]*>(?<source_ip>[^<]+)"
| eval detection_name="Windows Failed Logon", detection_source="windows_security"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "suspicious_sysmon_process": r'''
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<windows_event_id>\d+)</EventID>"
| search windows_event_id=1
| search _raw="*mshta.exe*" OR _raw="*regsvr32.exe*" OR _raw="*rundll32.exe*" OR _raw="*certutil.exe*" OR _raw="*bitsadmin.exe*" OR _raw="*wmic.exe*" OR _raw="*schtasks.exe*"
| eval detection_name="Suspicious Windows LOLBin Execution", detection_source="sysmon"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "linux_ssh_failures": r'''
index=linux ("Failed password" OR "authentication failure")
| rex field=_raw "from\s+(?<source_ip>\d+\.\d+\.\d+\.\d+)"
| eval detection_name="Linux SSH Authentication Failure", detection_source="linux_auth"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "dvwa_web_attack": r'''
index=web host=web-server
| rex field=_raw "^(?<source_ip>\S+)"
| eval decoded_event=lower(urldecode(_raw))
| where match(decoded_event,"union.*select|('|%27).*or.*('|%27)|<script|%3cscript|javascript:|onerror=|\.\./|%2e%2e|;cat\s|;id\s|/etc/passwd")
| eval detection_name=case(match(decoded_event,"union.*select|('|%27).*or.*('|%27)"),"DVWA SQL Injection Attempt",match(decoded_event,"<script|%3cscript|javascript:|onerror="),"DVWA XSS Attempt",match(decoded_event,"\.\./|%2e%2e|/etc/passwd"),"Web Path Traversal Attempt",true(),"Web Command Injection Attempt")
| eval detection_source="apache_dvwa"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "suricata_alerts": r'''
index=suricata event_type=alert
| spath
| eval detection_name=coalesce('alert.signature',signature,"Suricata Network Alert"), detection_source="suricata"
| eval source_ip=coalesce(src_ip,source_ip), destination_ip=coalesce(dest_ip,destination_ip)
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "yara_alerts": r'''
index=ai_triage event_type="yara_detection" matched=true
| eval detection_name="YARA File Signature Match", detection_source="yara"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
    "generic_security_alerts": r'''
index=security_alerts
| eval detection_name=coalesce(detection_name,search_name,rule_name,"Generic Security Alert"), detection_source="security_alerts"
| table _time detection_name detection_source host source sourcetype source_ip destination_ip _raw
| sort 0 - _time | head 20
''',
}


def initialize_processed_events_table() -> None:
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS processed_splunk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE NOT NULL,
                splunk_time TEXT,
                detection_name TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )"""
        )


def calculate_event_hash(event: dict) -> str:
    stable = {key: event.get(key) for key in (
        "_time", "detection_name", "detection_source", "host", "source",
        "sourcetype", "source_ip", "destination_ip", "_raw"
    )}
    encoded = json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def event_was_processed(event_hash: str) -> bool:
    with sqlite3.connect(DATABASE_FILE) as connection:
        return connection.execute(
            "SELECT 1 FROM processed_splunk_events WHERE event_hash=? LIMIT 1",
            (event_hash,),
        ).fetchone() is not None


def mark_event_processed(event_hash: str, event: dict, alert_id: str) -> None:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """INSERT OR IGNORE INTO processed_splunk_events
            (event_hash, splunk_time, detection_name, alert_id, processed_at)
            VALUES (?, ?, ?, ?, ?)""",
            (event_hash, event.get("_time"), event.get("detection_name"),
             alert_id, datetime.now(timezone.utc).isoformat()),
        )


def collect_live_alerts() -> list[dict]:
    alerts = []
    for detector, query in DETECTION_SEARCHES.items():
        try:
            events = run_splunk_search(query, earliest_time=SEARCH_WINDOW)
            print(f"Detector {detector}: {len(events)} alert(s)")
            alerts.extend(events)
        except Exception as exc:
            print(f"Detector {detector} failed: {type(exc).__name__}: {exc}")
    alerts.sort(key=lambda item: str(item.get("_time", "")), reverse=True)
    return alerts

def first_scalar(value):
    """Convert Splunk multivalue field into one normalized value. """
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if item not in (None, "", "-", "null"):
                return str(item)
        return None
    if value in (None, "", "-" "null"):
        return None

    return str(value)


def build_alert_payload(event: dict) -> dict:
    return {
        "search_name": event.get("detection_name", "Unknown Splunk Detection"),
        "source_system": "Splunk",
        "sourcetype": event.get("sourcetype") or event.get("source") or "unknown",
        "host": event.get("host", "unknown"),
        "source_ip": first_scalar(event.get("source_ip")),
        "destination_ip": first_scalar(event.get("destination_ip")),
        "_raw": event.get("_raw", ""),
    }


def send_triage_to_splunk(alert, result, event: dict) -> str:
    response = send_hec_event(
        {
            "event_type": "ai_triage_result",
            "alert_id": alert.alert_id,
            "detection_name": alert.detection_name,
            "detection_source": event.get("detection_source"),
            "severity": result.severity,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "summary": result.summary,
            "mitre_techniques": [item.model_dump() for item in result.mitre_techniques],
            "recommended_actions": result.recommended_actions,
            "requires_human_review": result.requires_human_review,
        },
        source="ai_soc_universal_pipeline",
        sourcetype="_json",
    )
    return str(response)


def process_event(event: dict, event_hash: str) -> None:
    alert = normalize_alert(build_alert_payload(event))
    save_alert(alert)
    print(f"Alert saved: {alert.alert_id} | {alert.detection_name}")
    result = triage_alert(alert)
    save_triage_result(alert.alert_id, result)
    hec_status = send_triage_to_splunk(alert, result, event)
    mark_event_processed(event_hash, event, alert.alert_id)
    print(f"Triage: {result.severity} | {result.verdict} | HEC: {hec_status}")


def main() -> None:
    initialize_processed_events_table()
    events = collect_live_alerts()
    if not events:
        print("No security alerts matched the configured Splunk detections.")
        return

    processed = duplicates = deferred = failed = 0
    for event in events:
        event_hash = calculate_event_hash(event)
        if event_was_processed(event_hash):
            duplicates += 1
            continue
        if processed >= MAX_NEW_ALERTS_PER_RUN:
            deferred += 1
            continue
        try:
            process_event(event, event_hash)
            processed += 1
        except Exception as exc:
            failed += 1
            print(f"Alert processing failed: {type(exc).__name__}: {exc}")

    print(
        "Universal pipeline summary: "
        f"processed={processed}, duplicates={duplicates}, "
        f"deferred={deferred}, failed={failed}"
    )


if __name__ == "__main__":
    main()
