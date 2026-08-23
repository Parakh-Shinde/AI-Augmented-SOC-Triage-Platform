import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from app.models import Alert, TriageResult

PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"

def initialize_database() -> None:
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                detection_name TEXT NOT NULL,
                source_system TEXT NOT NULL,
                log_source TEXT NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                raw_event TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        connection.commit()


def save_alert(alert: Alert) -> None:
    initialize_database()

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO incidents (
                alert_id, timestamp, detection_name, source_system,
                log_source, host, source_ip, destination_ip,
                raw_event, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.timestamp.isoformat(),
                alert.detection_name,
                alert.source_system,
                alert.log_source,
                alert.host,
                alert.source_ip,
                alert.destination_ip,
                alert.raw_event,
                alert.status
            )
        )
        connection.commit()
def save_triage_result(
    alert_id: str,
    result: TriageResult
) -> None:
    initialize_database()

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO triage_results (
                 alert_id, severity, verdict, confidence, summary,
                 mitre_techniques, evidence,
                 false_positive_indicators, recommended_actions,
                 requires_human_review, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?,  ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                result.severity,
                result.verdict,
                result.confidence,
                result.summary,
                json.dumps(
                    [
                       technique.model_dump()
                       for technique in result.mitre_techniques
                    ]
               ),
               json.dumps(result.evidence),
               json.dumps(result.false_positive_indicators),
               json.dumps(result.recommended_actions),
               int(result.requires_human_review),
               datetime.now(timezone.utc).isoformat()
            )
        )
        connection.commit()
if __name__ == "__main__":
    initialize_database()
    print(f"Database ready: {DATABASE_FILE}")
