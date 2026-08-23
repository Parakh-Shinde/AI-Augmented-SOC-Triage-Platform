import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"

ALLOWED_ACTIONS = {
    "block_source_ip",
    "isolate_host",
    "disable_user",
    "collect_forensic_data"
}


def initialize_soar_table() -> None:
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS soar_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT NOT NULL,
                executed_by TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES incidents(alert_id)
            )
            """
        )
        connection.commit()


def get_latest_review(alert_id: str) -> Optional[dict]:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT decision, analyst, notes, reviewed_at
            FROM analyst_reviews
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (alert_id,)
        ).fetchone()

    return dict(row) if row else None


def get_incident(alert_id: str) -> Optional[dict]:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT alert_id, host, source_ip, destination_ip,
                   detection_name, status
            FROM incidents
            WHERE alert_id = ?
            LIMIT 1
            """,
            (alert_id,)
        ).fetchone()

    return dict(row) if row else None


def determine_target(incident: dict, action: str) -> Optional[str]:
    if action == "block_source_ip":
        return incident.get("source_ip")

    if action == "isolate_host":
        return incident.get("host")

    if action == "disable_user":
        return "unknown-user"

    if action == "collect_forensic_data":
        return incident.get("host")

    return None


def save_soar_action(
    alert_id: str,
    action: str,
    target: str,
    mode: str,
    status: str,
    result: dict,
    executed_by: str
) -> None:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            INSERT INTO soar_actions (
                alert_id,
                action,
                target,
                mode,
                status,
                result,
                executed_by,
                executed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                action,
                target,
                mode,
                status,
                json.dumps(result),
                executed_by,
                datetime.now(timezone.utc).isoformat()
            )
        )
        connection.commit()


def execute_soar_action(
    alert_id: str,
    action: str,
    executed_by: str = "SOC Analyst",
    simulation: bool = True
) -> dict:
    initialize_soar_table()

    if action not in ALLOWED_ACTIONS:
        raise ValueError(
            f"Unsupported action: {action}"
        )

    incident = get_incident(alert_id)

    if not incident:
        raise ValueError(
            f"Incident not found: {alert_id}"
        )

    review = get_latest_review(alert_id)

    if not review:
        raise PermissionError(
            "SOAR action denied: analyst review is missing."
        )

    if review["decision"] != "containment_approved":
        raise PermissionError(
            "SOAR action denied: containment has not been approved."
        )

    target = determine_target(incident, action)

    if not target:
        raise ValueError(
            f"No valid target available for action: {action}"
        )

    if simulation:
        mode = "simulation"
        status = "simulated"

        result = {
            "message": "Action safely simulated; no system was changed.",
            "action": action,
            "target": target,
            "approved_by": review["analyst"],
            "approval_time": review["reviewed_at"]
        }
    else:
        raise PermissionError(
            "Live response actions are disabled in this lab version."
        )

    save_soar_action(
        alert_id=alert_id,
        action=action,
        target=target,
        mode=mode,
        status=status,
        result=result,
        executed_by=executed_by
    )

    return {
        "alert_id": alert_id,
        "action": action,
        "target": target,
        "mode": mode,
        "status": status,
        "result": result
    }


if __name__ == "__main__":
    initialize_soar_table()
    print("SOAR action table is ready.")
    print("Live response actions remain disabled.")