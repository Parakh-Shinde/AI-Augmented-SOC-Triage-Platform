import argparse
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.review_store import get_analyst_review
from app.splunk_hec import send_hec_event


PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"
SAMPLES_DIR = PROJECT_DIR / "samples"
QUARANTINE_DIR = PROJECT_DIR / "quarantine"


def initialize_quarantine_table() -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.chmod(0o700)

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantine_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                alert_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                status TEXT NOT NULL,
                executed_by TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                restored_by TEXT,
                restored_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES yara_scans(id),
                FOREIGN KEY (alert_id) REFERENCES incidents(alert_id)
            )
            """
        )
        connection.commit()


def get_yara_scan(scan_id: int) -> Optional[dict]:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                id,
                alert_id,
                file_name,
                file_path,
                sha256,
                matched,
                match_count,
                scan_status
            FROM yara_scans
            WHERE id = ?
            LIMIT 1
            """,
            (scan_id,)
        ).fetchone()

    return dict(row) if row else None


def get_quarantine_action(action_id: int) -> Optional[dict]:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT *
            FROM quarantine_actions
            WHERE id = ?
            LIMIT 1
            """,
            (action_id,)
        ).fetchone()

    return dict(row) if row else None


def validate_source_file(file_path: str) -> Path:
    source_path = Path(file_path).expanduser().resolve()
    allowed_directory = SAMPLES_DIR.resolve()

    if not source_path.exists():
        raise FileNotFoundError(
            f"Source file does not exist: {source_path}"
        )

    if not source_path.is_file():
        raise ValueError(
            "Only regular files can be quarantined."
        )

    if source_path.is_symlink():
        raise ValueError(
            "Symbolic links cannot be quarantined."
        )

    try:
        source_path.relative_to(allowed_directory)
    except ValueError as error:
        raise PermissionError(
            "Only files inside the project samples directory can be quarantined."
        ) from error

    return source_path


def require_containment_approval(alert_id: str) -> dict:
    review = get_analyst_review(alert_id)

    if not review:
        raise PermissionError(
            "Quarantine denied: analyst review is missing."
        )

    if review.get("decision") != "containment_approved":
        raise PermissionError(
            "Quarantine denied: containment has not been approved."
        )

    return review


def create_quarantine_path(scan: dict) -> Path:
    safe_name = Path(scan["file_name"]).name
    hash_prefix = scan["sha256"][:12]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    return QUARANTINE_DIR / (
        f"{timestamp}_{hash_prefix}_{safe_name}.quarantined"
    )


def save_quarantine_action(
    scan: dict,
    original_path: Path,
    quarantine_path: Path,
    executed_by: str
) -> int:
    quarantined_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DATABASE_FILE) as connection:
        cursor = connection.execute(
            """
            INSERT INTO quarantine_actions (
                scan_id,
                alert_id,
                file_name,
                sha256,
                original_path,
                quarantine_path,
                status,
                executed_by,
                quarantined_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan["id"],
                scan["alert_id"],
                scan["file_name"],
                scan["sha256"],
                str(original_path),
                str(quarantine_path),
                "quarantined",
                executed_by,
                quarantined_at
            )
        )
        connection.commit()
        return int(cursor.lastrowid)


def quarantine_scan(
    scan_id: int,
    executed_by: str
) -> dict:
    initialize_quarantine_table()

    scan = get_yara_scan(scan_id)

    if not scan:
        raise ValueError(
            f"YARA scan not found: {scan_id}"
        )

    if not scan.get("alert_id"):
        raise PermissionError(
            "Quarantine denied: the YARA scan is not linked to an incident."
        )

    if not bool(scan.get("matched")):
        raise PermissionError(
            "Quarantine denied: the file did not match a YARA rule."
        )

    review = require_containment_approval(scan["alert_id"])
    source_path = validate_source_file(scan["file_path"])
    quarantine_path = create_quarantine_path(scan)

    try:
        shutil.move(str(source_path), str(quarantine_path))

        action_id = save_quarantine_action(
            scan=scan,
            original_path=source_path,
            quarantine_path=quarantine_path,
            executed_by=executed_by
        )
    except Exception:
        if quarantine_path.exists() and not source_path.exists():
            shutil.move(str(quarantine_path), str(source_path))
        raise

    event = {
        "event_type": "yara_quarantine",
        "action_id": action_id,
        "scan_id": scan_id,
        "alert_id": scan["alert_id"],
        "file_name": scan["file_name"],
        "sha256": scan["sha256"],
        "original_path": str(source_path),
        "quarantine_path": str(quarantine_path),
        "status": "quarantined",
        "executed_by": executed_by,
        "approved_by": review["analyst"],
        "requires_human_review": False
    }

    try:
        response = send_hec_event(
            event=event,
            source="ai_soc_yara_quarantine",
            sourcetype="_json",
            index="ai_triage"
        )
        event["splunk_hec_status"] = response.get(
            "text",
            "unknown"
        )
    except Exception as error:
        event["splunk_hec_status"] = "failed"
        event["splunk_hec_error"] = str(error)

    return event


def restore_quarantined_file(
    action_id: int,
    restored_by: str
) -> dict:
    initialize_quarantine_table()

    action = get_quarantine_action(action_id)

    if not action:
        raise ValueError(
            f"Quarantine action not found: {action_id}"
        )

    if action["status"] != "quarantined":
        raise ValueError(
            "This quarantine action is not currently restorable."
        )

    quarantine_path = Path(
        action["quarantine_path"]
    ).expanduser().resolve()

    original_path = Path(
        action["original_path"]
    ).expanduser().resolve()

    if not quarantine_path.exists():
        raise FileNotFoundError(
            "The quarantined file is missing."
        )

    if original_path.exists():
        raise FileExistsError(
            "Restore denied because the original path already exists."
        )

    original_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantine_path), str(original_path))

    restored_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            UPDATE quarantine_actions
            SET status = ?,
                restored_by = ?,
                restored_at = ?
            WHERE id = ?
            """,
            (
                "restored",
                restored_by,
                restored_at,
                action_id
            )
        )
        connection.commit()

    event = {
        "event_type": "yara_quarantine_restore",
        "action_id": action_id,
        "alert_id": action["alert_id"],
        "file_name": action["file_name"],
        "sha256": action["sha256"],
        "restored_path": str(original_path),
        "status": "restored",
        "restored_by": restored_by,
        "restored_at": restored_at
    }

    try:
        response = send_hec_event(
            event=event,
            source="ai_soc_yara_quarantine",
            sourcetype="_json",
            index="ai_triage"
        )
        event["splunk_hec_status"] = response.get(
            "text",
            "unknown"
        )
    except Exception as error:
        event["splunk_hec_status"] = "failed"
        event["splunk_hec_error"] = str(error)

    return event


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Human-approved YARA quarantine service."
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    quarantine_parser = subparsers.add_parser(
        "quarantine"
    )
    quarantine_parser.add_argument(
        "scan_id",
        type=int
    )
    quarantine_parser.add_argument(
        "--analyst",
        required=True
    )

    restore_parser = subparsers.add_parser(
        "restore"
    )
    restore_parser.add_argument(
        "action_id",
        type=int
    )
    restore_parser.add_argument(
        "--analyst",
        required=True
    )

    arguments = parser.parse_args()

    if arguments.command == "quarantine":
        result = quarantine_scan(
            scan_id=arguments.scan_id,
            executed_by=arguments.analyst
        )
    else:
        result = restore_quarantined_file(
            action_id=arguments.action_id,
            restored_by=arguments.analyst
        )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()