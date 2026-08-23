import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yara

from app.splunk_hec import send_hec_event


PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"
DEFAULT_RULE_FILE = PROJECT_DIR / "rules" / "lab_test.yar"

MAX_FILE_SIZE = 25 * 1024 * 1024


def initialize_yara_table() -> None:
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS yara_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                matched INTEGER NOT NULL,
                match_count INTEGER NOT NULL,
                matched_rules TEXT NOT NULL,
                scan_status TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file_handle:
        for block in iter(lambda: file_handle.read(8192), b""):
            sha256.update(block)

    return sha256.hexdigest()


def validate_file(file_path: Path) -> Path:
    resolved_path = file_path.expanduser().resolve()

    if not resolved_path.exists():
        raise FileNotFoundError(
            f"File does not exist: {resolved_path}"
        )

    if not resolved_path.is_file():
        raise ValueError(
            f"Path is not a regular file: {resolved_path}"
        )

    if resolved_path.is_symlink():
        raise ValueError(
            "Symbolic links are not allowed for YARA scanning."
        )

    file_size = resolved_path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            "File exceeds the 25 MB lab scanning limit."
        )

    return resolved_path


def serialize_matches(matches: list) -> list[dict]:
    serialized_matches = []

    for match in matches:
        serialized_matches.append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "metadata": dict(match.meta)
            }
        )

    return serialized_matches


def save_yara_result(result: dict) -> None:
    initialize_yara_table()

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            INSERT INTO yara_scans (
                alert_id,
                file_name,
                file_path,
                sha256,
                file_size,
                matched,
                match_count,
                matched_rules,
                scan_status,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("alert_id"),
                result["file_name"],
                result["file_path"],
                result["sha256"],
                result["file_size"],
                int(result["matched"]),
                result["match_count"],
                json.dumps(result["matched_rules"]),
                result["scan_status"],
                result["scanned_at"]
            )
        )
        connection.commit()


def scan_file(
    file_path: str,
    alert_id: Optional[str] = None,
    rule_file: Optional[str] = None
) -> dict:
    selected_file = validate_file(Path(file_path))

    selected_rule_file = Path(
        rule_file
    ).expanduser().resolve() if rule_file else DEFAULT_RULE_FILE.resolve()

    if not selected_rule_file.exists():
        raise FileNotFoundError(
            f"YARA rule file does not exist: {selected_rule_file}"
        )

    compiled_rules = yara.compile(
        filepath=str(selected_rule_file)
    )

    matches = compiled_rules.match(
        str(selected_file),
        timeout=30
    )

    matched_rules = serialize_matches(matches)
    scan_time = datetime.now(timezone.utc).isoformat()

    result = {
        "event_type": "yara_detection",
        "alert_id": alert_id,
        "file_name": selected_file.name,
        "file_path": str(selected_file),
        "sha256": calculate_sha256(selected_file),
        "file_size": selected_file.stat().st_size,
        "matched": bool(matches),
        "match_count": len(matches),
        "matched_rules": matched_rules,
        "scan_status": "matched" if matches else "clean",
        "scanned_at": scan_time,
        "requires_human_review": bool(matches)
    }

    save_yara_result(result)

    try:
        hec_response = send_hec_event(
            event=result,
            source="ai_soc_yara",
            sourcetype="_json",
            index="ai_triage"
        )
        result["splunk_hec_status"] = hec_response.get(
            "text",
            "unknown"
        )
    except Exception as error:
        result["splunk_hec_status"] = "failed"
        result["splunk_hec_error"] = str(error)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a file using the AI SOC YARA service."
    )

    parser.add_argument(
        "file",
        help="Path of the file to scan."
    )

    parser.add_argument(
        "--alert-id",
        default=None,
        help="Optional incident alert ID."
    )

    parser.add_argument(
        "--rule-file",
        default=None,
        help="Optional YARA rule file."
    )

    arguments = parser.parse_args()

    result = scan_file(
        file_path=arguments.file,
        alert_id=arguments.alert_id,
        rule_file=arguments.rule_file
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()