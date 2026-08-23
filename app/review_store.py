import sqlite3
from datetime import datetime, timezone

from app.database import DATABASE_FILE


ALLOWED_DECISIONS = {
    "escalated",
    "false_positive",
    "containment_approved",
    "closed"
}


def save_analyst_review(
    alert_id: str,
    decision: str,
    analyst: str,
    notes: str
) -> None:
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(
            f"Invalid analyst decision: {decision}"
        )

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO analyst_reviews (
                alert_id,
                decision,
                analyst,
                notes,
                reviewed_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                decision,
                analyst,
                notes,
                datetime.now(timezone.utc).isoformat()
            )
        )

        connection.execute(
            """
            UPDATE incidents
            SET status = ?
            WHERE alert_id = ?
            """,
            (
                decision,
                alert_id
            )
        )

        connection.commit()


def get_analyst_review(
    alert_id: str
) -> dict | None:
    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                alert_id,
                decision,
                analyst,
                notes,
                reviewed_at
            FROM analyst_reviews
            WHERE alert_id = ?
            """,
            (alert_id,)
        ).fetchone()

    if row is None:
        return None

    return dict(row)