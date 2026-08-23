import os
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


PROJECT_DIR = Path.home() / "ai-soc-triage"
load_dotenv(PROJECT_DIR / ".env")

SPLUNK_URL = os.getenv(
    "SPLUNK_URL",
    "https://127.0.0.1:8089"
).rstrip("/")

SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

SPLUNK_VERIFY_SSL = (
    os.getenv("SPLUNK_VERIFY_SSL", "false").lower()
    == "true"
)


if not SPLUNK_VERIFY_SSL:
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )


def create_splunk_session() -> requests.Session:
    if not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
        raise ValueError(
            "Splunk username or password is missing from .env"
        )

    session = requests.Session()
    session.auth = (
        SPLUNK_USERNAME,
        SPLUNK_PASSWORD
    )
    session.verify = SPLUNK_VERIFY_SSL

    return session


def test_splunk_connection() -> str:
    session = create_splunk_session()

    response = session.get(
        f"{SPLUNK_URL}/services/server/info",
        params={"output_mode": "json"},
        timeout=20
    )

    response.raise_for_status()

    entries = response.json().get("entry", [])

    if not entries:
        return "unknown"

    return str(
        entries[0]
        .get("content", {})
        .get("version", "unknown")
    )


if __name__ == "__main__":
    version = test_splunk_connection()
    print(f"Splunk API connected. Version: {version}")