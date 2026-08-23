import os
from datetime import datetime, timezone
from typing import Any

import requests
from dotenv import load_dotenv


load_dotenv()

SPLUNK_HEC_URL = os.getenv(
    "SPLUNK_HEC_URL",
    "http://127.0.0.1:8088/services/collector/event"
)

SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")


def send_hec_event(
    event: dict[str, Any],
    source: str = "ai_soc_assistant",
    sourcetype: str = "_json",
    index: str = "ai_triage"
) -> dict:
    if not SPLUNK_HEC_TOKEN:
        raise ValueError(
            "SPLUNK_HEC_TOKEN is missing from the .env file."
        )

    payload = {
        "time": datetime.now(timezone.utc).timestamp(),
        "host": "soc-server",
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "event": event
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(
        SPLUNK_HEC_URL,
        headers=headers,
        json=payload,
        timeout=15
    )

    response.raise_for_status()
    return response.json()


def send_test_event() -> dict:
    test_event = {
        "event_type": "hec_connection_test",
        "status": "success",
        "message": "AI SOC Assistant connected to Splunk HEC",
        "requires_human_review": True
    }

    return send_hec_event(
        event=test_event,
        source="ai_soc_hec_test"
    )


if __name__ == "__main__":
    try:
        result = send_test_event()
        print("Splunk HEC response:", result)
    except requests.RequestException as error:
        print("Splunk HEC request failed:", error)
    except ValueError as error:
        print("Configuration error:", error)