import json

from app.splunk_client import (
    SPLUNK_URL,
    create_splunk_session
)


def run_splunk_search(
    search_query: str,
    earliest_time: str = "-24h",
    latest_time: str = "now"
) -> list[dict]:
    session = create_splunk_session()

    if not search_query.strip().startswith("search "):
        search_query = f"search {search_query}"

    response = session.post(
        f"{SPLUNK_URL}/services/search/jobs/export",
        data={
            "search": search_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json"
        },
        timeout=120
    )

    response.raise_for_status()

    results = []

    for line in response.text.splitlines():
        if not line.strip():
            continue

        event = json.loads(line)
        result = event.get("result")

        if result:
            results.append(result)

    return results


if __name__ == "__main__":
    events = run_splunk_search(
        """
        index=windows
        | head 5
        | table _time host source sourcetype _raw
        """,
        earliest_time="-30d"
    )

    print(f"Splunk events returned: {len(events)}")

    for event in events:
        print(json.dumps(event, indent=2))