from app.models import Alert
from app.redactor import redact_sensitive_data

def normalize_alert(payload: dict) -> Alert:
    raw_event = str(
        payload.get("raw_event")
        or payload.get("_raw")
        or ""
    )

    return Alert(
        detection_name=str(
            payload.get("detection_name")
            or payload.get("search_name")
            or "Unknown Detection"
        ),
        source_system=str(
            payload.get("source_system")
            or "Splunk"
        ),
        log_source=str(
            payload.get("log_source")
            or payload.get("sourcetype")
            or "unlnown"
        ),
        host=str(payload.get("host") or "unknown"),
        source_ip=payload.get("source_ip"),
        destination_ip=payload.get("destination_ip"),
        raw_event=redact_sensitive_data(raw_event)
    )
