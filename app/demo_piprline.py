from app.ai_triage import triage_alert
from app.database import save_alert, save_triage_result
from app.normalizer import normalize_alert

def main() -> None:
    payload = {
        "search_name": "SSH Brute Force",
        "sourcetype": "linux_secure",
        "host": "web-server",
        "source_ip": "10.0.10.40",
        "destination_ip": "10.0.10.20",
        "_raw": (
            "Six failed SSH login attempts for user admin"
            "from 10.0.10.40 within two minutes "
            "password=LAB_REDACTED"
        )
    }
    alert = normalize_alert(payload)
    save_alert(alert)

    print(f"Alert saved: {alert.alert_id}")
    print("Running local AI triage...")


    result = triage_alert(alert)
    save_triage_result(alert.alert_id, result)

    print(result.model_dump_json(indent=2))
    print("Triage result saved successfully.")

if __name__ == "__main__":
    main() 


