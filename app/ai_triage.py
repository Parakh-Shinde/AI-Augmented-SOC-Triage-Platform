import os
from pathlib import Path

from dotenv import load_dotenv
from ollama import chat

from app.mitre_mapper import map_mitre_techniques
from app.models import Alert, TriageResult
from app.prompt import SYSTEM_PROMPT

PROJECT_DIR = Path.home() / "ai-soc-triage"
load_dotenv(PROJECT_DIR / ".env")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")


def triage_alert(alert: Alert) -> TriageResult:
    response = chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": alert.model_dump_json(indent=2)
            }
        ],
        format=TriageResult.model_json_schema(),
        options={
            "temperature": 0
        }
    )
    return TriageResult.model_validate_json(
        response.message.content
    )

    if not result.mitre_techniques:
        result.mitre_techniques = map_mitre_techniques(alert)

    return result
