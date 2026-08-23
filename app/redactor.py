import re

def redact_sensitive_data(text: str, max_length: int = 4000) -> str:
    redacted = text

    redacted = re.sub(
        r"(?i)\b(password|passwd|pwd)=\S+",
        r"\1=[REDACTED]",
        redacted
    )

    redacted = re.sub(
        r"(?i)\b(api_key|token|secret)=\S+",
        r"\1=[REDACTED]",
        redacted
    )

    redacted = re.sub(
        r"(?i)authorization:\s*bearer\s+\S+",
        "authorization: Bearer [REDACTED]",
        redacted
    )

    redacted = re.sub(
        r"(?i)cookie:\s*\S+",
        "cookie: [REDACTED]",
        redacted
    )

    return redacted[:max_length]
