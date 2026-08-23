from app.models import Alert, MitreTechnique


def add_technique(
    techniques: list[MitreTechnique],
    technique_id: str,
    technique_name: str
) -> None:
    existing_ids = {
        technique.technique_id
        for technique in techniques
    }

    if technique_id not in existing_ids:
        techniques.append(
            MitreTechnique(
                technique_id=technique_id,
                technique_name=technique_name
            )
        )


def map_mitre_techniques(
    alert: Alert
) -> list[MitreTechnique]:
    text = (
        alert.detection_name
        + " "
        + alert.log_source
        + " "
        + alert.raw_event
    ).lower()

    techniques = []

    if "ssh" in text and (
        "brute force" in text
        or "failed login" in text
        or "failed ssh" in text
        or "authentication failure" in text
    ):
        add_technique(
            techniques,
            "T1110.001",
            "Password Guessing"
        )

    if "powershell" in text and (
        "encodedcommand" in text
        or "-enc " in text
        or "base64" in text
    ):
        add_technique(
            techniques,
            "T1059.001",
            "PowerShell"
        )

    if (
        "port scan" in text
        or "nmap" in text
        or "network service scan" in text
        or "multiple destination ports" in text
    ):
        add_technique(
            techniques,
            "T1046",
            "Network Service Discovery"
        )

    if (
        "sql injection" in text
        or "sqli" in text
        or "union select" in text
        or "' or '1'='1" in text
    ):
        add_technique(
            techniques,
            "T1190",
            "Exploit Public-Facing Application"
        )

    if (
        "cross-site scripting" in text
        or "reflected xss" in text
        or "xss" in text
        or "<script" in text
        or "javascript:" in text
        or "onerror=" in text
    ):
        add_technique(
            techniques,
            "T1190",
            "Exploit Public-Facing Application"
        )

    if (
        "reverse shell" in text
        or "netcat" in text
        or "nc.exe" in text
        or "/bin/bash -i" in text
    ):
        add_technique(
            techniques,
            "T1059",
            "Command and Scripting Interpreter"
        )

    if (
        "scheduled task" in text
        or "schtasks" in text
    ):
        add_technique(
            techniques,
            "T1053.005",
            "Scheduled Task"
        )

    if (
        "credential dumping" in text
        or "mimikatz" in text
        or "lsass" in text
    ):
        add_technique(
            techniques,
            "T1003.001",
            "LSASS Memory"
        )

    return techniques