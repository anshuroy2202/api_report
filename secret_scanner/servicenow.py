import os
from typing import Dict, Optional


def _import_requests():
    try:
        import requests
    except ImportError as exc:
        raise ImportError("requests is required for ServiceNow integration") from exc
    return requests


def load_servicenow_config() -> Dict[str, Optional[str]]:
    return {
        "instance": os.getenv("SERVICENOW_INSTANCE"),
        "user": os.getenv("SERVICENOW_USER"),
        "password": os.getenv("SERVICENOW_PASSWORD"),
        "table": os.getenv("SERVICENOW_TABLE", "incident"),
    }


def can_create_incidents() -> bool:
    config = load_servicenow_config()
    return bool(config["instance"] and config["user"] and config["password"])


def build_incident_payload(finding: Dict, score: int) -> Dict:
    short_description = f"Secret scanning alert: {finding['secret_type']} found in {finding['file']}"
    description = (
        f"A secret matching type '{finding['secret_type']}' was found in file {finding['file']}."
        f" Severity: {finding['severity']}. Prioritization score: {score}.\n\n"
        f"Excerpt: {finding['match_text']}"
    )
    return {
        "short_description": short_description,
        "description": description,
        "urgency": "3" if score < 60 else "2" if score < 90 else "1",
        "impact": "2" if score < 60 else "1",
        "caller_id": "automated_scanner",
        "category": "security",
    }


def create_servicenow_incident(finding: Dict, score: int) -> Optional[Dict]:
    config = load_servicenow_config()
    if not can_create_incidents():
        return None

    endpoint = f"https://{config['instance']}.service-now.com/api/now/table/{config['table']}"
    payload = build_incident_payload(finding, score)
    requests = _import_requests()
    response = requests.post(
        endpoint,
        auth=(config["user"], config["password"]),
        json=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()
