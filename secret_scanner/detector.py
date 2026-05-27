import re
from typing import Dict, List

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
    },
    {
        "name": "AWS Secret Key",
        "regex": re.compile(r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": "critical",
    },
    {
        "name": "Private Key",
        "regex": re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "severity": "critical",
    },
    {
        "name": "Generic Secret",
        "regex": re.compile(r"(?i)(password|passphrase|secret|api_key|token|client_secret)\s*[:=]\s*[\"']?([A-Za-z0-9\-_.+/]{8,100})[\"']?"),
        "severity": "high",
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
        "severity": "high",
    },
]


def find_secrets_in_text(text: str, file_path: str) -> List[Dict]:
    findings = []
    for pattern in SECRET_PATTERNS:
        for match in pattern["regex"].finditer(text):
            findings.append(
                {
                    "file": file_path,
                    "secret_type": pattern["name"],
                    "severity": pattern["severity"],
                    "match_text": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                }
            )
    return findings
