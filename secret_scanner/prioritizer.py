from typing import Dict

SEVERITY_SCORE = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 30,
}


def score_finding(finding: Dict) -> int:
    base = SEVERITY_SCORE.get(finding.get("severity"), 40)
    secret_type = finding.get("secret_type", "").lower()
    score = base

    if "aws" in secret_type or "private key" in secret_type:
        score += 10
    if "token" in secret_type or "api" in secret_type:
        score += 5
    if len(finding.get("match_text", "")) > 40:
        score += 5

    return min(score, 100)
