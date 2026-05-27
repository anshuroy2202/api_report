import os
from pathlib import Path
from typing import Dict, List, Optional

from .detector import find_secrets_in_text
from .github_repo import download_github_file, list_repository_files

SCAN_EXTENSIONS = {
    ".py",
    ".env",
    ".txt",
    ".md",
    ".json",
    ".yml",
    ".yaml",
    ".ini",
    ".sh",
}


def _should_scan_file(file_path: Path) -> bool:
    if file_path.name.startswith("."):
        return False
    if file_path.suffix in SCAN_EXTENSIONS:
        return True
    if file_path.name.lower() in {"dockerfile", "makefile", "compose.yml", "compose.yaml"}:
        return True
    return False


def scan_local_repo(root_path: str) -> List[Dict]:
    findings = []
    root_path_obj = Path(root_path)
    for path in root_path_obj.rglob("*"):
        if path.is_file() and _should_scan_file(path):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings.extend(find_secrets_in_text(text, str(path.relative_to(root_path_obj))))
    return findings


def scan_github_repo(full_name: str, token: Optional[str] = None) -> List[Dict]:
    findings = []
    files = list_repository_files(full_name, token=token)
    for file_item in files:
        try:
            content = download_github_file(file_item, token=token)
        except Exception:
            continue
        findings.extend(find_secrets_in_text(content, file_item.get("path", "unknown")))
    return findings
