import os
from typing import Dict, List, Optional

GITHUB_API_BASE = "https://api.github.com"


def _import_requests():
    try:
        import requests
    except ImportError as exc:
        raise ImportError("requests is required for GitHub scanning") from exc
    return requests


def github_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = token or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def list_repository_files(full_name: str, token: Optional[str] = None, path: str = "") -> List[Dict]:
    requests = _import_requests()
    url = f"{GITHUB_API_BASE}/repos/{full_name}/contents/{path}"
    response = requests.get(url, headers=github_headers(token))
    response.raise_for_status()

    contents = response.json()
    if isinstance(contents, dict) and contents.get("type") == "file":
        return [contents]

    files = []
    for item in contents:
        if item["type"] == "file":
            files.append(item)
        elif item["type"] == "dir":
            files.extend(list_repository_files(full_name, token=token, path=item["path"]))
    return files


def download_github_file(file_item: Dict, token: Optional[str] = None) -> str:
    url = file_item["download_url"]
    if not url:
        raise ValueError("GitHub file item does not include download_url")
    requests = _import_requests()
    response = requests.get(url, headers=github_headers(token))
    response.raise_for_status()
    return response.text
