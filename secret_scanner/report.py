from typing import Dict, List

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Secret Scanner Report</title>
    <style>
        body {{ font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f7f9fc; color: #222; }}
        h1 {{ color: #333; }}
        .summary {{ margin-bottom: 20px; }}
        .summary p {{ margin: 0.3em 0; }}
        table {{ border-collapse: collapse; width: 100%; background: white; }}
        th, td {{ border: 1px solid #d1d5db; padding: 12px 14px; text-align: left; }}
        th {{ background: #111827; color: white; }}
        tr:nth-child(even) {{ background: #f4f5f7; }}
        .critical {{ color: #b91c1c; font-weight: bold; }}
        .high {{ color: #b45309; font-weight: bold; }}
        .medium {{ color: #1d4ed8; font-weight: bold; }}
        .low {{ color: #047857; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Secret Scanner Report</h1>
    <div class="summary">
        <p><strong>Total findings:</strong> {total_findings}</p>
        <p><strong>Critical:</strong> {critical_count}</p>
        <p><strong>High:</strong> {high_count}</p>
        <p><strong>Medium:</strong> {medium_count}</p>
        <p><strong>Low:</strong> {low_count}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>File</th>
                <th>Secret Type</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Match Preview</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""


def _format_match_text(match_text: str) -> str:
    text = match_text.replace("<", "&lt;").replace(">", "&gt;")
    if len(text) > 80:
        return text[:77] + "..."
    return text


def generate_report(findings: List[Dict], output_path: str) -> None:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rows = []

    for idx, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "low").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        severity_class = severity if severity in severity_counts else "low"
        rows.append(
            f"<tr>"
            f"<td>{idx}</td>"
            f"<td>{finding.get('file')}</td>"
            f"<td>{finding.get('secret_type')}</td>"
            f"<td class=\"{severity_class}\">{severity.title()}</td>"
            f"<td>{finding.get('score')}</td>"
            f"<td>{_format_match_text(finding.get('match_text', ''))}</td>"
            f"</tr>"
        )

    html = REPORT_TEMPLATE.format(
        total_findings=len(findings),
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        rows="\n            ".join(rows),
    )

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(html)
