import argparse
import os
import sys
from typing import List

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        return None

from .prioritizer import score_finding
from .report import generate_report
from .scanner import scan_github_repo, scan_local_repo
from .servicenow import can_create_incidents, create_servicenow_incident


def print_findings(findings: List[dict]) -> None:
    if not findings:
        print("No secrets detected.")
        return

    for idx, finding in enumerate(findings, start=1):
        print(f"[{idx}] {finding['secret_type']} ({finding['severity']}) in {finding['file']}")
        print(f"    Match: {finding['match_text']}")
        print(f"    Score: {finding['score']}")
        print()


def create_tickets(findings: List[dict]) -> None:
    if not can_create_incidents():
        print("ServiceNow credentials not configured; skipping ticket creation.")
        return

    print("Creating ServiceNow incidents...")
    for finding in findings:
        response = create_servicenow_incident(finding, finding["score"])
        if response is not None:
            record = response.get("result")
            sys.stdout.write(f"Created incident: {record.get('number')} for {finding['file']}\n")
        else:
            sys.stdout.write(f"Failed to create incident for {finding['file']}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Secret scanner and ServiceNow incident generator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", help="Scan a local repository folder.")
    group.add_argument("--github", help="Scan a GitHub repository by full name (owner/repo).")
    parser.add_argument("--create-tickets", action="store_true", help="Create ServiceNow incidents for detected secrets.")
    parser.add_argument("--report", help="Write an HTML report to the provided file path.")
    parser.add_argument("--token", help="Optional GitHub access token.")

    args = parser.parse_args()

    load_dotenv()

    findings = []
    if args.local:
        findings = scan_local_repo(args.local)
    elif args.github:
        findings = scan_github_repo(args.github, token=args.token)

    for finding in findings:
        finding["score"] = score_finding(finding)

    print_findings(findings)

    if args.report:
        try:
            generate_report(findings, args.report)
            print(f"HTML report written to: {args.report}")
        except Exception as exc:
            print(f"Failed to write report: {exc}")

    if args.create_tickets:
        create_tickets(findings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
