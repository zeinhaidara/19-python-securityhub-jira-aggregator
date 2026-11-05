"""Aggregate AWS Security Hub findings and open Jira tickets for the worst ones.

Default mode only reads input files and prints a plan - it never talks to
Jira. Pass --execute to actually create tickets, which needs real Jira
credentials and is not exercised by the test suite.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

SEVERITY_WEIGHTS = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CRITICALITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_CRITICALITY = "MEDIUM"

# score = severity weight * criticality weight, bucketed into a Jira priority
PRIORITY_THRESHOLDS = [
    (12, "P1"),
    (6, "P2"),
    (3, "P3"),
    (0, "P4"),
]

PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]

ACTIVE_WORKFLOW_STATES = {"NEW", "NOTIFIED"}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    resource_id: str
    account_id: str
    region: str
    description: str
    workflow_state: str


class AggregatorError(Exception):
    pass


def load_findings(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    raw_findings = data["Findings"] if isinstance(data, dict) else data

    findings = []
    for raw in raw_findings:
        resources = raw.get("Resources") or [{}]
        severity = raw.get("Severity", {}).get("Label", "INFORMATIONAL").upper()
        findings.append(
            Finding(
                id=raw["Id"],
                title=raw.get("Title", raw["Id"]),
                severity=severity,
                resource_id=resources[0].get("Id", "unknown"),
                account_id=raw.get("AwsAccountId", "unknown"),
                region=raw.get("Region", "unknown"),
                description=raw.get("Description", ""),
                workflow_state=raw.get("Workflow", {}).get("Status", "NEW").upper(),
            )
        )
    return findings


def load_criticality_map(path: str | Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text())
    return {k: v.upper() for k, v in data.items()}


def criticality_for(finding: Finding, criticality_map: dict[str, str]) -> str:
    return criticality_map.get(finding.resource_id, DEFAULT_CRITICALITY)


def score_finding(finding: Finding, criticality_map: dict[str, str]) -> tuple[int, str, str]:
    severity_weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
    criticality = criticality_for(finding, criticality_map)
    criticality_weight = CRITICALITY_WEIGHTS.get(criticality, CRITICALITY_WEIGHTS[DEFAULT_CRITICALITY])
    score = severity_weight * criticality_weight

    priority = PRIORITY_THRESHOLDS[-1][1]
    for threshold, label in PRIORITY_THRESHOLDS:
        if score >= threshold:
            priority = label
            break

    return score, priority, criticality


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    score: int
    priority: str
    criticality: str


def prioritize(
    findings: list[Finding],
    criticality_map: dict[str, str],
    min_priority: str = "P3",
    include_resolved: bool = False,
) -> list[PrioritizedFinding]:
    if min_priority not in PRIORITY_ORDER:
        raise AggregatorError(f"unknown priority {min_priority!r}, expected one of {PRIORITY_ORDER}")
    max_rank = PRIORITY_ORDER.index(min_priority)

    prioritized = []
    for finding in findings:
        if not include_resolved and finding.workflow_state not in ACTIVE_WORKFLOW_STATES:
            continue
        score, priority, criticality = score_finding(finding, criticality_map)
        if PRIORITY_ORDER.index(priority) > max_rank:
            continue
        prioritized.append(PrioritizedFinding(finding, score, priority, criticality))

    prioritized.sort(key=lambda p: p.score, reverse=True)
    return prioritized


def finding_label(finding_id: str) -> str:
    return f"finding:{finding_id}"


class JiraClient:
    """Thin wrapper around the Jira REST API. Not exercised by tests."""

    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key

    def _session(self):
        import requests

        session = requests.Session()
        session.auth = (self.email, self.api_token)
        session.headers.update({"Content-Type": "application/json"})
        return session

    def find_existing_ticket(self, finding_id: str) -> str | None:
        session = self._session()
        jql = f'project = "{self.project_key}" AND labels = "{finding_label(finding_id)}"'
        response = session.get(f"{self.base_url}/rest/api/3/search", params={"jql": jql})
        response.raise_for_status()
        issues = response.json().get("issues", [])
        return issues[0]["key"] if issues else None

    def create_ticket(self, prioritized: PrioritizedFinding) -> str:
        session = self._session()
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{prioritized.finding.severity}] {prioritized.finding.title}",
                "description": prioritized.finding.description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": prioritized.priority},
                "labels": ["security-hub", finding_label(prioritized.finding.id)],
            }
        }
        response = session.post(f"{self.base_url}/rest/api/3/issue", json=payload)
        response.raise_for_status()
        return response.json()["key"]


class DryRunJiraClient:
    """In-memory stand-in for JiraClient, used by default and by tests."""

    def __init__(self, existing_finding_ids: set[str] | None = None):
        self.existing_finding_ids = set(existing_finding_ids or set())
        self.created: list[PrioritizedFinding] = []

    def find_existing_ticket(self, finding_id: str) -> str | None:
        return f"DRY-{finding_id}" if finding_id in self.existing_finding_ids else None

    def create_ticket(self, prioritized: PrioritizedFinding) -> str:
        self.created.append(prioritized)
        key = f"DRY-{len(self.created)}"
        self.existing_finding_ids.add(prioritized.finding.id)
        return key


@dataclass(frozen=True)
class TicketResult:
    finding_id: str
    priority: str
    action: str  # "created" or "skipped-existing"
    ticket_key: str


def open_tickets(prioritized_findings: list[PrioritizedFinding], client) -> list[TicketResult]:
    results = []
    for item in prioritized_findings:
        existing_key = client.find_existing_ticket(item.finding.id)
        if existing_key:
            results.append(TicketResult(item.finding.id, item.priority, "skipped-existing", existing_key))
            continue
        key = client.create_ticket(item)
        results.append(TicketResult(item.finding.id, item.priority, "created", key))
    return results


def render_report(results: list[TicketResult], prioritized_findings: list[PrioritizedFinding]) -> str:
    by_id = {p.finding.id: p for p in prioritized_findings}
    lines = [f"Processed {len(results)} finding(s)", ""]
    created = sum(1 for r in results if r.action == "created")
    skipped = sum(1 for r in results if r.action == "skipped-existing")
    lines.append(f"- created: {created}")
    lines.append(f"- skipped (already ticketed): {skipped}")
    lines.append("")
    lines.append("| Priority | Finding | Action | Ticket |")
    lines.append("|---|---|---|---|")
    for result in results:
        title = by_id[result.finding_id].finding.title
        lines.append(f"| {result.priority} | {title} | {result.action} | {result.ticket_key} |")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", help="path to a Security Hub GetFindings JSON export")
    parser.add_argument("--criticality-map", help="path to a JSON map of resource id to criticality")
    parser.add_argument("--min-priority", default="P3", choices=PRIORITY_ORDER)
    parser.add_argument("--include-resolved", action="store_true")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually create tickets via the real Jira API (needs --jira-url/--jira-project and "
        "JIRA_EMAIL/JIRA_API_TOKEN env vars); default is a dry-run plan",
    )
    parser.add_argument("--jira-url")
    parser.add_argument("--jira-project")
    return parser


def main(argv: list[str] | None = None) -> int:
    import os

    args = build_arg_parser().parse_args(argv)

    findings = load_findings(args.findings)
    criticality_map = load_criticality_map(args.criticality_map)
    prioritized = prioritize(
        findings, criticality_map, min_priority=args.min_priority, include_resolved=args.include_resolved
    )

    if args.execute:
        if not args.jira_url or not args.jira_project:
            print("--execute requires --jira-url and --jira-project", file=sys.stderr)
            return 2
        email = os.environ.get("JIRA_EMAIL")
        token = os.environ.get("JIRA_API_TOKEN")
        if not email or not token:
            print("--execute requires JIRA_EMAIL and JIRA_API_TOKEN env vars", file=sys.stderr)
            return 2
        client = JiraClient(args.jira_url, email, token, args.jira_project)
    else:
        client = DryRunJiraClient()

    results = open_tickets(prioritized, client)

    if args.format == "json":
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        print(render_report(results, prioritized))

    return 0


if __name__ == "__main__":
    sys.exit(main())
