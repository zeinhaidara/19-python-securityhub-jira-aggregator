import json
import unittest
from pathlib import Path

import aggregator

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def make_finding(**overrides):
    base = dict(
        id="finding-1",
        title="test finding",
        severity="HIGH",
        resource_id="arn:aws:s3:::bucket",
        account_id="123456789012",
        region="us-east-1",
        description="",
        workflow_state="NEW",
    )
    base.update(overrides)
    return aggregator.Finding(**base)


class LoadFindingsTests(unittest.TestCase):
    def test_loads_example_file(self):
        findings = aggregator.load_findings(EXAMPLES / "findings.json")
        self.assertEqual(len(findings), 5)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_accepts_plain_list(self):
        raw = [
            {
                "Id": "f-1",
                "Title": "t",
                "Severity": {"Label": "LOW"},
                "Resources": [{"Id": "r-1"}],
            }
        ]
        path = EXAMPLES / "_tmp_plain_list.json"
        path.write_text(json.dumps(raw))
        try:
            findings = aggregator.load_findings(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].workflow_state, "NEW")
        finally:
            path.unlink()


class ScoringTests(unittest.TestCase):
    def test_critical_severity_on_critical_asset_is_p1(self):
        finding = make_finding(severity="CRITICAL", resource_id="asset-1")
        score, priority, criticality = aggregator.score_finding(finding, {"asset-1": "CRITICAL"})
        self.assertEqual(score, 16)
        self.assertEqual(priority, "P1")
        self.assertEqual(criticality, "CRITICAL")

    def test_unknown_asset_defaults_to_medium_criticality(self):
        finding = make_finding(severity="LOW", resource_id="asset-unknown")
        score, priority, criticality = aggregator.score_finding(finding, {})
        self.assertEqual(criticality, "MEDIUM")
        self.assertEqual(score, 2)
        self.assertEqual(priority, "P4")

    def test_low_severity_on_low_asset_is_p4(self):
        finding = make_finding(severity="LOW", resource_id="asset-2")
        score, priority, _ = aggregator.score_finding(finding, {"asset-2": "LOW"})
        self.assertEqual(score, 1)
        self.assertEqual(priority, "P4")


class PrioritizeTests(unittest.TestCase):
    def test_filters_resolved_findings_by_default(self):
        findings = [
            make_finding(id="a", severity="CRITICAL", workflow_state="NEW"),
            make_finding(id="b", severity="CRITICAL", workflow_state="RESOLVED"),
        ]
        result = aggregator.prioritize(findings, {})
        self.assertEqual([p.finding.id for p in result], ["a"])

    def test_include_resolved_flag(self):
        findings = [make_finding(id="a", severity="CRITICAL", workflow_state="RESOLVED")]
        result = aggregator.prioritize(findings, {}, include_resolved=True)
        self.assertEqual([p.finding.id for p in result], ["a"])

    def test_min_priority_filters_low_scores(self):
        findings = [
            make_finding(id="high", severity="CRITICAL", resource_id="x"),
            make_finding(id="low", severity="LOW", resource_id="y"),
        ]
        criticality = {"x": "CRITICAL", "y": "LOW"}
        result = aggregator.prioritize(findings, criticality, min_priority="P1")
        self.assertEqual([p.finding.id for p in result], ["high"])

    def test_sorted_by_score_descending(self):
        findings = [
            make_finding(id="low", severity="LOW", resource_id="y"),
            make_finding(id="high", severity="CRITICAL", resource_id="x"),
        ]
        criticality = {"x": "CRITICAL", "y": "LOW"}
        result = aggregator.prioritize(findings, criticality, min_priority="P4")
        self.assertEqual([p.finding.id for p in result], ["high", "low"])

    def test_rejects_unknown_min_priority(self):
        with self.assertRaises(aggregator.AggregatorError):
            aggregator.prioritize([], {}, min_priority="P9")


class DryRunJiraClientTests(unittest.TestCase):
    def test_creates_ticket_for_new_finding(self):
        client = aggregator.DryRunJiraClient()
        finding = make_finding(id="new-finding")
        prioritized = aggregator.PrioritizedFinding(finding, 10, "P1", "HIGH")
        results = aggregator.open_tickets([prioritized], client)
        self.assertEqual(results[0].action, "created")
        self.assertEqual(len(client.created), 1)

    def test_skips_finding_with_existing_ticket(self):
        client = aggregator.DryRunJiraClient(existing_finding_ids={"dup-finding"})
        finding = make_finding(id="dup-finding")
        prioritized = aggregator.PrioritizedFinding(finding, 10, "P1", "HIGH")
        results = aggregator.open_tickets([prioritized], client)
        self.assertEqual(results[0].action, "skipped-existing")
        self.assertEqual(len(client.created), 0)

    def test_rerun_is_idempotent(self):
        client = aggregator.DryRunJiraClient()
        finding = make_finding(id="repeat-finding")
        prioritized = aggregator.PrioritizedFinding(finding, 10, "P1", "HIGH")
        first = aggregator.open_tickets([prioritized], client)
        second = aggregator.open_tickets([prioritized], client)
        self.assertEqual(first[0].action, "created")
        self.assertEqual(second[0].action, "skipped-existing")
        self.assertEqual(len(client.created), 1)


class RenderReportTests(unittest.TestCase):
    def test_report_counts_created_and_skipped(self):
        finding = make_finding(id="f-1")
        prioritized = aggregator.PrioritizedFinding(finding, 10, "P1", "HIGH")
        results = [
            aggregator.TicketResult("f-1", "P1", "created", "DRY-1"),
            aggregator.TicketResult("f-1", "P1", "skipped-existing", "DRY-1"),
        ]
        report = aggregator.render_report(results, [prioritized])
        self.assertIn("created: 1", report)
        self.assertIn("skipped (already ticketed): 1", report)


class MainCliTests(unittest.TestCase):
    def test_end_to_end_dry_run_against_examples(self):
        exit_code = aggregator.main(
            [
                str(EXAMPLES / "findings.json"),
                "--criticality-map",
                str(EXAMPLES / "asset-criticality.json"),
                "--format",
                "json",
            ]
        )
        self.assertEqual(exit_code, 0)

    def test_execute_without_jira_url_fails(self):
        exit_code = aggregator.main([str(EXAMPLES / "findings.json"), "--execute"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
