# Security Hub to Jira aggregator

A Python CLI that reads AWS Security Hub findings, ranks them by severity
combined with asset criticality, and opens one Jira ticket per finding that
clears the priority bar - skipping anything that already has an open
ticket.

**Scope.** The default and tested mode reads a static Security Hub
`GetFindings`-shaped JSON export and a static asset-criticality JSON map
from disk - there is no live call to the Security Hub API. Jira access
goes through a `--execute` flag that is off by default: without it the
tool only prints the plan (a dry run against an in-memory fake Jira
client); with it, a real `JiraClient` calls the Jira Cloud REST API, which
needs real credentials and is not covered by the test suite or CI. Azure
Security Center is out of scope - this challenge targets AWS Security Hub
only, scoped down from the broader multi-cloud prompt.

## Architecture

- `aggregator.py` - the whole tool.
  - `load_findings` parses the Security Hub JSON export (either the raw
    `{"Findings": [...]}` response shape or a plain list) into `Finding`
    objects.
  - `load_criticality_map` parses a flat JSON map of resource id/ARN to a
    `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` label; resources missing from the map
    default to `MEDIUM`.
  - `score_finding` combines the ASFF severity weight with the asset
    criticality weight (`score = severity_weight * criticality_weight`)
    and buckets the result into a Jira priority (`P1`-`P4`).
  - `prioritize` filters out resolved/suppressed findings (unless
    `--include-resolved`) and anything below `--min-priority`, then sorts
    by score.
  - `JiraClient` is the real Jira REST API wrapper (lazy-imports
    `requests`, not a hard dependency unless `--execute` is used).
    `DryRunJiraClient` is an in-memory stand-in with the same interface,
    used by default and by all tests.
  - `open_tickets` walks the prioritized findings, skips any that already
    have a ticket (matched by a `finding:<id>` label), and creates one
    otherwise.

## Scoring

| Severity (ASFF) | Weight |
|---|---|
| INFORMATIONAL | 0 |
| LOW | 1 |
| MEDIUM | 2 |
| HIGH | 3 |
| CRITICAL | 4 |

| Asset criticality | Weight |
|---|---|
| LOW | 1 |
| MEDIUM (default) | 2 |
| HIGH | 3 |
| CRITICAL | 4 |

| Score | Priority |
|---|---|
| >= 12 | P1 |
| >= 6 | P2 |
| >= 3 | P3 |
| < 3 | P4 |

A `CRITICAL` finding on a `CRITICAL` asset scores 16 (`P1`); the same
finding on an unlisted (default `MEDIUM`) asset scores 8 (`P2`).

## Prerequisites

- Python 3.12+ (tested on 3.12; no version-specific syntax used)
- `pip install -r requirements.txt` (`requests` is only imported when
  `--execute` is used)

## Usage

```bash
# Dry run: print what would be opened, without talking to Jira
python aggregator.py examples/findings.json --criticality-map examples/asset-criticality.json

# Machine-readable output
python aggregator.py examples/findings.json --criticality-map examples/asset-criticality.json --format json

# Only the worst findings
python aggregator.py examples/findings.json --min-priority P1

# Include findings Security Hub has already marked RESOLVED/SUPPRESSED
python aggregator.py examples/findings.json --include-resolved

# Actually create tickets (needs real Jira credentials, untested)
export JIRA_EMAIL=bot@example.com
export JIRA_API_TOKEN=change-me
python aggregator.py examples/findings.json --execute --jira-url https://example.atlassian.net --jira-project SEC
```

Sample input lives in [`examples/findings.json`](examples/findings.json) (a
mix of severities, resource types, and one `RESOLVED` finding) and
[`examples/asset-criticality.json`](examples/asset-criticality.json) (a
criticality label for a few of those resources, leaving others to the
`MEDIUM` default).

## Security considerations

- No AWS or Jira credentials are required for the default dry-run path;
  it only reads local files.
- `--execute` reads `JIRA_API_TOKEN` from the environment, never from a
  command-line flag or a file, so it doesn't end up in shell history or
  process listings.
- The tool never changes a Security Hub finding's workflow status; it
  only reads findings and creates Jira tickets.
- Treat the findings JSON and the printed report as containing account
  IDs, resource ARNs, and security posture data - handle them with the
  same sensitivity as raw Security Hub output.

## Idempotency

Before creating a ticket, the tool searches Jira for an existing issue
labeled `finding:<finding-id>` and skips creation if one is found.
Running the tool repeatedly against the same findings - in the same run
or a later one - creates at most one ticket per finding; see
`DryRunJiraClientTests.test_rerun_is_idempotent` in the test suite.

## Validation

```bash
pip install -r requirements-test.txt
python -m unittest discover -s tests
```

Tests run entirely against the fixtures in `examples/` and an in-memory
`DryRunJiraClient` - no network access or real Jira/AWS credentials
required. The real `JiraClient` and `--execute` path are not covered.
