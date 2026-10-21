# vuln-triage-mcp

<!-- mcp-name: io.github.kimmawla/vuln-triage-mcp -->

> An MCP server that tells your AI agent which vulnerabilities to fix first,
> combining OSV.dev, FIRST EPSS, and the CISA KEV catalog into one explainable priority score.

[badges: PyPI version, Python versions, license, tests]

## Why this exists
Two or three sentences. CVSS alone ranks by severity, not by likelihood of exploitation.
This server adds exploit probability (EPSS) and known exploitation (KEV), and shows its reasoning.
Example: a CVSS 9.8 nobody exploits ranks below a CVSS 8.8 that is being exploited in the wild.

## Quick start
### Claude Code
`claude mcp add vuln-triage -- uvx vuln-triage-mcp`
### Claude Desktop / other clients
JSON config snippet using `uvx`.
Requires: Python 3.12+, no API keys.

## Try it
Three example prompts and what to expect:
- "Which is most urgent: CVE-2021-44228, CVE-2023-4863, CVE-2019-10744?"
- "Is lodash 4.17.15 vulnerable? What should I upgrade to?"
- "Is CVE-XXXX actively exploited?"

## Tools
| Tool | Args | Use it when | Prefer another when |
|---|---|---|---|
| lookup_vulnerability | vuln_id | raw advisory details for one CVE/GHSA | user wants prioritization -> triage_vulnerability |
| find_vulns_for_package | name, ecosystem, version="" | "what vulns affect package X (version Y)" | user already has an ID |
| get_epss_score | cve_id | exploit-probability only | user wants overall priority -> triage_vulnerability |
| check_known_exploited | cve_id | "is this exploited in the wild" (CISA KEV) | same |
| triage_vulnerability | vuln_id | any "how urgent / what should I fix first" question | raw details only -> lookup_vulnerability |

## How scoring works
- Formula: CVSS (base) x 40 + EPSS x 35 + KEV +25; KEV-listed floors at 80
- Buckets: see the table below
- Missing data: component omitted, named in `reasoning`, lowers `confidence`
- Link to docs/scoring-spec.md

| Bucket | When |
|---|---|
| critical | score >= 80, or listed in CISA KEV (always floored to 80, whatever the confidence) |
| high | score 60-79 |
| medium | score 40-59 |
| low | score < 40 |
| unknown | not KEV-listed, and either no CVSS severity or low confidence (0-1 of 3 signals). Too little data to classify; the score is still returned, and `reasoning` names what is missing. **Not a low-risk verdict.** |

`unknown` takes precedence over high, medium, and low; it never applies to a KEV-listed vulnerability.

## Reliability and limits
- Partial results: if EPSS or KEV fails, the result names the missing source
- Truncation: `truncated`, `found_count` vs `returned_count`, `ranking_note`
- Stale KEV cache: `stale` and `catalog_fetched_at`
- Timeouts and retry policy (one line)
- Package queries return at most 50 advisories, sorted by severity

## Security
- Advisory text is untrusted third-party content (prompt injection vector):
  sanitized, length-capped, returned under `untrusted_text`, and flagged to the model in the server instructions
- Input validation on all IDs and ecosystems
- No credentials required or stored; read-only calls to three public APIs
- Reporting vulnerabilities in this project: SECURITY.md or email

## Evaluation
Golden set: 17 entries (16 CVEs, 1 GHSA) with expected buckets, confidence, and ordering, recorded 10/21/2026.
Result: 17/17 match on the recorded fixtures (`uv run pytest tests/test_golden.py`), and 17/17 against the live APIs on 10/21/2026 (`uv run pytest -m live tests/test_golden.py`). EPSS drifts daily, so the live run can diverge over time; re-record the fixtures with `uv run python scripts/record_golden_fixtures.py` when the golden set or scoring spec changes.

## Data sources and attribution
OSV.dev, FIRST EPSS (cite per their usage terms), CISA KEV. Not affiliated with any of them.

## Development
`uv sync`, `uv run pytest`, running the Inspector, live-test marker.

## License
MIT
