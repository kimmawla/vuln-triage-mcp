# Tool surface (v1, max 8 tools; we have 5)

| Tool | Args | Use when | Prefer another when |
|---|---|---|---|
| lookup_vulnerability | vuln_id | raw advisory details for one CVE/GHSA | user wants prioritization -> triage_vulnerability |
| find_vulns_for_package | name, ecosystem, version="" | "what vulns affect package X (version Y)" | user already has an ID |
| get_epss_score | cve_id | exploit-probability only | user wants overall priority -> triage_vulnerability |
| check_known_exploited | cve_id | "is this exploited in the wild" (CISA KEV) | same |
| triage_vulnerability | vuln_id | any "how urgent / what should I fix first" question | raw details only -> lookup_vulnerability |

## Behavior requirements
- triage_vulnerability runs OSV, EPSS and KEV via asyncio.gather under an overall timeout.
- If EPSS or KEV fails, return a partial result that names the missing source; don't raise.
- If OSV returns 404 for a well-formed CVE ID (no OSV record; common for vendor and
  closed-source products), don't raise: score from EPSS and KEV with no CVSS component,
  return `advisory: null`, and add `{"source": "osv", "reason": "no OSV.dev record
  (common for vendor/closed-source products)"}` to `missing_sources`.
- Still raise ToolError for a GHSA ID with no OSV record, and for OSV timeouts, 429,
  5xx, or other errors: only a 404 for a CVE means "no record".
- Resolve GHSA IDs to CVE aliases before EPSS/KEV; if no CVE alias, say so in the result.
- All external text stays under `untrusted_text`.
- Console script: vuln-triage-mcp = "vuln_triage_mcp.server:main"
