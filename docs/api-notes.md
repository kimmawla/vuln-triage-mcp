# External API facts (source of truth, do not guess beyond this)

## OSV.dev
- GET https://api.osv.dev/v1/vulns/{id}
- POST https://api.osv.dev/v1/query
  body: {"package": {"name": "...", "ecosystem": "..."}, "version": "..."}
- CVSS arrives as a vector string, not a number. Compute the base score with the `cvss` package; fall back to database_specific.severity.
- IDs are often GHSA-*; CVE IDs are in `aliases`.

## FIRST EPSS
- GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B (batches multiple CVEs)
- Returns `epss` and `percentile` as strings; convert to float.
- Needs CVE IDs only.

## CISA KEV
- GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- One JSON file. Download once, cache in memory with a 6h TTL, look up by `cveID`.