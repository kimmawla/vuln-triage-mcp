# External API facts (source of truth, do not guess beyond this)

## OSV.dev
- GET https://api.osv.dev/v1/vulns/{id}
- POST https://api.osv.dev/v1/query
  body: {"package": {"name": "...", "ecosystem": "..."}, "version": "..."}
- CVSS arrives as a vector string, not a number. Compute the base score with the `cvss` package; fall back to database_specific.severity.
- IDs are often GHSA-*; CVE IDs are in `aliases`.
- Pagination of POST /v1/query (observed 2026-10-21 with curl):
  - Response: top-level keys are `vulns` and, only when more results exist,
    `next_page_token` (an opaque string, ~146 chars). With no more results the
    key is absent (not null or empty); a query with no matches can also omit `vulns`.
  - Request: send the token back as `page_token`, alongside the same `package`
    (and `version`) as the original query: `{"package": {...}, "page_token": "..."}`.
  - Pitfall: sending it as `next_page_token` is silently ignored. OSV returns
    HTTP 200 with page 1 again (and a token), so a client using the wrong field
    loops forever.
  - Page size is not fixed and not configurable. Largest page seen: 3000 vulns.
    Later pages of the same query held 2250, 1800, 1500 and still had a token.
    Stop only when `next_page_token` is absent, never on a short page.
  - Most package queries fit on one page: django 1.2 (93 vulns, 325 KB), django
    all versions (324, 917 KB), and tensorflow all versions (861, 4.4 MB) returned
    no token. `linux` in `Debian:12` paginated: 7 pages, 14,979 unique vulns, no
    duplicates across pages, about 7 MB and 10 s per full page.

## FIRST EPSS
- GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B (batches multiple CVEs)
- Returns `epss` and `percentile` as strings; convert to float.
- Needs CVE IDs only.

## CISA KEV
- GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- One JSON file. Download once, cache in memory with a 6h TTL, look up by `cveID`.