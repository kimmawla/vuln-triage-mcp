"""Record live API responses for the golden-set test (tests/test_golden.py).

Usage: uv run python scripts/record_golden_fixtures.py

Reads the IDs in tests/golden.yaml and writes tests/fixtures/golden/recorded.json with
the raw OSV, EPSS, and KEV responses those IDs need, so the golden test replays them
deterministically with no network. Re-record when the scoring spec or golden set changes;
EPSS drifts daily, so expect small score changes between recordings.

Recorded data is trimmed to keep the file small without changing what the scorer sees:
OSV `affected[].versions` lists (unused by normalization) are cut to 3 entries, and the
KEV feed keeps only entries for golden CVEs (lookups for other CVEs are never made).
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml

from vuln_triage_mcp.clients import epss, kev, osv

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "golden.yaml"
OUT = ROOT / "tests" / "fixtures" / "golden" / "recorded.json"


def log(message: str) -> None:
    print(message, file=sys.stderr)


def trim_osv(record: dict) -> dict:
    for affected in record.get("affected", []):
        if "versions" in affected:
            affected["versions"] = affected["versions"][:3]
    return record


def main() -> None:
    ids = [entry["id"] for entry in yaml.safe_load(GOLDEN.read_text())]
    recorded: dict = {"recorded_at": datetime.now(UTC).isoformat(timespec="seconds"), "osv": {}, "epss": {}}

    with httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0)) as http:
        for vuln_id in ids:
            response = http.get(f"{osv.BASE_URL}/vulns/{vuln_id}")
            if response.status_code == 404:
                # Recorded as null and replayed as a 404 (e.g. closed-source products OSV doesn't cover).
                recorded["osv"][vuln_id] = None
                log(f"OSV  {vuln_id}: 404, not in OSV")
                continue
            response.raise_for_status()
            recorded["osv"][vuln_id] = trim_osv(response.json())
            log(f"OSV  {vuln_id}")

        # EPSS and KEV are keyed by CVE; GHSA entries reach them only via CVE aliases,
        # and the golden GHSA entries are there precisely because they have none.
        cve_ids = [vuln_id for vuln_id in ids if vuln_id.startswith("CVE-")]
        for start in range(0, len(cve_ids), epss.BATCH_SIZE):
            batch = cve_ids[start : start + epss.BATCH_SIZE]
            response = http.get(epss.BASE_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
            for row in response.json()["data"]:
                recorded["epss"][row["cve"]] = row
        log(f"EPSS {len(recorded['epss'])} of {len(cve_ids)} CVEs scored")

        response = http.get(kev.FEED_URL)
        response.raise_for_status()
        feed = response.json()
        wanted = set(cve_ids)
        recorded["kev"] = {
            "catalogVersion": feed.get("catalogVersion"),
            "dateReleased": feed.get("dateReleased"),
            "vulnerabilities": [v for v in feed["vulnerabilities"] if v.get("cveID") in wanted],
        }
        log(f"KEV  {len(recorded['kev']['vulnerabilities'])} of {len(cve_ids)} CVEs listed (catalog {feed.get('catalogVersion')})")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(recorded, indent=1, sort_keys=True) + "\n")
    log(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
