# Composite scoring spec (source of truth)

## Components
- CVSS: cvss/10 × 40
  - Always the CVSS **base** score, computed from base metrics only. Threat/temporal and
    environmental metrics in the vector (e.g. v4.0 `E:U`) are ignored, because EPSS and
    KEV already cover exploit likelihood; counting exploit maturity again through CVSS
    would double-count it. The full published vector is still returned in `cvss_vector`,
    with `cvss_metric_group: "base"`.
- EPSS: epss × 35
- KEV: +25 if listed

## Rules
- KEV-listed floors the total at 80, even when KEV data is stale or CVSS is missing;
  when the floor raises the score, reasoning says so and why (exploited in the wild).
- Buckets: >=80 critical, 60-79 high, 40-59 medium, <40 low, or unknown.
- unknown: the bucket is unknown when KEV is not listed (not_listed or unknown status,
  fresh or stale) AND either (a) confidence is "low" or (b) the CVSS component is
  missing. The numeric score is still returned. reasoning must name the missing
  signals (e.g. "CVSS severity") and say it is not a low-risk verdict.
- unknown is a "we don't know" result, never a low-risk verdict. It must not be
  reported as low risk or safe.
- KEV-listed always floors at 80 and is critical, whatever the confidence or missing
  data; it is never unknown.
- Missing inputs (CVSS null, EPSS missing, KEV unknown) omit that component
  and are named in `reasoning`. Never default to 0.
- CVSS null: reasoning must also say the score has no severity component, so the
  bucket reflects exploitation signals (EPSS, KEV) only.
- No OSV.dev record for a well-formed CVE (HTTP 404 only; common for vendor and
  closed-source products): CVSS is null and handled as above, and reasoning says there
  is no OSV record. EPSS and KEV still score normally.
- If additionally EPSS returned no score (not a failure) and KEV does not list it,
  reasoning says the ID may not exist or may be too new (check for typos), and
  confidence is "low". A failed EPSS or unknown KEV status never triggers this.
- `confidence`: "full" (3 signals), "partial" (2), "low" (1 or 0).
- `fix_available` is reported separately and never changes the score.
- CVSS version 2.0 or source ghsa_label: reasoning must say the score is
  approximate / from an older scale.
- Stale KEV data scores normally but adds a note to reasoning.

## Output (dataclass)
score, bucket, per-component contributions, confidence, reasoning

`bucket` is one of critical, high, medium, low, unknown; the triage tool's output
schema advertises these values.