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
- KEV-listed floors the total at 80, even when KEV data is stale.
- Buckets: >=80 critical, 60-79 high, 40-59 medium, <40 low.
- Missing inputs (CVSS null, EPSS missing, KEV unknown) omit that component
  and are named in `reasoning`. Never default to 0.
- `confidence`: "full" (3 signals), "partial" (2), "low" (1 or 0).
- `fix_available` is reported separately and never changes the score.
- CVSS version 2.0 or source ghsa_label: reasoning must say the score is
  approximate / from an older scale.
- Stale KEV data scores normally but adds a note to reasoning.

## Output (dataclass)
score, bucket, per-component contributions, confidence, reasoning