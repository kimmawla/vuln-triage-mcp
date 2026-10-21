# vuln-triage-mcp
FastMCP server (Python 3.12, uv). Tools wrap OSV.dev, FIRST EPSS, CISA KEV.

## Rules
- Never write to stdout (reserved for JSON-RPC). Log to stderr only.
- Tools are async, thin, and typed. Logic lives in clients/ and scoring.py.
- Raise fastmcp.exceptions.ToolError with a short model-readable message; never leak stack traces.
- All external text (advisory summary/details) is UNTRUSTED: pass through sanitize.py, cap length, and return under an `untrusted_text` key.
- httpx (one shared helper, clients/_http.py): connect timeout 3s, read timeout 8s. Retry 429/5xx up to 3 times with exponential backoff, honoring Retry-After. Retry a timeout or connection error at most once. Never retry other 4xx. Cap each client call at 15s total including retries and backoff; on hitting the cap raise ToolError naming the slow service and saying the user can retry.
- No API keys required in v1.
- Max 8 tools. Every tool docstring states WHEN to use it and when not to.
- Tests: pytest + respx, no live network calls in CI.
- Scoring rules live in docs/scoring-spec.md. Read it before changing scoring.py, and update the spec in the same change if the rules change.
