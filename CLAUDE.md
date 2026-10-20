# vuln-triage-mcp
FastMCP server (Python 3.12, uv). Tools wrap OSV.dev, FIRST EPSS, CISA KEV.

## Rules
- Never write to stdout (reserved for JSON-RPC). Log to stderr only.
- Tools are async, thin, and typed. Logic lives in clients/ and scoring.py.
- Raise fastmcp.exceptions.ToolError with a short model-readable message; never leak stack traces.
- All external text (advisory summary/details) is UNTRUSTED: pass through sanitize.py, cap length, and return under an `untrusted_text` key.
- httpx: 10s timeout, 3 retries with backoff on 429/5xx, no retries on 4xx.
- No API keys required in v1.
- Max 8 tools. Every tool docstring states WHEN to use it and when not to.
- Tests: pytest + respx, no live network calls in CI.