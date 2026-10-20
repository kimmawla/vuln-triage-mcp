"""Input validation for tool arguments. Errors never echo the raw input back."""

import re

from fastmcp.exceptions import ToolError

# [0-9] rather than \d: \d matches non-ASCII digits such as Arabic-Indic numerals.
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
# GHSA IDs use a restricted base32 alphabet, lowercase by convention.
_GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")

_MAX_ID_LEN = 64

VULN_ID_FORMATS = "CVE-YYYY-NNNN (4-7 digits) or GHSA-xxxx-xxxx-xxxx"

OSV_ECOSYSTEMS = ("PyPI", "npm", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist")
_ECOSYSTEMS_BY_KEY = {name.lower(): name for name in OSV_ECOSYSTEMS}


def validate_vuln_id(vuln_id: object) -> str:
    """Return the canonical form of a CVE or GHSA ID, or raise ToolError."""
    if not isinstance(vuln_id, str) or len(vuln_id) > _MAX_ID_LEN:
        raise ToolError(f"Invalid vulnerability ID. Expected {VULN_ID_FORMATS}.")
    candidate = vuln_id.strip()
    if not candidate.isascii():
        raise ToolError(f"Invalid vulnerability ID. Expected {VULN_ID_FORMATS}.")

    upper = candidate.upper()
    if _CVE_RE.fullmatch(upper):
        return upper
    if upper.startswith("GHSA-"):
        ghsa = "GHSA" + candidate[4:].lower()
        if _GHSA_RE.fullmatch(ghsa):
            return ghsa
    raise ToolError(f"Invalid vulnerability ID. Expected {VULN_ID_FORMATS}.")


def validate_ecosystem(ecosystem: object) -> str:
    """Return the canonical OSV ecosystem name (case-insensitive match), or raise ToolError."""
    if isinstance(ecosystem, str) and len(ecosystem) <= _MAX_ID_LEN:
        match = _ECOSYSTEMS_BY_KEY.get(ecosystem.strip().lower())
        if match is not None:
            return match
    raise ToolError(f"Unsupported ecosystem. Expected one of: {', '.join(OSV_ECOSYSTEMS)}.")
