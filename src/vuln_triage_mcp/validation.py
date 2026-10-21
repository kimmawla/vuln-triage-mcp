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


# Package names across the supported ecosystems: PyPI, npm (@scope/name), Go module paths,
# Maven group:artifact, crates.io, RubyGems, NuGet, Packagist vendor/package.
_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9@/._:+~-]*")
_MAX_PACKAGE_NAME_LEN = 256
# Versions: semver with pre-release/build (1.0.0-rc.1+b2), Go (v1.2.3), PEP 440 (2!1.0.post1).
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~:!-]*")
_MAX_VERSION_LEN = 128


def validate_cve_id(cve_id: object) -> str:
    """Return the canonical form of a CVE ID, or raise ToolError (with a hint for GHSA IDs)."""
    if isinstance(cve_id, str) and len(cve_id) <= _MAX_ID_LEN:
        candidate = cve_id.strip().upper()
        if candidate.isascii() and _CVE_RE.fullmatch(candidate):
            return candidate
        if candidate.startswith("GHSA-"):
            raise ToolError(
                "This tool needs a CVE ID, not a GHSA ID. Use lookup_vulnerability to find the "
                "advisory's CVE aliases, or triage_vulnerability, which resolves them itself."
            )
    raise ToolError("Invalid CVE ID. Expected CVE-YYYY-NNNN (4-7 digits).")


def validate_package_name(name: object) -> str:
    """Return a stripped package name, or raise ToolError."""
    if isinstance(name, str) and len(name) <= _MAX_PACKAGE_NAME_LEN:
        candidate = name.strip()
        if candidate.isascii() and _PACKAGE_NAME_RE.fullmatch(candidate):
            return candidate
    raise ToolError(
        f"Invalid package name. Expected an ASCII package name up to {_MAX_PACKAGE_NAME_LEN} "
        "characters, e.g. requests, @types/node, org.apache.logging.log4j:log4j-core."
    )


def validate_version(version: object) -> str | None:
    """Return a stripped version string, None if empty (meaning "all versions"), or raise ToolError."""
    if isinstance(version, str) and len(version) <= _MAX_VERSION_LEN:
        candidate = version.strip()
        if not candidate:
            return None
        if candidate.isascii() and _VERSION_RE.fullmatch(candidate):
            return candidate
    raise ToolError(
        f"Invalid version. Expected a version string up to {_MAX_VERSION_LEN} characters, "
        "e.g. 2.14.1, v1.2.3, 1.0.0-rc.1, or an empty string for all versions."
    )
