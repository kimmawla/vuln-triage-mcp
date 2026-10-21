"""Release metadata stays consistent across server.json, pyproject.toml, README, and the
installed package, so an MCP Registry publish can't drift from what PyPI ships.

server.json is validated against a vendored copy of the schema its $schema URL names
(tests/fixtures/registry/), so this runs offline. The live test re-fetches that URL
(skipped by default; run with -m live, and skipped if offline) and checks the vendored
copy is still current.
"""

import json
import re
import tomllib
from importlib import metadata
from pathlib import Path

import httpx
import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVER_JSON = json.loads((ROOT / "server.json").read_text())
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
README = (ROOT / "README.md").read_text()
SCHEMA_FILE = ROOT / "tests" / "fixtures" / "registry" / "server.schema.2025-12-11.json"
SCHEMA = json.loads(SCHEMA_FILE.read_text())

PROJECT = PYPROJECT["project"]
# Per the registry's PyPI ownership rule: `mcp-name: <server-name>` followed by a boundary
# (whitespace, an HTML tag, or the comment close "-->"), not glued to other characters.
MCP_NAME_RE = re.compile(r"mcp-name:\s*([^\s<]+?)(?=\s|<|-->|$)")


def pypi_package() -> dict:
    packages = [p for p in SERVER_JSON["packages"] if p["registryType"] == "pypi"]
    assert len(packages) == 1, packages
    return packages[0]


def test_server_json_validates_against_schema():
    assert SERVER_JSON["$schema"] == SCHEMA["$id"], "vendored schema doesn't match server.json's $schema"
    jsonschema.validate(SERVER_JSON, SCHEMA)


def test_version_matches_installed_package():
    installed = metadata.version("vuln-triage-mcp")
    assert SERVER_JSON["version"] == installed
    assert pypi_package()["version"] == installed
    assert PROJECT["version"] == installed


def test_pypi_identifier_matches_pyproject_name():
    assert pypi_package()["identifier"] == PROJECT["name"] == "vuln-triage-mcp"
    assert pypi_package()["transport"] == {"type": "stdio"}


def test_readme_marker_matches_server_name_exactly():
    names = MCP_NAME_RE.findall(README)
    assert names == [SERVER_JSON["name"]], f"README mcp-name markers {names} != {SERVER_JSON['name']!r}"
    assert f"<!-- mcp-name: {SERVER_JSON['name']} -->" in README


def test_console_script_matches_pypi_name():
    scripts = PROJECT["scripts"]
    assert list(scripts) == [PROJECT["name"]]
    assert scripts[PROJECT["name"]] == "vuln_triage_mcp.server:main"
    installed = {ep.name for ep in metadata.distribution("vuln-triage-mcp").entry_points if ep.group == "console_scripts"}
    assert installed == {PROJECT["name"]}


def test_description_matches_readme_tagline():
    tagline = re.search(r"^> (.+)$", README, re.MULTILINE)
    assert tagline, "README has no '> ' tagline"
    assert SERVER_JSON["description"] == tagline.group(1)


def test_repository_matches_project_urls():
    assert SERVER_JSON["repository"] == {"url": PROJECT["urls"]["Repository"], "source": "github"}
    assert PROJECT["urls"]["Issues"] == PROJECT["urls"]["Repository"] + "/issues"


@pytest.mark.live
def test_published_schema_matches_vendored_copy():
    try:
        response = httpx.get(SERVER_JSON["$schema"], timeout=15.0, follow_redirects=True)
    except httpx.TransportError as exc:
        pytest.skip(f"offline: {exc}")
    response.raise_for_status()
    published = response.json()

    jsonschema.validate(SERVER_JSON, published)
    assert published == SCHEMA, f"{SERVER_JSON['$schema']} changed upstream; refresh {SCHEMA_FILE.name}"
