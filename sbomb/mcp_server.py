"""SBOMB MCP server — exposes the scanner + offline OSV matcher as MCP tools.

Lets an AI agent (Claude Desktop, Cursor, Cognis.Studio, the uncensored-fleet)
drive sbomb over the Model Context Protocol. Everything runs locally / offline:
``sbomb_scan`` walks an unpacked rootfs and returns a CycloneDX SBOM with
known-vuln findings; ``sbomb_match`` resolves a package against the bundled
~262k-record OSV corpus; ``sbomb_cve`` looks a CVE/GHSA id up in that corpus.
No network, no active scanning.
"""
from __future__ import annotations

import json

from . import TOOL_VERSION
from .core import build_cyclonedx, match_vulnerabilities, scan_rootfs
from . import vulndb_local as _vdb


def _scan_to_json(target: str) -> str:
    comps = scan_rootfs(target)
    match_vulnerabilities(comps)
    return json.dumps(build_cyclonedx(comps, tool_version=TOOL_VERSION), indent=2)


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-sbomb[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-sbomb[mcp]'")
        return 1
    app = FastMCP("sbomb")

    @app.tool()
    def sbomb_scan(target: str) -> str:
        """Scan an unpacked firmware rootfs: emit a CycloneDX 1.5 SBOM and flag
        components with known CVEs. Returns JSON. Offline."""
        return _scan_to_json(target)

    @app.tool()
    def sbomb_match(package: str, version: str = "") -> str:
        """Match one package[@version] against the bundled ~262k-record offline
        OSV vulnerability corpus. Returns JSON advisories. Offline."""
        from .core import Component
        comp = Component(name=package, version=version, source="manual")
        res = _vdb.match_components([comp])
        return json.dumps(res, indent=2)

    @app.tool()
    def sbomb_cve(cve_id: str) -> str:
        """Look a CVE or GHSA id up in the bundled offline OSV corpus.
        Returns the matching records as JSON. Offline."""
        return json.dumps(_vdb.VulnDB().by_cve(cve_id), indent=2)

    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
