"""SBOMB MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from sbomb.core import scan, to_json

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
        """Generate a CycloneDX SBOM directly from an unpacked firmware root filesystem and flag components with known CVEs and EOL kernels.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
