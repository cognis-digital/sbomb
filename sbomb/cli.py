"""Command-line interface for SBOMB."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from . import datafeeds as _df
from . import feeds as _feeds
from . import vulndb_local as _vdb
from .core import (
    Component,
    build_cyclonedx,
    build_sarif,
    load_vuln_db,
    match_vulnerabilities,
    scan_rootfs,
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _print_table(components: List[Component], total_vulns: int) -> None:
    name_w = max([len(c.name) for c in components] + [9])
    ver_w = max([len(c.version) for c in components] + [7])
    src_w = max([len(c.source) for c in components] + [6])
    header = f"{'COMPONENT':<{name_w}}  {'VERSION':<{ver_w}}  {'SOURCE':<{src_w}}  VULNS"
    print(header)
    print("-" * len(header))
    for c in components:
        if c.vulnerabilities:
            vulns = ", ".join(
                (f"{v.id}({v.severity})"
                 + ("[KEV]" if getattr(v, "known_exploited", False) else ""))
                for v in sorted(
                    c.vulnerabilities,
                    key=lambda v: _SEVERITY_ORDER.get(v.severity, 4)))
        else:
            vulns = "-"
        print(f"{c.name:<{name_w}}  {c.version:<{ver_w}}  "
              f"{c.source:<{src_w}}  {vulns}")
    print()
    print(f"{len(components)} components, {total_vulns} vulnerability finding(s).")


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        components = scan_rootfs(args.rootfs)
    except (NotADirectoryError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not components:
        print("warning: no components detected in rootfs", file=sys.stderr)

    try:
        db = load_vuln_db(args.vuln_db)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to load vuln DB: {exc}", file=sys.stderr)
        return 2

    total_vulns = 0
    if not args.no_vuln:
        total_vulns = match_vulnerabilities(components, db)

        # --- data-feed enrichment (OSV discovery + CISA KEV prioritisation) ---
        if getattr(args, "osv", False):
            try:
                added = _feeds.enrich_with_osv(components, offline=args.offline)
                total_vulns += added
                print(f"OSV: +{added} additional advisory finding(s)",
                      file=sys.stderr)
            except (FileNotFoundError, ConnectionError) as exc:
                print(f"warning: OSV enrichment skipped: {exc}",
                      file=sys.stderr)
        if getattr(args, "kev", False):
            try:
                tagged = _feeds.enrich_with_kev(components, offline=args.offline)
                print(f"CISA KEV: {tagged} finding(s) are actively exploited",
                      file=sys.stderr)
            except (FileNotFoundError, ConnectionError) as exc:
                print(f"warning: KEV enrichment skipped: {exc}",
                      file=sys.stderr)

    if args.format in ("json", "sarif"):
        if args.format == "sarif":
            doc = build_sarif(components, tool_version=TOOL_VERSION)
            label = "SARIF report"
        else:
            doc = build_cyclonedx(components, tool_version=TOOL_VERSION)
            label = "CycloneDX SBOM"
        text = json.dumps(doc, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"wrote {label} to {args.output} "
                  f"({len(components)} components, {total_vulns} vulns)",
                  file=sys.stderr)
        else:
            print(text)
    else:
        if not components:
            print("(no components)")
        else:
            _print_table(components, total_vulns)
        if args.output:
            doc = build_cyclonedx(components, tool_version=TOOL_VERSION)
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(doc, indent=2) + "\n")
            print(f"(CycloneDX SBOM also written to {args.output})",
                  file=sys.stderr)

    # CI gate: non-zero when vulnerabilities are found (unless suppressed)
    if total_vulns > 0 and not args.no_fail:
        return 1
    return 0


def _components_from_args(args: argparse.Namespace) -> List[Component]:
    """Build the component list for `match` from either a scanned rootfs or a
    list of name[@version] specs / a components JSON file. Fully offline."""
    if getattr(args, "rootfs", None):
        return scan_rootfs(args.rootfs)
    comps: List[Component] = []
    if getattr(args, "from_json", None):
        data = json.loads(_read_text(args.from_json))
        items = data.get("components", data) if isinstance(data, dict) else data
        for it in items:
            if isinstance(it, str):
                name, _, ver = it.partition("@")
                comps.append(Component(name=name, version=ver, source="manual"))
            elif isinstance(it, dict):
                comps.append(Component(
                    name=it.get("name", ""),
                    version=it.get("version", ""),
                    purl=it.get("purl", ""),
                    source=it.get("source", "manual")))
        return comps
    for spec in getattr(args, "package", []) or []:
        name, _, ver = spec.partition("@")
        comps.append(Component(name=name, version=ver, source="manual"))
    return comps


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _cmd_match(args: argparse.Namespace) -> int:
    """Enrich components against the bundled 262k-record offline OSV corpus."""
    db = _vdb.VulnDB(args.db) if getattr(args, "db", None) else _vdb.default_db()

    # direct CVE/GHSA lookup mode (no component needed)
    if getattr(args, "cve", None):
        recs = db.by_cve(args.cve)
        if args.format == "json":
            print(json.dumps({"cve": args.cve, "records": recs}, indent=2))
        else:
            print(f"{args.cve}: {len(recs)} record(s) in bundled corpus")
            for r in recs:
                print(f"  {r.get('id')}  [{r.get('ecosystem')}]  "
                      f"{', '.join(r.get('packages', [])[:3])}")
        return 0 if recs else 1

    try:
        components = _components_from_args(args)
    except (NotADirectoryError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not components:
        print("error: nothing to match — pass a rootfs, --package NAME[@VER], "
              "--from-json FILE, or --cve CVE-ID", file=sys.stderr)
        return 2

    results = _vdb.match_components(
        components, db=db, ecosystem_strict=args.ecosystem_strict)
    total = sum(len(r["matches"]) for r in results)

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME, "version": TOOL_VERSION,
            "db_records": db.count(),
            "components_scanned": len(components),
            "components_with_advisories": len(results),
            "advisory_count": total,
            "results": results,
        }, indent=2))
    else:
        print(f"Matched {len(components)} component(s) against "
              f"{db.count():,} bundled OSV records.")
        for r in results:
            print(f"\n{r['component']} {r['version']} "
                  f"[{r['ecosystem'] or 'any'}] — {len(r['matches'])} advisory(ies)")
            for m in r["matches"][:args.limit]:
                cve = next((a for a in m["aliases"]
                            if a.upper().startswith("CVE-")), m["id"])
                print(f"  {cve:18} {m['ecosystem']:10} {m['summary'][:70]}")
        print(f"\n{len(results)} component(s) carry {total} advisory(ies).")

    if total > 0 and not args.no_fail:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate a CycloneDX SBOM from an unpacked firmware "
                    "rootfs and flag known-vuln components.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Human-readable table of components + vulns
  sbomb scan ./rootfs

  # CycloneDX JSON SBOM to stdout (pipe into CI / other tools)
  sbomb scan ./rootfs --format json > sbom.json

  # Write SBOM to a file and use as a CI gate (exit 1 if vulns found)
  sbomb scan ./rootfs -o sbom.json && echo CLEAN

  # Use your own offline vuln DB
  sbomb scan ./rootfs --vuln-db my_cves.json --format json
""",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan an unpacked rootfs and emit an SBOM.",
        description="Walk an unpacked firmware rootfs, discover software "
                    "components (dpkg/opkg/apk/os-release/busybox/python/"
                    "npm), emit a CycloneDX SBOM, and flag known-vuln "
                    "components.")
    scan.add_argument("rootfs", help="Path to the unpacked rootfs directory.")
    scan.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table",
        help="Output format (default: table). 'json' emits CycloneDX 1.5; "
             "'sarif' emits SARIF 2.1.0 for GitHub code-scanning.")
    scan.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write the CycloneDX SBOM JSON to FILE.")
    scan.add_argument(
        "--vuln-db", metavar="FILE",
        help="Path to a JSON vuln DB (defaults to the bundled offline DB).")
    scan.add_argument(
        "--no-vuln", action="store_true",
        help="Skip vulnerability matching (inventory only).")
    scan.add_argument(
        "--no-fail", action="store_true",
        help="Always exit 0 even when vulnerabilities are found.")
    scan.add_argument(
        "--osv", action="store_true",
        help="Enrich findings with OSV.dev advisories (per-component query).")
    scan.add_argument(
        "--kev", action="store_true",
        help="Tag findings present in the CISA Known Exploited Vulns catalog.")
    scan.add_argument(
        "--offline", action="store_true",
        help="Edge/air-gap mode: serve feed data from the local cache only "
             "(never touches the network). Warm the cache with 'sbomb feeds "
             "update' or import a snapshot first.")
    scan.set_defaults(func=_cmd_scan)

    # ---- match: enrich against the bundled 262k-record offline OSV corpus ----
    match = sub.add_parser(
        "match",
        help="Match components against the bundled 262k-record offline OSV DB.",
        description="Resolve firmware components (from a scanned rootfs, "
                    "--package specs, or a --from-json component list) against "
                    "the bundled ~262k real OSV vulnerability records "
                    "(sbomb/cognis_vulndb.jsonl.gz). 100%% offline / air-gap; "
                    "no network. Reports advisories that name each package "
                    "across PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet.")
    msrc = match.add_argument_group("input (choose one)")
    msrc.add_argument("rootfs", nargs="?",
                      help="Unpacked rootfs to scan, then match.")
    msrc.add_argument("--package", "-p", action="append", metavar="NAME[@VER]",
                      help="Match a single package (repeatable).")
    msrc.add_argument("--from-json", metavar="FILE",
                      help="Match a components JSON file "
                           "(list of {name,version} or name@ver strings, or a "
                           "CycloneDX-like {'components':[...]}).")
    msrc.add_argument("--cve", metavar="CVE-ID",
                      help="Look a CVE/GHSA id up directly in the corpus.")
    match.add_argument("--db", metavar="FILE",
                       help="Use an alternate .jsonl.gz corpus "
                            "(default: the bundled one).")
    match.add_argument(
        "--ecosystem-strict", action="store_true",
        help="Only keep advisories whose ecosystem matches the component's "
             "inferred ecosystem (cuts cross-ecosystem name collisions).")
    match.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="Output format (default: table).")
    match.add_argument("--limit", type=int, default=10, metavar="N",
                       help="Max advisories printed per component (table mode).")
    match.add_argument("--no-fail", action="store_true",
                       help="Exit 0 even when advisories are found.")
    match.set_defaults(func=_cmd_match)

    # ---- feeds: manage the bundled data-feed cache (osv, cisa-kev) ----------
    feeds_p = sub.add_parser(
        "feeds",
        help="Manage the bundled threat/vuln data feeds (osv, cisa-kev).",
        description="Edge/air-gap-deployable ingestion for this tool's "
                    "relevant catalog feeds: OSV.dev and CISA KEV. Keyless "
                    "HTTPS fetch -> disk cache -> offline re-serve -> snapshot "
                    "export/import for sneakernet into an air-gapped enclave.")
    fsub = feeds_p.add_subparsers(dest="feeds_cmd")
    fsub.add_parser("list", help="List this tool's relevant feeds + cache age.")
    fu = fsub.add_parser("update", help="Fetch + cache feed(s).")
    fu.add_argument("ids", nargs="*",
                    help="Feed ids (default: all relevant: cisa-kev osv).")
    fg = fsub.add_parser("get", help="Print cached/fetched feed content.")
    fg.add_argument("id", help="Feed id (cisa-kev or osv).")
    fg.add_argument("--offline", action="store_true",
                    help="Serve from cache only; never touch the network.")
    fe = fsub.add_parser("snapshot-export",
                         help="Tar the feed cache for air-gap transfer.")
    fe.add_argument("path")
    fi = fsub.add_parser("snapshot-import",
                         help="Import a feed-cache snapshot into the cache.")
    fi.add_argument("path")
    feeds_p.set_defaults(func=_cmd_feeds)

    # ---- mcp: serve the scanner/matcher as MCP tools for AI agents ----------
    mcp_p = sub.add_parser(
        "mcp",
        help="Run the MCP server (exposes scan/match/cve as agent tools).",
        description="Start an MCP stdio server exposing sbomb_scan, "
                    "sbomb_match and sbomb_cve. Requires the optional 'mcp' "
                    "extra: pip install 'cognis-sbomb[mcp]'.")
    mcp_p.set_defaults(func=_cmd_mcp)
    return parser


def _cmd_mcp(args: argparse.Namespace) -> int:
    from . import mcp_server
    return mcp_server.serve()


def _cmd_feeds(args: argparse.Namespace) -> int:
    cmd = getattr(args, "feeds_cmd", None)
    if cmd == "list":
        for f in _feeds.list_relevant_feeds():
            age = _df.cached_age_hours(f["id"])
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:10} {f.get('domain',''):8} [{fresh:>10}]  "
                  f"{f['name']}")
            print(f"             {f['url']}")
        return 0
    if cmd == "update":
        ids = args.ids or _feeds.RELEVANT_FEEDS
        cat = _feeds.relevant_catalog()
        rc = 0
        for fid in ids:
            if fid not in _feeds.RELEVANT_FEEDS:
                print(f"  {fid}: not a relevant feed for this tool "
                      f"(allowed: {', '.join(_feeds.RELEVANT_FEEDS)})",
                      file=sys.stderr)
                rc = 1
                continue
            if fid == "osv":
                # OSV is a per-package POST query, not a bulk download; it is
                # cached on demand during 'scan --osv'. Nothing to pull here.
                print("  osv: query feed — cached per-component during "
                      "'scan --osv' (no bulk pull)")
                continue
            try:
                pth = _df.update(fid, catalog=cat)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as exc:
                print(f"  {fid}: {exc}", file=sys.stderr)
                rc = 1
        return rc
    if cmd == "get":
        if args.id not in _feeds.RELEVANT_FEEDS:
            print(f"error: {args.id} is not a relevant feed "
                  f"(allowed: {', '.join(_feeds.RELEVANT_FEEDS)})",
                  file=sys.stderr)
            return 2
        try:
            data = _df.get(args.id, offline=args.offline,
                           catalog=_feeds.relevant_catalog())
        except (KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        text = (json.dumps(data, indent=2) if isinstance(data, (dict, list))
                else str(data))
        print(text[:4000])
        return 0
    if cmd == "snapshot-export":
        print(f"exported {_df.snapshot_export(args.path)} feed(s) -> "
              f"{args.path}")
        return 0
    if cmd == "snapshot-import":
        print(f"imported {_df.snapshot_import(args.path)} feed(s) from "
              f"{args.path}")
        return 0
    print("usage: sbomb feeds {list|update|get|snapshot-export|"
          "snapshot-import}", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
