"""Command-line interface for SBOMB."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Component,
    build_cyclonedx,
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
                f"{v.id}({v.severity})"
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

    if args.format == "json":
        doc = build_cyclonedx(components, tool_version=TOOL_VERSION)
        text = json.dumps(doc, indent=2)
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
            except OSError as exc:
                print(f"error: cannot write output file '{args.output}': {exc}",
                      file=sys.stderr)
                return 2
            print(f"wrote CycloneDX SBOM to {args.output} "
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
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(doc, indent=2) + "\n")
            except OSError as exc:
                print(f"error: cannot write output file '{args.output}': {exc}",
                      file=sys.stderr)
                return 2
            print(f"(CycloneDX SBOM also written to {args.output})",
                  file=sys.stderr)

    # CI gate: non-zero when vulnerabilities are found (unless suppressed)
    if total_vulns > 0 and not args.no_fail:
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
        "--format", choices=["table", "json"], default="table",
        help="Output format (default: table). 'json' emits CycloneDX 1.5.")
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
    scan.set_defaults(func=_cmd_scan)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
