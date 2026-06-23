"""cognis_vulndb — a bundled, offline, 260k+ real-vulnerability database.

Ships a consolidated compact OSV corpus (cognis_vulndb.jsonl.gz, ~262k real
vulns across PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata
per record: id, CVE/GHSA aliases, ecosystem, summary, severity (CVSS), affected
packages, published/modified dates, reference count. Pure standard library; works
fully offline / air-gapped — no network, no key.

    from vulndb_local import VulnDB
    db = VulnDB()                       # lazy-loads the bundled gz
    db.count()                          # -> 262351
    db.by_cve("CVE-2021-44228")         # -> [records ...]
    db.by_package("log4j-core")         # -> records affecting that package
    db.search("deserialization", 20)    # -> summary substring matches

Refresh/extend the corpus with `datafeeds.py bulk` (OSV/NVD/GHSA) — this bundle
is the offline baseline so the tool has 100k+ vulns the moment it's cloned.
"""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any, Iterator, Optional

_HERE = Path(__file__).resolve().parent
_DB = _HERE / "cognis_vulndb.jsonl.gz"


def _pkg_suffix(pkg: str) -> str:
    """Reduce a fully-qualified OSV package id to its short artifact name.

    Maven 'org.apache.logging.log4j:log4j-core' -> 'log4j-core'
    scoped npm   '@babel/traverse'              -> 'traverse'
    Go path      'github.com/foo/bar'           -> 'bar'
    Plain names are returned lowercased unchanged.
    """
    p = (pkg or "").lower().strip()
    if ":" in p:                       # Maven group:artifact
        p = p.split(":", 1)[1]
    if p.startswith("@") and "/" in p:  # scoped npm @scope/name
        p = p.split("/", 1)[1]
    if "/" in p:                        # Go module path or npm subpath
        p = p.rsplit("/", 1)[1]
    return p


class VulnDB:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else _DB
        self._records: Optional[list[dict]] = None
        self._by_cve: Optional[dict[str, list[dict]]] = None
        self._by_pkg: Optional[dict[str, list[dict]]] = None
        self._by_suffix: Optional[dict[str, list[dict]]] = None
        self._eco: Optional[dict[str, int]] = None

    # ----- loading -----------------------------------------------------
    def __iter__(self) -> Iterator[dict]:
        if self._records is not None:
            yield from self._records
            return
        if not self.path.exists():
            return
        with gzip.open(self.path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def load(self) -> list[dict]:
        if self._records is None:
            self._records = list(self)
        return self._records

    def count(self) -> int:
        return len(self.load())

    # ----- indexed lookups (built lazily on first use) -----------------
    def _index(self) -> None:
        if self._by_cve is not None:
            return
        self._by_cve, self._by_pkg, self._by_suffix = {}, {}, {}
        for r in self.load():
            for alias in (r.get("aliases") or []):
                self._by_cve.setdefault(alias.upper(), []).append(r)
            if r.get("id"):
                self._by_cve.setdefault(r["id"].upper(), []).append(r)
            for p in (r.get("packages") or []):
                if not p:
                    continue
                self._by_pkg.setdefault(p.lower(), []).append(r)
                suffix = _pkg_suffix(p)
                if suffix and suffix != p.lower():
                    self._by_suffix.setdefault(suffix, []).append(r)

    def by_cve(self, cve: str) -> list[dict]:
        self._index()
        return self._by_cve.get((cve or "").upper(), [])

    def by_package(self, name: str, ecosystem: Optional[str] = None) -> list[dict]:
        self._index()
        hits = self._by_pkg.get((name or "").lower(), [])
        if not hits:
            # fall back to the artifact-suffix index (Maven group:artifact ->
            # artifact, scoped npm @scope/name -> name) so a short component
            # name still resolves against fully-qualified OSV package ids.
            hits = self._by_suffix.get((name or "").lower(), [])
        if ecosystem:
            hits = [r for r in hits if r.get("ecosystem", "").lower() == ecosystem.lower()]
        return hits

    def ecosystems(self) -> dict[str, int]:
        """Return a {ecosystem -> record count} histogram (lazy, cached)."""
        if self._eco is None:
            self._eco = {}
            for r in self.load():
                e = r.get("ecosystem", "") or "unknown"
                self._eco[e] = self._eco.get(e, 0) + 1
        return self._eco

    def search(self, text: str, limit: int = 50) -> list[dict]:
        t = (text or "").lower()
        out = []
        for r in self:
            if t in (r.get("summary", "") or "").lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out


_DEFAULT_DB: Optional["VulnDB"] = None


def default_db() -> "VulnDB":
    """Return a process-wide shared VulnDB over the bundled corpus.

    Loading + indexing 262k records is not free, so callers that hit the
    bundled DB repeatedly (CLI, MCP, tests) reuse one instance instead of
    re-reading the gz each time.
    """
    global _DEFAULT_DB
    if _DEFAULT_DB is None:
        _DEFAULT_DB = VulnDB()
    return _DEFAULT_DB


def count() -> int:
    return default_db().count()


# --------------------------------------------------------------------------- #
# Component matching against the bundled offline OSV corpus
# --------------------------------------------------------------------------- #
# Map a sbomb Component's purl-type / detector source onto the OSV ecosystem
# label used in the bundled corpus, so a match can be ecosystem-scoped.
_SOURCE_ECOSYSTEM = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "go": "Go",
    "maven": "Maven",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}


def _component_ecosystem(component) -> Optional[str]:
    """Best-effort OSV ecosystem for a Component (purl type first, then source)."""
    purl = getattr(component, "purl", "") or ""
    if purl.startswith("pkg:"):
        ptype = purl[4:].split("/", 1)[0]
        if ptype in _SOURCE_ECOSYSTEM:
            return _SOURCE_ECOSYSTEM[ptype]
    return _SOURCE_ECOSYSTEM.get(getattr(component, "source", ""))


def match_components(components, db: Optional["VulnDB"] = None,
                     ecosystem_strict: bool = False) -> list[dict]:
    """Match sbomb Components against the bundled 262k-record OSV corpus.

    Returns a list of enrichment dicts (one per component that had a hit):
        {"component": name, "version": ver, "ecosystem": eco|None,
         "matches": [{"id", "aliases", "ecosystem", "severity", "summary"} ...]}

    Pure offline; no network. When ``ecosystem_strict`` is True, a hit is only
    kept if the corpus record's ecosystem agrees with the component's inferred
    ecosystem (cuts cross-ecosystem name collisions). The corpus does not carry
    affected-version ranges in the compact form, so this reports *advisories
    that name the package*; combine with the curated range DB (core.py) for
    version-gated findings.
    """
    db = db or VulnDB()
    out: list[dict] = []
    for c in components:
        name = getattr(c, "name", "") or ""
        if not name:
            continue
        eco = _component_ecosystem(c)
        hits = db.by_package(name, ecosystem=eco if ecosystem_strict else None)
        if not hits:
            continue
        seen: set[str] = set()
        matches: list[dict] = []
        for r in hits:
            rid = r.get("id", "")
            if rid in seen:
                continue
            seen.add(rid)
            matches.append({
                "id": rid,
                "aliases": r.get("aliases") or [],
                "ecosystem": r.get("ecosystem", ""),
                "severity": r.get("severity", ""),
                "summary": (r.get("summary", "") or "")[:300],
            })
        out.append({
            "component": name,
            "version": getattr(c, "version", ""),
            "ecosystem": eco,
            "matches": matches,
        })
    return out
