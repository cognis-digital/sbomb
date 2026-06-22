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


class VulnDB:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else _DB
        self._records: Optional[list[dict]] = None
        self._by_cve: Optional[dict[str, list[dict]]] = None
        self._by_pkg: Optional[dict[str, list[dict]]] = None

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
        self._by_cve, self._by_pkg = {}, {}
        for r in self.load():
            for alias in (r.get("aliases") or []):
                self._by_cve.setdefault(alias.upper(), []).append(r)
            if r.get("id"):
                self._by_cve.setdefault(r["id"].upper(), []).append(r)
            for p in (r.get("packages") or []):
                if p:
                    self._by_pkg.setdefault(p.lower(), []).append(r)

    def by_cve(self, cve: str) -> list[dict]:
        self._index()
        return self._by_cve.get((cve or "").upper(), [])

    def by_package(self, name: str, ecosystem: Optional[str] = None) -> list[dict]:
        self._index()
        hits = self._by_pkg.get((name or "").lower(), [])
        if ecosystem:
            hits = [r for r in hits if r.get("ecosystem", "").lower() == ecosystem.lower()]
        return hits

    def search(self, text: str, limit: int = 50) -> list[dict]:
        t = (text or "").lower()
        out = []
        for r in self:
            if t in (r.get("summary", "") or "").lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out


def count() -> int:
    return VulnDB().count()
