"""Edge/air-gap data-feed enrichment for SBOMB.

Wires the bundled :mod:`sbomb.datafeeds` ingestion layer (keyless HTTPS fetch ->
disk cache -> offline re-serve -> snapshot export/import) into the firmware SBOM
scanner so findings carry *real* public threat/vuln intelligence:

  * **cisa-kev** — CISA Known Exploited Vulnerabilities. Any CVE that SBOMB
    already matched against a component is checked against the live KEV catalog;
    if present, the finding is tagged ``known_exploited`` (with the KEV
    ``dateAdded`` and ransomware-campaign flag). KEV is the highest-priority
    "patch this first" signal for gov/enterprise/edge fleets.
  * **osv** — OSV.dev. For each detected component SBOMB queries OSV by
    ecosystem+name+version to discover *additional* advisories beyond the
    bundled offline DB, attaching the CVE/GHSA ids it returns.

Everything runs offline once the cache is warm (``--offline`` / ``get(...,
offline=True)``), so an air-gapped enclave keeps enriching against a snapshot.

This repo is restricted to its relevant catalog domain: feeds ``osv`` and
``cisa-kev`` only. Defensive / authorized-use intelligence only.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from . import datafeeds as _df
from .core import Component, Vulnerability

# The only catalog feeds this tool consumes.
RELEVANT_FEEDS = ["cisa-kev", "osv"]

# Map our component purl-type / source to an OSV ecosystem.
_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "deb": "Debian",
    "apk": "Alpine",
}


# --------------------------------------------------------------------------- #
# catalog helpers (filtered to this tool's domain)
# --------------------------------------------------------------------------- #
def relevant_catalog() -> dict:
    """Return the bundled catalog filtered to this tool's relevant feeds."""
    cat = _df.load_catalog()
    feeds = [f for f in cat.get("feeds", []) if f["id"] in RELEVANT_FEEDS]
    return {"_meta": cat.get("_meta", {}), "feeds": feeds}


def list_relevant_feeds() -> List[dict]:
    cat = relevant_catalog()
    return cat["feeds"]


# --------------------------------------------------------------------------- #
# cisa-kev enrichment
# --------------------------------------------------------------------------- #
def load_kev_index(*, offline: bool = False) -> Dict[str, dict]:
    """Return a {CVE-id -> KEV record} index from the cached/fetched KEV feed."""
    data = _df.get("cisa-kev", offline=offline, catalog=relevant_catalog())
    index: Dict[str, dict] = {}
    for rec in data.get("vulnerabilities", []):
        cve = rec.get("cveID")
        if cve:
            index[cve.upper()] = rec
    return index


def enrich_with_kev(components: List[Component], *, offline: bool = False
                    ) -> int:
    """Tag already-matched CVE findings that appear in CISA KEV.

    Adds ``known_exploited`` / ``kev_date_added`` / ``kev_ransomware`` to each
    matching :class:`Vulnerability` (attributes set dynamically; the SBOM/SARIF
    builders surface them). Returns the number of findings tagged.
    """
    kev = load_kev_index(offline=offline)
    tagged = 0
    for c in components:
        for v in c.vulnerabilities:
            rec = kev.get(v.id.upper())
            if rec is None:
                continue
            v.known_exploited = True  # type: ignore[attr-defined]
            v.kev_date_added = rec.get("dateAdded", "")  # type: ignore[attr-defined]
            ransom = rec.get("knownRansomwareCampaignUse", "Unknown")
            v.kev_ransomware = ransom  # type: ignore[attr-defined]
            tagged += 1
    return tagged


# --------------------------------------------------------------------------- #
# osv enrichment
# --------------------------------------------------------------------------- #
def _osv_ecosystem(c: Component) -> Optional[str]:
    if c.purl.startswith("pkg:"):
        ptype = c.purl[4:].split("/", 1)[0]
        if ptype in _OSV_ECOSYSTEM:
            return _OSV_ECOSYSTEM[ptype]
    return _OSV_ECOSYSTEM.get(c.source)


def _osv_query(name: str, ecosystem: str, version: str, *, offline: bool
               ) -> List[dict]:
    """Query OSV for one package@version. Offline: serve a cached query map.

    The OSV API is a POST query, so for air-gap use we cache a *map* of
    "<ecosystem>|<name>|<version>" -> response under the ``osv`` feed id (the
    ``osv_query_map`` cache key) and serve from it when ``offline``.
    """
    key = f"{ecosystem}|{name}|{version}"
    if offline:
        cached = _load_osv_query_map()
        return cached.get(key, {}).get("vulns", []) or []
    body = {"package": {"name": name, "ecosystem": ecosystem},
            "version": version}
    try:
        raw = _df.fetch("https://api.osv.dev/v1/query",
                        method="POST", data=json.dumps(body).encode())
        resp = json.loads(raw)
    except (ConnectionError, ValueError):
        return []
    # persist into the offline query map so the next --offline run sees it
    _save_osv_query(key, resp)
    return resp.get("vulns", []) or []


def _osv_map_path():
    return _df.cache_dir() / "osv_query_map.json"


def _load_osv_query_map() -> dict:
    p = _osv_map_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return {}
    return {}


def _save_osv_query(key: str, resp: dict) -> None:
    m = _load_osv_query_map()
    m[key] = {"vulns": resp.get("vulns", []) or []}
    _osv_map_path().write_text(json.dumps(m), encoding="utf-8")


def _best_cve_id(vuln: dict) -> str:
    """Prefer a CVE alias; fall back to the OSV/GHSA id."""
    for alias in vuln.get("aliases", []) or []:
        if alias.upper().startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def _osv_severity(vuln: dict) -> str:
    sev = (vuln.get("database_specific", {}) or {}).get("severity", "")
    return {
        "CRITICAL": "critical", "HIGH": "high",
        "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low",
    }.get(str(sev).upper(), "unknown")


def enrich_with_osv(components: List[Component], *, offline: bool = False
                    ) -> int:
    """Discover *additional* advisories per component via OSV.dev.

    Attaches any OSV-reported vuln not already present on the component.
    Returns the number of new findings added.
    """
    added = 0
    for c in components:
        eco = _osv_ecosystem(c)
        if not eco or not c.version:
            continue
        existing = {v.id.upper() for v in c.vulnerabilities}
        for vuln in _osv_query(c.name, eco, c.version, offline=offline):
            cve = _best_cve_id(vuln)
            if not cve or cve.upper() in existing:
                continue
            summary = vuln.get("summary") or vuln.get("details", "") or ""
            c.vulnerabilities.append(Vulnerability(
                id=cve,
                severity=_osv_severity(vuln),
                description=summary[:300],
                affected_versions="see OSV advisory " + vuln.get("id", ""),
            ))
            existing.add(cve.upper())
            added += 1
    return added
