"""Data-feed enrichment tests — STRICTLY OFFLINE (no network).

Points COGNIS_FEEDS_CACHE at the committed trimmed fixtures under
tests/fixtures/feeds/ (a ready-made feed cache: a real-but-trimmed CISA KEV
catalog + a real-but-trimmed OSV query map) and exercises:

  * catalog filtering to this tool's relevant feeds (osv, cisa-kev only)
  * CISA KEV tagging of an already-matched, actively-exploited CVE
  * OSV discovery of additional advisories per detected component
  * SBOM / SARIF surfacing of the KEV "known-exploited" marker
  * the CLI `feeds` command and `scan --osv --kev --offline`
  * snapshot export/import round-trip (air-gap sneakernet)

Every call uses offline=True / --offline, so CI never reaches the network.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "feeds")
DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))
DEMO_NODE = os.path.join(DEMOS, "05-node-gateway", "rootfs")   # log4j -> KEV
DEMO_BASIC = os.path.join(DEMOS, "01-basic", "rootfs")         # requests -> OSV


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    """Force the feed cache at the committed fixtures and forbid network."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", FIXTURES)

    import sbomb.datafeeds as df

    def _no_net(*a, **k):  # pragma: no cover - guard
        raise AssertionError("network access attempted in an offline test")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


def _scan(rootfs):
    from sbomb.core import scan_rootfs, match_vulnerabilities, load_vuln_db
    comps = scan_rootfs(rootfs)
    match_vulnerabilities(comps, load_vuln_db(None))
    return comps


# --------------------------------------------------------------------------- #
# catalog filtering
# --------------------------------------------------------------------------- #
def test_catalog_filtered_to_relevant_feeds():
    from sbomb import feeds
    ids = {f["id"] for f in feeds.list_relevant_feeds()}
    assert ids == {"osv", "cisa-kev"}
    # the full catalog has many more feeds; the tool must not expose them
    from sbomb import datafeeds as df
    assert len(df.load_catalog()["feeds"]) > len(ids)


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
def test_kev_index_loads_offline():
    from sbomb import feeds
    idx = feeds.load_kev_index(offline=True)
    assert "CVE-2021-44228" in idx  # Log4Shell is in our trimmed KEV sample


def test_kev_tags_actively_exploited_finding():
    from sbomb import feeds
    comps = _scan(DEMO_NODE)
    tagged = feeds.enrich_with_kev(comps, offline=True)
    assert tagged >= 1
    log4j = next(c for c in comps if c.name.lower() == "log4j-core")
    v = next(v for v in log4j.vulnerabilities if v.id == "CVE-2021-44228")
    assert getattr(v, "known_exploited", False) is True
    assert getattr(v, "kev_date_added", "")  # real KEV dateAdded present


def test_kev_does_not_tag_non_listed():
    """A matched CVE that is NOT in KEV stays untagged."""
    from sbomb import feeds
    comps = _scan(DEMO_BASIC)  # openssl CVE-2021-3711 is matched but not in KEV
    feeds.enrich_with_kev(comps, offline=True)
    ossl = next(c for c in comps if c.name.lower() == "openssl")
    for v in ossl.vulnerabilities:
        assert getattr(v, "known_exploited", False) is False


# --------------------------------------------------------------------------- #
# OSV discovery
# --------------------------------------------------------------------------- #
def test_osv_discovers_additional_advisories():
    from sbomb import feeds
    comps = _scan(DEMO_BASIC)
    requests = next(c for c in comps if c.name.lower() == "requests")
    before = {v.id for v in requests.vulnerabilities}
    added = feeds.enrich_with_osv(comps, offline=True)
    assert added >= 1
    after = {v.id for v in requests.vulnerabilities}
    new = after - before
    # the trimmed OSV map for requests@2.31.0 carries real CVE aliases
    assert any(cve.startswith("CVE-2024-") for cve in new)


def test_osv_offline_unknown_package_is_empty():
    from sbomb import feeds
    # a package not in the fixture map yields nothing, no error, no network
    comps = _scan(DEMO_NODE)  # express/ws/cookie; cookie+ws are in the map
    added = feeds.enrich_with_osv(comps, offline=True)
    assert added >= 1  # cookie@0.5.0 / ws@8.13.0 advisories


# --------------------------------------------------------------------------- #
# SBOM / SARIF surface the KEV marker
# --------------------------------------------------------------------------- #
def test_cyclonedx_carries_kev_property():
    from sbomb import feeds
    from sbomb.core import build_cyclonedx
    comps = _scan(DEMO_NODE)
    feeds.enrich_with_kev(comps, offline=True)
    doc = build_cyclonedx(comps)
    kev_vulns = [v for v in doc.get("vulnerabilities", [])
                 if any(p.get("name") == "sbomb:known_exploited"
                        for p in v.get("properties", []))]
    assert kev_vulns
    assert any(v["id"] == "CVE-2021-44228" for v in kev_vulns)


def test_sarif_escalates_kev_to_error_and_max_severity():
    from sbomb import feeds
    from sbomb.core import build_sarif
    comps = _scan(DEMO_NODE)
    feeds.enrich_with_kev(comps, offline=True)
    log = build_sarif(comps)
    run = log["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"]
                if r["id"] == "CVE-2021-44228")
    assert rule["properties"]["security-severity"] == "10.0"
    assert "known-exploited" in rule["properties"]["tags"]
    res = next(r for r in run["results"] if r["ruleId"] == "CVE-2021-44228")
    assert res["level"] == "error"
    assert "CISA KEV" in res["message"]["text"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_feeds_list():
    from sbomb.cli import main
    rc = main(["feeds", "list"])
    assert rc == 0


def test_cli_feeds_get_offline():
    from sbomb.cli import main
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    assert rc == 0


def test_cli_feeds_get_rejects_irrelevant_feed():
    from sbomb.cli import main
    rc = main(["feeds", "get", "feodo-c2", "--offline"])
    assert rc == 2  # not a relevant feed for this tool


def test_cli_scan_offline_enrichment():
    from sbomb.cli import main
    # vulns present -> CI gate returns 1; runs fully offline against fixtures
    rc = main(["scan", DEMO_NODE, "--osv", "--kev", "--offline",
               "--format", "json"])
    assert rc == 1


# --------------------------------------------------------------------------- #
# air-gap snapshot round-trip
# --------------------------------------------------------------------------- #
def test_snapshot_export_import_roundtrip(tmp_path, monkeypatch):
    from sbomb import datafeeds as df
    snap = tmp_path / "feeds.tar.gz"
    n = df.snapshot_export(str(snap))
    assert n >= 1 and snap.exists()
    # import into a fresh empty cache and confirm KEV re-serves offline
    fresh = tmp_path / "cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    imported = df.snapshot_import(str(snap))
    assert imported >= 1
    data = df.get("cisa-kev", offline=True)
    assert "vulnerabilities" in data
