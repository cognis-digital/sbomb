"""Tests for the bundled 262k-record offline OSV corpus + `match` subcommand.

STRICTLY OFFLINE — only the bundled sbomb/cognis_vulndb.jsonl.gz is touched;
no network. Proves real lookups resolve (Log4Shell / log4j-core), the
component matcher resolves fully-qualified OSV package ids from short firmware
component names, and the CLI `match` command behaves (formats, exit gate,
direct CVE lookup, alternate corpus).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sbomb import vulndb_local as vdb  # noqa: E402
from sbomb.core import Component, scan_rootfs  # noqa: E402
from sbomb.cli import main  # noqa: E402

DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))
DEMO_NODE = os.path.join(DEMOS, "05-node-gateway", "rootfs")

# One shared, fully-indexed DB instance for the whole module so the 262k-record
# corpus is loaded and indexed exactly once (keeps the suite fast). This is the
# same instance the CLI uses by default, so CLI tests pay the load cost once too.
_SHARED = vdb.default_db()
_SHARED.load()


# --------------------------------------------------------------------------- #
# corpus shape + scale
# --------------------------------------------------------------------------- #
def test_corpus_is_large():
    assert vdb.count() >= 100_000


def test_corpus_count_is_stable():
    db = _SHARED
    assert db.count() == db.count()  # idempotent (cached)


def test_records_carry_expected_fields():
    r = next(iter(_SHARED))
    for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert f in r


def test_ecosystems_histogram():
    eco = _SHARED.ecosystems()
    assert isinstance(eco, dict)
    assert sum(eco.values()) == vdb.count()
    # the bundled corpus spans multiple ecosystems
    assert len(eco) >= 3


# --------------------------------------------------------------------------- #
# real CVE / GHSA lookups
# --------------------------------------------------------------------------- #
def test_log4shell_resolves_by_cve():
    hits = _SHARED.by_cve("CVE-2021-44228")
    assert hits, "Log4Shell must resolve in the bundled corpus"
    rec = hits[0]
    assert "CVE-2021-44228" in (rec.get("aliases") or [])
    assert rec.get("ecosystem") == "Maven"
    assert any("log4j-core" in p for p in rec.get("packages", []))


def test_cve_lookup_is_case_insensitive():
    db = _SHARED
    assert db.by_cve("cve-2021-44228") == db.by_cve("CVE-2021-44228")


def test_unknown_cve_returns_empty():
    assert _SHARED.by_cve("CVE-0000-00000") == []


def test_ghsa_id_resolves():
    # the Log4Shell record is keyed under its GHSA id too
    db = _SHARED
    cve_hits = db.by_cve("CVE-2021-44228")
    ghsa = cve_hits[0]["id"]
    assert ghsa.startswith("GHSA-")
    assert db.by_cve(ghsa)


# --------------------------------------------------------------------------- #
# package lookups (exact + artifact-suffix fallback)
# --------------------------------------------------------------------------- #
def test_fully_qualified_maven_package_lookup():
    hits = _SHARED.by_package("org.apache.logging.log4j:log4j-core")
    assert hits
    assert any("CVE-2021-44228" in (r.get("aliases") or []) for r in hits)


def test_short_name_resolves_via_suffix_index():
    # 'log4j-core' alone resolves the Maven group:artifact record
    hits = _SHARED.by_package("log4j-core")
    assert hits
    assert any("CVE-2021-44228" in (r.get("aliases") or []) for r in hits)


def test_pkg_suffix_normalization():
    assert vdb._pkg_suffix("org.apache.logging.log4j:log4j-core") == "log4j-core"
    assert vdb._pkg_suffix("@babel/traverse") == "traverse"
    assert vdb._pkg_suffix("github.com/foo/bar") == "bar"
    assert vdb._pkg_suffix("Lodash") == "lodash"


def test_ecosystem_filtered_lookup():
    db = _SHARED
    maven = db.by_package("log4j-core", ecosystem="Maven")
    assert maven
    assert all(r.get("ecosystem") == "Maven" for r in maven)
    assert db.by_package("log4j-core", ecosystem="PyPI") == []


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #
def test_search_limit_respected():
    out = _SHARED.search("deserialization", limit=5)
    assert len(out) <= 5


# --------------------------------------------------------------------------- #
# match_components
# --------------------------------------------------------------------------- #
def test_match_components_log4j():
    comps = [Component(name="log4j-core", version="2.14.1",
                       source="npm", purl="pkg:maven/log4j-core@2.14.1")]
    res = vdb.match_components(comps, db=_SHARED)
    assert res and res[0]["component"] == "log4j-core"
    ids = {m["id"] for m in res[0]["matches"]}
    aliases = {a for m in res[0]["matches"] for a in m["aliases"]}
    assert "CVE-2021-44228" in aliases or any("44228" in i for i in ids)


def test_match_components_dedupes():
    comps = [Component(name="log4j-core", version="2.14.1")]
    res = vdb.match_components(comps, db=_SHARED)
    ids = [m["id"] for m in res[0]["matches"]]
    assert len(ids) == len(set(ids))


def test_match_components_no_hit():
    comps = [Component(name="definitely-not-a-real-package-xyz", version="1.0")]
    assert vdb.match_components(comps, db=_SHARED) == []


def test_match_components_on_real_rootfs():
    comps = scan_rootfs(DEMO_NODE)
    res = vdb.match_components(comps, db=_SHARED)
    assert res, "node-gateway components should resolve advisories"
    total = sum(len(r["matches"]) for r in res)
    assert total >= 1


def test_ecosystem_strict_filters():
    comps = [Component(name="log4j-core", version="2.14.1", source="python",
                       purl="pkg:pypi/log4j-core@2.14.1")]
    # inferred ecosystem PyPI -> Maven record filtered out under strict mode
    strict = vdb.match_components(comps, db=_SHARED, ecosystem_strict=True)
    loose = vdb.match_components(comps, db=_SHARED, ecosystem_strict=False)
    strict_n = sum(len(r["matches"]) for r in strict)
    loose_n = sum(len(r["matches"]) for r in loose)
    assert loose_n >= strict_n


# --------------------------------------------------------------------------- #
# CLI: match
# --------------------------------------------------------------------------- #
def test_cli_match_package_gate(capsys):
    rc = main(["match", "-p", "log4j-core"])
    assert rc == 1  # advisories present -> gate fails
    assert "advisory" in capsys.readouterr().out.lower()


def test_cli_match_package_no_fail():
    assert main(["match", "-p", "log4j-core", "--no-fail"]) == 0


def test_cli_match_json(capsys):
    main(["match", "-p", "log4j-core", "--format", "json", "--no-fail"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "sbomb"
    assert doc["db_records"] >= 100_000
    assert doc["advisory_count"] >= 1


def test_cli_match_cve_direct(capsys):
    rc = main(["match", "--cve", "CVE-2021-44228"])
    assert rc == 0
    assert "record" in capsys.readouterr().out


def test_cli_match_cve_json(capsys):
    main(["match", "--cve", "CVE-2021-44228", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["cve"] == "CVE-2021-44228"
    assert doc["records"]


def test_cli_match_unknown_cve_exit_1():
    assert main(["match", "--cve", "CVE-0000-00000"]) == 1


def test_cli_match_rootfs(capsys):
    rc = main(["match", DEMO_NODE, "--no-fail"])
    assert rc == 0
    assert "component" in capsys.readouterr().out.lower()


def test_cli_match_from_json(tmp_path, capsys):
    spec = tmp_path / "components.json"
    spec.write_text(json.dumps(
        {"components": [{"name": "log4j-core", "version": "2.14.1"}]}),
        encoding="utf-8")
    rc = main(["match", "--from-json", str(spec), "--no-fail"])
    assert rc == 0


def test_cli_match_nothing_to_match():
    assert main(["match"]) == 2


def test_cli_match_alternate_db(tmp_path):
    import gzip
    alt = tmp_path / "alt.jsonl.gz"
    rec = {"id": "GHSA-x", "aliases": ["CVE-2099-1"], "ecosystem": "npm",
           "summary": "test", "severity": "", "packages": ["leftpad"]}
    with gzip.open(alt, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    rc = main(["match", "-p", "leftpad", "--db", str(alt)])
    assert rc == 1
