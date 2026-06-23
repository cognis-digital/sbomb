"""Offline test: bundled vuln DB ships 100k+ real vulns with detailed metadata."""
from sbomb.vulndb_local import default_db

_DB = default_db()
_DB.load()


def test_has_100k_plus_vulns():
    assert _DB.count() >= 100000


def test_detailed_metadata():
    r = next(iter(_DB))
    for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert f in r


def test_cve_lookup():
    assert isinstance(_DB.by_cve("CVE-2021-44228"), list)
    assert _DB.by_cve("CVE-2021-44228")  # Log4Shell really resolves


def test_package_lookup():
    assert _DB.by_package("lodash") or _DB.by_package("django")
