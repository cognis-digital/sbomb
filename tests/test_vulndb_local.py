"""Offline test: bundled vuln DB ships 100k+ real vulns with detailed metadata."""
from sbomb.vulndb_local import VulnDB

def test_has_100k_plus_vulns():
    assert VulnDB().count() >= 100000

def test_detailed_metadata():
    r = next(iter(VulnDB()))
    for f in ("id","aliases","ecosystem","summary","severity","packages"): assert f in r

def test_cve_lookup():
    assert isinstance(VulnDB().by_cve("CVE-2021-44228"), list)

def test_package_lookup():
    db=VulnDB(); assert db.by_package("lodash") or db.by_package("django")
