"""Verify every shipped demo actually produces its documented findings.

Each demo is a self-contained unpacked-rootfs fixture under demos/<NN-name>/.
This test scans each one and asserts the exact CVE findings the SCENARIO.md
promises, so a demo can never silently stop firing. No network.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sbomb import scan_rootfs, match_vulnerabilities  # noqa: E402
from sbomb.core import load_vuln_db, build_sarif  # noqa: E402
from sbomb.cli import main  # noqa: E402

DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))


def _findings(rootfs, vuln_db=None):
    comps = scan_rootfs(rootfs)
    db = load_vuln_db(vuln_db)
    match_vulnerabilities(comps, db)
    found = {}
    for c in comps:
        for v in c.vulnerabilities:
            found.setdefault(c.name.lower(), set()).add(v.id)
    return comps, found


# (demo dir, custom vuln-db relpath or None, {component: {expected cve ids}})
CASES = [
    ("01-basic", None,
     {"openssl": {"CVE-2021-3711"}, "zlib": {"CVE-2018-25032"}}),
    ("02-debian-router", None,
     {"openssl": {"CVE-2021-3711"}, "curl": {"CVE-2022-32207"}}),
    ("03-alpine-ipcam", None,
     {"openssl": {"CVE-2022-3602"}}),
    ("04-busybox-banner", None,
     {"busybox": {"CVE-2021-42374"}}),
    ("05-node-gateway", None,
     {"log4j-core": {"CVE-2021-44228"}}),
    ("06-clean-device", None, {}),
    ("07-custom-vulndb", "vuln-db.json",
     {"glibc": {"CVE-2021-3999"}, "dropbear": {"CVE-2020-36254"}}),
    ("08-multidistro", None,
     {"openssl": {"CVE-2021-3711"}, "log4j-core": {"CVE-2021-44228"}}),
]


@pytest.mark.parametrize("demo,db_rel,expected", CASES,
                         ids=[c[0] for c in CASES])
def test_demo_fires(demo, db_rel, expected):
    rootfs = os.path.join(DEMOS, demo, "rootfs")
    assert os.path.isdir(rootfs), f"missing rootfs for {demo}"
    db = os.path.join(DEMOS, demo, db_rel) if db_rel else None
    comps, found = _findings(rootfs, db)
    assert comps, f"{demo} detected no components"
    # every promised finding must be present
    for name, cves in expected.items():
        assert name in found, f"{demo}: expected findings on {name}, got {found}"
        assert cves <= found[name], (
            f"{demo}: {name} missing {cves - found.get(name, set())}")
    # the clean demo must have NO findings at all
    if not expected:
        assert found == {}, f"{demo} should be clean, got {found}"


def test_demo_06_clean_exit_zero():
    rc = main(["scan", os.path.join(DEMOS, "06-clean-device", "rootfs")])
    assert rc == 0


def test_demo_02_gate_fails():
    rc = main(["scan", os.path.join(DEMOS, "02-debian-router", "rootfs")])
    assert rc == 1


def test_demo_07_custom_db_via_cli():
    base = os.path.join(DEMOS, "07-custom-vulndb")
    rc = main(["scan", os.path.join(base, "rootfs"),
               "--vuln-db", os.path.join(base, "vuln-db.json")])
    assert rc == 1
