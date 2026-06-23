"""Extra core-engine coverage: version comparison edge cases, every detector,
the curated range DB, custom-DB loading, and CycloneDX/SARIF detail. Offline."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sbomb.core import (  # noqa: E402
    Component,
    Vulnerability,
    DEFAULT_VULN_DB,
    build_cyclonedx,
    build_sarif,
    detect_apk,
    detect_busybox,
    detect_dpkg,
    detect_node_packages,
    detect_opkg,
    detect_os_release,
    detect_python_packages,
    load_vuln_db,
    match_vulnerabilities,
    scan_rootfs,
    version_compare,
    _normalize_version,
    _satisfies,
)
from sbomb.cli import main  # noqa: E402

DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))


def _r(name):
    return os.path.join(DEMOS, name, "rootfs")


# --------------------------------------------------------------------------- #
# version_compare edge cases
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("a,b,want", [
    ("1.0.0", "1.0.0", 0),
    ("1.0", "1.0.0", -1),       # fewer tokens sorts lower
    ("1.0.0", "1.0", 1),
    ("2.0", "10.0", -1),        # numeric, not lexical
    ("1.1.1l", "1.1.1", 1),     # alpha suffix sorts after bare number
    ("1.1.1", "1.1.1l", -1),
    ("1.2.3", "1.2.3a", -1),
    ("0.9.9", "1.0.0", -1),
    ("2020.81", "2020.79", 1),  # dropbear-style
    ("7.88.0", "7.84.0", 1),    # curl-style
])
def test_version_compare_cases(a, b, want):
    assert version_compare(a, b) == want


def test_normalize_strips_epoch_and_revision():
    assert _normalize_version("1:1.2.3-1ubuntu2") == "1.2.3"
    assert _normalize_version("  2.31.0  ") == "2.31.0"
    assert _normalize_version("1.1.1k-1+deb11u1") == "1.1.1k"


@pytest.mark.parametrize("ver,constraint,want", [
    ("1.0", "*", True),
    ("1.0", "", True),
    ("1.2.3", "==1.2.3", True),
    ("1.2.3", "=1.2.3", True),
    ("1.2.4", "==1.2.3", False),
    ("1.2.3", ">=1.0,<2.0", True),
    ("2.0.0", ">=1.0,<2.0", False),
    ("1.2.3", ">1.2.2", True),
    ("1.2.3", "<=1.2.3", True),
    ("", "<1.0", False),         # empty version never satisfies
    ("1.2.3", "1.2.3", True),    # bare version = exact match
    ("1.2.4", "1.2.3", False),
])
def test_satisfies_cases(ver, constraint, want):
    assert _satisfies(ver, constraint) is want


# --------------------------------------------------------------------------- #
# every detector fires on the multidistro demo
# --------------------------------------------------------------------------- #
def test_detect_dpkg():
    comps = detect_dpkg(_r("02-debian-router"))
    names = {c.name.lower() for c in comps}
    assert "openssl" in names
    assert all(c.source == "dpkg" for c in comps)


def test_detect_opkg():
    comps = detect_opkg(_r("01-basic"))
    names = {c.name.lower() for c in comps}
    assert "openssl" in names and "zlib" in names
    assert all(c.source == "opkg" for c in comps)


def test_detect_apk():
    comps = detect_apk(_r("03-alpine-ipcam"))
    assert comps
    assert all(c.source == "apk" for c in comps)


def test_detect_os_release():
    comps = detect_os_release(_r("01-basic"))
    assert len(comps) == 1
    assert comps[0].type == "operating-system"
    assert comps[0].name.lower() == "openwrt"


def test_detect_busybox():
    comps = detect_busybox(_r("04-busybox-banner"))
    assert len(comps) == 1
    assert comps[0].name == "busybox"
    assert comps[0].version  # banner version parsed from the binary


def test_detect_python():
    comps = detect_python_packages(_r("01-basic"))
    names = {c.name.lower() for c in comps}
    assert "requests" in names
    req = next(c for c in comps if c.name.lower() == "requests")
    assert req.purl == "pkg:pypi/requests@2.31.0"


def test_detect_node():
    comps = detect_node_packages(_r("05-node-gateway"))
    names = {c.name.lower() for c in comps}
    assert "log4j-core" in names
    assert all(c.source == "npm" for c in comps)


def test_detectors_empty_on_clean_dir(tmp_path):
    for det in (detect_dpkg, detect_opkg, detect_apk, detect_os_release,
                detect_busybox, detect_python_packages, detect_node_packages):
        assert det(str(tmp_path)) == []


# --------------------------------------------------------------------------- #
# scan dedupe + sort + error handling
# --------------------------------------------------------------------------- #
def test_scan_sorted_os_first():
    comps = scan_rootfs(_r("08-multidistro"))
    assert comps[0].type == "operating-system"
    rest = [c.name.lower() for c in comps[1:]]
    assert rest == sorted(rest)


def test_scan_bad_path_raises():
    with pytest.raises(NotADirectoryError):
        scan_rootfs(os.path.join(_r("01-basic"), "nope"))


# --------------------------------------------------------------------------- #
# curated range DB
# --------------------------------------------------------------------------- #
def test_default_db_entries_well_formed():
    for e in DEFAULT_VULN_DB:
        assert e["name"] and e["id"] and e["range"]
        assert e["id"].startswith("CVE-") or e["id"].startswith("GHSA-")


def test_load_custom_db(tmp_path):
    p = tmp_path / "db.json"
    p.write_text(json.dumps([
        {"name": "foo", "range": "<2.0", "id": "CVE-2099-1", "severity": "high"}
    ]), encoding="utf-8")
    db = load_vuln_db(str(p))
    comps = [Component(name="foo", version="1.0")]
    assert match_vulnerabilities(comps, db) == 1
    assert comps[0].vulnerabilities[0].id == "CVE-2099-1"


def test_load_bad_db_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_vuln_db(str(p))


def test_match_skips_unversioned():
    comps = [Component(name="openssl", version="")]
    assert match_vulnerabilities(comps) == 0


# --------------------------------------------------------------------------- #
# CycloneDX / SARIF detail
# --------------------------------------------------------------------------- #
def test_cyclonedx_serialnumber_unique():
    comps = scan_rootfs(_r("01-basic"))
    a = build_cyclonedx(comps)["serialNumber"]
    b = build_cyclonedx(comps)["serialNumber"]
    assert a != b and a.startswith("urn:uuid:")


def test_cyclonedx_component_properties():
    comps = scan_rootfs(_r("01-basic"))
    doc = build_cyclonedx(comps)
    c0 = next(c for c in doc["components"] if c.get("properties"))
    prop_names = {p["name"] for p in c0["properties"]}
    assert "sbomb:source" in prop_names
    assert "sbomb:evidence" in prop_names


def test_sarif_kev_property_promotes_severity():
    comps = [Component(name="log4j-core", version="2.14.1",
                       purl="pkg:maven/log4j-core@2.14.1", evidence="x")]
    match_vulnerabilities(comps)
    v = comps[0].vulnerabilities[0]
    v.known_exploited = True
    v.kev_date_added = "2021-12-10"
    v.kev_ransomware = "Known"
    log = build_sarif(comps)
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "10.0"
    assert "known-exploited" in rule["properties"]["tags"]
    res = log["runs"][0]["results"][0]
    assert res["level"] == "error"
    assert "CISA KEV" in res["message"]["text"]


def test_sarif_helpuri_for_cve():
    comps = scan_rootfs(_r("01-basic"))
    match_vulnerabilities(comps)
    log = build_sarif(comps)
    rule = next(r for r in log["runs"][0]["tool"]["driver"]["rules"]
                if r["id"].startswith("CVE-"))
    assert rule["helpUri"].startswith("https://nvd.nist.gov/vuln/detail/")


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #
def test_cli_no_command_prints_help():
    assert main([]) == 0


def test_cli_table_output(capsys):
    main(["scan", _r("02-debian-router")])
    out = capsys.readouterr().out
    assert "COMPONENT" in out and "VULNS" in out
    assert "CVE-2021-3711" in out


def test_cli_json_writes_file(tmp_path):
    out = tmp_path / "sbom.json"
    main(["scan", _r("01-basic"), "--format", "json", "-o", str(out),
          "--no-fail"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"


def test_cli_no_vuln_inventory_only(capsys):
    rc = main(["scan", _r("02-debian-router"), "--no-vuln"])
    assert rc == 0
    assert "0 vulnerability" in capsys.readouterr().out


def test_cli_custom_vuln_db_demo07():
    base = os.path.join(DEMOS, "07-custom-vulndb")
    rc = main(["scan", os.path.join(base, "rootfs"),
               "--vuln-db", os.path.join(base, "vuln-db.json"), "--no-fail"])
    assert rc == 0
