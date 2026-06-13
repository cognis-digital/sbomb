"""Smoke tests for SBOMB. No network. Runs the engine on the bundled demo."""
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sbomb import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    build_cyclonedx,
    match_vulnerabilities,
    scan_rootfs,
)
from sbomb.core import version_compare, _satisfies  # noqa: E402
from sbomb.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "rootfs")


def test_metadata():
    assert TOOL_NAME == "sbomb"
    assert TOOL_VERSION


def test_version_compare():
    assert version_compare("1.1.1k", "1.1.1l") < 0
    assert version_compare("1.1.1l", "1.1.1k") > 0
    assert version_compare("1.2.11", "1.2.12") < 0
    assert version_compare("3.0.7", "3.0.0") > 0
    assert version_compare("2.31.0", "2.31.0") == 0
    # epoch + distro revision are stripped
    assert version_compare("1:1.2.3-1ubuntu2", "1.2.3") == 0


def test_satisfies():
    assert _satisfies("1.1.1k", "<1.1.1l")
    assert not _satisfies("1.1.1l", "<1.1.1l")
    assert _satisfies("3.0.5", ">=3.0.0,<3.0.7")
    assert not _satisfies("3.0.7", ">=3.0.0,<3.0.7")


def test_scan_finds_components():
    comps = scan_rootfs(DEMO)
    names = {c.name.lower() for c in comps}
    # opkg, apk, os-release, python all contribute
    assert "openssl" in names
    assert "zlib" in names
    assert "dropbear" in names
    assert "libcurl" in names
    assert "musl" in names
    assert "requests" in names
    assert "openwrt" in names  # os-release
    # operating-system sorts first
    assert comps[0].type == "operating-system"


def test_sources_detected():
    comps = scan_rootfs(DEMO)
    by_name = {c.name.lower(): c for c in comps}
    assert by_name["openssl"].source == "opkg"
    assert by_name["musl"].source == "apk"
    assert by_name["requests"].source == "python"
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"


def test_vuln_matching():
    comps = scan_rootfs(DEMO)
    total = match_vulnerabilities(comps)
    assert total >= 2
    by_name = {c.name.lower(): c for c in comps}
    ossl_cves = {v.id for v in by_name["openssl"].vulnerabilities}
    assert "CVE-2021-3711" in ossl_cves
    zlib_cves = {v.id for v in by_name["zlib"].vulnerabilities}
    assert "CVE-2018-25032" in zlib_cves
    # patched versions must NOT be flagged
    assert by_name["dropbear"].vulnerabilities == []
    assert by_name["libcurl"].vulnerabilities == []


def test_cyclonedx_shape():
    comps = scan_rootfs(DEMO)
    match_vulnerabilities(comps)
    doc = build_cyclonedx(comps)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == len(comps)
    assert "vulnerabilities" in doc
    assert any(v["id"] == "CVE-2021-3711" for v in doc["vulnerabilities"])


def test_cli_exit_code_is_gate():
    # vulns present -> non-zero exit for CI gating
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1
    # suppressed gate -> exit 0
    rc = main(["scan", DEMO, "--no-fail"])
    assert rc == 0
    # inventory only -> no vulns -> exit 0
    rc = main(["scan", DEMO, "--no-vuln"])
    assert rc == 0


def test_cli_bad_path():
    rc = main(["scan", os.path.join(DEMO, "does-not-exist")])
    assert rc == 2
