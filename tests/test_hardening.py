"""Hardening tests — error paths, edge cases, and bad-input handling."""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from sbomb.cli import main
from sbomb.core import (
    load_vuln_db,
    match_vulnerabilities,
    scan_rootfs,
    Component,
)


# ---------------------------------------------------------------------------
# load_vuln_db — bad input
# ---------------------------------------------------------------------------

def test_load_vuln_db_missing_file():
    """Passing a non-existent path raises FileNotFoundError (not a traceback)."""
    with pytest.raises(FileNotFoundError):
        load_vuln_db("/no/such/file/cves.json")


def test_load_vuln_db_invalid_json():
    """Malformed JSON raises ValueError with a clear message."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as fh:
        fh.write("{not valid json")
        path = fh.name
    try:
        with pytest.raises(ValueError, match="not valid JSON"):
            load_vuln_db(path)
    finally:
        os.unlink(path)


def test_load_vuln_db_not_a_list():
    """A JSON object (not a list) raises ValueError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as fh:
        json.dump({"name": "openssl"}, fh)
        path = fh.name
    try:
        with pytest.raises(ValueError, match="JSON list"):
            load_vuln_db(path)
    finally:
        os.unlink(path)


def test_load_vuln_db_entry_missing_name():
    """Entry without 'name' raises ValueError with field name in message."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as fh:
        json.dump([{"id": "CVE-2099-1234", "range": "<1.0"}], fh)
        path = fh.name
    try:
        with pytest.raises(ValueError, match="'name'"):
            load_vuln_db(path)
    finally:
        os.unlink(path)


def test_load_vuln_db_entry_missing_id():
    """Entry without 'id' raises ValueError with field name in message."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as fh:
        json.dump([{"name": "openssl", "range": "<1.0"}], fh)
        path = fh.name
    try:
        with pytest.raises(ValueError, match="'id'"):
            load_vuln_db(path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# match_vulnerabilities — edge cases
# ---------------------------------------------------------------------------

def test_match_vulnerabilities_empty_components():
    """Empty component list returns 0 and does not crash."""
    total = match_vulnerabilities([])
    assert total == 0


def test_match_vulnerabilities_component_no_version():
    """Components with no version are skipped without KeyError."""
    comp = Component(name="openssl", version="")
    total = match_vulnerabilities([comp])
    assert total == 0
    assert comp.vulnerabilities == []


# ---------------------------------------------------------------------------
# scan_rootfs — edge cases
# ---------------------------------------------------------------------------

def test_scan_rootfs_empty_dir():
    """An empty rootfs returns an empty list (not an error)."""
    with tempfile.TemporaryDirectory() as d:
        comps = scan_rootfs(d)
    assert comps == []


def test_scan_rootfs_not_a_dir():
    """A path that is not a directory raises NotADirectoryError."""
    with pytest.raises(NotADirectoryError):
        scan_rootfs("/no/such/rootfs/dir")


# ---------------------------------------------------------------------------
# CLI — bad vuln-db path exits 2 with a clear message
# ---------------------------------------------------------------------------

def test_cli_bad_vuln_db(capsys):
    """Passing a missing --vuln-db path exits 2 and prints an error to stderr."""
    demo = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "rootfs")
    rc = main(["scan", demo, "--vuln-db", "/no/such/cves.json"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


def test_cli_malformed_vuln_db(capsys):
    """A malformed JSON vuln-db exits 2 with an error message (no traceback)."""
    demo = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "rootfs")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as fh:
        fh.write("this is not json")
        path = fh.name
    try:
        rc = main(["scan", demo, "--vuln-db", path])
        assert rc == 2
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()
    finally:
        os.unlink(path)


def test_cli_output_to_unwritable_path(capsys):
    """Trying to write output to a directory path exits 2 with a clear error."""
    demo = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "rootfs")
    # Passing a directory as the output file will fail on open(..., "w")
    with tempfile.TemporaryDirectory() as d:
        rc = main(["scan", demo, "--format", "json", "--output", d])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()
