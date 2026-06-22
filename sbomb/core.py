"""Core engine for SBOMB.

Walks an unpacked firmware rootfs, discovers software components from the
package databases and metadata commonly left in embedded Linux images
(dpkg, opkg, apk, os-release, busybox, python dist-info, node package.json),
emits a CycloneDX 1.5 SBOM, and matches components against a known-vuln
database using simple version-range logic.

Standard library only.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Vulnerability:
    id: str                       # e.g. CVE-2021-3711
    severity: str = "unknown"     # critical/high/medium/low/unknown
    description: str = ""
    affected_versions: str = ""   # human note, e.g. "<1.1.1l"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "description": self.description,
            "affected_versions": self.affected_versions,
        }


@dataclass
class Component:
    name: str
    version: str = ""
    type: str = "library"          # CycloneDX component type
    source: str = ""               # which detector found it (dpkg/opkg/apk/...)
    purl: str = ""                 # package URL
    evidence: str = ""             # path/file the evidence came from
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def bom_ref(self) -> str:
        return self.purl or f"{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "source": self.source,
            "purl": self.purl,
            "evidence": self.evidence,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


# --------------------------------------------------------------------------
# Version comparison (PEP-440-ish / dpkg-ish, good enough for matching)
# --------------------------------------------------------------------------
def _normalize_version(v: str) -> str:
    """Strip epoch and distro revision noise so we compare upstream versions."""
    v = v.strip()
    # drop dpkg epoch  '1:1.2.3'
    if ":" in v:
        v = v.split(":", 1)[1]
    # drop debian/distro revision  '1.2.3-1ubuntu2'
    if "-" in v:
        v = v.split("-", 1)[0]
    # drop alpine/openwrt suffix tails like '1.2.3_p4' -> keep numeric/alpha core
    return v.strip()


def _split_version(v: str) -> List:
    """Split into comparable tokens. Numeric chunks compare as ints; the
    presence of an alpha suffix (e.g. the 'l' in '1.1.1l') is captured so
    '1.1.1l' > '1.1.1'."""
    v = _normalize_version(v)
    tokens: List = []
    for part in re.split(r"[._]", v):
        m = re.match(r"^(\d+)([A-Za-z]*)$", part)
        if m:
            tokens.append((0, int(m.group(1))))
            if m.group(2):
                # alpha suffix sorts after the bare number
                tokens.append((1, m.group(2)))
        elif part.isdigit():
            tokens.append((0, int(part)))
        elif part:
            tokens.append((1, part))
    return tokens


def version_compare(a: str, b: str) -> int:
    """Return -1 if a<b, 0 if equal, 1 if a>b."""
    ta, tb = _split_version(a), _split_version(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        # mixed type tuples compare fine because first element is the kind tag
        return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


def _satisfies(version: str, constraint: str) -> bool:
    """Evaluate a single comma-separated constraint string against a version.
    Supports <, <=, >, >=, ==, =.  All parts must hold (AND)."""
    if not version:
        return False
    constraint = constraint.strip()
    if constraint in ("", "*"):
        return True
    for clause in constraint.split(","):
        clause = clause.strip()
        m = re.match(r"^(<=|>=|==|=|<|>)\s*(.+)$", clause)
        if not m:
            # bare version means exact match
            if version_compare(version, clause) != 0:
                return False
            continue
        op, target = m.group(1), m.group(2).strip()
        cmp = version_compare(version, target)
        ok = {
            "<": cmp < 0,
            "<=": cmp <= 0,
            ">": cmp > 0,
            ">=": cmp >= 0,
            "=": cmp == 0,
            "==": cmp == 0,
        }[op]
        if not ok:
            return False
    return True


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------
def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _purl(ptype: str, name: str, version: str) -> str:
    name = name.replace(" ", "%20")
    if version:
        return f"pkg:{ptype}/{name}@{version}"
    return f"pkg:{ptype}/{name}"


def detect_dpkg(rootfs: str) -> List[Component]:
    """Parse Debian/Ubuntu /var/lib/dpkg/status."""
    status = os.path.join(rootfs, "var", "lib", "dpkg", "status")
    out: List[Component] = []
    if not os.path.isfile(status):
        return out
    rel = os.path.relpath(status, rootfs)
    for block in _read(status).split("\n\n"):
        if not block.strip():
            continue
        fields: Dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and key:
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                fields[key.strip()] = val.strip()
        name = fields.get("Package")
        if not name:
            continue
        # skip not-installed entries
        if "installed" not in fields.get("Status", "installed").lower():
            continue
        ver = fields.get("Version", "")
        out.append(Component(
            name=name, version=ver, type="library", source="dpkg",
            purl=_purl("deb", name, ver), evidence=rel,
        ))
    return out


def detect_opkg(rootfs: str) -> List[Component]:
    """Parse OpenWrt/Yocto opkg status (/usr/lib/opkg/status or /var/lib/opkg/status)."""
    candidates = [
        os.path.join(rootfs, "usr", "lib", "opkg", "status"),
        os.path.join(rootfs, "var", "lib", "opkg", "status"),
    ]
    out: List[Component] = []
    for status in candidates:
        if not os.path.isfile(status):
            continue
        rel = os.path.relpath(status, rootfs)
        for block in _read(status).split("\n\n"):
            if not block.strip():
                continue
            fields: Dict[str, str] = {}
            for line in block.splitlines():
                if ":" in line and not line.startswith(" "):
                    k, v = line.split(":", 1)
                    fields[k.strip()] = v.strip()
            name = fields.get("Package")
            if not name:
                continue
            ver = fields.get("Version", "")
            out.append(Component(
                name=name, version=ver, type="library", source="opkg",
                purl=_purl("opkg", name, ver), evidence=rel,
            ))
    return out


def detect_apk(rootfs: str) -> List[Component]:
    """Parse Alpine /lib/apk/db/installed."""
    db = os.path.join(rootfs, "lib", "apk", "db", "installed")
    out: List[Component] = []
    if not os.path.isfile(db):
        return out
    rel = os.path.relpath(db, rootfs)
    for block in _read(db).split("\n\n"):
        if not block.strip():
            continue
        name = ver = None
        for line in block.splitlines():
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                ver = line[2:].strip()
        if name:
            out.append(Component(
                name=name, version=ver or "", type="library", source="apk",
                purl=_purl("apk", name, ver or ""), evidence=rel,
            ))
    return out


def detect_os_release(rootfs: str) -> List[Component]:
    """Parse /etc/os-release to record the base OS as an operating-system component."""
    for cand in (
        os.path.join(rootfs, "etc", "os-release"),
        os.path.join(rootfs, "usr", "lib", "os-release"),
    ):
        if os.path.isfile(cand):
            data = {}
            for line in _read(cand).splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            name = data.get("ID") or data.get("NAME") or "linux"
            ver = data.get("VERSION_ID", "")
            return [Component(
                name=name, version=ver, type="operating-system",
                source="os-release",
                purl=_purl("generic", name, ver),
                evidence=os.path.relpath(cand, rootfs),
            )]
    return []


def detect_busybox(rootfs: str) -> List[Component]:
    """Detect busybox version by scanning the binary for its version banner."""
    for cand in (
        os.path.join(rootfs, "bin", "busybox"),
        os.path.join(rootfs, "usr", "bin", "busybox"),
        os.path.join(rootfs, "sbin", "busybox"),
    ):
        if os.path.isfile(cand):
            try:
                with open(cand, "rb") as fh:
                    blob = fh.read(2_000_000)
            except OSError:
                continue
            m = re.search(rb"BusyBox v(\d+\.\d+\.\d+)", blob)
            ver = m.group(1).decode() if m else ""
            return [Component(
                name="busybox", version=ver, type="application",
                source="binary", purl=_purl("generic", "busybox", ver),
                evidence=os.path.relpath(cand, rootfs),
            )]
    return []


def detect_python_packages(rootfs: str) -> List[Component]:
    """Find installed python packages via *.dist-info/*.egg-info METADATA."""
    out: List[Component] = []
    seen = set()
    for dirpath, dirnames, _files in os.walk(rootfs):
        for d in dirnames:
            if d.endswith(".dist-info") or d.endswith(".egg-info"):
                meta = os.path.join(dirpath, d, "METADATA")
                if not os.path.isfile(meta):
                    meta = os.path.join(dirpath, d, "PKG-INFO")
                if not os.path.isfile(meta):
                    continue
                name = ver = ""
                for line in _read(meta).splitlines():
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        ver = line.split(":", 1)[1].strip()
                    if name and ver:
                        break
                key = (name.lower(), ver)
                if name and key not in seen:
                    seen.add(key)
                    out.append(Component(
                        name=name, version=ver, type="library",
                        source="python", purl=_purl("pypi", name.lower(), ver),
                        evidence=os.path.relpath(
                            os.path.join(dirpath, d), rootfs),
                    ))
    return out


def detect_node_packages(rootfs: str) -> List[Component]:
    """Find node modules via node_modules/*/package.json."""
    out: List[Component] = []
    seen = set()
    for dirpath, dirnames, _files in os.walk(rootfs):
        if os.path.basename(dirpath) == "node_modules":
            for mod in dirnames:
                pj = os.path.join(dirpath, mod, "package.json")
                if not os.path.isfile(pj):
                    continue
                try:
                    data = json.loads(_read(pj))
                except (ValueError, OSError):
                    continue
                name = data.get("name")
                ver = data.get("version", "")
                if not name:
                    continue
                key = (name, ver)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Component(
                    name=name, version=ver, type="library",
                    source="npm", purl=_purl("npm", name, ver),
                    evidence=os.path.relpath(pj, rootfs),
                ))
    return out


DETECTORS = [
    detect_os_release,
    detect_dpkg,
    detect_opkg,
    detect_apk,
    detect_busybox,
    detect_python_packages,
    detect_node_packages,
]


def scan_rootfs(rootfs: str) -> List[Component]:
    """Run every detector against an unpacked rootfs and return a deduped,
    sorted list of Components."""
    if not os.path.isdir(rootfs):
        raise NotADirectoryError(f"rootfs is not a directory: {rootfs}")
    found: List[Component] = []
    for det in DETECTORS:
        try:
            found.extend(det(rootfs))
        except OSError:
            continue
    # dedupe on (name lower, version, source)
    seen = set()
    deduped: List[Component] = []
    for c in found:
        key = (c.name.lower(), c.version, c.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    deduped.sort(key=lambda c: (c.type != "operating-system", c.name.lower(), c.version))
    return deduped


# --------------------------------------------------------------------------
# Vulnerability matching
# --------------------------------------------------------------------------
# Bundled, offline starter DB.  Each entry: {name, range, id, severity, desc}.
# 'range' is a comma-separated constraint over the *upstream* version.
DEFAULT_VULN_DB: List[dict] = [
    {"name": "openssl", "range": "<1.1.1l", "id": "CVE-2021-3711",
     "severity": "critical",
     "description": "SM2 decryption buffer overflow allowing RCE."},
    {"name": "openssl", "range": ">=3.0.0,<3.0.7", "id": "CVE-2022-3602",
     "severity": "high",
     "description": "X.509 punycode buffer overflow (Spooky SSL)."},
    {"name": "busybox", "range": "<1.34.0", "id": "CVE-2021-42374",
     "severity": "medium",
     "description": "Out-of-bounds read in unlzma applet."},
    {"name": "zlib", "range": "<1.2.12", "id": "CVE-2018-25032",
     "severity": "high",
     "description": "Memory corruption in deflate with memLevel=1."},
    {"name": "dropbear", "range": "<2020.79", "id": "CVE-2020-36254",
     "severity": "medium",
     "description": "Insufficient validation of usernames in scp."},
    {"name": "libcurl", "range": "<7.84.0", "id": "CVE-2022-32207",
     "severity": "critical",
     "description": "Cookie file permission / overwrite issue."},
    {"name": "curl", "range": "<7.84.0", "id": "CVE-2022-32207",
     "severity": "critical",
     "description": "Cookie file permission / overwrite issue."},
    {"name": "log4j-core", "range": ">=2.0,<2.17.1", "id": "CVE-2021-44228",
     "severity": "critical",
     "description": "Log4Shell JNDI remote code execution."},
    {"name": "glibc", "range": "<2.35", "id": "CVE-2021-3999",
     "severity": "high",
     "description": "Off-by-one buffer overflow in getcwd."},
]


def load_vuln_db(path: Optional[str] = None) -> List[dict]:
    """Load a vuln DB from a JSON file, or return the bundled default.
    The JSON file must be a list of objects with keys:
    name, range, id, severity (optional), description (optional)."""
    if not path:
        return list(DEFAULT_VULN_DB)
    data = json.loads(_read(path))
    if not isinstance(data, list):
        raise ValueError("vuln DB must be a JSON list of entries")
    return data


def match_vulnerabilities(components: List[Component],
                          db: Optional[List[dict]] = None) -> int:
    """Attach matching vulnerabilities to each component (in place).
    Returns the total number of vulnerability findings."""
    if db is None:
        db = DEFAULT_VULN_DB
    # index db by lowercased name for speed
    by_name: Dict[str, List[dict]] = {}
    for entry in db:
        by_name.setdefault(entry["name"].lower(), []).append(entry)
    total = 0
    for c in components:
        for entry in by_name.get(c.name.lower(), []):
            if not c.version:
                continue
            if _satisfies(c.version, entry.get("range", "*")):
                c.vulnerabilities.append(Vulnerability(
                    id=entry["id"],
                    severity=entry.get("severity", "unknown"),
                    description=entry.get("description", ""),
                    affected_versions=entry.get("range", ""),
                ))
                total += 1
    return total


# --------------------------------------------------------------------------
# CycloneDX 1.5 output
# --------------------------------------------------------------------------
def build_cyclonedx(components: List[Component],
                    tool_version: str = "1.0.0") -> dict:
    """Build a CycloneDX 1.5 JSON document (as a dict)."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    cyclone_components = []
    vulnerabilities = []
    for c in components:
        comp_obj = {
            "type": c.type,
            "bom-ref": c.bom_ref(),
            "name": c.name,
        }
        if c.version:
            comp_obj["version"] = c.version
        if c.purl:
            comp_obj["purl"] = c.purl
        if c.evidence:
            comp_obj["properties"] = [
                {"name": "sbomb:source", "value": c.source},
                {"name": "sbomb:evidence", "value": c.evidence},
            ]
        cyclone_components.append(comp_obj)
        for v in c.vulnerabilities:
            vulnerabilities.append({
                "id": v.id,
                "ratings": [{"severity": v.severity}],
                "description": v.description,
                "affects": [{"ref": c.bom_ref()}],
            })
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "sbomb", "name": "sbomb",
                       "version": tool_version}],
        },
        "components": cyclone_components,
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities
    return doc


# --------------------------------------------------------------------------
# SARIF 2.1.0 output (for GitHub code-scanning / generic SAST ingestion)
# --------------------------------------------------------------------------
# Map our severity vocabulary onto the SARIF result.level enum and the
# security-severity score GitHub uses to bucket alerts.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "warning",
}
_SARIF_SECURITY_SEVERITY = {
    "critical": "9.8",
    "high": "8.1",
    "medium": "5.5",
    "low": "3.1",
    "unknown": "5.0",
}


def build_sarif(components: List[Component],
                tool_version: str = "1.0.0") -> dict:
    """Build a SARIF 2.1.0 log from the vulnerability findings.

    Each vulnerable (component, CVE) pair becomes one SARIF result; each
    distinct CVE becomes a reusable rule under the tool driver. The component
    evidence path is emitted as the result location so GitHub code-scanning
    can anchor the alert. Components with no vulnerabilities produce no
    results (a clean scan yields an empty `results` array, which is valid)."""
    rules_index: Dict[str, int] = {}
    rules: List[dict] = []
    results: List[dict] = []
    for c in components:
        for v in c.vulnerabilities:
            if v.id not in rules_index:
                rules_index[v.id] = len(rules)
                rules.append({
                    "id": v.id,
                    "name": v.id.replace("-", ""),
                    "shortDescription": {"text": v.id},
                    "fullDescription": {
                        "text": v.description or v.id},
                    "helpUri": (
                        "https://nvd.nist.gov/vuln/detail/" + v.id
                        if v.id.upper().startswith("CVE-")
                        else ""),
                    "properties": {
                        "security-severity": _SARIF_SECURITY_SEVERITY.get(
                            v.severity, "5.0"),
                        "tags": ["security", "vulnerability"],
                    },
                })
            loc = c.evidence or c.bom_ref()
            results.append({
                "ruleId": v.id,
                "ruleIndex": rules_index[v.id],
                "level": _SARIF_LEVEL.get(v.severity, "warning"),
                "message": {
                    "text": (
                        f"{c.name} {c.version} is affected by {v.id} "
                        f"({v.severity}): {v.description} "
                        f"[affected: {v.affected_versions or 'see advisory'}]"
                    ).strip()
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.replace(os.sep, "/")},
                    }
                }],
                "partialFingerprints": {
                    "sbomb/component-cve": f"{c.bom_ref()}::{v.id}",
                },
            })
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sbomb",
                    "version": tool_version,
                    "informationUri": "https://github.com/cognis-digital/sbomb",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
