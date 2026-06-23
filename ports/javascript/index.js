#!/usr/bin/env node
// JavaScript / Node port of the sbomb core scan surface.
//
// Mirrors the Python reference: walk an unpacked firmware rootfs, discover
// components from the package databases embedded Linux images leave behind
// (dpkg / opkg / apk / os-release / busybox / npm), match them against a small
// embedded offline vuln DB with real CVEs, and emit a CycloneDX-shaped JSON
// document. Exit 1 when vulnerabilities are found (CI gate). Stdlib only.
import { readdirSync, statSync, readFileSync, existsSync } from "fs";
import { join, relative, sep } from "path";

// --- embedded offline vuln DB (real CVEs, upstream version ranges) ----------
const VULN_DB = [
  { name: "openssl", range: "<1.1.1l", id: "CVE-2021-3711", severity: "critical" },
  { name: "openssl", range: ">=3.0.0,<3.0.7", id: "CVE-2022-3602", severity: "high" },
  { name: "busybox", range: "<1.34.0", id: "CVE-2021-42374", severity: "medium" },
  { name: "zlib", range: "<1.2.12", id: "CVE-2018-25032", severity: "high" },
  { name: "dropbear", range: "<2020.79", id: "CVE-2020-36254", severity: "medium" },
  { name: "libcurl", range: "<7.84.0", id: "CVE-2022-32207", severity: "critical" },
  { name: "curl", range: "<7.84.0", id: "CVE-2022-32207", severity: "critical" },
  { name: "log4j-core", range: ">=2.0,<2.17.1", id: "CVE-2021-44228", severity: "critical" },
  { name: "glibc", range: "<2.35", id: "CVE-2021-3999", severity: "high" },
];

// --- version comparison (epoch/revision-stripped, alpha-suffix aware) --------
function normalize(v) {
  v = (v || "").trim();
  if (v.includes(":")) v = v.split(":").slice(1).join(":");
  if (v.includes("-")) v = v.split("-")[0];
  return v.trim();
}
function tokens(v) {
  const out = [];
  for (const part of normalize(v).split(/[._]/)) {
    const m = /^(\d+)([A-Za-z]*)$/.exec(part);
    if (m) {
      out.push([0, parseInt(m[1], 10)]);
      if (m[2]) out.push([1, m[2]]);
    } else if (/^\d+$/.test(part)) {
      out.push([0, parseInt(part, 10)]);
    } else if (part) {
      out.push([1, part]);
    }
  }
  return out;
}
function cmpTok(x, y) {
  if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
  if (x[1] === y[1]) return 0;
  return x[1] < y[1] ? -1 : 1;
}
export function versionCompare(a, b) {
  const ta = tokens(a), tb = tokens(b);
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const c = cmpTok(ta[i], tb[i]);
    if (c !== 0) return c;
  }
  if (ta.length === tb.length) return 0;
  return ta.length < tb.length ? -1 : 1;
}
export function satisfies(version, constraint) {
  if (!version) return false;
  constraint = (constraint || "").trim();
  if (constraint === "" || constraint === "*") return true;
  for (let clause of constraint.split(",")) {
    clause = clause.trim();
    const m = /^(<=|>=|==|=|<|>)\s*(.+)$/.exec(clause);
    if (!m) {
      if (versionCompare(version, clause) !== 0) return false;
      continue;
    }
    const c = versionCompare(version, m[2].trim());
    const ok = { "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c === 0, "==": c === 0 }[m[1]];
    if (!ok) return false;
  }
  return true;
}

// --- helpers ----------------------------------------------------------------
function read(p) {
  try { return readFileSync(p, "utf8").replace(/\r\n/g, "\n"); } catch { return ""; }
}
function rel(root, p) { return relative(root, p).split(sep).join("/"); }
function purl(t, n, v) { return v ? `pkg:${t}/${n}@${v}` : `pkg:${t}/${n}`; }

// --- detectors --------------------------------------------------------------
function parseControl(text) {
  // parse dpkg/opkg control-style "\n\n"-separated blocks
  return text.split("\n\n").filter((b) => b.trim()).map((block) => {
    const f = {};
    for (const line of block.split("\n")) {
      if (line[0] === " " || line[0] === "\t") continue;
      const i = line.indexOf(":");
      if (i > 0) f[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return f;
  });
}
function detectDpkg(root) {
  const p = join(root, "var", "lib", "dpkg", "status");
  if (!existsSync(p)) return [];
  return parseControl(read(p)).filter((f) => f.Package &&
    (f.Status || "installed").toLowerCase().includes("installed"))
    .map((f) => ({ name: f.Package, version: f.Version || "", type: "library",
      source: "dpkg", purl: purl("deb", f.Package, f.Version || ""), evidence: rel(root, p) }));
}
function detectOpkg(root) {
  for (const p of [join(root, "usr", "lib", "opkg", "status"), join(root, "var", "lib", "opkg", "status")]) {
    if (!existsSync(p)) continue;
    return parseControl(read(p)).filter((f) => f.Package).map((f) => ({
      name: f.Package, version: f.Version || "", type: "library", source: "opkg",
      purl: purl("opkg", f.Package, f.Version || ""), evidence: rel(root, p) }));
  }
  return [];
}
function detectApk(root) {
  const p = join(root, "lib", "apk", "db", "installed");
  if (!existsSync(p)) return [];
  const out = [];
  for (const block of read(p).split("\n\n")) {
    if (!block.trim()) continue;
    let name = null, ver = "";
    for (const line of block.split("\n")) {
      if (line.startsWith("P:")) name = line.slice(2).trim();
      else if (line.startsWith("V:")) ver = line.slice(2).trim();
    }
    if (name) out.push({ name, version: ver, type: "library", source: "apk",
      purl: purl("apk", name, ver), evidence: rel(root, p) });
  }
  return out;
}
function detectOsRelease(root) {
  for (const p of [join(root, "etc", "os-release"), join(root, "usr", "lib", "os-release")]) {
    if (!existsSync(p)) continue;
    const d = {};
    for (const line of read(p).split("\n")) {
      const i = line.indexOf("=");
      if (i > 0 && !line.trim().startsWith("#")) d[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^"|"$/g, "");
    }
    const name = d.ID || d.NAME || "linux";
    return [{ name, version: d.VERSION_ID || "", type: "operating-system",
      source: "os-release", purl: purl("generic", name, d.VERSION_ID || ""), evidence: rel(root, p) }];
  }
  return [];
}
function detectBusybox(root) {
  for (const p of [join(root, "bin", "busybox"), join(root, "usr", "bin", "busybox"), join(root, "sbin", "busybox")]) {
    if (!existsSync(p)) continue;
    let blob;
    try { blob = readFileSync(p); } catch { continue; }
    const m = /BusyBox v(\d+\.\d+\.\d+)/.exec(blob.toString("latin1"));
    const ver = m ? m[1] : "";
    return [{ name: "busybox", version: ver, type: "application", source: "binary",
      purl: purl("generic", "busybox", ver), evidence: rel(root, p) }];
  }
  return [];
}
function detectNode(root) {
  const out = [], seen = new Set();
  (function walk(dir) {
    let entries;
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      const fp = join(dir, e);
      let st;
      try { st = statSync(fp); } catch { continue; }
      if (!st.isDirectory()) continue;
      if (e === "node_modules") {
        for (const mod of readdirSync(fp)) {
          const pj = join(fp, mod, "package.json");
          if (!existsSync(pj)) continue;
          let data;
          try { data = JSON.parse(read(pj)); } catch { continue; }
          if (!data.name) continue;
          const key = `${data.name}@${data.version || ""}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push({ name: data.name, version: data.version || "", type: "library",
            source: "npm", purl: purl("npm", data.name, data.version || ""), evidence: rel(root, pj) });
          walk(join(fp, mod));
        }
      } else {
        walk(fp);
      }
    }
  })(root);
  return out;
}

function detectPython(root) {
  const out = [], seen = new Set();
  (function walk(dir) {
    let entries;
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      const fp = join(dir, e);
      let st;
      try { st = statSync(fp); } catch { continue; }
      if (!st.isDirectory()) continue;
      if (e.endsWith(".dist-info") || e.endsWith(".egg-info")) {
        let meta = join(fp, "METADATA");
        if (!existsSync(meta)) meta = join(fp, "PKG-INFO");
        if (!existsSync(meta)) continue;
        let name = "", ver = "";
        for (const line of read(meta).split("\n")) {
          if (line.startsWith("Name:")) name = line.slice(5).trim();
          else if (line.startsWith("Version:")) ver = line.slice(8).trim();
          if (name && ver) break;
        }
        const key = `${name.toLowerCase()}@${ver}`;
        if (name && !seen.has(key)) {
          seen.add(key);
          out.push({ name, version: ver, type: "library", source: "python",
            purl: purl("pypi", name.toLowerCase(), ver), evidence: rel(root, fp) });
        }
      } else {
        walk(fp);
      }
    }
  })(root);
  return out;
}

const DETECTORS = [detectOsRelease, detectDpkg, detectOpkg, detectApk, detectBusybox, detectPython, detectNode];

export function scanRootfs(root) {
  if (!existsSync(root) || !statSync(root).isDirectory())
    throw new Error(`rootfs is not a directory: ${root}`);
  const found = [];
  for (const d of DETECTORS) { try { found.push(...d(root)); } catch { /* skip */ } }
  const seen = new Set(), out = [];
  for (const c of found) {
    const k = `${c.name.toLowerCase()}|${c.version}|${c.source}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(c);
  }
  out.sort((a, b) => (a.type !== "operating-system") - (b.type !== "operating-system") ||
    a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || a.version.localeCompare(b.version));
  return out;
}

export function matchVulns(components) {
  const byName = {};
  for (const e of VULN_DB) (byName[e.name.toLowerCase()] ||= []).push(e);
  let total = 0;
  for (const c of components) {
    c.vulnerabilities = [];
    for (const e of byName[c.name.toLowerCase()] || []) {
      if (c.version && satisfies(c.version, e.range)) {
        c.vulnerabilities.push({ id: e.id, severity: e.severity, affected_versions: e.range });
        total++;
      }
    }
  }
  return total;
}

export function buildCycloneDX(components) {
  const comps = [], vulns = [];
  for (const c of components) {
    const o = { type: c.type, "bom-ref": c.purl || `${c.name}@${c.version}`, name: c.name };
    if (c.version) o.version = c.version;
    if (c.purl) o.purl = c.purl;
    comps.push(o);
    for (const v of c.vulnerabilities || [])
      vulns.push({ id: v.id, ratings: [{ severity: v.severity }], affects: [{ ref: o["bom-ref"] }] });
  }
  const doc = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
    metadata: { tools: [{ vendor: "sbomb", name: "sbomb", version: "port-js" }] }, components: comps };
  if (vulns.length) doc.vulnerabilities = vulns;
  return doc;
}

export function scan(target) {
  const comps = scanRootfs(target);
  const total = matchVulns(comps);
  return { tool: "sbomb", components: comps, vulnerabilities: total, sbom: buildCycloneDX(comps) };
}

import { fileURLToPath } from "url";
import { resolve } from "path";
const _isMain = process.argv[1] &&
  resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);
if (_isMain) {
  const target = process.argv[2] || ".";
  try {
    const r = scan(target);
    console.log(JSON.stringify(r.sbom, null, 2));
    process.exit(r.vulnerabilities > 0 ? 1 : 0);
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }
}
