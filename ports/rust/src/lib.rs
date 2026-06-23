//! Rust port of the sbomb core scan surface — fast, single binary, std-only.
//!
//! Mirrors the Python reference: walk an unpacked firmware rootfs, discover
//! components from the package databases embedded Linux images leave behind
//! (dpkg / opkg / apk / os-release / busybox / python / npm), match them
//! against a small embedded offline vuln DB with real CVEs, and emit a
//! CycloneDX-shaped JSON document. No external crates.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Vuln {
    pub id: String,
    pub severity: String,
    pub affected: String,
}

#[derive(Clone, Debug)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ctype: String,
    pub source: String,
    pub purl: String,
    pub evidence: String,
    pub vulns: Vec<Vuln>,
}

impl Component {
    pub fn bom_ref(&self) -> String {
        if !self.purl.is_empty() {
            self.purl.clone()
        } else {
            format!("{}@{}", self.name, self.version)
        }
    }
}

// embedded offline vuln DB (real CVEs, upstream version ranges)
const VULN_DB: &[(&str, &str, &str, &str)] = &[
    ("openssl", "<1.1.1l", "CVE-2021-3711", "critical"),
    ("openssl", ">=3.0.0,<3.0.7", "CVE-2022-3602", "high"),
    ("busybox", "<1.34.0", "CVE-2021-42374", "medium"),
    ("zlib", "<1.2.12", "CVE-2018-25032", "high"),
    ("dropbear", "<2020.79", "CVE-2020-36254", "medium"),
    ("libcurl", "<7.84.0", "CVE-2022-32207", "critical"),
    ("curl", "<7.84.0", "CVE-2022-32207", "critical"),
    ("log4j-core", ">=2.0,<2.17.1", "CVE-2021-44228", "critical"),
    ("glibc", "<2.35", "CVE-2021-3999", "high"),
];

// --------------------------------------------------------------------------
// Version comparison
// --------------------------------------------------------------------------
enum Tok {
    Num(u64),
    Alpha(String),
}

fn kind(t: &Tok) -> u8 {
    match t {
        Tok::Num(_) => 0,
        Tok::Alpha(_) => 1,
    }
}

fn cmp_tok(a: &Tok, b: &Tok) -> std::cmp::Ordering {
    let (ka, kb) = (kind(a), kind(b));
    if ka != kb {
        return ka.cmp(&kb);
    }
    match (a, b) {
        (Tok::Num(x), Tok::Num(y)) => x.cmp(y),
        (Tok::Alpha(x), Tok::Alpha(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    }
}

fn normalize(v: &str) -> String {
    let mut v = v.trim().to_string();
    if let Some(i) = v.find(':') {
        v = v[i + 1..].to_string();
    }
    if let Some(i) = v.find('-') {
        v = v[..i].to_string();
    }
    v.trim().to_string()
}

fn split_version(v: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    for part in normalize(v).split(|c| c == '.' || c == '_') {
        if part.is_empty() {
            continue;
        }
        // split a trailing alpha suffix off a numeric prefix: "1l" -> 1, "l"
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        let rest: String = part.chars().skip(digits.len()).collect();
        if !digits.is_empty() {
            out.push(Tok::Num(digits.parse().unwrap_or(0)));
            if !rest.is_empty() {
                out.push(Tok::Alpha(rest));
            }
        } else {
            out.push(Tok::Alpha(part.to_string()));
        }
    }
    out
}

pub fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let ta = split_version(a);
    let tb = split_version(b);
    let n = ta.len().min(tb.len());
    for i in 0..n {
        let c = cmp_tok(&ta[i], &tb[i]);
        if c != std::cmp::Ordering::Equal {
            return c;
        }
    }
    ta.len().cmp(&tb.len())
}

pub fn satisfies(version: &str, constraint: &str) -> bool {
    use std::cmp::Ordering::*;
    if version.is_empty() {
        return false;
    }
    let constraint = constraint.trim();
    if constraint.is_empty() || constraint == "*" {
        return true;
    }
    for clause in constraint.split(',') {
        let clause = clause.trim();
        let (op, target) = if let Some(r) = clause.strip_prefix("<=") {
            ("<=", r)
        } else if let Some(r) = clause.strip_prefix(">=") {
            (">=", r)
        } else if let Some(r) = clause.strip_prefix("==") {
            ("==", r)
        } else if let Some(r) = clause.strip_prefix('<') {
            ("<", r)
        } else if let Some(r) = clause.strip_prefix('>') {
            (">", r)
        } else if let Some(r) = clause.strip_prefix('=') {
            ("=", r)
        } else {
            ("=", clause)
        };
        let c = version_compare(version, target.trim());
        let ok = match op {
            "<" => c == Less,
            "<=" => c != Greater,
            ">" => c == Greater,
            ">=" => c != Less,
            "=" | "==" => c == Equal,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
fn read(p: &Path) -> String {
    fs::read_to_string(p)
        .unwrap_or_default()
        .replace("\r\n", "\n")
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn purl(t: &str, n: &str, v: &str) -> String {
    if v.is_empty() {
        format!("pkg:{t}/{n}")
    } else {
        format!("pkg:{t}/{n}@{v}")
    }
}

fn comp(name: &str, version: &str, ctype: &str, source: &str, purl: String, evidence: String) -> Component {
    Component {
        name: name.to_string(),
        version: version.to_string(),
        ctype: ctype.to_string(),
        source: source.to_string(),
        purl,
        evidence,
        vulns: Vec::new(),
    }
}

// parse dpkg/opkg control-style "\n\n"-separated blocks
fn parse_control(text: &str) -> Vec<std::collections::HashMap<String, String>> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        let mut f = std::collections::HashMap::new();
        for line in block.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            if let Some(i) = line.find(':') {
                f.insert(line[..i].trim().to_string(), line[i + 1..].trim().to_string());
            }
        }
        out.push(f);
    }
    out
}

// --------------------------------------------------------------------------
// Detectors
// --------------------------------------------------------------------------
fn detect_dpkg(root: &Path) -> Vec<Component> {
    let p = root.join("var/lib/dpkg/status");
    if !p.is_file() {
        return vec![];
    }
    let mut out = vec![];
    for f in parse_control(&read(&p)) {
        let name = match f.get("Package") {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let status = f.get("Status").map(|s| s.as_str()).unwrap_or("installed");
        if !status.to_lowercase().contains("installed") {
            continue;
        }
        let v = f.get("Version").cloned().unwrap_or_default();
        out.push(comp(name, &v, "library", "dpkg", purl("deb", name, &v), rel(root, &p)));
    }
    out
}

fn detect_opkg(root: &Path) -> Vec<Component> {
    for p in [root.join("usr/lib/opkg/status"), root.join("var/lib/opkg/status")] {
        if !p.is_file() {
            continue;
        }
        let mut out = vec![];
        for f in parse_control(&read(&p)) {
            let name = match f.get("Package") {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let v = f.get("Version").cloned().unwrap_or_default();
            out.push(comp(name, &v, "library", "opkg", purl("opkg", name, &v), rel(root, &p)));
        }
        return out;
    }
    vec![]
}

fn detect_apk(root: &Path) -> Vec<Component> {
    let p = root.join("lib/apk/db/installed");
    if !p.is_file() {
        return vec![];
    }
    let mut out = vec![];
    for block in read(&p).split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        let mut name = String::new();
        let mut v = String::new();
        for line in block.lines() {
            if let Some(r) = line.strip_prefix("P:") {
                name = r.trim().to_string();
            } else if let Some(r) = line.strip_prefix("V:") {
                v = r.trim().to_string();
            }
        }
        if !name.is_empty() {
            out.push(comp(&name, &v, "library", "apk", purl("apk", &name, &v), rel(root, &p)));
        }
    }
    out
}

fn detect_os_release(root: &Path) -> Vec<Component> {
    for p in [root.join("etc/os-release"), root.join("usr/lib/os-release")] {
        if !p.is_file() {
            continue;
        }
        let mut d = std::collections::HashMap::new();
        for line in read(&p).lines() {
            if line.trim().starts_with('#') {
                continue;
            }
            if let Some(i) = line.find('=') {
                d.insert(
                    line[..i].trim().to_string(),
                    line[i + 1..].trim().trim_matches('"').to_string(),
                );
            }
        }
        let name = d
            .get("ID")
            .or_else(|| d.get("NAME"))
            .cloned()
            .unwrap_or_else(|| "linux".to_string());
        let v = d.get("VERSION_ID").cloned().unwrap_or_default();
        return vec![comp(&name, &v, "operating-system", "os-release", purl("generic", &name, &v), rel(root, &p))];
    }
    vec![]
}

fn detect_busybox(root: &Path) -> Vec<Component> {
    for p in [
        root.join("bin/busybox"),
        root.join("usr/bin/busybox"),
        root.join("sbin/busybox"),
    ] {
        if !p.is_file() {
            continue;
        }
        let blob = fs::read(&p).unwrap_or_default();
        let text = String::from_utf8_lossy(&blob);
        let mut v = String::new();
        if let Some(idx) = text.find("BusyBox v") {
            let tail: String = text[idx + 9..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            v = tail;
        }
        return vec![comp("busybox", &v, "application", "binary", purl("generic", "busybox", &v), rel(root, &p))];
    }
    vec![]
}

fn walk_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.push(p.clone());
                walk_dirs(&p, out);
            }
        }
    }
}

fn detect_python(root: &Path) -> Vec<Component> {
    let mut dirs = Vec::new();
    walk_dirs(root, &mut dirs);
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for d in dirs {
        let base = d.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !base.ends_with(".dist-info") && !base.ends_with(".egg-info") {
            continue;
        }
        let mut meta = d.join("METADATA");
        if !meta.is_file() {
            meta = d.join("PKG-INFO");
        }
        if !meta.is_file() {
            continue;
        }
        let mut name = String::new();
        let mut v = String::new();
        for line in read(&meta).lines() {
            if let Some(r) = line.strip_prefix("Name:") {
                name = r.trim().to_string();
            } else if let Some(r) = line.strip_prefix("Version:") {
                v = r.trim().to_string();
            }
            if !name.is_empty() && !v.is_empty() {
                break;
            }
        }
        let key = format!("{}@{}", name.to_lowercase(), v);
        if !name.is_empty() && seen.insert(key) {
            out.push(comp(&name, &v, "library", "python", purl("pypi", &name.to_lowercase(), &v), rel(root, &d)));
        }
    }
    out
}

fn json_get<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    // minimal: find "key"\s*:\s*"value"
    let needle = format!("\"{key}\"");
    let i = text.find(&needle)?;
    let after = &text[i + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn detect_node(root: &Path) -> Vec<Component> {
    let mut dirs = Vec::new();
    walk_dirs(root, &mut dirs);
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for d in dirs {
        if d.file_name().and_then(|s| s.to_str()) != Some("node_modules") {
            continue;
        }
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let pj = e.path().join("package.json");
                if !pj.is_file() {
                    continue;
                }
                let text = read(&pj);
                let name = match json_get(&text, "name") {
                    Some(n) if !n.is_empty() => n.to_string(),
                    _ => continue,
                };
                let v = json_get(&text, "version").unwrap_or("").to_string();
                let key = format!("{name}@{v}");
                if seen.insert(key) {
                    out.push(comp(&name, &v, "library", "npm", purl("npm", &name, &v), rel(root, &pj)));
                }
            }
        }
    }
    out
}

pub fn scan_rootfs(root: &Path) -> std::io::Result<Vec<Component>> {
    if !root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("rootfs is not a directory: {}", root.display()),
        ));
    }
    let mut found = vec![];
    for det in [
        detect_os_release,
        detect_dpkg,
        detect_opkg,
        detect_apk,
        detect_busybox,
        detect_python,
        detect_node,
    ] {
        found.extend(det(root));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<Component> = vec![];
    for c in found {
        let k = format!("{}|{}|{}", c.name.to_lowercase(), c.version, c.source);
        if seen.insert(k) {
            out.push(c);
        }
    }
    out.sort_by(|a, b| {
        let oa = a.ctype != "operating-system";
        let ob = b.ctype != "operating-system";
        oa.cmp(&ob)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then(a.version.cmp(&b.version))
    });
    Ok(out)
}

pub fn match_vulns(components: &mut [Component]) -> usize {
    let mut total = 0;
    for c in components.iter_mut() {
        let lname = c.name.to_lowercase();
        for (name, rng, id, sev) in VULN_DB {
            if *name == lname && !c.version.is_empty() && satisfies(&c.version, rng) {
                c.vulns.push(Vuln {
                    id: id.to_string(),
                    severity: sev.to_string(),
                    affected: rng.to_string(),
                });
                total += 1;
            }
        }
    }
    total
}

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Emit a CycloneDX 1.5 JSON document (hand-rolled, std-only).
pub fn build_cyclonedx(components: &[Component]) -> String {
    let mut comps = Vec::new();
    let mut vulns = Vec::new();
    for c in components {
        let mut fields = vec![
            format!("{}:{}", jstr("type"), jstr(&c.ctype)),
            format!("{}:{}", jstr("bom-ref"), jstr(&c.bom_ref())),
            format!("{}:{}", jstr("name"), jstr(&c.name)),
        ];
        if !c.version.is_empty() {
            fields.push(format!("{}:{}", jstr("version"), jstr(&c.version)));
        }
        if !c.purl.is_empty() {
            fields.push(format!("{}:{}", jstr("purl"), jstr(&c.purl)));
        }
        comps.push(format!("{{{}}}", fields.join(",")));
        for v in &c.vulns {
            vulns.push(format!(
                "{{{}:{},{}:[{{{}:{}}}],{}:[{{{}:{}}}]}}",
                jstr("id"),
                jstr(&v.id),
                jstr("ratings"),
                jstr("severity"),
                jstr(&v.severity),
                jstr("affects"),
                jstr("ref"),
                jstr(&c.bom_ref())
            ));
        }
    }
    let mut doc = format!(
        "{{{}:{},{}:{},{}:1,{}:{{{}:[{{{}:{},{}:{},{}:{}}}]}},{}:[{}]",
        jstr("bomFormat"),
        jstr("CycloneDX"),
        jstr("specVersion"),
        jstr("1.5"),
        jstr("version"),
        jstr("metadata"),
        jstr("tools"),
        jstr("vendor"),
        jstr("sbomb"),
        jstr("name"),
        jstr("sbomb"),
        jstr("version"),
        jstr("port-rust"),
        jstr("components"),
        comps.join(",")
    );
    if !vulns.is_empty() {
        doc.push_str(&format!(",{}:[{}]", jstr("vulnerabilities"), vulns.join(",")));
    }
    doc.push('}');
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;
    use std::path::PathBuf;

    fn demo(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../demos")
            .join(name)
            .join("rootfs")
    }

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.1.1k", "1.1.1l"), Less);
        assert_eq!(version_compare("1.1.1l", "1.1.1k"), Greater);
        assert_eq!(version_compare("1.2.11", "1.2.12"), Less);
        assert_eq!(version_compare("3.0.7", "3.0.0"), Greater);
        assert_eq!(version_compare("2.31.0", "2.31.0"), Equal);
        assert_eq!(version_compare("1:1.2.3-1ubuntu2", "1.2.3"), Equal);
    }

    #[test]
    fn test_satisfies() {
        assert!(satisfies("1.1.1k", "<1.1.1l"));
        assert!(!satisfies("1.1.1l", "<1.1.1l"));
        assert!(satisfies("3.0.5", ">=3.0.0,<3.0.7"));
        assert!(!satisfies("3.0.7", ">=3.0.0,<3.0.7"));
    }

    #[test]
    fn test_scan_finds_components() {
        let comps = scan_rootfs(&demo("01-basic")).unwrap();
        let names: std::collections::HashSet<_> =
            comps.iter().map(|c| c.name.to_lowercase()).collect();
        for n in ["openssl", "zlib", "dropbear", "libcurl", "musl", "openwrt"] {
            assert!(names.contains(n), "missing {n}");
        }
        assert_eq!(comps[0].ctype, "operating-system");
    }

    #[test]
    fn test_match_vulns() {
        let mut comps = scan_rootfs(&demo("01-basic")).unwrap();
        let total = match_vulns(&mut comps);
        assert!(total >= 2, "expected >=2 got {total}");
        let by: std::collections::HashMap<_, _> =
            comps.iter().map(|c| (c.name.to_lowercase(), c)).collect();
        assert!(by["openssl"].vulns.iter().any(|v| v.id == "CVE-2021-3711"));
        assert!(by["zlib"].vulns.iter().any(|v| v.id == "CVE-2018-25032"));
        assert!(by["dropbear"].vulns.is_empty());
        assert!(by["libcurl"].vulns.is_empty());
    }

    #[test]
    fn test_node_gateway_log4shell() {
        let mut comps = scan_rootfs(&demo("05-node-gateway")).unwrap();
        match_vulns(&mut comps);
        let log4j = comps.iter().find(|c| c.name.to_lowercase() == "log4j-core");
        assert!(log4j.is_some(), "log4j-core not detected");
        assert!(log4j.unwrap().vulns.iter().any(|v| v.id == "CVE-2021-44228"));
    }

    #[test]
    fn test_clean_device() {
        let mut comps = scan_rootfs(&demo("06-clean-device")).unwrap();
        assert_eq!(match_vulns(&mut comps), 0);
    }

    #[test]
    fn test_build_cyclonedx() {
        let mut comps = scan_rootfs(&demo("02-debian-router")).unwrap();
        match_vulns(&mut comps);
        let doc = build_cyclonedx(&comps);
        assert!(doc.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(doc.contains("\"specVersion\":\"1.5\""));
        assert!(doc.contains("CVE-2021-3711"));
    }
}
