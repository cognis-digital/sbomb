// Go port of the sbomb core scan surface — single binary, zero deps.
//
// Mirrors the Python reference: walk an unpacked firmware rootfs, discover
// components from the package databases embedded Linux images leave behind
// (dpkg / opkg / apk / os-release / busybox / python / npm), match them
// against a small embedded offline vuln DB with real CVEs, and emit a
// CycloneDX-shaped JSON document. Standard library only.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------
type Vuln struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	AffectedVersions string `json:"affected_versions"`
}

type Component struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Purl     string `json:"purl"`
	Evidence string `json:"evidence"`
	Vulns    []Vuln `json:"vulnerabilities"`
}

func (c Component) BomRef() string {
	if c.Purl != "" {
		return c.Purl
	}
	return c.Name + "@" + c.Version
}

// embedded offline vuln DB (real CVEs, upstream version ranges)
type vulnEntry struct{ name, rng, id, sev string }

var vulnDB = []vulnEntry{
	{"openssl", "<1.1.1l", "CVE-2021-3711", "critical"},
	{"openssl", ">=3.0.0,<3.0.7", "CVE-2022-3602", "high"},
	{"busybox", "<1.34.0", "CVE-2021-42374", "medium"},
	{"zlib", "<1.2.12", "CVE-2018-25032", "high"},
	{"dropbear", "<2020.79", "CVE-2020-36254", "medium"},
	{"libcurl", "<7.84.0", "CVE-2022-32207", "critical"},
	{"curl", "<7.84.0", "CVE-2022-32207", "critical"},
	{"log4j-core", ">=2.0,<2.17.1", "CVE-2021-44228", "critical"},
	{"glibc", "<2.35", "CVE-2021-3999", "high"},
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------
type tok struct {
	kind int // 0 numeric, 1 alpha
	n    int
	s    string
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

var partRe = regexp.MustCompile(`^(\d+)([A-Za-z]*)$`)

func splitVersion(v string) []tok {
	var out []tok
	for _, part := range regexp.MustCompile(`[._]`).Split(normalizeVersion(v), -1) {
		if m := partRe.FindStringSubmatch(part); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, tok{0, n, ""})
			if m[2] != "" {
				out = append(out, tok{1, 0, m[2]})
			}
		} else if part != "" {
			if n, err := strconv.Atoi(part); err == nil {
				out = append(out, tok{0, n, ""})
			} else {
				out = append(out, tok{1, 0, part})
			}
		}
	}
	return out
}

func cmpTok(a, b tok) int {
	if a.kind != b.kind {
		if a.kind < b.kind {
			return -1
		}
		return 1
	}
	if a.kind == 0 {
		switch {
		case a.n < b.n:
			return -1
		case a.n > b.n:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a.s, b.s)
}

func VersionCompare(a, b string) int {
	ta, tb := splitVersion(a), splitVersion(b)
	n := len(ta)
	if len(tb) < n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		if c := cmpTok(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ta) < len(tb):
		return -1
	case len(ta) > len(tb):
		return 1
	default:
		return 0
	}
}

var clauseRe = regexp.MustCompile(`^(<=|>=|==|=|<|>)\s*(.+)$`)

func Satisfies(version, constraint string) bool {
	if version == "" {
		return false
	}
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}
	for _, clause := range strings.Split(constraint, ",") {
		clause = strings.TrimSpace(clause)
		m := clauseRe.FindStringSubmatch(clause)
		if m == nil {
			if VersionCompare(version, clause) != 0 {
				return false
			}
			continue
		}
		c := VersionCompare(version, strings.TrimSpace(m[2]))
		ok := false
		switch m[1] {
		case "<":
			ok = c < 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case ">=":
			ok = c >= 0
		case "=", "==":
			ok = c == 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------
func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func rel(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

func purl(t, n, v string) string {
	if v != "" {
		return "pkg:" + t + "/" + n + "@" + v
	}
	return "pkg:" + t + "/" + n
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// parse dpkg/opkg control-style "\n\n"-separated blocks
func parseControl(text string) []map[string]string {
	var out []map[string]string
	for _, block := range strings.Split(text, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		f := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue
			}
			if i := strings.Index(line, ":"); i > 0 {
				f[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
			}
		}
		out = append(out, f)
	}
	return out
}

func detectDpkg(root string) []Component {
	p := filepath.Join(root, "var", "lib", "dpkg", "status")
	if !exists(p) {
		return nil
	}
	var out []Component
	for _, f := range parseControl(readFile(p)) {
		name := f["Package"]
		if name == "" {
			continue
		}
		status := f["Status"]
		if status == "" {
			status = "installed"
		}
		if !strings.Contains(strings.ToLower(status), "installed") {
			continue
		}
		v := f["Version"]
		out = append(out, Component{name, v, "library", "dpkg", purl("deb", name, v), rel(root, p), nil})
	}
	return out
}

func detectOpkg(root string) []Component {
	for _, p := range []string{
		filepath.Join(root, "usr", "lib", "opkg", "status"),
		filepath.Join(root, "var", "lib", "opkg", "status"),
	} {
		if !exists(p) {
			continue
		}
		var out []Component
		for _, f := range parseControl(readFile(p)) {
			name := f["Package"]
			if name == "" {
				continue
			}
			v := f["Version"]
			out = append(out, Component{name, v, "library", "opkg", purl("opkg", name, v), rel(root, p), nil})
		}
		return out
	}
	return nil
}

func detectApk(root string) []Component {
	p := filepath.Join(root, "lib", "apk", "db", "installed")
	if !exists(p) {
		return nil
	}
	var out []Component
	for _, block := range strings.Split(readFile(p), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var name, v string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "P:") {
				name = strings.TrimSpace(line[2:])
			} else if strings.HasPrefix(line, "V:") {
				v = strings.TrimSpace(line[2:])
			}
		}
		if name != "" {
			out = append(out, Component{name, v, "library", "apk", purl("apk", name, v), rel(root, p), nil})
		}
	}
	return out
}

func detectOsRelease(root string) []Component {
	for _, p := range []string{
		filepath.Join(root, "etc", "os-release"),
		filepath.Join(root, "usr", "lib", "os-release"),
	} {
		if !exists(p) {
			continue
		}
		d := map[string]string{}
		for _, line := range strings.Split(readFile(p), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if i := strings.Index(line, "="); i > 0 {
				d[strings.TrimSpace(line[:i])] = strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
			}
		}
		name := d["ID"]
		if name == "" {
			name = d["NAME"]
		}
		if name == "" {
			name = "linux"
		}
		v := d["VERSION_ID"]
		return []Component{{name, v, "operating-system", "os-release", purl("generic", name, v), rel(root, p), nil}}
	}
	return nil
}

var busyboxRe = regexp.MustCompile(`BusyBox v(\d+\.\d+\.\d+)`)

func detectBusybox(root string) []Component {
	for _, p := range []string{
		filepath.Join(root, "bin", "busybox"),
		filepath.Join(root, "usr", "bin", "busybox"),
		filepath.Join(root, "sbin", "busybox"),
	} {
		if !exists(p) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v := ""
		if m := busyboxRe.FindSubmatch(b); m != nil {
			v = string(m[1])
		}
		return []Component{{"busybox", v, "application", "binary", purl("generic", "busybox", v), rel(root, p), nil}}
	}
	return nil
}

func detectPython(root string) []Component {
	var out []Component
	seen := map[string]bool{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		if !strings.HasSuffix(base, ".dist-info") && !strings.HasSuffix(base, ".egg-info") {
			return nil
		}
		meta := filepath.Join(p, "METADATA")
		if !exists(meta) {
			meta = filepath.Join(p, "PKG-INFO")
		}
		if !exists(meta) {
			return nil
		}
		var name, v string
		for _, line := range strings.Split(readFile(meta), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(line[5:])
			} else if strings.HasPrefix(line, "Version:") {
				v = strings.TrimSpace(line[8:])
			}
			if name != "" && v != "" {
				break
			}
		}
		key := strings.ToLower(name) + "@" + v
		if name != "" && !seen[key] {
			seen[key] = true
			out = append(out, Component{name, v, "library", "python", purl("pypi", strings.ToLower(name), v), rel(root, p), nil})
		}
		return nil
	})
	return out
}

func detectNode(root string) []Component {
	var out []Component
	seen := map[string]bool{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || filepath.Base(p) != "node_modules" {
			return nil
		}
		entries, _ := os.ReadDir(p)
		for _, e := range entries {
			pj := filepath.Join(p, e.Name(), "package.json")
			if !exists(pj) {
				continue
			}
			var data map[string]any
			if json.Unmarshal([]byte(readFile(pj)), &data) != nil {
				continue
			}
			name, _ := data["name"].(string)
			if name == "" {
				continue
			}
			v, _ := data["version"].(string)
			key := name + "@" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Component{name, v, "library", "npm", purl("npm", name, v), rel(root, pj), nil})
		}
		return nil
	})
	return out
}

var detectors = []func(string) []Component{
	detectOsRelease, detectDpkg, detectOpkg, detectApk, detectBusybox, detectPython, detectNode,
}

func ScanRootfs(root string) ([]Component, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, &os.PathError{Op: "scan", Path: root, Err: os.ErrInvalid}
	}
	var found []Component
	for _, d := range detectors {
		found = append(found, d(root)...)
	}
	seen := map[string]bool{}
	var out []Component
	for _, c := range found {
		k := strings.ToLower(c.Name) + "|" + c.Version + "|" + c.Source
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi := out[i].Type != "operating-system"
		oj := out[j].Type != "operating-system"
		if oi != oj {
			return !oi
		}
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

func MatchVulns(components []Component) int {
	byName := map[string][]vulnEntry{}
	for _, e := range vulnDB {
		byName[e.name] = append(byName[e.name], e)
	}
	total := 0
	for i := range components {
		c := &components[i]
		for _, e := range byName[strings.ToLower(c.Name)] {
			if c.Version != "" && Satisfies(c.Version, e.rng) {
				c.Vulns = append(c.Vulns, Vuln{e.id, e.sev, e.rng})
				total++
			}
		}
	}
	return total
}

func BuildCycloneDX(components []Component) map[string]any {
	var comps []map[string]any
	var vulns []map[string]any
	for _, c := range components {
		o := map[string]any{"type": c.Type, "bom-ref": c.BomRef(), "name": c.Name}
		if c.Version != "" {
			o["version"] = c.Version
		}
		if c.Purl != "" {
			o["purl"] = c.Purl
		}
		comps = append(comps, o)
		for _, v := range c.Vulns {
			vulns = append(vulns, map[string]any{
				"id":      v.ID,
				"ratings": []map[string]any{{"severity": v.Severity}},
				"affects": []map[string]any{{"ref": c.BomRef()}},
			})
		}
	}
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"tools": []map[string]any{{"vendor": "sbomb", "name": "sbomb", "version": "port-go"}},
		},
		"components": comps,
	}
	if len(vulns) > 0 {
		doc["vulnerabilities"] = vulns
	}
	return doc
}
