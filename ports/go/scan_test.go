package main

import (
	"path/filepath"
	"testing"
)

var demos = filepath.Join("..", "..", "demos")

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.1k", "1.1.1l", -1},
		{"1.1.1l", "1.1.1k", 1},
		{"1.2.11", "1.2.12", -1},
		{"3.0.7", "3.0.0", 1},
		{"2.31.0", "2.31.0", 0},
		{"1:1.2.3-1ubuntu2", "1.2.3", 0}, // epoch + revision stripped
	}
	for _, c := range cases {
		if got := VersionCompare(c.a, c.b); got != c.want {
			t.Errorf("VersionCompare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	if !Satisfies("1.1.1k", "<1.1.1l") {
		t.Error("1.1.1k should satisfy <1.1.1l")
	}
	if Satisfies("1.1.1l", "<1.1.1l") {
		t.Error("1.1.1l must not satisfy <1.1.1l")
	}
	if !Satisfies("3.0.5", ">=3.0.0,<3.0.7") {
		t.Error("3.0.5 should satisfy the range")
	}
	if Satisfies("3.0.7", ">=3.0.0,<3.0.7") {
		t.Error("3.0.7 must not satisfy the range")
	}
}

func TestScanFindsComponents(t *testing.T) {
	comps, err := ScanRootfs(filepath.Join(demos, "01-basic", "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range comps {
		names[c.Name] = true
	}
	for _, n := range []string{"openssl", "zlib", "dropbear", "libcurl", "musl", "openwrt"} {
		if !names[n] {
			t.Errorf("expected component %q", n)
		}
	}
	if comps[0].Type != "operating-system" {
		t.Errorf("OS component should sort first, got %q", comps[0].Type)
	}
}

func TestMatchVulns(t *testing.T) {
	comps, _ := ScanRootfs(filepath.Join(demos, "01-basic", "rootfs"))
	total := MatchVulns(comps)
	if total < 2 {
		t.Fatalf("expected >=2 vulns, got %d", total)
	}
	by := map[string]Component{}
	for _, c := range comps {
		by[c.Name] = c
	}
	has := func(c Component, id string) bool {
		for _, v := range c.Vulns {
			if v.ID == id {
				return true
			}
		}
		return false
	}
	if !has(by["openssl"], "CVE-2021-3711") {
		t.Error("openssl should flag CVE-2021-3711")
	}
	if !has(by["zlib"], "CVE-2018-25032") {
		t.Error("zlib should flag CVE-2018-25032")
	}
	if len(by["dropbear"].Vulns) != 0 {
		t.Error("patched dropbear must not be flagged")
	}
	if len(by["libcurl"].Vulns) != 0 {
		t.Error("patched libcurl must not be flagged")
	}
}

func TestNodeGatewayLog4Shell(t *testing.T) {
	comps, _ := ScanRootfs(filepath.Join(demos, "05-node-gateway", "rootfs"))
	MatchVulns(comps)
	found := false
	for _, c := range comps {
		if c.Name == "log4j-core" {
			for _, v := range c.Vulns {
				if v.ID == "CVE-2021-44228" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("node-gateway demo should surface Log4Shell")
	}
}

func TestCleanDeviceNoFindings(t *testing.T) {
	comps, _ := ScanRootfs(filepath.Join(demos, "06-clean-device", "rootfs"))
	if total := MatchVulns(comps); total != 0 {
		t.Errorf("clean device should have 0 findings, got %d", total)
	}
}

func TestBuildCycloneDX(t *testing.T) {
	comps, _ := ScanRootfs(filepath.Join(demos, "02-debian-router", "rootfs"))
	MatchVulns(comps)
	doc := BuildCycloneDX(comps)
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Error("bad CycloneDX header")
	}
	if _, ok := doc["vulnerabilities"]; !ok {
		t.Error("router demo should carry vulnerabilities")
	}
}
