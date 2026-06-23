// Smoke test for the JS port. Runs against the repo's real demo rootfs
// fixtures and asserts the same findings the Python reference produces.
// Pure stdlib (node:assert / node:test). No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  versionCompare, satisfies, scanRootfs, matchVulns, buildCycloneDX, scan,
} from "./index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEMOS = join(HERE, "..", "..", "demos");

test("versionCompare strips epoch/revision and orders alpha suffix", () => {
  assert.ok(versionCompare("1.1.1k", "1.1.1l") < 0);
  assert.ok(versionCompare("1.1.1l", "1.1.1k") > 0);
  assert.ok(versionCompare("1.2.11", "1.2.12") < 0);
  assert.equal(versionCompare("2.31.0", "2.31.0"), 0);
  assert.equal(versionCompare("1:1.2.3-1ubuntu2", "1.2.3"), 0);
});

test("satisfies evaluates AND constraints", () => {
  assert.ok(satisfies("1.1.1k", "<1.1.1l"));
  assert.ok(!satisfies("1.1.1l", "<1.1.1l"));
  assert.ok(satisfies("3.0.5", ">=3.0.0,<3.0.7"));
  assert.ok(!satisfies("3.0.7", ">=3.0.0,<3.0.7"));
});

test("scanRootfs detects components in the 01-basic demo", () => {
  const comps = scanRootfs(join(DEMOS, "01-basic", "rootfs"));
  const names = new Set(comps.map((c) => c.name.toLowerCase()));
  for (const n of ["openssl", "zlib", "dropbear", "libcurl", "musl", "openwrt"])
    assert.ok(names.has(n), `missing ${n}`);
  assert.equal(comps[0].type, "operating-system"); // OS sorts first
});

test("matchVulns flags vulnerable, spares patched", () => {
  const comps = scanRootfs(join(DEMOS, "01-basic", "rootfs"));
  const total = matchVulns(comps);
  assert.ok(total >= 2);
  const by = Object.fromEntries(comps.map((c) => [c.name.toLowerCase(), c]));
  assert.ok(by.openssl.vulnerabilities.some((v) => v.id === "CVE-2021-3711"));
  assert.ok(by.zlib.vulnerabilities.some((v) => v.id === "CVE-2018-25032"));
  assert.equal(by.dropbear.vulnerabilities.length, 0); // patched
  assert.equal(by.libcurl.vulnerabilities.length, 0);  // patched
});

test("node-gateway demo surfaces Log4Shell in node_modules", () => {
  const r = scan(join(DEMOS, "05-node-gateway", "rootfs"));
  const log4j = r.components.find((c) => c.name.toLowerCase() === "log4j-core");
  assert.ok(log4j, "log4j-core not detected");
  assert.ok(log4j.vulnerabilities.some((v) => v.id === "CVE-2021-44228"));
  assert.ok(r.vulnerabilities >= 1);
});

test("clean device demo yields zero findings", () => {
  const r = scan(join(DEMOS, "06-clean-device", "rootfs"));
  assert.equal(r.vulnerabilities, 0);
});

test("buildCycloneDX emits a 1.5 document", () => {
  const comps = scanRootfs(join(DEMOS, "02-debian-router", "rootfs"));
  matchVulns(comps);
  const doc = buildCycloneDX(comps);
  assert.equal(doc.bomFormat, "CycloneDX");
  assert.equal(doc.specVersion, "1.5");
  assert.equal(doc.components.length, comps.length);
  assert.ok(doc.vulnerabilities.some((v) => v.id === "CVE-2021-3711"));
});
