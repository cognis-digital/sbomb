# Ports of sbomb

The same firmware-rootfs scan surface, ported across languages so you can drop
sbomb into any stack or ship a single static binary. Every port:

- walks an **unpacked firmware rootfs**,
- discovers components from the real package databases embedded Linux images
  leave behind — **dpkg / opkg / apk / os-release / busybox / python / npm**,
- matches them against an **embedded offline vuln DB of real CVEs**
  (OpenSSL CVE-2021-3711, Log4Shell CVE-2021-44228, zlib CVE-2018-25032, …)
  with the same epoch/revision-stripping version-range logic as the reference,
- emits a **CycloneDX 1.5** JSON document, and
- **exits 1 when vulnerabilities are found** (CI gate), 2 on a bad path.

All ports share the rule IDs (CVE ids), the component shape, and the CycloneDX
output shape, so they are drop-in interchangeable with the Python reference.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../sbomb/` | `sbomb scan ./rootfs` | `pytest` (from repo root) |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js ./rootfs` | `node --test ports/javascript/test.mjs` |
| Go | `go/` | `cd ports/go && go run . ../../demos/01-basic/rootfs` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- ../../demos/01-basic/rootfs` | `cd ports/rust && cargo test` |

## Verify them

Each port is exercised by its own test suite against the repo's real demo
rootfs fixtures (`../demos/`), and all three non-Python ports are built + tested
on every push by the [`ports.yml`](../.github/workflows/ports.yml) GitHub
Actions workflow — so the ports are real and verifiable, not vaporware.

```bash
# run every port locally (skips any toolchain you don't have installed)
bash ../scripts/ports-test.sh
```

Worked example — the Node port against the Log4Shell demo:

```bash
$ node ports/javascript/index.js demos/05-node-gateway/rootfs | head -4
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
$ echo $?
1   # vulnerable -> non-zero exit (CI gate)
```

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md. Keep the component + CycloneDX shape and the exit-code
contract identical, and add a smoke test against `../demos/`.
