<a name="top"></a>

<div align="center">



<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=SBOMB&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="SBOMB"/>



# SBOMB



### Generate a CycloneDX SBOM directly from an unpacked firmware root filesystem and flag components with known CVEs and EOL kernels.



<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Generate+a+CycloneDX+SBOM+directly+from+an+unpacked+firmware;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>



[![PyPI](https://img.shields.io/pypi/v/cognis-sbomb.svg?color=6b46c1)](https://pypi.org/project/cognis-sbomb/) [![CI](https://github.com/cognis-digital/sbomb/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/sbomb/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)



*IoT / OT / Embedded — firmware, buses, and device security.*



</div>



```bash

pip install cognis-sbomb

sbomb scan .            # → prioritized findings in seconds

```



## Contents



- [Why sbomb?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Bundled 262k vuln DB](#bundled-db) · [Data feeds](#data-feeds) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Ports](#ports) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)



## Usage — step by step

`sbomb` walks an unpacked firmware rootfs, discovers components (dpkg/opkg/apk/os-release/busybox/python/npm), emits a CycloneDX SBOM, and flags known-vuln components. Exit `1` when vulns are found (unless suppressed).

1. **Install**
   ```bash
   pip install sbomb
   ```

2. **Scan an unpacked rootfs** for a component + vuln table:
   ```bash
   sbomb scan ./rootfs
   ```

3. **Emit a CycloneDX 1.5 SBOM** to stdout or a file:
   ```bash
   sbomb scan ./rootfs --format json > sbom.json
   sbomb scan ./rootfs -o sbom.json
   ```

4. **Use your own offline vuln DB**, or inventory only with `--no-vuln`:
   ```bash
   sbomb scan ./rootfs --vuln-db my_cves.json --format json
   ```

5. **Emit SARIF 2.1.0** for GitHub code-scanning / generic SAST ingestion:
   ```bash
   sbomb scan ./rootfs --format sarif -o results.sarif
   # then upload results.sarif via github/codeql-action/upload-sarif
   ```

6. **Use in CI** — the non-zero exit on vulns fails the build; `--no-fail` makes it advisory-only:
   ```bash
   sbomb scan ./rootfs -o sbom.json || echo "known-vuln components present"
   ```

7. **Match components against the bundled 262k-record OSV corpus** (fully offline — see [Bundled vulnerability database](#bundled-db)):
   ```bash
   sbomb match ./rootfs                  # advisories per detected component
   sbomb match -p log4j-core             # a single package
   sbomb match --cve CVE-2021-44228      # direct CVE/GHSA lookup
   ```

8. **Serve sbomb to an AI agent** over MCP (optional `mcp` extra):
   ```bash
   pip install "cognis-sbomb[mcp]" && sbomb mcp     # exposes sbomb_scan / sbomb_match / sbomb_cve
   ```

<a name="why"></a>

## Why sbomb?



Regulatory tailwind (EU CRA / FDA premarket SBOM mandates) — single binary that turns a squashfs into a compliance artifact. Compliance-deadline urgency drives adoption.



`sbomb` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="features"></a>

## Features



- ✅ Version Compare

- ✅ Detect Dpkg

- ✅ Detect Opkg

- ✅ Detect Apk

- ✅ Detect Os Release

- ✅ Detect Busybox

- ✅ Detect Python Packages

- ✅ Detect Node Packages

- ✅ CISA KEV + OSV data-feed enrichment (edge / air-gap, offline-capable)

- ✅ Bundled **262,351-record real OSV corpus** + offline `match` subcommand (`sbomb match`, no network)

- ✅ MCP server (`sbomb mcp`) — drive scan/match/CVE-lookup from any AI agent

- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer

- ✅ Real, CI-verified ports in Python, JavaScript, Go, and Rust (`ports/`) — each does the **full** rootfs→SBOM→CVE scan, not a stub



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="quick-start"></a>

## Quick start



```bash

pip install cognis-sbomb

sbomb --version

sbomb scan .                       # scan current project

sbomb scan . --format json         # machine-readable

sbomb scan . --fail-on high        # CI gate (non-zero exit)

```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="example"></a>

## Example



```text

$ sbomb scan demos/02-debian-router/rootfs

COMPONENT   VERSION             SOURCE  VULNS
---------------------------------------------
base-files  11.1+deb11u5        dpkg    -
curl        7.74.0-1.3+deb11u3  dpkg    CVE-2022-32207(critical)
dropbear    2022.83-1           dpkg    -
openssl     1.1.1k-1+deb11u1    dpkg    CVE-2021-3711(critical)
zlib1g      1:1.2.13.dfsg-1     dpkg    -

5 components, 2 vulnerability finding(s).   # exit code 1 (CI gate)

```



## Demos

Eight runnable, **verified** scenarios live under [`demos/`](demos/) — each is
a realistic unpacked firmware rootfs in the tool's real input formats plus a
`SCENARIO.md` (where the data came from, the run command, expected findings,
how to act). Every demo is exercised by `tests/test_demos.py`.

| Demo | Source | Outcome |
|---|---|---|
| [`01-basic`](demos/01-basic/) | opkg + apk + python | openssl + zlib (exit 1) |
| [`02-debian-router`](demos/02-debian-router/) | dpkg | openssl + curl (exit 1) |
| [`03-alpine-ipcam`](demos/03-alpine-ipcam/) | apk | openssl 3.0.5 "Spooky SSL" (exit 1) |
| [`04-busybox-banner`](demos/04-busybox-banner/) | busybox binary banner | busybox 1.31.1 (exit 1) |
| [`05-node-gateway`](demos/05-node-gateway/) | npm (nested) | vendored Log4Shell (exit 1) |
| [`06-clean-device`](demos/06-clean-device/) | opkg (patched) | **0 findings (exit 0)** |
| [`07-custom-vulndb`](demos/07-custom-vulndb/) | dpkg + opkg + `--vuln-db` | org-policy DB (exit 1) |
| [`08-multidistro`](demos/08-multidistro/) | every detector | 2 criticals (exit 1) |
| [`09-feed-enrichment`](demos/09-feed-enrichment/) | npm + **CISA KEV + OSV** (offline) | Log4Shell tagged `[KEV]`, +OSV advisories |

```bash
python -m sbomb scan demos/05-node-gateway/rootfs            # Log4Shell in node_modules
python -m sbomb scan demos/06-clean-device/rootfs            # clean -> exit 0
python -m sbomb scan demos/03-alpine-ipcam/rootfs --format sarif -o cam.sarif
# offline data-feed enrichment (see "Data feeds" below)
COGNIS_FEEDS_CACHE=tests/fixtures/feeds \
  python -m sbomb scan demos/05-node-gateway/rootfs --osv --kev --offline
```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="bundled-db"></a>

## Bundled vulnerability database — 262k real OSV records, fully offline

`sbomb` ships **`sbomb/cognis_vulndb.jsonl.gz` — 262,351 real vulnerability
records** consolidated from [OSV.dev](https://osv.dev) across PyPI, npm, Go,
Maven, RubyGems, crates.io and NuGet. Each record carries its OSV/GHSA id,
CVE aliases, ecosystem, summary, CVSS severity vector, affected packages and
dates. The loader (`sbomb/vulndb_local.py`, `VulnDB`) is **pure standard
library** and reads the gzip directly — no network, no API key, no extra
deps — so it works the moment the repo is cloned and on fully air-gapped gear.

```bash
sbomb match ./rootfs                 # match every detected component
sbomb match -p log4j-core            # match a single package
sbomb match --cve CVE-2021-44228     # look a CVE/GHSA up directly
sbomb match ./rootfs --format json   # machine-readable
sbomb match ./rootfs --ecosystem-strict   # cut cross-ecosystem name collisions
```

Worked example — Log4Shell really resolves out of the bundled corpus:

```text
$ sbomb match -p log4j-core
Matched 1 component(s) against 262,351 bundled OSV records.

log4j-core  [any] — 11 advisory(ies)
  CVE-2021-44228     Maven      Remote code injection in Log4j
  CVE-2021-45046     Maven      Incomplete fix for Apache Log4j vulnerability
  CVE-2021-45105     Maven      Improper Input Validation / Uncontrolled recursion
  CVE-2021-44832     Maven      Improper Input Validation and Injection in Apache Log4j2
  CVE-2017-5645      Maven      Deserialization of Untrusted Data in Log4j
  ...

1 component(s) carry 11 advisory(ies).   # exit code 1 (CI gate)
```

```python
from sbomb.vulndb_local import VulnDB
db = VulnDB()
db.count()                       # -> 262351
db.by_cve("CVE-2021-44228")      # -> the Log4Shell Maven record
db.by_package("log4j-core")      # -> short name resolves the group:artifact id
```

Two complementary matchers ship in the box:

| Matcher | Source | Version-gated? | Use |
|---|---|---|---|
| `sbomb scan` (curated DB) | `core.DEFAULT_VULN_DB` + `--vuln-db` | ✅ yes (range logic) | precise "this exact version is vulnerable" CI gate |
| `sbomb match` (bundled corpus) | `cognis_vulndb.jsonl.gz` (262k) | name-level (advisories that name the package) | breadth — surface every advisory touching a component, offline |

Refresh / extend the corpus at the edge from NVD / OSV / GHSA with
`python -m sbomb.datafeeds bulk` (see the air-gap workflow below).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="data-feeds"></a>

## Data feeds — CISA KEV + OSV (edge / air-gap ready)

`sbomb` ships a standard-library ingestion layer (`sbomb/datafeeds.py` +
`sbomb/feeds.py`, catalog in `sbomb/data_feeds_2026.json`) that pulls **real,
keyless, public** vulnerability intelligence over HTTPS, caches it to disk, and
**re-serves it offline** so the tool keeps working on disconnected / edge /
air-gapped gear. This repo consumes two feeds from the catalog:

| Feed id | Source | URL | Use |
|---|---|---|---|
| `cisa-kev` | CISA Known Exploited Vulnerabilities | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Tag matched CVEs that are **actively exploited** (`[KEV]`); escalate them to SARIF `error` / `security-severity 10.0` |
| `osv` | OSV.dev vulnerability query | `https://api.osv.dev/v1/query` | Discover **additional** advisories per detected component (PyPI/npm/Debian/Alpine), beyond the bundled offline DB |

### Enriched scan

```bash
sbomb scan ./rootfs --kev            # tag KEV-listed (actively-exploited) CVEs
sbomb scan ./rootfs --osv            # add OSV.dev advisories per component
sbomb scan ./rootfs --osv --kev      # both
```

KEV markers ride through to the outputs: a `sbomb:known_exploited` property on
the CycloneDX vulnerability, and a `known-exploited` tag + `security-severity
10.0` + `error` level on the SARIF result (so GitHub code-scanning surfaces it
at the top).

### `feeds` command

```bash
sbomb feeds list                       # this tool's relevant feeds + cache age
sbomb feeds update cisa-kev            # fetch + cache the live KEV catalog
sbomb feeds get cisa-kev --offline     # print cached content, no network
sbomb feeds snapshot-export feeds.tar.gz   # tar the cache for sneakernet
sbomb feeds snapshot-import feeds.tar.gz   # load it on the air-gapped box
```

The catalog is filtered to this tool's domain — `feeds list`/`get` only expose
`cisa-kev` and `osv`; other catalog feeds are rejected.

### Edge / air-gap workflow

1. On a connected host: `sbomb feeds update cisa-kev` warms the cache
   (`COGNIS_FEEDS_CACHE`, default `~/.cache/cognis-feeds`). OSV is a per-package
   query feed, so it is cached on demand during `scan --osv`.
2. `sbomb feeds snapshot-export feeds.tar.gz` tars the cache flat.
3. Sneakernet the tarball into the disconnected enclave.
4. `sbomb feeds snapshot-import feeds.tar.gz`, then run any scan with
   `--offline` — feed data is served from the local cache and the network is
   never touched.

Tests are **fully offline**: `tests/test_feeds.py` points `COGNIS_FEEDS_CACHE`
at committed trimmed fixtures (`tests/fixtures/feeds/`) and asserts the network
is never reached.



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="architecture"></a>

## Architecture



```mermaid
flowchart LR
  IN[target / manifest] --> P[sbomb<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="ai-stack"></a>

## Use it from any AI stack



`sbomb` is interoperable with every popular way of using AI:



- **MCP server** — `sbomb mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))

- **OpenAI-compatible / JSON** — pipe `sbomb scan . --format json` into any agent or LLM

- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line

- **CI / scripts** — exit codes + SARIF for non-AI pipelines



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="ports"></a>

## Polyglot ports — the full scan, in four languages

The same firmware-rootfs scan surface is ported to **JavaScript/Node, Go, and
Rust** alongside the Python reference. These are not stubs: each port walks a
rootfs, runs every detector (dpkg/opkg/apk/os-release/busybox/python/npm),
matches against an embedded real-CVE DB with identical version-range logic, and
emits the same CycloneDX 1.5 shape — exiting `1` when vulns are found.

```bash
node ports/javascript/index.js ./rootfs        # Node
cd ports/go   && go run .   ../../rootfs        # Go (single static binary)
cd ports/rust && cargo run -- ../../rootfs      # Rust
```

Every port has its own test suite against the real `demos/` fixtures, and all
three are built + tested on every push by
[`.github/workflows/ports.yml`](.github/workflows/ports.yml). See
[`ports/README.md`](ports/README.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>

## How it compares



| | **Cognis sbomb** | syft + cve-bin-tool |

|---|:---:|:---:|

| Self-hostable, no account | ✅ | varies |

| Single command, zero config | ✅ | ⚠️ |

| JSON + SARIF for CI | ✅ | varies |

| MCP-native (AI agents) | ✅ | ❌ |

| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |

| Open license | ✅ COCL | varies |



*Built in the spirit of **syft + cve-bin-tool**, re-framed the Cognis way. Missing a credit? Open a PR.*



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="integrations"></a>

## Integrations



Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`sbomb mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="install-anywhere"></a>

## Install — every way, every platform



```bash

pip install "git+https://github.com/cognis-digital/sbomb.git"    # pip (works today)

pipx install "git+https://github.com/cognis-digital/sbomb.git"   # isolated CLI

uv tool install "git+https://github.com/cognis-digital/sbomb.git" # uv

pip install cognis-sbomb                                          # PyPI (when published)

docker run --rm ghcr.io/cognis-digital/sbomb:latest --help        # Docker

brew install cognis-digital/tap/sbomb                             # Homebrew tap

curl -fsSL https://raw.githubusercontent.com/cognis-digital/sbomb/main/install.sh | sh

```



| Linux | macOS | Windows | Docker | Cloud |

|---|---|---|---|---|

| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/sbomb` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="related"></a>

## Related Cognis tools



- [`fwxray`](https://github.com/cognis-digital/fwxray) — Diff two firmware images and surface exactly what changed: new binaries, flipped config flags, added certs, and shifted entropy regions.

- [`canzap`](https://github.com/cognis-digital/canzap) — Replay, fuzz, and assert on CAN bus traffic from a .pcap or SocketCAN interface with a tiny YAML DSL.

- [`mqttspy`](https://github.com/cognis-digital/mqttspy) — Passively map an MQTT broker: enumerate topics, detect unauthenticated writes, spot PII/secrets in payloads, and emit a risk report.

- [`uefiscan`](https://github.com/cognis-digital/uefiscan) — Audit UEFI firmware dumps for missing Secure Boot keys, unsigned modules, S3 boot-script vulns, and known SMM threats.

- [`modpot`](https://github.com/cognis-digital/modpot) — Spin up a high-interaction Modbus/DNP3 ICS honeypot that logs attacker register reads/writes as structured JSON.

- [`keyhunt`](https://github.com/cognis-digital/keyhunt) — Scan firmware blobs and filesystem dumps for hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.



**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="contributing"></a>

## Contributing



PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).



> ### ⭐ If `sbomb` saved you time, **star it** — it genuinely helps others find it.



## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License



Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).



---



<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>


## Bundled vulnerability database

See **[Bundled vulnerability database — 262k real OSV records](#bundled-db)**
above for the full write-up: `sbomb/cognis_vulndb.jsonl.gz` ships **262,351
real OSV vulnerabilities** (PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with
CVE/GHSA aliases, ecosystem, CVSS severity, affected packages and dates,
queried offline via the `sbomb match` subcommand or the pure-stdlib
`vulndb_local.VulnDB` loader (`count`/`by_cve`/`by_package`/`search`).
