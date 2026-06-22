# Demo 08 — Messy multi-distro firmware (every detector at once)

Real production images are rarely tidy. This one is a Debian host that also
carries an Alpine container rootfs under `opt/container`, a Python virtualenv
under `opt/app/venv`, and a vendored Node/Java manifest under
`opt/app/node_modules`. The point is that `sbomb` fuses **all** detectors over
one tree and produces a single SBOM spanning os-release + dpkg + apk + python
+ npm.

## What's in the rootfs

- `rootfs/etc/os-release` — Debian 11 (bullseye)
- `rootfs/var/lib/dpkg/status` — `openssl 1.1.1f-1ubuntu2`, `zlib1g 1:1.2.11.dfsg-2`
- `rootfs/opt/container/lib/apk/db/installed` — `busybox 1.33.0-r0` (nested Alpine)
- `rootfs/opt/app/venv/.../flask-2.0.1.dist-info/METADATA` — `Flask 2.0.1` (python)
- `rootfs/opt/app/node_modules/log4j-core/package.json` — `log4j-core 2.10.0` (npm)

## Run it

```bash
python -m sbomb scan demos/08-multidistro/rootfs
python -m sbomb scan demos/08-multidistro/rootfs --format json -o image.cdx.json
```

## Expected result — 2 findings, exit 1

| Component | Version (normalized) | Source | Finding |
|---|---|---|---|
| `openssl`    | `1.1.1f`  | dpkg | **CVE-2021-3711 (critical)** — `1.1.1f < 1.1.1l` |
| `log4j-core` | `2.10.0`  | npm  | **CVE-2021-44228 (critical)** — Log4Shell range |

The scan also inventories Debian (`os-release`), `zlib1g`, the nested-Alpine
`busybox 1.33.0`, and `Flask 2.0.1` — clean, but present in the SBOM. (As in
demo 02, the Debian binary name `zlib1g` is reported clean because matching is
exact; `busybox 1.33.0` is patched against the bundled CVE-2021-42374 range.)

## How to act

This is the integration smoke test for the whole detector matrix. One command
gives you a complete CycloneDX inventory across mixed packaging systems plus
the two critical findings to remediate first (OpenSSL RCE, Log4Shell).
