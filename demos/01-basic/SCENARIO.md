# Demo 01 - Basic firmware rootfs scan

This demo ships a tiny, fake **unpacked firmware rootfs** under
`rootfs/` that mimics what you'd get after running `binwalk`/`unsquashfs`
on a real embedded Linux image. It contains:

- `etc/os-release` - an OpenWrt-style base OS marker.
- `usr/lib/opkg/status` - an **opkg** package database listing
  `openssl 1.1.1k`, `zlib 1.2.11`, `dropbear 2020.81`, and `libcurl 7.88.0`.
- `lib/apk/db/installed` - an Alpine-style **apk** DB listing `musl 1.2.4`
  and `scanelf 1.3.7`.
- `usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA`
  - a Python package detected via dist-info.

## Run it

```bash
# Human-readable table
python -m sbomb scan demos/01-basic/rootfs

# CycloneDX 1.5 JSON SBOM for CI / piping
python -m sbomb scan demos/01-basic/rootfs --format json
```

## Expected result

The scanner detects **8 components** (1 operating-system + 7 packages —
opkg, apk, and python all contribute) and flags **known vulnerabilities**
using the bundled offline DB:

- `openssl 1.1.1k`  -> **CVE-2021-3711 (critical)** because `1.1.1k < 1.1.1l`.
- `zlib 1.2.11`     -> **CVE-2018-25032 (high)** because `1.2.11 < 1.2.12`.

`dropbear 2020.81`, `libcurl 7.88.0`, `musl`, `scanelf`, and `requests` are
**clean** (their versions are above the vulnerable ranges).

Because vulnerabilities are found, the CLI exits with **status 1** - this
is intentional so it can be used as a CI gate. Pass `--no-fail` to always
exit 0.
