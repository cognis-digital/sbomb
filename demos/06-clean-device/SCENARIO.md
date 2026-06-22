# Demo 06 — Fully patched device (zero findings, the green-CI case)

The control case. A current OpenWrt 23.05 build where every tracked component
sits **above** its vulnerable range. This is what a passing CI gate looks
like — and it is just as important to demonstrate as the failing cases,
because it proves `sbomb` does not cry wolf.

## What's in the rootfs

- `rootfs/etc/os-release` — OpenWrt 23.05.2
- `rootfs/usr/lib/opkg/status` — opkg DB with:
  - `openssl 3.0.12` (≥ 3.0.7, ≥ 1.1.1l)
  - `zlib 1.3.1` (≥ 1.2.12)
  - `dropbear 2022.83` (≥ 2020.79)
  - `libcurl 8.5.0` (≥ 7.84.0)

## Run it

```bash
python -m sbomb scan demos/06-clean-device/rootfs
echo "exit code: $?"   # 0
```

## Expected result — 0 findings, exit 0

```
5 components, 0 vulnerability finding(s).
```

Every component is detected (so you still get a full inventory / SBOM), but
none matches a vuln range, so the CLI exits **0**. Use this as the "known
good" fixture when wiring `sbomb` into a pipeline: the gate should pass.

## How to act

Nothing to fix. Keep the SBOM (`--format json -o sbom.json`) as the
compliance artifact for this release — even a clean scan produces a valid
CycloneDX 1.5 document you can archive for CRA / FDA evidence.
