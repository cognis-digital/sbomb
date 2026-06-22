# Demo 04 — busybox version from the binary banner (no package DB)

The cheapest devices ship a Buildroot image with **no package manager at
all** — there is no dpkg/opkg/apk database to read. The only way to learn the
busybox version is to read it out of the binary itself. `sbomb`'s binary
detector greps the busybox executable for its `BusyBox vX.Y.Z` banner.

## What's in the rootfs

- `rootfs/bin/busybox` — a small **synthetic stub** that embeds the real
  busybox banner string `BusyBox v1.31.1 (...) multi-call binary.` It is
  **not** a real busybox build; it exists only so the banner detector has
  something to match. (sbomb reads the first ~2 MB and regex-matches the
  banner — it never executes the file.)
- `rootfs/etc/os-release` — a Buildroot marker for context.

## Run it

```bash
python -m sbomb scan demos/04-busybox-banner/rootfs
```

## Expected result — 1 finding, exit 1

| Component | Version | Source | Finding |
|---|---|---|---|
| `busybox` | `1.31.1` | `binary` | **CVE-2021-42374 (medium)** — `1.31.1 < 1.34.0` |

Note the `SOURCE` column reads `binary` (not a package DB), proving the
banner path fired. The `buildroot` os-release component is clean.

## How to act

There is no package manager to `upgrade` here — the fix is a firmware rebuild
with a newer busybox (≥ 1.34.0). This demo is the canonical "stripped
embedded image" case where SBOM tools that only parse package databases would
report **zero** components and miss the vulnerability entirely.
