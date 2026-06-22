# Demo 02 — Debian-based home router (dpkg database)

A mid-range home/SOHO router whose firmware is a Debian `armhf` build. After
pulling the image off the SPI flash and running `binwalk -e` / `unsquashfs`,
the analyst points `sbomb` at the extracted root filesystem. The component
truth lives in the Debian package database at `var/lib/dpkg/status`.

## What's in the rootfs

`rootfs/var/lib/dpkg/status` — a real-format dpkg status file listing:

- `openssl 1.1.1k-1+deb11u1`
- `curl 7.74.0-1.3+deb11u3`
- `zlib1g 1:1.2.13.dfsg-1`
- `dropbear 2022.83-1`
- `base-files 11.1+deb11u5`
- `ca-certificates 20210119` — **status `deinstall ok config-files`**, so it
  is *not installed* and `sbomb` correctly ignores it.

## Run it

```bash
python -m sbomb scan demos/02-debian-router/rootfs
```

## Expected result — 2 findings, exit 1

| Component | Version (normalized) | Finding |
|---|---|---|
| `openssl` | `1.1.1k` | **CVE-2021-3711 (critical)** — `1.1.1k < 1.1.1l` |
| `curl`    | `7.74.0` | **CVE-2022-32207 (critical)** — `7.74.0 < 7.84.0` |

`zlib1g` and `dropbear` are clean. Note that `sbomb` normalizes the dpkg
version string (`1.1.1k-1+deb11u1` → `1.1.1k`): it strips the Debian epoch
(`1:`) and the distro revision (`-1+deb11u1`) before comparing, which is why
the match works against the upstream range.

> The `zlib` binary package is named `zlib1g` on Debian (source `zlib`). Name
> matching is intentionally exact, so this entry is reported clean — a good
> reminder that distro binary names differ from upstream/source names. If your
> policy needs source-name matching, ship a custom vuln DB keyed on `zlib1g`
> (see demo 07).

## How to act

The router image is shipping an OpenSSL with a critical RCE and a `curl`
with a critical cookie-handling flaw. File a fix-forward against the BSP to
bump both, then re-scan; CI should go from exit 1 to exit 0.
