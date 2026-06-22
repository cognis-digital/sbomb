# Demo 03 — Alpine-based IP camera (apk database)

A cheap Wi-Fi IP camera. Its firmware is an Alpine Linux `armv7` image; the
vendor pinned OpenSSL 3.0.5, which lands inside the "Spooky SSL" window. The
package truth is Alpine's apk database at `lib/apk/db/installed`.

## What's in the rootfs

`rootfs/lib/apk/db/installed` — apk installed-DB blocks (`P:`/`V:` records) for:

- `musl 1.2.4-r2`
- `openssl 3.0.5-r0`
- `zlib 1.2.13-r0`
- `busybox 1.36.1-r2`

## Run it

```bash
python -m sbomb scan demos/03-alpine-ipcam/rootfs
# machine-readable CycloneDX:
python -m sbomb scan demos/03-alpine-ipcam/rootfs --format json
```

## Expected result — 1 finding, exit 1

| Component | Version (normalized) | Finding |
|---|---|---|
| `openssl` | `3.0.5` | **CVE-2022-3602 (high)** — in range `>=3.0.0,<3.0.7` |

`musl`, `zlib` (1.2.13 ≥ 1.2.12) and `busybox` (1.36.1 ≥ 1.34.0) are clean.
This is the case the simple `<X` ranges can't express on their own — the
OpenSSL 3.x advisory is a *bounded* range, and `sbomb` evaluates the
comma-separated `>=3.0.0,<3.0.7` constraint as an AND.

## How to act

Bump OpenSSL to ≥ 3.0.7 in the Alpine package feed and rebuild. Until then,
the device's TLS stack is vulnerable to the X.509 punycode buffer overflow.
