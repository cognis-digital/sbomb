# sbomb demos

Each folder is a self-contained, **runnable** scenario: a realistic unpacked
firmware rootfs (in the tool's real input formats — dpkg/opkg/apk databases,
busybox binaries, python dist-info, npm `package.json`) plus a `SCENARIO.md`
that explains where the data came from, the exact run command, the expected
findings, and how to act. Every demo is exercised by `tests/test_demos.py`,
so they cannot silently stop firing.

All CVE identifiers used here are real, publicly documented advisories drawn
from sbomb's bundled offline DB — nothing is fabricated.

| Demo | Packaging source | Outcome |
|---|---|---|
| [`01-basic`](01-basic/) | opkg + apk + python (OpenWrt) | openssl + zlib findings (exit 1) |
| [`02-debian-router`](02-debian-router/) | dpkg (Debian armhf) | openssl + curl findings (exit 1) |
| [`03-alpine-ipcam`](03-alpine-ipcam/) | apk (Alpine armv7) | openssl 3.0.5 "Spooky SSL" (exit 1) |
| [`04-busybox-banner`](04-busybox-banner/) | busybox binary banner (no pkg DB) | busybox 1.31.1 finding (exit 1) |
| [`05-node-gateway`](05-node-gateway/) | npm `node_modules` (nested) | vendored Log4Shell (exit 1) |
| [`06-clean-device`](06-clean-device/) | opkg (patched OpenWrt 23.05) | **0 findings (exit 0)** |
| [`07-custom-vulndb`](07-custom-vulndb/) | dpkg + opkg + `--vuln-db` | org-policy DB, 2 findings (exit 1) |
| [`08-multidistro`](08-multidistro/) | os-release + dpkg + apk + python + npm | full detector matrix, 2 criticals (exit 1) |

## Run them all

```bash
for d in demos/*/; do
  [ -d "$d/rootfs" ] || continue
  echo "== $d =="
  python -m sbomb scan "$d/rootfs" || true
done
```

(Demo 07 needs `--vuln-db demos/07-custom-vulndb/vuln-db.json` to use its
custom policy database.)
