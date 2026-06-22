# Demo 07 — Custom organizational vuln DB (`--vuln-db`)

A regulated manufacturer maintains its own curated advisory list (the
internal "must-block" set) rather than relying on the bundled starter DB.
`sbomb` accepts any JSON vuln DB via `--vuln-db`. This image is an industrial
gateway with components surfaced from **two** package sources (dpkg + opkg).

## What's in this demo

- `rootfs/var/lib/dpkg/status` — `glibc 2.31-13+deb11u5`, `openssl 1.1.1n-0+deb11u3`
- `rootfs/usr/lib/opkg/status` — `dropbear 2019.78`
- `vuln-db.json` — the org's policy DB. It reuses **only** grounded CVE
  identifiers already present in sbomb's bundled DB
  (`CVE-2021-3999`, `CVE-2020-36254`, `CVE-2021-3711`) — no fabricated IDs —
  but tightens descriptions to the org's "block" language.

## Run it

```bash
python -m sbomb scan demos/07-custom-vulndb/rootfs \
  --vuln-db demos/07-custom-vulndb/vuln-db.json
```

## Expected result — 2 findings, exit 1

| Component | Version (normalized) | Finding |
|---|---|---|
| `glibc`    | `2.31` | **CVE-2021-3999 (high)** — `2.31 < 2.35` |
| `dropbear` | `2019.78` | **CVE-2020-36254 (medium)** — `2019.78 < 2020.79` |

`openssl 1.1.1n` is **clean** here: `1.1.1n ≥ 1.1.1l`, so even though the org
DB carries a CVE-2021-3711 entry, the version is out of range. This shows the
matcher is range-driven, not name-driven — having an advisory for a package
does not flag a patched version of it.

## How to act

Run with your own DB in CI to enforce *your* baseline. Compare against the
default DB (drop `--vuln-db`) to see only the bundled findings, which here
overlap on glibc/dropbear. Keep the org DB in version control next to your
pipeline config.
