# Demo 09 — Air-gap data-feed enrichment (CISA KEV + OSV)

The same Node.js edge-gateway rootfs as demo 05, but scanned with the
**data-feed enrichment layer** turned on and running **fully offline** against
a committed feed cache — exactly how an air-gapped / disconnected edge box
would run it after a snapshot import.

Two real public feeds enrich the findings:

- **CISA KEV** (Known Exploited Vulnerabilities) — `log4j-core 2.14.1`'s
  `CVE-2021-44228` (Log4Shell) is on the KEV catalog, so the finding is tagged
  `[KEV]`, escalated to SARIF `error`, and given `security-severity 10.0`
  regardless of its base CVSS band. This is the "patch this first" signal.
- **OSV.dev** — per-component advisory discovery surfaces vulns the bundled
  offline DB doesn't carry, e.g. `cookie 0.5.0` (CVE-2024-47764) and
  `ws 8.13.0` (CVE-2024-37890, ...).

## Offline by construction

This demo points `COGNIS_FEEDS_CACHE` at the repo's committed, trimmed feed
cache (`tests/fixtures/feeds/`) — a real-but-small CISA KEV catalog plus a real
OSV query map — so it needs **zero network**.

## Run it

```sh
# from the repo root
COGNIS_FEEDS_CACHE=tests/fixtures/feeds \
  python -m sbomb scan demos/05-node-gateway/rootfs --osv --kev --offline
```

Expected (table) output:

```
OSV: +4 additional advisory finding(s)
CISA KEV: 1 finding(s) are actively exploited
COMPONENT   VERSION  SOURCE  VULNS
----------------------------------
cookie      0.5.0    npm     CVE-2024-47764(low)
express     4.18.2   npm     -
log4j-core  2.14.1   npm     CVE-2021-44228(critical)[KEV]
ws          8.13.0   npm     CVE-2024-37890(high), CVE-2026-48779(high), CVE-2026-45736(medium)
```

## Warming / refreshing the cache (when you DO have a network)

```sh
python -m sbomb feeds update cisa-kev          # pull the live KEV catalog
python -m sbomb feeds snapshot-export feeds.tar.gz   # sneakernet to the edge
# on the air-gapped box:
python -m sbomb feeds snapshot-import feeds.tar.gz
```
