# Demo 05 — Node.js edge gateway with a vendored Log4Shell sidecar

An industrial edge gateway runs a Node.js application bundled into the
firmware under `opt/app`, with its dependencies vendored into
`node_modules/`. The vendor also dropped a Java logging sidecar's manifest
into the same tree as an npm-style `package.json`, so `sbomb`'s node detector
surfaces it — and it happens to be a Log4Shell-era log4j.

## What's in the rootfs

`rootfs/opt/app/node_modules/` with `package.json` manifests for:

- `express 4.18.2`
- `ws 8.13.0`
- `log4j-core 2.14.1` — vendored java logging sidecar manifest
- `express/node_modules/cookie 0.5.0` — **nested** module, proving the
  recursive `node_modules` walk

## Run it

```bash
python -m sbomb scan demos/05-node-gateway/rootfs
# emit SARIF for GitHub code-scanning:
python -m sbomb scan demos/05-node-gateway/rootfs --format sarif -o gw.sarif
```

## Expected result — 1 finding, exit 1

| Component | Version | Source | Finding |
|---|---|---|---|
| `log4j-core` | `2.14.1` | `npm` | **CVE-2021-44228 (critical)** — Log4Shell, range `>=2.0,<2.17.1` |

`express`, `ws`, and the nested `cookie` are all clean. The nested-module
detection is the point: vulnerable transitive deps hide several levels deep,
and a flat scan would miss them.

## How to act

`log4j-core 2.14.1` is inside the Log4Shell range — remote code execution via
JNDI lookup. Rebuild the app image with log4j ≥ 2.17.1 (or remove the
vendored sidecar). The SARIF output uploads straight to the GitHub
code-scanning dashboard so the alert is tracked to closure.
