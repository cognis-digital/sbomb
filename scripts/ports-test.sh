#!/usr/bin/env bash
# Build + test every language port against the repo's real demo fixtures.
# Skips any toolchain that isn't installed. Run from the repo root.
set -u
DEMO="demos/01-basic/rootfs"   # known-vulnerable -> ports must exit 1
fail=0

echo "== Python (reference) =="
if command -v python >/dev/null 2>&1; then
  python -m pytest -q || fail=1
else
  echo "python: skipped"
fi

echo "== JavaScript / Node =="
if command -v node >/dev/null 2>&1; then
  node --test ports/javascript/test.mjs || fail=1
  node ports/javascript/index.js "$DEMO" >/dev/null; [ $? -eq 1 ] || { echo "node exit-code gate failed"; fail=1; }
else
  echo "node: skipped"
fi

echo "== Go =="
if command -v go >/dev/null 2>&1; then
  ( cd ports/go && go test ./... ) || fail=1
else
  echo "go: skipped"
fi

echo "== Rust =="
if command -v cargo >/dev/null 2>&1; then
  ( cd ports/rust && cargo test ) || fail=1
else
  echo "rust: skipped"
fi

exit $fail
