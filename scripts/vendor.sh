#!/usr/bin/env bash
# Vendor crates.io sources into ./vendor for air-gap builds.
# Usage: scripts/vendor.sh [--tarball]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/vendor.sh [--tarball]

  cargo vendor --locked vendor

  --tarball   also write dist/vendor.tar.gz

Air-gap build after vendoring:

  cp .cargo/config.toml.example .cargo/config.toml
  cargo build --locked --offline -p lexicon-cli

Tarball without --tarball:

  mkdir -p dist
  tar -czf dist/vendor.tar.gz vendor
EOF
}

MAKE_TARBALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tarball) MAKE_TARBALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ ! -f Cargo.lock ]]; then
  echo "Cargo.lock missing; commit a lockfile before vendoring" >&2
  exit 1
fi

echo "== cargo vendor --locked vendor"
cargo vendor --locked vendor

echo
echo "Vendored into $ROOT/vendor"
echo "Enable:  cp .cargo/config.toml.example .cargo/config.toml"
echo "Build:   cargo build --locked --offline -p lexicon-cli"
echo "Tarball: mkdir -p dist && tar -czf dist/vendor.tar.gz vendor"

if [[ "$MAKE_TARBALL" -eq 1 ]]; then
  mkdir -p "$ROOT/dist"
  tar -czf "$ROOT/dist/vendor.tar.gz" vendor
  echo "Wrote $ROOT/dist/vendor.tar.gz"
fi
