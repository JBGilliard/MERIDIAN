#!/usr/bin/env bash
# CycloneDX JSON SBOM for the lexicon CLI, written next to the binary.
# Usage: scripts/sbom.sh [binary-or-dir]
#
#   scripts/sbom.sh                         # target/release/lexicon.cdx.json
#   scripts/sbom.sh dist/lexicon            # dist/lexicon.cdx.json
#   scripts/sbom.sh dist                    # dist/lexicon.cdx.json
#
# Requires: cargo install cargo-cyclonedx --version 0.5.9 --locked
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/sbom.sh [binary-or-dir]

Writes lexicon.cdx.json next to the lexicon binary (CycloneDX JSON).
Default destination: target/release/lexicon.cdx.json

Install the generator on a networked builder:
  cargo install cargo-cyclonedx --version 0.5.9 --locked
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

if ! cargo cyclonedx --version >/dev/null 2>&1; then
  echo "cargo-cyclonedx not found. Install: cargo install cargo-cyclonedx --locked" >&2
  exit 1
fi

DEST="${1:-$ROOT/target/release}"
if [[ -f "$DEST" ]]; then
  OUT_DIR="$(cd "$(dirname "$DEST")" && pwd)"
elif [[ -d "$DEST" ]]; then
  OUT_DIR="$(cd "$DEST" && pwd)"
else
  mkdir -p "$DEST"
  OUT_DIR="$(cd "$DEST" && pwd)"
fi
OUT="$OUT_DIR/lexicon.cdx.json"

MANIFEST="$ROOT/crates/lexicon-cli/Cargo.toml"
PKGDIR="$ROOT/crates/lexicon-cli"
STAMP="meridian-sbom-tmp"

# cargo-cyclonedx writes next to the manifest; stamp name so we can mv it out.
rm -f "$PKGDIR/${STAMP}"* "$PKGDIR/${STAMP}".*

cdx_args=(
  cyclonedx
  --manifest-path "$MANIFEST"
  --format json
)
if cargo cyclonedx --help 2>/dev/null | grep -q -- '--spec-version'; then
  cdx_args+=(--spec-version 1.5)
fi
# --override-filename and --describe are mutually exclusive in cargo-cyclonedx 0.5+
if cargo cyclonedx --help 2>/dev/null | grep -q -- '--describe'; then
  cdx_args+=(--describe binaries)
else
  cdx_args+=(--override-filename "$STAMP")
fi

echo "== cargo ${cdx_args[*]}"
cargo "${cdx_args[@]}"

found=""
for cand in \
  "$PKGDIR/lexicon_bin.cdx.json" \
  "$PKGDIR/${STAMP}.cdx.json" \
  "$PKGDIR/${STAMP}.json" \
  "$PKGDIR/${STAMP}.cdx.xml" \
  "$PKGDIR/${STAMP}.xml"
do
  if [[ -f "$cand" ]]; then
    found="$cand"
    break
  fi
done
if [[ -z "$found" ]]; then
  found="$(find "$PKGDIR" -maxdepth 1 \( -name "${STAMP}*" -o -name 'lexicon*.cdx.json' \) -type f | head -n 1 || true)"
fi
if [[ -z "$found" || ! -f "$found" ]]; then
  echo "cargo-cyclonedx did not write $PKGDIR/${STAMP}*" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
mv "$found" "$OUT"
rm -f "$PKGDIR/${STAMP}"* || true
echo "Wrote $OUT"
