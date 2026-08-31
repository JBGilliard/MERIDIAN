#!/usr/bin/env bash
# Hash + detach-sign the intro packet (binary, SBOM, vendor tarball, deny report).
# Usage: scripts/release-sign.sh [--dist DIR] [--hashes-only]
#
# Looks in DIR (default: dist/) for:
#   lexicon | lexicon.exe
#   lexicon.cdx.json
#   vendor.tar.gz
#   deny-report.txt   (generated here if cargo-deny is available)
#
# Signs with cosign (COSIGN_KEY) if set, else gpg --detach-sign --armor.
# Writes SHA256SUMS and INTRO-PACKAGE.txt.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist"
HASHES_ONLY=0

usage() {
  cat <<'EOF'
Usage: scripts/release-sign.sh [--dist DIR] [--hashes-only]

Required in DIR (default dist/):
  lexicon or lexicon.exe, lexicon.cdx.json, vendor.tar.gz

deny-report.txt is generated with `cargo deny check` when missing.

  COSIGN_KEY     path to cosign private key (preferred when set)
  DENY_OFFLINE=1 pass --offline to cargo-deny (air-gap advisory db)

  --hashes-only  write SHA256SUMS + INTRO-PACKAGE.txt, do not sign
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST="$2"
      shift 2
      ;;
    --hashes-only) HASHES_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$DIST"
DIST="$(cd "$DIST" && pwd)"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

VERSION="$(awk '
  /^\[workspace.package\]/ { f=1; next }
  f && /^version =/ { gsub(/"/, "", $3); print $3; exit }
  f && /^\[/ { exit }
' "$ROOT/Cargo.toml")"
VERSION="${VERSION:-0.1.0}"

BIN=""
for cand in "$DIST/lexicon" "$DIST/lexicon.exe"; do
  if [[ -f "$cand" ]]; then
    BIN="$cand"
    break
  fi
done
if [[ -z "$BIN" && -f "$ROOT/target/release/lexicon" ]]; then
  cp "$ROOT/target/release/lexicon" "$DIST/lexicon"
  BIN="$DIST/lexicon"
fi
if [[ -z "$BIN" && -f "$ROOT/target/release/lexicon.exe" ]]; then
  cp "$ROOT/target/release/lexicon.exe" "$DIST/lexicon.exe"
  BIN="$DIST/lexicon.exe"
fi

SBOM="$DIST/lexicon.cdx.json"
VENDOR="$DIST/vendor.tar.gz"
DENY_REPORT="$DIST/deny-report.txt"

missing=0
if [[ -z "$BIN" ]]; then
  echo "missing binary: $DIST/lexicon (build --release and copy here, or run from target/release)" >&2
  missing=1
fi
if [[ ! -f "$SBOM" ]]; then
  echo "missing SBOM: $SBOM (scripts/sbom.sh $DIST)" >&2
  missing=1
fi
if [[ ! -f "$VENDOR" ]]; then
  echo "missing vendor tarball: $VENDOR (scripts/vendor.sh --tarball)" >&2
  missing=1
fi
if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

if [[ ! -f "$DENY_REPORT" ]]; then
  if ! cargo deny --version >/dev/null 2>&1; then
    echo "missing $DENY_REPORT and cargo-deny not installed (cargo install cargo-deny --locked)" >&2
    exit 1
  fi
  echo "== cargo deny check"
  deny_args=(deny check)
  if [[ "${DENY_OFFLINE:-}" == "1" ]]; then
    deny_args+=(--offline)
  fi
  # Unmaintained: warn, do not fail. Yanked + vulns still fail closed via deny.toml.
  deny_args+=(-W unmaintained)
  set +e
  cargo "${deny_args[@]}" >"$DENY_REPORT" 2>&1
  deny_rc=$?
  set -e
  if [[ "$deny_rc" -ne 0 ]]; then
    echo "cargo deny check failed (exit $deny_rc); see $DENY_REPORT" >&2
    exit "$deny_rc"
  fi
  echo "Wrote $DENY_REPORT"
fi

BIN_BASE="$(basename "$BIN")"
ARTIFACTS=("$BIN_BASE" "lexicon.cdx.json" "vendor.tar.gz" "deny-report.txt")

(
  cd "$DIST"
  : >SHA256SUMS
  for a in "${ARTIFACTS[@]}"; do
    sha256 "$a" >>SHA256SUMS
  done
)

sign_file() {
  local f="$1"
  if [[ -n "${COSIGN_KEY:-}" ]] && command -v cosign >/dev/null 2>&1; then
    cosign sign-blob --key "$COSIGN_KEY" --yes --output-signature "$f.sig" "$f"
  elif command -v gpg >/dev/null 2>&1; then
    gpg --detach-sign --armor --output "$f.asc" "$f"
  else
    echo "no signer: set COSIGN_KEY (cosign) or install gpg, or pass --hashes-only" >&2
    exit 1
  fi
}

if [[ "$HASHES_ONLY" -eq 0 ]]; then
  (
    cd "$DIST"
    for a in "${ARTIFACTS[@]}" SHA256SUMS; do
      sign_file "$a"
    done
  )
fi

CREATED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
RUSTC="$(rustc -V 2>/dev/null || echo "rustc not in PATH")"
SIGNER="none (--hashes-only)"
if [[ "$HASHES_ONLY" -eq 0 ]]; then
  if [[ -n "${COSIGN_KEY:-}" ]] && command -v cosign >/dev/null 2>&1; then
    SIGNER="cosign sign-blob --key (*.sig)"
  else
    SIGNER="gpg --detach-sign --armor (*.asc)"
  fi
fi

HASH_BODY="$(cat "$DIST/SHA256SUMS")"

cat >"$DIST/INTRO-PACKAGE.txt" <<EOF
MERIDIAN intro package
======================
Unclassified source/binary packet for accredited program-office evaluation.
Not a NICKA system of record. Official assignment remains NICKA.

version:     $VERSION
created:     $CREATED UTC
rustc:       $RUSTC
toolchain:   rust-toolchain.toml (1.85.0, profile=default)
signer:      $SIGNER

Artifacts (SHA-256):
$HASH_BODY

Verify hashes:
  sha256sum -c SHA256SUMS
  # macOS: shasum -a 256 -c SHA256SUMS

Verify signatures:
  gpg --verify SHA256SUMS.asc SHA256SUMS
  # or: cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS

Air-gap rebuild:
  tar -xzf vendor.tar.gz
  cp .cargo/config.toml.example .cargo/config.toml
  cargo build --locked --offline --release -p lexicon-cli

SBOM is CycloneDX JSON (lexicon.cdx.json). deny-report.txt is cargo deny check.
Default build writes names.sqlite only. bindings.sqlite is opt-in and classified.
EOF

echo "Wrote $DIST/SHA256SUMS"
echo "Wrote $DIST/INTRO-PACKAGE.txt"
if [[ "$HASHES_ONLY" -eq 0 ]]; then
  echo "Signed artifacts in $DIST"
fi
