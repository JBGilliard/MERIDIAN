#!/usr/bin/env bash
# Mint a batch, prove uniqueness, verify every name, check the ledger.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/meridian-demo.XXXXXX")"
trap 'rm -rf "$DATA"' EXIT

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="${TARGET_DIR}/debug/lexicon"
cargo build -q -p lexicon-cli
if [[ ! -x "$BIN" ]]; then
  echo "lexicon binary not at $BIN" >&2
  exit 1
fi

echo "== keygen"
"$BIN" --data-dir "$DATA" key generate --agency DIA --json
"$BIN" --data-dir "$DATA" key generate --agency CIA --json

echo "== mint 12 nicknames + 4 cryptonyms + 2 code words"
names=()
for _ in $(seq 1 12); do
  json="$("$BIN" --data-dir "$DATA" mint --type nickname --agency DIA --json)"
  name="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
  names+=("$name")
  printf '%s\n' "$json" > "$DATA/${name// /_}.json"
done
for _ in $(seq 1 4); do
  json="$("$BIN" --data-dir "$DATA" mint --type cryptonym --agency CIA --digraph AE --json)"
  name="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
  names+=("$name")
  printf '%s\n' "$json" > "$DATA/${name}.json"
done
for _ in $(seq 1 2); do
  json="$("$BIN" --data-dir "$DATA" mint --type codeword --agency DIA --json)"
  name="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
  names+=("$name")
  printf '%s\n' "$json" > "$DATA/${name}.json"
done

echo "== minted"
printf '%s\n' "${names[@]}"

uniq_count="$(printf '%s\n' "${names[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "$uniq_count" -ne "${#names[@]}" ]]; then
  echo "FAIL: collision in demo batch" >&2
  exit 1
fi

echo "== verify each file"
for f in "$DATA"/*.json; do
  "$BIN" --data-dir "$DATA" verify --file "$f" --ledger
done

echo "== ledger"
"$BIN" --data-dir "$DATA" ledger verify

echo "== linter rejects BLUE SPOON"
"$BIN" check --name "BLUE SPOON" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["ok"] is False, d'

echo "ok: ${#names[@]} unique names, all verified"
