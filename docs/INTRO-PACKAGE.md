# Intro package

The **intro package** is an unclassified artifact bundle for accredited program-office evaluation. It is not a deployed system, not a NICKA system of record, and not an IC enterprise service. Official assignment remains NICKA.

Adopters run their own RMF, replace sample registers with authoritative data, and build classified bindings on accredited hosts.

## Contents

A complete intro package lives in `dist/` (or your release staging dir):

| Artifact | Purpose |
|----------|---------|
| `lexicon` (or `lexicon.exe`) | Release binary (`cargo build --release -p lexicon-cli`) |
| `lexicon.cdx.json` | CycloneDX SBOM |
| `vendor.tar.gz` | Vendored crates.io sources for air-gap rebuild |
| `deny-report.txt` | Output of `cargo deny check` |
| `SHA256SUMS` | SHA-256 hashes of the above |
| `*.asc` or `*.sig` | Detached signatures (GPG or cosign) |
| `INTRO-PACKAGE.txt` | Human-readable manifest (version, rustc, hashes, verify steps) |

Public source tree and sample pool data are **UNCLASSIFIED**. Real SAP/SCI bindings are supplied by the adopter on classified systems.

## Build (networked builder)

```bash
# 1. Release binary
cargo build --locked --release -p lexicon-cli

# 2. Vendor + tarball
./scripts/vendor.sh --tarball

# 3. SBOM next to binary
mkdir -p dist
cp target/release/lexicon dist/
./scripts/sbom.sh dist/

# 4. Hash + sign + INTRO-PACKAGE.txt
./scripts/release-sign.sh --dist dist/
```

`release-sign.sh` runs `cargo deny check` if `deny-report.txt` is missing. Set `DENY_OFFLINE=1` on air-gapped builders that already have an advisory database cache.

### Signing

- **Preferred:** `COSIGN_KEY` set and `cosign` installed → `*.sig` files.
- **Fallback:** `gpg --detach-sign --armor` → `*.asc` files.
- **Hashes only:** `./scripts/release-sign.sh --hashes-only` when no signer is available yet.

## Verify (recipient)

```bash
cd dist

# Hashes
sha256sum -c SHA256SUMS
# macOS: shasum -a 256 -c SHA256SUMS

# Signatures (one of)
gpg --verify SHA256SUMS.asc SHA256SUMS
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
```

Read `INTRO-PACKAGE.txt` for the exact artifact list and rustc/toolchain pin (`rust-toolchain.toml`, currently 1.80.0).

## Air-gap rebuild

```bash
tar -xzf vendor.tar.gz
cp .cargo/config.toml.example .cargo/config.toml
cargo build --locked --offline --release -p lexicon-cli
```

Compare the rebuilt binary hash to `SHA256SUMS`. A mismatch means different linker flags, target triple, or tampering — investigate before accrediting.

## What evaluators should test

1. `lexicon ledger verify` on a fresh data dir (names-only OSS path).
2. `lexicon mint --seed <hex>` — must print candidates and **not** create SQLite files.
3. `lexicon ledger export` — names JSONL only by default; bindings require policy + `--bindings`.
4. Default build must not write attribution without `--include-attribution` and policy.
5. FIPS path: `lexicon --approved-mode ledger verify` with `--features fips` binary.

## Highside intro builds

For classified evaluation hosts, rebuild with:

```bash
cargo build --locked --offline --release -p lexicon-cli --features highside
# or highside,fips on the designated FIPS builder
```

Ship `policy.toml` separately per site; do not embed site policy in the public repo.

See also: [PROVENANCE.md](PROVENANCE.md), [SCRM.md](SCRM.md), [HIGH-SIDE.md](HIGH-SIDE.md).
