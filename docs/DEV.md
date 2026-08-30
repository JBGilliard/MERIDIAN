# Developer guide

Local development, feature builds, fuzzing, and CI parity for MERIDIAN / meridian-lexicon.

## Quick loop

```bash
cargo build -p lexicon-cli
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

Demo walkthrough: `scripts/demo.sh`.

## Workspace layout

| Crate | Role |
|-------|------|
| `lexicon-core` | VRF, mint, linter, Merkle ledger, signatures, marking, policy |
| `lexicon-pools` | Word lists, agencies, reject sets |
| `lexicon-cli` | `lexicon` binary |

Spec: [RFC-0001](RFC-0001.md). Operator docs: [README](../README.md), [HIGH-SIDE](HIGH-SIDE.md).

## Feature builds

```bash
# Default OSS
cargo build -p lexicon-cli

# Accredited profile (explicit --data-dir, policy.toml)
cargo build -p lexicon-cli --features highside

# FIPS 140-3 (needs cmake, ninja, go)
cargo build -p lexicon-cli --features fips
cargo test -p lexicon-core -p lexicon-cli --features fips

# Post-quantum event signatures
cargo build -p lexicon-cli --features pq

# HSM signer seam (stub)
cargo clippy -p lexicon-core --features hsm --all-targets -- -D warnings
```

Combined:

```bash
cargo build --release -p lexicon-cli --features highside,fips
```

## Local data dir

OSS default: `.meridian/` in cwd (keys + `names.sqlite`). Override:

```bash
./target/debug/lexicon --data-dir /tmp/lexicon-test key generate --agency DIA
```

Highside builds error without `--data-dir`. Place `policy.toml` in that directory — see [HIGH-SIDE.md](HIGH-SIDE.md) for schema.

## Supply-chain dev tools

```bash
cargo install cargo-deny cargo-cyclonedx cargo-audit --locked
cargo deny check
./scripts/vendor.sh
./scripts/sbom.sh
```

See [SCRM.md](SCRM.md) and [INTRO-PACKAGE.md](INTRO-PACKAGE.md).

## Fuzz

`fuzz/` is a separate Cargo workspace. **cargo-fuzz requires nightly.**

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
cd fuzz
cargo +nightly fuzz run mint_input
```

The `mint_input` target feeds arbitrary bytes into:

- VRF prove/verify round-trip (`Authority::from_seed`, `mint_alpha`)
- Pool index derivation and name composition (tiny embedded pool)
- Core linter (`LintEngine::core()`)

A panic is a bug. Corpus and artifacts are gitignored (`/fuzz/corpus`, `/fuzz/artifacts`, `/fuzz/target`).

Optional:

```bash
# Run with a timeout per input (seconds)
cargo +nightly fuzz run mint_input -- -max_total_time=300

# Minimize a crashing input
cargo +nightly fuzz tmin mint_input <crash-file>
```

Fuzz is not in default CI (nightly + long runtimes). Run before touching VRF, pools, or linter logic.

## CI parity

`.github/workflows/ci.yml` jobs:

| Job | Command |
|-----|---------|
| test | `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, hsm clippy/test |
| fips | apt install cmake ninja go; clippy + test `--features fips` |
| audit | `rustsec/audit-check` |
| deny | `cargo deny check` (EmbarkStudios/cargo-deny-action) |
| highside | `cargo check -p lexicon-cli --features highside` |
| sbom | release build + `./scripts/sbom.sh` → `lexicon.cdx.json` artifact |

Fuzz is **not** in CI (nightly + long runtimes). Run locally per [Fuzz](#fuzz) before touching VRF, pools, or linter logic.

Local pre-push:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo check -p lexicon-cli --features highside
```

## Release profile

Root `Cargo.toml`:

```toml
[profile.release]
panic = "abort"
strip = "symbols"
lto = true
codegen-units = 1
opt-level = 3
```

## musl static builds

Not shipped by default. Static musl binaries are possible with `x86_64-unknown-linux-musl` but require a musl toolchain and may affect SQLite/aws-lc linking. Document target triple and linker flags in your intro package if you ship musl — hash verification is mandatory.

## Debugging tips

- `RUST_BACKTRACE=1` for panics (dev builds only; release uses `panic=abort`).
- `lexicon --json` on any command for scriptable output.
- `lexicon ledger verify` prints crypto boundary status.
- `mint --seed <64-hex>` exercises the mint loop without touching the ledger.
