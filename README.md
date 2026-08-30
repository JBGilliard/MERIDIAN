# MERIDIAN

Open-source registry + deconfliction + nomenclature. Code is public; keys, data, and operational configuration never are.

This repository ships the first runnable slice: **meridian-lexicon**, the NICKA successor.

```
lexicon mint --type nickname --agency DIA
```

Names nobody can guess. A ledger that will not issue the same one twice.

## What this is

A reference implementation of deterministic, auditable name minting:

- **VRF-keyed** (ECVRF-EDWARDS25519-SHA512-TAI, [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html)). Pools can be public. Guessing resistance comes from the key, not a secret word list.
- **Globally unique** within a single-authority ledger. Retired and revoked names stay quarantined.
- **Style-linted** before commit. No pop-culture leftovers, no JANAP-119 collisions on the shipped sample list, no meaning-leaking pairs.
- **Legacy-capable.** Emits CIA-style cryptonyms (`AE` + word), SAP digraphs/trigraphs, single-word code words, and a distinct exercise-term namespace.

It is not a deployed IC system. Federation, PSI, FIPS 140-3 certification, and any statutory mandate are specified, not built. See [docs/RFC-0001.md](docs/RFC-0001.md).

## Quick start

```bash
cargo build -p lexicon-cli
./target/debug/lexicon keygen --agency DIA
./target/debug/lexicon mint --type nickname --agency DIA
./target/debug/lexicon mint --type cryptonym --agency CIA --digraph AE
./target/debug/lexicon check --name "BLUE SPOON"
./target/debug/lexicon ledger verify
./target/debug/lexicon pool inspect
```

Keys and the SQLite ledger land in `.meridian/` (override with `--data-dir`).

End-to-end walkthrough: `scripts/demo.sh`.

## Fuzz

`fuzz/` is its own Cargo workspace (cargo-fuzz requires that). Needs nightly:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run mint_input
```

The target feeds arbitrary seeds through VRF prove/verify, pool indexing, and the linter. A panic is a bug.

## Crates

| crate | role |
|-------|------|
| `lexicon-core` | VRF, mint loop, linter, Merkle log, SQLite ledger |
| `lexicon-pools` | Word lists, open-record digraph taxonomy, agency letter-blocks |
| `lexicon-cli` | `lexicon` binary |

## License

Apache-2.0. The patent grant matters for government adoption.
