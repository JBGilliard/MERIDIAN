# MERIDIAN

Open-source name registry for the U.S. intelligence community. This repository ships the first runnable slice: **meridian-lexicon**, the successor to NICKA.

```
lexicon mint --type nickname --agency DIA
```

## What this does

Meridian-lexicon mints names that no one can predict and anyone can verify.

- A name comes from a verifiable random function (VRF). The VRF is ECVRF-EDWARDS25519-SHA512-TAI, [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html).
- Each name is unique on one ledger. The ledger is SQLite and append-only. A Merkle tree binds the events in order.
- A style linter rejects a name before it is written. The linter blocks JANAP-119A Table II call signs, historical CIA cryptonyms, U.S. military acronyms, weapon names, and meaning-leak tokens.
- Retired and revoked names stay on the ledger. The ledger does not issue them again.

## Name types

| type | form | example |
|------|------|---------|
| `nickname` | two words, space, uppercase | `GRANITE SPIRE` |
| `codeword` | one word | `OXIDE` |
| `cryptonym` | digraph + word, no space | `AELANTERN` |
| `sap` | digraph or trigraph | `TK`, `HCS` |
| `exercise` | two words from the exercise pool | `COPPER RELAY` |

A cryptonym uses a CIA digraph (`AE`, `AM`, `ZR`, `GP`, `KU`, `MK`, `LI`, `JM`, `HT`, `MH`). Only CIA carries digraphs. Other agencies have no digraphs; `mint --type cryptonym` against them returns an error.

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

Keys and the ledger go in `.meridian/`. Use `--data-dir` to change this path.

End-to-end walkthrough: `scripts/demo.sh`.

## Signatures

Event signatures are Ed25519. The signature algorithm is a field on the key, not on the message. A future move to ML-DSA (FIPS 204) is one `key_rotated` event that names the new algorithm. The ledger format does not change.

The VRF is separate from event signatures. No post-quantum VRF standard exists yet. The VRF stays ECVRF-ed25519-TAI until one does.

## What this is not

Meridian-lexicon is a reference implementation, not a deployed system. These items are specified, not built:

- federation across authorities (pre-commit, quorum, loser-recall);
- FIPS 140-3 module boundary;
- a live authoritative reject feed (the bundled lists are samples);
- post-quantum transport (ML-KEM, FIPS 203).

See [docs/RFC-0001.md](docs/RFC-0001.md) for the full specification.

## Fuzz

`fuzz/` is a separate Cargo workspace. cargo-fuzz requires the nightly toolchain.

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run mint_input
```

The target pushes arbitrary seeds through VRF prove/verify, pool indexing, and the linter. A panic is a bug.

## Crates

| crate | role |
|-------|------|
| `lexicon-core` | VRF, mint loop, linter, Merkle tree, SQLite ledger, signatures |
| `lexicon-pools` | word lists, digraph taxonomy, agency letter-blocks, reject lists |
| `lexicon-cli` | the `lexicon` binary |

## License

Apache-2.0. The patent grant matters for government adoption.
