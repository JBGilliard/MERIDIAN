# MERIDIAN

**MERIDIAN-lexicon** is an open-source local naming registry. It mints un-guessable names with a verifiable random function (VRF), verifies names against an append-only ledger and word pools, and records every mint, retirement, and revocation with a Merkle chain.

Not endorsed, influenced, or sponsored by any U.S. government agency, including the Department of War or any element of the Intelligence Community.

This is not NICKA. Official IC name assignment stays with NICKA. MERIDIAN-lexicon is not a system of record and not an IC enterprise service — it ships as government-off-the-shelf (GOTS) reference software that a program office runs on its own infrastructure, under its own accreditation.

The repository and bundled pool data are UNCLASSIFIED. Bundled registers are development and test samples, not authoritative data. Production hosts use accreditor-approved registers and store classified bindings under site policy — see [docs/HIGH-SIDE.md](docs/HIGH-SIDE.md).

```
lexicon mint --type nickname --agency DIA
```

## Operating model

Each program office runs its own instance against its own ledger. A program office supplies its authority keys, its SCI/SAP registers, and its own RMF accreditation. There is no shared or federated service in this version — [RFC-0001](docs/RFC-0001.md) specifies federation, live authoritative registers, post-quantum transport, and HSM/PIV binding as future capabilities, not shipped ones.

Default (OSS) builds write only the unclassified names chain, in `.meridian/` in the working directory. The `highside` feature adds a second, policy-gated, classified bindings chain and requires an explicit `--data-dir` and a `policy.toml` — no implicit cwd path. See [docs/HIGH-SIDE.md](docs/HIGH-SIDE.md).

## Architecture

- A name comes from a verifiable random function (VRF): ECVRF-EDWARDS25519-SHA512-TAI, [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html). Nobody without the authority's secret key can predict the next name; anyone with the authority's public key can verify one that was issued.
- Each name is unique on one ledger. The ledger is SQLite and append-only; a Merkle tree binds its events in order.
- A style linter rejects a candidate name before the ledger writes it: JANAP-119A Table II call signs, historical CIA cryptonyms, U.S. military acronyms, weapon names, and meaning-leak tokens.
- Retired and revoked names stay on the ledger and are never reissued.
- Every issued name carries a typed CAPCO marking, signed and hashed into its event. `nickname`, `exercise`, and `sap` names always stay `U`; only `codeword` and `cryptonym` names carry a classified marking. See [RFC-0001 §4](docs/RFC-0001.md) for the marking grammar and [docs/HIGH-SIDE.md](docs/HIGH-SIDE.md) for the two-chain ledger that keeps markings out of the unclassified names chain.
- A SAP program is the source of truth for a set of names; a codeword or cryptonym bound to a program derives its marking from current program controls at read time. See [RFC-0001 §5](docs/RFC-0001.md) for programs, compartments, and CAPCO roll-up.

| crate | role |
|-------|------|
| `lexicon-core` | VRF, mint loop, linter, Merkle tree, SQLite ledger, signatures, classification marking, program model |
| `lexicon-pools` | word lists, digraph taxonomy, agency letter-blocks, reject lists |
| `lexicon-cli` | the `lexicon` binary |

## Name types

| type | form | example |
|------|------|---------|
| `nickname` | two words, space, uppercase | `GRANITE SPIRE` |
| `codeword` | one word | `OXIDE` |
| `cryptonym` | digraph + word, no space | `AELANTERN` |
| `sap` | digraph or trigraph | `TK`, `HCS` |
| `exercise` | two words from the exercise pool | `COPPER RELAY` |

A cryptonym uses a CIA digraph (`AE`, `AM`, `ZR`, `GP`, `KU`, `MK`, `LI`, `JM`, `HT`, `MH`; see [crates/lexicon-pools/data/digraphs.md](crates/lexicon-pools/data/digraphs.md)). Only CIA carries digraphs; `mint --type cryptonym` against a non-CIA agency returns an error.

## Quick start

```bash
cargo build -p lexicon-cli
./target/debug/lexicon key generate --agency DIA
./target/debug/lexicon key generate --agency CIA
./target/debug/lexicon mint --type nickname --agency DIA
./target/debug/lexicon mint --type cryptonym --agency CIA --digraph AE
./target/debug/lexicon check --name "BLUE SPOON"
./target/debug/lexicon ledger verify
```

Run `lexicon --help` for the full command and flag reference, including `--marking-file`/`--binding-file`, `--json`, `--include-attribution`, and `--approved-mode`. Run `scripts/demo.sh` for an end-to-end walkthrough. On accredited hosts, put classification markings in a marking or binding file; do not put classified strings on the command line.

## Security boundary

Attribution (OS-session identity, not PIV/CAC) is off by default and requires an explicit flag and policy permission. Classified persistence and export are policy-gated and fail closed. Default crypto is Ed25519/SHA-256 via RustCrypto; `--features fips` routes signatures and hashing through an AWS-LC FIPS 140-3 module. The VRF stays ECVRF-ed25519-TAI (NSA-approved SC-13(2), not FIPS-validated) until a post-quantum VRF standard exists.

See [SECURITY.md](SECURITY.md) for the full threat model, scope, and vulnerability-reporting process.

## Documentation

| Doc | Audience |
|-----|----------|
| [RFC-0001](docs/RFC-0001.md) | Protocol and format spec: names, VRF, markings, programs, ledger, linter, federation sketch |
| [docs/DEV.md](docs/DEV.md) | Developers (build, test, fuzz, CI parity) |
| [docs/HIGH-SIDE.md](docs/HIGH-SIDE.md) | Accredited high-side deployment, two-chain ledger, `policy.toml` |
| [docs/INTRO-PACKAGE.md](docs/INTRO-PACKAGE.md) | Intro artifact bundle for program-office evaluation |
| [docs/SCRM.md](docs/SCRM.md) | Supply chain (deny, vendor, SBOM) |
| [docs/PROVENANCE.md](docs/PROVENANCE.md) | Build and artifact traceability |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and threat model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

## License

Apache-2.0.
