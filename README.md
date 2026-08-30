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

A cryptonym uses a CIA digraph (`AE`, `AM`, `ZR`, `GP`, `KU`, `MK`, `LI`, `JM`, `HT`, `MH`). Only CIA carries digraphs. Other agencies have no digraphs. `mint --type cryptonym` against them returns an error.

## Classification

Every issued name carries a CAPCO marking. The marking is a typed struct, not a free-form string. It is signed and hashed into the event, so it cannot be changed after the mint.

```
lexicon --classification "TS//NOFORN//SCI/TK" mint --type codeword --agency DIA
```

The parser accepts `U`, `CUI`, `C`, `S`, `TS`, the caveats `NOFORN`, `ORCON`, `FISA`, `RSEN`, `REL TO <list>`, and the compartments `SCI/<dg>`, `SAP/<dg>`, `RD-FRD`, `CNWDI`. Unknown tokens are rejected at the CLI.

The ledger container stays unclassified. The marking is metadata about the name, not classification of the ledger. This keeps the ledger auditable by anyone, with no SCIF requirement to run the binary.

The display name has one namespace across all markings. A CUI program and a TS//SCI program cannot mint the same display name. This is the deconfliction invariant; do not change it. The collision message shows the winner's marking, so a CUI operator sees when a name is held as TS//SCI and stops.

### Banners

Every name-displaying command prints the classification at the top and the bottom of the page. The page marking is the maximum of the displayed content, floored by `--classification`. This is the CAPCO rule: a container takes the highest marking of its contents. If one name is `TS//SCI`, the page is `TS//SCI`.

```
CLASSIFICATION: TS//SCI//TK
----------------------------------------
  AVOS           TS//SCI//TK
  EGGCUP         CUI
----------------------------------------
CLASSIFICATION: TS//SCI//TK
```

`--marking <m>` filters the displayed content to one marking. This is the spillage guard. A CUI-only workstation runs `ledger names --marking CUI` and never materializes a TS name into its logs. The banner is then `CUI`, the max of the filtered set.

`--classification <m>` is a floor, not a filter. It can raise the banner (add a caveat by policy) but cannot lower it below the content max.

`ledger verify` shows the ledger's aggregate marking: the max of every name in the ledger. If the ledger holds one `TS//SCI` name, the ledger file is `TS//SCI`.

```
lexicon ledger names                      # banners + per-name marking
lexicon ledger names --marking CUI        # spillage guard
lexicon ledger lookup --name "GRANITE SPIRE"
lexicon ledger history --marking CUI
lexicon ledger verify                     # shows the aggregate marking
lexicon ledger export --file audit.jsonl  # banner = aggregate of exported events
```

## Quick start

```bash
cargo build -p lexicon-cli
./target/debug/lexicon key generate --agency DIA
./target/debug/lexicon mint --type nickname --agency DIA
./target/debug/lexicon mint --type cryptonym --agency CIA --digraph AE
./target/debug/lexicon check --name "BLUE SPOON"
./target/debug/lexicon ledger verify
./target/debug/lexicon pool inspect
```

Keys and the ledger go in `.meridian/`. Use `--data-dir` to change this path.

Add `--json` to any command for stable machine output (scripts, CI). The default is human-readable.

End-to-end walkthrough: `scripts/demo.sh`.

## Keys and control

```
lexicon key generate --agency DIA
lexicon key inspect --agency DIA
lexicon key rotate --agency DIA --co-author ODNI    # two-person control
lexicon revoke --name "OXIDE" --agency DIA --co-author ODNI --reason compromised
```

Two-person control: `key rotate --co-author <agency>` and `revoke --co-author <agency>` sign the event with both authorities. The ledger stores a two-part signature. `ledger audit --public-key <pk>` accepts multiple keys; a two-person event verifies only against both.

## Audit

```
lexicon ledger verify                              # hashes and name index
lexicon ledger audit --public-key <pk>            # + every signature
lexicon ledger audit --public-key <pk1> --public-key <pk2>   # two-person
lexicon ledger export --file audit.jsonl          # full event log for offline audit
```

`ledger audit` reports each event whose signature fails against the supplied key. A failure can mean a key rotation; the output names the seqs and tells the auditor to use the old key for those.

## Signatures

Event signatures are Ed25519. A signature is a list of parts, not one part. One part is the common case; two parts enable two-person control and a future hybrid scheme. The signature blob is not part of `canonical` and is not hashed into the Merkle tree, so the wire format can change without a ledger-format break.

The signature algorithm is a field on the key, not on the message. A future move to ML-DSA (FIPS 204) is one `key_rotated` event that names the new algorithm. The ledger format does not change.

ML-DSA-65 is implemented behind the `pq` feature (`cargo build --features pq`). The default build stays Ed25519-only; with `pq`, `SigAlg::MlDsa65` signs and verifies for real. A ledger carrying ML-DSA signatures reads (canonical + Merkle) in either build; only the `pq` build verifies the signatures.

The VRF is separate from event signatures. No post-quantum VRF standard exists yet. The VRF stays ECVRF-ed25519-TAI until one does.

## Steward commands

`pool agency` and `pool reject` edit the source data files. A rebuild and a `POOL_ID` bump ship the change into the binary. The commands say so in their output.

```
lexicon pool agency list
lexicon pool agency add --id USAF --first-letters ABCDE --sap TK
lexicon pool agency remove --id USAF
lexicon pool reject list --set historical
lexicon pool reject add --set historical --token TICTAC
lexicon pool reject remove --set historical --token TICTAC
```

Reject sets: `historical`, `military`. Agency `digraphs` are empty for non-CIA agencies. Cryptonym is a CIA convention.

The `historical` set holds real loaded codenames the tool refuses to mint — `OXCART`, `HAVE BLUE`, `MKULTRA`, `CORONA`, `STARGATE`, and the rest. The system's memory of IC nomenclature is encoded as what it won't mint. (Have Blue was the Lockheed Skunk Works stealth demonstrator at Groom Lake that led to the F-117.)

## What this is not

Meridian-lexicon is a reference implementation, not a deployed system. These items are specified, not built:

- federation across authorities (pre-commit, quorum, loser-recall);
- FIPS 140-3 module boundary;
- a live authoritative reject feed (the bundled lists are samples);
- post-quantum transport (ML-KEM, FIPS 203);
- HSM-backed key storage (the VRF takes the raw seed; an HSM cannot drive it — see the split-authority design in [RFC-0001 §3.1](docs/RFC-0001.md)).

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
| `lexicon-core` | VRF, mint loop, linter, Merkle tree, SQLite ledger, signatures, classification marking |
| `lexicon-pools` | word lists, digraph taxonomy, agency letter-blocks, reject lists |
| `lexicon-cli` | the `lexicon` binary |

## License

Apache-2.0. The patent grant matters for government adoption.
