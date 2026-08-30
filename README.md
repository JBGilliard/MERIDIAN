# MERIDIAN

Open-source name registry for the U.S. intelligence community. The first runnable part is **meridian-lexicon**, the successor to NICKA.

```
lexicon mint --type nickname --agency DIA
```

## What it does

Meridian-lexicon mints names that no person can predict and any person can verify.

- A name comes from a verifiable random function (VRF). The VRF is ECVRF-EDWARDS25519-SHA512-TAI, [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html).
- Each name is unique on one ledger. The ledger is SQLite and append-only. A Merkle tree binds the events in order.
- A style linter rejects a name before the ledger writes it. The linter blocks JANAP-119A Table II call signs, historical CIA cryptonyms, U.S. military acronyms, weapon names, and meaning-leak tokens.
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

Every issued name carries a CAPCO marking. The marking is a typed struct, not a free-form string. The mint signs it and hashes it into the event, so no person can change it after the mint.

```
lexicon --classification "TS//NOFORN//SCI/TK" mint --type codeword --agency DIA
```

The parser accepts `U`, `CUI`, `C`, `S`, `TS`; the caveats `NOFORN`, `ORCON`, `FISA`, `RSEN`, `HVSACO`, `REL TO <list>`; and the compartments `SCI/<dg>`, `SAP/<dg>`, `RD-FRD`, `CNWDI`. SCI and SAP designators must come from the bundled register (`crates/lexicon-pools/data/sci_register.json`, a sample — the accreditor ships the real one). REL TO accepts ISO 3166-1 alpha-3 codes and the FVEY collective. The parser rejects unknown SCI/SAP designators and country codes. It keeps a non-standard caveat as Other and the CLI prints a warning; it is never silent.

The ledger container stays unclassified. The marking is metadata about the name, not classification of the ledger. Any person can audit the ledger this way, with no SCIF requirement to run the binary.

The display name has one namespace across all markings. A CUI program and a TS//SCI program cannot mint the same display name. This is the deconfliction invariant; do not change it. The collision message shows the winner's marking, so a CUI operator sees when a name is held as TS//SCI and stops.

### Banners

Every command that shows a name prints the classification at the top and the bottom of the page. The page marking is the maximum of the displayed content, floored by `--classification`. This is the CAPCO rule: a container takes the highest marking of its contents. If one name is `TS//SCI`, the page is `TS//SCI`.

```
===== CLASSIFICATION: TS//SCI//TK ======
----------------------------------------
  AVOS           TS//SCI//TK
  EGGCUP         CUI
----------------------------------------
===== CLASSIFICATION: TS//SCI//TK ======
```

`--marking <m>` filters the displayed content to one marking. This is the spillage guard. A CUI-only workstation runs `ledger names --marking CUI` and never puts a TS name into its logs. The banner is then `CUI`, the max of the filtered set.

`--classification <m>` is a floor, not a filter. It can raise the banner (add a caveat by policy) but cannot lower it below the content max.

`ledger verify` shows the ledger's aggregate marking: the max of every name in the ledger. If the ledger holds one `TS//SCI` name, the ledger file is `TS//SCI`. It also prints a `STATUS` line that names the crypto boundary (rustcrypto vs AWS-LC FIPS 140-3).

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

Signed events bind the OS session: `whoami`, hostname, and machine-id. There is no `--user` / `--host` / `--ip` / `--hwid`. Those strings are a claim, not a PIV/CAC attestation.

The script `scripts/demo.sh` runs an end-to-end walkthrough.

## Commands

### Global flags

| flag | effect |
|------|--------|
| `--data-dir <p>` | keys and ledger path (default `.meridian`) |
| `--source-dir <p>` | source data dir for steward edits (default `crates/lexicon-pools/data`) |
| `--json` | stable machine output |
| `--classification <m>` | floor marking baked into mint/export artifacts |
| `--approved-mode` | refuse to run unless the FIPS 140-3 boundary is active |

### Keys

```
lexicon key generate --agency DIA
lexicon key inspect --agency DIA
lexicon key rotate --agency DIA --co-author ODNI --reason scheduled
```

`key generate` makes an issuing-authority keypair. `key inspect` shows the public key, the algorithm, and the key path. `key rotate` emits a signed `key_rotated` event, then writes the new key. With `--co-author <agency>` the event carries a two-part signature; the ledger stores both.

### Mint

```
lexicon mint --type nickname --agency DIA
lexicon mint --type cryptonym --agency CIA --digraph AE
lexicon mint --type codeword --agency DIA --max-attempts 128
```

`--type` sets the name form. `--agency` sets the issuer. `--digraph` sets the CIA digraph for a cryptonym. `--max-attempts` sets how many VRF tries the mint makes before it gives up (default 64). The mint runs the VRF, the linter, and the uniqueness check, then writes the event.

### Verify and check

```
lexicon verify --file name.json --ledger
lexicon check --name "BLUE SPOON" --type nickname
```

`verify` checks a minted-name JSON file: the VRF proof and the pool indices. With `--ledger` it also checks the name against the local ledger. `check` runs only the style linter on a candidate name; it does not touch the ledger.

### Retire and revoke

```
lexicon retire --name "OXIDE" --agency DIA --reason completed
lexicon revoke --name "OXIDE" --agency DIA --reason compromised --co-author ODNI
```

`retire` quarantines a name; the ledger never issues it again. `revoke` marks a name as compromised or cancelled. With `--co-author` the event carries a two-part signature for two-person control.

### Ledger

```
lexicon ledger verify
lexicon ledger root --sign --agency DIA
lexicon ledger names --marking CUI
lexicon ledger lookup --name "GRANITE SPIRE"
lexicon ledger history --agency DIA --type nickname --status issued --marking CUI
lexicon ledger export --file audit.jsonl
lexicon ledger audit --public-key <pk>
lexicon ledger audit --public-key <pk1> --public-key <pk2>
```

| subcommand | what it does |
|-----------|--------------|
| `verify` | checks hashes and the name index; prints the aggregate marking and the crypto boundary |
| `root` | shows the Merkle root and the event count; `--sign` writes a signed root snapshot |
| `names` | lists issued names with banners; `--marking` filters to one marking (spillage guard) |
| `lookup` | shows one name: status, type, agency, marking, attribution, sequence, time |
| `history` | lists name records; filters by `--agency`, `--type`, `--status`, `--marking` |
| `export` | writes the full event log as JSON lines for offline audit; `-` means stdout |
| `audit` | verifies the chain and every event signature against the supplied public key(s) |

`ledger audit` reports each event whose signature fails against the supplied key. A failure can mean a key rotation; the output names the seqs and tells the auditor to use the old key for those. A two-person event verifies only against both keys.

### Pool

```
lexicon pool inspect
lexicon pool inspect --agency DIA --type nickname
lexicon pool agency list
lexicon pool agency add --id USAF --first-letters ABCDE --digraphs AE,AM --sap TK
lexicon pool agency remove --id USAF
lexicon pool reject list --set historical
lexicon pool reject add --set historical --token TICTAC
lexicon pool reject remove --set historical --token TICTAC
```

`pool inspect` shows the bundled word lists and the agency allocations. With `--agency` and `--type` it shows the first and second pools for that name type. `pool agency` and `pool reject` are steward commands: they edit the source data files. A rebuild and a `POOL_ID` bump ship the change into the binary. The command output says so.

Reject sets: `historical`, `military`. Agency `digraphs` are empty for non-CIA agencies. Cryptonym is a CIA convention.

The `historical` set holds real loaded codenames the tool refuses to mint — `OXCART`, `HAVE BLUE`, `MKULTRA`, `CORONA`, `STARGATE`, and the rest. The system's memory of IC nomenclature is encoded as what it will not mint. (Have Blue was the Lockheed Skunk Works stealth demonstrator at Groom Lake that led to the F-117.)

## Signatures

Event signatures are Ed25519. A signature is a list of parts, not one part. One part is the common case; two parts enable two-person control and a future hybrid scheme. The signature blob is not part of `canonical` and the Merkle tree does not hash it, so the wire format can change without a ledger-format break.

The signature algorithm is a field on the key, not on the message. A future move to ML-DSA (FIPS 204) is one `key_rotated` event that names the new algorithm. The ledger format does not change.

ML-DSA-65 is built behind the `pq` feature (`cargo build --features pq`). The default build stays Ed25519-only; with `pq`, `SigAlg::MlDsa65` signs and verifies for real. A ledger that carries ML-DSA signatures reads (canonical + Merkle) in either build; only the `pq` build verifies the signatures.

The VRF is separate from event signatures. No post-quantum VRF standard exists yet. The VRF stays ECVRF-ed25519-TAI (NSA-approved SC-13(2), not FIPS-validated) until one does.

### FIPS 140-3

The default build uses rustcrypto (`sha2`, `ed25519-dalek`). `--features fips` routes SHA-256, Ed25519, and ML-DSA through AWS-LC (FIPS 140-3 module; cmake and go must compile). ECVRF stays on curve25519-dalek — no validated module implements it; the accreditor accepts SC-13(2) in the SSPP.

```
cargo build -p lexicon-cli --release --features fips
./target/release/lexicon --approved-mode ledger verify
```

`--approved-mode` exits unless the FIPS module is in FIPS mode and the SHA-256 and Ed25519 known-answer tests pass. `ledger verify` prints `STATUS crypto-boundary=...` so the AO can grep it.

## What this is not

Meridian-lexicon is a reference implementation, not a deployed system. These items are specified, not built:

- federation across authorities (pre-commit, quorum, loser-recall);
- a live authoritative reject feed or SCI/SAP register (the bundled lists are samples);
- post-quantum transport (ML-KEM, FIPS 203);
- HSM-backed key storage (`VrfSigner` / `RemoteVrfSigner` behind `--features hsm` is the seam; the proxy is unbuilt. Seed custody is the accreditor's — see [RFC-0001 §3.1](docs/RFC-0001.md));
- PIV/CAC user binding (events carry an OS-session claim; AU-10 non-repudiation waits on the HSM profile).

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
