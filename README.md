# MERIDIAN

MERIDIAN is an open-source name registry for the U.S. intelligence community. The first runnable part is **meridian-lexicon**. Meridian-lexicon is the successor to NICKA.

```
lexicon mint --type nickname --agency DIA
```

## What it does

Meridian-lexicon mints names that no person can predict. Any person can verify a name.

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

A cryptonym uses a CIA digraph (`AE`, `AM`, `ZR`, `GP`, `KU`, `MK`, `LI`, `JM`, `HT`, `MH`). Only CIA carries digraphs. Other agencies have no digraphs. `mint --type cryptonym` against a non-CIA agency returns an error.

## Classification

Every issued name carries a CAPCO marking. The marking is a typed struct, not a free-form string. The mint signs it and hashes it into the event. No person can change it after the mint.

```
lexicon --classification "TS//TK//SAR-QSV//NOFORN" mint --type codeword --agency DIA
```

### CAPCO grammar

The banner order is fixed: `CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM`.

- Levels: `U`, `CUI`, `C`, `S`, `TS`.
- SCI: bare designators (`TK`, `HCS`, `SI`, `G`, `KDK`). Do not write `SCI/TK`; write `TK`.
- SAP: `SAR-<pid>` or `SAR-<pid>-<compid>` (hyphen, not slash). `SAP` is the program type, not a control.
- Dissemination: `NOFORN`, `ORCON`, `FISA`, `RSEN`, `HVSACO`, `REL TO <list>`, `WAIVED`.
- AEA: `RD-FRD`, `CNWDI`.
- FGI: `FGI` or `FGI-<country>`.

SCI and SAP designators must come from the bundled register (`crates/lexicon-pools/data/sci_register.json`, a sample — the accreditor ships the real one). REL TO accepts ISO 3166-1 alpha-3 codes and the FVEY collective. The parser rejects unknown designators and country codes. It keeps a non-standard caveat as Other and prints a warning; it is never silent.

The parser accepts legacy strings (`SCI/TK`, `SAP/QSV`) and out-of-order tokens for rows already on the ledger. It re-displays them in the new grammar. This keeps old ledgers readable.

### Banner and portion

A banner spells out the level (`TOP SECRET`) and the full dissemination names (`NOFORN`). A portion abbreviates the level (`TS`) and the dissemination names (`NF`). The CLI puts a portion in parentheses: `(TS//SAR-QSV//NF)`.

```
banner:   TOP SECRET//TK//SAR-QSV//NOFORN
portion:  (TS//SAR-QSV//NF)
```

### Nickname stays U

A nickname, an exercise term, and a SAP designator stay `UNCLASSIFIED`. The mint refuses a higher level for these name types. Only a codeword or a cryptonym carries a classified marking.

### Deconfliction

The display name has one namespace across all markings. A CUI program and a TS//SCI program cannot mint the same display name. This is the deconfliction invariant; do not change it. The collision message shows the winner marking, so a CUI operator sees when a name is held as TS//SCI and stops.

The ledger container stays unclassified. The marking is metadata about the name, not classification of the ledger. Any person can audit the ledger this way. There is no SCIF requirement to run the binary.

## Programs

A SAP program is the source of truth for a set of names. A Program owns a PID (unclassified trigraph), a nickname (two words, U), and an optional codeword (one word, classified). A Compartment is a slice of a program. A Compartment owns an ID (trigraph), a nickname (two words, U), an optional codeword, an optional parent, an optional level, and per-slice controls.

```
Program QSV (unack, TS)
  sci: TK
  dissem: NOFORN
  Compartment HOL (sci: TK)
    codeword HOLLERED  ->  TS//TK//SAR-QSV-HOL//NOFORN
  nickname DILIGENTLY IMPRESSED  ->  U
```

The mint derives a codeword marking from the program and the compartment at read time. It does not store the marking for a program-bound codeword. A `program_controls_changed` event re-derives every bound codeword retroactively. The program is the source of truth; the event log is the audit trail.

A compartment may carry a level lower than the program (e.g. TEV flight-test at S). A single-slice document takes the slice level. A multi-slice roll-up takes the maximum of the included slice levels.

### Roll-up

A roll-up compiles one SAR token for a document. Sibling compartments are hyphen-joined to the PID. Subcompartments under one compartment are space-joined. `SAR-` is not repeated per slice. `//` does not separate siblings. SCI appears in the banner only if a slice in the document carries it.

```
standing:                TOP SECRET//SAR-DILIGENTLY IMPRESSED//NOFORN
CAPCO short, all slices:  TOP SECRET//TK//SAR-QSV-HOL-PER-SEN-TEV//NOFORN
DoD, all slices:         TOP SECRET//TK//SAR-DILIGENTLY IMPRESSED//NOFORN
propulsion only:          TOP SECRET//SAR-QSV-PER//NOFORN
nested (A1 A2 under PER):  SAR-QSV-HOL-PER A1 A2-SEN-TEV
```

DoDM 5205.07: PIDs stay out of the DoD banner. The DoD banner is the standing form (program nickname, no compartment IDs). Slices live in portion marks and the `slices` field. CAPCO short and portion keep the PID and the compartment IDs.

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

Signed events bind the OS session: `whoami`, hostname, and machine-id. There is no `--user`, `--host`, `--ip`, or `--hwid`. Those strings are a claim, not a PIV/CAC attestation.

The script `scripts/demo.sh` runs an end-to-end walkthrough.

## Commands

### Global flags

| flag | effect |
|------|--------|
| `--data-dir <p>` | set the keys and ledger path (default `.meridian`) |
| `--source-dir <p>` | set the source data dir for steward edits (default `crates/lexicon-pools/data`) |
| `--json` | emit stable machine output |
| `--classification <m>` | set the floor marking for mint and export artifacts |
| `--approved-mode` | refuse to run unless the FIPS 140-3 boundary is active |

### Keys

```
lexicon key generate --agency DIA
lexicon key inspect --agency DIA
lexicon key rotate --agency DIA --co-author ODNI --reason scheduled
```

- `key generate`: make an issuing-authority keypair for the agency.
- `key inspect`: show the public key, the algorithm, and the key path.
- `key rotate`: emit a signed `key_rotated` event, then write the new key. With `--co-author <agency>` the event carries a two-part signature; the ledger stores both.

### Mint

```
lexicon mint --type nickname --agency DIA
lexicon mint --type cryptonym --agency CIA --digraph AE
lexicon mint --type codeword --agency DIA --max-attempts 128
lexicon mint --type codeword --agency USAF --program QSV --compartment HOL
```

- `--type`: set the name form.
- `--agency`: set the issuer.
- `--digraph`: set the CIA digraph for a cryptonym.
- `--max-attempts`: set how many VRF tries the mint makes before it gives up (default 64).
- `--program`: bind the name to a SAP program. A codeword or cryptonym derives its marking from the program.
- `--compartment`: bind the name to a compartment of `--program`.

The mint runs the VRF, the linter, and the uniqueness check, then writes the event. A nickname, an exercise term, and a SAP designator stay U. The mint refuses a higher level for these types.

### Verify and check

```
lexicon verify --file name.json --ledger
lexicon check --name "BLUE SPOON" --type nickname
```

- `verify`: check a minted-name JSON file (the VRF proof and the pool indices). With `--ledger` also check the name against the local ledger.
- `check`: run only the style linter on a candidate name. It does not touch the ledger.

### Retire and revoke

```
lexicon retire --name "OXIDE" --agency DIA --reason completed
lexicon revoke --name "OXIDE" --agency DIA --reason compromised --co-author ODNI
```

- `retire`: quarantine a name. The ledger never issues it again.
- `revoke`: mark a name as compromised or cancelled. With `--co-author` the event carries a two-part signature for two-person control.

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
| `verify` | check hashes and the name index; print the aggregate marking and the crypto boundary |
| `root` | show the Merkle root and the event count; `--sign` writes a signed root snapshot |
| `names` | list issued names with banners; `--marking` filters to one marking (spillage guard) |
| `lookup` | show one name: status, type, agency, marking, attribution, sequence, time |
| `history` | list name records; filter by `--agency`, `--type`, `--status`, `--marking` |
| `export` | write the full event log as JSON lines for offline audit; `-` means stdout |
| `audit` | verify the chain and every event signature against the supplied public key(s) |

`ledger audit` reports each event whose signature fails against the supplied key. A failure can mean a key rotation; the output names the seqs and tells the auditor to use the old key for those. A two-person event verifies only against both keys.

### Program

```
lexicon program create --pid QSV --nickname "DILIGENTLY IMPRESSED" \
    --codeword VEIL --sap-type unacknowledged --level TS --agency USAF \
    --dissem NOFORN
lexicon program list
lexicon program show --pid QSV
lexicon program names --pid QSV
lexicon program banner --pid QSV --slices HOL,PER,SEN,TEV --profile capco
lexicon program compartment add --program QSV --id HOL \
    --nickname "HOLLOW FRAME" --codeword RIBBED --sci TK
lexicon program compartment add --program QSV --id TEV \
    --nickname "THERMAL ECHO" --codeword PULSE --level S
lexicon program controls add --program QSV --sci SI
lexicon program controls remove --program QSV --compartment SEN --sci TK
```

| subcommand | what it does |
|-----------|--------------|
| `create` | write a `program_created` event; record the PID, the nickname, the codeword, the SAP type, the level, and the controls |
| `list` | list the programs on the ledger with the aggregate banner |
| `show` | show one program: nickname, codeword, controls, compartments, exercises, and the standing banner |
| `names` | list every name that belongs to the program (PID, nickname, codeword, compartment names, minted names) |
| `banner` | render an explicit roll-up banner for a set of slices; `--profile dod` keeps PIDs out, `--profile capco` keeps them in |
| `compartment add` | write a `compartment_added` event; record the ID, the nickname, the codeword, the parent, the level, and the per-slice controls |
| `controls add` | write a `program_controls_changed` event that adds SCI, dissem, AEA, or FGI controls |
| `controls remove` | write a `program_controls_changed` event that removes controls |

`--sap-type` accepts `acknowledged`, `unacknowledged`, `waived`. A waived SAP derives `WAIVED` in the banner before other dissemination controls.

`program show` prints the standing banner (program record, no slices). It does not print a roll-up of all compartments. Use `program banner --slices ...` for a roll-up.

`program names` is the program-scoped lexicon view. The steward-assigned names (PID, nickname, codewords) are not in the `names` table, so `ledger names` does not show them. `program names` lists them.

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

- `pool inspect`: show the bundled word lists and the agency allocations. With `--agency` and `--type` show the first and second pools for that name type.
- `pool agency`: steward commands that edit the agency allocations in the source data files.
- `pool reject`: steward commands that edit the reject lists in the source data files.

A rebuild and a `POOL_ID` bump ship a steward change into the binary. The command output says so.

Reject sets: `historical`, `military`. Agency `digraphs` are empty for non-CIA agencies. Cryptonym is a CIA convention.

The `historical` set holds real loaded codenames the tool refuses to mint — `OXCART`, `HAVE BLUE`, `MKULTRA`, `CORONA`, `STARGATE`, and the rest. The system memory of IC nomenclature is encoded as what the tool will not mint. (Have Blue was the Lockheed Skunk Works stealth demonstrator at Groom Lake that led to the F-117.)

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
| `lexicon-core` | VRF, mint loop, linter, Merkle tree, SQLite ledger, signatures, classification marking, program model |
| `lexicon-pools` | word lists, digraph taxonomy, agency letter-blocks, reject lists |
| `lexicon-cli` | the `lexicon` binary |

## License

Apache-2.0. The patent grant matters for government adoption.
