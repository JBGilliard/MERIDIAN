# High-side deployment profile

MERIDIAN's default (OSS) build is an unclassified local naming registry. The **highside** Cargo feature is the accredited profile for environments that persist classified bindings and run under an explicit data-dir policy.

This is not NICKA. Official assignment remains NICKA. MERIDIAN is a reference implementation for program-office adoption after the adopter's own RMF.

## Two-chain ledger

| File | Classification | Contents |
|------|----------------|----------|
| `names.sqlite` | Unclassified | Events (U-only canonical), name index, Merkle snapshots. Always opened. |
| `bindings.sqlite` | Classified (optional) | Binding events, markings, program/compartment records, attribution. Opened only when policy allows persistence. |

```
names.sqlite          bindings.sqlite (policy-gated)
├── events            ├── binding_events
├── names             ├── bindings
└── snapshots         ├── programs
                      ├── compartments
                      └── program_controls
```

- **names** chain: `Issued` (U canonical), `Retired`, `Revoked`, `KeyRotated`, `Attempt`. Own Merkle root and signature.
- **bindings** chain: one binding per `Issued` `event_seq` (marking + attribution + `program_pid` + `compartment_id`) plus `ProgramCreated`, `CompartmentAdded`, `ProgramControlsChanged`. Own root and signature.

Combined `ledger.sqlite` from earlier prototypes is **not** migrated. Run `lexicon ledger migrate` to quarantine it, then start clean.

## Build

```bash
cargo build --release -p lexicon-cli --features highside
```

For FIPS 140-3 event signatures and hashes, build on a designated builder with cmake, ninja, and Go installed:

```bash
cargo build --release -p lexicon-cli --features highside,fips
./target/release/lexicon --approved-mode --data-dir /path/to/data ledger verify
```

CI compiles `highside` on every PR. Full `highside,fips` release binaries are produced on an air-gapped or controlled builder documented in the intro package workflow — not on public GitHub runners.

## Data directory

Highside builds **refuse** the OSS default `.meridian` cwd path. Every command needs an explicit `--data-dir`:

```bash
lexicon --data-dir /var/lexicon/keytab mint --type nickname --agency DIA
```

`<data-dir>/policy.toml` is **required**. Missing policy is a hard error (`PolicyViolation`), not a silent OSS default.

## policy.toml

Policy is the fail-closed gate for classified persistence, attribution, and export. Argv can only **tighten** policy; it cannot relax it.

Example (accredited site — adjust to your AO's SSPP):

```toml
classification_floor = "S"
allow_persist_markings = true
allow_attribution = true
allow_export_bindings = true
allow_export_attribution = false
required_banner = "SECRET//NOFORN"
```

| Field | Meaning |
|-------|---------|
| `classification_floor` | Minimum level for mint/export artifacts. Accepts `U`, `CUI`, `C`, `S`, `TS`, or a CAPCO string (level is parsed; remainder is not echoed on error). |
| `allow_persist_markings` | Open `bindings.sqlite` and write binding/program events. Required for `--persist-markings`. |
| `allow_attribution` | Collect OS-session attribution on mint/retire/revoke/program events. |
| `allow_export_bindings` | Permit `ledger export --bindings` (classified sidecar). |
| `allow_export_attribution` | Include attribution in lookup/history/export output. |
| `required_banner` | Banner written on export when no higher aggregate exists. Must be non-empty. |

Argv flags:

| Flag | Requires |
|------|----------|
| `--persist-markings` | `allow_persist_markings = true` |
| `--include-attribution` | `allow_attribution` and/or `allow_export_attribution` (collect vs export are separate) |
| `ledger export --bindings` | `allow_export_bindings = true` |

Binding commands (`program create`, compartment/controls, program-bound mint with classified marking) return `BindingsClosed` when `bindings.sqlite` is not open.

## Export defaults

- Default export is **names only** (unclassified chain).
- `--bindings` writes a second JSONL file (`<file>.bindings.jsonl`) with a classification banner header. Requires policy.
- Attribution is redacted from export unless `--include-attribution` and policy allow it.
- Highside deployments should treat the bindings sidecar as classified at rest and in transit.

## Operator checklist

1. Place `policy.toml` in `--data-dir` before any mint.
2. Generate authority keys under `<data-dir>/keys/`.
3. Use `--persist-markings` only when policy allows and the host is accredited for classified SQLite.
4. Never copy `bindings.sqlite` to unclassified systems without redaction and an approved transfer path.
5. Keep sample pool data (`sci_register.json`, `agencies.json`) off production; ship the accreditor's registers.

## Feature matrix

| Profile | Features | Notes |
|---------|----------|-------|
| OSS default | (none) | `.meridian` default, no bindings file, no attribution |
| Highside | `highside` | Explicit `--data-dir`, `policy.toml` required |
| FIPS | `fips` | AWS-LC for SHA-256 / Ed25519 / ML-DSA; ECVRF stays curve25519 |
| Post-quantum sigs | `pq` | ML-DSA-65 event signatures (young crate; evaluate in SSPP) |
| HSM seam | `hsm` | `RemoteVrfSigner` stub; proxy not shipped |

See also: [INTRO-PACKAGE.md](INTRO-PACKAGE.md), [SECURITY.md](../SECURITY.md), [RFC-0001](RFC-0001.md).
