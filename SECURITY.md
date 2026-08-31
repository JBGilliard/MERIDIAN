# Security

## Reporting vulnerabilities

Do **not** open public GitHub issues for exploitable vulnerabilities in accredited or classified deployments.

Contact the repository maintainers through your program office's established disclosure channel. Include:

- Affected commit or intro package hash (`SHA256SUMS`)
- Feature flags (`fips`, `highside`, `pq`)
- Reproduction steps on an unclassified fixture if possible
- Impact assessment (ledger integrity, key material, classification spillage)

## Scope and threat model

MERIDIAN-lexicon is a **local** naming registry reference implementation. It is not NICKA and not a federated IC enterprise service.

**In scope**

- Integrity of the append-only ledger (Merkle chain, event signatures)
- Unpredictability of minted names (VRF secrecy)
- Fail-closed policy (no silent classified persistence or export)
- Deconfliction across markings (one display-name namespace)
- Style linter rejecting loaded sensitive tokens

**Out of scope (specified, not built)**

- Cross-authority federation, quorum, loser-recall
- Live authoritative SCI/SAP registers (bundled data is sample)
- PIV/CAC user binding (attribution is OS-session claim only)
- HSM-backed production deployment (seam exists; proxy not shipped)
- Post-quantum transport (ML-KEM)

Assume an operator with shell access can exfiltrate anything they can read — including `bindings.sqlite` if they enabled persistence. Policy and argv gates reduce accidental spillage; they do not stop a malicious insider.

## Classification boundaries

| Component | Default classification |
|-----------|------------------------|
| Public repo + OSS binary | UNCLASSIFIED |
| `names.sqlite` | UNCLASSIFIED (U-only canonical events) |
| `bindings.sqlite` | Born classified when used; opt-in via policy |
| Sample pool JSON | UNCLASSIFIED, not authoritative |
| Export default | Names chain only |
| Export `--bindings` | Classified sidecar; policy + banner required |

Highside builds require explicit `--data-dir` and `policy.toml`. OSS builds default to no bindings file and no attribution.

## Cryptography

| Mechanism | Implementation | FIPS notes |
|-----------|----------------|------------|
| Event signatures | Ed25519 (default); ML-DSA-65 with `--features pq` | `fips` → AWS-LC for Ed25519/SHA-256/ML-DSA |
| VRF | ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) | Not FIPS-validated; SC-13(2) path |
| Merkle tree | SHA-256 | FIPS path uses AWS-LC |
| Keys at rest | Local JSON seeds (OSS) | HSM profile is adopter responsibility |

`--approved-mode` refuses to run unless the FIPS module is active and KATs pass (`--features fips`).

## Safe defaults (OSS)

Confirmed behavior evaluators should re-check on each release:

- No attribution unless `--include-attribution` **and** policy allows
- No `bindings.sqlite` unless `--persist-markings` **and** policy allows
- `ledger export` writes names only unless `--bindings` **and** policy allows
- `mint --seed` performs a dry run — **no** SQLite writes
- Legacy `ledger.sqlite` refuses open; migrate quarantines it

## Residual risks

- **SQLite** (C, bundled): memory-safety boundary in the Rust↔C FFI; track CVEs.
- **ECVRF on curve25519**: outside FIPS boundary; threat acceptance required.
- **ML-DSA (`pq`)**: optional, relatively new dependency.
- **Classification argv**: `--classification` on the command line is argv-audited; prefer marking files on high side when implemented.
- **Error messages**: parser avoids echoing full CAPCO+PID+compartment in errors; still treat logs as sensitive on classified hosts.

## Hardening recommendations for adopters

1. Run highside + FIPS on accredited OS builds; use `--approved-mode` in production scripts.
2. Separate unclassified names hosts from classified bindings hosts when possible.
3. Restrict filesystem permissions on `--data-dir` and keys.
4. Replace sample registers before any real SAP/SCI mint.
5. Ship intro package through signed, hash-verified transfer; rebuild offline when required.
6. Do not commit `policy.toml`, keys, or ledger files to git.

See also: [docs/HIGH-SIDE.md](docs/HIGH-SIDE.md), [docs/SCRM.md](docs/SCRM.md), [RFC-0001](docs/RFC-0001.md).
