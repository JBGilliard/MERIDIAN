# Supply chain risk management (SCRM)

MERIDIAN is Rust + crates.io dependencies + a bundled SQLite (via `rusqlite` `bundled`). This document is the adopter-facing SCRM summary. Details live in repo config and scripts.

## Policy files

| File | Role |
|------|------|
| `deny.toml` | `cargo deny check` — licenses, advisories, duplicate crates, source allowlist |
| `Cargo.lock` | Locked dependency graph; required for `--locked` / vendor / intro package |
| `rust-toolchain.toml` | Pinned `rustc` 1.85.0, `profile = default` |
| `.cargo/config.toml.example` | Vendored-sources replace for air-gap (`../vendor`) |

## cargo deny

```bash
cargo install cargo-deny --locked
cargo deny check
```

`deny.toml` configuration:

- **Advisories:** yanked crates denied; known vulnerabilities fail the check. Unmaintained crates warn (scripts pass `-W unmaintained` where supported).
- **Licenses:** allow-list only — MIT, Apache-2.0, BSD-2/3, ISC, Unicode-3.0, Zlib, CC0-1.0, NCSA, OpenSSL. Confidence threshold 0.93.
- **Bans:** duplicate versions warn (investigate, don't blindly allow).
- **Sources:** `crates.io` only. Unknown registries and git dependencies denied.

Intro package build embeds `deny-report.txt` via `scripts/release-sign.sh`.

## Vendoring

```bash
./scripts/vendor.sh           # writes vendor/
./scripts/vendor.sh --tarball # also dist/vendor.tar.gz
```

Air-gap sites copy `.cargo/config.toml.example` → `.cargo/config.toml` and build with `cargo build --locked --offline`. Do not commit `.cargo/config.toml` — networked CI must keep fetching from crates.io.

## SBOM

```bash
cargo install cargo-cyclonedx --locked
./scripts/sbom.sh                    # target/release/lexicon.cdx.json
./scripts/sbom.sh dist/lexicon       # next to staged binary
```

Format: CycloneDX JSON (spec 1.5 when supported). Shipped in the intro package as `lexicon.cdx.json`.

## CI and audit

GitHub Actions (`.github/workflows/ci.yml`):

- `fmt`, `clippy -D warnings`, `test` (workspace)
- `fips` job (cmake, ninja, go; clippy + test with `--features fips`)
- `cargo-audit` via `rustsec/audit-check`
- `cargo deny check` via `EmbarkStudios/cargo-deny-action`
- `highside` compile check (`cargo check -p lexicon-cli --features highside`)
- `sbom` job (release build + `./scripts/sbom.sh`; artifact `lexicon.cdx.json`)

Accredited release pipelines also embed `deny-report.txt` and SBOM in the intro package per [INTRO-PACKAGE.md](INTRO-PACKAGE.md).

## Residual supply-chain risks

| Risk | Mitigation / note |
|------|-------------------|
| SQLite C code (`rusqlite` bundled) | Track upstream SQLite advisories; rebuild on CVE |
| AWS-LC (`--features fips`) | Large native build graph; FIPS module boundary in SSPP |
| curve25519 / ECVRF | Outside FIPS module; SC-13(2) acceptance documented in README |
| `ml-dsa` (`--features pq`) | Young crate; optional; evaluate before production PQ cutover |
| Operator-introduced git/path deps | Denied by `deny.toml`; don't patch around it in production |

## Transfers to classified enclaves

1. Verify `SHA256SUMS` and detached signatures on the intro package.
2. Rebuild offline from `vendor.tar.gz` inside the enclave when policy requires bitwise reproducibility checks.
3. Import SBOM into the adopter's component inventory (e.g. eMASS, OWASP Dependency-Track).
4. Record `deny-report.txt` and advisory scan date in the POA&M if findings are accepted.

See also: [PROVENANCE.md](PROVENANCE.md), [INTRO-PACKAGE.md](INTRO-PACKAGE.md).
