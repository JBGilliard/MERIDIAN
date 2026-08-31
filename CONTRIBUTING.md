# Contributing

MERIDIAN is an open-source reference implementation for IC nomenclature and deconfliction. Contributions are welcome; production accreditation remains each adopter's responsibility.

## Before you start

1. Read [RFC-0001](docs/RFC-0001.md) for protocol semantics — especially deconfliction (one display-name namespace across markings) and program-derived markings.
2. Read [SECURITY.md](SECURITY.md) for classification and disclosure expectations.
3. Do not commit secrets: authority keys, `policy.toml` from accredited sites, real `bindings.sqlite`, or operational registers.

## Development setup

```bash
git clone <repo-url>
cd MERIDIAN
cargo build -p lexicon-cli
cargo test --workspace
```

See [docs/DEV.md](docs/DEV.md) for features, fuzzing, and local CI parity.

## Code standards

- `cargo fmt --all` — enforced in CI
- `cargo clippy --workspace --all-targets -- -D warnings` — no warnings
- Match existing style: sparse comments (why, not what), minimal diff scope
- Errors propagate as `lexicon_core::Error`; avoid new `unwrap()` in production paths (tests OK)

## Pull requests

1. Branch from `main`.
2. Keep PRs focused — one logical change per PR when possible.
3. Include tests for behavior changes in `lexicon-core` / `lexicon-cli`.
4. Update docs when CLI flags, policy, or ledger format change.
5. CI must pass: fmt, clippy, test, fips, cargo-audit, cargo-deny, highside compile, sbom.

For ledger or event canonicalization changes, call out **breaking** impact explicitly. Canonical bytes are the trust anchor.

## Steward data changes

Pool/agency/reject edits live under `crates/lexicon-pools/data/`. Steward commands (`lexicon pool agency`, `lexicon pool reject`) edit source files; a rebuild bumps `POOL_ID`. Note the pool ID change in the PR description.

Sample data must stay non-authoritative (`sample` / `not_authoritative` flags where applicable). Do not add live classified program facts to the public tree.

## Features and profiles

| Feature | Crate flags | When to use in dev |
|---------|-------------|-------------------|
| `highside` | `lexicon-cli/highside` | Policy + two-chain ledger behavior |
| `fips` | `fips` | AWS-LC crypto boundary |
| `pq` | `pq` | ML-DSA signatures |
| `hsm` | `hsm` | Stub signer seam |

CI compiles `highside` on every PR (`cargo check -p lexicon-cli --features highside`). When touching policy, ledger split, or export redaction, also run tests locally:

```bash
cargo test -p lexicon-core -p lexicon-cli --features highside
```

## License

By contributing, you agree that your contributions are licensed under the project's Apache-2.0 license.

## Questions

Use GitHub Discussions or issues for design questions that are not security-sensitive. For deployment/accreditation questions, work through your program office — maintainers do not speak for NICKA or any operational authority.
