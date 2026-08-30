//! meridian-lexicon core: VRF minting, uniqueness ledger, style linter.
//!
//! Secrets are keys. Pools, rules, and the algorithm are public on purpose.

pub mod authority;
pub mod error;
pub mod events;
pub mod ledger;
pub mod linter;
pub mod merkle;
pub mod mint;
pub mod pool;
pub mod types;
pub mod vrf;

pub use authority::Authority;
pub use error::{Error, Result};
pub use events::{Event, EventKind, NameStatus};
pub use ledger::{Ledger, SignedRoot};
pub use linter::{LintEngine, LintHit, LintSeverity, NameCandidate};
pub use merkle::InclusionProof;
pub use mint::{verify_issued, verify_mint, MintRequest, MintedName, Minter};
pub use pool::{Pool, PoolSet};
pub use types::{NameType, POOL_ID, POOL_ID_V1};
pub use vrf::{prove, verify, VrfOutput, VrfProof, PROOF_LEN, SUITE_STRING};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
