//! meridian-lexicon core: VRF minting, uniqueness ledger, style linter.
//!
//! Secrets are keys. Pools, rules, and the algorithm are public on purpose.

pub mod attribition;
pub mod authority;
pub mod error;
pub mod events;
pub mod janap;
pub mod ledger;
pub mod linter;
pub mod marking;
pub mod merkle;
pub mod mint;
pub mod pool;
pub mod sig;
pub mod types;
pub mod vrf;

pub use attribition::Attribution;
pub use authority::Authority;
pub use error::{Error, Result};
pub use events::{Event, EventKind, NameStatus};
pub use janap::{JanapEntry, JanapSlot, JanapTable};
pub use ledger::{EventRow, Ledger, NameRecord, SignedRoot};
pub use linter::{LintEngine, LintHit, LintRule, LintSeverity, NameCandidate, RejectListRule};
pub use merkle::InclusionProof;
pub use mint::{verify_issued, verify_mint, MintRequest, MintedName, Minter};
pub use pool::{Pool, PoolSet};
#[cfg(feature = "pq")]
pub use sig::MlDsaSigner;
pub use sig::{SigAlg, Signature, Signer};
pub use types::{NameType, POOL_ID, POOL_ID_V1};
pub use vrf::{prove, verify, VrfOutput, VrfProof, PROOF_LEN, SUITE_STRING};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
