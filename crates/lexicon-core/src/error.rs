use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vrf proof invalid")]
    VrfInvalid,

    #[error("vrf encode-to-curve failed")]
    VrfEncodeToCurve,

    #[error("name already on ledger ({status}): {name}")]
    NameTaken { name: String, status: String },

    #[error("lint rejected ({rule}): {detail}")]
    LintRejected { rule: String, detail: String },

    #[error("exhausted {0} mint attempts without a clean name")]
    MintExhausted(u32),

    #[error("unknown pool: {0}")]
    UnknownPool(String),

    #[error("unknown agency: {0}")]
    UnknownAgency(String),

    #[error("empty pool: {0}")]
    EmptyPool(String),

    #[error("name does not match VRF-derived pool indices")]
    IndexMismatch,

    #[error("ledger is empty")]
    LedgerEmpty,

    #[error("ledger corrupt: {0}")]
    LedgerCorrupt(String),

    #[error("no ledger event at seq {0}")]
    MissingEvent(u64),

    #[error("inclusion proof does not match root")]
    InclusionFailed,

    #[error("signature invalid")]
    BadSignature,

    #[error("key error: {0}")]
    Key(String),

    #[error("no key for {agency}; run: lexicon keygen --agency {agency}")]
    MissingKey { agency: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("time: {0}")]
    Time(String),

    #[error("parse: {0}")]
    Parse(String),
}
