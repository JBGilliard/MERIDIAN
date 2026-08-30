use clap::{Parser, Subcommand, ValueEnum};
use lexicon_core::events::{Event, EventKind};
use lexicon_core::ledger::Ledger;
use lexicon_core::linter::{LintSeverity, NameCandidate};
use lexicon_core::marking::{Level, Marking};
use lexicon_core::mint::{verify_mint, MintRequest, Minter};
use lexicon_core::pool::PoolWord;
use lexicon_core::program::{
    derive_marking, render_marking, roll_up_marking, Compartment, Control, ControlKind, Profile,
    Program, SapType,
};
use lexicon_core::types::{normalize, NameType};
use lexicon_core::{Authority, Error, Policy, PolicyOverrides, Signer};
use lexicon_pools::bundled;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod identity;
mod input_files;
mod steward;
mod ui;
use identity::session_attribution;
use input_files::{mint_marking, merge_controls, pick_opt, resolve, ResolvedInputs};
use ui::Ui;

const CLI_BANNER: &str = "\
NOT NICKA — official name assignment remains NICKA.

MERIDIAN-lexicon is an open-source local naming registry reference
implementation. It is not an IC enterprise service or system of record.

Ledger: names.sqlite (unclassified, always) + bindings.sqlite
(classified, optional, policy-gated via policy.toml).

Export defaults to the names chain only; --bindings and attribution
require explicit flags and policy.toml permission.

Prefer --marking-file / --binding-file on high side; --classification is argv-audited.

Data dir: OSS default .meridian in cwd; highside builds require
--data-dir and policy.toml (no implicit cwd path).
";

#[derive(Parser)]
#[command(
    name = "lexicon",
    about = "Local naming registry: mint, verify, and lint un-guessable names",
    long_about = "Local naming registry: mint, verify, and lint un-guessable names.\n\n\
NOT NICKA — official name assignment remains NICKA. Reference implementation\n\
only; not an IC enterprise service or system of record.",
    before_help = CLI_BANNER,
    version
)]
struct Cli {
    /// Ledger and keys. OSS default `.meridian`. Highside builds require an explicit path.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Source data dir for steward CRUD (agencies.json, reject lists).
    #[arg(long, global = true, default_value = "crates/lexicon-pools/data")]
    source_dir: PathBuf,
    /// Emit stable JSON for scripts. Default is human-readable.
    #[arg(long, global = true)]
    json: bool,
    /// Classification banner baked into export/mint artifacts (e.g. "CUI", "SECRET//NOFORN").
    /// Argv-audited; prefer `--marking-file` on high side.
    #[arg(long, global = true)]
    classification: Option<String>,
    /// Classification marking from JSON or TOML (`marking` field). Preferred on high side.
    #[arg(long, global = true, value_name = "PATH")]
    marking_file: Option<PathBuf>,
    /// Classified binding from JSON or TOML: marking, program_pid, compartment_id, controls.
    #[arg(long, global = true, value_name = "PATH")]
    binding_file: Option<PathBuf>,
    /// Refuse to run unless the FIPS 140-3 boundary is active (requires `--features fips`).
    #[arg(long, global = true)]
    approved_mode: bool,
    /// Persist classification markings. Argv cannot enable this if policy.toml forbids it.
    #[arg(long, global = true)]
    persist_markings: bool,
    /// Collect OS-session attribution and include it on lookup/history/export. Policy must allow it.
    #[arg(long, global = true)]
    include_attribution: bool,
    /// Test harness only. Honor LEXICON_USER / LEXICON_HOST. Stripped from release.
    #[cfg(debug_assertions)]
    #[arg(long, global = true, hide = true)]
    allow_env_identity: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Authority key management
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Mint a name (VRF + lint + uniqueness ledger). `--seed` prints
    /// candidates and does not open the ledger.
    Mint {
        #[arg(long, value_enum)]
        r#type: TypeArg,
        #[arg(long)]
        agency: String,
        #[arg(long)]
        digraph: Option<String>,
        #[arg(long, default_value_t = 64)]
        max_attempts: u32,
        /// Bind to a SAP program. Codeword/cryptonym markings derive from it.
        #[arg(long)]
        program: Option<String>,
        /// Bind to a compartment of `--program`.
        #[arg(long)]
        compartment: Option<String>,
        /// 32-byte VRF seed (64 hex chars). Prints candidates; writes nothing.
        #[arg(long, value_name = "HEX")]
        seed: Option<String>,
    },
    /// SAP program object model (create, compartments, controls)
    Program {
        #[command(subcommand)]
        cmd: ProgramCmd,
    },
    /// Verify a minted-name JSON file (VRF + pool indices)
    Verify {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        ledger: bool,
    },
    /// Run the style linter on a candidate name
    Check {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum, default_value_t = TypeArg::Nickname)]
        r#type: TypeArg,
    },
    Ledger {
        #[command(subcommand)]
        cmd: LedgerCmd,
    },
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
    /// Retire a name (quarantine; never reused)
    Retire {
        #[arg(long)]
        name: String,
        #[arg(long)]
        agency: String,
        #[arg(long, default_value = "completed")]
        reason: String,
    },
    /// Revoke a name (compromise / cancellation)
    Revoke {
        #[arg(long)]
        name: String,
        #[arg(long)]
        agency: String,
        #[arg(long, default_value = "compromised")]
        reason: String,
        #[arg(long, help = "second authorizer required for two-person control")]
        co_author: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate an issuing-authority keypair
    Generate {
        #[arg(long)]
        agency: String,
    },
    /// Show public key, algorithm, and key path
    Inspect {
        #[arg(long)]
        agency: String,
    },
    /// Rotate the authority key: emit a signed key_rotated event, then write the new key
    Rotate {
        #[arg(long)]
        agency: String,
        #[arg(long, help = "second authorizer required for two-person control")]
        co_author: Option<String>,
        #[arg(long, default_value = "scheduled")]
        reason: String,
    },
}

#[derive(Subcommand)]
enum ProgramCmd {
    /// Create a SAP program (signed ProgramCreated event)
    Create {
        #[arg(long)]
        pid: String,
        #[arg(long)]
        nickname: String,
        #[arg(long)]
        codeword: Option<String>,
        #[arg(long)]
        sap_type: String,
        #[arg(long)]
        level: String,
        #[arg(long)]
        agency: String,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        sci: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        dissem: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        aea: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        fgi: Vec<String>,
    },
    /// List programs on the ledger
    List,
    /// Show one program, its controls, and compartments
    Show {
        #[arg(long)]
        pid: String,
    },
    /// List every name belonging to a program: PID, nickname, codeword,
    /// compartment nicknames/codewords, and minted names bound to it.
    Names {
        #[arg(long)]
        pid: String,
    },
    /// Add a compartment under a program
    Compartment {
        #[command(subcommand)]
        cmd: CompartmentCmd,
    },
    /// Add or remove SCI/dissem/AEA/FGI controls
    Controls {
        #[command(subcommand)]
        cmd: ControlsCmd,
    },
    /// Render an explicit roll-up banner for a set of slices.
    /// Standing (no slices) is the default; pass --slices to compile.
    Banner {
        #[arg(long)]
        pid: String,
        #[arg(long, value_delimiter = ',', help = "compartment IDs to include")]
        slices: Vec<String>,
        #[arg(long, value_enum, default_value = "capco", help = "dod | capco")]
        profile: ProfileArg,
    },
}

#[derive(Subcommand)]
enum CompartmentCmd {
    /// Add a compartment under a program
    Add {
        #[arg(long)]
        program: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        nickname: String,
        #[arg(long)]
        codeword: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long, help = "slice level if lower than the program (e.g. S for TEV)")]
        level: Option<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        sci: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ControlsCmd {
    /// Add SCI/dissem/AEA/FGI controls (ProgramControlsChanged)
    Add {
        #[arg(long)]
        program: String,
        #[arg(long)]
        compartment: Option<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        sci: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        dissem: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        aea: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        fgi: Vec<String>,
    },
    /// Remove SCI/dissem/AEA/FGI controls (ProgramControlsChanged)
    Remove {
        #[arg(long)]
        program: String,
        #[arg(long)]
        compartment: Option<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        sci: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        dissem: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        aea: Vec<String>,
        #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
        fgi: Vec<String>,
    },
}

#[derive(Subcommand)]
enum LedgerCmd {
    Verify,
    Root {
        #[arg(long)]
        sign: bool,
        #[arg(long)]
        agency: Option<String>,
    },
    Names {
        /// Filter to one marking (spillage guard); e.g. `--marking CUI`.
        #[arg(long)]
        marking: Option<String>,
    },
    /// Look up one name: status, issuer, sequence, timestamp.
    Lookup {
        #[arg(long)]
        name: String,
    },
    /// List name records, optionally filtered.
    History {
        #[arg(long)]
        agency: Option<String>,
        #[arg(long, value_enum)]
        r#type: Option<TypeArg>,
        #[arg(long)]
        status: Option<String>,
        /// Filter to one marking (spillage guard); e.g. `--marking CUI`.
        #[arg(long)]
        marking: Option<String>,
    },
    /// Dump the unclassified names chain as JSON lines. `--bindings` writes a second classified file.
    Export {
        #[arg(long)]
        file: PathBuf,
        /// Also write classified bindings next to `--file`. Requires policy.allow_export_bindings.
        #[arg(long)]
        bindings: bool,
    },
    /// Verify chain integrity + every event signature against a public key.
    Audit {
        #[arg(long, num_args = 1.., help = "public key(s); one for single-signer events, two for two-person control")]
        public_key: Vec<String>,
    },
    /// Combined ledger.sqlite is not converted. Quarantine it and start clean.
    Migrate,
}

#[derive(Subcommand)]
enum PoolCmd {
    Inspect {
        #[arg(long)]
        agency: Option<String>,
        #[arg(long, value_enum)]
        r#type: Option<TypeArg>,
    },
    /// Steward: agency allocation CRUD (edits source; rebuild to ship)
    Agency {
        #[command(subcommand)]
        cmd: AgencyCmd,
    },
    /// Steward: reject-list CRUD (edits source; rebuild to ship)
    Reject {
        #[command(subcommand)]
        cmd: RejectCmd,
    },
}

#[derive(Subcommand)]
enum AgencyCmd {
    /// List agencies in the source agencies.json
    List,
    /// Add an agency allocation
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        first_letters: String,
        #[arg(long, value_delimiter = ',')]
        digraphs: Vec<String>,
        #[arg(long, value_delimiter = ',', help = "SAP designators")]
        sap: Vec<String>,
    },
    /// Remove an agency allocation
    Remove {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum RejectCmd {
    /// List tokens in a reject set
    List {
        #[arg(long)]
        set: String,
    },
    /// Add a token to a reject set
    Add {
        #[arg(long, help = "historical | military")]
        set: String,
        #[arg(long)]
        token: String,
    },
    /// Remove a token from a reject set
    Remove {
        #[arg(long, help = "historical | military")]
        set: String,
        #[arg(long)]
        token: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum TypeArg {
    #[value(alias = "NICKNAME")]
    Nickname,
    #[value(alias = "CODEWORD", alias = "CODE-WORD")]
    Codeword,
    #[value(alias = "CRYPTONYM")]
    Cryptonym,
    #[value(alias = "SAP", alias = "SAP-DESIGNATOR")]
    Sap,
    #[value(alias = "EXERCISE", alias = "EXERCISE-TERM")]
    Exercise,
}

impl From<TypeArg> for NameType {
    fn from(v: TypeArg) -> Self {
        match v {
            TypeArg::Nickname => NameType::Nickname,
            TypeArg::Codeword => NameType::CodeWord,
            TypeArg::Cryptonym => NameType::Cryptonym,
            TypeArg::Sap => NameType::SapDesignator,
            TypeArg::Exercise => NameType::ExerciseTerm,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    #[value(alias = "DOD")]
    Dod,
    #[value(alias = "CAPCO")]
    Capco,
}

impl From<ProfileArg> for Profile {
    fn from(v: ProfileArg) -> Self {
        match v {
            ProfileArg::Dod => Profile::DoDBanner,
            ProfileArg::Capco => Profile::CapcoBanner,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.approved_mode {
        lexicon_core::require_approved()?;
    } else {
        lexicon_core::init()?;
    }
    let inputs = resolve(
        cli.marking_file.as_deref(),
        cli.binding_file.as_deref(),
        cli.classification.as_deref(),
    )?;
    let ui = Ui::new(cli.json);
    if matches!(&cli.cmd, Cmd::Mint { seed: Some(_), .. }) {
        mint_from_seed(&cli, &inputs, &ui)?;
        return Ok(());
    }
    let data_dir = resolve_data_dir(cli.data_dir.as_deref())?;
    let policy = Policy::from_data_dir(&data_dir)?.tighten(&PolicyOverrides {
        persist_markings: cli.persist_markings,
        include_attribution: cli.include_attribution,
    })?;
    #[cfg(debug_assertions)]
    let allow_env_identity = cli.allow_env_identity;
    #[cfg(not(debug_assertions))]
    let allow_env_identity = false;
    match cli.cmd {
        Cmd::Key { cmd } => match cmd {
            KeyCmd::Generate { agency } => {
                let agency = agency.to_ascii_uppercase();
                let _ = bundled().agency(&agency)?;
                let keys = keys_dir(&data_dir);
                if keys.join(format!("{agency}.sk")).exists() {
                    return Err(format!("key already exists for {agency}").into());
                }
                let auth = Authority::generate(&agency);
                auth.save(&keys)?;
                let pk = hex::encode(auth.public_key());
                if ui.is_json() {
                    ui.json(&serde_json::json!({ "agency": agency, "public_key": pk, "path": keys.display().to_string() }));
                } else {
                    ui.heading(&format!("generated key for {agency}"));
                    ui.kv("public key", &pk);
                    ui.kv("path", &keys.display().to_string());
                }
            }
            KeyCmd::Inspect { agency } => {
                let agency = agency.to_ascii_uppercase();
                let keys = keys_dir(&data_dir);
                let auth = load_auth(&data_dir, &agency)?;
                let pk = hex::encode(auth.public_key());
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "agency": agency,
                        "algorithm": auth.alg().as_str(),
                        "public_key": pk,
                        "path": keys.join(format!("{agency}.sk")).display().to_string(),
                    }));
                } else {
                    ui.heading(&format!("authority {agency}"));
                    ui.kv("algorithm", auth.alg().as_str());
                    ui.kv("public key", &pk);
                    ui.kv(
                        "path",
                        &keys.join(format!("{agency}.sk")).display().to_string(),
                    );
                }
            }
            KeyCmd::Rotate {
                agency,
                co_author,
                reason,
            } => {
                let agency = agency.to_ascii_uppercase();
                let old = load_auth(&data_dir, &agency)?;
                let new = Authority::generate(&agency);
                let kind = EventKind::KeyRotated {
                    authority_id: agency.clone(),
                    old_pk: hex::encode(old.public_key()),
                    new_pk: hex::encode(new.public_key()),
                    new_alg: new.alg(),
                };
                let mut event = Event::new(kind);
                event.attribution =
                    session_attribution(policy.allow_attribution, allow_env_identity)?;
                let canonical = event.canonical_u_bytes();
                let mut led = open_ledger(&data_dir, &policy)?;
                let seq = if let Some(co) = &co_author {
                    let co_agency = co.to_ascii_uppercase();
                    let co_auth = load_auth(&data_dir, &co_agency)?;
                    let sig = lexicon_core::Signature::join(vec![
                        old.sign(&canonical),
                        co_auth.sign(&canonical),
                    ]);
                    led.append_with(event, sig)?
                } else {
                    led.append(event, &old)?
                };
                // Persist the new seed only after the rotation event is on the
                // ledger. A crash here leaves the old key active and the
                // rotation unrecorded — recoverable, no split-brain.
                new.save(&keys_dir(&data_dir))?;
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "agency": agency,
                        "seq": seq,
                        "old_pk": hex::encode(old.public_key()),
                        "new_pk": hex::encode(new.public_key()),
                        "new_alg": new.alg().as_str(),
                        "reason": reason,
                        "two_person": co_author.is_some(),
                    }));
                } else {
                    ui.status(true, &format!("rotated {agency} key (seq {seq})"));
                    ui.kv("old pk", &hex::encode(old.public_key()));
                    ui.kv("new pk", &hex::encode(new.public_key()));
                    ui.kv("algorithm", new.alg().as_str());
                    if co_author.is_some() {
                        ui.kv("co-author", "required");
                    }
                    ui.line(&format!("  destroy the old seed; {reason}"));
                }
            }
        },
        Cmd::Mint { seed: Some(_), .. } => unreachable!("seed mint handled before ledger open"),
        Cmd::Mint {
            r#type,
            agency,
            digraph,
            max_attempts,
            program,
            compartment,
            seed: None,
        } => {
            let agency = agency.to_ascii_uppercase();
            let auth = load_auth(&data_dir, &agency)?;
            let pools = bundled();
            let linter = lexicon_pools::bundled_linter();
            let mut ledger = open_ledger(&data_dir, &policy)?;
            let mut minter = Minter::new(&auth, pools, &linter, &mut ledger);
            let marking = mint_marking(&inputs);
            for w in marking.warnings() {
                eprintln!("warning: {w}");
            }
            let attribution = session_attribution(policy.allow_attribution, allow_env_identity)?;
            let program_pid = pick_opt(
                inputs
                    .binding
                    .as_ref()
                    .and_then(|b| b.program_pid.as_deref()),
                program.as_deref(),
            );
            let compartment_id = pick_opt(
                inputs
                    .binding
                    .as_ref()
                    .and_then(|b| b.compartment_id.as_deref()),
                compartment.as_deref(),
            );
            if compartment_id.is_some() && program_pid.is_none() {
                return Err(Error::Parse("compartment_id requires program_pid".into()).into());
            }
            let minted = minter.mint(MintRequest {
                name_type: r#type.into(),
                pool_id: pools.id.clone(),
                max_attempts,
                digraph,
                marking,
                attribution,
                program_pid: program_pid.clone(),
                compartment_id: compartment_id.clone(),
            })?;
            if ui.is_json() {
                let mut v = serde_json::to_value(&minted)?;
                let obj = v.as_object_mut().unwrap();
                if let Some(m) = &inputs.floor {
                    obj.insert("classification".into(), m.display_banner().into());
                }
                if let Some(p) = &program_pid {
                    obj.insert("program".into(), p.to_ascii_uppercase().into());
                }
                if let Some(c) = &compartment_id {
                    obj.insert("compartment".into(), c.to_ascii_uppercase().into());
                }
                ui.json(&v);
            } else {
                ui.heading(&format!("minted {}", minted.name));
                ui.kv("type", minted.name_type.as_str());
                ui.kv("agency", &minted.authority_id);
                ui.kv("sequence", &minted.sequence.to_string());
                ui.kv("nonce", &minted.nonce.to_string());
                ui.kv("marking", &ui::portion(&minted.marking));
                if let Some(p) = &program_pid {
                    ui.kv("program", &p.to_ascii_uppercase());
                }
                if let Some(c) = &compartment_id {
                    ui.kv("compartment", &c.to_ascii_uppercase());
                }
            }
        }
        Cmd::Verify { file, ledger } => {
            let raw = fs::read_to_string(&file)?;
            let minted: lexicon_core::MintedName = serde_json::from_str(&raw)?;
            let pools = bundled();
            if ledger {
                let led = open_ledger(&data_dir, &policy)?;
                lexicon_core::verify_issued(&minted, pools, &led)?;
            } else {
                verify_mint(&minted, pools)?;
            }
            if ui.is_json() {
                ui.json(&serde_json::json!({ "ok": true, "name": minted.name }));
            } else {
                ui.status(true, &minted.name);
            }
        }
        Cmd::Check { name, r#type } => {
            let ty: NameType = r#type.into();
            let words = normalize(&name)
                .split_whitespace()
                .map(PoolWord::new)
                .collect();
            let candidate = NameCandidate {
                name: normalize(&name),
                name_type: ty,
                words,
            };
            let hits = lexicon_pools::bundled_linter().check(&candidate);
            let ok = hits.iter().all(|h| h.severity != LintSeverity::Reject);
            if ui.is_json() {
                ui.json(&serde_json::json!({ "name": candidate.name, "ok": ok, "hits": hits }));
            } else {
                ui.status(ok, &candidate.name);
                for h in &hits {
                    let sev = match h.severity {
                        LintSeverity::Reject => "reject",
                        LintSeverity::Warn => "warn",
                    };
                    ui.line(&format!("    {}  {}  {}", h.rule, sev, h.detail));
                }
            }
        }
        Cmd::Ledger { cmd } => match cmd {
            LedgerCmd::Verify => {
                let led = open_ledger(&data_dir, &policy)?;
                led.verify_chain()?;
                let events = led.len()?;
                let root = hex::encode(led.root()?);
                let agg = led.aggregate_marking()?;
                let crypto = lexicon_core::boundary();
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "ok": true,
                        "events": events,
                        "root": root,
                        "marking": agg.to_string(),
                        "crypto": crypto,
                    }));
                } else {
                    ui.status(true, &format!("{events} events, root 0x{root}"));
                    ui.kv("marking", &agg.to_string());
                    ui.line(&lexicon_core::status_line());
                }
            }
            LedgerCmd::Root { sign, agency } => {
                let led = open_ledger(&data_dir, &policy)?;
                if sign {
                    let agency = agency
                        .ok_or(" --agency required with --sign")?
                        .to_ascii_uppercase();
                    let auth = load_auth(&data_dir, &agency)?;
                    let snap = led.sign_root(&auth)?;
                    if ui.is_json() {
                        ui.json(&snap);
                    } else {
                        ui.heading(&format!("signed root 0x{}", snap.root));
                        ui.kv("events", &snap.leaf_count.to_string());
                        ui.kv("by", &snap.authority_id);
                        ui.kv("at", &snap.signed_at);
                    }
                } else {
                    let events = led.len()?;
                    let root = hex::encode(led.root()?);
                    if ui.is_json() {
                        ui.json(&serde_json::json!({ "root": root, "events": events }));
                    } else {
                        ui.kv("root", &format!("0x{root}"));
                        ui.kv("events", &events.to_string());
                    }
                }
            }
            LedgerCmd::Names { marking } => {
                let show_attr = attribution_visible(&policy, cli.include_attribution)?;
                let led = open_ledger(&data_dir, &policy)?;
                let mut recs: Vec<_> = led
                    .name_records()?
                    .into_iter()
                    .filter(|r| r.status == "issued")
                    .collect();
                if let Some(m) = &marking {
                    let want: Marking = m.parse().map_err(|e| format!("bad --marking: {e}"))?;
                    recs.retain(|r| Marking::from_stored(&r.marking).is_ok_and(|rm| rm == want));
                }
                redact_attributions(&mut recs, show_attr);
                if ui.is_json() {
                    ui.json(&recs);
                } else {
                    let pm = page_marking(&recs, inputs.floor.as_ref());
                    ui.banner_top(&pm);
                    ui.heading(&format!("{} issued names", recs.len()));
                    for r in &recs {
                        ui.line(&format!(
                            "  {:<14} {}",
                            r.display,
                            ui::portion_of_stored(&r.marking)
                        ));
                    }
                    ui.banner_bottom(&pm);
                }
            }
            LedgerCmd::Lookup { name } => {
                let show_attr = attribution_visible(&policy, cli.include_attribution)?;
                let led = open_ledger(&data_dir, &policy)?;
                match led.lookup(&name)? {
                    Some(mut r) => {
                        if !show_attr {
                            r.attribution.clear();
                        }
                        if ui.is_json() {
                            ui.json(&r);
                        } else {
                            let pm = page_marking(
                                std::slice::from_ref(&r),
                                inputs.floor.as_ref(),
                            );
                            ui.banner_top(&pm);
                            ui.status(r.status == "issued", &r.display);
                            ui.kv("status", &r.status);
                            ui.kv("type", &r.name_type);
                            ui.kv("agency", &r.authority_id);
                            ui.kv("marking", &ui::portion_of_stored(&r.marking));
                            if let Some(pid) = &r.program_pid {
                                ui.kv("program", pid);
                            }
                            if let Some(cid) = &r.compartment_id {
                                ui.kv("compartment", cid);
                            }
                            if !r.attribution.is_empty() {
                                ui.kv("user", &r.attribution);
                            }
                            ui.kv("seq", &r.event_seq.to_string());
                            ui.kv("at", &r.created_at);
                            ui.banner_bottom(&pm);
                        }
                    }
                    None => {
                        if ui.is_json() {
                            ui.json(
                                &serde_json::json!({ "name": normalize(&name), "found": false }),
                            );
                        } else {
                            ui.status(false, "unknown name");
                        }
                    }
                }
            }
            LedgerCmd::History {
                agency,
                r#type,
                status,
                marking,
            } => {
                let show_attr = attribution_visible(&policy, cli.include_attribution)?;
                let led = open_ledger(&data_dir, &policy)?;
                let mut recs = led.name_records()?;
                if let Some(a) = &agency {
                    recs.retain(|r| r.authority_id.eq_ignore_ascii_case(a));
                }
                if let Some(t) = r#type {
                    let want = NameType::from(t).as_str();
                    recs.retain(|r| r.name_type == want);
                }
                if let Some(s) = &status {
                    recs.retain(|r| r.status.eq_ignore_ascii_case(s));
                }
                if let Some(m) = &marking {
                    // Spillage guard: filter to one marking so a CUI-only
                    // workstation never materializes a TS name into its logs.
                    let want: Marking = m.parse().map_err(|e| format!("bad --marking: {e}"))?;
                    recs.retain(|r| Marking::from_stored(&r.marking).is_ok_and(|rm| rm == want));
                }
                redact_attributions(&mut recs, show_attr);
                if ui.is_json() {
                    ui.json(&recs);
                } else {
                    let pm = page_marking(&recs, inputs.floor.as_ref());
                    ui.banner_top(&pm);
                    ui.heading(&format!("{} names", recs.len()));
                    for r in &recs {
                        let attr = if r.attribution.is_empty() {
                            String::new()
                        } else {
                            format!("  @{}", r.attribution)
                        };
                        ui.line(&format!(
                            "  {:<6} {:<14} {:<5} {}  {}{}",
                            r.status,
                            r.display,
                            r.authority_id,
                            ui::portion_of_stored(&r.marking),
                            r.created_at,
                            attr
                        ));
                    }
                    ui.banner_bottom(&pm);
                }
            }
            LedgerCmd::Export { file, bindings } => {
                let show_attr = attribution_visible(&policy, cli.include_attribution)?;
                let want_bindings = bindings_export_allowed(&policy, bindings)?;
                let mut led = open_ledger(&data_dir, &policy)?;
                let names = led.name_rows()?;
                let names_marking = names_export_marking(inputs.floor.as_ref());
                let names_banner = (!names.is_empty() || inputs.floor.is_some())
                    .then(|| export_banner_json(&names_marking));
                write_jsonl(&file, names_banner.as_ref(), &names)?;

                if want_bindings {
                    if file == Path::new("-") {
                        return Err("--bindings cannot write to stdout; pass --file <path>".into());
                    }
                    led.attach_bindings_read(&data_dir)?;
                    let mut brows = led.binding_rows()?;
                    redact_binding_export(&mut brows, show_attr);
                    let bind_marking =
                        bindings_export_marking(&led, &policy, inputs.floor.as_ref())?;
                    let bind_banner = export_banner_json(&bind_marking);
                    let bpath = bindings_sidecar(&file);
                    write_jsonl(&bpath, Some(&bind_banner), &brows)?;
                    if !ui.is_json() {
                        ui.status(
                            true,
                            &format!(
                                "{} names to {}; {} bindings to {}",
                                names.len(),
                                file.display(),
                                brows.len(),
                                bpath.display()
                            ),
                        );
                    }
                } else if file != Path::new("-") && !ui.is_json() {
                    ui.status(
                        true,
                        &format!("{} names to {}", names.len(), file.display()),
                    );
                }
            }
            LedgerCmd::Audit { public_key } => {
                let led = open_ledger(&data_dir, &policy)?;
                led.verify_chain()?;
                let pks: Vec<Vec<u8>> = public_key
                    .iter()
                    .map(|h| hex::decode(h.trim()).map_err(|e| format!("bad public key hex: {e}")))
                    .collect::<Result<_, _>>()?;
                let pk_refs: Vec<&[u8]> = pks.iter().map(Vec::as_slice).collect();
                let total = led.len()?;
                let mut failed = Vec::new();
                for seq in 1..=total {
                    if led.verify_event_signature(seq, &pk_refs).is_err() {
                        failed.push(seq);
                    }
                }
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "ok": failed.is_empty(),
                        "events": total,
                        "signatures_verified": total - (failed.len() as u64),
                        "failed": failed,
                    }));
                } else if failed.is_empty() {
                    ui.status(true, &format!("{total} events, all signatures verified"));
                } else {
                    ui.status(
                        false,
                        &format!(
                            "{}/{} signatures verified",
                            total - (failed.len() as u64),
                            total
                        ),
                    );
                    ui.line(&format!(
                        "    failed seqs: {}",
                        failed
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    ui.line(
                            "    (a failure may indicate a key rotation; audit with the old key for those seqs)",
                        );
                }
            }
            LedgerCmd::Migrate => {
                let had_legacy = data_dir.join("ledger.sqlite").exists();
                Ledger::migrate(&data_dir)?;
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "ok": true,
                        "legacy_quarantined": had_legacy,
                    }));
                } else if had_legacy {
                    ui.status(
                        true,
                        "quarantined ledger.sqlite (not converted); start clean",
                    );
                } else {
                    ui.status(true, "no combined ledger.sqlite; nothing to migrate");
                }
            }
        },
        Cmd::Pool { cmd } => match cmd {
            PoolCmd::Inspect { agency, r#type } => {
                let pools = bundled();
                if let Some(a) = agency {
                    let a = a.to_ascii_uppercase();
                    let alloc = pools.agency(&a)?;
                    if let Some(ty) = r#type {
                        let ty = NameType::from(ty);
                        let first = pools.first_pool(ty, &a)?;
                        let second = pools.second_pool(ty);
                        let fw: Vec<String> = first.words.iter().map(|w| w.word.clone()).collect();
                        let sw: Option<Vec<String>> =
                            second.map(|p| p.words.iter().map(|w| w.word.clone()).collect());
                        if ui.is_json() {
                            ui.json(&serde_json::json!({ "agency": a, "type": ty.as_str(), "first": fw, "second": sw }));
                        } else {
                            ui.heading(&format!("agency {a}, type {ty}"));
                            ui.kv("first", &format!("{} words", fw.len()));
                            ui.line(&format!("    {}", sample(&fw)));
                            if let Some(sw) = &sw {
                                ui.kv("second", &format!("{} words", sw.len()));
                                ui.line(&format!("    {}", sample(sw)));
                            }
                        }
                    } else {
                        if ui.is_json() {
                            ui.json(&serde_json::json!({
                                "agency": alloc.id, "first_letters": alloc.first_letters,
                                "digraphs": alloc.digraphs, "sap_designators": alloc.sap_designators,
                            }));
                        } else {
                            ui.heading(&format!("agency {}", alloc.id));
                            ui.kv("first letters", &alloc.first_letters);
                            ui.kv("digraphs", &alloc.digraphs.join(", "));
                            ui.kv("sap", &alloc.sap_designators.join(", "));
                        }
                    }
                } else {
                    if ui.is_json() {
                        ui.json(&serde_json::json!({
                            "pool_id": pools.id,
                            "agencies": pools.agencies.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
                            "nickname_first": pools.nickname_first.len(),
                            "nickname_second": pools.nickname_second.len(),
                            "codeword": pools.codeword.len(),
                            "cryptonym_word": pools.cryptonym_word.len(),
                            "exercise_first": pools.exercise_first.len(),
                            "exercise_second": pools.exercise_second.len(),
                        }));
                    } else {
                        ui.heading(&format!("pool {}", pools.id));
                        ui.kv("agencies", &pools.agencies.len().to_string());
                        ui.kv("nickname_first", &pools.nickname_first.len().to_string());
                        ui.kv("nickname_second", &pools.nickname_second.len().to_string());
                        ui.kv("codeword", &pools.codeword.len().to_string());
                        ui.kv("cryptonym_word", &pools.cryptonym_word.len().to_string());
                        ui.kv("exercise_first", &pools.exercise_first.len().to_string());
                        ui.kv("exercise_second", &pools.exercise_second.len().to_string());
                    }
                }
            }
            PoolCmd::Agency { cmd } => match cmd {
                AgencyCmd::List => {
                    let recs = steward::list_agencies(&cli.source_dir)?;
                    if ui.is_json() {
                        ui.json(&recs);
                    } else {
                        ui.heading(&format!(
                            "{} agencies in {}",
                            recs.len(),
                            cli.source_dir.display()
                        ));
                        for a in &recs {
                            ui.line(&format!(
                                "  {:<6} letters={} digraphs={} sap={}",
                                a.id,
                                a.first_letters,
                                a.digraphs.len(),
                                a.sap_designators.len()
                            ));
                        }
                    }
                }
                AgencyCmd::Add {
                    id,
                    first_letters,
                    digraphs,
                    sap,
                } => {
                    steward::add_agency(&cli.source_dir, &id, &first_letters, &digraphs, &sap)?;
                    if ui.is_json() {
                        ui.json(&serde_json::json!({ "added": id.to_ascii_uppercase() }));
                    } else {
                        ui.status(true, &format!("added agency {}", id.to_ascii_uppercase()));
                        ui.line("  rebuild and bump POOL_ID to ship");
                    }
                }
                AgencyCmd::Remove { id } => {
                    steward::remove_agency(&cli.source_dir, &id)?;
                    if ui.is_json() {
                        ui.json(&serde_json::json!({ "removed": id.to_ascii_uppercase() }));
                    } else {
                        ui.status(true, &format!("removed agency {}", id.to_ascii_uppercase()));
                        ui.line("  rebuild and bump POOL_ID to ship");
                    }
                }
            },
            PoolCmd::Reject { cmd } => {
                match cmd {
                    RejectCmd::List { set } => {
                        let tokens = steward::list_rejects(&cli.source_dir, &set)?;
                        if ui.is_json() {
                            ui.json(&serde_json::json!({ "set": set, "count": tokens.len(), "tokens": tokens }));
                        } else {
                            ui.heading(&format!("{set}: {} tokens", tokens.len()));
                            ui.names(&tokens);
                        }
                    }
                    RejectCmd::Add { set, token } => {
                        steward::add_reject(&cli.source_dir, &set, &token)?;
                        if ui.is_json() {
                            ui.json(&serde_json::json!({ "added": token.to_ascii_uppercase(), "set": set }));
                        } else {
                            ui.status(
                                true,
                                &format!("added {} to {set}", token.to_ascii_uppercase()),
                            );
                            ui.line("  rebuild and bump POOL_ID to ship");
                        }
                    }
                    RejectCmd::Remove { set, token } => {
                        steward::remove_reject(&cli.source_dir, &set, &token)?;
                        if ui.is_json() {
                            ui.json(&serde_json::json!({ "removed": token.to_ascii_uppercase(), "set": set }));
                        } else {
                            ui.status(
                                true,
                                &format!("removed {} from {set}", token.to_ascii_uppercase()),
                            );
                            ui.line("  rebuild and bump POOL_ID to ship");
                        }
                    }
                }
            }
        },
        Cmd::Program { cmd } => match cmd {
            ProgramCmd::Create {
                pid,
                nickname,
                codeword,
                sap_type,
                level,
                agency,
                sci,
                dissem,
                aea,
                fgi,
            } => {
                let agency = agency.to_ascii_uppercase();
                let pid = pid.to_ascii_uppercase();
                let sap_type = SapType::parse(&sap_type)?;
                let level = Level::parse(&level).ok_or_else(|| format!("bad --level: {level}"))?;
                let (sci, dissem, aea, fgi) = merge_controls(
                    inputs.binding.as_ref(),
                    &sci,
                    &dissem,
                    &aea,
                    &fgi,
                );
                let controls = collect_controls(sci, dissem, aea, fgi);
                {
                    let led = open_ledger(&data_dir, &policy)?;
                    for (label, val) in [
                        ("nickname", nickname.as_str()),
                        ("codeword", codeword.as_deref().unwrap_or("")),
                    ] {
                        if !val.is_empty() && led.is_display_name_taken(val)? {
                            return Err(format!(
                                "{label} '{val}' collides with an existing name in the global namespace"
                            )
                            .into());
                        }
                    }
                }
                let program = Program {
                    pid: pid.clone(),
                    nickname,
                    codeword,
                    sap_type,
                    level,
                    authority_id: agency.clone(),
                    controls,
                };
                let marking = derive_marking(&program, None);
                let seq = append_program_event(
                    &data_dir,
                    &policy,
                    &agency,
                    EventKind::ProgramCreated(program.clone()),
                    allow_env_identity,
                )?;
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "pid": program.pid,
                        "nickname": program.nickname,
                        "codeword": program.codeword,
                        "sap_type": program.sap_type.as_str(),
                        "level": program.level.as_str(),
                        "agency": program.authority_id,
                        "controls": program.controls,
                        "marking": marking.to_string(),
                        "seq": seq,
                    }));
                } else {
                    ui.status(true, &format!("created program {pid} (seq {seq})"));
                    ui.kv("nickname", &program.nickname);
                    ui.kv("sap type", program.sap_type.as_str());
                    ui.kv("level", program.level.as_str());
                    ui.kv("agency", &program.authority_id);
                    ui.kv("marking", &ui::portion(&marking));
                }
            }
            ProgramCmd::List => {
                let led = open_ledger(&data_dir, &policy)?;
                let programs = led.programs()?;
                if ui.is_json() {
                    ui.json(&programs);
                } else {
                    let mut agg = Marking::default();
                    for p in &programs {
                        agg = agg.max(&derive_marking(p, None));
                    }
                    ui.banner_top(&agg);
                    ui.heading(&format!("{} programs", programs.len()));
                    for p in &programs {
                        ui.line(&format!(
                            "  {:<6} {:<24} {:<14} {:<4} {}",
                            p.pid,
                            p.nickname,
                            p.sap_type.as_str(),
                            p.level.as_str(),
                            p.authority_id
                        ));
                    }
                    ui.banner_bottom(&agg);
                }
            }
            ProgramCmd::Show { pid } => {
                let led = open_ledger(&data_dir, &policy)?;
                match led.program(&pid)? {
                    Some(p) => {
                        let comps = led.compartments(&p.pid)?;
                        let standing = derive_marking(&p, None);
                        if ui.is_json() {
                            ui.json(&serde_json::json!({
                                "program": p,
                                "compartments": comps,
                                "marking": standing.to_string(),
                            }));
                        } else {
                            // Standing banner = program record, no slices.
                            // Roll-up of all slices is a separate command
                            // (`program banner --slices ...`); the show
                            // screen does not fake a compilation line.
                            ui.banner_top(&standing);
                            ui.heading(&format!("program {}", p.pid));
                            ui.kv("nickname", &p.nickname);
                            if let Some(cw) = &p.codeword {
                                ui.kv("codeword", cw);
                            }
                            ui.kv("sap type", p.sap_type.as_str());
                            ui.kv("level", p.level.as_str());
                            ui.kv("agency", &p.authority_id);
                            for kind in [
                                ControlKind::Sci,
                                ControlKind::Dissem,
                                ControlKind::Aea,
                                ControlKind::Fgi,
                            ] {
                                let vals = control_values(&p.controls, kind);
                                if !vals.is_empty() {
                                    ui.kv(kind.as_str(), &vals.join(", "));
                                }
                            }
                            ui.kv("marking", &ui::portion(&standing));
                            ui.kv("DoD banner", &render_marking(&p, None, Profile::DoDBanner));
                            if comps.is_empty() {
                                ui.line("  (no compartments)");
                            } else {
                                ui.heading("compartments");
                                for c in &comps {
                                    let cm = derive_marking(&p, Some(c));
                                    let sci = control_values(&c.controls, ControlKind::Sci);
                                    let mut line = format!("  {:<6} {:<16} ", c.id, c.nickname,);
                                    if let Some(cw) = &c.codeword {
                                        line.push_str(&format!("cw={cw} "));
                                    }
                                    if !sci.is_empty() {
                                        line.push_str(&format!("sci={} ", sci.join(",")));
                                    }
                                    line.push_str(&ui::portion(&cm));
                                    ui.line(&line);
                                }
                            }
                            // Exercises bound to this program (mint --type
                            // exercise --program QSV). Names stay U.
                            let exercises: Vec<_> = led
                                .name_records()?
                                .into_iter()
                                .filter(|r| {
                                    r.program_pid.as_deref() == Some(p.pid.as_str())
                                        && r.name_type == "exercise"
                                        && r.status == "issued"
                                })
                                .collect();
                            if exercises.is_empty() {
                                ui.line("  (no exercises)");
                            } else {
                                ui.heading("exercises");
                                for r in &exercises {
                                    ui.line(&format!(
                                        "  {:<24} {}",
                                        r.display,
                                        ui::portion_of_stored(&r.marking)
                                    ));
                                }
                            }
                            ui.banner_bottom(&standing);
                        }
                    }
                    None => {
                        if ui.is_json() {
                            ui.json(&serde_json::json!({
                                "pid": pid.to_ascii_uppercase(),
                                "found": false,
                            }));
                        } else {
                            ui.status(false, "unknown program");
                        }
                    }
                }
            }
            ProgramCmd::Names { pid } => {
                let led = open_ledger(&data_dir, &policy)?;
                let p = require_program(&led, &pid)?;
                let comps = led.compartments(&p.pid)?;
                // Steward-assigned names: PID, program nickname, program codeword,
                // each compartment's nickname and codeword. These are not in the
                // `names` table (not VRF-minted), so `ledger names` cannot show
                // them; this command is the program-scoped lexicon view.
                let mut rows: Vec<(String, String, String)> = Vec::new();
                rows.push((p.pid.clone(), "pid".into(), "U".into()));
                rows.push((p.nickname.clone(), "nickname".into(), "U".into()));
                if let Some(cw) = &p.codeword {
                    rows.push((
                        cw.clone(),
                        "codeword".into(),
                        render_marking(&p, None, Profile::Portion),
                    ));
                }
                for c in &comps {
                    rows.push((
                        c.nickname.clone(),
                        "compartment nickname".into(),
                        "U".into(),
                    ));
                    if let Some(cw) = &c.codeword {
                        rows.push((
                            cw.clone(),
                            "compartment codeword".into(),
                            render_marking(&p, Some(c), Profile::Portion),
                        ));
                    }
                }
                // Minted names bound to this program (VRF-derived, in the ledger).
                for r in led.name_records()? {
                    if r.program_pid.as_deref() == Some(p.pid.as_str()) && r.status == "issued" {
                        rows.push((r.display.clone(), r.name_type.clone(), r.marking.clone()));
                    }
                }
                if ui.is_json() {
                    ui.json(&rows);
                } else {
                    let agg = led.aggregate_marking()?;
                    ui.banner_top(&agg);
                    ui.heading(&format!("names for program {}", p.pid));
                    for (name, kind, marking) in &rows {
                        ui.line(&format!("  {:<24} {:<20} {}", name, kind, marking));
                    }
                    ui.banner_bottom(&agg);
                }
            }
            ProgramCmd::Compartment { cmd } => match cmd {
                CompartmentCmd::Add {
                    program,
                    id,
                    nickname,
                    codeword,
                    parent,
                    level,
                    sci,
                } => {
                    let mut led = open_ledger(&data_dir, &policy)?;
                    let p = require_program(&led, &program)?;
                    let agency = p.authority_id.clone();
                    let slice_level = level
                        .as_deref()
                        .and_then(lexicon_core::marking::Level::parse)
                        .ok_or_else(|| format!("bad --level: {:?}", level))?;
                    let controls = sci
                        .into_iter()
                        .map(|v| Control::new(ControlKind::Sci, v))
                        .collect();
                    // Deconfliction: compartment nickname/codeword share the global
                    // display-name namespace with issued names. Reject collisions.
                    for label in ["nickname", "codeword"] {
                        let val = if label == "nickname" {
                            nickname.as_str()
                        } else {
                            codeword.as_deref().unwrap_or("")
                        };
                        if !val.is_empty() && led.is_display_name_taken(val)? {
                            return Err(format!(
                                "{label} '{val}' collides with an existing name in the global namespace"
                            )
                            .into());
                        }
                    }
                    let c = Compartment {
                        program_pid: p.pid.clone(),
                        id: id.to_ascii_uppercase(),
                        nickname,
                        codeword,
                        parent_id: parent,
                        controls,
                        level: Some(slice_level),
                    };
                    let marking = derive_marking(&p, Some(&c));
                    let mut event = Event::new(EventKind::CompartmentAdded(c.clone()));
                    event.attribution =
                        session_attribution(policy.allow_attribution, allow_env_identity)?;
                    let auth = load_auth(&data_dir, &agency)?;
                    let seq = led.append(event, &auth)?;
                    if ui.is_json() {
                        ui.json(&serde_json::json!({
                            "program": c.program_pid,
                            "id": c.id,
                            "nickname": c.nickname,
                            "codeword": c.codeword,
                            "parent": c.parent_id,
                            "controls": c.controls,
                            "marking": marking.to_string(),
                            "seq": seq,
                        }));
                    } else {
                        ui.status(
                            true,
                            &format!(
                                "added compartment {} on {} (seq {seq})",
                                c.id, c.program_pid
                            ),
                        );
                        ui.kv("nickname", &c.nickname);
                        ui.kv("marking", &ui::portion(&marking));
                    }
                }
            },
            ProgramCmd::Controls { cmd } => {
                let (add, program, compartment, sci, dissem, aea, fgi) = match cmd {
                    ControlsCmd::Add {
                        program,
                        compartment,
                        sci,
                        dissem,
                        aea,
                        fgi,
                    } => (true, program, compartment, sci, dissem, aea, fgi),
                    ControlsCmd::Remove {
                        program,
                        compartment,
                        sci,
                        dissem,
                        aea,
                        fgi,
                    } => (false, program, compartment, sci, dissem, aea, fgi),
                };
                let (sci, dissem, aea, fgi) = merge_controls(
                    inputs.binding.as_ref(),
                    &sci,
                    &dissem,
                    &aea,
                    &fgi,
                );
                let delta = collect_controls(sci, dissem, aea, fgi);
                if delta.is_empty() {
                    return Err("need at least one of --sci/--dissem/--aea/--fgi".into());
                }
                let mut led = open_ledger(&data_dir, &policy)?;
                let p = require_program(&led, &program)?;
                if let Some(cid) = &compartment {
                    if led.compartment(&p.pid, cid)?.is_none() {
                        return Err(format!(
                            "unknown compartment {} on program {}",
                            cid.to_ascii_uppercase(),
                            p.pid
                        )
                        .into());
                    }
                }
                let agency = p.authority_id.clone();
                let (add_v, remove_v) = if add {
                    (delta.clone(), Vec::new())
                } else {
                    (Vec::new(), delta.clone())
                };
                let mut event = Event::new(EventKind::ProgramControlsChanged {
                    program_pid: p.pid.clone(),
                    compartment_id: compartment.clone(),
                    add: add_v,
                    remove: remove_v,
                });
                event.attribution =
                    session_attribution(policy.allow_attribution, allow_env_identity)?;
                let auth = load_auth(&data_dir, &agency)?;
                let seq = led.append(event, &auth)?;
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "program": p.pid,
                        "compartment": compartment.as_deref().map(|s| s.to_ascii_uppercase()),
                        "add": add,
                        "controls": delta,
                        "seq": seq,
                    }));
                } else {
                    let verb = if add { "added" } else { "removed" };
                    let target = match &compartment {
                        Some(cid) => format!("{} / {}", p.pid, cid.to_ascii_uppercase()),
                        None => p.pid,
                    };
                    ui.status(true, &format!("{verb} controls on {target} (seq {seq})"));
                }
            }
            ProgramCmd::Banner {
                pid,
                slices,
                profile,
            } => {
                let led = open_ledger(&data_dir, &policy)?;
                let p = require_program(&led, &pid)?;
                let all = led.compartments(&p.pid)?;
                let mut selected: Vec<&Compartment> = Vec::new();
                for sid in &slices {
                    let sid = sid.to_ascii_uppercase();
                    match all.iter().find(|c| c.id == sid) {
                        Some(c) => selected.push(c),
                        None => {
                            return Err(format!("unknown slice {sid} on program {}", p.pid).into());
                        }
                    }
                }
                let prof: Profile = profile.into();
                // `roll_up_marking` builds the CAPCO form (SAR-QSV-HOL-PER-SEN-TEV,
                // hyphen-joined siblings). The DoD banner drops PIDs per
                // DoDM 5205.07, so it swaps the SAR token to the program
                // nickname with no compartment suffix.
                let m = roll_up_marking(&p, &selected);
                let rollup = m.display_portion();
                let banner = match prof {
                    Profile::DoDBanner => {
                        let mut mb = m.clone();
                        for c in &mut mb.compartments {
                            if c.kind == lexicon_core::marking::CompartmentKind::Sap {
                                c.designator = p.nickname.clone();
                            }
                        }
                        mb.display_banner()
                    }
                    Profile::CapcoBanner => m.display_banner(),
                    // --profile is dod|capco; Portion is not a banner profile.
                    Profile::Portion => m.display_portion(),
                };
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "program": p.pid,
                        "slices": selected.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
                        "profile": format!("{prof:?}").to_lowercase(),
                        "banner": banner,
                        "rollup": rollup,
                    }));
                } else {
                    ui.banner_top(&m);
                    ui.kv("program", &p.pid);
                    ui.kv(
                        "slices",
                        &selected
                            .iter()
                            .map(|c| c.id.clone())
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    ui.kv("banner", &banner);
                    ui.kv("rollup", &rollup);
                    ui.banner_bottom(&m);
                }
            }
        },
        Cmd::Retire {
            name,
            agency,
            reason,
        } => {
            let agency = agency.to_ascii_uppercase();
            let mut event = Event::new(EventKind::Retired {
                name: name.clone(),
                reason,
                authority_id: agency.clone(),
            });
            event.attribution = session_attribution(policy.allow_attribution, allow_env_identity)?;
            append_lifecycle(&ui, &data_dir, &policy, &agency, event, None)?;
        }
        Cmd::Revoke {
            name,
            agency,
            reason,
            co_author,
        } => {
            let agency = agency.to_ascii_uppercase();
            let mut event = Event::new(EventKind::Revoked {
                name: name.clone(),
                reason,
                authority_id: agency.clone(),
            });
            event.attribution = session_attribution(policy.allow_attribution, allow_env_identity)?;
            append_lifecycle(
                &ui,
                &data_dir,
                &policy,
                &agency,
                event,
                co_author.as_deref(),
            )?;
        }
    }
    Ok(())
}

fn append_lifecycle(
    ui: &Ui,
    data: &Path,
    policy: &Policy,
    agency: &str,
    event: Event,
    co_author: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = load_auth(data, agency)?;
    let mut led = open_ledger(data, policy)?;
    let verb = event.kind.type_name();
    let norm = match &event.kind {
        EventKind::Retired { name, .. } | EventKind::Revoked { name, .. } => normalize(name),
        _ => return Err("append_lifecycle: not a retire/revoke event".into()),
    };
    let canonical = event.canonical_u_bytes();
    let seq = if let Some(co) = co_author {
        let co_agency = co.to_ascii_uppercase();
        let co_auth = load_auth(data, &co_agency)?;
        let sig =
            lexicon_core::Signature::join(vec![auth.sign(&canonical), co_auth.sign(&canonical)]);
        led.append_with(event, sig)?
    } else {
        led.append(event, &auth)?
    };
    if ui.is_json() {
        ui.json(&serde_json::json!({
            "name": norm,
            "seq": seq,
            "two_person": co_author.is_some(),
        }));
    } else {
        ui.status(true, &format!("{verb} {norm} (seq {seq})"));
        if co_author.is_some() {
            ui.kv("co-author", "required");
        }
    }
    Ok(())
}

fn resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf, Error> {
    match explicit {
        Some(p) => Ok(p.to_path_buf()),
        None => {
            #[cfg(feature = "highside")]
            {
                Err(Error::ImplicitDataDir)
            }
            #[cfg(not(feature = "highside"))]
            {
                Ok(PathBuf::from(".meridian"))
            }
        }
    }
}

fn keys_dir(data: &Path) -> PathBuf {
    data.join("keys")
}
fn load_auth(data: &Path, agency: &str) -> Result<Authority, Error> {
    Authority::load(&keys_dir(data), agency)
}
fn open_ledger(data: &Path, policy: &Policy) -> Result<Ledger, Error> {
    Ledger::open(data, policy)
}

fn parse_vrf_seed(hex_str: &str) -> Result<[u8; 32], Error> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| Error::Key(format!("decode seed: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Key("seed must be 32 bytes".into()))
}

fn mint_from_seed(cli: &Cli, inputs: &ResolvedInputs, ui: &Ui) -> Result<(), Box<dyn std::error::Error>> {
    let Cmd::Mint {
        seed: Some(seed_hex),
        r#type,
        agency,
        digraph,
        max_attempts,
        program,
        compartment,
    } = &cli.cmd
    else {
        unreachable!("seed mint");
    };
    let seed = parse_vrf_seed(seed_hex)?;
    let pools = bundled();
    let linter = lexicon_pools::bundled_linter();
    let marking = mint_marking(inputs);
    for w in marking.warnings() {
        eprintln!("warning: {w}");
    }
    let program_pid = pick_opt(
        inputs
            .binding
            .as_ref()
            .and_then(|b| b.program_pid.as_deref()),
        program.as_deref(),
    );
    let compartment_id = pick_opt(
        inputs
            .binding
            .as_ref()
            .and_then(|b| b.compartment_id.as_deref()),
        compartment.as_deref(),
    );
    if compartment_id.is_some() && program_pid.is_none() {
        return Err(Error::Parse("compartment_id requires program_pid".into()).into());
    }
    let agency = agency.to_ascii_uppercase();
    let candidates = Minter::mint_dry_run(
        &seed,
        &agency,
        pools,
        &linter,
        MintRequest {
            name_type: (*r#type).into(),
            pool_id: pools.id.clone(),
            max_attempts: *max_attempts,
            digraph: digraph.clone(),
            marking,
            attribution: Default::default(),
            program_pid,
            compartment_id,
        },
    )?;
    if ui.is_json() {
        ui.json(&serde_json::json!({
            "dry_run": true,
            "candidates": candidates,
        }));
    } else {
        ui.heading("candidates (not issued)");
        ui.kv("type", NameType::from(*r#type).as_str());
        ui.kv("agency", &agency);
        ui.names(
            &candidates
                .iter()
                .map(|m| m.name.clone())
                .collect::<Vec<_>>(),
        );
    }
    Ok(())
}

fn sample(words: &[String]) -> String {
    let n = words.len().min(8);
    let head: Vec<&str> = words.iter().take(n).map(String::as_str).collect();
    let mut s = head.join(", ");
    if words.len() > n {
        s.push_str(", ...");
    }
    s
}

fn collect_controls(
    sci: Vec<String>,
    dissem: Vec<String>,
    aea: Vec<String>,
    fgi: Vec<String>,
) -> Vec<Control> {
    let mut out = Vec::new();
    out.extend(sci.into_iter().map(|v| Control::new(ControlKind::Sci, v)));
    out.extend(
        dissem
            .into_iter()
            .map(|v| Control::new(ControlKind::Dissem, v)),
    );
    out.extend(aea.into_iter().map(|v| Control::new(ControlKind::Aea, v)));
    out.extend(fgi.into_iter().map(|v| Control::new(ControlKind::Fgi, v)));
    out
}

fn control_values(controls: &[Control], kind: ControlKind) -> Vec<&str> {
    controls
        .iter()
        .filter(|c| c.kind == kind)
        .map(|c| c.value.as_str())
        .collect()
}

fn require_program(led: &Ledger, pid: &str) -> Result<Program, Box<dyn std::error::Error>> {
    led.program(pid)?
        .ok_or_else(|| format!("unknown program: {}", pid.to_ascii_uppercase()).into())
}

fn append_program_event(
    data: &Path,
    policy: &Policy,
    agency: &str,
    kind: EventKind,
    allow_env_identity: bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut event = Event::new(kind);
    event.attribution = session_attribution(policy.allow_attribution, allow_env_identity)?;
    let auth = load_auth(data, agency)?;
    let mut led = open_ledger(data, policy)?;
    Ok(led.append(event, &auth)?)
}

/// `--include-attribution` without policy.allow_export_attribution is an error, not a silent omit.
fn attribution_visible(policy: &Policy, requested: bool) -> Result<bool, Error> {
    if requested && !policy.allow_export_attribution {
        return Err(Error::PolicyViolation(
            "--include-attribution is not allowed by policy.toml".into(),
        ));
    }
    Ok(requested && policy.allow_export_attribution)
}

/// `--bindings` without policy.allow_export_bindings is an error, not a silent omit.
fn bindings_export_allowed(policy: &Policy, requested: bool) -> Result<bool, Error> {
    if requested && !policy.allow_export_bindings {
        return Err(Error::PolicyViolation(
            "--bindings is not allowed by policy.toml".into(),
        ));
    }
    Ok(requested && policy.allow_export_bindings)
}

fn redact_attributions(recs: &mut [lexicon_core::NameRecord], show: bool) {
    if !show {
        for r in recs {
            r.attribution.clear();
        }
    }
}

fn redact_binding_export(rows: &mut [lexicon_core::BindingRow], show_attr: bool) {
    if !show_attr {
        for r in rows {
            r.attribution.clear();
        }
    }
}

fn names_export_marking(floor: Option<&Marking>) -> Marking {
    floor.cloned().unwrap_or_default()
}

fn bindings_export_marking(
    led: &Ledger,
    policy: &Policy,
    floor: Option<&Marking>,
) -> Result<Marking, Error> {
    let mut agg = led.aggregate_marking()?;
    if let Some(fm) = floor {
        agg = agg.max(fm);
    }
    if let Ok(req) = policy.required_banner.parse::<Marking>() {
        agg = agg.max(&req);
    }
    Ok(agg)
}

fn export_banner_json(m: &Marking) -> serde_json::Value {
    serde_json::json!({
        "_banner": true,
        "classification": m.display_banner(),
        "generated_at": lexicon_core::events::now_rfc3339(),
    })
}

/// `audit.jsonl` → `audit.bindings.jsonl`
fn bindings_sidecar(names_file: &Path) -> PathBuf {
    let stem = names_file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "export".into());
    let name = match names_file.extension() {
        Some(ext) => format!("{stem}.bindings.{}", ext.to_string_lossy()),
        None => format!("{stem}.bindings"),
    };
    match names_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn write_jsonl<T: serde::Serialize>(
    dest: &Path,
    banner: Option<&serde_json::Value>,
    rows: &[T],
) -> Result<(), Box<dyn std::error::Error>> {
    if dest == Path::new("-") {
        let stdout = std::io::stdout();
        let mut w = stdout.lock();
        write_jsonl_to(&mut w, banner, rows)?;
    } else {
        let mut f = std::fs::File::create(dest)?;
        write_jsonl_to(&mut f, banner, rows)?;
    }
    Ok(())
}

fn write_jsonl_to<W: Write, T: serde::Serialize>(
    w: &mut W,
    banner: Option<&serde_json::Value>,
    rows: &[T],
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(b) = banner {
        writeln!(w, "{b}")?;
    }
    for r in rows {
        writeln!(w, "{}", serde_json::to_string(r)?)?;
    }
    Ok(())
}

/// Page marking = max(displayed content), floored by resolved classification.
/// The banner is the aggregate of what's on the page, not the flag.
fn page_marking(recs: &[lexicon_core::NameRecord], floor: Option<&Marking>) -> Marking {
    let mut agg = Marking::default();
    for r in recs {
        if let Ok(m) = Marking::from_stored(&r.marking) {
            agg = agg.max(&m);
        }
    }
    if let Some(fm) = floor {
        agg = agg.max(fm);
    }
    agg
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn rejects_self_report_user_flag() {
        assert!(
            Cli::try_parse_from(["lexicon", "--user", "jdoe", "check", "--name", "X"]).is_err()
        );
    }

    #[test]
    fn rejects_self_report_host_ip_hwid() {
        for flag in ["--host", "--ip", "--hwid"] {
            assert!(
                Cli::try_parse_from(["lexicon", flag, "x", "check", "--name", "X"]).is_err(),
                "{flag} should be rejected"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn allow_env_identity_parses_in_debug() {
        let cli = Cli::try_parse_from(["lexicon", "--allow-env-identity", "check", "--name", "X"])
            .unwrap();
        assert!(cli.allow_env_identity);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn allow_env_identity_absent_in_release() {
        assert!(
            Cli::try_parse_from(["lexicon", "--allow-env-identity", "check", "--name", "X"])
                .is_err()
        );
    }

    #[test]
    fn approved_mode_parses() {
        let cli = Cli::try_parse_from(["lexicon", "--approved-mode", "ledger", "verify"]).unwrap();
        assert!(cli.approved_mode);
    }

    #[test]
    fn ledger_migrate_parses() {
        let cli = Cli::try_parse_from(["lexicon", "ledger", "migrate"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Ledger {
                cmd: LedgerCmd::Migrate
            }
        ));
    }

    #[test]
    fn data_dir_optional_at_parse() {
        let cli = Cli::try_parse_from(["lexicon", "check", "--name", "X"]).unwrap();
        assert!(cli.data_dir.is_none());
        assert!(!cli.persist_markings);
        assert!(!cli.include_attribution);
    }

    #[test]
    fn data_dir_and_policy_flags_parse() {
        let cli = Cli::try_parse_from([
            "lexicon",
            "--data-dir",
            "/var/lexicon",
            "--persist-markings",
            "--include-attribution",
            "check",
            "--name",
            "X",
        ])
        .unwrap();
        assert_eq!(cli.data_dir.as_deref(), Some(Path::new("/var/lexicon")));
        assert!(cli.persist_markings);
        assert!(cli.include_attribution);
    }

    #[test]
    fn attribution_hidden_without_flag() {
        let oss = Policy::default_oss();
        assert!(!attribution_visible(&oss, false).unwrap());
        assert!(matches!(
            attribution_visible(&oss, true),
            Err(Error::PolicyViolation(_))
        ));

        let mut allowed = Policy::default_oss();
        allowed.allow_export_attribution = true;
        assert!(!attribution_visible(&allowed, false).unwrap());
        assert!(attribution_visible(&allowed, true).unwrap());
    }

    #[test]
    fn redact_clears_attribution() {
        let rec = || lexicon_core::NameRecord {
            display: "OXIDE".into(),
            normalized: "OXIDE".into(),
            status: "issued".into(),
            name_type: "NICKNAME".into(),
            authority_id: "DIA".into(),
            event_seq: 1,
            created_at: String::new(),
            marking: "U".into(),
            attribution: "jdoe@ws001".into(),
            program_pid: None,
            compartment_id: None,
        };
        let mut keep = [rec()];
        redact_attributions(&mut keep, true);
        assert_eq!(keep[0].attribution, "jdoe@ws001");
        let mut hide = [rec()];
        redact_attributions(&mut hide, false);
        assert!(hide[0].attribution.is_empty());
    }

    #[test]
    fn export_default_is_names_only() {
        let cli =
            Cli::try_parse_from(["lexicon", "ledger", "export", "--file", "audit.jsonl"]).unwrap();
        match cli.cmd {
            Cmd::Ledger {
                cmd: LedgerCmd::Export { file, bindings },
            } => {
                assert_eq!(file, PathBuf::from("audit.jsonl"));
                assert!(!bindings);
            }
            _ => panic!("expected export"),
        }
    }

    #[test]
    fn export_bindings_flag_parses() {
        let cli = Cli::try_parse_from([
            "lexicon",
            "ledger",
            "export",
            "--file",
            "audit.jsonl",
            "--bindings",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Ledger {
                cmd: LedgerCmd::Export { bindings, .. },
            } => assert!(bindings),
            _ => panic!("expected export"),
        }
    }

    #[test]
    fn bindings_export_gate() {
        let oss = Policy::default_oss();
        assert!(!bindings_export_allowed(&oss, false).unwrap());
        assert!(matches!(
            bindings_export_allowed(&oss, true),
            Err(Error::PolicyViolation(_))
        ));

        let mut allowed = Policy::default_oss();
        allowed.allow_export_bindings = true;
        assert!(!bindings_export_allowed(&allowed, false).unwrap());
        assert!(bindings_export_allowed(&allowed, true).unwrap());
    }

    #[test]
    fn bindings_sidecar_inserts_before_extension() {
        assert_eq!(
            bindings_sidecar(Path::new("audit.jsonl")),
            PathBuf::from("audit.bindings.jsonl")
        );
        assert_eq!(
            bindings_sidecar(Path::new("/var/out/audit.jsonl")),
            PathBuf::from("/var/out/audit.bindings.jsonl")
        );
        assert_eq!(
            bindings_sidecar(Path::new("audit")),
            PathBuf::from("audit.bindings")
        );
    }

    #[test]
    fn names_export_marking_stays_u_unless_floored() {
        assert_eq!(names_export_marking(None).display_banner(), "UNCLASSIFIED");
        let s: Marking = "S".parse().unwrap();
        assert_eq!(names_export_marking(Some(&s)).display_banner(), "SECRET");
    }

    #[test]
    fn export_banner_uses_spelled_out_classification() {
        let m: Marking = "TS//TK//NOFORN".parse().unwrap();
        let v = export_banner_json(&m);
        assert_eq!(v["_banner"], true);
        assert_eq!(v["classification"], "TOP SECRET//TK//NOFORN");
        assert!(v["generated_at"].as_str().is_some());
    }

    #[test]
    fn write_jsonl_banner_then_rows() {
        let row = lexicon_core::NameRow {
            seq: 1,
            event_type: "issued".into(),
            created_at: "t".into(),
            name: Some("OXIDE".into()),
            canonical: "aa".into(),
            event_hash: "bb".into(),
            signature: "cc".into(),
        };
        let mut buf = Vec::new();
        let banner = export_banner_json(&Marking::default());
        write_jsonl_to(&mut buf, Some(&banner), &[row]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let mut lines = s.lines();
        let head = lines.next().unwrap();
        assert!(head.contains("\"_banner\":true"));
        assert!(head.contains("UNCLASSIFIED"));
        let body = lines.next().unwrap();
        assert!(body.contains("OXIDE"));
        assert!(!body.contains("marking"));
        assert!(!body.contains("attribution"));
        assert!(lines.next().is_none());
    }

    #[test]
    fn redact_binding_export_clears_attribution() {
        let row = || lexicon_core::BindingRow {
            seq: 1,
            event_type: "issued".into(),
            created_at: String::new(),
            names_seq: Some(1),
            marking: Some("TS".into()),
            program_pid: None,
            compartment_id: None,
            attribution: "jdoe@ws001".into(),
            canonical: String::new(),
            event_hash: String::new(),
            signature: String::new(),
        };
        let mut keep = [row()];
        redact_binding_export(&mut keep, true);
        assert_eq!(keep[0].attribution, "jdoe@ws001");
        let mut hide = [row()];
        redact_binding_export(&mut hide, false);
        assert!(hide[0].attribution.is_empty());
        let json = serde_json::to_string(&hide[0]).unwrap();
        assert!(!json.contains("attribution"));
        assert!(json.contains("marking"));
    }

    #[test]
    fn resolve_data_dir_profile() {
        #[cfg(not(feature = "highside"))]
        {
            assert_eq!(resolve_data_dir(None).unwrap(), PathBuf::from(".meridian"));
        }
        #[cfg(feature = "highside")]
        {
            assert!(matches!(
                resolve_data_dir(None),
                Err(Error::ImplicitDataDir)
            ));
        }
        assert_eq!(
            resolve_data_dir(Some(Path::new("/var/lexicon"))).unwrap(),
            PathBuf::from("/var/lexicon")
        );
    }

    #[test]
    fn mint_program_flags_parse() {
        let cli = Cli::try_parse_from([
            "lexicon",
            "mint",
            "--type",
            "codeword",
            "--agency",
            "DIA",
            "--program",
            "QSV",
            "--compartment",
            "HOL",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Mint {
                program,
                compartment,
                ..
            } => {
                assert_eq!(program.as_deref(), Some("QSV"));
                assert_eq!(compartment.as_deref(), Some("HOL"));
            }
            _ => panic!("expected mint"),
        }
    }

    #[test]
    fn mint_without_program_still_parses() {
        let cli = Cli::try_parse_from(["lexicon", "mint", "--type", "nickname", "--agency", "DIA"])
            .unwrap();
        match cli.cmd {
            Cmd::Mint {
                program,
                compartment,
                seed,
                ..
            } => {
                assert!(program.is_none());
                assert!(compartment.is_none());
                assert!(seed.is_none());
            }
            _ => panic!("expected mint"),
        }
    }

    #[test]
    fn mint_seed_parses() {
        let hex64 = "00".repeat(32);
        let cli = Cli::try_parse_from([
            "lexicon", "mint", "--type", "nickname", "--agency", "DIA", "--seed", &hex64,
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Mint { seed, .. } => assert_eq!(seed.as_deref(), Some(hex64.as_str())),
            _ => panic!("expected mint"),
        }
    }

    #[test]
    fn parse_vrf_seed_rejects_short() {
        assert!(parse_vrf_seed("00").is_err());
        assert!(parse_vrf_seed("zz").is_err());
        assert!(parse_vrf_seed(&"11".repeat(32)).is_ok());
    }

    #[test]
    fn mint_from_seed_smoke() {
        let hex64 = "11".repeat(32);
        let cli = Cli::try_parse_from([
            "lexicon",
            "--json",
            "mint",
            "--type",
            "nickname",
            "--agency",
            "DIA",
            "--seed",
            &hex64,
            "--max-attempts",
            "4",
        ])
        .unwrap();
        let inputs = resolve(None, None, None).unwrap();
        mint_from_seed(&cli, &inputs, &Ui::new(true)).unwrap();
    }

    #[test]
    fn marking_and_binding_file_flags_parse() {
        let cli = Cli::try_parse_from([
            "lexicon",
            "--marking-file",
            "/tmp/marking.json",
            "--binding-file",
            "/tmp/binding.toml",
            "check",
            "--name",
            "X",
        ])
        .unwrap();
        assert_eq!(
            cli.marking_file.as_deref(),
            Some(Path::new("/tmp/marking.json"))
        );
        assert_eq!(
            cli.binding_file.as_deref(),
            Some(Path::new("/tmp/binding.toml"))
        );
    }

    #[test]
    fn program_create_parses_repeatable_controls() {
        let cli = Cli::try_parse_from([
            "lexicon",
            "program",
            "create",
            "--pid",
            "QSV",
            "--nickname",
            "DILIGENTLY IMPRESSED",
            "--sap-type",
            "unack",
            "--level",
            "TS",
            "--agency",
            "DIA",
            "--sci",
            "TK",
            "--sci",
            "HCS",
            "--dissem",
            "NOFORN",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Program {
                cmd:
                    ProgramCmd::Create {
                        pid,
                        sap_type,
                        level,
                        sci,
                        dissem,
                        ..
                    },
            } => {
                assert_eq!(pid, "QSV");
                assert_eq!(sap_type, "unack");
                assert_eq!(level, "TS");
                assert_eq!(sci, vec!["TK", "HCS"]);
                assert_eq!(dissem, vec!["NOFORN"]);
            }
            _ => panic!("expected program create"),
        }
    }

    #[test]
    fn program_compartment_and_controls_parse() {
        let add = Cli::try_parse_from([
            "lexicon",
            "program",
            "compartment",
            "add",
            "--program",
            "QSV",
            "--id",
            "HOL",
            "--nickname",
            "HOLLERED",
            "--sci",
            "TK",
        ])
        .unwrap();
        match add.cmd {
            Cmd::Program {
                cmd:
                    ProgramCmd::Compartment {
                        cmd: CompartmentCmd::Add { id, sci, .. },
                    },
            } => {
                assert_eq!(id, "HOL");
                assert_eq!(sci, vec!["TK"]);
            }
            _ => panic!("expected compartment add"),
        }

        let ctl = Cli::try_parse_from([
            "lexicon",
            "program",
            "controls",
            "add",
            "--program",
            "QSV",
            "--compartment",
            "HOL",
            "--sci",
            "SI",
        ])
        .unwrap();
        match ctl.cmd {
            Cmd::Program {
                cmd:
                    ProgramCmd::Controls {
                        cmd: ControlsCmd::Add { sci, .. },
                    },
            } => assert_eq!(sci, vec!["SI"]),
            _ => panic!("expected controls add"),
        }
    }

    #[test]
    fn page_marking_is_typed_for_banner_profile() {
        let recs = [lexicon_core::NameRecord {
            display: "OXIDE".into(),
            normalized: "OXIDE".into(),
            status: "issued".into(),
            name_type: "CODE-WORD".into(),
            authority_id: "DIA".into(),
            event_seq: 1,
            created_at: String::new(),
            marking: "TS//TK//NOFORN".into(),
            attribution: String::new(),
            program_pid: None,
            compartment_id: None,
        }];
        let m = page_marking(&recs, None);
        assert_eq!(m.display_banner(), "TOP SECRET//TK//NOFORN");
        assert_eq!(m.display_portion(), "TS//TK//NF");
        let floored = page_marking(
            &recs,
            Some(&"TS//TK//SAR-QSV//NOFORN".parse().unwrap()),
        );
        assert_eq!(floored.display_banner(), "TOP SECRET//TK//SAR-QSV//NOFORN");
    }
}
