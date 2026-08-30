use clap::{Parser, Subcommand, ValueEnum};
use lexicon_core::events::{Event, EventKind};
use lexicon_core::ledger::Ledger;
use lexicon_core::linter::{LintSeverity, NameCandidate};
use lexicon_core::marking::{Level, Marking};
use lexicon_core::mint::{verify_mint, MintRequest, Minter};
use lexicon_core::pool::PoolWord;
use lexicon_core::program::{
    derive_marking, render_marking, roll_up_marking, Compartment, Control, ControlKind, Program,
    Profile, SapType,
};
use lexicon_core::types::{normalize, NameType};
use lexicon_core::{Authority, Error, Signer};
use lexicon_pools::bundled;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod identity;
mod steward;
mod ui;
use identity::session_attribution;
use ui::Ui;

#[derive(Parser)]
#[command(
    name = "lexicon",
    about = "meridian-lexicon: mint, verify, and lint un-guessable names",
    version
)]
struct Cli {
    #[arg(long, global = true, default_value = ".meridian")]
    data_dir: PathBuf,
    /// Source data dir for steward CRUD (agencies.json, reject lists).
    #[arg(long, global = true, default_value = "crates/lexicon-pools/data")]
    source_dir: PathBuf,
    /// Emit stable JSON for scripts. Default is human-readable.
    #[arg(long, global = true)]
    json: bool,
    /// Classification banner baked into export/mint artifacts (e.g. "CUI", "SECRET//NOFORN").
    #[arg(long, global = true)]
    classification: Option<String>,
    /// Refuse to run unless the FIPS 140-3 boundary is active (requires `--features fips`).
    #[arg(long, global = true)]
    approved_mode: bool,
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
    /// Mint a name (VRF + lint + uniqueness ledger)
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
    /// Dump the full event log as JSON lines for offline audit.
    Export {
        #[arg(long)]
        file: PathBuf,
    },
    /// Verify chain integrity + every event signature against a public key.
    Audit {
        #[arg(long, num_args = 1.., help = "public key(s); one for single-signer events, two for two-person control")]
        public_key: Vec<String>,
    },
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
    #[cfg(debug_assertions)]
    let allow_env_identity = cli.allow_env_identity;
    #[cfg(not(debug_assertions))]
    let allow_env_identity = false;
    let ui = Ui::new(cli.json);
    match cli.cmd {
        Cmd::Key { cmd } => match cmd {
            KeyCmd::Generate { agency } => {
                let agency = agency.to_ascii_uppercase();
                let _ = bundled().agency(&agency)?;
                let keys = keys_dir(&cli.data_dir);
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
                let keys = keys_dir(&cli.data_dir);
                let auth = load_auth(&cli.data_dir, &agency)?;
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
                let old = load_auth(&cli.data_dir, &agency)?;
                let new = Authority::generate(&agency);
                let kind = EventKind::KeyRotated {
                    authority_id: agency.clone(),
                    old_pk: hex::encode(old.public_key()),
                    new_pk: hex::encode(new.public_key()),
                    new_alg: new.alg(),
                };
                let mut event = Event::new(kind);
                event.attribution = session_attribution(allow_env_identity)?;
                let canonical = event.canonical_bytes();
                let mut led = open_ledger(&cli.data_dir)?;
                let seq = if let Some(co) = &co_author {
                    let co_agency = co.to_ascii_uppercase();
                    let co_auth = load_auth(&cli.data_dir, &co_agency)?;
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
                new.save(&keys_dir(&cli.data_dir))?;
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
        Cmd::Mint {
            r#type,
            agency,
            digraph,
            max_attempts,
            program,
            compartment,
        } => {
            let agency = agency.to_ascii_uppercase();
            let auth = load_auth(&cli.data_dir, &agency)?;
            let pools = bundled();
            let linter = lexicon_pools::bundled_linter();
            let mut ledger = open_ledger(&cli.data_dir)?;
            let mut minter = Minter::new(&auth, pools, &linter, &mut ledger);
            let marking = match &cli.classification {
                Some(c) => c
                    .parse::<Marking>()
                    .map_err(|e| format!("bad classification: {e}"))?,
                None => Marking::default(),
            };
            for w in marking.warnings() {
                eprintln!("warning: {w}");
            }
            let attribution = session_attribution(allow_env_identity)?;
            let minted = minter.mint(MintRequest {
                name_type: r#type.into(),
                pool_id: pools.id.clone(),
                max_attempts,
                digraph,
                marking,
                attribution,
                program_pid: program.clone(),
                compartment_id: compartment.clone(),
            })?;
            if ui.is_json() {
                let mut v = serde_json::to_value(&minted)?;
                let obj = v.as_object_mut().unwrap();
                if let Some(c) = &cli.classification {
                    obj.insert("classification".into(), c.clone().into());
                }
                if let Some(p) = &program {
                    obj.insert("program".into(), p.to_ascii_uppercase().into());
                }
                if let Some(c) = &compartment {
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
                if let Some(p) = &program {
                    ui.kv("program", &p.to_ascii_uppercase());
                }
                if let Some(c) = &compartment {
                    ui.kv("compartment", &c.to_ascii_uppercase());
                }
            }
        }
        Cmd::Verify { file, ledger } => {
            let raw = fs::read_to_string(&file)?;
            let minted: lexicon_core::MintedName = serde_json::from_str(&raw)?;
            let pools = bundled();
            if ledger {
                let led = open_ledger(&cli.data_dir)?;
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
                let led = open_ledger(&cli.data_dir)?;
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
                let led = open_ledger(&cli.data_dir)?;
                if sign {
                    let agency = agency
                        .ok_or(" --agency required with --sign")?
                        .to_ascii_uppercase();
                    let auth = load_auth(&cli.data_dir, &agency)?;
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
                let led = open_ledger(&cli.data_dir)?;
                let mut recs: Vec<_> = led
                    .name_records()?
                    .into_iter()
                    .filter(|r| r.status == "issued")
                    .collect();
                if let Some(m) = &marking {
                    let want: Marking = m.parse().map_err(|e| format!("bad --marking: {e}"))?;
                    recs.retain(|r| Marking::from_stored(&r.marking).is_ok_and(|rm| rm == want));
                }
                if ui.is_json() {
                    ui.json(&recs);
                } else {
                    let pm = page_marking(&recs, cli.classification.as_deref());
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
                let led = open_ledger(&cli.data_dir)?;
                match led.lookup(&name)? {
                    Some(r) => {
                        if ui.is_json() {
                            ui.json(&r);
                        } else {
                            let pm = page_marking(
                                std::slice::from_ref(&r),
                                cli.classification.as_deref(),
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
                            ui.kv("user", &r.attribution);
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
                let led = open_ledger(&cli.data_dir)?;
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
                if ui.is_json() {
                    ui.json(&recs);
                } else {
                    let pm = page_marking(&recs, cli.classification.as_deref());
                    ui.banner_top(&pm);
                    ui.heading(&format!("{} names", recs.len()));
                    for r in &recs {
                        ui.line(&format!(
                            "  {:<6} {:<14} {:<5} {}  {}  @{}",
                            r.status,
                            r.display,
                            r.authority_id,
                            ui::portion_of_stored(&r.marking),
                            r.created_at,
                            r.attribution
                        ));
                    }
                    ui.banner_bottom(&pm);
                }
            }
            LedgerCmd::Export { file } => {
                let led = open_ledger(&cli.data_dir)?;
                let rows = led.event_rows()?;
                // Container marking = max of exported event markings,
                // floored by --classification.
                let mut agg = Marking::default();
                for r in &rows {
                    if let Some(m) = r.marking.as_deref() {
                        if let Ok(parsed) = Marking::from_stored(m) {
                            agg = agg.max(&parsed);
                        }
                    }
                }
                if let Some(c) = &cli.classification {
                    if let Ok(fm) = c.parse::<Marking>() {
                        agg = agg.max(&fm);
                    }
                }
                let banner = (!rows.is_empty() || cli.classification.is_some()).then(|| {
                    serde_json::json!({
                        "_banner": true,
                        "classification": agg.to_string(),
                        "generated_at": lexicon_core::events::now_rfc3339(),
                    })
                });
                if file == Path::new("-") {
                    if let Some(b) = &banner {
                        let _ = writeln!(std::io::stdout(), "{b}");
                    }
                    for r in &rows {
                        let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string(r)?);
                    }
                } else {
                    let mut f = std::fs::File::create(&file)?;
                    if let Some(b) = &banner {
                        let _ = writeln!(f, "{b}");
                    }
                    for r in &rows {
                        let _ = writeln!(f, "{}", serde_json::to_string(r)?);
                    }
                    if !ui.is_json() {
                        ui.status(
                            true,
                            &format!("{} events to {}", rows.len(), file.display()),
                        );
                    }
                }
            }
            LedgerCmd::Audit { public_key } => {
                let led = open_ledger(&cli.data_dir)?;
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
                let controls = collect_controls(sci, dissem, aea, fgi);
                {
                    let led = open_ledger(&cli.data_dir)?;
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
                    &cli.data_dir,
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
                let led = open_ledger(&cli.data_dir)?;
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
                let led = open_ledger(&cli.data_dir)?;
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
                            ui.kv(
                                "DoD banner",
                                &render_marking(&p, None, Profile::DoDBanner),
                            );
                            if comps.is_empty() {
                                ui.line("  (no compartments)");
                            } else {
                                ui.heading("compartments");
                                for c in &comps {
                                    let cm = derive_marking(&p, Some(c));
                                    let sci = control_values(&c.controls, ControlKind::Sci);
                                    let mut line = format!(
                                        "  {:<6} {:<16} ",
                                        c.id, c.nickname,
                                    );
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
                                    ui.line(&format!("  {:<24} {}", r.display, ui::portion_of_stored(&r.marking)));
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
                let led = open_ledger(&cli.data_dir)?;
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
                    rows.push((c.nickname.clone(), "compartment nickname".into(), "U".into()));
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
                    let mut led = open_ledger(&cli.data_dir)?;
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
                    event.attribution = session_attribution(allow_env_identity)?;
                    let auth = load_auth(&cli.data_dir, &agency)?;
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
                let delta = collect_controls(sci, dissem, aea, fgi);
                if delta.is_empty() {
                    return Err("need at least one of --sci/--dissem/--aea/--fgi".into());
                }
                let mut led = open_ledger(&cli.data_dir)?;
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
                event.attribution = session_attribution(allow_env_identity)?;
                let auth = load_auth(&cli.data_dir, &agency)?;
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
                let led = open_ledger(&cli.data_dir)?;
                let p = require_program(&led, &pid)?;
                let all = led.compartments(&p.pid)?;
                let mut selected: Vec<&Compartment> = Vec::new();
                for sid in &slices {
                    let sid = sid.to_ascii_uppercase();
                    match all.iter().find(|c| c.id == sid) {
                        Some(c) => selected.push(c),
                        None => {
                            return Err(format!(
                                "unknown slice {sid} on program {}",
                                p.pid
                            )
                            .into());
                        }
                    }
                }
                let prof: Profile = profile.into();
                // Build the roll-up marking once; banner_top renders it via
                // display_banner, so the composite SAR token (spaces between
                // sibling compartments) is emitted correctly.
                let mut m = roll_up_marking(&p, &selected);
                if matches!(prof, Profile::DoDBanner) {
                    for c in &mut m.compartments {
                        if c.kind == lexicon_core::marking::CompartmentKind::Sap {
                            // SAR-<prog nickname>-<comp ids>; comp IDs stay
                            // (compartment nicknames contain spaces).
                            let head = p.nickname.clone();
                            c.designator = if selected.is_empty() {
                                head
                            } else {
                                let mut ids: Vec<String> =
                                    selected.iter().map(|x| x.id.to_ascii_uppercase()).collect();
                                ids.sort();
                                ids.dedup();
                                format!("{head}-{}", ids.join(" "))
                            };
                        }
                    }
                }
                let banner = m.display_banner();
                let portion = m.display_portion();
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "program": p.pid,
                        "slices": selected.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
                        "profile": format!("{prof:?}").to_lowercase(),
                        "banner": banner,
                        "portion": portion,
                    }));
                } else {
                    ui.banner_top(&m);
                    ui.kv("program", &p.pid);
                    ui.kv(
                        "slices",
                        &selected.iter().map(|c| c.id.clone()).collect::<Vec<_>>().join(","),
                    );
                    ui.kv("banner", &banner);
                    ui.kv("portion", &portion);
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
            event.attribution = session_attribution(allow_env_identity)?;
            append_lifecycle(&ui, &cli.data_dir, &agency, event, None)?;
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
            event.attribution = session_attribution(allow_env_identity)?;
            append_lifecycle(&ui, &cli.data_dir, &agency, event, co_author.as_deref())?;
        }
    }
    Ok(())
}

fn append_lifecycle(
    ui: &Ui,
    data: &Path,
    agency: &str,
    event: Event,
    co_author: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = load_auth(data, agency)?;
    let mut led = open_ledger(data)?;
    let verb = event.kind.type_name();
    let norm = match &event.kind {
        EventKind::Retired { name, .. } | EventKind::Revoked { name, .. } => normalize(name),
        _ => return Err("append_lifecycle: not a retire/revoke event".into()),
    };
    let canonical = event.canonical_bytes();
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

fn keys_dir(data: &Path) -> PathBuf {
    data.join("keys")
}
fn load_auth(data: &Path, agency: &str) -> Result<Authority, Error> {
    Authority::load(&keys_dir(data), agency)
}
fn open_ledger(data: &Path) -> Result<Ledger, Error> {
    Ledger::open(&data.join("ledger.sqlite"))
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
    agency: &str,
    kind: EventKind,
    allow_env_identity: bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut event = Event::new(kind);
    event.attribution = session_attribution(allow_env_identity)?;
    let auth = load_auth(data, agency)?;
    let mut led = open_ledger(data)?;
    Ok(led.append(event, &auth)?)
}

/// Page marking = max(displayed content), floored by `--classification`.
/// The banner is the aggregate of what's on the page, not the flag.
fn page_marking(recs: &[lexicon_core::NameRecord], floor: Option<&str>) -> Marking {
    let mut agg = Marking::default();
    for r in recs {
        if let Ok(m) = Marking::from_stored(&r.marking) {
            agg = agg.max(&m);
        }
    }
    if let Some(f) = floor {
        if let Ok(fm) = f.parse::<Marking>() {
            agg = agg.max(&fm);
        }
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
                ..
            } => {
                assert!(program.is_none());
                assert!(compartment.is_none());
            }
            _ => panic!("expected mint"),
        }
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
        let floored = page_marking(&recs, Some("TS//TK//SAR-QSV//NOFORN"));
        assert_eq!(floored.display_banner(), "TOP SECRET//TK//SAR-QSV//NOFORN");
    }
}
