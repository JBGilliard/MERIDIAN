use clap::{Parser, Subcommand, ValueEnum};
use lexicon_core::events::{Event, EventKind};
use lexicon_core::ledger::Ledger;
use lexicon_core::linter::{LintSeverity, NameCandidate};
use lexicon_core::mint::{verify_mint, MintRequest, Minter};
use lexicon_core::pool::PoolWord;
use lexicon_core::types::{normalize, NameType};
use lexicon_core::{Authority, Error, Signer};
use lexicon_pools::bundled;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod steward;
mod ui;
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
        #[arg(long, default_value = "scheduled")]
        reason: String,
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
    Names,
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
    },
    /// Dump the full event log as JSON lines for offline audit.
    Export {
        #[arg(long)]
        file: PathBuf,
    },
    /// Verify chain integrity + every event signature against a public key.
    Audit {
        #[arg(long)]
        public_key: String,
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
            KeyCmd::Rotate { agency, reason } => {
                let agency = agency.to_ascii_uppercase();
                let old = load_auth(&cli.data_dir, &agency)?;
                let new = Authority::generate(&agency);
                let kind = EventKind::KeyRotated {
                    authority_id: agency.clone(),
                    old_pk: hex::encode(old.public_key()),
                    new_pk: hex::encode(new.public_key()),
                    new_alg: new.alg(),
                };
                let mut led = open_ledger(&cli.data_dir)?;
                let seq = led.append(Event::new(kind), &old)?;
                // Only persist the new seed after the rotation event is durably
                // on the ledger. A crash before this line leaves the old key
                // active and the rotation unrecorded — recoverable.
                new.save(&keys_dir(&cli.data_dir))?;
                if ui.is_json() {
                    ui.json(&serde_json::json!({
                        "agency": agency,
                        "seq": seq,
                        "old_pk": hex::encode(old.public_key()),
                        "new_pk": hex::encode(new.public_key()),
                        "new_alg": new.alg().as_str(),
                        "reason": reason,
                    }));
                } else {
                    ui.status(true, &format!("rotated {agency} key (seq {seq})"));
                    ui.kv("old pk", &hex::encode(old.public_key()));
                    ui.kv("new pk", &hex::encode(new.public_key()));
                    ui.kv("algorithm", new.alg().as_str());
                    ui.line(&format!("  destroy the old seed; {reason}"));
                }
            }
        },
        Cmd::Mint {
            r#type,
            agency,
            digraph,
            max_attempts,
        } => {
            let agency = agency.to_ascii_uppercase();
            let auth = load_auth(&cli.data_dir, &agency)?;
            let pools = bundled();
            let linter = lexicon_pools::bundled_linter();
            let mut ledger = open_ledger(&cli.data_dir)?;
            let mut minter = Minter {
                authority: &auth,
                pools,
                linter: &linter,
                ledger: &mut ledger,
            };
            let minted = minter.mint(MintRequest {
                name_type: r#type.into(),
                pool_id: pools.id.clone(),
                max_attempts,
                digraph,
            })?;
            if ui.is_json() {
                ui.json(&minted);
            } else {
                ui.heading(&format!("minted {}", minted.name));
                ui.kv("type", minted.name_type.as_str());
                ui.kv("agency", &minted.authority_id);
                ui.kv("sequence", &minted.sequence.to_string());
                ui.kv("nonce", &minted.nonce.to_string());
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
        Cmd::Ledger { cmd } => {
            match cmd {
                LedgerCmd::Verify => {
                    let led = open_ledger(&cli.data_dir)?;
                    led.verify_chain()?;
                    let events = led.len()?;
                    let root = hex::encode(led.root()?);
                    if ui.is_json() {
                        ui.json(&serde_json::json!({ "ok": true, "events": events, "root": root }));
                    } else {
                        ui.status(true, &format!("{events} events, root 0x{root}"));
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
                LedgerCmd::Names => {
                    let led = open_ledger(&cli.data_dir)?;
                    let names = led.issued_names()?;
                    if ui.is_json() {
                        ui.json(&names);
                    } else {
                        ui.heading(&format!("{} issued names", names.len()));
                        ui.names(&names);
                    }
                }
                LedgerCmd::Lookup { name } => {
                    let led = open_ledger(&cli.data_dir)?;
                    match led.lookup(&name)? {
                        Some(r) => {
                            if ui.is_json() {
                                ui.json(&r);
                            } else {
                                ui.status(r.status == "issued", &r.display);
                                ui.kv("status", &r.status);
                                ui.kv("type", &r.name_type);
                                ui.kv("agency", &r.authority_id);
                                ui.kv("seq", &r.event_seq.to_string());
                                ui.kv("at", &r.created_at);
                            }
                        }
                        None => {
                            if ui.is_json() {
                                ui.json(&serde_json::json!({ "name": normalize(&name), "found": false }));
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
                    if ui.is_json() {
                        ui.json(&recs);
                    } else {
                        ui.heading(&format!("{} names", recs.len()));
                        for r in &recs {
                            ui.line(&format!(
                                "  {:<6} {:<10} {:<5} {}",
                                r.status, r.display, r.authority_id, r.created_at
                            ));
                        }
                    }
                }
                LedgerCmd::Export { file } => {
                    let led = open_ledger(&cli.data_dir)?;
                    let rows = led.event_rows()?;
                    if file == Path::new("-") {
                        for r in &rows {
                            let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string(r)?);
                        }
                    } else {
                        let mut f = std::fs::File::create(&file)?;
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
                    let pk = hex::decode(public_key.trim())
                        .map_err(|e| format!("bad public key hex: {e}"))?;
                    let total = led.len()?;
                    let mut failed = Vec::new();
                    for seq in 1..=total {
                        if led.verify_event_signature(seq, &pk).is_err() {
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
            }
        }
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
        Cmd::Retire {
            name,
            agency,
            reason,
        } => {
            retire_or_revoke(&ui, &cli.data_dir, &agency, &name, &reason, false)?;
        }
        Cmd::Revoke {
            name,
            agency,
            reason,
        } => {
            retire_or_revoke(&ui, &cli.data_dir, &agency, &name, &reason, true)?;
        }
    }
    Ok(())
}

fn retire_or_revoke(
    ui: &Ui,
    data: &Path,
    agency: &str,
    name: &str,
    reason: &str,
    revoke: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let agency = agency.to_ascii_uppercase();
    let auth = load_auth(data, &agency)?;
    let mut led = open_ledger(data)?;
    let kind = if revoke {
        EventKind::Revoked {
            name: name.to_string(),
            reason: reason.to_string(),
            authority_id: agency,
        }
    } else {
        EventKind::Retired {
            name: name.to_string(),
            reason: reason.to_string(),
            authority_id: agency,
        }
    };
    let seq = led.append(Event::new(kind), &auth)?;
    let norm = normalize(name);
    if ui.is_json() {
        ui.json(&serde_json::json!({ "name": norm, "seq": seq }));
    } else {
        let verb = if revoke { "revoked" } else { "retired" };
        ui.status(true, &format!("{verb} {norm} (seq {seq})"));
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
