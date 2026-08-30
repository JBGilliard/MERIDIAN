use clap::{Parser, Subcommand, ValueEnum};
use lexicon_core::events::{Event, EventKind};
use lexicon_core::ledger::Ledger;
use lexicon_core::linter::{LintSeverity, NameCandidate};
use lexicon_core::mint::{verify_mint, MintRequest, Minter};
use lexicon_core::pool::PoolWord;
use lexicon_core::types::{normalize, NameType};
use lexicon_core::{Authority, Error};
use lexicon_pools::bundled;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    /// Emit stable JSON for scripts. Default is human-readable.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an issuing-authority keypair
    Keygen {
        #[arg(long)]
        agency: String,
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
enum LedgerCmd {
    Verify,
    Root {
        #[arg(long)]
        sign: bool,
        #[arg(long)]
        agency: Option<String>,
    },
    Names,
}

#[derive(Subcommand)]
enum PoolCmd {
    Inspect {
        #[arg(long)]
        agency: Option<String>,
        #[arg(long, value_enum)]
        r#type: Option<TypeArg>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum TypeArg {
    Nickname,
    Codeword,
    Cryptonym,
    Sap,
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
        Cmd::Keygen { agency } => {
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
        Cmd::Ledger { cmd } => match cmd {
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
