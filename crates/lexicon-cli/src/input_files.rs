//! High-side marking/binding file loaders. Errors never echo CAPCO strings or PIDs.

use lexicon_core::marking::Marking;
use lexicon_core::Error;
use serde::Deserialize;
use std::path::Path;

const CLASSIFICATION_ARGV_WARNING: &str =
    "warning: --classification is argv-audited; prefer --marking-file on high side";

#[derive(Debug, Clone, Default)]
pub struct BindingInputs {
    pub marking: Option<Marking>,
    pub program_pid: Option<String>,
    pub compartment_id: Option<String>,
    pub sci: Vec<String>,
    pub dissem: Vec<String>,
    pub aea: Vec<String>,
    pub fgi: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedInputs {
    pub floor: Option<Marking>,
    pub binding: Option<BindingInputs>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkingFileDoc {
    #[serde(alias = "classification")]
    marking: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BindingFileDoc {
    marking: Option<String>,
    program_pid: Option<String>,
    compartment_id: Option<String>,
    #[serde(default)]
    sci: Vec<String>,
    #[serde(default)]
    dissem: Vec<String>,
    #[serde(default)]
    aea: Vec<String>,
    #[serde(default)]
    fgi: Vec<String>,
    #[serde(default)]
    controls: Option<ControlsDoc>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ControlsDoc {
    #[serde(default)]
    sci: Vec<String>,
    #[serde(default)]
    dissem: Vec<String>,
    #[serde(default)]
    aea: Vec<String>,
    #[serde(default)]
    fgi: Vec<String>,
}

pub fn warn_argv_classification(used: bool) {
    if used {
        eprintln!("{CLASSIFICATION_ARGV_WARNING}");
    }
}

pub fn resolve(
    cli_marking_file: Option<&Path>,
    cli_binding_file: Option<&Path>,
    argv_classification: Option<&str>,
) -> Result<ResolvedInputs, Error> {
    warn_argv_classification(argv_classification.is_some());

    let file_floor = cli_marking_file.map(load_marking_file).transpose()?;
    let binding = cli_binding_file.map(load_binding_file).transpose()?;

    let floor = binding
        .as_ref()
        .and_then(|b| b.marking.clone())
        .or(file_floor)
        .or_else(|| argv_classification.and_then(parse_marking_quiet));

    Ok(ResolvedInputs { floor, binding })
}

fn load_marking_file(path: &Path) -> Result<Marking, Error> {
    let doc: MarkingFileDoc = read_config(path, "marking-file")?;
    parse_marking_field(&doc.marking, "marking-file")
}

fn load_binding_file(path: &Path) -> Result<BindingInputs, Error> {
    let doc: BindingFileDoc = read_config(path, "binding-file")?;
    if doc.compartment_id.is_some() && doc.program_pid.is_none() {
        return Err(Error::Parse(
            "binding-file: compartment_id requires program_pid".into(),
        ));
    }
    let marking = doc
        .marking
        .as_deref()
        .map(|s| parse_marking_field(s, "binding-file"))
        .transpose()?;
    let mut sci = doc.sci;
    let mut dissem = doc.dissem;
    let mut aea = doc.aea;
    let mut fgi = doc.fgi;
    if let Some(c) = doc.controls {
        if sci.is_empty() {
            sci = c.sci;
        }
        if dissem.is_empty() {
            dissem = c.dissem;
        }
        if aea.is_empty() {
            aea = c.aea;
        }
        if fgi.is_empty() {
            fgi = c.fgi;
        }
    }
    Ok(BindingInputs {
        marking,
        program_pid: doc.program_pid,
        compartment_id: doc.compartment_id,
        sci,
        dissem,
        aea,
        fgi,
    })
}

fn read_config<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, Error> {
    let raw = std::fs::read_to_string(path)
        .map_err(|_| Error::Parse(format!("{label}: cannot read {}", path.display())))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "json" => {
            serde_json::from_str(&raw).map_err(|_| Error::Parse(format!("{label}: invalid JSON")))
        }
        "toml" => toml::from_str(&raw).map_err(|_| Error::Parse(format!("{label}: invalid TOML"))),
        _ => serde_json::from_str(&raw)
            .or_else(|_| toml::from_str(&raw))
            .map_err(|_| Error::Parse(format!("{label}: invalid format (use .json or .toml)"))),
    }
}

fn parse_marking_field(_raw: &str, label: &str) -> Result<Marking, Error> {
    parse_marking_quiet(_raw).ok_or_else(|| Error::Parse(format!("{label}: invalid marking")))
}

fn parse_marking_quiet(s: &str) -> Option<Marking> {
    s.parse::<Marking>().ok()
}

pub fn mint_marking(floor: &ResolvedInputs) -> Marking {
    floor
        .binding
        .as_ref()
        .and_then(|b| b.marking.clone())
        .or_else(|| floor.floor.clone())
        .unwrap_or_default()
}

pub fn pick_opt(bind: Option<&str>, argv: Option<&str>) -> Option<String> {
    bind.map(str::to_string)
        .or_else(|| argv.map(str::to_string))
}

pub fn merge_controls(
    binding: Option<&BindingInputs>,
    sci: &[String],
    dissem: &[String],
    aea: &[String],
    fgi: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let Some(b) = binding else {
        return (sci.to_vec(), dissem.to_vec(), aea.to_vec(), fgi.to_vec());
    };
    (
        if sci.is_empty() {
            b.sci.clone()
        } else {
            sci.to_vec()
        },
        if dissem.is_empty() {
            b.dissem.clone()
        } else {
            dissem.to_vec()
        },
        if aea.is_empty() {
            b.aea.clone()
        } else {
            aea.to_vec()
        },
        if fgi.is_empty() {
            b.fgi.clone()
        } else {
            fgi.to_vec()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn marking_file_json_parses() {
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(f, r#"{{"marking": "SECRET//NOFORN"}}"#).unwrap();
        let m = load_marking_file(f.path()).unwrap();
        assert_eq!(m.level, lexicon_core::marking::Level::Secret);
    }

    #[test]
    fn marking_file_toml_parses() {
        let mut f = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(f, r#"marking = "CUI""#).unwrap();
        let m = load_marking_file(f.path()).unwrap();
        assert_eq!(m.level, lexicon_core::marking::Level::Cui);
    }

    #[test]
    fn marking_file_bad_marking_no_spill() {
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(f, r#"{{"marking": "ZZZZ//NOFORN"}}"#).unwrap();
        let err = load_marking_file(f.path()).unwrap_err().to_string();
        assert!(err.contains("invalid marking"));
        assert!(!err.contains("ZZZZ"));
        assert!(!err.contains("NOFORN"));
    }

    #[test]
    fn binding_file_requires_program_for_compartment() {
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(f, r#"{{"compartment_id": "HOL", "program_pid": null}}"#).unwrap();
        let err = load_binding_file(f.path()).unwrap_err().to_string();
        assert!(err.contains("compartment_id requires program_pid"));
        assert!(!err.contains("HOL"));
    }

    #[test]
    fn binding_file_nested_controls() {
        let mut f = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(
            f,
            r#"
program_pid = "QSV"
marking = "TS//TK"
[controls]
sci = ["TK"]
dissem = ["NOFORN"]
"#
        )
        .unwrap();
        let b = load_binding_file(f.path()).unwrap();
        assert_eq!(b.program_pid.as_deref(), Some("QSV"));
        assert!(b.marking.is_some());
        assert_eq!(b.sci, vec!["TK"]);
        assert_eq!(b.dissem, vec!["NOFORN"]);
    }

    #[test]
    fn resolve_floor_precedence() {
        let mut mf = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(mf, r#"{{"marking": "SECRET"}}"#).unwrap();
        let mut bf = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(bf, r#"{{"marking": "TS//TK", "program_pid": "QSV"}}"#).unwrap();
        let r = resolve(Some(mf.path()), Some(bf.path()), Some("CUI")).unwrap();
        assert_eq!(
            r.floor.as_ref().map(|m| m.level),
            Some(lexicon_core::marking::Level::TopSecret)
        );
        assert_eq!(
            r.binding.as_ref().unwrap().program_pid.as_deref(),
            Some("QSV")
        );
    }

    #[test]
    fn merge_controls_argv_wins() {
        let bind = BindingInputs {
            sci: vec!["TK".into()],
            dissem: vec!["NOFORN".into()],
            ..Default::default()
        };
        let (sci, dissem, _, _) = merge_controls(Some(&bind), &["HCS".into()], &[], &[], &[]);
        assert_eq!(sci, vec!["HCS"]);
        assert_eq!(dissem, vec!["NOFORN"]);
    }
}
