//! Steward CRUD over the source data files (agencies.json, reject lists).
//!
//! These commands edit the source tree, not the running binary's bundled
//! pools (those are `include_str!`'d at build time). A steward who adds an
//! agency or a reject token here must rebuild and bump `POOL_ID` to ship the
//! change. The commands say so in their output.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const SET_FILES: &[(&str, &str)] = &[
    ("historical", "historical_cryptonyms.txt"),
    ("military", "military_acronyms.txt"),
];

#[derive(Deserialize, Serialize)]
struct AgenciesFile {
    agencies: Vec<AgencyEntry>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AgencyEntry {
    pub id: String,
    pub first_letters: String,
    pub digraphs: Vec<String>,
    pub sap_designators: Vec<String>,
}

pub fn list_agencies(source: &Path) -> Result<Vec<AgencyEntry>, String> {
    Ok(read_agencies(source)?.agencies)
}

pub fn add_agency(
    source: &Path,
    id: &str,
    first_letters: &str,
    digraphs: &[String],
    sap: &[String],
) -> Result<(), String> {
    let mut f = read_agencies(source)?;
    let id = id.to_ascii_uppercase();
    if f.agencies.iter().any(|a| a.id == id) {
        return Err(format!("agency {id} already exists"));
    }
    f.agencies.push(AgencyEntry {
        id,
        first_letters: first_letters.to_ascii_uppercase(),
        digraphs: digraphs.iter().map(|d| d.to_ascii_uppercase()).collect(),
        sap_designators: sap.iter().map(|s| s.to_ascii_uppercase()).collect(),
    });
    f.agencies.sort_by(|a, b| a.id.cmp(&b.id));
    write_agencies(source, &f)
}

pub fn remove_agency(source: &Path, id: &str) -> Result<(), String> {
    let mut f = read_agencies(source)?;
    let id = id.to_ascii_uppercase();
    let before = f.agencies.len();
    f.agencies.retain(|a| a.id != id);
    if f.agencies.len() == before {
        return Err(format!("agency {id} not found"));
    }
    write_agencies(source, &f)
}

pub fn list_rejects(source: &Path, set: &str) -> Result<Vec<String>, String> {
    let path = set_file(source, set)?;
    let mut out = Vec::new();
    for line in fs::read_to_string(&path)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let l = line.trim();
        if !l.is_empty() && !l.starts_with('#') {
            out.push(l.to_string());
        }
    }
    Ok(out)
}

pub fn add_reject(source: &Path, set: &str, token: &str) -> Result<(), String> {
    let path = set_file(source, set)?;
    let token = token.to_ascii_uppercase();
    let mut text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    if text.lines().any(|l| l.trim().eq_ignore_ascii_case(&token)) {
        return Err(format!("{token} already in {set}"));
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&token);
    text.push('\n');
    fs::write(&path, text).map_err(|e| e.to_string())
}

pub fn remove_reject(source: &Path, set: &str, token: &str) -> Result<(), String> {
    let path = set_file(source, set)?;
    let token = token.to_ascii_uppercase();
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().eq_ignore_ascii_case(&token))
        .collect();
    fs::write(&path, format!("{}\n", kept.join("\n"))).map_err(|e| e.to_string())
}

fn read_agencies(source: &Path) -> Result<AgenciesFile, String> {
    let path = source.join("agencies.json");
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn write_agencies(source: &Path, f: &AgenciesFile) -> Result<(), String> {
    let path = source.join("agencies.json");
    let text = serde_json::to_string_pretty(f).map_err(|e| e.to_string())?;
    fs::write(path, format!("{text}\n")).map_err(|e| e.to_string())
}

fn set_file(source: &Path, set: &str) -> Result<PathBuf, String> {
    for (name, file) in SET_FILES {
        if *name == set {
            return Ok(source.join(file));
        }
    }
    Err(format!(
        "unknown reject set '{set}'; known: {}",
        SET_FILES
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}
