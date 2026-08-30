//! SAP Program object model.
//!
//! Names bind to a Program (and optional Compartment). Markings are derived
//! at read time from current program+compartment controls — never stored for
//! program-bound names. A `ProgramControlsChanged` event re-derives retroactively;
//! the event log is the audit trail.

use crate::error::{Error, Result};
use crate::marking::{Caveat, Compartment as MarkingComp, CompartmentKind, Level, Marking};
use crate::types::normalize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SapType {
    Acknowledged,
    Unacknowledged,
    Waived,
}

impl SapType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::Unacknowledged => "unacknowledged",
            Self::Waived => "waived",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "acknowledged" | "ack" => Ok(Self::Acknowledged),
            "unacknowledged" | "unack" => Ok(Self::Unacknowledged),
            "waived" => Ok(Self::Waived),
            other => Err(Error::Parse(format!("unknown sap type: {other}"))),
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::Acknowledged => 1,
            Self::Unacknowledged => 2,
            Self::Waived => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Sci,
    Dissem,
    Aea,
    Fgi,
}

impl ControlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sci => "sci",
            Self::Dissem => "dissem",
            Self::Aea => "aea",
            Self::Fgi => "fgi",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sci" => Ok(Self::Sci),
            "dissem" => Ok(Self::Dissem),
            "aea" => Ok(Self::Aea),
            "fgi" => Ok(Self::Fgi),
            other => Err(Error::Parse(format!("unknown control kind: {other}"))),
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::Sci => 1,
            Self::Dissem => 2,
            Self::Aea => 3,
            Self::Fgi => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Control {
    pub kind: ControlKind,
    pub value: String,
}

impl Control {
    pub fn new(kind: ControlKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into().trim().to_ascii_uppercase(),
        }
    }

    fn matches(&self, kind: ControlKind, value: &str) -> bool {
        self.kind == kind && self.value.eq_ignore_ascii_case(value.trim())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub pid: String,
    pub nickname: String,
    pub codeword: Option<String>,
    pub sap_type: SapType,
    pub level: Level,
    pub authority_id: String,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compartment {
    pub program_pid: String,
    pub id: String,
    pub nickname: String,
    pub codeword: Option<String>,
    pub parent_id: Option<String>,
    pub controls: Vec<Control>,
    /// Override the program level for this slice (e.g. TEV at S). None
    /// means inherit the program level. A compartment may lower, not raise.
    pub level: Option<Level>,
}

/// Fold input. EventKind variants (events.rs) map 1:1 onto these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramEvent {
    Created(Program),
    CompartmentAdded(Compartment),
    ControlsChanged {
        program_pid: String,
        compartment_id: Option<String>,
        add: Vec<Control>,
        remove: Vec<Control>,
    },
}

/// In-memory fold of program events. Ledger persists the same transitions.
#[derive(Debug, Clone, Default)]
pub struct ProgramSet {
    programs: HashMap<String, Program>,
    compartments: HashMap<(String, String), Compartment>,
}

impl ProgramSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: ProgramEvent) -> Result<()> {
        match event {
            ProgramEvent::Created(mut p) => {
                normalize_program(&mut p);
                if p.pid.is_empty() {
                    return Err(Error::Parse("program pid is empty".into()));
                }
                if self.programs.contains_key(&p.pid) {
                    return Err(Error::Parse(format!("program already exists: {}", p.pid)));
                }
                self.programs.insert(p.pid.clone(), p);
            }
            ProgramEvent::CompartmentAdded(mut c) => {
                normalize_compartment(&mut c);
                if c.id.is_empty() {
                    return Err(Error::Parse("compartment id is empty".into()));
                }
                if !self.programs.contains_key(&c.program_pid) {
                    return Err(Error::Parse(format!("unknown program: {}", c.program_pid)));
                }
                let key = (c.program_pid.clone(), c.id.clone());
                if self.compartments.contains_key(&key) {
                    return Err(Error::Parse(format!(
                        "compartment {} already exists on {}",
                        c.id, c.program_pid
                    )));
                }
                self.compartments.insert(key, c);
            }
            ProgramEvent::ControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            } => {
                let pid = key(&program_pid);
                match compartment_id {
                    None => {
                        let p = self
                            .programs
                            .get_mut(&pid)
                            .ok_or_else(|| Error::Parse(format!("unknown program: {pid}")))?;
                        apply_delta(&mut p.controls, &add, &remove);
                    }
                    Some(cid) => {
                        let cid = key(&cid);
                        let c = self
                            .compartments
                            .get_mut(&(pid.clone(), cid.clone()))
                            .ok_or_else(|| {
                                Error::Parse(format!("unknown compartment {cid} on program {pid}"))
                            })?;
                        apply_delta(&mut c.controls, &add, &remove);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn program(&self, pid: &str) -> Option<&Program> {
        self.programs.get(&key(pid))
    }

    pub fn compartment(&self, pid: &str, id: &str) -> Option<&Compartment> {
        self.compartments.get(&(key(pid), key(id)))
    }

    pub fn programs(&self) -> impl Iterator<Item = &Program> {
        self.programs.values()
    }

    pub fn compartments(&self, pid: &str) -> Vec<&Compartment> {
        let pid = key(pid);
        let mut out: Vec<_> = self
            .compartments
            .values()
            .filter(|c| c.program_pid == pid)
            .collect();
        out.sort_by_key(|c| c.id.as_str());
        out
    }

    pub fn derive_marking(&self, pid: &str, compartment_id: Option<&str>) -> Result<Marking> {
        let p = self
            .program(pid)
            .ok_or_else(|| Error::Parse(format!("unknown program: {}", key(pid))))?;
        let c = match compartment_id {
            Some(id) => Some(self.compartment(pid, id).ok_or_else(|| {
                Error::Parse(format!(
                    "unknown compartment {} on program {}",
                    key(id),
                    key(pid)
                ))
            })?),
            None => None,
        };
        Ok(derive_marking(p, c))
    }
}

/// Level from program; SCI = program.sci ++ compartment.sci (deduped);
/// SAR = pid or pid-compid; AEA/FGI/dissem from the program.
pub fn derive_marking(program: &Program, compartment: Option<&Compartment>) -> Marking {    let mut sci: Vec<String> = values_of(&program.controls, ControlKind::Sci);
    if let Some(c) = compartment {
        for v in values_of(&c.controls, ControlKind::Sci) {
            if !sci.iter().any(|s| s == &v) {
                sci.push(v);
            }
        }
    }

    let mut compartments: Vec<MarkingComp> = sci
        .into_iter()
        .map(|designator| MarkingComp {
            kind: CompartmentKind::Sci,
            designator,
        })
        .collect();

    let pid = key(&program.pid);
    let sar = match compartment {
        Some(c) => format!("{pid}-{}", key(&c.id)),
        None => pid,
    };
    compartments.push(MarkingComp {
        kind: CompartmentKind::Sap,
        designator: sar,
    });

    for v in values_of(&program.controls, ControlKind::Aea) {
        compartments.push(aea_comp(&v));
    }
    for c in &program.controls {
        if c.kind != ControlKind::Fgi {
            continue;
        }
        let v = key(&c.value);
        let designator = if v.is_empty() || v == "FGI" {
            String::new()
        } else {
            v
        };
        compartments.push(MarkingComp {
            kind: CompartmentKind::Fgi,
            designator,
        });
    }

    let mut caveats: Vec<Caveat> = values_of(&program.controls, ControlKind::Dissem)
        .into_iter()
        .map(dissem_caveat)
        .collect();
    // Waived SAPs carry WAIVED; it's a program attribute, not operator dissem.
    // Placed before other dissem controls (e.g. //WAIVED//NOFORN).
    if program.sap_type == SapType::Waived
        && !caveats.iter().any(|c| matches!(c, Caveat::Waived))
    {
        caveats.insert(0, Caveat::Waived);
    }

    Marking {
        level: compartment
            .and_then(|c| c.level)
            .unwrap_or(program.level),
        caveats,
        compartments,
    }
}

fn key(s: &str) -> String {
    s.trim().to_ascii_uppercase()
}

/// Rendering profile. DoD SAP banners use the program nickname in the SAR
/// token; CAPCO short banners and portion marks use the PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    DoDBanner,
    CapcoBanner,
    Portion,
}

/// Render a single-compartment (or standing) marking. Thin wrapper over
/// the multi-compartment roll-up.
pub fn render_marking(
    program: &Program,
    compartment: Option<&Compartment>,
    profile: Profile,
) -> String {
    let comps: Vec<&Compartment> = match compartment {
        Some(c) => vec![c],
        None => vec![],
    };
    render_roll_up(program, &comps, profile)
}

/// Roll-up banner/portion for a document that contains `compartments`.
/// CAPCO: one program, sibling compartments hyphenated to the PID and
/// separated by spaces (alphanumeric order). `SAR-` is not repeated per
/// slice; `//` does not separate siblings. SCI appears only if a slice
/// in this document carries it.
pub fn render_roll_up(
    program: &Program,
    compartments: &[&Compartment],
    profile: Profile,
) -> String {
    let mut m = roll_up_marking(program, compartments);
    match profile {
        Profile::DoDBanner => {
            // DoDM 5205.07: PIDs stay out of the banner. The DoD banner is
            // the standing form (program nickname, no compartment IDs);
            // slices live in portion marks and the slices field.
            for c in &mut m.compartments {
                if c.kind == CompartmentKind::Sap {
                    c.designator = program.nickname.clone();
                }
            }
            m.display_banner()
        }
        Profile::CapcoBanner => m.display_banner(),
        Profile::Portion => m.display_portion(),
    }
}

/// Build the roll-up marking. SAR designator = `pid` or `pid-comp1 comp2 ...`
/// (comp IDs, space-separated, sorted). SCI = program SCI ∪ included
/// compartments' SCI. AEA/FGI/dissem from the program; WAIVED if waived.
pub fn roll_up_marking(program: &Program, compartments: &[&Compartment]) -> Marking {
    let mut sci: Vec<String> = values_of(&program.controls, ControlKind::Sci);
    for c in compartments {
        for v in values_of(&c.controls, ControlKind::Sci) {
            if !sci.iter().any(|s| s == &v) {
                sci.push(v);
            }
        }
    }
    let mut comps: Vec<MarkingComp> = sci
        .into_iter()
        .map(|designator| MarkingComp {
            kind: CompartmentKind::Sci,
            designator,
        })
        .collect();
    comps.push(MarkingComp {
        kind: CompartmentKind::Sap,
        designator: sar_designator(program, compartments, false),
    });
    for v in values_of(&program.controls, ControlKind::Aea) {
        comps.push(aea_comp(&v));
    }
    for ctl in &program.controls {
        if ctl.kind != ControlKind::Fgi {
            continue;
        }
        let v = key(&ctl.value);
        let designator = if v.is_empty() || v == "FGI" {
            String::new()
        } else {
            v
        };
        comps.push(MarkingComp {
            kind: CompartmentKind::Fgi,
            designator,
        });
    }
    let mut caveats: Vec<Caveat> = values_of(&program.controls, ControlKind::Dissem)
        .into_iter()
        .map(dissem_caveat)
        .collect();
    if program.sap_type == SapType::Waived
        && !caveats.iter().any(|c| matches!(c, Caveat::Waived))
    {
        caveats.insert(0, Caveat::Waived);
    }
    Marking {
        // Document level = highest level of any included portion. A
        // compartment may lower (TEV at S); standing uses program level.
        level: if compartments.is_empty() {
            program.level
        } else {
            compartments
                .iter()
                .map(|c| c.level.unwrap_or(program.level))
                .max()
                .unwrap_or(program.level)
        },
        caveats,
        compartments: comps,
    }
}

/// SAR designator. `use_nickname` swaps the PID for the program nickname
/// (DoD banner); compartment IDs stay (compartment nicknames contain
/// spaces and would be ambiguous between siblings).
///
/// CAPCO separators: hyphen joins a control to its compartments and joins
/// sibling compartments; space joins subcompartments under one compartment.
/// `SAR-QSV-HOL-PER-SEN-TEV` = four siblings; `SAR-QSV-HOL-PER A1 A2-SEN-TEV`
/// = HOL, PER (with A1 A2 nested), SEN, TEV.
fn sar_designator(program: &Program, compartments: &[&Compartment], use_nickname: bool) -> String {
    let head = if use_nickname {
        program.nickname.clone()
    } else {
        key(&program.pid)
    };
    if compartments.is_empty() {
        return head;
    }
    let entries: Vec<(String, Option<String>)> = compartments
        .iter()
        .map(|c| (key(&c.id), c.parent_id.as_deref().map(key)))
        .collect();
    let selected: std::collections::HashSet<String> =
        entries.iter().map(|(id, _)| id.clone()).collect();
    // Top-level = parent is None or parent not in the selected set.
    let mut top: Vec<&(String, Option<String>)> = entries
        .iter()
        .filter(|(_, p)| match p {
            None => true,
            Some(parent) => !selected.contains(parent),
        })
        .collect();
    top.sort_by(|a, b| a.0.cmp(&b.0));
    let parts: Vec<String> = top
        .iter()
        .map(|(id, _)| {
            let mut children: Vec<String> = entries
                .iter()
                .filter(|(_, p)| p.as_deref() == Some(id))
                .map(|(cid, _)| cid.clone())
                .collect();
            children.sort();
            children.dedup();
            if children.is_empty() {
                id.clone()
            } else {
                format!("{id} {}", children.join(" "))
            }
        })
        .collect();
    format!("{head}-{}", parts.join("-"))
}

fn normalize_program(p: &mut Program) {
    p.pid = key(&p.pid);
    p.nickname = normalize(&p.nickname);
    p.codeword = p
        .codeword
        .as_deref()
        .map(normalize)
        .filter(|s| !s.is_empty());
    p.authority_id = p.authority_id.trim().to_string();
    for c in &mut p.controls {
        c.value = key(&c.value);
    }
}

fn normalize_compartment(c: &mut Compartment) {
    c.program_pid = key(&c.program_pid);
    c.id = key(&c.id);
    c.nickname = normalize(&c.nickname);
    c.codeword = c
        .codeword
        .as_deref()
        .map(normalize)
        .filter(|s| !s.is_empty());
    c.parent_id = c.parent_id.as_deref().map(key).filter(|s| !s.is_empty());
    for ctl in &mut c.controls {
        ctl.value = key(&ctl.value);
    }
}

fn apply_delta(controls: &mut Vec<Control>, add: &[Control], remove: &[Control]) {
    for r in remove {
        controls.retain(|c| !c.matches(r.kind, &r.value));
    }
    for a in add {
        let v = key(&a.value);
        if v.is_empty() {
            continue;
        }
        if !controls.iter().any(|c| c.matches(a.kind, &v)) {
            controls.push(Control {
                kind: a.kind,
                value: v,
            });
        }
    }
}

fn values_of(controls: &[Control], kind: ControlKind) -> Vec<String> {
    controls
        .iter()
        .filter(|c| c.kind == kind && !c.value.is_empty())
        .map(|c| key(&c.value))
        .collect()
}

fn aea_comp(value: &str) -> MarkingComp {
    let up = key(value);
    let (head, rest) = match up.split_once('/') {
        Some((h, d)) => (h, d.to_string()),
        None => (up.as_str(), String::new()),
    };
    let kind = match head {
        "RD-FRD" | "RDFRD" => CompartmentKind::RdFrd,
        "CNWDI" => CompartmentKind::Cnwdi,
        _ => CompartmentKind::Other,
    };
    let designator = if kind == CompartmentKind::Other && rest.is_empty() {
        up
    } else {
        rest
    };
    MarkingComp { kind, designator }
}

fn dissem_caveat(value: String) -> Caveat {
    Caveat::parse(&value).unwrap_or(Caveat::Other { token: value })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qsv() -> Program {
        Program {
            pid: "QSV".into(),
            nickname: "DILIGENTLY IMPRESSED".into(),
            codeword: None,
            sap_type: SapType::Unacknowledged,
            level: Level::TopSecret,
            authority_id: "DIA".into(),
            controls: vec![
                Control::new(ControlKind::Sci, "TK"),
                Control::new(ControlKind::Dissem, "NOFORN"),
            ],
        }
    }

    fn hol() -> Compartment {
        Compartment {
            program_pid: "QSV".into(),
            id: "HOL".into(),
            nickname: "HOLLERED".into(),
            codeword: None,
            parent_id: None,
            controls: vec![Control::new(ControlKind::Sci, "TK")],
            level: None,
        }
    }

    #[test]
    fn derive_program_only() {
        let m = derive_marking(&qsv(), None);
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV//NF");
        assert_eq!(m.display_banner(), "TOP SECRET//TK//SAR-QSV//NOFORN");
    }

    #[test]
    fn waived_sap_emits_waived_before_dissem() {
        let mut p = qsv();
        p.sap_type = SapType::Waived;
        let m = derive_marking(&p, None);
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV//WAIVED//NF");
        assert_eq!(
            m.display_banner(),
            "TOP SECRET//TK//SAR-QSV//WAIVED//NOFORN"
        );
    }

    #[test]
    fn dod_banner_keeps_pids_out() {
        let p = qsv();
        let c = hol();
        // Standing: program nickname, no compartments.
        assert_eq!(
            render_marking(&p, None, Profile::DoDBanner),
            "TOP SECRET//TK//SAR-DILIGENTLY IMPRESSED//NOFORN"
        );
        // DoD banner drops compartment PIDs (DoDM 5205.07); slices live in
        // portion marks and the slices field, not the banner string.
        assert_eq!(
            render_marking(&p, Some(&c), Profile::DoDBanner),
            "TOP SECRET//TK//SAR-DILIGENTLY IMPRESSED//NOFORN"
        );
        // CAPCO short and portion keep the PID + compartment form.
        assert_eq!(
            render_marking(&p, Some(&c), Profile::CapcoBanner),
            "TOP SECRET//TK//SAR-QSV-HOL//NOFORN"
        );
        assert_eq!(
            render_marking(&p, Some(&c), Profile::Portion),
            "TS//TK//SAR-QSV-HOL//NF"
        );
    }

    #[test]
    fn roll_up_one_sap_with_sibling_compartments() {
        // Program has no SCI; only SEN carries TK. Standing banner has no TK;
        // roll-up including SEN pulls TK in. Sibling compartments are
        // hyphen-joined under one SAR token (CAPCO: hyphen joins siblings;
        // space joins subcompartments under one compartment).
        let mut p = qsv();
        p.controls.retain(|c| c.kind != ControlKind::Sci); // no TK on program
        let hol_c = Compartment {
            id: "HOL".into(),
            controls: vec![],
            ..hol()
        };
        let per_c = Compartment {
            id: "PER".into(),
            controls: vec![],
            ..hol()
        };
        let sen_c = Compartment {
            id: "SEN".into(),
            controls: vec![Control::new(ControlKind::Sci, "TK")],
            ..hol()
        };
        let tev_c = Compartment {
            id: "TEV".into(),
            controls: vec![],
            ..hol()
        };
        // Single-compartment portion (propulsion only): no TK.
        assert_eq!(
            render_roll_up(&p, &[&per_c], Profile::Portion),
            "TS//SAR-QSV-PER//NF"
        );
        // All four slices: TK appears (SEN included), one SAR token,
        // siblings hyphen-joined in alphanumeric order.
        let all: Vec<&Compartment> = vec![&hol_c, &per_c, &sen_c, &tev_c];
        assert_eq!(
            render_roll_up(&p, &all, Profile::CapcoBanner),
            "TOP SECRET//TK//SAR-QSV-HOL-PER-SEN-TEV//NOFORN"
        );
        // DoD banner: PIDs stay out; banner is the standing form.
        assert_eq!(
            render_roll_up(&p, &all, Profile::DoDBanner),
            "TOP SECRET//TK//SAR-DILIGENTLY IMPRESSED//NOFORN"
        );
        assert_eq!(
            render_roll_up(&p, &all, Profile::Portion),
            "TS//TK//SAR-QSV-HOL-PER-SEN-TEV//NF"
        );
        // Standing (no slices): no TK, no compartments.
        assert_eq!(
            render_roll_up(&p, &[], Profile::CapcoBanner),
            "TOP SECRET//SAR-QSV//NOFORN"
        );
    }

    #[test]
    fn roll_up_nests_subcompartments_with_spaces() {
        // PER has subcompartments A1, A2 (parent_id = PER). Siblings are
        // hyphen-joined; subcompartments under one compartment are
        // space-joined: SAR-QSV-HOL-PER A1 A2-SEN-TEV.
        let mut p = qsv();
        p.controls.retain(|c| c.kind != ControlKind::Sci);
        let hol_c = Compartment { id: "HOL".into(), controls: vec![], ..hol() };
        let per_c = Compartment { id: "PER".into(), controls: vec![], ..hol() };
        let a1 = Compartment {
            id: "A1".into(),
            parent_id: Some("PER".into()),
            controls: vec![],
            ..hol()
        };
        let a2 = Compartment {
            id: "A2".into(),
            parent_id: Some("PER".into()),
            controls: vec![],
            ..hol()
        };
        let sen_c = Compartment { id: "SEN".into(), controls: vec![], ..hol() };
        let tev_c = Compartment { id: "TEV".into(), controls: vec![], ..hol() };
        let all: Vec<&Compartment> = vec![&hol_c, &per_c, &a1, &a2, &sen_c, &tev_c];
        assert_eq!(
            render_roll_up(&p, &all, Profile::Portion),
            "TS//SAR-QSV-HOL-PER A1 A2-SEN-TEV//NF"
        );
    }

    #[test]
    fn per_compartment_level_overrides_for_slice() {
        // TEV at S while the program is TS. A TEV-only document is S;
        // a roll-up including a TS slice bumps back to TS.
        let mut p = qsv();
        p.controls.retain(|c| c.kind != ControlKind::Sci); // no SCI on program
        let tev = Compartment {
            id: "TEV".into(),
            level: Some(Level::Secret),
            controls: vec![],
            ..hol()
        };
        let sen = Compartment {
            id: "SEN".into(),
            level: None, // inherit TS
            controls: vec![Control::new(ControlKind::Sci, "TK")],
            ..hol()
        };
        // TEV-only portion: S, no TK.
        assert_eq!(
            render_roll_up(&p, &[&tev], Profile::Portion),
            "S//SAR-QSV-TEV//NF"
        );
        // TEV + SEN: max(S, TS) = TS, and TK appears (SEN included).
        let both: Vec<&Compartment> = vec![&tev, &sen];
        assert_eq!(
            render_roll_up(&p, &both, Profile::Portion),
            "TS//TK//SAR-QSV-SEN-TEV//NF"
        );
        // Standing: program TS, no slices.
        assert_eq!(
            render_roll_up(&p, &[], Profile::Portion),
            "TS//SAR-QSV//NF"
        );
    }

    #[test]
    fn derive_with_compartment() {
        let m = derive_marking(&qsv(), Some(&hol()));
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV-HOL//NF");
        assert_eq!(m.display_banner(), "TOP SECRET//TK//SAR-QSV-HOL//NOFORN");
    }

    #[test]
    fn sci_merges_without_dup() {
        let mut hol = hol();
        hol.controls = vec![
            Control::new(ControlKind::Sci, "TK"),
            Control::new(ControlKind::Sci, "HCS"),
        ];
        let m = derive_marking(&qsv(), Some(&hol));
        assert_eq!(m.to_string(), "TS//TK,HCS//SAR-QSV-HOL//NF");
    }

    #[test]
    fn aea_fgi_from_program_not_compartment() {
        let mut p = qsv();
        p.controls.push(Control::new(ControlKind::Aea, "CNWDI"));
        p.controls.push(Control::new(ControlKind::Fgi, "USA"));
        let mut hol = hol();
        hol.controls
            .push(Control::new(ControlKind::Dissem, "ORCON"));
        hol.controls.push(Control::new(ControlKind::Aea, "RD-FRD"));
        let m = derive_marking(&p, Some(&hol));
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV-HOL//CNWDI//FGI-USA//NF");

        p.controls.pop();
        p.controls.push(Control::new(ControlKind::Fgi, "FGI"));
        let m = derive_marking(&p, None);
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV//CNWDI//FGI//NF");
    }

    #[test]
    fn materializer_folds_and_rederives() {
        let mut set = ProgramSet::new();
        set.apply(ProgramEvent::Created(qsv())).unwrap();
        set.apply(ProgramEvent::CompartmentAdded(hol())).unwrap();
        assert_eq!(
            set.derive_marking("qsv", Some("hol")).unwrap().to_string(),
            "TS//TK//SAR-QSV-HOL//NF"
        );

        set.apply(ProgramEvent::ControlsChanged {
            program_pid: "QSV".into(),
            compartment_id: None,
            add: vec![Control::new(ControlKind::Sci, "SI")],
            remove: vec![Control::new(ControlKind::Dissem, "NOFORN")],
        })
        .unwrap();
        assert_eq!(
            set.derive_marking("QSV", Some("HOL")).unwrap().to_string(),
            "TS//TK,SI//SAR-QSV-HOL"
        );
    }

    #[test]
    fn materializer_rejects_duplicates_and_orphans() {
        let mut set = ProgramSet::new();
        set.apply(ProgramEvent::Created(qsv())).unwrap();
        assert!(set.apply(ProgramEvent::Created(qsv())).is_err());
        assert!(set.apply(ProgramEvent::CompartmentAdded(hol())).is_ok());
        assert!(set.apply(ProgramEvent::CompartmentAdded(hol())).is_err());
        let orphan = Compartment {
            program_pid: "ZZZ".into(),
            ..hol()
        };
        assert!(set.apply(ProgramEvent::CompartmentAdded(orphan)).is_err());
    }
}
