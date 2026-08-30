//! CAPCO classification marking. Typed, not a free-form string.
//! Travels with the `Issued` event (signed, hashed). The ledger
//! container stays unclassified; the marking is name metadata.

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    #[default]
    Unclassified,
    Cui,
    Confidential,
    Secret,
    TopSecret,
}

impl Level {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "U",
            Self::Cui => "CUI",
            Self::Confidential => "C",
            Self::Secret => "S",
            Self::TopSecret => "TS",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "U" | "UNCLASS" | "UNCLASSIFIED" => Some(Self::Unclassified),
            "CUI" => Some(Self::Cui),
            "C" | "CONF" | "CONFIDENTIAL" => Some(Self::Confidential),
            "S" | "SECRET" => Some(Self::Secret),
            "TS" | "TOPSECRET" | "TOP SECRET" => Some(Self::TopSecret),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caveat {
    Noforn,
    Orcon,
    Fisa,
    Rsen,
    RelTo { countries: Vec<String> },
    Other { token: String },
}

impl Caveat {
    fn tag(&self) -> u8 {
        match self {
            Self::Noforn => 1,
            Self::Orcon => 2,
            Self::Fisa => 3,
            Self::Rsen => 4,
            Self::RelTo { .. } => 5,
            Self::Other { .. } => 255,
        }
    }
    fn detail(&self) -> String {
        match self {
            Self::Noforn | Self::Orcon | Self::Fisa | Self::Rsen => String::new(),
            Self::RelTo { countries } => countries.join(","),
            Self::Other { token } => token.clone(),
        }
    }
    fn display(&self) -> String {
        match self {
            Self::Noforn => "NOFORN".into(),
            Self::Orcon => "ORCON".into(),
            Self::Fisa => "FISA".into(),
            Self::Rsen => "RSEN".into(),
            Self::RelTo { countries } => format!("REL TO {}", countries.join(",")),
            Self::Other { token } => token.clone(),
        }
    }
    fn parse(seg: &str) -> Option<Self> {
        let u = seg.trim();
        match u.to_ascii_uppercase().as_str() {
            "NOFORN" => Some(Self::Noforn),
            "ORCON" => Some(Self::Orcon),
            "FISA" => Some(Self::Fisa),
            "RSEN" => Some(Self::Rsen),
            s if s.starts_with("REL TO ") => Some(Self::RelTo {
                countries: s["REL TO ".len()..]
                    .split(',')
                    .map(|c| c.trim().to_ascii_uppercase())
                    .filter(|c| !c.is_empty())
                    .collect(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompartmentKind {
    Sci,
    Sap,
    RdFrd,
    Cnwdi,
    Other,
}

impl CompartmentKind {
    fn tag(&self) -> u8 {
        match self {
            Self::Sci => 1,
            Self::Sap => 2,
            Self::RdFrd => 3,
            Self::Cnwdi => 4,
            Self::Other => 255,
        }
    }
    fn display(&self) -> &'static str {
        match self {
            Self::Sci => "SCI",
            Self::Sap => "SAP",
            Self::RdFrd => "RD-FRD",
            Self::Cnwdi => "CNWDI",
            Self::Other => "OTHER",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SCI" => Some(Self::Sci),
            "SAP" => Some(Self::Sap),
            "RD-FRD" | "RDFRD" => Some(Self::RdFrd),
            "CNWDI" => Some(Self::Cnwdi),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Compartment {
    pub kind: CompartmentKind,
    pub designator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Marking {
    pub level: Level,
    #[serde(default)]
    pub caveats: Vec<Caveat>,
    #[serde(default)]
    pub compartments: Vec<Compartment>,
}

impl Marking {
    /// Canonical bytes: level, caveats (sorted), compartments (sorted).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.level.as_u8());
        let mut caveats = self.caveats.clone();
        caveats.sort_by_key(|c| (c.tag(), c.detail()));
        out.push(caveats.len() as u8);
        for c in &caveats {
            out.push(c.tag());
            let d = c.detail();
            out.extend_from_slice(&(d.len() as u16).to_le_bytes());
            out.extend_from_slice(d.as_bytes());
        }
        let mut comps = self.compartments.clone();
        comps.sort_by_key(|c| (c.kind.tag(), c.designator.clone()));
        out.push(comps.len() as u8);
        for c in &comps {
            out.push(c.kind.tag());
            out.extend_from_slice(&(c.designator.len() as u16).to_le_bytes());
            out.extend_from_slice(c.designator.as_bytes());
        }
        out
    }

    /// Container marking: higher level, caveats and compartments unioned.
    /// `max(TS//SCI/TK, CUI) = TS//SCI/TK` — upgraded by aggregation.
    pub fn max(&self, other: &Marking) -> Marking {
        let level = self.level.max(other.level);
        let mut caveats = self.caveats.clone();
        for c in &other.caveats {
            if !caveats.contains(c) {
                caveats.push(c.clone());
            }
        }
        let mut comps = self.compartments.clone();
        for c in &other.compartments {
            if !comps.contains(c) {
                comps.push(c.clone());
            }
        }
        Marking {
            level,
            caveats,
            compartments: comps,
        }
    }

    /// Fold the aggregate over a set of markings.
    pub fn aggregate(markings: impl IntoIterator<Item = Marking>) -> Marking {
        markings
            .into_iter()
            .fold(Marking::default(), |acc, m| acc.max(&m))
    }
}

impl std::fmt::Display for Marking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![self.level.as_str().to_string()];
        for c in &self.caveats {
            parts.push(c.display());
        }
        // CAPCO: same-kind designators comma-separated under one prefix
        // (SCI/TK,HCS), not repeated per subcompartment.
        let mut by_kind: Vec<(CompartmentKind, Vec<String>)> = Vec::new();
        for c in &self.compartments {
            if let Some(entry) = by_kind.iter_mut().find(|(k, _)| *k == c.kind) {
                entry.1.push(c.designator.clone());
            } else {
                by_kind.push((c.kind.clone(), vec![c.designator.clone()]));
            }
        }
        for (kind, dgs) in &by_kind {
            let nonempty: Vec<&str> = dgs
                .iter()
                .filter(|d| !d.is_empty())
                .map(String::as_str)
                .collect();
            if nonempty.is_empty() {
                parts.push(kind.display().to_string());
            } else {
                parts.push(format!("{}/{}", kind.display(), nonempty.join(",")));
            }
        }
        write!(f, "{}", parts.join("//"))
    }
}

impl std::str::FromStr for Marking {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::default());
        }
        let segs: Vec<&str> = s.split("//").collect();
        let level = Level::parse(segs[0])
            .ok_or_else(|| format!("unknown classification level '{}'", segs[0]))?;
        let mut caveats = Vec::new();
        let mut compartments = Vec::new();
        for seg in &segs[1..] {
            if let Some(c) = Caveat::parse(seg) {
                caveats.push(c);
                continue;
            }
            if let Some((kind, dgs)) = parse_compartment(seg) {
                for dg in dgs {
                    compartments.push(Compartment {
                        kind: kind.clone(),
                        designator: dg,
                    });
                }
                continue;
            }
            return Err(format!(
                "unknown CAPCO token '{seg}'; supported: NOFORN, ORCON, FISA, RSEN, REL TO <list>, SCI/<dg>, SAP/<dg>, RD-FRD, CNWDI"
            ));
        }
        Ok(Marking {
            level,
            caveats,
            compartments,
        })
    }
}

fn parse_compartment(seg: &str) -> Option<(CompartmentKind, Vec<String>)> {
    if let Some((kind, dg)) = seg.split_once('/') {
        let kind = CompartmentKind::parse(kind)?;
        // SCI/TK,HCS is two SCI compartments, not one "TK,HCS" designator.
        let dgs: Vec<String> = dg
            .split(',')
            .map(|d| d.trim().to_ascii_uppercase())
            .filter(|d| !d.is_empty())
            .collect();
        if dgs.is_empty() {
            return None;
        }
        return Some((kind, dgs));
    }
    if let Some(kind) = CompartmentKind::parse(seg) {
        return Some((kind, vec![String::new()]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let m: Marking = "TS//NOFORN//SCI/TK".parse().unwrap();
        assert_eq!(m.level, Level::TopSecret);
        assert_eq!(m.caveats, vec![Caveat::Noforn]);
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Sci,
                designator: "TK".into()
            }]
        );
        assert_eq!(m.to_string(), "TS//NOFORN//SCI/TK");
    }

    #[test]
    fn parse_rel_to() {
        let m: Marking = "S//REL TO USA,GBR".parse().unwrap();
        assert_eq!(
            m.caveats,
            vec![Caveat::RelTo {
                countries: vec!["USA".into(), "GBR".into()]
            }]
        );
        assert_eq!(m.to_string(), "S//REL TO USA,GBR");
    }

    #[test]
    fn parse_rdfrd_no_designator() {
        let m: Marking = "TS//RD-FRD".parse().unwrap();
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::RdFrd,
                designator: String::new()
            }]
        );
        assert_eq!(m.to_string(), "TS//RD-FRD");
    }

    #[test]
    fn unclassified_default() {
        let m: Marking = "".parse().unwrap();
        assert_eq!(m, Marking::default());
        assert_eq!(m.to_string(), "U");
    }

    #[test]
    fn rejects_banana() {
        assert!("banana".parse::<Marking>().is_err());
        assert!("TS//BANANA".parse::<Marking>().is_err());
    }

    #[test]
    fn canonical_stable_and_order_independent() {
        let m: Marking = "TS//NOFORN//SCI/TK".parse().unwrap();
        let m2: Marking = "TS//SCI/TK//NOFORN".parse().unwrap();
        assert_eq!(m.canonical_bytes(), m.canonical_bytes());
        assert_eq!(m.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn max_upgrades_by_aggregation() {
        let ts = "TS//SCI/TK".parse::<Marking>().unwrap();
        let cui: Marking = "CUI".parse().unwrap();
        let s_noforn: Marking = "S//NOFORN".parse().unwrap();
        // Higher level wins.
        assert_eq!(ts.max(&cui), ts);
        assert_eq!(cui.max(&ts), ts);
        // Caveats union.
        let m = s_noforn.max(&ts);
        assert_eq!(m.level, Level::TopSecret);
        assert!(m.caveats.contains(&Caveat::Noforn));
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "TK".into(),
        }));
        assert_eq!(m.to_string(), "TS//NOFORN//SCI/TK");
        // Aggregate folds.
        let agg = Marking::aggregate([cui, s_noforn, ts]);
        assert_eq!(agg, m);
    }

    #[test]
    fn comma_separated_compartments() {
        // CAPCO: one SCI prefix, comma-separated designators.
        let m: Marking = "TS//SCI/TK,HCS".parse().unwrap();
        assert_eq!(m.compartments.len(), 2);
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "TK".into()
        }));
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "HCS".into()
        }));
        assert_eq!(m.to_string(), "TS//SCI/TK,HCS");
        // Aggregate of TK and HCS produces the comma form, not SCI/TK//SCI/HCS.
        let tk: Marking = "TS//SCI/TK".parse().unwrap();
        let hcs: Marking = "TS//SCI/HCS".parse().unwrap();
        assert_eq!(tk.max(&hcs).to_string(), "TS//SCI/TK,HCS");
    }
}
