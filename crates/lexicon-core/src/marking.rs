//! CAPCO classification marking. Typed, not a free-form string.
//! Travels with the `Issued` event (signed, hashed). The ledger
//! container stays unclassified; the marking is name metadata.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

// Same files the accreditor replaces; rebuild picks them up.
const SCI_REGISTER_JSON: &str = include_str!("../../lexicon-pools/data/sci_register.json");
const ISO3166_ALPHA3: &str = include_str!("../../lexicon-pools/data/iso3166_alpha3.txt");

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
    Hvsaco,
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
            Self::Hvsaco => 6,
            Self::Other { .. } => 255,
        }
    }
    fn detail(&self) -> String {
        match self {
            Self::Noforn | Self::Orcon | Self::Fisa | Self::Rsen | Self::Hvsaco => String::new(),
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
            Self::Hvsaco => "HVSACO".into(),
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
            "HVSACO" => Some(Self::Hvsaco),
            s if s.starts_with("REL TO ") => Some(Self::RelTo {
                countries: s["REL TO ".len()..]
                    .split(',')
                    .map(|c| c.trim().to_ascii_uppercase())
                    .filter(|c| !c.is_empty())
                    .collect(),
            }),
            s if is_other_caveat(s) => Some(Self::Other { token: s.into() }),
            _ => None,
        }
    }
}

/// Dissemination-control shaped, not a compartment (`SCI/…`).
fn is_other_caveat(s: &str) -> bool {
    if s.is_empty() || s.contains('/') || CompartmentKind::parse(s).is_some() {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
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

/// Bundled SCI/SAP designator allow-list. Sample until the accreditor ships the real one.
#[derive(Debug, Clone)]
pub struct SciRegister {
    sci: HashSet<String>,
    sap: HashSet<String>,
}

impl SciRegister {
    pub fn from_json(json: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            sci: Vec<String>,
            #[serde(default)]
            sap: Vec<String>,
        }
        let f: File = serde_json::from_str(json).map_err(|e| e.to_string())?;
        Ok(Self {
            sci: f.sci.into_iter().map(|s| s.to_ascii_uppercase()).collect(),
            sap: f.sap.into_iter().map(|s| s.to_ascii_uppercase()).collect(),
        })
    }

    pub fn bundled() -> &'static Self {
        static R: OnceLock<SciRegister> = OnceLock::new();
        R.get_or_init(|| Self::from_json(SCI_REGISTER_JSON).expect("sci_register.json"))
    }

    pub fn allows(&self, kind: &CompartmentKind, designator: &str) -> bool {
        if designator.is_empty() {
            return true;
        }
        match kind {
            CompartmentKind::Sci => self.sci.contains(designator),
            CompartmentKind::Sap => self.sap.contains(designator),
            _ => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CountryRegister {
    codes: HashSet<String>,
}

impl CountryRegister {
    pub fn from_text(text: &str) -> Self {
        Self {
            codes: text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_ascii_uppercase())
                .collect(),
        }
    }

    pub fn bundled() -> &'static Self {
        static R: OnceLock<CountryRegister> = OnceLock::new();
        R.get_or_init(|| Self::from_text(ISO3166_ALPHA3))
    }

    pub fn contains(&self, code: &str) -> bool {
        self.codes.contains(code)
    }
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

    pub fn aggregate(markings: impl IntoIterator<Item = Marking>) -> Marking {
        markings
            .into_iter()
            .fold(Marking::default(), |acc, m| acc.max(&m))
    }

    pub fn warnings(&self) -> Vec<String> {
        self.caveats
            .iter()
            .filter_map(|c| match c {
                Caveat::Other { token } => Some(format!(
                    "non-standard caveat '{token}'; not a typed CAPCO control"
                )),
                _ => None,
            })
            .collect()
    }

    pub fn parse_with(
        s: &str,
        sci: &SciRegister,
        countries: &CountryRegister,
    ) -> Result<Self, String> {
        Self::parse_inner(s, Some(sci), Some(countries))
    }

    /// Rows already on the ledger. Mint-time register does not apply —
    /// a later sci_register must not make `ledger verify` fail.
    pub fn from_stored(s: &str) -> Result<Self, String> {
        Self::parse_inner(s, None, None)
    }

    fn parse_inner(
        s: &str,
        sci: Option<&SciRegister>,
        countries: Option<&CountryRegister>,
    ) -> Result<Self, String> {
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
                "unknown CAPCO token '{seg}'; supported: NOFORN, ORCON, FISA, RSEN, HVSACO, REL TO <ISO 3166-1 alpha-3>, SCI/<dg>, SAP/<dg>, RD-FRD, CNWDI"
            ));
        }
        if let Some(sci) = sci {
            for c in &compartments {
                if !sci.allows(&c.kind, &c.designator) {
                    let kind = c.kind.display();
                    return Err(format!(
                        "unknown {kind} designator '{}'; not in sci_register",
                        c.designator
                    ));
                }
            }
        }
        if let Some(countries) = countries {
            for c in &caveats {
                if let Caveat::RelTo { countries: list } = c {
                    if list.is_empty() {
                        return Err(
                            "REL TO requires at least one ISO 3166-1 alpha-3 country".into()
                        );
                    }
                    for code in list {
                        if !countries.contains(code) {
                            return Err(format!(
                                "unknown REL TO country '{code}'; not ISO 3166-1 alpha-3 or a recognized collective"
                            ));
                        }
                    }
                }
            }
        }
        Ok(Marking {
            level,
            caveats,
            compartments,
        })
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
        Self::parse_with(s, SciRegister::bundled(), CountryRegister::bundled())
    }
}

fn parse_compartment(seg: &str) -> Option<(CompartmentKind, Vec<String>)> {
    if let Some((kind, dg)) = seg.split_once('/') {
        let kind = CompartmentKind::parse(kind)?;
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
        let fvey: Marking = "S//REL TO FVEY".parse().unwrap();
        assert_eq!(
            fvey.caveats,
            vec![Caveat::RelTo {
                countries: vec!["FVEY".into()]
            }]
        );
    }

    #[test]
    fn parse_hvsaco() {
        let m: Marking = "TS//HVSACO//SCI/TK".parse().unwrap();
        assert_eq!(m.caveats, vec![Caveat::Hvsaco]);
        assert_eq!(m.to_string(), "TS//HVSACO//SCI/TK");
        let bytes = m.canonical_bytes();
        assert_eq!(bytes[2], 6);
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
    fn rejects_unknown_level() {
        assert!("banana".parse::<Marking>().is_err());
    }

    #[test]
    fn other_caveat_warns() {
        let m: Marking = "TS//BANANA".parse().unwrap();
        assert_eq!(
            m.caveats,
            vec![Caveat::Other {
                token: "BANANA".into()
            }]
        );
        assert!(!m.warnings().is_empty());
    }

    #[test]
    fn rejects_unknown_sci_designator() {
        let err = "TS//SCI/ZZZZ".parse::<Marking>().unwrap_err();
        assert!(err.contains("ZZZZ"), "{err}");
        assert!("TS//SCI/TK,ZZZZ".parse::<Marking>().is_err());
        let stored = Marking::from_stored("TS//SCI/ZZZZ").unwrap();
        assert_eq!(stored.level, Level::TopSecret);
        assert_eq!(stored.compartments[0].designator, "ZZZZ");
    }

    #[test]
    fn rejects_unknown_sap_designator() {
        assert!("TS//SAP/ZZZZ".parse::<Marking>().is_err());
        let m: Marking = "TS//SAP/BYEMAN".parse().unwrap();
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Sap,
                designator: "BYEMAN".into()
            }]
        );
    }

    #[test]
    fn rejects_unknown_rel_to_country() {
        assert!("S//REL TO ZZZ".parse::<Marking>().is_err());
        assert!("S//REL TO USA,ZZZ".parse::<Marking>().is_err());
        assert!("S//REL TO ".parse::<Marking>().is_err());
    }

    #[test]
    fn parse_with_threads_registers() {
        let sci = SciRegister::from_json(r#"{"sci":["FOO"],"sap":[]}"#).unwrap();
        let countries = CountryRegister::from_text("USA\n");
        assert!(Marking::parse_with("TS//SCI/FOO", &sci, &countries).is_ok());
        assert!(Marking::parse_with("TS//SCI/TK", &sci, &countries).is_err());
        assert!(Marking::parse_with("S//REL TO USA", &sci, &countries).is_ok());
        assert!(Marking::parse_with("S//REL TO GBR", &sci, &countries).is_err());
    }

    #[test]
    fn bundled_registers_cover_samples() {
        let sci = SciRegister::bundled();
        assert!(sci.allows(&CompartmentKind::Sci, "TK"));
        assert!(sci.allows(&CompartmentKind::Sci, "HCS"));
        assert!(!sci.allows(&CompartmentKind::Sci, "ZZZZ"));
        let c = CountryRegister::bundled();
        for code in ["USA", "GBR", "CAN", "AUS", "NZL", "FVEY"] {
            assert!(c.contains(code), "{code}");
        }
        assert!(!c.contains("ZZZ"));
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
