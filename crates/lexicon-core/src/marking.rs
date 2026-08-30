//! CAPCO classification marking. Typed, not a free-form string.
//! Travels with the `Issued` event (signed, hashed). The ledger
//! container stays unclassified; the marking is name metadata.
//!
//! Display order is CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM.
//! SCI is a bare designator (TK, not SCI/TK). SAP is SAR-<pid>[-<compid>].

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
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
    pub fn banner_str(self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Cui => "CUI",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
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
    // Waived SAP. Not a dissemination control; derived from SapType::Waived,
    // never operator-entered as a free caveat.
    Waived,
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
            Self::Waived => 7,
            Self::Other { .. } => 255,
        }
    }
    fn detail(&self) -> String {
        match self {
            Self::Noforn | Self::Orcon | Self::Fisa | Self::Rsen | Self::Hvsaco | Self::Waived => {
                String::new()
            }
            Self::RelTo { countries } => countries.join(","),
            Self::Other { token } => token.clone(),
        }
    }
    fn display(&self, banner: bool) -> String {
        match self {
            Self::Noforn => {
                if banner {
                    "NOFORN".into()
                } else {
                    "NF".into()
                }
            }
            Self::Orcon => {
                if banner {
                    "ORCON".into()
                } else {
                    "OC".into()
                }
            }
            Self::Fisa => "FISA".into(),
            Self::Rsen => {
                if banner {
                    "RSEN".into()
                } else {
                    "RS".into()
                }
            }
            Self::RelTo { countries } => {
                let list = countries.join(",");
                if banner {
                    format!("REL TO {list}")
                } else {
                    format!("REL {list}")
                }
            }
            Self::Hvsaco => "HVSACO".into(),
            Self::Waived => "WAIVED".into(),
            Self::Other { token } => token.clone(),
        }
    }
    pub(crate) fn parse(seg: &str) -> Option<Self> {
        let u = seg.trim();
        let s = u.to_ascii_uppercase();
        match s.as_str() {
            "NOFORN" | "NF" => Some(Self::Noforn),
            "ORCON" | "OC" => Some(Self::Orcon),
            "FISA" => Some(Self::Fisa),
            "RSEN" | "RS" => Some(Self::Rsen),
            "HVSACO" => Some(Self::Hvsaco),
            "WAIVED" => Some(Self::Waived),
            "REL TO" | "REL" => Some(Self::RelTo {
                countries: Vec::new(),
            }),
            s if s.starts_with("REL TO ") => Some(Self::RelTo {
                countries: parse_rel_countries(&s["REL TO ".len()..]),
            }),
            s if s.starts_with("REL ") => Some(Self::RelTo {
                countries: parse_rel_countries(&s["REL ".len()..]),
            }),
            _ => None,
        }
    }
}

fn parse_rel_countries(s: &str) -> Vec<String> {
    s.split(',')
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty())
        .collect()
}

/// Dissemination-control shaped, not SCI/SAR/AEA/FGI.
fn is_other_caveat(s: &str) -> bool {
    if s.is_empty() || s.contains('/') {
        return false;
    }
    if s.eq_ignore_ascii_case("SCI")
        || s.eq_ignore_ascii_case("SAP")
        || s.eq_ignore_ascii_case("SAR")
        || s.eq_ignore_ascii_case("FGI")
        || s.eq_ignore_ascii_case("WAIVED")
    {
        return false;
    }
    let up = s.to_ascii_uppercase();
    if up.starts_with("SAR-") || up.starts_with("FGI-") {
        return false;
    }
    if CompartmentKind::parse(s).is_some() {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompartmentKind {
    Sci,
    Sap,
    RdFrd,
    Cnwdi,
    Fgi,
    Other,
}

impl CompartmentKind {
    fn tag(self) -> u8 {
        match self {
            Self::Sci => 1,
            Self::Sap => 2,
            Self::RdFrd => 3,
            Self::Cnwdi => 4,
            Self::Fgi => 5,
            Self::Other => 255,
        }
    }
    fn display(self) -> &'static str {
        match self {
            Self::Sci => "SCI",
            Self::Sap => "SAP",
            Self::RdFrd => "RD-FRD",
            Self::Cnwdi => "CNWDI",
            Self::Fgi => "FGI",
            Self::Other => "OTHER",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SCI" => Some(Self::Sci),
            "SAP" => Some(Self::Sap),
            "RD-FRD" | "RDFRD" => Some(Self::RdFrd),
            "CNWDI" => Some(Self::Cnwdi),
            "FGI" => Some(Self::Fgi),
            _ => None,
        }
    }
    fn slot(self) -> Slot {
        match self {
            Self::Sci => Slot::Sci,
            Self::Sap => Slot::Sar,
            Self::RdFrd | Self::Cnwdi | Self::Other => Slot::Aea,
            Self::Fgi => Slot::Fgi,
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

    pub fn is_sci(&self, designator: &str) -> bool {
        !designator.is_empty() && self.sci.contains(&designator.to_ascii_uppercase())
    }

    pub fn allows(&self, kind: &CompartmentKind, designator: &str) -> bool {
        if designator.is_empty() {
            return true;
        }
        let d = designator.to_ascii_uppercase();
        match kind {
            CompartmentKind::Sci => self.sci.contains(&d),
            CompartmentKind::Sap => {
                self.sap.contains(&d)
                    || d.split_once('-')
                        .map(|(pid, _)| self.sap.contains(pid))
                        .unwrap_or(false)
            }
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
    /// `max(TS//TK, CUI) = TS//TK` — upgraded by aggregation.
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

    /// Portion mark: abbreviated level and dissem (TS, NF). CLI parenthesizes.
    pub fn display_portion(&self) -> String {
        self.render(false)
    }

    /// Banner mark: spelled-out level and full dissem names (TOP SECRET, NOFORN).
    pub fn display_banner(&self) -> String {
        self.render(true)
    }

    fn render(&self, banner: bool) -> String {
        let mut parts = vec![if banner {
            self.level.banner_str().to_string()
        } else {
            self.level.as_str().to_string()
        }];

        let sci: Vec<&str> = self
            .compartments
            .iter()
            .filter(|c| c.kind == CompartmentKind::Sci && !c.designator.is_empty())
            .map(|c| c.designator.as_str())
            .collect();
        if !sci.is_empty() {
            parts.push(sci.join(","));
        }

        for c in &self.compartments {
            if c.kind != CompartmentKind::Sap {
                continue;
            }
            if c.designator.is_empty() {
                parts.push("SAR".into());
            } else {
                parts.push(format!("SAR-{}", c.designator));
            }
        }

        for c in &self.compartments {
            match c.kind {
                CompartmentKind::RdFrd | CompartmentKind::Cnwdi | CompartmentKind::Other => {
                    if c.designator.is_empty() {
                        parts.push(c.kind.display().to_string());
                    } else {
                        parts.push(format!("{}/{}", c.kind.display(), c.designator));
                    }
                }
                _ => {}
            }
        }

        for c in &self.compartments {
            if c.kind != CompartmentKind::Fgi {
                continue;
            }
            if c.designator.is_empty() {
                parts.push("FGI".into());
            } else {
                parts.push(format!("FGI-{}", c.designator));
            }
        }

        for c in &self.caveats {
            parts.push(c.display(banner));
        }
        parts.join("//")
    }

    /// Structural checks: no bare SCI, SAR uses hyphen, SCI/SAR in register.
    /// CAPCO order is a parse concern; Display always emits it.
    pub fn validate(&self, sci: &SciRegister) -> Result<(), String> {
        for c in &self.compartments {
            match c.kind {
                CompartmentKind::Sci => {
                    if c.designator.is_empty() {
                        return Err(
                            "bare SCI token is not a valid control; use the designator (TK, not SCI)"
                                .into(),
                        );
                    }
                    if !sci.allows(&c.kind, &c.designator) {
                        return Err(format!(
                            "unknown SCI designator '{}'; not in sci_register",
                            c.designator
                        ));
                    }
                }
                CompartmentKind::Sap => {
                    if c.designator.is_empty() {
                        return Err("SAR requires a program designator (SAR-<pid>)".into());
                    }
                    if c.designator.contains('/') {
                        return Err(format!(
                            "SAR uses hyphen not slash: SAR-{}",
                            c.designator.replace('/', "-")
                        ));
                    }
                    if !sci.allows(&c.kind, &c.designator) {
                        return Err(format!(
                            "unknown SAR designator '{}'; not in sci_register",
                            c.designator
                        ));
                    }
                }
                _ => {}
            }
        }
        for c in &self.caveats {
            if let Caveat::RelTo { countries } = c {
                if countries.is_empty() {
                    return Err("REL TO requires at least one ISO 3166-1 alpha-3 country".into());
                }
            }
        }
        Ok(())
    }

    pub fn parse_with(
        s: &str,
        sci: &SciRegister,
        countries: &CountryRegister,
    ) -> Result<Self, String> {
        Self::parse_inner(s, Some(sci), Some(countries), true)
    }

    /// Rows already on the ledger. Mint-time register does not apply —
    /// a later sci_register must not make `ledger verify` fail.
    /// Accepts legacy `SCI/<dg>` / `SAP/<dg>` and out-of-order tokens.
    pub fn from_stored(s: &str) -> Result<Self, String> {
        Self::parse_inner(s, None, None, false)
    }

    fn parse_inner(
        s: &str,
        sci: Option<&SciRegister>,
        countries: Option<&CountryRegister>,
        strict_order: bool,
    ) -> Result<Self, String> {
        let s = s.trim();
        let s = s
            .strip_prefix('(')
            .and_then(|x| x.strip_suffix(')'))
            .unwrap_or(s)
            .trim();
        if s.is_empty() {
            return Ok(Self::default());
        }
        let segs: Vec<&str> = s.split("//").collect();
        let level = Level::parse(segs[0])
            .ok_or_else(|| format!("unknown classification level '{}'", segs[0]))?;
        let kind_sci = sci.unwrap_or(SciRegister::bundled());
        let mut caveats = Vec::new();
        let mut compartments = Vec::new();
        let mut last_slot = Slot::Sci;
        let mut seen = false;
        for seg in &segs[1..] {
            let parsed = parse_token(seg, kind_sci)?;
            let slot = parsed.slot();
            if strict_order && seen && slot < last_slot {
                return Err(format!(
                    "CAPCO order is CLASSIFICATION // SCI // SAR // AEA // FGI // DISSEM; '{seg}' is out of order"
                ));
            }
            last_slot = slot;
            seen = true;
            match parsed {
                Parsed::Comps(cs) => compartments.extend(cs),
                Parsed::Caveat(c) => caveats.push(c),
            }
        }
        let marking = Marking {
            level,
            caveats,
            compartments,
        };
        if let Some(sci) = sci {
            marking.validate(sci)?;
        }
        if let Some(countries) = countries {
            for c in &marking.caveats {
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
        Ok(marking)
    }
}

impl fmt::Display for Marking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_portion())
    }
}

impl std::str::FromStr for Marking {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_with(s, SciRegister::bundled(), CountryRegister::bundled())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Sci = 1,
    Sar = 2,
    Aea = 3,
    Fgi = 4,
    Dissem = 5,
}

enum Parsed {
    Comps(Vec<Compartment>),
    Caveat(Caveat),
}

impl Parsed {
    fn slot(&self) -> Slot {
        match self {
            Self::Comps(cs) => cs.first().map(|c| c.kind.slot()).unwrap_or(Slot::Sci),
            Self::Caveat(_) => Slot::Dissem,
        }
    }
}

fn parse_token(seg: &str, kind_sci: &SciRegister) -> Result<Parsed, String> {
    let u = seg.trim();
    if u.is_empty() {
        return Err("empty CAPCO token".into());
    }
    let up = u.to_ascii_uppercase();

    if up == "SAR" {
        return Err("SAR requires a program designator (SAR-<pid>)".into());
    }
    if let Some(dg) = up.strip_prefix("SAR-") {
        if dg.is_empty() {
            return Err("SAR requires a program designator (SAR-<pid>)".into());
        }
        if dg.contains('/') {
            return Err(format!(
                "SAR uses hyphen not slash: SAR-{}",
                dg.replace('/', "-")
            ));
        }
        return Ok(Parsed::Comps(vec![Compartment {
            kind: CompartmentKind::Sap,
            designator: dg.into(),
        }]));
    }

    if up == "FGI" {
        return Ok(Parsed::Comps(vec![Compartment {
            kind: CompartmentKind::Fgi,
            designator: String::new(),
        }]));
    }
    if let Some(dg) = up.strip_prefix("FGI-").or_else(|| up.strip_prefix("FGI/")) {
        if dg.is_empty() {
            return Ok(Parsed::Comps(vec![Compartment {
                kind: CompartmentKind::Fgi,
                designator: String::new(),
            }]));
        }
        return Ok(Parsed::Comps(vec![Compartment {
            kind: CompartmentKind::Fgi,
            designator: dg.into(),
        }]));
    }

    if let Some((kind_s, rest)) = up.split_once('/') {
        if let Some(kind) = CompartmentKind::parse(kind_s) {
            let dgs: Vec<String> = rest
                .split(',')
                .map(|d| d.trim().to_ascii_uppercase())
                .filter(|d| !d.is_empty())
                .collect();
            if dgs.is_empty() {
                return Err(format!("missing designator on {}", kind.display()));
            }
            if kind == CompartmentKind::Sci && dgs.iter().any(|d| d.is_empty()) {
                return Err(
                    "bare SCI token is not a valid control; use the designator (TK, not SCI)"
                        .into(),
                );
            }
            return Ok(Parsed::Comps(
                dgs.into_iter()
                    .map(|designator| Compartment { kind, designator })
                    .collect(),
            ));
        }
    }

    if let Some(kind) = CompartmentKind::parse(&up) {
        match kind {
            CompartmentKind::Sci => {
                return Err(
                    "bare SCI token is not a valid control; use the designator (TK, not SCI)"
                        .into(),
                );
            }
            CompartmentKind::Sap => {
                return Err("use SAR-<pid>, not a bare SAP token".into());
            }
            CompartmentKind::RdFrd | CompartmentKind::Cnwdi => {
                return Ok(Parsed::Comps(vec![Compartment {
                    kind,
                    designator: String::new(),
                }]));
            }
            CompartmentKind::Fgi | CompartmentKind::Other => {}
        }
    }

    if let Some(c) = Caveat::parse(u) {
        return Ok(Parsed::Caveat(c));
    }

    let parts: Vec<String> = up
        .split(',')
        .map(|p| p.trim().to_ascii_uppercase())
        .filter(|p| !p.is_empty())
        .collect();
    if !parts.is_empty() && parts.iter().all(|p| kind_sci.is_sci(p)) {
        return Ok(Parsed::Comps(
            parts
                .into_iter()
                .map(|designator| Compartment {
                    kind: CompartmentKind::Sci,
                    designator,
                })
                .collect(),
        ));
    }

    if is_other_caveat(&up) {
        return Ok(Parsed::Caveat(Caveat::Other { token: up }));
    }

    Err(format!(
        "unknown CAPCO token '{seg}'; supported: NOFORN/NF, ORCON/OC, FISA, RSEN/RS, HVSACO, REL TO <ISO 3166-1 alpha-3>, bare SCI designators, SAR-<pid>[-<compid>], FGI, RD-FRD, CNWDI (legacy SCI/<dg>, SAP/<dg> accepted)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_portion() {
        let m: Marking = "TS//TK//NOFORN".parse().unwrap();
        assert_eq!(m.level, Level::TopSecret);
        assert_eq!(m.caveats, vec![Caveat::Noforn]);
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Sci,
                designator: "TK".into()
            }]
        );
        assert_eq!(m.to_string(), "TS//TK//NF");
        assert_eq!(m.display_portion(), "TS//TK//NF");
    }

    #[test]
    fn banner_spells_out_level_and_dissem() {
        let m: Marking = "TS//TK//NF".parse().unwrap();
        assert_eq!(m.display_banner(), "TOP SECRET//TK//NOFORN");
        let s: Marking = "S//REL TO USA,GBR".parse().unwrap();
        assert_eq!(s.display_banner(), "SECRET//REL TO USA,GBR");
        assert_eq!(s.display_portion(), "S//REL USA,GBR");
        let u: Marking = "U".parse().unwrap();
        assert_eq!(u.display_banner(), "UNCLASSIFIED");
    }

    #[test]
    fn parse_portion_abbreviations() {
        let m: Marking = "TS//TK//NF".parse().unwrap();
        assert_eq!(m.caveats, vec![Caveat::Noforn]);
        let o: Marking = "S//OC".parse().unwrap();
        assert_eq!(o.caveats, vec![Caveat::Orcon]);
        let r: Marking = "S//RS".parse().unwrap();
        assert_eq!(r.caveats, vec![Caveat::Rsen]);
        let rel: Marking = "S//REL USA,GBR".parse().unwrap();
        assert_eq!(
            rel.caveats,
            vec![Caveat::RelTo {
                countries: vec!["USA".into(), "GBR".into()]
            }]
        );
    }

    #[test]
    fn parse_parenthesized_portion() {
        let m: Marking = "(TS//TK//NF)".parse().unwrap();
        assert_eq!(m.to_string(), "TS//TK//NF");
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
        assert_eq!(m.to_string(), "S//REL USA,GBR");
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
        let m: Marking = "TS//TK//HVSACO".parse().unwrap();
        assert_eq!(m.caveats, vec![Caveat::Hvsaco]);
        assert_eq!(m.to_string(), "TS//TK//HVSACO");
        let bytes = m.canonical_bytes();
        assert_eq!(bytes[2], 6);
    }

    #[test]
    fn parse_waived() {
        let m: Marking = "TS//SAR-QSV//WAIVED//NOFORN".parse().unwrap();
        assert!(m.caveats.contains(&Caveat::Waived));
        assert!(m.caveats.contains(&Caveat::Noforn));
        assert_eq!(m.to_string(), "TS//SAR-QSV//WAIVED//NF");
        // WAIVED is typed, not an Other caveat that warns.
        assert!(m.warnings().is_empty());
        // Canonical tag is distinct from HVSACO (6) — no collision.
        let waived = Marking {
            level: Level::TopSecret,
            caveats: vec![Caveat::Waived],
            compartments: vec![],
        };
        let hvsaco = Marking {
            level: Level::TopSecret,
            caveats: vec![Caveat::Hvsaco],
            compartments: vec![],
        };
        assert_ne!(waived.canonical_bytes(), hvsaco.canonical_bytes());
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
    fn parse_fgi() {
        let m: Marking = "S//FGI".parse().unwrap();
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Fgi,
                designator: String::new()
            }]
        );
        assert_eq!(m.to_string(), "S//FGI");
        let gbr: Marking = "S//FGI-GBR".parse().unwrap();
        assert_eq!(gbr.compartments[0].designator, "GBR");
        assert_eq!(gbr.to_string(), "S//FGI-GBR");
        assert_eq!(gbr.display_banner(), "SECRET//FGI-GBR");
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
        assert!("TS//ZZZZ".parse::<Marking>().is_ok()); // Other caveat, not SCI
        let stored = Marking::from_stored("TS//SCI/ZZZZ").unwrap();
        assert_eq!(stored.level, Level::TopSecret);
        assert_eq!(stored.compartments[0].designator, "ZZZZ");
        assert_eq!(stored.to_string(), "TS//ZZZZ");
    }

    #[test]
    fn rejects_bare_sci_token() {
        assert!("TS//SCI".parse::<Marking>().is_err());
        let err = Marking {
            level: Level::TopSecret,
            caveats: vec![],
            compartments: vec![Compartment {
                kind: CompartmentKind::Sci,
                designator: String::new(),
            }],
        }
        .validate(SciRegister::bundled())
        .unwrap_err();
        assert!(err.contains("bare SCI"), "{err}");
    }

    #[test]
    fn rejects_unknown_sap_designator() {
        assert!("TS//SAP/ZZZZ".parse::<Marking>().is_err());
        assert!("TS//SAR-ZZZZ".parse::<Marking>().is_err());
        let m: Marking = "TS//SAP/BYEMAN".parse().unwrap();
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Sap,
                designator: "BYEMAN".into()
            }]
        );
        assert_eq!(m.to_string(), "TS//SAR-BYEMAN");
    }

    #[test]
    fn parse_sar_hyphen_and_compartment() {
        let m: Marking = "TS//TK//SAR-QSV-HOL//NOFORN".parse().unwrap();
        assert_eq!(
            m.compartments,
            vec![
                Compartment {
                    kind: CompartmentKind::Sci,
                    designator: "TK".into()
                },
                Compartment {
                    kind: CompartmentKind::Sap,
                    designator: "QSV-HOL".into()
                }
            ]
        );
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV-HOL//NF");
        assert_eq!(m.display_banner(), "TOP SECRET//TK//SAR-QSV-HOL//NOFORN");
        assert!(m.validate(SciRegister::bundled()).is_ok());
        let err = "TS//SAR-QSV/HOL".parse::<Marking>().unwrap_err();
        assert!(err.contains("hyphen"), "{err}");
        let legacy: Marking = "TS//SAP/QSV".parse().unwrap();
        assert_eq!(legacy.to_string(), "TS//SAR-QSV");
    }

    #[test]
    fn sar_not_grouped() {
        let m: Marking = "TS//SAR-QSV//SAR-BYEMAN".parse().unwrap();
        assert_eq!(m.compartments.len(), 2);
        assert_eq!(m.to_string(), "TS//SAR-QSV//SAR-BYEMAN");
    }

    #[test]
    fn validate_sar_rejects_slash() {
        let m = Marking {
            level: Level::TopSecret,
            caveats: vec![],
            compartments: vec![Compartment {
                kind: CompartmentKind::Sap,
                designator: "QSV/HOL".into(),
            }],
        };
        let err = m.validate(SciRegister::bundled()).unwrap_err();
        assert!(err.contains("hyphen"), "{err}");
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
        assert!(Marking::parse_with("TS//FOO", &sci, &countries).is_ok());
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
        assert!(sci.allows(&CompartmentKind::Sap, "QSV"));
        assert!(sci.allows(&CompartmentKind::Sap, "QSV-HOL"));
        assert!(!sci.allows(&CompartmentKind::Sap, "ZZZZ-HOL"));
        let c = CountryRegister::bundled();
        for code in ["USA", "GBR", "CAN", "AUS", "NZL", "FVEY"] {
            assert!(c.contains(code), "{code}");
        }
        assert!(!c.contains("ZZZ"));
    }

    #[test]
    fn canonical_stable_and_order_independent() {
        let m = Marking::from_stored("TS//NOFORN//SCI/TK").unwrap();
        let m2: Marking = "TS//TK//NOFORN".parse().unwrap();
        assert_eq!(m.canonical_bytes(), m.canonical_bytes());
        assert_eq!(m.canonical_bytes(), m2.canonical_bytes());
        let m3 = Marking::from_stored("TS//SCI/TK//NOFORN").unwrap();
        assert_eq!(m.canonical_bytes(), m3.canonical_bytes());
    }

    #[test]
    fn strict_parse_rejects_out_of_order() {
        let err = "TS//NOFORN//SCI/TK".parse::<Marking>().unwrap_err();
        assert!(err.contains("order"), "{err}");
        for s in [
            "TS//NOFORN//TK",
            "TS//NF//SAR-QSV",
            "TS//SAR-QSV//TK",
            "TS//FGI//SAR-QSV",
            "TS//NOFORN//CNWDI",
            "TS//FGI//TK",
            "TS//CNWDI//TK",
        ] {
            let err = s.parse::<Marking>().unwrap_err();
            assert!(err.contains("order"), "{s}: {err}");
        }
        assert!("TS//TK//NOFORN".parse::<Marking>().is_ok());
        assert!("TS//SCI/TK//NOFORN".parse::<Marking>().is_ok());
        assert!("TS//TK//SAR-QSV//CNWDI//FGI//NOFORN"
            .parse::<Marking>()
            .is_ok());
    }

    #[test]
    fn from_stored_lenient_legacy_grammar() {
        let m = Marking::from_stored("TS//NOFORN//SCI/TK").unwrap();
        assert_eq!(
            m.compartments,
            vec![Compartment {
                kind: CompartmentKind::Sci,
                designator: "TK".into()
            }]
        );
        assert_eq!(m.caveats, vec![Caveat::Noforn]);
        assert_eq!(m.display_portion(), "TS//TK//NF");
        assert_eq!(m.display_banner(), "TOP SECRET//TK//NOFORN");
        let sap = Marking::from_stored("TS//SAP/BYEMAN").unwrap();
        assert_eq!(sap.to_string(), "TS//SAR-BYEMAN");
    }

    #[test]
    fn max_upgrades_by_aggregation() {
        let ts = "TS//TK".parse::<Marking>().unwrap();
        let cui: Marking = "CUI".parse().unwrap();
        let s_noforn: Marking = "S//NOFORN".parse().unwrap();
        assert_eq!(ts.max(&cui), ts);
        assert_eq!(cui.max(&ts), ts);
        let m = s_noforn.max(&ts);
        assert_eq!(m.level, Level::TopSecret);
        assert!(m.caveats.contains(&Caveat::Noforn));
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "TK".into(),
        }));
        assert_eq!(m.to_string(), "TS//TK//NF");
        let agg = Marking::aggregate([cui, s_noforn, ts]);
        assert_eq!(agg, m);
    }

    #[test]
    fn comma_separated_sci_no_prefix() {
        let m: Marking = "TS//TK,HCS".parse().unwrap();
        assert_eq!(m.compartments.len(), 2);
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "TK".into()
        }));
        assert!(m.compartments.contains(&Compartment {
            kind: CompartmentKind::Sci,
            designator: "HCS".into()
        }));
        assert_eq!(m.to_string(), "TS//TK,HCS");
        let legacy: Marking = "TS//SCI/TK,HCS".parse().unwrap();
        assert_eq!(legacy.to_string(), "TS//TK,HCS");
        let tk: Marking = "TS//TK".parse().unwrap();
        let hcs: Marking = "TS//HCS".parse().unwrap();
        assert_eq!(tk.max(&hcs).to_string(), "TS//TK,HCS");
    }

    #[test]
    fn capco_order_on_display() {
        let m: Marking = "TS//TK//SAR-QSV//CNWDI//FGI//NOFORN".parse().unwrap();
        assert_eq!(m.to_string(), "TS//TK//SAR-QSV//CNWDI//FGI//NF");
        assert_eq!(
            m.display_banner(),
            "TOP SECRET//TK//SAR-QSV//CNWDI//FGI//NOFORN"
        );
    }

    #[test]
    fn fgi_tag_does_not_collide() {
        let m: Marking = "S//FGI".parse().unwrap();
        let bytes = m.canonical_bytes();
        assert_eq!(bytes[2], 1); // one compartment
        assert_eq!(bytes[3], 5); // Fgi tag; Sci/Sap/RdFrd/Cnwdi stay 1–4
    }
}
