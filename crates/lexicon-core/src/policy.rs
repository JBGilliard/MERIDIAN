//! Data-dir policy. Bindings persistence, attribution, and export are off
//! unless this file and argv both allow them. Argv can only tighten.

use crate::error::{Error, Result};
use crate::marking::{Level, Marking};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FILENAME: &str = "policy.toml";

/// Session flags that may restrict a loaded policy. They cannot relax it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    pub persist_markings: bool,
    pub include_attribution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(deserialize_with = "de_floor", serialize_with = "ser_floor")]
    pub classification_floor: Level,
    pub allow_persist_markings: bool,
    pub allow_attribution: bool,
    pub allow_export_bindings: bool,
    pub allow_export_attribution: bool,
    pub required_banner: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self::default_oss()
    }
}

impl Policy {
    /// OSS / default-profile: everything gated off, floor U.
    pub fn default_oss() -> Self {
        Self {
            classification_floor: Level::Unclassified,
            allow_persist_markings: false,
            allow_attribution: false,
            allow_export_bindings: false,
            allow_export_attribution: false,
            required_banner: Level::Unclassified.banner_str().to_string(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Self::parse_toml(&raw)
    }

    pub fn parse_toml(raw: &str) -> Result<Self> {
        let p: Self = toml::from_str(raw).map_err(|e| Error::Parse(format!("policy.toml: {e}")))?;
        if p.required_banner.trim().is_empty() {
            return Err(Error::Parse("policy.toml: required_banner is empty".into()));
        }
        Ok(p)
    }

    /// Highside: file required. OSS: missing file → default_oss.
    pub fn from_data_dir(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(FILENAME);
        if path.exists() {
            return Self::load(&path);
        }
        if cfg!(feature = "highside") {
            Err(Error::PolicyViolation(
                "highside profile requires <data-dir>/policy.toml".into(),
            ))
        } else {
            Ok(Self::default_oss())
        }
    }

    /// Argv can only tighten. Asking for a capability policy forbids is an error.
    pub fn tighten(mut self, argv: &PolicyOverrides) -> Result<Self> {
        if argv.persist_markings && !self.allow_persist_markings {
            return Err(Error::PolicyViolation(
                "--persist-markings is not allowed by policy.toml".into(),
            ));
        }
        if argv.include_attribution && !self.allow_attribution && !self.allow_export_attribution {
            return Err(Error::PolicyViolation(
                "--include-attribution is not allowed by policy.toml".into(),
            ));
        }
        self.allow_persist_markings &= argv.persist_markings;
        self.allow_attribution &= argv.include_attribution;
        self.allow_export_attribution &= argv.include_attribution;
        Ok(self)
    }
}

fn parse_floor(s: &str) -> std::result::Result<Level, String> {
    if let Some(level) = Level::parse(s) {
        return Ok(level);
    }
    // CAPCO string: take the level, do not echo the rest in errors.
    s.parse::<Marking>()
        .map(|m| m.level)
        .map_err(|_| "unknown classification_floor".to_string())
}

fn de_floor<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Level, D::Error> {
    let s = String::deserialize(d)?;
    parse_floor(&s).map_err(serde::de::Error::custom)
}

fn ser_floor<S: serde::Serializer>(level: &Level, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(level.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
classification_floor = "S"
allow_persist_markings = true
allow_attribution = true
allow_export_bindings = true
allow_export_attribution = true
required_banner = "SECRET"
"#;

    #[test]
    fn default_oss_is_fail_closed() {
        let p = Policy::default_oss();
        assert_eq!(p.classification_floor, Level::Unclassified);
        assert!(!p.allow_persist_markings);
        assert!(!p.allow_attribution);
        assert!(!p.allow_export_bindings);
        assert!(!p.allow_export_attribution);
        assert_eq!(p.required_banner, "UNCLASSIFIED");
    }

    #[test]
    fn parse_full_schema() {
        let p = Policy::parse_toml(FULL).unwrap();
        assert_eq!(p.classification_floor, Level::Secret);
        assert!(p.allow_persist_markings);
        assert!(p.allow_attribution);
        assert!(p.allow_export_bindings);
        assert!(p.allow_export_attribution);
        assert_eq!(p.required_banner, "SECRET");
    }

    #[test]
    fn floor_accepts_capco_string() {
        let raw = r#"
classification_floor = "SECRET//NOFORN"
allow_persist_markings = false
allow_attribution = false
allow_export_bindings = false
allow_export_attribution = false
required_banner = "SECRET//NOFORN"
"#;
        let p = Policy::parse_toml(raw).unwrap();
        assert_eq!(p.classification_floor, Level::Secret);
    }

    #[test]
    fn unknown_floor_does_not_echo() {
        assert_eq!(
            parse_floor("NOTALEVEL").unwrap_err(),
            "unknown classification_floor"
        );
        let raw = r#"
classification_floor = "NOTALEVEL"
allow_persist_markings = false
allow_attribution = false
allow_export_bindings = false
allow_export_attribution = false
required_banner = "UNCLASSIFIED"
"#;
        assert!(Policy::parse_toml(raw).is_err());
    }

    #[test]
    fn missing_field_fails() {
        let err = Policy::parse_toml("classification_floor = \"U\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy.toml"), "{err}");
    }

    #[test]
    fn unknown_key_fails() {
        let raw = r#"
classification_floor = "U"
allow_persist_markings = false
allow_attribution = false
allow_export_bindings = false
allow_export_attribution = false
required_banner = "UNCLASSIFIED"
allow_persist_marking = true
"#;
        assert!(Policy::parse_toml(raw).is_err());
    }

    #[test]
    fn empty_banner_fails() {
        let raw = r#"
classification_floor = "U"
allow_persist_markings = false
allow_attribution = false
allow_export_bindings = false
allow_export_attribution = false
required_banner = "  "
"#;
        let err = Policy::parse_toml(raw).unwrap_err().to_string();
        assert!(err.contains("required_banner"), "{err}");
    }

    #[test]
    fn argv_cannot_enable_forbidden() {
        let p = Policy::default_oss();
        let err = p
            .clone()
            .tighten(&PolicyOverrides {
                persist_markings: true,
                include_attribution: false,
            })
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));

        let err = p
            .tighten(&PolicyOverrides {
                persist_markings: false,
                include_attribution: true,
            })
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));
    }

    #[test]
    fn argv_tightens_when_policy_allows() {
        let p = Policy::parse_toml(FULL).unwrap();
        let off = p
            .clone()
            .tighten(&PolicyOverrides {
                persist_markings: false,
                include_attribution: false,
            })
            .unwrap();
        assert!(!off.allow_persist_markings);
        assert!(!off.allow_attribution);
        assert!(!off.allow_export_attribution);
        // --bindings is its own flag; not tied to --include-attribution
        assert!(off.allow_export_bindings);

        let on = p
            .tighten(&PolicyOverrides {
                persist_markings: true,
                include_attribution: true,
            })
            .unwrap();
        assert!(on.allow_persist_markings);
        assert!(on.allow_attribution);
        assert!(on.allow_export_attribution);
    }

    #[test]
    fn include_attribution_collect_only() {
        let mut p = Policy::default_oss();
        p.allow_attribution = true;
        let on = p
            .tighten(&PolicyOverrides {
                persist_markings: false,
                include_attribution: true,
            })
            .unwrap();
        assert!(on.allow_attribution);
        assert!(!on.allow_export_attribution);
    }

    #[test]
    fn include_attribution_export_only() {
        let mut p = Policy::default_oss();
        p.allow_export_attribution = true;
        let on = p
            .tighten(&PolicyOverrides {
                persist_markings: false,
                include_attribution: true,
            })
            .unwrap();
        assert!(!on.allow_attribution);
        assert!(on.allow_export_attribution);
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILENAME);
        std::fs::write(&path, FULL).unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.classification_floor, Level::Secret);
        let from_dir = Policy::from_data_dir(dir.path()).unwrap();
        assert_eq!(from_dir, p);
    }

    #[test]
    fn missing_file_oss_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let r = Policy::from_data_dir(dir.path());
        #[cfg(not(feature = "highside"))]
        {
            assert_eq!(r.unwrap(), Policy::default_oss());
        }
        #[cfg(feature = "highside")]
        {
            assert!(matches!(r, Err(Error::PolicyViolation(_))));
        }
    }
}
