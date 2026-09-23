//! Output formatting. Default is human-readable. `--json` keeps the stable
//! machine shape that scripts (demo.sh) parse.
//!
//! Page banners use the CAPCO banner profile (TOP SECRET, NOFORN). Per-name
//! lines and lookup use the portion profile (TS, NF), parenthesized here.

use lexicon_core::marking::{CompartmentKind, Level, Marking};
use serde::Serialize;
use std::io::{IsTerminal, Write};
use std::sync::OnceLock;

pub struct Ui {
    json: bool,
    color: bool,
}

impl Ui {
    pub fn new(json: bool) -> Self {
        Self {
            json,
            color: json_color(),
        }
    }

    pub fn is_json(&self) -> bool {
        self.json
    }

    /// Emit a pre-shaped JSON value (the back-compat machine output).
    pub fn json<T: Serialize>(&self, value: &T) {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string_pretty(value).unwrap()
        );
    }

    /// Status line: `ok <msg>` or `FAIL <msg>`.
    pub fn status(&self, ok: bool, msg: &str) {
        if self.json {
            return;
        }
        let tag = if ok {
            self.paint(Color::Green, "ok")
        } else {
            self.paint(Color::Red, "FAIL")
        };
        let _ = writeln!(std::io::stdout(), "{tag}  {msg}");
    }

    /// `label  value` row. Dim label, bright value.
    pub fn kv(&self, label: &str, value: &str) {
        if self.json {
            return;
        }
        let l = self.paint(Color::Dim, &format!("{label:<10}"));
        let _ = writeln!(std::io::stdout(), "  {l} {value}");
    }

    pub fn heading(&self, msg: &str) {
        if self.json {
            return;
        }
        let _ = writeln!(std::io::stdout(), "{}", self.paint(Color::Bold, msg));
    }

    pub fn line(&self, msg: &str) {
        if self.json {
            return;
        }
        let _ = writeln!(std::io::stdout(), "{msg}");
    }

    pub fn names(&self, names: &[String]) {
        if self.json {
            return;
        }
        for n in names {
            let _ = writeln!(std::io::stdout(), "  {n}");
        }
    }

    /// Top classification banner + separator (CAPCO: every
    /// classified page carries the marking at the top).
    pub fn banner_top(&self, marking: &Marking) {
        if self.json {
            return;
        }
        let c = marking_color(marking);
        let line = banner_line(marking);
        let _ = writeln!(std::io::stdout(), "{}", self.paint_rgb(c, &line));
        let _ = writeln!(std::io::stdout(), "{}", "-".repeat(40));
    }

    /// Bottom classification banner. The torn-page rule: a page torn in
    /// half still carries its marking on each half.
    pub fn banner_bottom(&self, marking: &Marking) {
        if self.json {
            return;
        }
        let c = marking_color(marking);
        let _ = writeln!(std::io::stdout(), "{}", "-".repeat(40));
        let line = banner_line(marking);
        let _ = writeln!(std::io::stdout(), "{}", self.paint_rgb(c, &line));
    }

    fn paint(&self, c: Color, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        let code = match c {
            Color::Green => "32",
            Color::Red => "31",
            Color::Bold => "1",
            Color::Dim => "2",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    /// 24-bit truecolor. Used for the banner (exact DoD hex codes,
    /// not the 256-color palette).
    fn paint_rgb(&self, rgb: (u8, u8, u8), text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        let (r, g, b) = rgb;
        format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
    }
}

/// Portion mark, parenthesized. Per-name lines and lookup.
pub fn portion(marking: &Marking) -> String {
    format!("({})", marking.display_portion())
}

/// Re-display a stored marking string in portion form. Lenient — legacy
/// `SCI/<dg>` rows still render in the new grammar.
pub fn portion_of_stored(s: &str) -> String {
    match Marking::from_stored(s) {
        Ok(m) => portion(&m),
        Err(_) => format!("({s})"),
    }
}

fn banner_line(marking: &Marking) -> String {
    let label = format!("CLASSIFICATION: {}", marking.display_banner());
    // Center the label over the 40-char dash line below.
    let pad = (40_usize.saturating_sub(label.len() + 2)) / 2;
    let mut right = "=".repeat(pad);
    let left = "=".repeat(pad);
    if left.len() + 1 + label.len() + 1 + right.len() < 40 {
        right.push('=');
    }
    format!("{left} {label} {right}")
}

enum Color {
    Green,
    Red,
    Bold,
    Dim,
}

// DoD/IC banner colors (r, g, b) from the official hex codes.
fn marking_color(m: &Marking) -> (u8, u8, u8) {
    let has_sci = m
        .compartments
        .iter()
        .any(|c| c.kind == CompartmentKind::Sci);
    match (m.level, has_sci) {
        (Level::Unclassified, _) => (0x00, 0x7A, 0x33),
        (Level::Cui, _) => (0x50, 0x2B, 0x85),
        (Level::Confidential, _) => (0x00, 0x33, 0xA0),
        (Level::Secret, _) => (0xC8, 0x10, 0x2E),
        (Level::TopSecret, true) => (0xFC, 0xE8, 0x3A),
        (Level::TopSecret, false) => (0xFF, 0x8C, 0x00),
    }
}

// Color only on a real tty with NO_COLOR unset. Piped/CI
// stdout stays plain automatically.
fn json_color() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lexicon_core::marking::{Caveat, Compartment};

    fn ts_sci() -> Marking {
        Marking {
            level: Level::TopSecret,
            caveats: vec![Caveat::Noforn],
            compartments: vec![Compartment {
                kind: CompartmentKind::Sci,
                designator: "TK".into(),
            }],
        }
    }

    #[test]
    fn banner_line_uses_spelled_out_profile() {
        let line = banner_line(&ts_sci());
        assert!(
            line.contains("CLASSIFICATION: TOP SECRET//TK//NOFORN"),
            "{line}"
        );
        assert!(!line.contains("TS//"), "{line}");
        assert!(!line.contains("//NF"), "{line}");
    }

    #[test]
    fn portion_parenthesizes_abbreviations() {
        assert_eq!(portion(&ts_sci()), "(TS//TK//NF)");
        assert_eq!(portion_of_stored("TS//SCI/TK//NOFORN"), "(TS//TK//NF)");
        assert_eq!(portion(&Marking::default()), "(U)");
    }

    #[test]
    fn ts_sci_banner_is_yellow() {
        assert_eq!(marking_color(&ts_sci()), (0xFC, 0xE8, 0x3A));
        assert_eq!(
            marking_color(&Marking {
                level: Level::TopSecret,
                ..Default::default()
            }),
            (0xFF, 0x8C, 0x00)
        );
        assert_eq!(marking_color(&Marking::default()), (0x00, 0x7A, 0x33));
    }
}
