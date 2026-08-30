//! Output formatting. Default is human-readable. `--json` keeps the stable
//! machine shape that scripts (demo.sh) parse.

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
}

enum Color {
    Green,
    Red,
    Bold,
    Dim,
}

// Color only on a real tty and when NO_COLOR is unset. CI pipes stdout, so
// this stays plain text there automatically.
fn json_color() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err())
}
