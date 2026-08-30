use crate::pool::PoolWord;
use crate::types::NameType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    Reject,
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintHit {
    pub rule: String,
    pub severity: LintSeverity,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct NameCandidate {
    pub name: String,
    pub name_type: NameType,
    pub words: Vec<PoolWord>,
}

#[derive(Debug, Clone, Default)]
pub struct ExternalHooks {
    /// Trademark / pop-culture / living-person lookups. None = stub (use shipped lists only).
    pub trademark: Option<fn(&str) -> Option<String>>,
    pub pop_culture: Option<fn(&str) -> Option<String>>,
    pub living_person: Option<fn(&str) -> Option<String>>,
}

pub trait LintRule: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, candidate: &NameCandidate, hooks: &ExternalHooks) -> Vec<LintHit>;
}

pub struct LintEngine {
    rules: Vec<Box<dyn LintRule>>,
    pub hooks: ExternalHooks,
}

impl LintEngine {
    pub fn core() -> Self {
        Self {
            rules: vec![
                Box::new(BlocklistRule::default()),
                Box::new(PopCultureRule::default()),
                Box::new(TrademarkRule::default()),
                Box::new(LivingPersonRule),
                Box::new(SameWordRule),
                Box::new(BannedPairRule::default()),
                Box::new(Janap119Rule::default()),
                Box::new(EuphonyRule),
                Box::new(TransliterationRule),
                Box::new(MeaningLeakRule::default()),
            ],
            hooks: ExternalHooks::default(),
        }
    }

    pub fn check(&self, candidate: &NameCandidate) -> Vec<LintHit> {
        self.rules
            .iter()
            .flat_map(|r| r.check(candidate, &self.hooks))
            .collect()
    }

    pub fn first_reject(&self, candidate: &NameCandidate) -> Option<LintHit> {
        self.check(candidate)
            .into_iter()
            .find(|h| h.severity == LintSeverity::Reject)
    }

    /// Single-word gate for pool curation. Pair rules do not apply.
    pub fn rejects_word(&self, word: &str) -> Option<LintHit> {
        self.first_reject(&NameCandidate {
            name: word.to_ascii_uppercase(),
            name_type: NameType::CodeWord,
            words: vec![PoolWord::new(word)],
        })
    }
}

fn tokens(name: &str) -> Vec<String> {
    name.split_whitespace()
        .map(|s| s.to_ascii_uppercase())
        .collect()
}

fn compact(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

struct BlocklistRule {
    words: Vec<&'static str>,
}

impl Default for BlocklistRule {
    fn default() -> Self {
        Self {
            words: vec![
                "RAGE",
                "KILL",
                "RAPE",
                "NAZI",
                "JIHAD",
                "CRUSADE",
                "SLAVE",
                "GENOCIDE",
                "APARTHEID",
                "RACIST",
            ],
        }
    }
}

impl LintRule for BlocklistRule {
    fn name(&self) -> &'static str {
        "blocklist"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let hay = compact(&candidate.name);
        self.words
            .iter()
            .filter(|w| hay.contains(*w) || tokens(&candidate.name).iter().any(|t| t == *w))
            .map(|w| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("blocked token {w}"),
            })
            .collect()
    }
}

struct PopCultureRule {
    names: Vec<&'static str>,
}

impl Default for PopCultureRule {
    fn default() -> Self {
        Self {
            names: vec![
                "RICKYBOBBY",
                "ROIDRAGE",
                "STARWARS",
                "BATMAN",
                "VULCAN",
                "TURTLEPOWER",
                "MINDMELD",
                "DEATHGRIP",
                "HARRYPOTTER",
                "HOGWARTS",
                "SKYNET",
                "WAKANDA",
            ],
        }
    }
}

impl LintRule for PopCultureRule {
    fn name(&self) -> &'static str {
        "pop_culture"
    }
    fn check(&self, candidate: &NameCandidate, hooks: &ExternalHooks) -> Vec<LintHit> {
        let hay = compact(&candidate.name);
        let mut hits: Vec<LintHit> = self
            .names
            .iter()
            .filter(|n| hay.contains(*n))
            .map(|n| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("pop-culture token {n}"),
            })
            .collect();
        if let Some(hook) = hooks.pop_culture {
            if let Some(why) = hook(&candidate.name) {
                hits.push(LintHit {
                    rule: self.name().into(),
                    severity: LintSeverity::Reject,
                    detail: why,
                });
            }
        }
        hits
    }
}

struct TrademarkRule {
    marks: Vec<&'static str>,
}

impl Default for TrademarkRule {
    fn default() -> Self {
        Self {
            marks: vec![
                "GOOGLE",
                "MICROSOFT",
                "APPLE",
                "AMAZON",
                "TESLA",
                "NIKE",
                "DISNEY",
                "COCA",
                "PEPSI",
                "STARBUCKS",
            ],
        }
    }
}

impl LintRule for TrademarkRule {
    fn name(&self) -> &'static str {
        "trademark"
    }
    fn check(&self, candidate: &NameCandidate, hooks: &ExternalHooks) -> Vec<LintHit> {
        let hay = compact(&candidate.name);
        let mut hits: Vec<_> = self
            .marks
            .iter()
            .filter(|m| hay.contains(*m))
            .map(|m| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!(
                    "trademark token {m} (shipped sample; hook a real DB in production)"
                ),
            })
            .collect();
        if let Some(hook) = hooks.trademark {
            if let Some(why) = hook(&candidate.name) {
                hits.push(LintHit {
                    rule: self.name().into(),
                    severity: LintSeverity::Reject,
                    detail: why,
                });
            }
        }
        hits
    }
}

struct LivingPersonRule;

impl LintRule for LivingPersonRule {
    fn name(&self) -> &'static str {
        "living_person"
    }
    fn check(&self, candidate: &NameCandidate, hooks: &ExternalHooks) -> Vec<LintHit> {
        if let Some(hook) = hooks.living_person {
            if let Some(why) = hook(&candidate.name) {
                return vec![LintHit {
                    rule: self.name().into(),
                    severity: LintSeverity::Reject,
                    detail: why,
                }];
            }
        }
        Vec::new()
    }
}

struct SameWordRule;

impl LintRule for SameWordRule {
    fn name(&self) -> &'static str {
        "same_word"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let t = tokens(&candidate.name);
        if t.len() == 2 && t[0] == t[1] {
            return vec![LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: "identical pair".into(),
            }];
        }
        Vec::new()
    }
}

struct BannedPairRule {
    pairs: Vec<(&'static str, &'static str)>,
}

impl Default for BannedPairRule {
    fn default() -> Self {
        Self {
            pairs: vec![
                ("BLUE", "SPOON"),
                ("INFINITE", "JUSTICE"),
                ("ENDURING", "FREEDOM"),
                ("JUST", "CAUSE"),
                ("DESERT", "STORM"),
                ("IRAQI", "FREEDOM"),
                ("NEW", "DAWN"),
                ("INHERENT", "RESOLVE"),
            ],
        }
    }
}

impl LintRule for BannedPairRule {
    fn name(&self) -> &'static str {
        "banned_pair"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let t = tokens(&candidate.name);
        if t.len() != 2 {
            return Vec::new();
        }
        self.pairs
            .iter()
            .filter(|(a, b)| t[0] == *a && t[1] == *b)
            .map(|(a, b)| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("banned pair {a} {b}"),
            })
            .collect()
    }
}

struct Janap119Rule {
    callsigns: Vec<&'static str>,
}

impl Default for Janap119Rule {
    fn default() -> Self {
        // Sample only. Production should load ACP-119/JANAP-119.
        Self {
            callsigns: vec![
                "PANTHER", "EAGLE", "HAWK", "VIPER", "MUSTANG", "PHANTOM", "TOMCAT", "HORNET",
                "FALCON", "RAVEN",
            ],
        }
    }
}

impl LintRule for Janap119Rule {
    fn name(&self) -> &'static str {
        "janap119"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let t = tokens(&candidate.name);
        self.callsigns
            .iter()
            .filter(|c| t.iter().any(|w| w == *c) || compact(&candidate.name) == **c)
            .map(|c| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("JANAP-119/ACP-119 sample collision: {c}"),
            })
            .collect()
    }
}

struct EuphonyRule;

impl LintRule for EuphonyRule {
    fn name(&self) -> &'static str {
        "euphony"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let t = tokens(&candidate.name);
        let mut hits = Vec::new();
        // SAP tokens are 1–3 letters by convention (G, TK, HCS).
        if candidate.name_type != NameType::SapDesignator {
            for w in &t {
                if w.len() < 3 {
                    hits.push(LintHit {
                        rule: self.name().into(),
                        severity: LintSeverity::Reject,
                        detail: format!("too short: {w}"),
                    });
                }
            }
        }
        for w in &t {
            if consonant_run(w) >= 5 {
                hits.push(LintHit {
                    rule: self.name().into(),
                    severity: LintSeverity::Warn,
                    detail: format!("harsh cluster: {w}"),
                });
            }
        }
        if t.len() == 2 && rhyme(&t[0], &t[1]) {
            hits.push(LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Warn,
                detail: "rhyming pair".into(),
            });
        }
        hits
    }
}

fn is_vowel(c: char) -> bool {
    matches!(c, 'A' | 'E' | 'I' | 'O' | 'U' | 'Y')
}

fn consonant_run(w: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for c in w.chars() {
        if c.is_ascii_alphabetic() && !is_vowel(c) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn rhyme(a: &str, b: &str) -> bool {
    let tail = |s: &str| {
        s.chars()
            .rev()
            .take(3)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    };
    a.len() >= 3 && b.len() >= 3 && tail(a) == tail(b)
}

struct TransliterationRule;

impl LintRule for TransliterationRule {
    fn name(&self) -> &'static str {
        "transliteration"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        candidate
            .words
            .iter()
            .filter(|w| !w.unsafe_langs.is_empty())
            .map(|w| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("{} flagged unsafe for {}", w.word, w.unsafe_langs.join(",")),
            })
            .collect()
    }
}

struct MeaningLeakRule {
    leaks: Vec<&'static str>,
}

impl Default for MeaningLeakRule {
    fn default() -> Self {
        Self {
            leaks: vec![
                "SECRET",
                "COVERT",
                "CLASSIFIED",
                "SPY",
                "ASSASSIN",
                "NUCLEAR",
                "IRAN",
                "IRAQ",
                "CHINA",
                "RUSSIA",
                "MOSCOW",
                "TEHRAN",
                "BEIJING",
                "TERROR",
                "DRONE",
                "TARGET",
                "KILL",
            ],
        }
    }
}

impl LintRule for MeaningLeakRule {
    fn name(&self) -> &'static str {
        "meaning_leak"
    }
    fn check(&self, candidate: &NameCandidate, _: &ExternalHooks) -> Vec<LintHit> {
        let hay = compact(&candidate.name);
        self.leaks
            .iter()
            .filter(|w| hay.contains(*w))
            .map(|w| LintHit {
                rule: self.name().into(),
                severity: LintSeverity::Reject,
                detail: format!("meaning-leaking token {w}"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(name: &str) -> NameCandidate {
        NameCandidate {
            name: name.into(),
            name_type: NameType::Nickname,
            words: name.split_whitespace().map(PoolWord::new).collect(),
        }
    }

    #[test]
    fn rejects_known_bad() {
        let e = LintEngine::core();
        assert!(e.first_reject(&cand("BLUE SPOON")).is_some());
        assert!(e.first_reject(&cand("RICKY BOBBY")).is_some());
        assert!(e.first_reject(&cand("INFINITE JUSTICE")).is_some());
        assert!(e.first_reject(&cand("GRANITE GRANITE")).is_some());
        assert!(e.first_reject(&cand("COVERT ORBIT")).is_some());
        assert!(e.first_reject(&cand("EAGLE MESA")).is_some()); // JANAP sample
    }

    #[test]
    fn accepts_dull() {
        let e = LintEngine::core();
        assert!(e.first_reject(&cand("GRANITE SPIRE")).is_none());
        assert!(e.first_reject(&cand("COPPER LEDGER")).is_none());
        assert!(e.rejects_word("SECRET").is_some());
        assert!(e.rejects_word("GRANITE").is_none());
    }
}
