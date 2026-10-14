//! YARA rules (YARA-X, the VirusTotal Rust implementation): compiled once from a folder of
//! `.yar` / `.yara` files, then matched against each analysed file. Without the `yara` feature
//! the same API compiles to "no rules".

use std::path::Path;

/// One matching rule and where its patterns matched.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// Rule metadata as text: (identifier, value).
    pub meta: Vec<(String, String)>,
    /// Pattern matches: (identifier, file offset, length).
    pub strings: Vec<(String, u64, u64)>,
}

impl YaraMatch {
    /// Severity from the rule's `severity` metadata (1/2/3, high/medium/low, critical); 2 otherwise.
    pub fn severity(&self) -> u8 {
        let v = self.meta.iter().find(|(k, _)| k.eq_ignore_ascii_case("severity")).map(|(_, v)| v.trim().to_ascii_lowercase());
        match v.as_deref() {
            Some("1" | "high" | "critical") => 1,
            Some("3" | "low" | "info" | "informational") => 3,
            _ => 2,
        }
    }
}

/// Patterns listed per rule at most (a rule can match thousands of times).
pub const MAX_STRINGS_PER_RULE: usize = 64;
/// Scan time limit per file, in seconds.
pub const SCAN_TIMEOUT_SECS: u64 = 30;

/// Rule files of a folder (and its sub-folders), sorted.
pub fn rule_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara")) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[cfg(feature = "yara")]
mod imp {
    use super::*;

    /// Compiled rules.
    pub struct YaraRules {
        rules: yara_x::Rules,
        /// Number of rule files compiled.
        pub files: usize,
    }

    impl std::fmt::Debug for YaraRules {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "YaraRules({} files)", self.files)
        }
    }

    /// Compile every rule file of `dir`; each file is its own namespace (its file name). A file
    /// that does not compile is skipped and reported, the others are kept.
    pub fn compile_dir(dir: &Path) -> (Option<YaraRules>, Vec<String>) {
        let mut errors = Vec::new();
        let mut c = yara_x::Compiler::new();
        let mut files = 0;
        for p in rule_files(dir) {
            let name = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let src = match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("{}: {e}", p.display()));
                    continue;
                }
            };
            c.new_namespace(&name);
            let source = yara_x::SourceCode::from(src.as_str()).with_origin(p.to_string_lossy().as_ref());
            match c.add_source(source) {
                Ok(_) => files += 1,
                Err(e) => errors.push(e.to_string()),
            }
        }
        if files == 0 {
            return (None, errors);
        }
        (Some(YaraRules { rules: c.build(), files }), errors)
    }

    /// Match the rules against `data`. Errors (timeout) are returned as text.
    pub fn scan(rules: &YaraRules, data: &[u8]) -> Result<Vec<YaraMatch>, String> {
        let mut s = yara_x::Scanner::new(&rules.rules);
        s.set_timeout(std::time::Duration::from_secs(SCAN_TIMEOUT_SECS));
        let res = s.scan(data).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in res.matching_rules() {
            let meta = r
                .metadata()
                .map(|(k, v)| {
                    let v = match v {
                        yara_x::MetaValue::Integer(i) => i.to_string(),
                        yara_x::MetaValue::Float(f) => f.to_string(),
                        yara_x::MetaValue::Bool(b) => b.to_string(),
                        yara_x::MetaValue::String(s) => s.to_string(),
                        yara_x::MetaValue::Bytes(b) => b.to_string(),
                    };
                    (k.to_string(), v)
                })
                .collect();
            let mut strings = Vec::new();
            'outer: for p in r.patterns() {
                for m in p.matches() {
                    if strings.len() >= MAX_STRINGS_PER_RULE {
                        break 'outer;
                    }
                    let range = m.range();
                    strings.push((p.identifier().to_string(), range.start as u64, (range.end - range.start) as u64));
                }
            }
            out.push(YaraMatch {
                rule: r.identifier().to_string(),
                namespace: r.namespace().to_string(),
                tags: r.tags().map(|t| t.identifier().to_string()).collect(),
                meta,
                strings,
            });
        }
        Ok(out)
    }
}

#[cfg(not(feature = "yara"))]
mod imp {
    use super::*;

    /// Built without the `yara` feature: there are never any rules.
    #[derive(Debug)]
    pub struct YaraRules {
        pub files: usize,
    }

    pub fn compile_dir(dir: &Path) -> (Option<YaraRules>, Vec<String>) {
        let n = rule_files(dir).len();
        let e = if n > 0 { vec![format!("{n} rule file(s) ignored: PELens was built without YARA support")] } else { Vec::new() };
        (None, e)
    }

    pub fn scan(_rules: &YaraRules, _data: &[u8]) -> Result<Vec<YaraMatch>, String> {
        Ok(Vec::new())
    }
}

pub use imp::{YaraRules, compile_dir, scan};
