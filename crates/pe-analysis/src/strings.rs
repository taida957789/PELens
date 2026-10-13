//! String extraction (ASCII, UTF-8, UTF-16LE, .NET heaps) and hint/label classification.

use crate::model::{StringKind, StringRow};
use pe_db::Knowledge;
use pe_parser::PeFile;
use std::collections::{HashMap, HashSet};

pub const MAX_STRINGS: usize = 200_000;
pub const MAX_STRING_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct StringOptions {
    pub min_len: usize,
    pub ascii: bool,
    pub unicode: bool,
    pub utf8: bool,
}

impl Default for StringOptions {
    fn default() -> Self {
        Self { min_len: 4, ascii: true, unicode: true, utf8: true }
    }
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Raw extraction: (kind, offset, text).
pub fn extract(data: &[u8], o: StringOptions) -> Vec<(StringKind, u64, String)> {
    let mut out = Vec::new();
    let min = o.min_len.max(1);
    if o.ascii || o.utf8 {
        let mut i = 0;
        while i < data.len() && out.len() < MAX_STRINGS {
            let start = i;
            let mut has_multibyte = false;
            while i < data.len() {
                let b = data[i];
                if printable(b) {
                    i += 1;
                } else if o.utf8 && (0xc2..=0xf4).contains(&b) {
                    let n = if b >= 0xf0 {
                        4
                    } else if b >= 0xe0 {
                        3
                    } else {
                        2
                    };
                    if i + n <= data.len() && std::str::from_utf8(&data[i..i + n]).is_ok() {
                        has_multibyte = true;
                        i += n;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            let len_chars =
                if has_multibyte { std::str::from_utf8(&data[start..i]).map(|s| s.chars().count()).unwrap_or(0) } else { i - start };
            if len_chars >= min {
                let end = i.min(start + MAX_STRING_LEN);
                let s = String::from_utf8_lossy(&data[start..end]).into_owned();
                let kind = if has_multibyte { StringKind::Utf8 } else { StringKind::Ascii };
                if kind == StringKind::Ascii && o.ascii || kind == StringKind::Utf8 && o.utf8 {
                    out.push((kind, start as u64, s));
                }
            }
            i = if i == start { i + 1 } else { i };
        }
    }
    if o.unicode {
        // Runs are split whenever the script changes (latin vs. other) so that a stray
        // byte pair next to an ASCII string does not glue a CJK character to it.
        let latin = |u: u16| (u < 0x80 && printable(u as u8)) || (0xa0..0x250).contains(&u);
        let other = |u: u16| (0x250..0xd800).contains(&u) || (0xf900..0xfffe).contains(&u);
        for align in 0..2 {
            let mut i = align;
            while i + 1 < data.len() && out.len() < MAX_STRINGS {
                let start = i;
                let first = u16::from_le_bytes([data[i], data[i + 1]]);
                let class_latin = latin(first);
                if !class_latin && !other(first) {
                    i += 2;
                    continue;
                }
                let mut units = Vec::new();
                while i + 1 < data.len() {
                    let u = u16::from_le_bytes([data[i], data[i + 1]]);
                    let ok = if class_latin { latin(u) } else { other(u) };
                    if !ok {
                        break;
                    }
                    units.push(u);
                    i += 2;
                }
                // Non latin runs need twice the length to be kept (binary data noise).
                let need = if class_latin { min } else { min * 2 };
                if units.len() >= need {
                    units.truncate(MAX_STRING_LEN);
                    out.push((StringKind::Unicode, start as u64, String::from_utf16_lossy(&units)));
                }
            }
        }
    }
    out.sort_by_key(|(_, off, _)| *off);
    out
}

/// Location name of a file offset: section / resource / overlay / header names.
pub fn location_of(pe: &PeFile, off: u64) -> String {
    if let Some(ov) = &pe.overlay
        && off >= ov.offset
        && off < ov.offset + ov.size
    {
        return "overlay".into();
    }
    if let Some(sd) = &pe.security
        && off >= sd.offset as u64
        && off < sd.offset as u64 + sd.size as u64
    {
        return "certificate".into();
    }
    let Some(l) = pe.layout.as_ref() else { return "file".into() };
    if let Some(res) = &pe.resources {
        for e in &res.entries {
            if let Some(fo) = e.file_offset
                && off >= fo as u64
                && off < fo as u64 + e.size as u64
            {
                return format!("resource:{}", e.type_name());
            }
        }
    }
    if off < 0x40 {
        return "dos-header".into();
    }
    if let Some(d) = &pe.dos_header
        && off < d.e_lfanew as u64
    {
        return "dos-stub".into();
    }
    if off < l.optional_header.size_of_headers as u64 {
        return "header".into();
    }
    match l.section_of_offset(off) {
        Some(s) => format!("section:{}", s.name),
        None => "n/a".into(),
    }
}

/// Lookup tables built once per analysis from the knowledge base.
pub struct Classifier<'k> {
    k: &'k Knowledge,
    imports: HashSet<String>,
    exports: HashSet<String>,
    libraries: HashSet<String>,
    case_sensitive: bool,
    /// exact value → (category index, item index)
    exact: HashMap<String, (usize, usize)>,
    /// substring values (lower-cased unless case sensitive)
    contains: Vec<(String, usize, usize)>,
    exts: HashMap<String, (usize, usize)>,
    utils: HashMap<String, (usize, usize)>,
}

#[derive(Debug, Clone, Default)]
pub struct Classification {
    pub hint: Option<String>,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub flag: bool,
    pub whitelist: bool,
    pub blacklist: bool,
}

fn hint_name(k: &Knowledge, id: u8, fallback: &str) -> String {
    k.translations.hint(id).map(|h| h.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn default_hint(cat: &str) -> &'static str {
    match cat {
        "sids" => "sid",
        "privs" => "privilege",
        "agents" => "user-agent",
        "exts" | "folders" => "file",
        "regs" => "registry",
        "offices" => "office",
        "utils" => "utility",
        "stubs" => "dos-stub",
        _ => "string",
    }
}

impl<'k> Classifier<'k> {
    pub fn new(k: &'k Knowledge, pe: &PeFile) -> Self {
        let mut imports = HashSet::new();
        let mut libraries = HashSet::new();
        for l in &pe.imports.libraries {
            libraries.insert(l.name.to_ascii_lowercase());
            for f in &l.functions {
                if let Some(n) = &f.name {
                    imports.insert(n.to_ascii_lowercase());
                }
            }
        }
        if let Some(n) = &pe.dotnet {
            for m in &n.member_refs {
                imports.insert(m.name.to_ascii_lowercase());
            }
            for m in &n.impl_maps {
                imports.insert(m.import_name.to_ascii_lowercase());
            }
            for m in &n.module_refs {
                libraries.insert(m.to_ascii_lowercase());
            }
        }
        let exports =
            pe.exports.iter().flat_map(|e| e.functions.iter().filter_map(|f| f.name.clone())).map(|n| n.to_ascii_lowercase()).collect();
        let cs = k.strings.case_sensitive;
        let norm = |v: &str| if cs { v.to_string() } else { v.to_ascii_lowercase() };
        let mut exact = HashMap::new();
        let mut contains = Vec::new();
        let mut exts = HashMap::new();
        let mut utils = HashMap::new();
        for (ci, cat) in k.strings.categories.iter().enumerate() {
            for (ii, it) in cat.items.iter().enumerate() {
                let v = it.value.trim();
                match cat.name.as_str() {
                    "agents" | "regs" | "folders" | "offices" => contains.push((norm(v), ci, ii)),
                    "exts" => {
                        exts.entry(v.to_ascii_lowercase()).or_insert((ci, ii));
                    }
                    "utils" => {
                        utils.entry(v.to_ascii_lowercase()).or_insert((ci, ii));
                    }
                    _ => {
                        exact.entry(norm(v)).or_insert((ci, ii));
                        if k.strings.substring && v.len() >= 4 && cat.name == "strings" {
                            contains.push((norm(v), ci, ii));
                        }
                    }
                }
            }
        }
        Self { k, imports, exports, libraries, case_sensitive: cs, exact, contains, exts, utils }
    }

    fn db_entry(&self, ci: usize, ii: usize) -> Classification {
        let cat = &self.k.strings.categories[ci];
        let it = &cat.items[ii];
        let dh = default_hint(&cat.name);
        Classification {
            hint: Some(match it.hint {
                Some(h) => hint_name(self.k, h, dh),
                None => dh.to_string(),
            }),
            group: it.group,
            ti: it.ti.clone(),
            flag: it.flag || it.ti.is_some() && cat.name != "stubs",
            blacklist: it.blacklist,
            whitelist: cat.name == "stubs" && !it.flag,
        }
    }

    fn db_lookup(&self, t: &str, lower: &str) -> Option<(usize, usize)> {
        let key = if self.case_sensitive { t } else { lower };
        if let Some(&x) = self.exact.get(key) {
            return Some(x);
        }
        if let Some((_, ci, ii)) = self.contains.iter().find(|(v, _, _)| !v.is_empty() && key.contains(v.as_str())) {
            return Some((*ci, *ii));
        }
        if let Some((stem, ext)) = lower.rsplit_once('.')
            && !stem.is_empty()
            && !ext.is_empty()
            && ext.len() <= 8
            && let Some(&x) = self.exts.get(ext)
        {
            return Some(x);
        }
        if !self.utils.is_empty() {
            for w in lower.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_' && ch != '-') {
                let w = w.strip_suffix(".exe").unwrap_or(w);
                if let Some(&x) = self.utils.get(w) {
                    return Some(x);
                }
            }
        }
        None
    }

    pub fn classify(&self, s: &str) -> Classification {
        let t = s.trim();
        let lower = t.to_ascii_lowercase();
        if let Some((ci, ii)) = self.db_lookup(t, &lower) {
            return self.db_entry(ci, ii);
        }
        let mut c = Classification::default();
        // Function names known by the knowledge base.
        if t.len() >= 4
            && !t.contains(' ')
            && let Some(f) = self.k.functions.function("", t)
        {
            c.group = f.group;
            c.ti = f.ti.clone();
            c.flag = f.flag;
            c.hint = Some(if self.imports.contains(&lower) { hint_name(self.k, 26, "import") } else { "function".into() });
            c.whitelist = self.imports.contains(&lower) && !f.flag;
            return c;
        }
        if self.imports.contains(&lower) {
            c.hint = Some(hint_name(self.k, 26, "import"));
            c.whitelist = true;
            return c;
        }
        if self.exports.contains(&lower) {
            c.hint = Some(hint_name(self.k, 27, "export"));
            c.whitelist = true;
            return c;
        }
        if self.libraries.contains(&lower) || (lower.ends_with(".dll") && self.k.functions.library(&lower).is_some()) {
            c.hint = Some(hint_name(self.k, 30, "library"));
            c.whitelist = self.libraries.contains(&lower);
            if let Some(l) = self.k.functions.library(&lower) {
                c.flag = l.flag;
                c.group = l.group;
            }
            return c;
        }
        if t.contains('.')
            && !t.contains(' ')
            && let Some(ns) = self.k.namespaces.lookup(t)
        {
            c.hint = Some(hint_name(self.k, 29, "dotnet-namespace"));
            c.flag = ns.flag;
            c.group = ns.group;
            c.ti = ns.ti.clone();
            return c;
        }
        c.hint = heuristic_hint(t).map(str::to_string);
        if let Some(h) = &c.hint {
            c.flag = matches!(h.as_str(), "url-pattern" | "ip-address" | "base64" | "mutex" | "pipe");
        }
        c
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().is_ok_and(|v| v <= 255))
        && !s.starts_with("0.")
}

fn is_guid(s: &str) -> bool {
    let t = s.trim_matches(['{', '}']);
    let parts: Vec<&str> = t.split('-').collect();
    parts.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&parts).all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_base64(s: &str) -> bool {
    s.len() >= 16
        && s.len().is_multiple_of(4)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        && s.trim_end_matches('=').bytes().all(|b| b != b'=')
        && s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_uppercase())
        && s.bytes().any(|b| b.is_ascii_lowercase())
}

/// Built-in pattern recognition for strings not covered by the knowledge base.
pub fn heuristic_hint(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    if ["http://", "https://", "ftp://", "ws://", "wss://"].iter().any(|p| l.contains(p)) || (l.starts_with("www.") && l.len() > 6) {
        return Some("url-pattern");
    }
    if s.starts_with("1.2.840.") || s.starts_with("1.3.6.1.") || s.starts_with("2.5.29.") {
        return Some("oid");
    }
    if is_ipv4(s) || s.split(':').next().is_some_and(is_ipv4) && s.contains(':') {
        return Some("ip-address");
    }
    if l.starts_with("hkey_")
        || l.starts_with("hklm\\")
        || l.starts_with("hkcu\\")
        || l.contains("\\currentversion\\")
        || l.starts_with("software\\")
    {
        return Some("registry");
    }
    if l.starts_with("\\\\.\\pipe\\") || l.starts_with("\\\\?\\pipe") {
        return Some("pipe");
    }
    if l.starts_with("global\\") || l.starts_with("local\\") {
        return Some("mutex");
    }
    if l.starts_with("select ") && l.contains(" from ") {
        return Some("query");
    }
    if s.starts_with("S-1-") && s[4..].split('-').all(|p| p.parse::<u64>().is_ok()) {
        return Some("sid");
    }
    if is_guid(s) {
        return Some("guid");
    }
    if s.starts_with(".?AV") || s.starts_with(".?AU") || s.starts_with("??_7") {
        return Some("rtti");
    }
    if l.ends_with(".pdb") {
        return Some("debug");
    }
    if is_base64(s) {
        return Some("base64");
    }
    if (s.contains("%s") || s.contains("%d") || s.contains("%x") || s.contains("%i") || s.contains("%ls") || s.contains("%08X"))
        && s.len() > 3
    {
        return Some("format-string");
    }
    if s.len() >= 6 && (s.starts_with('^') && s.ends_with('$') || s.contains("[a-z") || s.contains("\\d") || s.contains("[0-9]")) {
        return Some("regex");
    }
    None
}

pub fn build_rows(k: &Knowledge, pe: &PeFile, data: &[u8], o: StringOptions) -> Vec<StringRow> {
    let cls = Classifier::new(k, pe);
    let mut rows: Vec<StringRow> = extract(data, o)
        .into_iter()
        .map(|(kind, offset, value)| {
            let location = location_of(pe, offset);
            let mut c = cls.classify(&value);
            if c.hint.as_deref() == Some("ip-address") && location == "resource:version" {
                c.hint = None;
                c.flag = false;
            }
            // URLs inside the Authenticode blob (CRL, OCSP, CPS…) are differentiated from hard-coded URLs.
            if c.hint.as_deref() == Some("url-pattern") && location == "certificate" {
                c.hint = Some("url-pattern (certificate)".into());
                c.flag = false;
            }
            StringRow {
                kind,
                size: value.chars().count(),
                offset,
                location,
                value,
                hint: c.hint,
                group: c.group,
                ti: c.ti,
                flag: c.flag,
                whitelist: c.whitelist,
                blacklist: c.blacklist,
            }
        })
        .collect();
    if let Some(n) = &pe.dotnet {
        let seen: HashSet<&str> = rows.iter().map(|r| r.value.as_str()).collect();
        let fresh: Vec<String> = n.user_strings.iter().filter(|v| !seen.contains(v.as_str())).cloned().collect();
        for (kind, list) in [(StringKind::DotNetUser, &fresh)] {
            for v in list.iter().filter(|v| v.chars().count() >= o.min_len) {
                let c = cls.classify(v);
                rows.push(StringRow {
                    kind,
                    size: v.chars().count(),
                    offset: 0,
                    location: "dotnet".into(),
                    value: v.clone(),
                    hint: c.hint,
                    group: c.group,
                    ti: c.ti,
                    flag: c.flag,
                    whitelist: c.whitelist,
                    blacklist: c.blacklist,
                });
            }
        }
    }
    rows
}

/// The URL part of a string flagged as url-pattern (drops leading length bytes / junk).
pub fn url_part(s: &str) -> &str {
    let l = s.to_ascii_lowercase();
    ["http://", "https://", "ftp://", "ws://", "wss://", "www."].iter().filter_map(|p| l.find(p)).min().map(|i| &s[i..]).unwrap_or(s)
}
