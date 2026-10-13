//! Typed views over each pestudio XML knowledge file.

use crate::dom::{Element, parse_int, payload};
use std::collections::{BTreeMap, HashMap};

fn opt_str(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|v| !v.is_empty() && !v.chars().all(|c| c == '-')).map(str::to_string)
}

fn opt_u8(e: &Element, a: &str) -> Option<u8> {
    e.attr_int(a).and_then(|v| u8::try_from(v).ok())
}

/// MITRE technique id ("1055" → "T1055"); "----"/"" → None.
fn ti(e: &Element) -> Option<String> {
    opt_str(e.attr("ti"))
}

// ---------------------------------------------------------------- settings.xml

#[derive(Debug, Clone, Default)]
pub struct Color {
    pub id: u8,
    pub rgb: (u8, u8, u8),
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct StreamSetting {
    pub id: String,
    pub flag: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct TableSetting {
    pub id: u8,
    pub enable: bool,
    pub flag: bool,
    pub desc: String,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub files: BTreeMap<String, String>,
    /// `<setting>` children: element name → attributes (ordered as in the file).
    pub setting: Vec<(String, Vec<(String, String)>)>,
    pub colors_enabled: bool,
    pub colors: Vec<Color>,
    pub standard_sections: Vec<String>,
    pub streams_flag: bool,
    pub streams: Vec<StreamSetting>,
    pub tables_flag: bool,
    pub tables: Vec<TableSetting>,
    pub tips: Vec<(String, String)>,
}

impl Settings {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut s = Settings::default();
        if let Some(f) = x.child("files") {
            for c in &f.children {
                s.files.insert(c.name.clone(), c.text_trim().to_string());
            }
        }
        if let Some(st) = x.child("setting") {
            for c in &st.children {
                s.setting.push((c.name.clone(), c.attrs.clone()));
            }
        }
        if let Some(c) = x.child("colors") {
            s.colors_enabled = c.attr_bool("enable");
            for col in c.children_named("color") {
                let g = |k: &str| col.attr_int(k).unwrap_or(0).clamp(0, 255) as u8;
                s.colors.push(Color {
                    id: col.attr_int("id").unwrap_or(0) as u8,
                    rgb: (g("r"), g("g"), g("b")),
                    name: col.text_trim().to_string(),
                });
            }
        }
        if let Some(sec) = x.child("sections") {
            s.standard_sections = sec.children_named("section").map(|e| e.text_trim().to_string()).collect();
        }
        if let Some(st) = x.child("streams") {
            s.streams_flag = st.attr_bool("flag");
            s.streams = st
                .children_named("stream")
                .map(|e| StreamSetting { id: e.attr_or("id", "").to_string(), flag: e.attr_bool("flag"), name: e.text_trim().to_string() })
                .collect();
        }
        if let Some(t) = x.child("tables") {
            s.tables_flag = t.attr_bool("flag");
            s.tables = t
                .children_named("table")
                .map(|e| TableSetting {
                    id: e.attr_int("id").unwrap_or(99) as u8,
                    enable: e.attr_bool("enable"),
                    flag: e.attr_bool("flag"),
                    desc: e.attr_or("desc", "").to_string(),
                    name: e.text_trim().to_string(),
                })
                .collect();
        }
        if let Some(t) = x.child("tips") {
            s.tips = t.children_named("tip").map(|e| (e.attr_or("id", "").to_string(), e.text_trim().to_string())).collect();
        }
        s
    }

    pub fn get(&self, elem: &str, attr: &str) -> Option<&str> {
        self.setting.iter().find(|(n, _)| n == elem)?.1.iter().find(|(k, _)| k == attr).map(|(_, v)| v.as_str())
    }

    pub fn get_int(&self, elem: &str, attr: &str, def: i64) -> i64 {
        self.get(elem, attr).and_then(parse_int).unwrap_or(def)
    }

    pub fn get_bool(&self, elem: &str, attr: &str, def: bool) -> bool {
        self.get(elem, attr).and_then(parse_int).map(|v| v != 0).unwrap_or(def)
    }

    /// Set a setting attribute in memory (inserting the element/attribute if missing).
    pub fn set(&mut self, elem: &str, attr: &str, value: &str) {
        if let Some((_, attrs)) = self.setting.iter_mut().find(|(n, _)| n == elem) {
            if let Some(a) = attrs.iter_mut().find(|(k, _)| k == attr) {
                a.1 = value.to_string();
            } else {
                attrs.push((attr.to_string(), value.to_string()));
            }
        } else {
            self.setting.push((elem.to_string(), vec![(attr.to_string(), value.to_string())]));
        }
    }

    pub fn color(&self, id: u8) -> Option<(u8, u8, u8)> {
        self.colors.iter().find(|c| c.id == id).map(|c| c.rgb)
    }

    pub fn is_standard_section(&self, name: &str) -> bool {
        self.standard_sections.iter().any(|s| s == name)
    }
}

// ---------------------------------------------------------------- indicators.xml / thresholds.xml

#[derive(Debug, Clone, Default)]
pub struct IndicatorDef {
    pub id: u32,
    /// 0 = disabled, 1 = enabled, 2 = enabled (conditional)
    pub enable: u8,
    pub severity: u8,
    pub kind: String,
    pub ti: Option<String>,
    pub detail: String,
    pub name: String,
}

pub fn load_indicators(doc: &Element) -> Vec<IndicatorDef> {
    let x = payload(doc);
    let Some(list) = x.child("indicators") else { return Vec::new() };
    list.children_named("item")
        .map(|e| IndicatorDef {
            id: e.attr_int("id").unwrap_or(0) as u32,
            enable: opt_u8(e, "enable").unwrap_or(1),
            severity: opt_u8(e, "severity").unwrap_or(3),
            kind: e.attr_or("type", "--").to_string(),
            ti: ti(e),
            detail: e.attr_or("detail", "%s").to_string(),
            name: e.text_trim().to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Threshold {
    pub id: u32,
    pub enable: bool,
    pub level: u8,
    pub min: i64,
    pub max: i64,
}

impl Threshold {
    /// Value outside [min, max]; -1 means "no bound".
    pub fn violated(&self, v: i64) -> bool {
        (self.min != -1 && v < self.min) || (self.max != -1 && v > self.max)
    }
}

pub fn load_thresholds(doc: &Element) -> Vec<Threshold> {
    let x = payload(doc);
    let Some(list) = x.child("thresholds") else { return Vec::new() };
    list.children_named("item")
        .map(|e| Threshold {
            id: e.attr_int("id").unwrap_or(0) as u32,
            enable: e.attr_bool("enable"),
            level: opt_u8(e, "level").unwrap_or(2),
            min: e.attr_int("min").unwrap_or(-1),
            max: e.attr_int("max").unwrap_or(-1),
        })
        .collect()
}

// ---------------------------------------------------------------- functions.xml

#[derive(Debug, Clone, Default)]
pub struct FunctionDef {
    pub name: String,
    pub group: Option<u8>,
    /// Ordinal mapped to this name (imports by ordinal).
    pub ordinal: Option<u16>,
    pub flag: bool,
    pub callback: bool,
    pub undocumented: bool,
    pub deprecated: bool,
    pub anti_debug: bool,
    pub hidden: bool,
    pub ti: Option<String>,
    /// Real name behind an alias (e.g. SystemFunction001 → RtlEncryptDES1block1key).
    pub map: Option<String>,
    pub hint: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct LibraryDef {
    pub name: String,
    pub flag: bool,
    pub group: Option<u8>,
    pub description: String,
    pub functions: Vec<FunctionDef>,
}

#[derive(Debug, Clone, Default)]
pub struct Functions {
    pub libs: Vec<LibraryDef>,
    lib_index: HashMap<String, usize>,
    /// lower(lib) → lower(fct) → (lib idx, fct idx)
    fct_index: HashMap<String, HashMap<String, usize>>,
    /// lower(fct) → first (lib idx, fct idx)
    global: HashMap<String, (usize, usize)>,
    /// lower(lib) → ordinal → fct idx
    ordinals: HashMap<String, HashMap<u16, usize>>,
}

fn group_attr(e: &Element) -> Option<u8> {
    opt_u8(e, "gp").or_else(|| opt_u8(e, "group"))
}

impl Functions {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut f = Functions::default();
        let Some(libs) = x.child("libs") else { return f };
        for l in libs.children_named("lib") {
            let mut lib = LibraryDef {
                name: l.attr_or("name", "").to_string(),
                flag: l.attr_bool("flag"),
                group: group_attr(l),
                description: l.attr_or("desc", "").to_string(),
                functions: Vec::new(),
            };
            for fc in l.children_named("fcts").flat_map(|x| x.children_named("fct")) {
                lib.functions.push(FunctionDef {
                    name: fc.text_trim().trim_end_matches('>').to_string(),
                    group: group_attr(fc),
                    ordinal: fc.attr_int("od").and_then(|v| u16::try_from(v).ok()),
                    flag: fc.attr_bool("flag"),
                    callback: fc.attr_bool("cb"),
                    undocumented: fc.attr_bool("un"),
                    deprecated: fc.attr_bool("cd"),
                    anti_debug: fc.attr_bool("ad"),
                    hidden: fc.attr_bool("hide"),
                    ti: ti(fc),
                    map: opt_str(fc.attr("map")),
                    hint: opt_u8(fc, "hint"),
                });
            }
            f.libs.push(lib);
        }
        f.reindex();
        f
    }

    pub fn reindex(&mut self) {
        self.lib_index.clear();
        self.fct_index.clear();
        self.global.clear();
        self.ordinals.clear();
        for (li, l) in self.libs.iter().enumerate() {
            let ln = l.name.to_ascii_lowercase();
            self.lib_index.entry(ln.clone()).or_insert(li);
            let m = self.fct_index.entry(ln.clone()).or_default();
            for (fi, fc) in l.functions.iter().enumerate() {
                let n = fc.name.to_ascii_lowercase();
                m.entry(n.clone()).or_insert(fi);
                self.global.entry(n).or_insert((li, fi));
                if let Some(o) = fc.ordinal {
                    self.ordinals.entry(ln.clone()).or_default().entry(o).or_insert(fi);
                }
            }
        }
    }

    pub fn library(&self, name: &str) -> Option<&LibraryDef> {
        self.lib_index.get(&name.to_ascii_lowercase()).map(|&i| &self.libs[i])
    }

    /// Function lookup: library-specific first, then any library (pestudio's empty-name lib holds generic entries).
    pub fn function(&self, lib: &str, name: &str) -> Option<&FunctionDef> {
        let ln = lib.to_ascii_lowercase();
        let n = name.to_ascii_lowercase();
        if let (Some(&li), Some(&fi)) = (self.lib_index.get(&ln), self.fct_index.get(&ln).and_then(|m| m.get(&n))) {
            return Some(&self.libs[li].functions[fi]);
        }
        // Strip A/W suffixes and decorations for a second chance.
        self.global.get(&n).map(|&(li, fi)| &self.libs[li].functions[fi]).or_else(|| {
            let base = n.trim_start_matches('_');
            let base = base.split('@').next().unwrap_or(base);
            let base = base.strip_suffix('a').or_else(|| base.strip_suffix('w')).unwrap_or(base);
            if base.len() < 2 {
                return None;
            }
            self.global.get(base).map(|&(li, fi)| &self.libs[li].functions[fi])
        })
    }

    pub fn function_by_ordinal(&self, lib: &str, ordinal: u16) -> Option<&FunctionDef> {
        let ln = lib.to_ascii_lowercase();
        let li = *self.lib_index.get(&ln)?;
        let fi = *self.ordinals.get(&ln)?.get(&ordinal)?;
        Some(&self.libs[li].functions[fi])
    }

    pub fn function_count(&self) -> usize {
        self.libs.iter().map(|l| l.functions.len()).sum()
    }

    pub fn set_library_flag(&mut self, lib: &str, flag: bool) -> bool {
        match self.lib_index.get(&lib.to_ascii_lowercase()) {
            Some(&i) => {
                self.libs[i].flag = flag;
                true
            }
            None => false,
        }
    }

    pub fn set_function_flag(&mut self, lib: &str, name: &str, flag: bool) -> bool {
        let ln = lib.to_ascii_lowercase();
        let n = name.to_ascii_lowercase();
        if let (Some(&li), Some(&fi)) = (self.lib_index.get(&ln), self.fct_index.get(&ln).and_then(|m| m.get(&n))) {
            self.libs[li].functions[fi].flag = flag;
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------- strings.xml

#[derive(Debug, Clone, Default)]
pub struct StringDef {
    pub value: String,
    pub name: Option<String>,
    pub flag: bool,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub hint: Option<u8>,
    pub sig: Option<u32>,
    /// Blacklisted (legacy `bl`/`fl` attributes).
    pub blacklist: bool,
}

#[derive(Debug, Clone, Default)]
pub struct StringCategory {
    pub name: String,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub hint: Option<u8>,
    pub items: Vec<StringDef>,
}

#[derive(Debug, Clone)]
pub struct StringsDb {
    pub minimum_size: usize,
    pub case_sensitive: bool,
    pub substring: bool,
    /// sids, privs, agents, exts, regs, folders, offices, utils, stubs, strings
    pub categories: Vec<StringCategory>,
}

impl Default for StringsDb {
    fn default() -> Self {
        Self { minimum_size: 4, case_sensitive: false, substring: false, categories: Vec::new() }
    }
}

impl StringsDb {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut s = StringsDb::default();
        if let Some(st) = x.path("settings/setting") {
            if let Some(v) = st.child("minimum-size").and_then(|e| parse_int(e.text_trim())) {
                s.minimum_size = v.max(1) as usize;
            }
            s.case_sensitive = st.child("case-sensitive").and_then(|e| parse_int(e.text_trim())).unwrap_or(0) != 0;
            s.substring = st.child("substring").and_then(|e| parse_int(e.text_trim())).unwrap_or(0) != 0;
        }
        for cat in &x.children {
            if cat.name == "settings" {
                continue;
            }
            let mut c = StringCategory {
                name: cat.name.clone(),
                group: group_attr(cat),
                ti: ti(cat),
                hint: opt_u8(cat, "hint"),
                items: Vec::new(),
            };
            for it in &cat.children {
                let value = it.text.trim().to_string();
                if value.is_empty() {
                    continue;
                }
                c.items.push(StringDef {
                    value,
                    name: opt_str(it.attr("name")),
                    flag: it.attr_bool("flag"),
                    group: group_attr(it).or(c.group),
                    ti: ti(it).or_else(|| c.ti.clone()),
                    hint: opt_u8(it, "hint").or(c.hint),
                    sig: it.attr_int("sig").map(|v| v as u32),
                    blacklist: it.attr_bool("bl") || it.attr_bool("fl"),
                });
            }
            s.categories.push(c);
        }
        s
    }

    pub fn category(&self, name: &str) -> Option<&StringCategory> {
        self.categories.iter().find(|c| c.name == name)
    }

    pub fn items(&self, name: &str) -> &[StringDef] {
        self.category(name).map(|c| c.items.as_slice()).unwrap_or(&[])
    }
}

// ---------------------------------------------------------------- signatures.xml

/// One byte of a pattern with nibble-level wildcards (`xx`, `0x`, `x3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternByte {
    pub value: u8,
    pub mask: u8,
}

impl PatternByte {
    pub fn matches(&self, b: u8) -> bool {
        b & self.mask == self.value & self.mask
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternKind {
    Bytes(Vec<PatternByte>),
    /// Literal text searched in section names and in the file content.
    Text(String),
}

impl Default for PatternKind {
    fn default() -> Self {
        PatternKind::Bytes(Vec::new())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Pattern {
    /// Match at the entry point (true) or at the start of the data / anywhere for text (false).
    pub ep: bool,
    pub kind: PatternKind,
}

fn parse_token(tok: &str) -> Option<PatternByte> {
    let t = tok.as_bytes();
    if t.len() == 1 {
        // A single hex digit (truncated pattern) is a high-nibble match.
        let v = (t[0] as char).to_digit(16)? as u8;
        return Some(PatternByte { value: v << 4, mask: 0xf0 });
    }
    if t.len() != 2 {
        return None;
    }
    let nib = |c: u8| -> Option<(u8, u8)> {
        match c {
            b'x' | b'X' | b'?' => Some((0, 0)),
            _ => (c as char).to_digit(16).map(|v| (v as u8, 0xf)),
        }
    };
    let (hv, hm) = nib(t[0])?;
    let (lv, lm) = nib(t[1])?;
    Some(PatternByte { value: (hv << 4) | lv, mask: (hm << 4) | lm })
}

impl Pattern {
    pub fn parse(src: &str, ep: bool) -> Option<Self> {
        let src = src.trim();
        if src.is_empty() {
            return None;
        }
        let toks: Option<Vec<PatternByte>> = src.split_whitespace().map(parse_token).collect();
        match toks {
            Some(b) => Some(Pattern { ep, kind: PatternKind::Bytes(b) }),
            None => Some(Pattern { ep, kind: PatternKind::Text(src.to_string()) }),
        }
    }

    pub fn len(&self) -> usize {
        match &self.kind {
            PatternKind::Bytes(b) => b.len(),
            PatternKind::Text(t) => t.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Anchored match at the start of `data` (byte patterns only).
    pub fn matches(&self, data: &[u8]) -> bool {
        match &self.kind {
            PatternKind::Bytes(b) => data.len() >= b.len() && b.iter().zip(data).all(|(p, d)| p.matches(*d)),
            PatternKind::Text(t) => data.starts_with(t.as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SignatureDef {
    pub name: String,
    pub more: String,
    pub flag: bool,
    /// Embedded-file signature (archive, document, …).
    pub file: bool,
    /// Packer/compiler/installer tooling.
    pub tool: bool,
    pub severity: u8,
    pub url: String,
    pub id: Option<u32>,
    pub patterns: Vec<Pattern>,
}

pub fn load_signatures(doc: &Element) -> Vec<SignatureDef> {
    let x = payload(doc);
    let Some(list) = x.child("sigs") else { return Vec::new() };
    list.children_named("sig")
        .map(|e| SignatureDef {
            name: e.attr_or("name", "").to_string(),
            more: e.attr_or("more", "").to_string(),
            flag: e.attr_bool("flag"),
            file: e.attr_bool("file"),
            tool: e.attr_bool("tool"),
            severity: opt_u8(e, "severity").unwrap_or(2),
            url: e.attr_or("url", "").to_string(),
            id: e.attr_int("id").map(|v| v as u32),
            patterns: e.children_named("pattern").filter_map(|p| Pattern::parse(p.text_trim(), p.attr_bool("ep"))).collect(),
        })
        .collect()
}

// ---------------------------------------------------------------- mitre.xml

#[derive(Debug, Clone, Default)]
pub struct Tactic {
    pub id: String,
    pub description: String,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Technique {
    pub id: String,
    pub tactic: String,
    pub flag: bool,
    pub level: u8,
    pub enable: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Mitre {
    pub url: String,
    pub tactics_url: String,
    pub techniques_url: String,
    pub tactics: Vec<Tactic>,
    pub techniques: Vec<Technique>,
}

impl Mitre {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut m = Mitre::default();
        let Some(root) = x.child("mitre") else { return m };
        m.url = root.attr_or("url", "https://attack.mitre.org").to_string();
        if let Some(t) = root.child("tactics") {
            m.tactics_url = t.attr_or("url", "tactics").to_string();
            m.tactics = t
                .children_named("ta")
                .map(|e| Tactic {
                    id: e.attr_or("id", "").to_string(),
                    description: e.attr_or("de", "").to_string(),
                    name: e.text_trim().to_string(),
                })
                .collect();
        }
        if let Some(t) = root.child("techniques") {
            m.techniques_url = t.attr_or("url", "techniques").to_string();
            m.techniques = t
                .children_named("ti")
                .map(|e| Technique {
                    id: e.attr_or("id", "").to_string(),
                    tactic: e.attr_or("ta", "").to_string(),
                    flag: e.attr_bool("flag"),
                    level: opt_u8(e, "level").unwrap_or(2),
                    enable: e.attr("enable").map(|v| v != "0").unwrap_or(true),
                    name: e.text_trim().to_string(),
                })
                .collect();
        }
        m
    }

    pub fn technique(&self, id: &str) -> Option<&Technique> {
        let id = id.trim_start_matches(['T', 't']);
        self.techniques.iter().find(|t| t.id == id)
    }

    pub fn tactic(&self, id: &str) -> Option<&Tactic> {
        let id = id.trim_start_matches(['T', 'A', 't', 'a']);
        self.tactics.iter().find(|t| t.id == id)
    }

    pub fn technique_url(&self, id: &str) -> String {
        format!("{}/{}/T{}", self.url.trim_end_matches('/'), self.techniques_url, id.trim_start_matches('T'))
    }

    pub fn tactic_url(&self, id: &str) -> String {
        format!("{}/{}/TA{}", self.url.trim_end_matches('/'), self.tactics_url, id.trim_start_matches(['T', 'A']))
    }
}

// ---------------------------------------------------------------- namespaces.xml

#[derive(Debug, Clone, Default)]
pub struct NamespaceDef {
    pub name: String,
    pub flag: bool,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub sig: Option<u32>,
    pub system: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Namespaces {
    pub system_enabled: bool,
    pub custom_enabled: bool,
    pub items: Vec<NamespaceDef>,
    index: HashMap<String, usize>,
}

impl Namespaces {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut n = Namespaces::default();
        let Some(root) = x.child("nsp") else { return n };
        for (tag, system) in [("nsp_system", true), ("nsp_custom", false)] {
            if let Some(list) = root.child(tag) {
                let en = list.attr("enable").map(|v| v != "0").unwrap_or(true);
                if system {
                    n.system_enabled = en;
                } else {
                    n.custom_enabled = en;
                }
                for e in list.children_named("item") {
                    n.items.push(NamespaceDef {
                        name: e.text_trim().to_string(),
                        flag: e.attr_bool("flag"),
                        group: group_attr(e),
                        ti: ti(e),
                        sig: e.attr_int("sig").map(|v| v as u32),
                        system,
                    });
                }
            }
        }
        n.reindex();
        n
    }

    pub fn reindex(&mut self) {
        self.index.clear();
        for (i, d) in self.items.iter().enumerate() {
            self.index.entry(d.name.clone()).or_insert(i);
        }
    }

    /// Longest namespace prefix matching `ns` (dot-separated boundary).
    pub fn lookup(&self, ns: &str) -> Option<&NamespaceDef> {
        let enabled = |d: &NamespaceDef| (d.system && self.system_enabled) || (!d.system && self.custom_enabled);
        let mut cand = ns;
        loop {
            if let Some(d) = self.index.get(cand).map(|&i| &self.items[i]).filter(|d| enabled(d)) {
                return Some(d);
            }
            {
                let p = cand.rfind('.')?;
                cand = &cand[..p]
            }
        }
    }
}

// ---------------------------------------------------------------- rich.xml

#[derive(Debug, Clone, Default)]
pub struct RichDb {
    pub prod_ids: HashMap<u16, String>,
    pub ides: HashMap<u8, String>,
    /// build number → (ide id, version label)
    pub builds: HashMap<u16, (u8, String)>,
}

impl RichDb {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut r = RichDb::default();
        let Some(root) = x.child("richheader") else { return r };
        if let Some(p) = root.child("prodId") {
            for e in p.children_named("item") {
                if let Some(id) = e.attr_int("id") {
                    r.prod_ids.insert(id as u16, e.text_trim().to_string());
                }
            }
        }
        if let Some(p) = root.child("ide") {
            for e in p.children_named("item") {
                if let Some(id) = e.attr_int("id") {
                    r.ides.insert(id as u8, e.text_trim().to_string());
                }
            }
        }
        if let Some(p) = root.child("version") {
            for e in p.children_named("item") {
                // build values are written with leading zeros ("04407"): decimal.
                if let Some(v) = e.attr("value").and_then(|s| s.trim().parse::<u32>().ok()) {
                    let ide = e.attr_int("ide").unwrap_or(23) as u8;
                    r.builds.insert(v as u16, (ide, e.text_trim().to_string()));
                }
            }
        }
        r
    }

    pub fn product(&self, id: u16) -> Option<&str> {
        self.prod_ids.get(&id).map(String::as_str)
    }

    /// "Visual Studio 2019 (16.x)" style label for a build number.
    pub fn tooling(&self, build: u16) -> Option<String> {
        let (ide, label) = self.builds.get(&build)?;
        let ide_name = self.ides.get(ide).cloned().unwrap_or_else(|| "Visual Studio".into());
        Some(if label.is_empty() { ide_name } else { format!("{ide_name} ({label})") })
    }
}

// ---------------------------------------------------------------- languages.xml

#[derive(Debug, Clone, Default)]
pub struct Languages {
    pub langs: Vec<(u16, bool, String)>,
    pub code_pages: HashMap<u32, String>,
}

impl Languages {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut l = Languages::default();
        if let Some(list) = x.child("langs") {
            for e in list.children_named("lang") {
                if let Some(id) = e.attr_int("id") {
                    l.langs.push((id as u16, e.attr_bool("flag"), e.text_trim().to_string()));
                }
            }
        }
        if let Some(list) = x.child("cps") {
            for e in list.children_named("cp") {
                if let Some(id) = e.attr("id").and_then(|s| s.trim().parse::<u32>().ok()) {
                    l.code_pages.insert(id, e.text_trim().to_string());
                }
            }
        }
        l
    }

    pub fn language(&self, id: u16) -> Option<(&str, bool)> {
        self.langs.iter().find(|(i, _, _)| *i == id).map(|(_, f, n)| (n.as_str(), *f))
    }

    pub fn set_flag(&mut self, id: u16, flag: bool) -> bool {
        match self.langs.iter_mut().find(|(i, _, _)| *i == id) {
            Some(l) => {
                l.1 = flag;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------- translations.xml

#[derive(Debug, Clone, Default)]
pub struct GroupDef {
    pub id: u8,
    pub rgb: (u8, u8, u8),
    pub level: u8,
    pub enable: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceTypeDef {
    pub id: u8,
    pub severity: u8,
    pub builtin: bool,
    pub file: bool,
    pub indicator: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct HintDef {
    pub id: i32,
    pub indicate: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Translations {
    pub text: HashMap<u32, String>,
    pub tooltips: HashMap<u32, String>,
    pub groups_enabled: bool,
    pub groups: Vec<GroupDef>,
    pub resources: Vec<ResourceTypeDef>,
    pub hints: Vec<HintDef>,
    pub locations: Vec<(String, (u8, u8, u8))>,
    /// Any other list section (machines, subsystems, debuggers, …): section → items (id attr or index, text)
    pub lists: HashMap<String, Vec<(String, String)>>,
}

fn rgb(e: &Element) -> (u8, u8, u8) {
    let g = |k: &str| e.attr_int(k).unwrap_or(0).clamp(0, 255) as u8;
    (g("r"), g("g"), g("b"))
}

impl Translations {
    pub fn from_dom(doc: &Element) -> Self {
        let x = payload(doc);
        let mut t = Translations::default();
        for sec in &x.children {
            match sec.name.as_str() {
                "text" => {
                    for e in sec.children_named("item") {
                        if let Some(id) = e.attr_int("id") {
                            t.text.insert(id as u32, e.text.clone());
                        }
                    }
                }
                "tooltips" => {
                    for e in sec.children_named("item") {
                        if let Some(id) = e.attr_int("id") {
                            t.tooltips.insert(id as u32, e.text_trim().to_string());
                        }
                    }
                }
                "groups" => {
                    t.groups_enabled = sec.attr_bool("enable");
                    t.groups = sec
                        .children_named("item")
                        .map(|e| GroupDef {
                            id: e.attr_int("id").unwrap_or(0) as u8,
                            rgb: rgb(e),
                            level: opt_u8(e, "level").unwrap_or(1),
                            enable: e.attr("enable").map(|v| v != "0").unwrap_or(true),
                            name: e.text_trim().to_string(),
                        })
                        .collect();
                }
                "resources" => {
                    t.resources = sec
                        .children_named("item")
                        .map(|e| ResourceTypeDef {
                            id: e.attr_int("id").unwrap_or(0) as u8,
                            severity: opt_u8(e, "severity").unwrap_or(4),
                            builtin: e.attr_bool("builtin"),
                            file: e.attr_bool("file"),
                            indicator: e.attr_bool("indicator"),
                            name: e.text_trim().to_string(),
                        })
                        .collect();
                }
                "hints" => {
                    t.hints = sec
                        .children_named("item")
                        .map(|e| HintDef {
                            id: e.attr_int("id").unwrap_or(-1) as i32,
                            indicate: e.attr_bool("indicate"),
                            name: e.text_trim().to_string(),
                        })
                        .collect();
                }
                "locations" => {
                    t.locations = sec.children_named("item").map(|e| (e.text_trim().to_string(), rgb(e))).collect();
                }
                "version" => {
                    for sub in &sec.children {
                        t.lists.insert(
                            format!("version/{}", sub.name),
                            sub.children.iter().map(|e| (e.attr_or("name", "").to_string(), e.text_trim().to_string())).collect(),
                        );
                    }
                }
                _ => {
                    let items: Vec<(String, String)> = sec
                        .children
                        .iter()
                        .enumerate()
                        .map(|(i, e)| (e.attr("id").map(str::to_string).unwrap_or_else(|| i.to_string()), e.text_trim().to_string()))
                        .collect();
                    t.lists.insert(sec.name.clone(), items);
                }
            }
        }
        t
    }

    pub fn tr(&self, id: u32) -> &str {
        self.text.get(&id).map(String::as_str).unwrap_or("")
    }

    pub fn group(&self, id: u8) -> Option<&GroupDef> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn hint(&self, id: u8) -> Option<&HintDef> {
        self.hints.iter().find(|h| h.id == id as i32)
    }

    pub fn list(&self, name: &str) -> &[(String, String)] {
        self.lists.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn severity_name(&self, s: u8) -> String {
        self.list("severities").iter().find(|(k, _)| k == &s.to_string()).map(|(_, v)| v.clone()).unwrap_or_else(|| match s {
            1 => "high".into(),
            2 => "medium".into(),
            3 => "low".into(),
            4 => "info".into(),
            6 => "none".into(),
            _ => "unknown".into(),
        })
    }
}
