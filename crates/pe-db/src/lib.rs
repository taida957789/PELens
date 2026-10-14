//! Loader for the pestudio XML knowledge base (settings, indicators, thresholds,
//! functions, strings, signatures, MITRE, namespaces, rich, languages, translations).
//!
//! The XML files are **not** bundled with this project. They are read at runtime from a
//! directory chosen by the user (their own pestudio installation). When a file is missing
//! the corresponding knowledge is empty and built-in defaults are used where needed.

pub mod dom;
pub mod edit;
pub mod model;

pub use model::*;
use std::path::{Path, PathBuf};

/// Logical knowledge files and their default file names (`settings.xml <files>` may override).
pub const FILES: [(&str, &str); 10] = [
    ("fthresholds", "thresholds.xml"),
    ("findicators", "indicators.xml"),
    ("fstrings", "strings.xml"),
    ("ffunctions", "functions.xml"),
    ("flanguages", "languages.xml"),
    ("ftranslations", "translations.xml"),
    ("fsignatures", "signatures.xml"),
    ("frich", "rich.xml"),
    ("fmitre", "mitre.xml"),
    ("fnsp", "namespaces.xml"),
];

#[derive(Debug, Clone, Default)]
pub struct Knowledge {
    pub dir: Option<PathBuf>,
    pub settings: Settings,
    pub indicators: Vec<IndicatorDef>,
    pub thresholds: Vec<Threshold>,
    pub functions: Functions,
    pub strings: StringsDb,
    pub signatures: Vec<SignatureDef>,
    pub mitre: Mitre,
    pub namespaces: Namespaces,
    pub rich: RichDb,
    pub languages: Languages,
    pub translations: Translations,
    /// Files that could not be read or parsed: (file, reason).
    pub errors: Vec<(String, String)>,
    /// Files successfully loaded.
    pub loaded: Vec<String>,
}

#[derive(Debug)]
pub enum DbError {
    Io(std::io::Error),
    Xml(dom::ParseError),
    NotFound(String),
    NoDirectory,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Io(e) => write!(f, "{e}"),
            DbError::Xml(e) => write!(f, "{e}"),
            DbError::NotFound(s) => write!(f, "element not found: {s}"),
            DbError::NoDirectory => write!(f, "no knowledge directory configured"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        DbError::Io(e)
    }
}

/// The PELens open knowledge base (`kb/`, CC0), compiled into the program. It is used when no
/// pestudio XML directory is given. Built by `tools/build_kb.py` from `kb/src`, stored deflated
/// (see build.rs) and inflated on first use.
pub mod open_kb {
    use std::sync::OnceLock;

    macro_rules! packed {
        ($($name:literal),*) => {
            [$(($name, include_bytes!(concat!(env!("OUT_DIR"), "/kb/", $name, ".deflate")) as &[u8])),*]
        };
    }

    const PACKED: [(&str, &[u8]); 11] = packed!(
        "settings.xml",
        "thresholds.xml",
        "indicators.xml",
        "strings.xml",
        "functions.xml",
        "languages.xml",
        "translations.xml",
        "signatures.xml",
        "rich.xml",
        "mitre.xml",
        "namespaces.xml"
    );

    /// (file name, XML text) of every file of the open knowledge base.
    pub fn files() -> &'static [(&'static str, String)] {
        static FILES: OnceLock<Vec<(&'static str, String)>> = OnceLock::new();
        FILES.get_or_init(|| {
            PACKED
                .iter()
                .map(|(name, packed)| {
                    let xml = miniz_oxide::inflate::decompress_to_vec(packed).expect("open knowledge base (build.rs output)");
                    (*name, String::from_utf8(xml).expect("UTF-8 knowledge base"))
                })
                .collect()
        })
    }

    pub fn file(name: &str) -> Option<&'static str> {
        files().iter().find(|(n, _)| *n == name).map(|(_, c)| c.as_str())
    }
}

impl Knowledge {
    /// The open knowledge base shipped with PELens (no directory: settings are kept in memory).
    pub fn builtin() -> Self {
        Self::load_with(None, |name| match open_kb::file(name) {
            Some(src) => dom::parse(src).map_err(DbError::Xml),
            None => Err(DbError::NotFound(name.to_string())),
        })
    }

    /// The knowledge base of a directory (pestudio's XML files or a copy of `kb/`).
    pub fn load(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let d = dir.clone();
        Self::load_with(Some(dir), move |name| read_dom(&d.join(name)))
    }

    fn load_with(dir: Option<PathBuf>, read: impl Fn(&str) -> Result<dom::Element, DbError>) -> Self {
        let mut k = Knowledge { dir, ..Default::default() };
        match read("settings.xml") {
            Ok(d) => {
                k.settings = Settings::from_dom(&d);
                k.loaded.push("settings.xml".into());
            }
            Err(e) => {
                k.errors.push(("settings.xml".into(), e.to_string()));
                k.settings = default_settings();
            }
        }
        for (key, def) in FILES {
            let name = k.settings.files.get(key).cloned().unwrap_or_else(|| def.to_string());
            let doc = match read(&name) {
                Ok(d) => d,
                Err(e) => {
                    k.errors.push((name, e.to_string()));
                    continue;
                }
            };
            match key {
                "fthresholds" => k.thresholds = load_thresholds(&doc),
                "findicators" => k.indicators = load_indicators(&doc),
                "fstrings" => k.strings = StringsDb::from_dom(&doc),
                "ffunctions" => k.functions = Functions::from_dom(&doc),
                "flanguages" => k.languages = Languages::from_dom(&doc),
                "ftranslations" => k.translations = Translations::from_dom(&doc),
                "fsignatures" => k.signatures = load_signatures(&doc),
                "frich" => k.rich = RichDb::from_dom(&doc),
                "fmitre" => k.mitre = Mitre::from_dom(&doc),
                _ => k.namespaces = Namespaces::from_dom(&doc),
            }
            k.loaded.push(name);
        }
        k
    }

    pub fn file_path(&self, key: &str) -> Option<PathBuf> {
        let dir = self.dir.as_ref()?;
        let def = FILES.iter().find(|(k, _)| *k == key).map(|(_, f)| *f).unwrap_or(key);
        let name = self.settings.files.get(key).cloned().unwrap_or_else(|| def.to_string());
        Some(dir.join(name))
    }

    pub fn indicator(&self, id: u32) -> Option<&IndicatorDef> {
        self.indicators.iter().find(|i| i.id == id)
    }

    pub fn threshold(&self, id: u32) -> Option<&Threshold> {
        self.thresholds.iter().find(|t| t.id == id && t.enable)
    }

    pub fn group_name(&self, id: u8) -> String {
        self.translations.group(id).map(|g| g.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| default_group_name(id).to_string())
    }

    // ------------------------------------------------------------ write-back

    fn patch_file(&self, key: &str, target: &edit::Target, attr: &str, value: &str) -> Result<(), DbError> {
        let path = if key == "settings" {
            self.dir.as_ref().ok_or(DbError::NoDirectory)?.join("settings.xml")
        } else {
            self.file_path(key).ok_or(DbError::NoDirectory)?
        };
        let src = std::fs::read_to_string(&path)?;
        let out = edit::set_attr(&src, target, attr, value).ok_or_else(|| DbError::NotFound(target.tag.to_string()))?;
        std::fs::write(&path, out)?;
        Ok(())
    }

    /// Change an indicator's severity (memory + indicators.xml).
    pub fn set_indicator_severity(&mut self, id: u32, severity: u8) -> Result<(), DbError> {
        let ids = id.to_string();
        self.patch_file(
            "findicators",
            &edit::Target { scope: None, tag: "item", key: edit::Key::Attr("id", &ids) },
            "severity",
            &severity.to_string(),
        )?;
        if let Some(i) = self.indicators.iter_mut().find(|i| i.id == id) {
            i.severity = severity;
        }
        Ok(())
    }

    pub fn set_indicator_enable(&mut self, id: u32, enable: u8) -> Result<(), DbError> {
        let ids = id.to_string();
        self.patch_file(
            "findicators",
            &edit::Target { scope: None, tag: "item", key: edit::Key::Attr("id", &ids) },
            "enable",
            &enable.to_string(),
        )?;
        if let Some(i) = self.indicators.iter_mut().find(|i| i.id == id) {
            i.enable = enable;
        }
        Ok(())
    }

    pub fn set_library_flag(&mut self, lib: &str, flag: bool) -> Result<(), DbError> {
        let name = self.functions.library(lib).map(|l| l.name.clone()).ok_or_else(|| DbError::NotFound(lib.into()))?;
        self.patch_file(
            "ffunctions",
            &edit::Target { scope: None, tag: "lib", key: edit::Key::Attr("name", &name) },
            "flag",
            if flag { "1" } else { "0" },
        )?;
        self.functions.set_library_flag(lib, flag);
        Ok(())
    }

    pub fn set_function_flag(&mut self, lib: &str, func: &str, flag: bool) -> Result<(), DbError> {
        let l = self.functions.library(lib).ok_or_else(|| DbError::NotFound(lib.into()))?;
        let lname = l.name.clone();
        let fname = l
            .functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(func))
            .map(|f| f.name.clone())
            .ok_or_else(|| DbError::NotFound(func.into()))?;
        self.patch_file(
            "ffunctions",
            &edit::Target { scope: Some(("lib", edit::Key::Attr("name", &lname))), tag: "fct", key: edit::Key::Text(&fname) },
            "flag",
            if flag { "1" } else { "0" },
        )?;
        self.functions.set_function_flag(lib, func, flag);
        Ok(())
    }

    pub fn set_language_flag(&mut self, lang: u16, flag: bool) -> Result<(), DbError> {
        // ids are written with mixed case hex (0x0C0C / 0x040c): find the literal spelling first.
        let path = self.file_path("flanguages").ok_or(DbError::NoDirectory)?;
        let src = std::fs::read_to_string(&path)?;
        let doc = dom::parse(&src).map_err(DbError::Xml)?;
        let spelled = dom::payload(&doc)
            .child("langs")
            .and_then(|l| l.children_named("lang").find(|e| e.attr_int("id") == Some(lang as i64)))
            .and_then(|e| e.attr("id").map(str::to_string))
            .ok_or_else(|| DbError::NotFound(format!("lang {lang:#06x}")))?;
        let out = edit::set_attr(
            &src,
            &edit::Target { scope: None, tag: "lang", key: edit::Key::Attr("id", &spelled) },
            "flag",
            if flag { "1" } else { "0" },
        )
        .ok_or_else(|| DbError::NotFound(spelled.clone()))?;
        std::fs::write(&path, out)?;
        self.languages.set_flag(lang, flag);
        Ok(())
    }

    pub fn set_signature_severity(&mut self, name: &str, severity: u8) -> Result<(), DbError> {
        self.patch_file(
            "fsignatures",
            &edit::Target { scope: None, tag: "sig", key: edit::Key::Attr("name", name) },
            "severity",
            &severity.to_string(),
        )?;
        for s in self.signatures.iter_mut().filter(|s| s.name == name) {
            s.severity = severity;
        }
        Ok(())
    }

    pub fn set_namespace_flag(&mut self, ns: &str, flag: bool) -> Result<(), DbError> {
        self.patch_file(
            "fnsp",
            &edit::Target { scope: None, tag: "item", key: edit::Key::Text(ns) },
            "flag",
            if flag { "1" } else { "0" },
        )?;
        for n in self.namespaces.items.iter_mut().filter(|n| n.name == ns) {
            n.flag = flag;
        }
        Ok(())
    }

    /// Persist one `<setting>` attribute to settings.xml.
    /// A missing `<elem>` is appended inside `<setting>` (e.g. the remake's own `<theme>`).
    pub fn save_setting(&mut self, elem: &str, attr: &str, value: &str) -> Result<(), DbError> {
        let target = edit::Target { scope: Some(("setting", edit::Key::First)), tag: elem, key: edit::Key::First };
        match self.patch_file("settings", &target, attr, value) {
            Err(DbError::NotFound(_)) => {
                let path = self.dir.as_ref().ok_or(DbError::NoDirectory)?.join("settings.xml");
                let src = std::fs::read_to_string(&path)?;
                let out = edit::insert_child(&src, "setting", elem, attr, value).ok_or_else(|| DbError::NotFound("setting".into()))?;
                std::fs::write(&path, out)?;
            }
            r => r?,
        }
        self.settings.set(elem, attr, value);
        Ok(())
    }
}

fn read_dom(path: &Path) -> Result<dom::Element, DbError> {
    let src = std::fs::read_to_string(path)?;
    dom::parse(&src).map_err(DbError::Xml)
}

pub fn default_group_name(id: u8) -> &'static str {
    const N: [&str; 33] = [
        "timer",
        "registry",
        "execution",
        "network",
        "crypto",
        "memory",
        "file",
        "synchro",
        "desktop",
        "services",
        "obfuscation",
        "resource",
        "windowing",
        "compression",
        "hooking",
        "sharing",
        "diagnostic",
        "administration",
        "exception",
        "reconnaissance",
        "console",
        "dynamic-library",
        "io",
        "Common-Object-Model (COM)",
        "desktop",
        "shell",
        "setup",
        "power",
        "",
        "directory-service",
        "security",
        "",
        "device",
    ];
    N.get(id as usize).copied().unwrap_or("")
}

/// Built-in `<setting>` defaults (used when settings.xml is unavailable).
pub fn default_settings() -> Settings {
    let mut s = Settings::default();
    let defaults: &[(&str, &[(&str, &str)])] = &[
        (
            "indicators",
            &[
                ("sort", "1"),
                ("flag", "1"),
                ("sec", "0"),
                ("label", "1"),
                ("level", "1"),
                ("jump", "1"),
                ("rich", "0"),
                ("separator", "|"),
                ("bytes", "32"),
            ],
        ),
        ("score", &[("enable", "0"), ("flag", "0"), ("all", "1"), ("key", "")]),
        (
            "footprints",
            &[
                ("enable", "1"),
                ("type", "2"),
                ("dos-stub", "1"),
                ("dos-header", "1"),
                ("debug", "1"),
                ("version", "1"),
                ("manifest", "1"),
                ("st", "0"),
                ("menu", "0"),
                ("dlg", "0"),
                ("icon", "0"),
                ("cur", "0"),
                ("bmp", "0"),
                ("rich", "1"),
                ("acl", "0"),
            ],
        ),
        ("groups", &[("enable", "1"), ("color", "1")]),
        ("mitre", &[("enable", "1"), ("ti", "1"), ("ta", "0"), ("dup", "0")]),
        ("rich", &[("fn", "1"), ("count", "0")]),
        ("directories", &[("invalid", "1"), ("missing", "1"), ("empty", "1")]),
        (
            "sections",
            &[
                ("characteristics", "1"),
                ("items", "1"),
                ("initial", "0"),
                ("uninitial", "0"),
                ("cache", "0"),
                ("page", "0"),
                ("read", "0"),
                ("jmp", "16"),
            ],
        ),
        ("libraries", &[("type", "1"), ("gp", "1"), ("dup", "0"), ("flag", "1"), ("bound", "0"), ("tip", "01")]),
        ("imports", &[("gp", "1"), ("type", "1"), ("flag", "1"), ("od", "1"), ("nsp", "1"), ("ft", "1"), ("fto", "1")]),
        (
            "exports",
            &[("gap", "1"), ("od", "1"), ("dup", "1"), ("decorate", "1"), ("flag", "1"), ("anonymous", "1"), ("loc", "1"), ("ep", "1")],
        ),
        (
            "resources",
            &[
                ("sort", "1"),
                ("sig", "1"),
                ("type", "1"),
                ("loc", "1"),
                ("flag", "1"),
                ("hash", "1"),
                ("ent", "1"),
                ("ratio", "1"),
                ("lang", "1"),
                ("size", "1"),
                ("hex", "1"),
                ("txt", "1"),
            ],
        ),
        (
            "strings",
            &[
                ("flag", "1"),
                ("offset", "1"),
                ("label", "1"),
                ("gp", "1"),
                ("utf8", "1"),
                ("utf16", "1"),
                ("sort", "0"),
                ("wl", "1"),
                ("type", "3"),
            ],
        ),
        ("exceptions", &[("enable", "1")]),
        ("relocations", &[("enable", "1")]),
        ("dotnet", &[("header", "1"), ("tables", "1"), ("streams", "1")]),
        ("namespaces", &[("flag", "1")]),
        ("overlay", &[("flag", "1"), ("score", "0")]),
        ("report", &[("enable", "1"), ("type", "0")]),
        ("google", &[("enable", "1")]),
        ("caption", &[("enable", "1")]),
        ("read-only", &[("enable", "1")]),
        ("thresholds", &[("enable", "1")]),
        ("tooltips", &[("enable", "1")]),
        ("stamps", &[("epoch", "0")]),
        ("yara", &[("enable", "1"), ("dir", "")]),
    ];
    for (e, attrs) in defaults {
        s.setting.push((e.to_string(), attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()));
    }
    s
}
