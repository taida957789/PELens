//! `pelens-cli` – command line front-end (pestudiox-compatible syntax).
//!
//! ```text
//! pelens-cli -file:input [-report:output] [-banner]
//!           [-xml:knowledge-dir] [-format:xml|json|text] [-vt] [-stdout] [-yara:rules-dir]
//! ```

use pe_analysis::report::{self, Format};
use pe_db::Knowledge;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DISCLAIMER: &str = "This software is provided 'as-is', without any expressed or implied warranty.\n\
In no event will the author be held liable for any damage arising from the use of this software.\n\
When retrieving the online score of a file, the file itself is not submitted, only its hash is sent.";

pub const USAGE: &str = "pelens-cli -file:input [-report:output] [-banner] [-xml:dir] [-format:xml|json|text] [-vt] [-stdout] [-yara:dir]\n\n\
-file:     input file to analyse\n\
-report:   report file (default: the name of the input file appended with the report extension)\n\
-banner:   hide the banner\n\
-xml:      directory holding the pestudio XML knowledge files (default: the built-in open knowledge base)\n\
-format:   report format (xml, json or text)\n\
-vt:       query the Virustotal score (hash only)\n\
-stdout:   write the report to the standard output\n\
-yara:     folder of YARA rules (.yar, .yara) to match (default: settings <yara dir>)";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Args {
    pub file: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub hide_banner: bool,
    pub xml_dir: Option<PathBuf>,
    pub format: Option<Format>,
    pub vt: bool,
    pub stdout: bool,
    pub help: bool,
    pub yara_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArgError {
    Unknown(String),
    BadFormat(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgError::Unknown(a) => write!(f, "unknown argument: {a}"),
            ArgError::BadFormat(a) => write!(f, "unknown report format: {a}"),
        }
    }
}

/// Parse pestudio style arguments: `-name:value`, `/name:value` or `--name=value`.
pub fn parse_args(args: &[String]) -> Result<Args, ArgError> {
    let mut a = Args::default();
    for raw in args {
        let body = raw.trim_start_matches("--").trim_start_matches(['-', '/']);
        let (name, value) = match body.find([':', '=']) {
            // keep drive letters ("C:\...") intact: split only at the first separator after the name
            Some(p) => (&body[..p], Some(&body[p + 1..])),
            None => (body, None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("file", Some(v)) if !v.is_empty() => a.file = Some(PathBuf::from(v)),
            ("report", Some(v)) if !v.is_empty() => a.report = Some(PathBuf::from(v)),
            ("banner", _) => a.hide_banner = true,
            ("xml", Some(v)) if !v.is_empty() => a.xml_dir = Some(PathBuf::from(v)),
            ("format", Some(v)) => {
                a.format = Some(match v.to_ascii_lowercase().as_str() {
                    "xml" => Format::Xml,
                    "json" => Format::Json,
                    "text" | "txt" => Format::Text,
                    _ => return Err(ArgError::BadFormat(v.to_string())),
                })
            }
            ("vt", _) => a.vt = true,
            ("yara", Some(v)) if !v.is_empty() => a.yara_dir = Some(PathBuf::from(v)),
            ("stdout", _) => a.stdout = true,
            ("help" | "?" | "h", _) => a.help = true,
            _ => return Err(ArgError::Unknown(raw.clone())),
        }
    }
    Ok(a)
}

/// Environment hooks (filesystem location of the executable, network client) for testability.
pub trait Env {
    fn exe_dir(&self) -> Option<PathBuf>;
    fn http(&self, k: &Knowledge) -> Box<dyn pe_online::HttpClient>;
    /// Where the VirusTotal key is kept (the Windows Credential Manager).
    fn key_store(&self) -> Box<dyn pe_online::secret::KeyStore>;
}

pub struct RealEnv;

impl Env for RealEnv {
    fn exe_dir(&self) -> Option<PathBuf> {
        std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
    }

    fn http(&self, k: &Knowledge) -> Box<dyn pe_online::HttpClient> {
        Box::new(pe_online::UreqClient::new(&pe_online::net_config(k)))
    }

    fn key_store(&self) -> Box<dyn pe_online::secret::KeyStore> {
        Box::new(pe_online::secret::CredentialStore::vt())
    }
}

/// Locate the knowledge directory: explicit, next to the executable, ./xml, ../xml.
pub fn find_xml_dir(explicit: Option<&Path>, exe_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let mut cands = Vec::new();
    if let Some(d) = exe_dir {
        cands.push(d.join("xml"));
    }
    cands.push(PathBuf::from("xml"));
    cands.push(PathBuf::from("../xml"));
    cands.into_iter().find(|c| c.join("settings.xml").exists())
}

pub fn banner() -> String {
    format!("pelens-cli {} | Malware Initial Assessment (pestudio-compatible)\n{DISCLAIMER}\n", env!("CARGO_PKG_VERSION"))
}

pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write, env: &dyn Env) -> i32 {
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(err, "{e}\n\n{USAGE}");
            return 2;
        }
    };
    if !a.hide_banner {
        // With -stdout the report is the only thing on stdout (pipe-friendly): banner → stderr.
        let sink: &mut dyn Write = if a.stdout { &mut *err } else { &mut *out };
        let _ = writeln!(sink, "{}", banner());
    }
    if a.help {
        let _ = writeln!(out, "{USAGE}");
        return 0;
    }
    let Some(file) = a.file.clone() else {
        let _ = writeln!(err, "missing -file:\n\n{USAGE}");
        return 2;
    };
    let mut k = match find_xml_dir(a.xml_dir.as_deref(), env.exe_dir().as_deref()) {
        Some(d) => Knowledge::load(d),
        None => Knowledge::builtin(),
    };
    for (f, e) in &k.errors {
        let _ = writeln!(err, "[!] {f}: {e}");
    }
    let store = env.key_store();
    match pe_online::secret::migrate_plaintext_key(&mut k, store.as_ref()) {
        Ok(true) => {
            let _ = writeln!(err, "[+] the Virustotal key was moved from settings.xml to the Windows Credential Manager");
        }
        Ok(false) => {}
        Err(e) => {
            let _ = writeln!(err, "[!] the Virustotal key stays in settings.xml ({e})");
        }
    }
    let mut opts = pe_analysis::Options::from_settings(&k);
    // -yara:<dir> wins over the settings; the setting is used when YARA is enabled
    let from_settings = k.settings.get("yara", "dir").filter(|d| !d.trim().is_empty() && k.settings.get_bool("yara", "enable", true));
    if let Some(dir) = a.yara_dir.clone().or(from_settings.map(PathBuf::from)) {
        let (rules, errors) = pe_analysis::yara::compile_dir(&dir);
        for e in &errors {
            let _ = writeln!(err, "[!] yara: {e}");
        }
        if rules.is_none() {
            let _ = writeln!(err, "[!] yara: no usable rule in {}", dir.display());
        }
        opts.yara = rules.map(std::sync::Arc::new);
    }
    let (data, mut an) = match pe_analysis::analyze_file(&file, &k, &opts) {
        Ok(x) => x,
        Err(e) => {
            let _ = writeln!(err, "[-] cannot read {}: {e}", file.display());
            return 1;
        }
    };
    if a.vt {
        let c = env.http(&k);
        pe_online::attach_score_with(&mut an, &k, c.as_ref(), store.as_ref());
    }
    let fmt = a.format.unwrap_or_else(|| Format::from_setting(k.settings.get_int("report", "type", 0)));
    let text = report::render(&an, &k, &data, fmt);
    if a.stdout {
        let _ = out.write_all(text.as_bytes());
        return 0;
    }
    let path = a.report.clone().unwrap_or_else(|| report::default_report_path(&file, fmt));
    match std::fs::write(&path, text) {
        Ok(()) => {
            let _ = writeln!(out, "[+] report: {}", path.display());
            let high = an.indicators.iter().filter(|i| i.severity == 1).count();
            let _ = writeln!(out, "[+] indicators: {} (high: {high})", an.indicators.len());
            0
        }
        Err(e) => {
            let _ = writeln!(err, "Cannot create Report file! ({}: {e})", path.display());
            1
        }
    }
}
