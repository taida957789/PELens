//! GUI state and actions, independent from the rendering code (fully unit-testable).

use crate::i18n::{self, Lang};
use pe_analysis::actions::{self, Modification};
use pe_analysis::model::{Analysis, ItemType};
use pe_analysis::report::{self, Format};
use pe_analysis::view::{self, Row, Table, ViewOptions};
use pe_db::Knowledge;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

/// File dialogs / external effects that tests replace.
pub trait Host {
    fn pick_open(&mut self) -> Option<PathBuf>;
    fn pick_save(&mut self, default_name: &str, filter: (&str, &[&str])) -> Option<PathBuf>;
    /// Language of the dialog titles and filter names.
    fn set_lang(&mut self, _lang: Lang) {}
}

pub struct Document {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub analysis: Analysis,
    pub dirty: bool,
    tables: HashMap<ItemType, Arc<Table>>,
    /// Bumped whenever cached tables are dropped (lets the visible-table cache know).
    pub generation: u64,
    flagged: HashMap<ItemType, usize>,
}

impl Document {
    pub fn new(path: PathBuf, data: Vec<u8>, analysis: Analysis) -> Self {
        Document { path, data, analysis, dirty: false, tables: HashMap::new(), generation: 0, flagged: HashMap::new() }
    }

    pub fn table(&mut self, k: &Knowledge, item: ItemType, o: &ViewOptions) -> Arc<Table> {
        let (a, d) = (&self.analysis, &self.data);
        self.tables.entry(item).or_insert_with(|| Arc::new(view::table(a, k, d, item, o))).clone()
    }

    pub fn invalidate(&mut self) {
        self.tables.clear();
        self.flagged.clear();
        self.generation += 1;
    }

    /// Cached number of flagged items of a view (tree badges).
    pub fn flagged(&mut self, item: ItemType) -> usize {
        let a = &self.analysis;
        *self.flagged.entry(item).or_insert_with(|| a.flagged_count(item))
    }

    pub fn file_name(&self) -> String {
        self.path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Dialog {
    None,
    Settings,
    About,
    /// Confirmation before discarding modifications (then run the pending action).
    ConfirmDiscard(Box<Pending>),
    /// Confirmation before overwriting the sample on save.
    ConfirmOverwrite(PathBuf),
    EntryPoint(String),
    Message(String),
}

/// Bytes per line of the hex view.
pub const HEX_WIDTH: usize = 16;
/// Largest range copied from the hex view to the clipboard.
pub const HEX_COPY_MAX: u64 = 1 << 20;

/// The hex view below the list-view (read only).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HexView {
    pub open: bool,
    /// Highlighted range: (file offset, size).
    pub range: Option<(u64, u64)>,
    /// Line the view should scroll to (consumed by the UI).
    pub scroll_to: Option<u64>,
    /// Text of the "go to" box (file offset or RVA, decimal or 0x hex).
    pub goto: String,
    /// Show and enter addresses as RVAs instead of file offsets.
    pub rva: bool,
}

/// One line of the hex view: hex bytes and their printable text.
pub fn hex_line(data: &[u8], line: usize) -> (String, String) {
    let start = (line * HEX_WIDTH).min(data.len());
    let bytes = &data[start..(start + HEX_WIDTH).min(data.len())];
    let mut hex = String::with_capacity(HEX_WIDTH * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            hex.push(if i == 8 { '-' } else { ' ' });
        }
        hex.push_str(&format!("{b:02X}"));
    }
    let text = bytes.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
    (hex, text)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pending {
    Open(PathBuf),
    Close,
    Exit,
}

/// Every action available from the menus, keyboard shortcuts and context menus.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Open(PathBuf),
    OpenDialog,
    Close,
    Save,
    SaveAs(PathBuf),
    CreateReport,
    CreateReportAt(PathBuf, Format),
    Exit,
    Select(ItemType),
    /// Select a view and filter it (tree sub-items).
    SelectFiltered(ItemType, String),
    ToggleDarkMode,
    /// Change the interface language (None = follow the system).
    SetLanguage(Option<Lang>),
    SelectNext,
    SelectPrevious,
    CopyText(String),
    OpenUrl(String),
    Dump {
        offset: u64,
        size: u64,
        name: String,
    },
    DumpTo {
        offset: u64,
        size: u64,
        path: PathBuf,
    },
    OpenEmbedded {
        offset: u64,
        size: u64,
    },
    Modify(Modification),
    SetIndicatorSeverity(u32, u8),
    ToggleLibraryFlag(String),
    ToggleFunctionFlag(String, String),
    ToggleLanguageFlag(u16),
    SetSignatureSeverity(String, u8),
    ToggleNamespaceFlag(String),
    QueryScore,
    /// Disassemble from an RVA (None: from the entry point).
    DisassembleAt(Option<u32>),
    /// Open the hex view on a range (file offset, size).
    ShowHex(u64, u64),
    ToggleHex,
    /// Go to the address typed in the hex view.
    HexGoto,
    /// Copy the highlighted range: as hex bytes (true) or as text (false).
    CopyHex(bool),
    /// VirusTotal score of an item (overlay, resource, URL): (label, hash or url, is_url).
    QueryItemScore(String, String, bool),
    /// Save text (e.g. dump of indicators) through the save dialog.
    SaveText {
        name: String,
        text: String,
    },
    SaveTextTo {
        path: PathBuf,
        text: String,
    },
    CheckUpdate,
    ShowDialog(Dialog),
    Confirm,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Effects {
    pub copied: Vec<String>,
    pub urls: Vec<String>,
    pub exit: bool,
    pub title: Option<String>,
}

pub struct State {
    pub knowledge: Knowledge,
    pub view: ViewOptions,
    pub doc: Option<Document>,
    pub selected: ItemType,
    pub selected_row: Option<usize>,
    pub filter: String,
    pub sort: Option<(usize, bool)>,
    pub show_duplicates: bool,
    pub hidden_columns: HashMap<ItemType, Vec<bool>>,
    pub status: String,
    pub dialog: Dialog,
    pub effects: Effects,
    pub busy: Option<Receiver<OpenResult>>,
    pub score_rx: Option<Receiver<pe_analysis::ScoreReport>>,
    pub update_rx: Option<Receiver<Result<String, String>>>,
    pub update_result: Option<String>,
    pub last_score_attempt: Option<std::time::Instant>,
    pub http: HttpFactory,
    /// Run analysis/network jobs synchronously (tests).
    pub synchronous: bool,
    /// Visible (filtered/sorted) table of the selected view, reused across frames.
    view_cache: Option<(ViewKey, Arc<Table>)>,
    pub hex: HexView,
    /// Compiled YARA rules (settings > YARA), shared with the analysis jobs.
    pub yara: Option<Arc<pe_analysis::yara::YaraRules>>,
    /// Rule files that did not compile, with the compiler's message.
    pub yara_errors: Vec<String>,
    /// Where the VirusTotal key is kept: in memory by default (tests), the Windows Credential
    /// Manager in the application (see main.rs).
    pub key_store: Arc<dyn pe_online::secret::KeyStore>,
    /// Interface language (settings.xml `<language code>`, else `system_lang`).
    pub lang: Lang,
    pub system_lang: Lang,
}

#[derive(Debug, Clone, PartialEq)]
struct ViewKey {
    path: PathBuf,
    generation: u64,
    item: ItemType,
    filter: String,
    sort: Option<(usize, bool)>,
    dups: bool,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Status shown while no file is loaded.
pub const IDLE: &str = "drag-and-drop a file to analyse...";

/// Result of a background analysis: (path, file bytes, analysis) or an error message.
pub type OpenResult = Result<(PathBuf, Vec<u8>, Analysis), String>;

/// Creates the HTTP client for network jobs (replaced by a mock in tests).
pub type HttpFactory = Arc<dyn Fn(&Knowledge) -> Box<dyn pe_online::HttpClient + Send> + Send + Sync>;

fn default_http() -> HttpFactory {
    Arc::new(|k: &Knowledge| Box::new(pe_online::UreqClient::new(&pe_online::net_config(k))) as Box<dyn pe_online::HttpClient + Send>)
}

impl State {
    pub fn new(knowledge: Knowledge) -> Self {
        let view = ViewOptions::from_settings(&knowledge);
        let mut s = State {
            knowledge,
            view,
            doc: None,
            selected: ItemType::Indicators,
            selected_row: None,
            filter: String::new(),
            sort: None,
            show_duplicates: true,
            hidden_columns: HashMap::new(),
            status: IDLE.into(),
            dialog: Dialog::None,
            effects: Effects::default(),
            busy: None,
            score_rx: None,
            update_rx: None,
            update_result: None,
            last_score_attempt: None,
            http: default_http(),
            synchronous: false,
            view_cache: None,
            hex: HexView::default(),
            yara: None,
            yara_errors: Vec::new(),
            key_store: Arc::new(pe_online::secret::MemoryStore::default()),
            lang: Lang::En,
            system_lang: Lang::En,
        };
        s.refresh_lang();
        s
    }

    pub fn title(&self) -> String {
        match &self.doc {
            Some(d) if self.knowledge.settings.get_bool("caption", "enable", true) => {
                format!("PELens {VERSION} | {}{}", d.path.display(), if d.dirty { " *" } else { "" })
            }
            _ => format!("PELens {VERSION}"),
        }
    }

    /// Interface text in the current language (the English text is the key).
    pub fn t<'a>(&self, key: &'a str) -> &'a str {
        i18n::translate(self.lang, key)
    }

    /// Translated template with `{0}`, `{1}`, … replaced.
    pub fn tf(&self, key: &str, args: &[&dyn std::fmt::Display]) -> String {
        i18n::fill(self.t(key), args)
    }

    /// UI text of a pestudio translation id. In English, translations.xml (pestudio's localisation
    /// file) wins; in other languages the built-in catalog does.
    pub fn tr(&self, id: u32, default: &str) -> String {
        if self.lang != Lang::En {
            return self.t(default).to_string();
        }
        match self.knowledge.translations.text.get(&id).map(|s| s.trim()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => default.to_string(),
        }
    }

    /// The language chosen in the settings (`None` = follow the system).
    pub fn language_setting(&self) -> Option<Lang> {
        self.knowledge.settings.get("language", "code").and_then(Lang::from_code)
    }

    /// Recompute `lang` after the setting or the system language changed.
    pub fn refresh_lang(&mut self) {
        self.lang = self.language_setting().unwrap_or(self.system_lang);
        if self.doc.is_none() && self.busy.is_none() {
            self.status = self.t(IDLE).into();
        }
    }

    pub fn set_system_lang(&mut self, lang: Lang) {
        self.system_lang = lang;
        self.refresh_lang();
    }

    /// Dark mode is the default; `<theme dark="0"/>` selects the light palette.
    pub fn dark_mode(&self) -> bool {
        self.knowledge.settings.get_bool("theme", "dark", true)
    }

    /// Expandable sub-items of a tree node: (label, filter, flagged).
    pub fn tree_children(&self, item: ItemType) -> Vec<(String, String, bool)> {
        let Some(d) = &self.doc else { return Vec::new() };
        let a = &d.analysis;
        match item {
            ItemType::Sections => a
                .sections
                .iter()
                .map(|s| {
                    let n = if s.nameless { "(nameless)".to_string() } else { s.name.clone() };
                    (self.t(&n).to_string(), n, !s.standard_name || s.self_modifying)
                })
                .collect(),
            ItemType::Libraries => a.libraries.iter().map(|l| (l.name.clone(), l.name.clone(), l.flag || l.spoofed)).collect(),
            ItemType::Resources => {
                let mut v: Vec<(String, String, bool)> = Vec::new();
                for r in &a.resources {
                    match v.iter_mut().find(|x| x.1 == r.type_name) {
                        Some(e) => e.2 |= r.severity <= 2,
                        None => v.push((r.type_name.clone(), r.type_name.clone(), r.severity <= 2)),
                    }
                }
                for e in v.iter_mut() {
                    let n = a.resources.iter().filter(|r| r.type_name == e.1).count();
                    e.0 = format!("{} ({n})", e.1);
                }
                v
            }
            ItemType::Indicators => [(1u8, "high"), (2, "medium"), (3, "low")]
                .iter()
                .filter_map(|(sev, name)| {
                    let n = a.indicators.iter().filter(|i| i.severity == *sev).count();
                    (n > 0).then(|| (format!("{} ({n})", self.t(name)), name.to_string(), *sev == 1))
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn read_only(&self) -> bool {
        self.knowledge.settings.get_bool("read-only", "enable", true)
    }

    /// Views shown in the tree for the current document.
    pub fn nodes(&self) -> Vec<ItemType> {
        ItemType::ALL.iter().copied().filter(|&t| view::view_enabled(&self.knowledge, t)).collect()
    }

    /// The table of the selected view after filter / sort / duplicates handling.
    pub fn visible_table(&mut self) -> Option<Arc<Table>> {
        let (k, o, sel) = (&self.knowledge, &self.view, self.selected);
        let doc = self.doc.as_mut()?;
        let key = ViewKey {
            path: doc.path.clone(),
            generation: doc.generation,
            item: sel,
            filter: self.filter.clone(),
            sort: self.sort,
            dups: self.show_duplicates,
        };
        if let Some((ck, t)) = &self.view_cache
            && *ck == key
        {
            return Some(t.clone());
        }
        let base = doc.table(k, sel, o);
        let t = if self.show_duplicates && self.filter.is_empty() && self.sort.is_none() {
            base
        } else {
            let mut t = (*base).clone();
            if !self.show_duplicates {
                t.dedup();
            }
            t.filter(&self.filter);
            if let Some((c, asc)) = self.sort {
                t.sort_by(c, asc);
            }
            Arc::new(t)
        };
        self.view_cache = Some((key, t.clone()));
        Some(t)
    }

    pub fn column_visible(&self, item: ItemType, col: usize) -> bool {
        self.hidden_columns.get(&item).and_then(|v| v.get(col)).is_none_or(|h| !h)
    }

    pub fn toggle_column(&mut self, item: ItemType, col: usize, ncols: usize) {
        let v = self.hidden_columns.entry(item).or_insert_with(|| vec![false; ncols]);
        let need = ncols.max(col + 1);
        if v.len() < need {
            v.resize(need, false);
        }
        v[col] = !v[col];
    }

    pub fn sort_column(&mut self, col: usize) {
        self.sort = match self.sort {
            Some((c, asc)) if c == col => Some((c, !asc)),
            _ => Some((col, true)),
        };
    }

    /// Analysis options from the settings, with the compiled YARA rules.
    pub fn options(&self) -> pe_analysis::Options {
        pe_analysis::Options { yara: self.yara.clone(), ..pe_analysis::Options::from_settings(&self.knowledge) }
    }

    /// (Re)compile the YARA rules of the folder set in settings > YARA.
    pub fn load_yara(&mut self) {
        self.yara = None;
        self.yara_errors.clear();
        let s = &self.knowledge.settings;
        let dir = s.get("yara", "dir").unwrap_or("").trim().to_string();
        if dir.is_empty() || !s.get_bool("yara", "enable", true) {
            return;
        }
        let (rules, errors) = pe_analysis::yara::compile_dir(std::path::Path::new(&dir));
        let files = rules.as_ref().map_or(0, |r| r.files);
        self.yara = rules.map(Arc::new);
        self.status = self.tf("YARA: {0} rule files, {1} errors", &[&files, &errors.len()]);
        self.yara_errors = errors;
    }

    fn reanalyze(&mut self, path: PathBuf, data: Vec<u8>, dirty: bool) {
        let opts = self.options();
        let mut a = pe_analysis::analyze(&data, &path.to_string_lossy(), &self.knowledge, &opts);
        // Keep what analyze_file() added from the disk / network for the same file.
        if let Some(old) = self.doc.as_ref().filter(|d| d.path == path).map(|d| &d.analysis) {
            a.network_drive = old.network_drive;
            a.removable_drive = old.removable_drive;
            a.footprints.extend(old.footprints.iter().filter(|f| f.item.starts_with("acl")).cloned());
            // indicators depend on the drive type: evaluate them again with the restored info
            a.indicators = pe_analysis::indicators::evaluate(&a, &self.knowledge, &data, &opts);
            pe_analysis::indicators::mitre_indicators(&mut a, &self.knowledge);
            if old.hashes.sha256 == a.hashes.sha256 && old.score.is_some() {
                a.score = old.score.clone();
                pe_analysis::indicators::score_indicators(&mut a, &self.knowledge);
            }
        }
        let mut d = Document::new(path, data, a);
        d.dirty = dirty;
        self.doc = Some(d);
        self.view_cache = None;
    }

    fn start_open(&mut self, path: PathBuf) {
        self.status = self.t("please wait while analyzing the file...").into();
        let k = self.knowledge.clone();
        let opts = self.options();
        let job = move || -> OpenResult {
            pe_analysis::analyze_file(&path, &k, &opts).map(|(d, a)| (path.clone(), d, a)).map_err(|e| format!("{}: {e}", path.display()))
        };
        let (tx, rx) = channel();
        if self.synchronous {
            let _ = tx.send(job());
        } else {
            std::thread::spawn(move || {
                let _ = tx.send(job());
            });
        }
        self.busy = Some(rx);
        self.poll();
    }

    /// Collect results of background jobs. Returns true when something changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if let Some(rx) = &self.busy
            && let Ok(r) = rx.try_recv()
        {
            self.busy = None;
            changed = true;
            match r {
                Ok((p, d, a)) => {
                    self.status = self.tf("{0} | {1} bytes | indicators: {2}", &[&a.file_type, &a.size, &a.indicators.len()]);
                    self.doc = Some(Document::new(p, d, a));
                    self.view_cache = None;
                    self.selected_row = None;
                    self.hex.range = None;
                    self.hex.scroll_to = Some(0);
                    self.view.disasm_start = None;
                    self.effects.title = Some(self.title());
                    if self.knowledge.settings.get_bool("score", "enable", false) {
                        self.apply(Action::QueryScore);
                        if self.knowledge.settings.get_bool("overlay", "score", false) {
                            let item = self.doc.as_ref().and_then(|d| Some(d.analysis.overlay_info.as_ref()?.hashes.md5.clone()));
                            if let Some(md5) = item {
                                self.apply(Action::QueryItemScore("overlay".into(), md5, false));
                            }
                        }
                    }
                }
                Err(e) => {
                    self.status = self.tf("Image not found ({0})", &[&e]);
                    self.dialog = Dialog::Message(e);
                }
            }
        }
        if let Some(rx) = &self.score_rx
            && let Ok(s) = rx.try_recv()
        {
            self.score_rx = None;
            changed = true;
            if let Some(d) = self.doc.as_mut() {
                d.analysis.score = Some(s);
                pe_analysis::indicators::score_indicators(&mut d.analysis, &self.knowledge);
                d.invalidate();
            }
        }
        if let Some(rx) = &self.update_rx
            && let Ok(r) = rx.try_recv()
        {
            self.update_rx = None;
            changed = true;
            self.update_result = Some(match r {
                Ok(v) if pe_online::is_newer(&v, env!("CARGO_PKG_VERSION")) => self.tf("The newest version of PELens is: {0}", &[&v]),
                Ok(_) => self.tf("PELens {0} | up to date", &[&env!("CARGO_PKG_VERSION")]),
                Err(e) => self.tf("internet connection failed ({0})", &[&e]),
            });
        }
        changed
    }

    /// Network watchdog: retry the score when the previous attempt was offline.
    pub fn watchdog(&mut self, now: std::time::Instant, every: std::time::Duration) {
        let offline = self.doc.as_ref().and_then(|d| d.analysis.score.as_ref()).is_some_and(|s| s.status.starts_with("offline"));
        let due = self.last_score_attempt.is_none_or(|t| now.duration_since(t) >= every);
        if offline && due && self.score_rx.is_none() {
            self.apply(Action::QueryScore);
        }
    }

    fn guard_discard(&mut self, p: Pending) -> bool {
        if self.doc.as_ref().is_some_and(|d| d.dirty) {
            self.dialog = Dialog::ConfirmDiscard(Box::new(p));
            return false;
        }
        true
    }

    pub fn apply_with(&mut self, a: Action, host: &mut dyn Host) {
        match a {
            Action::OpenDialog => {
                if let Some(p) = host.pick_open() {
                    self.apply(Action::Open(p));
                }
            }
            Action::CreateReport => {
                let Some(d) = &self.doc else { return };
                let fmt = Format::from_setting(self.knowledge.settings.get_int("report", "type", 0));
                let name = format!("{}.{}", d.file_name(), fmt.extension());
                if let Some(p) = host.pick_save(&name, (self.t("report"), &[fmt.extension()])) {
                    self.apply(Action::CreateReportAt(p, fmt));
                }
            }
            Action::Dump { offset, size, name } => {
                let Some(d) = &self.doc else { return };
                let n = actions::dump_name(&d.file_name(), &name);
                if let Some(p) = host.pick_save(&n, (self.t("dump"), &["dump"])) {
                    self.apply(Action::DumpTo { offset, size, path: p });
                }
            }
            Action::SaveText { name, text } => {
                let n = match &self.doc {
                    Some(d) => format!("{}.{name}.txt", d.file_name()),
                    None => format!("{name}.txt"),
                };
                if let Some(p) = host.pick_save(&n, (self.t("text"), &["txt"])) {
                    self.apply(Action::SaveTextTo { path: p, text });
                }
            }
            Action::Save => {
                let Some(d) = &self.doc else { return };
                if self.read_only() {
                    let n = d.file_name();
                    if let Some(p) = host.pick_save(&n, (self.t("executable"), &["exe", "dll", "sys"])) {
                        self.apply(Action::SaveAs(p));
                    }
                } else {
                    self.dialog = Dialog::ConfirmOverwrite(d.path.clone());
                }
            }
            other => self.apply(other),
        }
    }

    /// Apply an action that needs no host interaction.
    pub fn apply(&mut self, a: Action) {
        match a {
            Action::Open(p) => {
                if self.guard_discard(Pending::Open(p.clone())) {
                    self.start_open(p);
                }
            }
            Action::Close => {
                if self.guard_discard(Pending::Close) {
                    self.doc = None;
                    self.status = self.tr(607, "close file");
                    self.effects.title = Some(self.title());
                }
            }
            Action::Exit => {
                if self.guard_discard(Pending::Exit) {
                    self.effects.exit = true;
                }
            }
            Action::SaveAs(p) => self.save_to(&p),
            Action::CreateReportAt(p, fmt) => {
                let Some(d) = &self.doc else { return };
                let text = report::render(&d.analysis, &self.knowledge, &d.data, fmt);
                self.status = match std::fs::write(&p, text) {
                    Ok(()) => self.tf("report: {0}", &[&p.display()]),
                    Err(e) => self.tf("Cannot create Report file! ({0})", &[&e]),
                };
            }
            Action::Select(t) => {
                self.selected = t;
                self.selected_row = None;
                self.sort = None;
                self.filter.clear();
            }
            Action::SelectFiltered(t, f) => {
                self.apply(Action::Select(t));
                self.filter = f;
            }
            Action::ToggleDarkMode => {
                let dark = self.dark_mode();
                self.set_setting("theme", "dark", if dark { "0" } else { "1" });
            }
            Action::SetLanguage(l) => self.set_setting("language", "code", l.map(Lang::code).unwrap_or("auto")),
            Action::SelectNext | Action::SelectPrevious => {
                let nodes = self.nodes();
                let i = nodes.iter().position(|&n| n == self.selected).unwrap_or(0);
                let j = if a == Action::SelectNext { (i + 1) % nodes.len() } else { (i + nodes.len() - 1) % nodes.len() };
                self.apply(Action::Select(nodes[j]));
            }
            Action::CopyText(t) => {
                self.status = self.t("copy to clipboard").into();
                self.effects.copied.push(t);
            }
            Action::OpenUrl(u) => self.effects.urls.push(u),
            Action::DumpTo { offset, size, path } => {
                let Some(d) = &self.doc else { return };
                self.status = match actions::dump(&d.data, offset, size, &path) {
                    Ok(n) => self.tf("dump to file: {0} ({1} bytes)", &[&path.display(), &n]),
                    Err(e) => self.tf("dump failed: {0}", &[&e]),
                };
            }
            Action::OpenEmbedded { offset, size } => {
                let Some(d) = &self.doc else { return };
                let s = (offset as usize).min(d.data.len());
                let e = (offset.saturating_add(size) as usize).min(d.data.len());
                let path = std::env::temp_dir().join(format!("{}.embedded.0x{offset:08X}", d.file_name()));
                if std::fs::write(&path, &d.data[s..e]).is_ok() {
                    self.apply(Action::Open(path));
                }
            }
            Action::Modify(m) => {
                let Some(d) = self.doc.as_mut() else { return };
                let mut data = d.data.clone();
                match actions::apply(&mut data, m) {
                    Ok(()) => {
                        let p = d.path.clone();
                        self.reanalyze(p, data, true);
                        self.status = m.describe();
                        self.effects.title = Some(self.title());
                    }
                    Err(e) => self.dialog = Dialog::Message(e.to_string()),
                }
            }
            Action::SetIndicatorSeverity(id, sev) => {
                let r = self.knowledge.set_indicator_severity(id, sev);
                self.after_kb_change(r);
            }
            Action::ToggleLibraryFlag(l) => {
                let cur = self.knowledge.functions.library(&l).is_some_and(|d| d.flag);
                let r = self.knowledge.set_library_flag(&l, !cur);
                self.after_kb_change(r);
            }
            Action::ToggleFunctionFlag(l, f) => {
                let cur = self.knowledge.functions.function(&l, &f).is_some_and(|d| d.flag);
                let r = self.knowledge.set_function_flag(&l, &f, !cur);
                self.after_kb_change(r);
            }
            Action::ToggleLanguageFlag(id) => {
                let cur = self.knowledge.languages.language(id).is_some_and(|(_, f)| f);
                let r = self.knowledge.set_language_flag(id, !cur);
                self.after_kb_change(r);
            }
            Action::SetSignatureSeverity(n, s) => {
                let r = self.knowledge.set_signature_severity(&n, s);
                self.after_kb_change(r);
            }
            Action::ToggleNamespaceFlag(n) => {
                let cur = self.knowledge.namespaces.items.iter().any(|x| x.name == n && x.flag);
                let r = self.knowledge.set_namespace_flag(&n, !cur);
                self.after_kb_change(r);
            }
            Action::QueryScore => {
                let Some(d) = &self.doc else { return };
                let (api, key, _) = pe_online::vt_settings_with(&self.knowledge, self.key_store.as_ref());
                let md5 = d.analysis.hashes.md5.to_ascii_lowercase();
                let client = (self.http)(&self.knowledge);
                self.last_score_attempt = Some(std::time::Instant::now());
                let (tx, rx) = channel();
                let job = move || pe_online::vt_file_report(client.as_ref(), api, &key, &md5);
                if self.synchronous {
                    let _ = tx.send(job());
                } else {
                    std::thread::spawn(move || {
                        let _ = tx.send(job());
                    });
                }
                self.score_rx = Some(rx);
                self.poll();
            }
            Action::QueryItemScore(label, q, is_url) => {
                let (api, key, _) = pe_online::vt_settings_with(&self.knowledge, self.key_store.as_ref());
                let client = (self.http)(&self.knowledge);
                let r = if is_url {
                    pe_online::vt_url_report(client.as_ref(), &key, &q)
                } else {
                    pe_online::vt_file_report(client.as_ref(), api, &key, &q.to_ascii_lowercase())
                };
                let msg = if r.status == "ok" {
                    format!("virustotal > {}: {}/{} ({})", self.t(&label), r.positives, r.total, r.permalink)
                } else {
                    format!("virustotal > {}: {}", self.t(&label), r.status)
                };
                self.status = msg.clone();
                self.dialog = Dialog::Message(msg);
            }
            Action::SaveTextTo { path, text } => {
                self.status = match std::fs::write(&path, text) {
                    Ok(()) => self.tf("save to file: {0}", &[&path.display()]),
                    Err(e) => self.tf("save failed: {0}", &[&e]),
                };
            }
            Action::CheckUpdate => {
                let client = (self.http)(&self.knowledge);
                let url = self.knowledge.settings.get("update", "url").unwrap_or(pe_online::UPDATE_URL).to_string();
                let (tx, rx) = channel();
                let job = move || pe_online::check_update(client.as_ref(), &url);
                if self.synchronous {
                    let _ = tx.send(job());
                } else {
                    std::thread::spawn(move || {
                        let _ = tx.send(job());
                    });
                }
                self.update_rx = Some(rx);
                self.poll();
            }
            Action::DisassembleAt(rva) => {
                self.view.disasm_start = rva;
                if let Some(d) = self.doc.as_mut() {
                    d.invalidate();
                }
                self.apply(Action::Select(ItemType::Disassembly));
            }
            Action::ShowHex(off, size) => {
                self.hex.open = true;
                self.hex.range = Some((off, size));
                self.hex.scroll_to = Some(off);
            }
            Action::ToggleHex => self.hex.open = !self.hex.open,
            Action::HexGoto => match self.hex_address(&self.hex.goto.clone()) {
                Some(off) => {
                    self.hex.open = true;
                    self.hex.range = Some((off, 1));
                    self.hex.scroll_to = Some(off);
                }
                None => self.status = self.tf("invalid address: {0}", &[&self.hex.goto]),
            },
            Action::CopyHex(as_hex) => {
                let Some(d) = &self.doc else { return };
                let Some((off, size)) = self.hex.range else { return };
                let s = (off as usize).min(d.data.len());
                let e = (off.saturating_add(size.min(HEX_COPY_MAX)) as usize).min(d.data.len());
                let b = &d.data[s..e];
                let text = if as_hex {
                    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
                } else {
                    b.iter().map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' }).collect()
                };
                self.apply(Action::CopyText(text));
            }
            Action::ShowDialog(d) => self.dialog = d,
            Action::Confirm => {
                let dlg = std::mem::replace(&mut self.dialog, Dialog::None);
                match dlg {
                    Dialog::ConfirmDiscard(p) => {
                        if let Some(d) = self.doc.as_mut() {
                            d.dirty = false;
                        }
                        match *p {
                            Pending::Open(path) => self.apply(Action::Open(path)),
                            Pending::Close => self.apply(Action::Close),
                            Pending::Exit => self.apply(Action::Exit),
                        }
                    }
                    Dialog::ConfirmOverwrite(p) => self.save_to(&p),
                    Dialog::EntryPoint(s) => match actions::parse_address(&s) {
                        Some(v) => self.apply(Action::Modify(Modification::SetEntryPoint(v))),
                        None => self.dialog = Dialog::Message(self.tf("invalid address: {0}", &[&s])),
                    },
                    _ => {}
                }
            }
            Action::Cancel => self.dialog = Dialog::None,
            Action::OpenDialog | Action::Save | Action::CreateReport | Action::Dump { .. } | Action::SaveText { .. } => {}
        }
    }

    fn save_to(&mut self, p: &Path) {
        let Some(d) = self.doc.as_mut() else { return };
        match std::fs::write(p, &d.data) {
            Ok(()) => {
                d.dirty = false;
                d.path = p.to_path_buf();
                self.status = self.tf("save file: {0}", &[&p.display()]);
                self.effects.title = Some(self.title());
            }
            Err(e) => self.dialog = Dialog::Message(self.tf("save failed: {0}", &[&e])),
        }
    }

    fn after_kb_change(&mut self, r: Result<(), pe_db::DbError>) {
        match r {
            Ok(()) => {
                if let Some(d) = &self.doc {
                    let (p, data, dirty) = (d.path.clone(), d.data.clone(), d.dirty);
                    self.reanalyze(p, data, dirty);
                }
                self.status = self.t("settings saved").into();
            }
            Err(e) => self.dialog = Dialog::Message(e.to_string()),
        }
    }

    /// Persist a setting edited in the settings dialog.
    pub fn set_setting(&mut self, elem: &str, attr: &str, value: &str) {
        if (elem, attr) == ("score", "key") {
            self.set_vt_key(value);
            return;
        }
        let r = if self.knowledge.settings_path().is_some() {
            self.knowledge.save_setting(elem, attr, value)
        } else {
            self.knowledge.settings.set(elem, attr, value);
            Ok(())
        };
        if let Err(e) = r {
            // the element may be missing in settings.xml: keep the value in memory
            self.knowledge.settings.set(elem, attr, value);
            self.status = self.tf("setting kept in memory ({0})", &[&e]);
        }
        if elem == "language" {
            self.refresh_lang();
        }
        if elem == "yara" {
            self.load_yara();
            if let Some(d) = &self.doc {
                let (p, data, dirty) = (d.path.clone(), d.data.clone(), d.dirty);
                self.reanalyze(p, data, dirty);
            }
        }
        self.view = ViewOptions::from_settings(&self.knowledge);
        if let Some(d) = self.doc.as_mut() {
            d.invalidate();
        }
    }

    /// File offset of an address typed in the hex view (an RVA when the view shows RVAs).
    pub fn hex_address(&self, text: &str) -> Option<u64> {
        let d = self.doc.as_ref()?;
        let v = actions::parse_address(text)?;
        let off = if self.hex.rva { d.analysis.pe.layout.as_ref()?.rva_to_offset(v)? as u64 } else { v as u64 };
        (off < d.data.len() as u64).then_some(off)
    }

    /// Address of a file offset as the hex view shows it (file offset, or RVA when it maps).
    pub fn hex_label(&self, off: u64) -> String {
        let rva = self.hex.rva.then(|| self.doc.as_ref()?.analysis.pe.layout.as_ref()?.offset_to_rva(off)).flatten();
        match rva {
            Some(r) => format!("{r:08X}"),
            None if self.hex.rva => "--------".into(),
            None => format!("{off:08X}"),
        }
    }

    /// The VirusTotal key as stored (not `VT_API_KEY`): the key store, else a legacy plaintext setting.
    pub fn stored_key(&self) -> String {
        self.key_store.get().or_else(|| self.knowledge.settings.get("score", "key").map(str::to_string)).unwrap_or_default()
    }

    /// Save the VirusTotal key in the key store, never in settings.xml (an old plaintext key there
    /// is blanked). When the store fails the key is not written anywhere.
    fn set_vt_key(&mut self, key: &str) {
        match self.key_store.set(key) {
            Ok(()) => {
                if self.knowledge.settings.get("score", "key").is_some_and(|k| !k.is_empty()) {
                    let saved = self.knowledge.settings_path().is_some() && self.knowledge.save_setting("score", "key", "").is_ok();
                    if !saved {
                        self.knowledge.settings.set("score", "key", "");
                    }
                }
                let store = self.t(pe_online::secret::STORE_NAME);
                self.status = self.tf("the Virustotal key is stored in the {0}", &[&store]);
            }
            Err(e) => self.status = self.tf("cannot store the Virustotal key ({0})", &[&e]),
        }
    }

    /// Context menu entries for a row of the given view (labels from translations.xml when present).
    pub fn context_actions(&self, item: ItemType, row: &Row, columns: &[String], sep: &str) -> Vec<(String, Action)> {
        let t = |id: u32, d: &str| self.tr(id, d);
        let mut v: Vec<(String, Action)> = vec![(t(579, "copy line"), Action::CopyText(row.cells.join(sep)))];
        let props = columns.first().is_some_and(|c| c == "property");
        if let Some(first) = row.cells.first() {
            let label = match item {
                ItemType::Imports => t(600, "copy import name"),
                ItemType::Indicators => t(584, "copy indicator"),
                ItemType::Libraries => t(587, "copy name"),
                _ if props => t(582, "copy property"),
                _ => t(583, "copy item"),
            };
            v.push((label, Action::CopyText(first.clone())));
        }
        if row.cells.len() > 1 {
            let label = if props { t(580, "copy value") } else { t(581, "copy detail") };
            v.push((label, Action::CopyText(row.cells[1].clone())));
        }
        if let Some(i) = columns.iter().position(|c| c == "description")
            && let Some(d) = row.cells.get(i).filter(|d| !d.is_empty())
        {
            v.push((t(588, "copy description"), Action::CopyText(d.clone())));
        }
        if let Some(u) = &row.url {
            v.push((t(589, "lookup in Browser"), Action::OpenUrl(u.clone())));
        }
        if let Some(first) = row.cells.first().filter(|_| {
            matches!(item, ItemType::Strings | ItemType::Imports | ItemType::Exports | ItemType::Libraries | ItemType::Resources)
        }) {
            let q = if item == ItemType::Strings { row.cells.last().cloned().unwrap_or_default() } else { first.clone() };
            v.push((t(585, "search Virustotal"), Action::OpenUrl(pe_online::vt_search_content(&q))));
            v.push((self.t("search Google").into(), Action::OpenUrl(pe_online::google_search(&q))));
            if item == ItemType::Strings && row.cells.get(4).is_some_and(|h| h == "url-pattern") {
                v.push((self.t("score > Virustotal (url)").into(), Action::QueryItemScore("url".into(), q.clone(), true)));
            }
        }
        if let Some(h) = row.key.strip_prefix("hash:") {
            v.push((t(585, "search Virustotal"), Action::OpenUrl(pe_online::vt_search_hash(h))));
            v.push((
                self.t("score > Virustotal").into(),
                Action::QueryItemScore(row.cells.first().cloned().unwrap_or_default(), h.to_string(), false),
            ));
        }
        if let Some(ti) = &row.ti {
            v.push((t(602, "copy technique"), Action::CopyText(format!("T{}", ti.trim_start_matches('T')))));
            v.push((t(614, "attack.mitre.org"), Action::OpenUrl(pe_online::mitre_technique(ti))));
        }
        if let Some((off, size)) = row.dump {
            v.push((self.t("show in hex").into(), Action::ShowHex(off, size)));
            let label = if item == ItemType::DotNet { t(586, "dump stream") } else { t(233, "dump to file") };
            v.push((
                label,
                Action::Dump { offset: off, size, name: if row.key.is_empty() { item.name().to_string() } else { row.key.clone() } },
            ));
            if matches!(item, ItemType::Resources | ItemType::Overlay | ItemType::Image | ItemType::Sections) {
                v.push((t(595, "open in PELens"), Action::OpenEmbedded { offset: off, size }));
            }
        }
        if let Some(d) = &self.doc {
            if item == ItemType::Indicators {
                let tbl = pe_analysis::view::table(&d.analysis, &self.knowledge, &d.data, ItemType::Indicators, &self.view);
                v.push((
                    self.t("dump indicators to file").into(),
                    Action::SaveText { name: "indicators".into(), text: pe_analysis::view::table_text(&tbl, sep) },
                ));
            }
            if item == ItemType::Image {
                v.push((t(606, "copy file name"), Action::CopyText(d.file_name())));
            }
        }
        if let Some(id) = row.key.strip_prefix("indicator:").and_then(|s| s.parse::<u32>().ok()) {
            for (l, s) in [("severity +++", 1u8), ("severity ++", 2), ("severity +", 3)] {
                v.push((self.t(l).into(), Action::SetIndicatorSeverity(id, s)));
            }
        }
        if let Some(l) = row.key.strip_prefix("lib:") {
            v.push((self.t("toggle flag").into(), Action::ToggleLibraryFlag(l.to_string())));
            v.push((t(95, "open Virustotal in a Browser"), Action::OpenUrl(pe_online::vt_search_content(l))));
        }
        if let Some(rest) = row.key.strip_prefix("import:")
            && let Some((l, f)) = rest.split_once('|')
        {
            v.push((self.t("toggle flag").into(), Action::ToggleFunctionFlag(l.to_string(), f.to_string())));
            v.push((self.t("lookup in Browser (MSDN)").into(), Action::OpenUrl(pe_online::msdn_search(f))));
        }
        if let Some(ns) = row.key.strip_prefix("ns:") {
            v.push((t(601, "copy namespace"), Action::CopyText(ns.to_string())));
            v.push((self.t("toggle flag").into(), Action::ToggleNamespaceFlag(ns.to_string())));
        }
        if let Some(idx) = row.key.strip_prefix("resource:").and_then(|s| s.parse::<usize>().ok())
            && let Some(r) = self.doc.as_ref().and_then(|d| d.analysis.resources.get(idx))
        {
            v.push((self.t("toggle language flag").into(), Action::ToggleLanguageFlag((r.language & 0xffff) as u16)));
            v.push((
                self.t("score > Virustotal").into(),
                Action::QueryItemScore(self.tf("resource {0}", &[&r.name]), r.md5.clone(), false),
            ));
            if !r.signature.is_empty() && self.knowledge.signatures.iter().any(|s| s.name == r.signature) {
                for (l, s) in [("signature > severity +++", 1u8), ("signature > severity ++", 2), ("signature > severity +", 3)] {
                    v.push((self.t(l).into(), Action::SetSignatureSeverity(r.signature.clone(), s)));
                }
            }
        }
        if let Some(bit) = row.key.strip_prefix("fh-char:").and_then(|s| s.parse::<u16>().ok()) {
            if bit == pe_parser::headers::file_characteristics::DLL {
                let is_dll = row.cells.get(1).is_some_and(|c| c == "true");
                v.push((
                    self.t(if is_dll { "toggle DLL > EXE" } else { "toggle EXE > DLL" }).into(),
                    Action::Modify(Modification::SetDll(!is_dll)),
                ));
            } else {
                v.push((self.t("toggle characteristic").into(), Action::Modify(Modification::ToggleFileCharacteristic(bit))));
            }
        }
        if let Some(bit) = row.key.strip_prefix("dll-char:").and_then(|s| s.parse::<u16>().ok()) {
            v.push((self.t("toggle characteristic").into(), Action::Modify(Modification::ToggleDllCharacteristic(bit))));
        }
        if row.key == "ep" {
            v.push((t(603, "set entry-point"), Action::ShowDialog(Dialog::EntryPoint(String::new()))));
            v.push((self.t("disassemble here").into(), Action::DisassembleAt(None)));
        }
        // code addresses: TLS callbacks, branch targets in the disassembly, exports
        let code_rva = row.key.strip_prefix("rva:").and_then(|r| r.parse::<u32>().ok()).or_else(|| {
            let ordinal = row.key.strip_prefix("export:")?.parse::<u32>().ok()?;
            let e = self.doc.as_ref()?.analysis.exports.iter().find(|e| e.ordinal == ordinal && e.forwarder.is_none())?;
            (e.rva != 0).then_some(e.rva)
        });
        if let Some(rva) = code_rva {
            let label = if item == ItemType::Disassembly { "follow the branch" } else { "disassemble here" };
            v.push((self.t(label).into(), Action::DisassembleAt(Some(rva))));
        }
        if item == ItemType::Disassembly && self.view.disasm_start.is_some() {
            v.push((self.t("disassemble from the entry point").into(), Action::DisassembleAt(None)));
        }
        if row.key == "overlay" {
            v.push((self.tf("{0} overlay", &[&t(596, "delete")]), Action::Modify(Modification::RemoveOverlay)));
        }
        if let Some(j) = row.jump {
            v.push((self.tf("jump > {0}", &[&self.t(j.name())]), Action::Select(j)));
        }
        v
    }
}

/// Settings dialog model: (tab, label, element, attribute, choices).
pub struct SettingField {
    pub tab: &'static str,
    pub label: &'static str,
    pub elem: &'static str,
    pub attr: &'static str,
    /// Empty = boolean checkbox, otherwise (value, label) choices; ("*", _) = free text.
    pub choices: &'static [(&'static str, &'static str)],
}

pub const SETTING_FIELDS: &[SettingField] = &[
    SettingField {
        tab: "General",
        label: "language",
        elem: "language",
        attr: "code",
        choices: &[
            ("auto", "auto (system)"),
            ("en", "English"),
            ("zh-TW", "繁體中文"),
            ("zh-CN", "简体中文"),
            ("ja", "日本語"),
            ("ko", "한국어"),
            ("es", "Español"),
            ("de", "Deutsch"),
            ("fr", "Français"),
        ],
    },
    SettingField { tab: "General", label: "show groups color", elem: "groups", attr: "color", choices: &[] },
    SettingField { tab: "General", label: "show Mitre", elem: "mitre", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "show Mitre Tactics", elem: "mitre", attr: "ta", choices: &[] },
    SettingField { tab: "General", label: "show Mitre duplicates", elem: "mitre", attr: "dup", choices: &[] },
    SettingField { tab: "General", label: "show Relocations", elem: "relocations", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "show Exceptions", elem: "exceptions", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "show Epoch stamps", elem: "stamps", attr: "epoch", choices: &[] },
    SettingField { tab: "General", label: "sample is read-only", elem: "read-only", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "show sample in caption", elem: "caption", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "show strings", elem: "strings", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "extract CJK unicode strings", elem: "strings", attr: "cjk", choices: &[] },
    SettingField { tab: "General", label: "show tooltips", elem: "tooltips", attr: "enable", choices: &[] },
    SettingField { tab: "General", label: "upper-case hash values", elem: "hashes", attr: "case", choices: &[] },
    SettingField {
        tab: "General",
        label: "Report format:",
        elem: "report",
        attr: "type",
        choices: &[("0", "xml"), ("1", "json"), ("2", "text")],
    },
    SettingField {
        tab: "General",
        label: "Disable strings when file size exceeds:",
        elem: "strings",
        attr: "limit",
        choices: &[("256", "256 KB"), ("378", "378 KB"), ("512", "512 KB"), ("1024", "1024 KB"), ("0", "no-limit")],
    },
    SettingField {
        tab: "Footprints",
        label: "Type of footprints to use:",
        elem: "footprints",
        attr: "type",
        choices: &[("0", "md5"), ("1", "sha1"), ("2", "sha256")],
    },
    SettingField { tab: "Footprints", label: "dos-stub", elem: "footprints", attr: "dos-stub", choices: &[] },
    SettingField { tab: "Footprints", label: "dos-header", elem: "footprints", attr: "dos-header", choices: &[] },
    SettingField { tab: "Footprints", label: "rich-header", elem: "footprints", attr: "rich", choices: &[] },
    SettingField { tab: "Footprints", label: "debug", elem: "footprints", attr: "debug", choices: &[] },
    SettingField { tab: "Footprints", label: "version", elem: "footprints", attr: "version", choices: &[] },
    SettingField { tab: "Footprints", label: "manifest", elem: "footprints", attr: "manifest", choices: &[] },
    SettingField { tab: "Footprints", label: "string-tables", elem: "footprints", attr: "st", choices: &[] },
    SettingField { tab: "Footprints", label: "menus", elem: "footprints", attr: "menu", choices: &[] },
    SettingField { tab: "Footprints", label: "dialogs", elem: "footprints", attr: "dlg", choices: &[] },
    SettingField { tab: "Footprints", label: "icons", elem: "footprints", attr: "icon", choices: &[] },
    SettingField { tab: "Footprints", label: "cursors", elem: "footprints", attr: "cur", choices: &[] },
    SettingField { tab: "Footprints", label: "bitmaps", elem: "footprints", attr: "bmp", choices: &[] },
    SettingField {
        tab: "First-bytes (hex|text)",
        label: "Number of bytes to retrieve:",
        elem: "indicators",
        attr: "bytes",
        choices: &[("16", "16 bytes"), ("32", "32 bytes"), ("64", "64 bytes")],
    },
    SettingField { tab: "Virustotal", label: "enable Virustotal query", elem: "score", attr: "enable", choices: &[] },
    SettingField { tab: "Virustotal", label: "Key to use when proceeding to query:", elem: "score", attr: "key", choices: &[("*", "")] },
    SettingField { tab: "Virustotal", label: "favorite engine(s)", elem: "score", attr: "favorite", choices: &[("*", "")] },
    SettingField { tab: "Virustotal", label: "query overlay score", elem: "overlay", attr: "score", choices: &[] },
    SettingField { tab: "Virustotal", label: "API version", elem: "score", attr: "api", choices: &[("3", "v3"), ("2", "v2")] },
    SettingField { tab: "Virustotal", label: "proxy address", elem: "proxy", attr: "address", choices: &[("*", "")] },
    SettingField { tab: "Virustotal", label: "proxy port", elem: "proxy", attr: "port", choices: &[("*", "")] },
    SettingField {
        tab: "General",
        label: "Instructions to disassemble:",
        elem: "disassembly",
        attr: "count",
        choices: &[("32", "32"), ("64", "64"), ("128", "128"), ("256", "256")],
    },
    SettingField { tab: "YARA", label: "enable YARA scan", elem: "yara", attr: "enable", choices: &[] },
    SettingField { tab: "YARA", label: "YARA rules folder:", elem: "yara", attr: "dir", choices: &[("*", "")] },
];

pub fn setting_tabs() -> Vec<&'static str> {
    let mut v: Vec<&str> = Vec::new();
    for f in SETTING_FIELDS {
        if !v.contains(&f.tab) {
            v.push(f.tab);
        }
    }
    v
}

pub fn setting_default(f: &SettingField) -> &'static str {
    match (f.elem, f.attr) {
        ("footprints", "type") => "2",
        ("indicators", "bytes") => "32",
        ("report", "type") | ("strings", "limit") => "0",
        ("score", "api") => "3",
        ("disassembly", _) => "64",
        ("language", _) => "auto",
        ("score", "key") | ("score", "favorite") | ("proxy", _) | ("yara", "dir") => "",
        ("overlay", "score") | ("strings", "cjk") => "0",
        ("stamps", "epoch") | ("score", "enable") => "0",
        _ => "1",
    }
}

pub fn knowledge_dir_candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(d) = exe_dir {
        v.push(d.join("xml"));
    }
    v.push(PathBuf::from("xml"));
    v.push(PathBuf::from("../xml"));
    v
}

pub fn load_knowledge(explicit: Option<&Path>, exe_dir: Option<&Path>) -> Knowledge {
    if let Some(p) = explicit {
        return Knowledge::load(p);
    }
    match knowledge_dir_candidates(exe_dir).into_iter().find(|c| c.join("settings.xml").exists()) {
        Some(d) => Knowledge::load(d),
        None => builtin_knowledge(pe_db::user_config_dir()),
    }
}

/// The built-in knowledge base with the settings of `config_dir` (theme, language, YARA folder…
/// survive a restart); in memory only when there is no configuration folder.
pub fn builtin_knowledge(config_dir: Option<PathBuf>) -> Knowledge {
    match config_dir {
        Some(d) => Knowledge::builtin_with_user_settings(d.join("settings.xml")),
        None => Knowledge::builtin(),
    }
}
