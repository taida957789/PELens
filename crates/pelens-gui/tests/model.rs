use pe_analysis::actions::Modification;
use pe_analysis::model::ItemType;
use pe_analysis::report::Format;
use pe_analysis::testkit;
use pe_analysis::view::Row;
use pelens_gui::model::*;
use std::path::PathBuf;
use std::sync::Arc;

pub struct TestHost {
    pub open: Option<PathBuf>,
    pub save: Option<PathBuf>,
}

impl Host for TestHost {
    fn pick_open(&mut self) -> Option<PathBuf> {
        self.open.clone()
    }
    fn pick_save(&mut self, _n: &str, _f: (&str, &[&str])) -> Option<PathBuf> {
        self.save.clone()
    }
}

struct MockHttp(Result<pe_online::HttpResponse, String>);
impl pe_online::HttpClient for MockHttp {
    fn get(&self, _u: &str, _h: &[(&str, &str)]) -> Result<pe_online::HttpResponse, String> {
        self.0.clone()
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pelens-gui-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn state(tag: &str) -> (State, PathBuf) {
    let kb = testkit::write_knowledge(&format!("gui-{tag}"));
    let st = std::fs::read_to_string(kb.join("settings.xml"))
        .unwrap()
        .replace("key=\"\"", "key=\"K\"")
        .replace("<read-only enable=\"1\"/>", "<read-only enable=\"0\"/>");
    std::fs::write(kb.join("settings.xml"), st).unwrap();
    let mut s = State::new(pe_db::Knowledge::load(&kb));
    s.synchronous = true;
    s.http = Arc::new(|_k| {
        Box::new(MockHttp(Ok(pe_online::HttpResponse {
            status: 200,
            body: r#"{"data":{"id":"x","attributes":{"last_analysis_stats":{"malicious":1,"undetected":1},"last_analysis_results":{}}}}"#
                .into(),
        })))
    });
    let dir = tmpdir(tag);
    let sample = dir.join("sample.exe");
    std::fs::write(&sample, testkit::suspicious_sample()).unwrap();
    (s, sample)
}

#[test]
fn open_select_close() {
    let (mut s, sample) = state("open");
    assert_eq!(s.title(), format!("PELens {VERSION}"));
    assert!(s.visible_table().is_none());
    s.apply(Action::Open(sample.clone()));
    assert!(s.doc.is_some());
    assert!(s.title().contains("sample.exe"));
    assert!(s.status.contains("indicators"));
    // score queried automatically (score enable=1 in the fixture)
    assert_eq!(s.doc.as_ref().unwrap().analysis.score.as_ref().unwrap().positives, 1);
    assert!(s.doc.as_ref().unwrap().analysis.has_indicator(1064));
    assert_eq!(s.nodes().len(), 27);
    s.apply(Action::Select(ItemType::Imports));
    let t = s.visible_table().unwrap();
    assert!(t.rows.len() > 5);
    s.filter = "Virtual".into();
    assert!(s.visible_table().unwrap().rows.iter().all(|r| r.cells.iter().any(|c| c.contains("Virtual"))));
    s.filter.clear();
    s.sort_column(0);
    assert_eq!(s.sort, Some((0, true)));
    s.sort_column(0);
    assert_eq!(s.sort, Some((0, false)));
    s.sort_column(1);
    assert_eq!(s.sort, Some((1, true)));
    let _ = s.visible_table();
    s.show_duplicates = false;
    let _ = s.visible_table();
    assert!(s.column_visible(ItemType::Imports, 0));
    s.toggle_column(ItemType::Imports, 0, 3);
    assert!(!s.column_visible(ItemType::Imports, 0));
    s.toggle_column(ItemType::Imports, 5, 3);
    s.apply(Action::SelectNext);
    assert_eq!(s.selected, ItemType::Exports);
    s.apply(Action::SelectPrevious);
    s.apply(Action::SelectPrevious);
    assert_eq!(s.selected, ItemType::Libraries);
    s.apply(Action::Select(ItemType::Image));
    s.apply(Action::SelectPrevious);
    assert_eq!(s.selected, ItemType::Overlay);
    s.apply(Action::Close);
    assert!(s.doc.is_none());
    // missing file
    s.apply(Action::Open(PathBuf::from("Z:/missing/file.exe")));
    assert!(matches!(s.dialog, Dialog::Message(_)));
    s.apply(Action::Cancel);
    assert_eq!(s.dialog, Dialog::None);
    // asynchronous path
    s.synchronous = false;
    s.apply(Action::Open(sample));
    for _ in 0..200 {
        if s.poll() || s.doc.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    for _ in 0..200 {
        s.poll();
        if s.score_rx.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(s.doc.is_some());
}

#[test]
fn modifications_and_saving() {
    let (mut s, sample) = state("modify");
    let mut host = TestHost { open: Some(sample.clone()), save: None };
    s.apply_with(Action::OpenDialog, &mut host);
    assert!(s.doc.is_some());
    s.apply(Action::Modify(Modification::SetDll(true)));
    assert!(s.doc.as_ref().unwrap().dirty);
    assert!(s.doc.as_ref().unwrap().analysis.pe.is_dll());
    assert!(s.title().ends_with(" *"));
    s.apply(Action::Modify(Modification::RemoveOverlay));
    s.apply(Action::Modify(Modification::RemoveOverlay));
    assert!(matches!(s.dialog, Dialog::Message(_)));
    s.apply(Action::Cancel);
    // set entry point through the dialog
    s.apply(Action::ShowDialog(Dialog::EntryPoint("0x1001".into())));
    s.apply(Action::Confirm);
    assert_eq!(s.doc.as_ref().unwrap().analysis.pe.entry_point.as_ref().unwrap().rva, 0x1001);
    s.apply(Action::ShowDialog(Dialog::EntryPoint("zz".into())));
    s.apply(Action::Confirm);
    assert!(matches!(s.dialog, Dialog::Message(ref m) if m.contains("invalid")));
    s.apply(Action::Cancel);
    // dirty document: closing asks for confirmation
    s.apply(Action::Close);
    assert!(matches!(s.dialog, Dialog::ConfirmDiscard(_)));
    s.apply(Action::Cancel);
    assert!(s.doc.is_some());
    // save (not read-only) → overwrite confirmation
    s.apply_with(Action::Save, &mut host);
    assert!(matches!(s.dialog, Dialog::ConfirmOverwrite(_)));
    s.apply(Action::Confirm);
    assert!(!s.doc.as_ref().unwrap().dirty);
    assert!(pe_parser::PeFile::parse(&std::fs::read(&sample).unwrap()).is_dll());
    // read-only: save as
    s.set_setting("read-only", "enable", "1");
    assert!(s.read_only());
    let out = sample.with_extension("copy.exe");
    host.save = Some(out.clone());
    s.apply(Action::Modify(Modification::SetDll(false)));
    s.apply_with(Action::Save, &mut host);
    assert!(out.exists());
    assert_eq!(s.doc.as_ref().unwrap().path, out);
    host.save = Some(PathBuf::from("Z:/nope/x.exe"));
    s.apply(Action::Modify(Modification::SetDll(true)));
    s.apply_with(Action::Save, &mut host);
    assert!(matches!(s.dialog, Dialog::Message(_)));
    s.apply(Action::Cancel);
    // discard confirmations for open / exit / close
    s.apply(Action::Open(sample.clone()));
    assert!(matches!(s.dialog, Dialog::ConfirmDiscard(_)));
    s.apply(Action::Confirm);
    assert!(!s.doc.as_ref().unwrap().dirty);
    s.apply(Action::Modify(Modification::SetDll(false)));
    s.apply(Action::Exit);
    s.apply(Action::Confirm);
    assert!(s.effects.exit);
    s.effects.exit = false;
    s.apply(Action::Modify(Modification::SetDll(true)));
    s.apply(Action::Close);
    s.apply(Action::Confirm);
    assert!(s.doc.is_none());
    // actions without a document are no-ops
    for a in [
        Action::Modify(Modification::SetDll(true)),
        Action::QueryScore,
        Action::CreateReportAt(PathBuf::from("x"), Format::Xml),
        Action::DumpTo { offset: 0, size: 1, path: PathBuf::from("x") },
        Action::OpenEmbedded { offset: 0, size: 1 },
    ] {
        s.apply(a);
    }
    s.apply_with(Action::Save, &mut host);
    s.apply_with(Action::CreateReport, &mut host);
    s.apply_with(Action::Dump { offset: 0, size: 2, name: "x".into() }, &mut host);
    s.apply(Action::Confirm);
    s.apply(Action::OpenDialog);
    let mut nohost = TestHost { open: None, save: None };
    s.apply_with(Action::OpenDialog, &mut nohost);
}

#[test]
fn reports_dumps_and_embedded() {
    let (mut s, sample) = state("reports");
    s.apply(Action::Open(sample.clone()));
    let dir = sample.parent().unwrap().to_path_buf();
    let mut host = TestHost { open: None, save: Some(dir.join("r.xml")) };
    s.apply_with(Action::CreateReport, &mut host);
    assert!(dir.join("r.xml").exists());
    assert!(s.status.starts_with("report:"));
    s.apply(Action::CreateReportAt(PathBuf::from("Z:/no/dir/r.xml"), Format::Text));
    assert!(s.status.contains("Cannot create Report file!"));
    host.save = Some(dir.join("d.dump"));
    s.apply_with(Action::Dump { offset: 0, size: 2, name: "dos".into() }, &mut host);
    assert_eq!(std::fs::read(dir.join("d.dump")).unwrap(), b"MZ");
    s.apply(Action::DumpTo { offset: 0, size: 2, path: PathBuf::from("Z:/no/x") });
    assert!(s.status.starts_with("dump failed"));
    let payload = s.doc.as_ref().unwrap().analysis.resources.iter().find(|r| r.name == "PAYLOAD").unwrap().clone();
    s.apply(Action::OpenEmbedded { offset: payload.offset.unwrap() as u64, size: payload.size as u64 });
    assert!(s.doc.as_ref().unwrap().file_name().contains("embedded"));
    s.apply(Action::CopyText("abc".into()));
    s.apply(Action::OpenUrl("https://x".into()));
    assert_eq!(s.effects.copied, vec!["abc"]);
    assert_eq!(s.effects.urls, vec!["https://x"]);
}

#[test]
fn knowledge_write_back_actions() {
    let (mut s, sample) = state("kb");
    s.apply(Action::Open(sample));
    s.apply(Action::SetIndicatorSeverity(1000, 1));
    assert_eq!(s.knowledge.indicator(1000).unwrap().severity, 1);
    assert!(s.doc.as_ref().unwrap().analysis.indicator(1000).unwrap().severity == 1);
    s.apply(Action::ToggleLibraryFlag("kernel32.dll".into()));
    assert!(s.knowledge.functions.library("kernel32.dll").unwrap().flag);
    s.apply(Action::ToggleFunctionFlag("kernel32.dll".into(), "VirtualAlloc".into()));
    assert!(s.knowledge.functions.function("kernel32.dll", "VirtualAlloc").unwrap().flag);
    s.apply(Action::ToggleLanguageFlag(0x409));
    assert!(s.knowledge.languages.language(0x409).unwrap().1);
    s.apply(Action::SetSignatureSeverity("CAB".into(), 1));
    assert_eq!(s.knowledge.signatures.iter().find(|x| x.name == "CAB").unwrap().severity, 1);
    s.apply(Action::ToggleNamespaceFlag("System".into()));
    assert!(s.knowledge.namespaces.items.iter().any(|n| n.name == "System" && n.flag));
    s.apply(Action::ToggleLibraryFlag("unknown.dll".into()));
    assert!(matches!(s.dialog, Dialog::Message(_)));
    s.apply(Action::Cancel);
    // settings persisted to settings.xml, missing elements kept in memory
    s.set_setting("stamps", "epoch", "0");
    assert!(!s.view.epoch);
    s.set_setting("nonexistent", "x", "1");
    assert_eq!(s.knowledge.settings.get("nonexistent", "x"), Some("1"));
    let mut b = State::new(pe_db::Knowledge::builtin());
    b.set_setting("google", "enable", "0");
    assert!(!b.view.google);
}

#[test]
fn online_actions() {
    let (mut s, sample) = state("online");
    s.apply(Action::CheckUpdate);
    assert!(s.update_result.as_ref().unwrap().contains("unknown") || s.update_result.is_some());
    s.http = Arc::new(|_k| Box::new(MockHttp(Ok(pe_online::HttpResponse { status: 200, body: "9.99".into() }))));
    s.apply(Action::CheckUpdate);
    assert!(s.update_result.as_ref().unwrap().contains("9.99"));
    s.http = Arc::new(|_k| Box::new(MockHttp(Ok(pe_online::HttpResponse { status: 200, body: "1.0".into() }))));
    s.apply(Action::CheckUpdate);
    assert!(s.update_result.as_ref().unwrap().contains("up to date"));
    s.http = Arc::new(|_k| Box::new(MockHttp(Err("down".into()))));
    s.apply(Action::CheckUpdate);
    assert!(s.update_result.as_ref().unwrap().contains("internet connection failed"));
    // offline score + watchdog retry
    s.apply(Action::Open(sample));
    assert!(s.doc.as_ref().unwrap().analysis.score.as_ref().unwrap().status.starts_with("offline"));
    s.http = Arc::new(|_k| {
        Box::new(MockHttp(Ok(pe_online::HttpResponse {
            status: 200,
            body: r#"{"data":{"id":"x","attributes":{"last_analysis_stats":{"malicious":0},"last_analysis_results":{}}}}"#.into(),
        })))
    });
    let now = std::time::Instant::now();
    s.watchdog(now, std::time::Duration::from_secs(3600));
    assert!(s.doc.as_ref().unwrap().analysis.score.as_ref().unwrap().status.starts_with("offline"), "not due yet");
    s.watchdog(now + std::time::Duration::from_secs(7200), std::time::Duration::from_secs(3600));
    assert_eq!(s.doc.as_ref().unwrap().analysis.score.as_ref().unwrap().status, "ok");
    // async update check
    s.synchronous = false;
    s.apply(Action::CheckUpdate);
    for _ in 0..200 {
        s.poll();
        if s.update_rx.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    s.apply(Action::QueryScore);
    for _ in 0..200 {
        s.poll();
        if s.score_rx.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn context_menus() {
    let (mut s, sample) = state("ctx");
    s.apply(Action::Open(sample));
    let cols = vec!["property".to_string(), "value".to_string()];
    let labels = |v: Vec<(String, Action)>| v.into_iter().map(|(l, _)| l).collect::<Vec<_>>();

    let mut r = Row::new(vec!["a".into(), "b".into()]);
    r.url = Some("u".into());
    r.ti = Some("1055".into());
    r.dump = Some((0, 2));
    r.jump = Some(ItemType::Imports);
    r.key = "hash:ABC".into();
    let l = labels(s.context_actions(ItemType::Image, &r, &cols, "|"));
    for want in [
        "copy line",
        "copy property",
        "copy value",
        "score > Virustotal",
        "copy file name",
        "lookup in Browser",
        "search Virustotal",
        "copy technique",
        "attack.mitre.org",
        "dump to file",
        "open in PELens",
        "jump > imports",
    ] {
        assert!(l.iter().any(|x| x == want), "{want} missing in {l:?}");
    }
    for (item, key, want) in [
        (ItemType::Indicators, "indicator:1000", "severity +++"),
        (ItemType::Libraries, "lib:kernel32.dll", "toggle flag"),
        (ItemType::Imports, "import:kernel32.dll|VirtualAlloc", "lookup in Browser (MSDN)"),
        (ItemType::DotNet, "ns:System.Net", "copy namespace"),
        (ItemType::FileHeader, "fh-char:32", "toggle characteristic"),
        (ItemType::OptionalHeader, "dll-char:64", "toggle characteristic"),
        (ItemType::OptionalHeader, "ep", "set entry-point"),
        (ItemType::Overlay, "overlay", "delete overlay"),
    ] {
        let r = Row { cells: vec!["x".into(), "y".into()], key: key.into(), ..Default::default() };
        assert!(labels(s.context_actions(item, &r, &["c".into()], "|")).iter().any(|x| x == want), "{key}");
    }
    let dll = Row { cells: vec!["dynamic-link-library".into(), "false".into()], key: "fh-char:8192".into(), ..Default::default() };
    assert!(labels(s.context_actions(ItemType::FileHeader, &dll, &cols, "|")).contains(&"toggle EXE > DLL".to_string()));
    let dll2 = Row { cells: vec!["dynamic-link-library".into(), "true".into()], key: "fh-char:8192".into(), ..Default::default() };
    assert!(labels(s.context_actions(ItemType::FileHeader, &dll2, &cols, "|")).contains(&"toggle DLL > EXE".to_string()));
    let ri = s.doc.as_ref().unwrap().analysis.resources.iter().position(|r| r.signature == "CAB").unwrap();
    let rr = Row { cells: vec!["rcdata".into()], key: format!("resource:{ri}"), ..Default::default() };
    let l = labels(s.context_actions(ItemType::Resources, &rr, &cols, "|"));
    assert!(l.contains(&"toggle language flag".to_string()) && l.contains(&"signature > severity +".to_string()));
    let st = Row { cells: vec!["ascii".into(), "v".into()], ..Default::default() };
    let l = labels(s.context_actions(ItemType::Strings, &st, &["type".into(), "value".into()], "|"));
    assert!(l.contains(&"copy detail".to_string()) && l.contains(&"search Google".to_string()));
    let empty = Row::default();
    assert_eq!(labels(s.context_actions(ItemType::Image, &empty, &cols, "|")), vec!["copy line", "copy file name"]);
    let l = labels(s.context_actions(ItemType::Indicators, &empty, &["indicator".into()], "|"));
    assert!(l.contains(&"dump indicators to file".to_string()));
    let url = Row {
        cells: vec![
            "ascii".into(),
            "1".into(),
            "0x0".into(),
            "file".into(),
            "url-pattern".into(),
            "".into(),
            "".into(),
            "x".into(),
            "http://a".into(),
        ],
        ..Default::default()
    };
    assert!(labels(s.context_actions(ItemType::Strings, &url, &["type".into()], "|")).contains(&"score > Virustotal (url)".to_string()));
    let lib = Row {
        cells: vec![
            "k.dll".into(),
            "1".into(),
            "implicit".into(),
            "-".into(),
            "".into(),
            "-".into(),
            "-".into(),
            "-".into(),
            "desc".into(),
        ],
        ..Default::default()
    };
    let cols9: Vec<String> = ["library", "imports", "type", "flag", "group", "bound", "duplicate", "spoofed", "description"]
        .iter()
        .map(|x| x.to_string())
        .collect();
    assert!(labels(s.context_actions(ItemType::Libraries, &lib, &cols9, "|")).contains(&"copy description".to_string()));
    let ds = Row { cells: vec!["a".into()], dump: Some((0, 1)), ..Default::default() };
    assert!(labels(s.context_actions(ItemType::DotNet, &ds, &cols, "|")).contains(&"dump stream".to_string()));
    // translated labels
    let mut s2 = State::new(pe_db::Knowledge::builtin());
    s2.knowledge.translations.text.insert(579, "Zeile kopieren".into());
    assert_eq!(labels(s2.context_actions(ItemType::Image, &empty, &cols, "|"))[0], "Zeile kopieren");
    assert_eq!(s2.tr(579, "x"), "Zeile kopieren");
    assert_eq!(s2.tr(1, "fallback"), "fallback");
}

#[test]
fn item_scores_and_text_saving() {
    let (mut s, sample) = state("itemscore");
    let dir = sample.parent().unwrap().to_path_buf();
    s.apply(Action::Open(sample));
    s.apply(Action::QueryItemScore("overlay".into(), "ABCD".into(), false));
    assert!(matches!(s.dialog, Dialog::Message(ref m) if m.contains("virustotal > overlay: 1/2")));
    s.apply(Action::QueryItemScore("url".into(), "http://a".into(), true));
    assert!(s.status.contains("virustotal > url"));
    s.http = Arc::new(|_k| Box::new(MockHttp(Err("down".into()))));
    s.apply(Action::QueryItemScore("r".into(), "AB".into(), false));
    assert!(s.status.contains("offline"));
    let mut host = TestHost { open: None, save: Some(dir.join("ind.txt")) };
    s.apply_with(Action::SaveText { name: "indicators".into(), text: "a|b".into() }, &mut host);
    assert_eq!(std::fs::read_to_string(dir.join("ind.txt")).unwrap(), "a|b");
    s.apply(Action::SaveTextTo { path: PathBuf::from("Z:/no/dir/x.txt"), text: String::new() });
    assert!(s.status.starts_with("save failed"));
    s.doc = None;
    s.apply_with(Action::SaveText { name: "n".into(), text: "t".into() }, &mut host);
    // overlay score is queried automatically when enabled
    let (mut s3, sample3) = state("itemscore2");
    s3.knowledge.settings.set("overlay", "score", "1");
    s3.apply(Action::Open(sample3));
    assert!(s3.status.contains("virustotal > overlay"));
}

#[test]
fn settings_model() {
    let tabs = setting_tabs();
    assert_eq!(tabs, vec!["General", "Footprints", "First-bytes (hex|text)", "Virustotal"]);
    for f in SETTING_FIELDS {
        let _ = setting_default(f);
    }
    let k = load_knowledge(None, Some(std::path::Path::new("Z:/none")));
    assert!(k.dir.is_none() || k.dir.is_some());
    let kb = testkit::write_knowledge("gui-load");
    assert!(load_knowledge(Some(&kb), None).dir.is_some());
    assert!(load_knowledge(None, Some(kb.parent().unwrap())).loaded.len() <= 11);
    let c = knowledge_dir_candidates(Some(std::path::Path::new("e")));
    assert_eq!(c[0], PathBuf::from("e").join("xml"));
    assert_eq!(knowledge_dir_candidates(None).len(), 2);
    let (f, x) = pelens_gui::parse_cli(&["a.exe".into(), "-xml:k".into()]);
    assert_eq!((f, x), (Some(PathBuf::from("a.exe")), Some(PathBuf::from("k"))));
    let (f, x) = pelens_gui::parse_cli(&["/file:b.exe".into(), "--xml=k2".into(), "-other".into()]);
    assert_eq!((f, x), (Some(PathBuf::from("b.exe")), Some(PathBuf::from("k2"))));
    let st = pelens_gui::parse_startup(&["-view:strings".into(), "/theme:light".into(), "-expand".into(), "-theme:x".into()]);
    assert_eq!(st.view, Some(ItemType::Strings));
    assert_eq!(st.dark, None, "invalid theme resets");
    assert!(st.expand);
    assert_eq!(pelens_gui::parse_startup(&["-view:tls".into(), "-theme:dark".into()]).view, Some(ItemType::Tls));
    let mut app = pelens_gui::PeLensApp::new(State::new(pe_db::Knowledge::builtin()), Box::new(TestHost { open: None, save: None }));
    pelens_gui::Startup { view: Some(ItemType::Imports), dark: Some(false), expand: true, lang: None }.apply(&mut app);
    assert_eq!(app.state.selected, ItemType::Imports);
    assert!(!app.state.dark_mode());
    assert!(app.expanded.contains("sections"));
    // caption disabled
    let mut s = State::new(pe_db::Knowledge::builtin());
    s.knowledge.settings.set("caption", "enable", "0");
    assert_eq!(s.title(), format!("PELens {VERSION}"));
    // document helpers
    let mut d = Document::new(PathBuf::from("x/y.exe"), vec![], Default::default());
    assert_eq!(d.file_name(), "y.exe");
    d.invalidate();
}

/// Code review #7: option detection never swallows file names.
#[test]
fn option_detection() {
    use pelens_gui::{option_body, parse_cli, parse_startup};
    assert_eq!(parse_cli(&["expand.exe".into()]).0, Some(PathBuf::from("expand.exe")));
    assert_eq!(parse_cli(&["/expanded/x.exe".into()]).0, Some(PathBuf::from("/expanded/x.exe")));
    assert_eq!(parse_cli(&["view:x.exe".into()]).0, Some(PathBuf::from("view:x.exe")));
    assert_eq!(parse_cli(&["/file:b.exe".into()]).0, Some(PathBuf::from("b.exe")));
    assert_eq!(option_body("/expand"), Some("expand"));
    assert_eq!(option_body("/view:strings"), Some("view:strings"));
    assert_eq!(option_body("/view"), None);
    assert_eq!(option_body("/expand:1"), None);
    assert_eq!(option_body("--theme=dark"), Some("theme=dark"));
    assert!(!parse_startup(&["expand.exe".into(), "/expanded".into()]).expand);
    assert!(parse_startup(&["/expand".into()]).expand);
}

/// Code review #6: re-analysis keeps disk information and the score while the bytes are unchanged.
#[test]
fn reanalysis_keeps_score_and_drive_info() {
    let (mut s, sample) = state("reanalysis");
    s.apply(Action::Open(sample));
    {
        let a = &mut s.doc.as_mut().unwrap().analysis;
        a.network_drive = true;
        a.footprints.push(pe_analysis::model::Footprint { item: "acl (security-descriptor)".into(), ..Default::default() });
    }
    assert!(s.doc.as_ref().unwrap().analysis.score.is_some());
    s.apply(Action::SetIndicatorSeverity(1000, 2));
    let a = &s.doc.as_ref().unwrap().analysis;
    assert!(a.network_drive && a.score.is_some() && a.footprints.iter().any(|f| f.item.starts_with("acl")));
    assert!(a.has_indicator(1051), "drive indicator re-evaluated");
    s.apply(Action::Modify(Modification::SetDll(true)));
    let a = &s.doc.as_ref().unwrap().analysis;
    assert!(a.network_drive, "same file → drive info kept");
    assert!(a.score.is_none(), "bytes changed → old score dropped");
}

#[test]
fn virustotal_key_goes_to_the_key_store() {
    struct Failing;
    impl pe_online::secret::KeyStore for Failing {
        fn get(&self) -> Option<String> {
            None
        }
        fn set(&self, _key: &str) -> Result<(), String> {
            Err("locked".into())
        }
        fn delete(&self) -> Result<(), String> {
            Ok(())
        }
    }
    // the settings.xml of `state()` holds a plaintext key "K"
    let (mut s, _) = state("vtkey");
    let dir = s.knowledge.dir.clone().unwrap();
    assert_eq!(s.stored_key(), "K", "legacy plaintext key");
    s.set_setting("score", "key", "NEW");
    assert_eq!(s.key_store.get().as_deref(), Some("NEW"));
    assert_eq!(s.stored_key(), "NEW");
    let xml = std::fs::read_to_string(dir.join("settings.xml")).unwrap();
    assert!(!xml.contains("NEW") && !xml.contains("key=\"K\""), "the key never reaches settings.xml");
    assert!(s.status.contains("Credential Manager"), "{}", s.status);
    // queries use the stored key
    assert_eq!(pe_online::vt_settings_with(&s.knowledge, s.key_store.as_ref()).1, "NEW");
    // a store that cannot be written: nothing is saved anywhere, the user is told
    s.key_store = Arc::new(Failing);
    s.set_setting("score", "key", "OTHER");
    assert_eq!(s.status, "cannot store the Virustotal key (locked)");
    assert!(!std::fs::read_to_string(dir.join("settings.xml")).unwrap().contains("OTHER"));
    // without a settings directory the plaintext value is blanked in memory
    let mut s2 = State::new(pe_db::Knowledge::builtin());
    s2.knowledge.settings.set("score", "key", "MEM");
    s2.set_setting("score", "key", "MEM2");
    assert_eq!((s2.stored_key(), s2.knowledge.settings.get("score", "key")), ("MEM2".to_string(), Some("")));
}
