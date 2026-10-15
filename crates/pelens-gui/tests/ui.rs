use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use pe_analysis::model::ItemType;
use pe_analysis::testkit;
use pelens_gui::PeLensApp;
use pelens_gui::model::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct TestHost {
    open: Option<PathBuf>,
    save: Option<PathBuf>,
}

impl Host for TestHost {
    fn pick_open(&mut self) -> Option<PathBuf> {
        self.open.clone()
    }
    fn pick_save(&mut self, _n: &str, _f: (&str, &[&str])) -> Option<PathBuf> {
        self.save.clone()
    }
}

struct MockHttp;
impl pe_online::HttpClient for MockHttp {
    fn get(&self, url: &str, _h: &[(&str, &str)]) -> Result<pe_online::HttpResponse, String> {
        let body = if url.contains("/releases/latest") {
            r#"{"tag_name":"v9.99"}"#.to_string()
        } else {
            r#"{"data":{"id":"x","attributes":{"last_analysis_stats":{"malicious":2,"undetected":3},"last_analysis_results":{"Eng":{"category":"malicious","result":"Bad"}}}}}"#.to_string()
        };
        Ok(pe_online::HttpResponse { status: 200, body })
    }
}

#[derive(Debug)]
struct Dropped(PathBuf);
impl egui::DroppedFile for Dropped {
    fn path(&self) -> &Path {
        &self.0
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        std::fs::read(&self.0).map_err(|e| e.to_string())
    }
}

fn setup(tag: &str) -> (PeLensApp, PathBuf) {
    let kb = testkit::write_knowledge(&format!("ui-{tag}"));
    let st = std::fs::read_to_string(kb.join("settings.xml"))
        .unwrap()
        .replace("key=\"\"", "key=\"K\"")
        .replace("<read-only enable=\"1\"/>", "<read-only enable=\"0\"/>");
    std::fs::write(kb.join("settings.xml"), st).unwrap();
    let mut s = State::new(pe_db::Knowledge::load(&kb));
    s.synchronous = true;
    s.http = Arc::new(|_k| Box::new(MockHttp));
    let dir = std::env::temp_dir().join(format!("pestudio-ui-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sample = dir.join("sample.exe");
    std::fs::write(&sample, testkit::suspicious_sample()).unwrap();
    let host = TestHost { open: Some(sample.clone()), save: Some(dir.join("out.bin")) };
    (PeLensApp::new(s, Box::new(host)), sample)
}

fn harness(app: PeLensApp) -> Harness<'static, PeLensApp> {
    Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_ui_state(|ui, app: &mut PeLensApp| app.draw(ui), app)
}

#[test]
fn empty_window_and_menus() {
    let (app, _) = setup("empty");
    let mut h = harness(app);
    h.run();
    assert!(h.query_all_by_label("drag-and-drop a file to analyse...").count() >= 1);
    h.get_by_label("about").click();
    h.run();
    assert!(h.query_by_label("PELens | about").is_some());
    h.get_by_label("Check online for an update").click();
    h.run();
    assert!(h.state().state.update_result.as_ref().unwrap().contains("9.99"));
    h.state_mut().state.dialog = Dialog::None;
    h.get_by_label("settings").click();
    h.run();
    for tab in setting_tabs() {
        h.get_by_label(tab).click();
        h.run();
    }
    h.get_by_label("General").click();
    h.run();
    h.get_by_label("show Epoch stamps").click();
    h.run();
    assert_eq!(h.state().state.knowledge.settings.get("stamps", "epoch"), Some("0"));
    h.get_by_label("json").click();
    h.run();
    assert_eq!(h.state().state.knowledge.settings.get("report", "type"), Some("1"));
    h.get_by_label("Virustotal").click();
    h.run();
    h.state_mut().state.dialog = Dialog::None;
    h.run();
    // file menu → open
    h.get_by_label("file").click();
    h.run();
    h.get_by_label(&menu("open file", "O")).click();
    h.run();
    assert!(h.state().state.doc.is_some());
}

#[test]
fn browse_every_view() {
    let (mut app, sample) = setup("browse");
    app.state.apply(Action::Open(sample.clone()));
    let mut h = harness(app);
    h.run();
    assert!(h.query_by_label(&sample.display().to_string()).is_some());
    // tree navigation by clicking each node
    let nodes = h.state().state.nodes();
    for t in nodes {
        let label = {
            let a = &h.state().state.doc.as_ref().unwrap().analysis;
            let f = a.flagged_count(t);
            if f > 0 { format!("{} ({f})", t.name()) } else { t.name().to_string() }
        };
        h.get_all_by_label(&label).next().unwrap().click();
        h.run();
        assert_eq!(h.state().state.selected, t);
    }
    // keyboard: Tab / Shift+Tab
    h.state_mut().state.apply(Action::Select(ItemType::Image));
    h.run();
    h.key_press(egui::Key::Tab);
    h.run();
    assert_eq!(h.state().state.selected, ItemType::Footprints);
    h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Tab);
    h.run();
    assert_eq!(h.state().state.selected, ItemType::Image);
}

#[test]
fn table_interactions() {
    let (mut app, sample) = setup("table");
    app.state.apply(Action::Open(sample));
    app.state.apply(Action::Select(ItemType::Libraries));
    let mut h = harness(app);
    h.run();
    // sort by clicking the header
    h.get_by_label("library").click();
    h.run();
    assert_eq!(h.state().state.sort, Some((0, true)));
    // select a row then right click for the context menu
    h.get_by_label("ws2_32.dll").click();
    h.run();
    assert!(h.state().state.selected_row.is_some());
    h.get_by_label("ws2_32.dll").click_secondary();
    h.run();
    h.get_by_label("copy line").click();
    h.run();
    assert_eq!(h.state().state.status, "copy to clipboard");
    // column chooser
    h.get_by_label("column").click();
    h.run();
    h.get_all_by_label("imports").last().unwrap().click();
    h.run();
    assert!(!h.state().state.column_visible(ItemType::Libraries, 1));
    // double click a jump row (libraries → imports)
    h.state_mut().state.dialog = Dialog::None;
    h.get_by_label("ws2_32.dll").click();
    h.get_by_label("ws2_32.dll").click();
    h.run();
    // resources: selecting a row shows its decoded content
    h.state_mut().state.apply(Action::Select(ItemType::Resources));
    h.run();
    h.get_by_label("string-table").click();
    h.run();
    assert!(h.query_by_label("0: test").is_some());
    // search box + save the current view
    h.state_mut().state.apply(Action::Select(ItemType::Strings));
    h.run();
    h.get_by_label("save to file").click();
    h.run();
    assert!(h.state().state.status.starts_with("save to file:"));
    h.state_mut().state.filter = "evil".into();
    h.run();
    assert!(h.state_mut().state.visible_table().unwrap().rows.len() >= 2);
}

#[test]
fn dialogs_and_shortcuts() {
    let (mut app, sample) = setup("dialogs");
    app.state.apply(Action::Open(sample.clone()));
    let mut h = harness(app);
    h.run();
    // entry point dialog
    h.state_mut().state.dialog = Dialog::EntryPoint(String::new());
    h.run();
    for n in h.get_all_by_role(egui::accesskit::Role::TextInput) {
        n.type_text("2");
    }
    h.run();
    h.state_mut().state.dialog = Dialog::EntryPoint("0x1002".into());
    h.run();
    h.get_by_label("proceed").click();
    h.run();
    assert_eq!(h.state().state.doc.as_ref().unwrap().analysis.pe.entry_point.as_ref().unwrap().rva, 0x1002);
    // message dialog
    h.state_mut().state.dialog = Dialog::Message("hello".into());
    h.run();
    h.get_by_label("OK").click();
    h.run();
    assert_eq!(h.state().state.dialog, Dialog::None);
    // confirm discard (dirty document) → cancel
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::E);
    h.run();
    assert!(matches!(h.state().state.dialog, Dialog::ConfirmDiscard(_)));
    h.get_by_label("Cancel").click();
    h.run();
    // save with overwrite confirmation
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::S);
    h.run();
    assert!(matches!(h.state().state.dialog, Dialog::ConfirmOverwrite(_)));
    h.get_by_label("proceed").click();
    h.run();
    assert!(!h.state().state.doc.as_ref().unwrap().dirty);
    // report shortcut writes to the host path
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::R);
    h.run();
    assert!(h.state().state.status.starts_with("report:"));
    // open shortcut
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::O);
    h.run();
    // drag and drop
    h.input_mut().dropped_files.push(Arc::new(Dropped(sample.clone())));
    h.run();
    assert!(h.state().state.doc.is_some());
    // close and exit shortcuts
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::E);
    h.run();
    assert!(h.state().state.doc.is_none());
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::X);
    h.run();
    assert!(h.state().exit_requested);
}

#[test]
fn file_menu_and_copy_effects() {
    let (mut app, sample) = setup("menu");
    app.state.apply(Action::Open(sample));
    app.watchdog_every = std::time::Duration::from_millis(0);
    let mut h = harness(app);
    h.run();
    for item in [menu("save file", "S"), menu("create report", "R"), menu("close file", "E")] {
        h.get_by_label("file").click();
        h.run();
        h.get_by_label(&item).click();
        h.run();
        h.state_mut().state.dialog = Dialog::None;
        h.run();
    }
    assert!(h.state().state.doc.is_none());
    h.get_by_label("file").click();
    h.run();
    h.get_by_label(&menu("exit PELens", "X")).click();
    h.run();
    assert!(h.state().exit_requested);
    // url and title effects are forwarded to the context
    h.state_mut().state.apply(Action::OpenUrl("https://example.com".into()));
    h.state_mut().state.apply(Action::CopyText("x".into()));
    h.run();
    // busy spinner path
    let (tx, rx) = std::sync::mpsc::channel();
    h.state_mut().state.busy = Some(rx);
    h.step();
    drop(tx);
    h.state_mut().state.busy = None;
    h.run();
}

#[test]
fn tree_view_theme_and_layout() {
    let (mut app, sample) = setup("tree");
    app.state.apply(Action::Open(sample.clone()));
    let mut h = harness(app);
    h.run();
    assert!(h.state().state.dark_mode(), "dark mode is the default");
    assert!(!h.state().fonts_loaded.is_empty());
    // expand the sub-trees and pick children
    h.state_mut().expand_all(true);
    h.run();
    let high = h.state().state.tree_children(ItemType::Indicators)[0].0.clone();
    h.get_by_label(&high).click();
    h.run();
    assert_eq!(h.state().state.selected, ItemType::Indicators);
    assert_eq!(h.state().state.filter, "high");
    h.get_by_label(".upx0").click();
    h.run();
    assert_eq!((h.state().state.selected, h.state().state.filter.as_str()), (ItemType::Sections, ".upx0"));
    // clear search button
    h.get_by_label("⌫").click();
    h.run();
    assert!(h.state().state.filter.is_empty());
    let rc = h.state().state.tree_children(ItemType::Resources);
    assert!(rc.iter().any(|(l, _, f)| l.starts_with("rcdata") && *f));
    h.get_by_label(&rc[0].0).click();
    h.run();
    assert!(h.state().state.tree_children(ItemType::Libraries).iter().any(|(_, f, fl)| f == "evil lib" && *fl));
    assert!(h.state().state.tree_children(ItemType::Image).is_empty());
    // collapse via toggle and menu
    h.state_mut().toggle(ItemType::Sections.name());
    h.state_mut().expand_all(false);
    h.state_mut().toggle("root");
    h.run();
    h.state_mut().toggle("root");
    h.run();
    h.get_by_label("view").click();
    h.run();
    h.get_by_label("expand all").click();
    h.run();
    h.get_by_label("view").click();
    h.run();
    h.get_by_label("collapse all").click();
    h.run();
    // toggle the theme from the menu and the toolbar
    h.get_by_label("view").click();
    h.run();
    h.get_by_label("light mode").click();
    h.run();
    assert!(!h.state().state.dark_mode());
    assert!(!h.state().palette.dark);
    h.get_by_label("🌙").click();
    h.run();
    assert!(h.state().state.dark_mode());
    // toolbar buttons
    for icon in ["🛡", "📝", "⚙"] {
        h.get_by_label(icon).click();
        h.run();
        h.state_mut().state.dialog = Dialog::None;
        h.run();
    }
    // resources view with decoded content panel
    h.state_mut().state.apply(Action::Select(ItemType::Resources));
    h.run();
    h.get_by_label("string-table").click();
    h.run();
    h.get_by_label("string-table").click();
    h.run();
    // dirty status + strings location map + hover tooltips
    h.state_mut().state.apply(Action::Modify(pe_analysis::actions::Modification::SetDll(true)));
    h.state_mut().state.apply(Action::Select(ItemType::Strings));
    h.run();
    if let Some(n) = h.get_all_by_label("strings").next() {
        n.hover()
    }
    h.run();
    assert!(h.query_by_label("modified").is_some());
    let l = pelens_gui::theme::font_definitions(&[std::path::PathBuf::from("Z:/nope")], pelens_gui::i18n::Lang::En).1;
    assert!(l.is_empty());
    assert!(pelens_gui::theme::is_mono_column("md5") && !pelens_gui::theme::is_mono_column("name"));
    for t in ItemType::ALL {
        assert!(!pelens_gui::theme::icon(t).is_empty());
    }
}

#[test]
fn interface_language_switch() {
    use pelens_gui::i18n::Lang;
    let (mut app, sample) = setup("lang");
    app.state.apply(Action::Open(sample));
    let mut h = harness(app);
    h.run();
    // view > language > 日本語
    h.get_by_label("view").click();
    h.run();
    h.get_by_label("language ⏵").hover();
    h.run();
    h.get_by_label("日本語").click();
    h.run();
    assert_eq!(h.state().state.lang, Lang::Ja);
    assert!(!h.state().fonts_loaded.is_empty());
    // menus, tree, header and columns are translated
    assert!(h.query_by_label("ファイル").is_some());
    assert!(h.query_by_label_contains("インジケーター (").is_some());
    assert!(h.query_by_label_contains("セクション").is_some() && h.query_by_label("イメージ").is_some());
    h.state_mut().state.apply(Action::Select(ItemType::Libraries));
    h.run();
    assert!(h.query_all_by_label("ライブラリ").count() >= 2, "heading and column header");
    assert!(h.query_by_label("検索をクリア").is_none() && h.query_by_label("重複を表示").is_some());
    h.get_by_label("ファイル").click();
    h.run();
    assert!(h.query_by_label(&menu("ファイルを開く", "O")).is_some());
    h.key_press(egui::Key::Escape);
    h.run();
    // settings: the language drop-down
    h.state_mut().state.apply(Action::ShowDialog(Dialog::Settings));
    h.run();
    assert!(h.query_by_label("全般").is_some());
    let combo = h.get_by_role(egui::accesskit::Role::ComboBox);
    assert_eq!(combo.value().as_deref(), Some("日本語"));
    combo.click();
    h.run();
    h.get_by_label("Deutsch").click();
    h.run();
    assert_eq!(h.state().state.lang, Lang::De);
    h.get_by_role(egui::accesskit::Role::ComboBox).click();
    h.run();
    h.get_by_label("automatisch (System)").click();
    h.run();
    assert_eq!(h.state().state.language_setting(), None);
    h.get_by_role(egui::accesskit::Role::ComboBox).click();
    h.run();
    h.get_by_label("English").click();
    h.run();
    assert_eq!(h.state().state.lang, Lang::En);
    assert!(h.query_by_label("General").is_some());
    // back to the system language
    h.state_mut().state.apply(Action::SetLanguage(None));
    h.run();
    assert_eq!(h.state().state.language_setting(), None);
}

#[test]
fn hex_panel() {
    let (mut app, sample) = setup("hex");
    app.state.apply(Action::Open(sample));
    let mut h = harness(app);
    h.run();
    // view > hex view (Ctrl+H)
    h.get_by_label("view").click();
    h.run();
    h.get_by_label(&menu("hex view", "H")).click();
    h.run();
    assert!(h.state().state.hex.open);
    assert!(h.query_by_label_contains("4D 5A").is_some(), "first line of the file");
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::H);
    h.run();
    assert!(!h.state().state.hex.open);
    // a range from the sections view, copied as hex and text
    h.state_mut().state.apply(Action::ShowHex(0, 2));
    h.run();
    h.get_by_label("copy as hex").click();
    h.run();
    h.get_by_label("copy as text").click();
    h.run();
    assert!(h.query_by_label_contains("(2 bytes)").is_some());
    // go to an offset with Enter, then show RVAs
    h.state_mut().state.hex.goto = "0x40".into();
    h.run();
    h.get_by_label("RVA").click();
    h.run();
    h.state_mut().state.hex.rva = false;
    h.state_mut().state.apply(Action::HexGoto);
    h.run();
    assert_eq!(h.state().state.hex.range, Some((0x40, 1)));
    // with the hex view open, clicking a row with a range moves the view there
    h.state_mut().state.apply(Action::Select(ItemType::Sections));
    h.run();
    h.get_by_label(".rdata").click();
    h.run();
    let rdata =
        h.state().state.doc.as_ref().unwrap().analysis.sections.iter().find(|s| s.name == ".rdata").map(|s| (s.raw_address, s.raw_size));
    assert_eq!(h.state().state.hex.range, rdata);
    h.get_by_label("close").click();
    h.run();
    assert!(!h.state().state.hex.open);
}

/// A menu entry with its shortcut (⌘ on macOS, Ctrl elsewhere).
fn menu(label: &str, key: &str) -> String {
    format!("{label}\t{}", pelens_gui::ui::shortcut(key))
}
