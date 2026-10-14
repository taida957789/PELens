use pe_analysis::model::ItemType;
use pe_analysis::testkit;
use pelens_gui::i18n::{self, Lang};
use pelens_gui::model::*;
use std::collections::BTreeSet;

/// Keys that are not written as a literal inside t()/tf()/tr() in the sources.
const EXTRA: &[&str] = &[
    IDLE,
    "light mode",
    "dark mode",
    "toggle DLL > EXE",
    "toggle EXE > DLL",
    "severity +++",
    "severity ++",
    "severity +",
    "signature > severity +++",
    "signature > severity ++",
    "signature > severity +",
    "high",
    "medium",
    "low",
    "(nameless)",
    "overlay",
    "url",
    "auto (system)",
    "no-limit",
    "16 bytes",
    // credential store names (pe_online::secret::STORE_NAME on each platform)
    "Windows Credential Manager",
    "macOS Keychain",
    "Secret Service keyring",
    "32 bytes",
    "64 bytes",
];

fn keys(lang: Lang) -> BTreeSet<&'static str> {
    lang.catalog().keys().copied().collect()
}

fn placeholders(s: &str) -> BTreeSet<String> {
    (0..10).map(|i| format!("{{{i}}}")).filter(|p| s.contains(p.as_str())).collect()
}

/// String literals given to t( / tf( / tip( / tr(N, / t(N, in the GUI sources.
fn source_keys() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in ["src/model.rs", "src/ui.rs"] {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).unwrap();
        for (i, _) in src.match_indices('(') {
            let head = &src[..i];
            let name: String = head.chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>();
            let name: String = name.chars().rev().collect();
            if !matches!(name.as_str(), "t" | "tf" | "tip" | "tr") || head[..head.len() - name.len()].ends_with("fn ") {
                continue;
            }
            let mut rest = &src[i + 1..];
            // tr(607, "close file") / t(579, "copy line")
            if let Some(after) = rest.split_once(", ").filter(|(n, _)| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty()) {
                rest = after.1;
            }
            let Some(lit) = rest.strip_prefix('"') else { continue };
            let mut key = String::new();
            let mut chars = lit.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => key.push(match chars.next() {
                        Some('t') => '\t',
                        Some('n') => '\n',
                        Some(o) => o,
                        None => break,
                    }),
                    c => key.push(c),
                }
            }
            out.insert(key);
        }
    }
    out
}

#[test]
fn catalogs_are_complete_and_consistent() {
    let reference = keys(Lang::ZhTw);
    assert!(reference.len() > 200);
    assert!(Lang::En.catalog().is_empty(), "English is the key language");
    for l in Lang::ALL.into_iter().filter(|l| *l != Lang::En) {
        let k = keys(l);
        let missing: Vec<_> = reference.difference(&k).collect();
        let extra: Vec<_> = k.difference(&reference).collect();
        assert!(missing.is_empty() && extra.is_empty(), "{}: missing {missing:?}, extra {extra:?}", l.code());
        for (key, val) in l.catalog() {
            assert!(!val.trim().is_empty(), "{}: empty translation of {key:?}", l.code());
            assert_eq!(placeholders(key), placeholders(val), "{}: placeholders of {key:?}", l.code());
        }
    }
    // everything the interface asks for is translated
    let mut wanted: BTreeSet<String> = source_keys();
    assert!(wanted.contains("open file") && wanted.contains("close file") && wanted.contains("{0} items"), "{wanted:?}");
    wanted.extend(EXTRA.iter().map(|s| s.to_string()));
    wanted.extend(ItemType::ALL.iter().map(|t| t.name().to_string()));
    wanted.extend(SETTING_FIELDS.iter().flat_map(|f| [f.tab.to_string(), f.label.to_string()]));
    // every column of every view
    let k = testkit::knowledge("i18n-cols");
    for sample in [testkit::suspicious_sample(), testkit::dotnet_sample()] {
        let a = pe_analysis::analyze(&sample, "s.exe", &k, &pe_analysis::Options::default());
        let o = pe_analysis::view::ViewOptions::from_settings(&k);
        for t in ItemType::ALL {
            wanted.extend(pe_analysis::view::table(&a, &k, &sample, t, &o).columns);
        }
    }
    let missing: Vec<_> = wanted.iter().filter(|w| !reference.contains(w.as_str())).collect();
    assert!(missing.is_empty(), "untranslated interface text: {missing:?}");
}

#[test]
fn language_codes_and_helpers() {
    for l in Lang::ALL {
        assert_eq!(Lang::from_code(l.code()), Some(l));
        assert!(!l.native_name().is_empty());
    }
    assert_eq!(Lang::from_code("zh_TW.UTF-8"), Some(Lang::ZhTw));
    assert_eq!(Lang::from_code("zh-Hant-HK"), Some(Lang::ZhTw));
    assert_eq!(Lang::from_code("zh-HK"), Some(Lang::ZhTw));
    assert_eq!(Lang::from_code("zh-Hans-SG"), Some(Lang::ZhCn));
    assert_eq!(Lang::from_code("ZH"), Some(Lang::ZhCn));
    assert_eq!(Lang::from_code("de-AT"), Some(Lang::De));
    assert_eq!(Lang::from_code("en-US"), Some(Lang::En));
    assert_eq!(Lang::from_code("fr_CA@euro"), Some(Lang::Fr));
    assert_eq!(Lang::from_code("pt-BR"), None);
    assert_eq!(Lang::from_code(""), None);
    assert_eq!(Lang::from_code("auto"), None);
    let _ = i18n::system_lang();
    assert_eq!(i18n::translate(Lang::De, "open file"), "Datei öffnen");
    assert_eq!(i18n::translate(Lang::De, "no such text"), "no such text");
    assert_eq!(i18n::translate(Lang::En, "open file"), "open file");
    assert_eq!(i18n::fill("{1} / {0} / {1}", &[&"a", &2]), "2 / a / 2");
    let c = i18n::parse_catalog("# comment\n\na\tb\r\nno-tab line\nc\t\n");
    assert_eq!((c.get("a"), c.get("c"), c.len()), (Some(&"b"), Some(&""), 2));
}

#[test]
fn state_follows_the_language_setting() {
    let kb = testkit::write_knowledge("i18n-state");
    let mut s = State::new(pe_db::Knowledge::load(&kb));
    s.synchronous = true;
    assert_eq!(s.lang, Lang::En);
    assert_eq!(s.status, IDLE);
    // the system language applies while the setting is "auto" / missing
    s.set_system_lang(Lang::Ja);
    assert_eq!((s.lang, s.language_setting()), (Lang::Ja, None));
    assert_eq!(s.status, "解析するファイルをドラッグ＆ドロップしてください...");
    // an explicit choice is saved to settings.xml and wins over the system language
    s.apply(Action::SetLanguage(Some(Lang::ZhTw)));
    assert_eq!(s.lang, Lang::ZhTw);
    assert!(std::fs::read_to_string(kb.join("settings.xml")).unwrap().contains("code=\"zh-TW\""));
    let reloaded = State::new(pe_db::Knowledge::load(&kb));
    assert_eq!(reloaded.lang, Lang::ZhTw);
    assert_eq!(s.t("open file"), "開啟檔案");
    assert_eq!(s.tf("{0} items", &[&3]), "3 個項目");
    // in another language the built-in catalog wins over translations.xml
    assert_eq!(s.tr(579, "copy line"), "複製整列");
    // translated status messages and tree labels; filters stay in English
    let sample = std::env::temp_dir().join(format!("pelens-i18n-{}.exe", std::process::id()));
    std::fs::write(&sample, testkit::suspicious_sample()).unwrap();
    s.apply(Action::Open(sample.clone()));
    assert!(s.status.contains("位元組 | 指標："), "{}", s.status);
    let high = &s.tree_children(ItemType::Indicators)[0];
    assert!(high.0.starts_with("高 (") && high.1 == "high", "{high:?}");
    let row = pe_analysis::view::Row::new(vec!["a".into(), "b".into()]);
    let labels: Vec<String> =
        s.context_actions(ItemType::Sections, &row, &["name".into(), "md5".into()], "|").into_iter().map(|a| a.0).collect();
    assert_eq!(labels[..3], ["複製整列", "複製項目", "複製詳細資料"]);
    s.apply(Action::CopyText("x".into()));
    assert_eq!(s.status, "已複製到剪貼簿");
    // back to "auto": the system language again
    s.apply(Action::SetLanguage(None));
    assert_eq!((s.lang, s.language_setting()), (Lang::Ja, None));
    assert!(std::fs::read_to_string(kb.join("settings.xml")).unwrap().contains("code=\"auto\""));
    // -lang: for this session
    let mut s2 = State::new(pe_db::Knowledge::builtin());
    let st = pelens_gui::parse_startup(&["-lang:ko".into(), "/lang:xx".into()]);
    assert_eq!(st.lang, None, "an unknown code resets the option");
    pelens_gui::parse_startup(&["/lang:ko".into()]).apply_lang(&mut s2);
    assert_eq!(s2.lang, Lang::Ko);
    assert_eq!(s2.status, "분석할 파일을 끌어다 놓으세요...");
    let _ = std::fs::remove_file(sample);
}

#[test]
fn fonts_follow_the_language() {
    use pelens_gui::theme;
    let dir = std::env::temp_dir().join(format!("pelens-i18n-fonts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a/b")).unwrap();
    // a real font (egui's bundled Ubuntu) under the file names this platform looks for, in nested folders
    let bytes = egui::FontDefinitions::default().font_data["Ubuntu-Light"].font.to_vec();
    let mut wanted = std::collections::BTreeSet::new();
    for l in Lang::ALL {
        for (_, files) in theme::font_candidates(l) {
            wanted.insert(files[0]);
        }
    }
    for (i, n) in wanted.iter().enumerate() {
        let sub = if i % 2 == 0 { dir.join("a/b") } else { dir.clone() };
        std::fs::write(sub.join(n), &bytes).unwrap();
    }
    assert!(theme::index_fonts(std::slice::from_ref(&dir)).len() >= wanted.len().min(4));
    for l in Lang::ALL {
        let c = theme::font_candidates(l);
        assert_eq!(c.len(), 4, "proportional, monospace, CJK, Hangul/Hanja");
        let (defs, loaded) = theme::font_definitions(std::slice::from_ref(&dir), l);
        let fam = defs.families[&egui::FontFamily::Proportional].clone();
        // primary font, then the CJK fallback of the language, then the Hangul (Hanja for Korean) one
        assert_eq!(fam[0], c[0].1[0], "{l:?}");
        assert_eq!(fam[1], c[2].1[0], "{l:?}");
        assert!(fam.contains(&c[3].1[0].to_string()) || c[3].1[0] == c[2].1[0], "{l:?}: {fam:?}");
        assert!(loaded.len() >= 3, "{loaded:?}");
        assert_eq!(defs.families[&egui::FontFamily::Monospace][0], c[1].1[0]);
        // same metrics as the primary font: no baseline correction
        assert_eq!(defs.font_data[c[2].1[0]].tweak.y_offset_factor, 0.0);
    }
    // nothing found: egui's own fonts stay
    let (defs, loaded) = theme::font_definitions(&[dir.join("missing")], Lang::En);
    assert!(loaded.is_empty() && !defs.families[&egui::FontFamily::Proportional].is_empty());
    assert!(!theme::font_dirs().is_empty());
    // Yu Gothic (small ascent, large line gap) is moved down onto Segoe UI's baseline
    let dy = theme::baseline_offset((1.079, 1.33), (0.88, 1.602));
    assert!((dy - 0.335).abs() < 0.001, "{dy}");
    assert_eq!(theme::baseline_offset((1.0, 1.3), (1.0, 1.3)), 0.0);
    let (asc, h) = theme::em_metrics(&bytes).unwrap();
    assert!(asc > 0.5 && h > asc, "{asc} {h}");
    assert_eq!(theme::em_metrics(b"not a font"), None);
    if theme::index_fonts(&theme::font_dirs()).contains_key("yugothr.ttc") {
        let (defs, _) = theme::font_definitions(&theme::font_dirs(), Lang::Ja);
        assert!(defs.font_data["YuGothR.ttc"].tweak.y_offset_factor > 0.2);
    }
    let _ = std::fs::remove_dir_all(dir);
}
