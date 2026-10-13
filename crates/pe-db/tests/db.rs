use pe_db::dom::{self, parse_int};
use pe_db::edit::{self, Key, Target};
use pe_db::*;
use std::path::PathBuf;

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pe-db-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const SETTINGS: &str = r#"<!-- comment -->
<xml version="1.0" encoding="utf-8">
  <files>
    <fthresholds>thresholds.xml</fthresholds>
    <findicators>indicators.xml</findicators>
    <fstrings>strings.xml</fstrings>
    <ffunctions>functions.xml</ffunctions>
    <flanguages>languages.xml</flanguages>
    <ftranslations>translations.xml</ftranslations>
    <fsignatures>signatures.xml</fsignatures>
    <frich>rich.xml</frich>
    <fmitre>mitre.xml</fmitre>
    <fnsp>namespaces.xml</fnsp>
  </files>
  <setting>
    <indicators sort="1" flag="1" separator="|" bytes="32"/>
    <score enable="1" key=""/>
    <strings utf8="1" utf16="0"/>
  </setting>
  <colors enable="1">
    <color id="01" r="000" g="000" b="000">black</color>
    <color id="07" r="238" g="034" b="035">red</color>
  </colors>
  <sections><section>.text</section><section>.data</section></sections>
  <streams flag="1"><stream id="00" flag="0">#~</stream><stream id="ff" flag="1">Unknown</stream></streams>
  <tables flag="1" all="1"><table id="00" enable="1" flag="0" desc="">Module</table></tables>
  <tips><tip id="00">flag</tip></tips>
</xml>"#;

const INDICATORS: &str = r#"<xml version="1.0"><indicators>
<item enable="1" severity="3" id="1000" type="00" ti="----" detail="size: %i bytes">file > info</item>
<item enable="0" severity="1" id="1254" type="15" ti="1574" detail="count: %i">exports > forwarded</item>
</indicators></xml>"#;

const THRESHOLDS: &str = r#"<xml><thresholds>
<item id="001" enable="1" level="2" min="64" max="64"></item>
<item id="009" enable="1" level="2" min="256" max="-1"></item>
<item id="011" enable="0" level="2" min="-1" max="1024"></item>
</thresholds></xml>"#;

const FUNCTIONS: &str = r#"<xml><libs>
<lib name="kernel32.dll" flag="0" gp="--" desc="Windows NT BASE API">
  <fcts>
    <fct gp="02" od="---" flag="1" ti="1055">CreateRemoteThread</fct>
    <fct gp="05" od="--" flag="0" cb="1">VirtualAlloc</fct>
    <fct gp="--" od="--" flag="0" un="1" cd="1" ad="1" hide="1" hint="20">Strange></fct>
  </fcts>
</lib>
<lib name="ws2_32.dll" flag="1" group="03" desc="Sockets">
  <fcts>
    <fct gp="03" od="23" flag="1">socket</fct>
    <fct gp="04" od="--" flag="1" map="RtlEncryptDES">SystemFunction001</fct>
  </fcts>
</lib>
<lib name="" flag="0" gp="--">
  <fcts><fct gp="04" flag="1" ti="1001">Decrypt</fct></fcts>
</lib>
</libs></xml>"#;

const STRINGS: &str = "\u{feff}<xml><settings><setting><minimum-size>5</minimum-size><case-sensitive>1</case-sensitive><substring>1</substring></setting></settings>
<sids gp=\"30\"><sid name=\"\">S-1-5-18</sid></sids>
<privs gp=\"30\" ti=\"1134\"><priv>SeDebugPrivilege</priv></privs>
<agents hint=\"06\"><agent>Mozilla/</agent></agents>
<exts hint=\"17\"><ext>exe</ext></exts>
<stubs hint=\"\"><stub flag=\"1\">!This is a Win32 program.</stub><stub flag=\"0\"></stub></stubs>
<strings><string flag=\"1\" gp=\"04\" ti=\"1022\" sig=\"500\" bl=\"1\">EncryptMessage</string></strings>
</xml>";

const SIGNATURES: &str = r#"<xml><sigs>
<sig name="UPX" more="UPX packer" flag="1" file="0" tool="1" severity="2" url="upx.github.io" id="12">
  <pattern ep="1">60 BE xx xx 0x x3 8D</pattern>
  <pattern ep="0">UPX!</pattern>
  <pattern ep="1">F</pattern>
</sig>
<sig name="CAB" flag="1" file="1" tool="0" severity="2"><pattern ep="0">4D 53 43 46</pattern></sig>
</sigs></xml>"#;

const MITRE: &str = r#"<xml><mitre url="https://attack.mitre.org">
<tactics url="tactics"><ta id="0002" de="run code">Execution</ta></tactics>
<techniques url="techniques"><ti id="1055" ta="0005" flag="1" level="1" enable="1">Process Injection</ti><ti id="1001" ta="0011" flag="0" level="2" enable="0">Data Obfuscation</ti></techniques>
</mitre></xml>"#;

const NSP: &str = r#"<xml><nsp>
<nsp_system enable="1"><item flag="1" gp="03" ti="1011">System.Net</item><item flag="0" gp="--" ti="----">System</item></nsp_system>
<nsp_custom enable="0"><item flag="1" gp="10" ti="1001" sig="501">Costura</item></nsp_custom>
</nsp></xml>"#;

const RICH: &str = r#"<xml><richheader>
<prodId><item id="0x01">Import</item><item id="0x0103">Utc1900_C</item></prodId>
<ide><item id="00">.NET Framework</item><item id="21">Visual Studio 2019</item></ide>
<version><item value="30159" ide="21">16.11</item><item value="00000" ide="23"></item></version>
</richheader></xml>"#;

const LANGS: &str = r#"<xml><langs><lang id="0x0C0C" flag="1">french-Canada</lang><lang id="0x040c" flag="0">french-France</lang></langs>
<cps><cp id="1252">Western European</cp></cps></xml>"#;

const TRANSLATIONS: &str = r#"<xml>
<text><item id="0">hex</item><item id="1">relative</item></text>
<tooltips><item id="000">key tip</item></tooltips>
<version><os><item name="VOS_NT">Windows NT</item></os></version>
<locations><item r="220" g="220" b="220">image</item></locations>
<groups enable="1"><item id="02" r="247" g="071" b="071" level="1" enable="1">execution</item><item id="28" r="1" g="2" b="3" level="3" enable="0"></item></groups>
<resources><item id="25" severity="1" builtin="0" file="1" indicator="1">executable</item></resources>
<hints color="1"><item id="06" indicate="1">user-agent</item><item id="-1">unknown</item></hints>
<severities><item id="1">high</item><item id="2">medium</item></severities>
<machines><item id="00">Intel-386</item></machines>
</xml>"#;

fn write_all(dir: &PathBuf) {
    for (n, c) in [
        ("settings.xml", SETTINGS),
        ("indicators.xml", INDICATORS),
        ("thresholds.xml", THRESHOLDS),
        ("functions.xml", FUNCTIONS),
        ("strings.xml", STRINGS),
        ("signatures.xml", SIGNATURES),
        ("mitre.xml", MITRE),
        ("namespaces.xml", NSP),
        ("rich.xml", RICH),
        ("languages.xml", LANGS),
        ("translations.xml", TRANSLATIONS),
    ] {
        std::fs::write(dir.join(n), c).unwrap();
    }
}

#[test]
fn load_everything() {
    let d = tmpdir("load");
    write_all(&d);
    let k = Knowledge::load(&d);
    assert!(k.errors.is_empty(), "{:?}", k.errors);
    assert_eq!(k.loaded.len(), 11);

    // settings
    assert_eq!(k.settings.get("indicators", "separator"), Some("|"));
    assert_eq!(k.settings.get_int("indicators", "bytes", 0), 32);
    assert!(k.settings.get_bool("strings", "utf8", false));
    assert!(!k.settings.get_bool("strings", "utf16", true));
    assert!(k.settings.get_bool("missing", "x", true));
    assert_eq!(k.settings.color(7), Some((238, 34, 35)));
    assert_eq!(k.settings.color(99), None);
    assert!(k.settings.colors_enabled);
    assert!(k.settings.is_standard_section(".text"));
    assert!(!k.settings.is_standard_section(".upx0"));
    assert_eq!(k.settings.streams.len(), 2);
    assert!(k.settings.streams_flag && k.settings.tables_flag);
    assert_eq!(k.settings.tables[0].name, "Module");
    assert_eq!(k.settings.tips[0], ("00".to_string(), "flag".to_string()));

    // indicators / thresholds
    assert_eq!(k.indicators.len(), 2);
    let i = k.indicator(1254).unwrap();
    assert_eq!((i.enable, i.severity, i.ti.as_deref(), i.kind.as_str()), (0, 1, Some("1574"), "15"));
    assert_eq!(k.indicator(1000).unwrap().ti, None);
    assert!(k.indicator(1).is_none());
    assert_eq!(k.thresholds.len(), 3);
    let t = k.threshold(1).unwrap();
    assert!(t.violated(63) && t.violated(65) && !t.violated(64));
    let t9 = k.threshold(9).unwrap();
    assert!(!t9.violated(100_000) && t9.violated(10));
    assert!(k.threshold(11).is_none(), "disabled thresholds are hidden");

    // functions
    assert_eq!(k.functions.libs.len(), 3);
    assert_eq!(k.functions.function_count(), 6);
    let f = k.functions.function("KERNEL32.dll", "createremotethread").unwrap();
    assert_eq!((f.group, f.flag, f.ti.as_deref()), (Some(2), true, Some("1055")));
    let s = k.functions.function("kernel32.dll", "Strange").unwrap();
    assert!(s.undocumented && s.deprecated && s.anti_debug && s.hidden);
    assert_eq!(s.hint, Some(20));
    assert!(k.functions.function("kernel32.dll", "VirtualAlloc").unwrap().callback);
    // global and A/W fallback
    assert_eq!(k.functions.function("other.dll", "Decrypt").unwrap().ti.as_deref(), Some("1001"));
    assert_eq!(k.functions.function("other.dll", "DecryptW").unwrap().name, "Decrypt");
    assert_eq!(k.functions.function("other.dll", "_Decrypt@8").unwrap().name, "Decrypt");
    assert!(k.functions.function("other.dll", "Nope").is_none());
    assert_eq!(k.functions.function_by_ordinal("WS2_32.DLL", 23).unwrap().name, "socket");
    assert!(k.functions.function_by_ordinal("ws2_32.dll", 99).is_none());
    assert!(k.functions.function_by_ordinal("none.dll", 1).is_none());
    assert_eq!(k.functions.library("ws2_32.dll").unwrap().group, Some(3));
    assert_eq!(k.functions.function("ws2_32.dll", "SystemFunction001").unwrap().map.as_deref(), Some("RtlEncryptDES"));

    // strings
    assert_eq!(k.strings.minimum_size, 5);
    assert!(k.strings.case_sensitive && k.strings.substring);
    assert_eq!(k.strings.items("privs")[0].ti.as_deref(), Some("1134"));
    assert_eq!(k.strings.items("privs")[0].group, Some(30));
    assert_eq!(k.strings.items("agents")[0].hint, Some(6));
    assert_eq!(k.strings.items("stubs").len(), 1, "empty values skipped");
    let st = &k.strings.items("strings")[0];
    assert!(st.flag && st.blacklist);
    assert_eq!(st.sig, Some(500));
    assert!(k.strings.items("nope").is_empty());

    // signatures
    assert_eq!(k.signatures.len(), 2);
    let upx = &k.signatures[0];
    assert_eq!((upx.id, upx.tool, upx.file, upx.patterns.len()), (Some(12), true, false, 3));
    assert!(upx.patterns[0].matches(&[0x60, 0xbe, 1, 2, 0x05, 0x13, 0x8d, 0xff]));
    assert!(!upx.patterns[0].matches(&[0x60, 0xbe, 1, 2, 0x15, 0x13, 0x8d]));
    assert!(!upx.patterns[0].matches(&[0x60]));
    assert!(matches!(upx.patterns[1].kind, PatternKind::Text(ref t) if t == "UPX!"));
    assert!(upx.patterns[1].matches(b"UPX!xx") && !upx.patterns[1].matches(b"UP"));
    assert_eq!(upx.patterns[1].len(), 4);
    assert!(upx.patterns[2].matches(&[0xf3]) && !upx.patterns[2].matches(&[0x3f]));
    assert!(!upx.patterns[2].is_empty());

    // mitre
    assert_eq!(k.mitre.tactics.len(), 1);
    assert_eq!(k.mitre.technique("T1055").unwrap().name, "Process Injection");
    assert!(!k.mitre.technique("1001").unwrap().enable);
    assert_eq!(k.mitre.tactic("TA0002").unwrap().name, "Execution");
    assert_eq!(k.mitre.technique_url("1055"), "https://attack.mitre.org/techniques/T1055");
    assert_eq!(k.mitre.tactic_url("0002"), "https://attack.mitre.org/tactics/TA0002");

    // namespaces
    assert_eq!(k.namespaces.items.len(), 3);
    assert_eq!(k.namespaces.lookup("System.Net.Http").unwrap().name, "System.Net");
    assert_eq!(k.namespaces.lookup("System.IO").unwrap().name, "System");
    assert!(k.namespaces.lookup("Costura.Loader").is_none(), "custom disabled");
    assert!(k.namespaces.lookup("SystemX").is_none());

    // rich
    assert_eq!(k.rich.product(0x103), Some("Utc1900_C"));
    assert_eq!(k.rich.tooling(30159).as_deref(), Some("Visual Studio 2019 (16.11)"));
    assert_eq!(k.rich.tooling(0).as_deref(), Some("Visual Studio"));
    assert!(k.rich.tooling(1).is_none());

    // languages
    assert_eq!(k.languages.language(0x0c0c), Some(("french-Canada", true)));
    assert_eq!(k.languages.code_pages.get(&1252).map(String::as_str), Some("Western European"));

    // translations
    assert_eq!(k.translations.tr(1), "relative");
    assert_eq!(k.translations.tr(999), "");
    assert_eq!(k.translations.tooltips.get(&0).map(String::as_str), Some("key tip"));
    assert_eq!(k.translations.group(2).unwrap().rgb, (247, 71, 71));
    assert_eq!(k.group_name(2), "execution");
    assert_eq!(k.group_name(28), "", "empty name falls back to builtin (also empty)");
    assert_eq!(k.group_name(30), "security", "missing in xml falls back to builtin");
    assert_eq!(k.translations.resources[0].name, "executable");
    assert_eq!(k.translations.hint(6).unwrap().name, "user-agent");
    assert_eq!(k.translations.list("version/os")[0].1, "Windows NT");
    assert_eq!(k.translations.list("machines")[0], ("00".to_string(), "Intel-386".to_string()));
    assert!(k.translations.list("nothing").is_empty());
    assert_eq!(k.translations.locations[0].0, "image");
    assert_eq!(k.translations.severity_name(1), "high");
    assert_eq!(k.translations.severity_name(3), "low");
    assert_eq!(k.translations.severity_name(4), "info");
    assert_eq!(k.translations.severity_name(6), "none");
    assert_eq!(k.translations.severity_name(9), "unknown");
    assert!(k.file_path("fmitre").unwrap().ends_with("mitre.xml"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn write_back_preserves_format() {
    let d = tmpdir("write");
    write_all(&d);
    let mut k = Knowledge::load(&d);

    k.set_indicator_severity(1000, 1).unwrap();
    k.set_indicator_enable(1254, 1).unwrap();
    k.set_library_flag("WS2_32.dll", false).unwrap();
    k.set_function_flag("kernel32.dll", "virtualalloc", true).unwrap();
    k.set_language_flag(0x040c, true).unwrap();
    k.set_signature_severity("UPX", 1).unwrap();
    k.set_namespace_flag("System", true).unwrap();
    k.save_setting("score", "key", "abc\"<>&").unwrap();
    k.save_setting("strings", "newattr", "7").unwrap();
    k.save_setting("theme", "dark", "1").unwrap();
    assert!(edit::insert_child("<a></b>", "x", "e", "k", "v").is_none());

    assert!(k.set_library_flag("nope.dll", true).is_err());
    assert!(k.set_function_flag("nope.dll", "x", true).is_err());
    assert!(k.set_function_flag("kernel32.dll", "nothere", true).is_err());
    assert!(k.set_language_flag(0x1234, true).is_err());
    assert!(k.set_indicator_severity(4242, 1).is_err());

    let k2 = Knowledge::load(&d);
    assert_eq!(k2.indicator(1000).unwrap().severity, 1);
    assert_eq!(k2.indicator(1254).unwrap().enable, 1);
    assert!(!k2.functions.library("ws2_32.dll").unwrap().flag);
    assert!(k2.functions.function("kernel32.dll", "VirtualAlloc").unwrap().flag);
    assert!(k2.functions.function("kernel32.dll", "CreateRemoteThread").unwrap().flag);
    assert_eq!(k2.languages.language(0x040c), Some(("french-France", true)));
    assert_eq!(k2.signatures[0].severity, 1);
    assert!(k2.namespaces.items.iter().find(|n| n.name == "System").unwrap().flag);
    assert_eq!(k2.settings.get("score", "key"), Some("abc\"<>&"));
    assert_eq!(k2.settings.get("strings", "newattr"), Some("7"));
    assert_eq!(k2.settings.get("theme", "dark"), Some("1"));
    // comments kept
    let s = std::fs::read_to_string(d.join("settings.xml")).unwrap();
    assert!(s.starts_with("<!-- comment -->"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn missing_files_and_builtin() {
    let d = tmpdir("missing");
    let k = Knowledge::load(&d);
    assert_eq!(k.errors.len(), 11);
    assert!(k.get_bool_default());
    let b = Knowledge::builtin();
    assert!(b.dir.is_none());
    assert_eq!(b.settings.get("indicators", "separator"), Some("|"));
    let mut b = b;
    assert!(matches!(b.set_indicator_severity(1, 1), Err(DbError::NoDirectory)));
    assert!(matches!(b.save_setting("a", "b", "c"), Err(DbError::NoDirectory)));
    assert!(b.file_path("fmitre").is_none());
    assert_eq!(default_group_name(99), "");
    // malformed xml
    std::fs::write(d.join("settings.xml"), "<xml><setting><a x=\"1\"></xml>").unwrap();
    std::fs::write(d.join("mitre.xml"), "<xml><mitre></b></xml>").unwrap();
    let k = Knowledge::load(&d);
    assert!(k.loaded.iter().any(|f| f == "settings.xml"));
    let _ = std::fs::remove_dir_all(&d);
}

trait DefaultCheck {
    fn get_bool_default(&self) -> bool;
}
impl DefaultCheck for Knowledge {
    fn get_bool_default(&self) -> bool {
        self.settings.get_bool("groups", "enable", false)
    }
}

#[test]
fn error_display() {
    let e = DbError::NotFound("x".into());
    assert_eq!(e.to_string(), "element not found: x");
    assert_eq!(DbError::NoDirectory.to_string(), "no knowledge directory configured");
    let io: DbError = std::io::Error::other("boom").into();
    assert_eq!(io.to_string(), "boom");
    let x = DbError::Xml(dom::ParseError("bad".into()));
    assert_eq!(x.to_string(), "xml: bad");
    let _: &dyn std::error::Error = &x;
}

#[test]
fn dom_helpers() {
    let doc = dom::parse("\u{feff}<?xml version=\"1.0\"?><a x=\"0x10\" y=\"--\" z=\"abc\"><b>t&amp;x</b><![CDATA[raw]]><c/></a>").unwrap();
    let a = doc.child("a").unwrap();
    assert_eq!(a.attr_int("x"), Some(16));
    assert_eq!(a.attr_int("y"), None);
    assert_eq!(a.attr_int("z"), None);
    assert_eq!(a.attr_or("q", "d"), "d");
    assert!(!a.attr_bool("y"));
    assert_eq!(a.child("b").unwrap().text, "t&x");
    assert!(a.text.contains("raw"));
    assert_eq!(doc.path("a/b").unwrap().text_trim(), "t&x");
    assert!(doc.path("a/zz").is_none());
    assert_eq!(a.children_named("c").count(), 1);
    assert_eq!(dom::payload(&doc).name, "#document");
    assert_eq!(parse_int(" 12 "), Some(12));
    assert_eq!(parse_int("0XfF"), Some(255));
    assert_eq!(parse_int(""), None);
    // unclosed elements are closed at EOF
    let d2 = dom::parse("<a><b>").unwrap();
    assert_eq!(d2.child("a").unwrap().child("b").unwrap().name, "b");
    assert!(dom::parse("<a x=\"1></a>").is_err());
    assert!(dom::parse("<a>&bogus;</a>").is_ok());
    assert_eq!(dom::ParseError("e".into()).to_string(), "xml: e");
}

#[test]
fn edit_targets() {
    let src = r#"<x><lib name="a"><fct flag="0">F1</fct><fct flag='0'>F2</fct></lib><lib name="b"><fct>F1</fct></lib><e/></x>"#;
    let t = Target { scope: Some(("lib", Key::Attr("name", "b"))), tag: "fct", key: Key::Text("F1") };
    let out = edit::set_attr(src, &t, "flag", "1").unwrap();
    assert!(out.contains(r#"<lib name="b"><fct flag="1">F1</fct>"#), "{out}");
    let t2 = Target { scope: Some(("lib", Key::Attr("name", "a"))), tag: "fct", key: Key::Text("F2") };
    let out = edit::set_attr(&out, &t2, "flag", "1").unwrap();
    assert!(out.contains("<fct flag='1'>F2</fct>"), "{out}");
    let t3 = Target { scope: None, tag: "e", key: Key::First };
    let out = edit::set_attr(&out, &t3, "k", "v").unwrap();
    assert!(out.contains(r#"<e k="v"/>"#), "{out}");
    let none = Target { scope: None, tag: "zz", key: Key::First };
    assert!(edit::set_attr(src, &none, "k", "v").is_none());
    let scoped_none = Target { scope: Some(("lib", Key::Text("x"))), tag: "fct", key: Key::First };
    assert!(edit::find(src, &scoped_none).is_none());
    let mismatched = Target { scope: None, tag: "fct", key: Key::Text("F9") };
    assert!(edit::find(src, &mismatched).is_none());
    // attribute name that is a suffix of another one must not be confused
    let s2 = r#"<i xflag="0" flag="0"/>"#;
    let out = edit::set_attr(s2, &Target { scope: None, tag: "i", key: Key::First }, "flag", "1").unwrap();
    assert_eq!(out, r#"<i xflag="0" flag="1"/>"#);
}

/// Integration with the user's own pestudio installation (skipped when absent).
#[test]
fn real_knowledge_base_if_present() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../xml");
    if !dir.join("settings.xml").exists() {
        return;
    }
    let k = Knowledge::load(&dir);
    assert!(k.errors.is_empty(), "{:?}", k.errors);
    assert_eq!(k.indicators.len(), 150);
    assert_eq!(k.thresholds.len(), 19);
    assert_eq!(k.functions.libs.len(), 372);
    assert_eq!(k.functions.function_count(), 6315);
    assert_eq!(k.signatures.len(), 379);
    assert_eq!(k.signatures.iter().map(|s| s.patterns.len()).sum::<usize>(), 1508);
    assert_eq!(k.mitre.tactics.len(), 12);
    assert_eq!(k.mitre.techniques.len(), 249);
    assert_eq!(k.languages.langs.len(), 204);
    assert_eq!(k.languages.code_pages.len(), 152);
    assert_eq!(k.translations.groups.len(), 33);
    assert_eq!(k.strings.items("exts").len(), 647);
    assert_eq!(k.settings.standard_sections.len(), 44);
}
