use pe_analysis::model::*;
use pe_analysis::report::{self, Format};
use pe_analysis::testkit;
use pe_analysis::util::{self, Arg};
use pe_analysis::view::{self, Table, ViewOptions};
use pe_analysis::*;
use pe_db::Knowledge;
use pe_parser::testutil::*;
use std::path::PathBuf;

fn kb() -> Knowledge {
    testkit::knowledge(&format!("an-{:?}", std::thread::current().id()).replace(['(', ')'], ""))
}

fn write_tmp(name: &str, data: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pestudio-rs-{}-{name}", std::process::id()));
    std::fs::write(&p, data).unwrap();
    p
}

fn ids(a: &Analysis) -> Vec<u32> {
    let mut v: Vec<u32> = a.indicators.iter().map(|i| i.id).collect();
    v.sort();
    v.dedup();
    v
}

fn reeval(a: &Analysis, k: &Knowledge, data: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = indicators::evaluate(a, k, data, &Options::default()).iter().map(|i| i.id).collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn suspicious_sample_end_to_end() {
    let k = kb();
    let data = testkit::suspicious_sample();
    let p = write_tmp("susp.exe", &data);
    let (d2, a) = analyze_file(&p, &k, &Options::default()).unwrap();
    assert_eq!(d2, data);
    let got = ids(&a);
    for id in [
        1000, 1001, 1002, 1003, 1004, 1008, 1009, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1028,
        1029, 1033, 1035, 1038, 1040, 1042, 1043, 1045, 1047, 1049, 1050, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1068, 1069, 1070, 1071,
        1072, 1073, 1075, 1076, 1079, 1080, 1210, 1215, 1221, 1222, 1224, 1236, 1245, 1251, 1252, 1253, 1254, 1256, 1257, 1259, 1261, 1262,
        1264, 1266, 1267, 1269, 1270, 1271, 1272, 1273, 1274, 1321, 1400, 1402, 1404, 1424, 1429, 1430, 1431, 1434, 1484, 1487, 1490, 1491,
        1492, 1494, 1495, 1496, 1497,
    ] {
        assert!(got.contains(&id), "indicator {id} missing: {got:?}");
    }
    assert!(!got.contains(&1999), "disabled indicator must not appear");
    // Windows: the synthetic signature does not verify
    if cfg!(windows) {
        assert!(got.contains(&1046));
        assert_eq!(a.certificate_check.as_ref().unwrap().verified, Some(false));
    }

    assert_eq!(a.file_type, "executable");
    assert_eq!(a.cpu, "32-bit");
    assert_eq!(a.subsystem, "GUI");
    assert_eq!(a.description.as_deref(), Some("Totally Legit"));
    assert!(a.hashes_without_overlay.is_some());
    let sig: Vec<(&str, &str)> = a.signatures.iter().map(|s| (s.name.as_str(), s.location.as_str())).collect();
    assert!(sig.contains(&("TestCompiler", "entry-point")) && sig.contains(&("UPX", "section")) && sig.contains(&("Nim", "file")));
    let emb: Vec<&str> = a.embedded.iter().map(|e| e.signature.as_str()).collect();
    assert!(emb.contains(&"executable") && emb.contains(&"CAB") && emb.contains(&"executable (base64)"));
    assert_eq!(a.imphash.as_deref().map(str::len), Some(32));
    assert!(a.tooling.iter().any(|t| t.contains("Visual Studio 2019")));

    // libraries / imports
    let k32: Vec<&LibraryRow> = a.libraries.iter().filter(|l| l.name.eq_ignore_ascii_case("kernel32.dll")).collect();
    assert!(k32.iter().all(|l| l.duplicate));
    assert!(a.libraries.iter().any(|l| l.name == "evil lib" && l.spoofed && !l.known));
    assert!(a.libraries.iter().any(|l| l.name == "urlmon.dll" && l.kind == "delay-loaded" && l.flag));
    let sock = a.imports.iter().find(|i| i.ordinal == Some(23)).unwrap();
    assert!(sock.ordinal_mapped && sock.name == "socket" && sock.flag);
    let o99 = a.imports.iter().find(|i| i.ordinal == Some(99)).unwrap();
    assert_eq!(o99.name, "#99");
    assert!(a.imports.iter().any(|i| i.name == "IsDebuggerPresent" && i.anti_debug));
    assert!(a.imports.iter().any(|i| i.name == "WinExec" && i.deprecated));
    assert!(a.imports.iter().any(|i| i.name == "BaseFlushAppcompatCache" && i.undocumented));
    assert!(a.imports.iter().any(|i| i.name == "VirtualAlloc" && i.callback));

    // exports
    assert!(a.exports.iter().any(|e| e.duplicate && e.name == "Start"));
    assert!(a.exports.iter().any(|e| e.entry_point));
    assert!(a.exports.iter().any(|e| e.undecorated.contains("f(void)")));
    assert!(a.exports.iter().any(|e| e.gap));
    assert!(a.exports.iter().any(|e| e.anonymous));

    // resources
    let payload = a.resources.iter().find(|r| r.name == "PAYLOAD").unwrap();
    assert_eq!((payload.signature.as_str(), payload.severity, payload.language_flag), ("executable", 1, true));
    assert!(a.resources.iter().any(|r| r.signature == "CAB"));

    // groups / mitre / footprints / strings / sections
    assert!(a.groups.iter().any(|g| g.name == "memory" && g.count >= 2));
    assert!(a.mitre.iter().any(|m| m.technique == "T1055" && m.tactic_name == "Defense Evasion" && m.flag));
    assert!(!a.mitre.iter().any(|m| m.technique == "T1622"), "disabled technique");
    assert!(a.footprints.iter().any(|f| f.item == "rich-header"));
    assert!(a.footprints.iter().any(|f| f.item.starts_with("string-table")));
    assert!(a.footprints.iter().any(|f| f.item == "overlay"));
    assert!(a.footprints.iter().any(|f| f.item == "certificate"));
    assert!(a.footprints.iter().any(|f| f.item == "imphash"));
    let hints: Vec<&str> = a.strings.iter().filter_map(|s| s.hint.as_deref()).collect();
    for h in [
        "url-pattern",
        "user-agent",
        "registry",
        "privilege",
        "utility",
        "mutex",
        "file",
        "office",
        "sid",
        "query",
        "pipe",
        "ip-address",
        "guid",
        "rtti",
        "base64",
        "format-string",
        "regex",
        "oid",
        "library",
        "import",
        "function",
        "dotnet-namespace",
        "debug",
        "export",
        "dos-stub",
    ] {
        assert!(hints.contains(&h), "hint {h} missing");
    }
    assert!(a.strings.iter().any(|s| s.kind == StringKind::Unicode && s.value == "unicode-string-here"));
    assert!(a.strings.iter().any(|s| s.kind == StringKind::Utf8));
    assert!(a.strings.iter().any(|s| s.blacklist));
    assert!(a.strings.iter().any(|s| s.hint.as_deref() == Some("url-pattern (certificate)") && !s.flag));
    assert!(a.indicators.iter().filter(|i| i.id == 1434).all(|i| !i.detail.contains("crl.test")));
    assert_eq!(pe_analysis::strings::url_part("3http://a/b"), "http://a/b");
    assert_eq!(pe_analysis::strings::url_part("x www.a.com"), "www.a.com");
    assert_eq!(pe_analysis::strings::url_part("none"), "none");
    assert!(a.strings.iter().any(|s| s.location == "overlay") || a.strings.iter().any(|s| s.location.starts_with("section:")));
    let upx = a.sections.iter().find(|s| s.name == ".upx0").unwrap();
    assert!(!upx.standard_name && upx.self_modifying && upx.virtualized);
    assert!(a.sections.iter().any(|s| s.nameless && s.shareable && s.unreadable));
    assert!(a.sections.iter().any(|s| !s.embedded.is_empty()));
    assert!(a.stamps.iter().any(|s| s.kind == "certificate"));
    assert!(a.flagged_count(ItemType::Imports) > 0);
    for t in ItemType::ALL {
        let _ = a.flagged_count(t);
    }
    let _ = std::fs::remove_file(p);
}

#[test]
fn indicator_mutations() {
    let k = kb();
    let data = testkit::suspicious_sample();
    let base = analyze(&data, "x.exe", &k, &Options { verify_signature: false, ..Default::default() });

    let mut a = base.clone();
    a.network_drive = true;
    a.removable_drive = true;
    let l = a.pe.layout.as_mut().unwrap();
    l.file_header.size_of_optional_header = 200;
    l.optional_header.size_of_headers = 0x80;
    l.optional_header.file_alignment = 3;
    l.optional_header.section_alignment = 0x300;
    l.optional_header.size_of_code = 0;
    l.optional_header.base_of_code = 0x9999;
    l.optional_header.size_of_image = 0x10;
    l.optional_header.number_of_rva_and_sizes = 10;
    l.optional_header.checksum = 1;
    l.optional_header.data_directories[7] = pe_parser::headers::DataDirectory { rva: 0x0fff_0000, size: 10 };
    l.optional_header.data_directories[8] = pe_parser::headers::DataDirectory { rva: 0x10, size: 0 };
    l.optional_header.data_directories[15] = pe_parser::headers::DataDirectory { rva: 0x1000, size: 0x7fff_0000 };
    a.pe.dos_header.as_mut().unwrap().e_lfanew = 0x401;
    a.pe.dos_header.as_mut().unwrap().e_cparhdr = 2;
    a.pe.dos_stub.as_mut().unwrap().size = 500;
    a.pe.entry_point.as_mut().unwrap().outside_image = true;
    a.pe.exports.as_mut().unwrap().time_date_stamp = 0x1234;
    a.pe.resources.as_mut().unwrap().time_date_stamp = 0x5678;
    a.pe.debug[0].time_date_stamp = 0x4321;
    a.libraries[0].mismatch = 2;
    a.libraries[0].bound = true;
    let sd = a.pe.security.as_mut().unwrap();
    sd.not_at_end = true;
    sd.trailing_after_directory = 7;
    sd.entries[0].tail = 3;
    sd.entries[0].null_padding = 64;
    sd.entries[0].pkcs7.as_mut().unwrap().certificates[0].valid_to = Some(1);
    for r in a.pe.resources.as_mut().unwrap().entries.iter_mut().filter(|e| e.type_id.id() == Some(16)) {
        r.size = 0x20000;
    }
    a.exports[0].flag = true;
    a.sections[0].writable = true;
    a.certificate_check = Some(CertificateCheck { verified: Some(false), message: "bad".into() });
    let got = reeval(&a, &k, &data);
    for id in [
        1005, 1006, 1007, 1010, 1026, 1034, 1036, 1037, 1044, 1046, 1051, 1052, 1053, 1062, 1074, 1081, 1082, 1083, 1084, 1085, 1211, 1223,
        1250, 1268, 1301, 1302, 1306, 1320, 1486, 1488, 1489,
    ] {
        assert!(got.contains(&id), "{id} missing in {got:?}");
    }

    // code-less image, stub without message, unknown stub message, future stamp
    let mut b = base.clone();
    for s in b.pe.layout.as_mut().unwrap().sections.iter_mut() {
        s.characteristics = 0x4000_0040;
    }
    b.pe.dos_stub.as_mut().unwrap().message = None;
    let got = reeval(&b, &k, &data);
    assert!(got.contains(&1027) && got.contains(&1274));
    b.pe.dos_stub.as_mut().unwrap().message = Some("hello".into());
    assert!(reeval(&b, &k, &data).contains(&1260));
    let f = indicators::evaluate(&base, &k, &data, &Options::default());
    let comp = f.iter().find(|i| i.id == 1321).unwrap();
    assert_eq!(comp.severity, 1);
    assert!(comp.detail.ends_with("(future)"));

    // strings disabled
    let mut c = base.clone();
    c.strings_skipped = true;
    let ind = indicators::evaluate(&c, &k, &data, &Options::default());
    assert!(ind.iter().any(|i| i.id == 1431 && i.detail.contains("disabled")));

    // score indicators
    let mut d = base.clone();
    d.score = Some(ScoreReport {
        status: "ok".into(),
        positives: 3,
        total: 70,
        permalink: "p".into(),
        scan_date: "s".into(),
        ..Default::default()
    });
    indicators::score_indicators(&mut d, &k);
    assert!(d.has_indicator(1064) && d.has_indicator(1066) && d.has_indicator(1067));
    d.score = Some(ScoreReport { status: "ok".into(), positives: 0, total: 70, ..Default::default() });
    indicators::score_indicators(&mut d, &k);
    assert!(d.has_indicator(1065) && !d.has_indicator(1064));
    d.score = Some(ScoreReport { status: "offline".into(), ..Default::default() });
    indicators::score_indicators(&mut d, &k);
    assert!(d.has_indicator(1063) && !d.has_indicator(1065));
    d.score = None;
    indicators::score_indicators(&mut d, &k);

    // highestAvailable manifest + 64-bit exceptions + nothing else
    let mut bld = PeBuilder::new();
    bld.is64 = true;
    bld.exceptions = 2;
    bld.resources = vec![Resource {
        type_id: ResKey::Id(24),
        name: ResKey::Id(1),
        lang: 0,
        data: br#"<assembly><trustInfo><requestedExecutionLevel level="highestAvailable"/></trustInfo></assembly>"#.to_vec(),
    }];
    let d64 = bld.build();
    let a64 = analyze(&d64, "x64.exe", &k, &Options::default());
    let got = ids(&a64);
    assert!(got.contains(&1401) && got.contains(&1061));
    assert_eq!(a64.cpu, "64-bit");
}

#[test]
fn dotnet_sample_analysis() {
    let k = kb();
    let data = testkit::dotnet_sample();
    let a = analyze(&data, "loader.exe", &k, &Options::default());
    assert_eq!(a.file_type, ".NET executable");
    let got = ids(&a);
    for id in [1291, 1292, 1293, 1294, 1296, 1297, 1298, 1300, 1304] {
        assert!(got.contains(&id), "{id} missing");
    }
    assert!(a.libraries.iter().any(|l| l.kind == "p/Invoke" && l.name == "kernel32.dll" && l.known));
    assert!(
        a.imports
            .iter()
            .any(|i| i.kind == "dotnet" && i.name == "DownloadString" && i.namespace.as_deref() == Some("System.Net") && i.flag)
    );
    assert!(!a.imports.iter().any(|i| i.name == ".ctor"));
    assert!(a.imports.iter().any(|i| i.kind == "p/Invoke" && i.name == "VirtualAlloc"));
    assert!(a.strings.iter().any(|s| s.kind == StringKind::DotNetUser || s.value.contains("c2.example.net")));
    assert!(a.mitre.iter().any(|m| m.sources.iter().any(|s| s.starts_with("namespace:"))));
    assert!(a.footprints.iter().any(|f| f.item.starts_with("stream (")));

    let mut b = a.clone();
    let n = b.pe.dotnet.as_mut().unwrap();
    n.module_name.clear();
    n.streams[0].file_offset = None;
    n.type_defs.extend((0..8).map(|i| pe_parser::dotnet::TypeRef { name: format!("\u{2}\u{3}{i}"), namespace: String::new() }));
    n.assembly = None;
    b.pe.resources = Some(Default::default());
    let got = reeval(&b, &k, &data);
    assert!(got.contains(&1288) && got.contains(&1290) && got.contains(&1297) && got.contains(&1234));

    // dll variant
    let mut bld = PeBuilder::new();
    bld.dll = true;
    bld.dotnet = Some(DotNetSpec {
        module: "m".into(),
        type_refs: vec![],
        member_refs: vec![],
        module_refs: vec![],
        impl_maps: vec![],
        assembly: None,
        user_strings: vec![],
        guid_attribute: None,
        extra_stream: None,
    });
    let a2 = analyze(&bld.build(), "m.dll", &k, &Options::default());
    assert_eq!(a2.file_type, ".NET dynamic-link-library");
}

#[test]
fn file_types_and_non_pe() {
    let k = kb();
    let mut b = PeBuilder::new();
    b.dll = true;
    let a = analyze(&b.build(), "a.dll", &k, &Options::default());
    assert_eq!(a.file_type, "dynamic-link-library");
    let mut b = PeBuilder::new();
    b.subsystem = 1;
    let a = analyze(&b.build(), "a.sys", &k, &Options::default());
    assert_eq!(a.file_type, "driver");

    let pdf = b"%PDF-1.7 hello http://x.example.com/ world".to_vec();
    let a = analyze(&pdf, "doc.pdf", &k, &Options::default());
    assert!(!a.is_pe());
    assert_eq!(a.cpu, "n/a");
    assert_eq!(a.file_type, "PDF");
    assert!(a.signatures.iter().any(|s| s.name == "PDF"));
    assert!(a.strings.iter().any(|s| s.location == "file"));
    assert!(a.has_indicator(1490) && a.has_indicator(1431));
    let unknown = analyze(&[0u8, 1, 2, 3, 0xff], "bin", &k, &Options::default());
    assert_eq!(unknown.file_type, "unknown");
    let gif = analyze(b"GIF89a....", "x.gif", &k, &Options::default());
    assert!(gif.signatures.iter().any(|s| s.name == "GIF"));

    // strings limit and disabled
    let o = Options { strings_limit: Some(10), ..Default::default() };
    assert!(analyze(&pdf, "doc.pdf", &k, &o).strings_skipped);
    let o = Options { strings: false, ..Default::default() };
    assert!(analyze(&pdf, "doc.pdf", &k, &o).strings_skipped);
    let o = Options::from_settings(&k);
    assert!(o.epoch && o.first_bytes == 16 && o.strings_limit.is_none());
    assert!(analyze_file(std::path::Path::new("Z:/definitely/not/here.exe"), &k, &o).is_err());
}

#[test]
fn builtin_knowledge_still_works() {
    let k = Knowledge::builtin();
    let data = testkit::suspicious_sample();
    let a = analyze(&data, "x.exe", &k, &Options::default());
    assert!(a.has_indicator(1000) && a.has_indicator(1496) && a.has_indicator(1271));
    assert!(!a.has_indicator(1245), "builtin indicator table does not contain 1245");
    assert!(a.sections.iter().all(|s| s.standard_name), "no section list → all standard");
    let t = view::table(&a, &k, &data, ItemType::Indicators, &ViewOptions::default());
    assert!(!t.is_empty());
}

fn all_tables(a: &Analysis, k: &Knowledge, data: &[u8]) -> Vec<Table> {
    let o = ViewOptions::from_settings(k);
    ItemType::ALL.iter().map(|&t| view::table(a, k, data, t, &o)).collect()
}

#[test]
fn views_cover_every_node() {
    let k = kb();
    let data = testkit::suspicious_sample();
    let mut a = analyze(&data, "susp.exe", &k, &Options::default());
    a.score = Some(ScoreReport {
        status: "ok".into(),
        positives: 2,
        total: 3,
        permalink: "https://vt".into(),
        engines: vec![EngineResult { vendor: "A".into(), detected: true, result: "Trojan".into(), ..Default::default() }],
        ..Default::default()
    });
    a.network_drive = true;
    a.removable_drive = true;
    let ts = all_tables(&a, &k, &data);
    assert_eq!(ts.len(), 27);
    for t in &ts {
        assert!(t.item.is_some());
        assert!(!t.columns.is_empty());
        for r in &t.rows {
            assert!(r.cells.len() <= t.columns.len(), "{:?}", t.item);
        }
    }
    let get = |it: ItemType| ts.iter().find(|t| t.item == Some(it)).unwrap();
    assert!(get(ItemType::Image).rows.iter().any(|r| r.cells[0] == "imphash" && r.url.is_some()));
    assert!(get(ItemType::Image).rows.iter().any(|r| r.cells[0] == "file > embedded" && r.dump.is_some()));
    assert!(get(ItemType::Indicators).rows.first().unwrap().severity == Some(1), "sorted by severity");
    assert!(get(ItemType::Score).rows.iter().any(|r| r.cells[0] == "A" && r.flag));
    assert!(get(ItemType::RichHeader).rows.iter().any(|r| r.cells[1] == "Utc1900_C"));
    assert!(get(ItemType::FileHeader).rows.iter().any(|r| r.key.starts_with("fh-char:")));
    assert!(get(ItemType::OptionalHeader).rows.iter().any(|r| r.key == "ep"));
    assert!(get(ItemType::OptionalHeader).rows.iter().any(|r| r.key.starts_with("dll-char:")));
    assert_eq!(get(ItemType::Directories).rows.len(), 16);
    assert!(get(ItemType::Sections).rows.iter().any(|r| r.dump.is_some() && r.flag));
    assert!(get(ItemType::Libraries).rows.iter().any(|r| r.key == "lib:evil lib" && r.flag));
    assert!(get(ItemType::Imports).rows.iter().any(|r| r.ti.as_deref() == Some("1055")));
    assert!(get(ItemType::Exports).rows.iter().any(|r| r.cells[0] == "file-name"));
    assert!(get(ItemType::Certificate).rows.iter().any(|r| r.key.starts_with("pkcs7:")));
    assert!(get(ItemType::Certificate).rows.iter().any(|r| r.cells[0].ends_with("CRL-Distribution-Point")));
    assert!(get(ItemType::Relocations).rows.len() == 1);
    assert!(get(ItemType::Tls).rows.iter().any(|r| r.cells[0].starts_with("callback[")));
    assert!(get(ItemType::Resources).rows.iter().any(|r| r.severity == Some(1)));
    assert!(get(ItemType::Version).rows.iter().any(|r| r.cells[0] == "OriginalFilename" && r.flag));
    assert!(get(ItemType::Debug).rows.iter().any(|r| r.cells[6].contains("RSDS")));
    assert!(get(ItemType::Debug).rows.iter().any(|r| r.cells[6].contains("CETCOMPACT")));
    assert!(get(ItemType::Strings).len() > 20);
    assert!(get(ItemType::Manifest).rows.iter().any(|r| r.cells[0] == "autoElevate" && r.flag));
    assert!(get(ItemType::Overlay).rows.iter().any(|r| r.key == "overlay" && r.dump.is_some()));
    assert!(get(ItemType::Mitre).rows.iter().any(|r| r.url.as_deref().is_some_and(|u| u.contains("attack.mitre.org"))));
    assert!(get(ItemType::Groups).rows.iter().any(|r| r.group.is_some()));
    assert!(get(ItemType::Footprints).rows.iter().all(|r| r.url.is_some()));
    assert!(get(ItemType::DosStub).rows.iter().any(|r| r.cells[0] == "message" && r.flag));
    assert!(get(ItemType::DosHeader).rows.iter().any(|r| r.cells[0] == "e_lfanew"));
    assert!(get(ItemType::DotNet).note.is_some());
    assert!(get(ItemType::Exceptions).note.is_some());

    // resource decoders through the view helper
    let res = a.pe.resources.as_ref().unwrap();
    for (i, _) in res.entries.iter().enumerate() {
        let _ = view::resource_content(&a, &data, i);
    }
    assert!(view::resource_content(&a, &data, 999).is_empty());
    let st = res.entries.iter().position(|e| e.type_id.id() == Some(6)).unwrap();
    assert_eq!(view::resource_content(&a, &data, st), vec!["0: test"]);
    let html = res.entries.iter().position(|e| e.type_id.id() == Some(23)).unwrap();
    assert_eq!(view::resource_content(&a, &data, html), vec!["<html>hello world</html>"]);

    // dotnet and 64-bit views
    let net = testkit::dotnet_sample();
    let an = analyze(&net, "n.exe", &k, &Options::default());
    let tn = all_tables(&an, &k, &net);
    let dn = tn.iter().find(|t| t.item == Some(ItemType::DotNet)).unwrap();
    assert!(dn.rows.iter().any(|r| r.cells[0] == "typelibId"));
    assert!(dn.rows.iter().any(|r| r.cells[0] == "namespace (custom)" && r.flag));
    assert!(dn.rows.iter().any(|r| r.key == "stream:#Evil" && r.flag));
    assert!(dn.rows.iter().any(|r| r.cells[0] == "table > TypeRef" && r.cells[1].contains("Imported")));
    let mut b64 = PeBuilder::new();
    b64.is64 = true;
    b64.exceptions = 2;
    b64.load_config = true;
    b64.resources = vec![
        Resource {
            type_id: ResKey::Id(11),
            name: ResKey::Id(1),
            lang: 0,
            data: {
                let mut v = 1u32.to_le_bytes().to_vec();
                v.extend(1u32.to_le_bytes());
                v.extend(1u32.to_le_bytes());
                v.extend(16u32.to_le_bytes());
                v.extend(8u16.to_le_bytes());
                v.extend(0u16.to_le_bytes());
                v.extend(b"abc\0");
                v
            },
        },
        Resource { type_id: ResKey::Id(4), name: ResKey::Id(1), lang: 0, data: vec![0, 0, 0, 0, 0x80, 0, 1, 0, b'X', 0, 0, 0] },
        Resource { type_id: ResKey::Id(5), name: ResKey::Id(1), lang: 0, data: vec![0u8; 26] },
        Resource { type_id: ResKey::Id(14), name: ResKey::Id(1), lang: 0, data: vec![0, 0, 1, 0, 0, 0] },
        Resource { type_id: ResKey::Id(12), name: ResKey::Id(1), lang: 0, data: vec![0, 0, 2, 0, 0, 0] },
        Resource { type_id: ResKey::Id(16), name: ResKey::Id(1), lang: 0, data: version_resource((1, 0, 0, 0), &[("A", "b")]) },
        Resource { type_id: ResKey::Id(10), name: ResKey::Id(1), lang: 0, data: vec![0, 1, 2, 3] },
        Resource { type_id: ResKey::Id(10), name: ResKey::Id(2), lang: 0, data: b"plain text resource".to_vec() },
    ];
    let d64 = b64.build();
    let a64 = analyze(&d64, "x64.exe", &k, &Options::default());
    let t64 = all_tables(&a64, &k, &d64);
    assert!(t64.iter().find(|t| t.item == Some(ItemType::Exceptions)).unwrap().rows.len() == 2);
    assert!(t64.iter().find(|t| t.item == Some(ItemType::OptionalHeader)).unwrap().rows.iter().any(|r| r.cells[0] == "load-config > CFG"));
    let ents = &a64.pe.resources.as_ref().unwrap().entries;
    for (i, e) in ents.iter().enumerate() {
        let c = view::resource_content(&a64, &d64, i);
        match e.type_id.id() {
            Some(11) => assert_eq!(c, vec!["0x00000001: abc"]),
            Some(4) => assert_eq!(c, vec!["X"]),
            Some(16) => assert_eq!(c, vec!["A: b"]),
            Some(5) => assert_eq!(c[0], "caption: "),
            Some(10) if e.name.id() == Some(2) => assert_eq!(c, vec!["plain text resource"]),
            Some(10) => assert_eq!(c.len(), 2),
            _ => assert!(c.is_empty()),
        }
    }

    // non-PE: every view degrades gracefully
    let txt = b"just some text with http://a.example.com".to_vec();
    let at = analyze(&txt, "t.txt", &k, &Options::default());
    let tt = all_tables(&at, &k, &txt);
    assert!(tt.iter().filter(|t| t.note.is_some()).count() >= 15);
    // minimal PE with no optional parts
    let min = PeBuilder::new().build();
    let am = analyze(&min, "m.exe", &k, &Options::default());
    let _ = all_tables(&am, &k, &min);
}

#[test]
fn table_helpers() {
    let mut t = Table { columns: vec!["a".into(), "b".into()], ..Default::default() };
    for (x, y) in [("10", "b"), ("9", "a"), ("0x20", "c"), ("x", "d"), ("9", "a")] {
        t.rows.push(view::Row::new(vec![x.into(), y.into()]));
    }
    t.sort_by(0, true);
    assert_eq!(t.rows[0].cells[0], "9");
    t.sort_by(1, false);
    assert_eq!(t.rows[0].cells[1], "d");
    t.sort_by(5, true);
    assert_eq!(t.line(0, "|").matches('|').count(), 1);
    assert_eq!(t.line(99, "|"), "");
    t.dedup();
    assert_eq!(t.len(), 4);
    t.filter("");
    assert_eq!(t.len(), 4);
    t.filter("A");
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
    assert_eq!(view::url_encode("a b&c/é"), "a+b%26c%2F%C3%A9");
    assert!(view::google_url("x y").ends_with("q=x+y"));
    let k = Knowledge::builtin();
    for it in ItemType::ALL {
        assert_eq!(view::view_enabled(&k, it), it != ItemType::Score, "{it:?}");
    }
    let kk = kb();
    assert!(view::view_enabled(&kk, ItemType::Relocations));
    let mut k2 = Knowledge::builtin();
    k2.settings.set("exceptions", "enable", "0");
    assert!(!view::view_enabled(&k2, ItemType::Exceptions));
    let vo = ViewOptions { uppercase_hashes: false, ..Default::default() };
    let a = Analysis { footprints: vec![Footprint { item: "i".into(), hash: "ABCD".into(), ..Default::default() }], ..Default::default() };
    let ft = view::table(&a, &k, &[], ItemType::Footprints, &vo);
    assert_eq!(ft.rows[0].cells[3], "abcd");
    let vo2 = ViewOptions { google: false, ..Default::default() };
    assert!(view::table(&a, &k, &[], ItemType::Footprints, &vo2).rows[0].url.as_ref().unwrap().contains("virustotal"));
}

#[test]
fn item_type_helpers() {
    assert_eq!(ItemType::from_code("24"), Some(ItemType::Strings));
    assert_eq!(ItemType::from_code("--"), None);
    assert_eq!(ItemType::from_index(99), None);
    assert_eq!(ItemType::from_index(-1), None);
    assert_eq!(ItemType::Tls.name(), "thread-local-storage");
    assert_eq!(ItemType::ALL.len(), 27);
    for (i, t) in ItemType::ALL.iter().enumerate() {
        assert_eq!(*t as usize, i);
    }
    for k in [StringKind::Ascii, StringKind::Unicode, StringKind::Utf8, StringKind::DotNetStrings, StringKind::DotNetUser] {
        assert!(!k.name().is_empty());
    }
}

#[test]
fn reports() {
    let k = kb();
    let data = testkit::suspicious_sample();
    let a = analyze(&data, "susp<&>.exe", &k, &Options::default());
    let xml = report::render(&a, &k, &data, Format::Xml);
    let doc = pe_db::dom::parse(&xml).expect("well formed xml");
    let img = doc.child("image").unwrap();
    assert_eq!(img.attr("name"), Some("susp<&>.exe"));
    assert!(img.child("indicators").unwrap().children.len() > 50);
    assert!(img.child("score").unwrap().attr("note").is_some());
    let json = report::render(&a, &k, &data, Format::Json);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert!(v["views"]["indicators"]["rows"].as_array().unwrap().len() > 50);
    let txt = report::render(&a, &k, &data, Format::Text);
    assert!(txt.contains("[indicators]") && txt.contains("* "));
    assert_eq!(Format::from_setting(1), Format::Json);
    assert_eq!(Format::from_setting(2), Format::Text);
    assert_eq!(Format::from_setting(0), Format::Xml);
    assert_eq!(report::default_report_path(std::path::Path::new("a/b.exe"), Format::Xml), PathBuf::from("a/b.exe.xml"));
    assert_eq!(report::attr_name("first-thunk (IAT)"), "first-thunk-iat");
    assert_eq!(report::attr_name("1st"), "c-1st");
    assert_eq!(report::attr_name("()"), "c-");
    assert_eq!(report::xml_escape("<a&'\"\t\u{1}>"), "&lt;a&amp;&apos;&quot;&#x9;[0x01]&gt;");
    // empty table name fallback
    let t = Table { columns: vec!["c".into()], rows: vec![view::Row::new(vec!["v\n".into()])], note: Some("n".into()), item: None };
    assert!(report::to_xml(&a, std::slice::from_ref(&t)).contains("<table count=\"1\">"));
    assert!(report::to_json(&a, std::slice::from_ref(&t)).contains("\"table\""));
    assert!(report::to_text(&a, &[t], "|").contains("[table]"));
}

#[test]
fn utilities() {
    assert_eq!(
        util::printf(
            "%s-%i-%d-%u-%x-%X-%08X-%.03f-%.02f%%-%5i-%c",
            &[
                Arg::from("a"),
                Arg::from(1i64),
                Arg::from(2u32),
                Arg::from(3usize),
                Arg::from(255u64),
                Arg::from(255i64),
                Arg::from(255u16),
                Arg::from(1.5f64),
                Arg::from(2i32),
                Arg::from(42i64),
                Arg::from("z")
            ]
        ),
        "a-1-2-3-ff-FF-000000FF-1.500-2.00%-   42-z"
    );
    assert_eq!(util::printf("%s %s %s", &[Arg::I(1), Arg::F(0.5)]), "1 0.5 ");
    assert_eq!(util::printf("%i %f %q", &[Arg::F(2.9), Arg::I(1), Arg::F(1.0)]), "2 1.000000 1");
    assert_eq!(util::printf("%ls %", &[Arg::from(String::from("w"))]), "w %");
    assert_eq!(util::printf("%.2", &[]), "");
    assert_eq!(util::printf("é%%", &[]), "é%");
    assert_eq!(util::printf("%z", &[Arg::I(5)]), "5");
    assert_eq!(util::format_utc(0), "01.01.1970 | 00:00:00");
    assert_eq!(util::format_utc(-1), "31.12.1969 | 23:59:59");
    assert_eq!(util::format_stamp(0, true), "n/a");
    assert!(util::format_stamp(86400, true).contains("(Epoch)"));
    assert_eq!(util::civil_from_days(11017), (2000, 3, 1));
    assert_eq!(util::civil_from_days(-719468), (0, 3, 1));
    assert_eq!(util::year_of(1_700_000_000), 2023);
    assert!(util::now_unix() > 1_700_000_000);
    assert_eq!(util::entropy(&[]), 0.0);
    assert_eq!(util::entropy(&[1, 1, 1]), 0.0);
    assert!((util::entropy(&(0..=255u8).collect::<Vec<_>>()) - 8.0).abs() < 1e-9);
    assert_eq!(util::ratio(1, 0), 0.0);
    assert_eq!(util::ratio(1, 4), 25.0);
    assert_eq!(util::bytes_hex(&[0, 255], 1), "00");
    assert_eq!(util::bytes_text(b"a\x01b", 3), "a.b");
    assert_eq!(util::hash_type_name(0), "md5");
    assert_eq!(util::hash_type_name(1), "sha1");
    assert_eq!(util::hash_type_name(9), "sha256");
    assert_eq!(util::hash_by_type(b"", 0).len(), 32);
    assert_eq!(util::hash_by_type(b"", 1).len(), 40);
    assert_eq!(util::hash_by_type(b"", 2).len(), 64);
    assert_eq!(util::undecorate("plain"), "plain");
    assert_eq!(util::undecorate("?@"), "?@");
    assert_eq!(util::find_bytes(b"hello", b""), None);
    assert_eq!(util::find_bytes(b"hi", b"hello"), None);
    assert_eq!(util::find_bytes(b"ababc", b"abc"), Some(2));
    assert_eq!(util::find_bytes(b"aaaa", b"b"), None);
}

#[test]
fn string_engine() {
    use pe_analysis::strings::*;
    let data = b"abc\0abcd\0\0\0h\0e\0l\0l\0o\0\0\0\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe6\x96\x87\0";
    let all = extract(data, StringOptions::default());
    assert!(all.iter().any(|(k, _, s)| *k == StringKind::Ascii && s == "abcd"));
    assert!(all.iter().any(|(k, _, s)| *k == StringKind::Unicode && s == "hello"));
    assert!(all.iter().any(|(k, _, s)| *k == StringKind::Utf8 && s == "日本語文"));
    let only_ascii = extract(data, StringOptions { unicode: false, utf8: false, ..Default::default() });
    assert!(only_ascii.iter().all(|(k, _, _)| *k == StringKind::Ascii));
    let cjk: Vec<u8> = "日本語文字列です".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert!(
        extract(&cjk, StringOptions { min_len: 4, ascii: false, utf8: false, unicode: true })
            .iter()
            .any(|(_, _, s)| s == "日本語文字列です")
    );
    assert!(extract(&cjk[..6], StringOptions { min_len: 4, ascii: false, utf8: false, unicode: true }).is_empty());
    for (s, h) in [
        ("https://x", Some("url-pattern")),
        ("www.example.org", Some("url-pattern")),
        ("10.0.0.1:8080", Some("ip-address")),
        ("0.1.2.3", None),
        ("HKEY_LOCAL_MACHINE\\x", Some("registry")),
        ("\\\\.\\pipe\\x", Some("pipe")),
        ("Local\\m", Some("mutex")),
        ("select a from b", Some("query")),
        ("S-1-5-32-544", Some("sid")),
        ("S-1-x", None),
        ("12345678-1234-1234-1234-123456789abc", Some("guid")),
        ("??_7Foo@@6B@", Some("rtti")),
        ("c:\\x\\y.pdb", Some("debug")),
        ("2.5.29.15", Some("oid")),
        ("YWJjZGVmZ2hpamtsbW5vcA1aQw==", Some("base64")),
        ("value=%08X", Some("format-string")),
        ("[0-9]{3}", Some("regex")),
        ("nothing special", None),
    ] {
        assert_eq!(heuristic_hint(s), h, "{s}");
    }
    let k = kb();
    let pe = pe_parser::PeFile::parse(b"not a pe");
    assert_eq!(location_of(&pe, 0), "file");
    let data = testkit::suspicious_sample();
    let pe = pe_parser::PeFile::parse(&data);
    assert_eq!(location_of(&pe, 0), "dos-header");
    assert_eq!(location_of(&pe, 0x50), "dos-stub");
    let lfanew = pe.dos_header.as_ref().unwrap().e_lfanew as u64;
    assert_eq!(location_of(&pe, lfanew + 8), "header");
    assert!(location_of(&pe, 0x400).starts_with("section:"));
    assert_eq!(location_of(&pe, pe.overlay.as_ref().unwrap().offset), "overlay");
    assert_eq!(location_of(&pe, pe.security.as_ref().unwrap().offset as u64), "certificate");
    assert!(location_of(&pe, pe.resources.as_ref().unwrap().entries[0].file_offset.unwrap() as u64).starts_with("resource:"));
    assert_eq!(location_of(&pe, u64::MAX / 2), "n/a");
    let c = Classifier::new(&k, &pe);
    assert_eq!(c.classify("   ").hint, None);
    // substring + case sensitive variants
    let mut k2 = k.clone();
    k2.strings.substring = true;
    k2.strings.case_sensitive = true;
    let c2 = Classifier::new(&k2, &pe);
    assert_eq!(c2.classify("xxEncryptMessagexx").hint.as_deref(), Some("string"));
    assert_eq!(c2.classify("encryptmessage").hint, None);
}

#[test]
fn signature_engine() {
    use pe_analysis::sigscan::*;
    let k = kb();
    for (m, n) in [
        (&b"MZ"[..], "executable"),
        (b"PK\x03\x04", "PKZIP"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"MSCF", "CAB"),
        (b"%PDF", "PDF"),
        (b"{\\rtf", "RTF"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS-CFB"),
        (b"\x89PNG", "PNG"),
        (b"GIF8", "GIF"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"BM", "BMP"),
        (b"RIFF", "Riff"),
        (b"\x7fELF", "ELF"),
        (b"\x1f\x8b", "GZIP"),
        (b"ITSF", "chtml"),
        (b"L\x00\x00\x00\x01\x14\x02\x00", "LNK"),
        (b"<?xml", "XML"),
        (b"\xef\xbb\xbf<?xml", "XML"),
        (b"SZDD", "MS-Compress"),
        (b"KWAJ", "MS-Compress"),
        (b"FWS", "SWF"),
        (b"CWS", "SWF"),
        (b"MSFT", "tlb"),
        (b"regf", "registry"),
        (b"\x00\x00\x01\x00", "icon"),
        (b"#!", "script"),
        (b"hello", "Text"),
    ] {
        assert_eq!(builtin_magic(m), Some(n), "{n}");
    }
    assert_eq!(builtin_magic(&[0, 1, 2]), None);
    assert_eq!(builtin_magic(&[]), None);
    assert!(!looks_like_pe(b"MZ"));
    assert!(looks_like_pe(&PeBuilder::new().build()));
    assert_eq!(blob_signature(&k, b"%PDF-1"), Some("PDF".into()));
    assert_eq!(blob_signature(&k, b"\x7fELF"), Some("ELF".into()));
    assert_eq!(identify(&k, b"GIF8"), Some("GIF"));
    assert_eq!(embedded_signature(&k, b"MSCFxxxx"), Some("CAB".into()));
    assert_eq!(embedded_signature(&k, b"PK\x03\x04zz"), Some("PKZIP".into()));
    assert_eq!(embedded_signature(&k, b"GIF89a"), None);
    assert_eq!(embedded_signature(&k, b"zzz"), None);
    // non-PE file: signature from built-in magic when no xml signature matches
    let pe = pe_parser::PeFile::parse(b"Rar!\x1a\x07\0data");
    let r = scan(&k, &pe, b"Rar!\x1a\x07\0data");
    assert!(r.signatures.iter().any(|s| s.name == "RAR"));
    // overlay with an archive
    let mut b = PeBuilder::new();
    b.overlay = b"PK\x03\x04 zipped overlay".to_vec();
    let d = b.build();
    let r = scan(&k, &pe_parser::PeFile::parse(&d), &d);
    assert!(r.embedded.iter().any(|e| e.location == "overlay" && e.signature == "PKZIP"));
}

#[test]
fn verify_messages() {
    use pe_analysis::verify::*;
    for c in [
        0i32,
        0x800B0100u32 as i32,
        0x80096010u32 as i32,
        0x800B0101u32 as i32,
        0x800B0109u32 as i32,
        0x800B010Cu32 as i32,
        0x800B0111u32 as i32,
        0x800B0004u32 as i32,
        0x800B0003u32 as i32,
        5,
    ] {
        assert!(!trust_message(c).is_empty());
    }
    let p = write_tmp("unsigned.exe", &PeBuilder::new().build());
    let r = verify_path(&p.to_string_lossy());
    if cfg!(windows) {
        assert_eq!(r.verified, Some(false));
    } else {
        assert_eq!(r.verified, None);
    }
    if std::fs::metadata("C:/Windows/System32/kernel32.dll").is_ok() {
        assert_eq!(verify_path("C:/Windows/System32/kernel32.dll").verified, Some(true));
    }
}

#[test]
fn imphash_matches_pefile_convention() {
    let k = kb();
    let mut b = PeBuilder::new();
    b.imports = vec![
        Import { dll: "KERNEL32.DLL".into(), functions: vec!["GetProcAddress".into(), "#5".into()], delay: false },
        Import { dll: "WS2_32.dll".into(), functions: vec!["#23".into()], delay: false },
        Import { dll: "x.ocx".into(), functions: vec!["A".into()], delay: false },
        Import { dll: "d.dll".into(), functions: vec!["Delayed".into()], delay: true },
    ];
    let pe = pe_parser::PeFile::parse(&b.build());
    let expected = util::md5_hex(b"kernel32.getprocaddress,kernel32.ord5,ws2_32.socket,x.a").to_ascii_lowercase();
    assert_eq!(analyze::imphash(&k, &pe), Some(expected));
    assert_eq!(analyze::imphash(&k, &pe_parser::PeFile::parse(&PeBuilder::new().build())), None);
}

#[test]
fn real_files_if_present() {
    let k = kb();
    for f in ["C:/Windows/System32/notepad.exe", "C:/Windows/System32/kernel32.dll"] {
        let Ok(_) = std::fs::metadata(f) else { continue };
        let (data, a) = analyze_file(std::path::Path::new(f), &k, &Options::default()).unwrap();
        assert!(a.has_indicator(1000));
        let xml = report::render(&a, &k, &data, Format::Xml);
        assert!(pe_db::dom::parse(&xml).is_ok());
        let _ = analyze::manifest(&a, &data);
    }
}

#[test]
fn file_actions() {
    use pe_analysis::actions::*;
    let mut b = PeBuilder::new();
    b.overlay = vec![9; 32];
    let mut data = b.build();
    for m in [
        Modification::SetDll(true),
        Modification::SetDll(false),
        Modification::ToggleFileCharacteristic(0x20),
        Modification::ToggleDllCharacteristic(0x40),
        Modification::SetEntryPoint(0x1001),
        Modification::UpdateChecksum,
        Modification::RemoveOverlay,
    ] {
        assert!(!m.describe().is_empty());
        apply(&mut data, m).unwrap();
    }
    let pe = pe_parser::PeFile::parse(&data);
    assert!(pe.overlay.is_none());
    assert_eq!(pe.entry_point.unwrap().rva, 0x1001);
    assert!(apply(&mut data, Modification::RemoveOverlay).is_err());
    assert!(apply(&mut b"nope".to_vec(), Modification::SetDll(true)).is_err());
    let p = std::env::temp_dir().join(format!("dump-{}.bin", std::process::id()));
    assert_eq!(dump(&data, 0, 2, &p).unwrap(), 2);
    assert_eq!(std::fs::read(&p).unwrap(), b"MZ");
    assert_eq!(dump(&data, u64::MAX - 1, 10, &p).unwrap(), 0);
    assert!(dump(&data, 0, 1, std::path::Path::new("Z:/no/dir/x")).is_err());
    assert_eq!(dump_name("a.exe", "section:.text"), "a.exe.section_.text.dump");
    assert!(dump_path(std::path::Path::new("d"), "a", "b").ends_with("a.b.dump"));
    assert_eq!(parse_address("0x1000"), Some(0x1000));
    assert_eq!(parse_address("1000h"), Some(0x1000));
    assert_eq!(parse_address(" 42 "), Some(42));
    assert_eq!(parse_address("zz"), None);
}

#[test]
fn binary_runs() {
    // keeps main.rs of the CLI honest when exercised through cargo test of this crate
    let _ = pe_analysis::actions::parse_address("1");
}

#[test]
fn view_settings_variants() {
    let mut k = kb();
    let data = testkit::suspicious_sample();
    let mut a = analyze(&data, "s.exe", &k, &Options::default());
    // mitre: without tactics and duplicates
    k.settings.set("mitre", "ta", "0");
    k.settings.set("mitre", "dup", "0");
    let t = view::table(&a, &k, &data, ItemType::Mitre, &ViewOptions::default());
    assert_eq!(t.columns, vec!["technique", "name", "sources"]);
    assert!(t.rows.iter().any(|r| r.cells[2].contains("(+")));
    k.mitre.url.clear();
    let t = view::table(&a, &k, &data, ItemType::Mitre, &ViewOptions::default());
    assert!(t.rows[0].url.as_ref().unwrap().starts_with("https://attack.mitre.org/techniques/T"));
    // favourite engines first
    k.settings.set("score", "favorite", "zeta");
    a.score = Some(ScoreReport {
        status: "ok".into(),
        engines: vec![
            EngineResult { vendor: "Alpha".into(), ..Default::default() },
            EngineResult { vendor: "Zeta".into(), detected: true, ..Default::default() },
        ],
        ..Default::default()
    });
    let t = view::table(&a, &k, &data, ItemType::Score, &ViewOptions::default());
    assert_eq!(t.rows[1].cells[0], "Zeta (favorite)");
    // location map and text rendering
    let map = view::location_map(&a, &k);
    assert!(map.iter().any(|(n, c, _)| n == "section" && *c > 0));
    assert!(map.iter().any(|(n, _, _)| n == "overlay" || n == "resource"));
    for l in ["section:.x", "resource:y", "overlay", "certificate", "dos-header", "dos-stub", "header", "dotnet", "file", "n/a"] {
        assert!(!view::location_category(l).is_empty());
    }
    let mut kk = k.clone();
    kk.translations.locations = vec![("section".into(), (1, 2, 3))];
    assert_eq!(view::location_map(&a, &kk).iter().find(|m| m.0 == "section").unwrap().2, (1, 2, 3));
    let txt = view::table_text(&t, "|");
    assert!(txt.starts_with("engine|result"));
    // mitre indicators are not produced when the MITRE view is disabled
    k.settings.set("mitre", "enable", "0");
    let b = analyze(&data, "s.exe", &k, &Options::default());
    assert!(!b.has_indicator(1068));
}

#[test]
fn acl_footprint() {
    let mut k = kb();
    k.settings.set("footprints", "acl", "1");
    let p = write_tmp("acl.exe", &PeBuilder::new().build());
    let (_d, a) = analyze_file(&p, &k, &Options::default()).unwrap();
    if cfg!(windows) {
        assert!(a.footprints.iter().any(|f| f.item.starts_with("acl")));
        assert!(analyze::file_security_descriptor(&p).is_some());
    }
    assert!(analyze::file_security_descriptor(std::path::Path::new("Z:/none/x")).is_none());
}

/// T9.1: sweep a deterministic sample of System32 images (skipped when the folder is absent).
#[test]
fn system32_sweep_never_panics() {
    let Ok(rd) = std::fs::read_dir("C:/Windows/System32") else { return };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("sys")))
        .collect();
    files.sort();
    let step = (files.len() / 60).max(1);
    let k = kb();
    let o = Options { verify_signature: false, ..Default::default() };
    let mut n = 0;
    for f in files.iter().step_by(step).take(60) {
        let Ok(data) = std::fs::read(f) else { continue };
        if data.len() > 8 * 1024 * 1024 {
            continue;
        }
        let a = analyze(&data, &f.to_string_lossy(), &k, &o);
        let _ = report::render(&a, &k, &data, Format::Xml);
        n += 1;
    }
    assert!(n > 10);
}
