use pe_parser::debug::DebugInfo;
use pe_parser::headers::*;
use pe_parser::imports::ImportKind;
use pe_parser::resource_content::*;
use pe_parser::resources::{ResId, resource_type_name};
use pe_parser::testutil::der_builder as d;
use pe_parser::testutil::*;
use pe_parser::*;

fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend([0, 0]);
    v
}

fn string_table_block(strings: &[&str]) -> Vec<u8> {
    let mut b = Vec::new();
    for i in 0..16 {
        match strings.get(i) {
            Some(s) => {
                b.extend((s.encode_utf16().count() as u16).to_le_bytes());
                b.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
            }
            None => b.extend([0, 0]),
        }
    }
    b
}

fn message_table() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(2u32.to_le_bytes());
    // block 0: ids 1..2, block 1: ids 10..10
    b.extend(1u32.to_le_bytes());
    b.extend(2u32.to_le_bytes());
    b.extend(28u32.to_le_bytes());
    b.extend(10u32.to_le_bytes());
    b.extend(10u32.to_le_bytes());
    let e1 = {
        let mut e = Vec::new();
        let t = utf16z("Hello\r\n");
        e.extend(((t.len() + 4) as u16).to_le_bytes());
        e.extend(1u16.to_le_bytes());
        e.extend(t);
        e
    };
    let e2 = {
        let mut e = Vec::new();
        let t = b"ansi\0\0\0\0";
        e.extend(((t.len() + 4) as u16).to_le_bytes());
        e.extend(0u16.to_le_bytes());
        e.extend(t);
        e
    };
    let e3 = e1.clone();
    let after_blocks = 4 + 2 * 12;
    let block1 = after_blocks + e1.len() + e2.len();
    b.extend((block1 as u32).to_le_bytes());
    b.extend(e1);
    b.extend(e2);
    b.extend(e3);
    b
}

fn menu() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 0];
    // popup "File"
    b.extend(0x10u16.to_le_bytes());
    b.extend(utf16z("&File"));
    // item "Open" id 1
    b.extend(0u16.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(utf16z("&Open"));
    // last item end popup
    b.extend(0x80u16.to_le_bytes());
    b.extend(2u16.to_le_bytes());
    b.extend(utf16z("E&xit"));
    b
}

fn menu_ex() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(1u16.to_le_bytes());
    b.extend(4u16.to_le_bytes());
    b.extend(0u32.to_le_bytes()); // help id
    // item: type, state, id, flags(popup=1), text, align, helpid
    b.extend(0u32.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend(5u32.to_le_bytes());
    b.extend(0x81u16.to_le_bytes());
    b.extend(utf16z("Popup"));
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b.extend(0u32.to_le_bytes());
    b
}

fn dialog(extended: bool) -> Vec<u8> {
    let mut b = Vec::new();
    if extended {
        b.extend(1u16.to_le_bytes());
        b.extend(0xffffu16.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(0x40u32.to_le_bytes()); // style DS_SETFONT
        b.extend(1u16.to_le_bytes()); // count
        b.extend([0u8; 8]);
    } else {
        b.extend(0x40u32.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend([0u8; 8]);
    }
    b.extend(0u16.to_le_bytes()); // menu
    b.extend([0xff, 0xff, 0x05, 0x00]); // class ordinal
    b.extend(utf16z("Caption"));
    if extended {
        b.extend([8, 0, 0, 0, 0, 1]);
    } else {
        b.extend(8u16.to_le_bytes());
    }
    b.extend(utf16z("MS Shell Dlg"));
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b.extend(vec![0u8; if extended { 24 } else { 18 }]);
    b.extend([0xff, 0xff, 0x80, 0x00]); // button class
    b.extend(utf16z("OK"));
    b.extend(0u16.to_le_bytes());
    b
}

fn group_icon(cursor: bool) -> Vec<u8> {
    let mut b = vec![0, 0, if cursor { 2 } else { 1 }, 0, 1, 0];
    if cursor {
        b.extend(32u16.to_le_bytes());
        b.extend(64u16.to_le_bytes());
    } else {
        b.extend([0, 16, 0, 0]);
    }
    b.extend(1u16.to_le_bytes());
    b.extend(32u16.to_le_bytes());
    b.extend(1234u32.to_le_bytes());
    b.extend(7u16.to_le_bytes());
    b
}

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="My.App" version="1.0.0.0" processorArchitecture="amd64" publicKeyToken="abc" language="*"/>
  <description>My application</description>
  <dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/></dependentAssembly></dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level="requireAdministrator" uiAccess="true"/>
  </requestedPrivileges></security></trustInfo>
  <application><windowsSettings><autoElevate xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</autoElevate></windowsSettings></application>
</assembly>"#;

fn pogo() -> Vec<u8> {
    let mut b = b"PGU\0".to_vec();
    b.extend(0x1000u32.to_le_bytes());
    b.extend(0x10u32.to_le_bytes());
    b.extend(b".text$mn\0\0\0\0");
    b.extend(0x2000u32.to_le_bytes());
    b.extend(0x20u32.to_le_bytes());
    b.extend(b".rdata\0\0");
    b
}

fn full_builder(is64: bool) -> PeBuilder {
    let mut b = PeBuilder::new();
    b.is64 = is64;
    b.rich = vec![(0x0103, 30159, 12), (0x0001, 0, 3)];
    b.imports = vec![
        Import {
            dll: "KERNEL32.dll".into(),
            functions: vec!["CreateRemoteThread".into(), "VirtualAlloc".into(), "#42".into()],
            delay: false,
        },
        Import { dll: "ws2_32.dll".into(), functions: vec!["#23".into()], delay: false },
        Import { dll: "USER32.dll".into(), functions: vec!["MessageBoxW".into()], delay: true },
    ];
    b.exports = vec![
        Export { name: Some("Alpha".into()), rva: 0x1000, forwarder: None },
        Export { name: None, rva: 0x1002, forwarder: None },
        Export { name: Some("Fwd".into()), rva: 0, forwarder: Some("NTDLL.RtlAllocateHeap".into()) },
        Export { name: None, rva: 0, forwarder: None },
    ];
    b.resources = vec![
        Resource {
            type_id: ResKey::Id(16),
            name: ResKey::Id(1),
            lang: 0x409,
            data: version_resource((1, 2, 3, 4), &[("CompanyName", "ACME"), ("OriginalFilename", "app.exe"), ("FileDescription", "Test")]),
        },
        Resource { type_id: ResKey::Id(24), name: ResKey::Id(1), lang: 0x409, data: MANIFEST.as_bytes().to_vec() },
        Resource { type_id: ResKey::Id(6), name: ResKey::Id(2), lang: 0x409, data: string_table_block(&["first", "", "third"]) },
        Resource { type_id: ResKey::Id(11), name: ResKey::Id(1), lang: 0x409, data: message_table() },
        Resource { type_id: ResKey::Id(4), name: ResKey::Id(1), lang: 0x409, data: menu() },
        Resource { type_id: ResKey::Id(4), name: ResKey::Id(2), lang: 0x409, data: menu_ex() },
        Resource { type_id: ResKey::Id(5), name: ResKey::Id(1), lang: 0x419, data: dialog(false) },
        Resource { type_id: ResKey::Id(5), name: ResKey::Id(2), lang: 0x419, data: dialog(true) },
        Resource { type_id: ResKey::Id(14), name: ResKey::Id(1), lang: 0, data: group_icon(false) },
        Resource { type_id: ResKey::Id(12), name: ResKey::Id(1), lang: 0, data: group_icon(true) },
        Resource {
            type_id: ResKey::Name("PAYLOAD".into()),
            name: ResKey::Name("BIN".into()),
            lang: 0x804,
            data: b"MZ\x90\x00embedded".to_vec(),
        },
    ];
    b.tls_callbacks = 2;
    b.relocations = true;
    b.pdb_path = Some("C:\\build\\app.pdb".into());
    let mut nb10 = b"NB10".to_vec();
    nb10.extend([0u8; 12]);
    nb10.extend(b"old.pdb\0");
    let mut misc = 1u32.to_le_bytes().to_vec();
    misc.extend(40u32.to_le_bytes());
    misc.extend([0, 0, 0, 0]);
    misc.extend(b"image.exe\0");
    let mut miscw = 1u32.to_le_bytes().to_vec();
    miscw.extend(40u32.to_le_bytes());
    miscw.extend([1, 0, 0, 0]);
    miscw.extend(utf16z("wide.exe"));
    let mut repro = 4u32.to_le_bytes().to_vec();
    repro.extend([1, 2, 3, 4]);
    let mut cks = b"SHA256\0".to_vec();
    cks.extend([9u8; 32]);
    b.extra_debug = vec![
        (13, pogo()),
        (12, [1u32, 2, 3, 4, 5].iter().flat_map(|v| v.to_le_bytes()).collect()),
        (20, 1u32.to_le_bytes().to_vec()),
        (16, repro),
        (19, cks),
        (2, nb10),
        (2, b"NB09xxxx".to_vec()),
        (4, misc),
        (4, miscw),
        (99, vec![1, 2, 3]),
    ];
    b.load_config = true;
    b.exceptions = if is64 { 3 } else { 0 };
    b.extra_sections = vec![
        ExtraSection { name: ".upx0".into(), data: vec![], characteristics: 0xe000_0080, virtual_size: Some(0x2000) },
        ExtraSection { name: "".into(), data: vec![0x41; 0x300], characteristics: 0xc000_0040, virtual_size: None },
    ];
    b.overlay = b"OVERLAY-DATA-1234567890".to_vec();
    b.certificate = Some(d::authenticode(false));
    b.fix_checksum = true;
    b
}

fn check_full(is64: bool) {
    let data = full_builder(is64).build();
    let pe = PeFile::parse(&data);
    assert!(pe.is_pe());
    assert_eq!(pe.is_64(), is64);
    assert!(!pe.is_dll());
    assert!(!pe.is_driver());
    assert!(!pe.is_dotnet());
    let l = pe.layout.as_ref().unwrap();

    // DOS / stub / rich
    let dos = pe.dos_header.as_ref().unwrap();
    assert_eq!(dos.e_magic, IMAGE_DOS_SIGNATURE);
    assert_eq!(dos.fields().len(), 31);
    assert_eq!(pe.dos_stub.as_ref().unwrap().message.as_deref(), Some("!This program cannot be run in DOS mode."));
    let rich = pe.rich.as_ref().unwrap();
    assert!(rich.checksum_valid());
    assert_eq!(rich.entries.len(), 2);
    assert_eq!(rich.entries[0].prod_id, 0x103);
    assert_eq!(rich.entries[0].build, 30159);
    assert_eq!(rich.entries[0].comp_id(), (0x103 << 16) | 30159);
    assert_eq!(&rich.raw_decoded[..4], b"DanS");

    // headers
    assert_eq!(machine_name(l.file_header.machine), if is64 { "Amd64" } else { "Intel-386" });
    assert_eq!(machine_is_64(l.file_header.machine), is64);
    assert!(l.file_header.is_executable());
    assert_eq!(subsystem_name(l.optional_header.subsystem), "GUI");
    assert_eq!(os_name(6, 0), "Windows Vista | Server 2008");
    assert_eq!(l.optional_header.data_directories.len(), 16);
    assert_eq!(pe.computed_checksum(&data), Some(l.optional_header.checksum));
    assert_eq!(l.optional_header.base_of_data.is_some(), !is64);

    // sections
    let names: Vec<&str> = l.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec![".text", ".rdata", ".rsrc", ".reloc", ".upx0", ""]);
    let upx = &l.sections[4];
    assert!(upx.is_virtualized() && upx.is_self_modifying() && upx.is_readable());
    assert!(!upx.is_shared());
    assert!(section_flag_names(upx.characteristics).contains(&"writable"));
    assert!(pe.truncated_sections.is_empty());
    assert_eq!(l.section_name_of_rva(0x10), "header");
    assert_eq!(l.section_name_of_rva(0x1000), ".text");
    assert_eq!(l.section_name_of_rva(0xfff_ffff), "n/a");
    assert!(l.offset_to_rva(0x10).is_some());
    assert!(l.offset_to_rva(0x400).is_some());
    assert!(l.offset_to_rva(data.len() as u64 + 10).is_none());
    assert!(l.rva_to_offset(0xfff_ffff).is_none());

    // entry point
    let ep = pe.entry_point.as_ref().unwrap();
    assert_eq!(ep.section.as_deref(), Some(".text"));
    assert!(!ep.zero && !ep.in_header && !ep.outside_image && !ep.in_non_executable_section);
    assert!(!ep.not_in_first_section && !ep.in_last_section);

    // imports
    let imps = &pe.imports;
    assert_eq!(imps.libraries.len(), 3);
    assert_eq!(imps.function_count(), 5);
    assert_eq!(imps.ordinal_count(), 2);
    let k = &imps.libraries[0];
    assert_eq!(k.name, "KERNEL32.dll");
    assert_eq!(k.functions[0].name.as_deref(), Some("CreateRemoteThread"));
    assert_eq!(k.functions[2].ordinal, Some(42));
    assert_eq!(k.functions[2].display_name(), "#42");
    assert_eq!(k.functions[0].display_name(), "CreateRemoteThread");
    assert!(!k.is_bound() && !k.int_missing);
    assert_eq!(k.int_iat_mismatch, 0);
    let dl = &imps.libraries[2];
    assert_eq!(dl.kind, ImportKind::DelayLoaded);
    assert_eq!(dl.functions[0].name.as_deref(), Some("MessageBoxW"));
    assert_eq!(dl.attributes, 1);

    // exports
    let e = pe.exports.as_ref().unwrap();
    assert_eq!(e.dll_name, "test.dll");
    assert_eq!(e.functions.len(), 4);
    assert_eq!(e.forwarded_count(), 1);
    assert_eq!(e.anonymous_count(), 1);
    assert_eq!(e.gap_count(), 1);
    assert_eq!(e.functions[2].forwarder.as_deref(), Some("NTDLL.RtlAllocateHeap"));
    assert_eq!(e.functions[1].display_name(), "#2");
    assert_eq!(e.functions[0].display_name(), "Alpha");
    assert!(e.duplicate_names.is_empty());

    // resources
    let res = pe.resources.as_ref().unwrap();
    assert_eq!(res.entries.len(), 11);
    assert!(res.total_size() > 0);
    assert_eq!(res.loops, 0);
    assert!(res.languages().contains(&0x419));
    let named = res.entries.iter().find(|e| e.type_id == ResId::Name("PAYLOAD".into())).unwrap();
    assert_eq!(named.name.to_string(), "BIN");
    assert_eq!(named.type_name(), "PAYLOAD");
    assert!(!named.is_builtin_type());
    assert_eq!(named.language, 0x804);
    assert_eq!(&pe.resource_data(&data, named)[..2], b"MZ");
    assert_eq!(resource_type_name(16), Some("version"));
    assert_eq!(resource_type_name(999), None);
    assert_eq!(ResId::Id(5).to_string(), "5");
    assert_eq!(ResId::Id(5).id(), Some(5));
    assert_eq!(ResId::Name("x".into()).id(), None);
    assert_eq!(ResId::default(), ResId::Id(0));

    let vi = pe.version_info(&data).unwrap();
    let f = vi.fixed.as_ref().unwrap();
    assert_eq!(f.file_version(), "1.2.3.4");
    assert_eq!(f.product_version(), "1.2.3.4");
    assert_eq!(f.os_name(), "Windows NT | Windows 32-bit");
    assert_eq!(f.type_name(), "executable");
    assert_eq!(f.subtype_name(), "n/a");
    assert!(f.flag_names().is_empty());
    assert_eq!(vi.get("companyname"), Some("ACME"));
    assert_eq!(vi.get("nope"), None);
    assert_eq!(vi.translations, vec![(0x409, 0x4b0)]);

    let (_, m) = pe.manifest(&data).unwrap();
    assert_eq!(m.execution_level.as_deref(), Some("requireAdministrator"));
    assert_eq!(m.ui_access, Some(true));
    assert_eq!(m.auto_elevate, Some(true));
    assert_eq!(m.identity.as_ref().unwrap().name, "My.App");
    assert_eq!(m.identity.as_ref().unwrap().processor_architecture, "amd64");
    assert_eq!(m.dependencies[0].name, "Microsoft.Windows.Common-Controls");
    assert_eq!(m.description.as_deref(), Some("My application"));
    assert!(m.has_trust_info && !m.malformed);

    let st = res.of_type(6).next().unwrap();
    let strings = parse_string_table(pe.resource_data(&data, st), 2);
    assert_eq!(strings, vec![(16, "first".to_string()), (18, "third".to_string())]);
    let mt = res.of_type(11).next().unwrap();
    let msgs = parse_message_table(pe.resource_data(&data, mt));
    assert_eq!(msgs, vec![(1, "Hello".to_string()), (2, "ansi".to_string()), (10, "Hello".to_string())]);
    let menus: Vec<_> = res.of_type(4).collect();
    assert_eq!(parse_menu(pe.resource_data(&data, menus[0])), vec!["&File", "&Open", "E&xit"]);
    assert_eq!(parse_menu(pe.resource_data(&data, menus[1])), vec!["Popup"]);
    let dlgs: Vec<_> = res.of_type(5).collect();
    for dd in dlgs {
        let dl = parse_dialog(pe.resource_data(&data, dd)).unwrap();
        assert_eq!(dl.caption, "Caption");
        assert_eq!(dl.font, "MS Shell Dlg");
        assert_eq!(dl.controls, vec!["OK"]);
    }
    let gi = parse_group_icon(pe.resource_data(&data, res.of_type(14).next().unwrap()), false);
    assert_eq!((gi[0].width, gi[0].height, gi[0].id, gi[0].bytes_in_res), (256, 16, 7, 1234));
    let gc = parse_group_icon(pe.resource_data(&data, res.of_type(12).next().unwrap()), true);
    assert_eq!((gc[0].width, gc[0].height), (32, 32));

    // debug
    assert_eq!(pe.debug.len(), 11);
    let rsds = &pe.debug[0];
    assert_eq!(rsds.type_name(), "CodeView");
    assert_eq!(rsds.pdb_path(), Some("C:\\build\\app.pdb"));
    match &rsds.info {
        DebugInfo::Rsds { guid, age, .. } => {
            assert_eq!(*age, 1);
            assert_eq!(debug::format_guid(guid), "03020100-0504-0706-0809-0A0B0C0D0E0F");
        }
        x => panic!("{x:?}"),
    }
    let kinds: Vec<&str> = pe.debug.iter().map(|d| d.type_name()).collect();
    assert!(kinds.contains(&"POGO") && kinds.contains(&"vcFeature") && kinds.contains(&"REPRO"));
    assert!(matches!(pe.debug[1].info, DebugInfo::Pogo { ref entries, .. } if entries.len() == 2 && entries[0].2 == ".text$mn"));
    assert!(matches!(pe.debug[2].info, DebugInfo::VcFeature { pre_vc11: 1, c_cpp: 2, gs: 3, sdl: 4, guard_n: 5 }));
    assert!(matches!(pe.debug[3].info, DebugInfo::ExDllCharacteristics { flags: 1 }));
    assert!(matches!(pe.debug[4].info, DebugInfo::Repro { ref hash } if hash == &[1, 2, 3, 4]));
    assert!(matches!(pe.debug[5].info, DebugInfo::PdbChecksum { ref algorithm, .. } if algorithm == "SHA256"));
    assert_eq!(pe.debug[6].pdb_path(), Some("old.pdb"));
    assert!(matches!(pe.debug[7].info, DebugInfo::CodeViewOther { ref signature } if signature == "NB09"));
    assert!(matches!(pe.debug[8].info, DebugInfo::Misc { unicode: false, ref text, .. } if text == "image.exe"));
    assert!(matches!(pe.debug[9].info, DebugInfo::Misc { unicode: true, ref text, .. } if text == "wide.exe"));
    assert!(matches!(pe.debug[10].info, DebugInfo::None));
    assert_eq!(pe.debug[10].pdb_path(), None);
    assert!(!pe.debug[0].data(&reader::Reader::new(&data)).is_empty());

    // TLS / relocations / exceptions / load config
    let tls = pe.tls.as_ref().unwrap();
    assert_eq!(tls.callbacks.len(), 2);
    assert_eq!(pe.relocations.len(), 1);
    assert_eq!(pe.relocations[0].entries.len(), 4);
    assert_eq!(misc_dirs::relocation_type_name(pe.relocations[0].entries[0].0), if is64 { "dir64" } else { "high-low" });
    assert_eq!(pe.exceptions.len(), if is64 { 3 } else { 0 });
    let lc = pe.load_config.as_ref().unwrap();
    assert!(lc.has_gs() && lc.has_cfg());
    assert_eq!(lc.has_safe_seh(), !is64);

    // certificate
    let sec = pe.security.as_ref().unwrap();
    assert_eq!(sec.entries.len(), 1);
    let wc = &sec.entries[0];
    assert_eq!(certificate::cert_revision_name(wc.revision), "WIN_CERT_REVISION_2_0");
    assert_eq!(certificate::cert_type_name(wc.certificate_type), "WIN_CERT_TYPE_PKCS_SIGNED_DATA");
    assert_eq!(wc.tail, 0);
    assert!(!sec.not_at_end);
    let a = sec.authenticode().unwrap();
    assert_eq!(a.digest_algorithm, "sha256");
    assert_eq!(a.image_digest, vec![0xab; 32]);
    assert_eq!(a.certificates.len(), 2);
    let s = a.signer.as_ref().unwrap();
    assert_eq!(s.serial, "91");
    assert_eq!(s.program_name.as_deref(), Some("Prog"));
    assert_eq!(s.more_info_url.as_deref(), Some("http://more.info"));
    assert_eq!(s.signing_time, Some(1612325106));
    assert_eq!(s.digest_algorithm, "sha256");
    assert_eq!(s.encryption_algorithm, "rsa");
    let sc = a.signer_certificate().unwrap();
    assert_eq!(sc.subject_cn, "Signer Co");
    assert_eq!(sc.issuer_cn, "Test CA");
    assert_eq!(sc.email.as_deref(), Some("a@b.c"));
    assert_eq!(sc.crl_urls, vec!["http://crl.test/ca.crl"]);
    assert_eq!(sc.purposes, vec!["Code Signing"]);
    assert_eq!(sc.signature_algorithm, "sha256RSA");
    assert_eq!(sc.valid_from, Some(1577836800));
    assert_eq!(sc.valid_to, Some(1893456000));
    assert!(sc.subject.contains("CN=Signer Co") && sc.subject.contains("C=US"));
    assert_eq!(a.counter_signer.as_ref().unwrap().signing_time, Some(1612325107));
    assert_eq!(a.counter_signer_certificate().unwrap().subject_cn, "TS Counter");
    assert_eq!(a.nested_signatures, 2);

    // overlay sits before the certificate
    let ov = pe.overlay.as_ref().unwrap();
    assert_eq!(&data[ov.offset as usize..ov.offset as usize + 7], b"OVERLAY");
}

#[test]
fn full_pe32() {
    check_full(false);
}

#[test]
fn full_pe64() {
    check_full(true);
}

#[test]
fn rfc3161_timestamp_and_tail() {
    let mut cert = d::authenticode(true);
    cert.extend([0xde, 0xad, 0, 0, 0, 0]);
    let mut b = PeBuilder::new();
    b.certificate = Some(cert);
    let data = b.build();
    let pe = PeFile::parse(&data);
    let wc = &pe.security.as_ref().unwrap().entries[0];
    assert_eq!(wc.tail, 2);
    assert!(wc.null_padding >= 4);
    let a = wc.pkcs7.as_ref().unwrap();
    let cs = a.counter_signer.as_ref().unwrap();
    assert_eq!(cs.signing_time, Some(1646370367));
    assert!(a.certificates.iter().any(|c| c.subject_cn == "TS Signer"));
    // no overlay: the certificate closes the file
    assert!(pe.overlay.is_none());
}

#[test]
fn dotnet_metadata() {
    let mut b = PeBuilder::new();
    b.dotnet = Some(DotNetSpec {
        module: "evil.exe".into(),
        type_refs: vec![("System.Net".into(), "WebClient".into()), ("".into(), "Object".into())],
        member_refs: vec![(1, "DownloadString".into())],
        module_refs: vec!["kernel32.dll".into()],
        impl_maps: vec![("VirtualAlloc".into(), 1)],
        assembly: Some("Evil".into()),
        user_strings: vec!["http://bad.example/x".into(), "".into()],
        guid_attribute: Some("11111111-2222-3333-4444-555555555555".into()),
        extra_stream: Some("#Weird".into()),
        unknown_table: false,
    });
    let data = b.build();
    let pe = PeFile::parse(&data);
    assert!(pe.is_dotnet());
    let n = pe.dotnet.as_ref().unwrap();
    assert!(n.is_strong_name_signed());
    assert_eq!(n.header.major_runtime_version, 2);
    assert_eq!(n.runtime_version, "v4.0.30319");
    assert_eq!(n.metadata_signature, 0x424A_5342);
    assert_eq!(n.streams.len(), 6);
    assert!(n.stream("#Weird").is_some());
    assert!(n.stream("#Nope").is_none());
    assert_eq!(n.module_name, "evil.exe");
    assert!(n.module_mvid.is_some());
    assert_eq!(n.type_refs[0].full_name(), "System.Net.WebClient");
    assert_eq!(n.type_refs[1].full_name(), "Object");
    assert_eq!(n.member_refs[0].name, "DownloadString");
    assert_eq!(n.member_refs[0].parent, "System.Net.WebClient");
    assert_eq!(n.module_refs, vec!["kernel32.dll"]);
    assert_eq!(n.impl_maps[0].import_name, "VirtualAlloc");
    assert_eq!(n.impl_maps[0].module, "kernel32.dll");
    assert_eq!(n.assembly.as_ref().unwrap().name, "Evil");
    assert_eq!(n.assembly.as_ref().unwrap().version, "1.2.3.4");
    assert_eq!(n.typelib_id.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
    assert!(n.custom_attributes.iter().any(|a| a.ends_with("GuidAttribute")));
    assert_eq!(n.user_strings, vec!["http://bad.example/x"]);
    assert!(n.strings_heap.contains(&"WebClient".to_string()));
    assert_eq!(n.row_count(0), 1);
    assert_eq!(n.row_count(99), 0);
    assert_eq!(dotnet::TABLE_NAMES[28], "ImplMap");
    assert_eq!(dotnet::compressed_u32(&[0x81, 0x02], 0), Some((0x102, 2)));
    assert_eq!(dotnet::compressed_u32(&[0xc0, 0, 1, 2], 0), Some((0x102, 4)));
    assert_eq!(dotnet::compressed_u32(&[0xff], 0), None);
}

#[test]
fn dll_driver_and_odd_entry_points() {
    let mut b = PeBuilder::new();
    b.dll = true;
    b.entry_offset_in_text = None;
    b.subsystem = 1;
    let data = b.build();
    let pe = PeFile::parse(&data);
    assert!(pe.is_dll() && pe.is_driver());
    assert!(pe.entry_point.as_ref().unwrap().zero);

    // entry point in the header and outside the image
    let mut data = PeBuilder::new().build();
    let pe = PeFile::parse(&data);
    patch::set_entry_point(&mut data, &pe, 0x10).unwrap();
    let pe2 = PeFile::parse(&data);
    assert!(pe2.entry_point.as_ref().unwrap().in_header);
    patch::set_entry_point(&mut data, &pe, 0x7fff_0000).unwrap();
    let pe3 = PeFile::parse(&data);
    assert!(pe3.entry_point.as_ref().unwrap().outside_image);
    // entry point in a non-executable last section
    let rdata = pe.layout.as_ref().unwrap().sections[1].virtual_address;
    patch::set_entry_point(&mut data, &pe, rdata).unwrap();
    let pe4 = PeFile::parse(&data);
    let ep = pe4.entry_point.as_ref().unwrap();
    assert!(ep.in_non_executable_section && ep.not_in_first_section && ep.in_last_section);
}

#[test]
fn patches() {
    let mut b = PeBuilder::new();
    b.overlay = vec![1, 2, 3];
    b.certificate = Some(vec![0x30, 0x00]);
    let mut data = b.build();
    let pe = PeFile::parse(&data);
    assert!(!pe.is_dll());
    let v = patch::set_dll(&mut data, &pe, true).unwrap();
    assert!(v & file_characteristics::DLL != 0);
    assert!(PeFile::parse(&data).is_dll());
    let v = patch::set_dll(&mut data, &pe, false).unwrap();
    assert_eq!(v & file_characteristics::DLL, 0);
    let v = patch::toggle_file_characteristic(&mut data, &pe, file_characteristics::LARGE_ADDRESS_AWARE).unwrap();
    assert!(v & file_characteristics::LARGE_ADDRESS_AWARE != 0);
    let v = patch::toggle_dll_characteristic(&mut data, &pe, dll_characteristics::DYNAMIC_BASE).unwrap();
    assert_eq!(v & dll_characteristics::DYNAMIC_BASE, 0);
    let c = patch::update_checksum(&mut data, &pe).unwrap();
    assert_eq!(PeFile::parse(&data).layout.unwrap().optional_header.checksum, c);
    let pe = PeFile::parse(&data);
    let ov = pe.overlay.clone().unwrap();
    assert_eq!(&data[ov.offset as usize..ov.offset as usize + 3], &[1, 2, 3]);
    assert_eq!(ov.size, 8, "overlay keeps the alignment padding before the certificate");
    let removed = patch::remove_overlay(&mut data, &pe).unwrap();
    assert!(removed >= 3);
    let pe2 = PeFile::parse(&data);
    assert!(pe2.overlay.is_none());
    assert!(pe2.security.is_none(), "certificate after the overlay is dropped too");
    assert_eq!(patch::remove_overlay(&mut data, &pe2), Err(patch::PatchError::NoOverlay));

    let not_pe = PeFile::parse(b"hello");
    let mut buf = b"hello".to_vec();
    assert_eq!(patch::set_dll(&mut buf, &not_pe, true), Err(patch::PatchError::NotPe));
    assert_eq!(patch::PatchError::NotPe.to_string(), "not a PE image");
    assert_eq!(patch::PatchError::OutOfBounds.to_string(), "field outside of the file");
    assert_eq!(patch::PatchError::NoOverlay.to_string(), "the file has no overlay");
    let _: &dyn std::error::Error = &patch::PatchError::NotPe;
    // out of bounds write
    let mut tiny = data[..0x80].to_vec();
    assert_eq!(patch::set_entry_point(&mut tiny, &pe, 1), Err(patch::PatchError::OutOfBounds));
    // odd-length checksum input
    assert_eq!(patch::compute_checksum(&[1, 2, 3], 100), 0x0201 + 3 + 3);
}

#[test]
fn not_pe_inputs() {
    for d in [&b""[..], b"MZ", b"ZM\0\0", &[0u8; 64][..]] {
        let pe = PeFile::parse(d);
        assert!(!pe.is_pe() && !pe.is_64() && !pe.is_dll() && !pe.is_dotnet() && !pe.is_driver());
        assert!(pe.sections().is_empty());
        assert!(pe.version_info(d).is_none());
        assert!(pe.manifest(d).is_none());
        assert!(pe.computed_checksum(d).is_none());
    }
    // MZ with bad PE signature
    let mut data = PeBuilder::new().build();
    let lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data[lfanew] = b'X';
    let pe = PeFile::parse(&data);
    assert!(pe.dos_header.is_some() && !pe.pe_signature_valid && !pe.is_pe());
}

#[test]
fn malformed_never_panics() {
    let mut b = full_builder(false);
    b.dotnet = Some(DotNetSpec {
        module: "m".into(),
        type_refs: vec![("A".into(), "B".into())],
        member_refs: vec![(1, "C".into())],
        module_refs: vec!["k".into()],
        impl_maps: vec![("f".into(), 1)],
        assembly: Some("a".into()),
        user_strings: vec!["s".into()],
        guid_attribute: Some("g".into()),
        extra_stream: None,
        unknown_table: false,
    });
    for base in [b.build(), full_builder(true).build()] {
        // truncations
        let step = (base.len() / 97).max(1);
        let mut n = 0;
        while n < base.len() {
            let pe = PeFile::parse(&base[..n]);
            let _ = pe.version_info(&base[..n]);
            n += step;
        }
        // deterministic byte corruption
        let mut seed: u64 = 0x1234_5678;
        for _ in 0..300 {
            let mut d = base.clone();
            for _ in 0..16 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let pos = (seed >> 33) as usize % d.len();
                d[pos] = (seed >> 17) as u8;
            }
            let pe = PeFile::parse(&d);
            let _ = pe.version_info(&d);
            let _ = pe.manifest(&d);
            let _ = pe.computed_checksum(&d);
        }
    }
}

#[test]
fn content_decoders_edge_cases() {
    assert!(VersionInfo::parse(&[]).is_none());
    assert!(VersionInfo::parse(&[2, 0, 0, 0, 0, 0]).is_none());
    let mut bad = version_resource((1, 0, 0, 0), &[]);
    bad[6] = b'X';
    assert!(VersionInfo::parse(&bad).is_none());
    assert!(parse_message_table(&[]).is_empty());
    assert!(parse_menu(&[]).is_empty());
    assert!(parse_dialog(&[]).is_none());
    assert!(parse_group_icon(&[], false).is_empty());
    assert_eq!(parse_string_table(&[], 1), vec![]);
    let m = Manifest::parse(b"not xml");
    assert!(m.malformed && m.identity.is_none());
    assert_eq!(decode_text(&[0xff, 0xfe, b'a', 0, b'b', 0]), "ab");
    assert_eq!(decode_text(&[b'a', 0, b'b', 0]), "ab");
    assert_eq!(decode_text(&[0xef, 0xbb, 0xbf, b'x']), "x");

    let fi =
        FixedFileInfo { file_type: 3, file_subtype: 6, file_os: 0x10000, file_flags: 0x3, file_flags_mask: 0x3f, ..Default::default() };
    assert_eq!(fi.type_name(), "device-driver");
    assert_eq!(fi.subtype_name(), "Network-driver");
    assert_eq!(fi.os_name(), "MS-DOS");
    assert_eq!(fi.flag_names(), vec!["debug", "prerelease"]);
    let font = FixedFileInfo { file_type: 4, file_subtype: 3, ..Default::default() };
    assert_eq!(font.subtype_name(), "truetype-font");
    assert_eq!(FixedFileInfo { file_type: 9, ..Default::default() }.type_name(), "unknown");
    for (t, os) in [(1u32, "Windows 16-bit"), (0x40000, "Windows NT"), (0x30000, "OS/2 32-bit"), (77, "Unknown")] {
        assert_eq!(FixedFileInfo { file_os: t, ..Default::default() }.os_name(), os);
    }
    for t in 0..25 {
        let _ = debug::debug_type_name(t);
    }
    for t in 0..12 {
        let _ = misc_dirs::relocation_type_name(t);
    }
    for m in [0x14c, 0x8664, 0xaa64, 0x1c0, 0x1234] {
        let _ = machine_name(m);
    }
    for s in 0..20 {
        let _ = subsystem_name(s);
    }
    for (a, b) in [(10, 0), (6, 3), (6, 2), (6, 1), (5, 2), (5, 1), (5, 0), (4, 0), (1, 1)] {
        let _ = os_name(a, b);
    }
    assert_eq!(certificate::cert_revision_name(0x100), "WIN_CERT_REVISION_1_0");
    assert_eq!(certificate::cert_revision_name(7), "unknown");
    for t in 0..6 {
        let _ = certificate::cert_type_name(t);
    }
}

#[test]
fn der_helpers() {
    use pe_parser::der;
    assert!(der::parse(&[]).is_none());
    assert!(der::parse(&[0x30]).is_none());
    assert!(der::parse(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
    // indefinite length
    let t = der::parse(&[0x30, 0x80, 0x02, 0x01, 0x05, 0, 0]).unwrap();
    assert_eq!(t.children().len(), 1);
    assert_eq!(der::oid_to_string(&[]), "");
    assert_eq!(der::oid_name("9.9.9"), "");
    let utc_b = d::utc("491231235959Z");
    let utc = der::parse(&utc_b).unwrap();
    assert_eq!(der::parse_time(&utc), Some(2524607999));
    let utc50_b = d::utc("500101000000Z");
    let utc50 = der::parse(&utc50_b).unwrap();
    assert_eq!(der::parse_time(&utc50), Some(-631152000));
    let bad_b = d::printable("x");
    let bad = der::parse(&bad_b).unwrap();
    assert_eq!(der::parse_time(&bad), None);
    let b_b = d::bmp("hé");
    let b = der::parse(&b_b).unwrap();
    assert_eq!(der::string_value(&b), "hé");
    let n_b = d::name(&[("2.5.4.3", "cn"), ("1.2.3.4", "x")]);
    let n = der::parse(&n_b).unwrap();
    assert_eq!(der::name_to_string(&n), "CN=cn, 1.2.3.4=x");
    assert_eq!(der::name_attr(&n, "O"), None);
    assert_eq!(der::days_from_civil(1970, 1, 1), 0);
    assert_eq!(der::days_from_civil(2000, 3, 1), 11017);
    assert_eq!(der::days_from_civil(-1, 3, 1), -719468 - 366);
    assert!(certificate::parse_pkcs7(&d::seq(&[d::oid("1.2.3")])).is_none());
    assert!(certificate::parse_pkcs7(&d::int(&[1])).is_none());
    assert!(certificate::parse_x509(&der::parse(&d::seq(&[])).unwrap()).is_none());
    let long = d::octet(&vec![7u8; 70000]);
    assert_eq!(der::parse(&long).unwrap().content.len(), 70000);
}

#[test]
fn reader_and_layout_helpers() {
    let r = reader::Reader::new(&[1, 0, 2, 0, 0, 0, b'a', b'b', 0, b'c', 0, 0, 0]);
    assert_eq!(r.len(), 13);
    assert!(!r.is_empty());
    assert_eq!(r.u16(0), Some(1));
    assert_eq!(r.u32(2), Some(2));
    assert_eq!(r.u64(100), None);
    assert_eq!(r.bytes(usize::MAX, 2), None);
    assert_eq!(r.bytes_clamped(100, 4), &[] as &[u8]);
    assert_eq!(r.bytes_clamped(11, 100).len(), 2);
    assert_eq!(r.cstr(6, 100).as_deref(), Some("ab"));
    assert_eq!(r.cstr(100, 1), None);
    assert_eq!(r.wstr(9, 10).as_deref(), Some("c"));
    assert_eq!(r.wstr(12, 10), None);
    assert_eq!(r.wstr_n(9, 1).as_deref(), Some("c"));
    assert_eq!(r.data().len(), 13);
    assert_eq!(reader::align_up(5, 0), 5);
    assert_eq!(reader::align_down(5, 0), 5);
    assert_eq!(reader::align_up(5, 4), 8);
    assert_eq!(reader::align_down(5, 4), 4);
    assert!(reader::Reader::new(&[]).is_empty());
}

#[test]
fn bound_imports_and_mismatches() {
    // Hand craft: bound import directory in the header area + IAT that differs from INT.
    let mut b = PeBuilder::new();
    b.imports = vec![Import { dll: "a.dll".into(), functions: vec!["F1".into(), "F2".into()], delay: false }];
    let mut data = b.build();
    let pe = PeFile::parse(&data);
    let l = pe.layout.as_ref().unwrap().clone();
    let lib = &pe.imports.libraries[0];
    // corrupt IAT entries: one inside the image, one far outside
    let iat_off = l.rva_to_offset(lib.iat_rva).unwrap();
    data[iat_off..iat_off + 4].copy_from_slice(&0x0040_1000u32.to_le_bytes());
    data[iat_off + 4..iat_off + 8].copy_from_slice(&0x7700_0000u32.to_le_bytes());
    // bound import directory at 0x300 (header slack)
    let bound_off = 0x300usize;
    let mut bd = Vec::new();
    bd.extend(0x1111u32.to_le_bytes());
    bd.extend(24u16.to_le_bytes());
    bd.extend(1u16.to_le_bytes());
    bd.extend(0x2222u32.to_le_bytes());
    bd.extend(30u16.to_le_bytes());
    bd.extend(0u16.to_le_bytes());
    bd.extend([0u8; 8]);
    bd.extend(b"a.dll\0");
    bd.extend(b"b.dll\0");
    data[bound_off..bound_off + bd.len()].copy_from_slice(&bd);
    let dd = l.optional_header.data_directories_offset as usize + 11 * 8;
    data[dd..dd + 4].copy_from_slice(&(bound_off as u32).to_le_bytes());
    data[dd + 4..dd + 8].copy_from_slice(&(bd.len() as u32).to_le_bytes());
    // remove INT so the IAT is used
    let pe2 = PeFile::parse(&data);
    let lib2 = &pe2.imports.libraries[0];
    assert_eq!(lib2.int_iat_mismatch, 2);
    assert_eq!(lib2.invalid_iat_entries, 1);
    assert_eq!(pe2.imports.bound.len(), 1);
    assert_eq!(pe2.imports.bound[0].module_name, "a.dll");
    assert_eq!(pe2.imports.bound[0].forwarders[0].module_name, "b.dll");
    let desc = lib.descriptor_offset as usize;
    data[desc..desc + 4].copy_from_slice(&0u32.to_le_bytes());
    let pe3 = PeFile::parse(&data);
    assert!(pe3.imports.libraries[0].int_missing);
}

#[test]
fn duplicate_exports_and_long_section_names() {
    let mut b = PeBuilder::new();
    b.exports = vec![
        Export { name: Some("Same".into()), rva: 0x1000, forwarder: None },
        Export { name: Some("Same".into()), rva: 0x1001, forwarder: None },
    ];
    let data = b.build();
    let pe = PeFile::parse(&data);
    assert_eq!(pe.exports.as_ref().unwrap().duplicate_names, vec!["Same"]);

    // "/4" section name resolved through the COFF string table
    let mut data = PeBuilder::new().build();
    let pe = PeFile::parse(&data);
    let l = pe.layout.as_ref().unwrap();
    let fh = l.file_header.offset as usize;
    let strtab = data.len();
    data.extend(20u32.to_le_bytes());
    data.extend(b".debug_info\0");
    data[fh + 8..fh + 12].copy_from_slice(&(strtab as u32).to_le_bytes());
    data[fh + 12..fh + 16].copy_from_slice(&0u32.to_le_bytes());
    let sh = l.sections[0].header_offset as usize;
    data[sh..sh + 8].copy_from_slice(b"/4\0\0\0\0\0\0");
    let pe2 = PeFile::parse(&data);
    assert_eq!(pe2.sections()[0].name, ".debug_info");
}

#[test]
fn resource_loop_and_truncated_sections() {
    let mut b = PeBuilder::new();
    b.resources = vec![Resource { type_id: ResKey::Id(10), name: ResKey::Id(1), lang: 0, data: vec![1, 2, 3] }];
    let mut data = b.build();
    let pe = PeFile::parse(&data);
    let res_off = pe.resources.as_ref().unwrap().offset as usize;
    // make the first type entry point back at the root directory
    data[res_off + 16 + 4..res_off + 16 + 8].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let pe2 = PeFile::parse(&data);
    assert!(pe2.resources.as_ref().unwrap().loops > 0);

    let full = PeBuilder::new().build();
    let cut = &full[..full.len() - 0x100];
    let pe3 = PeFile::parse(cut);
    assert!(!pe3.truncated_sections.is_empty());
}

#[test]
fn security_directory_odd_cases() {
    // directory pointing past the end of the file
    let mut data = PeBuilder::new().build();
    let pe = PeFile::parse(&data);
    let dd = pe.layout.as_ref().unwrap().optional_header.data_directories_offset as usize + 4 * 8;
    data[dd..dd + 4].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
    data[dd + 4..dd + 8].copy_from_slice(&16u32.to_le_bytes());
    let pe2 = PeFile::parse(&data);
    assert!(pe2.security.as_ref().unwrap().entries.is_empty());

    // certificate followed by trailing data → overlay after the directory
    let mut b = PeBuilder::new();
    b.certificate = Some(d::authenticode(false));
    let mut data = b.build();
    data.extend(b"appended after signature");
    let pe3 = PeFile::parse(&data);
    assert!(pe3.security.as_ref().unwrap().not_at_end);
    let ov = pe3.overlay.as_ref().unwrap();
    assert_eq!(ov.size as usize, b"appended after signature".len());

    // X.509 (type 1) entry is kept but not decoded
    let mut b = PeBuilder::new();
    b.certificate = Some(vec![0x30, 0x00]);
    let mut data = b.build();
    let pe4 = PeFile::parse(&data);
    let off = pe4.security.as_ref().unwrap().offset as usize;
    data[off + 6] = 1;
    let pe5 = PeFile::parse(&data);
    assert!(pe5.security.as_ref().unwrap().authenticode().is_none());
}

/// Real-world files (Windows only, skipped when missing).
#[test]
fn system_binaries_if_present() {
    let files = [
        "C:/Windows/System32/notepad.exe",
        "C:/Windows/System32/kernel32.dll",
        "C:/Windows/System32/ntdll.dll",
        "C:/Windows/SysWOW64/kernel32.dll",
        "C:/Windows/System32/drivers/null.sys",
        "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/mscorlib.dll",
    ];
    for f in files {
        let Ok(data) = std::fs::read(f) else { continue };
        let pe = PeFile::parse(&data);
        assert!(pe.is_pe(), "{f}");
        assert_eq!(pe.computed_checksum(&data), Some(pe.layout.as_ref().unwrap().optional_header.checksum), "{f}");
        assert!(pe.rich.as_ref().is_none_or(|r| r.checksum_valid()), "{f}");
    }
}

/// Code review #1: deeply nested counter-signatures must not overflow the stack.
#[test]
fn deeply_nested_counter_signatures() {
    let leaf = d::seq(&[
        d::int(&[1]),
        d::seq(&[d::name(&[("2.5.4.3", "x")]), d::int(&[1])]),
        d::alg("1.3.14.3.2.26"),
        d::alg("1.2.840.113549.1.1.1"),
        d::octet(&[0]),
    ]);
    // Build 3000 levels iteratively (a recursive builder would itself be the problem).
    let mut inner = leaf;
    for _ in 0..3000 {
        inner = d::seq(&[
            d::int(&[1]),
            d::seq(&[d::name(&[("2.5.4.3", "x")]), d::int(&[1])]),
            d::alg("1.3.14.3.2.26"),
            d::alg("1.2.840.113549.1.1.1"),
            d::octet(&[0]),
            d::ctx(1, &[d::seq(&[d::oid("1.2.840.113549.1.9.6"), d::set(&[inner])])]),
        ]);
    }
    let sd = d::seq(&[d::int(&[1]), d::set(&[]), d::seq(&[d::oid("1.3.6.1.4.1.311.2.1.4")]), d::set(&[inner])]);
    let blob = d::seq(&[d::oid("1.2.840.113549.1.7.2"), d::ctx(0, &[sd])]);
    // Run on a small stack: without the nesting limit this aborts the process.
    let h = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let a = certificate::parse_pkcs7(&blob).unwrap();
            assert!(a.signer.is_some() && a.counter_signer.is_some());
        })
        .unwrap();
    h.join().unwrap();
}

/// Code review #2: many descriptors sharing one huge thunk table stay bounded.
#[test]
fn import_budget_is_global() {
    let mut b = PeBuilder::new();
    b.extra_sections =
        vec![ExtraSection { name: ".imp".into(), data: vec![0u8; 0x200 + 30_001 * 4], characteristics: 0x4000_0040, virtual_size: None }];
    let mut data = b.build();
    let pe = PeFile::parse(&data);
    let l = pe.layout.as_ref().unwrap().clone();
    let s = l.sections.iter().find(|s| s.name == ".imp").unwrap().clone();
    let (raw, va) = (s.pointer_to_raw_data as usize, s.virtual_address);
    data[raw..raw + 6].copy_from_slice(b"a.dll\0");
    let table = 0x200u32;
    for i in 0..30_000usize {
        let o = raw + table as usize + i * 4;
        data[o..o + 4].copy_from_slice(&0x8000_0001u32.to_le_bytes());
    }
    for k in 0..10usize {
        let o = raw + 16 + k * 20;
        data[o..o + 4].copy_from_slice(&(va + table).to_le_bytes()); // INT
        data[o + 12..o + 16].copy_from_slice(&va.to_le_bytes()); // name
        data[o + 16..o + 20].copy_from_slice(&(va + table).to_le_bytes()); // IAT
    }
    let dd = l.optional_header.data_directories_offset as usize + 8;
    data[dd..dd + 4].copy_from_slice(&(va + 16).to_le_bytes());
    data[dd + 4..dd + 8].copy_from_slice(&(11u32 * 20).to_le_bytes());
    let pe = PeFile::parse(&data);
    assert_eq!(pe.imports.function_count(), imports::MAX_TOTAL_FUNCTIONS);
    assert!(pe.imports.truncated);
    assert!(pe.imports.libraries.len() < 10, "parsing stops once the budget is spent");
    assert!(!PeFile::parse(&PeBuilder::new().build()).imports.truncated);
}

/// Code review #5: rows declared for an unknown table do not hide the known tables.
#[test]
fn dotnet_unknown_table_keeps_known_tables() {
    let mut b = PeBuilder::new();
    b.dotnet = Some(DotNetSpec {
        module: "m.exe".into(),
        type_refs: vec![("System.Net".into(), "WebClient".into())],
        member_refs: vec![(1, "DownloadString".into())],
        module_refs: vec!["kernel32.dll".into()],
        impl_maps: vec![("VirtualAlloc".into(), 1)],
        assembly: Some("A".into()),
        unknown_table: true,
        ..Default::default()
    });
    let pe = PeFile::parse(&b.build());
    let n = pe.dotnet.unwrap();
    assert_eq!(n.unknown_tables, vec![50]);
    assert_eq!(n.module_name, "m.exe");
    assert_eq!(n.type_refs.len(), 1);
    assert_eq!(n.member_refs[0].name, "DownloadString");
    assert_eq!(n.impl_maps[0].module, "kernel32.dll");
    assert_eq!(n.assembly.unwrap().name, "A");
}
