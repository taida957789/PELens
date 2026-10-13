//! Test fixtures: a small, self-written knowledge base in the pestudio XML format and
//! sample images built with `pe_parser::testutil`. Shared by the tests of every crate.

use pe_db::Knowledge;
use pe_parser::testutil::*;
use std::path::PathBuf;

/// Every indicator id evaluated by the engine, with (severity, type, name, detail).
pub const INDICATORS: &[(u32, u8, &str, &str, &str)] = &[
    (1000, 3, "00", "file > info", "size: %i bytes, entropy: %.03f"),
    (1001, 3, "10", "file > type", "%s, %s, %s"),
    (1002, 3, "08", "file > description", "%s"),
    (1003, 3, "--", "file > first %s bytes (hex)", "%s"),
    (1004, 3, "--", "file > first %s bytes (text)", "%s"),
    (1005, 1, "10", "optional-header > size", "%i bytes"),
    (1006, 1, "09", "file-header > size", "%i bytes"),
    (1007, 3, "09", "sections > alignment", "%i"),
    (1008, 3, "01", "file", "%s"),
    (1009, 3, "01", "file > version", "%s"),
    (1010, 3, "09", "file > alignment", "%i"),
    (1011, 3, "17", "certificate > info", "size: %i bytes, offset: 0x%08X, file-ratio: %.02f%%"),
    (1012, 1, "17", "stamp-compiler > stamp-certificate", "%s"),
    (1013, 3, "08", "rich-header > footprint", "%s"),
    (1014, 3, "09", "file > image-base", "0x%08X"),
    (1015, 3, "26", "overlay > first %s bytes (hex)", "%s"),
    (1016, 3, "26", "overlay > first %s bytes (text)", "%s"),
    (1017, 1, "26", "overlay > info", "signature: %s, offset: 0x%08X, size: %i bytes, entropy: %.03f"),
    (1019, 3, "08", "rich-header > checksum", "checksum: 0x%08X, offset: 0x%08X"),
    (1020, 3, "21", "resource > first %s bytes (hex)", "%s"),
    (1021, 3, "21", "resource > first %s bytes (text)", "%s"),
    (1022, 3, "00", "file > name", "%s"),
    (1023, 2, "13", "libraries > duplicate", "%s"),
    (1024, 3, "12", "entry-point > first %s bytes (hex)", "%s"),
    (1025, 1, "13", "injection > technique", "%s"),
    (1026, 3, "13", "libraries > bound", "%s"),
    (1027, 3, "09", "file > code-less", "%s"),
    (1028, 1, "20", "resource > file", "signature: %s, offset: 0x%08X, size: %i bytes"),
    (1029, 1, "20", "section > file", "signature: %s, offset: 0x%08X, size: %i bytes"),
    (1033, 3, "19", "thread-local-storage > callback", "%s"),
    (1034, 1, "12", "entry-point > invalid", "0x%08X"),
    (1035, 2, "26", "overlay > entropy", "%.03f"),
    (1036, 2, "10", "file > checksum", "0x%08X"),
    (1037, 1, "17", "certificate > tail", "%i bytes"),
    (1038, 3, "17", "certificate > serial-number", "%s"),
    (1040, 3, "17", "certificate > type", "%s"),
    (1042, 2, "17", "certificate > stamp > valid-from", "%s"),
    (1043, 3, "17", "certificate > PKCS7 > size", "%i bytes"),
    (1044, 3, "17", "certificate > PKCS7 > NULL-padding", "%i bytes"),
    (1045, 2, "15", "entry-point > export", "%s"),
    (1046, 1, "17", "certificate > signature-info", "%s"),
    (1047, 3, "17", "certificate", "%s"),
    (1049, 3, "17", "certificate > stamp > signing", "%s"),
    (1050, 3, "17", "certificate > stamp > valid-to", "%s"),
    (1051, 2, "09", "file > network", "%s"),
    (1052, 2, "09", "file > removable", "%s"),
    (1053, 2, "17", "certificate > stamp", "%s (expired)"),
    (1054, 3, "17", "certificate > first %s bytes (hex)", "%s"),
    (1055, 3, "17", "certificate", "%s"),
    (1056, 3, "10", "security > protection", "%s"),
    (1057, 3, "21", "version > first %s bytes (hex)", "%s"),
    (1058, 3, "21", "version > first %s bytes (text)", "%s"),
    (1059, 3, "23", "first %s bytes (hex)", "%s"),
    (1060, 3, "23", "first %s bytes (text)", "%s"),
    (1061, 3, "16", "exceptions > count", "%i"),
    (1062, 1, "06", "dos-header > offset > unusual", "0x%08X"),
    (1063, 3, "05", "virustotal > score", "%s"),
    (1064, 1, "05", "virustotal > score", "%i/%i"),
    (1065, 3, "05", "virustotal > score", "%s"),
    (1066, 3, "05", "virustotal > permalink", "%s"),
    (1067, 3, "05", "virustotal > scan-date", "%s"),
    (1068, 2, "04", "mitre > technique", "%s"),
    (1069, 3, "04", "mitre > tactic", "%s"),
    (1070, 3, "09", "file-header > offset", "0x%08X"),
    (1071, 3, "23", "debug > file-name", "%s"),
    (1072, 2, "12", "section > virtualized", "name: %s"),
    (1073, 2, "23", "debug > GUID", "%s"),
    (1074, 2, "23", "stamp > debug", "%s"),
    (1075, 3, "23", "debug > age", "%i"),
    (1076, 3, "23", "debug > stream", "type: %s, size: %i bytes, file-ratio: %.02f%%, stamp: %s"),
    (1079, 3, "26", "overlay", "%s"),
    (1080, 3, "21", "resource", "%s"),
    (1081, 2, "10", "optional-header > size-of-code", "%i bytes"),
    (1082, 2, "09", "base-of-code > suspicious", "0x%08X"),
    (1083, 2, "09", "file-alignment > suspicious", "0x%08X"),
    (1084, 2, "09", "size-of-image > suspicious", "0x%08X"),
    (1085, 2, "09", "size-of-headers > suspicious", "0x%08X"),
    (1210, 3, "10", "directories > count", "%i"),
    (1211, 2, "10", "optional-header > directories", "count: %i"),
    (1215, 3, "11", "sections > file-ratio", "%.02f%%"),
    (1221, 3, "21", "resources > info", "count: %i, size: %i bytes, file-ratio: %.02f%%"),
    (1222, 1, "12", "sections > executable", "%s"),
    (1223, 2, "12", "section > writable", "name: %s"),
    (1224, 3, "12", "entry-point > location", "0x%08X (section: %s)"),
    (1234, 3, "21", "resources > instances > dotnet", "%i"),
    (1236, 3, "21", "languages > names", "%s"),
    (1245, 2, "12", "sections > flag", "name: %s"),
    (1250, 3, "15", "exports", "%s"),
    (1251, 3, "15", "exports > names", "%s"),
    (1252, 2, "15", "exports > duplicates", "count: %i"),
    (1253, 3, "15", "exports > count", "%i"),
    (1254, 2, "15", "exports > forwarded", "count: %i"),
    (1256, 2, "15", "exports > anonymous", "count: %i"),
    (1257, 2, "15", "exports > gaps", "count: %i"),
    (1259, 3, "00", "exports > file-name", "%s"),
    (1260, 2, "06", "dos-stub > message", "%s"),
    (1261, 1, "24", "symbols > flag", "%s"),
    (1262, 3, "14", "imports > count", "%i"),
    (1264, 3, "14", "imports > ordinal > count", "%i"),
    (1266, 1, "14", "imports > flag", "%s"),
    (1267, 2, "24", "string > suspicious", "size: %i bytes"),
    (1268, 2, "14", "imports > spoofing", "count: %i"),
    (1269, 2, "13", "libraries > flag", "%s (%s)"),
    (1270, 1, "13", "libraries > spoofing", "%s"),
    (1271, 3, "01", "imphash > md5", "%s"),
    (1272, 2, "14", "imports > callback", "%i"),
    (1273, 2, "14", "imports", "%s"),
    (1274, 1, "06", "dos-stub > suspicious", "%s"),
    (1288, 3, "20", ".NET > property > missing", "%s"),
    (1290, 2, "20", ".NET > stream > suspicious", "stream[%i]"),
    (1291, 1, "20", ".NET > stream > flag", "%s"),
    (1292, 3, "20", ".NET > module > name", "%s"),
    (1293, 3, "20", ".NET > file > strongly-named", "%s"),
    (1294, 3, "20", ".NET > methods > managed", "%i"),
    (1296, 3, "13", "libraries > p/invoke", "%s"),
    (1297, 1, "20", ".NET > file > obfuscated", "%s"),
    (1298, 1, "20", ".NET > namespace > flag", "%s"),
    (1300, 3, "20", ".NET > stream", "%s"),
    (1301, 1, "11", "directory > missing", "%s"),
    (1302, 3, "11", "directory > invalid", "%s"),
    (1304, 3, "20", ".NET > assembly > GUID", "%s"),
    (1306, 1, "11", "directories > empty > count", "%i/%i"),
    (1320, 2, "11", "stamp > directory", "%s"),
    (1321, 3, "09", "stamp > compiler", "%s"),
    (1400, 1, "25", "manifest > privilege", "%s"),
    (1401, 2, "25", "manifest > privilege", "%s"),
    (1402, 1, "25", "manifest > UAC", "%s"),
    (1404, 3, "25", "manifest > general", "name: %s, description: %s, level: %s"),
    (1424, 3, "23", "file > internal > name", "%s"),
    (1429, 3, "24", "strings > ignore > count", "%i"),
    (1430, 2, "24", "strings > flag > count", "%i"),
    (1431, 3, "24", "strings > status", "%s"),
    (1434, 2, "24", "string > url-pattern", "%s"),
    (1484, 2, "13", "libraries", "%s"),
    (1486, 1, "21", "version > size", "%i bytes"),
    (1487, 3, "21", "file-name > version", "%s"),
    (1488, 2, "06", "dos-header > unusual", "%i bytes"),
    (1489, 2, "06", "dos-stub > size > unusual", "%i bytes"),
    (1490, 3, "--", "file > signature", "%s"),
    (1491, 2, "24", "label > %s", "%s"),
    (1492, 3, "02", "group > types", "%s"),
    (1494, 1, "12", "sections > unreadable", "name: %s"),
    (1495, 2, "12", "sections > shared", "name: %s"),
    (1496, 1, "12", "sections > self-modifying", "name: %s"),
    (1497, 2, "12", "sections > nameless", "count: %i"),
];

pub fn indicators_xml() -> String {
    let mut s = String::from("<xml version=\"1.0\"><indicators>\n");
    for (id, sev, t, n, d) in INDICATORS {
        let ti = if *id == 1254 { "1574" } else { "----" };
        s.push_str(&format!(
            "<item enable=\"1\" severity=\"{sev}\" id=\"{id}\" type=\"{t}\" ti=\"{ti}\" detail=\"{}\">{}</item>\n",
            d.replace('&', "&amp;").replace('<', "&lt;"),
            n.replace('>', "&gt;")
        ));
    }
    s.push_str("<item enable=\"0\" severity=\"3\" id=\"1999\" type=\"--\" detail=\"%s\">disabled</item>\n");
    s.push_str("</indicators></xml>");
    s
}

pub const SETTINGS: &str = r#"<xml version="1.0" encoding="utf-8">
  <files><fthresholds>thresholds.xml</fthresholds><findicators>indicators.xml</findicators><fstrings>strings.xml</fstrings><ffunctions>functions.xml</ffunctions><flanguages>languages.xml</flanguages><ftranslations>translations.xml</ftranslations><fsignatures>signatures.xml</fsignatures><frich>rich.xml</frich><fmitre>mitre.xml</fmitre><fnsp>namespaces.xml</fnsp></files>
  <setting>
    <indicators sort="1" flag="1" sec="0" label="1" level="1" jump="1" rich="0" separator="|" bytes="16"/>
    <score enable="1" flag="0" all="1" key="" api="3"/>
    <footprints enable="1" type="2" dos-stub="1" dos-header="1" debug="1" version="1" manifest="1" st="1" menu="1" dlg="1" icon="1" cur="1" bmp="1" rich="1" acl="0"/>
    <groups enable="1" color="1"/>
    <mitre enable="1" ti="1" ta="1" dup="0"/>
    <strings flag="1" offset="1" label="1" gp="1" utf8="1" utf16="1" sort="0" wl="1" type="3"/>
    <exceptions enable="1"/>
    <relocations enable="1"/>
    <report enable="1" type="0"/>
    <google enable="1"/>
    <caption enable="1"/>
    <read-only enable="1"/>
    <stamps epoch="1"/>
  </setting>
  <colors enable="1"><color id="01" r="000" g="000" b="000">black</color><color id="06" r="168" g="000" b="000">red_dark</color><color id="08" r="255" g="245" b="250">red_light</color><color id="12" r="000" g="000" b="149">blue_dark</color><color id="04" r="173" g="173" b="173">gray</color><color id="15" r="204" g="102" b="000">yellow_dark</color><color id="02" r="255" g="255" b="255">white</color></colors>
  <sections><section>.text</section><section>.rdata</section><section>.data</section><section>.rsrc</section><section>.reloc</section></sections>
  <streams flag="1"><stream id="00" flag="0">#~</stream><stream id="01" flag="0">#-</stream><stream id="02" flag="0">#Strings</stream><stream id="03" flag="0">#US</stream><stream id="04" flag="0">#GUID</stream><stream id="05" flag="0">#Blob</stream><stream id="ff" flag="1">Unknown</stream></streams>
  <tables flag="1" all="1"><table id="01" enable="1" flag="0" desc="Imported Class(es)">TypeRef</table><table id="28" enable="1" flag="0" desc="Unmanaged code reached with p/Invoke">p/Invoke</table></tables>
  <tips><tip id="00">flag</tip></tips>
</xml>"#;

pub const THRESHOLDS: &str = r#"<xml><thresholds>
<item id="002" enable="1" level="2" min="20" max="368"></item>
<item id="009" enable="1" level="2" min="200" max="-1"></item>
<item id="023" enable="1" level="2" min="2004" max="-1"></item>
<item id="030" enable="1" level="2" min="-1" max="2099"></item>
</thresholds></xml>"#;

pub const FUNCTIONS: &str = r#"<xml><libs>
<lib name="kernel32.dll" flag="0" gp="--" desc="Windows NT BASE API Client">
  <fcts>
    <fct gp="02" od="---" flag="1" ti="1055">CreateRemoteThread</fct>
    <fct gp="05" od="---" flag="1" ti="1055">VirtualAllocEx</fct>
    <fct gp="05" od="---" flag="1" ti="1055">WriteProcessMemory</fct>
    <fct gp="05" od="--" flag="0" cb="1">VirtualAlloc</fct>
    <fct gp="16" od="--" flag="1" ad="1" ti="1622">IsDebuggerPresent</fct>
    <fct gp="--" od="--" flag="0" cd="1">WinExec</fct>
    <fct gp="--" od="--" flag="0" un="1">BaseFlushAppcompatCache</fct>
  </fcts>
</lib>
<lib name="ws2_32.dll" flag="1" gp="03" desc="Windows Socket 2.0">
  <fcts><fct gp="03" od="23" flag="1" ti="1095">socket</fct></fcts>
</lib>
<lib name="user32.dll" flag="0" gp="12" desc="Multi-User Windows USER API">
  <fcts><fct gp="12" od="--" flag="0">MessageBoxW</fct><fct gp="14" od="--" flag="1" ti="1179">SetWindowsHookExW</fct></fcts>
</lib>
<lib name="urlmon.dll" flag="1" gp="03" desc="OLE32 Extensions"><fcts><fct gp="03" flag="1" ti="1105">URLDownloadToFileW</fct></fcts></lib>
<lib name="" flag="0" gp="--">
  <fcts><fct gp="03" flag="1" ti="1071">DownloadString</fct><fct gp="--" flag="0" hide="1">.ctor</fct></fcts>
</lib>
</libs></xml>"#;

pub const STRINGS: &str = r#"<xml>
<settings><setting><minimum-size>4</minimum-size><case-sensitive>0</case-sensitive><substring>0</substring></setting></settings>
<sids gp="30"><sid name="">S-1-5-18</sid></sids>
<privs gp="30" ti="1134"><priv>SeDebugPrivilege</priv></privs>
<agents hint="06"><agent>Mozilla/</agent></agents>
<exts hint="17"><ext>exe</ext><ext>bat</ext></exts>
<regs hint="01"><reg gp="01">CurrentVersion\Run</reg></regs>
<folders><folder>%TEMP%</folder></folders>
<offices><office hint="23">AutoOpen</office></offices>
<utils hint="13"><util ti="1490">bcdedit</util><util>vssadmin</util></utils>
<stubs hint=""><stub flag="0">!This program cannot be run in DOS mode.</stub><stub flag="1">!This is a Win32 program.</stub></stubs>
<strings><string flag="1" gp="04" ti="1022" bl="1">EncryptMessage</string><string gp="10" ti="1001">ConfusedByAttribute</string></strings>
</xml>"#;

pub const SIGNATURES: &str = r#"<xml><sigs>
<sig name="TestCompiler" more="push ebp prologue" flag="1" file="0" tool="1" severity="3"><pattern ep="1">55 8B EC 33 xx 5D</pattern></sig>
<sig name="UPX" more="UPX packer" flag="1" file="0" tool="1" severity="2" url="upx.github.io"><pattern ep="0">.upx0</pattern></sig>
<sig name="Nim" flag="1" file="0" tool="1" severity="4"><pattern ep="0">_NimMainModule</pattern></sig>
<sig name="CAB" more="Cabinet (CAB) file" flag="1" file="1" tool="1" severity="2"><pattern ep="0">4D 53 43 46</pattern></sig>
<sig name="PDF" more="Portable Document Format" flag="1" file="1" tool="0" severity="2"><pattern ep="0">25 50 44 46</pattern></sig>
</sigs></xml>"#;

pub const MITRE: &str = r#"<xml><mitre url="https://attack.mitre.org">
<tactics url="tactics"><ta id="0002" de="run code">Execution</ta><ta id="0005" de="evade">Defense Evasion</ta><ta id="0011" de="c2">Command and Control</ta></tactics>
<techniques url="techniques">
<ti id="1055" ta="0005" flag="1" level="1" enable="1">Process Injection</ti>
<ti id="1001" ta="0011" flag="0" level="2" enable="1">Data Obfuscation</ti>
<ti id="1574" ta="0005" flag="1" level="2" enable="1">Hijack Execution Flow</ti>
<ti id="1622" ta="0005" flag="1" level="2" enable="0">Debugger Evasion</ti>
</techniques></mitre></xml>"#;

pub const NAMESPACES: &str = r#"<xml><nsp>
<nsp_system enable="1"><item flag="1" gp="03" ti="1071">System.Net</item><item flag="0" gp="--" ti="----">System</item></nsp_system>
<nsp_custom enable="1"><item flag="1" gp="10" ti="1001">Costura</item></nsp_custom>
</nsp></xml>"#;

pub const RICH: &str = r#"<xml><richheader>
<prodId><item id="0x01">Import</item><item id="0x0103">Utc1900_C</item></prodId>
<ide><item id="21">Visual Studio 2019</item></ide>
<version><item value="30159" ide="21">16.11</item></version>
</richheader></xml>"#;

pub const LANGUAGES: &str = r#"<xml><langs>
<lang id="0x0000" flag="0">neutral</lang><lang id="0x0409" flag="0">english-US</lang><lang id="0x0419" flag="1">russian</lang><lang id="0x0804" flag="0">chinese-PRC</lang>
</langs><cps><cp id="1252">Western European</cp></cps></xml>"#;

pub const TRANSLATIONS: &str = r#"<xml>
<text><item id="0">hex</item></text>
<groups enable="1">
<item id="02" r="247" g="071" b="071" level="1" enable="1">execution</item>
<item id="03" r="255" g="100" b="177" level="1" enable="1">network</item>
<item id="05" r="045" g="155" b="255" level="1" enable="1">memory</item>
<item id="16" r="170" g="170" b="170" level="2" enable="1">diagnostic</item>
</groups>
<resources>
<item id="25" severity="1" builtin="0" file="1" indicator="1">executable</item>
<item id="12" severity="4" builtin="1" file="0" indicator="1">rcdata</item>
<item id="00" severity="4" builtin="1" file="0" indicator="0">manifest</item>
</resources>
<hints color="1"><item id="01" indicate="1">registry</item><item id="06" indicate="1">user-agent</item><item id="13" indicate="1">utility</item><item id="17" indicate="1">file</item><item id="26" indicate="0">import</item><item id="-1">unknown</item></hints>
<severities><item id="1">high</item><item id="2">medium</item><item id="3">low</item></severities>
</xml>"#;

/// Write the fixture knowledge base to a fresh temporary directory.
pub fn write_knowledge(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pestudio-rs-kb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    let files: [(&str, String); 11] = [
        ("settings.xml", SETTINGS.into()),
        ("indicators.xml", indicators_xml()),
        ("thresholds.xml", THRESHOLDS.into()),
        ("functions.xml", FUNCTIONS.into()),
        ("strings.xml", STRINGS.into()),
        ("signatures.xml", SIGNATURES.into()),
        ("mitre.xml", MITRE.into()),
        ("namespaces.xml", NAMESPACES.into()),
        ("rich.xml", RICH.into()),
        ("languages.xml", LANGUAGES.into()),
        ("translations.xml", TRANSLATIONS.into()),
    ];
    for (n, c) in files {
        std::fs::write(d.join(n), c).expect("write fixture");
    }
    d
}

pub fn knowledge(tag: &str) -> Knowledge {
    Knowledge::load(write_knowledge(tag))
}

/// A "suspicious" 32-bit sample exercising most indicators.
pub fn suspicious_sample() -> Vec<u8> {
    let mut b = PeBuilder::new();
    b.rich = vec![(0x0103, 30159, 5)];
    b.stub_message = "This is a Win32 program.".into();
    b.timestamp = 0xF000_0000; // year 2097: inside the fixture thresholds but in the future
    b.imports = vec![
        Import {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                "CreateRemoteThread".into(),
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "VirtualAlloc".into(),
                "IsDebuggerPresent".into(),
                "WinExec".into(),
                "BaseFlushAppcompatCache".into(),
            ],
            delay: false,
        },
        Import { dll: "ws2_32.dll".into(), functions: vec!["#23".into(), "#99".into()], delay: false },
        Import { dll: "kernel32.dll".into(), functions: vec!["GetTickCount".into()], delay: false },
        Import { dll: "evil lib".into(), functions: vec!["Run".into()], delay: false },
        Import { dll: "urlmon.dll".into(), functions: vec!["URLDownloadToFileW".into()], delay: true },
        Import { dll: "user32.dll".into(), functions: vec!["SetWindowsHookExW".into()], delay: false },
    ];
    b.exports = vec![
        Export { name: Some("Start".into()), rva: 0x1000, forwarder: None },
        Export { name: Some("Start".into()), rva: 0x1002, forwarder: None },
        Export { name: None, rva: 0x1003, forwarder: None },
        Export { name: None, rva: 0, forwarder: None },
        Export { name: Some("Fwd".into()), rva: 0, forwarder: Some("kernel32.Sleep".into()) },
        Export { name: Some("?f@@YAXXZ".into()), rva: 0x1004, forwarder: None },
    ];
    b.export_dll_name = "other.dll".into();
    let mut payload = Vec::new();
    payload.extend(PeBuilder::new().build());
    b.resources = vec![
        Resource { type_id: ResKey::Id(16), name: ResKey::Id(1), lang: 0x409, data: version_resource((6, 6, 6, 6), &[("FileDescription", "Totally Legit"), ("OriginalFilename", "legit.exe"), ("InternalName", "legit"), ("FileVersion", "6.6.6.6")]) },
        Resource {
            type_id: ResKey::Id(24),
            name: ResKey::Id(1),
            lang: 0x409,
            data: br#"<assembly><assemblyIdentity name="evil" version="1.0.0.0"/><description>d</description><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="true"/></requestedPrivileges></security></trustInfo><autoElevate>true</autoElevate></assembly>"#.to_vec(),
        },
        Resource { type_id: ResKey::Id(10), name: ResKey::Name("PAYLOAD".into()), lang: 0x419, data: payload },
        Resource { type_id: ResKey::Id(10), name: ResKey::Id(2), lang: 0x804, data: b"MSCF\0\0\0\0cabinet".to_vec() },
        Resource { type_id: ResKey::Id(6), name: ResKey::Id(1), lang: 0x409, data: { let mut v = vec![]; for i in 0..16u16 { if i == 0 { v.extend(4u16.to_le_bytes()); v.extend("test".encode_utf16().flat_map(|u| u.to_le_bytes())); } else { v.extend([0, 0]); } } v } },
        Resource { type_id: ResKey::Id(23), name: ResKey::Id(1), lang: 0x409, data: b"<html>hello world</html>".to_vec() },
        Resource { type_id: ResKey::Id(2), name: ResKey::Id(1), lang: 0x409, data: b"BM\0\0\0\0\0\0\0\0".to_vec() },
    ];
    b.tls_callbacks = 1;
    b.relocations = true;
    b.pdb_path = Some("C:\\dev\\evil.pdb".into());
    b.extra_debug = vec![(20, 1u32.to_le_bytes().to_vec())];
    b.load_config = true;
    let mut strings = Vec::new();
    for s in [
        "http://evil.example.com/payload.bin",
        "Mozilla/5.0 (Windows NT 10.0)",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SeDebugPrivilege",
        "cmd.exe /c bcdedit /set safeboot",
        "Global\\EvilMutex",
        "dropper.bat",
        "%TEMP%\\x.exe",
        "EncryptMessage",
        "AutoOpen",
        "S-1-5-18",
        "SELECT * FROM Win32_Process",
        "\\\\.\\pipe\\evil",
        "192.168.10.20",
        "{12345678-1234-1234-1234-123456789ABC}",
        ".?AVCEvil@@",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ1234==",
        "Hello %s, value %d",
        "^[a-z]+\\d$",
        "1.2.840.113549.1.1.1",
        "kernel32.dll",
        "CreateRemoteThread",
        "DownloadString",
        "System.Net.WebClient",
        "_NimMainModule",
        "TVqQAAMAAAAEAAAA",
    ] {
        strings.extend(s.as_bytes());
        strings.push(0);
    }
    while strings.len() % 2 != 0 {
        strings.push(0);
    }
    strings.extend([0, 0]);
    strings.extend("unicode-string-here".encode_utf16().flat_map(|u| u.to_le_bytes()));
    strings.extend([0, 0]);
    strings.extend("ünïcödé-utf8".as_bytes());
    strings.push(0);
    strings.extend(vec![b'A'; 300]);
    strings.push(0);
    // embedded PE inside a section
    let mut data_sec = strings;
    while data_sec.len() % 16 != 0 {
        data_sec.push(0);
    }
    data_sec.extend(PeBuilder::new().build());
    b.extra_sections = vec![
        ExtraSection { name: ".data".into(), data: data_sec, characteristics: 0xc000_0040, virtual_size: None },
        ExtraSection { name: ".upx0".into(), data: vec![], characteristics: 0xe000_0080, virtual_size: Some(0x1000) },
        ExtraSection { name: "".into(), data: vec![0x90; 0x10], characteristics: 0x1000_0020, virtual_size: Some(0x8) },
    ];
    b.overlay = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    b.certificate = Some(pe_parser::testutil::der_builder::authenticode(false));
    b.dll_characteristics = 0x0140 | 0x4000 | 0x0020;
    b.build()
}

/// .NET sample (strong-named, typelib GUID, p/Invoke, obfuscator namespace).
pub fn dotnet_sample() -> Vec<u8> {
    let mut b = PeBuilder::new();
    b.dotnet = Some(DotNetSpec {
        module: "loader.exe".into(),
        type_refs: vec![
            ("System.Net".into(), "WebClient".into()),
            ("Costura".into(), "AssemblyLoader".into()),
            ("System".into(), "Object".into()),
        ],
        member_refs: vec![(1, "DownloadString".into()), (3, ".ctor".into())],
        module_refs: vec!["kernel32.dll".into()],
        impl_maps: vec![("VirtualAlloc".into(), 1)],
        assembly: Some("Loader".into()),
        user_strings: vec!["http://c2.example.net/a".into(), "plain user string".into()],
        guid_attribute: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
        extra_stream: Some("#Evil".into()),
    });
    b.dll = false;
    b.build()
}
