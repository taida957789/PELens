//! Compress the open knowledge base (kb/*.xml) into OUT_DIR. The binaries then hold no plain-text
//! copy of its strings, which antivirus engines would otherwise mistake for malware.
use std::path::Path;

const FILES: [&str; 11] = [
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
    "namespaces.xml",
];

fn main() {
    let kb = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb");
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("kb");
    std::fs::create_dir_all(&out).expect("create OUT_DIR/kb");
    for name in FILES {
        let src = kb.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        let data = std::fs::read(&src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
        let packed = miniz_oxide::deflate::compress_to_vec(&data, 9);
        std::fs::write(out.join(format!("{name}.deflate")), packed).expect("write compressed kb");
    }
}
