//! The complete pipeline: analysis (indicators, strings, signatures, footprints), every view and
//! every report format.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pe_analysis::model::ItemType;
use pe_analysis::report::Format;
use std::sync::OnceLock;

fn knowledge() -> &'static pe_db::Knowledge {
    static K: OnceLock<pe_db::Knowledge> = OnceLock::new();
    K.get_or_init(pe_db::Knowledge::builtin)
}

fuzz_target!(|data: &[u8]| {
    let k = knowledge();
    // WinVerifyTrust is Windows code, not ours, and would write a temporary file per input.
    let opts = pe_analysis::Options { verify_signature: false, ..Default::default() };
    let a = pe_analysis::analyze(data, "fuzz.exe", k, &opts);
    let o = pe_analysis::view::ViewOptions::from_settings(k);
    for t in ItemType::ALL {
        let _ = pe_analysis::view::table(&a, k, data, t, &o);
    }
    for f in [Format::Xml, Format::Json, Format::Text] {
        let _ = pe_analysis::report::render(&a, k, data, f);
    }
});
