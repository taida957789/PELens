//! Whole PE parsing: headers, sections, directories, imports, exports, resources, debug, TLS…
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe_parser::PeFile::parse(data);
});
