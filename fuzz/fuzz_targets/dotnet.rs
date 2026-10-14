//! .NET metadata: the input replaces the metadata root (after "BSJB") of a valid .NET sample, so
//! that the mutations reach the stream headers, the #~ tables and the heaps.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn sample() -> &'static (Vec<u8>, usize) {
    static S: OnceLock<(Vec<u8>, usize)> = OnceLock::new();
    S.get_or_init(|| {
        let d = pe_analysis::testkit::dotnet_sample();
        let at = d.windows(4).position(|w| w == b"BSJB").expect("metadata root") + 4;
        (d, at)
    })
}

fuzz_target!(|data: &[u8]| {
    let (base, at) = sample();
    let mut pe = base.clone();
    let n = data.len().min(pe.len() - at);
    pe[*at..at + n].copy_from_slice(&data[..n]);
    let _ = pe_parser::PeFile::parse(&pe);
    let _ = pe_parser::dotnet::compressed_u32(data, 0);
});
