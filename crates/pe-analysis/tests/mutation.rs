//! Mutation regression test (stable Rust, runs in CI): corrupt valid samples in many ways with a
//! fixed seed and check that parsing and the whole analysis never panic and never hang.
//! Coverage-guided fuzzing lives in `fuzz/` (cargo-fuzz, nightly).
//!
//! `PELENS_MUTATIONS=<n>` scales the number of iterations (default 1).

use pe_analysis::model::ItemType;
use pe_analysis::report::Format;
use pe_analysis::testkit;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// xorshift64*: deterministic, so a failure is reproducible from its iteration number.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const INTERESTING_U32: [u32; 10] = [0, 1, 2, 0x7f, 0xffff, 0x1_0000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

/// Offset biased towards the headers (where the parser takes most of its decisions).
fn offset(rng: &mut Rng, len: usize) -> usize {
    if rng.below(2) == 0 { rng.below(len.min(1024)) } else { rng.below(len) }
}

fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        let len = data.len();
        if len < 8 {
            return;
        }
        match rng.below(7) {
            0 => {
                let o = offset(rng, len);
                data[o] ^= 1 << rng.below(8);
            }
            1 => {
                let o = offset(rng, len - 4) & !3;
                let v = match rng.below(3) {
                    0 => INTERESTING_U32[rng.below(INTERESTING_U32.len())],
                    1 => len as u32 + rng.below(16) as u32,
                    _ => rng.next() as u32,
                };
                data[o..o + 4].copy_from_slice(&v.to_le_bytes());
            }
            2 => {
                let o = offset(rng, len - 2);
                let v = [0u16, 1, 0x7fff, 0x8000, 0xffff][rng.below(5)];
                data[o..o + 2].copy_from_slice(&v.to_le_bytes());
            }
            3 => data.truncate(rng.below(len)),
            4 => {
                let o = rng.below(len);
                let n = rng.below((len - o).min(4096)) + 1;
                let chunk = data[o..o + n].to_vec();
                let at = rng.below(len);
                data.splice(at..at, chunk);
            }
            5 => {
                let o = rng.below(len);
                let n = rng.below((len - o).min(512)) + 1;
                data[o..o + n].fill(if rng.below(2) == 0 { 0 } else { 0xff });
            }
            _ => {
                let o = offset(rng, len);
                data[o] = rng.next() as u8;
            }
        }
    }
}

fn scale() -> usize {
    std::env::var("PELENS_MUTATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

/// Save the failing input next to the test binary and fail with a reproducible message.
fn fail(kind: &str, seed: u64, i: usize, data: &[u8], what: String) -> ! {
    let p = std::env::temp_dir().join(format!("pelens-mutation-{kind}-{seed:x}-{i}.bin"));
    let _ = std::fs::write(&p, data);
    panic!("{kind} iteration {i} (seed {seed:#x}): {what}; input saved to {}", p.display());
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    vec![("suspicious", testkit::suspicious_sample()), ("dotnet", testkit::dotnet_sample())]
}

#[test]
fn parser_survives_mutations() {
    let iterations = 6_000 * scale();
    for (name, base) in samples() {
        let seed = 0x5eed_0000 ^ base.len() as u64;
        let mut rng = Rng(seed);
        for i in 0..iterations {
            let mut d = base.clone();
            mutate(&mut rng, &mut d);
            let t = Instant::now();
            match catch_unwind(AssertUnwindSafe(|| pe_parser::PeFile::parse(&d))) {
                Err(e) => fail(&format!("parse-{name}"), seed, i, &d, format!("panic: {:?}", e.downcast_ref::<String>())),
                // output stays proportional to the input: one resource per 8-byte entry slot,
                // one export per 4-byte address slot plus one per 4-byte name slot (aliases)
                Ok(pe) => {
                    let res = pe.resources.as_ref().map_or(0, |r| r.entries.len());
                    let exp = pe.exports.as_ref().map_or(0, |e| e.functions.len());
                    if res > d.len() / 8 || exp > d.len() / 2 {
                        fail(&format!("parse-{name}"), seed, i, &d, format!("{res} resources, {exp} exports"));
                    }
                }
            }
            if t.elapsed() > Duration::from_secs(5) {
                fail(&format!("parse-{name}"), seed, i, &d, format!("took {:?}", t.elapsed()));
            }
        }
    }
}

#[test]
fn analysis_survives_mutations() {
    let iterations = 400 * scale();
    let k = testkit::knowledge("mutation");
    let opts = pe_analysis::Options { verify_signature: false, ..Default::default() };
    let view = pe_analysis::view::ViewOptions::from_settings(&k);
    let mut slowest = Duration::ZERO;
    for (name, base) in samples() {
        let seed = 0xa11a_0000 ^ base.len() as u64;
        let mut rng = Rng(seed);
        for i in 0..iterations {
            let mut d = base.clone();
            mutate(&mut rng, &mut d);
            let t = Instant::now();
            let r = catch_unwind(AssertUnwindSafe(|| {
                let a = pe_analysis::analyze(&d, "m.exe", &k, &opts);
                // views and reports of every 8th input (they are the slow part)
                if i % 8 == 0 {
                    for item in ItemType::ALL {
                        let _ = pe_analysis::view::table(&a, &k, &d, item, &view);
                    }
                    for f in [Format::Xml, Format::Json, Format::Text] {
                        let _ = pe_analysis::report::render(&a, &k, &d, f);
                    }
                }
            }));
            if let Err(e) = r {
                fail(&format!("analyze-{name}"), seed, i, &d, format!("panic: {:?}", e.downcast_ref::<String>()));
            }
            let el = t.elapsed();
            slowest = slowest.max(el);
            if el > Duration::from_secs(10) {
                fail(&format!("analyze-{name}"), seed, i, &d, format!("took {el:?}"));
            }
        }
    }
    eprintln!("slowest analysis: {slowest:?}");
}

#[test]
fn mutator_changes_inputs() {
    let mut rng = Rng(1);
    let base = testkit::suspicious_sample();
    let changed = (0..200)
        .filter(|_| {
            let mut d = base.clone();
            mutate(&mut rng, &mut d);
            d != base
        })
        .count();
    assert!(changed > 190, "{changed}");
    let mut tiny = vec![1u8, 2, 3];
    mutate(&mut rng, &mut tiny);
    assert_eq!(tiny, [1, 2, 3], "inputs shorter than 8 bytes are left alone");
}

/// Inputs found by fuzzing (tests/corpus): analysis and reports stay small and fast.
#[test]
fn corpus_inputs_stay_bounded() {
    let k = testkit::knowledge("corpus");
    let opts = pe_analysis::Options { verify_signature: false, ..Default::default() };
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.path().extension().is_some_and(|x| x == "bin")) {
        let d = std::fs::read(e.path()).unwrap();
        let t = Instant::now();
        let a = pe_analysis::analyze(&d, "c.exe", &k, &opts);
        let report = pe_analysis::report::render(&a, &k, &d, Format::Text);
        assert!(report.len() < 64 * d.len().max(16 * 1024), "{:?}: {} byte report", e.path(), report.len());
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}: {:?}", e.path(), t.elapsed());
        if e.file_name() == "exports-count-bomb.bin" {
            let ex = a.pe.exports.as_ref().expect("exports");
            assert!(ex.truncated && ex.functions.len() < 5000, "{}", ex.functions.len());
            let v = pe_analysis::view::table(&a, &k, &d, ItemType::Exports, &pe_analysis::view::ViewOptions::from_settings(&k));
            assert!(v.note.as_deref().is_some_and(|n| n.starts_with("truncated")));
        }
        n += 1;
    }
    assert!(n >= 1);
}
