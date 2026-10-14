//! Compare the open knowledge base with another one (e.g. pestudio's XML) on local files:
//! `cargo run --release -p pe-analysis --example kb_compare -- <xml-dir> <file-or-dir>...`
//! Prints totals of indicators, high indicators, flagged imports and signature hits for both.
use pe_db::Knowledge;
use std::path::{Path, PathBuf};

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let q = e.path();
                let ext = q.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                if q.is_file() && matches!(ext.as_str(), "exe" | "dll" | "sys") {
                    out.push(q);
                }
            }
        }
    } else if p.is_file() {
        out.push(p.to_path_buf());
    }
}

#[derive(Default, Debug)]
struct Totals {
    indicators: usize,
    high: usize,
    flagged_imports: usize,
    signatures: usize,
    files_with_high: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(xml) = args.first() else {
        eprintln!("usage: kb_compare <xml-dir> <file-or-dir>...");
        std::process::exit(2);
    };
    let mut list = Vec::new();
    for a in &args[1..] {
        files(Path::new(a), &mut list);
    }
    let kbs = [("open kb", Knowledge::builtin()), ("other", Knowledge::load(xml))];
    let opts = pe_analysis::Options { verify_signature: false, strings_limit: Some(32 << 20), ..Default::default() };
    let mut totals = [Totals::default(), Totals::default()];
    for f in &list {
        let Ok(data) = std::fs::read(f) else { continue };
        for (i, (_, k)) in kbs.iter().enumerate() {
            let a = pe_analysis::analyze(&data, &f.to_string_lossy(), k, &opts);
            let t = &mut totals[i];
            let high = a.indicators.iter().filter(|x| x.severity == 1).count();
            t.indicators += a.indicators.len();
            t.high += high;
            t.files_with_high += usize::from(high > 0);
            t.flagged_imports += a.imports.iter().filter(|x| x.flag).count();
            t.signatures += a.signatures.len();
        }
    }
    println!("{} files", list.len());
    for (i, (name, _)) in kbs.iter().enumerate() {
        println!("{name:>8}: {:?}", totals[i]);
    }
    let pct = |a: usize, b: usize| if b == 0 { 100.0 } else { a as f64 * 100.0 / b as f64 };
    println!(
        "open/other: indicators {:.0}%, high {:.0}%, files with high {:.0}%, flagged imports {:.0}%, signatures {:.0}%",
        pct(totals[0].indicators, totals[1].indicators),
        pct(totals[0].high, totals[1].high),
        pct(totals[0].files_with_high, totals[1].files_with_high),
        pct(totals[0].flagged_imports, totals[1].flagged_imports),
        pct(totals[0].signatures, totals[1].signatures)
    );
}
