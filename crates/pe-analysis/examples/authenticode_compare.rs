//! Compare the Rust Authenticode verifier with WinVerifyTrust on local files (Windows):
//! `cargo run --release -p pe-analysis --example authenticode_compare -- <roots.pem> <file-or-dir>...`
use pe_analysis::authenticode::{self, TrustStore};
use std::path::{Path, PathBuf};

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let q = e.path();
            let ext = q.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if q.is_file() && matches!(ext.as_str(), "exe" | "dll" | "sys") {
                out.push(q);
            }
        }
    } else if p.is_file() {
        out.push(p.to_path_buf());
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut store = TrustStore::microsoft();
    store.roots.extend(authenticode::pem_certificates(&std::fs::read_to_string(&a[0]).unwrap_or_default()));
    let mut list = Vec::new();
    for p in &a[1..] {
        files(Path::new(p), &mut list);
    }
    let now = pe_analysis::util::now_unix();
    let (mut signed, mut same, mut diff) = (0, 0, Vec::new());
    for f in &list {
        let Ok(data) = std::fs::read(f) else { continue };
        let pe = pe_parser::PeFile::parse(&data);
        if pe.security.as_ref().and_then(|s| s.authenticode()).is_none() {
            continue;
        }
        signed += 1;
        let ours = authenticode::verify(&data, &store, now);
        let win = pe_analysis::verify::verify_path(&f.to_string_lossy());
        if (ours == authenticode::Outcome::Ok) == (win.verified == Some(true)) {
            same += 1;
        } else {
            diff.push(format!("{}: ours {:?} | windows {}", f.display(), ours, win.message));
        }
    }
    println!("{signed} signed files, {same} agree");
    for d in diff.iter().take(40) {
        println!("{d}");
    }
}
