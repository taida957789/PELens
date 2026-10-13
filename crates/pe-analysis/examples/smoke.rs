fn main() {
    let k = pe_db::Knowledge::load("../xml");
    let o = pe_analysis::Options::default();
    for p in std::env::args().skip(1) {
        let t = std::time::Instant::now();
        let (_d, a) = pe_analysis::analyze_file(std::path::Path::new(&p), &k, &o).unwrap();
        println!(
            "== {p} {:?} type={} sig={:?} imphash={:?} ind={} strings={} groups={} mitre={} libs={} imps={} res={} foot={} emb={:?} tooling={:?} cert={:?}",
            t.elapsed(),
            a.file_type,
            a.signatures.iter().map(|s| &s.name).collect::<Vec<_>>(),
            a.imphash,
            a.indicators.len(),
            a.strings.len(),
            a.groups.len(),
            a.mitre.len(),
            a.libraries.len(),
            a.imports.len(),
            a.resources.len(),
            a.footprints.len(),
            a.embedded.iter().map(|e| (&e.signature, &e.location)).collect::<Vec<_>>(),
            a.tooling,
            a.certificate_check.as_ref().map(|c| &c.message)
        );
        for i in a.indicators.iter().filter(|i| i.severity <= 2).take(25) {
            println!("  [{}] {} {} | {}", i.severity, i.id, i.name, i.detail.chars().take(110).collect::<String>());
        }
    }
}
