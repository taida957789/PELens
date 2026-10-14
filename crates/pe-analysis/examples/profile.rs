//! Time every stage of an analysis: `cargo run --release -p pe-analysis --example profile -- <file> [xml-dir]`
use pe_analysis::model::ItemType;
use pe_analysis::report::Format;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: profile <file> [xml-dir]");
        std::process::exit(2);
    };
    let k = args.get(1).map(pe_db::Knowledge::load).unwrap_or_else(pe_db::Knowledge::builtin);
    let t = Instant::now();
    let data = std::fs::read(path).expect("read");
    println!("{:>9.1} ms  read ({} bytes)", ms(t), data.len());
    let t = Instant::now();
    let pe = pe_parser::PeFile::parse(&data);
    println!("{:>9.1} ms  parse", ms(t));
    drop(pe);
    let opts = pe_analysis::Options { verify_signature: false, ..Default::default() };
    let t = Instant::now();
    let a = pe_analysis::analyze(&data, path, &k, &opts);
    println!("{:>9.1} ms  analyze ({} strings, {} indicators)", ms(t), a.strings.len(), a.indicators.len());
    let o = pe_analysis::view::ViewOptions::from_settings(&k);
    for item in ItemType::ALL {
        let t = Instant::now();
        let v = pe_analysis::view::table(&a, &k, &data, item, &o);
        println!("{:>9.1} ms  view {} ({} rows)", ms(t), item.name(), v.rows.len());
    }
    for f in [Format::Xml, Format::Json, Format::Text] {
        let t = Instant::now();
        let r = pe_analysis::report::render(&a, &k, &data, f);
        println!("{:>9.1} ms  report {f:?} ({} bytes)", ms(t), r.len());
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
