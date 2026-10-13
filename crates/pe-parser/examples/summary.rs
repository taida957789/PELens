use pe_parser::PeFile;
fn main() {
    let list = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    for p in list.lines() {
        let Ok(data) = std::fs::read(p) else { continue };
        let pe = PeFile::parse(&data);
        let l = match pe.layout.as_ref() {
            Some(l) => l,
            None => {
                println!("{p}|notpe");
                continue;
            }
        };
        let nimp = pe
            .imports
            .libraries
            .iter()
            .filter(|x| x.kind == pe_parser::imports::ImportKind::Implicit)
            .map(|x| x.functions.len())
            .sum::<usize>();
        let ndel = pe
            .imports
            .libraries
            .iter()
            .filter(|x| x.kind == pe_parser::imports::ImportKind::DelayLoaded)
            .map(|x| x.functions.len())
            .sum::<usize>();
        let nexp = pe
            .exports
            .as_ref()
            .map(|e| e.functions.iter().filter(|f| !f.gap).map(|f| f.ordinal).collect::<std::collections::BTreeSet<_>>().len())
            .unwrap_or(0);
        println!(
            "{p}|{}|{}|{}|{}|{}|{}",
            l.sections.len(),
            nimp,
            ndel,
            nexp,
            pe.resources.as_ref().map(|r| r.entries.len()).unwrap_or(0),
            pe.overlay.as_ref().map(|o| o.offset).unwrap_or(0)
        );
    }
}
