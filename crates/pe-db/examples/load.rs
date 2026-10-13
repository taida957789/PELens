fn main() {
    let k = pe_db::Knowledge::load(std::env::args().nth(1).unwrap());
    println!("errors={:?}\nloaded={:?}", k.errors, k.loaded);
    println!(
        "indicators={} thresholds={} libs={} fcts={} sigs={} patterns={} tactics={} techniques={} nsp={} prod={} ides={} builds={} langs={} cps={} text={} groups={} hints={} res={} lists={}",
        k.indicators.len(),
        k.thresholds.len(),
        k.functions.libs.len(),
        k.functions.function_count(),
        k.signatures.len(),
        k.signatures.iter().map(|s| s.patterns.len()).sum::<usize>(),
        k.mitre.tactics.len(),
        k.mitre.techniques.len(),
        k.namespaces.items.len(),
        k.rich.prod_ids.len(),
        k.rich.ides.len(),
        k.rich.builds.len(),
        k.languages.langs.len(),
        k.languages.code_pages.len(),
        k.translations.text.len(),
        k.translations.groups.len(),
        k.translations.hints.len(),
        k.translations.resources.len(),
        k.translations.lists.len()
    );
    for c in &k.strings.categories {
        print!("{}={} ", c.name, c.items.len());
    }
    println!();
    println!(
        "settings={} colors={} sections={} tables={} streams={}",
        k.settings.setting.len(),
        k.settings.colors.len(),
        k.settings.standard_sections.len(),
        k.settings.tables.len(),
        k.settings.streams.len()
    );
    println!("{:?}", k.functions.function("kernel32.dll", "CreateRemoteThread"));
    println!("{:?}", k.functions.function_by_ordinal("ws2_32.dll", 23));
    println!("{:?}", k.rich.tooling(30159));
}
