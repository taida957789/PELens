use pe_parser::PeFile;
fn main() {
    for p in std::env::args().skip(1) {
        let data = std::fs::read(&p).unwrap();
        let pe = PeFile::parse(&data);
        let l = pe.layout.as_ref().unwrap();
        println!(
            "== {p} 64={} secs={} imps={} funcs={} exps={} res={} dbg={} tls={} relocblocks={} exc={} lc={} cert={} net={} ovl={:?} ep={:?} rich={} cks={:08x}/{:08x}",
            pe.is_64(),
            l.sections.len(),
            pe.imports.libraries.len(),
            pe.imports.function_count(),
            pe.exports.as_ref().map(|e| e.functions.len()).unwrap_or(0),
            pe.resources.as_ref().map(|r| r.entries.len()).unwrap_or(0),
            pe.debug.len(),
            pe.tls.as_ref().map(|t| t.callbacks.len()).unwrap_or(0),
            pe.relocations.len(),
            pe.exceptions.len(),
            pe.load_config.is_some(),
            pe.security.as_ref().map(|s| s.entries.len()).unwrap_or(0),
            pe.dotnet.is_some(),
            pe.overlay.as_ref().map(|o| (o.offset, o.size)),
            pe.entry_point.as_ref().map(|e| e.section.clone()),
            pe.rich.as_ref().map(|r| r.entries.len()).unwrap_or(0),
            l.optional_header.checksum,
            pe.computed_checksum(&data).unwrap()
        );
        if let Some(r) = &pe.rich {
            println!(" rich valid={}", r.checksum_valid());
        }
        if let Some(a) = pe.security.as_ref().and_then(|s| s.authenticode()) {
            println!(
                " signer={:?}\n certs={:?}\n counter={:?} nested={}",
                a.signer,
                a.certificates.iter().map(|c| (&c.subject_cn, &c.serial, c.valid_from, &c.crl_urls)).collect::<Vec<_>>(),
                a.counter_signer,
                a.nested_signatures
            );
        }
        if let Some(v) = pe.version_info(&data) {
            println!(" ver={:?} {:?}", v.fixed.as_ref().map(|f| f.file_version()), v.strings.iter().take(3).collect::<Vec<_>>());
        }
        if let Some((_, m)) = pe.manifest(&data) {
            println!(
                " manifest level={:?} ui={:?} auto={:?} id={:?} deps={}",
                m.execution_level,
                m.ui_access,
                m.auto_elevate,
                m.identity.as_ref().map(|i| &i.name),
                m.dependencies.len()
            );
        }
        for d in &pe.debug {
            println!(
                " dbg {} {:?}",
                d.type_name(),
                match &d.info {
                    pe_parser::debug::DebugInfo::Rsds { path, .. } => path.clone(),
                    x => format!("{:?}", x).chars().take(60).collect(),
                }
            );
        }
        if let Some(n) = &pe.dotnet {
            println!(
                " net ver={} module={} streams={:?} trefs={} mrefs={} asm={:?} refs={} guid={:?} us={} attrs={:?}",
                n.runtime_version,
                n.module_name,
                n.streams.iter().map(|s| &s.name).collect::<Vec<_>>(),
                n.type_refs.len(),
                n.member_refs.len(),
                n.assembly.as_ref().map(|a| (&a.name, &a.version)),
                n.assembly_refs.len(),
                n.typelib_id,
                n.user_strings.len(),
                n.custom_attributes.iter().take(5).collect::<Vec<_>>()
            );
        }
    }
}
