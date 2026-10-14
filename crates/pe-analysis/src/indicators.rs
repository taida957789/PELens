//! Indicator engine: evaluates every indicator id of indicators.xml against an analysis.

use crate::analyze::Options;
use crate::model::*;
use crate::util::{Arg, bytes_hex, bytes_text, entropy, format_stamp, now_unix, printf, ratio, year_of};
use pe_db::{IndicatorDef, Knowledge};
use pe_parser::debug::{DebugInfo, format_guid};
use pe_parser::headers::{DIRECTORY_NAMES, dir, dll_characteristics as dc};
use pe_parser::reader::Reader;

/// Built-in definitions used when indicators.xml is not available: (id, severity, type, name, detail).
pub const BUILTIN: &[(u32, u8, &str, &str, &str)] = &[
    (1000, 3, "00", "file > info", "size: %i bytes, entropy: %.03f"),
    (1001, 3, "10", "file > type", "%s, %s, %s"),
    (1002, 3, "08", "file > description", "%s"),
    (1003, 3, "--", "file > first %s bytes (hex)", "%s"),
    (1004, 3, "--", "file > first %s bytes (text)", "%s"),
    (1005, 1, "10", "optional-header > size", "%i bytes"),
    (1006, 1, "09", "file-header > size", "%i bytes"),
    (1011, 3, "17", "certificate > info", "size: %i bytes, offset: 0x%08X, file-ratio: %.02f%%"),
    (1012, 1, "17", "stamp-compiler > stamp-certificate", "%s"),
    (1013, 3, "08", "rich-header > footprint", "%s"),
    (1017, 1, "26", "overlay > info", "signature: %s, offset: 0x%08X, size: %i bytes, entropy: %.03f"),
    (1019, 3, "08", "rich-header > checksum", "checksum: 0x%08X, offset: 0x%08X"),
    (1022, 3, "00", "file > name", "%s"),
    (1024, 3, "12", "entry-point > first %s bytes (hex)", "%s"),
    (1025, 1, "13", "injection > technique", "%s"),
    (1028, 1, "20", "resource > file", "signature: %s, offset: 0x%08X, size: %i bytes"),
    (1029, 1, "20", "section > file", "signature: %s, offset: 0x%08X, size: %i bytes"),
    (1033, 3, "19", "thread-local-storage > callback", "%s"),
    (1034, 1, "12", "entry-point > invalid", "0x%08X"),
    (1056, 3, "10", "security > protection", "%s"),
    (1068, 2, "04", "mitre > technique", "%s"),
    (1069, 3, "04", "mitre > tactic", "%s"),
    (1266, 1, "14", "imports > flag", "%s"),
    (1271, 3, "01", "imphash > md5", "%s"),
    (1321, 3, "09", "stamp > compiler", "%s"),
    (1490, 3, "--", "file > signature", "%s"),
    (1496, 1, "12", "sections > self-modifying", "name: %s"),
];

struct Ctx<'a> {
    k: &'a Knowledge,
    out: Vec<Indicator>,
    builtin: Vec<IndicatorDef>,
}

impl Ctx<'_> {
    fn def(&self, id: u32) -> Option<&IndicatorDef> {
        if self.k.indicators.is_empty() { self.builtin.iter().find(|d| d.id == id) } else { self.k.indicator(id) }
    }

    fn emit_named(&mut self, id: u32, name_args: &[Arg], args: &[Arg]) {
        let Some(def) = self.def(id).cloned() else { return };
        if def.enable == 0 {
            return;
        }
        let name = if name_args.is_empty() { def.name.clone() } else { printf(&def.name, name_args) };
        self.out.push(Indicator {
            id,
            severity: def.severity,
            enable: def.enable,
            kind: ItemType::from_code(&def.kind),
            name,
            detail: printf(&def.detail, args),
            ti: def.ti.clone(),
        });
    }

    fn emit(&mut self, id: u32, args: &[Arg]) {
        self.emit_named(id, &[], args);
    }

    fn threshold_violated(&self, id: u32, v: i64) -> bool {
        self.k.threshold(id).is_some_and(|t| t.violated(v))
    }
}

fn s<T: Into<Arg>>(v: T) -> Arg {
    v.into()
}

const INJECTION_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtMapViewOfSection",
];

pub fn evaluate(a: &Analysis, k: &Knowledge, data: &[u8], o: &Options) -> Vec<Indicator> {
    let builtin = BUILTIN
        .iter()
        .map(|(id, sev, t, n, d)| IndicatorDef {
            id: *id,
            enable: 1,
            severity: *sev,
            kind: t.to_string(),
            ti: None,
            detail: d.to_string(),
            name: n.to_string(),
        })
        .collect();
    let mut c = Ctx { k, out: Vec::new(), builtin };
    let nb = o.first_bytes;
    let r = Reader::new(data);

    // ---------------------------------------------------------- file
    c.emit(1000, &[s(a.size), s(a.entropy)]);
    c.emit(1022, &[s(a.file_name.clone())]);
    c.emit(1008, &[s(format!("sha256: {}", a.hashes.sha256))]);
    c.emit(1001, &[s(a.cpu.clone()), s(a.file_type.clone()), s(a.subsystem.clone())]);
    if let Some(d) = &a.description {
        c.emit(1002, &[s(d.clone())]);
    }
    c.emit_named(1003, &[s(nb)], &[s(bytes_hex(data, nb))]);
    c.emit_named(1004, &[s(nb)], &[s(bytes_text(data, nb))]);
    let sig_names: Vec<String> =
        a.signatures.iter().map(|x| if x.more.is_empty() { x.name.clone() } else { format!("{} ({})", x.name, x.more) }).collect();
    if !sig_names.is_empty() {
        c.emit(1490, &[s(sig_names.join(", "))]);
    }
    if a.network_drive {
        c.emit(1051, &[s(a.path.clone())]);
    }
    if a.removable_drive {
        c.emit(1052, &[s(a.path.clone())]);
    }

    let Some(l) = a.pe.layout.as_ref() else {
        string_indicators(&mut c, a);
        return c.out;
    };
    let pe = &a.pe;
    let oh = &l.optional_header;
    let fh = &l.file_header;

    // ---------------------------------------------------------- footprints / version
    if let Some(i) = &a.imphash {
        c.emit(1271, &[s(i.clone())]);
    }
    let vi = pe.version_info(data);
    if let Some(v) = vi.as_ref().and_then(|v| v.get("FileVersion")) {
        c.emit(1009, &[s(v.to_string())]);
    }
    if let Some(v) = vi.as_ref().and_then(|v| v.get("OriginalFilename")).filter(|v| !v.is_empty())
        && !v.eq_ignore_ascii_case(&a.file_name)
        && !a.file_name.to_ascii_lowercase().starts_with(&v.to_ascii_lowercase())
    {
        c.emit(1487, &[s(format!("{v} (file: {})", a.file_name))]);
    }
    if let Some(v) = vi.as_ref().and_then(|v| v.get("InternalName")).filter(|v| !v.is_empty()) {
        c.emit(1424, &[s(v.to_string())]);
    }
    if let Some(res) = &pe.resources
        && let Some(ve) = res.of_type(16).next()
    {
        let b = ve.data(&r);
        c.emit_named(1057, &[s(nb)], &[s(bytes_hex(b, nb))]);
        c.emit_named(1058, &[s(nb)], &[s(bytes_text(b, nb))]);
        if ve.size > 0x10000 || (ve.size > 0 && ve.size < 92) {
            c.emit(1486, &[s(ve.size)]);
        }
    }

    // ---------------------------------------------------------- dos-header / stub / rich
    if let Some(dh) = &pe.dos_header {
        if dh.e_lfanew < 0x40 || dh.e_lfanew > 0x400 || dh.e_lfanew % 4 != 0 {
            c.emit(1062, &[s(dh.e_lfanew)]);
        }
        if dh.e_cparhdr != 4 || dh.e_lfarlc != 0x40 && dh.e_lfarlc != 0 && dh.e_lfarlc < 0x40 {
            c.emit(1488, &[s(dh.e_lfanew)]);
        }
    }
    if let Some(st) = &pe.dos_stub {
        if c.threshold_violated(2, st.size as i64) {
            c.emit(1489, &[s(st.size)]);
        }
        match &st.message {
            Some(m) => {
                let stubs = k.strings.items("stubs");
                match stubs.iter().find(|x| x.value.trim() == m.trim()) {
                    Some(x) if x.flag => c.emit(1274, &[s(m.clone())]),
                    Some(_) => {}
                    None if !stubs.is_empty() => c.emit(1260, &[s(m.clone())]),
                    None => {}
                }
            }
            None if st.size > 0 => c.emit(1274, &[s("stub without message")]),
            None => {}
        }
    }
    if let Some(rich) = &pe.rich {
        c.emit(1013, &[s(crate::util::md5_hex(&rich.raw_decoded))]);
        c.emit(1019, &[s(rich.key), s(rich.offset)]);
    }

    // ---------------------------------------------------------- file-header
    c.emit(1070, &[s(fh.offset)]);
    let expected_opt = if l.is_64() { 240 } else { 224 };
    if fh.size_of_optional_header != expected_opt {
        c.emit(1005, &[s(fh.size_of_optional_header)]);
    }
    let table_end = fh.offset as u64 + 20 + fh.size_of_optional_header as u64 + l.sections.len() as u64 * 40;
    if table_end > oh.size_of_headers as u64 {
        c.emit(1006, &[s(table_end - fh.offset as u64)]);
    }
    let compiler = fh.time_date_stamp;
    c.emit(1321, &[s(format_stamp(compiler, o.epoch))]);

    // ---------------------------------------------------------- optional-header
    if oh.number_of_rva_and_sizes != 16 {
        c.emit(1211, &[s(oh.number_of_rva_and_sizes)]);
    }
    c.emit(1210, &[s(oh.number_of_rva_and_sizes)]);
    c.emit(1014, &[s(oh.image_base)]);
    let code_sections: u64 = l.sections.iter().filter(|x| x.is_executable()).map(|x| x.size_of_raw_data as u64).sum();
    if oh.size_of_code == 0 && code_sections > 0 {
        c.emit(1081, &[s(oh.size_of_code)]);
    }
    if l.sections.iter().all(|x| !x.is_executable()) && !pe.is_dotnet() {
        c.emit(1027, &[s("no executable section")]);
    }
    if !l.sections.iter().any(|x| x.virtual_address == oh.base_of_code) && oh.base_of_code != 0 {
        c.emit(1082, &[s(oh.base_of_code)]);
    }
    if !oh.file_alignment.is_power_of_two()
        || oh.file_alignment < 0x200 && oh.file_alignment != oh.section_alignment
        || oh.file_alignment > 0x10000
    {
        c.emit(1083, &[s(oh.file_alignment)]);
        c.emit(1010, &[s(oh.file_alignment)]);
    }
    if oh.section_alignment < oh.file_alignment || !oh.section_alignment.is_power_of_two() {
        c.emit(1007, &[s(oh.section_alignment)]);
    }
    let computed_image = l
        .sections
        .iter()
        .map(|x| x.virtual_address as u64 + crate::align(l.virtual_extent(x).max(1), oh.section_alignment.max(1) as u64))
        .max()
        .unwrap_or(0);
    if computed_image > 0 && (oh.size_of_image as u64) < computed_image {
        c.emit(1084, &[s(oh.size_of_image)]);
    }
    if (oh.size_of_headers as u64) < table_end || oh.file_alignment != 0 && oh.size_of_headers % oh.file_alignment != 0 {
        c.emit(1085, &[s(oh.size_of_headers)]);
    }
    if oh.checksum != 0
        && let Some(cs) = a.checksum_real
        && cs != oh.checksum
    {
        c.emit(1036, &[s(oh.checksum)]);
    }
    // protection summary
    let mut prot = Vec::new();
    let dch = oh.dll_characteristics;
    if dch & dc::DYNAMIC_BASE != 0 {
        prot.push("ASLR");
    }
    if dch & dc::HIGH_ENTROPY_VA != 0 {
        prot.push("High-Entropy");
    }
    if dch & dc::NX_COMPAT != 0 {
        prot.push("DEP");
    }
    if dch & dc::GUARD_CF != 0 {
        prot.push("CFG");
    }
    if dch & dc::FORCE_INTEGRITY != 0 {
        prot.push("CI");
    }
    if dch & dc::NO_SEH == 0 && !l.is_64() && pe.load_config.as_ref().is_some_and(|lc| lc.has_safe_seh()) {
        prot.push("SafeSEH");
    }
    if pe.load_config.as_ref().is_some_and(|lc| lc.has_gs()) {
        prot.push("GS");
    }
    if pe.debug.iter().any(|d| matches!(d.info, DebugInfo::ExDllCharacteristics { flags } if flags & 1 != 0)) {
        prot.push("CET");
    }
    c.emit(1056, &[s(if prot.is_empty() { "none".to_string() } else { prot.join(", ") })]);

    // ---------------------------------------------------------- entry-point
    if let Some(ep) = &pe.entry_point
        && !ep.zero
    {
        if let Some(fo) = ep.file_offset {
            let b = r.bytes_clamped(fo as usize, nb);
            c.emit_named(1024, &[s(nb)], &[s(bytes_hex(b, nb))]);
        }
        c.emit(1224, &[s(ep.rva), s(ep.section.clone().unwrap_or_else(|| "n/a".into()))]);
        if ep.outside_image || ep.in_header || ep.in_non_executable_section {
            c.emit(1034, &[s(ep.rva)]);
        }
        if a.exports.iter().any(|e| e.entry_point) {
            let n = a.exports.iter().find(|e| e.entry_point).map(|e| e.name.clone()).unwrap_or_default();
            c.emit(1045, &[s(n)]);
        }
    }

    // ---------------------------------------------------------- directories
    let mut empty = 0;
    let mut used = 0;
    for (i, d) in oh.data_directories.iter().enumerate() {
        if d.rva == 0 && d.size == 0 {
            continue;
        }
        used += 1;
        if d.rva == 0 || d.size == 0 {
            empty += 1;
            continue;
        }
        let ok = if i == dir::SECURITY {
            (d.rva as u64) < a.size
        } else {
            l.rva_to_offset(d.rva).is_some() || (d.rva as u64) < oh.size_of_image as u64
        };
        if !ok {
            c.emit(1301, &[s(DIRECTORY_NAMES[i])]);
        } else if i != dir::SECURITY && (d.rva as u64 + d.size as u64) > oh.size_of_image as u64 {
            c.emit(1302, &[s(DIRECTORY_NAMES[i])]);
        }
    }
    if empty > 0 {
        c.emit(1306, &[s(empty), s(used)]);
    }
    // directory stamps differing from the compiler stamp
    let mut dir_stamps = Vec::new();
    if let Some(e) = &pe.exports
        && e.time_date_stamp != 0
        && e.time_date_stamp != compiler
        && e.time_date_stamp != u32::MAX
    {
        dir_stamps.push(format!("export: {}", format_stamp(e.time_date_stamp, o.epoch)));
    }
    if let Some(rs) = &pe.resources
        && rs.time_date_stamp != 0
        && rs.time_date_stamp != compiler
    {
        dir_stamps.push(format!("resource: {}", format_stamp(rs.time_date_stamp, o.epoch)));
    }
    for st in dir_stamps {
        c.emit(1320, &[s(st)]);
    }
    // compiler stamp sanity (thresholds 023/030 bound the year, future stamps are forged)
    if compiler != 0 {
        let y = year_of(compiler as i64);
        let future = compiler as i64 > now_unix() + 86400;
        if (future || c.threshold_violated(23, y) || c.threshold_violated(30, y))
            && let Some(i) = c.out.iter_mut().find(|i| i.id == 1321)
        {
            i.severity = 1;
            i.detail.push_str(if future { " (future)" } else { " (suspicious)" });
        }
    }

    // ---------------------------------------------------------- sections
    for sct in &a.sections {
        if sct.self_modifying {
            c.emit(1496, &[s(sct.name.clone())]);
        }
        if sct.writable && (sct.entry_point || matches!(sct.name.as_str(), ".text" | ".rdata" | "CODE" | "text" | ".code")) {
            c.emit(1223, &[s(sct.name.clone())]);
        }
        if sct.virtualized {
            c.emit(1072, &[s(sct.name.clone())]);
        }
        if !sct.standard_name {
            c.emit(1245, &[s(sct.name.clone())]);
        }
        if sct.unreadable {
            c.emit(1494, &[s(sct.name.clone())]);
        }
        if sct.shareable {
            c.emit(1495, &[s(sct.name.clone())]);
        }
    }
    let nameless = a.sections.iter().filter(|x| x.nameless).count();
    if nameless > 0 {
        c.emit(1497, &[s(nameless)]);
    }
    let execs = a.sections.iter().filter(|x| x.executable).count();
    if execs > 1 {
        c.emit(1222, &[s(format!("{execs} executable sections"))]);
    }
    let sec_total: u64 = a.sections.iter().map(|x| x.raw_size).sum();
    c.emit(1215, &[s(ratio(sec_total, a.size))]);
    for e in &a.embedded {
        if e.location.starts_with("section:") || e.location.starts_with("overlay") {
            c.emit(1029, &[s(format!("{} ({})", e.signature, e.location)), s(e.offset), s(e.size)]);
        }
    }

    // ---------------------------------------------------------- libraries / imports
    for lib in &a.libraries {
        if lib.flag {
            c.emit(1269, &[s(lib.name.clone()), s(lib.description.clone())]);
        }
        if lib.spoofed && lib.kind != "p/Invoke" {
            c.emit(1270, &[s(lib.name.clone())]);
        }
        if lib.bound {
            c.emit(1026, &[s(lib.name.clone())]);
        }
    }
    let dups: Vec<String> = a.libraries.iter().filter(|l| l.duplicate).map(|l| l.name.clone()).collect();
    if !dups.is_empty() {
        let mut d = dups;
        d.sort_by_key(|x| x.to_ascii_lowercase());
        d.dedup_by(|x, y| x.eq_ignore_ascii_case(y));
        c.emit(1023, &[s(d.join(", "))]);
    }
    let unknown: Vec<String> = a.libraries.iter().filter(|l| !l.known && l.kind != "p/Invoke").map(|l| l.name.clone()).collect();
    if !unknown.is_empty() && !k.functions.libs.is_empty() {
        c.emit(1484, &[s(format!("unknown: {}", unknown.join(", ")))]);
    }
    let pinv: Vec<String> = a.libraries.iter().filter(|l| l.kind == "p/Invoke").map(|l| l.name.clone()).collect();
    if !pinv.is_empty() {
        c.emit(1296, &[s(pinv.join(", "))]);
    }
    let native_imports: Vec<&ImportRow> = a.imports.iter().filter(|i| i.kind != "dotnet").collect();
    c.emit(1262, &[s(native_imports.len())]);
    let ords = native_imports.iter().filter(|i| i.ordinal.is_some()).count();
    if ords > 0 {
        c.emit(1264, &[s(ords)]);
    }
    let flagged: Vec<String> = a.imports.iter().filter(|i| i.flag).map(|i| i.name.clone()).collect();
    if !flagged.is_empty() {
        c.emit(1266, &[s(format!("count: {} ({})", flagged.len(), flagged.iter().take(16).cloned().collect::<Vec<_>>().join(", ")))]);
    }
    let mismatches: usize = a.libraries.iter().map(|l| l.mismatch).sum();
    if mismatches > 0 {
        c.emit(1268, &[s(mismatches)]);
    }
    let cbs = a.imports.iter().filter(|i| i.callback).count();
    if cbs > 0 {
        c.emit(1272, &[s(cbs)]);
    }
    let special: Vec<String> = a
        .imports
        .iter()
        .filter(|i| i.deprecated || i.undocumented || i.anti_debug)
        .map(|i| {
            let t = if i.anti_debug {
                "anti-debug"
            } else if i.undocumented {
                "undocumented"
            } else {
                "deprecated"
            };
            format!("{} ({t})", i.name)
        })
        .collect();
    if !special.is_empty() {
        c.emit(1273, &[s(special.join(", "))]);
    }
    let inj: Vec<&str> = INJECTION_APIS
        .iter()
        .copied()
        .filter(|n| a.imports.iter().any(|i| i.name.trim_end_matches(['A', 'W']) == *n || i.name == *n))
        .collect();
    if inj.len() >= 2 {
        c.emit(1025, &[s(inj.join(", "))]);
    }
    if !a.groups.is_empty() {
        c.emit(1492, &[s(a.groups.iter().map(|g| format!("{} ({})", g.name, g.count)).collect::<Vec<_>>().join(", "))]);
    }

    // ---------------------------------------------------------- exports
    if let Some(e) = &pe.exports {
        c.emit(1253, &[s(e.functions.len())]);
        let names: Vec<String> = a.exports.iter().filter(|x| !x.name.is_empty()).take(8).map(|x| x.name.clone()).collect();
        if !names.is_empty() {
            c.emit(1251, &[s(names.join(", "))]);
        }
        let fl: Vec<String> = a.exports.iter().filter(|x| x.flag).map(|x| x.name.clone()).collect();
        if !fl.is_empty() {
            c.emit(1250, &[s(fl.join(", "))]);
        }
        if !e.duplicate_names.is_empty() {
            c.emit(1252, &[s(e.duplicate_names.len())]);
        }
        if e.forwarded_count() > 0 {
            c.emit(1254, &[s(e.forwarded_count())]);
        }
        if e.anonymous_count() > 0 {
            c.emit(1256, &[s(e.anonymous_count())]);
        }
        if e.gap_count() > 0 {
            c.emit(1257, &[s(e.gap_count())]);
        }
        if !e.dll_name.is_empty() && !e.dll_name.eq_ignore_ascii_case(&a.file_name) {
            c.emit(1259, &[s(e.dll_name.clone())]);
        }
    }

    // ---------------------------------------------------------- exceptions
    if !pe.exceptions.is_empty() {
        c.emit(1061, &[s(pe.exceptions.len())]);
    }

    // ---------------------------------------------------------- TLS
    if let Some(t) = &pe.tls {
        for cb in &t.callbacks {
            c.emit(1033, &[s(format!("0x{cb:X}"))]);
        }
    }

    // ---------------------------------------------------------- certificate
    if let Some(sd) = &pe.security {
        c.emit(1011, &[s(sd.size), s(sd.offset), s(ratio(sd.size as u64, a.size))]);
        let b = r.bytes_clamped(sd.offset as usize, nb);
        c.emit_named(1054, &[s(nb)], &[s(bytes_hex(b, nb))]);
        for wc in &sd.entries {
            c.emit(1040, &[s(pe_parser::certificate::cert_type_name(wc.certificate_type))]);
            if wc.tail > 0 {
                c.emit(1037, &[s(wc.tail)]);
            }
            if wc.null_padding > 8 {
                c.emit(1044, &[s(wc.null_padding)]);
            }
            if let Some(au) = &wc.pkcs7 {
                c.emit(1043, &[s(au.der_size)]);
                if let Some(cert) = au.signer_certificate() {
                    c.emit(1047, &[s(cert.subject_cn.clone())]);
                    c.emit(1055, &[s(cert.issuer_cn.clone())]);
                    c.emit(1038, &[s(cert.serial.clone())]);
                    if let Some(f) = cert.valid_from {
                        c.emit(1042, &[s(crate::util::format_utc(f))]);
                    }
                    if let Some(t) = cert.valid_to {
                        c.emit(1050, &[s(crate::util::format_utc(t))]);
                        if t < now_unix() {
                            c.emit(1053, &[s(crate::util::format_utc(t))]);
                        }
                    }
                    if let (Some(f), Some(t)) = (cert.valid_from, cert.valid_to) {
                        let cs = compiler as i64;
                        if compiler != 0 && (cs < f || cs > t) {
                            c.emit(
                                1012,
                                &[s(format!(
                                    "compiler: {} outside [{} - {}]",
                                    format_stamp(compiler, false),
                                    crate::util::format_utc(f),
                                    crate::util::format_utc(t)
                                ))],
                            );
                        }
                    }
                }
                let st = au.signer.as_ref().and_then(|x| x.signing_time).or(au.counter_signer.as_ref().and_then(|x| x.signing_time));
                if let Some(t) = st {
                    c.emit(1049, &[s(crate::util::format_utc(t))]);
                }
            }
        }
        if sd.not_at_end {
            c.emit(1037, &[s(sd.trailing_after_directory)]);
        }
        if let Some(chk) = &a.certificate_check
            && chk.verified == Some(false)
        {
            c.emit(1046, &[s(chk.message.clone())]);
        }
    }

    // ---------------------------------------------------------- resources
    if let Some(res) = &pe.resources {
        c.emit(1221, &[s(res.entries.len()), s(res.total_size()), s(ratio(res.total_size(), a.size))]);
        let mut langs: Vec<String> = a.resources.iter().map(|r| r.language_name.clone()).collect();
        langs.sort();
        langs.dedup();
        if !langs.is_empty() {
            c.emit(1236, &[s(langs.join(", "))]);
        }
        for rr in &a.resources {
            if !rr.signature.is_empty() && rr.severity <= 2 {
                c.emit(1080, &[s(format!("{}:{} ({})", rr.type_name, rr.name, rr.signature))]);
                c.emit_named(1020, &[s(nb)], &[s(rr.first_bytes_hex.clone())]);
                c.emit_named(1021, &[s(nb)], &[s(rr.first_bytes_text.clone())]);
            }
        }
        if pe.is_dotnet() {
            let n = pe.dotnet.as_ref().map(|n| n.manifest_resources.len()).unwrap_or(0);
            c.emit(1234, &[s(n)]);
        }
    }
    for e in &a.embedded {
        if e.location.starts_with("resource:") {
            c.emit(1028, &[s(format!("{} ({})", e.signature, e.location)), s(e.offset), s(e.size)]);
        }
    }

    // ---------------------------------------------------------- debug
    for d in &pe.debug {
        c.emit(
            1076,
            &[s(d.type_name()), s(d.size_of_data), s(ratio(d.size_of_data as u64, a.size)), s(format_stamp(d.time_date_stamp, o.epoch))],
        );
        if d.time_date_stamp != 0 && d.time_date_stamp != compiler && d.kind != 16 && d.kind != 20 && d.kind != 13 {
            c.emit(1074, &[s(format_stamp(d.time_date_stamp, o.epoch))]);
        }
        match &d.info {
            DebugInfo::Rsds { guid, age, path } => {
                c.emit(1071, &[s(path.clone())]);
                c.emit(1073, &[s(format_guid(guid))]);
                c.emit(1075, &[s(*age)]);
                let b = d.data(&r);
                c.emit_named(1059, &[s(nb)], &[s(bytes_hex(b, nb))]);
                c.emit_named(1060, &[s(nb)], &[s(bytes_text(b, nb))]);
            }
            DebugInfo::Nb10 { age, path, .. } => {
                c.emit(1071, &[s(path.clone())]);
                c.emit(1075, &[s(*age)]);
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------- manifest
    if let Some((_, m)) = pe.manifest(data) {
        match m.execution_level.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("requireadministrator") => c.emit(1400, &[s("requireAdministrator")]),
            Some("highestavailable") => c.emit(1401, &[s("highestAvailable")]),
            _ => {}
        }
        if m.auto_elevate == Some(true) {
            c.emit(1402, &[s("autoElevate")]);
        }
        if m.ui_access == Some(true) {
            c.emit(1402, &[s("uiAccess")]);
        }
        if let Some(id) = &m.identity {
            c.emit(
                1404,
                &[
                    s(id.name.clone()),
                    s(m.description.clone().unwrap_or_default()),
                    s(m.execution_level.clone().unwrap_or_else(|| "n/a".into())),
                ],
            );
        }
    }

    // ---------------------------------------------------------- overlay
    if let Some(ov) = &pe.overlay {
        let b = &data[ov.offset as usize..(ov.offset + ov.size) as usize];
        let sig = crate::sigscan::blob_signature(k, b).unwrap_or_else(|| "unknown".into());
        let ent = entropy(b);
        c.emit(1017, &[s(sig.clone()), s(ov.offset), s(ov.size), s(ent)]);
        c.emit(1079, &[s(sig)]);
        c.emit_named(1015, &[s(nb)], &[s(bytes_hex(b, nb))]);
        c.emit_named(1016, &[s(nb)], &[s(bytes_text(b, nb))]);
        if ent > 7.0 {
            c.emit(1035, &[s(ent)]);
        }
    }

    // ---------------------------------------------------------- .NET
    if let Some(n) = &pe.dotnet {
        if !n.module_name.is_empty() {
            c.emit(1292, &[s(n.module_name.clone())]);
        } else {
            c.emit(1288, &[s("module name")]);
        }
        if n.assembly.is_none() && !pe.is_dll() {
            c.emit(1288, &[s("assembly")]);
        }
        if n.is_strong_name_signed() {
            c.emit(1293, &[s("strong-name-signed")]);
        }
        if let Some(g) = &n.typelib_id {
            c.emit(1304, &[s(g.clone())]);
        }
        c.emit(1294, &[s(n.methods.len())]);
        let known: Vec<String> = k.settings.streams.iter().filter(|x| x.name != "Unknown").map(|x| x.name.clone()).collect();
        // tables stream declaring rows for tables without a schema → suspicious #~ stream
        if !n.unknown_tables.is_empty() {
            let idx = n.streams.iter().position(|x| x.name == "#~" || x.name == "#-").unwrap_or(0);
            c.emit(1290, &[s(idx)]);
        }
        for (i, st) in n.streams.iter().enumerate() {
            c.emit(1300, &[s(format!("{} ({} bytes)", st.name, st.size))]);
            let is_known = if known.is_empty() {
                ["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"].contains(&st.name.as_str())
            } else {
                known.contains(&st.name)
            };
            if !is_known {
                c.emit(1291, &[s(st.name.clone())]);
            }
            if st.file_offset.is_none() || st.size as u64 > a.size {
                c.emit(1290, &[s(i)]);
            }
        }
        // obfuscation
        let mut obf: Vec<String> = Vec::new();
        for attr in &n.custom_attributes {
            let short = attr.rsplit('.').next().unwrap_or(attr);
            if k.strings.items("strings").iter().any(|x| x.group == Some(10) && x.value == short)
                || short.contains("Obfuscat")
                || short.contains("Confused")
            {
                obf.push(short.to_string());
            }
        }
        for t in n.type_defs.iter().chain(n.type_refs.iter()) {
            if let Some(ns) = k.namespaces.lookup(&t.full_name()).filter(|d| d.group == Some(10) && !d.system)
                && !obf.contains(&ns.name)
            {
                obf.push(ns.name.clone());
            }
        }
        let weird = n.type_defs.iter().filter(|t| t.name.chars().any(|ch| !ch.is_ascii() || ch.is_control())).count();
        if weird > n.type_defs.len() / 4 && weird > 2 {
            obf.push(format!("{weird} non-ascii type names"));
        }
        if !obf.is_empty() {
            c.emit(1297, &[s(obf.join(", "))]);
        }
        let mut nsflag: Vec<String> = Vec::new();
        for t in &n.type_refs {
            if let Some(ns) = k.namespaces.lookup(&t.full_name()).filter(|d| d.flag)
                && !nsflag.contains(&ns.name)
            {
                nsflag.push(ns.name.clone());
            }
        }
        for ns in nsflag {
            c.emit(1298, &[s(ns)]);
        }
    }

    string_indicators(&mut c, a);
    c.out
}

fn string_indicators(c: &mut Ctx, a: &Analysis) {
    if a.strings_skipped {
        c.emit(1431, &[s("disabled (file size limit)")]);
        return;
    }
    let flagged = a.strings.iter().filter(|x| x.flag).count();
    c.emit(1431, &[s(format!("count: {}, flagged: {}", a.strings.len(), flagged))]);
    c.emit(1430, &[s(flagged)]);
    c.emit(1429, &[s(a.strings.iter().filter(|x| x.whitelist).count())]);
    let bl: Vec<String> = a.strings.iter().filter(|x| x.blacklist).map(|x| x.value.clone()).collect();
    if !bl.is_empty() {
        c.emit(1261, &[s(bl.join(", "))]);
    }
    let long_limit = c.k.threshold(9).map(|t| t.min).unwrap_or(256).max(1) as usize;
    for st in a.strings.iter().filter(|x| x.size >= long_limit).take(16) {
        c.emit(1267, &[s(st.size)]);
    }
    let mut urls: Vec<String> = a
        .strings
        .iter()
        .filter(|x| x.hint.as_deref() == Some("url-pattern"))
        .map(|x| crate::strings::url_part(x.value.trim()).to_string())
        .collect();
    urls.sort();
    urls.dedup();
    for u in urls.iter().take(32) {
        c.emit(1434, &[s(u.clone())]);
    }
    // labels
    let mut labels: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for st in &a.strings {
        if let Some(h) = &st.hint {
            let indicate = c.k.translations.hints.iter().find(|x| &x.name == h).map(|x| x.indicate).unwrap_or(matches!(
                h.as_str(),
                "registry"
                    | "privilege"
                    | "user-agent"
                    | "mutex"
                    | "query"
                    | "sid"
                    | "utility"
                    | "regex"
                    | "base64"
                    | "security"
                    | "ip-address"
                    | "pipe"
            ));
            if indicate {
                *labels.entry(h.clone()).or_default() += 1;
            }
        }
    }
    for (h, n) in labels {
        c.emit_named(1491, &[s(h)], &[s(format!("count: {n}"))]);
    }
}

/// MITRE indicators (computed once the MITRE view is built).
pub fn mitre_indicators(a: &mut Analysis, k: &Knowledge) {
    if !k.settings.get_bool("mitre", "enable", true) {
        return;
    }
    let mut c = Ctx {
        k,
        out: Vec::new(),
        builtin: BUILTIN
            .iter()
            .map(|(id, sev, t, n, d)| IndicatorDef {
                id: *id,
                enable: 1,
                severity: *sev,
                kind: t.to_string(),
                ti: None,
                detail: d.to_string(),
                name: n.to_string(),
            })
            .collect(),
    };
    let mut tactics: Vec<String> = Vec::new();
    for m in &a.mitre {
        c.emit(1068, &[s(format!("{} {}", m.technique, m.technique_name))]);
        if !m.tactic_name.is_empty() && !tactics.contains(&m.tactic_name) {
            tactics.push(m.tactic_name.clone());
        }
    }
    for t in tactics {
        c.emit(1069, &[s(t)]);
    }
    a.indicators.extend(c.out);
}

/// VirusTotal indicators (computed when a score is attached).
pub fn score_indicators(a: &mut Analysis, k: &Knowledge) {
    let Some(sc) = a.score.clone() else { return };
    let mut c = Ctx { k, out: Vec::new(), builtin: Vec::new() };
    a.indicators.retain(|i| !(1063..=1067).contains(&i.id));
    match sc.status.as_str() {
        "ok" => {
            if sc.positives > 0 {
                c.emit(1064, &[s(sc.positives), s(sc.total)]);
            } else {
                c.emit(1065, &[s(format!("0/{}", sc.total))]);
            }
            c.emit(1066, &[s(sc.permalink.clone())]);
            c.emit(1067, &[s(sc.scan_date.clone())]);
        }
        other => c.emit(1063, &[s(other.to_string())]),
    }
    a.indicators.extend(c.out);
}
