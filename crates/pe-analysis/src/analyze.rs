//! Analysis pipeline: PE parsing → enrichment with the knowledge base → indicators.

use crate::model::*;
use crate::strings::{self, StringOptions};
use crate::util::{self, entropy, hash_by_type, hash_type_name, md5_hex, ratio};
use crate::{indicators, sigscan};
use pe_db::Knowledge;
use pe_parser::PeFile;
use pe_parser::headers::{DIRECTORY_NAMES, dir, machine_is_64, subsystem_name};
use pe_parser::imports::ImportKind;
use pe_parser::resource_content;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct Options {
    /// Skip string extraction above this size (bytes); None = no limit.
    pub strings_limit: Option<u64>,
    pub strings: bool,
    pub epoch: bool,
    pub first_bytes: usize,
    /// Run WinVerifyTrust on signed files (Windows only).
    pub verify_signature: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { strings_limit: None, strings: true, epoch: false, first_bytes: 32, verify_signature: true }
    }
}

impl Options {
    pub fn from_settings(k: &Knowledge) -> Self {
        let s = &k.settings;
        Options {
            strings_limit: match s.get_int("strings", "limit", 0) {
                v if v > 0 => Some(v as u64 * 1024),
                _ => None,
            },
            strings: s.get_bool("strings", "enable", true),
            epoch: s.get_bool("stamps", "epoch", false),
            first_bytes: s.get_int("indicators", "bytes", 32).clamp(1, 256) as usize,
            verify_signature: true,
        }
    }
}

pub fn analyze_file(path: &std::path::Path, k: &Knowledge, o: &Options) -> std::io::Result<(Vec<u8>, Analysis)> {
    let data = std::fs::read(path)?;
    let mut a = analyze(&data, &path.to_string_lossy(), k, o);
    drive_type(path, &mut a);
    if k.settings.get_bool("footprints", "enable", true)
        && k.settings.get_bool("footprints", "acl", false)
        && let Some(sd) = file_security_descriptor(path)
    {
        let t = k.settings.get_int("footprints", "type", 2);
        add_footprint(&mut a, t, "acl (security-descriptor)", "file", &sd);
    }
    Ok((data, a))
}

/// Raw security descriptor (owner, group, DACL) of a file, used for the "acl" footprint.
#[cfg(windows)]
pub fn file_security_descriptor(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetFileSecurityW, OWNER_SECURITY_INFORMATION,
    };
    let w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let what = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut need = 0u32;
    // SAFETY: first call only queries the required size (null buffer, zero length).
    unsafe { GetFileSecurityW(w.as_ptr(), what, std::ptr::null_mut(), 0, &mut need) };
    if need == 0 {
        return None;
    }
    let mut buf = vec![0u8; need as usize];
    // SAFETY: `buf` has exactly `need` bytes and outlives the call.
    let ok = unsafe { GetFileSecurityW(w.as_ptr(), what, buf.as_mut_ptr() as _, need, &mut need) };
    (ok != 0).then_some(buf)
}

#[cfg(not(windows))]
pub fn file_security_descriptor(_path: &std::path::Path) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
fn drive_type(path: &std::path::Path, a: &mut Analysis) {
    use std::os::windows::ffi::OsStrExt;
    let full = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = full.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    let root: String = if s.starts_with(r"UNC\") || s.starts_with(r"\\") {
        a.network_drive = true;
        return;
    } else {
        s.chars().take(3).collect()
    };
    let w: Vec<u16> = std::ffi::OsStr::new(&root).encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: `w` is a valid NUL-terminated UTF-16 string that outlives the call.
    let t = unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(w.as_ptr()) };
    a.network_drive = t == 4;
    a.removable_drive = t == 2;
}

#[cfg(not(windows))]
fn drive_type(_path: &std::path::Path, _a: &mut Analysis) {}

pub fn analyze(data: &[u8], path: &str, k: &Knowledge, o: &Options) -> Analysis {
    let pe = PeFile::parse(data);
    let file_name = std::path::Path::new(path).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string());
    // Every pass over the whole file runs once, side by side (they dominate large files).
    let overlay = pe.overlay.as_ref().map(|ov| (ov.offset as usize, (ov.offset + ov.size) as usize));
    let (hashes, entropy_all, without_overlay, overlay_info, checksum_real) = std::thread::scope(|s| {
        let info = overlay.map(|(start, end)| {
            s.spawn(move || {
                let b = &data[start..end];
                OverlayInfo {
                    hashes: util::hashes(b),
                    entropy: entropy(b),
                    signature: sigscan::blob_signature(k, b).unwrap_or_else(|| "unknown".into()),
                }
            })
        });
        let pe = &pe;
        let checksum = s.spawn(move || pe.computed_checksum(data));
        let ent = s.spawn(move || entropy(data));
        let (h, without) = match overlay {
            Some((start, _)) => {
                let (whole, prefix) = util::hashes_with_prefix(data, start);
                (whole, Some(prefix))
            }
            None => (util::hashes(data), None),
        };
        (h, ent.join().unwrap_or_default(), without, info.and_then(|t| t.join().ok()), checksum.join().ok().flatten())
    });
    let mut a = Analysis {
        path: path.to_string(),
        file_name,
        size: data.len() as u64,
        hashes,
        entropy: entropy_all,
        hashes_without_overlay: without_overlay,
        overlay_info,
        checksum_real,
        ..Default::default()
    };
    a.pe = pe;
    describe_type(&mut a, data);
    let scan = sigscan::scan(k, &a.pe, data);
    a.signatures = scan.signatures;
    a.embedded = scan.embedded;
    if a.is_pe() {
        a.imphash = imphash(k, &a.pe);
        build_sections(&mut a, k, data);
        build_libraries_imports(&mut a, k);
        build_exports(&mut a, k);
        build_resources(&mut a, k, data, o.first_bytes);
        build_stamps(&mut a);
        a.tooling = tooling(k, &a.pe);
    }
    let limit_hit = o.strings_limit.is_some_and(|l| a.size > l);
    if o.strings && !limit_hit {
        let so = StringOptions {
            min_len: k.strings.minimum_size.max(1),
            ascii: true,
            unicode: k.settings.get_bool("strings", "utf16", true),
            utf8: k.settings.get_bool("strings", "utf8", true),
            unicode_cjk: k.settings.get_bool("strings", "cjk", false),
        };
        a.strings = strings::build_rows(k, &a.pe, data, so);
    } else {
        a.strings_skipped = true;
    }
    build_footprints(&mut a, k, data);
    build_groups(&mut a, k);
    if o.verify_signature && a.pe.security.as_ref().is_some_and(|s| s.authenticode().is_some()) {
        a.certificate_check = Some(crate::verify::verify_data(path, data));
    }
    a.indicators = indicators::evaluate(&a, k, data, o);
    build_mitre(&mut a, k);
    indicators::mitre_indicators(&mut a, k);
    a
}

fn describe_type(a: &mut Analysis, data: &[u8]) {
    let Some(l) = a.pe.layout.as_ref() else {
        a.cpu = "n/a".into();
        a.file_type = crate::sigscan::builtin_magic(data).unwrap_or("unknown").to_string();
        a.subsystem = "n/a".into();
        return;
    };
    a.cpu = if machine_is_64(l.file_header.machine) || l.is_64() { "64-bit".into() } else { "32-bit".into() };
    a.file_type = if a.pe.is_dotnet() && a.pe.is_dll() {
        ".NET dynamic-link-library".into()
    } else if a.pe.is_dotnet() {
        ".NET executable".into()
    } else if a.pe.is_driver() {
        "driver".into()
    } else if a.pe.is_dll() {
        "dynamic-link-library".into()
    } else {
        "executable".into()
    };
    a.subsystem = subsystem_name(l.optional_header.subsystem).to_string();
    if let Some(vi) = a.pe.version_info(data) {
        a.description = vi.get("FileDescription").filter(|s| !s.is_empty()).map(str::to_string);
    }
}

/// imphash compatible with pefile (implicit imports only).
pub fn imphash(k: &Knowledge, pe: &PeFile) -> Option<String> {
    let mut parts = Vec::new();
    for l in pe.imports.libraries.iter().filter(|l| l.kind == ImportKind::Implicit) {
        let lname = l.name.to_ascii_lowercase();
        let base = ["ocx", "sys", "dll"].iter().find_map(|e| lname.strip_suffix(&format!(".{e}"))).unwrap_or(&lname).to_string();
        for f in &l.functions {
            let fname = match (&f.name, f.ordinal) {
                (Some(n), _) => n.to_ascii_lowercase(),
                (None, Some(o)) => {
                    let mapped = if ["ws2_32", "wsock32", "oleaut32"].contains(&base.as_str()) {
                        k.functions.function_by_ordinal(&l.name, o).map(|f| f.name.to_ascii_lowercase())
                    } else {
                        None
                    };
                    mapped.unwrap_or_else(|| format!("ord{o}"))
                }
                _ => continue,
            };
            parts.push(format!("{base}.{fname}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(md5_hex(parts.join(",").as_bytes()).to_ascii_lowercase())
}

fn build_sections(a: &mut Analysis, k: &Knowledge, data: &[u8]) {
    let l = a.pe.layout.as_ref().expect("pe");
    let ep_section = a.pe.entry_point.as_ref().and_then(|e| e.section_index);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for s in &l.sections {
        *counts.entry(s.name.as_str()).or_default() += 1;
    }
    for s in &l.sections {
        let ptr = l.raw_pointer(s);
        let size = l.raw_size(s);
        let raw = &data[(ptr as usize).min(data.len())..((ptr + size) as usize).min(data.len())];
        let mut dirs = Vec::new();
        for (i, d) in l.optional_header.data_directories.iter().enumerate() {
            if d.rva != 0 && i != dir::SECURITY && l.section_of_rva(d.rva).is_some_and(|x| x.index == s.index) {
                dirs.push(DIRECTORY_NAMES[i].to_string());
            }
        }
        let mut caves = Vec::new();
        if s.size_of_raw_data > s.virtual_size && s.virtual_size > 0 {
            let start = ptr + s.virtual_size as u64;
            let slack = &data[(start as usize).min(data.len())..((ptr + size) as usize).min(data.len())];
            if !slack.is_empty() && slack.iter().all(|&b| b == 0) {
                caves.push((start, slack.len() as u64));
            }
        }
        let embedded: Vec<String> = a
            .embedded
            .iter()
            .filter(|e| e.location == format!("section:{}", s.name))
            .map(|e| format!("{} @ 0x{:08X}", e.signature, e.offset))
            .collect();
        a.sections.push(SectionRow {
            index: s.index,
            name: s.name.clone(),
            md5: md5_hex(raw),
            entropy: entropy(raw),
            file_ratio: ratio(size, a.size),
            raw_address: s.pointer_to_raw_data as u64,
            raw_size: s.size_of_raw_data as u64,
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
            characteristics: s.characteristics,
            flags: pe_parser::headers::section_flag_names(s.characteristics),
            standard_name: k.settings.standard_sections.is_empty() || k.settings.is_standard_section(&s.name),
            duplicate_name: counts.get(s.name.as_str()).copied().unwrap_or(0) > 1,
            writable: s.is_writable(),
            executable: s.is_executable(),
            shareable: s.is_shared(),
            self_modifying: s.is_self_modifying(),
            virtualized: s.is_virtualized(),
            unreadable: !s.is_readable(),
            nameless: s.name.trim().is_empty(),
            entry_point: ep_section == Some(s.index),
            directories: dirs,
            embedded,
            caves,
        });
    }
}

fn spoofed_library(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let ext_ok = [".dll", ".sys", ".exe", ".drv", ".ocx", ".cpl", ".efi", ".tlb", ".olb"].iter().any(|e| n.ends_with(e));
    n.is_empty() || n.contains(['\\', '/', ':', ' ']) || !ext_ok || n.bytes().any(|b| !(0x21..0x7f).contains(&b))
}

fn build_libraries_imports(a: &mut Analysis, k: &Knowledge) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for lib in &a.pe.imports.libraries {
        *seen.entry(lib.name.to_ascii_lowercase()).or_default() += 1;
    }
    let bound_names: Vec<String> = a.pe.imports.bound.iter().map(|b| b.module_name.to_ascii_lowercase()).collect();
    for lib in &a.pe.imports.libraries {
        let def = k.functions.library(&lib.name);
        let kind = match lib.kind {
            ImportKind::Implicit => "implicit",
            ImportKind::DelayLoaded => "delay-loaded",
        };
        let bound = lib.is_bound() || bound_names.contains(&lib.name.to_ascii_lowercase());
        a.libraries.push(LibraryRow {
            name: lib.name.clone(),
            kind: kind.into(),
            imports: lib.functions.len(),
            flag: def.is_some_and(|d| d.flag),
            group: def.and_then(|d| d.group),
            description: def.map(|d| d.description.clone()).unwrap_or_default(),
            known: def.is_some(),
            duplicate: seen.get(&lib.name.to_ascii_lowercase()).copied().unwrap_or(0) > 1,
            spoofed: spoofed_library(&lib.name),
            bound,
            stamp: lib.time_date_stamp,
            missing_int: lib.int_missing,
            mismatch: lib.int_iat_mismatch,
        });
        for f in &lib.functions {
            let (def, mapped) = match (&f.name, f.ordinal) {
                (Some(n), _) => (k.functions.function(&lib.name, n), false),
                (None, Some(o)) => (k.functions.function_by_ordinal(&lib.name, o), true),
                _ => (None, false),
            };
            let name = match (&f.name, def, mapped) {
                (Some(n), _, _) => n.clone(),
                (None, Some(d), true) => d.name.clone(),
                _ => f.display_name(),
            };
            a.imports.push(ImportRow {
                name,
                ordinal: f.ordinal,
                ordinal_mapped: mapped && def.is_some(),
                library: lib.name.clone(),
                kind: kind.into(),
                hint: f.hint,
                int_value: f.int_value,
                iat_value: f.iat_value,
                group: def.and_then(|d| d.group),
                ti: def.and_then(|d| d.ti.clone()),
                flag: def.is_some_and(|d| d.flag),
                deprecated: def.is_some_and(|d| d.deprecated),
                undocumented: def.is_some_and(|d| d.undocumented),
                anti_debug: def.is_some_and(|d| d.anti_debug),
                callback: def.is_some_and(|d| d.callback),
                map: def.and_then(|d| d.map.clone()),
                mismatch: lib.time_date_stamp == 0 && lib.kind == ImportKind::Implicit && !lib.int_missing && f.int_value != f.iat_value,
                namespace: None,
            });
        }
    }
    // .NET: p/Invoke libraries and imported members.
    if let Some(n) = a.pe.dotnet.clone() {
        let mut pinv: BTreeMap<String, usize> = BTreeMap::new();
        for m in &n.impl_maps {
            *pinv.entry(m.module.clone()).or_default() += 1;
        }
        for (m, c) in &pinv {
            let def = k.functions.library(m).or_else(|| k.functions.library(&format!("{m}.dll")));
            a.libraries.push(LibraryRow {
                name: m.clone(),
                kind: "p/Invoke".into(),
                imports: *c,
                flag: def.is_some_and(|d| d.flag),
                group: def.and_then(|d| d.group),
                description: def.map(|d| d.description.clone()).unwrap_or_default(),
                known: def.is_some(),
                spoofed: false,
                ..Default::default()
            });
        }
        for m in &n.impl_maps {
            let def = k.functions.function(&m.module, &m.import_name);
            a.imports.push(ImportRow {
                name: m.import_name.clone(),
                library: m.module.clone(),
                kind: "p/Invoke".into(),
                group: def.and_then(|d| d.group),
                ti: def.and_then(|d| d.ti.clone()),
                flag: def.is_some_and(|d| d.flag),
                callback: def.is_some_and(|d| d.callback),
                ..Default::default()
            });
        }
        for m in &n.member_refs {
            if m.name == ".ctor" || m.name == ".cctor" {
                continue;
            }
            let ns_def = k.namespaces.lookup(&m.parent);
            let def = k.functions.function("", &m.name).filter(|d| !d.hidden);
            let ns = m.parent.rsplit_once('.').map(|(a, _)| a.to_string()).unwrap_or_default();
            a.imports.push(ImportRow {
                name: m.name.clone(),
                library: m.parent.clone(),
                kind: "dotnet".into(),
                group: def.and_then(|d| d.group).or(ns_def.and_then(|d| d.group)),
                ti: def.and_then(|d| d.ti.clone()).or(ns_def.and_then(|d| d.ti.clone())),
                flag: def.is_some_and(|d| d.flag) || ns_def.is_some_and(|d| d.flag),
                namespace: Some(ns),
                ..Default::default()
            });
        }
    }
}

fn build_exports(a: &mut Analysis, k: &Knowledge) {
    let Some(e) = a.pe.exports.as_ref() else { return };
    let l = a.pe.layout.as_ref().expect("pe");
    let ep = a.pe.entry_point.as_ref().map(|e| e.rva).unwrap_or(0);
    let dups: std::collections::HashSet<&String> = e.duplicate_names.iter().collect();
    for f in &e.functions {
        let name = f.name.clone().unwrap_or_default();
        let def = f.name.as_ref().and_then(|n| k.functions.function(&e.dll_name, n));
        a.exports.push(ExportRow {
            ordinal: f.ordinal,
            undecorated: util::undecorate(&name),
            name,
            rva: f.rva,
            function_index: f.function_index,
            name_rva: f.name_rva,
            forwarder: f.forwarder.clone(),
            gap: f.gap,
            anonymous: f.is_anonymous(),
            duplicate: f.name.as_ref().is_some_and(|n| dups.contains(n)),
            flag: def.is_some_and(|d| d.flag),
            entry_point: ep != 0 && f.rva == ep,
            location: if f.gap { "n/a".into() } else { l.section_name_of_rva(f.rva) },
        });
    }
}

/// Resource bytes hashed and scanned: at most this many times the file size…
const RESOURCE_SCAN_FACTOR: u64 = 8;
/// …but always at least this much.
const RESOURCE_SCAN_MIN: u64 = 64 << 20;
/// md5 shown for a resource left out of the scan budget.
pub const RESOURCE_SKIPPED: &str = "n/a (overlapping resources, not hashed)";

fn build_resources(a: &mut Analysis, k: &Knowledge, data: &[u8], first_bytes: usize) {
    let Some(res) = a.pe.resources.as_ref() else { return };
    // Entries may share one data blob (crafted files repeat it thousands of times): hash once.
    struct BlobInfo {
        embedded: Option<String>,
        signature: Option<Option<String>>,
        entropy: f64,
        md5: String,
    }
    let mut cache: HashMap<(Option<u32>, u32), BlobInfo> = HashMap::new();
    // Distinct blobs can still overlap (thousands of entries each claiming most of the file), so
    // the bytes hashed and scanned are capped: past the budget a blob is listed without them.
    let mut budget = (data.len() as u64).saturating_mul(RESOURCE_SCAN_FACTOR).max(RESOURCE_SCAN_MIN);
    for e in &res.entries {
        let blob = e.data(&pe_parser::reader::Reader::new(data));
        let info = cache.entry((e.file_offset, e.size)).or_insert_with(|| {
            if (blob.len() as u64) > budget {
                return BlobInfo { embedded: None, signature: Some(None), entropy: 0.0, md5: RESOURCE_SKIPPED.into() };
            }
            budget -= blob.len() as u64;
            BlobInfo { embedded: sigscan::embedded_signature(k, blob), signature: None, entropy: entropy(blob), md5: md5_hex(blob) }
        });
        let lang = (e.language & 0xffff) as u16;
        let (lname, lflag) = k.languages.language(lang).map(|(n, f)| (n.to_string(), f)).unwrap_or_else(|| ("unknown".into(), false));
        let tname = e.type_name();
        let signature = match (&info.embedded, e.is_builtin_type()) {
            (Some(s), _) => s.clone(),
            (None, true) => String::new(),
            (None, false) => info.signature.get_or_insert_with(|| sigscan::blob_signature(k, blob)).clone().unwrap_or_default(),
        };
        let def = k
            .translations
            .resources
            .iter()
            .find(|d| (!signature.is_empty() && d.name.eq_ignore_ascii_case(&signature)) || d.name.eq_ignore_ascii_case(&tname));
        let severity =
            if signature == "executable" { 1 } else { def.map(|d| d.severity).unwrap_or(if e.is_builtin_type() { 4 } else { 3 }) };
        a.resources.push(ResourceRow {
            type_name: tname,
            name: e.name.to_string(),
            language: e.language,
            language_name: lname,
            language_flag: lflag,
            code_page: e.code_page,
            size: e.size,
            offset: e.file_offset,
            file_ratio: ratio(e.size as u64, a.size),
            entropy: info.entropy,
            md5: info.md5.clone(),
            signature,
            severity,
            builtin: e.is_builtin_type(),
            first_bytes_hex: util::bytes_hex(blob, first_bytes),
            first_bytes_text: util::bytes_text(blob, first_bytes),
            stamp: res.time_date_stamp,
        });
    }
}

fn build_stamps(a: &mut Analysis) {
    let pe = &a.pe;
    let l = pe.layout.as_ref().expect("pe");
    let mut s = vec![StampRow { kind: "compiler".into(), value: l.file_header.time_date_stamp }];
    for d in &pe.debug {
        s.push(StampRow { kind: format!("debug ({})", d.type_name()), value: d.time_date_stamp });
    }
    if let Some(r) = &pe.resources {
        s.push(StampRow { kind: "resource".into(), value: r.time_date_stamp });
    }
    if let Some(e) = &pe.exports {
        s.push(StampRow { kind: "export".into(), value: e.time_date_stamp });
    }
    for lib in &pe.imports.libraries {
        if lib.time_date_stamp != 0 && lib.time_date_stamp != u32::MAX {
            s.push(StampRow { kind: format!("import ({})", lib.name), value: lib.time_date_stamp });
        }
    }
    for b in &pe.imports.bound {
        s.push(StampRow { kind: format!("bound-import ({})", b.module_name), value: b.time_date_stamp });
    }
    if let Some(lc) = &pe.load_config {
        s.push(StampRow { kind: "load-config".into(), value: lc.time_date_stamp });
    }
    if let Some(t) =
        pe.security.as_ref().and_then(|x| x.authenticode()).and_then(|a| a.signer.as_ref()).and_then(|s| s.signing_time.or(None))
    {
        s.push(StampRow { kind: "certificate".into(), value: t as u32 });
    } else if let Some(t) =
        pe.security.as_ref().and_then(|x| x.authenticode()).and_then(|a| a.counter_signer.as_ref()).and_then(|s| s.signing_time)
    {
        s.push(StampRow { kind: "certificate".into(), value: t as u32 });
    }
    a.stamps = s;
}

fn tooling(k: &Knowledge, pe: &PeFile) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(r) = &pe.rich {
        for e in &r.entries {
            if let Some(t) = k.rich.tooling(e.build)
                && !out.contains(&t)
            {
                out.push(t);
            }
        }
    }
    if let Some(l) = pe.layout.as_ref() {
        let lv = format!("linker {}.{}", l.optional_header.major_linker_version, l.optional_header.minor_linker_version);
        if out.is_empty() {
            out.push(lv);
        }
    }
    out
}

pub(crate) fn add_footprint(a: &mut Analysis, t: i64, item: &str, location: &str, data: &[u8]) {
    a.footprints.push(Footprint {
        item: item.into(),
        location: location.into(),
        hash_type: hash_type_name(t).into(),
        hash: hash_by_type(data, t),
        size: data.len() as u64,
    });
}

fn build_footprints(a: &mut Analysis, k: &Knowledge, data: &[u8]) {
    let s = &k.settings;
    if !s.get_bool("footprints", "enable", true) {
        return;
    }
    let t = s.get_int("footprints", "type", 2);
    let on = |key: &str| s.get_bool("footprints", key, true);
    // the whole-file hashes are already known: no second pass over the file
    let image = Footprint {
        item: "image".into(),
        location: "file".into(),
        hash_type: hash_type_name(t).into(),
        hash: a.hashes.by_type(t).into(),
        size: a.size,
    };
    a.footprints.push(image);
    if let Some(h) = &a.hashes_without_overlay {
        let ov = a.pe.overlay.as_ref().map(|o| o.offset).unwrap_or(0);
        let f = Footprint {
            item: "image (without overlay)".into(),
            location: "file".into(),
            hash_type: hash_type_name(t).into(),
            hash: h.by_type(t).into(),
            size: ov,
        };
        a.footprints.push(f);
    }
    if let Some(i) = a.imphash.clone() {
        a.footprints.push(Footprint { item: "imphash".into(), location: "imports".into(), hash_type: "md5".into(), hash: i, size: 0 });
    }
    // borrow the parsed file without copying it (add_footprint needs `a` mutably)
    let pe = std::mem::take(&mut a.pe);
    if on("dos-header") && data.len() >= 64 && pe.dos_header.is_some() {
        add_footprint(a, t, "dos-header", "dos-header", &data[..64]);
    }
    if on("dos-stub")
        && let Some(st) = &pe.dos_stub
    {
        let b = &data[(st.offset as usize).min(data.len())..((st.offset + st.size) as usize).min(data.len())];
        if !b.is_empty() {
            add_footprint(a, t, "dos-stub", "dos-stub", b);
        }
    }
    if on("rich")
        && let Some(r) = &pe.rich
    {
        add_footprint(a, t, "rich-header", "rich-header", &r.raw_decoded);
    }
    if on("debug") {
        for d in &pe.debug {
            let b = d.data(&pe_parser::reader::Reader::new(data));
            if !b.is_empty() {
                add_footprint(a, t, &format!("debug ({})", d.type_name()), "debug", b);
            }
        }
    }
    if let Some(res) = &pe.resources {
        let r = pe_parser::reader::Reader::new(data);
        for e in &res.entries {
            let key = match e.type_id.id() {
                Some(16) => "version",
                Some(24) => "manifest",
                Some(6) => "st",
                Some(4) => "menu",
                Some(5) => "dlg",
                Some(3) | Some(14) => "icon",
                Some(1) | Some(12) => "cur",
                Some(2) => "bmp",
                _ => "",
            };
            if !key.is_empty() && s.get_bool("footprints", key, matches!(key, "version" | "manifest")) {
                let b = e.data(&r);
                if !b.is_empty() {
                    add_footprint(a, t, &format!("{} ({})", e.type_name(), e.name), "resource", b);
                }
            }
        }
    }
    if let (Some(ov), Some(info)) = (&pe.overlay, &a.overlay_info) {
        let hash = info.hashes.by_type(t).to_string();
        a.footprints.push(Footprint {
            item: "overlay".into(),
            location: "overlay".into(),
            hash_type: hash_type_name(t).into(),
            hash,
            size: ov.size,
        });
    }
    if let Some(sd) = &pe.security {
        let b = &data[(sd.offset as usize).min(data.len())..((sd.offset as u64 + sd.size as u64) as usize).min(data.len())];
        if !b.is_empty() {
            add_footprint(a, t, "certificate", "certificate", b);
        }
    }
    if let Some(n) = &pe.dotnet {
        for st in &n.streams {
            if let Some(fo) = st.file_offset {
                let b = &data[fo as usize..((fo as u64 + st.size as u64) as usize).min(data.len())];
                add_footprint(a, t, &format!("stream ({})", st.name), "dotnet", b);
            }
        }
    }
    a.pe = pe;
}

fn build_groups(a: &mut Analysis, k: &Knowledge) {
    let mut map: BTreeMap<u8, Vec<String>> = BTreeMap::new();
    for i in &a.imports {
        if let Some(g) = i.group {
            map.entry(g).or_default().push(i.name.clone());
        }
    }
    for s in &a.strings {
        if let Some(g) = s.group {
            let e = map.entry(g).or_default();
            if !e.contains(&s.value) {
                e.push(s.value.clone());
            }
        }
    }
    for (id, items) in map {
        let def = k.translations.group(id);
        a.groups.push(GroupRow {
            id,
            name: k.group_name(id),
            count: items.len(),
            rgb: def.map(|d| d.rgb).unwrap_or((200, 200, 200)),
            level: def.map(|d| d.level).unwrap_or(1),
            items,
        });
    }
}

fn build_mitre(a: &mut Analysis, k: &Knowledge) {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut add = |ti: &Option<String>, src: String| {
        if let Some(t) = ti {
            let e = map.entry(t.trim_start_matches('T').to_string()).or_default();
            if !e.contains(&src) {
                e.push(src);
            }
        }
    };
    for i in &a.imports {
        add(&i.ti, format!("import: {}", i.name));
    }
    for s in &a.strings {
        add(&s.ti, format!("string: {}", s.value));
    }
    for i in &a.indicators {
        add(&i.ti, format!("indicator: {}", i.name));
    }
    if let Some(n) = &a.pe.dotnet {
        for t in &n.type_refs {
            if let Some(ns) = k.namespaces.lookup(&t.full_name()) {
                add(&ns.ti, format!("namespace: {}", ns.name));
            }
        }
    }
    for (id, sources) in map {
        let tech = k.mitre.technique(&id);
        if tech.is_some_and(|t| !t.enable) {
            continue;
        }
        let tactic = tech.and_then(|t| k.mitre.tactic(&t.tactic));
        a.mitre.push(MitreRow {
            technique: format!("T{id}"),
            technique_name: tech.map(|t| t.name.clone()).unwrap_or_default(),
            tactic: tech.map(|t| format!("TA{}", t.tactic)).unwrap_or_default(),
            tactic_name: tactic.map(|t| t.name.clone()).unwrap_or_default(),
            flag: tech.is_some_and(|t| t.flag),
            level: tech.map(|t| t.level).unwrap_or(2),
            sources,
        });
    }
}

/// Manifest helper for views/indicators.
pub fn manifest(a: &Analysis, data: &[u8]) -> Option<resource_content::Manifest> {
    a.pe.manifest(data).map(|(_, m)| m)
}
