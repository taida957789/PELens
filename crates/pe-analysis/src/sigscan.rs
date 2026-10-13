//! Signature engine (signatures.xml): entry-point signatures (PEiD style), file-type
//! signatures and embedded-file detection inside resources, sections and the overlay.

use crate::model::{EmbeddedFile, SignatureHit};
use crate::util::find_bytes;
use pe_db::{Knowledge, PatternKind, SignatureDef};
use pe_parser::PeFile;

fn hit(s: &SignatureDef, location: &str, offset: u64, size: u64) -> SignatureHit {
    SignatureHit {
        name: s.name.clone(),
        more: s.more.clone(),
        location: location.to_string(),
        offset,
        size,
        file: s.file,
        tool: s.tool,
        severity: s.severity,
        url: s.url.clone(),
    }
}

/// File-type signature of a blob (ep=0 byte patterns anchored at the start).
pub fn identify(k: &Knowledge, data: &[u8]) -> Option<&'static str> {
    let _ = k;
    builtin_magic(data)
}

/// Signature name of a blob using the knowledge base first and built-in magics as fallback.
pub fn blob_signature(k: &Knowledge, data: &[u8]) -> Option<String> {
    for s in &k.signatures {
        for p in s.patterns.iter().filter(|p| !p.ep) {
            if let PatternKind::Bytes(_) = p.kind
                && p.matches(data)
            {
                return Some(s.name.clone());
            }
        }
    }
    identify(k, data).map(str::to_string)
}

/// Well-known magics used when no knowledge base entry matches.
pub fn builtin_magic(d: &[u8]) -> Option<&'static str> {
    let starts = |m: &[u8]| d.starts_with(m);
    if starts(b"MZ") {
        return Some("executable");
    }
    let table: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "PKZIP"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"MSCF", "CAB"),
        (b"%PDF", "PDF"),
        (b"{\\rtf", "RTF"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS-CFB"),
        (b"\x89PNG", "PNG"),
        (b"GIF8", "GIF"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"BM", "BMP"),
        (b"RIFF", "Riff"),
        (b"\x7fELF", "ELF"),
        (b"\x1f\x8b", "GZIP"),
        (b"ITSF", "chtml"),
        (b"L\x00\x00\x00\x01\x14\x02\x00", "LNK"),
        (b"<?xml", "XML"),
        (b"\xef\xbb\xbf<?xml", "XML"),
        (b"SZDD", "MS-Compress"),
        (b"KWAJ", "MS-Compress"),
        (b"FWS", "SWF"),
        (b"CWS", "SWF"),
        (b"MSFT", "tlb"),
        (b"regf", "registry"),
        (b"\x00\x00\x01\x00", "icon"),
        (b"#!", "script"),
    ];
    for (m, n) in table {
        if starts(m) {
            return Some(n);
        }
    }
    let txt = d.iter().take(256).all(|&b| b == b'\r' || b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b));
    if !d.is_empty() && txt {
        return Some("Text");
    }
    None
}

/// True when `d` starts with a plausible PE image (MZ + valid e_lfanew + PE signature).
pub fn looks_like_pe(d: &[u8]) -> bool {
    if !d.starts_with(b"MZ") || d.len() < 0x40 {
        return false;
    }
    let lfanew = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    (0x40..0x1000).contains(&lfanew) && d.get(lfanew..lfanew + 4) == Some(b"PE\0\0")
}

pub struct ScanResult {
    pub signatures: Vec<SignatureHit>,
    pub embedded: Vec<EmbeddedFile>,
}

pub fn scan(k: &Knowledge, pe: &PeFile, data: &[u8]) -> ScanResult {
    let mut sigs = Vec::new();
    let mut embedded = Vec::new();

    // Entry-point signatures.
    if let Some(ep_off) = pe.entry_point.as_ref().and_then(|e| e.file_offset) {
        let at = &data[(ep_off as usize).min(data.len())..];
        for s in &k.signatures {
            if s.patterns.iter().any(|p| p.ep && matches!(p.kind, PatternKind::Bytes(_)) && p.matches(at)) {
                sigs.push(hit(s, "entry-point", ep_off, 0));
            }
        }
    }

    // Text signatures: section names and file content.
    let names: Vec<&str> = pe.sections().iter().map(|s| s.name.as_str()).collect();
    for s in &k.signatures {
        for p in &s.patterns {
            if let PatternKind::Text(t) = &p.kind {
                if t.starts_with('.') && names.iter().any(|n| n.eq_ignore_ascii_case(t)) {
                    sigs.push(hit(s, "section", 0, 0));
                    break;
                }
                if !t.starts_with('.')
                    && let Some(o) = find_bytes(data, t.as_bytes())
                {
                    sigs.push(hit(s, "file", o as u64, t.len() as u64));
                    break;
                }
            }
        }
    }

    // Whole-file signature (non PE input such as documents/archives).
    if !pe.is_pe()
        && let Some(name) = blob_signature(k, data)
    {
        if let Some(s) = k.signatures.iter().find(|s| s.name == name) {
            sigs.push(hit(s, "file", 0, data.len() as u64));
        } else {
            sigs.push(SignatureHit { name, location: "file".into(), size: data.len() as u64, severity: 3, ..Default::default() });
        }
    }

    // Embedded files: resources.
    if let Some(res) = &pe.resources {
        for e in &res.entries {
            let blob = pe.resource_data(data, e);
            if blob.len() < 4 {
                continue;
            }
            if let Some(name) = embedded_signature(k, blob) {
                embedded.push(EmbeddedFile {
                    signature: name,
                    location: format!("resource:{}:{}", e.type_name(), e.name),
                    offset: e.file_offset.unwrap_or(0) as u64,
                    size: e.size as u64,
                });
            }
        }
    }
    // Embedded executables hidden inside sections / overlay (any MZ with a valid PE header).
    let mut regions: Vec<(String, u64, u64)> = Vec::new();
    if let Some(l) = pe.layout.as_ref() {
        for s in &l.sections {
            regions.push((format!("section:{}", s.name), l.raw_pointer(s), l.raw_size(s)));
        }
    }
    if let Some(ov) = &pe.overlay {
        regions.push(("overlay".into(), ov.offset, ov.size));
        let blob = &data[ov.offset as usize..(ov.offset + ov.size) as usize];
        if let Some(name) = embedded_signature(k, blob).filter(|n| n != "Text")
            && name != "executable"
        {
            embedded.push(EmbeddedFile { signature: name, location: "overlay".into(), offset: ov.offset, size: ov.size });
        }
    }
    let res_ranges: Vec<(u64, u64)> =
        pe.resources.iter().flat_map(|r| r.entries.iter().filter_map(|e| e.file_offset.map(|o| (o as u64, e.size as u64)))).collect();
    for (name, start, size) in regions {
        let end = (start + size).min(data.len() as u64) as usize;
        let mut pos = start as usize;
        while pos + 2 < end {
            let Some(rel) = find_bytes(&data[pos..end], b"MZ") else { break };
            let at = pos + rel;
            if at != 0 && looks_like_pe(&data[at..end]) {
                let inside_res = res_ranges.iter().any(|(o, s)| at as u64 == *o && *s > 0);
                if !inside_res {
                    embedded.push(EmbeddedFile {
                        signature: "executable".into(),
                        location: name.clone(),
                        offset: at as u64,
                        size: (end - at) as u64,
                    });
                }
            }
            pos = at + 2;
        }
    }
    // Base64-encoded executable ("TVqQAAMAAAAEAAAA" == base64("MZ\x90\0\x03\0\0\0\x04\0\0\0")).
    if let Some(o) = find_bytes(data, b"TVqQAAMAAAAEAAAA") {
        embedded.push(EmbeddedFile {
            signature: "executable (base64)".into(),
            location: crate::strings::location_of(pe, o as u64),
            offset: o as u64,
            size: 0,
        });
    }
    sigs.dedup_by(|a, b| a.name == b.name && a.location == b.location);
    ScanResult { signatures: sigs, embedded }
}

/// Signature of an embedded blob (only "interesting" file types are reported).
pub fn embedded_signature(k: &Knowledge, blob: &[u8]) -> Option<String> {
    if looks_like_pe(blob) {
        return Some("executable".into());
    }
    for s in &k.signatures {
        if !s.file {
            continue;
        }
        if s.patterns.iter().any(|p| !p.ep && matches!(p.kind, PatternKind::Bytes(_)) && p.matches(blob)) {
            return Some(s.name.clone());
        }
    }
    match builtin_magic(blob)? {
        "PKZIP" | "RAR" | "7-Zip" | "CAB" | "PDF" | "RTF" | "MS-CFB" | "ELF" | "GZIP" | "chtml" | "LNK" | "SWF" | "MS-Compress"
        | "script" => builtin_magic(blob).map(str::to_string),
        _ => None,
    }
}
