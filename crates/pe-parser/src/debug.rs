//! Debug directory and the stream formats it references.

use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;

pub fn debug_type_name(t: u32) -> &'static str {
    match t {
        0 => "unknown",
        1 => "COFF",
        2 => "CodeView",
        3 => "FPO",
        4 => "MISC",
        5 => "exception",
        6 => "fixup",
        7 => "omapToSrc",
        8 => "omapFromSrc",
        9 => "Borland",
        10 => "reserved10",
        11 => "clsid",
        12 => "vcFeature",
        13 => "POGO",
        14 => "iltcg",
        15 => "mpx",
        16 => "REPRO",
        17 => "embedded portable PDB",
        19 => "pdb-checksum",
        20 => "Extended Dll Characteristics",
        _ => "unknown",
    }
}

#[derive(Debug, Clone)]
pub enum DebugInfo {
    Rsds { guid: [u8; 16], age: u32, path: String },
    Nb10 { offset: u32, signature: u32, age: u32, path: String },
    CodeViewOther { signature: String },
    Misc { data_type: u32, unicode: bool, text: String },
    Pogo { signature: String, entries: Vec<(u32, u32, String)> },
    VcFeature { pre_vc11: u32, c_cpp: u32, gs: u32, sdl: u32, guard_n: u32 },
    ExDllCharacteristics { flags: u32 },
    Repro { hash: Vec<u8> },
    PdbChecksum { algorithm: String, checksum: Vec<u8> },
    None,
}

pub mod ex_dll {
    pub const CET_COMPAT: u32 = 0x01;
    pub const CET_COMPAT_STRICT_MODE: u32 = 0x02;
    pub const CET_SET_CONTEXT_IP_VALIDATION_RELAXED: u32 = 0x04;
    pub const CET_DYNAMIC_APIS_ALLOW_IN_PROC: u32 = 0x08;
    pub const FORWARD_CFI_COMPAT: u32 = 0x40;
    pub const HOTPATCH_COMPATIBLE: u32 = 0x80;

    pub const ALL: [(u32, &str); 6] = [
        (CET_COMPAT, "Control-flow Enforcement Technology (CETCOMPACT)"),
        (CET_COMPAT_STRICT_MODE, "CET strict mode"),
        (CET_SET_CONTEXT_IP_VALIDATION_RELAXED, "CET context-IP validation relaxed"),
        (CET_DYNAMIC_APIS_ALLOW_IN_PROC, "CET dynamic APIs in-proc"),
        (FORWARD_CFI_COMPAT, "forward CFI compatible"),
        (HOTPATCH_COMPATIBLE, "hotpatch compatible"),
    ];
}

#[derive(Debug, Clone)]
pub struct DebugEntry {
    /// File offset of the IMAGE_DEBUG_DIRECTORY.
    pub entry_offset: u32,
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub kind: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub info: DebugInfo,
}

impl DebugEntry {
    pub fn type_name(&self) -> &'static str {
        debug_type_name(self.kind)
    }

    pub fn data<'a>(&self, r: &Reader<'a>) -> &'a [u8] {
        r.bytes_clamped(self.pointer_to_raw_data as usize, self.size_of_data as usize)
    }

    pub fn pdb_path(&self) -> Option<&str> {
        match &self.info {
            DebugInfo::Rsds { path, .. } | DebugInfo::Nb10 { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// GUID in registry format.
pub fn format_guid(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

pub fn parse(r: &Reader, l: &Layout) -> Vec<DebugEntry> {
    let mut out = Vec::new();
    let Some(d) = l.optional_header.directory(dir::DEBUG) else { return out };
    let Some(base) = l.rva_to_offset(d.rva) else { return out };
    let n = (d.size / 28).min(256) as usize;
    for i in 0..n {
        let o = base + i * 28;
        let Some(b) = r.bytes(o, 28) else { break };
        let f = |k: usize| u32::from_le_bytes([b[k], b[k + 1], b[k + 2], b[k + 3]]);
        let mut e = DebugEntry {
            entry_offset: o as u32,
            characteristics: f(0),
            time_date_stamp: f(4),
            major_version: u16::from_le_bytes([b[8], b[9]]),
            minor_version: u16::from_le_bytes([b[10], b[11]]),
            kind: f(12),
            size_of_data: f(16),
            address_of_raw_data: f(20),
            pointer_to_raw_data: f(24),
            info: DebugInfo::None,
        };
        if e.pointer_to_raw_data == 0
            && e.address_of_raw_data != 0
            && let Some(po) = l.rva_to_offset(e.address_of_raw_data)
        {
            e.pointer_to_raw_data = po as u32;
        }
        let data = e.data(r);
        e.info = decode(e.kind, data);
        out.push(e);
    }
    out
}

fn decode(kind: u32, data: &[u8]) -> DebugInfo {
    let r = Reader::new(data);
    match kind {
        2 => match r.bytes(0, 4) {
            Some(b"RSDS") => {
                let mut guid = [0u8; 16];
                if let Some(g) = r.bytes(4, 16) {
                    guid.copy_from_slice(g);
                }
                DebugInfo::Rsds { guid, age: r.u32(20).unwrap_or(0), path: r.cstr(24, 1024).unwrap_or_default() }
            }
            Some(b"NB10") => DebugInfo::Nb10 {
                offset: r.u32(4).unwrap_or(0),
                signature: r.u32(8).unwrap_or(0),
                age: r.u32(12).unwrap_or(0),
                path: r.cstr(16, 1024).unwrap_or_default(),
            },
            Some(sig) => DebugInfo::CodeViewOther { signature: String::from_utf8_lossy(sig).into_owned() },
            None => DebugInfo::None,
        },
        4 => {
            let data_type = r.u32(0).unwrap_or(0);
            let unicode = r.u8(8).unwrap_or(0) != 0;
            let text = if unicode { r.wstr(12, 512).unwrap_or_default() } else { r.cstr(12, 1024).unwrap_or_default() };
            DebugInfo::Misc { data_type, unicode, text }
        }
        12 => DebugInfo::VcFeature {
            pre_vc11: r.u32(0).unwrap_or(0),
            c_cpp: r.u32(4).unwrap_or(0),
            gs: r.u32(8).unwrap_or(0),
            sdl: r.u32(12).unwrap_or(0),
            guard_n: r.u32(16).unwrap_or(0),
        },
        13 => {
            let sig = r.bytes(0, 4).map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string()).unwrap_or_default();
            let mut entries = Vec::new();
            let mut o = 4usize;
            while o + 8 < data.len() && entries.len() < 4096 {
                let rva = r.u32(o).unwrap_or(0);
                let size = r.u32(o + 4).unwrap_or(0);
                let name = r.cstr(o + 8, 256).unwrap_or_default();
                o = (o + 8 + name.len() + 1 + 3) & !3;
                entries.push((rva, size, name));
            }
            DebugInfo::Pogo { signature: sig, entries }
        }
        16 => {
            let len = r.u32(0).unwrap_or(0) as usize;
            DebugInfo::Repro { hash: r.bytes_clamped(4, len.min(64)).to_vec() }
        }
        19 => {
            let alg = r.cstr(0, 64).unwrap_or_default();
            let cs = r.bytes_clamped(alg.len() + 1, 64).to_vec();
            DebugInfo::PdbChecksum { algorithm: alg, checksum: cs }
        }
        20 => DebugInfo::ExDllCharacteristics { flags: r.u32(0).unwrap_or(0) },
        _ => DebugInfo::None,
    }
}
