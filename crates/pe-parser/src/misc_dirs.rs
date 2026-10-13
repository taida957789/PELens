//! TLS, base relocations, exception table (.pdata) and load-configuration directory.

use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;

// ---------------------------------------------------------------- TLS

#[derive(Debug, Clone, Default)]
pub struct Tls {
    pub offset: u32,
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    /// Callback virtual addresses.
    pub callbacks: Vec<u64>,
}

impl Tls {
    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::TLS)?;
        let o = l.rva_to_offset(d.rva)?;
        let mut t = Tls { offset: o as u32, ..Default::default() };
        let ptr = |off: usize| if l.is_64() { r.u64(off) } else { r.u32(off).map(|v| v as u64) };
        let ps = if l.is_64() { 8 } else { 4 };
        t.start_address_of_raw_data = ptr(o)?;
        t.end_address_of_raw_data = ptr(o + ps)?;
        t.address_of_index = ptr(o + 2 * ps)?;
        t.address_of_callbacks = ptr(o + 3 * ps)?;
        t.size_of_zero_fill = r.u32(o + 4 * ps)?;
        t.characteristics = r.u32(o + 4 * ps + 4)?;
        if let Some(rva) = l.va_to_rva(t.address_of_callbacks)
            && let Some(mut co) = l.rva_to_offset(rva)
        {
            while t.callbacks.len() < 1024 {
                match ptr(co) {
                    Some(0) | None => break,
                    Some(cb) => t.callbacks.push(cb),
                }
                co += ps;
            }
        }
        Some(t)
    }
}

// ---------------------------------------------------------------- relocations

pub fn relocation_type_name(t: u8) -> &'static str {
    match t {
        0 => "absolute",
        1 => "high",
        2 => "low",
        3 => "high-low",
        4 => "high-adjust",
        5 => "mips-jump-addr",
        9 => "ia64",
        10 => "dir64",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Default)]
pub struct RelocationBlock {
    pub offset: u32,
    pub page_rva: u32,
    pub block_size: u32,
    /// (type, offset within page)
    pub entries: Vec<(u8, u16)>,
}

pub fn parse_relocations(r: &Reader, l: &Layout) -> Vec<RelocationBlock> {
    let mut out = Vec::new();
    let Some(d) = l.optional_header.directory(dir::BASERELOC) else { return out };
    let Some(base) = l.rva_to_offset(d.rva) else { return out };
    let end = base + d.size as usize;
    let mut o = base;
    while o + 8 <= end && out.len() < 65536 {
        let (Some(page), Some(size)) = (r.u32(o), r.u32(o + 4)) else { break };
        if size < 8 {
            break;
        }
        let mut b = RelocationBlock { offset: o as u32, page_rva: page, block_size: size, entries: Vec::new() };
        let n = ((size - 8) / 2) as usize;
        for i in 0..n {
            let Some(e) = r.u16(o + 8 + i * 2) else { break };
            b.entries.push(((e >> 12) as u8, e & 0x0fff));
        }
        out.push(b);
        o += size as usize;
    }
    out
}

// ---------------------------------------------------------------- exceptions

#[derive(Debug, Clone, Default)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

pub fn parse_exceptions(r: &Reader, l: &Layout) -> Vec<RuntimeFunction> {
    let mut out = Vec::new();
    let Some(d) = l.optional_header.directory(dir::EXCEPTION) else { return out };
    let Some(base) = l.rva_to_offset(d.rva) else { return out };
    let arm = matches!(l.file_header.machine, 0xaa64 | 0x01c4 | 0xa641);
    let es = if arm { 8 } else { 12 };
    let n = (d.size as usize / es).min(1 << 20);
    for i in 0..n {
        let o = base + i * es;
        let (Some(a), Some(b)) = (r.u32(o), r.u32(o + 4)) else { break };
        if arm {
            out.push(RuntimeFunction { begin: a, end: 0, unwind: b });
        } else {
            let Some(c) = r.u32(o + 8) else { break };
            out.push(RuntimeFunction { begin: a, end: b, unwind: c });
        }
    }
    out
}

// ---------------------------------------------------------------- load config

pub mod guard_flags {
    pub const CF_INSTRUMENTED: u32 = 0x0000_0100;
    pub const CFW_INSTRUMENTED: u32 = 0x0000_0200;
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
    pub const RF_INSTRUMENTED: u32 = 0x0002_0000;
    pub const EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
    pub const XFG_ENABLED: u32 = 0x0080_0000;
}

#[derive(Debug, Clone, Default)]
pub struct LoadConfig {
    pub offset: u32,
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

impl LoadConfig {
    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::LOAD_CONFIG)?;
        let o = l.rva_to_offset(d.rva)?;
        let size = r.u32(o)?;
        let lim = size as usize;
        let rd32 = |k: usize| if k + 4 <= lim { r.u32(o + k).unwrap_or(0) } else { 0 };
        let rdp = |k32: usize, k64: usize| -> u64 {
            if l.is_64() {
                if k64 + 8 <= lim { r.u64(o + k64).unwrap_or(0) } else { 0 }
            } else if k32 + 4 <= lim {
                r.u32(o + k32).unwrap_or(0) as u64
            } else {
                0
            }
        };
        Some(LoadConfig {
            offset: o as u32,
            size,
            time_date_stamp: rd32(4),
            major_version: if lim >= 10 { r.u16(o + 8).unwrap_or(0) } else { 0 },
            minor_version: if lim >= 12 { r.u16(o + 10).unwrap_or(0) } else { 0 },
            global_flags_clear: rd32(12),
            global_flags_set: rd32(16),
            security_cookie: rdp(0x3c, 0x58),
            se_handler_table: rdp(0x40, 0x60),
            se_handler_count: rdp(0x44, 0x68),
            guard_cf_check_function_pointer: rdp(0x48, 0x70),
            guard_cf_dispatch_function_pointer: rdp(0x4c, 0x78),
            guard_cf_function_table: rdp(0x50, 0x80),
            guard_cf_function_count: rdp(0x54, 0x88),
            guard_flags: if l.is_64() { rd32(0x90) } else { rd32(0x58) },
        })
    }

    /// Stack buffer-overrun detection (/GS) cookie present.
    pub fn has_gs(&self) -> bool {
        self.security_cookie != 0
    }

    pub fn has_safe_seh(&self) -> bool {
        self.se_handler_table != 0 && self.se_handler_count != 0
    }

    pub fn has_cfg(&self) -> bool {
        self.guard_flags & guard_flags::CF_INSTRUMENTED != 0
    }
}
