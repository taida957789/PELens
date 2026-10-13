//! Import directory, delay-load import directory and bound-import directory.

use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;

const MAX_LIBRARIES: usize = 4096;
const MAX_FUNCTIONS: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportKind {
    #[default]
    Implicit,
    DelayLoaded,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    /// Raw value of the Import Name Table (OriginalFirstThunk) entry.
    pub int_value: u64,
    /// Raw value of the Import Address Table (FirstThunk) entry, as stored on disk.
    pub iat_value: u64,
    /// RVA of the IAT slot.
    pub iat_rva: u32,
    /// RVA of the hint/name entry (0 when imported by ordinal).
    pub name_rva: u32,
}

impl ImportedFunction {
    pub fn display_name(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(n), _) => n.clone(),
            (None, Some(o)) => format!("#{o}"),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ImportedLibrary {
    pub name: String,
    pub kind: ImportKind,
    /// File offset of the descriptor.
    pub descriptor_offset: u32,
    pub name_rva: u32,
    pub int_rva: u32,
    pub iat_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    /// Delay-load attributes (1 = RVA based).
    pub attributes: u32,
    pub functions: Vec<ImportedFunction>,
    /// The descriptor has no Import Name Table and the IAT was used instead.
    pub int_missing: bool,
    /// Number of entries for which INT and IAT disagree (unbound image).
    pub int_iat_mismatch: usize,
    /// IAT entries that point outside the image (invalid / pre-patched).
    pub invalid_iat_entries: usize,
}

impl ImportedLibrary {
    pub fn is_bound(&self) -> bool {
        self.time_date_stamp != 0 && self.kind == ImportKind::Implicit
    }
}

#[derive(Debug, Clone, Default)]
pub struct BoundForwarderRef {
    pub time_date_stamp: u32,
    pub module_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct BoundImport {
    pub time_date_stamp: u32,
    pub module_name: String,
    pub forwarders: Vec<BoundForwarderRef>,
}

#[derive(Debug, Clone, Default)]
pub struct Imports {
    pub libraries: Vec<ImportedLibrary>,
    pub bound: Vec<BoundImport>,
}

impl Imports {
    pub fn function_count(&self) -> usize {
        self.libraries.iter().map(|l| l.functions.len()).sum()
    }

    pub fn ordinal_count(&self) -> usize {
        self.libraries.iter().flat_map(|l| &l.functions).filter(|f| f.name.is_none()).count()
    }

    pub fn parse(r: &Reader, l: &Layout) -> Self {
        let mut out = Imports::default();
        if let Some(d) = l.optional_header.directory(dir::IMPORT) {
            parse_implicit(r, l, d.rva, &mut out.libraries);
        }
        if let Some(d) = l.optional_header.directory(dir::DELAY_IMPORT) {
            parse_delay(r, l, d.rva, &mut out.libraries);
        }
        if let Some(d) = l.optional_header.directory(dir::BOUND_IMPORT) {
            out.bound = parse_bound(r, l, d.rva, d.size);
        }
        out
    }
}

fn thunk_size(l: &Layout) -> usize {
    if l.is_64() { 8 } else { 4 }
}

fn read_thunk(r: &Reader, l: &Layout, rva: u32) -> Option<u64> {
    let off = l.rva_to_offset(rva)?;
    if l.is_64() { r.u64(off) } else { r.u32(off).map(|v| v as u64) }
}

fn ordinal_flag(l: &Layout) -> u64 {
    if l.is_64() { 1 << 63 } else { 1 << 31 }
}

fn decode_thunk(r: &Reader, l: &Layout, v: u64, f: &mut ImportedFunction, va_based: bool) {
    if v & ordinal_flag(l) != 0 {
        f.ordinal = Some((v & 0xffff) as u16);
        return;
    }
    let mut rva = (v & 0x7fff_ffff) as u32;
    if va_based {
        rva = l.va_to_rva(v).unwrap_or(rva);
    }
    f.name_rva = rva;
    if let Some(off) = l.rva_to_offset(rva) {
        f.hint = r.u16(off);
        f.name = r.cstr(off + 2, 512).filter(|s| !s.is_empty());
    }
}

fn walk_thunks(r: &Reader, l: &Layout, lib: &mut ImportedLibrary, int_rva: u32, iat_rva: u32, va_based: bool) {
    let ts = thunk_size(l) as u32;
    let lookup = if int_rva != 0 && l.rva_to_offset(int_rva).is_some() {
        int_rva
    } else {
        lib.int_missing = true;
        iat_rva
    };
    let image_end = l.image_base() + l.optional_header.size_of_image as u64;
    for i in 0..MAX_FUNCTIONS as u32 {
        let Some(v) = read_thunk(r, l, lookup.wrapping_add(i * ts)) else { break };
        if v == 0 {
            break;
        }
        let iat_slot = iat_rva.wrapping_add(i * ts);
        let iat_value = read_thunk(r, l, iat_slot).unwrap_or(0);
        let mut f = ImportedFunction { int_value: v, iat_value, iat_rva: iat_slot, ..Default::default() };
        decode_thunk(r, l, v, &mut f, va_based);
        if !lib.int_missing && iat_value != v && lib.time_date_stamp == 0 {
            lib.int_iat_mismatch += 1;
            let in_image = iat_value >= l.image_base() && iat_value < image_end;
            if iat_value & ordinal_flag(l) == 0 && iat_value > l.optional_header.size_of_image as u64 && !in_image {
                lib.invalid_iat_entries += 1;
            }
        }
        lib.functions.push(f);
    }
}

fn parse_implicit(r: &Reader, l: &Layout, rva: u32, out: &mut Vec<ImportedLibrary>) {
    for i in 0..MAX_LIBRARIES as u32 {
        let drva = rva.wrapping_add(i * 20);
        let Some(off) = l.rva_to_offset(drva) else { break };
        let (Some(int_rva), Some(ts), Some(fwd), Some(name_rva), Some(iat_rva)) =
            (r.u32(off), r.u32(off + 4), r.u32(off + 8), r.u32(off + 12), r.u32(off + 16))
        else {
            break;
        };
        if int_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        let mut lib = ImportedLibrary {
            name: l.cstr_at_rva(r, name_rva, 256).unwrap_or_default(),
            kind: ImportKind::Implicit,
            descriptor_offset: off as u32,
            name_rva,
            int_rva,
            iat_rva,
            time_date_stamp: ts,
            forwarder_chain: fwd,
            ..Default::default()
        };
        walk_thunks(r, l, &mut lib, int_rva, iat_rva, false);
        out.push(lib);
    }
}

fn parse_delay(r: &Reader, l: &Layout, rva: u32, out: &mut Vec<ImportedLibrary>) {
    for i in 0..MAX_LIBRARIES as u32 {
        let drva = rva.wrapping_add(i * 32);
        let Some(off) = l.rva_to_offset(drva) else { break };
        let Some(d) = r.bytes(off, 32) else { break };
        let f = |k: usize| u32::from_le_bytes([d[k], d[k + 1], d[k + 2], d[k + 3]]);
        let (attrs, name, _hmod, iat, int, _biat, _uiat, ts) = (f(0), f(4), f(8), f(12), f(16), f(20), f(24), f(28));
        if name == 0 && iat == 0 && int == 0 {
            break;
        }
        let va_based = attrs & 1 == 0;
        let fix = |v: u32| if va_based { l.va_to_rva(v as u64).unwrap_or(v) } else { v };
        let name_rva = fix(name);
        let mut lib = ImportedLibrary {
            name: l.cstr_at_rva(r, name_rva, 256).unwrap_or_default(),
            kind: ImportKind::DelayLoaded,
            descriptor_offset: off as u32,
            name_rva,
            int_rva: fix(int),
            iat_rva: fix(iat),
            time_date_stamp: ts,
            attributes: attrs,
            ..Default::default()
        };
        let (int_rva, iat_rva) = (lib.int_rva, lib.iat_rva);
        walk_thunks(r, l, &mut lib, int_rva, iat_rva, va_based);
        // Delay IATs legitimately differ from INTs (they point to thunks), so the mismatch is meaningless.
        lib.int_iat_mismatch = 0;
        lib.invalid_iat_entries = 0;
        out.push(lib);
    }
}

fn parse_bound(r: &Reader, l: &Layout, rva: u32, size: u32) -> Vec<BoundImport> {
    let mut out = Vec::new();
    // Bound import data normally lives in the header area, so RVA == file offset.
    let Some(base) = l.rva_to_offset(rva).or(Some(rva as usize)) else { return out };
    let end = base + size as usize;
    let mut p = base;
    while p + 8 <= end && out.len() < MAX_LIBRARIES {
        let (Some(ts), Some(name_off), Some(nfwd)) = (r.u32(p), r.u16(p + 4), r.u16(p + 6)) else { break };
        if ts == 0 && name_off == 0 && nfwd == 0 {
            break;
        }
        let mut b = BoundImport {
            time_date_stamp: ts,
            module_name: r.cstr(base + name_off as usize, 256).unwrap_or_default(),
            forwarders: Vec::new(),
        };
        p += 8;
        for _ in 0..nfwd {
            let (Some(fts), Some(fname)) = (r.u32(p), r.u16(p + 4)) else { break };
            b.forwarders
                .push(BoundForwarderRef { time_date_stamp: fts, module_name: r.cstr(base + fname as usize, 256).unwrap_or_default() });
            p += 8;
        }
        out.push(b);
    }
    out
}
