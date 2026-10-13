//! .NET CLR header, metadata root, streams and tables (ECMA-335 partition II).

use crate::headers::{DataDirectory, dir};
use crate::layout::Layout;
use crate::reader::Reader;

pub mod clr_flags {
    pub const IL_ONLY: u32 = 0x0000_0001;
    pub const REQUIRED_32BIT: u32 = 0x0000_0002;
    pub const IL_LIBRARY: u32 = 0x0000_0004;
    pub const STRONG_NAME_SIGNED: u32 = 0x0000_0008;
    pub const NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
    pub const TRACK_DEBUG_DATA: u32 = 0x0001_0000;
    pub const PREFERRED_32BIT: u32 = 0x0002_0000;

    pub const ALL: [(u32, &str); 7] = [
        (IL_ONLY, "IL-Only"),
        (REQUIRED_32BIT, "32-bit-required"),
        (IL_LIBRARY, "IL-Library"),
        (STRONG_NAME_SIGNED, "strong-name-signed"),
        (NATIVE_ENTRYPOINT, "native-entry-point"),
        (TRACK_DEBUG_DATA, "track-debug-data"),
        (PREFERRED_32BIT, "32-bit-preferred"),
    ];
}

pub const TABLE_NAMES: [&str; 45] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "Method",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "ENCLog",
    "ENCMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

#[derive(Debug, Clone, Default)]
pub struct ClrHeader {
    pub offset: u32,
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point: u32,
    pub resources: DataDirectory,
    pub strong_name_signature: DataDirectory,
    pub code_manager_table: DataDirectory,
    pub vtable_fixups: DataDirectory,
    pub export_address_table_jumps: DataDirectory,
    pub managed_native_header: DataDirectory,
}

#[derive(Debug, Clone, Default)]
pub struct Stream {
    pub name: String,
    /// Offset relative to the metadata root.
    pub offset: u32,
    pub size: u32,
    /// Absolute file offset (None when outside the file).
    pub file_offset: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeRef {
    pub namespace: String,
    pub name: String,
}

impl TypeRef {
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() { self.name.clone() } else { format!("{}.{}", self.namespace, self.name) }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemberRef {
    pub name: String,
    /// Full name of the parent type (when the parent is a TypeRef/TypeDef).
    pub parent: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImplMap {
    pub import_name: String,
    pub module: String,
    pub flags: u16,
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyInfo {
    pub name: String,
    pub culture: String,
    pub version: String,
    pub flags: u32,
    pub hash_alg_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ManifestResourceInfo {
    pub name: String,
    pub offset: u32,
    pub flags: u32,
    /// Implementation coded index raw value (0 = embedded in this module).
    pub implementation: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DotNet {
    pub header: ClrHeader,
    pub metadata_offset: Option<u32>,
    pub metadata_signature: u32,
    pub metadata_major: u16,
    pub metadata_minor: u16,
    pub runtime_version: String,
    pub metadata_flags: u16,
    pub streams: Vec<Stream>,
    pub tables_major: u8,
    pub tables_minor: u8,
    pub heap_sizes: u8,
    pub valid_mask: u64,
    pub sorted_mask: u64,
    /// Row counts per table id (0..64).
    pub rows: Vec<u32>,
    pub extra_data: Option<u32>,
    pub module_name: String,
    pub module_mvid: Option<[u8; 16]>,
    pub type_refs: Vec<TypeRef>,
    pub type_defs: Vec<TypeRef>,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
    pub member_refs: Vec<MemberRef>,
    pub module_refs: Vec<String>,
    pub impl_maps: Vec<ImplMap>,
    pub assembly: Option<AssemblyInfo>,
    pub assembly_refs: Vec<AssemblyInfo>,
    pub manifest_resources: Vec<ManifestResourceInfo>,
    /// Value of [assembly: Guid("...")] (typelib id).
    pub typelib_id: Option<String>,
    /// Names of every custom attribute type applied.
    pub custom_attributes: Vec<String>,
    pub strings_heap: Vec<String>,
    pub user_strings: Vec<String>,
}

impl DotNet {
    pub fn is_strong_name_signed(&self) -> bool {
        self.header.flags & clr_flags::STRONG_NAME_SIGNED != 0
    }

    pub fn stream(&self, name: &str) -> Option<&Stream> {
        self.streams.iter().find(|s| s.name == name)
    }

    pub fn row_count(&self, table: usize) -> u32 {
        self.rows.get(table).copied().unwrap_or(0)
    }

    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::CLR)?;
        let o = l.rva_to_offset(d.rva)?;
        let dd = |k: usize| DataDirectory { rva: r.u32(o + k).unwrap_or(0), size: r.u32(o + k + 4).unwrap_or(0) };
        let header = ClrHeader {
            offset: o as u32,
            cb: r.u32(o)?,
            major_runtime_version: r.u16(o + 4)?,
            minor_runtime_version: r.u16(o + 6)?,
            metadata: dd(8),
            flags: r.u32(o + 16)?,
            entry_point: r.u32(o + 20)?,
            resources: dd(24),
            strong_name_signature: dd(32),
            code_manager_table: dd(40),
            vtable_fixups: dd(48),
            export_address_table_jumps: dd(56),
            managed_native_header: dd(64),
        };
        let mut net = DotNet { header, ..Default::default() };
        if let Some(mo) = l.rva_to_offset(net.header.metadata.rva) {
            net.metadata_offset = Some(mo as u32);
            parse_metadata(r, mo, net.header.metadata.size as usize, &mut net);
        }
        Some(net)
    }
}

fn parse_metadata(r: &Reader, mo: usize, msize: usize, net: &mut DotNet) {
    net.metadata_signature = r.u32(mo).unwrap_or(0);
    if net.metadata_signature != 0x424A_5342 {
        return;
    }
    net.metadata_major = r.u16(mo + 4).unwrap_or(0);
    net.metadata_minor = r.u16(mo + 6).unwrap_or(0);
    let vlen = r.u32(mo + 12).unwrap_or(0) as usize;
    net.runtime_version = r.cstr(mo + 16, vlen.min(256)).unwrap_or_default();
    let p = mo + 16 + ((vlen + 3) & !3);
    net.metadata_flags = r.u16(p).unwrap_or(0);
    let nstreams = r.u16(p + 2).unwrap_or(0) as usize;
    let mut sp = p + 4;
    for _ in 0..nstreams.min(32) {
        let (Some(off), Some(size)) = (r.u32(sp), r.u32(sp + 4)) else { break };
        let name = r.cstr(sp + 8, 32).unwrap_or_default();
        sp += 8 + ((name.len() + 1 + 3) & !3);
        let fo = mo.checked_add(off as usize).filter(|&v| v < r.len()).map(|v| v as u32);
        net.streams.push(Stream { name, offset: off, size, file_offset: fo });
    }
    let _ = msize;
    let heap = |name: &str| -> &[u8] {
        net.streams
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.file_offset.map(|fo| r.bytes_clamped(fo as usize, s.size as usize)))
            .unwrap_or(&[])
    };
    let strings = heap("#Strings").to_vec();
    let blob = heap("#Blob").to_vec();
    let guid = heap("#GUID").to_vec();
    let us = heap("#US").to_vec();
    let tables = if !heap("#~").is_empty() { heap("#~").to_vec() } else { heap("#-").to_vec() };
    net.strings_heap = split_strings_heap(&strings);
    net.user_strings = split_user_strings(&us);
    if !tables.is_empty() {
        parse_tables(&tables, &strings, &blob, &guid, net);
    }
}

fn split_strings_heap(h: &[u8]) -> Vec<String> {
    h.split(|&b| b == 0).filter(|s| !s.is_empty()).take(200_000).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

/// Read an ECMA-335 compressed unsigned integer. Returns (value, bytes consumed).
pub fn compressed_u32(b: &[u8], o: usize) -> Option<(u32, usize)> {
    let b0 = *b.get(o)?;
    if b0 & 0x80 == 0 {
        Some((b0 as u32, 1))
    } else if b0 & 0xc0 == 0x80 {
        Some(((((b0 & 0x3f) as u32) << 8) | *b.get(o + 1)? as u32, 2))
    } else if b0 & 0xe0 == 0xc0 {
        Some(((((b0 & 0x1f) as u32) << 24) | ((*b.get(o + 1)? as u32) << 16) | ((*b.get(o + 2)? as u32) << 8) | *b.get(o + 3)? as u32, 4))
    } else {
        None
    }
}

fn split_user_strings(h: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut o = 1usize; // index 0 is the empty string
    while o < h.len() && out.len() < 200_000 {
        let Some((len, n)) = compressed_u32(h, o) else { break };
        o += n;
        let len = len as usize;
        if len == 0 {
            continue;
        }
        let body = &h[o.min(h.len())..(o + len).min(h.len())];
        let chars = &body[..body.len().saturating_sub(1) & !1];
        let units: Vec<u16> = chars.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = String::from_utf16_lossy(&units);
        if !s.is_empty() {
            out.push(s);
        }
        o += len;
    }
    out
}

#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Idx(usize),
    Coded(&'static [usize]),
}

const NA: usize = 64; // placeholder for unused tags in a coded index

const TYPE_DEF_OR_REF: &[usize] = &[2, 1, 27];
const HAS_CONSTANT: &[usize] = &[4, 8, 23];
const HAS_CUSTOM_ATTRIBUTE: &[usize] = &[6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43];
const HAS_FIELD_MARSHAL: &[usize] = &[4, 8];
const HAS_DECL_SECURITY: &[usize] = &[2, 6, 32];
const MEMBER_REF_PARENT: &[usize] = &[2, 1, 26, 6, 27];
const HAS_SEMANTICS: &[usize] = &[20, 23];
const METHOD_DEF_OR_REF: &[usize] = &[6, 10];
const MEMBER_FORWARDED: &[usize] = &[4, 6];
const IMPLEMENTATION: &[usize] = &[38, 35, 39];
const CUSTOM_ATTRIBUTE_TYPE: &[usize] = &[NA, NA, 6, 10, NA];
const RESOLUTION_SCOPE: &[usize] = &[0, 26, 35, 1];
const TYPE_OR_METHOD_DEF: &[usize] = &[2, 6];

fn schema(t: usize) -> &'static [Col] {
    use Col::*;
    match t {
        0 => &[U16, Str, Guid, Guid, Guid],
        1 => &[Coded(RESOLUTION_SCOPE), Str, Str],
        2 => &[U32, Str, Str, Coded(TYPE_DEF_OR_REF), Idx(4), Idx(6)],
        3 => &[Idx(4)],
        4 => &[U16, Str, Blob],
        5 => &[Idx(6)],
        6 => &[U32, U16, U16, Str, Blob, Idx(8)],
        7 => &[Idx(8)],
        8 => &[U16, U16, Str],
        9 => &[Idx(2), Coded(TYPE_DEF_OR_REF)],
        10 => &[Coded(MEMBER_REF_PARENT), Str, Blob],
        11 => &[U16, Coded(HAS_CONSTANT), Blob],
        12 => &[Coded(HAS_CUSTOM_ATTRIBUTE), Coded(CUSTOM_ATTRIBUTE_TYPE), Blob],
        13 => &[Coded(HAS_FIELD_MARSHAL), Blob],
        14 => &[U16, Coded(HAS_DECL_SECURITY), Blob],
        15 => &[U16, U32, Idx(2)],
        16 => &[U32, Idx(4)],
        17 => &[Blob],
        18 => &[Idx(2), Idx(20)],
        19 => &[Idx(20)],
        20 => &[U16, Str, Coded(TYPE_DEF_OR_REF)],
        21 => &[Idx(2), Idx(23)],
        22 => &[Idx(23)],
        23 => &[U16, Str, Blob],
        24 => &[U16, Idx(6), Coded(HAS_SEMANTICS)],
        25 => &[Idx(2), Coded(METHOD_DEF_OR_REF), Coded(METHOD_DEF_OR_REF)],
        26 => &[Str],
        27 => &[Blob],
        28 => &[U16, Coded(MEMBER_FORWARDED), Str, Idx(26)],
        29 => &[U32, Idx(4)],
        30 => &[U32, U32],
        31 => &[U32],
        32 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        33 => &[U32],
        34 => &[U32, U32, U32],
        35 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        36 => &[U32, Idx(35)],
        37 => &[U32, U32, U32, Idx(35)],
        38 => &[U32, Str, Blob],
        39 => &[U32, U32, Str, Str, Coded(IMPLEMENTATION)],
        40 => &[U32, U32, Str, Coded(IMPLEMENTATION)],
        41 => &[Idx(2), Idx(2)],
        42 => &[U16, U16, Coded(TYPE_OR_METHOD_DEF), Str],
        43 => &[Coded(METHOD_DEF_OR_REF), Blob],
        44 => &[Idx(42), Coded(TYPE_DEF_OR_REF)],
        _ => &[],
    }
}

struct Ctx<'a> {
    rows: &'a [u32],
    str4: bool,
    guid4: bool,
    blob4: bool,
}

impl Ctx<'_> {
    fn size(&self, c: Col) -> usize {
        match c {
            Col::U16 => 2,
            Col::U32 => 4,
            Col::Str => {
                if self.str4 {
                    4
                } else {
                    2
                }
            }
            Col::Guid => {
                if self.guid4 {
                    4
                } else {
                    2
                }
            }
            Col::Blob => {
                if self.blob4 {
                    4
                } else {
                    2
                }
            }
            Col::Idx(t) => {
                if self.rows.get(t).copied().unwrap_or(0) > 0xffff {
                    4
                } else {
                    2
                }
            }
            Col::Coded(tabs) => {
                let bits = usize::BITS - (tabs.len() - 1).leading_zeros();
                let max = tabs.iter().map(|&t| self.rows.get(t).copied().unwrap_or(0)).max().unwrap_or(0);
                if (max as u64) < (1u64 << (16 - bits)) { 2 } else { 4 }
            }
        }
    }

    fn row_size(&self, t: usize) -> usize {
        schema(t).iter().map(|&c| self.size(c)).sum()
    }
}

fn coded_decode(tabs: &[usize], v: u32) -> (usize, u32) {
    let bits = usize::BITS - (tabs.len() - 1).leading_zeros();
    let tag = (v & ((1 << bits) - 1)) as usize;
    (tabs.get(tag).copied().unwrap_or(NA), v >> bits)
}

fn heap_str(h: &[u8], idx: u32) -> String {
    let s = h.get(idx as usize..).unwrap_or(&[]);
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len()).min(1024);
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn heap_blob(h: &[u8], idx: u32) -> Vec<u8> {
    match compressed_u32(h, idx as usize) {
        Some((len, n)) => {
            let s = idx as usize + n;
            h.get(s..(s + len as usize).min(h.len())).unwrap_or(&[]).to_vec()
        }
        None => Vec::new(),
    }
}

fn parse_tables(t: &[u8], strings: &[u8], blob: &[u8], guid: &[u8], net: &mut DotNet) {
    let r = Reader::new(t);
    net.tables_major = r.u8(4).unwrap_or(0);
    net.tables_minor = r.u8(5).unwrap_or(0);
    net.heap_sizes = r.u8(6).unwrap_or(0);
    net.valid_mask = r.u64(8).unwrap_or(0);
    net.sorted_mask = r.u64(16).unwrap_or(0);
    let mut rows = vec![0u32; 64];
    let mut p = 24usize;
    for (i, row) in rows.iter_mut().enumerate() {
        if net.valid_mask & (1u64 << i) != 0 {
            *row = r.u32(p).unwrap_or(0);
            p += 4;
        }
    }
    if net.heap_sizes & 0x40 != 0 {
        net.extra_data = r.u32(p);
        p += 4;
    }
    net.rows = rows.clone();
    let ctx = Ctx { rows: &rows, str4: net.heap_sizes & 1 != 0, guid4: net.heap_sizes & 2 != 0, blob4: net.heap_sizes & 4 != 0 };
    // Unknown tables (45..63) have no schema; stop decoding content past them.
    let mut table_off = [0usize; 64];
    for (i, off) in table_off.iter_mut().enumerate() {
        *off = p;
        if rows[i] > 0 {
            if i >= 45 {
                return;
            }
            p = p.saturating_add(ctx.row_size(i).saturating_mul(rows[i] as usize));
        }
    }
    let read_row = |tid: usize, row: usize| -> Option<Vec<u32>> {
        let rs = ctx.row_size(tid);
        let mut o = table_off[tid].checked_add(rs.checked_mul(row)?)?;
        let mut out = Vec::new();
        for &c in schema(tid) {
            let v = match ctx.size(c) {
                2 => r.u16(o)? as u32,
                _ => r.u32(o)?,
            };
            out.push(v);
            o += ctx.size(c);
        }
        Some(out)
    };
    let cap = |n: u32| (n as usize).min(200_000);

    // Module
    if rows[0] > 0
        && let Some(m) = read_row(0, 0)
    {
        net.module_name = heap_str(strings, m[1]);
        let gi = m[2] as usize;
        if gi > 0
            && let Some(g) = guid.get((gi - 1) * 16..gi * 16)
        {
            let mut a = [0u8; 16];
            a.copy_from_slice(g);
            net.module_mvid = Some(a);
        }
    }
    for i in 0..cap(rows[1]) {
        let Some(v) = read_row(1, i) else { break };
        net.type_refs.push(TypeRef { name: heap_str(strings, v[1]), namespace: heap_str(strings, v[2]) });
    }
    for i in 0..cap(rows[2]) {
        let Some(v) = read_row(2, i) else { break };
        net.type_defs.push(TypeRef { name: heap_str(strings, v[1]), namespace: heap_str(strings, v[2]) });
    }
    for i in 0..cap(rows[4]) {
        let Some(v) = read_row(4, i) else { break };
        net.fields.push(heap_str(strings, v[1]));
    }
    for i in 0..cap(rows[6]) {
        let Some(v) = read_row(6, i) else { break };
        net.methods.push(heap_str(strings, v[3]));
    }
    let type_name = |tab: usize, idx: u32, net: &DotNet| -> String {
        let i = idx as usize;
        if i == 0 {
            return String::new();
        }
        match tab {
            1 => net.type_refs.get(i - 1).map(|t| t.full_name()).unwrap_or_default(),
            2 => net.type_defs.get(i - 1).map(|t| t.full_name()).unwrap_or_default(),
            26 => net.module_refs.get(i - 1).cloned().unwrap_or_default(),
            _ => String::new(),
        }
    };
    for i in 0..cap(rows[26]) {
        let Some(v) = read_row(26, i) else { break };
        net.module_refs.push(heap_str(strings, v[0]));
    }
    for i in 0..cap(rows[10]) {
        let Some(v) = read_row(10, i) else { break };
        let (tab, idx) = coded_decode(MEMBER_REF_PARENT, v[0]);
        let parent = type_name(tab, idx, net);
        net.member_refs.push(MemberRef { name: heap_str(strings, v[1]), parent });
    }
    for i in 0..cap(rows[28]) {
        let Some(v) = read_row(28, i) else { break };
        let module = net.module_refs.get((v[3] as usize).wrapping_sub(1)).cloned().unwrap_or_default();
        net.impl_maps.push(ImplMap { flags: v[0] as u16, import_name: heap_str(strings, v[2]), module });
    }
    if rows[32] > 0
        && let Some(v) = read_row(32, 0)
    {
        net.assembly = Some(AssemblyInfo {
            hash_alg_id: v[0],
            version: format!("{}.{}.{}.{}", v[1], v[2], v[3], v[4]),
            flags: v[5],
            public_key: heap_blob(blob, v[6]),
            name: heap_str(strings, v[7]),
            culture: heap_str(strings, v[8]),
        });
    }
    for i in 0..cap(rows[35]) {
        let Some(v) = read_row(35, i) else { break };
        net.assembly_refs.push(AssemblyInfo {
            version: format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]),
            flags: v[4],
            public_key: heap_blob(blob, v[5]),
            name: heap_str(strings, v[6]),
            culture: heap_str(strings, v[7]),
            hash_alg_id: 0,
        });
    }
    for i in 0..cap(rows[40]) {
        let Some(v) = read_row(40, i) else { break };
        net.manifest_resources.push(ManifestResourceInfo {
            offset: v[0],
            flags: v[1],
            name: heap_str(strings, v[2]),
            implementation: v[3],
        });
    }
    // Custom attributes: resolve the attribute type name; capture GuidAttribute's value.
    for i in 0..cap(rows[12]) {
        let Some(v) = read_row(12, i) else { break };
        let (tab, idx) = coded_decode(CUSTOM_ATTRIBUTE_TYPE, v[1]);
        let attr_type = match tab {
            10 => net.member_refs.get((idx as usize).wrapping_sub(1)).map(|m| m.parent.clone()).unwrap_or_default(),
            6 => {
                // Constructor defined in this module: find owning type by method list position (best effort).
                String::new()
            }
            _ => String::new(),
        };
        if attr_type.is_empty() {
            continue;
        }
        if attr_type.ends_with("GuidAttribute") && net.typelib_id.is_none() {
            let val = heap_blob(blob, v[2]);
            if val.len() > 3
                && val[0] == 1
                && val[1] == 0
                && let Some((len, n)) = compressed_u32(&val, 2)
            {
                let s = 2 + n;
                if let Some(b) = val.get(s..s + len as usize) {
                    net.typelib_id = Some(String::from_utf8_lossy(b).into_owned());
                }
            }
        }
        if !net.custom_attributes.contains(&attr_type) {
            net.custom_attributes.push(attr_type);
        }
    }
}
