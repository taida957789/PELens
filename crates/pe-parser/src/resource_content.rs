//! Decoders for the content of well-known resource types.

use crate::reader::Reader;

// ---------------------------------------------------------------- version

#[derive(Debug, Clone, Default)]
pub struct FixedFileInfo {
    pub signature: u32,
    pub struc_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

fn ver4(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

impl FixedFileInfo {
    pub fn file_version(&self) -> String {
        ver4(self.file_version_ms, self.file_version_ls)
    }

    pub fn product_version(&self) -> String {
        ver4(self.product_version_ms, self.product_version_ls)
    }

    pub fn os_name(&self) -> &'static str {
        match self.file_os {
            0x0001_0000 => "MS-DOS",
            0x0004_0000 => "Windows NT",
            0x0000_0001 => "Windows 16-bit",
            0x0000_0004 => "Windows 32-bit",
            0x0004_0004 => "Windows NT | Windows 32-bit",
            0x0001_0001 => "MS-DOS | Windows 16-bit",
            0x0001_0004 => "MS-DOS | Windows 32-bit",
            0x0002_0000 => "OS/2 16-bit",
            0x0003_0000 => "OS/2 32-bit",
            0x0000_0002 => "PM-16-bit",
            0x0000_0003 => "PM-32-bit",
            _ => "Unknown",
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self.file_type {
            1 => "executable",
            2 => "dynamic-link library",
            3 => "device-driver",
            4 => "font",
            5 => "virtual-device",
            7 => "static-link library",
            _ => "unknown",
        }
    }

    pub fn subtype_name(&self) -> &'static str {
        if self.file_type == 3 {
            match self.file_subtype {
                1 => "Printer-driver",
                2 => "Keyboard-driver",
                3 => "Language-driver",
                4 => "Display-driver",
                5 => "Mouse driver",
                6 => "Network-driver",
                7 => "System-driver",
                8 => "Installable-driver",
                9 => "Sound-driver",
                10 => "Communication-driver",
                12 => "Printer-driver",
                _ => "Unknown-Driver",
            }
        } else if self.file_type == 4 {
            match self.file_subtype {
                1 => "raster-font",
                2 => "vector-font",
                3 => "truetype-font",
                _ => "unknown-font",
            }
        } else {
            "n/a"
        }
    }

    pub fn flag_names(&self) -> Vec<&'static str> {
        let f = self.file_flags & self.file_flags_mask;
        let t = [(1, "debug"), (2, "prerelease"), (4, "patched"), (8, "privatebuild"), (0x10, "infoinferred"), (0x20, "specialbuild")];
        t.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub fixed: Option<FixedFileInfo>,
    /// (language/codepage key, name, value)
    pub strings: Vec<(String, String, String)>,
    /// Translation pairs (language, code page)
    pub translations: Vec<(u16, u16)>,
}

impl VersionInfo {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings.iter().find(|(_, k, _)| k.eq_ignore_ascii_case(key)).map(|(_, _, v)| v.as_str())
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        let r = Reader::new(data);
        let node = parse_node(&r, 0, data.len(), 0)?;
        if node.key != "VS_VERSION_INFO" {
            return None;
        }
        let mut vi = VersionInfo::default();
        if node.value_len >= 52 {
            let o = node.value_off;
            if r.u32(o) == Some(0xFEEF_04BD) {
                let g = |k: usize| r.u32(o + k).unwrap_or(0);
                vi.fixed = Some(FixedFileInfo {
                    signature: g(0),
                    struc_version: g(4),
                    file_version_ms: g(8),
                    file_version_ls: g(12),
                    product_version_ms: g(16),
                    product_version_ls: g(20),
                    file_flags_mask: g(24),
                    file_flags: g(28),
                    file_os: g(32),
                    file_type: g(36),
                    file_subtype: g(40),
                    file_date_ms: g(44),
                    file_date_ls: g(48),
                });
            }
        }
        for child in &node.children {
            if child.key == "StringFileInfo" {
                for table in &child.children {
                    for s in &table.children {
                        let value = if s.value_type == 1 && s.value_len > 0 {
                            r.wstr(s.value_off, s.value_len.min(8192)).unwrap_or_default()
                        } else {
                            String::new()
                        };
                        vi.strings.push((table.key.clone(), s.key.clone(), value.trim_end_matches('\0').to_string()));
                    }
                }
            } else if child.key == "VarFileInfo" {
                for var in &child.children {
                    if var.key == "Translation" {
                        let mut o = var.value_off;
                        let end = var.value_off + var.value_len;
                        while o + 4 <= end {
                            if let (Some(lang), Some(cp)) = (r.u16(o), r.u16(o + 2)) {
                                vi.translations.push((lang, cp));
                            }
                            o += 4;
                        }
                    }
                }
            }
        }
        Some(vi)
    }
}

#[derive(Debug, Default)]
struct VNode {
    key: String,
    value_type: u16,
    value_off: usize,
    /// bytes for binary values, characters for text values
    value_len: usize,
    children: Vec<VNode>,
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

fn parse_node(r: &Reader, off: usize, limit: usize, depth: usize) -> Option<VNode> {
    if depth > 6 {
        return None;
    }
    let len = r.u16(off)? as usize;
    let vlen = r.u16(off + 2)? as usize;
    let vtype = r.u16(off + 4)?;
    if len < 6 {
        return None;
    }
    let end = (off + len).min(limit);
    let key = r.wstr(off + 6, 64)?;
    let key_end = off + 6 + (key.encode_utf16().count() + 1) * 2;
    let value_off = align4(key_end);
    let value_bytes = if vtype == 1 { vlen * 2 } else { vlen };
    let mut node = VNode { key, value_type: vtype, value_off, value_len: vlen, children: Vec::new() };
    let mut c = align4(value_off + value_bytes);
    while c + 6 < end {
        match parse_node(r, c, end, depth + 1) {
            Some(child) => {
                let clen = r.u16(c).unwrap_or(0) as usize;
                node.children.push(child);
                if clen == 0 {
                    break;
                }
                c = align4(c + clen);
            }
            None => break,
        }
    }
    Some(node)
}

// ---------------------------------------------------------------- string table

/// Decode an RT_STRING block. Returns (string id, text) pairs.
pub fn parse_string_table(data: &[u8], block_id: u32) -> Vec<(u32, String)> {
    let r = Reader::new(data);
    let mut out = Vec::new();
    let mut o = 0usize;
    for i in 0..16u32 {
        let Some(len) = r.u16(o) else { break };
        o += 2;
        if len > 0 {
            let s = r.wstr_n(o, len as usize).unwrap_or_default();
            out.push((block_id.saturating_sub(1) * 16 + i, s));
            o += len as usize * 2;
        }
    }
    out
}

// ---------------------------------------------------------------- message table

pub fn parse_message_table(data: &[u8]) -> Vec<(u32, String)> {
    let r = Reader::new(data);
    let mut out = Vec::new();
    let Some(nblocks) = r.u32(0) else { return out };
    for b in 0..(nblocks as usize).min(4096) {
        let bo = 4 + b * 12;
        let (Some(low), Some(high), Some(mut eo)) = (r.u32(bo), r.u32(bo + 4), r.u32(bo + 8).map(|v| v as usize)) else {
            break;
        };
        if high < low {
            continue;
        }
        for id in low..=high.min(low.saturating_add(65535)) {
            let (Some(len), Some(flags)) = (r.u16(eo), r.u16(eo + 2)) else { break };
            if len < 4 {
                break;
            }
            let body = r.bytes_clamped(eo + 4, len as usize - 4);
            let text = if flags & 1 != 0 {
                let units: Vec<u16> = body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&units)
            } else {
                String::from_utf8_lossy(body).into_owned()
            };
            out.push((id, text.trim_end_matches(['\0', '\r', '\n']).to_string()));
            eo += len as usize;
        }
    }
    out
}

// ---------------------------------------------------------------- menu

/// Extract the item texts of a menu template (standard or extended).
pub fn parse_menu(data: &[u8]) -> Vec<String> {
    let r = Reader::new(data);
    let mut out = Vec::new();
    let Some(version) = r.u16(0) else { return out };
    let Some(hdr) = r.u16(2) else { return out };
    if version == 1 {
        let mut o = 4 + hdr as usize;
        while o + 14 <= data.len() && out.len() < 10_000 {
            let flags = r.u16(o + 12).unwrap_or(0);
            let text = r.wstr(o + 14, 1024).unwrap_or_default();
            o = align4(o + 14 + (text.encode_utf16().count() + 1) * 2);
            if flags & 1 != 0 {
                o += 4;
            }
            if !text.is_empty() {
                out.push(text);
            }
        }
    } else {
        let mut o = 4 + hdr as usize;
        while o + 2 <= data.len() && out.len() < 10_000 {
            let flags = r.u16(o).unwrap_or(0);
            o += 2;
            if flags & 0x10 == 0 {
                o += 2;
            }
            let text = r.wstr(o, 1024).unwrap_or_default();
            o += (text.encode_utf16().count() + 1) * 2;
            if !text.is_empty() {
                out.push(text);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- dialog

#[derive(Debug, Clone, Default)]
pub struct Dialog {
    pub extended: bool,
    pub caption: String,
    pub font: String,
    pub controls: Vec<String>,
}

fn sz_or_ord(r: &Reader, o: usize) -> (String, usize) {
    match r.u16(o) {
        Some(0) => (String::new(), o + 2),
        Some(0xffff) => (format!("#{}", r.u16(o + 2).unwrap_or(0)), o + 4),
        Some(_) => {
            let s = r.wstr(o, 1024).unwrap_or_default();
            let n = (s.encode_utf16().count() + 1) * 2;
            (s, o + n)
        }
        None => (String::new(), o),
    }
}

pub fn parse_dialog(data: &[u8]) -> Option<Dialog> {
    let r = Reader::new(data);
    let extended = r.u16(0)? == 1 && r.u16(2)? == 0xffff;
    let mut d = Dialog { extended, ..Default::default() };
    let (style, count, mut o) = if extended { (r.u32(12)?, r.u16(16)?, 26usize) } else { (r.u32(0)?, r.u16(8)?, 18usize) };
    let (_menu, o2) = sz_or_ord(&r, o);
    let (_class, o3) = sz_or_ord(&r, o2);
    let (caption, mut o4) = sz_or_ord(&r, o3);
    d.caption = caption;
    if style & 0x40 != 0 {
        // DS_SETFONT
        o4 += if extended { 6 } else { 2 };
        let f = r.wstr(o4, 256).unwrap_or_default();
        o4 += (f.encode_utf16().count() + 1) * 2;
        d.font = f;
    }
    o = o4;
    for _ in 0..count.min(4096) {
        o = align4(o);
        o += if extended { 24 } else { 18 };
        if o >= data.len() {
            break;
        }
        let (_cls, a) = sz_or_ord(&r, o);
        let (title, b) = sz_or_ord(&r, a);
        let extra = r.u16(b).unwrap_or(0) as usize;
        o = b + 2 + extra;
        if !title.is_empty() {
            d.controls.push(title);
        }
    }
    Some(d)
}

// ---------------------------------------------------------------- icon / cursor groups

#[derive(Debug, Clone, Default)]
pub struct GroupIconEntry {
    pub width: u16,
    pub height: u16,
    pub color_count: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes_in_res: u32,
    pub id: u16,
}

pub fn parse_group_icon(data: &[u8], cursor: bool) -> Vec<GroupIconEntry> {
    let r = Reader::new(data);
    let mut out = Vec::new();
    let n = r.u16(4).unwrap_or(0) as usize;
    for i in 0..n.min(1024) {
        let o = 6 + i * 14;
        let Some(b) = r.bytes(o, 14) else { break };
        let (w, h) = if cursor {
            (u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]]) / 2)
        } else {
            (if b[0] == 0 { 256 } else { b[0] as u16 }, if b[1] == 0 { 256 } else { b[1] as u16 })
        };
        out.push(GroupIconEntry {
            width: w,
            height: h,
            color_count: if cursor { 0 } else { b[2] },
            planes: u16::from_le_bytes([b[4], b[5]]),
            bit_count: u16::from_le_bytes([b[6], b[7]]),
            bytes_in_res: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            id: u16::from_le_bytes([b[12], b[13]]),
        });
    }
    out
}

// ---------------------------------------------------------------- manifest

#[derive(Debug, Clone, Default)]
pub struct AssemblyIdentity {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub processor_architecture: String,
    pub public_key_token: String,
    pub language: String,
}

#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub raw: String,
    pub identity: Option<AssemblyIdentity>,
    pub execution_level: Option<String>,
    pub ui_access: Option<bool>,
    pub auto_elevate: Option<bool>,
    pub description: Option<String>,
    pub dependencies: Vec<AssemblyIdentity>,
    pub has_trust_info: bool,
    /// Basic well-formedness problems (unbalanced tags, missing root).
    pub malformed: bool,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{}=", name.to_ascii_lowercase());
    let mut start = 0;
    while let Some(p) = lower[start..].find(&needle) {
        let at = start + p;
        let prev_ok = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric();
        let v = at + needle.len();
        if prev_ok {
            let q = tag.as_bytes().get(v).copied()?;
            if q == b'"' || q == b'\'' {
                let rest = &tag[v + 1..];
                let end = rest.find(q as char)?;
                return Some(rest[..end].to_string());
            }
        }
        start = v;
    }
    None
}

fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let lower = xml.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut start = 0;
    let needle = name.to_ascii_lowercase();
    while let Some(p) = lower[start..].find('<') {
        let at = start + p + 1;
        let rest = &lower[at..];
        let rest = rest.split_once(':').filter(|(pre, _)| !pre.contains(['>', ' ', '/'])).map(|(_, r)| r).unwrap_or(rest);
        let skip = lower[at..].len() - rest.len();
        if rest.starts_with(&needle) && rest[needle.len()..].starts_with([' ', '>', '/', '\t', '\r', '\n']) {
            let end = lower[at..].find('>').map(|e| at + e).unwrap_or(lower.len());
            out.push(&xml[at + skip..end]);
        }
        start = at;
    }
    out
}

fn element_text(xml: &str, name: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let open = lower.find(&format!("<{}", name.to_ascii_lowercase()))?;
    let gt = lower[open..].find('>')? + open + 1;
    let close = lower[gt..].find("</")? + gt;
    Some(xml[gt..close].trim().to_string())
}

fn identity(tag: &str) -> AssemblyIdentity {
    AssemblyIdentity {
        kind: attr(tag, "type").unwrap_or_default(),
        name: attr(tag, "name").unwrap_or_default(),
        version: attr(tag, "version").unwrap_or_default(),
        processor_architecture: attr(tag, "processorArchitecture").unwrap_or_default(),
        public_key_token: attr(tag, "publicKeyToken").unwrap_or_default(),
        language: attr(tag, "language").unwrap_or_default(),
    }
}

impl Manifest {
    pub fn parse(data: &[u8]) -> Self {
        let raw = decode_text(data);
        let mut m = Manifest { raw: raw.clone(), ..Default::default() };
        let lower = raw.to_ascii_lowercase();
        m.malformed = !lower.contains("<assembly") || !lower.contains("</assembly");
        let ids = tags(&raw, "assemblyIdentity");
        // The first identity outside <dependentAssembly> is the application's own.
        let dep_start = lower.find("<dependentassembly").unwrap_or(usize::MAX);
        for t in &ids {
            let pos = t.as_ptr() as usize - raw.as_ptr() as usize;
            if pos < dep_start && m.identity.is_none() {
                m.identity = Some(identity(t));
            } else if pos > dep_start {
                m.dependencies.push(identity(t));
            }
        }
        if let Some(t) = tags(&raw, "requestedExecutionLevel").first() {
            m.execution_level = attr(t, "level");
            m.ui_access = attr(t, "uiAccess").map(|v| v.eq_ignore_ascii_case("true"));
        }
        m.auto_elevate = element_text(&raw, "autoElevate").map(|v| v.eq_ignore_ascii_case("true"));
        m.description = element_text(&raw, "description").filter(|s| !s.is_empty());
        m.has_trust_info = lower.contains("trustinfo");
        m
    }
}

/// Decode resource text: UTF-8 (with/without BOM) or UTF-16LE (BOM or heuristic).
pub fn decode_text(data: &[u8]) -> String {
    if data.starts_with(&[0xff, 0xfe]) || (data.len() >= 4 && data[1] == 0 && data[3] == 0 && data[0] != 0) {
        let body = if data.starts_with(&[0xff, 0xfe]) { &data[2..] } else { data };
        let units: Vec<u16> = body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units).trim_end_matches('\0').to_string();
    }
    let body = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    String::from_utf8_lossy(body).trim_end_matches('\0').to_string()
}
