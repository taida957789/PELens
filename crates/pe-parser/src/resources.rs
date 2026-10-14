//! Resource directory tree (type / name / language).

use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;
use std::collections::HashSet;

const MAX_ENTRIES: usize = 100_000;

pub const RT_NAMES: [(u16, &str); 24] = [
    (1, "cursor"),
    (2, "bitmap"),
    (3, "icon"),
    (4, "menu"),
    (5, "dialog"),
    (6, "string-table"),
    (7, "font-directory"),
    (8, "font"),
    (9, "accelerator"),
    (10, "rcdata"),
    (11, "message-table"),
    (12, "cursor-group"),
    (14, "icon-group"),
    (16, "version"),
    (17, "dlgInclude"),
    (19, "Plug-and-play"),
    (20, "Vxd"),
    (21, "Animated-cursor"),
    (22, "Animated-icon"),
    (23, "HTML"),
    (24, "manifest"),
    (240, "dialog-data"),
    (241, "toolbar"),
    (0x2002, "MUI"),
];

pub fn resource_type_name(id: u16) -> Option<&'static str> {
    RT_NAMES.iter().find(|(i, _)| *i == id).map(|(_, n)| *n)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResId {
    Id(u32),
    Name(String),
}

impl Default for ResId {
    fn default() -> Self {
        ResId::Id(0)
    }
}

impl std::fmt::Display for ResId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResId::Id(i) => write!(f, "{i}"),
            ResId::Name(s) => write!(f, "{s}"),
        }
    }
}

impl ResId {
    pub fn id(&self) -> Option<u32> {
        match self {
            ResId::Id(i) => Some(*i),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResourceEntry {
    pub type_id: ResId,
    pub name: ResId,
    pub language: u32,
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
    /// File offset of the data (None if the RVA is not backed by the file).
    pub file_offset: Option<u32>,
    /// File offset of the IMAGE_RESOURCE_DATA_ENTRY.
    pub entry_offset: u32,
}

impl ResourceEntry {
    pub fn type_name(&self) -> String {
        match &self.type_id {
            ResId::Id(i) => resource_type_name(*i as u16).map(str::to_string).unwrap_or_else(|| i.to_string()),
            ResId::Name(s) => s.clone(),
        }
    }

    pub fn is_builtin_type(&self) -> bool {
        matches!(self.type_id, ResId::Id(i) if resource_type_name(i as u16).is_some())
    }

    pub fn data<'a>(&self, r: &Reader<'a>) -> &'a [u8] {
        match self.file_offset {
            Some(o) => r.bytes_clamped(o as usize, self.size as usize),
            None => &[],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Resources {
    pub offset: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub entries: Vec<ResourceEntry>,
    /// Detected self-references / loops in the directory tree.
    pub loops: usize,
}

impl Resources {
    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::RESOURCE)?;
        let base = l.rva_to_offset(d.rva)?;
        let mut res = Resources {
            offset: base as u32,
            time_date_stamp: r.u32(base + 4)?,
            major_version: r.u16(base + 8)?,
            minor_version: r.u16(base + 10)?,
            ..Default::default()
        };
        let mut seen = Seen::default();
        let mut path: Vec<ResId> = Vec::new();
        walk(r, l, base, 0, 0, &mut path, &mut seen, &mut res);
        Some(res)
    }

    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size as u64).sum()
    }

    pub fn of_type(&self, id: u32) -> impl Iterator<Item = &ResourceEntry> {
        self.entries.iter().filter(move |e| e.type_id == ResId::Id(id))
    }

    pub fn languages(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.entries.iter().map(|e| e.language).collect();
        v.sort();
        v.dedup();
        v
    }
}

fn read_name(r: &Reader, base: usize, raw: u32) -> ResId {
    if raw & 0x8000_0000 != 0 {
        let o = base + (raw & 0x7fff_ffff) as usize;
        let len = r.u16(o).unwrap_or(0) as usize;
        ResId::Name(r.wstr_n(o + 2, len.min(1024)).unwrap_or_default())
    } else {
        ResId::Id(raw)
    }
}

/// Directories and directory-entry slots already walked. Directories may overlap (a directory
/// starting 8 bytes into another shares its entries), so entry slots are tracked as well: entries
/// never overlap, hence at most one entry per 8 bytes of the file, whatever the tree looks like.
#[derive(Default)]
struct Seen {
    dirs: HashSet<usize>,
    slots: HashSet<usize>,
}

#[allow(clippy::too_many_arguments)]
fn walk(r: &Reader, l: &Layout, base: usize, rel: usize, depth: usize, path: &mut Vec<ResId>, seen: &mut Seen, res: &mut Resources) {
    if depth > 8 || res.entries.len() >= MAX_ENTRIES {
        return;
    }
    if !seen.dirs.insert(rel) {
        res.loops += 1;
        return;
    }
    let o = base + rel;
    let (Some(named), Some(ids)) = (r.u16(o + 12), r.u16(o + 14)) else { return };
    let n = named as usize + ids as usize;
    for i in 0..n {
        let eo = o + 16 + i * 8;
        let (Some(name), Some(off)) = (r.u32(eo), r.u32(eo + 4)) else { break };
        // a slot overlapping one already read (directories can start at any byte)
        if (eo.saturating_sub(7)..eo + 8).any(|x| seen.slots.contains(&x)) {
            res.loops += 1;
            continue;
        }
        seen.slots.insert(eo);
        let id = read_name(r, base, name);
        path.push(id);
        if off & 0x8000_0000 != 0 {
            walk(r, l, base, (off & 0x7fff_ffff) as usize, depth + 1, path, seen, res);
        } else {
            let de = base + off as usize;
            if let (Some(rva), Some(size), Some(cp)) = (r.u32(de), r.u32(de + 4), r.u32(de + 8)) {
                let lang = match path.get(2) {
                    Some(ResId::Id(x)) => *x,
                    _ => 0,
                };
                res.entries.push(ResourceEntry {
                    type_id: path.first().cloned().unwrap_or_default(),
                    name: path.get(1).cloned().unwrap_or_default(),
                    language: lang,
                    data_rva: rva,
                    size,
                    code_page: cp,
                    file_offset: l.rva_to_offset(rva).map(|v| v as u32),
                    entry_offset: de as u32,
                });
            }
        }
        path.pop();
        if res.entries.len() >= MAX_ENTRIES {
            break;
        }
    }
}
