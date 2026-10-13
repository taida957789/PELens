//! Tolerant, panic-free parser for Portable Executable images.
//!
//! `PeFile::parse` never fails on malformed input: every directory that cannot be
//! decoded is simply absent, and anomalies are recorded for the analysis layer.

pub mod certificate;
pub mod debug;
pub mod der;
pub mod dotnet;
pub mod exports;
pub mod headers;
pub mod imports;
pub mod layout;
pub mod misc_dirs;
pub mod patch;
pub mod reader;
pub mod resource_content;
pub mod resources;
#[doc(hidden)]
pub mod testutil;

use headers::*;
use layout::Layout;
use reader::Reader;

#[derive(Debug, Clone, Default)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct EntryPoint {
    pub rva: u32,
    pub file_offset: Option<u64>,
    pub section: Option<String>,
    pub section_index: Option<usize>,
    /// Entry point is zero (DLL without entry point, or resource-only image).
    pub zero: bool,
    /// Entry point lies inside the headers (MZ instructions executed).
    pub in_header: bool,
    /// Entry point lies outside every section / outside the image.
    pub outside_image: bool,
    /// Section holding the entry point is not executable.
    pub in_non_executable_section: bool,
    /// Entry point not located in the first executable section.
    pub not_in_first_section: bool,
    /// Section holding the entry point is the last section.
    pub in_last_section: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PeFile {
    pub file_size: u64,
    pub dos_header: Option<DosHeader>,
    pub dos_stub: Option<DosStub>,
    pub rich: Option<RichHeader>,
    /// Present when the "PE\0\0" signature was found.
    pub layout: Option<Layout>,
    pub pe_signature_valid: bool,
    pub imports: imports::Imports,
    pub exports: Option<exports::Exports>,
    pub resources: Option<resources::Resources>,
    pub debug: Vec<debug::DebugEntry>,
    pub tls: Option<misc_dirs::Tls>,
    pub relocations: Vec<misc_dirs::RelocationBlock>,
    pub exceptions: Vec<misc_dirs::RuntimeFunction>,
    pub load_config: Option<misc_dirs::LoadConfig>,
    pub security: Option<certificate::SecurityDirectory>,
    pub dotnet: Option<dotnet::DotNet>,
    pub overlay: Option<Overlay>,
    pub entry_point: Option<EntryPoint>,
    /// Section headers that extend past the end of the file.
    pub truncated_sections: Vec<usize>,
}

impl PeFile {
    pub fn is_pe(&self) -> bool {
        self.layout.is_some()
    }

    pub fn is_64(&self) -> bool {
        self.layout.as_ref().is_some_and(|l| l.is_64())
    }

    pub fn is_dll(&self) -> bool {
        self.layout.as_ref().is_some_and(|l| l.file_header.is_dll())
    }

    pub fn is_dotnet(&self) -> bool {
        self.dotnet.is_some()
    }

    pub fn is_driver(&self) -> bool {
        self.layout.as_ref().is_some_and(|l| {
            l.optional_header.subsystem == 1 || l.optional_header.dll_characteristics & dll_characteristics::WDM_DRIVER != 0
        })
    }

    pub fn sections(&self) -> &[Section] {
        self.layout.as_ref().map(|l| l.sections.as_slice()).unwrap_or(&[])
    }

    /// Parse an image. Never panics; non-PE input yields a `PeFile` with `layout == None`.
    pub fn parse(data: &[u8]) -> PeFile {
        let r = Reader::new(data);
        let mut pe = PeFile { file_size: data.len() as u64, ..Default::default() };
        let Some(dos) = DosHeader::parse(&r) else { return pe };
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return pe;
        }
        let lfanew = dos.e_lfanew;
        let stub_end = (lfanew as u64).min(data.len() as u64) as u32;
        pe.rich = RichHeader::parse(&r, stub_end);
        let stub_limit = pe.rich.as_ref().map(|x| x.offset).unwrap_or(stub_end).max(DosHeader::SIZE as u32);
        pe.dos_stub = Some(DosStub::parse(&r, stub_limit.min(stub_end.max(DosHeader::SIZE as u32))));
        pe.dos_header = Some(dos);
        let nt = lfanew as usize;
        if r.u32(nt) != Some(IMAGE_NT_SIGNATURE) {
            return pe;
        }
        pe.pe_signature_valid = true;
        let Some(fh) = FileHeader::parse(&r, nt + 4) else { return pe };
        let opt_off = nt + 4 + FileHeader::SIZE;
        let Some(oh) = OptionalHeader::parse(&r, opt_off, fh.size_of_optional_header) else { return pe };
        let sec_off = opt_off + fh.size_of_optional_header as usize;
        let mut sections = Vec::new();
        for i in 0..(fh.number_of_sections as usize).min(96) {
            match Section::parse(&r, sec_off + i * Section::SIZE, i) {
                Some(s) => sections.push(s),
                None => break,
            }
        }
        let mut layout = Layout { file_size: data.len() as u64, file_header: fh, optional_header: oh, sections };
        resolve_long_section_names(&r, &mut layout);
        for s in &layout.sections {
            if s.size_of_raw_data > 0 && layout.raw_pointer(s) + s.size_of_raw_data as u64 > data.len() as u64 {
                pe.truncated_sections.push(s.index);
            }
        }

        pe.imports = imports::Imports::parse(&r, &layout);
        pe.exports = exports::Exports::parse(&r, &layout);
        pe.resources = resources::Resources::parse(&r, &layout);
        pe.debug = debug::parse(&r, &layout);
        pe.tls = misc_dirs::Tls::parse(&r, &layout);
        pe.relocations = misc_dirs::parse_relocations(&r, &layout);
        pe.exceptions = misc_dirs::parse_exceptions(&r, &layout);
        pe.load_config = misc_dirs::LoadConfig::parse(&r, &layout);
        pe.security = certificate::SecurityDirectory::parse(&r, &layout);
        pe.dotnet = dotnet::DotNet::parse(&r, &layout);
        pe.overlay = compute_overlay(data, &layout, pe.security.as_ref());
        pe.entry_point = Some(entry_point(&layout));
        pe.layout = Some(layout);
        pe
    }

    /// Resource payload helper.
    pub fn resource_data<'a>(&self, data: &'a [u8], e: &resources::ResourceEntry) -> &'a [u8] {
        e.data(&Reader::new(data))
    }

    pub fn version_info(&self, data: &[u8]) -> Option<resource_content::VersionInfo> {
        let res = self.resources.as_ref()?;
        let e = res.of_type(16).next()?;
        resource_content::VersionInfo::parse(self.resource_data(data, e))
    }

    pub fn manifest(&self, data: &[u8]) -> Option<(resources::ResourceEntry, resource_content::Manifest)> {
        let res = self.resources.as_ref()?;
        let e = res.of_type(24).next()?;
        Some((e.clone(), resource_content::Manifest::parse(self.resource_data(data, e))))
    }

    pub fn computed_checksum(&self, data: &[u8]) -> Option<u32> {
        let l = self.layout.as_ref()?;
        Some(patch::compute_checksum(data, l.optional_header.checksum_offset() as usize))
    }
}

/// Section names of the form "/123" refer to the COFF string table (object files and some MinGW images).
fn resolve_long_section_names(r: &Reader, l: &mut Layout) {
    let fh = &l.file_header;
    if fh.pointer_to_symbol_table == 0 {
        return;
    }
    let strtab = fh.pointer_to_symbol_table as usize + fh.number_of_symbols as usize * 18;
    for s in l.sections.iter_mut() {
        if let Some(num) = s.name.strip_prefix('/')
            && let Ok(n) = num.parse::<usize>()
            && let Some(name) = r.cstr(strtab + n, 256)
            && !name.is_empty()
        {
            s.name = name;
        }
    }
}

fn compute_overlay(data: &[u8], l: &Layout, sec: Option<&certificate::SecurityDirectory>) -> Option<Overlay> {
    let end = l.end_of_image_data().min(l.file_size);
    if end >= l.file_size {
        return None;
    }
    if let Some(sd) = sec.filter(|s| (s.offset as u64) < l.file_size && s.offset as u64 >= end) {
        let sec_start = sd.offset as u64;
        let sec_end = (sec_start + sd.size as u64).min(l.file_size);
        // Bytes between the last section and the certificate: alignment padding unless non-zero.
        let gap = &data[end as usize..sec_start as usize];
        if gap.iter().any(|&b| b != 0) {
            return Some(Overlay { offset: end, size: sec_start - end });
        }
        if sec_end < l.file_size {
            return Some(Overlay { offset: sec_end, size: l.file_size - sec_end });
        }
        return None;
    }
    Some(Overlay { offset: end, size: l.file_size - end })
}

fn entry_point(l: &Layout) -> EntryPoint {
    let rva = l.optional_header.address_of_entry_point;
    let mut ep = EntryPoint { rva, zero: rva == 0, ..Default::default() };
    if rva == 0 {
        return ep;
    }
    ep.file_offset = l.rva_to_offset(rva).map(|v| v as u64);
    ep.in_header = (rva as u64) < l.optional_header.size_of_headers as u64;
    if let Some(s) = l.section_of_rva(rva) {
        ep.section = Some(s.name.clone());
        ep.section_index = Some(s.index);
        ep.in_non_executable_section = !s.is_executable();
        let first_exec = l.sections.iter().find(|x| x.is_executable()).map(|x| x.index);
        ep.not_in_first_section = first_exec.is_some_and(|f| f != s.index);
        ep.in_last_section = s.index + 1 == l.sections.len() && l.sections.len() > 1;
    } else if !ep.in_header {
        ep.outside_image = true;
    }
    if rva >= l.optional_header.size_of_image {
        ep.outside_image = true;
    }
    ep
}
