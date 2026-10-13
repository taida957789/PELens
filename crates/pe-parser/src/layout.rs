//! Address translation shared by every directory parser.

use crate::headers::{FileHeader, OptionalHeader, Section};
use crate::reader::{Reader, align_down};

#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub file_size: u64,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<Section>,
}

impl Layout {
    pub fn is_64(&self) -> bool {
        self.optional_header.is_64()
    }

    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base
    }

    /// Raw pointer as the Windows loader rounds it (down to 512 when FileAlignment >= 512).
    pub fn raw_pointer(&self, s: &Section) -> u64 {
        if self.optional_header.file_alignment >= 0x200 {
            align_down(s.pointer_to_raw_data as u64, 0x200)
        } else {
            s.pointer_to_raw_data as u64
        }
    }

    /// Bytes actually backed by the file for this section.
    pub fn raw_size(&self, s: &Section) -> u64 {
        let ptr = self.raw_pointer(s);
        let declared = s.size_of_raw_data as u64;
        let vs = if s.virtual_size == 0 { declared } else { s.virtual_size as u64 };
        declared.min(crate::reader::align_up(vs, 0x1000)).min(self.file_size.saturating_sub(ptr))
    }

    /// Virtual extent of a section (max of virtual and raw size when VirtualSize is zero).
    pub fn virtual_extent(&self, s: &Section) -> u64 {
        if s.virtual_size == 0 { s.size_of_raw_data as u64 } else { s.virtual_size as u64 }
    }

    pub fn section_of_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| {
            let start = s.virtual_address as u64;
            let ext = self.virtual_extent(s).max(s.size_of_raw_data as u64);
            (rva as u64) >= start && (rva as u64) < start + ext
        })
    }

    pub fn section_of_offset(&self, off: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            let p = self.raw_pointer(s);
            let sz = self.raw_size(s);
            sz > 0 && off >= p && off < p + sz
        })
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if (rva as u64) < self.optional_header.size_of_headers as u64 || self.sections.is_empty() {
            return ((rva as u64) < self.file_size).then_some(rva as usize);
        }
        let s = self.section_of_rva(rva)?;
        let delta = (rva - s.virtual_address) as u64;
        if delta >= s.size_of_raw_data as u64 {
            // Address lies in the zero-filled tail of the section.
            return None;
        }
        let off = self.raw_pointer(s) + delta;
        (off < self.file_size).then_some(off as usize)
    }

    pub fn offset_to_rva(&self, off: u64) -> Option<u32> {
        if off < self.optional_header.size_of_headers as u64 {
            return Some(off as u32);
        }
        let s = self.section_of_offset(off)?;
        Some(s.virtual_address.wrapping_add((off - self.raw_pointer(s)) as u32))
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.image_base()).and_then(|v| u32::try_from(v).ok())
    }

    /// Read `len` bytes at `rva` (clamped).
    pub fn read_rva<'a>(&self, r: &Reader<'a>, rva: u32, len: usize) -> Option<&'a [u8]> {
        let off = self.rva_to_offset(rva)?;
        Some(r.bytes_clamped(off, len))
    }

    pub fn cstr_at_rva(&self, r: &Reader, rva: u32, max: usize) -> Option<String> {
        r.cstr(self.rva_to_offset(rva)?, max)
    }

    /// Name of the section holding an RVA, or "header" / "n/a".
    pub fn section_name_of_rva(&self, rva: u32) -> String {
        if (rva as u64) < self.optional_header.size_of_headers as u64 {
            return "header".into();
        }
        self.section_of_rva(rva).map(|s| s.name.clone()).unwrap_or_else(|| "n/a".into())
    }

    /// End of the last byte covered by headers or sections (start of overlay).
    pub fn end_of_image_data(&self) -> u64 {
        let mut end = self.optional_header.size_of_headers as u64;
        for s in &self.sections {
            if s.size_of_raw_data == 0 {
                continue;
            }
            let e = self.raw_pointer(s) + s.size_of_raw_data as u64;
            end = end.max(e);
        }
        end
    }
}
