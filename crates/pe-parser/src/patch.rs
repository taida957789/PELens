//! In-place modifications of a PE image (pestudio "modify" features) and checksum computation.

use crate::PeFile;
use crate::headers::{dir, file_characteristics};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    NotPe,
    OutOfBounds,
    NoOverlay,
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::NotPe => write!(f, "not a PE image"),
            PatchError::OutOfBounds => write!(f, "field outside of the file"),
            PatchError::NoOverlay => write!(f, "the file has no overlay"),
        }
    }
}

impl std::error::Error for PatchError {}

/// PE checksum as computed by `CheckSumMappedFile` (the stored CheckSum field is treated as zero).
pub fn compute_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i < data.len() {
        let w = if i + 1 < data.len() { u16::from_le_bytes([data[i], data[i + 1]]) } else { data[i] as u16 };
        if !(i >= checksum_offset && i < checksum_offset + 4) {
            sum += w as u64;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        i += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

fn write_u16(data: &mut [u8], off: usize, v: u16) -> Result<(), PatchError> {
    data.get_mut(off..off + 2).ok_or(PatchError::OutOfBounds)?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], off: usize, v: u32) -> Result<(), PatchError> {
    data.get_mut(off..off + 4).ok_or(PatchError::OutOfBounds)?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn layout(pe: &PeFile) -> Result<&crate::layout::Layout, PatchError> {
    pe.layout.as_ref().ok_or(PatchError::NotPe)
}

/// Toggle a bit of IMAGE_FILE_HEADER.Characteristics.
pub fn toggle_file_characteristic(data: &mut [u8], pe: &PeFile, bit: u16) -> Result<u16, PatchError> {
    let l = layout(pe)?;
    let v = l.file_header.characteristics ^ bit;
    write_u16(data, l.file_header.offset as usize + 18, v)?;
    Ok(v)
}

/// Switch the image between DLL and EXE.
pub fn set_dll(data: &mut [u8], pe: &PeFile, dll: bool) -> Result<u16, PatchError> {
    let l = layout(pe)?;
    let mut v = l.file_header.characteristics;
    if dll {
        v |= file_characteristics::DLL;
    } else {
        v &= !file_characteristics::DLL;
    }
    write_u16(data, l.file_header.offset as usize + 18, v)?;
    Ok(v)
}

/// Toggle a bit of IMAGE_OPTIONAL_HEADER.DllCharacteristics.
pub fn toggle_dll_characteristic(data: &mut [u8], pe: &PeFile, bit: u16) -> Result<u16, PatchError> {
    let l = layout(pe)?;
    let v = l.optional_header.dll_characteristics ^ bit;
    write_u16(data, l.optional_header.dll_characteristics_offset() as usize, v)?;
    Ok(v)
}

pub fn set_entry_point(data: &mut [u8], pe: &PeFile, rva: u32) -> Result<(), PatchError> {
    let l = layout(pe)?;
    write_u32(data, l.optional_header.entry_point_offset() as usize, rva)
}

/// Rewrite the CheckSum field with the computed value.
pub fn update_checksum(data: &mut [u8], pe: &PeFile) -> Result<u32, PatchError> {
    let l = layout(pe)?;
    let off = l.optional_header.checksum_offset() as usize;
    let c = compute_checksum(data, off);
    write_u32(data, off, c)?;
    Ok(c)
}

/// Remove the overlay. When the security directory lives inside the removed area it is cleared.
pub fn remove_overlay(data: &mut Vec<u8>, pe: &PeFile) -> Result<u64, PatchError> {
    let l = layout(pe)?;
    let ov = pe.overlay.as_ref().ok_or(PatchError::NoOverlay)?;
    let start = ov.offset as usize;
    let removed = data.len().saturating_sub(start) as u64;
    if let Some(d) = l.optional_header.directory(dir::SECURITY)
        && d.rva as usize >= start
    {
        let o = l.optional_header.data_directories_offset as usize + dir::SECURITY * 8;
        write_u32(data, o, 0)?;
        write_u32(data, o + 4, 0)?;
    }
    data.truncate(start);
    Ok(removed)
}
