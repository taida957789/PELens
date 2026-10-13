//! File-level actions shared by the GUI and the CLI: dumps and image modifications.

use pe_parser::PeFile;
use pe_parser::patch::{self, PatchError};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modification {
    /// Switch the image between DLL (true) and EXE (false).
    SetDll(bool),
    ToggleFileCharacteristic(u16),
    ToggleDllCharacteristic(u16),
    SetEntryPoint(u32),
    RemoveOverlay,
    UpdateChecksum,
}

impl Modification {
    pub fn describe(&self) -> String {
        match self {
            Modification::SetDll(true) => "toggle EXE > DLL".into(),
            Modification::SetDll(false) => "toggle DLL > EXE".into(),
            Modification::ToggleFileCharacteristic(b) => format!("toggle file-header characteristic 0x{b:04X}"),
            Modification::ToggleDllCharacteristic(b) => format!("toggle DllCharacteristics 0x{b:04X}"),
            Modification::SetEntryPoint(r) => format!("set entry-point 0x{r:08X}"),
            Modification::RemoveOverlay => "delete overlay".into(),
            Modification::UpdateChecksum => "update checksum".into(),
        }
    }
}

/// Apply a modification to an in-memory image.
pub fn apply(data: &mut Vec<u8>, m: Modification) -> Result<(), PatchError> {
    let pe = PeFile::parse(data);
    match m {
        Modification::SetDll(d) => patch::set_dll(data, &pe, d).map(|_| ()),
        Modification::ToggleFileCharacteristic(b) => patch::toggle_file_characteristic(data, &pe, b).map(|_| ()),
        Modification::ToggleDllCharacteristic(b) => patch::toggle_dll_characteristic(data, &pe, b).map(|_| ()),
        Modification::SetEntryPoint(r) => patch::set_entry_point(data, &pe, r),
        Modification::RemoveOverlay => patch::remove_overlay(data, &pe).map(|_| ()),
        Modification::UpdateChecksum => patch::update_checksum(data, &pe).map(|_| ()),
    }
}

/// Write `size` bytes from `offset` to `path` (clamped to the data).
pub fn dump(data: &[u8], offset: u64, size: u64, path: &Path) -> std::io::Result<u64> {
    let start = (offset as usize).min(data.len());
    let end = (offset.saturating_add(size) as usize).min(data.len());
    std::fs::write(path, &data[start..end])?;
    Ok((end - start) as u64)
}

/// Default dump file name: "<file>.<item>.dump" with unsafe characters replaced.
pub fn dump_name(file_name: &str, item: &str) -> String {
    let clean: String = item.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
    format!("{file_name}.{clean}.dump")
}

pub fn dump_path(dir: &Path, file_name: &str, item: &str) -> PathBuf {
    dir.join(dump_name(file_name, item))
}

/// Parse a user supplied entry point ("0x1234", "1234h" or decimal).
pub fn parse_address(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
    }
    if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        return u32::from_str_radix(h, 16).ok();
    }
    t.parse().ok()
}
