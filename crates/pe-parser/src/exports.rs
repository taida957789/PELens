//! Export directory.

use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;

const MAX_EXPORTS: usize = 1 << 20;

#[derive(Debug, Clone, Default)]
pub struct ExportedFunction {
    pub ordinal: u32,
    /// Index in the AddressOfFunctions array.
    pub function_index: u32,
    pub rva: u32,
    pub name: Option<String>,
    pub name_rva: u32,
    pub forwarder: Option<String>,
    /// Empty slot in the address table (rva == 0).
    pub gap: bool,
}

impl ExportedFunction {
    pub fn is_anonymous(&self) -> bool {
        self.name.is_none() && !self.gap
    }

    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("#{}", self.ordinal))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Exports {
    pub offset: u32,
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub dll_name: String,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
    pub functions: Vec<ExportedFunction>,
    /// Names exported more than once.
    pub duplicate_names: Vec<String>,
    /// NumberOfFunctions / NumberOfNames claim more entries than the file holds.
    pub truncated: bool,
}

impl Exports {
    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::EXPORT)?;
        let off = l.rva_to_offset(d.rva)?;
        let w = |k: usize| r.u32(off + k);
        let mut e = Exports {
            offset: off as u32,
            characteristics: w(0)?,
            time_date_stamp: w(4)?,
            major_version: r.u16(off + 8)?,
            minor_version: r.u16(off + 10)?,
            name_rva: w(12)?,
            base: w(16)?,
            number_of_functions: w(20)?,
            number_of_names: w(24)?,
            address_of_functions: w(28)?,
            address_of_names: w(32)?,
            address_of_name_ordinals: w(36)?,
            ..Default::default()
        };
        e.dll_name = l.cstr_at_rva(r, e.name_rva, 256).unwrap_or_default();
        // Never trust the counts beyond what the arrays can hold in the file: a corrupted count
        // would otherwise produce up to MAX_EXPORTS empty "gap" entries from a few bytes.
        let in_file = |rva: u32, width: usize| l.rva_to_offset(rva).map_or(0, |o| r.len().saturating_sub(o) / width);
        let nfuncs = (e.number_of_functions as usize).min(MAX_EXPORTS).min(in_file(e.address_of_functions, 4));
        let nnames = (e.number_of_names as usize).min(MAX_EXPORTS).min(in_file(e.address_of_names, 4));
        e.truncated = nfuncs < e.number_of_functions as usize || nnames < e.number_of_names as usize;
        let fstart = d.rva;
        let fend = d.rva.saturating_add(d.size);

        // names[i] -> function index
        let mut names: Vec<Vec<(String, u32)>> = vec![Vec::new(); nfuncs];
        let mut seen = std::collections::HashMap::<String, u32>::new();
        for i in 0..nnames {
            let Some(name_rva) = l.rva_to_offset(e.address_of_names.wrapping_add(i as u32 * 4)).and_then(|o| r.u32(o)) else {
                break;
            };
            let Some(idx) = l.rva_to_offset(e.address_of_name_ordinals.wrapping_add(i as u32 * 2)).and_then(|o| r.u16(o)) else {
                break;
            };
            let name = l.cstr_at_rva(r, name_rva, 1024).unwrap_or_default();
            *seen.entry(name.clone()).or_default() += 1;
            if let Some(slot) = names.get_mut(idx as usize) {
                slot.push((name, name_rva));
            }
        }
        let mut dups: Vec<String> = seen.into_iter().filter(|(_, c)| *c > 1).map(|(n, _)| n).collect();
        dups.sort();
        e.duplicate_names = dups;

        let functions_off = l.rva_to_offset(e.address_of_functions);
        for (i, slot) in names.iter_mut().enumerate().take(nfuncs) {
            let rva = functions_off.and_then(|o| r.u32(o + i * 4)).unwrap_or(0);
            let forwarder = if rva >= fstart && rva < fend { l.cstr_at_rva(r, rva, 512).filter(|s| !s.is_empty()) } else { None };
            let base = ExportedFunction {
                ordinal: e.base.wrapping_add(i as u32),
                function_index: i as u32,
                rva,
                forwarder,
                gap: rva == 0,
                ..Default::default()
            };
            let slot = std::mem::take(slot);
            if slot.is_empty() {
                e.functions.push(base);
            } else {
                for (n, nrva) in slot {
                    e.functions.push(ExportedFunction { name: Some(n), name_rva: nrva, ..base.clone() });
                }
            }
        }
        Some(e)
    }

    pub fn forwarded_count(&self) -> usize {
        self.functions.iter().filter(|f| f.forwarder.is_some()).count()
    }

    pub fn anonymous_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_anonymous()).count()
    }

    pub fn gap_count(&self) -> usize {
        self.functions.iter().filter(|f| f.gap).count()
    }
}
