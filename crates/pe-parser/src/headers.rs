//! DOS header, DOS stub, Rich header, COFF file header, optional header, data directories, sections.

use crate::reader::Reader;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const PE32_MAGIC: u16 = 0x10b;
pub const PE32PLUS_MAGIC: u16 = 0x20b;
pub const ROM_MAGIC: u16 = 0x107;

#[derive(Debug, Clone, Default)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl DosHeader {
    pub const SIZE: usize = 64;

    pub fn parse(r: &Reader) -> Option<Self> {
        let w = |i: usize| r.u16(i * 2).unwrap_or(0);
        r.bytes(0, Self::SIZE)?;
        let mut res = [0u16; 4];
        for (i, v) in res.iter_mut().enumerate() {
            *v = w(14 + i);
        }
        let mut res2 = [0u16; 10];
        for (i, v) in res2.iter_mut().enumerate() {
            *v = w(20 + i);
        }
        Some(Self {
            e_magic: w(0),
            e_cblp: w(1),
            e_cp: w(2),
            e_crlc: w(3),
            e_cparhdr: w(4),
            e_minalloc: w(5),
            e_maxalloc: w(6),
            e_ss: w(7),
            e_sp: w(8),
            e_csum: w(9),
            e_ip: w(10),
            e_cs: w(11),
            e_lfarlc: w(12),
            e_ovno: w(13),
            e_res: res,
            e_oemid: w(18),
            e_oeminfo: w(19),
            e_res2: res2,
            e_lfanew: r.u32(0x3c)?,
        })
    }

    /// (name, value) list in declaration order, used by views and reports.
    pub fn fields(&self) -> Vec<(&'static str, u32)> {
        let mut v = vec![
            ("e_magic", self.e_magic as u32),
            ("e_cblp", self.e_cblp as u32),
            ("e_cp", self.e_cp as u32),
            ("e_crlc", self.e_crlc as u32),
            ("e_cparhdr", self.e_cparhdr as u32),
            ("e_minalloc", self.e_minalloc as u32),
            ("e_maxalloc", self.e_maxalloc as u32),
            ("e_ss", self.e_ss as u32),
            ("e_sp", self.e_sp as u32),
            ("e_csum", self.e_csum as u32),
            ("e_ip", self.e_ip as u32),
            ("e_cs", self.e_cs as u32),
            ("e_lfarlc", self.e_lfarlc as u32),
            ("e_ovno", self.e_ovno as u32),
        ];
        for (i, r) in self.e_res.iter().enumerate() {
            v.push((["e_res[0]", "e_res[1]", "e_res[2]", "e_res[3]"][i], *r as u32));
        }
        v.push(("e_oemid", self.e_oemid as u32));
        v.push(("e_oeminfo", self.e_oeminfo as u32));
        const R2: [&str; 10] = [
            "e_res2[0]",
            "e_res2[1]",
            "e_res2[2]",
            "e_res2[3]",
            "e_res2[4]",
            "e_res2[5]",
            "e_res2[6]",
            "e_res2[7]",
            "e_res2[8]",
            "e_res2[9]",
        ];
        for (i, r) in self.e_res2.iter().enumerate() {
            v.push((R2[i], *r as u32));
        }
        v.push(("e_lfanew", self.e_lfanew));
        v
    }
}

#[derive(Debug, Clone, Default)]
pub struct DosStub {
    pub offset: u32,
    pub size: u32,
    /// Printable message found in the stub (e.g. "!This program cannot be run in DOS mode.").
    pub message: Option<String>,
}

impl DosStub {
    pub fn parse(r: &Reader, end: u32) -> Self {
        let offset = DosHeader::SIZE as u32;
        let size = end.saturating_sub(offset);
        let bytes = r.bytes_clamped(offset as usize, size as usize);
        Self { offset, size, message: stub_message(bytes) }
    }
}

/// Extract the longest printable run inside a DOS stub, cut at the `$` terminator used by INT 21h/09h.
fn stub_message(b: &[u8]) -> Option<String> {
    let mut best: Option<(usize, usize)> = None;
    let mut start = None;
    for (i, &c) in b.iter().chain(std::iter::once(&0u8)).enumerate() {
        let printable = (0x20..0x7f).contains(&c) && c != b'$';
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= 8 && best.is_none_or(|(bs, be)| i - s > be - bs) {
                    best = Some((s, i));
                }
                start = None;
            }
            _ => {}
        }
    }
    best.map(|(s, e)| String::from_utf8_lossy(&b[s..e]).trim().to_string())
}

#[derive(Debug, Clone, Default)]
pub struct RichEntry {
    pub prod_id: u16,
    pub build: u16,
    pub count: u32,
}

impl RichEntry {
    pub fn comp_id(&self) -> u32 {
        ((self.prod_id as u32) << 16) | self.build as u32
    }
}

#[derive(Debug, Clone, Default)]
pub struct RichHeader {
    /// File offset of "DanS".
    pub offset: u32,
    /// Offset just past the key that follows "Rich".
    pub end: u32,
    pub key: u32,
    pub entries: Vec<RichEntry>,
    pub checksum_computed: u32,
    /// Decoded (clear-text) bytes from DanS to Rich, used for footprint hashing.
    pub raw_decoded: Vec<u8>,
}

impl RichHeader {
    pub fn checksum_valid(&self) -> bool {
        self.key == self.checksum_computed
    }

    pub fn parse(r: &Reader, limit: u32) -> Option<Self> {
        let limit = (limit as usize).min(r.len());
        let area = r.bytes(0, limit)?;
        // Find "Rich" marker scanning dword-aligned after DOS header.
        let mut rich_off = None;
        let mut o = 0x40;
        while o + 8 <= area.len() {
            if &area[o..o + 4] == b"Rich" {
                rich_off = Some(o);
                break;
            }
            o += 4;
        }
        let rich_off = rich_off?;
        let key = r.u32(rich_off + 4)?;
        // Walk backwards to find "DanS" ^ key.
        let mut dans = None;
        let mut p = rich_off;
        while p >= 0x40 + 4 {
            p -= 4;
            if r.u32(p)? ^ key == 0x536e_6144 {
                dans = Some(p);
                break;
            }
        }
        let dans = dans?;
        let mut raw_decoded = Vec::with_capacity(rich_off - dans);
        let mut q = dans;
        while q < rich_off {
            let v = r.u32(q)? ^ key;
            raw_decoded.extend_from_slice(&v.to_le_bytes());
            q += 4;
        }
        let mut entries = Vec::new();
        // Header: DanS + 3 padding dwords, then (comp_id, count) pairs.
        let mut e = dans + 16;
        while e + 8 <= rich_off {
            let comp = r.u32(e)? ^ key;
            let count = r.u32(e + 4)? ^ key;
            entries.push(RichEntry { prod_id: (comp >> 16) as u16, build: (comp & 0xffff) as u16, count });
            e += 8;
        }
        // Checksum: dans offset + rol(byte,i) over the DOS header/stub (e_lfanew excluded) + rol(comp,count).
        let mut csum: u32 = dans as u32;
        for i in 0..dans {
            if (0x3c..0x40).contains(&i) {
                continue;
            }
            csum = csum.wrapping_add((area[i] as u32).rotate_left(i as u32 & 31));
        }
        for en in &entries {
            csum = csum.wrapping_add(en.comp_id().rotate_left(en.count & 31));
        }
        Some(Self { offset: dans as u32, end: (rich_off + 8) as u32, key, entries, checksum_computed: csum, raw_decoded })
    }
}

pub mod file_characteristics {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    pub const MACHINE_32BIT: u16 = 0x0100;
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000;
    pub const DLL: u16 = 0x2000;
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    pub const BYTES_REVERSED_HI: u16 = 0x8000;

    pub const ALL: [(u16, &str); 15] = [
        (RELOCS_STRIPPED, "relocation-stripped"),
        (EXECUTABLE_IMAGE, "file-can-be-executed"),
        (LINE_NUMS_STRIPPED, "line-stripped-from-file"),
        (LOCAL_SYMS_STRIPPED, "local-symbols-stripped-from-file"),
        (AGGRESSIVE_WS_TRIM, "aggressive-working-set-trim"),
        (LARGE_ADDRESS_AWARE, "large-address-aware"),
        (BYTES_REVERSED_LO, "bytes-of-machine-words-reversed-Low"),
        (MACHINE_32BIT, "32-bit-words-support"),
        (DEBUG_STRIPPED, "debug-stripped"),
        (REMOVABLE_RUN_FROM_SWAP, "media-run-from-swap"),
        (NET_RUN_FROM_SWAP, "network-run-from-swap"),
        (SYSTEM, "system-image"),
        (DLL, "dynamic-link-library"),
        (UP_SYSTEM_ONLY, "uniprocessor"),
        (BYTES_REVERSED_HI, "bytes-of-machine-words-reversed-Hi"),
    ];
}

#[derive(Debug, Clone, Default)]
pub struct FileHeader {
    pub offset: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl FileHeader {
    pub const SIZE: usize = 20;

    pub fn parse(r: &Reader, off: usize) -> Option<Self> {
        Some(Self {
            offset: off as u32,
            machine: r.u16(off)?,
            number_of_sections: r.u16(off + 2)?,
            time_date_stamp: r.u32(off + 4)?,
            pointer_to_symbol_table: r.u32(off + 8)?,
            number_of_symbols: r.u32(off + 12)?,
            size_of_optional_header: r.u16(off + 16)?,
            characteristics: r.u16(off + 18)?,
        })
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & file_characteristics::DLL != 0
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & file_characteristics::EXECUTABLE_IMAGE != 0
    }
}

pub fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "Intel-386",
        0x0162 => "MipsR3000",
        0x0166 => "MipsR4000",
        0x0168 => "MipsR10000",
        0x0169 => "Mipsv2",
        0x0184 => "Alpha",
        0x01a2 => "SH3",
        0x01a3 => "SH3DSP",
        0x01a4 => "SH3E",
        0x01a6 => "SH4",
        0x01a8 => "SH5",
        0x01c0 => "ARM",
        0x01c2 => "ARM-Thumb",
        0x01c4 => "ARM-Thumb-2-little-Indian",
        0x01d3 => "AM33",
        0x01f0 => "PowerPc",
        0x01f1 => "PowerPcfp",
        0x0200 => "IA64",
        0x0266 => "Mips16",
        0x0284 => "Alpha64",
        0x0366 => "MipsFpu",
        0x0466 => "MipsFpu16",
        0x0520 => "TriCore",
        0x0cef => "CEF",
        0x0ebc => "EBC",
        0x5032 => "RISCV32",
        0x5064 => "RISCV64",
        0x8664 => "Amd64",
        0x9041 => "M32R",
        0xa641 => "ARM64EC",
        0xaa64 => "ARM64",
        0xc0ee => "CEE",
        _ => "unknown",
    }
}

pub fn machine_is_64(m: u16) -> bool {
    matches!(m, 0x8664 | 0x0200 | 0xaa64 | 0xa641 | 0x0284 | 0x5064)
}

pub mod dll_characteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_ISOLATION: u16 = 0x0200;
    pub const NO_SEH: u16 = 0x0400;
    pub const NO_BIND: u16 = 0x0800;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const WDM_DRIVER: u16 = 0x2000;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;

    pub const ALL: [(u16, &str); 11] = [
        (HIGH_ENTROPY_VA, "High-Entropy"),
        (DYNAMIC_BASE, "Address-Space-Layout-Randomization (ASLR)"),
        (FORCE_INTEGRITY, "Code-Integrity (CI)"),
        (NX_COMPAT, "Data Execution Prevention (DEP)"),
        (NO_ISOLATION, "Image isolation (disabled)"),
        (NO_SEH, "Structured-Exception Handling (SEH) (disabled)"),
        (NO_BIND, "image-bound (disabled)"),
        (APPCONTAINER, "AppContainer"),
        (WDM_DRIVER, "Windows-Driver Model (WDM)"),
        (GUARD_CF, "Control-Flow Guard (CFG)"),
        (TERMINAL_SERVER_AWARE, "Terminal-Server aware (TSA)"),
    ];
}

pub fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "Native",
        2 => "GUI",
        3 => "console",
        5 => "os2",
        7 => "posix",
        8 => "win9x-driver",
        9 => "Windows-CE",
        10 => "EFI-application",
        11 => "EFI-driver-boot-service",
        12 => "EFI-driver-run-time-service",
        13 => "EFI-ROM",
        14 => "Xbox",
        16 => "Windows-boot-application",
        _ => "unknown",
    }
}

/// Friendly OS name from optional-header OS version.
pub fn os_name(major: u16, minor: u16) -> &'static str {
    match (major, minor) {
        (10, _) => "Windows 10/11 | Server 2016+",
        (6, 3) => "Windows 8.1 | Server 2012 R2",
        (6, 2) => "Windows 8 | Server 2012",
        (6, 1) => "Windows 7 | Server 2008 R2",
        (6, 0) => "Windows Vista | Server 2008",
        (5, 2) => "Windows XP 64-bit | Server 2003",
        (5, 1) => "Windows XP",
        (5, 0) => "Windows 2000",
        (4, _) => "Windows NT 4.0",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

pub const DIRECTORY_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "relocation",
    "debug",
    "architecture",
    "global-pointer",
    "thread-local-storage",
    "load-configuration",
    "bound-import",
    "import-address",
    "delay-loaded",
    ".NET",
    "reserved",
];

pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR: usize = 14;
    pub const RESERVED: usize = 15;
}

#[derive(Debug, Clone, Default)]
pub struct OptionalHeader {
    pub offset: u32,
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
    /// File offset of the first data directory entry.
    pub data_directories_offset: u32,
}

impl OptionalHeader {
    pub fn is_64(&self) -> bool {
        self.magic == PE32PLUS_MAGIC
    }

    /// Offset of the `CheckSum` field.
    pub fn checksum_offset(&self) -> u32 {
        self.offset + 64
    }

    pub fn entry_point_offset(&self) -> u32 {
        self.offset + 16
    }

    pub fn dll_characteristics_offset(&self) -> u32 {
        self.offset + 70
    }

    pub fn parse(r: &Reader, off: usize, size: u16) -> Option<Self> {
        let magic = r.u16(off)?;
        let is64 = magic == PE32PLUS_MAGIC;
        let mut h = Self {
            offset: off as u32,
            magic,
            major_linker_version: r.u8(off + 2)?,
            minor_linker_version: r.u8(off + 3)?,
            size_of_code: r.u32(off + 4)?,
            size_of_initialized_data: r.u32(off + 8)?,
            size_of_uninitialized_data: r.u32(off + 12)?,
            address_of_entry_point: r.u32(off + 16)?,
            base_of_code: r.u32(off + 20)?,
            ..Default::default()
        };
        let o;
        if is64 {
            h.image_base = r.u64(off + 24)?;
            o = off + 32;
        } else {
            h.base_of_data = Some(r.u32(off + 24)?);
            h.image_base = r.u32(off + 28)? as u64;
            o = off + 32;
        }
        h.section_alignment = r.u32(o)?;
        h.file_alignment = r.u32(o + 4)?;
        h.major_os_version = r.u16(o + 8)?;
        h.minor_os_version = r.u16(o + 10)?;
        h.major_image_version = r.u16(o + 12)?;
        h.minor_image_version = r.u16(o + 14)?;
        h.major_subsystem_version = r.u16(o + 16)?;
        h.minor_subsystem_version = r.u16(o + 18)?;
        h.win32_version_value = r.u32(o + 20)?;
        h.size_of_image = r.u32(o + 24)?;
        h.size_of_headers = r.u32(o + 28)?;
        h.checksum = r.u32(o + 32)?;
        h.subsystem = r.u16(o + 36)?;
        h.dll_characteristics = r.u16(o + 38)?;
        let mut p = o + 40;
        if is64 {
            h.size_of_stack_reserve = r.u64(p)?;
            h.size_of_stack_commit = r.u64(p + 8)?;
            h.size_of_heap_reserve = r.u64(p + 16)?;
            h.size_of_heap_commit = r.u64(p + 24)?;
            p += 32;
        } else {
            h.size_of_stack_reserve = r.u32(p)? as u64;
            h.size_of_stack_commit = r.u32(p + 4)? as u64;
            h.size_of_heap_reserve = r.u32(p + 8)? as u64;
            h.size_of_heap_commit = r.u32(p + 12)? as u64;
            p += 16;
        }
        h.loader_flags = r.u32(p)?;
        h.number_of_rva_and_sizes = r.u32(p + 4)?;
        p += 8;
        h.data_directories_offset = p as u32;
        // The loader honours at most 16 entries, and only those inside SizeOfOptionalHeader.
        let max_by_size = (size as usize).saturating_sub(p - off) / 8;
        let n = (h.number_of_rva_and_sizes as usize).min(16).min(max_by_size);
        for i in 0..n {
            let rva = r.u32(p + i * 8).unwrap_or(0);
            let sz = r.u32(p + i * 8 + 4).unwrap_or(0);
            h.data_directories.push(DataDirectory { rva, size: sz });
        }
        Some(h)
    }

    pub fn directory(&self, idx: usize) -> Option<DataDirectory> {
        self.data_directories.get(idx).copied().filter(|d| d.rva != 0 || d.size != 0)
    }
}

pub mod section_characteristics {
    pub const TYPE_NO_PAD: u32 = 0x0000_0008;
    pub const CNT_CODE: u32 = 0x0000_0020;
    pub const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const LNK_INFO: u32 = 0x0000_0200;
    pub const LNK_REMOVE: u32 = 0x0000_0800;
    pub const LNK_COMDAT: u32 = 0x0000_1000;
    pub const GPREL: u32 = 0x0000_8000;
    pub const LNK_NRELOC_OVFL: u32 = 0x0100_0000;
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
    pub const MEM_NOT_CACHED: u32 = 0x0400_0000;
    pub const MEM_NOT_PAGED: u32 = 0x0800_0000;
    pub const MEM_SHARED: u32 = 0x1000_0000;
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;
}

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub index: usize,
    /// File offset of the IMAGE_SECTION_HEADER.
    pub header_offset: u32,
    pub raw_name: [u8; 8],
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl Section {
    pub const SIZE: usize = 40;

    pub fn parse(r: &Reader, off: usize, index: usize) -> Option<Self> {
        let raw = r.bytes(off, 8)?;
        let mut raw_name = [0u8; 8];
        raw_name.copy_from_slice(raw);
        let end = raw.iter().position(|&c| c == 0).unwrap_or(8);
        Some(Self {
            index,
            header_offset: off as u32,
            raw_name,
            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            virtual_size: r.u32(off + 8)?,
            virtual_address: r.u32(off + 12)?,
            size_of_raw_data: r.u32(off + 16)?,
            pointer_to_raw_data: r.u32(off + 20)?,
            pointer_to_relocations: r.u32(off + 24)?,
            pointer_to_linenumbers: r.u32(off + 28)?,
            number_of_relocations: r.u16(off + 32)?,
            number_of_linenumbers: r.u16(off + 34)?,
            characteristics: r.u32(off + 36)?,
        })
    }

    pub fn has(&self, flag: u32) -> bool {
        self.characteristics & flag != 0
    }

    pub fn is_executable(&self) -> bool {
        self.has(section_characteristics::MEM_EXECUTE) || self.has(section_characteristics::CNT_CODE)
    }

    pub fn is_writable(&self) -> bool {
        self.has(section_characteristics::MEM_WRITE)
    }

    pub fn is_readable(&self) -> bool {
        self.has(section_characteristics::MEM_READ)
    }

    pub fn is_shared(&self) -> bool {
        self.has(section_characteristics::MEM_SHARED)
    }

    pub fn is_self_modifying(&self) -> bool {
        self.is_writable() && self.is_executable()
    }

    /// Section occupies no bytes in the file but has a virtual size.
    pub fn is_virtualized(&self) -> bool {
        self.size_of_raw_data == 0 && self.virtual_size > 0
    }
}

/// Characteristics bit → readable name, used by the sections view.
pub fn section_flag_names(c: u32) -> Vec<&'static str> {
    use section_characteristics::*;
    let table: [(u32, &str); 14] = [
        (CNT_CODE, "code"),
        (CNT_INITIALIZED_DATA, "initialized-data"),
        (CNT_UNINITIALIZED_DATA, "uninitialized-data"),
        (LNK_INFO, "link-info"),
        (LNK_REMOVE, "link-remove"),
        (LNK_COMDAT, "comdat"),
        (GPREL, "gp-relative"),
        (MEM_DISCARDABLE, "discardable"),
        (MEM_NOT_CACHED, "not-cachable"),
        (MEM_NOT_PAGED, "not-pageable"),
        (MEM_SHARED, "shareable"),
        (MEM_EXECUTE, "executable"),
        (MEM_READ, "readable"),
        (MEM_WRITE, "writable"),
    ];
    table.iter().filter(|(b, _)| c & b != 0).map(|(_, n)| *n).collect()
}
