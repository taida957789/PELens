//! Synthetic PE builder used by tests across the workspace.
//!
//! Layout produced:
//!   0x000  DOS header + stub (+ optional Rich header)
//!   ...    NT headers + section table
//!   0x400  sections (file alignment 0x200, section alignment 0x1000)
//!   .text  code (entry point at its start)
//!   .rdata imports / delay imports / exports / debug / TLS / load-config / CLR+metadata
//!   .rsrc  resources
//!   .reloc base relocations
//!   + extra user sections, overlay and certificate

pub mod der_builder;

pub struct Import {
    pub dll: String,
    /// Name or `#ordinal`.
    pub functions: Vec<String>,
    pub delay: bool,
}

pub struct Export {
    pub name: Option<String>,
    pub rva: u32,
    pub forwarder: Option<String>,
}

pub struct Resource {
    pub type_id: ResKey,
    pub name: ResKey,
    pub lang: u16,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub enum ResKey {
    Id(u16),
    Name(String),
}

pub struct ExtraSection {
    pub name: String,
    pub data: Vec<u8>,
    pub characteristics: u32,
    pub virtual_size: Option<u32>,
}

pub struct PeBuilder {
    pub is64: bool,
    pub dll: bool,
    pub machine: Option<u16>,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub timestamp: u32,
    pub code: Vec<u8>,
    pub entry_offset_in_text: Option<u32>,
    pub stub_message: String,
    pub rich: Vec<(u16, u16, u32)>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub export_dll_name: String,
    pub resources: Vec<Resource>,
    pub tls_callbacks: usize,
    pub relocations: bool,
    pub pdb_path: Option<String>,
    pub extra_debug: Vec<(u32, Vec<u8>)>,
    pub load_config: bool,
    pub dotnet: Option<DotNetSpec>,
    pub exceptions: usize,
    pub extra_sections: Vec<ExtraSection>,
    pub overlay: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
    pub fix_checksum: bool,
}

#[derive(Default)]
pub struct DotNetSpec {
    pub module: String,
    pub type_refs: Vec<(String, String)>,
    pub member_refs: Vec<(usize, String)>,
    pub module_refs: Vec<String>,
    pub impl_maps: Vec<(String, usize)>,
    pub assembly: Option<String>,
    pub user_strings: Vec<String>,
    pub guid_attribute: Option<String>,
    pub extra_stream: Option<String>,
    /// Declare rows for table 0x32 (no schema), as obfuscators/crafted files do.
    pub unknown_table: bool,
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self {
            is64: false,
            dll: false,
            machine: None,
            subsystem: 2,
            dll_characteristics: 0x8140,
            timestamp: 0x5f00_0000,
            code: vec![0x55, 0x8b, 0xec, 0x33, 0xc0, 0x5d, 0xc3, 0x90],
            entry_offset_in_text: Some(0),
            stub_message: "This program cannot be run in DOS mode.".into(),
            rich: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            export_dll_name: "test.dll".into(),
            resources: Vec::new(),
            tls_callbacks: 0,
            relocations: false,
            pdb_path: None,
            extra_debug: Vec::new(),
            load_config: false,
            dotnet: None,
            exceptions: 0,
            extra_sections: Vec::new(),
            overlay: Vec::new(),
            certificate: None,
            fix_checksum: false,
        }
    }
}

const SA: u32 = 0x1000;
const FA: u32 = 0x200;

fn align(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

struct Blob {
    base: u32,
    bytes: Vec<u8>,
}

impl Blob {
    fn new(base: u32) -> Self {
        Self { base, bytes: Vec::new() }
    }
    fn pad(&mut self, a: usize) {
        while !self.bytes.len().is_multiple_of(a) {
            self.bytes.push(0);
        }
    }
    fn alloc(&mut self, b: &[u8]) -> u32 {
        self.pad(4);
        let rva = self.base + self.bytes.len() as u32;
        self.bytes.extend_from_slice(b);
        rva
    }
    fn reserve(&mut self, n: usize) -> u32 {
        self.alloc(&vec![0u8; n])
    }
    fn put32(&mut self, rva: u32, v: u32) {
        let o = (rva - self.base) as usize;
        self.bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(&mut self, rva: u32, v: u64) {
        let o = (rva - self.base) as usize;
        self.bytes[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn cstr(&mut self, s: &str) -> u32 {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        self.alloc(&b)
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Build a VS_VERSIONINFO blob with the given string pairs.
pub fn version_resource(file_version: (u16, u16, u16, u16), strings: &[(&str, &str)]) -> Vec<u8> {
    fn node(key: &str, value: &[u8], vtype: u16, value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0u8; 6];
        b.extend(utf16(key));
        b.extend([0, 0]);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b.extend_from_slice(value);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        for c in children {
            b.extend_from_slice(c);
            while !b.len().is_multiple_of(4) {
                b.push(0);
            }
        }
        let len = b.len() as u16;
        b[0..2].copy_from_slice(&len.to_le_bytes());
        b[2..4].copy_from_slice(&value_len.to_le_bytes());
        b[4..6].copy_from_slice(&vtype.to_le_bytes());
        b
    }
    let mut fixed = Vec::new();
    let ms = ((file_version.0 as u32) << 16) | file_version.1 as u32;
    let ls = ((file_version.2 as u32) << 16) | file_version.3 as u32;
    for v in [0xFEEF04BDu32, 0x10000, ms, ls, ms, ls, 0x3f, 0, 0x40004, 1, 0, 0, 0] {
        fixed.extend(v.to_le_bytes());
    }
    let strs: Vec<Vec<u8>> = strings
        .iter()
        .map(|(k, v)| {
            let mut val = utf16(v);
            val.extend([0, 0]);
            node(k, &val, 1, (v.encode_utf16().count() + 1) as u16, &[])
        })
        .collect();
    let table = node("040904b0", &[], 1, 0, &strs);
    let sfi = node("StringFileInfo", &[], 1, 0, &[table]);
    let trans = node("Translation", &[0x09, 0x04, 0xb0, 0x04], 0, 4, &[]);
    let vfi = node("VarFileInfo", &[], 1, 0, &[trans]);
    node("VS_VERSION_INFO", &fixed, 0, 52, &[sfi, vfi])
}

impl PeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(&self) -> Vec<u8> {
        let ptr = if self.is64 { 8u32 } else { 4 };
        let image_base: u64 = if self.is64 { 0x1_4000_0000 } else { 0x40_0000 };
        let text_rva = SA;
        let mut code = self.code.clone();
        if code.is_empty() {
            code.push(0xc3);
        }
        let text_vsize = align(code.len() as u32, 16).max(16);
        let rdata_rva = text_rva + align(text_vsize, SA);
        let mut rd = Blob::new(rdata_rva);
        let mut dirs = [(0u32, 0u32); 16];

        // ---- imports
        let implicit: Vec<&Import> = self.imports.iter().filter(|i| !i.delay).collect();
        if !implicit.is_empty() {
            let desc = rd.reserve((implicit.len() + 1) * 20);
            for (i, imp) in implicit.iter().enumerate() {
                let n = imp.functions.len() + 1;
                let int = rd.reserve(n * ptr as usize);
                let iat = rd.reserve(n * ptr as usize);
                for (k, f) in imp.functions.iter().enumerate() {
                    let v: u64 = if let Some(o) = f.strip_prefix('#') {
                        let o: u64 = o.parse().unwrap_or(1);
                        o | if self.is64 { 1 << 63 } else { 1 << 31 }
                    } else {
                        let mut hn = vec![0u8, 0];
                        hn.extend(f.as_bytes());
                        hn.push(0);
                        rd.alloc(&hn) as u64
                    };
                    let (a, b) = (int + k as u32 * ptr, iat + k as u32 * ptr);
                    if self.is64 {
                        rd.put64(a, v);
                        rd.put64(b, v);
                    } else {
                        rd.put32(a, v as u32);
                        rd.put32(b, v as u32);
                    }
                }
                let name = rd.cstr(&imp.dll);
                let d = desc + i as u32 * 20;
                rd.put32(d, int);
                rd.put32(d + 12, name);
                rd.put32(d + 16, iat);
            }
            dirs[1] = (desc, (implicit.len() as u32 + 1) * 20);
        }
        let delayed: Vec<&Import> = self.imports.iter().filter(|i| i.delay).collect();
        if !delayed.is_empty() {
            let desc = rd.reserve((delayed.len() + 1) * 32);
            for (i, imp) in delayed.iter().enumerate() {
                let n = imp.functions.len() + 1;
                let int = rd.reserve(n * ptr as usize);
                let iat = rd.reserve(n * ptr as usize);
                for (k, f) in imp.functions.iter().enumerate() {
                    let mut hn = vec![0u8, 0];
                    hn.extend(f.as_bytes());
                    hn.push(0);
                    let v = rd.alloc(&hn) as u64;
                    if self.is64 {
                        rd.put64(int + k as u32 * ptr, v);
                        rd.put64(iat + k as u32 * ptr, image_base + text_rva as u64);
                    } else {
                        rd.put32(int + k as u32 * ptr, v as u32);
                        rd.put32(iat + k as u32 * ptr, (image_base + text_rva as u64) as u32);
                    }
                }
                let name = rd.cstr(&imp.dll);
                let d = desc + i as u32 * 32;
                rd.put32(d, 1);
                rd.put32(d + 4, name);
                rd.put32(d + 12, iat);
                rd.put32(d + 16, int);
            }
            dirs[13] = (desc, (delayed.len() as u32 + 1) * 32);
        }

        // ---- exports
        if !self.exports.is_empty() {
            let dirp = rd.reserve(40);
            let n = self.exports.len() as u32;
            let funcs = rd.reserve(n as usize * 4);
            let named: Vec<(usize, &String)> =
                self.exports.iter().enumerate().filter_map(|(i, e)| e.name.as_ref().map(|n| (i, n))).collect();
            let names = rd.reserve(named.len() * 4);
            let ords = rd.reserve(named.len() * 2 + 2);
            for (k, (i, nm)) in named.iter().enumerate() {
                let s = rd.cstr(nm);
                rd.put32(names + k as u32 * 4, s);
                let o = (ords - rd.base) as usize + k * 2;
                rd.bytes[o..o + 2].copy_from_slice(&(*i as u16).to_le_bytes());
            }
            let dll = rd.cstr(&self.export_dll_name);
            let mut fwd_rvas = Vec::new();
            for (i, e) in self.exports.iter().enumerate() {
                if let Some(f) = &e.forwarder {
                    let r = rd.cstr(f);
                    fwd_rvas.push((i, r));
                } else {
                    rd.put32(funcs + i as u32 * 4, e.rva);
                }
            }
            let end = rd.base + rd.bytes.len() as u32;
            for (i, r) in fwd_rvas {
                rd.put32(funcs + i as u32 * 4, r);
            }
            rd.put32(dirp + 4, self.timestamp);
            rd.put32(dirp + 12, dll);
            rd.put32(dirp + 16, 1);
            rd.put32(dirp + 20, n);
            rd.put32(dirp + 24, named.len() as u32);
            rd.put32(dirp + 28, funcs);
            rd.put32(dirp + 32, names);
            rd.put32(dirp + 36, ords);
            dirs[0] = (dirp, end - dirp);
        }

        // ---- debug
        let mut dbg_entries: Vec<(u32, Vec<u8>)> = Vec::new();
        if let Some(p) = &self.pdb_path {
            let mut cv = b"RSDS".to_vec();
            cv.extend((0u8..16).collect::<Vec<_>>());
            cv.extend(1u32.to_le_bytes());
            cv.extend(p.as_bytes());
            cv.push(0);
            dbg_entries.push((2, cv));
        }
        dbg_entries.extend(self.extra_debug.iter().cloned());
        let mut debug_fixups = Vec::new();
        if !dbg_entries.is_empty() {
            let d = rd.reserve(dbg_entries.len() * 28);
            for (i, (kind, data)) in dbg_entries.iter().enumerate() {
                let drva = rd.alloc(data);
                let e = d + i as u32 * 28;
                rd.put32(e + 4, self.timestamp);
                rd.put32(e + 12, *kind);
                rd.put32(e + 16, data.len() as u32);
                rd.put32(e + 20, drva);
                debug_fixups.push((e + 24, drva));
            }
            dirs[6] = (d, dbg_entries.len() as u32 * 28);
        }

        // ---- TLS
        if self.tls_callbacks > 0 {
            let t = rd.reserve(if self.is64 { 40 } else { 24 });
            let cbs = rd.reserve((self.tls_callbacks + 1) * ptr as usize);
            let idx = rd.reserve(4);
            for i in 0..self.tls_callbacks {
                let va = image_base + text_rva as u64 + i as u64;
                if self.is64 { rd.put64(cbs + i as u32 * ptr, va) } else { rd.put32(cbs + i as u32 * ptr, va as u32) }
            }
            let cb_va = image_base + cbs as u64;
            let idx_va = image_base + idx as u64;
            if self.is64 {
                rd.put64(t + 16, idx_va);
                rd.put64(t + 24, cb_va);
            } else {
                rd.put32(t + 8, idx_va as u32);
                rd.put32(t + 12, cb_va as u32);
            }
            dirs[9] = (t, if self.is64 { 40 } else { 24 });
        }

        // ---- load config
        if self.load_config {
            let size: u32 = if self.is64 { 0x94 } else { 0x5c };
            let lc = rd.reserve(size as usize);
            rd.put32(lc, size);
            let cookie = image_base + rdata_rva as u64;
            if self.is64 {
                rd.put64(lc + 0x58, cookie);
                rd.put32(lc + 0x90, 0x100);
            } else {
                rd.put32(lc + 0x3c, cookie as u32);
                rd.put32(lc + 0x40, cookie as u32);
                rd.put32(lc + 0x44, 1);
                rd.put32(lc + 0x58, 0x100);
            }
            dirs[10] = (lc, size);
        }

        // ---- exceptions
        if self.exceptions > 0 {
            let p = rd.reserve(self.exceptions * 12);
            for i in 0..self.exceptions as u32 {
                rd.put32(p + i * 12, text_rva + i);
                rd.put32(p + i * 12 + 4, text_rva + i + 1);
                rd.put32(p + i * 12 + 8, rdata_rva);
            }
            dirs[3] = (p, self.exceptions as u32 * 12);
        }

        // ---- .NET
        if let Some(net) = &self.dotnet {
            let (meta, msize) = build_metadata(net);
            let clr = rd.reserve(72);
            let m = rd.alloc(&meta);
            rd.put32(clr, 72);
            rd.put32(clr + 4, 2 | (5 << 16));
            rd.put32(clr + 8, m);
            rd.put32(clr + 12, msize);
            rd.put32(clr + 16, 1 | 8);
            rd.put32(clr + 20, 0x0600_0001);
            dirs[14] = (clr, 72);
        }
        if rd.bytes.is_empty() {
            rd.reserve(16);
        }

        // ---- resources
        let rdata_vsize = rd.bytes.len() as u32;
        let rsrc_rva = rdata_rva + align(rdata_vsize, SA);
        let rsrc = if self.resources.is_empty() { None } else { Some(build_resources(&self.resources, rsrc_rva)) };
        let after_rsrc = rsrc_rva + rsrc.as_ref().map(|b| align(b.len() as u32, SA)).unwrap_or(0);
        if let Some(b) = &rsrc {
            dirs[2] = (rsrc_rva, b.len() as u32);
        }

        // ---- relocations
        let reloc_rva = after_rsrc;
        let reloc = if self.relocations {
            let mut b = Vec::new();
            b.extend(text_rva.to_le_bytes());
            b.extend(16u32.to_le_bytes());
            let t: u16 = if self.is64 { 10 } else { 3 };
            for o in [0u16, 4, 8] {
                b.extend(((t << 12) | o).to_le_bytes());
            }
            b.extend(0u16.to_le_bytes());
            dirs[5] = (reloc_rva, b.len() as u32);
            Some(b)
        } else {
            None
        };
        let mut next_rva = reloc_rva + reloc.as_ref().map(|b| align(b.len() as u32, SA)).unwrap_or(0);

        // ---- section table
        struct S {
            name: String,
            rva: u32,
            vsize: u32,
            data: Vec<u8>,
            ch: u32,
        }
        let mut secs = vec![
            S { name: ".text".into(), rva: text_rva, vsize: text_vsize, data: code, ch: 0x6000_0020 },
            S { name: ".rdata".into(), rva: rdata_rva, vsize: rdata_vsize, data: rd.bytes.clone(), ch: 0x4000_0040 },
        ];
        if let Some(b) = rsrc {
            secs.push(S { name: ".rsrc".into(), rva: rsrc_rva, vsize: b.len() as u32, data: b, ch: 0x4000_0040 });
        }
        if let Some(b) = reloc {
            secs.push(S { name: ".reloc".into(), rva: reloc_rva, vsize: b.len() as u32, data: b, ch: 0x4200_0040 });
        }
        for x in &self.extra_sections {
            let vs = x.virtual_size.unwrap_or(x.data.len().max(1) as u32);
            secs.push(S { name: x.name.clone(), rva: next_rva, vsize: vs, data: x.data.clone(), ch: x.characteristics });
            next_rva += align(vs.max(x.data.len() as u32).max(1), SA);
        }
        let size_of_image = secs.iter().map(|s| s.rva + align(s.vsize.max(s.data.len() as u32).max(1), SA)).max().unwrap_or(SA);

        // ---- headers
        let mut out = vec![0u8; 0x40];
        out[0] = b'M';
        out[1] = b'Z';
        out[2..4].copy_from_slice(&0x90u16.to_le_bytes());
        out[4..6].copy_from_slice(&3u16.to_le_bytes());
        out[8..10].copy_from_slice(&4u16.to_le_bytes());
        out[0x18..0x1a].copy_from_slice(&0x40u16.to_le_bytes());
        let mut stub = vec![0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21];
        stub.extend(self.stub_message.as_bytes());
        stub.extend(b"\r\r\n$");
        while stub.len() % 8 != 0 {
            stub.push(0);
        }
        out.extend(&stub);
        if !self.rich.is_empty() {
            let dans = out.len();
            let mut clear: Vec<u32> = vec![0x536e_6144, 0, 0, 0];
            for (p, b, c) in &self.rich {
                clear.push(((*p as u32) << 16) | *b as u32);
                clear.push(*c);
            }
            // checksum
            let mut csum: u32 = dans as u32;
            for (i, &byte) in out.iter().enumerate().take(dans) {
                if (0x3c..0x40).contains(&i) {
                    continue;
                }
                csum = csum.wrapping_add((byte as u32).rotate_left(i as u32 & 31));
            }
            for (p, b, c) in &self.rich {
                csum = csum.wrapping_add((((*p as u32) << 16) | *b as u32).rotate_left(*c & 31));
            }
            for v in clear {
                out.extend((v ^ csum).to_le_bytes());
            }
            out.extend(b"Rich");
            out.extend(csum.to_le_bytes());
            while !out.len().is_multiple_of(16) {
                out.push(0);
            }
        }
        let lfanew = out.len() as u32;
        out[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        out.extend(b"PE\0\0");
        let machine = self.machine.unwrap_or(if self.is64 { 0x8664 } else { 0x14c });
        let opt_size: u16 = if self.is64 { 240 } else { 224 };
        let mut ch: u16 = 0x0002 | if self.is64 { 0x20 } else { 0x100 };
        if self.dll {
            ch |= 0x2000;
        }
        out.extend(machine.to_le_bytes());
        out.extend((secs.len() as u16).to_le_bytes());
        out.extend(self.timestamp.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(opt_size.to_le_bytes());
        out.extend(ch.to_le_bytes());
        let opt_start = out.len();
        let headers_size = align(opt_start as u32 + opt_size as u32 + secs.len() as u32 * 40, FA).max(0x400);
        let ep = self.entry_offset_in_text.map(|o| text_rva + o).unwrap_or(0);
        out.extend((if self.is64 { 0x20bu16 } else { 0x10b }).to_le_bytes());
        out.extend([14u8, 30]);
        out.extend(align(text_vsize, FA).to_le_bytes());
        out.extend(0x1000u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(ep.to_le_bytes());
        out.extend(text_rva.to_le_bytes());
        if self.is64 {
            out.extend(image_base.to_le_bytes());
        } else {
            out.extend(rdata_rva.to_le_bytes());
            out.extend((image_base as u32).to_le_bytes());
        }
        out.extend(SA.to_le_bytes());
        out.extend(FA.to_le_bytes());
        for v in [6u16, 0, 0, 0, 6, 0] {
            out.extend(v.to_le_bytes());
        }
        out.extend(0u32.to_le_bytes());
        out.extend(size_of_image.to_le_bytes());
        out.extend(headers_size.to_le_bytes());
        out.extend(0u32.to_le_bytes()); // checksum
        out.extend(self.subsystem.to_le_bytes());
        out.extend(self.dll_characteristics.to_le_bytes());
        if self.is64 {
            for v in [0x100000u64, 0x1000, 0x100000, 0x1000] {
                out.extend(v.to_le_bytes());
            }
        } else {
            for v in [0x100000u32, 0x1000, 0x100000, 0x1000] {
                out.extend(v.to_le_bytes());
            }
        }
        out.extend(0u32.to_le_bytes());
        out.extend(16u32.to_le_bytes());
        let dd_off = out.len();
        for (r, s) in dirs {
            out.extend(r.to_le_bytes());
            out.extend(s.to_le_bytes());
        }
        // section headers
        let mut raw = headers_size;
        let mut raw_ptrs = Vec::new();
        for s in &secs {
            let mut name = [0u8; 8];
            for (i, b) in s.name.bytes().take(8).enumerate() {
                name[i] = b;
            }
            out.extend(name);
            out.extend(s.vsize.to_le_bytes());
            out.extend(s.rva.to_le_bytes());
            let rs = align(s.data.len() as u32, FA);
            out.extend(rs.to_le_bytes());
            out.extend((if rs == 0 { 0 } else { raw }).to_le_bytes());
            out.extend([0u8; 12]);
            out.extend(s.ch.to_le_bytes());
            raw_ptrs.push(raw);
            raw += rs;
        }
        out.resize(headers_size as usize, 0);
        for (i, s) in secs.iter().enumerate() {
            let rs = align(s.data.len() as u32, FA) as usize;
            if rs == 0 {
                continue;
            }
            let start = raw_ptrs[i] as usize;
            out.resize(start, 0);
            out.extend(&s.data);
            out.resize(start + rs, 0);
        }
        // patch debug PointerToRawData
        for (field_rva, data_rva) in debug_fixups {
            let rdata_raw = raw_ptrs[1];
            let fo = (rdata_raw + field_rva - rdata_rva) as usize;
            let v = rdata_raw + data_rva - rdata_rva;
            out[fo..fo + 4].copy_from_slice(&v.to_le_bytes());
        }
        out.extend(&self.overlay);
        if let Some(cert) = &self.certificate {
            while !out.len().is_multiple_of(8) {
                out.push(0);
            }
            let off = out.len() as u32;
            let len = (cert.len() + 8) as u32;
            out.extend(len.to_le_bytes());
            out.extend(0x0200u16.to_le_bytes());
            out.extend(2u16.to_le_bytes());
            out.extend(cert);
            while !out.len().is_multiple_of(8) {
                out.push(0);
            }
            let total = out.len() as u32 - off;
            let o = dd_off + 4 * 8;
            out[o..o + 4].copy_from_slice(&off.to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&total.to_le_bytes());
        }
        if self.fix_checksum {
            let off = opt_start + 64;
            let c = crate::patch::compute_checksum(&out, off);
            out[off..off + 4].copy_from_slice(&c.to_le_bytes());
        }
        out
    }
}

fn build_resources(res: &[Resource], base_rva: u32) -> Vec<u8> {
    // Group by type -> name -> lang (insertion order, named entries first as required).
    use std::collections::BTreeMap;
    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    enum K {
        N(String),
        I(u16),
    }
    let key = |k: &ResKey| match k {
        ResKey::Id(i) => K::I(*i),
        ResKey::Name(s) => K::N(s.clone()),
    };
    let mut tree: BTreeMap<K, BTreeMap<K, Vec<(u16, usize)>>> = BTreeMap::new();
    for (i, r) in res.iter().enumerate() {
        tree.entry(key(&r.type_id)).or_default().entry(key(&r.name)).or_default().push((r.lang, i));
    }
    // Sizes: directories first, then data entries, then strings, then data.
    let dir_size = |n: usize| 16 + n * 8;
    let mut size = dir_size(tree.len());
    for names in tree.values() {
        size += dir_size(names.len());
        for langs in names.values() {
            size += dir_size(langs.len());
        }
    }
    let data_entries_off = size;
    size += res.len() * 16;
    let mut strings: Vec<u8> = Vec::new();
    let strings_off = size;
    let mut name_off = std::collections::HashMap::new();
    for (t, names) in &tree {
        for k in std::iter::once(t).chain(names.keys()) {
            if let K::N(s) = k
                && !name_off.contains_key(s)
            {
                name_off.insert(s.clone(), strings_off + strings.len());
                strings.extend((s.encode_utf16().count() as u16).to_le_bytes());
                strings.extend(utf16(s));
            }
        }
    }
    let mut data_off = align((strings_off + strings.len()) as u32, 8) as usize;
    let mut data_pos = Vec::new();
    for r in res {
        data_pos.push(data_off);
        data_off = align((data_off + r.data.len()) as u32, 8) as usize;
    }
    let mut out = vec![0u8; data_off];
    let w32 = |out: &mut Vec<u8>, o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let w16 = |out: &mut Vec<u8>, o: usize, v: u16| out[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let name_field = |k: &K| -> u32 {
        match k {
            K::I(i) => *i as u32,
            K::N(s) => 0x8000_0000 | name_off[s] as u32,
        }
    };
    let count = |m: &[&K]| (m.iter().filter(|k| matches!(k, K::N(_))).count(), m.iter().filter(|k| matches!(k, K::I(_))).count());
    let mut cursor = dir_size(tree.len());
    let tkeys: Vec<&K> = tree.keys().collect();
    let (n, i) = count(&tkeys);
    w16(&mut out, 12, n as u16);
    w16(&mut out, 14, i as u16);
    let mut de_index = 0usize;
    let mut entry_of_res = vec![0usize; res.len()];
    for (ti, (t, names)) in tree.iter().enumerate() {
        let tdir = cursor;
        w32(&mut out, 16 + ti * 8, name_field(t));
        w32(&mut out, 16 + ti * 8 + 4, 0x8000_0000 | tdir as u32);
        let nkeys: Vec<&K> = names.keys().collect();
        let (n, i) = count(&nkeys);
        w16(&mut out, tdir + 12, n as u16);
        w16(&mut out, tdir + 14, i as u16);
        cursor += dir_size(names.len());
        for (ni, (nm, langs)) in names.iter().enumerate() {
            let ndir = cursor;
            w32(&mut out, tdir + 16 + ni * 8, name_field(nm));
            w32(&mut out, tdir + 16 + ni * 8 + 4, 0x8000_0000 | ndir as u32);
            w16(&mut out, ndir + 14, langs.len() as u16);
            cursor += dir_size(langs.len());
            for (li, (lang, ri)) in langs.iter().enumerate() {
                let de = data_entries_off + de_index * 16;
                entry_of_res[*ri] = de;
                de_index += 1;
                w32(&mut out, ndir + 16 + li * 8, *lang as u32);
                w32(&mut out, ndir + 16 + li * 8 + 4, de as u32);
            }
        }
    }
    out[strings_off..strings_off + strings.len()].copy_from_slice(&strings);
    for (ri, r) in res.iter().enumerate() {
        let de = entry_of_res[ri];
        w32(&mut out, de, base_rva + data_pos[ri] as u32);
        w32(&mut out, de + 4, r.data.len() as u32);
        w32(&mut out, de + 8, 1252);
        out[data_pos[ri]..data_pos[ri] + r.data.len()].copy_from_slice(&r.data);
    }
    out
}

fn build_metadata(n: &DotNetSpec) -> (Vec<u8>, u32) {
    // heaps
    let mut strings = vec![0u8];
    let mut sidx = std::collections::HashMap::new();
    let mut s = |v: &str, strings: &mut Vec<u8>| -> u16 {
        if v.is_empty() {
            return 0;
        }
        *sidx.entry(v.to_string()).or_insert_with(|| {
            let i = strings.len() as u16;
            strings.extend(v.as_bytes());
            strings.push(0);
            i
        })
    };
    let mut blob = vec![0u8];
    let mut guid = Vec::new();
    guid.extend((1u8..=16).collect::<Vec<_>>());
    let mut us = vec![0u8];
    for u in &n.user_strings {
        let b = utf16(u);
        us.push((b.len() + 1) as u8);
        us.extend(b);
        us.push(0);
    }
    // tables
    let mut rows = [0u32; 64];
    let mut tbl: Vec<u8> = Vec::new();
    // Module
    rows[0] = 1;
    let mn = s(&n.module, &mut strings);
    let mut module = vec![0, 0];
    module.extend(mn.to_le_bytes());
    module.extend(1u16.to_le_bytes());
    module.extend([0, 0, 0, 0]);
    // TypeRef: ResolutionScope(2) Name Namespace
    let mut typeref = Vec::new();
    let mut trs: Vec<(String, String)> = n.type_refs.clone();
    if n.guid_attribute.is_some() {
        trs.push(("System.Runtime.InteropServices".into(), "GuidAttribute".into()));
    }
    for (ns, name) in &trs {
        typeref.extend(((1u16 << 2) | 2).to_le_bytes());
        typeref.extend(s(name, &mut strings).to_le_bytes());
        typeref.extend(s(ns, &mut strings).to_le_bytes());
    }
    rows[1] = trs.len() as u32;
    // MemberRef: Parent(MemberRefParent, 3 bits, TypeRef=1) Name Sig
    let mut memberref = Vec::new();
    let mut mrs = n.member_refs.clone();
    if n.guid_attribute.is_some() {
        mrs.push((trs.len(), ".ctor".into()));
    }
    for (t, name) in &mrs {
        memberref.extend((((*t as u16) << 3) | 1).to_le_bytes());
        memberref.extend(s(name, &mut strings).to_le_bytes());
        memberref.extend(0u16.to_le_bytes());
    }
    rows[10] = mrs.len() as u32;
    // CustomAttribute: Parent(HasCustomAttribute,5 bits; Assembly=14) Type(CustomAttributeType,3 bits; MemberRef=3) Value
    let mut ca = Vec::new();
    if let Some(g) = &n.guid_attribute {
        let mut val = vec![1u8, 0, g.len() as u8];
        val.extend(g.as_bytes());
        val.extend([0, 0]);
        let bi = blob.len() as u16;
        blob.push(val.len() as u8);
        blob.extend(val);
        ca.extend(((1u16 << 5) | 14).to_le_bytes());
        ca.extend(((mrs.len() as u16) << 3 | 3).to_le_bytes());
        ca.extend(bi.to_le_bytes());
        rows[12] = 1;
    }
    // ModuleRef
    let mut moduleref = Vec::new();
    for m in &n.module_refs {
        moduleref.extend(s(m, &mut strings).to_le_bytes());
    }
    rows[26] = n.module_refs.len() as u32;
    // ImplMap: flags, MemberForwarded(1 bit; MethodDef=1), name, scope
    let mut implmap = Vec::new();
    for (name, scope) in &n.impl_maps {
        implmap.extend(0u16.to_le_bytes());
        implmap.extend(((1u16 << 1) | 1).to_le_bytes());
        implmap.extend(s(name, &mut strings).to_le_bytes());
        implmap.extend((*scope as u16).to_le_bytes());
    }
    rows[28] = n.impl_maps.len() as u32;
    // Assembly
    let mut asm = Vec::new();
    if let Some(a) = &n.assembly {
        asm.extend(0x8004u32.to_le_bytes());
        for v in [1u16, 2, 3, 4] {
            asm.extend(v.to_le_bytes());
        }
        asm.extend(0u32.to_le_bytes());
        asm.extend(0u16.to_le_bytes());
        asm.extend(s(a, &mut strings).to_le_bytes());
        asm.extend(0u16.to_le_bytes());
        rows[32] = 1;
    }
    if n.unknown_table {
        rows[50] = 3;
    }
    let mut valid: u64 = 0;
    for (i, r) in rows.iter().enumerate() {
        if *r > 0 {
            valid |= 1 << i;
        }
    }
    tbl.extend(0u32.to_le_bytes());
    tbl.extend([2u8, 0, 0, 1]);
    tbl.extend(valid.to_le_bytes());
    tbl.extend(0u64.to_le_bytes());
    for r in rows.iter().filter(|r| **r > 0) {
        tbl.extend(r.to_le_bytes());
    }
    for part in [&module, &typeref, &memberref, &ca, &moduleref, &implmap, &asm] {
        tbl.extend(part.iter());
    }
    let pad = |v: &mut Vec<u8>| {
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
    };
    for v in [&mut tbl, &mut strings, &mut us, &mut guid, &mut blob] {
        pad(v);
    }
    let mut streams: Vec<(&str, Vec<u8>)> = vec![("#~", tbl), ("#Strings", strings), ("#US", us), ("#GUID", guid), ("#Blob", blob)];
    if let Some(x) = &n.extra_stream {
        streams.push((x.as_str(), vec![0xcc; 8]));
    }
    let version = b"v4.0.30319\0\0";
    let mut hdr = Vec::new();
    hdr.extend(0x424A_5342u32.to_le_bytes());
    hdr.extend(1u16.to_le_bytes());
    hdr.extend(1u16.to_le_bytes());
    hdr.extend(0u32.to_le_bytes());
    hdr.extend((version.len() as u32).to_le_bytes());
    hdr.extend(version);
    hdr.extend(0u16.to_le_bytes());
    hdr.extend((streams.len() as u16).to_le_bytes());
    let headers_len: usize = streams.iter().map(|(n, _)| 8 + ((n.len() + 1 + 3) & !3)).sum();
    let mut off = hdr.len() + headers_len;
    let mut body: Vec<u8> = Vec::new();
    for (name, data) in &streams {
        hdr.extend((off as u32).to_le_bytes());
        hdr.extend((data.len() as u32).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        nb.push(0);
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        hdr.extend(nb);
        off += data.len();
        body.extend(data);
    }
    hdr.extend(body);
    let len = hdr.len() as u32;
    (hdr, len)
}
