//! Tabular views of an analysis: one `Table` per pestudio tree node.
//! The GUI renders these tables and the XML report serialises them, so both stay in sync.

use crate::model::*;
use crate::util::{self, bytes_hex, bytes_text, entropy, format_stamp, format_utc, ratio};
use pe_db::Knowledge;
use pe_parser::debug::{DebugInfo, format_guid};
use pe_parser::dotnet::{TABLE_NAMES, clr_flags};
use pe_parser::headers::{DIRECTORY_NAMES, dll_characteristics, file_characteristics, machine_name, os_name, subsystem_name};
use pe_parser::reader::Reader;
use pe_parser::resource_content::{self, Manifest};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Row {
    pub cells: Vec<String>,
    pub flag: bool,
    pub severity: Option<u8>,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub jump: Option<ItemType>,
    pub url: Option<String>,
    /// File range that can be dumped (offset, size).
    pub dump: Option<(u64, u64)>,
    /// Stable identifier used by context actions.
    pub key: String,
}

impl Row {
    pub fn new(cells: Vec<String>) -> Self {
        Row { cells, ..Default::default() }
    }

    pub fn kv(k: &str, v: impl Into<String>) -> Self {
        Row::new(vec![k.to_string(), v.into()])
    }

    fn flag(mut self, f: bool) -> Self {
        self.flag = f;
        self
    }

    fn key(mut self, k: impl Into<String>) -> Self {
        self.key = k.into();
        self
    }

    fn dump(mut self, off: u64, size: u64) -> Self {
        self.dump = Some((off, size));
        self
    }

    fn url(mut self, u: impl Into<String>) -> Self {
        self.url = Some(u.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub item: Option<ItemType>,
    pub columns: Vec<String>,
    pub rows: Vec<Row>,
    /// Message shown instead of rows (n/a, disabled, …).
    pub note: Option<String>,
}

impl Table {
    fn new(item: ItemType, cols: &[&str]) -> Self {
        Table { item: Some(item), columns: cols.iter().map(|c| c.to_string()).collect(), ..Default::default() }
    }

    fn props(item: ItemType) -> Self {
        Table::new(item, &["property", "value"])
    }

    fn na(item: ItemType, msg: &str) -> Self {
        let mut t = Table::props(item);
        t.note = Some(msg.to_string());
        t
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Sort by a column (numeric aware).
    pub fn sort_by(&mut self, col: usize, ascending: bool) {
        fn num(s: &str) -> Option<f64> {
            let t = s.trim().trim_end_matches('%').trim_end_matches(" bytes");
            let v = match t.strip_prefix("0x") {
                Some(h) => u64::from_str_radix(h, 16).ok().map(|v| v as f64),
                None => t.parse::<f64>().ok(),
            };
            v.filter(|f| f.is_finite())
        }
        // Total order: every numeric cell sorts before every text cell; numbers by value, text
        // case-insensitively. Mixing the two comparisons per pair would not be transitive.
        let key = |r: &Row| -> (u8, f64, String) {
            let c = r.cells.get(col).map(String::as_str).unwrap_or("");
            match num(c) {
                Some(v) => (0, v, String::new()),
                None => (1, 0.0, c.to_ascii_lowercase()),
            }
        };
        let mut keyed: Vec<((u8, f64, String), Row)> = std::mem::take(&mut self.rows).into_iter().map(|r| (key(&r), r)).collect();
        keyed.sort_by(|(a, _), (b, _)| {
            let o = a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)).then_with(|| a.2.cmp(&b.2));
            if ascending { o } else { o.reverse() }
        });
        self.rows = keyed.into_iter().map(|(_, r)| r).collect();
    }

    /// Keep rows where any cell contains `needle` (case insensitive).
    pub fn filter(&mut self, needle: &str) {
        if needle.is_empty() {
            return;
        }
        let n = needle.to_ascii_lowercase();
        self.rows.retain(|r| r.cells.iter().any(|c| c.to_ascii_lowercase().contains(&n)));
    }

    /// Remove duplicate rows (same cells), as with the "show duplicates" switch turned off.
    pub fn dedup(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.rows.retain(|r| seen.insert(r.cells.clone()));
    }

    /// Text rendering of one row joined with `sep` (copy line).
    pub fn line(&self, i: usize, sep: &str) -> String {
        self.rows.get(i).map(|r| r.cells.join(sep)).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct ViewOptions {
    pub epoch: bool,
    pub first_bytes: usize,
    pub uppercase_hashes: bool,
    pub google: bool,
}

impl Default for ViewOptions {
    fn default() -> Self {
        Self { epoch: false, first_bytes: 32, uppercase_hashes: true, google: true }
    }
}

impl ViewOptions {
    pub fn from_settings(k: &Knowledge) -> Self {
        ViewOptions {
            epoch: k.settings.get_bool("stamps", "epoch", false),
            first_bytes: k.settings.get_int("indicators", "bytes", 32).clamp(1, 256) as usize,
            uppercase_hashes: k.settings.get_int("hashes", "case", 1) != 0,
            google: k.settings.get_bool("google", "enable", true),
        }
    }

    fn hash(&self, h: &str) -> String {
        if self.uppercase_hashes { h.to_ascii_uppercase() } else { h.to_ascii_lowercase() }
    }
}

pub fn google_url(q: &str) -> String {
    format!("https://www.google.com/search?q={}", url_encode(q))
}

pub fn url_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut o = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => {
                o.push('%');
                o.push(HEX[(b >> 4) as usize] as char);
                o.push(HEX[(b & 15) as usize] as char);
            }
        }
    }
    o
}

fn yes(b: bool) -> String {
    if b { "x".into() } else { "-".into() }
}

fn hex32(v: u64) -> String {
    format!("0x{v:08X}")
}

fn hex16(v: u64) -> String {
    format!("0x{v:04X}")
}

/// Build the table for one view.
pub fn table(a: &Analysis, k: &Knowledge, data: &[u8], item: ItemType, o: &ViewOptions) -> Table {
    let t = match item {
        ItemType::Image => image(a, data, o),
        ItemType::Footprints => footprints(a, o),
        ItemType::Groups => groups(a),
        ItemType::Indicators => indicators(a, k),
        ItemType::Mitre => mitre(a, k),
        ItemType::Score => score(a, k),
        ItemType::DosStub => dos_stub(a, data, o),
        ItemType::DosHeader => dos_header(a),
        ItemType::RichHeader => rich(a, k),
        ItemType::FileHeader => file_header(a, o),
        ItemType::OptionalHeader => optional_header(a),
        ItemType::Directories => directories(a, o),
        ItemType::Sections => sections(a, o),
        ItemType::Libraries => libraries(a, k),
        ItemType::Imports => imports(a, k),
        ItemType::Exports => exports(a),
        ItemType::Exceptions => exceptions(a),
        ItemType::Certificate => certificate(a, data, o),
        ItemType::Relocations => relocations(a),
        ItemType::Tls => tls(a),
        ItemType::DotNet => dotnet(a, k, data, o),
        ItemType::Resources => resources(a, o),
        ItemType::Version => version(a, data),
        ItemType::Debug => debug(a, data, o),
        ItemType::Strings => strings(a, k),
        ItemType::Manifest => manifest(a, data),
        ItemType::Overlay => overlay(a, k, data, o),
    };
    Table { item: Some(item), ..t }
}

fn need_pe(a: &Analysis, item: ItemType) -> Option<Table> {
    (!a.is_pe()).then(|| Table::na(item, "n/a (not a portable executable)"))
}

fn image(a: &Analysis, data: &[u8], o: &ViewOptions) -> Table {
    let mut t = Table::props(ItemType::Image);
    t.rows.push(Row::kv("file > name", a.file_name.clone()));
    t.rows.push(Row::kv("file > path", a.path.clone()));
    t.rows.push(Row::kv("file > size", format!("{} bytes", a.size)));
    t.rows.push(Row::kv("file > entropy", format!("{:.3}", a.entropy)));
    for (n, h) in [("md5", &a.hashes.md5), ("sha1", &a.hashes.sha1), ("sha256", &a.hashes.sha256)] {
        t.rows.push(Row::kv(n, o.hash(h)).url(google_url(h)).key(format!("hash:{h}")));
    }
    if let Some(h) = &a.hashes_without_overlay {
        t.rows.push(Row::kv("md5 (without overlay)", o.hash(&h.md5)).url(google_url(&h.md5)));
        t.rows.push(Row::kv("sha256 (without overlay)", o.hash(&h.sha256)).url(google_url(&h.sha256)));
    }
    t.rows.push(Row::kv("first-bytes-hex", bytes_hex(data, o.first_bytes)));
    t.rows.push(Row::kv("first-bytes-text", bytes_text(data, o.first_bytes)));
    t.rows.push(Row::kv("cpu", a.cpu.clone()));
    t.rows.push(Row::kv("type", a.file_type.clone()));
    t.rows.push(Row::kv("subsystem", a.subsystem.clone()));
    if let Some(d) = &a.description {
        t.rows.push(Row::kv("description", d.clone()));
    }
    for s in &a.signatures {
        let v = if s.more.is_empty() { s.name.clone() } else { format!("{} ({})", s.name, s.more) };
        t.rows.push(Row::kv("signature", format!("{v} @ {}", s.location)).flag(s.severity <= 2 && s.tool).key(format!("sig:{}", s.name)));
    }
    for e in &a.embedded {
        t.rows.push(
            Row::kv("file > embedded", format!("{} @ {} (0x{:08X})", e.signature, e.location, e.offset)).flag(true).dump(e.offset, e.size),
        );
    }
    if let Some(i) = &a.imphash {
        t.rows
            .push(Row::kv("imphash", i.clone()).url(format!("https://www.virustotal.com/gui/search/imphash:{i}")).key(format!("hash:{i}")));
    }
    for tl in &a.tooling {
        t.rows.push(Row::kv("tooling", tl.clone()));
    }
    if let Some(l) = a.pe.layout.as_ref() {
        if let Some(ep) = &a.pe.entry_point {
            t.rows.push(
                Row::kv("entry-point", format!("0x{:08X} ({})", ep.rva, ep.section.clone().unwrap_or_else(|| "n/a".into())))
                    .jump_to(ItemType::OptionalHeader),
            );
        }
        let sec: u64 = a.sections.iter().map(|s| s.raw_size).sum();
        t.rows.push(Row::kv("file-ratio > sections", format!("{:.2}%", ratio(sec, a.size))).jump_to(ItemType::Sections));
        if let Some(r) = &a.pe.resources {
            t.rows.push(Row::kv("file-ratio > resources", format!("{:.2}%", ratio(r.total_size(), a.size))).jump_to(ItemType::Resources));
        }
        if let Some(ov) = &a.pe.overlay {
            t.rows.push(Row::kv("file-ratio > overlay", format!("{:.2}%", ratio(ov.size, a.size))).jump_to(ItemType::Overlay));
        }
        if let Some(sd) = &a.pe.security {
            t.rows
                .push(Row::kv("file-ratio > certificate", format!("{:.2}%", ratio(sd.size as u64, a.size))).jump_to(ItemType::Certificate));
        }
        if let Some(st) = &a.pe.dos_stub {
            t.rows.push(Row::kv("file-ratio > dos-stub", format!("{:.2}%", ratio(st.size as u64, a.size))).jump_to(ItemType::DosStub));
        }
        let _ = l;
    }
    for s in &a.stamps {
        t.rows.push(Row::kv(&format!("stamp > {}", s.kind), format_stamp(s.value, o.epoch)));
    }
    if a.network_drive {
        t.rows.push(Row::kv("file > location", "network").flag(true));
    }
    if a.removable_drive {
        t.rows.push(Row::kv("file > location", "removable").flag(true));
    }
    t
}

trait Jump {
    fn jump_to(self, t: ItemType) -> Self;
}
impl Jump for Row {
    fn jump_to(mut self, t: ItemType) -> Self {
        self.jump = Some(t);
        self
    }
}

fn footprints(a: &Analysis, o: &ViewOptions) -> Table {
    let mut t = Table::new(ItemType::Footprints, &["item", "location", "type", "footprint", "size"]);
    for f in &a.footprints {
        let mut r = Row::new(vec![f.item.clone(), f.location.clone(), f.hash_type.clone(), o.hash(&f.hash), f.size.to_string()]);
        r.url = Some(if o.google { google_url(&f.hash) } else { format!("https://www.virustotal.com/gui/search/{}", f.hash) });
        r.key = format!("hash:{}", f.hash);
        t.rows.push(r);
    }
    t
}

fn groups(a: &Analysis) -> Table {
    let mut t = Table::new(ItemType::Groups, &["group", "count", "items"]);
    for g in &a.groups {
        let mut r = Row::new(vec![g.name.clone(), g.count.to_string(), g.items.iter().take(24).cloned().collect::<Vec<_>>().join(", ")]);
        r.group = Some(g.id);
        r.jump = Some(ItemType::Imports);
        r.key = format!("group:{}", g.id);
        t.rows.push(r);
    }
    t
}

fn indicators(a: &Analysis, k: &Knowledge) -> Table {
    let mut t = Table::new(ItemType::Indicators, &["indicator", "detail", "level", "id", "technique"]);
    let mut list: Vec<&Indicator> = a.indicators.iter().collect();
    if k.settings.get_bool("indicators", "sort", true) {
        list.sort_by_key(|i| (i.severity, i.id));
    }
    for i in list {
        let mut r = Row::new(vec![
            i.name.clone(),
            i.detail.clone(),
            k.translations.severity_name(i.severity),
            i.id.to_string(),
            i.ti.clone().map(|x| format!("T{x}")).unwrap_or_default(),
        ]);
        r.severity = Some(i.severity);
        r.flag = i.severity == 1;
        r.jump = i.kind;
        r.ti = i.ti.clone();
        r.key = format!("indicator:{}", i.id);
        t.rows.push(r);
    }
    t
}

fn mitre(a: &Analysis, k: &Knowledge) -> Table {
    // `ta` shows the tactic columns, `dup` lists every source (otherwise only the count beyond the first)
    let show_ta = k.settings.get_bool("mitre", "ta", true);
    let dup = k.settings.get_bool("mitre", "dup", true);
    let mut t = if show_ta {
        Table::new(ItemType::Mitre, &["technique", "name", "tactic", "tactic-name", "sources"])
    } else {
        Table::new(ItemType::Mitre, &["technique", "name", "sources"])
    };
    for m in &a.mitre {
        let sources =
            if dup || m.sources.len() < 2 { m.sources.join(", ") } else { format!("{} (+{})", m.sources[0], m.sources.len() - 1) };
        let cells = if show_ta {
            vec![m.technique.clone(), m.technique_name.clone(), m.tactic.clone(), m.tactic_name.clone(), sources]
        } else {
            vec![m.technique.clone(), m.technique_name.clone(), sources]
        };
        let mut r = Row::new(cells);
        r.flag = m.flag;
        r.ti = Some(m.technique.trim_start_matches('T').to_string());
        r.url = Some(if k.mitre.url.is_empty() {
            format!("https://attack.mitre.org/techniques/{}", m.technique)
        } else {
            k.mitre.technique_url(&m.technique)
        });
        r.key = format!("technique:{}", m.technique);
        t.rows.push(r);
    }
    t
}

fn score(a: &Analysis, k: &Knowledge) -> Table {
    let mut t = Table::new(ItemType::Score, &["engine", "result", "detected", "version", "update"]);
    let favorites: Vec<String> = k
        .settings
        .get("score", "favorite")
        .unwrap_or("")
        .split([',', ';'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let Some(s) = &a.score else {
        t.note = Some("n/a (online score not retrieved)".into());
        return t;
    };
    if s.status != "ok" {
        t.note = Some(s.status.clone());
        return t;
    }
    t.rows.push(
        Row::new(vec!["virustotal".into(), format!("{}/{}", s.positives, s.total), String::new(), s.scan_date.clone(), String::new()])
            .url(s.permalink.clone())
            .flag(s.positives > 0),
    );
    let mut engines: Vec<&EngineResult> = s.engines.iter().collect();
    // favourite engines first (stable for the others)
    engines.sort_by_key(|e| !favorites.contains(&e.vendor.to_ascii_lowercase()));
    for e in engines {
        let fav = favorites.contains(&e.vendor.to_ascii_lowercase());
        let name = if fav { format!("{} (favorite)", e.vendor) } else { e.vendor.clone() };
        t.rows.push(
            Row::new(vec![name, e.result.clone(), yes(e.detected), e.version.clone(), e.update.clone()])
                .flag(e.detected)
                .key(format!("engine:{}", e.vendor)),
        );
    }
    t
}

fn dos_stub(a: &Analysis, data: &[u8], o: &ViewOptions) -> Table {
    if let Some(t) = need_pe(a, ItemType::DosStub).filter(|_| a.pe.dos_stub.is_none()) {
        return t;
    }
    let mut t = Table::props(ItemType::DosStub);
    let Some(st) = &a.pe.dos_stub else { return Table::na(ItemType::DosStub, "n/a") };
    let b = &data[(st.offset as usize).min(data.len())..((st.offset + st.size) as usize).min(data.len())];
    t.rows.push(
        Row::kv("location", format!("0x{:08X} - 0x{:08X}", st.offset, st.offset + st.size))
            .dump(st.offset as u64, st.size as u64)
            .key("dos-stub"),
    );
    t.rows.push(Row::kv("size", format!("{} bytes", st.size)));
    t.rows.push(Row::kv("file-ratio", format!("{:.2}%", ratio(st.size as u64, a.size))));
    t.rows
        .push(Row::kv("message", st.message.clone().unwrap_or_else(|| "n/a".into())).flag(a.has_indicator(1260) || a.has_indicator(1274)));
    let h = util::hashes(b);
    t.rows.push(Row::kv("md5", o.hash(&h.md5)).url(google_url(&h.md5)));
    t.rows.push(Row::kv("sha1", o.hash(&h.sha1)).url(google_url(&h.sha1)));
    t.rows.push(Row::kv("sha256", o.hash(&h.sha256)).url(google_url(&h.sha256)));
    t.rows.push(Row::kv("entropy", format!("{:.3}", entropy(b))));
    t.rows.push(Row::kv("first-bytes-hex", bytes_hex(b, o.first_bytes)));
    t.rows.push(Row::kv("first-bytes-text", bytes_text(b, o.first_bytes)));
    t
}

fn dos_header(a: &Analysis) -> Table {
    let Some(d) = &a.pe.dos_header else { return Table::na(ItemType::DosHeader, "n/a") };
    let mut t = Table::props(ItemType::DosHeader);
    for (n, v) in d.fields() {
        let mut r = Row::kv(n, if n == "e_lfanew" { hex32(v as u64) } else { hex16(v as u64) });
        if n == "e_lfanew" {
            r.flag = a.has_indicator(1062);
            r.jump = Some(ItemType::FileHeader);
        }
        t.rows.push(r);
    }
    t
}

fn rich(a: &Analysis, k: &Knowledge) -> Table {
    let Some(r) = &a.pe.rich else { return Table::na(ItemType::RichHeader, "n/a (no rich-header)") };
    let mut t = Table::new(ItemType::RichHeader, &["product-id", "product", "build-id", "count", "tooling"]);
    t.rows.push(
        Row::new(vec!["offset".into(), hex32(r.offset as u64), String::new(), String::new(), String::new()])
            .dump(r.offset as u64, (r.end - r.offset) as u64),
    );
    t.rows.push(
        Row::new(vec![
            "checksum".into(),
            hex32(r.key as u64),
            format!("computed: {}", hex32(r.checksum_computed as u64)),
            if r.checksum_valid() { "valid".into() } else { "invalid".into() },
            String::new(),
        ])
        .flag(!r.checksum_valid()),
    );
    t.rows.push(Row::new(vec!["md5".into(), util::md5_hex(&r.raw_decoded), String::new(), String::new(), String::new()]));
    for e in &r.entries {
        t.rows.push(Row::new(vec![
            hex16(e.prod_id as u64),
            k.rich.product(e.prod_id).unwrap_or("unknown").to_string(),
            e.build.to_string(),
            e.count.to_string(),
            k.rich.tooling(e.build).unwrap_or_default(),
        ]));
    }
    t
}

fn file_header(a: &Analysis, o: &ViewOptions) -> Table {
    let Some(l) = a.pe.layout.as_ref() else { return Table::na(ItemType::FileHeader, "n/a (not a portable executable)") };
    let f = &l.file_header;
    let mut t = Table::props(ItemType::FileHeader);
    t.rows.push(Row::kv("file-header > offset", hex32(f.offset as u64)));
    t.rows.push(Row::kv("machine", format!("{} ({})", machine_name(f.machine), hex16(f.machine as u64))));
    t.rows.push(Row::kv("sections > count", f.number_of_sections.to_string()).jump_to(ItemType::Sections));
    t.rows.push(
        Row::kv("stamp > compiler", format_stamp(f.time_date_stamp, o.epoch)).flag(a.indicator(1321).is_some_and(|i| i.severity == 1)),
    );
    t.rows.push(Row::kv("pointer-symbol-table", hex32(f.pointer_to_symbol_table as u64)));
    t.rows.push(Row::kv("number-of-symbols", f.number_of_symbols.to_string()));
    t.rows.push(Row::kv("size-of-optional-header", format!("{} bytes", f.size_of_optional_header)).flag(a.has_indicator(1005)));
    t.rows.push(Row::kv("characteristics", hex16(f.characteristics as u64)));
    for (bit, name) in file_characteristics::ALL {
        t.rows.push(Row::kv(name, if f.characteristics & bit != 0 { "true" } else { "false" }).key(format!("fh-char:{bit}")));
    }
    t
}

fn optional_header(a: &Analysis) -> Table {
    let Some(l) = a.pe.layout.as_ref() else { return Table::na(ItemType::OptionalHeader, "n/a (not a portable executable)") };
    let h = &l.optional_header;
    let mut t = Table::props(ItemType::OptionalHeader);
    let p = |t: &mut Table, k: &str, v: String| t.rows.push(Row::kv(k, v));
    p(&mut t, "magic", format!("{} ({})", if h.is_64() { "PE+" } else { "PE" }, hex16(h.magic as u64)));
    p(&mut t, "linker > version", format!("{}.{}", h.major_linker_version, h.minor_linker_version));
    t.rows.push(Row::kv("size-of-code", format!("{} bytes", h.size_of_code)).flag(a.has_indicator(1081)));
    p(&mut t, "size-of-initialized-data", format!("{} bytes", h.size_of_initialized_data));
    p(&mut t, "size-of-uninitialized-data", format!("{} bytes", h.size_of_uninitialized_data));
    t.rows.push(
        Row::kv("entry-point", format!("{} ({})", hex32(h.address_of_entry_point as u64), l.section_name_of_rva(h.address_of_entry_point)))
            .flag(a.has_indicator(1034))
            .key("ep"),
    );
    t.rows.push(
        Row::kv("base-of-code", format!("{} ({})", hex32(h.base_of_code as u64), l.section_name_of_rva(h.base_of_code)))
            .flag(a.has_indicator(1082)),
    );
    if let Some(b) = h.base_of_data {
        p(&mut t, "base-of-data", format!("{} ({})", hex32(b as u64), l.section_name_of_rva(b)));
    }
    p(&mut t, "image-base", format!("0x{:X}", h.image_base));
    p(&mut t, "section-alignment", hex32(h.section_alignment as u64));
    t.rows.push(Row::kv("file-alignment", hex32(h.file_alignment as u64)).flag(a.has_indicator(1083)));
    p(
        &mut t,
        "os > version",
        format!("{}.{} ({})", h.major_os_version, h.minor_os_version, os_name(h.major_os_version, h.minor_os_version)),
    );
    p(&mut t, "image > version", format!("{}.{}", h.major_image_version, h.minor_image_version));
    p(&mut t, "subsystem > version", format!("{}.{}", h.major_subsystem_version, h.minor_subsystem_version));
    p(&mut t, "Win32VersionValue", hex32(h.win32_version_value as u64));
    t.rows.push(Row::kv("size-of-image", hex32(h.size_of_image as u64)).flag(a.has_indicator(1084)));
    t.rows.push(Row::kv("size-of-headers", hex32(h.size_of_headers as u64)).flag(a.has_indicator(1085)));
    let real = a.checksum_real.unwrap_or(0);
    t.rows.push(Row::kv("checksum-builtin", hex32(h.checksum as u64)).flag(h.checksum != 0 && h.checksum != real));
    p(&mut t, "checksum-real", hex32(real as u64));
    p(&mut t, "subsystem", subsystem_name(h.subsystem).to_string());
    p(&mut t, "DllCharacteristics", hex16(h.dll_characteristics as u64));
    for (bit, name) in dll_characteristics::ALL {
        t.rows.push(Row::kv(name, if h.dll_characteristics & bit != 0 { "true" } else { "false" }).key(format!("dll-char:{bit}")));
    }
    p(&mut t, "size-of-stack-reserve", format!("0x{:X}", h.size_of_stack_reserve));
    p(&mut t, "size-of-stack-commit", format!("0x{:X}", h.size_of_stack_commit));
    p(&mut t, "size-of-heap-reserve", format!("0x{:X}", h.size_of_heap_reserve));
    p(&mut t, "size-of-heap-commit", format!("0x{:X}", h.size_of_heap_commit));
    p(&mut t, "LoaderFlags", hex32(h.loader_flags as u64));
    t.rows.push(Row::kv("directories", h.number_of_rva_and_sizes.to_string()).flag(a.has_indicator(1211)).jump_to(ItemType::Directories));
    if let Some(lc) = &a.pe.load_config {
        p(&mut t, "load-config > security-cookie (GS)", format!("0x{:X}", lc.security_cookie));
        p(&mut t, "load-config > SEH-table", format!("0x{:X} ({} handlers)", lc.se_handler_table, lc.se_handler_count));
        p(&mut t, "load-config > guard-flags", hex32(lc.guard_flags as u64));
        p(&mut t, "load-config > CFG", (if lc.has_cfg() { "true" } else { "false" }).to_string());
    }
    if let Some(i) = a.indicator(1056) {
        p(&mut t, "security > protection", i.detail.clone());
    }
    t
}

fn directories(a: &Analysis, o: &ViewOptions) -> Table {
    let Some(l) = a.pe.layout.as_ref() else { return Table::na(ItemType::Directories, "n/a (not a portable executable)") };
    let mut t = Table::new(ItemType::Directories, &["name", "address", "size", "location", "file-offset", "status", "stamp"]);
    let stamp_of = |i: usize| -> u32 {
        match i {
            0 => a.pe.exports.as_ref().map(|e| e.time_date_stamp).unwrap_or(0),
            2 => a.pe.resources.as_ref().map(|r| r.time_date_stamp).unwrap_or(0),
            6 => a.pe.debug.first().map(|d| d.time_date_stamp).unwrap_or(0),
            10 => a.pe.load_config.as_ref().map(|d| d.time_date_stamp).unwrap_or(0),
            _ => 0,
        }
    };
    let targets = [
        Some(ItemType::Exports),
        Some(ItemType::Imports),
        Some(ItemType::Resources),
        Some(ItemType::Exceptions),
        Some(ItemType::Certificate),
        Some(ItemType::Relocations),
        Some(ItemType::Debug),
        None,
        None,
        Some(ItemType::Tls),
        Some(ItemType::OptionalHeader),
        Some(ItemType::Libraries),
        Some(ItemType::Imports),
        Some(ItemType::Libraries),
        Some(ItemType::DotNet),
        None,
    ];
    for (i, name) in DIRECTORY_NAMES.iter().enumerate() {
        let d = l.optional_header.data_directories.get(i).copied().unwrap_or_default();
        let status = if i >= l.optional_header.data_directories.len() {
            "missing"
        } else if d.rva == 0 && d.size == 0 {
            "n/a"
        } else if d.rva == 0 || d.size == 0 {
            "empty"
        } else if i == 4 {
            if (d.rva as u64) < a.size { "valid" } else { "invalid" }
        } else if l.rva_to_offset(d.rva).is_some() || (d.rva as u64) < l.optional_header.size_of_image as u64 {
            "valid"
        } else {
            "invalid"
        };
        let loc = if d.rva == 0 {
            "n/a".into()
        } else if i == 4 {
            "file".into()
        } else {
            l.section_name_of_rva(d.rva)
        };
        let fo = if i == 4 { Some(d.rva as usize) } else { l.rva_to_offset(d.rva) };
        let mut r = Row::new(vec![
            name.to_string(),
            hex32(d.rva as u64),
            format!("{} bytes", d.size),
            loc,
            fo.filter(|_| d.rva != 0).map(|v| hex32(v as u64)).unwrap_or_else(|| "n/a".into()),
            status.into(),
            format_stamp(stamp_of(i), o.epoch),
        ]);
        r.flag = matches!(status, "invalid" | "empty") && d.rva != 0;
        r.jump = targets[i];
        if let Some(f) = fo.filter(|_| d.rva != 0 && d.size != 0) {
            r.dump = Some((f as u64, d.size as u64));
        }
        t.rows.push(r);
    }
    t
}

fn sections(a: &Analysis, _o: &ViewOptions) -> Table {
    if let Some(t) = need_pe(a, ItemType::Sections) {
        return t;
    }
    let mut t = Table::new(
        ItemType::Sections,
        &[
            "name",
            "md5",
            "entropy",
            "file-ratio",
            "raw-address",
            "raw-size",
            "virtual-address",
            "virtual-size",
            "characteristics",
            "flags",
            "entry-point",
            "directories",
            "items",
            "file-cave",
        ],
    );
    for s in &a.sections {
        let mut flags = s.flags.iter().map(|f| f.to_string()).collect::<Vec<_>>();
        if s.self_modifying {
            flags.push("self-modifying".into());
        }
        if s.virtualized {
            flags.push("virtual".into());
        }
        let mut r = Row::new(vec![
            if s.nameless { "(nameless)".into() } else { s.name.clone() },
            s.md5.clone(),
            format!("{:.3}", s.entropy),
            format!("{:.2}%", s.file_ratio),
            hex32(s.raw_address),
            hex32(s.raw_size),
            hex32(s.virtual_address as u64),
            hex32(s.virtual_size as u64),
            hex32(s.characteristics as u64),
            flags.join(", "),
            yes(s.entry_point),
            s.directories.join(", "),
            s.embedded.join(", "),
            s.caves.iter().map(|(o, z)| format!("0x{o:08X} ({z} bytes)")).collect::<Vec<_>>().join(", "),
        ]);
        r.flag = !s.standard_name || s.self_modifying || s.duplicate_name || !s.embedded.is_empty();
        r.key = format!("section:{}", s.index);
        r.url = Some(google_url(&s.md5));
        if s.raw_size > 0 {
            r.dump = Some((s.raw_address, s.raw_size));
        }
        t.rows.push(r);
    }
    t
}

fn libraries(a: &Analysis, k: &Knowledge) -> Table {
    if a.libraries.is_empty() {
        return Table::na(ItemType::Libraries, if a.is_pe() { "n/a (no library)" } else { "n/a (not a portable executable)" });
    }
    let mut t =
        Table::new(ItemType::Libraries, &["library", "imports", "type", "flag", "group", "bound", "duplicate", "spoofed", "description"]);
    for l in &a.libraries {
        let mut r = Row::new(vec![
            l.name.clone(),
            l.imports.to_string(),
            l.kind.clone(),
            yes(l.flag),
            l.group.map(|g| k.group_name(g)).unwrap_or_default(),
            yes(l.bound),
            yes(l.duplicate),
            yes(l.spoofed),
            l.description.clone(),
        ]);
        r.flag = l.flag || l.spoofed;
        r.group = l.group;
        r.jump = Some(ItemType::Imports);
        r.url = Some(google_url(&l.name));
        r.key = format!("lib:{}", l.name);
        t.rows.push(r);
    }
    t
}

fn imports(a: &Analysis, k: &Knowledge) -> Table {
    if a.imports.is_empty() {
        return Table::na(ItemType::Imports, if a.is_pe() { "n/a (no import)" } else { "n/a (not a portable executable)" });
    }
    let mut t = Table::new(
        ItemType::Imports,
        &[
            "import",
            "group",
            "technique",
            "type",
            "ordinal",
            "library",
            "flag",
            "deprecated",
            "undocumented",
            "anti-debug",
            "callback",
            "hint",
            "first-thunk-original (INT)",
            "first-thunk (IAT)",
            "map",
            "namespace",
        ],
    );
    if a.pe.imports.truncated {
        t.note = Some(format!("truncated after {} functions", pe_parser::imports::MAX_TOTAL_FUNCTIONS));
    }
    for i in &a.imports {
        let mut r = Row::new(vec![
            i.name.clone(),
            i.group.map(|g| k.group_name(g)).unwrap_or_default(),
            i.ti.clone().map(|x| format!("T{x}")).unwrap_or_default(),
            i.kind.clone(),
            i.ordinal.map(|o| o.to_string()).unwrap_or_else(|| "-".into()),
            i.library.clone(),
            yes(i.flag),
            yes(i.deprecated),
            yes(i.undocumented),
            yes(i.anti_debug),
            yes(i.callback),
            i.hint.map(|h| h.to_string()).unwrap_or_default(),
            if i.kind == "implicit" || i.kind == "delay-loaded" { format!("0x{:X}", i.int_value) } else { String::new() },
            if i.kind == "implicit" || i.kind == "delay-loaded" { format!("0x{:X}", i.iat_value) } else { String::new() },
            i.map.clone().unwrap_or_default(),
            i.namespace.clone().unwrap_or_default(),
        ]);
        r.flag = i.flag || i.mismatch;
        r.group = i.group;
        r.ti = i.ti.clone();
        r.jump = Some(ItemType::Libraries);
        r.url = Some(format!("https://learn.microsoft.com/en-us/search/?terms={}", url_encode(&i.name)));
        r.key = format!("import:{}|{}", i.library, i.name);
        t.rows.push(r);
    }
    t
}

const EXPORTS_TRUNCATED: &str = "truncated: the export directory claims more entries than the file holds";

fn exports(a: &Analysis) -> Table {
    let truncated = a.pe.exports.as_ref().is_some_and(|e| e.truncated);
    if a.exports.is_empty() {
        let note = match &a.pe.exports {
            Some(_) if truncated => EXPORTS_TRUNCATED,
            Some(_) => "empty",
            None => "n/a (no export)",
        };
        return Table::na(ItemType::Exports, note);
    }
    let mut t = Table::new(
        ItemType::Exports,
        &["ordinal", "name", "undecorated", "address", "location", "forwarded", "gap", "anonymous", "duplicate", "entry-point", "flag"],
    );
    if truncated {
        t.note = Some(EXPORTS_TRUNCATED.into());
    }
    if let Some(e) = &a.pe.exports {
        t.rows.push(Row::new(vec![
            "file-name".into(),
            e.dll_name.clone(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]));
    }
    for e in &a.exports {
        let mut r = Row::new(vec![
            e.ordinal.to_string(),
            e.name.clone(),
            if e.undecorated != e.name { e.undecorated.clone() } else { String::new() },
            hex32(e.rva as u64),
            e.location.clone(),
            e.forwarder.clone().unwrap_or_else(|| "-".into()),
            yes(e.gap),
            yes(e.anonymous),
            yes(e.duplicate),
            yes(e.entry_point),
            yes(e.flag),
        ]);
        r.flag = e.flag || e.duplicate || e.entry_point;
        if !e.name.is_empty() {
            r.url = Some(google_url(&e.name));
        }
        r.key = format!("export:{}", e.ordinal);
        t.rows.push(r);
    }
    t
}

fn exceptions(a: &Analysis) -> Table {
    if a.pe.exceptions.is_empty() {
        return Table::na(ItemType::Exceptions, "n/a (no exception)");
    }
    let mut t = Table::new(ItemType::Exceptions, &["address (begin)", "address (end)", "address (unwind)", "location"]);
    let l = a.pe.layout.as_ref();
    for f in &a.pe.exceptions {
        t.rows.push(Row::new(vec![
            hex32(f.begin as u64),
            hex32(f.end as u64),
            hex32(f.unwind as u64),
            l.map(|l| l.section_name_of_rva(f.begin)).unwrap_or_default(),
        ]));
    }
    t
}

fn certificate(a: &Analysis, data: &[u8], o: &ViewOptions) -> Table {
    let Some(sd) = &a.pe.security else { return Table::na(ItemType::Certificate, "n/a (no certificate)") };
    let mut t = Table::props(ItemType::Certificate);
    t.rows.push(
        Row::kv("location", format!("0x{:08X} ({} bytes)", sd.offset, sd.size)).dump(sd.offset as u64, sd.size as u64).key("certificate"),
    );
    t.rows.push(Row::kv("file-ratio", format!("{:.2}%", ratio(sd.size as u64, a.size))));
    let b = Reader::new(data).bytes_clamped(sd.offset as usize, o.first_bytes);
    t.rows.push(Row::kv("first-bytes-hex", bytes_hex(b, o.first_bytes)));
    if sd.not_at_end {
        t.rows.push(Row::kv("data after the certificate", format!("{} bytes", sd.trailing_after_directory)).flag(true));
    }
    if let Some(c) = &a.certificate_check {
        t.rows.push(Row::kv("signature-info", c.message.clone()).flag(c.verified == Some(false)));
    }
    for (i, w) in sd.entries.iter().enumerate() {
        t.rows.push(
            Row::kv(
                "WIN_CERTIFICATE",
                format!(
                    "{} | {} | {} bytes",
                    pe_parser::certificate::cert_revision_name(w.revision),
                    pe_parser::certificate::cert_type_name(w.certificate_type),
                    w.length
                ),
            )
            .dump(w.offset as u64, w.length as u64)
            .key(format!("cert:{i}")),
        );
        if w.tail > 0 {
            t.rows.push(
                Row::kv("tail", format!("{} bytes", w.tail))
                    .flag(true)
                    .dump(w.tail_offset as u64, w.tail as u64)
                    .key(format!("cert-tail:{i}")),
            );
        }
        if w.null_padding > 0 {
            t.rows.push(Row::kv("size-PKCS7-null-padding", format!("{} bytes", w.null_padding)));
        }
        let Some(au) = &w.pkcs7 else { continue };
        t.rows.push(
            Row::kv("size-PKCS7", format!("{} bytes", au.der_size)).dump(w.offset as u64 + 8, au.der_size as u64).key(format!("pkcs7:{i}")),
        );
        t.rows.push(Row::kv("hash-algorithm", au.digest_algorithm.clone()));
        t.rows.push(Row::kv("image-digest", util::hex_upper(&au.image_digest)));
        if au.nested_signatures > 0 {
            t.rows.push(Row::kv("nested-signatures", au.nested_signatures.to_string()));
        }
        if let Some(s) = &au.signer {
            t.rows.push(Row::kv("signer > issued-by", s.issuer.clone()));
            t.rows.push(Row::kv("signer > serial-number", s.serial.clone()));
            t.rows.push(Row::kv("signer > hash-encryption-algorithm", s.encryption_algorithm.clone()));
            if let Some(p) = &s.program_name {
                t.rows.push(Row::kv("program-name", p.clone()));
            }
            if let Some(u) = &s.more_info_url {
                t.rows.push(Row::kv("more-info-url", u.clone()).url(u.clone()));
            }
            if let Some(st) = s.signing_time {
                t.rows.push(Row::kv("stamp > signing", format_utc(st)));
            }
        }
        if let Some(cs) = &au.counter_signer {
            t.rows.push(Row::kv("counter-signer > issued-by", cs.issuer.clone()));
            if let Some(st) = cs.signing_time {
                t.rows.push(Row::kv("counter-signer > stamp > signing", format_utc(st)));
            }
        }
        for (ci, c) in au.certificates.iter().enumerate() {
            let tp = util::sha1_hex(&c.der);
            t.rows.push(
                Row::kv(&format!("certificate[{ci}] > issued-to"), c.subject.clone()).key(format!("x509:{i}:{ci}")).url(google_url(&tp)),
            );
            t.rows.push(Row::kv(&format!("certificate[{ci}] > issued-by"), c.issuer.clone()));
            t.rows.push(Row::kv(&format!("certificate[{ci}] > serial-number"), c.serial.clone()));
            t.rows.push(Row::kv(&format!("certificate[{ci}] > thumbprint"), tp));
            t.rows.push(Row::kv(&format!("certificate[{ci}] > signature-algorithm"), c.signature_algorithm.clone()));
            let expired = c.valid_to.is_some_and(|v| v < util::now_unix());
            t.rows.push(Row::kv(&format!("certificate[{ci}] > valid-from"), c.valid_from.map(format_utc).unwrap_or_default()));
            t.rows.push(
                Row::kv(
                    &format!("certificate[{ci}] > valid-to"),
                    c.valid_to.map(|v| format!("{}{}", format_utc(v), if expired { " (expired)" } else { "" })).unwrap_or_default(),
                )
                .flag(expired),
            );
            if let Some(e) = &c.email {
                t.rows.push(Row::kv(&format!("certificate[{ci}] > email"), e.clone()));
            }
            for u in &c.crl_urls {
                t.rows.push(Row::kv(&format!("certificate[{ci}] > CRL-Distribution-Point"), u.clone()).url(u.clone()));
            }
            if !c.purposes.is_empty() {
                t.rows.push(Row::kv(&format!("certificate[{ci}] > purpose(s)"), c.purposes.join(", ")));
            }
        }
    }
    if let Some(i) = a.indicator(1012) {
        t.rows.push(Row::kv("stamp-compiler > stamp-certificate", i.detail.clone()).flag(true));
    }
    t
}

fn relocations(a: &Analysis) -> Table {
    if a.pe.relocations.is_empty() {
        return Table::na(ItemType::Relocations, "n/a (no relocation)");
    }
    let mut t = Table::new(ItemType::Relocations, &["page", "block-size", "count", "types", "location"]);
    let l = a.pe.layout.as_ref();
    for b in &a.pe.relocations {
        let mut types: Vec<&str> = b.entries.iter().map(|(ty, _)| pe_parser::misc_dirs::relocation_type_name(*ty)).collect();
        types.sort();
        types.dedup();
        t.rows.push(
            Row::new(vec![
                hex32(b.page_rva as u64),
                b.block_size.to_string(),
                b.entries.len().to_string(),
                types.join(", "),
                l.map(|l| l.section_name_of_rva(b.page_rva)).unwrap_or_default(),
            ])
            .dump(b.offset as u64, b.block_size as u64),
        );
    }
    t
}

fn tls(a: &Analysis) -> Table {
    let Some(x) = &a.pe.tls else { return Table::na(ItemType::Tls, "n/a (no thread-local-storage)") };
    let mut t = Table::props(ItemType::Tls);
    t.rows.push(Row::kv("data-begin", format!("0x{:X}", x.start_address_of_raw_data)));
    t.rows.push(Row::kv("data-end", format!("0x{:X}", x.end_address_of_raw_data)));
    t.rows.push(Row::kv("index", format!("0x{:X}", x.address_of_index)));
    t.rows.push(Row::kv("callbacks", format!("0x{:X}", x.address_of_callbacks)));
    t.rows.push(Row::kv("size-of-zero-fill", x.size_of_zero_fill.to_string()));
    t.rows.push(Row::kv("characteristics", hex32(x.characteristics as u64)));
    let l = a.pe.layout.as_ref();
    for (i, cb) in x.callbacks.iter().enumerate() {
        let sec = l.and_then(|l| l.va_to_rva(*cb).map(|r| l.section_name_of_rva(r))).unwrap_or_default();
        t.rows.push(Row::kv(&format!("callback[{i}]"), format!("0x{cb:X} ({sec})")).flag(true));
    }
    t
}

fn dotnet(a: &Analysis, k: &Knowledge, data: &[u8], o: &ViewOptions) -> Table {
    let Some(n) = &a.pe.dotnet else { return Table::na(ItemType::DotNet, "n/a (not a .NET file)") };
    let mut t = Table::props(ItemType::DotNet);
    let h = &n.header;
    t.rows.push(Row::kv("header > runtime-version", format!("{}.{}", h.major_runtime_version, h.minor_runtime_version)));
    t.rows.push(Row::kv("header > flags", hex32(h.flags as u64)));
    for (bit, name) in clr_flags::ALL {
        t.rows.push(Row::kv(&format!("header > {name}"), if h.flags & bit != 0 { "true" } else { "false" }));
    }
    t.rows.push(Row::kv("entry-point (token | address)", hex32(h.entry_point as u64)));
    t.rows.push(Row::kv("resources (size)", format!("{} bytes", h.resources.size)));
    t.rows.push(Row::kv("strong-name-signature (size)", format!("{} bytes", h.strong_name_signature.size)));
    t.rows.push(Row::kv("vtable-fixup-size", format!("{} bytes", h.vtable_fixups.size)));
    t.rows.push(Row::kv("export-address-table-jump (size)", format!("{} bytes", h.export_address_table_jumps.size)));
    t.rows.push(Row::kv(
        "metadata > signature",
        if n.metadata_signature == 0x424A_5342 { "BSJB".into() } else { hex32(n.metadata_signature as u64) },
    ));
    t.rows.push(Row::kv("metadata > version", n.runtime_version.clone()));
    t.rows.push(Row::kv("module > name", n.module_name.clone()));
    if let Some(m) = &n.module_mvid {
        t.rows.push(Row::kv("module > mvid", format_guid(m)));
    }
    if let Some(asm) = &n.assembly {
        t.rows.push(Row::kv(
            "assembly",
            format!("{} {} ({})", asm.name, asm.version, if asm.culture.is_empty() { "neutral" } else { &asm.culture }),
        ));
    }
    if let Some(g) = &n.typelib_id {
        t.rows.push(Row::kv("typelibId", g.clone()).url(format!("https://www.virustotal.com/gui/search/netguid:{g}")));
    }
    for st in &n.streams {
        let b = st.file_offset.map(|f| Reader::new(data).bytes_clamped(f as usize, st.size as usize)).unwrap_or(&[]);
        let flagged = k.settings.streams.iter().find(|x| x.name == st.name).map(|x| x.flag).unwrap_or(true);
        let mut r = Row::kv(
            &format!("stream > {}", st.name),
            format!(
                "offset: 0x{:08X}, size: {} bytes, file-ratio: {:.2}%, md5: {}",
                st.offset,
                st.size,
                ratio(st.size as u64, a.size),
                o.hash(&util::md5_hex(b))
            ),
        );
        r.flag = flagged;
        if let Some(f) = st.file_offset {
            r.dump = Some((f as u64, st.size as u64));
        }
        r.key = format!("stream:{}", st.name);
        t.rows.push(r);
    }
    for (i, name) in TABLE_NAMES.iter().enumerate() {
        let c = n.row_count(i);
        if c > 0 {
            let desc = k
                .settings
                .tables
                .iter()
                .find(|x| x.id as usize == i)
                .map(|x| x.desc.clone())
                .filter(|d| d != "n/a" && !d.is_empty())
                .unwrap_or_default();
            t.rows.push(Row::kv(
                &format!("table > {name}"),
                if desc.is_empty() { format!("{c} rows") } else { format!("{c} rows ({desc})") },
            ));
        }
    }
    for r in &n.assembly_refs {
        t.rows.push(Row::kv("assembly-ref", format!("{} {}", r.name, r.version)));
    }
    for r in &n.manifest_resources {
        t.rows.push(Row::kv("manifest-resource", r.name.clone()));
    }
    let mut namespaces: Vec<String> = n.type_refs.iter().map(|t| t.namespace.clone()).filter(|s| !s.is_empty()).collect();
    namespaces.sort();
    namespaces.dedup();
    for ns in namespaces {
        let def = k.namespaces.lookup(&ns);
        let kind = match def {
            Some(d) if d.system => "namespace (system)",
            Some(_) => "namespace (custom)",
            None if ns.starts_with("System") || ns.starts_with("Microsoft") => "namespace (system)",
            None => "namespace (custom)",
        };
        let mut r = Row::kv(kind, ns.clone()).key(format!("ns:{ns}"));
        r.flag = def.is_some_and(|d| d.flag);
        r.group = def.and_then(|d| d.group);
        r.ti = def.and_then(|d| d.ti.clone());
        t.rows.push(r);
    }
    t
}

fn resources(a: &Analysis, o: &ViewOptions) -> Table {
    if a.resources.is_empty() {
        return Table::na(ItemType::Resources, "n/a (no resource)");
    }
    let mut t = Table::new(
        ItemType::Resources,
        &[
            "type",
            "name",
            "file-offset",
            "signature",
            "size",
            "file-ratio",
            "md5",
            "entropy",
            "language",
            "code-page",
            "first-bytes-hex",
            "first-bytes-text",
        ],
    );
    for (i, r) in a.resources.iter().enumerate() {
        let mut row = Row::new(vec![
            r.type_name.clone(),
            r.name.clone(),
            r.offset.map(|v| hex32(v as u64)).unwrap_or_else(|| "n/a".into()),
            r.signature.clone(),
            r.size.to_string(),
            format!("{:.2}%", r.file_ratio),
            o.hash(&r.md5),
            format!("{:.3}", r.entropy),
            format!("{} ({})", r.language_name, hex16(r.language as u64)),
            r.code_page.to_string(),
            r.first_bytes_hex.split(' ').take(o.first_bytes).collect::<Vec<_>>().join(" "),
            r.first_bytes_text.chars().take(o.first_bytes).collect(),
        ]);
        row.flag = r.severity <= 2 || r.language_flag;
        row.severity = Some(r.severity);
        row.key = format!("resource:{i}");
        row.url = Some(google_url(&r.md5));
        if let Some(off) = r.offset {
            row.dump = Some((off as u64, r.size as u64));
        }
        t.rows.push(row);
    }
    t
}

/// Decoded content of a resource (string tables, messages, dialogs, menus, icons, version, manifest, text).
pub fn resource_content(a: &Analysis, data: &[u8], index: usize) -> Vec<String> {
    let Some(res) = a.pe.resources.as_ref() else { return Vec::new() };
    let Some(e) = res.entries.get(index) else { return Vec::new() };
    let b = e.data(&Reader::new(data));
    match e.type_id.id() {
        Some(6) => {
            resource_content::parse_string_table(b, e.name.id().unwrap_or(1)).into_iter().map(|(i, s)| format!("{i}: {s}")).collect()
        }
        Some(11) => resource_content::parse_message_table(b).into_iter().map(|(i, s)| format!("0x{i:08X}: {s}")).collect(),
        Some(4) => resource_content::parse_menu(b),
        Some(5) => resource_content::parse_dialog(b)
            .map(|d| {
                let mut v = vec![format!("caption: {}", d.caption), format!("font: {}", d.font)];
                v.extend(d.controls.into_iter().map(|c| format!("control: {c}")));
                v
            })
            .unwrap_or_default(),
        Some(14) | Some(12) => resource_content::parse_group_icon(b, e.type_id.id() == Some(12))
            .into_iter()
            .map(|g| format!("{}x{} {}bpp id={} ({} bytes)", g.width, g.height, g.bit_count, g.id, g.bytes_in_res))
            .collect(),
        Some(16) => resource_content::VersionInfo::parse(b)
            .map(|v| v.strings.into_iter().map(|(_, k, v)| format!("{k}: {v}")).collect())
            .unwrap_or_default(),
        Some(24) | Some(23) => resource_content::decode_text(b).lines().map(str::to_string).collect(),
        _ => {
            if crate::sigscan::builtin_magic(b) == Some("Text") {
                resource_content::decode_text(b).lines().take(500).map(str::to_string).collect()
            } else {
                vec![bytes_hex(b, 64), bytes_text(b, 64)]
            }
        }
    }
}

fn version(a: &Analysis, data: &[u8]) -> Table {
    let Some(v) = a.pe.version_info(data) else { return Table::na(ItemType::Version, "n/a (no version)") };
    let mut t = Table::props(ItemType::Version);
    if let Some(f) = &v.fixed {
        t.rows.push(Row::kv("FileVersion (fixed)", f.file_version()));
        t.rows.push(Row::kv("ProductVersion (fixed)", f.product_version()));
        t.rows.push(Row::kv("file-flags", f.flag_names().join(", ")));
        t.rows.push(Row::kv("file-os", f.os_name()));
        t.rows.push(Row::kv("file-type", f.type_name()));
        t.rows.push(Row::kv("file-subtype", f.subtype_name()));
    }
    for (lang, k, val) in &v.strings {
        let mut r = Row::kv(k, val.clone());
        r.flag = (k == "OriginalFilename" && a.has_indicator(1487)) || (k == "InternalName" && a.has_indicator(1423));
        r.url = Some(google_url(val));
        r.key = format!("version:{lang}:{k}");
        t.rows.push(r);
    }
    for (l, c) in &v.translations {
        t.rows.push(Row::kv("Translation", format!("{} | {}", hex16(*l as u64), c)));
    }
    if let Some(e) = a.pe.resources.as_ref().and_then(|r| r.of_type(16).next()) {
        let b = e.data(&Reader::new(data));
        let h = util::hashes(b);
        t.rows.push(Row::kv("md5", h.md5.clone()).url(google_url(&h.md5)));
        t.rows.push(Row::kv("sha256", h.sha256.clone()).url(google_url(&h.sha256)));
        t.rows.push(Row::kv("size", format!("{} bytes", e.size)).flag(a.has_indicator(1486)));
    }
    t
}

fn debug(a: &Analysis, data: &[u8], o: &ViewOptions) -> Table {
    if a.pe.debug.is_empty() {
        return Table::na(ItemType::Debug, "n/a (no debug)");
    }
    let mut t = Table::new(ItemType::Debug, &["type", "stamp", "size", "file-ratio", "address", "file-offset", "detail", "md5"]);
    for (i, d) in a.pe.debug.iter().enumerate() {
        let detail = match &d.info {
            DebugInfo::Rsds { guid, age, path } => format!("RSDS | GUID: {} | age: {} | file: {}", format_guid(guid), age, path),
            DebugInfo::Nb10 { signature, age, path, .. } => format!("NB10 | signature: 0x{signature:08X} | age: {age} | file: {path}"),
            DebugInfo::CodeViewOther { signature } => signature.clone(),
            DebugInfo::Misc { text, .. } => text.clone(),
            DebugInfo::Pogo { signature, entries } => format!(
                "{signature} | {} entries ({})",
                entries.len(),
                entries.iter().take(6).map(|e| e.2.clone()).collect::<Vec<_>>().join(", ")
            ),
            DebugInfo::VcFeature { pre_vc11, c_cpp, gs, sdl, guard_n } => {
                format!("pre-VC11: {pre_vc11}, C/C++: {c_cpp}, /GS: {gs}, /sdl: {sdl}, guardN: {guard_n}")
            }
            DebugInfo::ExDllCharacteristics { flags } => {
                let names: Vec<&str> = pe_parser::debug::ex_dll::ALL.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).collect();
                format!("0x{flags:08X} ({})", names.join(", "))
            }
            DebugInfo::Repro { hash } => util::hex_upper(hash),
            DebugInfo::PdbChecksum { algorithm, checksum } => format!("{algorithm}: {}", util::hex_upper(checksum)),
            DebugInfo::None => String::new(),
        };
        let b = d.data(&Reader::new(data));
        let mut r = Row::new(vec![
            d.type_name().to_string(),
            format_stamp(d.time_date_stamp, o.epoch),
            d.size_of_data.to_string(),
            format!("{:.2}%", ratio(d.size_of_data as u64, a.size)),
            hex32(d.address_of_raw_data as u64),
            hex32(d.pointer_to_raw_data as u64),
            detail,
            o.hash(&util::md5_hex(b)),
        ]);
        r.flag =
            d.time_date_stamp != 0 && a.indicators.iter().any(|x| x.id == 1074 && x.detail == format_stamp(d.time_date_stamp, o.epoch));
        if d.size_of_data > 0 {
            r.dump = Some((d.pointer_to_raw_data as u64, d.size_of_data as u64));
        }
        r.key = format!("debug:{i}");
        t.rows.push(r);
    }
    t
}

fn strings(a: &Analysis, k: &Knowledge) -> Table {
    if a.strings_skipped {
        return Table::na(ItemType::Strings, "strings disabled (file size limit)");
    }
    let mut t = Table::new(ItemType::Strings, &["type", "size", "file-offset", "location", "label", "group", "technique", "flag", "value"]);
    t.rows.reserve(a.strings.len());
    let mut group_names: std::collections::HashMap<u8, String> = std::collections::HashMap::new();
    for (i, s) in a.strings.iter().enumerate() {
        let mut r = Row::new(vec![
            s.kind.name().into(),
            s.size.to_string(),
            if s.kind == StringKind::DotNetUser { "n/a".into() } else { hex32(s.offset) },
            s.location.clone(),
            s.hint.clone().unwrap_or_default(),
            s.group.map(|g| group_names.entry(g).or_insert_with(|| k.group_name(g)).clone()).unwrap_or_default(),
            s.ti.as_ref().map(|x| format!("T{x}")).unwrap_or_default(),
            yes(s.flag),
            s.value.clone(),
        ]);
        r.flag = s.flag;
        r.group = s.group;
        r.ti = s.ti.clone();
        r.url = Some(google_url(&s.value));
        r.key = format!("string:{i}");
        t.rows.push(r);
    }
    t
}

fn manifest(a: &Analysis, data: &[u8]) -> Table {
    let Some((e, m)) = a.pe.manifest(data) else { return Table::na(ItemType::Manifest, "n/a (no manifest)") };
    let mut t = Table::props(ItemType::Manifest);
    let Manifest { identity, execution_level, ui_access, auto_elevate, description, dependencies, raw, malformed, has_trust_info } = m;
    if let Some(i) = identity {
        t.rows.push(Row::kv("assembly > name", i.name));
        t.rows.push(Row::kv("assembly > version", i.version));
        t.rows.push(Row::kv("assembly > type", i.kind));
        t.rows.push(Row::kv("assembly > processorArchitecture", i.processor_architecture));
        t.rows.push(Row::kv("assembly > publicKeyToken", i.public_key_token));
        t.rows.push(Row::kv("assembly > language", i.language));
    }
    t.rows.push(Row::kv("trustInfo", if has_trust_info { "true" } else { "false" }));
    t.rows.push(
        Row::kv("requestedExecutionLevel", execution_level.unwrap_or_else(|| "n/a".into()))
            .flag(a.has_indicator(1400) || a.has_indicator(1401)),
    );
    t.rows.push(Row::kv("uiAccess", ui_access.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into())).flag(ui_access == Some(true)));
    t.rows
        .push(Row::kv("autoElevate", auto_elevate.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into())).flag(auto_elevate == Some(true)));
    if let Some(d) = description {
        t.rows.push(Row::kv("description", d));
    }
    for d in dependencies {
        t.rows.push(Row::kv("dependentAssembly", format!("{} {}", d.name, d.version)));
    }
    if malformed {
        t.rows.push(Row::kv("anomaly", "malformed manifest").flag(true));
    }
    let mut r = Row::kv("raw", raw);
    if let Some(off) = e.file_offset {
        r.dump = Some((off as u64, e.size as u64));
    }
    r.key = "manifest".into();
    t.rows.push(r);
    t
}

fn overlay(a: &Analysis, k: &Knowledge, data: &[u8], o: &ViewOptions) -> Table {
    let Some(ov) = &a.pe.overlay else { return Table::na(ItemType::Overlay, "n/a (no overlay)") };
    let b = &data[ov.offset as usize..(ov.offset + ov.size) as usize];
    let mut t = Table::props(ItemType::Overlay);
    // hashes, entropy and signature were computed once by the analysis
    let info = a.overlay_info.clone().unwrap_or_else(|| crate::model::OverlayInfo {
        hashes: util::hashes(b),
        entropy: entropy(b),
        signature: crate::sigscan::blob_signature(k, b).unwrap_or_else(|| "unknown".into()),
    });
    let sig = info.signature;
    t.rows
        .push(Row::kv("location", format!("0x{:08X} - 0x{:08X}", ov.offset, ov.offset + ov.size)).dump(ov.offset, ov.size).key("overlay"));
    t.rows.push(Row::kv("size", format!("{} bytes", ov.size)));
    t.rows.push(Row::kv("file-ratio", format!("{:.2}%", ratio(ov.size, a.size))));
    t.rows.push(Row::kv("entropy", format!("{:.3}", info.entropy)).flag(a.has_indicator(1035)));
    t.rows.push(Row::kv("signature", sig).flag(true));
    let h = info.hashes;
    t.rows.push(Row::kv("md5", o.hash(&h.md5)).url(google_url(&h.md5)).key(format!("hash:{}", h.md5)));
    t.rows.push(Row::kv("sha1", o.hash(&h.sha1)).url(google_url(&h.sha1)));
    t.rows.push(Row::kv("sha256", o.hash(&h.sha256)).url(google_url(&h.sha256)).key(format!("hash:{}", h.sha256)));
    t.rows.push(Row::kv("first-bytes-hex", bytes_hex(b, o.first_bytes)));
    t.rows.push(Row::kv("first-bytes-text", bytes_text(b, o.first_bytes)));
    let n = a.strings.iter().filter(|s| s.location == "overlay").count();
    t.rows.push(Row::kv("strings", n.to_string()).jump_to(ItemType::Strings));
    t
}

/// Whether a view is enabled by the settings (pestudio hides some views by default).
pub fn view_enabled(k: &Knowledge, item: ItemType) -> bool {
    let s = &k.settings;
    match item {
        ItemType::Exceptions => s.get_bool("exceptions", "enable", true),
        ItemType::Relocations => s.get_bool("relocations", "enable", true),
        ItemType::Mitre => s.get_bool("mitre", "enable", true),
        ItemType::Score => s.get_bool("score", "enable", true),
        ItemType::Groups => s.get_bool("groups", "enable", true),
        ItemType::Footprints => s.get_bool("footprints", "enable", true),
        ItemType::Strings => s.get_bool("strings", "enable", true),
        _ => true,
    }
}

/// Location category of a string location ("section:.text" → "section").
pub fn location_category(loc: &str) -> &'static str {
    match loc.split(':').next().unwrap_or("") {
        "section" => "section",
        "resource" => "resource",
        "overlay" => "overlay",
        "certificate" => "certificate",
        "dos-header" => "dos-header",
        "dos-stub" => "dos-stub",
        "header" => "file-header",
        "dotnet" => "dot-net",
        "file" => "image",
        _ => "unknown",
    }
}

/// Strings location map: (category, count, colour) in order of first appearance.
pub fn location_map(a: &Analysis, k: &Knowledge) -> Vec<(String, usize, (u8, u8, u8))> {
    let mut out: Vec<(String, usize, (u8, u8, u8))> = Vec::new();
    for s in &a.strings {
        let c = location_category(&s.location);
        match out.iter_mut().find(|(n, _, _)| n == c) {
            Some(e) => e.1 += 1,
            None => {
                let rgb =
                    k.translations.locations.iter().find(|(n, _)| n == c).map(|(_, c)| *c).filter(|c| *c != (0, 0, 0)).unwrap_or(match c {
                        "section" => (255, 228, 196),
                        "resource" => (218, 112, 214),
                        "overlay" => (46, 139, 87),
                        "certificate" => (144, 238, 144),
                        "dot-net" => (100, 149, 237),
                        _ => (200, 200, 200),
                    });
                out.push((c.to_string(), 1, rgb));
            }
        }
    }
    out
}

/// Plain text rendering of a table ("save to file").
pub fn table_text(t: &Table, sep: &str) -> String {
    let mut o = t.columns.join(sep);
    o.push('\n');
    for i in 0..t.rows.len() {
        o.push_str(&t.line(i, sep));
        o.push('\n');
    }
    o
}
