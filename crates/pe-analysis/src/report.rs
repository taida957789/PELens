//! Report generation (XML like pestudio, plus JSON and plain text) built from the view tables.

use crate::model::{Analysis, ItemType};
use crate::view::{self, Table, ViewOptions};
use pe_db::Knowledge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Xml,
    Json,
    Text,
}

impl Format {
    pub fn from_setting(v: i64) -> Self {
        match v {
            1 => Format::Json,
            2 => Format::Text,
            _ => Format::Xml,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Xml => "xml",
            Format::Json => "json",
            Format::Text => "txt",
        }
    }
}

/// XML escaping that also neutralises characters invalid in XML 1.0.
pub fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    xml_escape_into(&mut o, s);
    o
}

/// Append `s` escaped for an XML attribute (no allocation when nothing needs escaping).
pub fn xml_escape_into(o: &mut String, s: &str) {
    let plain = |b: &u8| *b >= 0x20 && !matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'' | 0xEF);
    if s.bytes().all(|b| plain(&b)) {
        o.push_str(s);
        return;
    }
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            '\t' | '\n' | '\r' => o.push_str(&format!("&#x{:X};", c as u32)),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => o.push_str(&format!("[0x{:02X}]", c as u32)),
            c => o.push(c),
        }
    }
}

/// Column title → XML attribute name.
pub fn attr_name(c: &str) -> String {
    let mut s: String =
        c.chars().map(|ch| if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' { ch.to_ascii_lowercase() } else { '-' }).collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() || s.starts_with(|c: char| c.is_ascii_digit()) { format!("c-{s}") } else { s }
}

pub fn tables(a: &Analysis, k: &Knowledge, data: &[u8]) -> Vec<Table> {
    let o = ViewOptions::from_settings(k);
    ItemType::ALL.iter().filter(|&&t| view::view_enabled(k, t)).map(|&t| view::table(a, k, data, t, &o)).collect()
}

pub fn render(a: &Analysis, k: &Knowledge, data: &[u8], f: Format) -> String {
    let ts = tables(a, k, data);
    match f {
        Format::Xml => to_xml(a, &ts),
        Format::Json => to_json(a, &ts),
        Format::Text => to_text(a, &ts, k.settings.get("indicators", "separator").unwrap_or("|")),
    }
}

pub fn to_xml(a: &Analysis, ts: &[Table]) -> String {
    let mut o = String::from("<?xml version='1.0' encoding='utf-8'?>\n");
    o.push_str(&format!(
        "<image name=\"{}\" path=\"{}\" size=\"{}\" md5=\"{}\" sha256=\"{}\" indicators=\"{}\" generator=\"pelens {}\">\n",
        xml_escape(&a.file_name),
        xml_escape(&a.path),
        a.size,
        a.hashes.md5,
        a.hashes.sha256,
        a.indicators.len(),
        env!("CARGO_PKG_VERSION")
    ));
    for t in ts {
        let name = t.item.map(|i| i.name()).unwrap_or("table");
        let cols: Vec<String> = t.columns.iter().map(|c| attr_name(c)).collect();
        match &t.note {
            Some(n) if t.rows.is_empty() => {
                o.push_str(&format!("  <{name} note=\"{}\"/>\n", xml_escape(n)));
                continue;
            }
            _ => o.push_str(&format!("  <{name} count=\"{}\">\n", t.rows.len())),
        }
        for r in &t.rows {
            o.push_str("    <item");
            for (c, v) in cols.iter().zip(&r.cells) {
                o.push(' ');
                o.push_str(c);
                o.push_str("=\"");
                xml_escape_into(&mut o, v);
                o.push('"');
            }
            if r.flag {
                o.push_str(" flagged=\"x\"");
            }
            if let Some(s) = r.severity {
                o.push_str(&format!(" severity=\"{s}\""));
            }
            if let Some(ti) = &r.ti {
                o.push_str(&format!(" ti=\"T{}\"", xml_escape(ti.trim_start_matches('T'))));
            }
            o.push_str("/>\n");
        }
        o.push_str(&format!("  </{name}>\n"));
    }
    o.push_str("</image>\n");
    o
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    json_str_into(&mut o, s);
    o
}

/// Append `s` as a JSON string literal (no allocation when nothing needs escaping).
fn json_str_into(o: &mut String, s: &str) {
    o.push('"');
    if s.bytes().all(|b| b >= 0x20 && b != b'"' && b != b'\\') {
        o.push_str(s);
        o.push('"');
        return;
    }
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
}

pub fn to_json(a: &Analysis, ts: &[Table]) -> String {
    let mut o = format!(
        "{{\"name\":{},\"path\":{},\"size\":{},\"md5\":{},\"sha256\":{},\"views\":{{",
        json_str(&a.file_name),
        json_str(&a.path),
        a.size,
        json_str(&a.hashes.md5),
        json_str(&a.hashes.sha256)
    );
    for (ti, t) in ts.iter().enumerate() {
        if ti > 0 {
            o.push(',');
        }
        let name = t.item.map(|i| i.name()).unwrap_or("table");
        o.push_str(&format!("{}:{{", json_str(name)));
        if let Some(n) = &t.note {
            o.push_str(&format!("\"note\":{},", json_str(n)));
        }
        o.push_str("\"rows\":[");
        let keys: Vec<String> = t.columns.iter().map(|c| json_str(c)).collect();
        for (ri, r) in t.rows.iter().enumerate() {
            if ri > 0 {
                o.push(',');
            }
            o.push('{');
            for (ci, (c, v)) in keys.iter().zip(&r.cells).enumerate() {
                if ci > 0 {
                    o.push(',');
                }
                o.push_str(c);
                o.push(':');
                json_str_into(&mut o, v);
            }
            if r.flag {
                o.push_str(",\"flagged\":true");
            }
            if let Some(s) = r.severity {
                o.push_str(&format!(",\"severity\":{s}"));
            }
            o.push('}');
        }
        o.push_str("]}");
    }
    o.push_str("}}");
    o
}

pub fn to_text(a: &Analysis, ts: &[Table], sep: &str) -> String {
    let mut o = format!("pelens report | {} | {} bytes | sha256: {}\n", a.path, a.size, a.hashes.sha256);
    for t in ts {
        let name = t.item.map(|i| i.name()).unwrap_or("table");
        o.push_str(&format!("\n[{name}]\n"));
        if let Some(n) = &t.note {
            o.push_str(&format!("{n}\n"));
        }
        if !t.rows.is_empty() {
            o.push_str(&t.columns.join(sep));
            o.push('\n');
        }
        for i in 0..t.rows.len() {
            if t.rows[i].flag {
                o.push_str("* ");
            }
            o.push_str(&t.line(i, sep));
            o.push('\n');
        }
    }
    o
}

/// Default report path: "<input>.xml" (pestudio convention).
pub fn default_report_path(input: &std::path::Path, f: Format) -> std::path::PathBuf {
    let mut s = input.as_os_str().to_os_string();
    s.push(".");
    s.push(f.extension());
    std::path::PathBuf::from(s)
}
