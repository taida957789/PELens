//! Hashing, entropy, time formatting, printf-style formatting and byte previews.

use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn md5_hex(data: &[u8]) -> String {
    hex_upper(&Md5::digest(data))
}

pub fn sha1_hex(data: &[u8]) -> String {
    hex_upper(&Sha1::digest(data))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_upper(&Sha256::digest(data))
}

/// Below this size the three digests are computed one after the other (threads cost more).
const PARALLEL_HASH_MIN: usize = 1 << 20;

pub fn hashes(data: &[u8]) -> Hashes {
    if data.len() < PARALLEL_HASH_MIN {
        return Hashes { md5: md5_hex(data), sha1: sha1_hex(data), sha256: sha256_hex(data) };
    }
    std::thread::scope(|s| {
        let md5 = s.spawn(|| md5_hex(data));
        let sha1 = s.spawn(|| sha1_hex(data));
        let sha256 = sha256_hex(data);
        Hashes { md5: md5.join().unwrap_or_default(), sha1: sha1.join().unwrap_or_default(), sha256 }
    })
}

/// Hashes of `data[..split]` and of all of `data` in one pass: the prefix state is finalized on a
/// copy, then the same hasher continues with the rest (used for "without overlay").
pub fn hashes_with_prefix(data: &[u8], split: usize) -> (Hashes, Hashes) {
    fn one<D: md5::Digest + Clone>(data: &[u8], split: usize) -> (String, String) {
        let mut h = D::new();
        h.update(&data[..split]);
        let prefix = hex_upper(&h.clone().finalize());
        h.update(&data[split..]);
        (hex_upper(&h.finalize()), prefix)
    }
    let split = split.min(data.len());
    let ((md5, md5p), (sha1, sha1p), (sha256, sha256p)) = std::thread::scope(|s| {
        let a = s.spawn(|| one::<Md5>(data, split));
        let b = s.spawn(|| one::<Sha1>(data, split));
        let c = one::<Sha256>(data, split);
        (a.join().unwrap_or_default(), b.join().unwrap_or_default(), c)
    });
    (Hashes { md5, sha1, sha256 }, Hashes { md5: md5p, sha1: sha1p, sha256: sha256p })
}

impl Hashes {
    /// The digest selected by a footprint type (0 = md5, 1 = sha1, otherwise sha256).
    pub fn by_type(&self, t: i64) -> &str {
        match t {
            0 => &self.md5,
            1 => &self.sha1,
            _ => &self.sha256,
        }
    }
}

/// Footprint type selector as stored in settings (`footprints type`): 0 = md5, 1 = sha1, 2 = sha256.
pub fn hash_by_type(data: &[u8], t: i64) -> String {
    match t {
        0 => md5_hex(data),
        1 => sha1_hex(data),
        _ => sha256_hex(data),
    }
}

pub fn hash_type_name(t: i64) -> &'static str {
    match t {
        0 => "md5",
        1 => "sha1",
        _ => "sha256",
    }
}

/// Shannon entropy in bits per byte (0..8).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

pub fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { part as f64 * 100.0 / total as f64 }
}

/// "dd.mm.yyyy | hh:mm:ss" style UTC rendering used across the views.
pub fn format_utc(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{:02}.{:02}.{:04} | {:02}:{:02}:{:02}", d, m, y, secs / 3600, (secs % 3600) / 60, secs % 60)
}

pub fn format_stamp(ts: u32, epoch: bool) -> String {
    if ts == 0 {
        return "n/a".into();
    }
    if epoch { format!("{} (UTC) - {:08} (Epoch)", format_utc(ts as i64), ts) } else { format!("{} (UTC)", format_utc(ts as i64)) }
}

pub fn year_of(ts: i64) -> i64 {
    civil_from_days(ts.div_euclid(86400)).0
}

/// Inverse of days_from_civil (Howard Hinnant).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Hex preview "4D 5A 90 00 …".
pub fn bytes_hex(b: &[u8], n: usize) -> String {
    b.iter().take(n).map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

/// Text preview where non printable bytes are rendered as '.'.
pub fn bytes_text(b: &[u8], n: usize) -> String {
    b.iter().take(n).map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' }).collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    S(String),
    I(i64),
    F(f64),
}

impl From<&str> for Arg {
    fn from(s: &str) -> Self {
        Arg::S(s.to_string())
    }
}
impl From<String> for Arg {
    fn from(s: String) -> Self {
        Arg::S(s)
    }
}
impl From<i64> for Arg {
    fn from(v: i64) -> Self {
        Arg::I(v)
    }
}
impl From<u64> for Arg {
    fn from(v: u64) -> Self {
        Arg::I(v as i64)
    }
}
impl From<usize> for Arg {
    fn from(v: usize) -> Self {
        Arg::I(v as i64)
    }
}
impl From<u32> for Arg {
    fn from(v: u32) -> Self {
        Arg::I(v as i64)
    }
}
impl From<u16> for Arg {
    fn from(v: u16) -> Self {
        Arg::I(v as i64)
    }
}
impl From<i32> for Arg {
    fn from(v: i32) -> Self {
        Arg::I(v as i64)
    }
}
impl From<f64> for Arg {
    fn from(v: f64) -> Self {
        Arg::F(v)
    }
}

/// Minimal printf: %s %i %d %u %x %X %08X %.03f %.02f %%.
pub fn printf(fmt: &str, args: &[Arg]) -> String {
    let mut out = String::new();
    let mut it = args.iter();
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            let ch = fmt[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push('%');
            break;
        }
        if b[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }
        let mut zero = false;
        let mut width = 0usize;
        let mut prec: Option<usize> = None;
        if b[i] == b'0' {
            zero = true;
            i += 1;
        }
        while i < b.len() && b[i].is_ascii_digit() {
            width = width * 10 + (b[i] - b'0') as usize;
            i += 1;
        }
        if i < b.len() && b[i] == b'.' {
            i += 1;
            let mut p = 0;
            while i < b.len() && b[i].is_ascii_digit() {
                p = p * 10 + (b[i] - b'0') as usize;
                i += 1;
            }
            prec = Some(p);
        }
        while i < b.len() && (b[i] == b'l' || b[i] == b'h') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let conv = b[i];
        i += 1;
        let a = it.next();
        let s = match (conv, a) {
            (b's', Some(Arg::S(s))) => s.clone(),
            (b's', Some(Arg::I(v))) => v.to_string(),
            (b's', Some(Arg::F(v))) => format!("{v}"),
            (b'i' | b'd' | b'u', Some(Arg::I(v))) => v.to_string(),
            (b'i' | b'd' | b'u', Some(Arg::F(v))) => (*v as i64).to_string(),
            (b'x', Some(Arg::I(v))) => format!("{:x}", *v as u64),
            (b'X', Some(Arg::I(v))) => format!("{:X}", *v as u64),
            (b'f', Some(Arg::F(v))) => format!("{:.*}", prec.unwrap_or(6), v),
            (b'f', Some(Arg::I(v))) => format!("{:.*}", prec.unwrap_or(6), *v as f64),
            (_, Some(Arg::S(s))) => s.clone(),
            (_, Some(Arg::I(v))) => v.to_string(),
            (_, Some(Arg::F(v))) => v.to_string(),
            (_, None) => String::new(),
        };
        if s.len() < width {
            let pad = if zero { '0' } else { ' ' };
            out.extend(std::iter::repeat_n(pad, width - s.len()));
        }
        out.push_str(&s);
    }
    out
}

/// Undecorate an MSVC C++ symbol; returns the input when not decorated.
pub fn undecorate(name: &str) -> String {
    if !name.starts_with('?') {
        return name.to_string();
    }
    msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()).unwrap_or_else(|_| name.to_string())
}

/// Boyer-Moore-free substring search (memchr on the first byte).
pub fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        {
            let p = hay[i..=hay.len() - needle.len()].iter().position(|&b| b == first)?;
            let s = i + p;
            if &hay[s..s + needle.len()] == needle {
                return Some(s);
            }
            i = s + 1;
        }
    }
    None
}
