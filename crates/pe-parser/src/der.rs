//! Minimal tolerant DER/BER reader for Authenticode PKCS#7 blobs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub header_len: usize,
    pub content: &'a [u8],
    /// Header + content as found in the input.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn total_len(&self) -> usize {
        self.header_len + self.content.len()
    }

    pub fn is_constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// Child TLVs of a constructed element.
    pub fn children(&self) -> Vec<Tlv<'a>> {
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            match parse(rest) {
                Some(t) => {
                    rest = &rest[t.total_len().min(rest.len())..];
                    out.push(t);
                }
                None => break,
            }
            if out.len() > 100_000 {
                break;
            }
        }
        out
    }
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const OID: u8 = 0x06;
pub const INTEGER: u8 = 0x02;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;

pub fn parse(b: &[u8]) -> Option<Tlv<'_>> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hl) = if l0 & 0x80 == 0 {
        (l0 as usize, 2)
    } else if l0 == 0x80 {
        // Indefinite length (BER): content runs to the end, minus end-of-contents if present.
        let rest = &b[2..];
        let n = if rest.ends_with(&[0, 0]) { rest.len() - 2 } else { rest.len() };
        (n, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hl.checked_add(len)?;
    let end = end.min(b.len());
    let content = b.get(hl..end)?;
    Some(Tlv { tag, header_len: hl, content, raw: &b[..end] })
}

pub fn oid_to_string(b: &[u8]) -> String {
    if b.is_empty() {
        return String::new();
    }
    let mut parts = vec![(b[0] / 40) as u64, (b[0] % 40) as u64];
    let mut v: u64 = 0;
    for &c in &b[1..] {
        v = (v << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

pub fn oid_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "rsa",
        "1.2.840.113549.1.1.4" => "md5RSA",
        "1.2.840.113549.1.1.5" => "sha1RSA",
        "1.2.840.113549.1.1.11" => "sha256RSA",
        "1.2.840.113549.1.1.12" => "sha384RSA",
        "1.2.840.113549.1.1.13" => "sha512RSA",
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "1.3.14.3.2.29" => "sha1RSA",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.10045.2.1" => "ecPublicKey",
        "1.2.840.10045.4.3.2" => "sha256ECDSA",
        "1.2.840.10045.4.3.3" => "sha384ECDSA",
        "1.2.840.113549.1.7.2" => "signedData",
        "1.2.840.113549.1.9.3" => "contentType",
        "1.2.840.113549.1.9.4" => "messageDigest",
        "1.2.840.113549.1.9.5" => "signingTime",
        "1.2.840.113549.1.9.6" => "counterSignature",
        "1.3.6.1.4.1.311.2.1.4" => "SPC_INDIRECT_DATA",
        "1.3.6.1.4.1.311.2.1.12" => "SPC_SP_OPUS_INFO",
        "1.3.6.1.4.1.311.3.3.1" => "RFC3161 timestamp",
        "1.2.840.113549.1.9.16.1.4" => "TSTInfo",
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.17" => "postal-code",
        "1.2.840.113549.1.9.1" => "E",
        "2.5.29.15" => "keyUsage",
        "2.5.29.31" => "CRL-Distribution-Point",
        "2.5.29.37" => "extKeyUsage",
        "1.3.6.1.5.5.7.3.3" => "Code Signing",
        "1.3.6.1.5.5.7.3.8" => "Time Stamping",
        _ => "",
    }
}

/// Parse UTCTime / GeneralizedTime into a Unix timestamp.
pub fn parse_time(t: &Tlv) -> Option<i64> {
    let s = std::str::from_utf8(t.content).ok()?;
    let s = s.trim_end_matches('Z');
    let (y, rest) = match t.tag {
        UTC_TIME => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        GENERALIZED_TIME => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |a: usize| -> Option<i64> { rest.get(a..a + 2).and_then(|v| v.parse().ok()) };
    let (mo, d, h, mi) = (num(0)?, num(2)?, num(4)?, num(6)?);
    let sec = num(8).unwrap_or(0);
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

/// Howard Hinnant's days_from_civil.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Decode an ASN.1 string type into text.
pub fn string_value(t: &Tlv) -> String {
    match t.tag {
        0x1e => {
            // BMPString (UTF-16BE)
            let units: Vec<u16> = t.content.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(t.content).into_owned(),
    }
}

/// X.501 Name → "CN=..., O=..., C=..." string.
pub fn name_to_string(name: &Tlv) -> String {
    let mut parts = Vec::new();
    for rdn in name.children() {
        for atv in rdn.children() {
            let c = atv.children();
            if c.len() >= 2 && c[0].tag == OID {
                let oid = oid_to_string(c[0].content);
                let label = match oid_name(&oid) {
                    "" => oid.clone(),
                    n => n.to_string(),
                };
                parts.push(format!("{label}={}", string_value(&c[1])));
            }
        }
    }
    parts.join(", ")
}

/// Get the value for a given attribute short name (e.g. "CN") from a Name.
pub fn name_attr(name: &Tlv, short: &str) -> Option<String> {
    for rdn in name.children() {
        for atv in rdn.children() {
            let c = atv.children();
            if c.len() >= 2 && c[0].tag == OID && oid_name(&oid_to_string(c[0].content)) == short {
                return Some(string_value(&c[1]));
            }
        }
    }
    None
}
