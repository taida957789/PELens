//! Security directory: WIN_CERTIFICATE entries and Authenticode PKCS#7 content.

use crate::der::{self, Tlv};
use crate::headers::dir;
use crate::layout::Layout;
use crate::reader::Reader;

pub fn cert_revision_name(r: u16) -> &'static str {
    match r {
        0x0100 => "WIN_CERT_REVISION_1_0",
        0x0200 => "WIN_CERT_REVISION_2_0",
        _ => "unknown",
    }
}

pub fn cert_type_name(t: u16) -> &'static str {
    match t {
        1 => "WIN_CERT_TYPE_X509",
        2 => "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
        3 => "WIN_CERT_TYPE_RESERVED_1",
        4 => "WIN_CERT_TYPE_TS_STACK_SIGNED",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Default)]
pub struct X509Info {
    pub subject: String,
    pub issuer: String,
    pub subject_cn: String,
    pub issuer_cn: String,
    pub serial: String,
    pub signature_algorithm: String,
    pub valid_from: Option<i64>,
    pub valid_to: Option<i64>,
    pub email: Option<String>,
    pub crl_urls: Vec<String>,
    pub purposes: Vec<String>,
    /// DER encoding (thumbprint = sha1 of it).
    pub der: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SignerInfo {
    pub issuer: String,
    pub serial: String,
    pub digest_algorithm: String,
    pub encryption_algorithm: String,
    pub signing_time: Option<i64>,
    pub program_name: Option<String>,
    pub more_info_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Authenticode {
    pub digest_algorithm: String,
    /// Hash of the image as recorded in SPC_INDIRECT_DATA.
    pub image_digest: Vec<u8>,
    pub certificates: Vec<X509Info>,
    pub signer: Option<SignerInfo>,
    pub counter_signer: Option<SignerInfo>,
    /// Number of nested signatures (dual signing).
    pub nested_signatures: usize,
    /// Size of the DER structure.
    pub der_size: usize,
}

impl Authenticode {
    /// The certificate that matches the signer (issuer + serial).
    pub fn signer_certificate(&self) -> Option<&X509Info> {
        let s = self.signer.as_ref()?;
        self.certificates.iter().find(|c| c.serial == s.serial).or(self.certificates.first())
    }

    pub fn counter_signer_certificate(&self) -> Option<&X509Info> {
        let s = self.counter_signer.as_ref()?;
        self.certificates.iter().find(|c| c.serial == s.serial)
    }
}

#[derive(Debug, Clone, Default)]
pub struct WinCertificate {
    pub offset: u32,
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
    pub pkcs7: Option<Authenticode>,
    /// Zero bytes trailing the DER structure inside the entry.
    pub null_padding: u32,
    /// Non-zero bytes trailing the DER structure inside the entry.
    pub tail: u32,
    pub tail_offset: u32,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityDirectory {
    pub offset: u32,
    pub size: u32,
    pub entries: Vec<WinCertificate>,
    /// Bytes appended after the security directory up to end of file.
    pub trailing_after_directory: u64,
    /// The security directory does not extend to the end of the file (unusual).
    pub not_at_end: bool,
}

impl SecurityDirectory {
    pub fn parse(r: &Reader, l: &Layout) -> Option<Self> {
        let d = l.optional_header.directory(dir::SECURITY)?;
        // The security directory address is a file offset, not an RVA.
        let base = d.rva as usize;
        if base >= r.len() {
            return Some(SecurityDirectory { offset: d.rva, size: d.size, ..Default::default() });
        }
        let end = base.saturating_add(d.size as usize).min(r.len());
        let mut sd = SecurityDirectory { offset: d.rva, size: d.size, ..Default::default() };
        let mut o = base;
        while o + 8 <= end && sd.entries.len() < 16 {
            let (Some(len), Some(rev), Some(ty)) = (r.u32(o), r.u16(o + 4), r.u16(o + 6)) else { break };
            if len < 8 {
                break;
            }
            let body = r.bytes_clamped(o + 8, len as usize - 8);
            let mut wc = WinCertificate { offset: o as u32, length: len, revision: rev, certificate_type: ty, ..Default::default() };
            if ty == 2
                && let Some(a) = parse_pkcs7(body)
            {
                let used = a.der_size.min(body.len());
                let rest = &body[used..];
                let zeros = rest.iter().rev().take_while(|&&b| b == 0).count();
                let nonzero_end = rest.len() - zeros;
                wc.null_padding = zeros as u32;
                wc.tail = nonzero_end as u32;
                wc.tail_offset = (o + 8 + used) as u32;
                wc.pkcs7 = Some(a);
            }
            sd.entries.push(wc);
            o += (len as usize + 7) & !7;
        }
        sd.trailing_after_directory = (r.len() as u64).saturating_sub(end as u64);
        sd.not_at_end = sd.trailing_after_directory > 0;
        Some(sd)
    }

    pub fn authenticode(&self) -> Option<&Authenticode> {
        self.entries.iter().find_map(|e| e.pkcs7.as_ref())
    }
}

pub fn parse_pkcs7(body: &[u8]) -> Option<Authenticode> {
    let ci = der::parse(body)?;
    if ci.tag != der::SEQUENCE {
        return None;
    }
    let ci_children = ci.children();
    let oid = ci_children.first()?;
    if oid.tag != der::OID || der::oid_to_string(oid.content) != "1.2.840.113549.1.7.2" {
        return None;
    }
    let explicit = ci_children.get(1)?;
    let sd = explicit.children().into_iter().next()?;
    let mut a = parse_signed_data(&sd, 0);
    a.der_size = ci.total_len();
    Some(a)
}

fn alg_name(alg: &Tlv) -> String {
    alg.children()
        .first()
        .filter(|t| t.tag == der::OID)
        .map(|t| {
            let s = der::oid_to_string(t.content);
            match der::oid_name(&s) {
                "" => s,
                n => n.to_string(),
            }
        })
        .unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Nesting limit for counter-signatures / timestamp tokens (real files use 2–3 levels).
const MAX_NESTING: usize = 8;

fn parse_signed_data(sd: &Tlv, depth: usize) -> Authenticode {
    if depth > MAX_NESTING {
        return Authenticode::default();
    }
    let mut a = Authenticode::default();
    let items = sd.children();
    // version, digestAlgorithms, contentInfo, [0] certs?, [1] crls?, signerInfos
    if let Some(content) = items.get(2) {
        let c = content.children();
        if let Some(inner) = c.get(1).and_then(|e| e.children().into_iter().next()) {
            // SpcIndirectDataContent ::= SEQ { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }
            if let Some(digest_info) = inner.children().get(1) {
                let di = digest_info.children();
                if let Some(alg) = di.first() {
                    a.digest_algorithm = alg_name(alg);
                }
                if let Some(d) = di.get(1) {
                    a.image_digest = d.content.to_vec();
                }
            }
        }
    }
    for it in items.iter().skip(3) {
        match it.tag {
            0xa0 => {
                // Only plain X.509 certificates (SEQUENCE); [1]/[2]/[3] are attribute/other certificates.
                for cert in it.children().into_iter().filter(|c| c.tag == der::SEQUENCE) {
                    if let Some(x) = parse_x509(&cert) {
                        a.certificates.push(x);
                    }
                }
            }
            der::SET => {
                if let Some(si) = it.children().into_iter().next() {
                    let (signer, counter, nested, ts_certs) = parse_signer_info(&si, depth + 1);
                    a.signer = Some(signer);
                    a.counter_signer = counter;
                    a.nested_signatures = nested;
                    a.certificates.extend(ts_certs);
                }
            }
            _ => {}
        }
    }
    a
}

fn integer_hex(t: &Tlv) -> String {
    let c = t.content;
    let c = if c.len() > 1 && c[0] == 0 { &c[1..] } else { c };
    hex(c)
}

pub fn parse_x509(cert: &Tlv) -> Option<X509Info> {
    let parts = cert.children();
    let tbs = parts.first()?;
    let mut f = tbs.children();
    if f.first().map(|t| t.tag) == Some(0xa0) {
        f.remove(0);
    }
    let serial = f.first()?;
    let issuer = f.get(2)?;
    let validity = f.get(3)?.children();
    let subject = f.get(4)?;
    let mut x = X509Info {
        subject: der::name_to_string(subject),
        issuer: der::name_to_string(issuer),
        subject_cn: der::name_attr(subject, "CN").unwrap_or_default(),
        issuer_cn: der::name_attr(issuer, "CN").unwrap_or_default(),
        serial: integer_hex(serial),
        signature_algorithm: parts.get(1).map(alg_name).unwrap_or_default(),
        valid_from: validity.first().and_then(der::parse_time),
        valid_to: validity.get(1).and_then(der::parse_time),
        email: der::name_attr(subject, "E"),
        der: cert_bytes(cert),
        ..Default::default()
    };
    if let Some(ext) = f.iter().find(|t| t.tag == 0xa3) {
        for e in ext.children().into_iter().flat_map(|s| s.children()) {
            let ec = e.children();
            let Some(oid) = ec.first().filter(|t| t.tag == der::OID) else { continue };
            let oid = der::oid_to_string(oid.content);
            let Some(val) = ec.last() else { continue };
            match oid.as_str() {
                "2.5.29.31" => collect_uris(val.content, &mut x.crl_urls),
                "2.5.29.37" => {
                    if let Some(seq) = der::parse(val.content) {
                        for p in seq.children() {
                            let s = der::oid_to_string(p.content);
                            x.purposes.push(match der::oid_name(&s) {
                                "" => s,
                                n => n.to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(x)
}

fn cert_bytes(t: &Tlv) -> Vec<u8> {
    t.raw.to_vec()
}

fn collect_uris(b: &[u8], out: &mut Vec<String>) {
    // Walk the tree and pick every [6] (uniformResourceIdentifier) value.
    fn walk(t: &Tlv, out: &mut Vec<String>, depth: usize) {
        if depth > 10 {
            return;
        }
        if t.tag == 0x86 {
            out.push(String::from_utf8_lossy(t.content).into_owned());
        } else if t.is_constructed() {
            for c in t.children() {
                walk(&c, out, depth + 1);
            }
        }
    }
    if let Some(t) = der::parse(b) {
        walk(&t, out, 0);
    }
}

fn spc_string(t: &Tlv) -> Option<String> {
    // SpcString ::= CHOICE { unicode [0] IMPLICIT BMPString, ascii [1] IMPLICIT IA5String }
    let inner = t.children().into_iter().next().unwrap_or(*t);
    match inner.tag {
        0x80 => {
            let units: Vec<u16> = inner.content.as_chunks::<2>().0.iter().map(|&c| u16::from_be_bytes(c)).collect();
            Some(String::from_utf16_lossy(&units))
        }
        0x81 => Some(String::from_utf8_lossy(inner.content).into_owned()),
        _ => None,
    }
}

fn parse_attrs(
    attrs: &Tlv,
    si: &mut SignerInfo,
    counter: &mut Option<SignerInfo>,
    nested: &mut usize,
    ts_certs: &mut Vec<X509Info>,
    depth: usize,
) {
    for attr in attrs.children() {
        let c = attr.children();
        let Some(oid) = c.first().filter(|t| t.tag == der::OID) else { continue };
        let oid = der::oid_to_string(oid.content);
        let Some(values) = c.get(1) else { continue };
        let first = values.children().into_iter().next();
        match oid.as_str() {
            "1.2.840.113549.1.9.5" => {
                if let Some(t) = first {
                    si.signing_time = der::parse_time(&t);
                }
            }
            "1.3.6.1.4.1.311.2.1.12" => {
                if let Some(opus) = first {
                    for e in opus.children() {
                        match e.tag {
                            0xa0 => si.program_name = spc_string(&e),
                            0xa1 => {
                                let link = e.children().into_iter().next().unwrap_or(e);
                                if link.tag == 0x80 {
                                    si.more_info_url = Some(String::from_utf8_lossy(link.content).into_owned());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "1.2.840.113549.1.9.6" => {
                if let Some(cs) = first {
                    let (c, _, _, _) = parse_signer_info(&cs, depth + 1);
                    *counter = Some(c);
                }
            }
            "1.3.6.1.4.1.311.3.3.1" => {
                // RFC3161 timestamp token (ContentInfo SignedData with TSTInfo)
                if let Some(tok) = first {
                    let ch = tok.children();
                    if let Some(sd) = ch.get(1).and_then(|e| e.children().into_iter().next()) {
                        let inner = parse_signed_data(&sd, depth + 1);
                        let mut cs = inner.signer.clone().unwrap_or_default();
                        if cs.signing_time.is_none() {
                            cs.signing_time = tst_gen_time(&sd);
                        }
                        ts_certs.extend(inner.certificates);
                        *counter = Some(cs);
                    }
                }
            }
            "1.3.6.1.4.1.311.2.4.1" => *nested += values.children().len(),
            _ => {}
        }
    }
}

fn tst_gen_time(sd: &Tlv) -> Option<i64> {
    let items = sd.children();
    let content = items.get(2)?.children();
    let octet = content.get(1)?.children().into_iter().next()?;
    let tst = der::parse(octet.content)?;
    tst.children().iter().find(|t| t.tag == der::GENERALIZED_TIME).and_then(der::parse_time)
}

fn parse_signer_info(si: &Tlv, depth: usize) -> (SignerInfo, Option<SignerInfo>, usize, Vec<X509Info>) {
    if depth > MAX_NESTING {
        return (SignerInfo::default(), None, 0, Vec::new());
    }
    let mut s = SignerInfo::default();
    let mut counter = None;
    let mut nested = 0;
    let mut ts_certs = Vec::new();
    let f = si.children();
    if let Some(ias) = f.get(1) {
        let c = ias.children();
        if let Some(i) = c.first() {
            s.issuer = der::name_to_string(i);
        }
        if let Some(sn) = c.get(1) {
            s.serial = integer_hex(sn);
        }
    }
    if let Some(alg) = f.get(2) {
        s.digest_algorithm = alg_name(alg);
    }
    let mut idx = 3;
    if let Some(auth) = f.get(3).filter(|t| t.tag == 0xa0) {
        parse_attrs(auth, &mut s, &mut counter, &mut nested, &mut ts_certs, depth);
        idx = 4;
    }
    if let Some(alg) = f.get(idx) {
        s.encryption_algorithm = alg_name(alg);
    }
    if let Some(unauth) = f.iter().skip(idx).find(|t| t.tag == 0xa1) {
        parse_attrs(unauth, &mut s, &mut counter, &mut nested, &mut ts_certs, depth);
    }
    (s, counter, nested, ts_certs)
}
