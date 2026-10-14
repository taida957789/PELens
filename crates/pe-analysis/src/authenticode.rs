//! Authenticode verification in pure Rust: used on Linux and macOS, where WinVerifyTrust is not
//! available, and testable everywhere.
//!
//! Checks, in the order WinVerifyTrust reports them:
//! 1. the image digest of the file against the one signed in `SpcIndirectDataContent`;
//! 2. the signer's signature over the signed attributes (RSA PKCS#1 v1.5 / PSS, ECDSA P-256/P-384);
//! 3. the timestamp (PKCS#9 counter-signature or RFC 3161 token) when there is one;
//! 4. the certificate chain up to a trusted root (the system store plus Microsoft's code-signing
//!    roots, which Linux and macOS do not ship), validity at the signing time, code-signing usage.
//!
//! Revocation is not checked (PELens calls WinVerifyTrust without revocation checks as well).

use crate::model::CertificateCheck;
use pe_parser::der::{self, Tlv};
use std::sync::OnceLock;

// ---------------------------------------------------------------- outcome

/// Result of a verification, with WinVerifyTrust's wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    NoSignature,
    BadDigest,
    BadSignature,
    /// No chain could be built (an issuer certificate is missing or does not sign its subject).
    Chaining,
    UntrustedRoot,
    NotTimeValid,
    WrongUsage,
    /// Malformed or unknown structure / algorithm (the text says which).
    Malformed(String),
}

impl Outcome {
    pub fn message(&self) -> String {
        match self {
            Outcome::Ok => "This digital signature is OK.".into(),
            Outcome::NoSignature => "No signature was present in the subject.".into(),
            Outcome::BadDigest => "The digital signature of the object did not verify (bad digest).".into(),
            Outcome::BadSignature => "The digital signature of the object did not verify (bad signature).".into(),
            Outcome::Chaining => "A certificate chain could not be built to a trusted root authority.".into(),
            Outcome::UntrustedRoot => "The certificate chain terminates in an untrusted root.".into(),
            Outcome::NotTimeValid => "A required certificate is not within its validity period.".into(),
            Outcome::WrongUsage => "The certificate is not valid for code signing.".into(),
            Outcome::Malformed(m) => format!("The signature could not be verified: {m}."),
        }
    }

    pub fn check(&self) -> CertificateCheck {
        CertificateCheck { verified: Some(*self == Outcome::Ok), message: self.message() }
    }
}

// ---------------------------------------------------------------- trust store

/// Microsoft's code-signing and timestamping roots (public certificates).
const MICROSOFT_ROOTS: [&[u8]; 6] = [
    include_bytes!("../roots/Microsoft_Root_Certificate_Authority_2010.cer"),
    include_bytes!("../roots/Microsoft_Root_Certificate_Authority_2011.cer"),
    include_bytes!("../roots/Microsoft_Time_Stamp_Root_Certificate_Authority_2014.cer"),
    include_bytes!("../roots/Microsoft_Identity_Verification_Root_Certificate_Authority_2020.cer"),
    include_bytes!("../roots/Microsoft_Root_Certificate_Authority.cer"),
    include_bytes!("../roots/Microsoft_Root_Authority.cer"),
];

/// Trusted root certificates (DER).
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    pub roots: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Microsoft's code-signing roots only.
    pub fn microsoft() -> Self {
        TrustStore { roots: MICROSOFT_ROOTS.iter().map(|r| r.to_vec()).collect() }
    }

    /// Microsoft's roots plus the roots of the operating system (loaded once).
    pub fn system() -> &'static TrustStore {
        static STORE: OnceLock<TrustStore> = OnceLock::new();
        STORE.get_or_init(|| {
            let mut s = TrustStore::microsoft();
            for r in os_roots() {
                if !s.roots.contains(&r) {
                    s.roots.push(r);
                }
            }
            s
        })
    }
}

/// PEM bundles of the common Linux distributions (Debian/Ubuntu, Fedora/RHEL, Alpine, SUSE, Arch).
pub const LINUX_BUNDLES: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

#[cfg(target_os = "linux")]
fn os_roots() -> Vec<Vec<u8>> {
    LINUX_BUNDLES.iter().find_map(|p| std::fs::read_to_string(p).ok()).map(|t| pem_certificates(&t)).unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn os_roots() -> Vec<Vec<u8>> {
    // the system roots and the administrator's additions
    let mut out = Vec::new();
    for keychain in ["/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"] {
        if let Ok(o) = std::process::Command::new("/usr/bin/security").args(["find-certificate", "-a", "-p", keychain]).output() {
            out.extend(pem_certificates(&String::from_utf8_lossy(&o.stdout)));
        }
    }
    out
}

/// Windows verifies with WinVerifyTrust and its own store; Microsoft's roots are enough here.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_roots() -> Vec<Vec<u8>> {
    Vec::new()
}

/// Certificates of a PEM text (`-----BEGIN CERTIFICATE-----` blocks).
pub fn pem_certificates(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            body = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(b) = body.take().and_then(|b| base64_decode(&b)) {
                out.push(b);
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        }
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- hashes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn from_oid(oid: &str) -> Option<Hash> {
        Some(match oid {
            "1.2.840.113549.2.5" => Hash::Md5,
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            _ => return None,
        })
    }

    pub fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest;
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Hash::Md5 => run::<md5::Md5>(parts),
            Hash::Sha1 => run::<sha1::Sha1>(parts),
            Hash::Sha256 => run::<sha2::Sha256>(parts),
            Hash::Sha384 => run::<sha2::Sha384>(parts),
            Hash::Sha512 => run::<sha2::Sha512>(parts),
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        self.digest_parts(&[data])
    }
}

/// Authenticode image digest: the whole file except the checksum, the security directory entry and
/// the certificate table (and anything after it).
pub fn image_digest(data: &[u8], hash: Hash) -> Option<Vec<u8>> {
    let pe = pe_parser::PeFile::parse(data);
    let l = pe.layout.as_ref()?;
    let checksum = l.optional_header.checksum_offset() as usize;
    let entry = l.optional_header.data_directories_offset as usize + pe_parser::headers::dir::SECURITY * 8;
    let table = pe.security.as_ref().map_or(data.len(), |s| s.offset as usize).min(data.len());
    if !(checksum + 4 <= entry && entry + 8 <= table) {
        return None;
    }
    Some(hash.digest_parts(&[&data[..checksum], &data[checksum + 4..entry], &data[entry + 8..table]]))
}

// ---------------------------------------------------------------- X.509

fn oid_of(t: &Tlv) -> String {
    der::oid_to_string(t.content)
}

/// (algorithm OID, parameters) of an AlgorithmIdentifier.
fn algorithm<'a>(t: &Tlv<'a>) -> Option<(String, Option<Tlv<'a>>)> {
    let c = t.children();
    let oid = c.first().filter(|o| o.tag == der::OID)?;
    Some((oid_of(oid), c.get(1).copied()))
}

/// The parts of a certificate the verification needs.
#[derive(Debug, Clone)]
pub struct Cert<'a> {
    pub raw: &'a [u8],
    tbs: &'a [u8],
    sig_alg: String,
    sig_params: Option<Tlv<'a>>,
    signature: &'a [u8],
    pub serial: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    spki: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    /// Extended key usages (None: no EKU extension, any usage).
    eku: Option<Vec<String>>,
    /// Subject key identifier.
    ski: Option<&'a [u8]>,
}

pub fn parse_cert(raw: &[u8]) -> Option<Cert<'_>> {
    let top = der::parse(raw)?;
    let parts = top.children();
    let (tbs, alg, sig) = (parts.first()?, parts.get(1)?, parts.get(2)?);
    let (sig_alg, sig_params) = algorithm(alg)?;
    let mut f = tbs.children();
    if f.first().is_some_and(|v| v.tag == 0xa0) {
        f.remove(0);
    }
    let (serial, issuer, validity, subject, spki) = (f.first()?, f.get(2)?, f.get(3)?, f.get(4)?, f.get(5)?);
    let times = validity.children();
    let mut c = Cert {
        raw: top.raw,
        tbs: tbs.raw,
        sig_alg,
        sig_params,
        signature: sig.content.get(1..)?,
        serial: serial.content,
        issuer: issuer.raw,
        subject: subject.raw,
        spki: spki.raw,
        not_before: times.first().and_then(der::parse_time)?,
        not_after: times.get(1).and_then(der::parse_time)?,
        eku: None,
        ski: None,
    };
    if let Some(ext) = f.iter().find(|e| e.tag == 0xa3) {
        for e in ext.children().first().map(|s| s.children()).unwrap_or_default() {
            let ec = e.children();
            let Some(id) = ec.first().map(oid_of) else { continue };
            let Some(value) = ec.last().filter(|v| v.tag == 0x04).and_then(|v| der::parse(v.content)) else { continue };
            match id.as_str() {
                "2.5.29.37" => c.eku = Some(value.children().iter().map(oid_of).collect()),
                "2.5.29.14" => c.ski = Some(value.content),
                _ => {}
            }
        }
    }
    Some(c)
}

impl Cert<'_> {
    fn allows_code_signing(&self) -> bool {
        self.eku.as_ref().is_none_or(|u| u.iter().any(|o| o == "1.3.6.1.5.5.7.3.3" || o == "2.5.29.37.0"))
    }

    fn valid_at(&self, t: i64) -> bool {
        self.not_before <= t && t <= self.not_after
    }

    /// Whether `issuer` signed this certificate.
    fn signed_by(&self, issuer: &Cert) -> bool {
        self.issuer == issuer.subject
            && verify_signature(issuer.spki, &self.sig_alg, self.sig_params, None, self.tbs, self.signature).is_ok()
    }
}

// ---------------------------------------------------------------- signatures

/// Verify `signature` over `message` with the key of `spki`. `alg` is a signature algorithm OID,
/// or a key algorithm (rsaEncryption, id-ecPublicKey) completed by `digest`.
fn verify_signature(
    spki: &[u8],
    alg: &str,
    params: Option<Tlv>,
    digest: Option<Hash>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    let (kind, hash) = match alg {
        "1.2.840.113549.1.1.4" => ("rsa", Some(Hash::Md5)),
        "1.2.840.113549.1.1.5" => ("rsa", Some(Hash::Sha1)),
        "1.2.840.113549.1.1.11" => ("rsa", Some(Hash::Sha256)),
        "1.2.840.113549.1.1.12" => ("rsa", Some(Hash::Sha384)),
        "1.2.840.113549.1.1.13" => ("rsa", Some(Hash::Sha512)),
        "1.2.840.113549.1.1.1" => ("rsa", digest),
        "1.2.840.113549.1.1.10" => ("pss", None),
        "1.2.840.10045.4.1" => ("ecdsa", Some(Hash::Sha1)),
        "1.2.840.10045.4.3.2" => ("ecdsa", Some(Hash::Sha256)),
        "1.2.840.10045.4.3.3" => ("ecdsa", Some(Hash::Sha384)),
        "1.2.840.10045.4.3.4" => ("ecdsa", Some(Hash::Sha512)),
        "1.2.840.10045.2.1" => ("ecdsa", digest),
        other => return Err(format!("signature algorithm {other}")),
    };
    match kind {
        "rsa" => {
            let hash = hash.ok_or("digest algorithm")?;
            let key = rsa::RsaPublicKey::from_public_key_der(spki).map_err(|e| e.to_string())?;
            let hashed = hash.digest(message);
            let scheme = match hash {
                Hash::Md5 => rsa::Pkcs1v15Sign::new::<md5::Md5>(),
                Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                Hash::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                Hash::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                Hash::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            key.verify(scheme, &hashed, signature)
                // legacy signers (old timestamping services) sign the bare hash without DigestInfo
                .or_else(|_| key.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &hashed, signature))
                .map_err(|e| e.to_string())
        }
        "pss" => {
            // RSASSA-PSS-params: [0] hash (default SHA-1), [1] MGF1, [2] salt length (default 20)
            let mut hash = Hash::Sha1;
            let mut salt = 20usize;
            for p in params.map(|p| p.children()).unwrap_or_default() {
                match p.tag {
                    0xa0 => {
                        if let Some(h) = p.children().first().and_then(algorithm).and_then(|(o, _)| Hash::from_oid(&o)) {
                            hash = h;
                        }
                    }
                    0xa2 => {
                        if let Some(n) = p.children().first() {
                            salt = n.content.iter().fold(0usize, |a, b| (a << 8) | *b as usize);
                        }
                    }
                    _ => {}
                }
            }
            let key = rsa::RsaPublicKey::from_public_key_der(spki).map_err(|e| e.to_string())?;
            let hashed = hash.digest(message);
            let scheme = match hash {
                Hash::Md5 => return Err("PSS with MD5".into()),
                Hash::Sha1 => rsa::Pss::new_with_salt::<sha1::Sha1>(salt),
                Hash::Sha256 => rsa::Pss::new_with_salt::<sha2::Sha256>(salt),
                Hash::Sha384 => rsa::Pss::new_with_salt::<sha2::Sha384>(salt),
                Hash::Sha512 => rsa::Pss::new_with_salt::<sha2::Sha512>(salt),
            };
            key.verify(scheme, &hashed, signature).map_err(|e| e.to_string())
        }
        _ => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let hashed = hash.ok_or("digest algorithm")?.digest(message);
            if let Ok(k) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) {
                let s = p256::ecdsa::Signature::from_der(signature).map_err(|e| e.to_string())?;
                return k.verify_prehash(&hashed, &s).map_err(|e| e.to_string());
            }
            if let Ok(k) = p384::ecdsa::VerifyingKey::from_public_key_der(spki) {
                let s = p384::ecdsa::Signature::from_der(signature).map_err(|e| e.to_string())?;
                return k.verify_prehash(&hashed, &s).map_err(|e| e.to_string());
            }
            Err("elliptic curve (P-256 and P-384 are supported)".into())
        }
    }
}

// ---------------------------------------------------------------- PKCS#7 SignedData

struct Signer<'a> {
    issuer: Option<&'a [u8]>,
    serial: Option<&'a [u8]>,
    ski: Option<&'a [u8]>,
    digest: Option<Hash>,
    signed_attrs: Option<Tlv<'a>>,
    sig_alg: String,
    sig_params: Option<Tlv<'a>>,
    signature: &'a [u8],
    unsigned_attrs: Option<Tlv<'a>>,
}

struct SignedData<'a> {
    /// Encapsulated content: (type OID, the content TLV inside [0]).
    content_type: String,
    content: Option<Tlv<'a>>,
    certs: Vec<Cert<'a>>,
    signer: Signer<'a>,
}

fn parse_signer<'a>(si: &Tlv<'a>) -> Option<Signer<'a>> {
    let f = si.children();
    let sid = f.get(1)?;
    let (issuer, serial, ski) = if sid.tag == der::SEQUENCE {
        let c = sid.children();
        (Some(c.first()?.raw), Some(c.get(1)?.content), None)
    } else {
        (None, None, Some(sid.content))
    };
    let digest = f.get(2).and_then(algorithm).and_then(|(o, _)| Hash::from_oid(&o));
    let mut i = 3;
    let signed_attrs = f.get(i).filter(|t| t.tag == 0xa0).copied();
    if signed_attrs.is_some() {
        i += 1;
    }
    let (sig_alg, sig_params) = algorithm(f.get(i)?)?;
    let signature = f.get(i + 1)?.content;
    let unsigned_attrs = f.get(i + 2).filter(|t| t.tag == 0xa1).copied();
    Some(Signer { issuer, serial, ski, digest, signed_attrs, sig_alg, sig_params, signature, unsigned_attrs })
}

/// ContentInfo { signedData } → SignedData.
fn parse_signed_data(content_info: &[u8]) -> Option<SignedData<'_>> {
    let ci = der::parse(content_info).filter(|t| t.tag == der::SEQUENCE)?;
    let c = ci.children();
    if oid_of(c.first()?) != "1.2.840.113549.1.7.2" {
        return None;
    }
    let sd = c.get(1)?.children().into_iter().next()?;
    let items = sd.children();
    let encap = items.get(2)?.children();
    let content_type = encap.first().map(oid_of).unwrap_or_default();
    let content = encap.get(1).and_then(|e| e.children().into_iter().next());
    let mut certs = Vec::new();
    let mut signer = None;
    for it in items.iter().skip(3) {
        match it.tag {
            0xa0 => certs.extend(it.children().iter().filter(|c| c.tag == der::SEQUENCE).filter_map(|c| parse_cert(c.raw))),
            der::SET => signer = it.children().first().and_then(parse_signer),
            _ => {}
        }
    }
    Some(SignedData { content_type, content, certs, signer: signer? })
}

/// Attribute values of an attribute set ([0] / [1] / SET of Attribute ::= SEQ { OID, SET OF value }).
fn attribute<'a>(attrs: &Tlv<'a>, oid: &str) -> Option<Tlv<'a>> {
    attrs.children().into_iter().find_map(|a| {
        let c = a.children();
        (c.first().map(oid_of).as_deref() == Some(oid)).then(|| c.get(1).and_then(|set| set.children().into_iter().next())).flatten()
    })
}

/// The bytes the signer signed: the signed attributes re-tagged as SET.
fn signed_bytes(s: &Signer) -> Option<Vec<u8>> {
    let attrs = s.signed_attrs?;
    let mut raw = attrs.raw.to_vec();
    raw[0] = der::SET;
    Some(raw)
}

/// The same attributes in DER order (SET OF sorted by encoding). Some signers store them unsorted
/// but sign the canonical form, which is what CryptoAPI hashes.
fn sorted_set(attrs: &Tlv) -> Vec<u8> {
    let mut items: Vec<&[u8]> = attrs.children().iter().map(|c| c.raw).collect();
    items.sort();
    let body: Vec<u8> = items.concat();
    let mut out = vec![der::SET];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = n.to_be_bytes();
        let len = &len[len.iter().position(|&b| b != 0).unwrap_or(len.len() - 1)..];
        out.push(0x80 | len.len() as u8);
        out.extend_from_slice(len);
    }
    out.extend(body);
    out
}

/// Check that `s` signed `content` (its digest in the messageDigest attribute) with `cert`.
fn check_signer(s: &Signer, content: &[u8], cert: &Cert) -> Outcome {
    let Some(hash) = s.digest else { return Outcome::Malformed("unknown digest algorithm".into()) };
    let digest = hash.digest(content);
    let message = match signed_bytes(s) {
        Some(attrs) => {
            let md = s.signed_attrs.as_ref().and_then(|a| attribute(a, "1.2.840.113549.1.9.4"));
            if md.map(|m| m.content) != Some(digest.as_slice()) {
                return Outcome::BadDigest;
            }
            attrs
        }
        None => content.to_vec(),
    };
    let mut result = verify_signature(cert.spki, &s.sig_alg, s.sig_params, Some(hash), &message, s.signature);
    if result.is_err()
        && let Some(attrs) = &s.signed_attrs
    {
        let sorted = sorted_set(attrs);
        if sorted != message {
            result = verify_signature(cert.spki, &s.sig_alg, s.sig_params, Some(hash), &sorted, s.signature);
        }
    }
    match result {
        Ok(()) => Outcome::Ok,
        Err(e) if e.starts_with("signature algorithm") || e.starts_with("elliptic") => Outcome::Malformed(e),
        Err(_) => Outcome::BadSignature,
    }
}

fn find_signer_cert<'c, 'a>(s: &Signer, certs: &'c [Cert<'a>]) -> Option<&'c Cert<'a>> {
    certs.iter().find(|c| match (s.issuer, s.serial, s.ski) {
        (Some(i), Some(n), _) => c.issuer == i && strip_zero(c.serial) == strip_zero(n),
        (_, _, Some(k)) => c.ski == Some(k),
        _ => false,
    })
}

fn strip_zero(b: &[u8]) -> &[u8] {
    if b.len() > 1 && b[0] == 0 { &b[1..] } else { b }
}

/// Build the chain from `leaf` and check it at time `t`: every certificate valid at `t`, each
/// signed by the next, the last one a trusted root (or signed by one).
fn check_chain(leaf: &Cert, pool: &[Cert], anchors: &[Cert], t: i64) -> Outcome {
    let mut cur = leaf.clone();
    for _ in 0..10 {
        if !cur.valid_at(t) {
            return Outcome::NotTimeValid;
        }
        if anchors.iter().any(|a| a.raw == cur.raw) {
            return Outcome::Ok;
        }
        if let Some(a) = anchors.iter().find(|a| cur.signed_by(a)) {
            return if a.valid_at(t) { Outcome::Ok } else { Outcome::NotTimeValid };
        }
        if cur.issuer == cur.subject {
            // self-signed, not in the store
            return if cur.signed_by(&cur) { Outcome::UntrustedRoot } else { Outcome::Chaining };
        }
        match pool.iter().find(|c| c.raw != cur.raw && cur.signed_by(c)) {
            Some(next) => cur = next.clone(),
            None => return Outcome::Chaining,
        }
    }
    Outcome::Chaining
}

/// Signing time from a timestamp in the unsigned attributes, if the timestamp verifies.
fn timestamp(main: &SignedData, store: &TrustStore, anchors: &[Cert]) -> Option<i64> {
    let unsigned = main.signer.unsigned_attrs?;
    // PKCS#9 counter-signature: a SignerInfo over the main signature, its certificate in the main bag
    if let Some(cs) = attribute(&unsigned, "1.2.840.113549.1.9.6").and_then(|t| parse_signer(&t)) {
        let cert = find_signer_cert(&cs, &main.certs)?;
        let time = cs.signed_attrs.as_ref().and_then(|a| attribute(a, "1.2.840.113549.1.9.5")).and_then(|t| der::parse_time(&t))?;
        let ok =
            check_signer(&cs, main.signer.signature, cert) == Outcome::Ok && check_chain(cert, &main.certs, anchors, time) == Outcome::Ok;
        return ok.then_some(time);
    }
    // RFC 3161 token (Microsoft's 1.3.6.1.4.1.311.3.3.1 attribute): SignedData over a TSTInfo
    let token = attribute(&unsigned, "1.3.6.1.4.1.311.3.3.1")?;
    let ts = parse_signed_data(token.raw)?;
    if ts.content_type != "1.2.840.113549.1.9.16.1.4" {
        return None;
    }
    let tst_der = ts.content?.content;
    let tst = der::parse(tst_der)?.children();
    // TSTInfo ::= SEQ { version, policy, messageImprint SEQ { alg, OCTET }, serial, genTime, ... }
    let imprint = tst.get(2)?.children();
    let ih = imprint.first().and_then(algorithm).and_then(|(o, _)| Hash::from_oid(&o))?;
    if imprint.get(1)?.content != ih.digest(main.signer.signature).as_slice() {
        return None;
    }
    let time = tst.get(4).and_then(der::parse_time)?;
    let pool: Vec<Cert> = ts.certs.iter().chain(main.certs.iter()).cloned().collect();
    let cert = find_signer_cert(&ts.signer, &pool)?;
    let _ = store;
    let ok = check_signer(&ts.signer, tst_der, cert) == Outcome::Ok && check_chain(cert, &pool, anchors, time) == Outcome::Ok;
    ok.then_some(time)
}

/// Verify the Authenticode signature of a PE image at time `now` (Unix seconds).
pub fn verify(data: &[u8], store: &TrustStore, now: i64) -> Outcome {
    let pe = pe_parser::PeFile::parse(data);
    let Some(sec) = pe.security.as_ref() else { return Outcome::NoSignature };
    let Some(entry) = sec.entries.iter().find(|e| e.certificate_type == 2) else { return Outcome::NoSignature };
    // WIN_CERTIFICATE: dwLength, wRevision, wCertificateType, then the PKCS#7 blob
    let start = entry.offset as usize + 8;
    let end = (entry.offset as usize + entry.length as usize).min(data.len());
    let Some(blob) = data.get(start..end.max(start)) else { return Outcome::Malformed("certificate table".into()) };
    let Some(sd) = parse_signed_data(blob) else { return Outcome::Malformed("PKCS#7 SignedData".into()) };
    if sd.content_type != "1.3.6.1.4.1.311.2.1.4" {
        return Outcome::Malformed("not an Authenticode SpcIndirectDataContent".into());
    }
    let Some(content) = sd.content else { return Outcome::Malformed("empty content".into()) };
    // 1. image digest
    let di = content.children().get(1).map(|d| d.children()).unwrap_or_default();
    let Some(hash) = di.first().and_then(algorithm).and_then(|(o, _)| Hash::from_oid(&o)) else {
        return Outcome::Malformed("unknown image digest algorithm".into());
    };
    let signed_digest = di.get(1).map(|d| d.content).unwrap_or_default();
    if image_digest(data, hash).as_deref() != Some(signed_digest) {
        return Outcome::BadDigest;
    }
    // 2. signer
    let Some(cert) = find_signer_cert(&sd.signer, &sd.certs) else { return Outcome::Chaining };
    let r = check_signer(&sd.signer, content.content, cert);
    if r != Outcome::Ok {
        return r;
    }
    if !cert.allows_code_signing() {
        return Outcome::WrongUsage;
    }
    // 3./4. chain at the timestamp, else now
    let anchors: Vec<Cert> = store.roots.iter().filter_map(|r| parse_cert(r)).collect();
    let t = timestamp(&sd, store, &anchors).unwrap_or(now);
    check_chain(cert, &sd.certs, &anchors, t)
}

/// [`verify`] against the system store at the current time.
pub fn verify_now(data: &[u8]) -> CertificateCheck {
    verify(data, TrustStore::system(), crate::util::now_unix()).check()
}
