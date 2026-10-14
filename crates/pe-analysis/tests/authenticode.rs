//! The Rust Authenticode verifier on synthetic signatures: a test PKI signs a PE built by
//! `PeBuilder`, then every outcome is produced on purpose.

use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::EncodePublicKey;
use pe_analysis::authenticode::{self, Hash, Outcome, TrustStore};
use sha2::Digest;

// ---------------------------------------------------------------- DER writer

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = n.to_be_bytes();
        let len = &len[len.iter().position(|&b| b != 0).unwrap()..];
        out.push(0x80 | len.len() as u8);
        out.extend_from_slice(len);
    }
    out.extend_from_slice(body);
    out
}
fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}
fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &items.concat())
}
fn ctx(n: u8, body: &[u8]) -> Vec<u8> {
    tlv(0xa0 + n, body)
}
fn int(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut b = b[b.iter().position(|&x| x != 0).unwrap_or(7)..].to_vec();
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}
fn octets(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}
fn bits(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0];
    v.extend_from_slice(b);
    tlv(0x03, &v)
}
fn oid(s: &str) -> Vec<u8> {
    let p: Vec<u64> = s.split('.').map(|x| x.parse().unwrap()).collect();
    let mut body = vec![(p[0] * 40 + p[1]) as u8];
    for &v in &p[2..] {
        let mut chunk = vec![(v & 0x7f) as u8];
        let mut v = v >> 7;
        while v > 0 {
            chunk.insert(0, (v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        body.extend(chunk);
    }
    tlv(0x06, &body)
}
fn alg(o: &str) -> Vec<u8> {
    seq(&[oid(o)])
}
fn alg_null(o: &str) -> Vec<u8> {
    seq(&[oid(o), vec![0x05, 0x00]])
}
fn utc(t: i64) -> Vec<u8> {
    // YYMMDDhhmmssZ for 1950..2049
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil(days);
    tlv(0x17, format!("{:02}{m:02}{d:02}{:02}{:02}{:02}Z", y % 100, secs / 3600, secs / 60 % 60, secs % 60).as_bytes())
}
fn gen_time(t: i64) -> Vec<u8> {
    let (y, m, d) = civil(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    tlv(0x18, format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}Z", s / 3600, s / 60 % 60, s % 60).as_bytes())
}
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}
fn name(cn: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid("2.5.4.3"), tlv(0x0c, cn.as_bytes())])])])
}

// ---------------------------------------------------------------- keys and certificates

const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const DAY: i64 = 86400;
const NOW: i64 = 1_750_000_000; // 2025-06-15

enum Key {
    Ec(p256::ecdsa::SigningKey),
    Rsa(rsa::RsaPrivateKey),
    /// RSA signing the signer info with RSASSA-PSS (SHA-256, salt 32)
    Pss(rsa::RsaPrivateKey),
}

impl Key {
    fn ec(seed: u8) -> Key {
        Key::Ec(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap())
    }
    fn rsa_key() -> rsa::RsaPrivateKey {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap()
    }
    fn rsa() -> Key {
        Key::Rsa(Key::rsa_key())
    }
    fn spki(&self) -> Vec<u8> {
        match self {
            Key::Ec(k) => k.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec(),
            Key::Rsa(k) | Key::Pss(k) => rsa::pkcs8::EncodePublicKey::to_public_key_der(&k.to_public_key()).unwrap().as_bytes().to_vec(),
        }
    }
    /// (signature algorithm of certificates, signature of `msg`)
    fn sign(&self, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::Ec(k) => {
                let s: p256::ecdsa::Signature = k.sign(msg);
                (alg(ECDSA_SHA256), s.to_der().as_bytes().to_vec())
            }
            Key::Rsa(k) => {
                let h = sha2::Sha256::digest(msg);
                (alg_null("1.2.840.113549.1.1.11"), k.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &h).unwrap())
            }
            Key::Pss(k) => {
                use rand_chacha::rand_core::SeedableRng;
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11);
                let h = sha2::Sha256::digest(msg);
                (pss_alg(), k.sign_with_rng(&mut rng, rsa::Pss::new_with_salt::<sha2::Sha256>(32), &h).unwrap())
            }
        }
    }
    /// SignerInfo signature algorithm (the key algorithm, the digest is SHA-256).
    fn signer_alg(&self) -> Vec<u8> {
        match self {
            Key::Ec(_) => alg(ECDSA_SHA256),
            Key::Rsa(_) => alg_null("1.2.840.113549.1.1.1"),
            Key::Pss(_) => pss_alg(),
        }
    }
}

/// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
fn pss_alg() -> Vec<u8> {
    let params = seq(&[ctx(0, &alg_null(SHA256)), ctx(1, &seq(&[oid("1.2.840.113549.1.1.8"), alg_null(SHA256)])), ctx(2, &int(32))]);
    seq(&[oid("1.2.840.113549.1.1.10"), params])
}

struct CertSpec<'a> {
    serial: u64,
    subject: &'a str,
    issuer: &'a str,
    from: i64,
    to: i64,
    eku: Option<&'a str>,
}

fn cert(spec: &CertSpec, subject_key: &Key, issuer_key: &Key) -> Vec<u8> {
    let (sig_alg, _) = issuer_key.sign(b"");
    let mut tbs = vec![
        ctx(0, &int(2)),
        int(spec.serial),
        sig_alg.clone(),
        name(spec.issuer),
        seq(&[utc(spec.from), utc(spec.to)]),
        name(spec.subject),
        subject_key.spki(),
    ];
    if let Some(u) = spec.eku {
        let ext = seq(&[oid("2.5.29.37"), octets(&seq(&[oid(u)]))]);
        tbs.push(ctx(3, &seq(&[ext])));
    }
    let tbs = seq(&tbs);
    let (_, sig) = issuer_key.sign(&tbs);
    seq(&[tbs, sig_alg, bits(&sig)])
}

struct Pki {
    root_key: Key,
    root: Vec<u8>,
    ca_key: Key,
    ca: Vec<u8>,
    leaf_key: Key,
    leaf: Vec<u8>,
    tsa_key: Key,
    tsa: Vec<u8>,
}

fn pki(leaf_eku: &str, leaf_to: i64, leaf_key: Key) -> Pki {
    let (root_key, ca_key, tsa_key) = (Key::ec(1), Key::ec(2), Key::ec(4));
    let root = cert(
        &CertSpec { serial: 1, subject: "Test Root", issuer: "Test Root", from: NOW - 3650 * DAY, to: NOW + 3650 * DAY, eku: None },
        &root_key,
        &root_key,
    );
    let ca = cert(
        &CertSpec { serial: 2, subject: "Test CA", issuer: "Test Root", from: NOW - 1000 * DAY, to: NOW + 1000 * DAY, eku: None },
        &ca_key,
        &root_key,
    );
    let leaf = cert(
        &CertSpec { serial: 0x8001, subject: "Test Signer", issuer: "Test CA", from: NOW - 400 * DAY, to: leaf_to, eku: Some(leaf_eku) },
        &leaf_key,
        &ca_key,
    );
    let tsa = cert(
        &CertSpec {
            serial: 3,
            subject: "Test TSA",
            issuer: "Test Root",
            from: NOW - 1000 * DAY,
            to: NOW + 1000 * DAY,
            eku: Some("1.3.6.1.5.5.7.3.8"),
        },
        &tsa_key,
        &root_key,
    );
    Pki { root_key, root, ca_key, ca, leaf_key, leaf, tsa_key, tsa }
}

fn store(p: &Pki) -> TrustStore {
    TrustStore { roots: vec![p.root.clone()] }
}

// ---------------------------------------------------------------- signing

fn attr(o: &str, value: Vec<u8>) -> Vec<u8> {
    seq(&[oid(o), set(&[value])])
}

/// SignerInfo (issuer+serial) signing `content` with signed attributes.
fn signer_info(
    key: &Key,
    issuer: &str,
    serial: u64,
    content_type: &str,
    content: &[u8],
    extra: Vec<Vec<u8>>,
    unsigned: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut attrs =
        vec![attr("1.2.840.113549.1.9.3", oid(content_type)), attr("1.2.840.113549.1.9.4", octets(&sha2::Sha256::digest(content)))];
    attrs.extend(extra);
    let signed = set(&attrs);
    let (_, sig) = key.sign(&signed);
    let mut si = vec![int(1), seq(&[name(issuer), int(serial)]), alg(SHA256), ctx(0, &attrs.concat()), key.signer_alg(), octets(&sig)];
    if let Some(u) = unsigned {
        si.push(tlv(0xa1, &u));
    }
    seq(&si)
}

fn signed_data(content_type: &str, content: Vec<u8>, certs: &[&[u8]], si: Vec<u8>) -> Vec<u8> {
    let sd = seq(&[int(1), set(&[alg(SHA256)]), seq(&[oid(content_type), ctx(0, &content)]), ctx(0, &certs.concat()), set(&[si])]);
    seq(&[oid("1.2.840.113549.1.7.2"), ctx(0, &sd)])
}

enum Ts {
    None,
    Rfc3161(i64),
    Pkcs9(i64),
}

/// Sign the unsigned image `pe`: append the certificate table and set the security directory.
fn sign(pe: &[u8], p: &Pki, certs: &[&[u8]], ts: Ts) -> Vec<u8> {
    let mut data = pe.to_vec();
    while !data.len().is_multiple_of(8) {
        data.push(0);
    }
    let table = data.len();
    let l = pe_parser::PeFile::parse(&data).layout.unwrap();
    let dd = l.optional_header.data_directories_offset as usize + 4 * 8;
    data[dd..dd + 4].copy_from_slice(&(table as u32).to_le_bytes());
    let digest = authenticode::image_digest(&data, Hash::Sha256).unwrap();
    // SpcIndirectDataContent { SpcAttributeTypeAndOptionalValue, DigestInfo }
    let spc = seq(&[seq(&[oid("1.3.6.1.4.1.311.2.1.15"), seq(&[])]), seq(&[alg_null(SHA256), octets(&digest)])]);
    // the messageDigest covers the content octets of SpcIndirectDataContent (without its header)
    let spc_body = &spc[2 + usize::from(spc[1] & 0x80 != 0) * (spc[1] & 0x7f) as usize..];
    let signed =
        |unsigned: Option<Vec<u8>>| signer_info(&p.leaf_key, "Test CA", 0x8001, "1.3.6.1.4.1.311.2.1.4", spc_body, vec![], unsigned);
    let first = signed(None);
    let unsigned = match ts {
        Ts::None => None,
        Ts::Rfc3161(t) | Ts::Pkcs9(t) => {
            // the timestamp covers the signature value of the signer
            let f = pe_parser::der::parse(&first).unwrap().children();
            let sig_value = f.iter().rev().find(|t| t.tag == 0x04).unwrap().content.to_vec();
            Some(match ts {
                Ts::Rfc3161(_) => {
                    let tst = seq(&[
                        int(1),
                        oid("1.2.3.4"),
                        seq(&[alg(SHA256), octets(&sha2::Sha256::digest(&sig_value))]),
                        int(99),
                        gen_time(t),
                    ]);
                    let si = signer_info(&p.tsa_key, "Test Root", 3, "1.2.840.113549.1.9.16.1.4", &tst, vec![], None);
                    let token = signed_data("1.2.840.113549.1.9.16.1.4", octets(&tst), &[&p.tsa], si);
                    attr("1.3.6.1.4.1.311.3.3.1", token)
                }
                _ => {
                    let cs = signer_info(
                        &p.tsa_key,
                        "Test Root",
                        3,
                        "1.2.840.113549.1.7.1",
                        &sig_value,
                        vec![attr("1.2.840.113549.1.9.5", utc(t))],
                        None,
                    );
                    attr("1.2.840.113549.1.9.6", cs)
                }
            })
        }
    };
    let si = if unsigned.is_some() { signed(unsigned) } else { first };
    let mut all: Vec<&[u8]> = certs.to_vec();
    if matches!(ts, Ts::Pkcs9(_)) {
        all.push(&p.tsa);
    }
    let pkcs7 = signed_data("1.3.6.1.4.1.311.2.1.4", spc, &all, si);
    let len = 8 + pkcs7.len();
    let mut wc = (len as u32).to_le_bytes().to_vec();
    wc.extend(0x0200u16.to_le_bytes());
    wc.extend(2u16.to_le_bytes());
    wc.extend(&pkcs7);
    while !wc.len().is_multiple_of(8) {
        wc.push(0);
    }
    data.extend(&wc);
    data[dd + 4..dd + 8].copy_from_slice(&(wc.len() as u32).to_le_bytes());
    data
}

fn image() -> Vec<u8> {
    pe_parser::testutil::PeBuilder::new().build()
}

const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

#[test]
fn valid_signatures() {
    let p = pki(CODE_SIGNING, NOW + 300 * DAY, Key::ec(3));
    let signed = sign(&image(), &p, &[&p.leaf, &p.ca], Ts::None);
    assert_eq!(authenticode::verify(&signed, &store(&p), NOW), Outcome::Ok);
    assert_eq!(Outcome::Ok.check().verified, Some(true));
    // the chain may also end at a certificate that is itself in the store
    let with_root = sign(&image(), &p, &[&p.leaf, &p.ca, &p.root], Ts::None);
    assert_eq!(authenticode::verify(&with_root, &store(&p), NOW), Outcome::Ok);
    // RSA signer (PKCS#1 v1.5)
    let r = pki(CODE_SIGNING, NOW + 300 * DAY, Key::rsa());
    let signed = sign(&image(), &r, &[&r.leaf, &r.ca], Ts::None);
    assert_eq!(authenticode::verify(&signed, &store(&r), NOW), Outcome::Ok);
    // RSA signer with RSASSA-PSS
    let s = pki(CODE_SIGNING, NOW + 300 * DAY, Key::Pss(Key::rsa_key()));
    assert_eq!(authenticode::verify(&sign(&image(), &s, &[&s.leaf, &s.ca], Ts::None), &store(&s), NOW), Outcome::Ok);
    // any extended key usage is accepted for code signing
    let any = pki("2.5.29.37.0", NOW + 300 * DAY, Key::ec(3));
    assert_eq!(authenticode::verify(&sign(&image(), &any, &[&any.leaf, &any.ca], Ts::None), &store(&any), NOW), Outcome::Ok);
}

#[test]
fn failures() {
    let p = pki(CODE_SIGNING, NOW + 300 * DAY, Key::ec(3));
    let pe = image();
    let signed = sign(&pe, &p, &[&p.leaf, &p.ca], Ts::None);
    let s = store(&p);
    // unsigned file / not a PE
    assert_eq!(authenticode::verify(&pe, &s, NOW), Outcome::NoSignature);
    assert_eq!(authenticode::verify(b"MZ", &s, NOW), Outcome::NoSignature);
    // one byte changed in the code
    let mut tampered = signed.clone();
    tampered[0x200] ^= 1;
    assert_eq!(authenticode::verify(&tampered, &s, NOW), Outcome::BadDigest);
    assert!(Outcome::BadDigest.message().contains("bad digest"));
    // the checksum is not covered
    let l = pe_parser::PeFile::parse(&signed).layout.unwrap();
    let mut cs = signed.clone();
    let o = l.optional_header.checksum_offset() as usize;
    cs[o] ^= 0xff;
    assert_eq!(authenticode::verify(&cs, &s, NOW), Outcome::Ok);
    // the signature value changed (last bytes of the ECDSA signature in the table)
    let sig_pos = signed.windows(4).rposition(|w| w[0] == 0x04 && w[1] >= 0x46 && w[1] <= 0x48 && w[2] == 0x30).unwrap();
    let mut bad = signed.clone();
    bad[sig_pos + 10] ^= 0x55;
    assert!(
        matches!(authenticode::verify(&bad, &s, NOW), Outcome::BadSignature | Outcome::Malformed(_)),
        "{:?}",
        authenticode::verify(&bad, &s, NOW)
    );
    // missing intermediate, unknown root, expired, wrong usage
    let no_ca = sign(&pe, &p, &[&p.leaf], Ts::None);
    assert_eq!(authenticode::verify(&no_ca, &s, NOW), Outcome::Chaining);
    let self_signed_root = sign(&pe, &p, &[&p.leaf, &p.ca, &p.root], Ts::None);
    assert_eq!(authenticode::verify(&self_signed_root, &TrustStore::default(), NOW), Outcome::UntrustedRoot);
    assert_eq!(authenticode::verify(&signed, &TrustStore::default(), NOW), Outcome::Chaining);
    assert_eq!(authenticode::verify(&signed, &s, NOW + 500 * DAY), Outcome::NotTimeValid);
    let tls = pki("1.3.6.1.5.5.7.3.1", NOW + 300 * DAY, Key::ec(3));
    assert_eq!(authenticode::verify(&sign(&pe, &tls, &[&tls.leaf, &tls.ca], Ts::None), &store(&tls), NOW), Outcome::WrongUsage);
    // a signer certificate that is not in the bag
    let other = pki(CODE_SIGNING, NOW + 300 * DAY, Key::ec(9));
    assert_eq!(authenticode::verify(&sign(&pe, &p, &[&other.ca], Ts::None), &s, NOW), Outcome::Chaining);
    // garbage in the certificate table
    let mut junk = signed.clone();
    let start = pe_parser::PeFile::parse(&signed).security.unwrap().offset as usize + 8;
    junk[start] = 0x05;
    assert!(matches!(authenticode::verify(&junk, &s, NOW), Outcome::Malformed(_) | Outcome::NoSignature));
    for o in [
        Outcome::NoSignature,
        Outcome::BadSignature,
        Outcome::Chaining,
        Outcome::UntrustedRoot,
        Outcome::NotTimeValid,
        Outcome::WrongUsage,
        Outcome::Malformed("x".into()),
    ] {
        assert_eq!(o.check().verified, Some(false));
        assert!(!o.message().is_empty());
    }
}

#[test]
fn timestamps_extend_expired_certificates() {
    // the signer certificate expired; the signature was timestamped while it was valid
    let p = pki(CODE_SIGNING, NOW + 300 * DAY, Key::ec(3));
    let later = NOW + 600 * DAY;
    for ts in [Ts::Rfc3161(NOW), Ts::Pkcs9(NOW)] {
        let signed = sign(&image(), &p, &[&p.leaf, &p.ca], ts);
        assert_eq!(authenticode::verify(&signed, &store(&p), later), Outcome::Ok);
    }
    // a timestamp outside the validity does not help
    let signed = sign(&image(), &p, &[&p.leaf, &p.ca], Ts::Rfc3161(NOW + 400 * DAY));
    assert_eq!(authenticode::verify(&signed, &store(&p), later), Outcome::NotTimeValid);
    let _ = (&p.root_key, &p.ca_key);
}

#[test]
fn stores_and_helpers() {
    let ms = TrustStore::microsoft();
    assert_eq!(ms.roots.len(), 6);
    assert!(ms.roots.iter().all(|r| authenticode::parse_cert(r).is_some()));
    assert!(TrustStore::system().roots.len() >= ms.roots.len());
    // PEM bundles
    let der = &ms.roots[0];
    let b64 = {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in der.chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
            for i in 0..4 {
                s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        s
    };
    let pem = format!("junk\n-----BEGIN CERTIFICATE-----\n{}\n{}\n-----END CERTIFICATE-----\n", &b64[..64], &b64[64..]);
    assert_eq!(authenticode::pem_certificates(&pem), vec![der.clone()]);
    assert_eq!(authenticode::base64_decode("TWFu"), Some(b"Man".to_vec()));
    assert_eq!(authenticode::base64_decode("bad*"), None);
    assert!(!authenticode::LINUX_BUNDLES.is_empty());
    // hashes
    for (o, n) in
        [("1.2.840.113549.2.5", 16), ("1.3.14.3.2.26", 20), (SHA256, 32), ("2.16.840.1.101.3.4.2.2", 48), ("2.16.840.1.101.3.4.2.3", 64)]
    {
        assert_eq!(Hash::from_oid(o).unwrap().digest(b"x").len(), n);
    }
    assert_eq!(Hash::from_oid("1.2.3"), None);
    assert_eq!(authenticode::image_digest(b"not a pe", Hash::Sha256), None);
    // the whole-file entry point uses the system store
    let check = authenticode::verify_now(&image());
    assert_eq!((check.verified, check.message.as_str()), (Some(false), "No signature was present in the subject."));
}
