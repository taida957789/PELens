//! DER writer for synthetic Authenticode blobs used in tests.

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else if n < 0x100 {
        v.extend([0x81, n as u8]);
    } else if n < 0x10000 {
        v.extend([0x82, (n >> 8) as u8, n as u8]);
    } else {
        v.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(content);
    v
}

pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &items.concat())
}

pub fn ctx(n: u8, items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa0 | n, &items.concat())
}

pub fn ctx_prim(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

pub fn int(b: &[u8]) -> Vec<u8> {
    tlv(0x02, b)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn bitstring(b: &[u8]) -> Vec<u8> {
    let mut c = vec![0u8];
    c.extend_from_slice(b);
    tlv(0x03, &c)
}

pub fn utc(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}

pub fn gentime(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}

pub fn printable(s: &str) -> Vec<u8> {
    tlv(0x13, s.as_bytes())
}

pub fn bmp(s: &str) -> Vec<u8> {
    tlv(0x1e, &s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect::<Vec<_>>())
}

pub fn oid(s: &str) -> Vec<u8> {
    let parts: Vec<u64> = s.split('.').map(|p| p.parse().unwrap()).collect();
    let mut b = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        let mut stack = vec![(p & 0x7f) as u8];
        let mut v = p >> 7;
        while v > 0 {
            stack.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        b.extend(stack);
    }
    tlv(0x06, &b)
}

pub fn alg(o: &str) -> Vec<u8> {
    seq(&[oid(o), null()])
}

pub fn name(pairs: &[(&str, &str)]) -> Vec<u8> {
    seq(&pairs.iter().map(|(o, v)| set(&[seq(&[oid(o), printable(v)])])).collect::<Vec<_>>())
}

pub fn certificate(serial: &[u8], subject_cn: &str, issuer_cn: &str, crl: Option<&str>) -> Vec<u8> {
    let mut exts = vec![seq(&[oid("2.5.29.37"), octet(&seq(&[oid("1.3.6.1.5.5.7.3.3")]))])];
    if let Some(u) = crl {
        exts.push(seq(&[oid("2.5.29.31"), octet(&seq(&[seq(&[ctx(0, &[ctx(0, &[ctx_prim(6, u.as_bytes())])])])]))]));
    }
    let tbs = seq(&[
        ctx(0, &[int(&[2])]),
        int(serial),
        alg("1.2.840.113549.1.1.11"),
        name(&[("2.5.4.3", issuer_cn), ("2.5.4.10", "Issuer Org")]),
        seq(&[utc("200101000000Z"), gentime("20300101000000Z")]),
        name(&[("2.5.4.3", subject_cn), ("2.5.4.6", "US"), ("1.2.840.113549.1.9.1", "a@b.c")]),
        seq(&[alg("1.2.840.113549.1.1.1"), bitstring(&[0])]),
        ctx(3, &[seq(&exts)]),
    ]);
    seq(&[tbs, alg("1.2.840.113549.1.1.11"), bitstring(&[1, 2, 3])])
}

/// Authenticode SignedData with signer, program name, url, counter signature, nested signature
/// and optionally an RFC3161 timestamp token.
pub fn authenticode(rfc3161: bool) -> Vec<u8> {
    let issuer = name(&[("2.5.4.3", "Test CA")]);
    let indirect = seq(&[
        oid("1.3.6.1.4.1.311.2.1.4"),
        ctx(0, &[seq(&[seq(&[oid("1.3.6.1.4.1.311.2.1.15"), seq(&[])]), seq(&[alg("2.16.840.1.101.3.4.2.1"), octet(&[0xab; 32])])])]),
    ]);
    let opus = seq(&[
        ctx(0, &[ctx_prim(0, &"Prog".encode_utf16().flat_map(|u| u.to_be_bytes()).collect::<Vec<_>>())]),
        ctx(1, &[ctx_prim(0, b"http://more.info")]),
    ]);
    let auth = ctx(
        0,
        &[
            seq(&[oid("1.2.840.113549.1.9.3"), set(&[oid("1.3.6.1.4.1.311.2.1.4")])]),
            seq(&[oid("1.2.840.113549.1.9.5"), set(&[utc("210203040506Z")])]),
            seq(&[oid("1.3.6.1.4.1.311.2.1.12"), set(&[opus])]),
        ],
    );
    let unauth_item = if rfc3161 {
        let tst = seq(&[
            int(&[1]),
            oid("1.2.3.4"),
            seq(&[alg("2.16.840.1.101.3.4.2.1"), octet(&[0; 32])]),
            int(&[9]),
            gentime("20220304050607Z"),
        ]);
        let ts_signer = seq(&[
            int(&[1]),
            seq(&[name(&[("2.5.4.3", "TS CA")]), int(&[0x07])]),
            alg("2.16.840.1.101.3.4.2.1"),
            alg("1.2.840.113549.1.1.1"),
            octet(&[0; 4]),
        ]);
        let ts_sd = seq(&[
            int(&[3]),
            set(&[alg("2.16.840.1.101.3.4.2.1")]),
            seq(&[oid("1.2.840.113549.1.9.16.1.4"), ctx(0, &[octet(&tst)])]),
            ctx(0, &[certificate(&[0x07], "TS Signer", "TS CA", None), ctx(1, &[seq(&[])])]),
            set(&[ts_signer]),
        ]);
        seq(&[oid("1.3.6.1.4.1.311.3.3.1"), set(&[seq(&[oid("1.2.840.113549.1.7.2"), ctx(0, &[ts_sd])])])])
    } else {
        let counter = seq(&[
            int(&[1]),
            seq(&[name(&[("2.5.4.3", "TS CA")]), int(&[0x02])]),
            alg("1.3.14.3.2.26"),
            ctx(0, &[seq(&[oid("1.2.840.113549.1.9.5"), set(&[utc("210203040507Z")])])]),
            alg("1.2.840.113549.1.1.1"),
            octet(&[0; 4]),
        ]);
        seq(&[oid("1.2.840.113549.1.9.6"), set(&[counter])])
    };
    let nested = seq(&[oid("1.3.6.1.4.1.311.2.4.1"), set(&[seq(&[]), seq(&[])])]);
    let signer = seq(&[
        int(&[1]),
        seq(&[issuer, int(&[0x00, 0x91])]),
        alg("2.16.840.1.101.3.4.2.1"),
        auth,
        alg("1.2.840.113549.1.1.1"),
        octet(&[0x55; 16]),
        ctx(1, &[unauth_item, nested]),
    ]);
    let sd = seq(&[
        int(&[1]),
        set(&[alg("2.16.840.1.101.3.4.2.1")]),
        indirect,
        ctx(
            0,
            &[
                certificate(&[0x00, 0x91], "Signer Co", "Test CA", Some("http://crl.test/ca.crl")),
                certificate(&[0x02], "TS Counter", "TS CA", None),
            ],
        ),
        set(&[signer]),
    ]);
    seq(&[oid("1.2.840.113549.1.7.2"), ctx(0, &[sd])])
}
