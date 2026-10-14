//! Authenticode PKCS#7 / X.509 / RFC 3161 DER decoding, fed directly with the signature blob.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe_parser::certificate::parse_pkcs7(data);
    if let Some(t) = pe_parser::der::parse(data) {
        let _ = pe_parser::der::parse_time(&t);
        let _ = pe_parser::der::name_to_string(&t);
        let _ = pe_parser::der::string_value(&t);
        let _ = pe_parser::certificate::parse_x509(&t);
    }
});
