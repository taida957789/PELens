use pe_online::*;
use std::cell::RefCell;

struct Mock {
    responses: RefCell<Vec<Result<HttpResponse, String>>>,
    seen: RefCell<Vec<(String, Vec<(String, String)>)>>,
}

impl Mock {
    fn new(r: Vec<Result<HttpResponse, String>>) -> Self {
        Mock { responses: RefCell::new(r), seen: RefCell::new(Vec::new()) }
    }
}

impl HttpClient for Mock {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String> {
        self.seen.borrow_mut().push((url.to_string(), headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()));
        self.responses.borrow_mut().remove(0)
    }
}

fn ok(body: &str) -> Result<HttpResponse, String> {
    Ok(HttpResponse { status: 200, body: body.into() })
}

const V3: &str = r#"{"data":{"id":"abc","attributes":{"last_analysis_date":1700000000,
 "last_analysis_stats":{"malicious":2,"suspicious":1,"undetected":3,"harmless":0},
 "last_analysis_results":{"Zed":{"category":"malicious","result":"Trojan.X","engine_version":"1","engine_update":"20240101"},
                          "alpha":{"category":"undetected","result":null},
                          "Beta":{"category":"suspicious","result":"Heur"}}}}}"#;

const V2: &str = r#"{"response_code":1,"positives":1,"total":2,"scan_date":"2024-01-01 00:00:00","permalink":"https://vt/p","scan_id":"sid",
 "scans":{"B":{"detected":false,"result":null,"version":"2","update":"u"},"A":{"detected":true,"result":"Mal"}}}"#;

#[test]
fn virustotal_v3() {
    let m = Mock::new(vec![ok(V3)]);
    let r = vt_file_report(&m, VtApi::V3, "KEY", "abc");
    assert_eq!(r.status, "ok");
    assert_eq!((r.positives, r.total), (3, 6));
    assert_eq!(r.engines[0].vendor, "Beta");
    assert_eq!(r.engines[1].vendor, "Zed");
    assert!(r.engines[1].detected && r.engines[1].result == "Trojan.X" && r.engines[1].version == "1");
    assert_eq!(r.engines[2].vendor, "alpha");
    assert!(r.permalink.ends_with("/gui/file/abc/detection"));
    assert_eq!(r.scan_date, "14.11.2023 | 22:13:20");
    let seen = m.seen.borrow();
    assert_eq!(seen[0].0, "https://www.virustotal.com/api/v3/files/abc");
    assert_eq!(seen[0].1, vec![("x-apikey".to_string(), "KEY".to_string())]);
}

#[test]
fn virustotal_v2_and_errors() {
    let m = Mock::new(vec![
        ok(V2),
        ok(r#"{"response_code":0}"#),
        ok("garbage"),
        Ok(HttpResponse { status: 204, body: String::new() }),
        Err("dns".into()),
    ]);
    let r = vt_file_report(&m, VtApi::V2, "K", "h");
    assert_eq!((r.status.as_str(), r.positives, r.total), ("ok", 1, 2));
    assert_eq!(r.engines[0].vendor, "A");
    assert_eq!(r.permalink, "https://vt/p");
    assert!(m.seen.borrow()[0].0.contains("/vtapi/v2/file/report?apikey=K&resource=h"));
    assert_eq!(vt_file_report(&m, VtApi::V2, "K", "h").status, "Item not found at Virustotal");
    assert_eq!(vt_file_report(&m, VtApi::V2, "K", "h").status, "error: invalid response");
    assert_eq!(vt_file_report(&m, VtApi::V2, "K", "h").status, "The quota has been reached.");
    assert!(vt_file_report(&m, VtApi::V2, "K", "h").status.starts_with("offline"));
    assert!(vt_file_report(&m, VtApi::V3, " ", "h").status.starts_with("disabled"));

    let m3 = Mock::new(vec![Ok(HttpResponse { status: 404, body: String::new() }), Err("x".into()), ok("{}"), ok("nope")]);
    assert_eq!(vt_file_report(&m3, VtApi::V3, "K", "h").status, "Item not found at Virustotal");
    assert!(vt_file_report(&m3, VtApi::V3, "K", "h").status.starts_with("offline"));
    assert_eq!(vt_file_report(&m3, VtApi::V3, "K", "h").status, "Item not found at Virustotal");
    assert_eq!(vt_file_report(&m3, VtApi::V3, "K", "h").status, "error: invalid response");
    for c in [204, 401, 403, 404, 429, 500] {
        assert!(!status_message(c).is_empty());
    }
    // v2 without permalink
    let r = parse_v2(r#"{"response_code":1}"#, "zz");
    assert!(r.permalink.ends_with("/gui/file/zz/detection"));
    // v3 without stats
    let r = parse_v3(r#"{"data":{"attributes":{"last_analysis_results":{"a":{"category":"malicious"}}}}}"#, "q");
    assert_eq!((r.positives, r.total), (0, 1));
}

#[test]
fn url_report() {
    let m = Mock::new(vec![ok(V3), Err("x".into()), Ok(HttpResponse { status: 401, body: String::new() })]);
    let r = vt_url_report(&m, "K", "http://a/");
    assert_eq!(r.status, "ok");
    assert_eq!(r.permalink, format!("https://www.virustotal.com/gui/url/{}", base64_url_nopad(b"http://a/")));
    assert!(vt_url_report(&m, "K", "u").status.starts_with("offline"));
    assert_eq!(vt_url_report(&m, "K", "u").status, "invalid key");
    assert!(vt_url_report(&m, "", "u").status.starts_with("disabled"));
    assert_eq!(base64_url_nopad(b"http://a/"), "aHR0cDovL2Ev");
    assert_eq!(base64_url_nopad(b"a"), "YQ");
    assert_eq!(base64_url_nopad(b"ab"), "YWI");
    assert_eq!(base64_url_nopad(b"\xfb\xff"), "-_8");
}

#[test]
fn links() {
    assert_eq!(vt_gui_file("x"), "https://www.virustotal.com/gui/file/x/detection");
    assert_eq!(vt_search_hash("h"), "https://www.virustotal.com/gui/search/hash:h");
    assert_eq!(vt_search_imphash("i"), "https://www.virustotal.com/gui/search/imphash:i");
    assert_eq!(vt_search_content("a b"), "https://www.virustotal.com/gui/search/content:%22a+b%22");
    assert_eq!(vt_search_netguid("g"), "https://www.virustotal.com/gui/search/netguid:g");
    assert!(google_search("q").contains("google.com/search?q=q"));
    assert!(msdn_search("CreateFileW").ends_with("terms=CreateFileW"));
    assert_eq!(mitre_technique("T1055"), "https://attack.mitre.org/techniques/T1055");
    assert_eq!(mitre_technique("1055"), "https://attack.mitre.org/techniques/T1055");
}

#[test]
fn update_check() {
    let m = Mock::new(vec![ok("\n 9.62 \nmore"), ok("   \n"), Ok(HttpResponse { status: 500, body: String::new() }), Err("x".into())]);
    assert_eq!(check_update(&m, UPDATE_URL).unwrap(), "9.62");
    assert!(check_update(&m, UPDATE_URL).is_err());
    assert!(check_update(&m, UPDATE_URL).is_err());
    assert!(check_update(&m, UPDATE_URL).is_err());
    assert!(is_newer("9.62", "9.61"));
    assert!(is_newer("10.0", "9.61"));
    assert!(!is_newer("9.61", "9.61"));
    assert!(!is_newer("9.6", "9.61"));
}

#[test]
fn settings_and_attach() {
    let mut k = pe_db::Knowledge::builtin();
    let (api, key, en) = vt_settings(&k);
    assert_eq!(api, VtApi::V3);
    assert!(!en);
    let _ = key;
    k.settings.set("score", "enable", "1");
    k.settings.set("score", "key", "abc");
    k.settings.set("score", "api", "2");
    let (api, key, en) = vt_settings(&k);
    assert_eq!((api, key.as_str(), en), (VtApi::V2, "abc", true));
    assert!(net_config(&k).proxy.is_none());
    k.settings.set("proxy", "address", "10.0.0.1");
    assert_eq!(net_config(&k).proxy.as_deref(), Some("10.0.0.1"));
    k.settings.set("proxy", "port", "8080");
    k.settings.set("proxy", "agent", "UA");
    let nc = net_config(&k);
    assert_eq!(nc.proxy.as_deref(), Some("10.0.0.1:8080"));
    assert_eq!(nc.user_agent.as_deref(), Some("UA"));

    let data = pe_parser::testutil::PeBuilder::new().build();
    let mut a = pe_analysis::analyze(&data, "x.exe", &k, &pe_analysis::Options::default());
    let m = Mock::new(vec![ok(V2)]);
    attach_score(&mut a, &k, &m);
    assert_eq!(a.score.as_ref().unwrap().positives, 1);
    assert!(m.seen.borrow()[0].0.contains(&a.hashes.md5.to_ascii_lowercase()));
    k.settings.set("score", "enable", "0");
    let m = Mock::new(vec![]);
    attach_score(&mut a, &k, &m);
    assert_eq!(a.score.as_ref().unwrap().status, "disabled");
}

#[test]
fn real_client_offline_paths() {
    // An unroutable proxy makes the request fail fast without touching the internet.
    let c = UreqClient::new(&NetConfig { proxy: Some("127.0.0.1:9".into()), timeout_secs: 2, user_agent: None });
    assert!(c.get("http://example.invalid/", &[("a", "b")]).is_err());
    let c2 = UreqClient::new(&NetConfig::default());
    assert!(c2.get("http://127.0.0.1:9/", &[]).is_err());
    let _ = network_alive(std::time::Duration::from_millis(1));
    // a bad proxy string is ignored
    let _ = UreqClient::new(&NetConfig { proxy: Some("::::".into()), timeout_secs: 0, user_agent: Some("x".into()) });
}

#[test]
fn local_http_server() {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        for body_status in [("9.70", 200u16), ("nope", 404)] {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let (b, st) = body_status;
            let _ = write!(s, "HTTP/1.1 {st} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len());
        }
    });
    let c = UreqClient::new(&NetConfig::default());
    let r = c.get(&format!("http://127.0.0.1:{port}/version.txt"), &[("X-Test", "1")]).unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "9.70"));
    let r = c.get(&format!("http://127.0.0.1:{port}/missing"), &[]).unwrap();
    assert_eq!(r.status, 404);
    t.join().unwrap();
}

/// Code review minor: a proxy address without a port is still used.
#[test]
fn proxy_without_port() {
    let mut k = pe_db::Knowledge::builtin();
    k.settings.set("proxy", "address", "10.1.1.1");
    k.settings.set("proxy", "port", " ");
    assert_eq!(net_config(&k).proxy.as_deref(), Some("10.1.1.1"));
}
