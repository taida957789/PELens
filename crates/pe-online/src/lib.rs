//! Online services: VirusTotal score (hash only, the sample is never uploaded), search links
//! (VirusTotal, Google, MITRE, Microsoft Learn), update check and network status.

pub mod secret;

use pe_analysis::{EngineResult, ScoreReport};
use serde_json::Value;
use std::time::Duration;

pub const VT_HOST: &str = "https://www.virustotal.com";
/// Latest PELens release (GitHub API); `<update url>` in settings.xml may point to a plain-text file instead.
pub const UPDATE_URL: &str = "https://api.github.com/repos/taida957789/PELens/releases/latest";
pub const USER_AGENT: &str = "pelens";

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Minimal HTTP abstraction so the logic can be tested without network access.
pub trait HttpClient {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String>;
}

#[derive(Debug, Clone, Default)]
pub struct NetConfig {
    /// "host:port" of an HTTP proxy.
    pub proxy: Option<String>,
    pub timeout_secs: u64,
    pub user_agent: Option<String>,
}

pub struct UreqClient {
    agent: ureq::Agent,
}

impl UreqClient {
    pub fn new(cfg: &NetConfig) -> Self {
        let mut b = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(if cfg.timeout_secs == 0 { 20 } else { cfg.timeout_secs }))
            .user_agent(cfg.user_agent.as_deref().unwrap_or(USER_AGENT));
        if let Some(p) = cfg.proxy.as_deref().filter(|p| !p.is_empty())
            && let Ok(px) = ureq::Proxy::new(p)
        {
            b = b.proxy(px);
        }
        UreqClient { agent: b.build() }
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(r) => {
                let status = r.status();
                Ok(HttpResponse { status, body: r.into_string().map_err(|e| e.to_string())? })
            }
            Err(ureq::Error::Status(code, r)) => Ok(HttpResponse { status: code, body: r.into_string().unwrap_or_default() }),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtApi {
    V2,
    V3,
}

pub fn status_message(code: u16) -> String {
    match code {
        204 | 429 => "The quota has been reached.".into(),
        401 => "invalid key".into(),
        403 => "The server understands the request but refuses to authorize it".into(),
        404 => "Item not found at Virustotal".into(),
        c => format!("network error (http {c})"),
    }
}

fn report(status: &str, resource: &str) -> ScoreReport {
    ScoreReport { status: status.into(), resource: resource.into(), ..Default::default() }
}

/// Query VirusTotal for a hash (md5/sha1/sha256). Only the hash leaves the machine.
pub fn vt_file_report(c: &dyn HttpClient, api: VtApi, key: &str, hash: &str) -> ScoreReport {
    if key.trim().is_empty() {
        return report("disabled: no Virustotal key configured", hash);
    }
    match api {
        VtApi::V3 => {
            let url = format!("{VT_HOST}/api/v3/files/{hash}");
            match c.get(&url, &[("x-apikey", key)]) {
                Err(e) => report(&format!("offline: {e}"), hash),
                Ok(r) if r.status != 200 => report(&status_message(r.status), hash),
                Ok(r) => parse_v3(&r.body, hash),
            }
        }
        VtApi::V2 => {
            let url = format!("{VT_HOST}/vtapi/v2/file/report?apikey={key}&resource={hash}");
            match c.get(&url, &[]) {
                Err(e) => report(&format!("offline: {e}"), hash),
                Ok(r) if r.status != 200 => report(&status_message(r.status), hash),
                Ok(r) => parse_v2(&r.body, hash),
            }
        }
    }
}

pub fn parse_v3(body: &str, hash: &str) -> ScoreReport {
    let Ok(v) = serde_json::from_str::<Value>(body) else { return report("error: invalid response", hash) };
    let attrs = &v["data"]["attributes"];
    if attrs.is_null() {
        return report("Item not found at Virustotal", hash);
    }
    let mut engines: Vec<EngineResult> = attrs["last_analysis_results"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(vendor, e)| EngineResult {
                    vendor: vendor.clone(),
                    detected: e["category"].as_str() == Some("malicious") || e["category"].as_str() == Some("suspicious"),
                    result: e["result"].as_str().unwrap_or("").to_string(),
                    version: e["engine_version"].as_str().unwrap_or("").to_string(),
                    update: e["engine_update"].as_str().unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    engines.sort_by(|a, b| b.detected.cmp(&a.detected).then(a.vendor.to_ascii_lowercase().cmp(&b.vendor.to_ascii_lowercase())));
    let stats = &attrs["last_analysis_stats"];
    let positives = (stats["malicious"].as_u64().unwrap_or(0) + stats["suspicious"].as_u64().unwrap_or(0)) as u32;
    let total = stats.as_object().map(|m| m.values().filter_map(Value::as_u64).sum::<u64>() as u32).unwrap_or(engines.len() as u32);
    let date = attrs["last_analysis_date"].as_i64().map(pe_analysis::util::format_utc).unwrap_or_default();
    let id = v["data"]["id"].as_str().unwrap_or(hash).to_string();
    ScoreReport {
        status: "ok".into(),
        resource: hash.into(),
        positives,
        total,
        scan_date: date,
        permalink: vt_gui_file(&id),
        scan_id: id,
        engines,
    }
}

pub fn parse_v2(body: &str, hash: &str) -> ScoreReport {
    let Ok(v) = serde_json::from_str::<Value>(body) else { return report("error: invalid response", hash) };
    if v["response_code"].as_i64() != Some(1) {
        return report("Item not found at Virustotal", hash);
    }
    let mut engines: Vec<EngineResult> = v["scans"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(vendor, e)| EngineResult {
                    vendor: vendor.clone(),
                    detected: e["detected"].as_bool().unwrap_or(false),
                    result: e["result"].as_str().unwrap_or("").to_string(),
                    version: e["version"].as_str().unwrap_or("").to_string(),
                    update: e["update"].as_str().unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    engines.sort_by(|a, b| b.detected.cmp(&a.detected).then(a.vendor.to_ascii_lowercase().cmp(&b.vendor.to_ascii_lowercase())));
    ScoreReport {
        status: "ok".into(),
        resource: hash.into(),
        positives: v["positives"].as_u64().unwrap_or(0) as u32,
        total: v["total"].as_u64().unwrap_or(0) as u32,
        scan_date: v["scan_date"].as_str().unwrap_or("").to_string(),
        permalink: v["permalink"].as_str().map(str::to_string).unwrap_or_else(|| vt_gui_file(hash)),
        scan_id: v["scan_id"].as_str().unwrap_or("").to_string(),
        engines,
    }
}

/// URL score (hard-coded URLs found in strings).
pub fn vt_url_report(c: &dyn HttpClient, key: &str, url: &str) -> ScoreReport {
    if key.trim().is_empty() {
        return report("disabled: no Virustotal key configured", url);
    }
    let id = base64_url_nopad(url.as_bytes());
    match c.get(&format!("{VT_HOST}/api/v3/urls/{id}"), &[("x-apikey", key)]) {
        Err(e) => report(&format!("offline: {e}"), url),
        Ok(r) if r.status != 200 => report(&status_message(r.status), url),
        Ok(r) => {
            let mut s = parse_v3(&r.body, url);
            s.permalink = format!("{VT_HOST}/gui/url/{id}");
            s
        }
    }
}

pub fn base64_url_nopad(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        let k = ch.len() + 1;
        for i in 0..k {
            o.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    o
}

// ---------------------------------------------------------------- links

pub fn vt_gui_file(hash: &str) -> String {
    format!("{VT_HOST}/gui/file/{hash}/detection")
}

pub fn vt_search_hash(h: &str) -> String {
    format!("{VT_HOST}/gui/search/hash:{h}")
}

pub fn vt_search_imphash(h: &str) -> String {
    format!("{VT_HOST}/gui/search/imphash:{h}")
}

pub fn vt_search_content(s: &str) -> String {
    format!("{VT_HOST}/gui/search/content:%22{}%22", pe_analysis::view::url_encode(s))
}

pub fn vt_search_netguid(g: &str) -> String {
    format!("{VT_HOST}/gui/search/netguid:{g}")
}

pub fn google_search(q: &str) -> String {
    pe_analysis::view::google_url(q)
}

pub fn msdn_search(api: &str) -> String {
    format!("https://learn.microsoft.com/en-us/search/?terms={}", pe_analysis::view::url_encode(api))
}

pub fn mitre_technique(id: &str) -> String {
    format!("https://attack.mitre.org/techniques/T{}", id.trim_start_matches(['T', 't']))
}

// ---------------------------------------------------------------- update / network

/// Newest version advertised by the update URL: the `tag_name` of a GitHub release (without the
/// leading "v"), else the first non-empty line of a plain-text file.
pub fn check_update(c: &dyn HttpClient, url: &str) -> Result<String, String> {
    let r = c.get(url, &[("Accept", "application/vnd.github+json")])?;
    if r.status != 200 {
        return Err(status_message(r.status));
    }
    if let Ok(v) = serde_json::from_str::<Value>(&r.body)
        && v.is_object()
    {
        let tag = v["tag_name"].as_str().map(|t| t.trim().trim_start_matches(['v', 'V']));
        return tag.filter(|t| !t.is_empty()).map(str::to_string).ok_or_else(|| "no release found".into());
    }
    r.body.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string).ok_or_else(|| "empty response".into())
}

/// Compare dotted versions ("0.3.0" < "0.4.0").
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let p = |s: &str| s.split(['.', ' ']).map(|x| x.trim().parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    p(candidate) > p(current)
}

/// Lightweight connectivity probe (TCP connect to the VirusTotal host).
pub fn network_alive(timeout: Duration) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = "www.virustotal.com:443".to_socket_addrs() else { return false };
    addrs.next().is_some_and(|a| std::net::TcpStream::connect_timeout(&a, timeout).is_ok())
}

/// Settings → (api, key, enabled).
/// (API version, key, enabled) with the key from `VT_API_KEY`, the system credential store or
/// a legacy plaintext `<score key>` (see [`secret::resolve_key`]).
pub fn vt_settings(k: &pe_db::Knowledge) -> (VtApi, String, bool) {
    vt_settings_with(k, &secret::CredentialStore::vt())
}

pub fn vt_settings_with(k: &pe_db::Knowledge, store: &dyn secret::KeyStore) -> (VtApi, String, bool) {
    let s = &k.settings;
    let key = secret::resolve_key(k, store);
    let api = if s.get_int("score", "api", 3) == 2 { VtApi::V2 } else { VtApi::V3 };
    (api, key, s.get_bool("score", "enable", true))
}

pub fn net_config(k: &pe_db::Knowledge) -> NetConfig {
    let s = &k.settings;
    let proxy = match (s.get("proxy", "address"), s.get("proxy", "port")) {
        (Some(a), Some(p)) if !a.is_empty() && !p.trim().is_empty() => Some(format!("{a}:{}", p.trim())),
        (Some(a), _) if !a.is_empty() => Some(a.to_string()),
        _ => None,
    };
    NetConfig {
        proxy,
        timeout_secs: s.get_int("proxy", "timeout", 20).max(1) as u64,
        user_agent: s.get("proxy", "agent").map(str::to_string),
    }
}

/// Attach the VirusTotal score to an analysis and derive the score indicators.
pub fn attach_score(a: &mut pe_analysis::Analysis, k: &pe_db::Knowledge, c: &dyn HttpClient) {
    attach_score_with(a, k, c, &secret::CredentialStore::vt());
}

pub fn attach_score_with(a: &mut pe_analysis::Analysis, k: &pe_db::Knowledge, c: &dyn HttpClient, store: &dyn secret::KeyStore) {
    let (api, key, enabled) = vt_settings_with(k, store);
    if !enabled {
        a.score = Some(report("disabled", &a.hashes.md5));
    } else {
        a.score = Some(vt_file_report(c, api, &key, &a.hashes.md5.to_ascii_lowercase()));
    }
    pe_analysis::indicators::score_indicators(a, k);
}
