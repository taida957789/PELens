//! User-interface languages: built-in catalogs (English text → translation) and locale detection.
//!
//! The English text is the key, so a missing entry simply shows the English text. Catalogs are
//! tab-separated files in `i18n/` (`key<TAB>translation`, `#` comments). Analysis data (table
//! cells, indicators, reports) is never translated: it stays identical to the reports and to
//! what the search box matches.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Lang {
    #[default]
    En,
    ZhTw,
    ZhCn,
    Ja,
    Ko,
    Es,
    De,
    Fr,
}

impl Lang {
    pub const ALL: [Lang; 8] = [Lang::En, Lang::ZhTw, Lang::ZhCn, Lang::Ja, Lang::Ko, Lang::Es, Lang::De, Lang::Fr];

    /// BCP 47 code, as stored in settings.xml (`<language code="zh-TW"/>`) and given to `-lang:`.
    pub fn code(self) -> &'static str {
        ["en", "zh-TW", "zh-CN", "ja", "ko", "es", "de", "fr"][self as usize]
    }

    /// The language's name in that language (menu entries).
    pub fn native_name(self) -> &'static str {
        ["English", "繁體中文", "简体中文", "日本語", "한국어", "Español", "Deutsch", "Français"][self as usize]
    }

    /// Parse a language code or a locale name (`zh_TW.UTF-8`, `zh-Hant-HK`, `de-AT`, …).
    pub fn from_code(s: &str) -> Option<Lang> {
        let s = s.split(['.', '@']).next().unwrap_or("").trim().replace('_', "-").to_ascii_lowercase();
        let mut parts = s.split('-');
        let lang = match parts.next()? {
            "en" => Lang::En,
            "zh" => {
                let rest: Vec<&str> = parts.collect();
                let traditional = rest.iter().any(|p| matches!(*p, "hant" | "tw" | "hk" | "mo"));
                return Some(if traditional { Lang::ZhTw } else { Lang::ZhCn });
            }
            "ja" => Lang::Ja,
            "ko" => Lang::Ko,
            "es" => Lang::Es,
            "de" => Lang::De,
            "fr" => Lang::Fr,
            _ => return None,
        };
        Some(lang)
    }

    fn source(self) -> &'static str {
        match self {
            Lang::En => "",
            Lang::ZhTw => include_str!("../i18n/zh-TW.tsv"),
            Lang::ZhCn => include_str!("../i18n/zh-CN.tsv"),
            Lang::Ja => include_str!("../i18n/ja.tsv"),
            Lang::Ko => include_str!("../i18n/ko.tsv"),
            Lang::Es => include_str!("../i18n/es.tsv"),
            Lang::De => include_str!("../i18n/de.tsv"),
            Lang::Fr => include_str!("../i18n/fr.tsv"),
        }
    }

    /// The catalog of this language (empty for English).
    pub fn catalog(self) -> &'static HashMap<&'static str, &'static str> {
        static CATALOGS: OnceLock<Vec<HashMap<&'static str, &'static str>>> = OnceLock::new();
        &CATALOGS.get_or_init(|| Lang::ALL.iter().map(|l| parse_catalog(l.source())).collect())[self as usize]
    }
}

/// Parse `key<TAB>translation` lines; blank lines and lines starting with `#` are ignored.
pub fn parse_catalog(src: &str) -> HashMap<&str, &str> {
    src.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(k, v)| (k, v.trim_end_matches('\r')))
        .collect()
}

/// The translation of `key`, or `key` itself when the catalog has none.
pub fn translate(lang: Lang, key: &str) -> &str {
    lang.catalog().get(key).copied().unwrap_or(key)
}

/// Replace `{0}`, `{1}`, … in a (translated) template.
pub fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = template.to_string();
    for (i, a) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), &a.to_string());
    }
    out
}

/// Language of the user's Windows display locale (or `LC_ALL` / `LANG` elsewhere); English when
/// the locale has no catalog.
pub fn system_lang() -> Lang {
    locale_name().as_deref().and_then(Lang::from_code).unwrap_or_default()
}

#[cfg(windows)]
fn locale_name() -> Option<String> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    // SAFETY: the buffer is LOCALE_NAME_MAX_LENGTH (85) wide characters, as the API requires.
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
    (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
}

/// macOS: the first preferred language of the user (GUI apps get no LANG); Linux and other Unix
/// systems: LC_ALL / LC_MESSAGES / LANG.
#[cfg(not(windows))]
fn locale_name() -> Option<String> {
    sys_locale::get_locale()
        .filter(|l| !l.is_empty() && l != "C" && l != "POSIX")
        .or_else(|| ["LC_ALL", "LC_MESSAGES", "LANG"].iter().filter_map(|v| std::env::var(v).ok()).find(|v| !v.is_empty()))
}
