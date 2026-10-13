//! Format-preserving attribute updates (pestudio rewrites its XML files when the user
//! toggles a flag or changes a severity; comments and layout must survive).

use quick_xml::Reader;
use quick_xml::events::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key<'a> {
    /// Element whose attribute `name` equals `value`.
    Attr(&'a str, &'a str),
    /// Element whose text content equals the value.
    Text(&'a str),
    /// First matching element.
    First,
}

#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// Optional enclosing element (tag + key) restricting the search.
    pub scope: Option<(&'a str, Key<'a>)>,
    pub tag: &'a str,
    pub key: Key<'a>,
}

fn escape_attr(v: &str) -> String {
    v.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Byte range of the start tag of the target element.
pub fn find(src: &str, t: &Target) -> Option<(usize, usize)> {
    let mut r = Reader::from_str(src);
    r.config_mut().check_end_names = false;
    let mut depth: usize = 0;
    let mut scope_depth: Option<usize> = None;
    let mut pending: Option<(usize, usize)> = None;
    loop {
        let before = r.buffer_position() as usize;
        let ev = r.read_event().ok()?;
        let after = r.buffer_position() as usize;
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_empty = matches!(ev, Event::Empty(_));
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let attr = |k: &str| {
                    e.attributes()
                        .with_checks(false)
                        .flatten()
                        .find(|a| a.key.as_ref() == k.as_bytes())
                        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
                };
                pending = None;
                if let Some((stag, skey)) = t.scope
                    && scope_depth.is_none()
                    && name == stag
                {
                    let hit = match skey {
                        Key::Attr(k, v) => attr(k).as_deref() == Some(v),
                        Key::First => true,
                        Key::Text(_) => false,
                    };
                    if hit && !is_empty {
                        scope_depth = Some(depth);
                    }
                }
                let in_scope = t.scope.is_none() || scope_depth.is_some_and(|d| depth > d);
                if in_scope && name == t.tag {
                    match t.key {
                        Key::Attr(k, v) if attr(k).as_deref() == Some(v) => return Some((before, after)),
                        Key::First => return Some((before, after)),
                        Key::Text(_) if !is_empty => pending = Some((before, after)),
                        _ => {}
                    }
                }
                if !is_empty {
                    depth += 1;
                }
            }
            Event::Text(ref x) => {
                if let (Some(p), Key::Text(want)) = (pending, t.key) {
                    let s = x.unescape().map(|c| c.into_owned()).unwrap_or_default();
                    if s.trim() == want {
                        return Some(p);
                    }
                }
                pending = None;
            }
            Event::End(_) => {
                pending = None;
                depth = depth.saturating_sub(1);
                if scope_depth == Some(depth) {
                    scope_depth = None;
                }
            }
            Event::Eof => return None,
            _ => {}
        }
    }
}

/// Set (or insert) attribute `attr` on the target element. Returns the new document.
pub fn set_attr(src: &str, t: &Target, attr: &str, value: &str) -> Option<String> {
    let (s, e) = find(src, t)?;
    let tag = &src[s..e];
    let val = escape_attr(value);
    let new_tag = replace_in_tag(tag, attr, &val);
    Some(format!("{}{}{}", &src[..s], new_tag, &src[e..]))
}

fn replace_in_tag(tag: &str, attr: &str, val: &str) -> String {
    let bytes = tag.as_bytes();
    let needle = format!("{attr}=");
    let mut from = 0;
    while let Some(p) = tag[from..].find(&needle) {
        let at = from + p;
        let prev = if at == 0 { b' ' } else { bytes[at - 1] };
        if prev.is_ascii_whitespace() {
            let q = at + needle.len();
            if let Some(&quote) = bytes.get(q)
                && (quote == b'"' || quote == b'\'')
                && let Some(end) = tag[q + 1..].find(quote as char)
            {
                return format!("{}{}{}", &tag[..q + 1], val, &tag[q + 1 + end..]);
            }
        }
        from = at + needle.len();
    }
    // Insert before the closing `>` / `/>`.
    let close = if tag.ends_with("/>") { tag.len() - 2 } else { tag.len() - 1 };
    let head = tag[..close].trim_end();
    format!("{head} {attr}=\"{val}\"{}", &tag[close..])
}

/// Insert `<elem attr="value"/>` as the last child of the first `<parent>` element.
pub fn insert_child(src: &str, parent: &str, elem: &str, attr: &str, value: &str) -> Option<String> {
    let close = format!("</{parent}>");
    let at = src.find(&close)?;
    // indentation of the closing tag; the new child gets two more spaces
    let line_start = src[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let indent: String = src[line_start..at].chars().take_while(|c| c.is_whitespace()).collect();
    let insert = format!("  <{elem} {attr}=\"{}\"/>\n{indent}", escape_attr(value));
    Some(format!("{}{}{}", &src[..at], insert, &src[at..]))
}
