//! Tiny DOM built on quick-xml, tolerant to the non-standard pestudio XML layout
//! (the root element is literally named `xml`, files may start with a BOM).

use quick_xml::Reader;
use quick_xml::events::Event;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn attr_or<'a>(&'a self, name: &str, def: &'a str) -> &'a str {
        self.attr(name).unwrap_or(def)
    }

    /// Integer attribute; accepts decimal or 0x-hex, "--"/"---" or empty → None.
    pub fn attr_int(&self, name: &str) -> Option<i64> {
        parse_int(self.attr(name)?)
    }

    pub fn attr_bool(&self, name: &str) -> bool {
        self.attr_int(name).unwrap_or(0) != 0
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Find a descendant by slash separated path, e.g. `"mitre/tactics"`.
    pub fn path(&self, path: &str) -> Option<&Element> {
        let mut cur = self;
        for p in path.split('/').filter(|s| !s.is_empty()) {
            cur = cur.child(p)?;
        }
        Some(cur)
    }

    pub fn text_trim(&self) -> &str {
        self.text.trim()
    }
}

pub fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() || s.chars().all(|c| c == '-') {
        return None;
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).ok();
    }
    s.parse::<i64>().ok()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xml: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parse a document and return a synthetic root holding the top-level elements.
pub fn parse(src: &str) -> Result<Element, ParseError> {
    let src = src.trim_start_matches('\u{feff}');
    let mut r = Reader::from_str(src);
    r.config_mut().trim_text(false);
    r.config_mut().check_end_names = false;
    let mut stack: Vec<Element> = vec![Element { name: "#document".into(), ..Default::default() }];
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => {
                stack.push(start_element(&e)?);
            }
            Ok(Event::Empty(e)) => {
                let el = start_element(&e)?;
                stack.last_mut().expect("root").children.push(el);
            }
            Ok(Event::End(_)) => {
                if stack.len() > 1 {
                    let el = stack.pop().expect("non-empty");
                    stack.last_mut().expect("root").children.push(el);
                }
            }
            Ok(Event::Text(t)) => {
                let s = t.unescape().map(|c| c.into_owned()).unwrap_or_else(|_| String::from_utf8_lossy(&t).into_owned());
                stack.last_mut().expect("root").text.push_str(&s);
            }
            Ok(Event::CData(t)) => {
                stack.last_mut().expect("root").text.push_str(&String::from_utf8_lossy(&t));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ParseError(format!("{e} at {}", r.buffer_position()))),
        }
    }
    while stack.len() > 1 {
        let el = stack.pop().expect("non-empty");
        stack.last_mut().expect("root").children.push(el);
    }
    Ok(stack.pop().expect("root"))
}

fn start_element(e: &quick_xml::events::BytesStart) -> Result<Element, ParseError> {
    let mut el = Element { name: String::from_utf8_lossy(e.name().as_ref()).into_owned(), ..Default::default() };
    for a in e.attributes().with_checks(false) {
        let a = a.map_err(|x| ParseError(x.to_string()))?;
        let k = String::from_utf8_lossy(a.key.as_ref()).into_owned();
        let v = a.unescape_value().map(|c| c.into_owned()).unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned());
        el.attrs.push((k, v));
    }
    Ok(el)
}

/// Return the payload root (`<xml>` element) of a pestudio file, or the document itself.
pub fn payload(doc: &Element) -> &Element {
    doc.child("xml").unwrap_or(doc)
}
