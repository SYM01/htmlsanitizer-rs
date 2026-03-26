use std::io;
use std::sync::Arc;

use crate::tags::{ascii_lower_in_place, AllowList, Tag};

pub(crate) type UrlSanitizerFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    LtSign,
    TagName,
    TagEnd,
    AttrGap,
    AttrName,
    EqualSign,
    AttrSpace,
    AttrVal,
    ValSpace,
    AttrQVal,
    ETagStart,
    ETagName,
    ErrTag,
    ETagAttr,
    ETagEnd,
    NonHtml,
}

fn legal_keyword_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-')
}

/// HTML entity unescaping (mirrors Go's `html.UnescapeString`).
fn unescape_html(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'&' {
            if let Some((ch, advance)) = try_unescape_entity(bytes, i) {
                out.push_str(&ch);
                i += advance;
                continue;
            }
        }
        // Advance through a full UTF-8 character
        let start = i;
        i += 1;
        while i < len && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        if let Ok(ch) = std::str::from_utf8(&bytes[start..i]) {
            out.push_str(ch);
        }
    }
    out
}

fn try_unescape_entity(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let rest = &bytes[start..];
    if rest.len() < 2 {
        return None;
    }

    // Numeric character reference: &#...
    if rest[1] == b'#' {
        return try_unescape_numeric(rest);
    }

    // Named character reference
    try_unescape_named(rest)
}

fn try_unescape_numeric(rest: &[u8]) -> Option<(String, usize)> {
    if rest.len() < 3 {
        return None;
    }
    let (radix, digit_start) = if rest[2] == b'x' || rest[2] == b'X' {
        (16, 3)
    } else {
        (10, 2)
    };

    let mut end = digit_start;
    while end < rest.len() && end < digit_start + 10 {
        let b = rest[end];
        let valid = match radix {
            16 => b.is_ascii_hexdigit(),
            _ => b.is_ascii_digit(),
        };
        if !valid {
            break;
        }
        end += 1;
    }

    if end == digit_start {
        return None;
    }

    let digits = std::str::from_utf8(&rest[digit_start..end]).ok()?;
    let code = u32::from_str_radix(digits, radix).ok()?;
    let ch = char::from_u32(code).unwrap_or('\u{FFFD}');

    let consumed = if end < rest.len() && rest[end] == b';' {
        end + 1
    } else {
        end
    };

    Some((ch.to_string(), consumed))
}

fn try_unescape_named(rest: &[u8]) -> Option<(String, usize)> {
    // Common named entities used in HTML attribute values, sorted by name for binary search
    static ENTITIES: &[(&[u8], &str)] = &[
        (b"&NewLine;", "\n"),
        (b"&Tab;", "\t"),
        (b"&acute;", "\u{00B4}"),
        (b"&amp;", "&"),
        (b"&apos;", "'"),
        (b"&brvbar;", "\u{00A6}"),
        (b"&cedil;", "\u{00B8}"),
        (b"&cent;", "\u{00A2}"),
        (b"&colon;", ":"),
        (b"&comma;", ","),
        (b"&copy;", "\u{00A9}"),
        (b"&curren;", "\u{00A4}"),
        (b"&deg;", "\u{00B0}"),
        (b"&divide;", "\u{00F7}"),
        (b"&frac12;", "\u{00BD}"),
        (b"&frac14;", "\u{00BC}"),
        (b"&frac34;", "\u{00BE}"),
        (b"&gt;", ">"),
        (b"&iexcl;", "\u{00A1}"),
        (b"&iquest;", "\u{00BF}"),
        (b"&laquo;", "\u{00AB}"),
        (b"&lpar;", "("),
        (b"&lt;", "<"),
        (b"&macr;", "\u{00AF}"),
        (b"&micro;", "\u{00B5}"),
        (b"&middot;", "\u{00B7}"),
        (b"&nbsp;", "\u{00A0}"),
        (b"&not;", "\u{00AC}"),
        (b"&ordm;", "\u{00BA}"),
        (b"&ordf;", "\u{00AA}"),
        (b"&para;", "\u{00B6}"),
        (b"&period;", "."),
        (b"&plusmn;", "\u{00B1}"),
        (b"&pound;", "\u{00A3}"),
        (b"&quot;", "\""),
        (b"&raquo;", "\u{00BB}"),
        (b"&reg;", "\u{00AE}"),
        (b"&rpar;", ")"),
        (b"&sect;", "\u{00A7}"),
        (b"&semi;", ";"),
        (b"&shy;", "\u{00AD}"),
        (b"&sup1;", "\u{00B9}"),
        (b"&sup2;", "\u{00B2}"),
        (b"&sup3;", "\u{00B3}"),
        (b"&times;", "\u{00D7}"),
        (b"&uml;", "\u{00A8}"),
        (b"&yen;", "\u{00A5}"),
    ];

    for &(entity, replacement) in ENTITIES {
        if rest.len() >= entity.len() && &rest[..entity.len()] == entity {
            return Some((replacement.to_string(), entity.len()));
        }
    }
    None
}

pub struct SanitizeWriter<W: io::Write> {
    pub(crate) allow_list: AllowList,
    pub(crate) url_sanitizer: UrlSanitizerFn,
    w: W,
    state: State,

    tag_name: Vec<u8>,
    tag_idx: Option<usize>,
    non_html_tag_idx: Option<usize>,
    keep_non_html: bool,
    attr: Vec<u8>,
    val: Vec<u8>,
    quote: u8,
    last_byte: u8,

    buf: Vec<u8>,
}

impl<W: io::Write> SanitizeWriter<W> {
    pub fn new(w: W, allow_list: AllowList, url_sanitizer: UrlSanitizerFn) -> Self {
        Self {
            allow_list,
            url_sanitizer,
            w,
            state: State::Normal,
            tag_name: Vec::new(),
            tag_idx: None,
            non_html_tag_idx: None,
            keep_non_html: false,
            attr: Vec::new(),
            val: Vec::new(),
            quote: 0,
            last_byte: 0,
            buf: Vec::new(),
        }
    }

    fn flush_buf(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.w.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Escape attribute value characters: ' " < >
    fn safe_append(&mut self, p: &[u8]) {
        let danger = p.iter().any(|&b| matches!(b, b'\'' | b'<' | b'>' | b'"'));
        if !danger {
            self.buf.extend_from_slice(p);
            return;
        }
        for &b in p {
            match b {
                b'\'' => self.buf.extend_from_slice(b"&#39;"),
                b'<' => self.buf.extend_from_slice(b"&lt;"),
                b'>' => self.buf.extend_from_slice(b"&gt;"),
                b'"' => self.buf.extend_from_slice(b"&#34;"),
                _ => self.buf.push(b),
            }
        }
    }

    fn tag(&self) -> Option<&Tag> {
        self.tag_idx.map(|i| &self.allow_list.tags[i])
    }

    /// Write a sanitized tag attribute and value.
    fn safe_append_attr(&mut self) {
        let tag_idx = match self.tag_idx {
            Some(idx) => idx,
            None => return,
        };

        ascii_lower_in_place(&mut self.attr);
        let (ok, url_attr) = self.allow_list.tags[tag_idx].attr_exists(&self.attr);
        if !ok && !self.allow_list.attr_exists(&self.attr) {
            return;
        }

        if url_attr {
            let raw = unescape_html(std::str::from_utf8(&self.val).unwrap_or(""));
            if let Some(new_url) = (self.url_sanitizer)(&raw) {
                let val_bytes = new_url.into_bytes();
                self.buf.push(b' ');
                self.buf.extend_from_slice(&self.attr);
                self.buf.extend_from_slice(b"=\"");
                self.safe_append(&val_bytes);
                self.buf.push(b'"');
            }
        } else {
            self.buf.push(b' ');
            self.buf.extend_from_slice(&self.attr);
            self.buf.extend_from_slice(b"=\"");
            // Avoid cloning self.val by collecting the escaped bytes separately
            let val = &self.val;
            let danger = val.iter().any(|&b| matches!(b, b'\'' | b'<' | b'>' | b'"'));
            if !danger {
                self.buf.extend_from_slice(val);
            } else {
                for &b in val.iter() {
                    match b {
                        b'\'' => self.buf.extend_from_slice(b"&#39;"),
                        b'<' => self.buf.extend_from_slice(b"&lt;"),
                        b'>' => self.buf.extend_from_slice(b"&gt;"),
                        b'"' => self.buf.extend_from_slice(b"&#34;"),
                        _ => self.buf.push(b),
                    }
                }
            }
            self.buf.push(b'"');
        }
    }

    fn non_html_tag_name(&self) -> Option<&str> {
        self.non_html_tag_idx
            .map(|i| self.allow_list.non_html_tags[i].name.as_str())
    }

    // --- State handlers ---

    fn s_normal(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            match data[*off] {
                b'<' => {
                    self.state = State::LtSign;
                    *off += 1;
                    self.flush_buf()?;
                    return Ok(());
                }
                b'>' => {
                    self.buf.extend_from_slice(b"&gt;");
                }
                b => {
                    self.buf.push(b);
                }
            }
            *off += 1;
        }
        self.flush_buf()
    }

    fn s_non_html(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            match data[*off] {
                b'<' => {
                    self.state = State::LtSign;
                    *off += 1;
                    self.flush_buf()?;
                    return Ok(());
                }
                b'>' => {
                    if self.keep_non_html {
                        self.buf.extend_from_slice(b"&gt;");
                    }
                }
                b => {
                    if self.keep_non_html {
                        self.buf.push(b);
                    }
                }
            }
            *off += 1;
        }
        self.flush_buf()
    }

    fn s_lt_sign(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        let b = data[*off];
        match b {
            b'/' => {
                *off += 1;
                self.state = State::ETagStart;
                self.tag_name.clear();
            }
            _ if self.non_html_tag_idx.is_some() => {
                self.state = State::NonHtml;
                if self.keep_non_html {
                    self.buf.extend_from_slice(b"&lt;");
                }
            }
            _ => {
                *off += 1;
                if legal_keyword_byte(b) {
                    self.state = State::TagName;
                    self.tag_name.clear();
                    self.tag_name.push(b);
                    self.tag_idx = None;
                    return Ok(());
                }
                self.state = State::ErrTag;
            }
        }
        Ok(())
    }

    fn s_tag_name(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            match b {
                b'>' => {
                    ascii_lower_in_place(&mut self.tag_name);
                    let name = std::str::from_utf8(&self.tag_name).unwrap_or("");
                    self.tag_idx = self.allow_list.find_tag(name);
                    self.non_html_tag_idx = self.allow_list.check_non_html_tag(name);
                    self.state = State::TagEnd;

                    if self.tag_idx.is_none() {
                        return Ok(());
                    }
                    self.buf.push(b'<');
                    self.buf.extend_from_slice(
                        self.allow_list.tags[self.tag_idx.unwrap()].name.as_bytes(),
                    );
                    return Ok(());
                }
                _ => {
                    if legal_keyword_byte(b) {
                        self.tag_name.push(b);
                        *off += 1;
                        continue;
                    }
                    *off += 1;
                    self.state = State::AttrGap;
                    self.last_byte = b;

                    ascii_lower_in_place(&mut self.tag_name);
                    let name = std::str::from_utf8(&self.tag_name).unwrap_or("");
                    self.tag_idx = self.allow_list.find_tag(name);
                    self.non_html_tag_idx = self.allow_list.check_non_html_tag(name);
                    if self.tag_idx.is_none() {
                        return Ok(());
                    }
                    self.buf.push(b'<');
                    self.buf.extend_from_slice(
                        self.allow_list.tags[self.tag_idx.unwrap()].name.as_bytes(),
                    );
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn s_tag_end(&mut self, _data: &[u8], off: &mut usize) -> io::Result<()> {
        // eat '>'
        *off += 1;
        self.state = State::Normal;

        if self.non_html_tag_idx.is_some() {
            if self.last_byte == b'/' {
                self.non_html_tag_idx = None;
                self.keep_non_html = false;
            } else {
                self.state = State::NonHtml;
                self.keep_non_html = self.tag_idx.is_some()
                    && self.non_html_tag_name() == self.tag().map(|t| t.name.as_str());
            }
        }

        if self.tag_idx.is_none() {
            self.buf.clear();
            self.last_byte = 0;
            return Ok(());
        }

        if self.last_byte == b'/' {
            self.buf.extend_from_slice(b" /");
            self.last_byte = 0;
        }
        self.buf.push(b'>');
        self.flush_buf()
    }

    fn s_attr_gap(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'>' {
                self.state = State::TagEnd;
                return Ok(());
            }
            if legal_keyword_byte(b) {
                *off += 1;
                self.attr.clear();
                self.attr.push(b);
                self.state = State::AttrName;
                return Ok(());
            }
            self.last_byte = b;
            *off += 1;
        }
        Ok(())
    }

    fn s_attr_name(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'=' {
                *off += 1;
                self.state = State::EqualSign;
                return Ok(());
            }
            if b.is_ascii_whitespace() {
                *off += 1;
                self.state = State::AttrSpace;
                return Ok(());
            }
            if legal_keyword_byte(b) {
                self.attr.push(b);
                *off += 1;
                continue;
            }
            // default: non-keyword, non-'=' byte
            self.last_byte = 0;
            self.state = State::AttrGap;

            if self.tag_idx.is_none() {
                return Ok(());
            }

            // name-only attribute
            ascii_lower_in_place(&mut self.attr);
            let allowed = {
                let (ok, _) = self.allow_list.tags[self.tag_idx.unwrap()].attr_exists(&self.attr);
                ok || self.allow_list.attr_exists(&self.attr)
            };
            if allowed {
                self.buf.push(b' ');
                self.buf.extend_from_slice(&self.attr);
            }
            return Ok(());
        }
        Ok(())
    }

    fn s_equal_sign(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        self.val.clear();
        let b = data[*off];

        if b == b'>' {
            self.safe_append_attr();
            self.state = State::TagEnd;
        } else if b == b'\'' || b == b'"' {
            *off += 1;
            self.quote = b;
            self.state = State::AttrQVal;
        } else if b.is_ascii_whitespace() {
            *off += 1;
            self.state = State::ValSpace;
        } else {
            *off += 1;
            self.state = State::AttrVal;
            self.val.push(b);
        }
        Ok(())
    }

    /// Emit a bare (value-less) attribute if it is allowed and not a URL attribute.
    fn emit_bare_attr_if_allowed(&mut self) {
        if let Some(tag_idx) = self.tag_idx {
            ascii_lower_in_place(&mut self.attr);
            let allowed = {
                let (ok, url_attr) = self.allow_list.tags[tag_idx].attr_exists(&self.attr);
                (ok && !url_attr) || self.allow_list.attr_exists(&self.attr)
            };
            if allowed {
                self.buf.push(b' ');
                self.buf.extend_from_slice(&self.attr);
            }
        }
    }

    fn s_attr_space(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'=' {
                *off += 1;
                self.state = State::EqualSign;
                return Ok(());
            }
            if b.is_ascii_whitespace() {
                *off += 1;
                continue;
            }
            if legal_keyword_byte(b) || b == b'>' {
                self.emit_bare_attr_if_allowed();

                if b == b'>' {
                    self.state = State::TagEnd;
                    return Ok(());
                }

                *off += 1;
                self.attr.clear();
                self.attr.push(b);
                self.state = State::AttrName;
                return Ok(());
            }
            // default
            self.emit_bare_attr_if_allowed();

            *off += 1;
            self.last_byte = b;
            self.state = State::AttrGap;
            return Ok(());
        }
        Ok(())
    }

    fn s_attr_val(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'>' {
                self.state = State::TagEnd;
                self.safe_append_attr();
                return Ok(());
            }
            if b.is_ascii_whitespace() {
                *off += 1;
                self.last_byte = 0;
                self.state = State::AttrGap;
                self.safe_append_attr();
                return Ok(());
            }
            self.val.push(b);
            *off += 1;
        }
        Ok(())
    }

    fn s_val_space(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'>' {
                self.safe_append_attr();
                self.state = State::TagEnd;
                return Ok(());
            }
            if b == b'\'' || b == b'"' {
                *off += 1;
                self.quote = b;
                self.state = State::AttrQVal;
                return Ok(());
            }
            if b.is_ascii_whitespace() {
                *off += 1;
                continue;
            }
            *off += 1;
            self.state = State::AttrVal;
            self.val.clear();
            self.val.push(b);
            return Ok(());
        }
        Ok(())
    }

    fn s_attr_qval(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == self.quote {
                *off += 1;
                self.safe_append_attr();
                self.last_byte = 0;
                self.state = State::AttrGap;
                return Ok(());
            }
            self.val.push(b);
            *off += 1;
        }
        Ok(())
    }

    fn s_etag_start(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        let b = data[*off];
        if legal_keyword_byte(b) {
            *off += 1;
            self.tag_name.clear();
            self.tag_name.push(b);
            self.state = State::ETagName;
        } else if self.non_html_tag_idx.is_some() {
            self.state = State::NonHtml;
            if self.keep_non_html {
                self.buf.extend_from_slice(b"&lt;/");
            }
        } else {
            self.state = State::ErrTag;
        }
        Ok(())
    }

    fn s_etag_name(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            let b = data[*off];
            if b == b'>' {
                if self.non_html_tag_idx.is_some() {
                    if self
                        .non_html_tag_name()
                        .is_some_and(|n| self.tag_name.eq_ignore_ascii_case(n.as_bytes()))
                    {
                        self.non_html_tag_idx = None;
                        self.keep_non_html = false;
                    } else {
                        if self.keep_non_html {
                            let tn = self.tag_name.clone();
                            self.safe_append(b"</");
                            self.safe_append(&tn);
                        }
                        self.state = State::NonHtml;
                        return Ok(());
                    }
                }

                ascii_lower_in_place(&mut self.tag_name);
                let name = std::str::from_utf8(&self.tag_name).unwrap_or("");
                self.tag_idx = self.allow_list.find_tag(name);
                if self.tag_idx.is_none() {
                    self.state = State::ErrTag;
                    return Ok(());
                }

                self.state = State::ETagEnd;
                self.buf.extend_from_slice(b"</");
                self.buf
                    .extend_from_slice(self.allow_list.tags[self.tag_idx.unwrap()].name.as_bytes());
                return Ok(());
            }

            if legal_keyword_byte(b) {
                self.tag_name.push(b);
                *off += 1;
                continue;
            }

            if self.non_html_tag_idx.is_some() {
                let is_end = self
                    .non_html_tag_name()
                    .is_some_and(|n| self.tag_name.eq_ignore_ascii_case(n.as_bytes()));
                if !is_end {
                    if self.keep_non_html {
                        let tn = self.tag_name.clone();
                        self.safe_append(b"</");
                        self.safe_append(&tn);
                    }
                    self.state = State::NonHtml;
                    return Ok(());
                }
                // is end tag of non-html element
                self.non_html_tag_idx = None;
                self.keep_non_html = false;
            }

            // default (fallthrough from non-html end-tag case, or regular tag)
            ascii_lower_in_place(&mut self.tag_name);
            let name = std::str::from_utf8(&self.tag_name).unwrap_or("");
            self.tag_idx = self.allow_list.find_tag(name);
            if self.tag_idx.is_none() {
                self.state = State::ErrTag;
                return Ok(());
            }

            *off += 1;
            self.state = State::ETagAttr;
            self.buf.extend_from_slice(b"</");
            self.buf
                .extend_from_slice(self.allow_list.tags[self.tag_idx.unwrap()].name.as_bytes());
            return Ok(());
        }
        Ok(())
    }

    fn s_err_tag(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            if data[*off] == b'>' {
                *off += 1;
                self.state = State::Normal;
                self.buf.clear();
                return Ok(());
            }
            *off += 1;
        }
        Ok(())
    }

    fn s_etag_attr(&mut self, data: &[u8], off: &mut usize) -> io::Result<()> {
        while *off < data.len() {
            if data[*off] == b'>' {
                self.state = State::ETagEnd;
                return Ok(());
            }
            *off += 1;
        }
        Ok(())
    }

    fn s_etag_end(&mut self, _data: &[u8], off: &mut usize) -> io::Result<()> {
        // eat '>'
        *off += 1;
        self.state = State::Normal;
        self.buf.push(b'>');
        self.flush_buf()
    }
}

impl<W: io::Write> io::Write for SanitizeWriter<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let mut off = 0;

        while off < p.len() {
            match self.state {
                State::Normal => self.s_normal(p, &mut off)?,
                State::NonHtml => self.s_non_html(p, &mut off)?,
                State::LtSign => self.s_lt_sign(p, &mut off)?,
                State::TagName => self.s_tag_name(p, &mut off)?,
                State::TagEnd => self.s_tag_end(p, &mut off)?,
                State::AttrGap => self.s_attr_gap(p, &mut off)?,
                State::AttrName => self.s_attr_name(p, &mut off)?,
                State::EqualSign => self.s_equal_sign(p, &mut off)?,
                State::AttrSpace => self.s_attr_space(p, &mut off)?,
                State::AttrVal => self.s_attr_val(p, &mut off)?,
                State::ValSpace => self.s_val_space(p, &mut off)?,
                State::AttrQVal => self.s_attr_qval(p, &mut off)?,
                State::ETagStart => self.s_etag_start(p, &mut off)?,
                State::ETagName => self.s_etag_name(p, &mut off)?,
                State::ErrTag => self.s_err_tag(p, &mut off)?,
                State::ETagAttr => self.s_etag_attr(p, &mut off)?,
                State::ETagEnd => self.s_etag_end(p, &mut off)?,
            }
        }

        Ok(off)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf()?;
        self.w.flush()
    }
}
