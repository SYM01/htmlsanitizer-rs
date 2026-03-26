use url::Url;

/// Check if a byte is an ASCII control character (matching Go's stringContainsCTLByte).
fn contains_ctl_byte(s: &str) -> bool {
    s.bytes().any(|b| b < b' ' || b == 0x7f)
}

/// Check if the first path segment of a relative URL contains a colon.
/// Go's url.Parse rejects these: "first path segment in URL cannot contain colon".
fn first_segment_has_colon(s: &str) -> bool {
    let path = s.split('?').next().unwrap_or(s);
    let path = path.split('#').next().unwrap_or(path);
    let first_seg = path.split('/').next().unwrap_or(path);
    first_seg.contains(':')
}

/// Percent-encode a byte sequence as a URL path, matching Go's net/url encodePath rules.
/// NOT escaped: alphanumeric, `-`, `_`, `.`, `~`, `$`, `&`, `+`, `,`, `/`, `:`, `;`, `=`, `@`
/// Everything else (including `"`, `'`, `(`, `)`, `!`, `*`, `?`, space) is percent-encoded.
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

fn go_path_encode(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || matches!(
                b,
                b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'
            )
        {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_DIGITS[(b >> 4) as usize] as char);
            out.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
        }
    }
    out
}

/// Percent-decode a string (e.g. `%22` → `"`).
fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Default URL sanitizer. Accepts http, https, or empty scheme.
/// Rejects opaque URIs and other schemes.
/// Matches Go's DefaultURLSanitizer behavior.
pub fn default_url_sanitizer(raw_url: &str) -> Option<String> {
    // Reject URLs containing control characters (Go 1.17+)
    if contains_ctl_byte(raw_url) {
        return None;
    }

    // Try parsing as absolute URL first
    match Url::parse(raw_url) {
        Ok(u) => {
            // Reject opaque URIs (cannot-be-a-base)
            if u.cannot_be_a_base() {
                return None;
            }
            match u.scheme() {
                "http" | "https" => {
                    // Reject percent-encoded ASCII in host (Go rejects these)
                    if let Some(host) = u.host_str() {
                        let scheme_prefix = format!("{}://", u.scheme());
                        if let Some(after_scheme) = raw_url.strip_prefix(&scheme_prefix) {
                            let raw_host = after_scheme.split('/').next().unwrap_or("");
                            let raw_host = raw_host.split('?').next().unwrap_or(raw_host);
                            let raw_host = raw_host.split('#').next().unwrap_or(raw_host);
                            let raw_host = if let Some(pos) = raw_host.rfind('@') {
                                &raw_host[pos + 1..]
                            } else {
                                raw_host
                            };
                            if raw_host != host && !raw_host.eq_ignore_ascii_case(host) {
                                return None;
                            }
                        }
                    }
                    Some(u.to_string())
                }
                _ => None,
            }
        }
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            // Go rejects relative URLs where the first path segment contains ':'
            if first_segment_has_colon(raw_url) {
                return None;
            }

            // Validate by parsing against a dummy base
            let base = Url::parse("http://x.invalid/").unwrap();
            if base.join(raw_url).is_err() {
                return None;
            }

            // Re-serialize using Go-compatible encoding.
            // Split raw URL into path, query, fragment, then re-encode the path.
            let (rest, fragment) = match raw_url.find('#') {
                Some(pos) => (&raw_url[..pos], Some(&raw_url[pos + 1..])),
                None => (raw_url, None),
            };
            let (path_part, query) = match rest.find('?') {
                Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
                None => (rest, None),
            };

            // Percent-decode the path first (in case it had existing encoding),
            // then re-encode using Go rules
            let decoded = percent_decode(path_part);
            let mut result = go_path_encode(&decoded);

            if let Some(q) = query {
                result.push('?');
                result.push_str(q);
            }
            if let Some(f) = fragment {
                result.push('#');
                result.push_str(f);
            }

            Some(result)
        }
        Err(_) => None,
    }
}
