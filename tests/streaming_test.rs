//! Streaming/chunked write tests: verify that splitting input at any byte
//! position produces the same output as a single-call sanitize.

use htmlsanitizer::{sanitize_string, HtmlSanitizer};
use std::io::Write;

/// Split input at every byte position and verify output matches single-call.
fn chunked_write_check(input: &str) {
    let expected = sanitize_string(input);
    let data = input.as_bytes();

    for split in 1..data.len() {
        let mut buf = Vec::new();
        {
            let sanitizer = HtmlSanitizer::new();
            let mut w = sanitizer.new_writer(&mut buf);
            w.write_all(&data[..split]).unwrap();
            w.write_all(&data[split..]).unwrap();
        }
        let got = String::from_utf8(buf).unwrap();
        assert_eq!(got, expected, "chunked split={} input={:?}", split, input);
    }
}

#[test]
fn chunked_write_simple_link() {
    chunked_write_check("<a href=\"http://example.com\" class=\"link\">text</a>");
}

#[test]
fn chunked_write_script_removal() {
    chunked_write_check("<script>alert(1)</script><p>safe</p>");
}

#[test]
fn chunked_write_img_with_attrs() {
    chunked_write_check("<div class=\"c\"><img src=\"http://x.com/i.png\" alt=\"pic\" /></div>");
}

#[test]
fn chunked_write_disallowed_attr() {
    chunked_write_check("<span style=\"color:red\">hello</span>");
}

#[test]
fn chunked_write_single_quoted_attr() {
    chunked_write_check("<a href='http://example.com'>link</a>");
}

#[test]
fn chunked_write_xss_payload() {
    chunked_write_check("<IMG SRC=\"javascript:alert('XSS');\">");
}

#[test]
fn chunked_write_nested_tags() {
    chunked_write_check("<div><p><span>deep</span></p></div>");
}

#[test]
fn chunked_write_style_tag() {
    chunked_write_check("<style>body{color:red}</style><p>text</p>");
}

#[test]
fn chunked_write_malformed_html() {
    chunked_write_check("<span class=\"  ");
}

#[test]
fn chunked_write_comment() {
    chunked_write_check("<!--comment--><p>after</p>");
}

/// Write single bytes at a time for various inputs.
#[test]
fn single_byte_write() {
    let inputs = [
        "<a href=\"http://example.com\">link</a>",
        "<script>alert(1)</script>safe",
        "<p class=\"x\" id=\"y\">text</p>",
        "<img src=\"http://x.com/i.png\" />",
        "plain text only",
        "<div><script>bad</script><span>good</span></div>",
    ];

    for input in &inputs {
        let expected = sanitize_string(input);
        let mut buf = Vec::new();
        {
            let sanitizer = HtmlSanitizer::new();
            let mut w = sanitizer.new_writer(&mut buf);
            for &b in input.as_bytes() {
                w.write_all(&[b]).unwrap();
            }
        }
        let got = String::from_utf8(buf).unwrap();
        assert_eq!(got, expected, "single-byte write for input={:?}", input);
    }
}

/// Three-way split: write in three chunks at every pair of split positions.
#[test]
fn three_way_split() {
    let input = "<a href=\"http://example.com\">link</a>";
    let expected = sanitize_string(input);
    let data = input.as_bytes();

    for i in 1..data.len() - 1 {
        for j in i + 1..data.len() {
            let mut buf = Vec::new();
            {
                let sanitizer = HtmlSanitizer::new();
                let mut w = sanitizer.new_writer(&mut buf);
                w.write_all(&data[..i]).unwrap();
                w.write_all(&data[i..j]).unwrap();
                w.write_all(&data[j..]).unwrap();
            }
            let got = String::from_utf8(buf).unwrap();
            assert_eq!(
                got, expected,
                "three-way split i={} j={} input={:?}",
                i, j, input
            );
        }
    }
}

/// Empty writes interspersed should not affect output.
#[test]
fn empty_writes() {
    let input = "<p>hello</p>";
    let expected = sanitize_string(input);
    let data = input.as_bytes();

    let mut buf = Vec::new();
    {
        let sanitizer = HtmlSanitizer::new();
        let mut w = sanitizer.new_writer(&mut buf);
        w.write_all(b"").unwrap();
        w.write_all(&data[..5]).unwrap();
        w.write_all(b"").unwrap();
        w.write_all(&data[5..]).unwrap();
        w.write_all(b"").unwrap();
    }
    let got = String::from_utf8(buf).unwrap();
    assert_eq!(got, expected);
}
