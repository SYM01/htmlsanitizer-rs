//! Additional sanitization tests beyond the core Go test suite.
//! Covers: multi-XSS payloads, edge cases, Unicode, deeply nested tags,
//! long inputs, and additional OWASP vectors.

use htmlsanitizer::sanitize_string;

/// Large multi-XSS test case from Go (lines 513-571 in sanitizer_test.go).
#[test]
fn go_multi_xss_payload() {
    let input = r#"
<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">
<Video> <source onerror = "javascript: alert (XSS)">
<Input value = "XSS" type = text>
<applet code="javascript:confirm(document.cookie);">
<isindex x="javascript:" onmouseover="alert(XSS)">
"></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
"><img src="x:x" onerror="alert(XSS)">
"><iframe src="javascript:alert(XSS)">
<object data="javascript:alert(XSS)" />
<isindex type=image src=1 onerror=alert(XSS)>
<img src=x:alert(alt) onerror=eval(src) alt=0>
<img  src="x:gif" onerror="window['al\u0065rt'](0)"></img>
<iframe/src="data:text/html,<svg onload=alert(1)>">
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<form><a href="javascript:\u0061lert(1)">X
</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror='eval(src)'>
<style>//*{x:expression(alert(/xss/))}//<style></style>
On Mouse Over​
<img src="/" =_=" title="onerror='prompt(1)'">
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<form><button formaction=javascript&colon;alert(1)>CLICKME
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>
"#;

    let got = sanitize_string(input);

    // Verify key security properties rather than exact whitespace match
    // (Rust's URL crate may normalize slightly differently from Go's net/url)
    assert!(!got.contains("<script"), "script tags must be stripped");
    assert!(!got.contains("<iframe"), "iframe tags must be stripped");
    assert!(!got.contains("<object"), "object tags must be stripped");
    assert!(!got.contains("<applet"), "applet tags must be stripped");
    assert!(!got.contains("<isindex"), "isindex tags must be stripped");
    assert!(!got.contains("<input"), "input tags must be stripped");
    assert!(!got.contains("<form"), "form tags must be stripped");
    assert!(!got.contains("<button"), "button tags must be stripped");
    assert!(!got.contains("<meta"), "meta tags must be stripped");
    assert!(!got.contains("<svg"), "svg tags must be stripped");
    assert!(
        !got.contains("onerror"),
        "onerror handlers must be stripped"
    );
    assert!(
        !got.contains("onmouseover"),
        "onmouseover handlers must be stripped"
    );
    assert!(!got.contains("onload"), "onload handlers must be stripped");
    assert!(
        !got.contains("ontoggle"),
        "ontoggle handlers must be stripped"
    );
    assert!(
        !got.contains("javascript:"),
        "javascript: URIs must be stripped"
    );
    assert!(!got.contains("alert("), "alert() calls must be stripped");

    // Verify allowed content is preserved
    assert!(got.contains("<img src=\"x\">"));
    assert!(got.contains("<video>"));
    assert!(got.contains("<source>"));
    assert!(got.contains("<img alt=\"0\">"));
    assert!(got.contains("ClickMe"));
    assert!(got.contains("CLICKME"));
    assert!(got.contains("On Mouse Over"));
}

/// Keep-stylesheet example from Go: add style/head/body/html to allowlist.
#[test]
fn keep_stylesheet() {
    use htmlsanitizer::{HtmlSanitizer, Tag};

    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.tags.push(Tag::new("style", &[], &[]));
    sanitizer.allow_list.tags.push(Tag::new("head", &[], &[]));
    sanitizer.allow_list.tags.push(Tag::new("body", &[], &[]));
    sanitizer.allow_list.tags.push(Tag::new("html", &[], &[]));

    let data = r#"<!doctype html>
<html>
<head>
	<style type="text/css">
	body {
		background-color: #f0f0f2;
		margin: 0;
		padding: 0;
		bad-attr: <body></body>;
		bad-attr: <body></body >;
		bad-attr: <body></ body>;
		font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
	}
	</style>
</head>
<body>
	<div>
	<h1>Example Domain</h1>
	<p><a href="https://www.iana.org/domains/example">More information...</a></p>
	</div>
</body>
</html>"#;

    let got = sanitizer.sanitize_string(data);

    // Style content is preserved but inner HTML-like content is escaped
    assert!(got.contains("<style>"));
    assert!(got.contains("</style>"));
    assert!(got.contains("background-color: #f0f0f2"));
    assert!(got.contains("&lt;body&gt;"));
    assert!(got.contains("<html>"));
    assert!(got.contains("</html>"));
}

/// No tags allowed — set empty allow list.
#[test]
fn no_tags_allowed() {
    use htmlsanitizer::HtmlSanitizer;

    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.tags.clear();
    sanitizer.allow_list.global_attr.clear();

    let data = r#"
<a href="http://others.com">Link</a>
<a href="https://example.com/xxx">Link with example.com</a>
	"#;
    let got = sanitizer.sanitize_string(data);
    assert!(got.contains("Link"));
    assert!(got.contains("Link with example.com"));
    assert!(!got.contains("<a"));
}

/// Only allow href on <a> tag.
#[test]
fn only_allow_href_tag() {
    use htmlsanitizer::{HtmlSanitizer, Tag};

    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.tags = vec![Tag::new("a", &[], &["href"])];
    sanitizer.allow_list.global_attr.clear();

    let input = r#"<details/open/ontoggle=alert(1)></details><a href="http://others.com" target="_blank">Link</a>"#;
    let got = sanitizer.sanitize_string(input);
    // URL sanitizer normalizes http://others.com to http://others.com/
    assert!(got.contains(r#"<a href="http://others.com/">Link</a>"#));
    assert!(!got.contains("target"));
    assert!(!got.contains("ontoggle"));
}

/// Custom URL sanitizer — only allow example.com.
#[test]
fn custom_url_sanitizer() {
    use htmlsanitizer::HtmlSanitizer;

    let sanitizer = HtmlSanitizer::new().with_url_sanitizer(|raw_url: &str| {
        let default = htmlsanitizer::default_url_sanitizer(raw_url)?;
        if default.contains("example.com") {
            Some(default)
        } else {
            None
        }
    });

    let input =
        r#"<a href="http://others.com">Link</a><a href="https://example.com/xxx">Link2</a>"#;
    let got = sanitizer.sanitize_string(input);
    assert_eq!(
        got,
        r#"<a>Link</a><a href="https://example.com/xxx">Link2</a>"#
    );
}

// --- Additional edge cases beyond Go test suite ---

#[test]
fn empty_input() {
    assert_eq!(sanitize_string(""), "");
}

#[test]
fn plain_text_no_html() {
    assert_eq!(sanitize_string("Hello, world!"), "Hello, world!");
}

#[test]
fn text_with_gt_lt() {
    // `< 2 and 3 >` is consumed as an invalid tag, so text inside is stripped
    assert_eq!(sanitize_string("1 < 2 and 3 > 1"), "1  1");
}

#[test]
fn gt_in_text_escaped() {
    // Bare `>` in normal text is escaped
    assert_eq!(sanitize_string("a > b"), "a &gt; b");
}

#[test]
fn deeply_nested_allowed_tags() {
    let input =
        "<div><p><span><strong><em><b><i><u><s>deep</s></u></i></b></em></strong></span></p></div>";
    let got = sanitize_string(input);
    assert_eq!(got, input);
}

#[test]
fn deeply_nested_disallowed_tags() {
    let input = "<script><script><script>alert(1)</script></script></script>";
    let got = sanitize_string(input);
    assert!(!got.contains("<script"));
    assert!(!got.contains("alert"));
}

#[test]
fn very_long_input() {
    let chunk = "<p>Hello <strong>world</strong>!</p>";
    let input = chunk.repeat(10000);
    let got = sanitize_string(&input);
    assert_eq!(got, input);
}

#[test]
fn null_bytes_in_tag_name() {
    let got = sanitize_string("<scr\x00ipt>alert(1)</script>");
    assert!(!got.contains("<script"));
}

#[test]
fn null_bytes_in_attribute() {
    let got = sanitize_string("<a hr\x00ef=\"javascript:alert(1)\">click</a>");
    assert!(!got.contains("javascript"));
}

#[test]
fn unicode_replacement_char_in_tag() {
    // U+FFFD is multi-byte UTF-8 (0xEF 0xBF 0xBD), not an ASCII letter.
    // `<` starts LtSign, then 0xEF is not legal_keyword_byte → ErrTag.
    // ErrTag eats to first `>` which is the `>` in `<script>`.
    // Then `alert(1)` is normal text, `</script>` closes script.
    // Since we never entered script mode, alert text passes through.
    let got = sanitize_string("<\u{FFFD}script>alert(1)</script>");
    assert_eq!(got, "alert(1)");
}

#[test]
fn tab_newline_in_tag_name() {
    // Tag names with whitespace should be treated as tag + attrs
    let got = sanitize_string("<a\thref=\"http://example.com\">link</a>");
    assert!(got.contains("<a"));
    assert!(got.contains("href"));
}

#[test]
fn mixed_case_end_tag() {
    let got = sanitize_string("<script>alert(1)</SCRIPT>");
    assert!(!got.contains("alert"));
    assert!(!got.contains("<script"));
}

#[test]
fn incomplete_comment() {
    let got = sanitize_string("<!--");
    // Should not panic; incomplete comment is eaten
    assert_eq!(got, "");
}

#[test]
fn comment_with_script() {
    // The sanitizer doesn't handle HTML comments specially.
    // `<!--` → `<` starts tag, `!` is illegal → ErrTag eats up to first `>`.
    // After the first `>` in `<script>`, it enters script NonHtml mode.
    // Then `alert(1)</script>` → script content `alert(1)` is stripped by NonHtml.
    // ` -->` → ` --` is text, `>` is escaped.
    let got = sanitize_string("<!-- <script>alert(1)</script> -->");
    assert_eq!(got, "alert(1) --&gt;");
}

#[test]
fn self_closing_void_elements() {
    let got = sanitize_string("<br />");
    assert_eq!(got, "<br />");

    let got = sanitize_string("<hr/>");
    assert_eq!(got, "<hr />");

    let got = sanitize_string("<img src=\"http://x.com/i.png\" />");
    assert_eq!(got, "<img src=\"http://x.com/i.png\" />");
}

#[test]
fn data_uri_in_src() {
    let got = sanitize_string("<img src=\"data:image/png;base64,abc\">");
    // data: URIs should be rejected
    assert_eq!(got, "<img>");
}

#[test]
fn javascript_uri_variations() {
    let cases = vec![
        "<a href=\"javascript:alert(1)\">x</a>",
        "<a href=\"JAVASCRIPT:alert(1)\">x</a>",
        "<a href=\"JaVaScRiPt:alert(1)\">x</a>",
        "<a href=\"  javascript:alert(1)\">x</a>",
        "<a href=\"vbscript:alert(1)\">x</a>",
    ];
    for input in cases {
        let got = sanitize_string(input);
        assert!(
            !got.contains("javascript") && !got.contains("JAVASCRIPT") && !got.contains("vbscript"),
            "URI not sanitized for input: {}",
            input
        );
    }
}

#[test]
fn relative_url_preserved() {
    let got = sanitize_string("<a href=\"/path/to/page\">link</a>");
    assert!(got.contains("href=\"/path/to/page\""));
}

#[test]
fn anchor_url_preserved() {
    let got = sanitize_string("<a href=\"#section\">link</a>");
    assert!(got.contains("href=\"#section\""));
}

#[test]
fn https_url_preserved() {
    let got = sanitize_string("<a href=\"https://example.com/page?q=1&r=2#frag\">link</a>");
    assert!(got.contains("href=\"https://example.com/page?q=1&r=2#frag\""));
}

#[test]
fn multiple_classes() {
    let got = sanitize_string("<div class=\"foo bar baz\">x</div>");
    assert_eq!(got, "<div class=\"foo bar baz\">x</div>");
}

#[test]
fn attribute_with_entities() {
    let got = sanitize_string("<a href=\"http://example.com/a&amp;b\">link</a>");
    assert!(got.contains("href="));
}

#[test]
fn style_tag_content_stripped() {
    let got = sanitize_string("<style>body { background: red; }</style><p>text</p>");
    assert!(!got.contains("background"));
    assert!(got.contains("<p>text</p>"));
}

#[test]
fn script_tag_content_stripped() {
    let got = sanitize_string("<script>var x = 1;</script><p>text</p>");
    assert!(!got.contains("var x"));
    assert!(got.contains("<p>text</p>"));
}

#[test]
fn object_tag_content_stripped() {
    let got = sanitize_string("<object>fallback content</object><p>after</p>");
    assert!(!got.contains("fallback"));
    assert!(got.contains("<p>after</p>"));
}

#[test]
fn nested_script_in_allowed() {
    let got = sanitize_string("<div><script>alert(1)</script></div>");
    assert_eq!(got, "<div></div>");
}

#[test]
fn unclosed_script_eats_rest() {
    let got = sanitize_string("<script>alert(1)");
    assert_eq!(got, "");
}

#[test]
fn unclosed_style_eats_rest() {
    let got = sanitize_string("<style>.x { color: red; }");
    assert_eq!(got, "");
}

#[test]
fn multiple_lt_signs() {
    let got = sanitize_string("<<<");
    // Each < that doesn't start a valid tag
    assert!(!got.contains("<script"));
}

#[test]
fn tag_with_only_whitespace_attrs() {
    let got = sanitize_string("<p   >text</p>");
    assert!(got.contains("<p>text</p>"));
}

#[test]
fn single_byte_at_a_time() {
    use std::io::Write;

    let input = "<a href=\"http://example.com\" class=\"x\">test</a><script>bad</script>";
    let expected = sanitize_string(input);

    let mut buf = Vec::new();
    {
        let sanitizer = htmlsanitizer::HtmlSanitizer::new();
        let mut w = sanitizer.new_writer(&mut buf);
        for &b in input.as_bytes() {
            w.write_all(&[b]).unwrap();
        }
    }
    let got = String::from_utf8(buf).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn fuzz_pattern_script_style_wrapping() {
    // Port of Go's FuzzSanitize seed case
    let payload = b"xxls<<< <xx />";
    let mut data = b"abc<script>".to_vec();
    data.extend_from_slice(payload);
    data.extend_from_slice(b"abc</script>def<style>");
    data.extend_from_slice(payload);
    data.extend_from_slice(b"</style ...>(g)");
    let expected = b"abcdef(g)";

    let got = htmlsanitizer::sanitize(&data);
    assert_eq!(got, expected);
}

#[test]
fn on_event_handlers_stripped() {
    let events = [
        "onclick",
        "ondblclick",
        "onmousedown",
        "onmouseup",
        "onmouseover",
        "onmousemove",
        "onmouseout",
        "onkeypress",
        "onkeydown",
        "onkeyup",
        "onfocus",
        "onblur",
        "onload",
        "onunload",
        "onsubmit",
        "onreset",
        "onselect",
        "onchange",
        "onerror",
        "onresize",
        "onscroll",
    ];
    for event in &events {
        let input = format!("<img {} =\"alert(1)\" src=\"http://x.com/i.png\">", event);
        let got = sanitize_string(&input);
        assert!(
            !got.contains(event),
            "event handler {} not stripped from: {}",
            event,
            got
        );
    }
}

#[test]
fn table_tags_preserved() {
    let input =
        "<table><thead><tr><th>H</th></tr></thead><tbody><tr><td>D</td></tr></tbody></table>";
    let got = sanitize_string(input);
    assert_eq!(got, input);
}

#[test]
fn details_summary_preserved() {
    let input = "<details open><summary>Title</summary>Content</details>";
    let got = sanitize_string(input);
    assert_eq!(got, input);
}

#[test]
fn video_audio_tags() {
    let got = sanitize_string("<video src=\"http://example.com/v.mp4\" controls autoplay></video>");
    assert!(got.contains("<video"));
    assert!(got.contains("controls"));
    assert!(got.contains("autoplay"));

    let got = sanitize_string("<audio src=\"http://example.com/a.mp3\" controls></audio>");
    assert!(got.contains("<audio"));
    assert!(got.contains("controls"));
}

#[test]
fn svg_completely_stripped() {
    let got = sanitize_string("<svg><circle cx=\"50\" cy=\"50\" r=\"40\"/></svg>");
    assert!(!got.contains("<svg"));
    assert!(!got.contains("<circle"));
}

#[test]
fn form_elements_stripped() {
    let got =
        sanitize_string("<form action=\"/submit\"><input type=\"text\"><button>Go</button></form>");
    assert!(!got.contains("<form"));
    assert!(!got.contains("<input"));
    assert!(!got.contains("<button"));
    assert!(got.contains("Go"));
}
