//! AllowList tests: clone deep copy, remove_tag, find_tag, custom URL sanitizer, empty list.

use htmlsanitizer::{default_allow_list, HtmlSanitizer, Tag};

#[test]
fn clone_deep_copy_tags() {
    let original = default_allow_list();
    let mut clone = original.clone();

    let orig_tag_count = original.tags.len();

    // Mutate clone's tag slice
    clone.tags.push(Tag::new("custom", &[], &[]));
    assert_eq!(
        original.tags.len(),
        orig_tag_count,
        "appending to clone.tags changed original"
    );
}

#[test]
fn clone_deep_copy_tag_attrs() {
    let original = default_allow_list();
    let mut clone = original.clone();

    let orig_first_attr_count = original.tags[0].attr.len();

    // Mutate a Tag's attrs inside the clone
    clone.tags[0].attr.push("style".to_string());
    assert_eq!(
        original.tags[0].attr.len(),
        orig_first_attr_count,
        "mutating clone Tag.attr changed original"
    );
}

#[test]
fn clone_deep_copy_global_attr() {
    let original = default_allow_list();
    let mut clone = original.clone();

    let orig_global_count = original.global_attr.len();

    clone.global_attr.push("data-x".to_string());
    assert_eq!(
        original.global_attr.len(),
        orig_global_count,
        "appending to clone.global_attr changed original"
    );
}

#[test]
fn remove_tag() {
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.remove_tag("a");

    let input = r#"
<h1 class="h1">hello</h1>
<p>
	Hello, world<br>
	Welcome to use <a href="https://github.com/sym01/htmlsanitizer">htmlsanitizer</a>
</p>"#;

    let got = sanitizer.sanitize_string(input);

    // Links should be stripped but text preserved
    assert!(got.contains("<h1"));
    assert!(got.contains("hello"));
    assert!(got.contains("<br>"));
    assert!(got.contains("htmlsanitizer"));
    assert!(!got.contains("<a "));
    assert!(!got.contains("</a>"));
}

#[test]
fn find_tag_existing() {
    let mut al = default_allow_list();
    let idx = al.find_tag("a");
    assert!(idx.is_some(), "should find 'a' tag");
    assert_eq!(al.tags[idx.unwrap()].name, "a");
}

#[test]
fn find_tag_nonexistent() {
    let mut al = default_allow_list();
    assert!(al.find_tag("blink").is_none());
    assert!(al.find_tag("marquee").is_none());
    assert!(al.find_tag("script").is_none()); // script is non-html, not in tags
}

#[test]
fn empty_allow_list_strips_everything() {
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.tags.clear();
    sanitizer.allow_list.global_attr.clear();
    sanitizer.allow_list.non_html_tags.clear();

    let input = "<div class=\"x\"><p>Hello <a href=\"http://example.com\">world</a></p></div>";
    let got = sanitizer.sanitize_string(input);

    assert!(!got.contains('<'), "no tags should remain: {}", got);
    assert!(got.contains("Hello"));
    assert!(got.contains("world"));
}

#[test]
fn custom_url_sanitizer_domain_restrict() {
    let sanitizer = HtmlSanitizer::new().with_url_sanitizer(|raw_url: &str| {
        let default = htmlsanitizer::default_url_sanitizer(raw_url)?;
        if let Ok(u) = url::Url::parse(&default) {
            if u.host_str() == Some("example.com") {
                return Some(default);
            }
        }
        None
    });

    let input =
        r#"<a href="http://others.com">Other</a><a href="https://example.com/page">Example</a>"#;
    let got = sanitizer.sanitize_string(input);

    assert_eq!(
        got,
        r#"<a>Other</a><a href="https://example.com/page">Example</a>"#
    );
}

#[test]
fn add_custom_tag() {
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer
        .allow_list
        .tags
        .push(Tag::new("custom-tag", &["data-value"], &[]));

    let input = r#"<custom-tag data-value="123" onclick="alert(1)">content</custom-tag>"#;
    let got = sanitizer.sanitize_string(input);

    assert!(got.contains("<custom-tag"));
    assert!(got.contains("data-value=\"123\""));
    assert!(!got.contains("onclick"));
}

#[test]
fn remove_tag_then_sanitize() {
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.remove_tag("img");

    let input = r#"<p>Text</p><img src="http://example.com/i.png"><p>More</p>"#;
    let got = sanitizer.sanitize_string(input);

    assert!(!got.contains("<img"));
    assert!(got.contains("<p>Text</p>"));
    assert!(got.contains("<p>More</p>"));
}

#[test]
fn attr_exists_check() {
    let al = default_allow_list();

    // Global attributes
    assert!(al.attr_exists(b"class"));
    assert!(al.attr_exists(b"id"));
    assert!(!al.attr_exists(b"style"));
    assert!(!al.attr_exists(b"onclick"));
}

#[test]
fn tag_attr_exists_check() {
    let tag = Tag::new("a", &["rel", "target"], &["href"]);

    assert_eq!(tag.attr_exists(b"href"), (true, true));
    assert_eq!(tag.attr_exists(b"rel"), (true, false));
    assert_eq!(tag.attr_exists(b"target"), (true, false));
    assert_eq!(tag.attr_exists(b"onclick"), (false, false));
}

#[test]
fn non_html_tag_check() {
    let mut al = default_allow_list();
    assert!(al.check_non_html_tag("script").is_some());
    assert!(al.check_non_html_tag("style").is_some());
    assert!(al.check_non_html_tag("object").is_some());
    assert!(al.check_non_html_tag("div").is_none());
}
