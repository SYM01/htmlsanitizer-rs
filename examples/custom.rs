//! Customizing the sanitizer: removing tags, adding tags, and custom URL sanitizers.

use htmlsanitizer::{HtmlSanitizer, Tag};

fn main() {
    // Remove a tag from the default allow list
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer.allow_list.remove_tag("a");

    let input = r#"<a href="http://example.com">click</a> <p>safe</p>"#;
    println!("With <a> removed:");
    println!("  Input:  {input}");
    println!("  Output: {}", sanitizer.sanitize_string(input));
    // Output: click <p>safe</p>

    // Add a custom tag
    let mut sanitizer = HtmlSanitizer::new();
    sanitizer
        .allow_list
        .add_tag(Tag::new("custom-el", &["data-x"], &[]));

    let input = r#"<custom-el data-x="1" onclick="bad">content</custom-el>"#;
    println!("\nWith <custom-el> added:");
    println!("  Input:  {input}");
    println!("  Output: {}", sanitizer.sanitize_string(input));
    // Output: <custom-el data-x="1">content</custom-el>

    // Custom URL sanitizer: only allow a specific domain
    let sanitizer = HtmlSanitizer::new().with_url_sanitizer(|raw_url| {
        let sanitized = htmlsanitizer::default_url_sanitizer(raw_url)?;
        if sanitized.contains("trusted.com") {
            Some(sanitized)
        } else {
            None
        }
    });

    println!("\nWith domain-restricted URL sanitizer:");
    let input = r#"<a href="http://trusted.com/page">ok</a> <a href="http://evil.com">bad</a>"#;
    println!("  Input:  {input}");
    println!("  Output: {}", sanitizer.sanitize_string(input));
    // Output: <a href="http://trusted.com/page">ok</a> <a>bad</a>
}
