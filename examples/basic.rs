//! Basic HTML sanitization using the default allow list.

fn main() {
    // Sanitize an HTML string with the default allow list
    let input = r#"<p>Hello <b>world</b></p><script>alert("xss")</script>"#;
    let clean = htmlsanitizer::sanitize_string(input);
    println!("Input:  {input}");
    println!("Output: {clean}");
    // Output: <p>Hello <b>world</b></p>

    // Sanitize bytes
    let bytes = b"<img src=\"http://example.com/img.png\" onerror=\"alert(1)\">";
    let clean_bytes = htmlsanitizer::sanitize(bytes);
    println!("\nInput:  {}", String::from_utf8_lossy(bytes));
    println!("Output: {}", String::from_utf8_lossy(&clean_bytes));
    // Output: <img src="http://example.com/img.png">
}
