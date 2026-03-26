//! Streaming sanitization using the io::Write interface.

use std::io::Write;

use htmlsanitizer::HtmlSanitizer;

fn main() {
    let sanitizer = HtmlSanitizer::new();
    let mut output = Vec::new();

    {
        let mut writer = sanitizer.new_writer(&mut output);

        // Write HTML in chunks — state is preserved between writes
        writer
            .write_all(b"<p>Hello </p><scr")
            .expect("write failed");
        writer
            .write_all(b"ipt>alert('xss')</script>")
            .expect("write failed");
        writer.write_all(b"<b>world</b>").expect("write failed");
    }

    let result = String::from_utf8(output).unwrap();
    println!("Streamed output: {result}");
    // Output: <p>Hello </p><b>world</b>
}
