#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Basic: sanitize arbitrary input, should not panic
    let _ = htmlsanitizer::sanitize(data);

    // 2. Wrap in script tags (mirrors Go fuzz test pattern)
    // abc<script>{data}abc</script>def<style>{data}</style ...>(g)
    // Expected output: abcdef(g)
    let mut wrapped = b"abc<script>".to_vec();
    wrapped.extend_from_slice(data);
    wrapped.extend_from_slice(b"abc</script>def<style>");
    wrapped.extend_from_slice(data);
    wrapped.extend_from_slice(b"</style ...>(g)");

    let result = htmlsanitizer::sanitize(&wrapped);
    assert_eq!(
        result,
        b"abcdef(g)",
        "script/style wrapping failed for input: {:?}",
        String::from_utf8_lossy(data)
    );

    // 3. Verify no script tags survive in output of arbitrary input
    let result = htmlsanitizer::sanitize(data);
    let lower: Vec<u8> = result.iter().map(|b| b.to_ascii_lowercase()).collect();
    assert!(
        !lower.windows(7).any(|w| w == b"<script"),
        "script tag found in sanitized output"
    );
    assert!(
        !lower.windows(6).any(|w| w == b"<style"),
        "style tag found in sanitized output"
    );
});
