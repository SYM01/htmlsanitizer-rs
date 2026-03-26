# htmlsanitizer

A fast, allowlist-based HTML sanitizer for Rust.

Ported from [sym01/htmlsanitizer](https://github.com/sym01/htmlsanitizer) (Go).

## Features

- O(n) streaming FSM parser — no DOM tree allocation
- Allowlist-based: only explicitly permitted tags and attributes pass through
- URL attribute sanitization (rejects `javascript:`, `data:`, etc.)
- Customizable allow list and URL sanitizer
- Optional WASM/npm support via the `wasm` feature

## Usage

```rust
use htmlsanitizer::{sanitize_string, HtmlSanitizer};

// Quick one-shot sanitization with the default allow list
let safe = sanitize_string("<script>alert(1)</script><p>hello</p>");
assert_eq!(safe, "<p>hello</p>");

// Custom sanitizer with a modified allow list
let mut s = HtmlSanitizer::new();
s.allow_list.remove_tag("a");
let safe = s.sanitize_string("<a href=\"http://x.com\">link</a>");
assert_eq!(safe, "link");
```

## License

MIT
