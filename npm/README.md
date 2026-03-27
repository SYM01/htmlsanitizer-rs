# @bytevet/htmlsanitizer

[![npm](https://img.shields.io/npm/v/@bytevet/htmlsanitizer)](https://www.npmjs.com/package/@bytevet/htmlsanitizer)
[![CI](https://github.com/SYM01/htmlsanitizer-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/SYM01/htmlsanitizer-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/SYM01/htmlsanitizer-rs/blob/main/LICENSE)

A fast, allowlist-based HTML sanitizer powered by WebAssembly. [**3.7–44x faster**](#performance) than DOMPurify on real HTML content.

Ships a pre-built WASM binary — no native toolchain required.

Also available in [Rust](https://crates.io/crates/htmlsanitizer) and [Go](https://github.com/SYM01/htmlsanitizer).

## Features

- **O(n) streaming parser** — DFA-based finite state machine; no DOM tree, no backtracking
- **Allowlist-based** — only explicitly permitted tags and attributes pass through; everything else is stripped
- **URL sanitization** — rejects `javascript:`, `data:`, `ftp:`, control characters, and opaque URIs
- **Customizable** — add/remove tags, modify allowed attributes
- **Identical output** to the native Rust crate — same sanitization engine compiled to WASM

## Installation

```bash
npm install @bytevet/htmlsanitizer
```

## Quick Start

```ts
import { sanitize } from "@bytevet/htmlsanitizer";

const safe = sanitize('<p>Hello</p><script>alert("xss")</script>');
// => "<p>Hello</p>"
```

## Usage

### Default Sanitization

```ts
import { sanitize } from "@bytevet/htmlsanitizer";

sanitize('<img src=x onerror="alert(1)">');
// => '<img src="x">'

sanitize('<a href="javascript:alert(1)">click</a>');
// => '<a>click</a>'
```

### Custom Configuration

```ts
import { HtmlSanitizer } from "@bytevet/htmlsanitizer";

const s = new HtmlSanitizer();

// Remove a tag from the allow list
s.removeTag("a");
s.sanitize('<a href="http://example.com">link</a>');
// => "link"

// Add a custom tag
// Arguments: name, comma-separated attributes, comma-separated URL attributes
s.addTag("custom-el", "data-x,title", "href");
s.sanitize('<custom-el data-x="1" onclick="bad">content</custom-el>');
// => '<custom-el data-x="1">content</custom-el>'

// Add a global attribute (allowed on all tags)
s.addGlobalAttr("data-testid");

// Release WASM memory when done (instance is unusable after this)
s.free();
```

## API Reference

| Export | Description |
|---|---|
| `sanitize(input: string): string` | One-shot sanitization with the default allow list |
| `new HtmlSanitizer()` | Create a configurable sanitizer instance |
| `.sanitize(input: string): string` | Sanitize HTML using the instance's configuration |
| `.addTag(name, attrs?, urlAttrs?)` | Add a tag; `attrs` and `urlAttrs` are comma-separated strings |
| `.removeTag(name: string)` | Remove a tag from the allow list |
| `.addGlobalAttr(name: string)` | Allow an attribute on all tags |
| `.free()` | Release WASM memory; the instance is unusable after this |

## Default Allow List

The default allow list permits 68 commonly used HTML tags. All other tags are stripped — their text content is preserved. Tags in the non-HTML list (`script`, `style`, `object`) have both their tags **and** content removed.

**Global attributes** (allowed on every permitted tag): `class`, `id`

<details>
<summary>View all 68 default tags</summary>

| Category | Tags |
|---|---|
| Structural | `address`, `article`, `aside`, `footer`, `header`, `h1`–`h6`, `hgroup`, `main`, `nav`, `section` |
| Block content | `blockquote`, `dd`, `div`, `dl`, `dt`, `figcaption`, `figure`, `hr`, `li`, `ol`, `p`, `pre`, `ul` |
| Inline text | `a`, `abbr`, `b`, `bdi`, `bdo`, `br`, `cite`, `code`, `data`, `em`, `i`, `kbd`, `mark`, `q`, `s`, `small`, `span`, `strong`, `sub`, `sup`, `time`, `u` |
| Media | `area`, `audio`, `img`, `map`, `track`, `video`, `picture`, `source` |
| Table | `caption`, `col`, `colgroup`, `table`, `tbody`, `td`, `tfoot`, `th`, `thead`, `tr` |
| Edit marks | `del`, `ins` |
| Interactive | `details`, `summary` |

**Notable tag-specific attributes:**

| Tag | Regular attributes | URL attributes |
|---|---|---|
| `a` | `rel`, `target`, `referrerpolicy` | `href` |
| `img` | `alt`, `crossorigin`, `height`, `width`, `loading`, `referrerpolicy` | `src` |
| `video` | `autoplay`, `buffered`, `controls`, `crossorigin`, `duration`, `loop`, `muted`, `preload`, `height`, `width` | `src`, `poster` |
| `audio` | `autoplay`, `controls`, `crossorigin`, `duration`, `loop`, `muted`, `preload` | `src` |
| `td` / `th` | `colspan`, `rowspan` (+ `scope` for `th`) | — |

</details>

## URL Sanitization

Attributes marked as URL attributes (`href`, `src`, `poster`, `cite`, etc.) are validated by the URL sanitizer. The default behavior:

**Accepted:**
- `http://` and `https://` URLs
- Relative URLs (paths, fragments, query strings)

**Rejected:**
- `javascript:` (including case variations and HTML-entity-encoded forms)
- `data:` URIs
- `ftp:` and all other non-HTTP schemes
- URLs containing ASCII control characters (bytes < 0x20 or 0x7F)
- Opaque (cannot-be-a-base) URIs
- Percent-encoded ASCII in hostnames

When a URL is rejected, the attribute is removed but the tag and its content are preserved (e.g., `<a href="javascript:...">text</a>` becomes `<a>text</a>`).

## Security Considerations

- **Defense in depth.** This sanitizer is designed as one layer of an XSS mitigation strategy. Combine it with Content Security Policy headers and context-aware output encoding.
- **Not a full HTML parser.** The DFA-based approach handles real-world HTML effectively but does not build a DOM tree. It is designed to be conservative — when in doubt, content is stripped.
- **Fuzz-tested.** The project includes a `cargo-fuzz` harness. If you discover a bypass, please report it via [GitHub Issues](https://github.com/SYM01/htmlsanitizer-rs/issues).
- **Tested against known XSS vectors.** The test suite includes vectors from OWASP and other common XSS payloads.

## Performance

Benchmarked with [Vitest bench](https://vitest.dev/guide/features#benchmarking) on Node.js against [DOMPurify](https://github.com/cure53/DOMPurify) (with jsdom):

| Payload | @bytevet/htmlsanitizer | DOMPurify + jsdom | Ratio |
|---|---|---|---|
| Simple HTML (small) | 56,716 ops/s | 15,253 ops/s | **3.7x faster** |
| XSS vectors | 40,908 ops/s | 5,373 ops/s | **7.6x faster** |
| Blog post (medium) | 33,259 ops/s | 1,381 ops/s | **24x faster** |
| Mixed safe + dangerous | 40,326 ops/s | 3,987 ops/s | **10x faster** |
| Large document (~50 KB) | 1,054 ops/s | 24 ops/s | **44x faster** |

> DOMPurify is faster on tiny plain-text inputs (no HTML tags) due to WASM call overhead (~10 µs). For any real HTML content, `@bytevet/htmlsanitizer` is **3.7–44x faster**, with the advantage growing as input size increases.

## License

MIT — see [LICENSE](https://github.com/SYM01/htmlsanitizer-rs/blob/main/LICENSE).
