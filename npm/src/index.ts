/**
 * @bytevet/htmlsanitizer — A fast, allowlist-based HTML sanitizer powered by WebAssembly.
 *
 * @example
 * ```ts
 * import { sanitize, HtmlSanitizer } from "@bytevet/htmlsanitizer";
 *
 * // Quick sanitization with defaults
 * const clean = sanitize('<script>alert("xss")</script><p>Hello</p>');
 * // => "<p>Hello</p>"
 *
 * // Custom configuration
 * const s = new HtmlSanitizer();
 * s.removeTag("a");
 * const result = s.sanitize('<a href="http://example.com">link</a>');
 * // => "link"
 * ```
 */

import {
  sanitize as wasmSanitize,
  WasmHtmlSanitizer,
} from "../pkg/htmlsanitizer.js";

/**
 * Sanitize an HTML string using the default allow list.
 *
 * @param input - Raw HTML string to sanitize.
 * @returns Sanitized HTML string with dangerous elements/attributes removed.
 *
 * @example
 * ```ts
 * sanitize('<img src=x onerror="alert(1)">');
 * // => '<img src="x">'
 * ```
 */
export function sanitize(input: string): string {
  return wasmSanitize(input);
}

/**
 * A configurable HTML sanitizer.
 *
 * Create an instance to customize which tags and attributes are allowed,
 * then call `.sanitize()` to process HTML strings.
 *
 * @example
 * ```ts
 * const s = new HtmlSanitizer();
 * s.removeTag("img");
 * s.sanitize('<img src="x"><p>text</p>');
 * // => '<p>text</p>'
 * ```
 */
export class HtmlSanitizer {
  private inner: WasmHtmlSanitizer;

  constructor() {
    this.inner = new WasmHtmlSanitizer();
  }

  /**
   * Sanitize an HTML string using this sanitizer's configuration.
   */
  sanitize(input: string): string {
    return this.inner.sanitize(input);
  }

  /**
   * Remove a tag from the allow list.
   *
   * @param name - Lowercase tag name to remove (e.g. "script", "a", "img").
   */
  removeTag(name: string): void {
    this.inner.removeTag(name);
  }

  /**
   * Add a tag to the allow list.
   *
   * @param name - Lowercase tag name (e.g. "custom-element").
   * @param attrs - Comma-separated non-URL attribute names, or empty string.
   * @param urlAttrs - Comma-separated URL attribute names, or empty string.
   */
  addTag(name: string, attrs = "", urlAttrs = ""): void {
    this.inner.addTag(name, attrs, urlAttrs);
  }

  /**
   * Add a global attribute allowed on all tags.
   *
   * @param name - Attribute name (e.g. "data-testid").
   */
  addGlobalAttr(name: string): void {
    this.inner.addGlobalAttr(name);
  }

  /**
   * Free the underlying WASM memory. The instance cannot be used after this.
   */
  free(): void {
    this.inner.free();
  }
}
