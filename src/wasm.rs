use wasm_bindgen::prelude::*;

use crate::HtmlSanitizer;

/// Sanitize an HTML string using the default allow list.
#[wasm_bindgen]
pub fn sanitize(input: &str) -> String {
    HtmlSanitizer::new().sanitize_string(input)
}

/// A configurable HTML sanitizer for use from JavaScript/TypeScript.
#[wasm_bindgen]
pub struct WasmHtmlSanitizer {
    inner: HtmlSanitizer,
}

impl Default for WasmHtmlSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmHtmlSanitizer {
    /// Create a new sanitizer with the default allow list.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: HtmlSanitizer::new(),
        }
    }

    /// Sanitize an HTML string.
    pub fn sanitize(&self, input: &str) -> String {
        self.inner.sanitize_string(input)
    }

    /// Remove a tag from the allow list by name (must be lowercase).
    #[wasm_bindgen(js_name = "removeTag")]
    pub fn remove_tag(&mut self, name: &str) {
        self.inner.allow_list.remove_tag(name);
    }

    /// Add a tag to the allow list.
    /// `attrs` and `url_attrs` are comma-separated attribute names (or empty string for none).
    #[wasm_bindgen(js_name = "addTag")]
    pub fn add_tag(&mut self, name: &str, attrs: &str, url_attrs: &str) {
        let attr: Vec<&str> = if attrs.is_empty() {
            vec![]
        } else {
            attrs.split(',').map(|s| s.trim()).collect()
        };
        let url_attr: Vec<&str> = if url_attrs.is_empty() {
            vec![]
        } else {
            url_attrs.split(',').map(|s| s.trim()).collect()
        };
        self.inner
            .allow_list
            .add_tag(crate::Tag::new(name, &attr, &url_attr));
    }

    /// Add a global attribute that is allowed on all tags.
    #[wasm_bindgen(js_name = "addGlobalAttr")]
    pub fn add_global_attr(&mut self, name: &str) {
        self.inner.allow_list.global_attr.push(name.to_string());
    }
}
