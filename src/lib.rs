pub mod dfa;
pub mod tags;
pub mod url;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use dfa::SanitizeWriter;
pub use tags::{default_allow_list, AllowList, Tag};
pub use url::default_url_sanitizer;

use dfa::UrlSanitizerFn;
use std::io::Write;
use std::sync::{Arc, OnceLock};

/// HTML sanitizer with a configurable allow list and URL sanitizer.
pub struct HtmlSanitizer {
    pub allow_list: AllowList,
    url_sanitizer: UrlSanitizerFn,
}

impl HtmlSanitizer {
    /// Create a new sanitizer with a clone of the default allow list.
    pub fn new() -> Self {
        Self {
            allow_list: default_allow_list(),
            url_sanitizer: Arc::new(default_url_sanitizer),
        }
    }

    /// Create a new sanitizer with a custom URL sanitizer.
    pub fn with_url_sanitizer<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        self.url_sanitizer = Arc::new(f);
        self
    }

    /// Set a custom URL sanitizer.
    pub fn set_url_sanitizer<F>(&mut self, f: F)
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        self.url_sanitizer = Arc::new(f);
    }

    /// Create a new `SanitizeWriter` wrapping the given writer.
    pub fn new_writer<W: std::io::Write>(&self, w: W) -> SanitizeWriter<W> {
        SanitizeWriter::new(w, self.allow_list.clone(), self.url_sanitizer.clone())
    }

    /// Sanitize HTML bytes and return sanitized output.
    pub fn sanitize(&self, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(data.len());
        {
            let mut w = self.new_writer(&mut buf);
            let _ = w.write_all(data);
        }
        buf
    }

    /// Sanitize an HTML string.
    pub fn sanitize_string(&self, data: &str) -> String {
        String::from_utf8(self.sanitize(data.as_bytes())).unwrap_or_default()
    }
}

impl Default for HtmlSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

fn default_sanitizer() -> &'static HtmlSanitizer {
    static INSTANCE: OnceLock<HtmlSanitizer> = OnceLock::new();
    INSTANCE.get_or_init(HtmlSanitizer::new)
}

/// Convenience: sanitize HTML bytes with the default allow list.
pub fn sanitize(data: &[u8]) -> Vec<u8> {
    default_sanitizer().sanitize(data)
}

/// Convenience: sanitize an HTML string with the default allow list.
pub fn sanitize_string(data: &str) -> String {
    default_sanitizer().sanitize_string(data)
}
