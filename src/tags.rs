use std::collections::HashMap;

/// A single HTML tag with its allowed attributes.
#[derive(Debug, Clone)]
pub struct Tag {
    /// Tag name (must be lowercase).
    pub name: String,
    /// Allowed non-URL attributes (must be lowercase).
    pub attr: Vec<String>,
    /// Allowed URL-related attributes (must be lowercase).
    pub url_attr: Vec<String>,
}

impl Tag {
    pub fn new(name: &str, attr: &[&str], url_attr: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            attr: attr.iter().map(|s| s.to_string()).collect(),
            url_attr: url_attr.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Check whether an attribute exists on this tag. Returns `(exists, is_url_attr)`.
    pub fn attr_exists(&self, name: &[u8]) -> (bool, bool) {
        let name = std::str::from_utf8(name).unwrap_or("");
        for a in &self.url_attr {
            if a == name {
                return (true, true);
            }
        }
        for a in &self.attr {
            if a == name {
                return (true, false);
            }
        }
        (false, false)
    }
}

/// Specifies all allowed HTML tags and attributes for the sanitizer.
#[derive(Debug, Clone)]
pub struct AllowList {
    /// Allowed tags.
    pub tags: Vec<Tag>,
    /// Globally allowed attributes (e.g. `class`, `id`).
    pub global_attr: Vec<String>,
    /// Non-HTML tags like `<script>`, `<style>` whose content is not real HTML.
    pub non_html_tags: Vec<Tag>,

    tag_map: Option<HashMap<String, usize>>,
    non_html_tag_map: Option<HashMap<String, usize>>,
}

impl AllowList {
    fn build_tag_map(&mut self) {
        let mut map = HashMap::with_capacity(self.tags.len());
        for (i, tag) in self.tags.iter().enumerate() {
            map.insert(tag.name.clone(), i);
        }
        self.tag_map = Some(map);
    }

    fn build_non_html_tag_map(&mut self) {
        let mut map = HashMap::with_capacity(self.non_html_tags.len());
        for (i, tag) in self.non_html_tags.iter().enumerate() {
            map.insert(tag.name.clone(), i);
        }
        self.non_html_tag_map = Some(map);
    }

    /// Check whether a global attribute exists.
    pub fn attr_exists(&self, name: &[u8]) -> bool {
        let name = std::str::from_utf8(name).unwrap_or("");
        self.global_attr.iter().any(|a| a == name)
    }

    /// Check if a tag name is a non-HTML tag (e.g. `script`, `style`).
    /// The name must already be lowercased.
    pub fn check_non_html_tag(&mut self, name: &str) -> Option<usize> {
        if self.non_html_tag_map.is_none() {
            self.build_non_html_tag_map();
        }
        self.non_html_tag_map.as_ref().unwrap().get(name).copied()
    }

    /// Add a tag to the allow list.
    pub fn add_tag(&mut self, tag: Tag) {
        self.tags.push(tag);
        self.tag_map = None;
    }

    /// Remove all tags with the given name (must be lowercase).
    pub fn remove_tag(&mut self, name: &str) {
        self.tags.retain(|t| t.name != name);
        self.tag_map = None;
    }

    /// Find a tag by its lowercased name.
    pub fn find_tag(&mut self, name: &str) -> Option<usize> {
        if self.tag_map.is_none() {
            self.build_tag_map();
        }
        self.tag_map.as_ref().unwrap().get(name).copied()
    }
}

/// Lowercase ASCII A-Z bytes in place.
pub fn ascii_lower_in_place(p: &mut [u8]) {
    p.make_ascii_lowercase();
}

/// Create the default allow list matching the Go `DefaultAllowList`.
pub fn default_allow_list() -> AllowList {
    AllowList {
        tags: vec![
            Tag::new("address", &[], &[]),
            Tag::new("article", &[], &[]),
            Tag::new("aside", &[], &[]),
            Tag::new("footer", &[], &[]),
            Tag::new("header", &[], &[]),
            Tag::new("h1", &[], &[]),
            Tag::new("h2", &[], &[]),
            Tag::new("h3", &[], &[]),
            Tag::new("h4", &[], &[]),
            Tag::new("h5", &[], &[]),
            Tag::new("h6", &[], &[]),
            Tag::new("hgroup", &[], &[]),
            Tag::new("main", &[], &[]),
            Tag::new("nav", &[], &[]),
            Tag::new("section", &[], &[]),
            Tag::new("blockquote", &[], &["cite"]),
            Tag::new("dd", &[], &[]),
            Tag::new("div", &[], &[]),
            Tag::new("dl", &[], &[]),
            Tag::new("dt", &[], &[]),
            Tag::new("figcaption", &[], &[]),
            Tag::new("figure", &[], &[]),
            Tag::new("hr", &[], &[]),
            Tag::new("li", &[], &[]),
            Tag::new("ol", &[], &[]),
            Tag::new("p", &[], &[]),
            Tag::new("pre", &[], &[]),
            Tag::new("ul", &[], &[]),
            Tag::new("a", &["rel", "target", "referrerpolicy"], &["href"]),
            Tag::new("abbr", &["title"], &[]),
            Tag::new("b", &[], &[]),
            Tag::new("bdi", &[], &[]),
            Tag::new("bdo", &[], &[]),
            Tag::new("br", &[], &[]),
            Tag::new("cite", &[], &[]),
            Tag::new("code", &[], &[]),
            Tag::new("data", &["value"], &[]),
            Tag::new("em", &[], &[]),
            Tag::new("i", &[], &[]),
            Tag::new("kbd", &[], &[]),
            Tag::new("mark", &[], &[]),
            Tag::new("q", &[], &["cite"]),
            Tag::new("s", &[], &[]),
            Tag::new("small", &[], &[]),
            Tag::new("span", &[], &[]),
            Tag::new("strong", &[], &[]),
            Tag::new("sub", &[], &[]),
            Tag::new("sup", &[], &[]),
            Tag::new("time", &["datetime"], &[]),
            Tag::new("u", &[], &[]),
            Tag::new(
                "area",
                &["alt", "coords", "shape", "target", "rel", "referrerpolicy"],
                &["href"],
            ),
            Tag::new(
                "audio",
                &[
                    "autoplay",
                    "controls",
                    "crossorigin",
                    "duration",
                    "loop",
                    "muted",
                    "preload",
                ],
                &["src"],
            ),
            Tag::new(
                "img",
                &[
                    "alt",
                    "crossorigin",
                    "height",
                    "width",
                    "loading",
                    "referrerpolicy",
                ],
                &["src"],
            ),
            Tag::new("map", &["name"], &[]),
            Tag::new("track", &["default", "kind", "label", "srclang"], &["src"]),
            Tag::new(
                "video",
                &[
                    "autoplay",
                    "buffered",
                    "controls",
                    "crossorigin",
                    "duration",
                    "loop",
                    "muted",
                    "preload",
                    "height",
                    "width",
                ],
                &["src", "poster"],
            ),
            Tag::new("picture", &[], &[]),
            Tag::new("source", &["type"], &["src"]),
            Tag::new("del", &[], &[]),
            Tag::new("ins", &[], &[]),
            Tag::new("caption", &[], &[]),
            Tag::new("col", &["span"], &[]),
            Tag::new("colgroup", &[], &[]),
            Tag::new("table", &[], &[]),
            Tag::new("tbody", &[], &[]),
            Tag::new("td", &["colspan", "rowspan"], &[]),
            Tag::new("tfoot", &[], &[]),
            Tag::new("th", &["colspan", "rowspan", "scope"], &[]),
            Tag::new("thead", &[], &[]),
            Tag::new("tr", &[], &[]),
            Tag::new("details", &["open"], &[]),
            Tag::new("summary", &[], &[]),
        ],
        global_attr: vec!["class".to_string(), "id".to_string()],
        non_html_tags: vec![
            Tag::new("script", &[], &[]),
            Tag::new("style", &[], &[]),
            Tag::new("object", &[], &[]),
        ],
        tag_map: None,
        non_html_tag_map: None,
    }
}
