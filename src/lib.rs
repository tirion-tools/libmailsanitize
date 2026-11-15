//! mailsanitize: one HTML part in, either a
//! sanitized document (ammonia allowlist, lightningcss reprint, dark policy v1 / strict) or the
//! plain-text fallback, each with a [`SanitizeManifest`]. Modules:
//! `color`, `css`, `dom`, `image` are the dark-mode transform, `sanitize` adds
//! the resource ids, `text` is the isolated HTML-to-text converter (html5ever tokenizer only; it
//! shares none of the sanitize pipeline).

pub mod color;
pub mod css;
pub mod dom;
pub mod image;
pub mod sanitize;
pub mod text;

use proto::v1::sanitizer::{
    HiddenCount, ManifestLink, RemoteImage, SanitizeManifest, Theme,
};

/// Sanitized document plus its manifest.
pub struct Sanitized {
    pub manifest: SanitizeManifest,
    pub document: String,
}

/// Text fallback plus its manifest (links and hidden counts) and stats.
pub struct Text {
    pub manifest: SanitizeManifest,
    pub text: String,
    pub hidden_chars: u32,
    pub dropped_elements: u32,
}

fn links_and_hidden(t: &text::TextOut) -> SanitizeManifest {
    SanitizeManifest {
        links: t
            .links
            .iter()
            .enumerate()
            .map(|(i, l)| ManifestLink {
                index: u32::try_from(i + 1).unwrap_or(u32::MAX),
                href: l.url.clone(),
                text_samples: l.samples.clone(),
            })
            .collect(),
        hidden: t
            .hidden
            .iter()
            .map(|&(r, n)| HiddenCount {
                reason: r as i32,
                chars: n,
            })
            .collect(),
        ..SanitizeManifest::default()
    }
}

/// Sanitizes one HTML part. `cid_ids` are the resource ids ([`sanitize::cid_resource_id`]) of the
/// CID parts the caller can supply. Light keeps the sender's colours; dark themes apply dark
/// policy v1 (strict: also re-colour sender text on preserved fills). The manifest's links and
/// hidden counts come from the text converter run over the sanitized (pre-dark) document, i.e.
/// what the rendered message shows.
pub fn sanitize(input: &str, theme: Theme, cid_ids: Vec<String>) -> Sanitized {
    sanitize::begin(cid_ids);
    let sanitized = sanitize::sanitize(input);
    let res = sanitize::finish();
    let mut manifest = links_and_hidden(&text::html_to_text(&sanitized));
    manifest.resource_ids_used = res.cid_used;
    manifest.remote_images = res
        .remote
        .into_iter()
        .map(|(id, url, width, height)| RemoteImage {
            id,
            url,
            width,
            height,
        })
        .collect();
    manifest.remote_images_dropped = res.remote_dropped;
    let document = match theme {
        Theme::DarkV1 | Theme::DarkStrict => {
            color::STRICT.store(
                theme == Theme::DarkStrict,
                std::sync::atomic::Ordering::Relaxed,
            );
            let html = dom::process(&sanitized, css::Mode::Transform).html;
            color::STRICT.store(false, std::sync::atomic::Ordering::Relaxed);
            html
        }
        Theme::Light | Theme::Unspecified => sanitized,
    };
    Sanitized { manifest, document }
}

/// The plain-text fallback of one HTML part (invalid UTF-8 already replaced by the caller).
pub fn text(input: &str) -> Text {
    let t = text::html_to_text(input);
    Text {
        manifest: links_and_hidden(&t),
        hidden_chars: t.hidden_chars,
        dropped_elements: t.dropped_elements,
        text: t.text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_lists_links_with_samples_and_counts_hidden_text() {
        let t = text(
            "<p>Hello <a href='https://example.com/a'>example.com</a> and \
             <a href='https://evil.test/'>https://bank.test/</a>\
             <span style='display:none'>secret</span>\u{202e}x</p>\
             <p><a href='https://example.com/a'>again</a> <a href='javascript:alert(1)'>js</a></p>",
        );
        assert!(t.text.contains("Links:\n[1] https://example.com/a\n[2] https://evil.test/  (the link text shows a different address)"));
        assert!(!t.text.contains("secret"));
        assert_eq!(t.manifest.links.len(), 2);
        assert_eq!(t.manifest.links[0].index, 1);
        assert_eq!(
            t.manifest.links[0].text_samples,
            vec!["example.com", "again"]
        );
        assert_eq!(t.manifest.links[1].text_samples, vec!["https://bank.test/"]);
        let reasons: Vec<_> = t
            .manifest
            .hidden
            .iter()
            .map(|h| (h.reason, h.chars))
            .collect();
        assert!(reasons.contains(&(text::Hidden::DisplayNone as i32, 6)));
        assert!(reasons.contains(&(text::Hidden::BidiControl as i32, 1)));
    }

    #[test]
    fn sanitize_maps_cid_and_remote_images_to_resource_ids() {
        let cid = sanitize::cid_resource_id(b"logo@x");
        let s = sanitize(
            "<img src='cid:logo@x'><img src='cid:other@x'>\
             <img src='https://img.test/a.png' width='40' height='20'><img src='ftp://x/y'>\
             <script>alert(1)</script><a href='https://example.com/'>go</a>",
            Theme::Light,
            vec![cid.clone()],
        );
        assert!(s.document.contains(&format!("resource://{cid}/")));
        assert!(s.document.contains("resource://img-0/"));
        assert!(!s.document.contains("img.test"));
        assert!(!s.document.contains("other@x"));
        assert!(!s.document.contains("alert"));
        assert_eq!(s.manifest.resource_ids_used, vec![cid]);
        assert_eq!(s.manifest.remote_images.len(), 1);
        let r = &s.manifest.remote_images[0];
        assert_eq!(
            (r.id.as_str(), r.url.as_str(), r.width, r.height),
            ("img-0", "https://img.test/a.png", 40, 20)
        );
        // ftp: never reaches the image filter (ammonia drops non-allowlisted schemes first).
        assert!(!s.document.contains("ftp:"));
        assert_eq!(s.manifest.remote_images_dropped, 0);
        assert_eq!(s.manifest.links.len(), 1);
        assert!(sanitize::valid_resource_id(
            &s.manifest.resource_ids_used[0]
        ));
    }

    #[test]
    fn dark_strict_differs_from_v1_only_by_policy() {
        let html = "<table><tr><td bgcolor='#ff8800' style='color:#ffffff'>Buy</td></tr></table><p>text</p>";
        let light = sanitize(html, Theme::Light, vec![]).document;
        let dark = sanitize(html, Theme::DarkV1, vec![]).document;
        let strict = sanitize(html, Theme::DarkStrict, vec![]).document;
        assert_ne!(light, dark);
        assert_ne!(dark, strict);
        assert_eq!(
            sanitize(html, Theme::DarkV1, vec![]).document,
            dark,
            "strict must not leak"
        );
    }

    #[test]
    fn cid_id_is_stable() {
        // Pinned: callers compute the same value.
        assert_eq!(sanitize::cid_resource_id(b""), "cid-cbf29ce484222325");
        assert_eq!(sanitize::cid_resource_id(b"a"), "cid-af63dc4c8601ec8c");
    }
}
