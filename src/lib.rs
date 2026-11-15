//! HTML email sanitizer: one HTML part in, either a sanitized document (ammonia allowlist,
//! lightningcss reprint, optional dark-mode transform) or a plain-text fallback, each with a
//! [`Manifest`] of the links, hidden text and image references found.
//!
//! - [`sanitize`]: allowlist sanitizing; image sources become opaque `<scheme>://<id>/`
//!   references the caller resolves; [`Theme::Dark`] applies dark policy v1.
//! - [`text`]: an isolated HTML-to-text converter (html5ever tokenizer only; it shares none of the
//!   sanitize pipeline), for when sanitizing or rendering has failed.
//!
//! Both are pure functions of their input, bounded in output size, and keep per-call state per
//! thread, so documents may be processed concurrently on different threads.

mod color;
mod css;
mod dom;
mod image;
mod sanitize;
mod text;

pub use sanitize::{
    MAX_CID_IDS, MAX_REMOTE_IMAGES, MAX_RESOURCE_ID, cid_resource_id, valid_resource_id,
};
pub use text::{Hidden, MAX_LINKS, MAX_URL, TEXT_CAP};

/// Caller-chosen strings that end up in the output.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    /// URL scheme of rewritten image references, `<scheme>://<id>/`: `[a-z][a-z0-9+.-]*`.
    pub resource_scheme: &'a str,
    /// Line appended to the text when it was cut at [`TEXT_CAP`].
    pub truncated_mark: &'a str,
}

impl Default for Config<'static> {
    fn default() -> Self {
        Config {
            resource_scheme: "mail-resource",
            truncated_mark: "[The text of this message was truncated]",
        }
    }
}

fn valid_scheme(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'.' | b'-')
        })
}

/// Colour treatment of the sanitized document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    /// The sender's colours.
    Light,
    /// Dark policy v1: backgrounds darkened, text and borders re-coloured to reach contrast
    /// targets; brand fills and sender-dark surfaces kept.
    Dark,
    /// Dark policy v1 that also re-colours sender text on preserved fills (WCAG AA).
    DarkStrict,
}

/// One listed link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLink {
    /// 1-based, the number shown in the text fallback's link list.
    pub index: u32,
    /// http, https or mailto; printable ASCII, at most [`MAX_URL`] bytes.
    pub href: String,
    /// Visible link texts, at most 4, each at most 256 characters.
    pub text_samples: Vec<String>,
}

/// Characters hidden from the reader for one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiddenCount {
    pub reason: Hidden,
    pub chars: u32,
}

/// A blocked remote image and the placeholder id it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteImage {
    /// `img-N`, valid per [`valid_resource_id`].
    pub id: String,
    /// Canonical http(s) URL, at most [`MAX_URL`] bytes.
    pub url: String,
    /// Size hints from the `width`/`height` attributes, 0 when absent.
    pub width: u32,
    pub height: u32,
}

/// What a document contains besides its text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// At most [`MAX_LINKS`], document order.
    pub links: Vec<ManifestLink>,
    /// One entry per reason with a non-zero count, in [`Hidden`] order.
    pub hidden: Vec<HiddenCount>,
    /// The listed CID resource ids the document references (at most [`MAX_CID_IDS`]).
    pub resource_ids_used: Vec<String>,
    /// At most [`MAX_REMOTE_IMAGES`].
    pub remote_images: Vec<RemoteImage>,
    /// Remote images over the cap.
    pub remote_images_dropped: u32,
}

/// Sanitized document plus its manifest.
pub struct Sanitized {
    pub manifest: Manifest,
    pub document: String,
}

/// Text fallback plus its manifest (links and hidden counts) and stats.
pub struct Text {
    pub manifest: Manifest,
    pub text: String,
    pub hidden_chars: u32,
    pub dropped_elements: u32,
}

fn links_and_hidden(t: &text::TextOut) -> Manifest {
    Manifest {
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
            .map(|&(reason, chars)| HiddenCount { reason, chars })
            .collect(),
        ..Manifest::default()
    }
}

/// Sanitizes one HTML part. `cid_ids` are the resource ids ([`cid_resource_id`]) of the CID parts
/// the caller can supply; other `cid:` references are dropped. The manifest's links and hidden
/// counts come from the text converter run over the sanitized (pre-dark) document, i.e. what the
/// rendered message shows.
///
/// # Panics
/// If `config.resource_scheme` is not `[a-z][a-z0-9+.-]*`.
pub fn sanitize(input: &str, theme: Theme, cid_ids: Vec<String>, config: &Config) -> Sanitized {
    assert!(
        valid_scheme(config.resource_scheme),
        "invalid resource scheme"
    );
    sanitize::begin(config.resource_scheme, cid_ids);
    let sanitized = sanitize::sanitize(input);
    let res = sanitize::finish();
    let mut manifest = links_and_hidden(&text::html_to_text(&sanitized, config.truncated_mark));
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
        Theme::Dark | Theme::DarkStrict => {
            color::STRICT.with(|s| s.set(theme == Theme::DarkStrict));
            let html = dom::process(&sanitized, css::Mode::Transform).html;
            color::STRICT.with(|s| s.set(false));
            html
        }
        Theme::Light => sanitized,
    };
    Sanitized { manifest, document }
}

/// The plain-text fallback of one HTML part (invalid UTF-8 already replaced by the caller).
pub fn text(input: &str, config: &Config) -> Text {
    let t = text::html_to_text(input, config.truncated_mark);
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
            &Config::default(),
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
        assert!(reasons.contains(&(Hidden::DisplayNone, 6)));
        assert!(reasons.contains(&(Hidden::BidiControl, 1)));
    }

    #[test]
    fn sanitize_maps_cid_and_remote_images_to_resource_ids() {
        let cid = cid_resource_id(b"logo@x");
        let s = sanitize(
            "<img src='cid:logo@x'><img src='cid:other@x'>\
             <img src='https://img.test/a.png' width='40' height='20'><img src='ftp://x/y'>\
             <script>alert(1)</script><a href='https://example.com/'>go</a>",
            Theme::Light,
            vec![cid.clone()],
            &Config::default(),
        );
        assert!(s.document.contains(&format!("mail-resource://{cid}/")));
        assert!(s.document.contains("mail-resource://img-0/"));
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
        assert!(valid_resource_id(&s.manifest.resource_ids_used[0]));
    }

    #[test]
    fn dark_strict_differs_from_v1_only_by_policy() {
        let html = "<table><tr><td bgcolor='#ff8800' style='color:#ffffff'>Buy</td></tr></table><p>text</p>";
        let light = sanitize(html, Theme::Light, vec![], &Config::default()).document;
        let dark = sanitize(html, Theme::Dark, vec![], &Config::default()).document;
        let strict = sanitize(html, Theme::DarkStrict, vec![], &Config::default()).document;
        assert_ne!(light, dark);
        assert_ne!(dark, strict);
        assert_eq!(
            sanitize(html, Theme::Dark, vec![], &Config::default()).document,
            dark,
            "strict must not leak"
        );
    }

    #[test]
    fn cid_id_is_stable() {
        // Pinned: callers compute the same value, so it never changes.
        assert_eq!(cid_resource_id(b""), "cid-cbf29ce484222325");
        assert_eq!(cid_resource_id(b"a"), "cid-af63dc4c8601ec8c");
    }

    #[test]
    fn caller_strings_reach_the_output() {
        let cfg = Config {
            resource_scheme: "x-res",
            truncated_mark: "[cut]",
        };
        let s = sanitize(
            "<img src='https://img.test/a.png' width='5'>",
            Theme::Light,
            vec![],
            &cfg,
        );
        assert!(s.document.contains("x-res://img-0/"));
        assert_eq!(s.manifest.remote_images[0].width, 5);
        let t = text(&format!("<p>{}</p>", "a ".repeat(TEXT_CAP)), &cfg);
        assert!(t.text.trim_end().ends_with("[cut]"));
    }

    #[test]
    #[should_panic(expected = "invalid resource scheme")]
    fn rejects_an_invalid_scheme() {
        let cfg = Config {
            resource_scheme: "x\"",
            ..Config::default()
        };
        sanitize("<p>a</p>", Theme::Light, vec![], &cfg);
    }

    #[test]
    fn strict_policy_stays_on_its_thread() {
        let html = "<table><tr><td bgcolor='#ff8800' style='color:#ffffff'>Buy</td></tr></table>";
        let dark = sanitize(html, Theme::Dark, vec![], &Config::default()).document;
        color::STRICT.with(|s| s.set(true));
        let other = std::thread::spawn(move || {
            sanitize(html, Theme::Dark, vec![], &Config::default()).document
        })
        .join()
        .expect("thread");
        color::STRICT.with(|s| s.set(false));
        assert_eq!(other, dark);
    }
}
