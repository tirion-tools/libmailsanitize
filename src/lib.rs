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
mod roundtrip;
mod sanitize;
mod text;

pub use sanitize::{
    MAX_CID_IDS, MAX_INLINE_BYTES, MAX_INLINE_IMAGES, MAX_REMOTE_IMAGES, MAX_RESOURCE_ID,
    OFF_RESOURCE_ID, cid_resource_id, valid_resource_id,
};
pub use text::{Hidden, MAX_LINKS, MAX_SAMPLE_CHARS, MAX_URL, TEXT_CAP, valid_link_sample};

/// What the sanitized document does with images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Images {
    /// CID, inline and remote images become resource references listed in the manifest.
    #[default]
    Resources,
    /// Every `<img>` source becomes `<scheme>://`[`OFF_RESOURCE_ID`]`/` (the caller's placeholder),
    /// CSS images are dropped, and the manifest lists no image: nothing of the sender's image
    /// bytes is decoded here or handed on.
    Off,
}

/// Caller choices: strings that end up in the output, and the image policy.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    /// URL scheme of rewritten image references, `<scheme>://<id>/`: `[a-z][a-z0-9+.-]*`.
    pub resource_scheme: &'a str,
    /// Line appended to the text when it was cut at [`TEXT_CAP`].
    pub truncated_mark: &'a str,
    pub images: Images,
}

impl Default for Config<'static> {
    fn default() -> Self {
        Config {
            resource_scheme: "mail-resource",
            truncated_mark: "[The text of this message was truncated]",
            images: Images::Resources,
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
    /// Visible link texts, at most 4: each as the reader sees it, on one line with whitespace
    /// collapsed and the text's character policy applied (no controls, bidi controls or invisible
    /// characters), at most [`MAX_SAMPLE_CHARS`] characters ([`valid_link_sample`]).
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

/// An inline (`data:`) image: its bytes are the sender's, undecoded; the caller supplies them under
/// `id` (after whatever validation or transcoding it applies) or shows a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineImage {
    /// `dat-N`, valid per [`valid_resource_id`].
    pub id: String,
    /// Declared PNG or JPEG, base64-decoded; never empty.
    pub data: Vec<u8>,
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
    /// At most [`MAX_INLINE_IMAGES`], together at most [`MAX_INLINE_BYTES`]; identical bytes share
    /// one entry.
    pub inline_images: Vec<InlineImage>,
    /// Inline images over the caps, undecodable, or of another type.
    pub inline_images_dropped: u32,
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
/// The finished document is parsed again and must hold exactly the allowlisted elements in the
/// sanitizer's frame, with no `</` in a `<style>` text. Otherwise it fails closed: the document is
/// the [`text`] fallback, escaped, its `<body>` marked `data-gx-fallback="text"`, and the manifest
/// is the fallback's (no images).
///
/// # Panics
/// If `config.resource_scheme` is not `[a-z][a-z0-9+.-]*`.
pub fn sanitize(input: &str, theme: Theme, cid_ids: Vec<String>, config: &Config) -> Sanitized {
    assert!(
        valid_scheme(config.resource_scheme),
        "invalid resource scheme"
    );
    sanitize::begin(
        config.resource_scheme,
        cid_ids,
        config.images == Images::Off,
    );
    let (sanitized, elements) = sanitize::sanitize(input);
    let mut manifest = links_and_hidden(&text::html_to_text(&sanitized, config.truncated_mark));
    // The dark pass reads the inline images (transparent-PNG backdrops) before `finish`.
    let document = themed(sanitized, theme);
    let res = sanitize::finish();
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
    manifest.inline_images = res
        .inline
        .into_iter()
        .map(|(id, data)| InlineImage { id, data })
        .collect();
    manifest.inline_images_dropped = res.inline_dropped;
    if roundtrip::holds(&elements, &document) {
        Sanitized { manifest, document }
    } else {
        failed_closed(input, theme, config)
    }
}

/// What [`sanitize`] returns for a document that fails the output check.
fn failed_closed(input: &str, theme: Theme, config: &Config) -> Sanitized {
    let t = text::html_to_text(input, config.truncated_mark);
    Sanitized {
        manifest: links_and_hidden(&t),
        document: themed(sanitize::text_document(&t.text), theme),
    }
}

fn themed(sanitized: String, theme: Theme) -> String {
    match theme {
        Theme::Dark | Theme::DarkStrict => {
            color::STRICT.with(|s| s.set(theme == Theme::DarkStrict));
            let html = dom::process(&sanitized, css::Mode::Transform).html;
            color::STRICT.with(|s| s.set(false));
            html
        }
        Theme::Light => sanitized,
    }
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

    const THEMES: [Theme; 3] = [Theme::Light, Theme::Dark, Theme::DarkStrict];

    /// CSS escapes that lightningcss decodes: printed as is, `</style>` would end the element and
    /// the rest would be markup the allowlist never saw (fuzz finding of 2026-11-17).
    #[test]
    fn css_escapes_cannot_close_a_style_element() {
        for html in [
            r#"<style>a{font-family:"\3c/style\3e\3cscript\3e alert(1)\3c/script\3e"}</style><p>x</p>"#,
            r#"<style>a{font-family:"\3c/style\3e\3ciframe src=https://e.test/\3e\3cmeta http-equiv=refresh content=0;url=https://e.test/\3e\3cimg src=https://e.test/t.png\3e\3c a href=https://e.test/\3e x\3c/a\3e"}</style><p>x</p>"#,
            r#"<style>a{background:url(data:image/png;base64,\3c/style\3e\3cscript\3ealert\28 1\29\3c/script\3e)}</style><p>x</p>"#,
            r#"<style>a[title="\3c/style\3e\3cscript\3e"]{color:red}</style><p>x</p>"#,
            r#"<style>a{--x:"\3c/style\3e\3cscript\3e"}</style><p>x</p>"#,
            r#"<style>a{x:\3c/style\3e\3cscript\3e}</style><p>x</p>"#,
            r#"<style>@media (max-width:600px){a{font-family:"\3c/style\3e\3cscript\3e"}}</style><p>x</p>"#,
            r"<style>.a\3c script{color:red}</style><p>x</p>",
            r#"<p style='font-family:"\3c/style\3e\3cscript\3e"'>x</p>"#,
        ] {
            for theme in THEMES {
                let d = sanitize(html, theme, vec![], &Config::default()).document;
                let lower = d.to_ascii_lowercase();
                for bad in ["<script", "<iframe", "<meta http-equiv", "<img", "<a "] {
                    assert!(!lower.contains(bad), "{theme:?} {html}: {bad} in {d}");
                }
                assert_eq!(
                    lower.matches("</style").count(),
                    lower.matches("<style").count(),
                    "{theme:?} {html}: {d}"
                );
                assert!(!d.contains("data-gx-fallback"), "{theme:?} {html}: {d}");
                assert!(d.ends_with(">x</p></body></html>"), "{theme:?} {html}: {d}");
            }
        }
    }

    #[test]
    fn schemes_are_read_as_the_browser_reads_them() {
        let d = sanitize(
            "<a href='\u{1}data:text/html,x'>a</a><a href=' \tdata:text/html,x'>b</a>\
             <img src='\u{1}data:image/svg+xml,x'><a href='\u{1}https://e.test/'>c</a>",
            Theme::Light,
            vec![],
            &Config::default(),
        )
        .document;
        assert!(!d.contains("data:"), "{d}");
        assert!(d.contains("https://e.test/"), "{d}");
    }

    #[test]
    fn media_ranges_survive_the_escaping() {
        let html = "<style>@media (max-width:600px){b{color:red}}@media (400px<width<700px){i{color:red}}</style>";
        for theme in THEMES {
            let d = sanitize(html, theme, vec![], &Config::default()).document;
            assert!(d.contains("@media (width<=600px)"), "{d}");
            assert!(d.contains("@media (400px< width<700px)"), "{d}");
        }
    }

    #[test]
    fn failing_the_check_gives_the_text_in_the_frame() {
        let html = "<p>Hi &amp; <b>there</b> <a href='https://e.test/'>e.test</a></p><script>alert(1)</script><p>&lt;script&gt;</p>";
        for theme in THEMES {
            let s = failed_closed(html, theme, &Config::default());
            assert!(
                s.document.contains(" data-gx-fallback=\"text\""),
                "{}",
                s.document
            );
            assert!(s.document.contains("Hi &amp; there"), "{}", s.document);
            assert!(s.document.contains("&lt;script&gt;"), "{}", s.document);
            assert!(!s.document.to_ascii_lowercase().contains("<script"));
            assert!(!s.document.contains("<a "));
            assert!(
                roundtrip::holds(
                    &roundtrip::expected("<div style=\"white-space:pre-wrap\">x</div>"),
                    &s.document
                ),
                "{}",
                s.document
            );
            assert_eq!(s.manifest.links.len(), 1);
            assert_eq!(s.manifest.links[0].href, "https://e.test/");
            assert!(s.manifest.remote_images.is_empty());
        }
    }

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

    /// The renderer reports a click in its WHATWG form; the manifest must list that same form, or
    /// the caller cannot find the link text for the click-time check (Graphein F1, 2026-11-20).
    #[test]
    fn kept_hrefs_are_the_urls_a_click_reports() {
        let s = sanitize(
            "<a href='https://evil.example/x/../login'>www.mybank-portal.example</a>\
             <a href='HTTPS://Evil.Example:443/a/%2e%2E/b?q=a b#f'>two</a>\
             <a href='http:\\\\evil.example\\c\\.\\d'>three</a>\
             <a href='https://[x/'>broken</a>",
            Theme::Light,
            vec![],
            &Config::default(),
        );
        let d = &s.document;
        assert!(d.contains("href=\"https://evil.example/login\""), "{d}");
        assert!(
            d.contains("href=\"https://evil.example/b?q=a%20b#f\""),
            "{d}"
        );
        assert!(d.contains("href=\"http://evil.example/c/d\""), "{d}");
        assert!(!d.contains(".."), "{d}");
        assert!(!d.contains("[x"), "{d}");
        let hrefs: Vec<_> = s.manifest.links.iter().map(|l| l.href.as_str()).collect();
        assert_eq!(
            hrefs,
            [
                "https://evil.example/login",
                "https://evil.example/b?q=a%20b#f",
                "http://evil.example/c/d"
            ]
        );
        assert_eq!(
            s.manifest.links[0].text_samples,
            vec!["www.mybank-portal.example"]
        );
    }

    /// A link the manifest cannot list (over MAX_URL, or beyond MAX_LINKS distinct links) is
    /// inert, not clickable but unlisted (Graphein F1 variants A and B).
    #[test]
    fn links_the_manifest_cannot_list_are_inert() {
        let long = format!(
            "<a href='https://evil.example/login?{}'>www.mybank-portal.example</a>",
            "a".repeat(MAX_URL)
        );
        let s = sanitize(&long, Theme::Light, vec![], &Config::default());
        assert!(!s.document.contains("href"), "{}", s.document);
        assert!(s.manifest.links.is_empty());

        let mut html: String = (0..MAX_LINKS)
            .map(|i| format!("<a href='https://pad.example/{i}'>pad {i}</a> "))
            .collect();
        html.push_str("<a href='https://pad.example/0'>again</a>");
        html.push_str("<a href='https://evil.example/login'>www.paypal.com</a>");
        html.push_str("<a href='mailto:x@evil.example'>mail</a>");
        for theme in THEMES {
            let s = sanitize(&html, theme, vec![], &Config::default());
            assert!(!s.document.contains("evil.example"), "{theme:?}");
            assert_eq!(
                s.document.matches("href=\"https://pad.example/0\"").count(),
                2
            );
            assert!(s.document.contains("www.paypal.com"));
            assert_eq!(s.manifest.links.len(), MAX_LINKS);
            assert_eq!(s.manifest.links[0].text_samples, vec!["pad 0", "again"]);
            assert!(
                s.manifest
                    .links
                    .iter()
                    .all(|l| l.href.starts_with("https://pad.example/"))
            );
        }
    }

    /// Image sources the URL check never saw (Graphein security review 2026-11-20 F2): strings in
    /// `image-set()` (lightningcss keeps them as tokens, and its visitor skips image-set images),
    /// carried through custom properties and `var()`, reached a printed document's image decoders.
    #[test]
    fn css_image_sources_the_url_check_cannot_see_are_dropped() {
        let webp = "data:image/webp;base64,UklGRg==";
        let png = format!("data:image/png;base64,{PNG_B64}");
        for css in [
            format!("background-image:image-set(\"{webp}\" 1x)"),
            format!("background-image:-webkit-image-set(\"{webp}\" 1x)"),
            format!("background-image:image-set(url({webp}) 1x)"),
            format!("background-image:image-set(\"{png}\" 1x)"),
            format!("background-image:var(--x,image-set(\"{webp}\" 1x))"),
            format!("background:#fff var(--x,url({webp}))"),
            format!("--a:image-set(\"{webp}\" 1x)"),
            format!("--a:\"{webp}\""),
            "--a:red".to_string(),
            "background-image:var(--a)".to_string(),
            "color:env(--a)".to_string(),
            format!("background:cross-fade(url(a.png),image-set(\"{webp}\" 1x),50%)"),
            format!("list-style-image:-webkit-image-set(\"{webp}\" 1x)"),
            format!("border-image-source:image-set(\"{webp}\" 1x)"),
            format!("x-unknown:\"{webp}\""),
            "mask-image:element(#a)".to_string(),
        ] {
            for html in [
                format!("<p style='{css}'>x</p>"),
                format!("<style>p{{{css}}}</style><p>x</p>"),
                format!("<style>@media screen{{p{{{css}}}}}</style><p>x</p>"),
            ] {
                for images in [Images::Resources, Images::Off] {
                    let cfg = Config {
                        images,
                        ..Config::default()
                    };
                    let d = sanitize(&html, Theme::Light, vec![], &cfg).document;
                    for bad in [
                        "data:",
                        "image-set",
                        "cross-fade",
                        "element(",
                        "var(",
                        "env(",
                        "--a",
                        "UklGR",
                    ] {
                        assert!(!d.contains(bad), "{html}: {bad} in {d}");
                    }
                    assert!(d.ends_with(">x</p></body></html>"), "{html}: {d}");
                }
            }
        }
        // What the URL check does see stays as it was.
        let s = sanitize(
            &format!(
                "<p style='color:red;font-family:\"Arial\";background:url({png})'>x</p>\
                 <p style='background-image:linear-gradient(red,blue)'>y</p>"
            ),
            Theme::Light,
            vec![],
            &Config::default(),
        );
        assert!(s.document.contains("color:red"), "{}", s.document);
        assert!(s.document.contains("Arial"), "{}", s.document);
        assert!(
            s.document.contains("mail-resource://dat-0/"),
            "{}",
            s.document
        );
        assert!(s.document.contains("linear-gradient"), "{}", s.document);
    }

    // 1x1 transparent PNG.
    const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNgAAIAAAUAAen63NgAAAAASUVORK5CYII=";

    fn png_bytes() -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(PNG_B64)
            .expect("b64")
    }

    #[test]
    fn inline_images_become_resources_and_never_stay_in_the_document() {
        let html = format!(
            "<img src='data:image/png;base64,{PNG_B64}'>\
             <img src=' DATA:image/PNG;base64,{} '>\
             <div style=\"background-image:url('data:image/png;base64,{PNG_B64}')\">x</div>\
             <style>td{{background:url(data:image/jpeg;base64,/9j/4AAQ)}}</style>\
             <img src='data:image/svg+xml;base64,PHN2Zz4='><img src='data:image/png;base64,!!!'>",
            PNG_B64[..20].to_string() + "\n" + &PNG_B64[20..]
        );
        for theme in [Theme::Light, Theme::Dark, Theme::DarkStrict] {
            let s = sanitize(&html, theme, vec![], &Config::default());
            assert!(!s.document.contains("base64"), "{theme:?}: {}", s.document);
            assert!(!s.document.contains("data:"), "{theme:?}");
            assert_eq!(
                s.document.matches("mail-resource://dat-0/").count(),
                3,
                "{}",
                s.document
            );
            assert!(
                s.document.contains("mail-resource://dat-1/"),
                "{}",
                s.document
            );
            let m = &s.manifest;
            assert_eq!(m.inline_images.len(), 2);
            assert_eq!(m.inline_images[0].id, "dat-0");
            assert_eq!(m.inline_images[0].data, png_bytes());
            assert_eq!(
                m.inline_images[1].data,
                [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]
            );
            assert_eq!(m.inline_images_dropped, 2, "svg and undecodable");
            assert!(m.inline_images.iter().all(|i| valid_resource_id(&i.id)));
        }
    }

    #[test]
    fn inline_images_are_capped() {
        use base64::Engine;
        let mut html = String::new();
        for i in 0..=MAX_INLINE_IMAGES {
            let b = base64::engine::general_purpose::STANDARD.encode([0x89, b'P', i as u8]);
            html.push_str(&format!("<img src='data:image/png;base64,{b}'>"));
        }
        let big = base64::engine::general_purpose::STANDARD.encode(vec![7u8; MAX_INLINE_BYTES]);
        html.push_str(&format!("<img src='data:image/jpeg;base64,{big}'>"));
        let s = sanitize(&html, Theme::Light, vec![], &Config::default());
        assert_eq!(s.manifest.inline_images.len(), MAX_INLINE_IMAGES);
        assert_eq!(s.manifest.inline_images_dropped, 2);
        assert!(!s.document.contains(&format!("dat-{MAX_INLINE_IMAGES}/")));
    }

    #[test]
    fn images_off_maps_every_image_to_the_placeholder() {
        let cid = cid_resource_id(b"logo@x");
        let cfg = Config {
            images: Images::Off,
            ..Config::default()
        };
        let html = format!(
            "<img src='cid:logo@x' width='40' alt='Logo'><img src='https://img.test/a.png'>\
             <img src='data:image/png;base64,{PNG_B64}'>\
             <p style=\"color:red;background:url('data:image/png;base64,{PNG_B64}')\">t</p>\
             <style>p{{background-image:url(data:image/png;base64,{PNG_B64});color:blue}}</style>"
        );
        for theme in [Theme::Light, Theme::Dark] {
            let s = sanitize(&html, theme, vec![cid.clone()], &cfg);
            assert_eq!(
                s.document.matches("mail-resource://off/").count(),
                3,
                "{}",
                s.document
            );
            assert!(!s.document.contains("base64") && !s.document.contains("img.test"));
            assert!(!s.document.contains(&cid));
            assert!(s.document.contains("width=\"40\"") && s.document.contains("Logo"));
            let m = &s.manifest;
            assert!(m.resource_ids_used.is_empty() && m.remote_images.is_empty());
            assert!(m.inline_images.is_empty());
            assert_eq!(m.remote_images_dropped + m.inline_images_dropped, 0);
        }
    }

    #[test]
    fn dark_backdrop_still_reads_inline_pngs() {
        // Dark text-coloured transparent PNG: gets a backdrop in dark mode (dom.rs image rule).
        let mut img = Vec::new();
        {
            let mut e = png::Encoder::new(&mut img, 8, 8);
            e.set_color(png::ColorType::Rgba);
            e.set_depth(png::BitDepth::Eight);
            let mut w = e.write_header().expect("header");
            let mut px = vec![0u8; 8 * 8 * 4];
            for (i, p) in px.chunks_exact_mut(4).enumerate() {
                p[3] = if i % 2 == 0 { 255 } else { 0 };
            }
            w.write_image_data(&px).expect("data");
        }
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode(&img);
        let html = format!("<img src='data:image/png;base64,{b}'>");
        let d = sanitize(&html, Theme::Dark, vec![], &Config::default());
        assert!(d.document.contains("background-color:"), "{}", d.document);
        assert_eq!(d.manifest.inline_images[0].data, img);
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
            ..Config::default()
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

    /// Newsletter link text laid out over several source lines (indentation, `<br>`, tabs, padding
    /// characters, a bidi control): every sample is the one-line text the reader sees, which a
    /// consumer re-checking the contract accepts (Graphein refused the whole manifest of such
    /// messages: "Couldn't read this message").
    #[test]
    fn link_samples_are_one_line_of_visible_text() {
        let html = "<table><tr><td>\n  <a href='https://shop.example/offer'>\n    Learn\n    more\n  </a>\n\
                    <a href='https://shop.example/help'>Help&nbsp;centre<br>\t1-800-555-0100</a>\n\
                    <a href='https://shop.example/x'>&#x202e;Pay&#8203;&shy;&#847; now&#x2028;</a>\n\
                    <a href='https://shop.example/y'><img alt=' Shop\n logo ' src='https://img.test/l.png'> \n</a>\n\
                    </td></tr></table>";
        let want = [
            vec!["Learn more"],
            vec!["Help centre 1-800-555-0100"],
            vec!["Pay now"],
            vec!["Shop logo"],
        ];
        let t = text(html, &Config::default());
        let s = sanitize(html, Theme::Light, vec![], &Config::default());
        for m in [&t.manifest, &s.manifest] {
            let got: Vec<_> = m.links.iter().map(|l| l.text_samples.clone()).collect();
            assert_eq!(got, want);
            assert!(
                m.links
                    .iter()
                    .flat_map(|l| &l.text_samples)
                    .all(|x| valid_link_sample(x))
            );
        }
        // "abc abc …": the 256th character is a space, so the sample ends at 255 on "abc".
        let long = format!(
            "<a href='https://shop.example/'>{}</a>",
            "abc\n".repeat(400)
        );
        let l = &text(&long, &Config::default()).manifest.links[0].text_samples[0];
        assert_eq!(l.chars().count(), MAX_SAMPLE_CHARS - 1);
        assert!(l.ends_with("abc") && valid_link_sample(l));
        for bad in [
            "a\nb",
            "a\tb",
            " a",
            "a ",
            "a\u{a0}b",
            "\u{202e}a",
            "a\u{200b}",
            "a\u{7}",
        ] {
            assert!(!valid_link_sample(bad), "{bad:?}");
        }
    }
}
