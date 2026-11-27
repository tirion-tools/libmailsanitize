//! The sanitizer on arbitrary bytes: the text fallback on the lossy decoding of every input, and
//! sanitize under the theme picked by the first byte for valid UTF-8. Asserts the output
//! contract: the manifest bounds and its link text samples (`valid_link_sample`), no forbidden
//! characters in the fallback text, and a sanitized
//! document with no `<script` anywhere in its text that, parsed again with html5ever (its own
//! tree, not the library's), holds no active content:
//! - no `</` in a `<style>` text (nothing can end the element early);
//! - no script, frame, plugin, form, `<base>`, `<link>`, `<template>`, SVG or MathML element, and
//!   one `<meta>`, the frame's `charset` (no `http-equiv`);
//! - no `on*` attribute, no `javascript:`, `vbscript:` or `data:` URL (inline images leave as
//!   `dat-N` resources);
//! - in every `<style>` text and `style` attribute, outside CSS strings and comments: every
//!   `url(` names a `mail-resource://` reference, and no image function the URL check cannot
//!   see (`image-set`, `cross-fade`, `element`, `paint`, `-webkit-canvas`), no `var()`/`env()`
//!   and no custom property (Graphein security review 2026-11-20 F2);
//! - the sanitizer's own output check held (no `data-gx-fallback` on `<body>`).
#![no_main]

use html5ever::tendril::TendrilSink;
use html5ever::{ParseOpts, local_name, ns, parse_document};
use libfuzzer_sys::fuzz_target;
use mailsanitize::{Config, Manifest, Theme};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

fn check_manifest(m: &Manifest) {
    assert!(m.links.len() <= mailsanitize::MAX_LINKS);
    for (i, l) in m.links.iter().enumerate() {
        assert_eq!(l.index as usize, i + 1);
        assert!(
            l.href.len() <= mailsanitize::MAX_URL
                && l.href.bytes().all(|b| (0x21..=0x7e).contains(&b))
        );
        assert!(l.text_samples.len() <= 4);
        assert!(
            l.text_samples
                .iter()
                .all(|s| mailsanitize::valid_link_sample(s))
        );
    }
    assert!(m.resource_ids_used.len() <= mailsanitize::MAX_CID_IDS);
    assert!(m.remote_images.len() <= mailsanitize::MAX_REMOTE_IMAGES);
    for r in &m.remote_images {
        assert!(mailsanitize::valid_resource_id(&r.id));
        assert!(r.url.len() <= mailsanitize::MAX_URL && r.url.starts_with("http"));
    }
}

const FORBIDDEN: &[&str] = &[
    "applet",
    "audio",
    "base",
    "button",
    "canvas",
    "dialog",
    "embed",
    "form",
    "frame",
    "frameset",
    "iframe",
    "input",
    "link",
    "math",
    "noembed",
    "noframes",
    "noscript",
    "object",
    "option",
    "param",
    "picture",
    "plaintext",
    "portal",
    "script",
    "select",
    "source",
    "svg",
    "template",
    "textarea",
    "title",
    "track",
    "video",
    "xmp",
];

const URL_ATTRIBUTES: &[&str] = &[
    "action",
    "background",
    "cite",
    "codebase",
    "data",
    "dynsrc",
    "formaction",
    "href",
    "icon",
    "longdesc",
    "lowsrc",
    "manifest",
    "ping",
    "poster",
    "src",
    "srcset",
    "usemap",
];

/// A URL attribute as the browser's URL parser reads its scheme: tabs and newlines removed,
/// leading and trailing C0 controls and spaces trimmed, lowercase.
fn url_start(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect::<String>()
        .trim_matches(|c: char| c <= ' ')
        .to_ascii_lowercase()
}

/// Every node of the document, template contents included, without recursion.
fn nodes(root: &Handle) -> Vec<Handle> {
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(n) = stack.pop() {
        stack.extend(n.children.borrow().iter().rev().cloned());
        if let NodeData::Element {
            template_contents, ..
        } = &n.data
            && let Some(t) = template_contents.borrow().as_ref()
        {
            stack.push(t.clone());
        }
        out.push(n);
    }
    out
}

/// A CSS identifier code point (`\` escapes aside).
fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || !c.is_ascii()
}

/// CSS text, lowercase, without its comments (lightningcss keeps `/*! … */`), and with the
/// contents of its strings removed (quotes kept), except a string that is a `url(` argument.
fn outside_strings(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut quote = None;
    let mut keep = false;
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quote) {
            ('\\', _) => {
                let n = chars.next();
                if quote.is_none() || keep {
                    out.push(c);
                    out.extend(n.map(|n| n.to_ascii_lowercase()));
                }
            }
            ('/', None) if chars.peek() == Some(&'*') => {
                chars.next();
                let mut star = false;
                for n in chars.by_ref() {
                    if star && n == '/' {
                        break;
                    }
                    star = n == '*';
                }
                out.push(' ');
            }
            ('"' | '\'', None) => {
                let t = out.trim_end();
                keep = t.ends_with("url(")
                    && !t[..t.len() - 4].chars().next_back().is_some_and(ident_char);
                quote = Some(c);
                out.push(c);
            }
            (_, Some(q)) if c == q => {
                quote = None;
                out.push(c);
            }
            (_, Some(_)) if !keep => {}
            _ => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// The identifiers of CSS text (as `outside_strings` leaves it) that are followed by `(`, with
/// the byte offset after the `(`: function names, matched whole, so a longer identifier that
/// merely contains `url` or `-webkit-canvas` (`\u{fffd}url(`, a browser's function of that name)
/// is not one of them.
fn functions(t: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    let mut escaped = false;
    for (i, c) in t.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            start.get_or_insert(i);
        } else if ident_char(c) {
            start.get_or_insert(i);
        } else {
            if let (Some(s), '(') = (start, c) {
                out.push((&t[s..i], i + 1));
            }
            start = None;
        }
    }
    out
}

/// Printed CSS loads no image but the document's own resources.
fn check_css(css: &str, sheet: bool) {
    let t = outside_strings(css);
    let calls = functions(&t);
    for (name, _) in &calls {
        assert!(
            ![
                "image-set",
                "-webkit-image-set",
                "cross-fade",
                "-webkit-cross-fade",
                "element",
                "-moz-element",
                "paint",
                "-webkit-canvas",
                "var",
                "env",
            ]
            .contains(name),
            "{name}() in CSS: {css}"
        );
    }
    // A custom property: `--` starting a declaration (a selector may be an identifier `--x`).
    let mut blocks = vec![!sheet];
    let mut prelude = 0;
    for (i, c) in t.char_indices() {
        match c {
            '{' => {
                blocks.push(!t[prelude..i].trim_start().starts_with('@'));
                prelude = i + 1;
            }
            '}' => {
                blocks.pop();
                prelude = i + 1;
            }
            ';' => prelude = i + 1,
            '-' if blocks.last() == Some(&true) => {
                assert!(
                    !(t[i..].starts_with("--") && t[prelude..i].trim().is_empty()),
                    "custom property in CSS: {css}"
                );
            }
            _ => {}
        }
    }
    for (name, after) in calls {
        if name == "url" {
            let rest = t[after..].trim_start().trim_start_matches(['"', '\'']);
            assert!(rest.starts_with("mail-resource://"), "url( in CSS: {css}");
        }
    }
}

fn check_document(doc: &str) {
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(doc);
    let mut metas = 0;
    for n in nodes(&dom.document) {
        let NodeData::Element { name, attrs, .. } = &n.data else {
            continue;
        };
        let tag = &*name.local;
        assert!(name.ns == ns!(html), "{name:?} element");
        assert!(!FORBIDDEN.contains(&tag), "<{tag}> element");
        let attrs = attrs.borrow();
        if name.local == local_name!("meta") {
            metas += 1;
            assert!(attrs.len() == 1 && attrs[0].name.local == local_name!("charset"));
        }
        if name.local == local_name!("body") {
            assert!(
                !attrs.iter().any(|a| &*a.name.local == "data-gx-fallback"),
                "the output check failed"
            );
        }
        if name.local == local_name!("style") {
            let text: String = n
                .children
                .borrow()
                .iter()
                .filter_map(|c| match &c.data {
                    NodeData::Text { contents } => Some(contents.borrow().to_string()),
                    _ => None,
                })
                .collect();
            assert!(!text.contains("</"), "</ in a <style>: {text}");
            check_css(&text, true);
        }
        for a in attrs.iter() {
            let attr = (*a.name.local).to_ascii_lowercase();
            if attr == "style" {
                check_css(&a.value, false);
            }
            assert!(!attr.starts_with("on"), "{attr} attribute on <{tag}>");
            if URL_ATTRIBUTES.contains(&attr.as_str()) {
                let url = url_start(&a.value);
                assert!(
                    !url.starts_with("javascript:") && !url.starts_with("vbscript:"),
                    "{attr}={url}"
                );
                assert!(!url.starts_with("data:"), "{attr}={url} on <{tag}>");
            }
        }
    }
    assert_eq!(metas, 1);
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, html)) = data.split_first() else {
        return;
    };
    let cfg = Config::default();
    let t = mailsanitize::text(&String::from_utf8_lossy(html), &cfg);
    check_manifest(&t.manifest);
    assert!(!t.text.chars().any(|c| matches!(
        c,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}' | '\u{feff}'
    ) || (c.is_control() && c != '\n' && c != '\t')));
    if let Ok(s) = std::str::from_utf8(html) {
        let theme = [
            Theme::Light,
            Theme::Dark,
            Theme::DarkStrict,
            Theme::HighContrast,
            Theme::HighContrastDark,
        ][usize::from(sel % 5)];
        let ids = vec![mailsanitize::cid_resource_id(b"a@b")];
        let out = mailsanitize::sanitize(s, theme, ids, &cfg);
        check_manifest(&out.manifest);
        assert!(!out.document.to_ascii_lowercase().contains("<script"));
        check_document(&out.document);
    }
});
