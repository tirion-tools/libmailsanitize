//! The sanitizer on arbitrary bytes: the text fallback on the lossy decoding of every input, and
//! sanitize under the theme picked by the first byte for valid UTF-8. Asserts the output
//! contract: the manifest bounds, no forbidden characters in the fallback text, and a sanitized
//! document with no `<script` anywhere in its text that, parsed again with html5ever (its own
//! tree, not the library's), holds no active content:
//! - no `</` in a `<style>` text (nothing can end the element early);
//! - no script, frame, plugin, form, `<base>`, `<link>`, `<template>`, SVG or MathML element, and
//!   one `<meta>`, the frame's `charset` (no `http-equiv`);
//! - no `on*` attribute, no `javascript:` or `vbscript:` URL, `data:` only for PNG/JPEG images;
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
        assert!(l.text_samples.iter().all(|s| s.chars().count() <= 256));
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
        }
        for a in attrs.iter() {
            let attr = (*a.name.local).to_ascii_lowercase();
            assert!(!attr.starts_with("on"), "{attr} attribute on <{tag}>");
            if URL_ATTRIBUTES.contains(&attr.as_str()) {
                let url = url_start(&a.value);
                assert!(
                    !url.starts_with("javascript:") && !url.starts_with("vbscript:"),
                    "{attr}={url}"
                );
                assert!(
                    !url.starts_with("data:")
                        || (tag == "img"
                            && attr == "src"
                            && (url.starts_with("data:image/png;base64,")
                                || url.starts_with("data:image/jpeg;base64,"))),
                    "{attr}={url} on <{tag}>"
                );
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
        let theme = [Theme::Light, Theme::Dark, Theme::DarkStrict][usize::from(sel % 3)];
        let ids = vec![mailsanitize::cid_resource_id(b"a@b")];
        let out = mailsanitize::sanitize(s, theme, ids, &cfg);
        check_manifest(&out.manifest);
        assert!(!out.document.to_ascii_lowercase().contains("<script"));
        check_document(&out.document);
    }
});
