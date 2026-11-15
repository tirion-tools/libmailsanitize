//! Sanitize pipeline: ammonia allowlist + lightningcss CSS reprint. Image sources become opaque
//! `<scheme>://<id>/` references (the caller's scheme); only the caller maps ids to bytes:
//! - `cid:` parts: id = [`cid_resource_id`] of the Content-ID, kept only when the caller listed
//!   that id, recorded in `resource_ids_used`;
//! - http(s) images: a sanitizer-assigned placeholder id `img-N` (manifest `remote_images`, at
//!   most [`MAX_REMOTE_IMAGES`]); the caller supplies them later or shows the placeholder;
//! - inline `data:` PNG/JPEG are kept; every other source is dropped.
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use lol_html::{RewriteStrSettings, element, rewrite_str, text};

use crate::color::parse_attr_color;
use crate::css::{sanitize_style_attr, sanitize_stylesheet};

#[derive(Default)]
struct Prescan {
    color_scheme: Option<String>,
    body_bg: Option<String>,
    body_text: Option<String>,
    body_link: Option<String>,
    body_style: Option<String>,
}

fn builder() -> ammonia::Builder<'static> {
    let mut b = ammonia::Builder::default();
    b.tags(HashSet::from([
        "a",
        "abbr",
        "b",
        "big",
        "blockquote",
        "br",
        "center",
        "code",
        "div",
        "em",
        "font",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "i",
        "img",
        "li",
        "mark",
        "ol",
        "p",
        "pre",
        "s",
        "small",
        "span",
        "strike",
        "strong",
        "style",
        "sub",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "tt",
        "u",
        "ul",
    ]))
    .clean_content_tags(HashSet::from(["script", "title"]))
    .generic_attributes(HashSet::from([
        "style", "class", "id", "dir", "lang", "title", "align", "valign", "width", "height",
        "bgcolor", "role",
    ]))
    .tag_attributes(HashMap::from([
        ("a", HashSet::from(["href"])),
        ("img", HashSet::from(["src", "alt", "border"])),
        (
            "table",
            HashSet::from(["border", "cellpadding", "cellspacing", "bordercolor"]),
        ),
        (
            "td",
            HashSet::from(["colspan", "rowspan", "nowrap", "bordercolor"]),
        ),
        (
            "th",
            HashSet::from(["colspan", "rowspan", "nowrap", "bordercolor"]),
        ),
        ("font", HashSet::from(["color", "face", "size"])),
        ("ol", HashSet::from(["start", "type"])),
    ]))
    .url_schemes(HashSet::from(["http", "https", "mailto", "data", "cid"]))
    .link_rel(Some("noopener noreferrer"))
    .attribute_filter(|element, attribute, value| match (element, attribute) {
        ("img", "src") => {
            let v = value.trim_start().to_ascii_lowercase();
            if v.starts_with("data:image/png;base64,") || v.starts_with("data:image/jpeg;base64,") {
                Some(Cow::Borrowed(value))
            } else if v.starts_with("cid:") {
                map_cid(value.trim()).map(Cow::Owned)
            } else {
                map_remote(value).map(Cow::Owned)
            }
        }
        (_, "href") => {
            let v = value.trim_start().to_ascii_lowercase();
            (!(v.starts_with("data:") || v.starts_with("cid:"))).then_some(Cow::Borrowed(value))
        }
        (_, "style") => sanitize_style_attr(value).map(Cow::Owned),
        _ => Some(Cow::Borrowed(value)),
    });
    b
}

/// Upper bounds on the manifest (the caller re-checks them).
pub const MAX_CID_IDS: usize = 64;
pub const MAX_REMOTE_IMAGES: usize = 256;
pub const MAX_RESOURCE_ID: usize = 64;

/// Resource id of a Content-ID (without `<>`): `cid-` + FNV-1a-64 of its bytes, lowercase hex.
/// Callers compute the same id for the parts they can supply.
pub fn cid_resource_id(content_id: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in content_id {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("cid-{h:016x}")
}

/// `[a-z0-9-]{1,64}`.
pub fn valid_resource_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RESOURCE_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Per-document state; [`begin`] resets it, [`finish`] takes it out.
#[derive(Default)]
pub struct Resources {
    /// `<scheme>://` of the rewritten references.
    pub prefix: String,
    pub cid_allowed: Vec<String>,
    pub cid_used: Vec<String>,
    /// (placeholder id, canonical URL, width, height).
    pub remote: Vec<(String, String, u32, u32)>,
    pub remote_dropped: u32,
}

thread_local! {
    static RESOURCES: RefCell<Resources> = RefCell::new(Resources::default());
}

pub fn begin(scheme: &str, cid_allowed: Vec<String>) {
    RESOURCES.with(|r| {
        *r.borrow_mut() = Resources {
            prefix: format!("{scheme}://"),
            cid_allowed,
            ..Resources::default()
        }
    });
}

pub fn finish() -> Resources {
    RESOURCES.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn map_cid(reference: &str) -> Option<String> {
    let id = cid_resource_id(&percent_decode(&reference[4..]));
    RESOURCES.with(|r| {
        let mut r = r.borrow_mut();
        if !r.cid_allowed.contains(&id) {
            return None;
        }
        if !r.cid_used.contains(&id) {
            r.cid_used.push(id.clone());
        }
        Some(format!("{}{id}/", r.prefix))
    })
}

fn map_remote(value: &str) -> Option<String> {
    let url = match crate::text::link_target(value) {
        crate::text::LinkOut::Url(u) if u.starts_with("http") => Some(u),
        _ => None,
    };
    RESOURCES.with(|r| {
        let mut r = r.borrow_mut();
        match url {
            Some(u) if r.remote.len() < MAX_REMOTE_IMAGES => {
                let id = format!("img-{}", r.remote.len());
                r.remote.push((id.clone(), u, 0, 0));
                Some(format!("{}{id}/", r.prefix))
            }
            _ => {
                r.remote_dropped = r.remote_dropped.saturating_add(1);
                None
            }
        }
    })
}

/// Records the rendered size hint of a remote placeholder (`img-N`).
fn note_size(src: &str, w: Option<String>, h: Option<String>) {
    let Some(n) = RESOURCES.with(|r| {
        src.strip_prefix(r.borrow().prefix.as_str())?
            .strip_prefix("img-")?
            .strip_suffix('/')?
            .parse::<usize>()
            .ok()
    }) else {
        return;
    };
    let px = |v: Option<String>| {
        v.and_then(|v| v.trim().trim_end_matches("px").parse::<u32>().ok())
            .unwrap_or(0)
            .min(16384)
    };
    RESOURCES.with(|r| {
        if let Some(e) = r.borrow_mut().remote.get_mut(n) {
            e.2 = px(w);
            e.3 = px(h);
        }
    });
}

thread_local! {
    static BUILDER: ammonia::Builder<'static> = builder();
}

pub fn sanitize(input: &str) -> String {
    // 1. Pre-scan for document-level presentation that fragment sanitizing would drop.
    let pre = Rc::new(RefCell::new(Prescan::default()));
    let (p1, p2) = (pre.clone(), pre.clone());
    let _ = rewrite_str(
        input,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!("meta[name]", move |el| {
                    let name = el
                        .get_attribute("name")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if name == "color-scheme" || name == "supported-color-schemes" {
                        p1.borrow_mut().color_scheme = el.get_attribute("content");
                    }
                    Ok(())
                }),
                element!("body", move |el| {
                    let mut p = p2.borrow_mut();
                    p.body_bg = el.get_attribute("bgcolor");
                    p.body_text = el.get_attribute("text");
                    p.body_link = el.get_attribute("link");
                    p.body_style = el.get_attribute("style");
                    Ok(())
                }),
            ],
            ..RewriteStrSettings::new()
        },
    );
    let pre = pre.borrow();

    // 2. Allowlist sanitize (style attributes are re-serialised through lightningcss).
    let cleaned = BUILDER.with(|b| b.clean(input).to_string());

    // 3. Re-serialise <style> sheets through the CSS sanitizer.
    let buffer = Rc::new(RefCell::new(String::new()));
    let buf = buffer.clone();
    let cleaned = rewrite_str(
        &cleaned,
        RewriteStrSettings {
            element_content_handlers: vec![
                text!("style", move |t| {
                    buf.borrow_mut().push_str(t.as_str());
                    if t.last_in_text_node() {
                        let css = sanitize_stylesheet(&buf.borrow());
                        buf.borrow_mut().clear();
                        t.replace(&css, lol_html::html_content::ContentType::Html);
                    } else {
                        t.remove();
                    }
                    Ok(())
                }),
                element!("img[src]", |el| {
                    if let Some(src) = el.get_attribute("src") {
                        note_size(&src, el.get_attribute("width"), el.get_attribute("height"));
                    }
                    Ok(())
                }),
            ],
            ..RewriteStrSettings::new()
        },
    )
    .unwrap_or_default();

    // 4. Rebuild a document; body presentation is re-applied to the new <body> so sender
    //    `body { … }` rules (e.g. in their dark media query) still target the same element.
    let mut head = String::from("<meta charset=\"utf-8\">");
    if let Some(cs) = &pre.color_scheme
        && cs.to_ascii_lowercase().contains("dark")
    {
        head.push_str("<style>:root{color-scheme:light dark}</style>");
    }
    let mut wrapper_style = String::new();
    if let Some(c) = pre.body_bg.as_deref().and_then(parse_attr_color) {
        wrapper_style.push_str(&format!("background-color:{};", c.css()));
    }
    if let Some(c) = pre.body_text.as_deref().and_then(parse_attr_color) {
        wrapper_style.push_str(&format!("color:{};", c.css()));
    }
    if let Some(s) = pre.body_style.as_deref().and_then(sanitize_style_attr) {
        wrapper_style.push_str(&s);
    }
    let mut wrapper = String::from("<body class=\"gx-body\"");
    if let Some(c) = pre.body_link.as_deref().and_then(parse_attr_color) {
        head.push_str(&format!(
            "<style>:where(.gx-body) :where(a:link,a:visited){{color:{}}}</style>",
            c.css()
        ));
        wrapper.push_str(&format!(" data-gx-link=\"{}\"", c.css()));
    }
    if !wrapper_style.is_empty() {
        wrapper.push_str(&format!(
            " style=\"{}\"",
            wrapper_style.replace('"', "&quot;")
        ));
    }
    wrapper.push('>');
    format!("<!DOCTYPE html><html><head>{head}</head>{wrapper}{cleaned}</body></html>")
}
