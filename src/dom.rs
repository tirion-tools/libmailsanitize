//! Post-sanitize document pass: the full transform and the hybrid
//! preflight. Tracks the background each element paints on so text
//! colours can be chosen against their real context.

use std::cell::RefCell;
use std::rc::Rc;

use lol_html::html_content::ContentType;
use lol_html::{RewriteStrSettings, element, rewrite_str, text};

use crate::color::{
    CANVAS, Rgb, blink_auto_dark_bg, contrast, map_bg, map_border, map_fg, parse_attr_color,
    required_contrast,
};
use crate::css::{
    BlockColors, Mode, SimpleRule, Stats, process_stylesheet, recolor_style_attr, scan_style_attr,
};
use crate::image::{low_contrast_fraction, visible_pixels};

const BLACK: Rgb = Rgb::hex(0x000000);
const WHITE: Rgb = Rgb::hex(0xffffff);
const UA_LINK: Rgb = Rgb::hex(0x0000ee);
/// Transparent image gets a backdrop when more than this share of its visible pixels would
/// fall below 3:1 on the dark background (and did not on the original one).
pub const IMAGE_LOW_FRACTION: f32 = 0.25;

pub fn text_color() -> Rgb {
    map_fg(BLACK, CANVAS, WHITE)
}
pub fn link_color() -> Rgb {
    map_fg(UA_LINK, CANVAS, WHITE)
}

#[derive(Clone, Copy)]
struct Frame {
    orig_fg: Rgb,
    mapped_fg: Rgb,
    orig_bg: Rgb,
    mapped_bg: Rgb,
    image: bool,
}

struct Walker {
    mode: Mode,
    stack: Vec<Frame>,
    simple: Vec<SimpleRule>,
    link_orig: Rgb,
    link_mapped: Rgb,
    stats: Stats,
}

pub struct DomResult {
    pub html: String,
    pub sender_dark: bool,
    pub stats: Stats,
}

fn class_colors(
    simple: &[SimpleRule],
    tag: &str,
    classes: &[&str],
    id: Option<&str>,
) -> (BlockColors, Option<Rgb>) {
    let mut out = BlockColors::default();
    let mut rule_ctx_bg = None;
    for rule in simple {
        if rule.selectors.iter().any(|c| {
            c.matches(tag, classes, id)
                && (c.tag.is_some() || !c.classes.is_empty() || c.id.is_some())
        }) {
            if rule.colors.bg.is_some() {
                out.bg = rule.colors.bg;
            }
            if rule.colors.fg.is_some() {
                out.fg = rule.colors.fg;
                rule_ctx_bg = rule.colors.bg;
            }
            out.image |= rule.colors.image;
        }
    }
    (out, rule_ctx_bg)
}

fn prepend_style(existing: Option<String>, decl: &str) -> String {
    match existing {
        Some(s) if !s.trim().is_empty() => format!("{decl};{s}"),
        _ => decl.to_string(),
    }
}

fn on_element(w: &mut Walker, el: &mut lol_html::html_content::Element) {
    let tag = el.tag_name().to_ascii_lowercase();
    let parent = *w.stack.last().expect("root frame");
    let class_attr = el.get_attribute("class").unwrap_or_default();
    let classes: Vec<&str> = class_attr.split_whitespace().collect();
    let id = el.get_attribute("id");
    let (cls, cls_rule_bg) = class_colors(&w.simple, &tag, &classes, id.as_deref());
    let style = el.get_attribute("style");
    let inline = style.as_deref().map(scan_style_attr).unwrap_or_default();
    let attr_bg = el
        .get_attribute("bgcolor")
        .as_deref()
        .and_then(parse_attr_color);
    let font_fg = if tag == "font" {
        el.get_attribute("color")
            .as_deref()
            .and_then(parse_attr_color)
    } else {
        None
    };

    if let Some(link) = el
        .get_attribute("data-gx-link")
        .as_deref()
        .and_then(parse_attr_color)
    {
        w.link_orig = link;
        w.link_mapped = map_fg(link, CANVAS, WHITE);
        el.remove_attribute("data-gx-link");
    }

    // Precedence: inline style > class rule > presentational attribute.
    let own_bg = inline.bg.or(cls.bg).or(attr_bg);
    let own_image = inline.image || cls.image;
    let image = own_image || (parent.image && own_bg.is_none());
    let orig_bg = own_bg
        .map(|b| b.over(parent.orig_bg))
        .unwrap_or(parent.orig_bg);
    let mapped_bg = match (w.mode, own_bg) {
        (_, None) => parent.mapped_bg,
        (Mode::Transform, Some(b)) => map_bg(b).over(parent.mapped_bg),
        (Mode::Scan, Some(_)) => blink_auto_dark_bg(orig_bg),
    };

    let mut orig_fg = parent.orig_fg;
    let mut mapped_fg = parent.mapped_fg;
    if tag == "a" {
        orig_fg = w.link_orig;
        mapped_fg = w.link_mapped;
    }

    if w.mode == Mode::Transform {
        let mut new_style = style.clone();
        if let Some(s) = style.as_deref() {
            new_style =
                recolor_style_attr(s, mapped_bg, orig_bg, image, &mut w.stats).or(new_style);
        }
        if let Some(b) = attr_bg {
            w.stats.colors_seen += 1;
            let m = map_bg(b);
            if m != b {
                w.stats.colors_rewritten += 1;
            }
            let _ = el.set_attribute("bgcolor", &m.css());
        }
        if let Some(c) = el
            .get_attribute("bordercolor")
            .as_deref()
            .and_then(parse_attr_color)
        {
            w.stats.colors_seen += 1;
            let _ = el.set_attribute(
                "bordercolor",
                &map_border(c, parent.mapped_bg, parent.orig_bg).css(),
            );
        }
        if let Some(c) = font_fg {
            w.stats.colors_seen += 1;
            let m = if image {
                c
            } else {
                map_fg(c, mapped_bg, orig_bg)
            };
            if m != c {
                w.stats.colors_rewritten += 1;
                w.stats.fg_contrast_fixes += 1;
            }
            let _ = el.set_attribute("color", &m.css());
        }

        // Effective text colour of this element after the stylesheet/inline rewrite.
        // Precedence: inline > class rule > <font color>; otherwise inherited (or link colour).
        let explicit = inline.fg.is_some() || (font_fg.is_some() && cls.fg.is_none());
        if let Some(fg) = inline.fg {
            orig_fg = fg;
            mapped_fg = if image {
                fg
            } else {
                map_fg(fg, mapped_bg, orig_bg)
            };
        } else if let Some(fg) = cls.fg {
            orig_fg = fg;
            let rule_ctx = cls_rule_bg
                .map(|b| map_bg(b).over(CANVAS))
                .unwrap_or(CANVAS);
            let rule_orig = cls_rule_bg.map(|b| b.over(WHITE)).unwrap_or(WHITE);
            mapped_fg = map_fg(fg, rule_ctx, rule_orig);
        } else if let Some(fg) = font_fg {
            orig_fg = fg;
            mapped_fg = if image {
                fg
            } else {
                map_fg(fg, mapped_bg, orig_bg)
            };
        }
        // A class/inherited/link colour was chosen for another background than the one this
        // element paints on: inject an explicit colour picked against the real context.
        let context_changed = own_bg.is_some() || tag == "a" || cls.fg.is_some();
        let needed = required_contrast(orig_fg, mapped_bg, orig_bg);
        if context_changed
            && !explicit
            && !image
            && contrast(mapped_fg.over(mapped_bg), mapped_bg) < needed
        {
            let desired = map_fg(orig_fg, mapped_bg, orig_bg);
            new_style = Some(prepend_style(
                new_style,
                &format!("color:{}", desired.css()),
            ));
            mapped_fg = desired;
            w.stats.injected_text_colors += 1;
        }
        if let Some(s) = new_style {
            let _ = el.set_attribute("style", &s);
        }
    }

    if tag == "img"
        && let Some(px) = el.get_attribute("src").as_deref().and_then(visible_pixels)
    {
        let low_new = low_contrast_fraction(&px, mapped_bg);
        let low_orig = low_contrast_fraction(&px, orig_bg.over(WHITE));
        if low_new > IMAGE_LOW_FRACTION && low_orig <= IMAGE_LOW_FRACTION {
            let backdrop = orig_bg.over(WHITE).css();
            let decl = match w.mode {
                Mode::Transform => format!("background-color:{backdrop};border-radius:4px"),
                // `only light` stops Blink's forced darkening of the backdrop itself.
                Mode::Scan => {
                    format!("color-scheme:only light;background-color:{backdrop};border-radius:4px")
                }
            };
            let s = prepend_style(el.get_attribute("style"), &decl);
            let _ = el.set_attribute("style", &s);
            w.stats.image_backdrops += 1;
        }
    }

    let frame = Frame {
        orig_fg,
        mapped_fg,
        orig_bg,
        mapped_bg,
        image,
    };
    if let Some(handlers) = el.end_tag_handlers() {
        w.stack.push(frame);
        let _ = handlers; // pop is registered by the caller (needs the Rc)
    }
}

pub fn process(sanitized: &str, mode: Mode) -> DomResult {
    // Pass 1: stylesheets (detect sender dark CSS, collect simple-selector colours, recolour).
    let sheets: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let buffer = Rc::new(RefCell::new(String::new()));
    {
        let (sheets, buffer) = (sheets.clone(), buffer.clone());
        let _ = rewrite_str(
            sanitized,
            RewriteStrSettings {
                element_content_handlers: vec![text!("style", move |t| {
                    buffer.borrow_mut().push_str(t.as_str());
                    if t.last_in_text_node() {
                        sheets
                            .borrow_mut()
                            .push(std::mem::take(&mut *buffer.borrow_mut()));
                    }
                    Ok(())
                })],
                ..RewriteStrSettings::new()
            },
        );
    }
    let mut stats = Stats::default();
    let mut sender_dark = false;
    let mut simple = Vec::new();
    let mut rewritten = Vec::new();
    for css in sheets.borrow().iter() {
        let r = process_stylesheet(css, mode);
        sender_dark |= r.sender_dark;
        simple.extend(r.simple);
        stats.colors_seen += r.stats.colors_seen;
        stats.colors_rewritten += r.stats.colors_rewritten;
        stats.fg_contrast_fixes += r.stats.fg_contrast_fixes;
        stats.sender_dark_rules_kept += r.stats.sender_dark_rules_kept;
        rewritten.push(r.css);
    }
    let mut link_orig = UA_LINK;
    for rule in &simple {
        let is_a = rule
            .selectors
            .iter()
            .any(|c| c.tag.as_deref() == Some("a") && c.classes.is_empty() && c.id.is_none());
        if let (true, Some(fg)) = (is_a, rule.colors.fg) {
            link_orig = fg;
        }
    }
    let root = match mode {
        Mode::Transform => Frame {
            orig_fg: BLACK,
            mapped_fg: text_color(),
            orig_bg: WHITE,
            mapped_bg: CANVAS,
            image: false,
        },
        Mode::Scan => Frame {
            orig_fg: BLACK,
            mapped_fg: BLACK,
            orig_bg: WHITE,
            mapped_bg: blink_auto_dark_bg(WHITE),
            image: false,
        },
    };
    let walker = Rc::new(RefCell::new(Walker {
        mode,
        stack: vec![root],
        simple,
        link_orig,
        link_mapped: if mode == Mode::Transform {
            map_fg(link_orig, CANVAS, WHITE)
        } else {
            link_orig
        },
        stats,
    }));

    // Pass 2: elements.
    let head_css = match mode {
        Mode::Transform => format!(
            "<style>:root{{color-scheme:dark!important}}:where(html){{background-color:{};color:{}}}:where(a:link),:where(a:visited){{color:{}}}</style>",
            CANVAS.css(),
            text_color().css(),
            link_color().css()
        ),
        // Sender ships dark CSS: opt the document out of Blink auto-dark and let it apply.
        // Otherwise neutralise any declared color-scheme so Blink's auto-dark applies.
        Mode::Scan if sender_dark => "<style>:root{color-scheme:light dark}</style>".to_string(),
        Mode::Scan => "<style>:root{color-scheme:normal!important}</style>".to_string(),
    };
    let sheet_index = Rc::new(RefCell::new(0usize));
    let rewritten = Rc::new(rewritten);
    let (w1, w2) = (walker.clone(), walker.clone());
    let html = rewrite_str(
        sanitized,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!("head", move |el| {
                    el.append(&head_css, ContentType::Html);
                    Ok(())
                }),
                text!("style", {
                    let (idx, sheets) = (sheet_index.clone(), rewritten.clone());
                    move |t| {
                        if t.last_in_text_node() {
                            let mut i = idx.borrow_mut();
                            if mode == Mode::Transform {
                                t.replace(
                                    sheets.get(*i).map(String::as_str).unwrap_or(""),
                                    ContentType::Html,
                                );
                            }
                            *i += 1;
                        } else if mode == Mode::Transform {
                            t.remove();
                        }
                        Ok(())
                    }
                }),
                element!("*", move |el| {
                    on_element(&mut w1.borrow_mut(), el);
                    if let Some(handlers) = el.end_tag_handlers() {
                        let w = w2.clone();
                        handlers.push(Box::new(move |_end| {
                            w.borrow_mut().stack.pop();
                            Ok(())
                        }));
                    }
                    Ok(())
                }),
            ],
            ..RewriteStrSettings::new()
        },
    )
    .unwrap_or_default();
    let stats = walker.borrow().stats.clone();
    DomResult {
        html,
        sender_dark,
        stats,
    }
}
