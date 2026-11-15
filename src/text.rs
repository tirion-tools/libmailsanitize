//! Isolated HTML-to-text fallback.
//!
//! Used only after sanitizing or rendering a part has failed, so it shares as little as possible
//! with the path that just failed: it runs html5ever's *tokenizer* alone (no tree builder, no
//! ammonia, no lightningcss, no lol_html, no dark transform) and keeps its own bounded element
//! stack. Cost is linear in the input; every structure is capped (constants below).
//!
//! Output (both parts plain bytes, returned in one sealed memfd):
//!   links: `N<TAB>FLAG<TAB>URL<LF>` per listed link, N = 1.., FLAG `-` or `m` (link text shows
//!          another address), URL printable ASCII only (http, https, mailto);
//!   text:  UTF-8 with `\n` line ends, footnote markers ` [N]` after link text and a final
//!          `Links:` list.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;

use html5ever::LocalName;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, Tag, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};

use crate::color::{Rgb, contrast};

/// Body text cap in bytes (the footnote list is bounded separately by MAX_LINKS × MAX_URL).
pub const TEXT_CAP: usize = 1 << 20;
pub const MAX_LINKS: usize = 256;
pub const MAX_URL: usize = 2048;
/// Elements tracked on the stack; deeper elements are flattened into their tracked ancestor.
pub const MAX_DEPTH: usize = 512;
/// A line longer than this many characters gets a forced line break (protects Pango shaping).
pub const MAX_LINE_CHARS: usize = 4096;
pub const MAX_ALT_CHARS: usize = 256;
/// Inline `style` bytes evaluated per element; `<style>` bytes and rules kept per document.
pub const MAX_STYLE_SCAN: usize = 8 << 10;
pub const MAX_SHEET_BYTES: usize = 64 << 10;
pub const MAX_SHEET_RULES: usize = 512;
/// How far an end tag / an implied close searches down the stack.
pub const END_TAG_SEARCH: usize = 64;
pub const IMPLIED_SEARCH: usize = 16;
/// Combining marks kept after one base character; variation selectors kept after one base.
pub const MAX_COMBINING: usize = 4;
/// Quote and list nesting shown as prefixes (deeper levels share the last prefix).
pub const MAX_INDENT: usize = 8;
/// Attributes kept per tag before tokenizing: html5ever's tokenizer checks each new attribute
/// against all earlier ones of the same tag (quadratic; 150,000 attributes exceed RLIMIT_CPU).
pub const MAX_ATTRS: usize = 128;
const CHUNK: usize = 64 << 10;
/// Text below this computed font size is hidden (preheader `font-size:0/1px` tricks).
const MIN_FONT_PX: f32 = 2.0;
/// WCAG contrast below this between text and its background is "colour on colour".
const MIN_CONTRAST: f32 = 1.25;
/// Offsets at or beyond this (px, negative) are "off-screen".
const OFFSCREEN_PX: f32 = -500.0;
pub const TRUNCATED_MARK: &str = "[The text of this message was truncated]";
pub const MISMATCH_NOTE: &str = "  (the link text shows a different address)";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reason {
    DisplayNone,
    Visibility,
    MsoHide,
    Opacity,
    ZeroBox,
    FontSize,
    Transparent,
    ColorOnColor,
    Offscreen,
    Clip,
    HiddenAttr,
}
const REASONS: [(Hidden, Reason); 11] = [
    (Hidden::DisplayNone, Reason::DisplayNone),
    (Hidden::VisibilityHidden, Reason::Visibility),
    (Hidden::MsoHide, Reason::MsoHide),
    (Hidden::Opacity, Reason::Opacity),
    (Hidden::Clipped, Reason::ZeroBox),
    (Hidden::TinyFont, Reason::FontSize),
    (Hidden::Opacity, Reason::Transparent),
    (Hidden::LowContrast, Reason::ColorOnColor),
    (Hidden::Offscreen, Reason::Offscreen),
    (Hidden::Clipped, Reason::Clip),
    (Hidden::DisplayNone, Reason::HiddenAttr),
];

/// Manifest reason (proto `HiddenCount.Reason`) of each hidden-text rule.
pub use proto::v1::sanitizer::hidden_count::Reason as Hidden;

/// Most visible-text samples kept per listed link (manifest `ManifestLink.text_samples`).
pub const MAX_SAMPLES: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Inline,
    Line,
    Para,
    Cell,
    Row,
    Table,
    List { ordered: bool },
    Li,
    Quote,
    Pre,
    Anchor,
    Style,
    Drop,
}

fn kind_of(name: &str) -> Kind {
    match name {
        "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "dl" | "figure" | "address"
        | "fieldset" => Kind::Para,
        "div" | "dt" | "dd" | "section" | "article" | "header" | "footer" | "nav" | "main"
        | "aside" | "center" | "form" | "summary" | "details" | "figcaption" | "caption"
        | "legend" | "body" | "html" | "option" | "menu" | "dir" | "dialog" | "hgroup"
        | "search" | "tbody" | "thead" | "tfoot" | "optgroup" | "noscript" => Kind::Line,
        "td" | "th" => Kind::Cell,
        "tr" => Kind::Row,
        "table" => Kind::Table,
        "ul" | "menuitem" => Kind::List { ordered: false },
        "ol" => Kind::List { ordered: true },
        "li" => Kind::Li,
        "blockquote" => Kind::Quote,
        "pre" | "xmp" | "listing" | "plaintext" => Kind::Pre,
        "a" => Kind::Anchor,
        "style" => Kind::Style,
        "script" | "title" | "template" | "noembed" | "noframes" | "iframe" | "object"
        | "applet" | "svg" | "canvas" | "audio" | "video" | "select" | "datalist" | "map"
        | "frameset" | "xml" => Kind::Drop,
        _ => Kind::Inline,
    }
}

fn is_void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "image"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
            | "keygen"
            | "basefont"
            | "bgsound"
            | "frame"
    )
}

/// Start tags that close an open `<p>` (HTML "close a p element in button scope").
fn closes_p(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "center"
            | "details"
            | "dialog"
            | "dir"
            | "div"
            | "dl"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hgroup"
            | "hr"
            | "main"
            | "menu"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "listing"
            | "section"
            | "summary"
            | "table"
            | "ul"
            | "li"
            | "dd"
            | "dt"
            | "plaintext"
            | "xmp"
            | "search"
    )
}

fn is_heading(name: &str) -> bool {
    matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

// ---- character policy ------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Space,
    Newline,
    Control,
    Bidi,
    Invisible,
    Joiner,
    TagChar,
    Combining,
    VarSel,
    Keep,
}

fn class_of(c: char) -> Class {
    match c {
        '\t' | '\n' | '\u{0c}' | '\r' | ' ' => Class::Space,
        '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}' => Class::Space,
        '\u{2028}' | '\u{2029}' => Class::Newline,
        '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}' => Class::Control,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' | '\u{61c}' => {
            Class::Bidi
        }
        '\u{200b}'
        | '\u{2060}'..='\u{2064}'
        | '\u{feff}'
        | '\u{ad}'
        | '\u{34f}'
        | '\u{180e}'
        | '\u{115f}'
        | '\u{1160}'
        | '\u{3164}'
        | '\u{ffa0}'
        | '\u{17b4}'
        | '\u{17b5}'
        | '\u{206a}'..='\u{206f}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0001}' => Class::Invisible,
        '\u{200c}' | '\u{200d}' => Class::Joiner,
        '\u{e0020}'..='\u{e007f}' => Class::TagChar,
        '\u{300}'..='\u{36f}'
        | '\u{1ab0}'..='\u{1aff}'
        | '\u{1dc0}'..='\u{1dff}'
        | '\u{20d0}'..='\u{20ff}'
        | '\u{fe20}'..='\u{fe2f}' => Class::Combining,
        '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}' => Class::VarSel,
        _ => Class::Keep,
    }
}

#[derive(Default)]
struct Removed {
    control: usize,
    bidi: usize,
    invisible: usize,
    joiner: usize,
    tag: usize,
    combining: usize,
    varsel: usize,
}

/// The output writer: whitespace collapsing, block breaks, prefixes, the character policy and
/// the byte cap all live here, so every byte of body text passes through `raw`.
struct Out {
    s: String,
    cap: usize,
    truncated: bool,
    want_space: bool,
    want_sep: bool,
    want_breaks: u8,
    trailing_nl: u8,
    line_chars: usize,
    quote: usize,
    list: usize,
    marker: Option<String>,
    prev: Option<char>,
    prev_class: Class,
    joiner: Option<char>,
    combining: usize,
    tag_seq: bool,
    content_chars: usize,
    forced_breaks: usize,
    removed: Removed,
}

impl Out {
    fn new(cap: usize) -> Out {
        Out {
            s: String::new(),
            cap,
            truncated: false,
            want_space: false,
            want_sep: false,
            want_breaks: 0,
            trailing_nl: 0,
            line_chars: 0,
            quote: 0,
            list: 0,
            marker: None,
            prev: None,
            prev_class: Class::Space,
            joiner: None,
            combining: 0,
            tag_seq: false,
            content_chars: 0,
            forced_breaks: 0,
            removed: Removed::default(),
        }
    }

    fn raw(&mut self, c: char) {
        if self.truncated {
            return;
        }
        if self.s.len() + c.len_utf8() > self.cap {
            self.truncated = true;
            return;
        }
        self.s.push(c);
        if c == '\n' {
            self.trailing_nl = self.trailing_nl.saturating_add(1);
            self.line_chars = 0;
        } else {
            self.trailing_nl = 0;
            self.line_chars += 1;
            // Every byte of body text passes here (prefixes, separators, preformatted
            // whitespace included), so the line bound holds for all of them.
            if self.line_chars >= MAX_LINE_CHARS && self.s.len() < self.cap {
                self.s.push('\n');
                self.trailing_nl = 1;
                self.line_chars = 0;
                self.forced_breaks += 1;
            }
        }
    }

    fn raw_str(&mut self, s: &str) {
        for c in s.chars() {
            self.raw(c);
        }
    }

    fn at_line_start(&self) -> bool {
        self.s.is_empty() || self.trailing_nl > 0
    }

    /// Requests `n` line breaks (1 = new line, 2 = blank line) before the next content.
    fn brk(&mut self, n: u8) {
        self.want_breaks = self.want_breaks.max(n);
        self.word_boundary();
    }

    /// `<br>`, a preformatted newline or U+2028: one more line than already pending.
    fn hard_break(&mut self) {
        let have = self.want_breaks.max(if self.s.is_empty() {
            0
        } else {
            self.trailing_nl
        });
        self.want_breaks = (have + 1).min(2).max(self.want_breaks);
        self.word_boundary();
    }

    fn word_boundary(&mut self) {
        if self.joiner.take().is_some() {
            self.removed.joiner += 1;
        }
        self.prev = None;
        self.prev_class = Class::Space;
        self.tag_seq = false;
        self.combining = 0;
    }

    /// Resolves pending breaks, prefix, cell separator and space before one visible character.
    fn begin(&mut self) {
        if !self.s.is_empty() {
            let need = self.want_breaks.saturating_sub(self.trailing_nl);
            for _ in 0..need {
                self.raw('\n');
            }
        }
        if self.at_line_start() {
            for _ in 0..self.quote.min(MAX_INDENT) {
                self.raw_str("> ");
            }
            let levels = self.list.min(MAX_INDENT);
            match self.marker.take() {
                Some(m) => {
                    for _ in 1..levels {
                        self.raw_str("  ");
                    }
                    self.raw_str(&m);
                }
                None => {
                    for _ in 0..levels {
                        self.raw_str("  ");
                    }
                }
            }
        } else if self.want_sep {
            self.raw_str(" | ");
        } else if self.want_space {
            self.raw(' ');
        }
        self.want_breaks = 0;
        self.want_space = false;
        self.want_sep = false;
    }

    fn visible(&mut self, c: char, class: Class) {
        self.begin();
        if let Some(j) = self.joiner.take() {
            self.raw(j);
        }
        self.raw(c);
        self.content_chars += 1;
        self.prev = Some(c);
        self.prev_class = class;
    }

    /// One run of document text. `pre`: whitespace is kept literally.
    fn text(&mut self, s: &str, pre: bool) {
        for c in s.chars() {
            if self.truncated {
                return;
            }
            let class = class_of(c);
            match class {
                Class::Space if pre => match c {
                    '\n' => self.hard_break(),
                    '\r' | '\u{0c}' => {}
                    _ => {
                        self.begin();
                        self.raw(if c == '\t' { '\t' } else { ' ' });
                        self.word_boundary();
                    }
                },
                Class::Space => {
                    self.want_space = true;
                    self.word_boundary();
                }
                Class::Newline => self.hard_break(),
                Class::Control => self.removed.control += 1,
                Class::Bidi => self.removed.bidi += 1,
                Class::Invisible => self.removed.invisible += 1,
                Class::Joiner => {
                    // Kept only between two visible characters (emoji ZWJ sequences, Indic and
                    // Persian shaping); runs of joiners used as invisible padding are dropped.
                    if self.prev.is_some() && self.joiner.is_none() {
                        self.joiner = Some(c);
                    } else {
                        self.removed.joiner += 1;
                    }
                }
                Class::TagChar => {
                    // Only inside an emoji tag sequence (subdivision flags start with U+1F3F4);
                    // anything else is invisible "ASCII smuggling".
                    if self.tag_seq {
                        self.visible(c, class);
                        self.tag_seq = c != '\u{e007f}';
                    } else {
                        self.removed.tag += 1;
                    }
                }
                Class::VarSel => {
                    if self.prev.is_some()
                        && !matches!(self.prev_class, Class::VarSel | Class::Joiner)
                    {
                        let seq = self.tag_seq;
                        self.visible(c, class);
                        self.tag_seq = seq;
                    } else {
                        self.removed.varsel += 1;
                    }
                }
                Class::Combining => {
                    if self.combining < MAX_COMBINING {
                        self.combining += 1;
                        self.visible(c, class);
                    } else {
                        self.removed.combining += 1;
                    }
                }
                Class::Keep => {
                    self.combining = 0;
                    self.visible(c, class);
                    self.tag_seq = c == '\u{1f3f4}';
                }
            }
        }
    }
}

// ---- colours and lengths ---------------------------------------------------------------------

const NAMED: &[(&str, u32)] = &[
    ("black", 0x000000),
    ("white", 0xffffff),
    ("red", 0xff0000),
    ("green", 0x008000),
    ("blue", 0x0000ff),
    ("yellow", 0xffff00),
    ("gray", 0x808080),
    ("grey", 0x808080),
    ("silver", 0xc0c0c0),
    ("maroon", 0x800000),
    ("purple", 0x800080),
    ("fuchsia", 0xff00ff),
    ("magenta", 0xff00ff),
    ("lime", 0x00ff00),
    ("olive", 0x808000),
    ("navy", 0x000080),
    ("teal", 0x008080),
    ("aqua", 0x00ffff),
    ("cyan", 0x00ffff),
    ("orange", 0xffa500),
    ("whitesmoke", 0xf5f5f5),
    ("snow", 0xfffafa),
    ("ivory", 0xfffff0),
    ("ghostwhite", 0xf8f8ff),
    ("gainsboro", 0xdcdcdc),
    ("lightgray", 0xd3d3d3),
    ("lightgrey", 0xd3d3d3),
    ("darkgray", 0xa9a9a9),
    ("darkgrey", 0xa9a9a9),
    ("dimgray", 0x696969),
    ("dimgrey", 0x696969),
    ("floralwhite", 0xfffaf0),
    ("linen", 0xfaf0e6),
    ("seashell", 0xfff5ee),
    ("mintcream", 0xf5fffa),
    ("azure", 0xf0ffff),
    ("aliceblue", 0xf0f8ff),
    ("honeydew", 0xf0fff0),
    ("beige", 0xf5f5dc),
    ("oldlace", 0xfdf5e6),
    ("lavender", 0xe6e6fa),
    ("darkblue", 0x00008b),
    ("darkred", 0x8b0000),
    ("darkgreen", 0x006400),
    ("lightblue", 0xadd8e6),
    ("pink", 0xffc0cb),
];

fn hexval(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

/// CSS colour subset (hex, rgb()/rgba(), named, transparent); `bare_hex` for legacy attributes.
/// Unknown syntax returns None, i.e. "no decision", never "hidden".
fn parse_color(v: &str, bare_hex: bool) -> Option<Rgb> {
    let v = v
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    if v == "transparent" {
        return Some(Rgb {
            r: 0.0,
            g: 0.0,
            b: 0.0,
            a: 0.0,
        });
    }
    let h = match v.strip_prefix('#') {
        Some(h) => h,
        None if bare_hex => v.as_str(),
        None => return None,
    };
    if !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()) {
        let d = |i: usize| hexval(&h[i..i + 1]).map(|x| (x * 17) as u8);
        let dd = |i: usize| hexval(&h[i..i + 2]).map(|x| x as u8);
        return match h.len() {
            3 => Some(Rgb::from_u8(d(0)?, d(1)?, d(2)?, 1.0)),
            4 => Some(Rgb::from_u8(d(0)?, d(1)?, d(2)?, d(3)? as f32 / 255.0)),
            6 => Some(Rgb::from_u8(dd(0)?, dd(2)?, dd(4)?, 1.0)),
            8 => Some(Rgb::from_u8(dd(0)?, dd(2)?, dd(4)?, dd(6)? as f32 / 255.0)),
            _ => None,
        };
    }
    None
}

fn parse_color_any(v: &str, bare_hex: bool) -> Option<Rgb> {
    let t = v
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    if let Some(c) = parse_color(&t, bare_hex) {
        return Some(c);
    }
    if let Some(inner) = t.strip_prefix("rgba(").or_else(|| t.strip_prefix("rgb(")) {
        let inner = inner.strip_suffix(')')?;
        let parts: Vec<&str> = inner
            .split(|c: char| c == ',' || c == '/' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < 3 || parts.len() > 4 {
            return None;
        }
        let ch = |p: &str| -> Option<u8> {
            if let Some(pc) = p.strip_suffix('%') {
                Some((pc.parse::<f32>().ok()?.clamp(0.0, 100.0) * 2.55).round() as u8)
            } else {
                Some(p.parse::<f32>().ok()?.clamp(0.0, 255.0).round() as u8)
            }
        };
        let a = match parts.get(3) {
            Some(p) => match p.strip_suffix('%') {
                Some(pc) => pc.parse::<f32>().ok()? / 100.0,
                None => p.parse::<f32>().ok()?,
            },
            None => 1.0,
        };
        return Some(Rgb::from_u8(
            ch(parts[0])?,
            ch(parts[1])?,
            ch(parts[2])?,
            a.clamp(0.0, 1.0),
        ));
    }
    NAMED
        .iter()
        .find(|(n, _)| *n == t)
        .map(|(_, v)| Rgb::hex(*v))
}

/// A CSS length in px (`font` = the parent's font size for em/%). None = not a length we know.
fn len_px(v: &str, font: f32) -> Option<f32> {
    let v = v
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    let end = v
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(v.len());
    let (num, unit) = v.split_at(end);
    let n: f32 = num.parse().ok()?;
    if !n.is_finite() {
        return None;
    }
    Some(match unit.trim() {
        "" | "px" => n,
        "pt" => n * 4.0 / 3.0,
        "pc" => n * 16.0,
        "in" => n * 96.0,
        "cm" => n * 96.0 / 2.54,
        "mm" => n * 96.0 / 25.4,
        "em" => n * font,
        "rem" => n * 16.0,
        "ex" | "ch" => n * font * 0.5,
        "%" => n * font / 100.0,
        _ if n == 0.0 => 0.0,
        _ => return None,
    })
}

fn font_size(v: &str, parent: f32) -> Option<f32> {
    let t = v
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    Some(match t.as_str() {
        "xx-small" => 9.0,
        "x-small" => 10.0,
        "small" => 13.0,
        "medium" => 16.0,
        "large" => 18.0,
        "x-large" => 24.0,
        "xx-large" => 32.0,
        "xxx-large" => 48.0,
        "smaller" => parent / 1.2,
        "larger" => parent * 1.2,
        _ => len_px(&t, parent)?,
    })
}

// ---- declarations ------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Bg {
    Color(Rgb),
    Image,
}

/// The subset of CSS that decides visibility, accumulated in cascade order (sheet, then inline).
#[derive(Clone, Default, Debug)]
struct Decls {
    display_none: Option<bool>,
    display_important: bool,
    visibility_hidden: Option<bool>,
    mso_hide: bool,
    opacity_zero: Option<bool>,
    font: Option<String>,
    max_h: Option<String>,
    h: Option<String>,
    max_w: Option<String>,
    w: Option<String>,
    overflow_hidden: Option<bool>,
    position_abs: Option<bool>,
    left: Option<String>,
    top: Option<String>,
    text_indent: Option<String>,
    clip_hidden: Option<bool>,
    color: Option<Rgb>,
    bg: Option<Bg>,
}

/// Splits `a:b; c:d` at top-level semicolons (parentheses and quotes respected), comments removed.
fn declarations(style: &str, limit: usize) -> Vec<(String, String)> {
    let mut end = style.len().min(limit);
    while !style.is_char_boundary(end) {
        end -= 1;
    }
    let s = &style[..end];
    let mut out = vec![];
    let mut cur = String::new();
    let (mut depth, mut quote, mut comment) = (0i32, None::<char>, false);
    let mut it = s.chars().peekable();
    fn flush(cur: &mut String, out: &mut Vec<(String, String)>) {
        if let Some((k, v)) = cur.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if !k.is_empty() {
                out.push((k, v.trim().to_string()));
            }
        }
        cur.clear();
    }
    while let Some(c) = it.next() {
        if comment {
            if c == '*' && it.peek() == Some(&'/') {
                it.next();
                comment = false;
            }
            continue;
        }
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '/' if it.peek() == Some(&'*') => {
                it.next();
                comment = true;
            }
            '"' | '\'' => {
                quote = Some(c);
                cur.push(c);
            }
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth = (depth - 1).max(0);
                cur.push(c);
            }
            ';' if depth == 0 => flush(&mut cur, &mut out),
            _ => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

fn first_token_color(v: &str) -> Option<Rgb> {
    // `background` shorthand: the first token that parses as a colour; rgb(...) kept whole.
    let mut depth = 0;
    let mut start = 0;
    let bytes: Vec<(usize, char)> = v.char_indices().collect();
    let mut tokens = vec![];
    for &(i, c) in &bytes {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_whitespace() && depth == 0 => {
                tokens.push(&v[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    tokens.push(&v[start..]);
    tokens
        .into_iter()
        .filter(|t| !t.is_empty())
        .find_map(|t| parse_color_any(t, false))
}

impl Decls {
    fn apply(&mut self, decls: &[(String, String)], from_sheet: bool) {
        for (k, v) in decls {
            let important = v.to_ascii_lowercase().contains("!important");
            let lv = v.trim_end_matches("!important").trim().to_ascii_lowercase();
            match k.as_str() {
                "display" => {
                    if !from_sheet && self.display_important {
                        continue;
                    }
                    self.display_none = Some(lv == "none");
                    if from_sheet {
                        self.display_important = important;
                    }
                }
                "visibility" => self.visibility_hidden = Some(lv == "hidden" || lv == "collapse"),
                "mso-hide" => self.mso_hide = lv == "all",
                "opacity" => {
                    let o = lv
                        .strip_suffix('%')
                        .and_then(|p| p.trim().parse::<f32>().ok().map(|x| x / 100.0))
                        .or_else(|| lv.parse::<f32>().ok());
                    self.opacity_zero = o.map(|o| o <= 0.05);
                }
                "font-size" => self.font = Some(lv),
                "font" => {
                    // Shorthand: the first token that is a size (`font:0/0 a`, `12px/1.4 Arial`).
                    if let Some(t) = lv
                        .split_whitespace()
                        .map(|t| t.split('/').next().unwrap_or(""))
                        .find(|t| {
                            t.starts_with(|c: char| c.is_ascii_digit() || c == '.')
                                || matches!(
                                    *t,
                                    "xx-small"
                                        | "x-small"
                                        | "small"
                                        | "medium"
                                        | "large"
                                        | "x-large"
                                        | "xx-large"
                                )
                        })
                    {
                        self.font = Some(t.to_string());
                    }
                }
                "max-height" => self.max_h = Some(lv),
                "height" => self.h = Some(lv),
                "max-width" => self.max_w = Some(lv),
                "width" => self.w = Some(lv),
                "overflow" | "overflow-y" | "overflow-x" => {
                    self.overflow_hidden = Some(lv.starts_with("hidden") || lv.starts_with("clip"))
                }
                "position" => self.position_abs = Some(lv == "absolute" || lv == "fixed"),
                "left" | "right" => self.left = Some(lv),
                "top" => self.top = Some(lv),
                "text-indent" => self.text_indent = Some(lv),
                "clip" => self.clip_hidden = Some(lv.starts_with("rect(")),
                "clip-path" => {
                    let compact: String = lv.chars().filter(|c| !c.is_whitespace()).collect();
                    self.clip_hidden = Some(
                        compact.starts_with("inset(50%")
                            || compact.starts_with("inset(100%")
                            || compact.starts_with("circle(0"),
                    );
                }
                "color" => {
                    if let Some(c) = parse_color_any(&lv, false) {
                        self.color = Some(c);
                    }
                }
                "background-color" => {
                    if let Some(c) = parse_color_any(&lv, false) {
                        self.bg = Some(Bg::Color(c));
                    }
                }
                "background" => {
                    if lv.contains("url(") || lv.contains("gradient(") {
                        self.bg = Some(Bg::Image);
                    } else if let Some(c) = first_token_color(&lv) {
                        self.bg = Some(Bg::Color(c));
                    }
                }
                "background-image" => {
                    if lv.contains("url(") || lv.contains("gradient(") {
                        self.bg = Some(Bg::Image);
                    }
                }
                _ => {}
            }
        }
    }

    /// Non-inherited hiding that a descendant cannot undo (display, mso-hide, opacity, clipped
    /// boxes, off-screen positioning).
    fn gone(&self, font: f32) -> Option<Reason> {
        if self.display_none == Some(true) {
            return Some(Reason::DisplayNone);
        }
        if self.mso_hide {
            return Some(Reason::MsoHide);
        }
        if self.opacity_zero == Some(true) {
            return Some(Reason::Opacity);
        }
        let tiny = |v: &Option<String>| {
            v.as_deref()
                .and_then(|v| len_px(v, font))
                .is_some_and(|px| px <= 1.0)
        };
        if self.overflow_hidden == Some(true)
            && (tiny(&self.max_h) || tiny(&self.h) || tiny(&self.max_w) || tiny(&self.w))
        {
            return Some(Reason::ZeroBox);
        }
        let far = |v: &Option<String>| {
            v.as_deref()
                .and_then(|v| len_px(v, font))
                .is_some_and(|px| px <= OFFSCREEN_PX)
        };
        if self.position_abs == Some(true) && (far(&self.left) || far(&self.top)) {
            return Some(Reason::Offscreen);
        }
        if far(&self.text_indent) && self.overflow_hidden == Some(true) {
            return Some(Reason::Offscreen);
        }
        if self.clip_hidden == Some(true)
            && (self.position_abs == Some(true) || self.overflow_hidden == Some(true))
        {
            return Some(Reason::Clip);
        }
        None
    }
}

// ---- stylesheet subset -------------------------------------------------------------------------

struct Rule {
    tag: Option<String>,
    classes: Vec<String>,
    id: Option<String>,
    decls: Vec<(String, String)>,
}

/// One compound selector of `tag`, `.class` and `#id` parts; anything else (combinators,
/// attributes, pseudo-classes) is not matched at all.
fn parse_selector(sel: &str) -> Option<(Option<String>, Vec<String>, Option<String>)> {
    let sel = sel.trim().to_ascii_lowercase();
    if sel.is_empty() || sel.len() > 128 {
        return None;
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let (mut tag, mut classes, mut id) = (None, vec![], None);
    let mut rest = sel.as_str();
    let head_end = rest.find(|c: char| !ok(c)).unwrap_or(rest.len());
    if head_end > 0 {
        tag = Some(rest[..head_end].to_string());
        rest = &rest[head_end..];
    }
    while let Some(kind) = rest.bytes().next() {
        // Only ASCII `.` and `#` may follow (slicing after them stays on a char boundary).
        if kind != b'.' && kind != b'#' {
            return None;
        }
        let tail = &rest[1..];
        let end = tail.find(|c: char| !ok(c)).unwrap_or(tail.len());
        if end == 0 {
            return None;
        }
        if kind == b'.' {
            classes.push(tail[..end].to_string());
        } else {
            id = Some(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    Some((tag, classes, id))
}

/// Top-level rules only (`@media`, `@supports` … blocks are skipped: the reader renders at
/// a desktop width and screen media), at most MAX_SHEET_RULES.
fn parse_sheet(css: &str, rules: &mut Vec<Rule>) {
    let mut s = String::with_capacity(css.len());
    let mut it = css.chars().peekable();
    while let Some(c) = it.next() {
        if c == '/' && it.peek() == Some(&'*') {
            it.next();
            let mut prev = ' ';
            for d in it.by_ref() {
                if prev == '*' && d == '/' {
                    break;
                }
                prev = d;
            }
        } else {
            s.push(c);
        }
    }
    let mut rest = s.as_str();
    while let Some(open) = rest.find('{') {
        let prelude = rest[..open].trim();
        let after = &rest[open + 1..];
        // Matching close brace (nested blocks for at-rules).
        let (mut depth, mut close) = (1i32, None);
        for (i, c) in after.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.unwrap_or(after.len());
        let body = &after[..close];
        rest = after.get(close + 1..).unwrap_or("");
        // Statements like `@import …;` before the block.
        let prelude = prelude.rsplit(';').next().unwrap_or("").trim();
        if prelude.starts_with('@') || body.contains('{') {
            continue;
        }
        let decls = declarations(body, MAX_STYLE_SCAN);
        if decls.is_empty() {
            continue;
        }
        for sel in prelude.split(',') {
            if rules.len() >= MAX_SHEET_RULES {
                return;
            }
            if let Some((tag, classes, id)) = parse_selector(sel) {
                rules.push(Rule {
                    tag,
                    classes,
                    id,
                    decls: decls.clone(),
                });
            }
        }
    }
}

// ---- links ---------------------------------------------------------------------------------------

pub(crate) enum LinkOut {
    Url(String),
    Scheme,
    TooLong,
}

/// Link target policy: http, https and mailto only; the listed form is printable ASCII, every
/// other byte (non-ASCII, space, quotes, controls, bidi controls) percent-encoded, so homoglyph
/// hosts and RTL overrides cannot disguise it.
pub(crate) fn link_target(href: &str) -> LinkOut {
    let cleaned: String = href
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") || lower.starts_with("mailto:") {
        7
    } else {
        return LinkOut::Scheme;
    };
    let mut out = String::with_capacity(cleaned.len());
    out.push_str(&lower[..scheme_len]);
    for b in cleaned.as_bytes()[scheme_len..].iter().copied() {
        if (0x21..=0x7e).contains(&b)
            && !matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
        if out.len() > MAX_URL {
            return LinkOut::TooLong;
        }
    }
    if out.len() == scheme_len {
        return LinkOut::Scheme;
    }
    LinkOut::Url(out)
}

/// Host of an http(s) URL or of `www.` text, lowercase, without userinfo, port and a leading `www.`.
fn host_of(s: &str) -> Option<String> {
    let l = s.trim().to_ascii_lowercase();
    let rest = l
        .strip_prefix("https://")
        .or_else(|| l.strip_prefix("http://"))
        .or_else(|| l.starts_with("www.").then_some(l.as_str()))?;
    let auth = rest
        .split(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace())
        .next()
        .unwrap_or("");
    let host = auth.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

struct Anchor {
    url: Option<String>,
    hidden: bool,
    start_chars: usize,
    has_image: bool,
    sample: String,
}

// ---- the converter ---------------------------------------------------------------------------

#[derive(Clone)]
struct El {
    name: LocalName,
    kind: Kind,
    gone: Option<Reason>,
    invisible: bool,
    drop: bool,
    font_px: f32,
    fg: Rgb,
    bg: Option<Rgb>,
    pre: bool,
    foreign: bool,
    raw: bool,
    quote: usize,
    list: usize,
    ol_next: i64,
    anchor: Option<usize>,
    text_hidden: Option<Reason>,
}

impl El {
    fn root() -> El {
        El {
            name: LocalName::from(""),
            kind: Kind::Line,
            gone: None,
            invisible: false,
            drop: false,
            font_px: 16.0,
            fg: Rgb::hex(0x000000),
            bg: Some(Rgb::hex(0xffffff)),
            pre: false,
            foreign: false,
            raw: false,
            quote: 0,
            list: 0,
            ol_next: 1,
            anchor: None,
            text_hidden: None,
        }
    }

    fn visible_for_layout(&self) -> bool {
        self.gone.is_none() && !self.drop
    }
}

fn hidden_reason(el: &El) -> Option<Reason> {
    if let Some(r) = el.gone {
        return Some(r);
    }
    if el.invisible {
        return Some(Reason::Visibility);
    }
    if el.font_px < MIN_FONT_PX {
        return Some(Reason::FontSize);
    }
    if el.fg.a < 0.1 {
        return Some(Reason::Transparent);
    }
    if let Some(bg) = el.bg
        && contrast(el.fg.over(bg), bg) < MIN_CONTRAST
    {
        return Some(Reason::ColorOnColor);
    }
    None
}

struct State {
    out: Out,
    stack: Vec<El>,
    overflow: usize,
    overflowed: usize,
    sheet_buf: String,
    sheet_bytes: usize,
    rules: Vec<Rule>,
    by_class: HashMap<String, Vec<usize>>,
    by_id: HashMap<String, Vec<usize>>,
    by_tag: HashMap<String, Vec<usize>>,
    anchors: Vec<Anchor>,
    open_anchor: Option<usize>,
    links: Vec<Link>,
    link_ids: HashMap<String, usize>,
    hidden_chars: [usize; 11],
    hidden_elements: usize,
}

fn attr<'a>(tag: &'a Tag, name: &str) -> Option<&'a str> {
    tag.attrs
        .iter()
        .find(|a| a.name.ns.is_empty() && &*a.name.local == name)
        .map(|a| &*a.value)
}

fn parse_int(v: &str) -> Option<i64> {
    let t = v.trim();
    let digits = t
        .strip_prefix('-')
        .or_else(|| t.strip_prefix('+'))
        .unwrap_or(t);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 || end > 9 {
        return None;
    }
    let n: i64 = digits[..end].parse().ok()?;
    Some(if t.starts_with('-') { -n } else { n }.clamp(-999_999, 999_999))
}

impl State {
    fn new(cap: usize) -> State {
        State {
            out: Out::new(cap),
            stack: vec![El::root()],
            overflow: 0,
            overflowed: 0,
            sheet_buf: String::new(),
            sheet_bytes: 0,
            rules: vec![],
            by_class: HashMap::new(),
            by_id: HashMap::new(),
            by_tag: HashMap::new(),
            anchors: vec![],
            open_anchor: None,
            links: vec![],
            link_ids: HashMap::new(),
            hidden_chars: [0; 11],
            hidden_elements: 0,
        }
    }

    fn top(&self) -> &El {
        self.stack.last().expect("root")
    }

    fn sync_prefix(&mut self) {
        let t = self.stack.last().expect("root");
        self.out.quote = t.quote;
        self.out.list = t.list;
    }

    /// Index of the nearest open element named in `names`, searching at most `limit` entries and
    /// stopping at any element in `stop`.
    fn find(&self, names: &[&str], stop: &[&str], limit: usize) -> Option<usize> {
        for (n, i) in (1..self.stack.len()).rev().enumerate() {
            if n >= limit {
                return None;
            }
            let name = &*self.stack[i].name;
            if names.contains(&name) {
                return Some(i);
            }
            if stop.contains(&name) {
                return None;
            }
        }
        None
    }

    fn pop_to(&mut self, idx: usize) {
        while self.stack.len() > idx.max(1) {
            let el = self.stack.pop().expect("non-root");
            self.close(el);
        }
        self.sync_prefix();
    }

    fn close(&mut self, el: El) {
        if el.kind == Kind::Style {
            let css = std::mem::take(&mut self.sheet_buf);
            let before = self.rules.len();
            parse_sheet(&css, &mut self.rules);
            for i in before..self.rules.len() {
                let r = &self.rules[i];
                if let Some(c) = r.classes.first() {
                    self.by_class.entry(c.clone()).or_default().push(i);
                } else if let Some(id) = &r.id {
                    self.by_id.entry(id.clone()).or_default().push(i);
                } else if let Some(t) = &r.tag {
                    self.by_tag.entry(t.clone()).or_default().push(i);
                }
            }
            return;
        }
        if let Some(ai) = el.anchor {
            self.finish_anchor(ai);
            self.open_anchor = self
                .stack
                .iter()
                .rev()
                .take(END_TAG_SEARCH)
                .find_map(|e| e.anchor);
        }
        if !el.visible_for_layout() {
            return;
        }
        match el.kind {
            Kind::Para | Kind::Quote | Kind::Pre => self.out.brk(2),
            Kind::List { .. } => self.out.brk(if el.list > 1 { 1 } else { 2 }),
            Kind::Line | Kind::Li | Kind::Row | Kind::Table => self.out.brk(1),
            Kind::Cell => self.out.want_space = true,
            _ => {}
        }
    }

    fn finish_anchor(&mut self, ai: usize) {
        let (url, hidden, start, has_image, sample) = {
            let a = &mut self.anchors[ai];
            (
                a.url.take(),
                a.hidden,
                a.start_chars,
                a.has_image,
                std::mem::take(&mut a.sample),
            )
        };
        let Some(url) = url else { return };
        // A link with nothing visible inside (hidden text, no image) is not listed: the reader of
        // the rendered message could not see or click it either.
        if hidden || (self.out.content_chars == start && !has_image) {
            return;
        }
        let num = match self.link_ids.get(&url) {
            Some(&n) => {
                let l = &mut self.links[n - 1];
                if !sample.is_empty()
                    && l.samples.len() < MAX_SAMPLES
                    && !l.samples.contains(&sample)
                {
                    l.samples.push(sample);
                }
                n
            }
            None if self.links.len() < MAX_LINKS => {
                let mismatch = match (host_of(&sample), host_of(&url)) {
                    (Some(shown), Some(real)) => shown != real,
                    _ => false,
                };
                let samples = if sample.is_empty() {
                    vec![]
                } else {
                    vec![sample]
                };
                self.links.push(Link {
                    url: url.clone(),
                    mismatch,
                    samples,
                });
                self.link_ids.insert(url, self.links.len());
                self.links.len()
            }
            None => {
                return;
            }
        };
        if self.out.content_chars == start {
            self.out.text("[link]", false);
        }
        self.out.want_space = true;
        self.out.word_boundary();
        self.out.text(&format!("[{num}]"), false);
    }

    fn matching_rules(&self, name: &str, classes: &[&str], id: Option<&str>) -> Vec<usize> {
        let mut hits = vec![];
        let matches = |r: &Rule| {
            r.tag.as_deref().is_none_or(|t| t == name)
                && r.classes.iter().all(|c| classes.contains(&c.as_str()))
                && r.id.as_deref().is_none_or(|i| Some(i) == id)
        };
        for c in classes {
            for &i in self.by_class.get(*c).into_iter().flatten() {
                if matches(&self.rules[i]) {
                    hits.push(i);
                }
            }
        }
        if let Some(id) = id {
            for &i in self.by_id.get(id).into_iter().flatten() {
                if matches(&self.rules[i]) {
                    hits.push(i);
                }
            }
        }
        for &i in self.by_tag.get(name).into_iter().flatten() {
            if matches(&self.rules[i]) {
                hits.push(i);
            }
        }
        hits.sort_unstable();
        hits.dedup();
        hits
    }

    /// Computes the element's state from its parent and attributes.
    fn element(&mut self, tag: &Tag, name: &str, kind: Kind) -> El {
        let parent = self.top().clone();
        let mut el = El {
            name: tag.name.clone(),
            kind,
            anchor: None,
            raw: false,
            ..parent.clone()
        };
        el.foreign = parent.foreign || name == "svg" || name == "math";
        el.drop = parent.drop || kind == Kind::Drop || kind == Kind::Style;
        el.pre = parent.pre || kind == Kind::Pre;
        let mut d = Decls::default();
        let class_attr = attr(tag, "class").unwrap_or("");
        let classes: Vec<String> = class_attr
            .split_ascii_whitespace()
            .take(32)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let class_refs: Vec<&str> = classes.iter().map(String::as_str).collect();
        let id = attr(tag, "id").map(|i| i.trim().to_ascii_lowercase());
        let mut sheet_hit = false;
        if !self.rules.is_empty() {
            for i in self.matching_rules(name, &class_refs, id.as_deref()) {
                d.apply(&self.rules[i].decls, true);
                sheet_hit = true;
            }
        }
        let sheet_gone = d.gone(parent.font_px).is_some() || d.visibility_hidden == Some(true);
        // Legacy presentational attributes (lower precedence than CSS).
        let mut attr_fg = None;
        let mut attr_bg = None;
        if let Some(c) = attr(tag, "color").and_then(|v| parse_color_any(v, true)) {
            attr_fg = Some(c);
        }
        if name == "body"
            && let Some(c) = attr(tag, "text").and_then(|v| parse_color_any(v, true))
        {
            attr_fg = Some(c);
        }
        if let Some(c) = attr(tag, "bgcolor").and_then(|v| parse_color_any(v, true)) {
            attr_bg = Some(Bg::Color(c));
        }
        if attr(tag, "background").is_some_and(|v| !v.trim().is_empty()) {
            attr_bg = Some(Bg::Image);
        }
        if let Some(style) = attr(tag, "style") {
            d.apply(&declarations(style, MAX_STYLE_SCAN), false);
        }
        // Font size, colours, background.
        if let Some(px) = d.font.as_deref().and_then(|f| font_size(f, parent.font_px)) {
            el.font_px = px.clamp(0.0, 1000.0);
        } else if name == "font"
            && let Some(n) = attr(tag, "size").and_then(parse_int)
        {
            el.font_px = match n {
                i64::MIN..=1 => 10.0,
                2 => 13.0,
                3 => 16.0,
                4 => 18.0,
                5 => 24.0,
                6 => 32.0,
                _ => 48.0,
            };
        }
        if let Some(c) = d.color.or(attr_fg) {
            el.fg = c;
        }
        if name == "a" && d.color.is_none() && attr_fg.is_none() {
            el.fg = Rgb::hex(0x0000ee);
        }
        match d.bg.or(attr_bg) {
            Some(Bg::Image) => el.bg = None,
            Some(Bg::Color(c)) if c.a >= 0.99 => el.bg = Some(Rgb { a: 1.0, ..c }),
            Some(Bg::Color(c)) if c.a > 0.01 => el.bg = parent.bg.map(|b| c.over(b)),
            _ => {}
        }
        // Hiding.
        if el.gone.is_none() {
            el.gone = d.gone(parent.font_px);
            if el.gone.is_none() && attr(tag, "hidden").is_some() {
                el.gone = Some(Reason::HiddenAttr);
            }
            if el.gone.is_some() && !el.drop {
                self.hidden_elements += 1;
                if sheet_hit && sheet_gone {}
            }
        }
        if let Some(v) = d.visibility_hidden {
            el.invisible = v;
        }
        el.text_hidden = hidden_reason(&el);
        el
    }

    fn open(&mut self, tag: &Tag) -> TokenSinkResult<()> {
        let name: &str = &tag.name;
        let foreign = self.top().foreign;
        // Implied closes (bounded searches).
        if !foreign {
            const SCOPE: &[&str] = &[
                "table", "td", "th", "caption", "html", "button", "object", "applet", "marquee",
                "template",
            ];
            if closes_p(name)
                && let Some(i) = self.find(&["p"], SCOPE, IMPLIED_SEARCH)
            {
                self.pop_to(i);
            }
            if is_heading(name) && is_heading(&self.top().name) {
                let n = self.stack.len() - 1;
                self.pop_to(n);
            }
            let implied: Option<(&[&str], &[&str])> = match name {
                "li" => Some((&["li"], &["ul", "ol", "menu", "table", "td", "th"])),
                "dt" | "dd" => Some((&["dt", "dd"], &["dl", "table", "td", "th"])),
                "td" | "th" => Some((&["td", "th"], &["tr", "table"])),
                "tr" => Some((&["tr"], &["table", "tbody", "thead", "tfoot"])),
                "tbody" | "thead" | "tfoot" => Some((&["tbody", "thead", "tfoot"], &["table"])),
                "option" => Some((&["option"], &["select", "datalist", "optgroup"])),
                "a" => Some((&["a"], SCOPE)),
                _ => None,
            };
            if let Some((names, stop)) = implied
                && let Some(i) = self.find(names, stop, IMPLIED_SEARCH)
            {
                self.pop_to(i);
            }
        }
        let kind = if foreign && name != "svg" && name != "math" {
            Kind::Inline
        } else {
            kind_of(name)
        };
        let void = is_void(name) || (foreign && tag.self_closing);
        // Hidden elements are still tracked (their descendants inherit the state), never emitted.
        let el = self.element(tag, name, kind);
        let shown = el.visible_for_layout();
        // Void elements.
        if void {
            if shown && !foreign {
                match name {
                    "br" => self.out.hard_break(),
                    "hr" => {
                        self.out.brk(2);
                        self.out.text("----------", false);
                        self.out.brk(2);
                    }
                    "img" | "image" => self.image(tag, &el),
                    _ => {}
                }
            }
            return TokenSinkResult::Continue;
        }
        // Block breaks and list markers before the content.
        let mut el = el;
        if shown {
            match kind {
                Kind::Para | Kind::Pre => self.out.brk(2),
                Kind::Quote => {
                    self.out.brk(2);
                    el.quote += 1;
                }
                Kind::List { .. } => {
                    self.out.brk(if el.list > 0 { 1 } else { 2 });
                    el.list += 1;
                    el.ol_next = attr(tag, "start").and_then(parse_int).unwrap_or(1);
                }
                Kind::Li => {
                    self.out.brk(1);
                    let list = self.find(&["ul", "ol", "menu", "dir"], &[], END_TAG_SEARCH);
                    let marker = match list {
                        Some(i) if &*self.stack[i].name == "ol" => {
                            let n = attr(tag, "value")
                                .and_then(parse_int)
                                .unwrap_or(self.stack[i].ol_next);
                            self.stack[i].ol_next = n.saturating_add(1);
                            format!("{n}. ")
                        }
                        _ => "\u{2022} ".to_string(),
                    };
                    if list.is_none() {
                        el.list += 1;
                    }
                    self.out.marker = Some(marker);
                }
                Kind::Line | Kind::Row | Kind::Table => self.out.brk(1),
                Kind::Cell => {
                    if !self.out.at_line_start() && self.out.want_breaks == 0 {
                        self.out.want_sep = true;
                    }
                }
                _ => {}
            }
        }
        if kind == Kind::Anchor {
            let url = attr(tag, "href").and_then(|h| match link_target(h) {
                LinkOut::Url(u) => Some(u),
                LinkOut::Scheme | LinkOut::TooLong => None,
            });
            self.anchors.push(Anchor {
                url,
                hidden: el.text_hidden.is_some() || el.drop,
                start_chars: self.out.content_chars,
                has_image: false,
                sample: String::new(),
            });
            el.anchor = Some(self.anchors.len() - 1);
        }
        // Raw-text elements switch the tokenizer state (HTML content only).
        let raw = if foreign {
            None
        } else {
            match name {
                "script" => Some(TokenSinkResult::RawData(RawKind::ScriptData)),
                "style" | "xmp" | "iframe" | "noembed" | "noframes" => {
                    Some(TokenSinkResult::RawData(RawKind::Rawtext))
                }
                "title" | "textarea" => Some(TokenSinkResult::RawData(RawKind::Rcdata)),
                "plaintext" => Some(TokenSinkResult::Plaintext),
                _ => None,
            }
        };
        // Raw-text elements are pushed even beyond the cap: they cannot contain elements and are
        // closed by their own end tag, and their content must stay classified (script, style).
        el.raw = raw.is_some();
        if self.stack.len() > MAX_DEPTH && raw.is_none() {
            self.overflow += 1;
            self.overflowed += 1;
        } else {
            if el.anchor.is_some() {
                self.open_anchor = el.anchor;
            }
            self.stack.push(el);
            self.sync_prefix();
        }
        raw.unwrap_or(TokenSinkResult::Continue)
    }

    fn image(&mut self, tag: &Tag, el: &El) {
        if el.text_hidden.is_some() {
            return;
        }
        let small = |k: &str| {
            attr(tag, k)
                .and_then(|v| len_px(v, el.font_px))
                .is_some_and(|px| px <= 2.0)
        };
        if small("width") || small("height") {
            return;
        }
        if let Some(ai) = self.open_anchor {
            self.anchors[ai].has_image = true;
        }
        let alt = attr(tag, "alt").map(str::trim).unwrap_or("");
        if alt.is_empty() {
            return;
        }
        let alt: String = alt.chars().take(MAX_ALT_CHARS).collect();
        self.out.text("[", false);
        self.out.text(&alt, false);
        self.out.text("]", false);
        if let Some(ai) = self.open_anchor {
            push_sample(&mut self.anchors[ai].sample, &alt);
        }
    }

    fn end_tag(&mut self, tag: &Tag) {
        let name: &str = &tag.name;
        if name == "br" {
            if self.top().visible_for_layout() {
                self.out.hard_break();
            }
            return;
        }
        if self.overflow > 0 {
            // Beyond MAX_DEPTH only raw-text elements are on the stack; anything else just
            // balances an element that was never pushed.
            if self.top().raw && &*self.top().name == name {
                let n = self.stack.len() - 1;
                self.pop_to(n);
            } else {
                self.overflow -= 1;
            }
            return;
        }
        if matches!(name, "body" | "html" | "head") {
            if name == "head"
                && let Some(i) = self.find(&["head"], &[], END_TAG_SEARCH)
            {
                self.pop_to(i);
            }
            return;
        }
        let found = if is_heading(name) {
            self.find(&["h1", "h2", "h3", "h4", "h5", "h6"], &[], END_TAG_SEARCH)
        } else {
            self.find(&[name], &[], END_TAG_SEARCH)
        };
        match found {
            Some(i) => self.pop_to(i),
            None if name == "p" && self.top().visible_for_layout() => self.out.brk(2),
            None => {}
        }
    }

    fn chars(&mut self, t: &str) {
        let top = self.top();
        if top.kind == Kind::Style && self.sheet_bytes < MAX_SHEET_BYTES {
            let room = MAX_SHEET_BYTES - self.sheet_bytes;
            let mut end = t.len().min(room);
            while !t.is_char_boundary(end) {
                end -= 1;
            }
            self.sheet_buf.push_str(&t[..end]);
            self.sheet_bytes += end;
            return;
        }
        if top.drop {
            return;
        }
        if let Some(r) = top.text_hidden {
            let n = t.chars().filter(|c| !c.is_whitespace()).count();
            let slot = REASONS.iter().position(|(_, x)| *x == r).expect("reason");
            self.hidden_chars[slot] += n;
            return;
        }
        let pre = top.pre;
        self.out.text(t, pre);
        if let Some(ai) = self.open_anchor {
            push_sample(&mut self.anchors[ai].sample, t);
        }
    }

    fn finish(mut self) -> TextOut {
        self.pop_to(1);
        let truncated = self.out.truncated;
        let mut text = std::mem::take(&mut self.out.s);
        let body_len = text.trim_end().len();
        text.truncate(body_len);
        if truncated {
            text.push_str("\n\n");
            text.push_str(TRUNCATED_MARK);
        }
        if !self.links.is_empty() {
            if !text.is_empty() {
                text.push_str("\n\n");
            }
            text.push_str("Links:");
            for (i, l) in self.links.iter().enumerate() {
                text.push_str(&format!(
                    "\n[{}] {}{}",
                    i + 1,
                    l.url,
                    if l.mismatch { MISMATCH_NOTE } else { "" }
                ));
            }
        }
        if !text.is_empty() {
            text.push('\n');
        }
        let r = &self.out.removed;
        let mut hidden: Vec<(Hidden, u32)> = Vec::new();
        let mut add = |reason: Hidden, n: usize| {
            if n == 0 {
                return;
            }
            let n = u32::try_from(n).unwrap_or(u32::MAX);
            match hidden.iter_mut().find(|(h, _)| *h == reason) {
                Some((_, c)) => *c = c.saturating_add(n),
                None => hidden.push((reason, n)),
            }
        };
        for (i, (h, _)) in REASONS.iter().enumerate() {
            add(*h, self.hidden_chars[i]);
        }
        add(
            Hidden::InvisibleChar,
            r.invisible + r.joiner + r.tag + r.varsel,
        );
        add(Hidden::BidiControl, r.bidi);
        hidden.sort_by_key(|(h, _)| *h as i32);
        let hidden_chars = self.hidden_chars.iter().sum::<usize>();
        TextOut {
            text,
            links: self.links,
            hidden,
            hidden_chars: u32::try_from(hidden_chars).unwrap_or(u32::MAX),
            dropped_elements: u32::try_from(self.hidden_elements + self.overflowed)
                .unwrap_or(u32::MAX),
            truncated,
        }
    }
}

/// One listed link: the printable-ASCII target, the mismatch flag and visible text samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub url: String,
    pub mismatch: bool,
    pub samples: Vec<String>,
}

fn push_sample(sample: &mut String, t: &str) {
    for c in t.chars() {
        if sample.len() >= 256 {
            return;
        }
        sample.push(c);
    }
}

struct Sink {
    st: RefCell<State>,
}

impl TokenSink for Sink {
    type Handle = ();

    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        let mut st = self.st.borrow_mut();
        match token {
            Token::TagToken(tag) => match tag.kind {
                TagKind::StartTag => return st.open(&tag),
                TagKind::EndTag => st.end_tag(&tag),
            },
            Token::CharacterTokens(t) => st.chars(&t),
            Token::NullCharacterToken => {}
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

pub struct TextOut {
    pub text: String,
    /// Listed links in number order (`links[i]` is `[i + 1]` in the text).
    pub links: Vec<Link>,
    /// Hidden characters by manifest reason, reasons with a non-zero count only, reason order.
    pub hidden: Vec<(Hidden, u32)>,
    /// Characters hidden by the style rules (not counting removed format characters).
    pub hidden_chars: u32,
    pub dropped_elements: u32,
    pub truncated: bool,
}

fn ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

fn find(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    b.get(from..)?
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + from)
}

/// End of a comment body starting at `from`: just past the first `-->` or `--!>` (linear).
fn comment_end(b: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(p) = find(b, i, b"--") {
        if b.get(p + 2) == Some(&b'>') {
            return p + 3;
        }
        if b[p + 2..].starts_with(b"!>") {
            return p + 4;
        }
        i = p + 1;
    }
    b.len()
}

/// Raw-text end: `</name` (ASCII case-insensitive) followed by whitespace, `/` or `>`.
fn raw_end(b: &[u8], from: usize, name: &[u8]) -> usize {
    let mut i = from;
    while let Some(p) = find(b, i, b"</") {
        let s = p + 2;
        let e = s + name.len();
        if e <= b.len()
            && b[s..e].eq_ignore_ascii_case(name)
            && (e == b.len() || ws(b[e]) || b[e] == b'/' || b[e] == b'>')
        {
            return p;
        }
        i = p + 2;
    }
    b.len()
}

/// Linear pre-pass that keeps at most MAX_ATTRS attributes per tag (the rest of the tag up to its
/// `>` is dropped). It follows the tokenizer's tag, attribute, comment and raw-text boundaries; where
/// it diverges (foreign content) the effect is limited to which attributes survive. Cuts start at an
/// attribute name and end before an ASCII `>`, so the result stays valid UTF-8.
fn cap_attributes(input: &str) -> (Cow<'_, str>, usize) {
    let b = input.as_bytes();
    let n = b.len();
    let mut out: Option<String> = None;
    let (mut copied, mut capped, mut i) = (0usize, 0usize, 0usize);
    while i < n {
        let Some(lt) = b[i..].iter().position(|&c| c == b'<') else {
            break;
        };
        i += lt;
        if b[i..].starts_with(b"<!--") {
            let s = i + 4;
            i = if b[s..].starts_with(b">") {
                s + 1
            } else if b[s..].starts_with(b"->") {
                s + 2
            } else {
                comment_end(b, s)
            };
            continue;
        }
        if i + 1 < n && (b[i + 1] == b'!' || b[i + 1] == b'?') {
            i = find(b, i + 1, b">").map_or(n, |p| p + 1);
            continue;
        }
        let mut j = i + 1;
        let end_tag = j < n && b[j] == b'/';
        if end_tag {
            j += 1;
        }
        if !(j < n && b[j].is_ascii_alphabetic()) {
            i += 1;
            continue;
        }
        let name_start = j;
        while j < n && !ws(b[j]) && b[j] != b'/' && b[j] != b'>' {
            j += 1;
        }
        let name = &b[name_start..j];
        let (mut count, mut cut) = (0usize, None);
        loop {
            while j < n && (ws(b[j]) || b[j] == b'/') {
                j += 1;
            }
            if j >= n || b[j] == b'>' {
                break;
            }
            count += 1;
            if count == MAX_ATTRS + 1 {
                cut = Some(j);
            }
            j += 1;
            while j < n && !ws(b[j]) && b[j] != b'/' && b[j] != b'>' && b[j] != b'=' {
                j += 1;
            }
            let mut k = j;
            while k < n && ws(b[k]) {
                k += 1;
            }
            if k < n && b[k] == b'=' {
                k += 1;
                while k < n && ws(b[k]) {
                    k += 1;
                }
                if k < n && (b[k] == b'"' || b[k] == b'\'') {
                    let q = b[k];
                    k = b[k + 1..]
                        .iter()
                        .position(|&c| c == q)
                        .map_or(n, |p| k + 1 + p + 1);
                } else {
                    while k < n && !ws(b[k]) && b[k] != b'>' {
                        k += 1;
                    }
                }
                j = k;
            }
        }
        if let Some(c) = cut {
            let o = out.get_or_insert_with(|| String::with_capacity(n));
            o.push_str(&input[copied..c]);
            copied = j.min(n);
            capped += 1;
        }
        i = (j + 1).min(n);
        if !end_tag {
            let raw: &[&[u8]] = &[
                b"script",
                b"style",
                b"xmp",
                b"iframe",
                b"noembed",
                b"noframes",
                b"textarea",
                b"title",
            ];
            if raw.iter().any(|r| name.eq_ignore_ascii_case(r)) {
                i = raw_end(b, i, name);
            } else if name.eq_ignore_ascii_case(b"plaintext") {
                break;
            }
        }
    }
    match out {
        Some(mut o) => {
            o.push_str(&input[copied..]);
            (Cow::Owned(o), capped)
        }
        None => (Cow::Borrowed(input), 0),
    }
}

/// Converts one HTML part. `input` is already UTF-8 (the helper decodes lossily).
pub fn html_to_text(input: &str) -> TextOut {
    let (capped_input, _) = cap_attributes(input);
    let input: &str = &capped_input;
    let tok = Tokenizer::new(
        Sink {
            st: RefCell::new(State::new(TEXT_CAP)),
        },
        TokenizerOpts::default(),
    );
    let q = BufferQueue::default();
    let mut rest = input;
    let mut stopped = false;
    while !rest.is_empty() {
        let mut cut = rest.len().min(CHUNK);
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        q.push_back(StrTendril::from_slice(&rest[..cut]));
        rest = &rest[cut..];
        let _ = tok.feed(&q);
        if tok.sink.st.borrow().out.truncated {
            stopped = true;
            break;
        }
    }
    if !stopped {
        tok.end();
    }
    let Sink { st } = tok.sink;
    let st = st.into_inner();
    st.finish()
}
