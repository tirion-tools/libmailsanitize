//! CSS handling on top of lightningcss: sanitizing re-serialisation, the dark-policy
//! recolouring visitor, and background/foreground scans used for DOM context.

use std::convert::Infallible;

use lightningcss::declaration::DeclarationBlock;
use lightningcss::properties::Property;
use lightningcss::rules::{CssRule, CssRuleList};
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleAttribute, StyleSheet};
use lightningcss::traits::{Parse, ToCss};
use lightningcss::values::color::{CssColor, RGBA};
use lightningcss::values::url::Url;
use lightningcss::visit_types;
use lightningcss::visitor::{Visit, VisitTypes, Visitor};

use crate::color::{CANVAS, Rgb, Role, map};

const WHITE: Rgb = Rgb::hex(0xffffff);

pub fn parse_color(s: &str) -> Option<Rgb> {
    CssColor::parse_string(s).ok().and_then(|c| to_rgb(&c))
}

fn to_rgb(c: &CssColor) -> Option<Rgb> {
    match c {
        CssColor::CurrentColor | CssColor::System(..) | CssColor::LightDark(..) => None,
        _ => RGBA::try_from(c)
            .ok()
            .map(|x| Rgb::from_u8(x.red, x.green, x.blue, x.alpha_f32())),
    }
}

fn to_css_color(c: Rgb) -> CssColor {
    let (r, g, b) = c.to_u8();
    CssColor::RGBA(RGBA::new(r, g, b, c.a))
}

fn parser_options<'i>() -> ParserOptions<'i> {
    ParserOptions {
        error_recovery: true,
        ..ParserOptions::default()
    }
}

fn printer() -> PrinterOptions<'static> {
    PrinterOptions {
        minify: true,
        ..PrinterOptions::default()
    }
}

/// A sheet printed for a `<style>` element. Every sheet that reaches the document is printed here.
fn sheet_html(sheet: &StyleSheet) -> String {
    sheet
        .to_css(printer())
        .map(|r| html_inert(&r.code))
        .unwrap_or_default()
}

/// A declaration block printed for a `style` attribute. Every block that reaches the document is
/// printed here.
fn attr_html(attr: &StyleAttribute) -> Option<String> {
    attr.to_css(printer()).ok().map(|r| html_inert(&r.code))
}

/// Printed CSS made inert as HTML. lightningcss decodes escapes and prints what they stand for
/// (`"\3c/style\3e"` prints as `"</style>"`), and a `</style` in a sheet ends the element in every
/// HTML parser, so the rest of the sheet would be parsed as markup. A `<` starts markup only when a
/// letter, `/`, `!` or `?` follows it, so none does here: in a string and after a backslash the
/// `<` becomes the escape `\3c `, and a bare `<` (a delim, as in `@media (400px<width)`) gets a
/// space after it. The CSS means the same.
fn html_inert(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut quote = None;
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quote) {
            ('\\', _) => match chars.next() {
                Some('<') => out.push_str("\\3c "),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            ('<', Some(_)) => out.push_str("\\3c "),
            ('<', None) => {
                out.push('<');
                if chars
                    .peek()
                    .is_some_and(|n| n.is_ascii_alphabetic() || matches!(n, '/' | '!' | '?'))
                {
                    out.push(' ');
                }
            }
            ('"' | '\'', None) => {
                quote = Some(c);
                out.push(c);
            }
            (_, Some(q)) if c == q => {
                quote = None;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn role_for(name: &str) -> Role {
    match name {
        "color"
        | "text-fill-color"
        | "text-stroke-color"
        | "text-decoration-color"
        | "text-decoration"
        | "text-emphasis-color"
        | "text-emphasis"
        | "caret-color"
        | "fill"
        | "stroke" => Role::Foreground,
        n if n.starts_with("border")
            || n.starts_with("outline")
            || n.starts_with("column-rule") =>
        {
            Role::Border
        }
        _ => Role::Background,
    }
}

// ---------------------------------------------------------------------------
// Sanitizing re-serialisation (the CSS allowlist).
// ---------------------------------------------------------------------------

const DENIED_PROPERTIES: &[&str] = &[
    "position",
    "behavior",
    "z-index",
    "animation",
    "transition",
    "cursor",
    "content",
];

struct UrlCheck {
    unsafe_url: bool,
}

impl<'i> Visitor<'i> for UrlCheck {
    type Error = Infallible;
    fn visit_types(&self) -> VisitTypes {
        visit_types!(URLS)
    }
    fn visit_url(&mut self, url: &mut Url<'i>) -> Result<(), Self::Error> {
        let u = url.url.trim_start().to_ascii_lowercase();
        if !(u.starts_with("data:image/png;base64,") || u.starts_with("data:image/jpeg;base64,")) {
            self.unsafe_url = true;
        }
        Ok(())
    }
}

fn property_allowed(p: &mut Property) -> bool {
    let id = p.property_id();
    let name = id.name();
    if DENIED_PROPERTIES.iter().any(|d| name.starts_with(d)) {
        return false;
    }
    let mut check = UrlCheck { unsafe_url: false };
    let _ = p.visit(&mut check);
    !check.unsafe_url
}

struct Sanitizer;

impl<'i> Visitor<'i> for Sanitizer {
    type Error = Infallible;
    fn visit_types(&self) -> VisitTypes {
        visit_types!(RULES | PROPERTIES)
    }
    fn visit_rule_list(&mut self, rules: &mut CssRuleList<'i>) -> Result<(), Self::Error> {
        rules
            .0
            .retain(|r| matches!(r, CssRule::Style(_) | CssRule::Media(_)));
        rules.visit_children(self)
    }
    fn visit_declaration_block(
        &mut self,
        decls: &mut DeclarationBlock<'i>,
    ) -> Result<(), Self::Error> {
        decls.declarations.retain_mut(property_allowed);
        decls.important_declarations.retain_mut(property_allowed);
        Ok(())
    }
}

pub fn sanitize_stylesheet(css: &str) -> String {
    let Ok(mut sheet) = StyleSheet::parse(css, parser_options()) else {
        return String::new();
    };
    let _ = sheet.visit(&mut Sanitizer);
    sheet_html(&sheet)
}

pub fn sanitize_style_attr(value: &str) -> Option<String> {
    let mut attr = StyleAttribute::parse(value, parser_options()).ok()?;
    let _ = Sanitizer.visit_declaration_block(&mut attr.declarations);
    let code = attr_html(&attr)?;
    if code.is_empty() { None } else { Some(code) }
}

// ---------------------------------------------------------------------------
// Context scan: which background / text colour does a declaration block set?
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct BlockColors {
    /// First non-transparent colour in a background-* declaration (colour or gradient stop).
    pub bg: Option<Rgb>,
    /// A url() background image is present: text sits on an image.
    pub image: bool,
    /// Value of `color`, when set.
    pub fg: Option<Rgb>,
}

#[derive(Default)]
struct Scan {
    active: Option<Role>,
    in_background: bool,
    out: BlockColors,
}

impl<'i> Visitor<'i> for Scan {
    type Error = Infallible;
    fn visit_types(&self) -> VisitTypes {
        visit_types!(PROPERTIES | COLORS | URLS)
    }
    fn visit_property(&mut self, p: &mut Property<'i>) -> Result<(), Self::Error> {
        let id = p.property_id();
        let name = id.name();
        self.in_background = name.starts_with("background");
        self.active = if self.in_background {
            Some(Role::Background)
        } else if name == "color" {
            Some(Role::Foreground)
        } else {
            None
        };
        if self.active.is_some() {
            p.visit_children(self)?;
        }
        Ok(())
    }
    fn visit_color(&mut self, c: &mut CssColor) -> Result<(), Self::Error> {
        if let Some(rgb) = to_rgb(c) {
            match self.active {
                Some(Role::Background) if rgb.a > 0.001 && self.out.bg.is_none() => {
                    self.out.bg = Some(rgb)
                }
                Some(Role::Foreground) => self.out.fg = Some(rgb),
                _ => {}
            }
        }
        Ok(())
    }
    fn visit_url(&mut self, _url: &mut Url<'i>) -> Result<(), Self::Error> {
        if self.in_background {
            self.out.image = true;
        }
        Ok(())
    }
}

pub fn scan_block(decls: &mut DeclarationBlock) -> BlockColors {
    let mut scan = Scan::default();
    let _ = decls.visit(&mut scan);
    scan.out
}

pub fn scan_style_attr(value: &str) -> BlockColors {
    match StyleAttribute::parse(value, parser_options()) {
        Ok(mut a) => scan_block(&mut a.declarations),
        Err(_) => BlockColors::default(),
    }
}

// ---------------------------------------------------------------------------
// Recolouring visitor.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub colors_seen: u32,
    pub colors_rewritten: u32,
    pub fg_contrast_fixes: u32,
    pub injected_text_colors: u32,
    pub image_backdrops: u32,
    pub sender_dark_rules_kept: u32,
}

/// A rule whose selectors are all simple compounds (`tag`, `.class`, `#id`, `tag.class`).
#[derive(Clone, Debug)]
pub struct SimpleRule {
    pub selectors: Vec<Compound>,
    pub colors: BlockColors,
}

#[derive(Clone, Debug, Default)]
pub struct Compound {
    pub tag: Option<String>,
    pub classes: Vec<String>,
    pub id: Option<String>,
}

impl Compound {
    pub fn matches(&self, tag: &str, classes: &[&str], id: Option<&str>) -> bool {
        self.tag
            .as_deref()
            .is_none_or(|t| t.eq_ignore_ascii_case(tag))
            && self.classes.iter().all(|c| classes.contains(&c.as_str()))
            && self.id.as_deref().is_none_or(|i| Some(i) == id)
    }
}

fn parse_compound(s: &str) -> Option<Compound> {
    let s = s.trim();
    let s = s
        .strip_suffix(":link")
        .or_else(|| s.strip_suffix(":visited"))
        .unwrap_or(s);
    if s.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || matches!(c, '>' | '+' | '~' | ':' | '[' | '*' | '('))
    {
        return None;
    }
    let mut out = Compound::default();
    let mut rest = s;
    let first_mark = rest.find(['.', '#']).unwrap_or(rest.len());
    if first_mark > 0 {
        out.tag = Some(rest[..first_mark].to_ascii_lowercase());
    }
    rest = &rest[first_mark..];
    while !rest.is_empty() {
        let kind = rest.as_bytes()[0];
        let body = &rest[1..];
        let end = body.find(['.', '#']).unwrap_or(body.len());
        let name = body[..end].to_string();
        if name.is_empty() {
            return None;
        }
        if kind == b'.' {
            out.classes.push(name)
        } else {
            out.id = Some(name)
        }
        rest = &body[end..];
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// Rewrite colours.
    Transform,
    /// Only detect sender dark CSS and collect simple rules (hybrid preflight).
    Scan,
}

pub struct Recolor {
    mode: Mode,
    role: Role,
    ctx_bg: Rgb,
    ctx_orig_bg: Rgb,
    image_ctx: bool,
    pub sender_dark: bool,
    pub simple: Vec<SimpleRule>,
    pub stats: Stats,
}

impl Recolor {
    pub fn new(mode: Mode, ctx_bg: Rgb, ctx_orig_bg: Rgb, image_ctx: bool) -> Recolor {
        Recolor {
            mode,
            role: Role::Background,
            ctx_bg,
            ctx_orig_bg,
            image_ctx,
            sender_dark: false,
            simple: Vec::new(),
            stats: Stats::default(),
        }
    }
}

fn is_dark_media(q: &str) -> bool {
    let q = q.to_ascii_lowercase();
    q.contains("prefers-color-scheme") && q.contains("dark")
}

/// Dark-only queries the transform can resolve statically (no other conditions).
fn is_plain_dark_media(q: &str) -> bool {
    let q: String = q
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    matches!(
        q.as_str(),
        "(prefers-color-scheme:dark)"
            | "screenand(prefers-color-scheme:dark)"
            | "onlyscreenand(prefers-color-scheme:dark)"
            | "alland(prefers-color-scheme:dark)"
    )
}

fn media_query(m: &lightningcss::rules::media::MediaRule) -> String {
    m.query
        .to_css_string(PrinterOptions::default())
        .unwrap_or_default()
}

impl<'i> Visitor<'i> for Recolor {
    type Error = Infallible;
    fn visit_types(&self) -> VisitTypes {
        visit_types!(RULES | PROPERTIES | COLORS)
    }
    fn visit_rule_list(&mut self, rules: &mut CssRuleList<'i>) -> Result<(), Self::Error> {
        if self.mode == Mode::Scan {
            return rules.visit_children(self);
        }
        // The sender's own dark design is resolved statically: plain
        // `@media (prefers-color-scheme: dark)` blocks are unwrapped in place (kept verbatim,
        // not recoloured), so the document no longer depends on CEF's prefers-color-scheme.
        let old = std::mem::take(&mut rules.0);
        let mut out = Vec::with_capacity(old.len());
        for rule in old {
            match rule {
                CssRule::Media(m) if is_dark_media(&media_query(&m)) => {
                    self.sender_dark = true;
                    self.stats.sender_dark_rules_kept += m.rules.0.len() as u32;
                    if is_plain_dark_media(&media_query(&m)) {
                        out.extend(m.rules.0);
                    } else {
                        out.push(CssRule::Media(m));
                    }
                }
                mut other => {
                    self.visit_rule(&mut other)?;
                    out.push(other);
                }
            }
        }
        rules.0 = out;
        Ok(())
    }
    fn visit_rule(&mut self, rule: &mut CssRule<'i>) -> Result<(), Self::Error> {
        match rule {
            CssRule::Media(m) => {
                let query = m
                    .query
                    .to_css_string(PrinterOptions::default())
                    .unwrap_or_default();
                if is_dark_media(&query) {
                    // The sender's own dark design: kept verbatim and applied by prefers-color-scheme.
                    self.sender_dark = true;
                    self.stats.sender_dark_rules_kept += m.rules.0.len() as u32;
                    return Ok(());
                }
                m.rules.visit(self)
            }
            CssRule::Style(s) => {
                let colors = scan_block(&mut s.declarations);
                let selectors = s
                    .selectors
                    .to_css_string(PrinterOptions::default())
                    .unwrap_or_default();
                let compounds: Option<Vec<Compound>> =
                    selectors.split(',').map(parse_compound).collect();
                if let Some(selectors) = compounds
                    && (colors.bg.is_some() || colors.fg.is_some() || colors.image)
                {
                    self.simple.push(SimpleRule {
                        selectors,
                        colors: colors.clone(),
                    });
                }
                if self.mode == Mode::Scan {
                    return Ok(());
                }
                let saved = (self.ctx_bg, self.ctx_orig_bg, self.image_ctx);
                if let Some(bg) = colors.bg {
                    self.ctx_bg = crate::color::map_bg(bg).over(CANVAS);
                    self.ctx_orig_bg = bg.over(WHITE);
                }
                self.image_ctx |= colors.image;
                s.declarations.visit(self)?;
                s.rules.visit(self)?;
                (self.ctx_bg, self.ctx_orig_bg, self.image_ctx) = saved;
                Ok(())
            }
            _ => rule.visit_children(self),
        }
    }
    fn visit_property(&mut self, p: &mut Property<'i>) -> Result<(), Self::Error> {
        if self.mode == Mode::Scan {
            return Ok(());
        }
        let id = p.property_id();
        self.role = role_for(id.name());
        p.visit_children(self)
    }
    fn visit_color(&mut self, c: &mut CssColor) -> Result<(), Self::Error> {
        if self.mode == Mode::Scan {
            return Ok(());
        }
        let Some(rgb) = to_rgb(c) else { return Ok(()) };
        self.stats.colors_seen += 1;
        if self.role == Role::Foreground && self.image_ctx {
            return Ok(()); // text designed for a background image: keep the sender's colour
        }
        let new = map(rgb, self.role, self.ctx_bg, self.ctx_orig_bg);
        if new != rgb {
            *c = to_css_color(new);
            self.stats.colors_rewritten += 1;
            if self.role == Role::Foreground {
                self.stats.fg_contrast_fixes += 1;
            }
        }
        Ok(())
    }
}

pub struct SheetResult {
    pub css: String,
    pub sender_dark: bool,
    pub simple: Vec<SimpleRule>,
    pub stats: Stats,
}

pub fn process_stylesheet(css: &str, mode: Mode) -> SheetResult {
    let Ok(mut sheet) = StyleSheet::parse(css, parser_options()) else {
        return SheetResult {
            css: String::new(),
            sender_dark: false,
            simple: Vec::new(),
            stats: Stats::default(),
        };
    };
    let mut v = Recolor::new(mode, CANVAS, WHITE, false);
    let _ = sheet.visit(&mut v);
    let css = if mode == Mode::Transform {
        sheet_html(&sheet)
    } else {
        css.to_string()
    };
    SheetResult {
        css,
        sender_dark: v.sender_dark,
        simple: v.simple,
        stats: v.stats,
    }
}

/// Recolours an inline style attribute in the given context. Returns the new value and stats.
pub fn recolor_style_attr(
    value: &str,
    ctx_bg: Rgb,
    ctx_orig_bg: Rgb,
    image_ctx: bool,
    stats: &mut Stats,
) -> Option<String> {
    let mut attr = StyleAttribute::parse(value, parser_options()).ok()?;
    let mut v = Recolor::new(Mode::Transform, ctx_bg, ctx_orig_bg, image_ctx);
    let _ = attr.declarations.visit(&mut v);
    stats.colors_seen += v.stats.colors_seen;
    stats.colors_rewritten += v.stats.colors_rewritten;
    stats.fg_contrast_fixes += v.stats.fg_contrast_fixes;
    attr_html(&attr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printed_css_opens_no_markup() {
        for (printed, inert) in [
            // Strings: the escape, which means the same character.
            (r#"a{b:"</style><x>"}"#, r#"a{b:"\3c /style>\3c x>"}"#),
            (r#"a{b:'<a'}"#, r#"a{b:'\3c a'}"#),
            // An escaped `<` in an identifier.
            (r".a\<script{b:c}", r".a\3c script{b:c}"),
            // Delims: a space after the `<` unless a comparison or a number follows.
            ("a{b:</style>}", "a{b:< /style>}"),
            ("a{b:<!--}", "a{b:< !--}"),
            ("a{b:<?x}", "a{b:< ?x}"),
            (
                "@media (width<=600px){a{b:c}}",
                "@media (width<=600px){a{b:c}}",
            ),
            (
                "@media (400px<width<700px){a{b:c}}",
                "@media (400px< width<700px){a{b:c}}",
            ),
            // A quote inside a string of the other kind, and an escaped quote.
            (r#"a{b:"'<x",c:<y}"#, r#"a{b:"'\3c x",c:< y}"#),
            (r#"a{b:"\"<x"}"#, r#"a{b:"\"\3c x"}"#),
            (r"a{b:c\\}", r"a{b:c\\}"),
        ] {
            assert_eq!(html_inert(printed), inert, "{printed}");
        }
    }

    #[test]
    fn escapes_print_inert_in_sheets_and_attributes() {
        let sheet = sanitize_stylesheet(
            r#"a{font-family:"\3c/style\3e\3cscript\3e"}b[title="\3c/style\3e"]{color:red}c{--x:"\3c/style\3e"}"#,
        );
        assert!(!sheet.contains("</") && !sheet.contains("<s"), "{sheet}");
        assert!(
            sheet.contains(r#"font-family:"\3c /style>\3c script>""#),
            "{sheet}"
        );
        let attr = sanitize_style_attr(r#"font-family:"\3cscript\3e""#).expect("kept");
        assert_eq!(attr, r#"font-family:"\3c script>""#);
        let dark = process_stylesheet(r#"a{font-family:"\3c/style\3e"}"#, Mode::Transform).css;
        assert!(!dark.contains("</"), "{dark}");
        let recolored = recolor_style_attr(
            r#"font-family:"\3c/style\3e""#,
            CANVAS,
            WHITE,
            false,
            &mut Stats::default(),
        )
        .expect("kept");
        assert!(!recolored.contains("</"), "{recolored}");
    }
}
