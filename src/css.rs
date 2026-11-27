//! CSS handling on top of lightningcss: sanitizing re-serialisation, the recolouring visitor (dark
//! policy or fixed palette), and background/foreground scans used for DOM context.

use std::convert::Infallible;

use lightningcss::declaration::DeclarationBlock;
use lightningcss::properties::Property;
use lightningcss::properties::custom::{CustomPropertyName, Token, TokenList, TokenOrValue};
use lightningcss::rules::{CssRule, CssRuleList};
use lightningcss::selector::{Component, PseudoClass, SelectorList};
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleAttribute, StyleSheet};
use lightningcss::traits::{Parse, ToCss};
use lightningcss::values::color::{CssColor, RGBA};
use lightningcss::values::image::Image;
use lightningcss::values::url::Url;
use lightningcss::visit_types;
use lightningcss::visitor::{Visit, VisitTypes, Visitor};

use crate::color::{CANVAS, Policy, Rgb, Role, map};

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

/// Rewrites inline image URLs to their resource reference (`crate::sanitize::map_css_url`) and
/// flags any other URL, and every `image-set()`: lightningcss's visitor skips the images of an
/// image set, so neither its `url()` nor its string sources (`image-set("data:…" 1x)`) would be
/// checked.
struct UrlCheck {
    unsafe_url: bool,
}

impl<'i> Visitor<'i> for UrlCheck {
    type Error = Infallible;
    fn visit_types(&self) -> VisitTypes {
        visit_types!(URLS | IMAGES)
    }
    fn visit_url(&mut self, url: &mut Url<'i>) -> Result<(), Self::Error> {
        match crate::sanitize::map_css_url(&url.url) {
            Some(mapped) => url.url = mapped.into(),
            None => self.unsafe_url = true,
        }
        Ok(())
    }
    fn visit_image(&mut self, image: &mut Image<'i>) -> Result<(), Self::Error> {
        if matches!(image, Image::ImageSet(_)) {
            self.unsafe_url = true;
            return Ok(());
        }
        image.visit_children(self)
    }
}

/// Functions whose arguments a browser reads as images, strings included (`image-set("…")`), or
/// that paint something other than an image URL.
const IMAGE_FUNCTIONS: &[&str] = &[
    "image-set",
    "-webkit-image-set",
    "cross-fade",
    "-webkit-cross-fade",
    "image",
    "element",
    "-moz-element",
    "paint",
    "-webkit-canvas",
];

/// A token list (an unparsed or unknown property's value) that could load an image the URL check
/// never sees: a string token (an image source inside `image-set()`), a raw or unparsed URL token,
/// an image function, or a `var()`/`env()` (whose value is substituted after sanitizing).
fn risky_tokens(tokens: &TokenList) -> bool {
    tokens.0.iter().any(|t| match t {
        TokenOrValue::Token(
            Token::String(_) | Token::UnquotedUrl(_) | Token::BadUrl(_) | Token::Function(_),
        )
        | TokenOrValue::Var(_)
        | TokenOrValue::Env(_) => true,
        TokenOrValue::Function(f) => {
            IMAGE_FUNCTIONS
                .iter()
                .any(|n| f.name.0.eq_ignore_ascii_case(n))
                || risky_tokens(&f.arguments)
        }
        _ => false,
    })
}

fn property_allowed(p: &mut Property) -> bool {
    let id = p.property_id();
    let name = id.name();
    if DENIED_PROPERTIES.iter().any(|d| name.starts_with(d)) {
        return false;
    }
    // Custom properties (`--x`) only matter through var(), which is dropped below; dropping both
    // keeps a value from reaching an image property after the URL check (image-set strings).
    match p {
        Property::Custom(c) => {
            if matches!(c.name, CustomPropertyName::Custom(_)) || risky_tokens(&c.value) {
                return false;
            }
        }
        Property::Unparsed(u) => {
            if risky_tokens(&u.value) {
                return false;
            }
        }
        _ => {}
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

/// The part of a `style` attribute value before its first declaration whose name starts with `&`
/// (the CSS nesting selector). Style attributes cannot hold nested rules: a browser drops
/// `&::before{...}` whole when its braces survive. Templates that flatten SCSS sometimes lose the
/// braces (`&: :before position:absolute; ...; opacity:0;`), and then nothing marks where the
/// nested rule ends, so its declarations would land on the element itself (`display:block;
/// opacity:0` meant for `::before` hid a newsletter's table cells). Such a declaration therefore
/// ends the attribute: it and every declaration after it are dropped. Quotes, brackets, comments
/// and backslash escapes are respected, so a `&` inside a value (a URL, a string) changes nothing.
/// Every path that reads a raw style attribute goes through this.
pub fn without_nested_rule(value: &str) -> &str {
    let b = value.as_bytes();
    let (mut i, mut depth, mut at_start) = (0, 0usize, true);
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = value[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
                continue;
            }
            c if c.is_ascii_whitespace() => {}
            b'&' if at_start => return &value[..i],
            b'\\' => {
                at_start = false;
                i += 2;
                continue;
            }
            q @ (b'"' | b'\'') => {
                at_start = false;
                i += 1;
                // A string ends at its closing quote or, unclosed, at a newline.
                while i < b.len() && b[i] != q && b[i] != b'\n' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'(' | b'[' | b'{' => {
                at_start = false;
                depth += 1;
            }
            b')' | b']' | b'}' => {
                at_start = false;
                depth = depth.saturating_sub(1);
            }
            b';' => at_start = depth == 0,
            _ => at_start = false,
        }
        i += 1;
    }
    value
}

pub fn sanitize_style_attr(value: &str) -> Option<String> {
    let mut attr = StyleAttribute::parse(without_nested_rule(value), parser_options()).ok()?;
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

/// The rule styles links: the subject of every selector is a link (`a`, `:link`, `:visited`,
/// `:any-link`, `:local-link`) or sits inside one (`a span`, `a::after`, `a > b + c`).
fn styles_links(selectors: &SelectorList) -> bool {
    let link = |c: &Component| match c {
        Component::LocalName(n) => n.lower_name.0.eq_ignore_ascii_case("a"),
        Component::NonTSPseudoClass(p) => {
            matches!(
                p,
                PseudoClass::Link | PseudoClass::Visited | PseudoClass::LocalLink
            ) || matches!(p, PseudoClass::AnyLink(_))
        }
        _ => false,
    };
    selectors.0.iter().all(|s| {
        // Compounds from the subject leftwards. One left of a child or descendant combinator (or
        // of the one before a pseudo-element) is an ancestor of the subject; one left of a sibling
        // combinator is not.
        let mut iter = s.iter();
        let mut ancestor = true;
        loop {
            if iter.by_ref().any(|c| ancestor && link(c)) {
                return true;
            }
            match iter.next_sequence() {
                Some(combinator) => ancestor = combinator.is_ancestor(),
                None => return false,
            }
        }
    })
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// Rewrite colours under the policy.
    Transform(Policy),
    /// Only detect sender dark CSS and collect simple rules (hybrid preflight).
    Scan,
}

pub struct Recolor {
    mode: Mode,
    role: Role,
    ctx_bg: Rgb,
    ctx_orig_bg: Rgb,
    image_ctx: bool,
    /// The colours style a link's text (fixed palette only).
    link: bool,
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
            link: false,
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
        if !matches!(self.mode, Mode::Transform(Policy::Dark { .. })) {
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
                // A fixed palette re-colours the sender's dark design like the rest.
                if is_dark_media(&query) && !matches!(self.mode, Mode::Transform(Policy::Fixed(_)))
                {
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
                let saved = (self.ctx_bg, self.ctx_orig_bg, self.image_ctx, self.link);
                if let Mode::Transform(Policy::Fixed(_)) = self.mode {
                    // Nested rules of a link rule (`a{span{…}}`) style inside the link.
                    self.link |= styles_links(&s.selectors);
                } else if let Some(bg) = colors.bg {
                    self.ctx_bg = crate::color::map_bg(bg).over(CANVAS);
                    self.ctx_orig_bg = bg.over(WHITE);
                }
                self.image_ctx |= colors.image;
                s.declarations.visit(self)?;
                s.rules.visit(self)?;
                (self.ctx_bg, self.ctx_orig_bg, self.image_ctx, self.link) = saved;
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
        let strict = match self.mode {
            Mode::Scan => return Ok(()),
            Mode::Transform(Policy::Fixed(palette)) => {
                // Fully transparent paints nothing and stays. Every other colour (`currentColor`,
                // system colours and `light-dark()` included) becomes the palette's, text on
                // background images too.
                let rgb = to_rgb(c);
                if rgb.is_some_and(|x| x.a <= 0.001) {
                    return Ok(());
                }
                self.stats.colors_seen += 1;
                let new = palette.color(self.role, self.link);
                if rgb != Some(new) {
                    *c = to_css_color(new);
                    self.stats.colors_rewritten += 1;
                }
                return Ok(());
            }
            Mode::Transform(Policy::Dark { strict }) => strict,
        };
        let Some(rgb) = to_rgb(c) else { return Ok(()) };
        self.stats.colors_seen += 1;
        if self.role == Role::Foreground && self.image_ctx {
            return Ok(()); // text designed for a background image: keep the sender's colour
        }
        let new = map(rgb, self.role, self.ctx_bg, self.ctx_orig_bg, strict);
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
    let css = if mode != Mode::Scan {
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

/// Recolours an inline style attribute in the given context (`link`: the element is a link or
/// inside one). Returns the new value and stats.
pub fn recolor_style_attr(
    value: &str,
    policy: Policy,
    ctx_bg: Rgb,
    ctx_orig_bg: Rgb,
    image_ctx: bool,
    link: bool,
    stats: &mut Stats,
) -> Option<String> {
    let mut attr = StyleAttribute::parse(value, parser_options()).ok()?;
    let mut v = Recolor::new(Mode::Transform(policy), ctx_bg, ctx_orig_bg, image_ctx);
    v.link = link;
    let _ = attr.declarations.visit(&mut v);
    stats.colors_seen += v.stats.colors_seen;
    stats.colors_rewritten += v.stats.colors_rewritten;
    stats.fg_contrast_fixes += v.stats.fg_contrast_fixes;
    attr_html(&attr)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::color::{HIGH_CONTRAST, HIGH_CONTRAST_DARK};

    const POLICIES: [Policy; 4] = [
        Policy::Dark { strict: false },
        Policy::Dark { strict: true },
        Policy::Fixed(HIGH_CONTRAST),
        Policy::Fixed(HIGH_CONTRAST_DARK),
    ];

    fn first_rule_styles_links(css: &str) -> bool {
        let sheet = StyleSheet::parse(css, parser_options()).expect("parses");
        match &sheet.rules.0[0] {
            CssRule::Style(s) => styles_links(&s.selectors),
            other => panic!("{css}: {other:?}"),
        }
    }

    #[test]
    fn link_rules_are_those_whose_subject_is_in_a_link() {
        for css in [
            "a{}",
            "A{}",
            "a:link{}",
            "a:visited,a:hover{}",
            ":link{}",
            ":any-link{}",
            ".x a.btn{}",
            "a span{}",
            "td > a > b{}",
            "a > b + c{}",
            "a::after{}",
            "#id a:hover strong{}",
        ] {
            assert!(first_rule_styles_links(css), "{css}");
        }
        for css in [
            "p{}",
            "a, p{}",
            "abbr{}",
            ".a{}",
            "a + p{}",
            "a ~ p span{}",
            "[href]{}",
        ] {
            assert!(!first_rule_styles_links(css), "{css}");
        }
    }

    /// A colour as the printer writes it.
    fn printed(c: Rgb) -> String {
        to_css_color(c).to_css_string(printer()).expect("prints")
    }

    #[test]
    fn a_fixed_palette_replaces_every_colour_of_a_sheet() {
        for p in [HIGH_CONTRAST, HIGH_CONTRAST_DARK] {
            let css = process_stylesheet(
                "body{color:#333;background:#fafafa linear-gradient(red,blue)}\
                 p{color:currentColor;background-color:light-dark(#fff,#000);border:1px solid #ccc}\
                 a,a:visited{color:#f0f0f0!important;text-decoration-color:olive}\
                 .btn span{color:Canvas;background-color:transparent;outline-color:rgba(9,9,9,.5)}\
                 @media (prefers-color-scheme:dark){p{color:#eee}}\
                 a{span{color:green}}",
                Mode::Transform(Policy::Fixed(p)),
            )
            .css;
            let (text, bg, link) = (printed(p.text), printed(p.bg), printed(p.link));
            for want in [
                format!("body{{color:{text};background:"),
                format!("linear-gradient({bg},{bg})"),
                format!("color:{text};background-color:{bg};border:1px solid {text}"),
                format!("a,a:visited{{text-decoration-color:{link};color:{link}!important}}"),
                format!("@media (prefers-color-scheme:dark){{p{{color:{text}}}}}"),
                format!("span{{color:{link}}}"),
                format!("outline-color:{text}"),
            ] {
                assert!(css.contains(&want), "{want} not in {css}");
            }
            for gone in [
                "#333",
                "#fafafa",
                "red",
                "blue",
                "#ccc",
                "f0f0f0",
                "olive",
                "Canvas",
                "#eee",
                "green",
                "light-dark",
                "currentColor",
                "rgba",
            ] {
                assert!(!css.contains(gone), "{gone} in {css}");
            }
            // The span of `.btn span` is not known to be in a link; transparent stays.
            assert!(css.contains(&format!(".btn span{{color:{text};")), "{css}");
            assert!(
                !css.contains(&format!("background-color:{bg};outline")),
                "{css}"
            );
        }
    }

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
        for policy in POLICIES {
            let css = process_stylesheet(
                r#"a{font-family:"\3c/style\3e";color:red}"#,
                Mode::Transform(policy),
            )
            .css;
            assert!(!css.contains("</"), "{css}");
            let recolored = recolor_style_attr(
                r#"font-family:"\3c/style\3e";color:red"#,
                policy,
                CANVAS,
                WHITE,
                false,
                false,
                &mut Stats::default(),
            )
            .expect("kept");
            assert!(!recolored.contains("</"), "{recolored}");
        }
    }

    /// A nested rule flattened with its braces lost (`&::before{...}` from SCSS).
    const FLATTENED: &str = "padding:0px; border:1px solid #ccc; position: relative; &: :before \
        position:absolute; background: #8a5db5 color: white; display: block; top: 0; bottom: 0; \
        right: 100%; left: -40px; opacity: 0;";

    #[test]
    fn a_flattened_nested_rule_ends_the_style_attribute() {
        let s = sanitize_style_attr(FLATTENED).expect("kept");
        for kept in ["padding:0", "border:1px solid #ccc"] {
            assert!(s.contains(kept), "{kept}: {s}");
        }
        for gone in ["display", "opacity", "left", "absolute", "background", "&"] {
            assert!(!s.contains(gone), "{gone}: {s}");
        }
        // Only `&` at the start of a declaration counts, after whitespace or comments.
        assert_eq!(
            without_nested_rule("color:red;/* x */ &.a{x:y}"),
            "color:red;/* x */ "
        );
        assert_eq!(without_nested_rule("&:hover{color:red}"), "");
        assert_eq!(without_nested_rule("color:red;;\n&"), "color:red;;\n");
    }

    #[test]
    fn an_ampersand_inside_a_value_does_not_end_the_style_attribute() {
        for value in [
            r#"font-family:"a;&b"; opacity:0"#,
            "font-family:'a;&b'; opacity:0",
            r#"font-family:"a\";&b"; opacity:0"#,
            "background:url(https://e.test/a?b=1;&c=2); opacity:0",
            "background:url('https://e.test/a?b=1;&c=2'); opacity:0",
            "color:red/*;&x:y*/; opacity:0",
            r"font-family:a\;&b; opacity:0",
            "--x:[;&y]; opacity:0",
            "--x:a & b; opacity:0",
        ] {
            assert_eq!(without_nested_rule(value), value);
        }
        let s = sanitize_style_attr("background:url(https://e.test/a?b=1;&c=2); opacity:0")
            .expect("kept");
        assert!(s.contains("opacity:0"), "{s}");
    }

    /// With its braces intact a nested rule gives the element none of its declarations
    /// (lightningcss alone drops the rule whole, as a browser does); like the flattened form, it
    /// ends the attribute.
    #[test]
    fn a_nested_rule_with_braces_does_not_style_the_element() {
        for value in [
            "padding:1px; &::before{opacity:0; display:block}",
            "padding:1px; &::before{opacity:0; display:block}; color:red",
        ] {
            let s = sanitize_style_attr(value).expect("kept");
            assert_eq!(s, "padding:1px", "{value}");
        }
    }
}
