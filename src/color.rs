//! Colour math (WCAG contrast, OKLCH via `palette`), the dark policy rules and the fixed
//! high-contrast palettes.

use palette::{FromColor, Lab, OklabHue, Oklch, Srgb};

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Rgb {
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

impl Rgb {
    pub const fn hex(v: u32) -> Rgb {
        Rgb {
            r: ((v >> 16) & 0xff) as f32 / 255.0,
            g: ((v >> 8) & 0xff) as f32 / 255.0,
            b: (v & 0xff) as f32 / 255.0,
            a: 1.0,
        }
    }
    pub fn from_u8(r: u8, g: u8, b: u8, a: f32) -> Rgb {
        Rgb {
            r: r as f32 / 255.0,
            g: g as f32 / 255.0,
            b: b as f32 / 255.0,
            a,
        }
    }
    pub fn to_u8(self) -> (u8, u8, u8) {
        let q = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
        (q(self.r), q(self.g), q(self.b))
    }
    pub fn css(self) -> String {
        let (r, g, b) = self.to_u8();
        if self.a >= 0.999 {
            format!("#{r:02x}{g:02x}{b:02x}")
        } else {
            format!("rgba({r},{g},{b},{:.3})", self.a)
        }
    }
    /// Composite over an opaque backdrop.
    pub fn over(self, bg: Rgb) -> Rgb {
        let a = self.a.clamp(0.0, 1.0);
        Rgb {
            r: self.r * a + bg.r * (1.0 - a),
            g: self.g * a + bg.g * (1.0 - a),
            b: self.b * a + bg.b * (1.0 - a),
            a: 1.0,
        }
    }
    pub fn with_alpha(self, a: f32) -> Rgb {
        Rgb { a, ..self }
    }
}

fn linearize(c: f32) -> f32 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// WCAG 2.x relative luminance.
pub fn luminance(c: Rgb) -> f32 {
    0.2126 * linearize(c.r) + 0.7152 * linearize(c.g) + 0.0722 * linearize(c.b)
}

/// WCAG 2.x contrast ratio between two opaque colours.
pub fn contrast(a: Rgb, b: Rgb) -> f32 {
    let (x, y) = (luminance(a) + 0.05, luminance(b) + 0.05);
    if x > y { x / y } else { y / x }
}

pub fn oklch(c: Rgb) -> (f32, f32, f32) {
    let o = Oklch::from_color(Srgb::new(c.r, c.g, c.b));
    (o.l, o.chroma, o.hue.into_positive_degrees())
}

/// OKLCH -> sRGB, reducing chroma (keeping L and hue) until the colour is in gamut.
pub fn from_oklch(l: f32, chroma: f32, hue: f32, a: f32) -> Rgb {
    let to = |ch: f32| Srgb::from_color(Oklch::new(l, ch, OklabHue::from_degrees(hue)));
    let inside = |s: &Srgb| {
        [s.red, s.green, s.blue]
            .iter()
            .all(|v| (-0.0005..=1.0005).contains(v))
    };
    let mut s = to(chroma);
    if !inside(&s) {
        let (mut lo, mut hi) = (0.0f32, chroma);
        for _ in 0..20 {
            let mid = (lo + hi) / 2.0;
            if inside(&to(mid)) { lo = mid } else { hi = mid }
        }
        s = to(lo);
    }
    Rgb {
        r: s.red.clamp(0.0, 1.0),
        g: s.green.clamp(0.0, 1.0),
        b: s.blue.clamp(0.0, 1.0),
        a,
    }
}

/// How the transform re-colours a document.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Policy {
    /// Dark policy v1; `strict` also re-colours sender text on preserved fills (WCAG AA).
    Dark { strict: bool },
    /// Every colour becomes one of the palette's.
    Fixed(Palette),
}

// ---------------------------------------------------------------------------
// High-contrast palettes. Constants of the library: no caller or theme changes them.
// ---------------------------------------------------------------------------

/// A fixed palette: every text and border colour of the document becomes `text`, every background
/// `bg`, and the text of every link `link`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Palette {
    pub text: Rgb,
    pub bg: Rgb,
    pub link: Rgb,
    /// The document's `color-scheme` is dark (system colours and form controls follow it).
    pub dark: bool,
}

/// Black on white; links 10.2:1 on the background (the High Contrast theme's `text.link`).
pub const HIGH_CONTRAST: Palette = Palette {
    text: Rgb::hex(0x000000),
    bg: Rgb::hex(0xffffff),
    link: Rgb::hex(0x0033aa),
    dark: false,
};
/// White on black; links 13.1:1 on the background (the High Contrast Dark theme's `text.link`).
pub const HIGH_CONTRAST_DARK: Palette = Palette {
    text: Rgb::hex(0xffffff),
    bg: Rgb::hex(0x000000),
    link: Rgb::hex(0x9cd2ff),
    dark: true,
};

impl Palette {
    /// The palette's colour for a colour in `role`; `link` when it styles a link's text.
    pub fn color(&self, role: Role, link: bool) -> Rgb {
        match role {
            Role::Foreground if link => self.link,
            Role::Foreground | Role::Border => self.text,
            Role::Background => self.bg,
        }
    }
}

// ---------------------------------------------------------------------------
// Dark policy v1. All constants are listed here.
// ---------------------------------------------------------------------------

/// Reader canvas in dark mode (OKLCH L = 0.235).
pub const CANVAS: Rgb = Rgb::hex(0x1e1e1e);
/// Backgrounds at or below this OKLCH lightness are already dark and are kept.
pub const BG_KEEP_DARK_L: f32 = 0.45;
/// Backgrounds with at least this OKLCH chroma (and L >= BRAND_MIN_L) are brand fills and are kept.
pub const BRAND_CHROMA: f32 = 0.10;
pub const BRAND_MIN_L: f32 = 0.40;
/// Light backgrounds map to L' = BG_BASE_L + (1 - L) * BG_SLOPE (white -> canvas).
pub const BG_BASE_L: f32 = 0.235;
pub const BG_SLOPE: f32 = 0.6;
pub const BG_MAX_CHROMA: f32 = 0.06;
/// Text must reach this ratio against its mapped background (WCAG AA + margin).
pub const TEXT_TARGET: f32 = 4.6;
/// Borders/outlines (non-text graphics) target, WCAG 1.4.11.
pub const BORDER_TARGET: f32 = 3.0;
/// Text that must change starts at L' = max(L, INVERT_BASE_L - INVERT_SLOPE * L).
pub const INVERT_BASE_L: f32 = 0.96;
pub const INVERT_SLOPE: f32 = 0.5;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Role {
    Foreground,
    Background,
    Border,
}

pub fn map_bg(c: Rgb) -> Rgb {
    if c.a <= 0.001 {
        return c;
    }
    let (l, ch, h) = oklch(c);
    if l <= BG_KEEP_DARK_L || (ch >= BRAND_CHROMA && l >= BRAND_MIN_L) {
        return c;
    }
    // Never lighten a background: mid-tones below the crossover (L ~0.52) stay as sent.
    let l2 = (BG_BASE_L + (1.0 - l) * BG_SLOPE).min(l);
    if l2 >= l {
        return c;
    }
    from_oklch(l2, ch.min(BG_MAX_CHROMA), h, c.a)
}

/// Pick a lightness (same hue, gamut-clamped chroma) so `c` reaches `target` against `bg`.
/// Colours that already reach the target are returned unchanged.
pub fn ensure_contrast(c: Rgb, bg: Rgb, target: f32) -> Rgb {
    if c.a <= 0.001 {
        return c;
    }
    let bg = bg.over(CANVAS);
    if contrast(c.over(bg), bg) >= target {
        return c;
    }
    let (l, ch, h) = oklch(c);
    let lighter = contrast(Rgb::hex(0xffffff), bg) >= contrast(Rgb::hex(0x000000), bg);
    let probe = |lv: f32| from_oklch(lv, ch, h, 1.0);
    if lighter {
        // Invert dark text (black -> 0.96, #222 -> ~0.83), then lighten until it passes.
        let start = l.max(INVERT_BASE_L - INVERT_SLOPE * l);
        if contrast(probe(start), bg) >= target {
            return probe(start).with_alpha(1.0);
        }
        let (mut lo, mut hi) = (start, 1.0f32);
        for _ in 0..18 {
            let mid = (lo + hi) / 2.0;
            if contrast(probe(mid), bg) >= target {
                hi = mid
            } else {
                lo = mid
            }
        }
        probe(hi)
    } else {
        let start = l.min(0.40);
        if contrast(probe(start), bg) >= target {
            return probe(start);
        }
        let (mut lo, mut hi) = (0.0f32, start);
        for _ in 0..18 {
            let mid = (lo + hi) / 2.0;
            if contrast(probe(mid), bg) >= target {
                lo = mid
            } else {
                hi = mid
            }
        }
        probe(lo)
    }
}

fn same_color(a: Rgb, b: Rgb) -> bool {
    let (x, y) = (a.to_u8(), b.to_u8());
    x.0.abs_diff(y.0) <= 1 && x.1.abs_diff(y.1) <= 1 && x.2.abs_diff(y.2) <= 1
}

/// Contrast text must reach in dark mode. Where the policy changed the background it owns
/// the result and requires TEXT_TARGET. Where the background was preserved verbatim (brand
/// fill, sender-dark surface, unchanged context) the sender's own light-mode pair is kept
/// if dark mode is no worse (e.g. white on an orange button), unless `strict` (the strict AA
/// variant) is set.
pub fn required_contrast(c: Rgb, bg: Rgb, orig_bg: Rgb, strict: bool) -> f32 {
    let (now_bg, then_bg) = (bg.over(CANVAS), orig_bg.over(Rgb::hex(0xffffff)));
    if !same_color(now_bg, then_bg) {
        TEXT_TARGET
    } else if strict {
        4.5 // WCAG AA; sender pairs that already pass stay untouched
    } else {
        TEXT_TARGET.min(contrast(c.over(then_bg), then_bg))
    }
}

pub fn map_fg(c: Rgb, bg: Rgb, orig_bg: Rgb, strict: bool) -> Rgb {
    if c.a > 0.001 {
        let now_bg = bg.over(CANVAS);
        if contrast(c.over(now_bg), now_bg) >= required_contrast(c, bg, orig_bg, strict) {
            return c;
        }
    }
    ensure_contrast(c, bg, TEXT_TARGET)
}

/// Light borders darken like backgrounds; darker borders are lightened to 3:1 against the
/// mapped background, but never past the contrast they had in the sender's light design.
pub fn map_border(c: Rgb, bg: Rgb, orig_bg: Rgb) -> Rgb {
    if c.a <= 0.001 {
        return c;
    }
    let (l, _, _) = oklch(c);
    if l > 0.6 {
        return map_bg(c);
    }
    let then_bg = orig_bg.over(Rgb::hex(0xffffff));
    let target = BORDER_TARGET.min(contrast(c.over(then_bg), then_bg));
    ensure_contrast(c, bg, target)
}

pub fn map(c: Rgb, role: Role, ctx_bg: Rgb, ctx_orig_bg: Rgb, strict: bool) -> Rgb {
    match role {
        Role::Background => map_bg(c),
        Role::Foreground => map_fg(c, ctx_bg, ctx_orig_bg, strict),
        Role::Border => map_border(c, ctx_bg, ctx_orig_bg),
    }
}

// ---------------------------------------------------------------------------
// Approximation of Blink's auto-dark background inversion (used only by the
// hybrid preflight to predict what Blink will paint behind an image).
// Source: third_party/blink/renderer/platform/graphics/dark_mode_color_filter.cc
// (Lab L' = min(110 - L, 100)) and dark_mode_settings_builder.cc (background
// brightness threshold 205) at Chromium 156.0.8078.88.
// ---------------------------------------------------------------------------
pub fn blink_auto_dark_bg(c: Rgb) -> Rgb {
    let (r, g, b) = c.to_u8();
    let brightness = (r as f32 * 299.0 + g as f32 * 587.0 + b as f32 * 114.0) / 1000.0;
    if brightness <= 205.0 {
        return c;
    }
    let mut lab = Lab::from_color(Srgb::new(c.r, c.g, c.b));
    lab.l = (110.0 - lab.l).min(100.0);
    let s = Srgb::from_color(lab);
    Rgb {
        r: s.red.clamp(0.0, 1.0),
        g: s.green.clamp(0.0, 1.0),
        b: s.blue.clamp(0.0, 1.0),
        a: c.a,
    }
}

/// Parses legacy HTML colour attributes (`bgcolor`, `<font color>`): CSS colours plus bare hex.
pub fn parse_attr_color(value: &str) -> Option<Rgb> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let bare_hex = (v.len() == 3 || v.len() == 6) && v.chars().all(|c| c.is_ascii_hexdigit());
    let text = if bare_hex {
        format!("#{v}")
    } else {
        v.to_string()
    };
    crate::css::parse_color(&text)
}
