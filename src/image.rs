//! Transparent-image visibility analysis for the backdrop rule.

use base64::Engine;

use crate::color::{Rgb, contrast};

const MAX_DIMENSION: u32 = 4096;
const MAX_SAMPLES: usize = 4096;

/// Visible (alpha >= 128) pixels of a transparent PNG, subsampled. None for opaque or non-PNG images.
pub fn visible_pixels(src: &str) -> Option<Vec<Rgb>> {
    let payload = src.trim().strip_prefix("data:image/png;base64,")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .ok()?;
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;
    let (w, h) = reader.info().size();
    if w == 0 || h == 0 || w > MAX_DIMENSION || h > MAX_DIMENSION {
        return None;
    }
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let channels = match info.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::GrayscaleAlpha => 2,
        _ => return None, // no alpha channel after tRNS expansion: opaque
    };
    let total = (w * h) as usize;
    let step = (total / MAX_SAMPLES).max(1);
    let mut transparent = false;
    let mut out = Vec::new();
    for i in (0..total).step_by(step) {
        let px = &buf[i * channels..i * channels + channels];
        let (rgb, a) = if channels == 4 {
            ((px[0], px[1], px[2]), px[3])
        } else {
            ((px[0], px[0], px[0]), px[1])
        };
        if a < 250 {
            transparent = true;
        }
        if a >= 128 {
            out.push(Rgb::from_u8(rgb.0, rgb.1, rgb.2, 1.0));
        }
    }
    if transparent && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

/// Fraction of visible pixels whose contrast against `bg` is below 3:1 (WCAG 1.4.11 graphics).
pub fn low_contrast_fraction(pixels: &[Rgb], bg: Rgb) -> f32 {
    let low = pixels.iter().filter(|p| contrast(**p, bg) < 3.0).count();
    low as f32 / pixels.len() as f32
}
