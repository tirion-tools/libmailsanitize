//! Every document of the content corpus (`tests/corpus`, plus the generated text-fallback
//! fixtures when `MAILSANITIZE_EXTRA_CORPUS` names their directory) through `text` and, for valid
//! UTF-8, `sanitize` under every theme: the output bounds hold, no script survives, the output
//! check holds (no plain-text fallback), and the result is deterministic. The fuzz findings kept in
//! `fuzz/corpus/sanitize/crash-*` run as the fuzz target runs them.
use std::path::{Path, PathBuf};

use mailsanitize::{
    Config, MAX_LINKS, MAX_REMOTE_IMAGES, MAX_URL, Manifest, Theme, cid_resource_id, sanitize,
    text, valid_link_sample, valid_resource_id,
};

const THEMES: [Theme; 5] = [
    Theme::Light,
    Theme::Dark,
    Theme::DarkStrict,
    Theme::HighContrast,
    Theme::HighContrastDark,
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("corpus dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "html") {
            out.push(p);
        }
    }
}

fn check(m: &Manifest) {
    assert!(m.links.len() <= MAX_LINKS);
    for (i, l) in m.links.iter().enumerate() {
        assert_eq!(l.index as usize, i + 1);
        assert!(l.href.len() <= MAX_URL && l.href.bytes().all(|b| (0x21..=0x7e).contains(&b)));
        assert!(l.text_samples.len() <= 4);
        assert!(
            l.text_samples.iter().all(|s| valid_link_sample(s)),
            "{:?}",
            l.text_samples
        );
    }
    assert!(m.remote_images.len() <= MAX_REMOTE_IMAGES);
    assert!(m.remote_images.iter().all(|r| valid_resource_id(&r.id)));
    assert!(
        m.hidden
            .windows(2)
            .all(|w| (w[0].reason as u8) < (w[1].reason as u8))
    );
}

#[test]
fn corpus_documents_keep_the_output_contract() {
    let mut files = vec![];
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus"),
        &mut files,
    );
    if let Some(extra) = std::env::var_os("MAILSANITIZE_EXTRA_CORPUS") {
        walk(Path::new(&extra), &mut files);
    }
    assert!(
        files.len() >= 25,
        "corpus missing: {} documents",
        files.len()
    );
    let cfg = Config::default();
    for f in &files {
        let bytes = std::fs::read(f).expect("read");
        let t = text(&String::from_utf8_lossy(&bytes), &cfg);
        check(&t.manifest);
        // The stress documents of the text fallback are for the converter only.
        if f.components().any(|c| c.as_os_str() == "text-fallback") {
            continue;
        }
        let Ok(html) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for theme in THEMES {
            let a = sanitize(html, theme, vec![], &cfg);
            check(&a.manifest);
            assert!(
                !a.document.to_ascii_lowercase().contains("<script"),
                "{}",
                f.display()
            );
            assert!(
                !a.document.contains("data-gx-fallback"),
                "{} failed the output check",
                f.display()
            );
            let b = sanitize(html, theme, vec![], &cfg);
            assert_eq!(a.document, b.document, "{} not deterministic", f.display());
        }
    }
}

/// `dark-mode/25-flattened-nested-rule.html`: the declarations of a nested rule flattened into the
/// cells' style attributes (braces lost) reach neither the document nor the hidden-text counts,
/// and the cells' own declarations before it are kept.
#[test]
fn a_flattened_nested_rule_leaves_the_cells_visible() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/dark-mode/25-flattened-nested-rule.html");
    let html = std::fs::read_to_string(path).expect("read");
    let cfg = Config::default();
    for theme in THEMES {
        let out = sanitize(&html, theme, vec![], &cfg);
        assert!(!out.document.contains("opacity"), "{theme:?}");
        assert!(!out.document.contains("left:-40px"), "{theme:?}");
        assert!(out.document.contains("border-left:3px solid"), "{theme:?}");
        assert!(out.manifest.hidden.is_empty(), "{theme:?}");
    }
    let t = text(&html, &cfg);
    assert!(t.manifest.hidden.is_empty(), "{:?}", t.manifest.hidden);
    assert!(t.text.contains("Library extends weekend opening hours"));
}

/// Every `#rgb`/`#rrggbb` colour of a document, as six lowercase digits.
fn hex_colors(doc: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = doc;
    while let Some(at) = rest.find('#') {
        rest = &rest[at + 1..];
        let len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        let hex = rest[..len].to_ascii_lowercase();
        out.push(match len {
            3 => hex.chars().flat_map(|c| [c, c]).collect(),
            _ => hex,
        });
        rest = &rest[len..];
    }
    out
}

/// `high-contrast/`: under the high-contrast themes every colour in the document is one of the
/// theme's palette (text, background, link), every link's style ends with the link colour and an
/// underline, which outrank the sender's rules, and every image is kept. The fixtures use no
/// colour that prints as a name, so a sender colour that survived would show here.
#[test]
fn high_contrast_documents_hold_only_the_palette() {
    let mut files = vec![];
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/high-contrast"),
        &mut files,
    );
    assert!(!files.is_empty());
    let cfg = Config::default();
    let ids: Vec<String> = ["logo.png", "hero.jpg", "icon.png"]
        .iter()
        .map(|c| cid_resource_id(c.as_bytes()))
        .collect();
    for f in &files {
        let html = std::fs::read_to_string(f).expect("read");
        for (theme, text, bg, link) in [
            (Theme::HighContrast, "000000", "ffffff", "0033aa"),
            (Theme::HighContrastDark, "ffffff", "000000", "9cd2ff"),
        ] {
            let out = sanitize(&html, theme, ids.clone(), &cfg);
            let d = &out.document;
            for c in hex_colors(d) {
                assert!(
                    [text, bg, link].contains(&c.as_str()),
                    "{theme:?} #{c}: {d}"
                );
            }
            assert!(
                !d.contains("rgb") && !d.contains("light-dark"),
                "{theme:?}: {d}"
            );
            let decl = format!("color:#{link}!important;text-decoration:underline!important");
            let styles: Vec<&str> = d
                .match_indices("<a ")
                .map(|(at, _)| &d[at..at + d[at..].find('>').expect("tag end")])
                .filter(|tag| tag.contains(" href=\""))
                .map(|tag| {
                    let v = &tag[tag.find(" style=\"").expect("style") + 8..];
                    &v[..v.find('"').expect("value end")]
                })
                .collect();
            // Links hidden colour-on-colour in the sender's design are not in the manifest, but the
            // palette shows them: every one of them.
            assert_eq!(styles.len(), html.matches("<a href").count(), "{theme:?}");
            for style in styles {
                assert!(style.ends_with(&decl), "{theme:?}: {style}");
            }
            assert_eq!(
                d.matches("<img").count(),
                html.matches("<img").count(),
                "{theme:?}"
            );
            // The palette keeps every picture the sender's colours keep (a CSS `url(cid:…)` is
            // refused in every theme, `map_css_url`).
            let light = sanitize(&html, Theme::Light, ids.clone(), &cfg);
            assert_eq!(
                out.manifest.resource_ids_used, light.manifest.resource_ids_used,
                "{theme:?}"
            );
        }
    }
}

/// Each kept fuzz finding (`fuzz/corpus/sanitize/crash-*`, the libFuzzer input and its minimised
/// form) as the fuzz target reads it (the first byte picks the theme, the rest is the part), under
/// every theme.
#[test]
fn fuzz_findings_keep_the_output_contract() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/sanitize");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).expect("fuzz corpus").flatten() {
        if !e.file_name().to_string_lossy().starts_with("crash-") {
            continue;
        }
        let data = std::fs::read(e.path()).expect("read");
        let (_, html) = data.split_first().expect("a selector byte");
        let html = std::str::from_utf8(html).expect("UTF-8");
        for theme in THEMES {
            let out = sanitize(html, theme, vec![], &Config::default());
            check(&out.manifest);
            let doc = out.document.to_ascii_lowercase();
            assert!(!doc.contains("<script"), "{}", e.path().display());
            assert!(!doc.contains("data-gx-fallback"), "{}", e.path().display());
        }
        n += 1;
    }
    assert!(n >= 2, "fuzz findings missing: {n}");
}
