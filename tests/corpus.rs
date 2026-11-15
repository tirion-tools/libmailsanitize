//! Every document of the content corpus (`tests/corpus`, plus the generated text-fallback
//! fixtures when `MAILSANITIZE_EXTRA_CORPUS` names their directory) through `text` and, for valid
//! UTF-8, `sanitize` under every theme: the output bounds hold, no script survives, and the
//! result is deterministic.
use std::path::{Path, PathBuf};

use mailsanitize::{
    Config, MAX_LINKS, MAX_REMOTE_IMAGES, MAX_URL, Manifest, Theme, sanitize, text,
    valid_resource_id,
};

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
        for theme in [Theme::Light, Theme::Dark, Theme::DarkStrict] {
            let a = sanitize(html, theme, vec![], &cfg);
            check(&a.manifest);
            assert!(
                !a.document.to_ascii_lowercase().contains("<script"),
                "{}",
                f.display()
            );
            let b = sanitize(html, theme, vec![], &cfg);
            assert_eq!(a.document, b.document, "{} not deterministic", f.display());
        }
    }
}
