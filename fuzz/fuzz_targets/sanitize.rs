//! The sanitizer on arbitrary bytes: the text fallback on the lossy decoding of every input, and
//! sanitize under the theme picked by the first byte for valid UTF-8. Asserts the output
//! contract: the manifest bounds and no forbidden characters in the fallback text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mailsanitize::{Config, Manifest, Theme};

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
    }
});
