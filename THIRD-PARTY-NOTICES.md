# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

None. The corpus in `tests/corpus/` (HTML documents, images and the text-fallback generator) and the fuzz seeds in
`fuzz/corpus/` are synthetic, written for this repository; the brand names in them are invented.

## Dependencies (not bundled)

Dependencies are not vendored: they are fetched at build time (Rust crates from crates.io, pinned in `Cargo.lock`) under their own licences, and the gate
checks their licences (`cargo deny`, `deny.toml`). Nothing from them is redistributed in this repository.

- The CSS stack (`lightningcss`, `cssparser`, `selectors` and their helpers) is MPL-2.0 and used unmodified; the
  crates are listed by name in `deny.toml`. Everything else is under permissive licences.
