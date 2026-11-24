# libmailsanitize

An HTML email sanitizer in Rust. One HTML part goes in. One of two things comes out:

- a sanitized document, optionally re-coloured for a dark theme;
- a plain-text fallback.

Each comes with a manifest of the links, the hidden text and the image references the part contains.

## Builds on

This crate is glue around existing libraries; it does not replace them, and fixes found in them go upstream:

- **[ammonia](https://crates.io/crates/ammonia)** does the HTML sanitizing (html5ever's tree builder, allowlists, URL
  scheme filter). This crate only configures it for email: the tag, attribute and scheme allowlists and an attribute
  filter for image sources.
- **[lightningcss](https://crates.io/crates/lightningcss)** parses and re-prints all CSS. Ammonia does not parse CSS
  values; this crate adds the CSS allowlist as a lightningcss visitor. Only style and `@media` rules are kept. The
  properties `position`, `z-index`, `content`, `behavior`, `cursor`, `animation*` and `transition*` are dropped, and so
  is every `url()` except inline PNG/JPEG, which becomes a resource reference like an `<img>` source. A declaration is
  also dropped when it holds an image source the URL check cannot see: any `image-set()` (lightningcss's visitor skips
  its images, and its sources may be strings), `cross-fade()`, `element()`, `paint()`; any custom property (`--x`) and
  any `var()` or `env()` (substituted after sanitizing); and, in a value lightningcss keeps as raw tokens, any string or
  raw URL token.
- **[html5ever](https://crates.io/crates/html5ever)**'s tokenizer drives the text fallback; **[lol_html](https://crates.io/crates/lol_html)**
  does the streaming rewrites (pre-scan, dark transform); **[palette](https://crates.io/crates/palette)** does the colour
  maths.

What it adds:
- the email allowlist;
- image references rewritten to caller-resolved ids, with a manifest: `cid:` parts, remote images (placeholder ids),
  and inline `data:` PNG/JPEG, whose base64-decoded bytes travel in the manifest (`inline_images`) instead of the
  document, so the caller decides what a renderer's image decoders ever see (for example a re-encoding of its own);
- an images-off policy (`Config::images`, `Images::Off`): every image source becomes one placeholder id and the
  manifest lists no image;
- dark policy v1;
- a bounded text fallback that counts hidden text and flags links whose text shows a different address.

Related projects, and why this crate does not use them:

- [html2text](https://crates.io/crates/html2text) overlaps with the text fallback. The fallback must share no code path
  with the sanitizer it backs up (no tree builder), must be bounded in time and memory, and reports hidden text and
  deceptive links. html2text does none of these.
- [css-sanitizer](https://crates.io/crates/css-sanitizer) is a policy-driven CSS sanitizer on lightningcss (Apache-2.0,
  one maintainer, first released 2026). It overlaps with the CSS allowlist, which is about 60 lines here. That allowlist
  shares its lightningcss parse with the dark-mode colour scan.
- [safe-email-html](https://www.npmjs.com/package/safe-email-html) is the same idea for JavaScript, built on DOMPurify.

## Scope

- **Allowlist sanitizing** with [ammonia](https://crates.io/crates/ammonia). Tags, attributes and URL schemes are allowlisted.
  Scripts and their content are removed. Every `style` attribute and `<style>` sheet is parsed and re-printed by
  [lightningcss](https://crates.io/crates/lightningcss), so CSS that does not parse is dropped, not passed through.
  A `style` attribute ends at its first declaration whose name starts with `&` (a nested rule such as `&::before{…}`,
  often flattened with its braces lost): attributes cannot hold nested rules, and without braces nothing marks where
  the rule ends, so its declarations would land on the element itself. The text fallback reads attributes the same way.
  The printed CSS is made inert as HTML before it goes back into the document: no `<` in it is followed by a letter,
  `/`, `!` or `?`. Inside strings and identifiers it becomes the CSS escape `\3c `; a bare `<` (a media range) gets a
  space after it.
- **Output check** (defence in depth): the finished document is parsed again with html5ever and must have the shape the
  sanitizer meant. That is the frame (`<meta charset>` and `<style>` in the head) around exactly ammonia's elements, in
  the same order and nesting, with no `</` in any `<style>` text. A document that fails fails closed: `sanitize` returns
  the text fallback, escaped, in the same frame, its `<body>` marked `data-gx-fallback="text"`. Its manifest is the
  fallback's, with no images.
- **Image references**: no image source in the output can reach the network.
  - `cid:` references become `<scheme>://cid-<hash>/`, but only when the caller listed that id.
  - `http(s)` images become placeholders `<scheme>://img-N/`. Their URLs and size hints are listed in the manifest.
  - Inline PNG and JPEG `data:` URLs (`<img src>` and CSS `url()`) become `<scheme>://dat-N/`; their decoded bytes are in
    the manifest.
  - Every other source is dropped.

  The caller resolves the ids (for example, after the user asks to load remote images).
- **Links**: every kept `href` is clickable only if the manifest can list it.
  - `http(s)` targets are rewritten to their WHATWG serialisation (the [url](https://crates.io/crates/url) crate, the
    parser ammonia uses), which is the URL a browser reports when the link is clicked: dot segments resolved, `\` read as
    `/`, default ports dropped, unsafe bytes percent-encoded. One that does not parse is dropped.
  - A link whose listed form is over 2048 bytes, and every new distinct link after the first 256, loses its `href`, so
    the anchor is inert rather than clickable but missing from the manifest.
- **Dark policy v1** (`Theme::Dark`, `Theme::DarkStrict`). Light backgrounds are darkened, and text and borders are
  re-coloured to reach contrast targets in OKLCH. Brand fills and surfaces the sender already made dark are kept.
  Low-contrast images get a backing.
- **Text fallback** (`text`) for when sanitizing or rendering a part has failed. It shares as little as possible with the
  path that just failed: it uses html5ever's tokenizer alone (no tree builder, no ammonia, no lightningcss) with its own
  bounded element stack. Its output:
  - text with footnote markers `[N]` and a final `Links:` list;
  - links flagged when their text shows a different address than their target;
  - counts of hidden characters by reason (`display:none`, zero-size, off-screen, colour on colour, invisible and
    bidi-control characters, …).

  The text never contains bidi controls or invisible characters.

Not in scope:
- MIME parsing and charset decoding: the input is one decoded HTML part, as `&str`;
- fetching images;
- rendering;
- any phishing verdict. The manifest gives the facts; scoring them is up to the caller.

## API

```rust
use mailsanitize::{Config, Theme, cid_resource_id, sanitize, text};

let cfg = Config { resource_scheme: "app-resource", truncated_mark: "[truncated]" };
let ids = vec![cid_resource_id(b"logo@example.com")]; // the CID parts you can supply
let out = sanitize(html, Theme::Dark, ids, &cfg);
// out.document: sanitized HTML; out.manifest: links, hidden counts, resource_ids_used, remote_images
let fallback = text(html, &cfg);
// fallback.text, fallback.manifest, fallback.hidden_chars, fallback.dropped_elements
```

`Config::default()` uses the scheme `mail-resource` and the mark `[The text of this message was truncated]`.

`cid_resource_id` is `cid-` followed by the FNV-1a-64 hash of the Content-ID bytes, in lowercase hex. A caller that
supplies CID parts computes the same id. The value is fixed by a test.

`Hidden` has stable discriminants (1–10), so a wire format can carry the hidden-text reason as an integer.

## Security model

- **Input is hostile.** Every structure is capped: the constants are in `src/text.rs` and `src/sanitize.rs`. At most:
  - 1 MiB of body text;
  - 256 links;
  - 2048-byte URLs;
  - 512 tracked elements;
  - 128 attributes per tag;
  - 64 KiB and 512 rules of stylesheet;
  - 64 CID ids;
  - 256 remote images.

  The text converter's cost is linear in its input.
- **The output contract** is what a consumer may rely on, and what the fuzz target and the corpus test assert:
  - no `<script` in the document, and no `</` in a `<style>` text;
  - the document parses to the allowlisted elements only: no script, frame, plugin, form, `<base>`, `<link>`, SVG or
    MathML element, no `<meta>` but the frame's `charset`, no `on*` attribute, no `javascript:` or `data:` URL;
  - in CSS (sheets and `style` attributes, outside strings), every `url()` is a `<scheme>://` reference, and there is no
    `image-set()`, `cross-fade()`, `element()`, `paint()`, `var()`, `env()` or custom property;
  - every link is http, https or mailto, at most 2048 bytes of printable ASCII; every visible `<a href>` within the
    1 MiB of body text is listed (http(s) in the WHATWG form the document carries, then percent-encoded as above);
  - at most 4 text samples per link, each the one-line text the reader sees: whitespace collapsed, no leading or
    trailing space, no control, line break, tab, bidi control or invisible character, at most 256 characters
    (`valid_link_sample`);
  - every resource id matches `[a-z0-9-]{1,64}`;
  - remote image URLs are http(s);
  - the text contains no bidi controls, zero-width characters or control characters other than `\n` and `\t`.

  A consumer that crosses a trust boundary should still re-check these bounds.
- **No `unsafe`** (`#![forbid(unsafe_code)]` through the crate lints). Panics are possible only on a broken invariant
  or an invalid `Config`. Run it in a process you can afford to lose: the library makes no system calls of its own and
  needs no file system or network, so it fits a seccomp or Landlock sandbox with no rules.
- **Concurrency.** Per-call state is thread-local. Concurrent calls on different threads do not interfere.
- **Dependencies** are pinned by `Cargo.lock`, and every gate uses `--locked`. Licences are permissive. The exception is
  the CSS stack (cssparser, lightningcss, selectors, …), which is MPL-2.0; it is unmodified and listed in `deny.toml`.

## Tests

- Unit tests are in `src/`.
- `tests/corpus.rs` runs every document of the synthetic corpus in `tests/corpus/`:
  - `hostile/`: a hostile document, a representative one and the CSS-escape breakouts of MAILSANITIZE-2026-001;
  - `dark-mode/`: 25 dark-mode fixtures and their images (24: an HTML-only notice whose link texts span source lines;
    25: newsletter cells whose style attributes carry a nested rule flattened with its braces lost);
  - `text-fallback/textgen.py`: writes 34 text-fallback stress documents, up to 4 MiB each.

  Every document goes through every theme and through the text fallback. The output contract is checked, and no document
  may need the fail-closed fallback. The kept fuzz findings (`fuzz/corpus/sanitize/crash-*`: the input and its
  minimised form) run under every theme.
- `fuzz/` holds the cargo-fuzz target `sanitize` and its seed corpus. The target parses every sanitized document again with
  html5ever's own tree (`markup5ever_rcdom`, not the library's) and asserts the output contract on it.

## Advisories

- **MAILSANITIZE-2026-001** (fixed in 0.1.2): allowlist bypass through CSS escapes in `<style>`. See
  [`docs/advisories/MAILSANITIZE-2026-001.md`](docs/advisories/MAILSANITIZE-2026-001.md).

## Gates

Every check runs locally, in a pinned toolchain container (`tools/container/Dockerfile`: Rust 1.93.1 by digest, plus
cargo-fuzz 0.13.2 and cargo-deny 0.20.2):

```sh
tools/container.sh tools/gate.sh            # fmt, clippy, test, fuzz, audit
tools/container.sh tools/gate.sh test       # one job
FUZZ_SECONDS=600 tools/container.sh tools/gate.sh fuzz
```

| Job | What |
|---|---|
| `fmt` | `cargo fmt --check` of the crate and the fuzz harness |
| `clippy` | `cargo clippy --locked --all-targets -D warnings` of both |
| `test` | `cargo test --locked --release`, with the generated text-fallback fixtures added to the corpus |
| `fuzz` | every cargo-fuzz target for `FUZZ_SECONDS` (default 60), built with AddressSanitizer |
| `audit` | `cargo deny check`: advisories, licences, bans, sources |

The library ships no binaries, so there is no release artifact to reproduce. Consumers pin a commit.

`.github/workflows/` mirrors the gate for when the repository is hosted. `checks.yml` is a cheap check on every push.
`ci.yml` runs the full gate on tags and on manual dispatch.

## Contributing

This repository is not accepting contributions at this time: issues and pull requests are not accepted. Report
security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT, see `LICENSE`. Third-party material: `THIRD-PARTY-NOTICES.md`.
